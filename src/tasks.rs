use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    crypto::EncryptionKey,
    manifest,
    model::{EventEnvelope, EventIds},
    storage::{StorageError, for_each_run_event_with_key},
};

pub const TASK_SPLIT_POLICY_V1: &str = "agent-task-or-session-v1";
pub const MAX_LOGICAL_TASKS: usize = 100_000;
const MAX_TASK_SESSION_ASSOCIATIONS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskBoundaryKind {
    AgentTask,
    AgentSession,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogicalTask {
    pub logical_task_id: String,
    pub boundary_kind: TaskBoundaryKind,
    pub native_id: String,
    pub event_count: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskIndex {
    pub schema_version: u32,
    pub split_policy: &'static str,
    pub run_id: String,
    pub tasks: Vec<LogicalTask>,
    pub unassigned_events: u64,
}

struct TaskAccumulator {
    boundary_kind: TaskBoundaryKind,
    native_id: String,
    event_count: u64,
    first_sequence: u64,
    last_sequence: u64,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    sessions: BTreeSet<String>,
}

/// Return the stable logical-task boundary for one event. Explicit Agent task
/// IDs take precedence; otherwise an Agent session is the conservative task
/// boundary. Run-scoped events intentionally remain unassigned.
#[must_use]
pub fn logical_task_id(ids: &EventIds) -> Option<String> {
    ids.task_id
        .as_ref()
        .map(|id| format!("task:{id}"))
        .or_else(|| ids.session_id.as_ref().map(|id| format!("session:{id}")))
}

#[must_use]
pub fn matches_logical_task(event: &EventEnvelope, logical_id: &str) -> bool {
    logical_task_id(&event.ids).as_deref() == Some(logical_id)
}

pub fn load_with_key(
    run_dir: &Path,
    encryption: Option<&EncryptionKey>,
) -> Result<TaskIndex, StorageError> {
    let manifest = manifest::read(&run_dir.join("manifest.json"))?;
    let effective_encryption = manifest.effective_encryption_key(encryption)?;
    manifest.verify_authentication(encryption)?;
    let mut tasks = BTreeMap::<String, TaskAccumulator>::new();
    let mut unassigned_events = 0_u64;
    let mut session_associations = 0_usize;
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        &manifest.run_id,
        effective_encryption.as_ref(),
        |event| {
            let Some(logical_id) = logical_task_id(&event.ids) else {
                unassigned_events = unassigned_events.saturating_add(1);
                return Ok(());
            };
            if !tasks.contains_key(&logical_id) && tasks.len() == MAX_LOGICAL_TASKS {
                return Err(StorageError::AnalysisLimitExceeded {
                    operation: "logical task index",
                    limit: MAX_LOGICAL_TASKS,
                });
            }
            let (boundary_kind, native_id) = if let Some(task_id) = &event.ids.task_id {
                (TaskBoundaryKind::AgentTask, task_id.clone())
            } else {
                (
                    TaskBoundaryKind::AgentSession,
                    event.ids.session_id.clone().unwrap_or_default(),
                )
            };
            let accumulator = tasks.entry(logical_id).or_insert_with(|| TaskAccumulator {
                boundary_kind,
                native_id,
                event_count: 0,
                first_sequence: event.sequence,
                last_sequence: event.sequence,
                first_seen_at: event.wall_time,
                last_seen_at: event.wall_time,
                sessions: BTreeSet::new(),
            });
            accumulator.event_count = accumulator.event_count.saturating_add(1);
            accumulator.last_sequence = event.sequence;
            accumulator.last_seen_at = event.wall_time;
            if let Some(session_id) = event.ids.session_id
                && !accumulator.sessions.contains(&session_id)
            {
                if session_associations == MAX_TASK_SESSION_ASSOCIATIONS {
                    return Err(StorageError::AnalysisLimitExceeded {
                        operation: "logical task/session association index",
                        limit: MAX_TASK_SESSION_ASSOCIATIONS,
                    });
                }
                accumulator.sessions.insert(session_id);
                session_associations = session_associations.saturating_add(1);
            }
            Ok(())
        },
    )?;
    Ok(TaskIndex {
        schema_version: 1,
        split_policy: TASK_SPLIT_POLICY_V1,
        run_id: manifest.run_id,
        tasks: tasks
            .into_iter()
            .map(|(logical_task_id, task)| LogicalTask {
                logical_task_id,
                boundary_kind: task.boundary_kind,
                native_id: task.native_id,
                event_count: task.event_count,
                first_sequence: task.first_sequence,
                last_sequence: task.last_sequence,
                first_seen_at: task.first_seen_at,
                last_seen_at: task.last_seen_at,
                session_ids: task.sessions.into_iter().collect(),
            })
            .collect(),
        unassigned_events,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn explicit_tasks_split_one_session_and_session_only_events_stay_conservative() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "gateway-run";
        write_atomic(
            &temporary.path().join("manifest.json"),
            &Manifest::new(
                run_id.to_owned(),
                CommandMetadata {
                    argv: vec!["hermes gateway".to_owned()],
                    cwd: temporary.path().to_path_buf(),
                    executable: None,
                    executable_sha256: None,
                    agent: Some("hermes".to_owned()),
                    agent_version: None,
                    runtime: Some("python".to_owned()),
                    executable_tls_surfaces: Vec::new(),
                    environment: BTreeMap::new(),
                },
                CapturePolicy::default(),
            ),
        )
        .unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), run_id, CapturePolicy::default()).unwrap();
        for (task, event) in [
            (Some("cron-a"), "a-start"),
            (Some("message-b"), "b-start"),
            (Some("cron-a"), "a-end"),
            (None, "session-heartbeat"),
            (Some("message-b"), "b-end"),
        ] {
            let mut pending = store.event("hook:hermes", event);
            pending.ids.session_id = Some("shared-gateway-session".to_owned());
            pending.ids.task_id = task.map(str::to_owned);
            store.append(pending).await.unwrap();
        }
        store.shutdown().await.unwrap();

        let index = load_with_key(temporary.path(), None).unwrap();
        assert_eq!(index.split_policy, TASK_SPLIT_POLICY_V1);
        assert_eq!(index.tasks.len(), 3);
        assert_eq!(index.unassigned_events, 0);
        assert_eq!(
            index.tasks[0].logical_task_id,
            "session:shared-gateway-session"
        );
        assert_eq!(index.tasks[0].event_count, 1);
        assert_eq!(index.tasks[1].logical_task_id, "task:cron-a");
        assert_eq!(index.tasks[1].event_count, 2);
        assert_eq!(index.tasks[2].logical_task_id, "task:message-b");
        assert_eq!(index.tasks[2].event_count, 2);
    }
}
