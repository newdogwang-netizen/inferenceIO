use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    crypto::EncryptionKey,
    manifest,
    model::TerminalState,
    storage::{StorageError, for_each_run_event_with_key},
};

pub const DEFAULT_TIMELINE_PAGE_SIZE: usize = 10_000;
pub const MAX_TIMELINE_PAGE_SIZE: usize = 100_000;

#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    pub logical_task_id: Option<String>,
    pub session_id: Option<String>,
    pub turn_id: Option<String>,
    pub inference_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    pub sequence: u64,
    pub elapsed_ns: u64,
    pub wall_time: DateTime<Utc>,
    pub source: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<TerminalState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelinePage {
    pub entries: Vec<TimelineEntry>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after_sequence: Option<u64>,
}

pub fn load(run_dir: &Path, filter: &TimelineFilter) -> Result<Vec<TimelineEntry>, StorageError> {
    load_with_key(run_dir, filter, None)
}

pub fn load_with_key(
    run_dir: &Path,
    filter: &TimelineFilter,
    encryption: Option<&EncryptionKey>,
) -> Result<Vec<TimelineEntry>, StorageError> {
    let page = load_page_with_key(run_dir, filter, None, MAX_TIMELINE_PAGE_SIZE, encryption)?;
    if page.truncated {
        return Err(StorageError::AnalysisLimitExceeded {
            operation: "timeline result",
            limit: MAX_TIMELINE_PAGE_SIZE,
        });
    }
    Ok(page.entries)
}

pub fn load_page_with_key(
    run_dir: &Path,
    filter: &TimelineFilter,
    after_sequence: Option<u64>,
    limit: usize,
    encryption: Option<&EncryptionKey>,
) -> Result<TimelinePage, StorageError> {
    if limit == 0 || limit > MAX_TIMELINE_PAGE_SIZE {
        return Err(StorageError::AnalysisLimitExceeded {
            operation: "timeline page",
            limit: MAX_TIMELINE_PAGE_SIZE,
        });
    }
    let manifest = manifest::read(&run_dir.join("manifest.json"))?;
    let effective_encryption = manifest.effective_encryption_key(encryption)?;
    manifest.verify_authentication(encryption)?;
    let encryption = effective_encryption.as_ref();
    let mut entries = Vec::with_capacity(limit.min(1_024));
    let mut truncated = false;
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        &manifest.run_id,
        encryption,
        |event| {
            if after_sequence.is_some_and(|sequence| event.sequence <= sequence) {
                return Ok(());
            }
            if !matches_filter(&event, filter) {
                return Ok(());
            }
            if entries.len() == limit {
                truncated = true;
                return Ok(());
            }
            entries.push(TimelineEntry {
                sequence: event.sequence,
                elapsed_ns: event.monotonic_ns,
                wall_time: event.wall_time,
                source: event.source,
                event: event.event,
                logical_task_id: crate::tasks::logical_task_id(&event.ids),
                task_id: event.ids.task_id,
                session_id: event.ids.session_id,
                turn_id: event.ids.turn_id,
                inference_id: event.ids.inference_id,
                attempt_id: event.ids.attempt_id,
                parent_id: event.ids.parent_id,
                terminal_state: event.terminal_state,
                summary: event.normalized.as_ref().and_then(compact_summary),
            });
            Ok(())
        },
    )?;
    let next_after_sequence = truncated
        .then(|| entries.last().map(|entry| entry.sequence))
        .flatten();
    Ok(TimelinePage {
        entries,
        truncated,
        next_after_sequence,
    })
}

fn matches_filter(event: &crate::model::EventEnvelope, filter: &TimelineFilter) -> bool {
    filter
        .logical_task_id
        .as_ref()
        .is_none_or(|value| crate::tasks::matches_logical_task(event, value))
        && filter
            .session_id
            .as_ref()
            .is_none_or(|value| event.ids.session_id.as_ref() == Some(value))
        && filter
            .turn_id
            .as_ref()
            .is_none_or(|value| event.ids.turn_id.as_ref() == Some(value))
        && filter
            .inference_id
            .as_ref()
            .is_none_or(|value| event.ids.inference_id.as_ref() == Some(value))
}

fn compact_summary(value: &serde_json::Value) -> Option<String> {
    let candidates = [
        ("model", value.pointer("/summary/model")),
        ("status", value.get("status")),
        ("state", value.get("reason")),
        ("tool", value.get("tool_name")),
        ("pid", value.get("pid")),
        ("bytes", value.get("observed_bytes")),
        ("chunks", value.get("chunks")),
        ("sse", value.pointer("/semantic/type")),
        ("error", value.get("error_kind")),
    ];
    let fields: Vec<String> = candidates
        .into_iter()
        .filter_map(|(name, value)| {
            let value = value?;
            let rendered = match value {
                serde_json::Value::String(text) => crate::metadata::bounded_string(text),
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::Bool(boolean) => boolean.to_string(),
                _ => return None,
            };
            Some(format!("{name}={rendered}"))
        })
        .collect();
    (!fields.is_empty()).then(|| fields.join(" "))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn timeline_pages_are_bounded_and_resume_after_the_last_sequence() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "timeline-page";
        write_atomic(
            &temporary.path().join("manifest.json"),
            &Manifest::new(
                run_id.to_owned(),
                CommandMetadata {
                    argv: vec!["test".to_owned()],
                    cwd: PathBuf::from("/tmp"),
                    executable: None,
                    executable_sha256: None,
                    agent: None,
                    agent_version: None,
                    runtime: None,
                    executable_tls_surfaces: Vec::new(),
                    environment: BTreeMap::new(),
                },
                CapturePolicy::default(),
            ),
        )
        .unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), run_id, CapturePolicy::default()).unwrap();
        for event in ["first", "second", "third"] {
            store.append(store.event("test", event)).await.unwrap();
        }
        store.shutdown().await.unwrap();

        let first = load_page_with_key(temporary.path(), &TimelineFilter::default(), None, 2, None)
            .unwrap();
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(first.truncated);
        assert_eq!(first.next_after_sequence, Some(2));

        let second = load_page_with_key(
            temporary.path(),
            &TimelineFilter::default(),
            first.next_after_sequence,
            2,
            None,
        )
        .unwrap();
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].sequence, 3);
        assert!(!second.truncated);
        assert_eq!(second.next_after_sequence, None);
    }

    #[test]
    fn timeline_page_rejects_zero_or_excessive_limits_before_reading() {
        let temporary = tempfile::tempdir().unwrap();
        for limit in [0, MAX_TIMELINE_PAGE_SIZE + 1] {
            assert!(matches!(
                load_page_with_key(
                    temporary.path(),
                    &TimelineFilter::default(),
                    None,
                    limit,
                    None,
                ),
                Err(StorageError::AnalysisLimitExceeded { .. })
            ));
        }
    }
}
