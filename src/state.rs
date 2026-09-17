use std::{collections::BTreeMap, path::Path};

use serde::Serialize;

use crate::{
    crypto::EncryptionKey,
    manifest,
    storage::{StorageError, for_each_run_event_with_key},
};

const MAX_STATE_TRACKED_ITEMS: usize = 100_000;

#[derive(Debug, Clone, Serialize)]
pub struct StateNode {
    pub id: String,
    pub kind: String,
    pub observed: bool,
    pub first_sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StateGraph {
    pub nodes: Vec<StateNode>,
    pub edges: Vec<StateEdge>,
    pub unresolved: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub analysis_truncated: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted_observations: u64,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl StateGraph {
    #[must_use]
    pub fn unresolved_count(&self) -> u64 {
        let unresolved = u64::try_from(self.unresolved.len()).unwrap_or(u64::MAX);
        if self.analysis_truncated {
            unresolved.saturating_add(self.omitted_observations.max(1))
        } else {
            unresolved
        }
    }
}

#[derive(Debug, Clone)]
struct Reference {
    kind: &'static str,
    id: String,
    inference_id: String,
    sequence: u64,
}

pub fn analyze(run_dir: &Path) -> Result<StateGraph, StorageError> {
    analyze_with_key(run_dir, None)
}

pub fn analyze_with_key(
    run_dir: &Path,
    encryption: Option<&EncryptionKey>,
) -> Result<StateGraph, StorageError> {
    analyze_with_key_and_limit(run_dir, encryption, MAX_STATE_TRACKED_ITEMS)
}

fn analyze_with_key_and_limit(
    run_dir: &Path,
    encryption: Option<&EncryptionKey>,
    limit: usize,
) -> Result<StateGraph, StorageError> {
    let manifest = manifest::read(&run_dir.join("manifest.json"))?;
    let effective_encryption = manifest.effective_encryption_key(encryption)?;
    manifest.verify_authentication(encryption)?;
    let encryption = effective_encryption.as_ref();
    let mut response_nodes = BTreeMap::<String, u64>::new();
    let mut inference_targets = BTreeMap::<String, String>::new();
    let mut references = Vec::new();
    let mut analysis_truncated = false;
    let mut omitted_observations = 0_u64;

    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        &manifest.run_id,
        encryption,
        |event| {
            let Some(inference_id) = event.ids.inference_id.clone() else {
                return Ok(());
            };

            if event.source == "proxy"
                && event.event == "logical_inference_request"
                && let Some(summary) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("summary"))
            {
                push_reference(
                    &mut references,
                    "response",
                    summary.get("previous_response_id"),
                    &inference_id,
                    event.sequence,
                    limit,
                    &mut analysis_truncated,
                    &mut omitted_observations,
                );
                push_reference(
                    &mut references,
                    "conversation",
                    summary.get("conversation"),
                    &inference_id,
                    event.sequence,
                    limit,
                    &mut analysis_truncated,
                    &mut omitted_observations,
                );
                push_reference(
                    &mut references,
                    "cached_content",
                    summary.get("cached_content"),
                    &inference_id,
                    event.sequence,
                    limit,
                    &mut analysis_truncated,
                    &mut omitted_observations,
                );
            }
            if event.source == "proxy"
                && event.event == "sse_event"
                && let Some(semantic) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("semantic"))
            {
                if let Some(response_id) =
                    semantic.get("response_id").and_then(|value| value.as_str())
                {
                    insert_observation(
                        &mut response_nodes,
                        response_id.to_owned(),
                        event.sequence,
                        limit,
                        &mut analysis_truncated,
                        &mut omitted_observations,
                    );
                    insert_observation(
                        &mut inference_targets,
                        inference_id.clone(),
                        response_id.to_owned(),
                        limit,
                        &mut analysis_truncated,
                        &mut omitted_observations,
                    );
                }
                push_reference(
                    &mut references,
                    "response",
                    semantic.get("previous_response_id"),
                    &inference_id,
                    event.sequence,
                    limit,
                    &mut analysis_truncated,
                    &mut omitted_observations,
                );
            }
            Ok(())
        },
    )?;

    let mut nodes = BTreeMap::<String, StateNode>::new();
    for (id, sequence) in response_nodes {
        nodes.insert(
            node_key("response", &id),
            StateNode {
                id,
                kind: "response".to_owned(),
                observed: true,
                first_sequence: sequence,
            },
        );
    }
    let mut edges = BTreeMap::<String, StateEdge>::new();
    for reference in references {
        let key = node_key(reference.kind, &reference.id);
        let observed = reference.kind == "response" && nodes.contains_key(&key);
        nodes.entry(key.clone()).or_insert_with(|| StateNode {
            id: reference.id.clone(),
            kind: reference.kind.to_owned(),
            observed,
            first_sequence: reference.sequence,
        });
        let target = inference_targets.get(&reference.inference_id).map_or_else(
            || format!("inference:{}", reference.inference_id),
            |response| node_key("response", response),
        );
        if !nodes.contains_key(&target) {
            nodes.insert(
                target.clone(),
                StateNode {
                    id: reference.inference_id.clone(),
                    kind: "inference".to_owned(),
                    observed: true,
                    first_sequence: reference.sequence,
                },
            );
        }
        let relation = match reference.kind {
            "response" => "previous_response",
            "conversation" => "conversation_state",
            "cached_content" => "cached_content",
            _ => "reference",
        };
        let edge_key = format!("{key}\0{target}\0{relation}");
        edges.entry(edge_key).or_insert(StateEdge {
            from: key,
            to: target,
            relation: relation.to_owned(),
            inference_id: Some(reference.inference_id),
        });
    }

    let unresolved = nodes
        .iter()
        .filter(|(_, node)| !node.observed)
        .map(|(key, _)| key.clone())
        .collect();
    Ok(StateGraph {
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
        unresolved,
        analysis_truncated,
        omitted_observations,
    })
}

fn push_reference(
    output: &mut Vec<Reference>,
    kind: &'static str,
    value: Option<&serde_json::Value>,
    inference_id: &str,
    sequence: u64,
    limit: usize,
    analysis_truncated: &mut bool,
    omitted_observations: &mut u64,
) {
    if let Some(id) = value
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
    {
        if output.len() < limit {
            output.push(Reference {
                kind,
                id: id.to_owned(),
                inference_id: inference_id.to_owned(),
                sequence,
            });
        } else {
            note_omission(analysis_truncated, omitted_observations);
        }
    }
}

fn insert_observation<K: Ord, V>(
    output: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    limit: usize,
    analysis_truncated: &mut bool,
    omitted_observations: &mut u64,
) {
    if output.contains_key(&key) {
        return;
    }
    if output.len() < limit {
        output.insert(key, value);
    } else {
        note_omission(analysis_truncated, omitted_observations);
    }
}

fn note_omission(analysis_truncated: &mut bool, omitted_observations: &mut u64) {
    *analysis_truncated = true;
    *omitted_observations = omitted_observations.saturating_add(1);
}

fn node_key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use serde_json::json;

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        model::EventIds,
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn reports_missing_previous_response_and_cached_content() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "state", CapturePolicy::default()).unwrap();
        write_atomic(
            &temporary.path().join("manifest.json"),
            &Manifest::new(
                "state".to_owned(),
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
        let mut request = store.event("proxy", "logical_inference_request");
        request.ids = EventIds {
            inference_id: Some("inference-1".to_owned()),
            ..EventIds::default()
        };
        request.normalized = Some(json!({
            "summary": {
                "previous_response_id": "response-missing",
                "cached_content": "cache-missing",
            }
        }));
        store.append(request).await.unwrap();
        let mut response = store.event("proxy", "sse_event");
        response.ids = EventIds {
            inference_id: Some("inference-1".to_owned()),
            ..EventIds::default()
        };
        response.normalized = Some(json!({
            "semantic": {"response_id": "response-current"}
        }));
        store.append(response).await.unwrap();
        let mut spoofed = store.event("hook:test", "logical_inference_request");
        spoofed.ids.inference_id = Some("spoofed-inference".to_owned());
        spoofed.normalized = Some(json!({
            "summary": {"previous_response_id": "spoofed-response"}
        }));
        store.append(spoofed).await.unwrap();
        store.shutdown().await.unwrap();

        let graph = analyze(temporary.path()).unwrap();
        assert!(
            graph
                .unresolved
                .contains(&"response:response-missing".to_owned())
        );
        assert!(
            graph
                .unresolved
                .contains(&"cached_content:cache-missing".to_owned())
        );
        assert_eq!(graph.edges.len(), 2);
        assert!(
            !graph
                .unresolved
                .contains(&"response:spoofed-response".to_owned())
        );
        assert!(
            graph
                .edges
                .iter()
                .all(|edge| edge.to == "response:response-current")
        );

        let bounded = analyze_with_key_and_limit(temporary.path(), None, 1).unwrap();
        assert!(bounded.analysis_truncated);
        assert_eq!(bounded.omitted_observations, 1);
        assert_eq!(bounded.edges.len(), 1);
        assert!(bounded.unresolved_count() > bounded.unresolved.len() as u64);
    }
}
