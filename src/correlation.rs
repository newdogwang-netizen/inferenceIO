use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    crypto::EncryptionKey,
    metadata,
    model::{EventEnvelope, EventIds, PendingEvent},
    storage::{RunStore, StorageError, for_each_run_event_with_key},
};

const PRE_WINDOW_BEFORE_MS: i64 = 250;
const PRE_WINDOW_AFTER_MS: i64 = 10_000;
const COMPLETION_WINDOW_BEFORE_MS: i64 = 10 * 60 * 1000;
const COMPLETION_WINDOW_AFTER_MS: i64 = 1_000;
const MAX_RECORDED_CANDIDATES: usize = 1_024;
const MAX_CORRELATION_ITEMS: usize = 100_000;
const MAX_CORRELATION_INDEX_ENTRIES: usize = 2 * MAX_CORRELATION_ITEMS;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CorrelationReport {
    pub resolved: u64,
    pub unresolved: u64,
    pub unmatched_transports: u64,
    pub skipped_existing: bool,
}

#[derive(Debug, Clone, Copy)]
enum AnchorKind {
    PreRequest,
    Completion,
}

#[derive(Debug, Clone)]
struct Anchor {
    kind: AnchorKind,
    sequence: u64,
    wall_time: DateTime<Utc>,
    source: String,
    event: String,
    ids: EventIds,
    model: Option<String>,
}

#[derive(Debug, Clone)]
struct Transport {
    sequence: u64,
    wall_time: DateTime<Utc>,
    inference_id: String,
    attempt_id: Option<String>,
    session_id: Option<String>,
    provider_response_ids: BTreeSet<String>,
    model: Option<String>,
    request_fingerprint: Option<String>,
    response_status: Option<u16>,
    terminal_state: Option<crate::model::TerminalState>,
}

struct CandidateSet<'a> {
    candidates: Vec<&'a Transport>,
    total: u64,
    truncated: bool,
}

pub async fn derive(
    store: &RunStore,
    run_dir: &Path,
    encryption: Option<&EncryptionKey>,
) -> Result<CorrelationReport, StorageError> {
    store.flush().await?;
    let mut anchors = Vec::new();
    let mut transports = Vec::new();
    let mut transport_indices = BTreeMap::new();
    let mut pending_response_status = BTreeMap::new();
    let mut pending_response_ids = BTreeMap::new();
    let mut pending_terminal_state = BTreeMap::new();
    let mut agent_scopes = BTreeMap::<String, EventIds>::new();
    let mut existing = false;
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        store.run_id(),
        encryption,
        |event| {
            if event.source == "correlation" {
                existing = true;
                return Ok(());
            }
            if event.source == "proxy"
                && event.event == "logical_inference_request"
                && let Some(inference_id) = event.ids.inference_id.clone()
            {
                let response_status = take_pending(&mut pending_response_status, &event);
                let provider_response_ids =
                    take_pending(&mut pending_response_ids, &event).unwrap_or_default();
                let terminal_state = take_pending(&mut pending_terminal_state, &event);
                let index = transports.len();
                transports.push(Transport {
                    sequence: event.sequence,
                    wall_time: event.wall_time,
                    inference_id,
                    attempt_id: event.ids.attempt_id.clone(),
                    session_id: event.ids.session_id.clone(),
                    provider_response_ids,
                    model: model_from_transport(&event),
                    request_fingerprint: request_fingerprint(&event),
                    response_status,
                    terminal_state,
                });
                remember_transport(&mut transport_indices, &event, index);
            }
            if event.source == "proxy" && event.event == "transport_response_started" {
                let response_status = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("status"))
                    .and_then(Value::as_u64)
                    .and_then(|status| u16::try_from(status).ok());
                if let Some(index) = transport_index(&transport_indices, &event) {
                    transports[index].response_status = response_status;
                } else if let Some(response_status) = response_status {
                    remember_pending(&mut pending_response_status, &event, response_status);
                }
            }
            if event.source == "proxy"
                && event.event == "sse_event"
                && let Some(response_id) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.pointer("/semantic/response_id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            {
                if let Some(index) = transport_index(&transport_indices, &event) {
                    transports[index].provider_response_ids.insert(response_id);
                } else {
                    let mut identifiers = BTreeSet::new();
                    identifiers.insert(response_id);
                    remember_pending(&mut pending_response_ids, &event, identifiers);
                }
            }
            if event.source == "proxy" && event.event == "transport_attempt_finished" {
                if let Some(index) = transport_index(&transport_indices, &event) {
                    transports[index]
                        .terminal_state
                        .clone_from(&event.terminal_state);
                } else if let Some(state) = event.terminal_state.clone() {
                    remember_pending(&mut pending_terminal_state, &event, state);
                }
            }
            if let Some(kind) = anchor_kind(&event)
                && (event.ids.session_id.is_some()
                    || event.ids.turn_id.is_some()
                    || event.ids.inference_id.is_some())
            {
                anchors.push(Anchor {
                    kind,
                    sequence: event.sequence,
                    wall_time: event.wall_time,
                    source: event.source.clone(),
                    event: event.event.clone(),
                    ids: event.ids.clone(),
                    model: model_from_anchor(&event),
                });
            }
            if (event.source == "session" || event.source.starts_with("hook:"))
                && let Some(session_id) = event.ids.session_id.clone()
            {
                agent_scopes.entry(session_id).or_insert(event.ids.clone());
            }
            ensure_correlation_limit(
                anchors.len(),
                MAX_CORRELATION_ITEMS,
                "correlation anchor index",
            )?;
            ensure_correlation_limit(
                transports.len(),
                MAX_CORRELATION_ITEMS,
                "correlation transport index",
            )?;
            ensure_correlation_limit(
                transport_indices.len(),
                MAX_CORRELATION_INDEX_ENTRIES,
                "correlation transport identifier index",
            )?;
            ensure_correlation_limit(
                pending_response_status.len(),
                MAX_CORRELATION_INDEX_ENTRIES,
                "correlation pending-status index",
            )?;
            ensure_correlation_limit(
                pending_terminal_state.len(),
                MAX_CORRELATION_INDEX_ENTRIES,
                "correlation pending-terminal index",
            )?;
            ensure_correlation_limit(
                pending_response_ids.len(),
                MAX_CORRELATION_INDEX_ENTRIES,
                "correlation pending-response-identifier index",
            )?;
            ensure_correlation_limit(
                agent_scopes.len(),
                MAX_CORRELATION_ITEMS,
                "correlation agent-scope index",
            )?;
            Ok(())
        },
    )?;
    if existing {
        return Ok(CorrelationReport {
            skipped_existing: true,
            ..CorrelationReport::default()
        });
    }

    anchors.sort_by_key(|anchor| anchor.sequence);
    transports.sort_by_key(|transport| transport.sequence);
    let mut transports_by_time: Vec<usize> = (0..transports.len()).collect();
    transports_by_time
        .sort_by_key(|index| (transports[*index].wall_time, transports[*index].sequence));
    let mut transports_by_exact_id = BTreeMap::<String, Vec<usize>>::new();
    for (index, transport) in transports.iter().enumerate() {
        transports_by_exact_id
            .entry(transport.inference_id.clone())
            .or_default()
            .push(index);
        for response_id in &transport.provider_response_ids {
            transports_by_exact_id
                .entry(response_id.clone())
                .or_default()
                .push(index);
        }
    }
    let mut matched = BTreeSet::new();
    // A native session transcript can describe the same model call after its
    // pre-request hook has already claimed the transport. Retain only those
    // pre-request scopes so a completion may corroborate (but never steal)
    // an already matched transport from the same logical session.
    let mut pre_request_scopes = BTreeMap::<String, Vec<EventIds>>::new();
    let mut report = CorrelationReport::default();
    for anchor in &anchors {
        let selection = candidates_for_anchor(
            anchor,
            &transports,
            &transports_by_time,
            &transports_by_exact_id,
            &matched,
            &pre_request_scopes,
        );
        let event = if selection.total == 1 {
            let transport = selection.candidates[0];
            let corroborates_existing = matched.contains(&transport.inference_id);
            matched.insert(transport.inference_id.clone());
            remember_pre_request_scope(&mut pre_request_scopes, anchor, transport);
            report.resolved = report.resolved.saturating_add(1);
            resolved_event(store, anchor, transport, corroborates_existing)
        } else if !selection.truncated
            && retry_chain_is_unique(anchor, &selection.candidates, &anchors)
        {
            for transport in &selection.candidates {
                matched.insert(transport.inference_id.clone());
                remember_pre_request_scope(&mut pre_request_scopes, anchor, transport);
            }
            report.resolved = report.resolved.saturating_add(1);
            resolved_retry_chain_event(store, anchor, &selection.candidates)
        } else {
            report.unresolved = report.unresolved.saturating_add(1);
            unresolved_anchor_event(store, anchor, &selection)
        };
        store.append(event).await?;
    }
    for transport in transports
        .iter()
        .filter(|transport| !matched.contains(&transport.inference_id))
    {
        if let Some(scope) = transport
            .session_id
            .as_ref()
            .and_then(|session_id| agent_scopes.get(session_id))
        {
            store
                .append(transport_session_scope_event(store, transport, scope))
                .await?;
            report.resolved = report.resolved.saturating_add(1);
        } else {
            store
                .append(unmatched_transport_event(store, transport))
                .await?;
            report.unresolved = report.unresolved.saturating_add(1);
            report.unmatched_transports = report.unmatched_transports.saturating_add(1);
        }
    }
    Ok(report)
}

fn ensure_correlation_limit(
    length: usize,
    limit: usize,
    operation: &'static str,
) -> Result<(), StorageError> {
    if length > limit {
        return Err(StorageError::AnalysisLimitExceeded { operation, limit });
    }
    Ok(())
}

fn candidates_for_anchor<'a>(
    anchor: &Anchor,
    transports: &'a [Transport],
    transports_by_time: &[usize],
    transports_by_exact_id: &BTreeMap<String, Vec<usize>>,
    matched: &BTreeSet<String>,
    pre_request_scopes: &BTreeMap<String, Vec<EventIds>>,
) -> CandidateSet<'a> {
    let (before_ms, after_ms) = match anchor.kind {
        AnchorKind::PreRequest => (PRE_WINDOW_BEFORE_MS, PRE_WINDOW_AFTER_MS),
        AnchorKind::Completion => (COMPLETION_WINDOW_BEFORE_MS, COMPLETION_WINDOW_AFTER_MS),
    };
    let start = anchor
        .wall_time
        .checked_sub_signed(chrono::TimeDelta::milliseconds(before_ms))
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let end = anchor
        .wall_time
        .checked_add_signed(chrono::TimeDelta::milliseconds(after_ms))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let first = transports_by_time.partition_point(|index| transports[*index].wall_time < start);
    let after_last =
        transports_by_time.partition_point(|index| transports[*index].wall_time <= end);
    if let Some(exact_id) = anchor.ids.inference_id.as_ref()
        && let Some(exact) = transports_by_exact_id.get(exact_id)
    {
        let mut candidates = Vec::new();
        let mut total = 0_u64;
        for index in exact {
            let transport = &transports[*index];
            if candidate_allowed(anchor, transport, matched, pre_request_scopes, true) {
                total = total.saturating_add(1);
                if candidates.len() < MAX_RECORDED_CANDIDATES {
                    candidates.push(transport);
                }
            }
        }
        if total > 0 {
            candidates.sort_by_key(|transport| transport.sequence);
            return CandidateSet {
                truncated: total > u64::try_from(candidates.len()).unwrap_or(u64::MAX),
                candidates,
                total,
            };
        }
    }
    let mut candidates = Vec::new();
    let mut total = 0_u64;
    for index in &transports_by_time[first..after_last] {
        let transport = &transports[*index];
        if candidate_allowed(anchor, transport, matched, pre_request_scopes, false) {
            total = total.saturating_add(1);
            if candidates.len() < MAX_RECORDED_CANDIDATES {
                candidates.push(transport);
            }
        }
    }
    candidates.sort_by_key(|transport| transport.sequence);
    CandidateSet {
        truncated: total > u64::try_from(candidates.len()).unwrap_or(u64::MAX),
        candidates,
        total,
    }
}

fn candidate_allowed(
    anchor: &Anchor,
    transport: &Transport,
    matched: &BTreeSet<String>,
    pre_request_scopes: &BTreeMap<String, Vec<EventIds>>,
    exact_identifier: bool,
) -> bool {
    (exact_identifier || models_compatible(anchor.model.as_deref(), transport.model.as_deref()))
        && (!matched.contains(&transport.inference_id)
            || completion_corroborates_pre_request(anchor, transport, pre_request_scopes))
}

fn remember_pre_request_scope(
    scopes: &mut BTreeMap<String, Vec<EventIds>>,
    anchor: &Anchor,
    transport: &Transport,
) {
    if matches!(anchor.kind, AnchorKind::PreRequest) {
        scopes
            .entry(transport.inference_id.clone())
            .or_default()
            .push(anchor.ids.clone());
    }
}

fn completion_corroborates_pre_request(
    anchor: &Anchor,
    transport: &Transport,
    scopes: &BTreeMap<String, Vec<EventIds>>,
) -> bool {
    if !matches!(anchor.kind, AnchorKind::Completion) {
        return false;
    }
    if transport_matches_exact_identifier(anchor, transport) {
        return true;
    }
    scopes
        .get(&transport.inference_id)
        .is_some_and(|known| known.iter().any(|ids| same_logical_scope(&anchor.ids, ids)))
}

fn same_logical_scope(left: &EventIds, right: &EventIds) -> bool {
    if let (Some(left), Some(right)) = (&left.session_id, &right.session_id) {
        return left == right;
    }
    if let (Some(left), Some(right)) = (&left.task_id, &right.task_id) {
        return left == right;
    }
    if let (Some(left), Some(right)) = (&left.turn_id, &right.turn_id) {
        return left == right;
    }
    false
}

fn anchor_kind(event: &EventEnvelope) -> Option<AnchorKind> {
    let label: String = event
        .event
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    if matches!(
        label.as_str(),
        "beforemodel" | "preapirequest" | "modelcallstarted"
    ) {
        Some(AnchorKind::PreRequest)
    } else if event.source == "session"
        && matches!(label.as_str(), "sessionassistant" | "sessiongemini")
    {
        Some(AnchorKind::Completion)
    } else {
        None
    }
}

fn exact_or_in_window(anchor: &Anchor, transport: &Transport) -> bool {
    if transport_matches_exact_identifier(anchor, transport) {
        return true;
    }
    let delta = transport
        .wall_time
        .signed_duration_since(anchor.wall_time)
        .num_milliseconds();
    match anchor.kind {
        AnchorKind::PreRequest => (-PRE_WINDOW_BEFORE_MS..=PRE_WINDOW_AFTER_MS).contains(&delta),
        AnchorKind::Completion => {
            (-COMPLETION_WINDOW_AFTER_MS..=COMPLETION_WINDOW_BEFORE_MS).contains(&-delta)
        }
    }
}

fn transport_matches_exact_identifier(anchor: &Anchor, transport: &Transport) -> bool {
    anchor.ids.inference_id.as_ref().is_some_and(|identifier| {
        identifier == &transport.inference_id
            || transport.provider_response_ids.contains(identifier)
    })
}

fn models_compatible(anchor: Option<&str>, transport: Option<&str>) -> bool {
    match (anchor, transport) {
        (Some(anchor), Some(transport)) => anchor.eq_ignore_ascii_case(transport),
        _ => true,
    }
}

fn retry_chain_is_unique(anchor: &Anchor, candidates: &[&Transport], anchors: &[Anchor]) -> bool {
    if !matches!(anchor.kind, AnchorKind::PreRequest) || candidates.len() < 2 {
        return false;
    }
    let Some(fingerprint) = candidates[0].request_fingerprint.as_deref() else {
        return false;
    };
    if candidates.iter().any(|candidate| {
        candidate.request_fingerprint.as_deref() != Some(fingerprint)
            || candidate.inference_id == candidates[0].inference_id
                && candidate.attempt_id == candidates[0].attempt_id
                && candidate.sequence != candidates[0].sequence
    }) {
        return false;
    }
    if candidates[..candidates.len() - 1]
        .iter()
        .any(|candidate| !candidate.is_retriable_failure())
    {
        return false;
    }
    !anchors.iter().any(|other| {
        other.sequence != anchor.sequence
            && matches!(other.kind, AnchorKind::PreRequest)
            && candidates.iter().any(|transport| {
                models_compatible(other.model.as_deref(), transport.model.as_deref())
                    && exact_or_in_window(other, transport)
            })
    })
}

impl Transport {
    fn is_retriable_failure(&self) -> bool {
        self.response_status.is_some_and(|status| {
            matches!(status, 408 | 409 | 425 | 429) || (500..=599).contains(&status)
        }) || matches!(
            self.terminal_state,
            Some(
                crate::model::TerminalState::Error
                    | crate::model::TerminalState::Cancelled
                    | crate::model::TerminalState::Incomplete
            )
        )
    }
}

fn resolved_event(
    store: &RunStore,
    anchor: &Anchor,
    transport: &Transport,
    corroborates_existing: bool,
) -> PendingEvent {
    let exact = transport_matches_exact_identifier(anchor, transport);
    let confidence = if exact {
        1.0
    } else if corroborates_existing {
        0.9
    } else {
        match anchor.kind {
            AnchorKind::PreRequest => 0.9,
            AnchorKind::Completion => 0.65,
        }
    };
    let mut event = store.event("correlation", "inference_correlation");
    event.ids = EventIds {
        task_id: anchor.ids.task_id.clone(),
        session_id: anchor.ids.session_id.clone(),
        turn_id: anchor.ids.turn_id.clone(),
        inference_id: Some(transport.inference_id.clone()),
        parent_id: anchor
            .ids
            .inference_id
            .clone()
            .filter(|native| native != &transport.inference_id),
        ..EventIds::default()
    };
    event.normalized = Some(json!({
        "anchor_sequence": anchor.sequence,
        "transport_sequence": transport.sequence,
        "anchor_source": anchor.source,
        "anchor_event": anchor.event,
        "native_inference_id": anchor.ids.inference_id,
        "method": if exact {
            "exact_id"
        } else if corroborates_existing {
            "shared_scope_unique_temporal_candidate"
        } else {
            "unique_temporal_candidate"
        },
    }));
    event.confidence = Some(confidence);
    event.evidence = vec![
        format!("{}:{}", anchor.source, anchor.event),
        if exact {
            "exact_inference_id".to_owned()
        } else if corroborates_existing {
            "shared_agent_scope_and_unique_candidate_in_bounded_window".to_owned()
        } else {
            "unique_candidate_in_bounded_window".to_owned()
        },
    ];
    event
}

fn resolved_retry_chain_event(
    store: &RunStore,
    anchor: &Anchor,
    transports: &[&Transport],
) -> PendingEvent {
    let canonical = anchor
        .ids
        .inference_id
        .clone()
        .unwrap_or_else(|| transports[0].inference_id.clone());
    let mut event = store.event("correlation", "inference_correlation");
    event.ids = EventIds {
        task_id: anchor.ids.task_id.clone(),
        session_id: anchor.ids.session_id.clone(),
        turn_id: anchor.ids.turn_id.clone(),
        inference_id: Some(canonical),
        parent_id: anchor.ids.parent_id.clone(),
        ..EventIds::default()
    };
    event.normalized = Some(json!({
        "anchor_sequence": anchor.sequence,
        "anchor_source": anchor.source,
        "anchor_event": anchor.event,
        "native_inference_id": anchor.ids.inference_id,
        "transport_sequences": transports.iter().map(|transport| transport.sequence).collect::<Vec<_>>(),
        "transport_inference_ids": transports.iter().map(|transport| &transport.inference_id).collect::<Vec<_>>(),
        "attempt_ids": transports.iter().map(|transport| &transport.attempt_id).collect::<Vec<_>>(),
        "request_fingerprint": transports[0].request_fingerprint,
        "method": "unique_retry_chain",
    }));
    event.confidence = Some(0.9);
    event.evidence = vec![
        format!("{}:{}", anchor.source, anchor.event),
        "identical_request_fingerprint".to_owned(),
        "preceding_attempts_retriable".to_owned(),
        "unique_pre_request_anchor".to_owned(),
    ];
    event
}

fn unresolved_anchor_event(
    store: &RunStore,
    anchor: &Anchor,
    selection: &CandidateSet<'_>,
) -> PendingEvent {
    let mut event = store.event("correlation", "inference_correlation_unresolved");
    event.ids = anchor.ids.clone();
    event.normalized = Some(json!({
        "reason": if selection.total == 0 { "no_transport_candidate" } else { "ambiguous_transport_candidates" },
        "anchor_sequence": anchor.sequence,
        "anchor_source": anchor.source,
        "anchor_event": anchor.event,
        "candidate_count": selection.total,
        "candidate_inference_ids": selection.candidates.iter().map(|candidate| &candidate.inference_id).collect::<Vec<_>>(),
        "candidate_ids_truncated": selection.truncated,
    }));
    event.confidence = Some(0.0);
    event.evidence = vec![format!("{}:{}", anchor.source, anchor.event)];
    event
}

fn unmatched_transport_event(store: &RunStore, transport: &Transport) -> PendingEvent {
    let mut event = store.event("correlation", "inference_correlation_unresolved");
    event.ids.inference_id = Some(transport.inference_id.clone());
    event.normalized = Some(json!({
        "reason": "no_unique_agent_anchor",
        "transport_sequence": transport.sequence,
    }));
    event.confidence = Some(0.0);
    event.evidence = vec!["proxy:logical_inference_request".to_owned()];
    event
}

fn transport_session_scope_event(
    store: &RunStore,
    transport: &Transport,
    scope: &EventIds,
) -> PendingEvent {
    let mut event = store.event("correlation", "inference_correlation");
    event.ids = EventIds {
        task_id: scope.task_id.clone(),
        session_id: transport.session_id.clone(),
        inference_id: Some(transport.inference_id.clone()),
        ..EventIds::default()
    };
    event.normalized = Some(json!({
        "transport_sequence": transport.sequence,
        "method": "exact_transport_session_id",
    }));
    event.confidence = Some(0.8);
    event.evidence = vec![
        "proxy:provider_session_header".to_owned(),
        "agent:matching_session_id".to_owned(),
    ];
    event
}

fn model_from_transport(event: &EventEnvelope) -> Option<String> {
    metadata::value_string(
        event
            .normalized
            .as_ref()
            .and_then(|value| value.pointer("/summary/model")),
    )
}

fn request_fingerprint(event: &EventEnvelope) -> Option<String> {
    let normalized = event.normalized.as_ref()?;
    let path = normalized.get("path")?.as_str()?;
    let hash = normalized.get("sha256")?.as_str()?;
    let model = model_from_transport(event)
        .unwrap_or_default()
        .to_ascii_lowercase();
    Some(format!("{path}\0{hash}\0{model}"))
}

fn attempt_lookup_key(event: &EventEnvelope) -> Option<String> {
    event
        .ids
        .attempt_id
        .as_ref()
        .map(|attempt| format!("attempt:{attempt}"))
}

fn inference_lookup_key(event: &EventEnvelope) -> Option<String> {
    event
        .ids
        .inference_id
        .as_ref()
        .map(|inference| format!("inference:{inference}"))
}

fn remember_transport(indices: &mut BTreeMap<String, usize>, event: &EventEnvelope, index: usize) {
    if let Some(key) = attempt_lookup_key(event) {
        indices.insert(key, index);
    }
    if let Some(key) = inference_lookup_key(event) {
        indices.insert(key, index);
    }
}

fn transport_index(indices: &BTreeMap<String, usize>, event: &EventEnvelope) -> Option<usize> {
    attempt_lookup_key(event)
        .and_then(|key| indices.get(&key).copied())
        .or_else(|| inference_lookup_key(event).and_then(|key| indices.get(&key).copied()))
}

fn remember_pending<T: Clone>(pending: &mut BTreeMap<String, T>, event: &EventEnvelope, value: T) {
    if let Some(key) = attempt_lookup_key(event) {
        pending.insert(key, value.clone());
    }
    if let Some(key) = inference_lookup_key(event) {
        pending.insert(key, value);
    }
}

fn take_pending<T>(pending: &mut BTreeMap<String, T>, event: &EventEnvelope) -> Option<T> {
    let attempt_key = attempt_lookup_key(event);
    let inference_key = inference_lookup_key(event);
    let value = attempt_key
        .as_ref()
        .and_then(|key| pending.remove(key))
        .or_else(|| inference_key.as_ref().and_then(|key| pending.remove(key)));
    if let Some(key) = attempt_key {
        pending.remove(&key);
    }
    if let Some(key) = inference_key {
        pending.remove(&key);
    }
    value
}

fn model_from_anchor(event: &EventEnvelope) -> Option<String> {
    let normalized = event.normalized.as_ref()?;
    [
        "/llm_request/model",
        "/request/model",
        "/kwargs/model",
        "/model",
        "/message/model",
    ]
    .into_iter()
    .find_map(|pointer| metadata::value_string(normalized.pointer(pointer)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{model::EventIds, policy::CapturePolicy, storage::for_each_event};

    use super::*;

    #[test]
    fn correlation_cardinality_limit_is_a_structured_analysis_error() {
        assert!(matches!(
            ensure_correlation_limit(
                MAX_CORRELATION_ITEMS + 1,
                MAX_CORRELATION_ITEMS,
                "correlation test index",
            ),
            Err(StorageError::AnalysisLimitExceeded {
                operation: "correlation test index",
                limit: MAX_CORRELATION_ITEMS,
            })
        ));
    }

    #[test]
    fn time_index_keeps_exact_ids_outside_the_temporal_window() {
        let now = Utc::now();
        let anchor = Anchor {
            kind: AnchorKind::PreRequest,
            sequence: 1,
            wall_time: now,
            source: "hook:test".to_owned(),
            event: "pre_api_request".to_owned(),
            ids: EventIds {
                inference_id: Some("exact".to_owned()),
                ..EventIds::default()
            },
            model: Some("model".to_owned()),
        };
        let transports = vec![
            Transport {
                sequence: 2,
                wall_time: now + chrono::TimeDelta::hours(1),
                inference_id: "exact".to_owned(),
                attempt_id: None,
                session_id: None,
                provider_response_ids: BTreeSet::new(),
                model: Some("model".to_owned()),
                request_fingerprint: None,
                response_status: None,
                terminal_state: None,
            },
            Transport {
                sequence: 3,
                wall_time: now + chrono::TimeDelta::seconds(30),
                inference_id: "unrelated".to_owned(),
                attempt_id: None,
                session_id: None,
                provider_response_ids: BTreeSet::new(),
                model: Some("model".to_owned()),
                request_fingerprint: None,
                response_status: None,
                terminal_state: None,
            },
        ];
        let by_time = vec![1, 0];
        let by_exact_id = BTreeMap::from([
            ("exact".to_owned(), vec![0]),
            ("unrelated".to_owned(), vec![1]),
        ]);
        let candidates = candidates_for_anchor(
            &anchor,
            &transports,
            &by_time,
            &by_exact_id,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(candidates.total, 1);
        assert!(!candidates.truncated);
        assert_eq!(candidates.candidates[0].inference_id, "exact");
    }

    #[test]
    fn provider_response_id_beats_concurrent_temporal_candidates() {
        let now = Utc::now();
        let anchor = Anchor {
            kind: AnchorKind::Completion,
            sequence: 10,
            wall_time: now,
            source: "session".to_owned(),
            event: "session_assistant".to_owned(),
            ids: EventIds {
                session_id: Some("session-1".to_owned()),
                inference_id: Some("message-exact".to_owned()),
                ..EventIds::default()
            },
            model: Some("provider-response-model".to_owned()),
        };
        let transports = vec![
            Transport {
                sequence: 1,
                wall_time: now,
                inference_id: "transport-1".to_owned(),
                attempt_id: None,
                session_id: Some("session-1".to_owned()),
                provider_response_ids: BTreeSet::new(),
                model: Some("requested-model".to_owned()),
                request_fingerprint: None,
                response_status: None,
                terminal_state: None,
            },
            Transport {
                sequence: 2,
                wall_time: now,
                inference_id: "transport-2".to_owned(),
                attempt_id: None,
                session_id: Some("session-1".to_owned()),
                provider_response_ids: BTreeSet::from(["message-exact".to_owned()]),
                model: Some("requested-model".to_owned()),
                request_fingerprint: None,
                response_status: None,
                terminal_state: None,
            },
        ];
        let candidates = candidates_for_anchor(
            &anchor,
            &transports,
            &[0, 1],
            &BTreeMap::from([("message-exact".to_owned(), vec![1])]),
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(candidates.total, 1);
        assert_eq!(candidates.candidates[0].inference_id, "transport-2");
    }

    #[test]
    fn ambiguous_candidate_evidence_is_bounded_without_losing_the_count() {
        let now = Utc::now();
        let anchor = Anchor {
            kind: AnchorKind::PreRequest,
            sequence: 1,
            wall_time: now,
            source: "hook:test".to_owned(),
            event: "pre_api_request".to_owned(),
            ids: EventIds::default(),
            model: None,
        };
        let transports: Vec<_> = (0..MAX_RECORDED_CANDIDATES + 2)
            .map(|index| Transport {
                sequence: u64::try_from(index).unwrap_or(u64::MAX) + 2,
                wall_time: now,
                inference_id: format!("inference-{index:05}"),
                attempt_id: None,
                session_id: None,
                provider_response_ids: BTreeSet::new(),
                model: None,
                request_fingerprint: None,
                response_status: None,
                terminal_state: None,
            })
            .collect();
        let by_time: Vec<_> = (0..transports.len()).collect();
        let candidates = candidates_for_anchor(
            &anchor,
            &transports,
            &by_time,
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            candidates.total,
            u64::try_from(MAX_RECORDED_CANDIDATES + 2).unwrap()
        );
        assert_eq!(candidates.candidates.len(), MAX_RECORDED_CANDIDATES);
        assert!(candidates.truncated);
    }

    #[tokio::test]
    async fn links_only_a_unique_bounded_model_candidate() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "correlation", CapturePolicy::default()).unwrap();
        let mut hook = store.event("gemini", "BeforeModel");
        hook.ids = EventIds {
            task_id: Some("task-1".to_owned()),
            session_id: Some("session-1".to_owned()),
            turn_id: Some("turn-1".to_owned()),
            ..EventIds::default()
        };
        hook.normalized = Some(json!({"llm_request": {"model": "model-1"}}));
        store.append(hook).await.unwrap();
        let mut request = store.event("proxy", "logical_inference_request");
        request.ids.inference_id = Some("transport-1".to_owned());
        request.normalized = Some(json!({"summary": {"model": "model-1"}}));
        store.append(request).await.unwrap();
        let mut spoofed = store.event("hook:test", "logical_inference_request");
        spoofed.ids.inference_id = Some("spoofed-transport".to_owned());
        spoofed.normalized = Some(json!({"summary": {"model": "model-1"}}));
        store.append(spoofed).await.unwrap();

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 1);
        assert_eq!(report.unresolved, 0);
        store.shutdown().await.unwrap();
        let mut correlation = None;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.event == "inference_correlation" {
                correlation = Some(event);
            }
            Ok(())
        })
        .unwrap();
        let correlation = correlation.unwrap();
        assert_eq!(correlation.ids.task_id.as_deref(), Some("task-1"));
        assert_eq!(correlation.ids.session_id.as_deref(), Some("session-1"));
        assert_eq!(correlation.ids.inference_id.as_deref(), Some("transport-1"));
        assert_eq!(correlation.confidence, Some(0.9));
    }

    #[tokio::test]
    async fn session_completion_corroborates_a_pre_request_in_the_same_session() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create(
            temporary.path(),
            "session-corroboration",
            CapturePolicy::default(),
        )
        .unwrap();
        let mut hook = store.event("hook:gemini", "BeforeModel");
        hook.ids.task_id = Some("task-1".to_owned());
        hook.ids.session_id = Some("session-1".to_owned());
        store.append(hook).await.unwrap();

        let mut request = store.event("proxy", "logical_inference_request");
        request.ids.inference_id = Some("transport-1".to_owned());
        store.append(request).await.unwrap();

        let mut completion = store.event("session", "session_gemini");
        completion.ids.task_id = Some("task-1".to_owned());
        completion.ids.session_id = Some("session-1".to_owned());
        completion.ids.turn_id = Some("turn-1".to_owned());
        completion.ids.inference_id = Some("native-1".to_owned());
        store.append(completion).await.unwrap();

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 2);
        assert_eq!(report.unresolved, 0);
        assert_eq!(report.unmatched_transports, 0);
        store.shutdown().await.unwrap();

        let mut correlations = Vec::new();
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.event == "inference_correlation" {
                correlations.push(event);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(correlations.len(), 2);
        let corroboration = &correlations[1];
        assert_eq!(
            corroboration.ids.inference_id.as_deref(),
            Some("transport-1")
        );
        assert_eq!(corroboration.ids.parent_id.as_deref(), Some("native-1"));
        assert_eq!(corroboration.confidence, Some(0.9));
        assert_eq!(
            corroboration
                .normalized
                .as_ref()
                .and_then(|value| value.get("method"))
                .and_then(Value::as_str),
            Some("shared_scope_unique_temporal_candidate")
        );
    }

    #[tokio::test]
    async fn session_completion_cannot_reuse_another_sessions_transport() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "cross-session", CapturePolicy::default()).unwrap();
        let mut hook = store.event("hook:gemini", "BeforeModel");
        hook.ids.session_id = Some("session-1".to_owned());
        store.append(hook).await.unwrap();

        let mut request = store.event("proxy", "logical_inference_request");
        request.ids.inference_id = Some("transport-1".to_owned());
        store.append(request).await.unwrap();

        let mut completion = store.event("session", "session_gemini");
        completion.ids.session_id = Some("session-2".to_owned());
        completion.ids.inference_id = Some("native-2".to_owned());
        store.append(completion).await.unwrap();

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 1);
        assert_eq!(report.unresolved, 1);
        assert_eq!(report.unmatched_transports, 0);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exact_provider_session_scope_resolves_an_internal_transport() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create(
            temporary.path(),
            "transport-session-scope",
            CapturePolicy::default(),
        )
        .unwrap();
        let mut lifecycle = store.event("hook:claude", "SessionStart");
        lifecycle.ids.session_id = Some("session-1".to_owned());
        store.append(lifecycle).await.unwrap();

        let mut request = store.event("proxy", "logical_inference_request");
        request.ids.session_id = Some("session-1".to_owned());
        request.ids.inference_id = Some("transport-1".to_owned());
        store.append(request).await.unwrap();

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 1);
        assert_eq!(report.unresolved, 0);
        assert_eq!(report.unmatched_transports, 0);
        store.shutdown().await.unwrap();

        let mut method = None;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.event == "inference_correlation" {
                method = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("method"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(method.as_deref(), Some("exact_transport_session_id"));
    }

    #[tokio::test]
    async fn uncorroborated_transport_session_header_remains_unresolved() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create(
            temporary.path(),
            "uncorroborated-session-scope",
            CapturePolicy::default(),
        )
        .unwrap();
        let mut request = store.event("proxy", "logical_inference_request");
        request.ids.session_id = Some("untrusted-session".to_owned());
        request.ids.inference_id = Some("transport-1".to_owned());
        store.append(request).await.unwrap();

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 0);
        assert_eq!(report.unresolved, 1);
        assert_eq!(report.unmatched_transports, 1);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_candidates_are_reported_as_ambiguous() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "ambiguous", CapturePolicy::default()).unwrap();
        let mut hook = store.event("gemini", "BeforeModel");
        hook.ids.session_id = Some("session-1".to_owned());
        store.append(hook).await.unwrap();
        for id in ["transport-1", "transport-2"] {
            let mut request = store.event("proxy", "logical_inference_request");
            request.ids.inference_id = Some(id.to_owned());
            store.append(request).await.unwrap();
        }
        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 0);
        assert_eq!(report.unmatched_transports, 2);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn groups_identical_transports_only_after_a_retriable_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "retry-chain", CapturePolicy::default()).unwrap();
        let mut hook = store.event("hermes", "pre_api_request");
        hook.ids.session_id = Some("session-1".to_owned());
        hook.ids.inference_id = Some("native-inference".to_owned());
        hook.normalized = Some(json!({"model": "model-1"}));
        store.append(hook).await.unwrap();

        for (index, status) in [500_u16, 200].into_iter().enumerate() {
            let inference = format!("transport-{index}");
            let attempt = format!("attempt-{index}");
            let ids = EventIds {
                inference_id: Some(inference),
                attempt_id: Some(attempt),
                ..EventIds::default()
            };
            let mut request = store.event("proxy", "logical_inference_request");
            request.ids = ids.clone();
            request.normalized = Some(json!({
                "path": "/v1/responses",
                "sha256": "sha256:request",
                "summary": {"model": "model-1"},
            }));
            store.append(request).await.unwrap();
            let mut response = store.event("proxy", "transport_response_started");
            response.ids = ids.clone();
            response.normalized = Some(json!({"status": status}));
            store.append(response).await.unwrap();
            let mut finished = store.event("proxy", "transport_attempt_finished");
            finished.ids = ids;
            finished.terminal_state = Some(crate::model::TerminalState::Complete);
            store.append(finished).await.unwrap();
        }

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 1);
        assert_eq!(report.unresolved, 0);
        store.shutdown().await.unwrap();
        let mut retry_group = None;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.event == "inference_correlation"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("method"))
                    .and_then(Value::as_str)
                    == Some("unique_retry_chain")
            {
                retry_group = Some(event);
            }
            Ok(())
        })
        .unwrap();
        let retry_group = retry_group.unwrap();
        assert_eq!(
            retry_group.ids.inference_id.as_deref(),
            Some("native-inference")
        );
        assert_eq!(
            retry_group
                .normalized
                .as_ref()
                .and_then(|value| value.get("transport_inference_ids"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
    }

    #[tokio::test]
    async fn retry_grouping_survives_response_events_committed_before_request_summary() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "out-of-order", CapturePolicy::default()).unwrap();
        let mut hook = store.event("gemini", "BeforeModel");
        hook.ids.session_id = Some("session".to_owned());
        hook.normalized = Some(json!({"llm_request": {"model": "test-model"}}));
        store.append(hook).await.unwrap();

        for (index, status) in [500_u64, 200].into_iter().enumerate() {
            let ids = EventIds {
                inference_id: Some(format!("transport-{index}")),
                attempt_id: Some(format!("attempt-{index}")),
                ..EventIds::default()
            };
            let mut response = store.event("proxy", "transport_response_started");
            response.ids = ids.clone();
            response.normalized = Some(json!({"status": status}));
            store.append(response).await.unwrap();
            let mut finished = store.event("proxy", "transport_attempt_finished");
            finished.ids = ids.clone();
            finished.terminal_state = Some(crate::model::TerminalState::Complete);
            store.append(finished).await.unwrap();
            let mut request = store.event("proxy", "logical_inference_request");
            request.ids.inference_id = ids.inference_id;
            request.normalized = Some(json!({
                "path": "/v1/responses",
                "sha256": "sha256:same",
                "summary": {"model": "test-model"},
            }));
            store.append(request).await.unwrap();
        }

        let report = derive(&store, temporary.path(), None).await.unwrap();
        assert_eq!(report.resolved, 1);
        assert_eq!(report.unresolved, 0);
        store.shutdown().await.unwrap();
        let mut methods = Vec::new();
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.event == "inference_correlation" {
                methods.push(
                    event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("method"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                );
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(methods, vec![Some("unique_retry_chain".to_owned())]);
    }
}
