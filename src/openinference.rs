use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    audit,
    blob_keys::read_blob_reference,
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    model::{EventEnvelope, PayloadRef, TerminalState},
    secure_fs::commit_path_noreplace,
    storage::{StorageError, for_each_run_event_with_key},
};

const MAX_ATTRIBUTE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 100_000;
const MAX_EVIDENCE_SEQUENCES: usize = 100_000;
const MAX_PAYLOAD_CHUNKS: usize = 100_000;

#[derive(Debug, Clone, Serialize)]
pub struct OpenInferenceExportReport {
    pub run_id: String,
    pub output: PathBuf,
    pub format: &'static str,
    pub spans: u64,
    pub attempts: u64,
    pub payloads_omitted: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct SpanRecord {
    pub(crate) schema_version: u32,
    pub(crate) format: &'static str,
    pub(crate) trace_id: String,
    pub(crate) span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parent_span_id: Option<String>,
    pub(crate) name: String,
    pub(crate) start_time: DateTime<Utc>,
    pub(crate) end_time: DateTime<Utc>,
    pub(crate) status: SpanStatus,
    pub(crate) attributes: Map<String, Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SpanStatus {
    pub(crate) code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

#[derive(Debug)]
pub(crate) struct BuiltSpans {
    pub(crate) spans: Vec<SpanRecord>,
    pub(crate) attempts: u64,
    pub(crate) payloads_omitted: u64,
}

#[derive(Default)]
struct Invocation {
    inference_id: String,
    attempt_id: String,
    task_id: Option<String>,
    logical_task_id: Option<String>,
    session_id: Option<String>,
    turn_id: Option<String>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    method: Option<String>,
    path: Option<String>,
    upstream: Option<String>,
    model: Option<String>,
    status: Option<u16>,
    terminal_state: Option<TerminalState>,
    request_payload: PayloadEvidence,
    response_payload: PayloadEvidence,
    input_tokens: u64,
    output_tokens: u64,
    event_sequences: Vec<u64>,
    event_sequence_count: u64,
    event_sequences_truncated: bool,
}

#[derive(Default)]
struct PayloadEvidence {
    chunks: Vec<PayloadRef>,
    captured_bytes: u64,
    omitted: bool,
}

impl PayloadEvidence {
    fn push(&mut self, reference: PayloadRef) {
        self.captured_bytes = self.captured_bytes.saturating_add(reference.size);
        if self.omitted {
            return;
        }
        if reference.truncated
            || self.captured_bytes > MAX_ATTRIBUTE_BYTES
            || self.chunks.len() >= MAX_PAYLOAD_CHUNKS
        {
            self.chunks.clear();
            self.omitted = true;
        } else {
            self.chunks.push(reference);
        }
    }
}

#[derive(Default)]
struct Correlation {
    canonical: String,
    task_id: Option<String>,
    logical_task_id: Option<String>,
    session_id: Option<String>,
    turn_id: Option<String>,
}

type Invocations = BTreeMap<String, Invocation>;
type Correlations = BTreeMap<String, Correlation>;

pub fn export_openinference_with_key(
    run_dir: &Path,
    output: &Path,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<OpenInferenceExportReport> {
    let run_dir = run_dir.canonicalize()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let name = output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("OpenInference export path has no file name"))?;
    let output = parent.join(name);
    anyhow::ensure!(
        !output.starts_with(&run_dir),
        "OpenInference export must be outside the source run"
    );
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite existing OpenInference export {}",
        output.display()
    );

    let inspection = inspect_run_with_key(&run_dir, true, key)?;
    let key = inspection.manifest.effective_encryption_key(key)?;
    let key = key.as_ref();
    anyhow::ensure!(
        inspection.manifest.status != "running",
        "refusing to export a run that is still being recorded"
    );
    anyhow::ensure!(
        inspection.log.discarded_tail_bytes == 0
            && inspection.missing_blobs.is_empty()
            && inspection.corrupt_blobs.is_empty(),
        "source run must pass event and blob integrity checks before export"
    );
    let audit_root = run_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("source run has no parent directory"))?;
    audit::append(
        audit_root,
        "export",
        "intent",
        &inspection.manifest.run_id,
        Some(json!({"format": "openinference"})),
    )?;

    let built = build_spans(&run_dir, key, &inspection)?;
    let temporary = parent.join(format!(
        ".iorec-openinference-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let mut writer = BufWriter::new(file);
    for span in &built.spans {
        write_json_line(&mut writer, span)?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    if let Err(error) = commit_path_noreplace(&parent, &temporary, &output) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    File::open(&parent)?.sync_all()?;
    audit::append(
        audit_root,
        "export",
        "complete",
        &inspection.manifest.run_id,
        Some(json!({"format": "openinference"})),
    )?;

    Ok(OpenInferenceExportReport {
        run_id: inspection.manifest.run_id,
        output,
        format: "iorec-openinference-jsonl-v1",
        spans: u64::try_from(built.spans.len()).unwrap_or(u64::MAX),
        attempts: built.attempts,
        payloads_omitted: built.payloads_omitted,
    })
}

pub(crate) fn build_spans(
    run_dir: &Path,
    key: Option<&EncryptionKey>,
    inspection: &crate::inspect::Inspection,
) -> anyhow::Result<BuiltSpans> {
    let (attempts, correlations) = collect_attempts(run_dir, &inspection.manifest.run_id, key)?;
    let mut spans = Vec::new();
    spans.try_reserve(attempts.len().saturating_add(1))?;
    let trace_id = stable_hex(&inspection.manifest.run_id, 16);
    let root_span_id = stable_hex(&format!("{}:agent", inspection.manifest.run_id), 8);
    spans.push(root_span(inspection, &trace_id, &root_span_id));
    let mut payloads_omitted = 0_u64;
    for attempt in attempts.values() {
        let correlation = correlations.get(&attempt.inference_id);
        let (span, omitted) =
            attempt_span(run_dir, key, &trace_id, &root_span_id, attempt, correlation)?;
        payloads_omitted = payloads_omitted.saturating_add(omitted);
        spans.push(span);
    }
    Ok(BuiltSpans {
        spans,
        attempts: u64::try_from(attempts.len()).unwrap_or(u64::MAX),
        payloads_omitted,
    })
}

fn collect_attempts(
    run_dir: &Path,
    run_id: &str,
    key: Option<&EncryptionKey>,
) -> Result<(Invocations, Correlations), StorageError> {
    let mut attempts = BTreeMap::new();
    let mut correlations = BTreeMap::new();
    for_each_run_event_with_key(&run_dir.join("events.jsonl"), run_id, key, |event| {
        update_correlation(&event, &mut correlations)?;
        if event.source != "proxy" {
            return Ok(());
        }
        let Some(attempt_id) = event.ids.attempt_id.clone() else {
            return Ok(());
        };
        if attempts.len() >= MAX_ATTEMPTS && !attempts.contains_key(&attempt_id) {
            return Err(StorageError::AnalysisLimitExceeded {
                operation: "OpenInference attempt index",
                limit: MAX_ATTEMPTS,
            });
        }
        let inference_id = event.ids.inference_id.clone().unwrap_or_default();
        let attempt = attempts
            .entry(attempt_id.clone())
            .or_insert_with(|| Invocation {
                inference_id,
                attempt_id,
                ..Invocation::default()
            });
        attempt.first_seen.get_or_insert(event.wall_time);
        attempt.last_seen = Some(event.wall_time);
        attempt.event_sequence_count = attempt.event_sequence_count.saturating_add(1);
        if attempt.event_sequences.len() < MAX_EVIDENCE_SEQUENCES {
            attempt.event_sequences.push(event.sequence);
        } else {
            attempt.event_sequences_truncated = true;
        }
        attempt.task_id = event.ids.task_id.clone().or_else(|| attempt.task_id.take());
        attempt.logical_task_id =
            crate::tasks::logical_task_id(&event.ids).or_else(|| attempt.logical_task_id.take());
        attempt.session_id = event
            .ids
            .session_id
            .clone()
            .or_else(|| attempt.session_id.take());
        attempt.turn_id = event.ids.turn_id.clone().or_else(|| attempt.turn_id.take());
        update_attempt(attempt, &event);
        Ok(())
    })?;
    Ok((attempts, correlations))
}

fn update_correlation(
    event: &EventEnvelope,
    correlations: &mut BTreeMap<String, Correlation>,
) -> Result<(), StorageError> {
    if event.source != "correlation" || event.event != "inference_correlation" {
        return Ok(());
    }
    let canonical = event.ids.inference_id.clone().unwrap_or_default();
    let members = event
        .normalized
        .as_ref()
        .and_then(|value| value.get("transport_inference_ids"))
        .and_then(Value::as_array);
    let mut insert = |member: &str| -> Result<(), StorageError> {
        if correlations.len() >= MAX_ATTEMPTS && !correlations.contains_key(member) {
            return Err(StorageError::AnalysisLimitExceeded {
                operation: "OpenInference correlation index",
                limit: MAX_ATTEMPTS,
            });
        }
        correlations.insert(
            member.to_owned(),
            Correlation {
                canonical: canonical.clone(),
                task_id: event.ids.task_id.clone(),
                logical_task_id: crate::tasks::logical_task_id(&event.ids),
                session_id: event.ids.session_id.clone(),
                turn_id: event.ids.turn_id.clone(),
            },
        );
        Ok(())
    };
    if let Some(members) = members {
        for member in members.iter().filter_map(Value::as_str) {
            insert(member)?;
        }
    } else {
        insert(&canonical)?;
    }
    Ok(())
}

fn update_attempt(attempt: &mut Invocation, event: &EventEnvelope) {
    let normalized = event.normalized.as_ref();
    match event.event.as_str() {
        "transport_request_started" => {
            attempt.start.get_or_insert(event.wall_time);
            attempt.method = string_field(normalized, "method").or_else(|| attempt.method.take());
            attempt.path = string_field(normalized, "uri").or_else(|| attempt.path.take());
            attempt.upstream =
                string_field(normalized, "upstream").or_else(|| attempt.upstream.take());
        }
        "logical_inference_request" => {
            attempt.model = normalized
                .and_then(|value| value.pointer("/summary/model"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| attempt.model.take());
            attempt.path = string_field(normalized, "path").or_else(|| attempt.path.take());
        }
        "request_body_chunk" => {
            if let Some(reference) = event.raw.clone() {
                attempt.request_payload.push(reference);
            }
        }
        "response_body_chunk" => {
            if let Some(reference) = event.raw.clone() {
                attempt.response_payload.push(reference);
            }
        }
        "websocket_frame" => {
            if let Some(reference) = event.raw.clone() {
                match string_field(normalized, "direction").as_deref() {
                    Some("client_to_upstream") => attempt.request_payload.push(reference),
                    Some("upstream_to_client") => attempt.response_payload.push(reference),
                    _ => {}
                }
            }
        }
        "transport_response_started" => {
            attempt.status = normalized
                .and_then(|value| value.get("status"))
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok());
        }
        "sse_event" => {
            attempt.input_tokens = attempt
                .input_tokens
                .saturating_add(token_field(normalized, "/semantic/input_tokens"));
            attempt.output_tokens = attempt
                .output_tokens
                .saturating_add(token_field(normalized, "/semantic/output_tokens"));
        }
        "transport_attempt_finished" => {
            attempt.end = Some(event.wall_time);
            attempt.terminal_state.clone_from(&event.terminal_state);
            attempt.status = normalized
                .and_then(|value| value.get("status"))
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .or(attempt.status);
        }
        _ => {}
    }
}

fn root_span(inspection: &crate::inspect::Inspection, trace_id: &str, span_id: &str) -> SpanRecord {
    let manifest = &inspection.manifest;
    let mut attributes = Map::new();
    attributes.insert("openinference.span.kind".to_owned(), json!("AGENT"));
    attributes.insert("iorec.run_id".to_owned(), json!(manifest.run_id));
    attributes.insert(
        "iorec.coverage.claim".to_owned(),
        json!(manifest.coverage.claim),
    );
    attributes.insert(
        "metadata".to_owned(),
        json!(
            json!({
                "iorec.capture_sources": manifest.coverage.capture_sources,
                "iorec.known_gaps": manifest.coverage.known_gaps,
            })
            .to_string()
        ),
    );
    SpanRecord {
        schema_version: 1,
        format: "iorec-openinference-jsonl-v1",
        trace_id: trace_id.to_owned(),
        span_id: span_id.to_owned(),
        parent_span_id: None,
        name: manifest
            .command
            .agent
            .clone()
            .unwrap_or_else(|| "iorec agent run".to_owned()),
        start_time: manifest.started_at,
        end_time: manifest.finished_at.unwrap_or(manifest.started_at),
        status: SpanStatus {
            code: if manifest.exit_code == Some(0) {
                "OK"
            } else {
                "ERROR"
            },
            message: (manifest.exit_code != Some(0))
                .then(|| format!("target exit code {:?}", manifest.exit_code)),
        },
        attributes,
    }
}

fn attempt_span(
    run_dir: &Path,
    key: Option<&EncryptionKey>,
    trace_id: &str,
    parent_span_id: &str,
    attempt: &Invocation,
    correlation: Option<&Correlation>,
) -> anyhow::Result<(SpanRecord, u64)> {
    let mut attributes = Map::new();
    attributes.insert("openinference.span.kind".to_owned(), json!("LLM"));
    let (system, inferred) = infer_llm_system(attempt.path.as_deref(), attempt.upstream.as_deref());
    attributes.insert("llm.system".to_owned(), json!(system));
    attributes.insert("iorec.llm_system_inferred".to_owned(), json!(inferred));
    attributes.insert("iorec.attempt_id".to_owned(), json!(attempt.attempt_id));
    let logical_id = correlation.map_or(attempt.inference_id.as_str(), |value| {
        value.canonical.as_str()
    });
    attributes.insert("iorec.logical_inference_id".to_owned(), json!(logical_id));
    if let Some(task_id) = correlation
        .and_then(|value| value.task_id.as_deref())
        .or(attempt.task_id.as_deref())
    {
        attributes.insert("iorec.task_id".to_owned(), json!(task_id));
    }
    if let Some(logical_task_id) = correlation
        .and_then(|value| value.logical_task_id.as_deref())
        .or(attempt.logical_task_id.as_deref())
    {
        attributes.insert("iorec.logical_task_id".to_owned(), json!(logical_task_id));
    }
    if let Some(session_id) = correlation
        .and_then(|value| value.session_id.as_deref())
        .or(attempt.session_id.as_deref())
    {
        attributes.insert("session.id".to_owned(), json!(session_id));
    }
    if let Some(turn_id) = correlation
        .and_then(|value| value.turn_id.as_deref())
        .or(attempt.turn_id.as_deref())
    {
        attributes.insert("iorec.turn_id".to_owned(), json!(turn_id));
    }
    if let Some(model) = &attempt.model {
        attributes.insert("llm.model_name".to_owned(), json!(model));
    }
    if attempt.input_tokens > 0 {
        attributes.insert(
            "llm.token_count.prompt".to_owned(),
            json!(attempt.input_tokens),
        );
    }
    if attempt.output_tokens > 0 {
        attributes.insert(
            "llm.token_count.completion".to_owned(),
            json!(attempt.output_tokens),
        );
    }
    if let Some(method) = &attempt.method {
        attributes.insert("http.request.method".to_owned(), json!(method));
    }
    if let Some(path) = &attempt.path {
        attributes.insert("url.path".to_owned(), json!(path));
    }
    if let Some(status) = attempt.status {
        attributes.insert("http.response.status_code".to_owned(), json!(status));
    }
    attributes.insert(
        "iorec.evidence.event_sequences".to_owned(),
        json!(attempt.event_sequences),
    );
    attributes.insert(
        "iorec.evidence.event_sequence_count".to_owned(),
        json!(attempt.event_sequence_count),
    );
    if attempt.event_sequences_truncated {
        attributes.insert(
            "iorec.evidence.event_sequences_truncated".to_owned(),
            json!(true),
        );
    }

    let mut omitted = 0_u64;
    omitted = omitted.saturating_add(insert_payload(
        run_dir,
        key,
        &attempt.request_payload,
        "input",
        &mut attributes,
    )?);
    omitted = omitted.saturating_add(insert_payload(
        run_dir,
        key,
        &attempt.response_payload,
        "output",
        &mut attributes,
    )?);
    let start = attempt
        .start
        .or(attempt.first_seen)
        .or(attempt.end)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let end = attempt.end.or(attempt.last_seen).unwrap_or(start);
    let error = attempt.status.is_some_and(|status| status >= 400)
        || !matches!(attempt.terminal_state, Some(TerminalState::Complete));
    let name = format!(
        "{} {}",
        attempt.method.as_deref().unwrap_or("LLM"),
        attempt.path.as_deref().unwrap_or("inference")
    );
    Ok((
        SpanRecord {
            schema_version: 1,
            format: "iorec-openinference-jsonl-v1",
            trace_id: trace_id.to_owned(),
            span_id: stable_hex(
                &format!("{}:{}", attempt.inference_id, attempt.attempt_id),
                8,
            ),
            parent_span_id: Some(parent_span_id.to_owned()),
            name,
            start_time: start,
            end_time: end.max(start),
            status: SpanStatus {
                code: if error { "ERROR" } else { "OK" },
                message: error.then(|| {
                    format!(
                        "HTTP status {:?}, terminal {:?}",
                        attempt.status, attempt.terminal_state
                    )
                }),
            },
            attributes,
        },
        omitted,
    ))
}

fn insert_payload(
    run_dir: &Path,
    key: Option<&EncryptionKey>,
    payload: &PayloadEvidence,
    prefix: &str,
    attributes: &mut Map<String, Value>,
) -> anyhow::Result<u64> {
    if payload.chunks.is_empty() && !payload.omitted {
        return Ok(0);
    }
    if payload.omitted {
        attributes.insert(format!("iorec.{prefix}.omitted"), json!(true));
        attributes.insert(
            format!("iorec.{prefix}.captured_bytes"),
            json!(payload.captured_bytes),
        );
        return Ok(1);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(payload.captured_bytes).unwrap_or(0));
    for reference in &payload.chunks {
        bytes.extend(load_blob(run_dir, reference, key)?);
    }
    let media_type = payload
        .chunks
        .first()
        .and_then(|reference| reference.media_type.as_deref())
        .unwrap_or("application/octet-stream");
    match String::from_utf8(bytes) {
        Ok(value) => {
            attributes.insert(format!("{prefix}.value"), json!(value));
            attributes.insert(format!("{prefix}.mime_type"), json!(media_type));
        }
        Err(error) => {
            attributes.insert(
                format!("{prefix}.value"),
                json!(STANDARD.encode(error.into_bytes())),
            );
            attributes.insert(
                format!("{prefix}.mime_type"),
                json!("application/octet-stream"),
            );
            attributes.insert(format!("iorec.{prefix}.encoding"), json!("base64"));
        }
    }
    Ok(0)
}

fn load_blob(
    run_dir: &Path,
    reference: &PayloadRef,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<Vec<u8>> {
    read_blob_reference(
        run_dir,
        reference,
        key,
        crate::storage::MAX_SINGLE_BLOB_BYTES,
    )
    .map_err(Into::into)
}

fn infer_llm_system(path: Option<&str>, upstream: Option<&str>) -> (&'static str, bool) {
    let path = path.unwrap_or_default().to_ascii_lowercase();
    let upstream = upstream.unwrap_or_default().to_ascii_lowercase();
    if path.contains("/messages") || upstream.contains("anthropic.com") {
        ("anthropic", true)
    } else if path.contains(":generatecontent")
        || path.contains(":streamgeneratecontent")
        || upstream.contains("googleapis.com")
    {
        ("vertexai", true)
    } else if upstream.contains("openai.com") {
        ("openai", true)
    } else {
        ("unknown", false)
    }
}

fn string_field(value: Option<&Value>, field: &str) -> Option<String> {
    value?.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn token_field(value: Option<&Value>, pointer: &str) -> u64 {
    value
        .and_then(|value| value.pointer(pointer))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn stable_hex(value: &str, bytes: usize) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..bytes])
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        model::EventIds,
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[test]
    fn payload_evidence_drops_references_after_the_attribute_budget() {
        let mut payload = PayloadEvidence::default();
        payload.push(PayloadRef {
            sha256: "sha256:first".to_owned(),
            size: MAX_ATTRIBUTE_BYTES,
            media_type: None,
            truncated: false,
        });
        assert_eq!(payload.chunks.len(), 1);
        assert!(!payload.omitted);

        payload.push(PayloadRef {
            sha256: "sha256:second".to_owned(),
            size: 1,
            media_type: None,
            truncated: false,
        });
        assert!(payload.chunks.is_empty());
        assert!(payload.omitted);
        assert_eq!(payload.captured_bytes, MAX_ATTRIBUTE_BYTES + 1);
    }

    #[tokio::test]
    async fn exports_required_openinference_attributes_and_raw_payloads() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run");
        let mut manifest = Manifest::new(
            "openinference-run".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
                cwd: PathBuf::from("/tmp"),
                executable: None,
                executable_sha256: None,
                agent: Some("test-agent".to_owned()),
                agent_version: None,
                runtime: None,
                executable_tls_surfaces: Vec::new(),
                environment: BTreeMap::new(),
            },
            CapturePolicy::default(),
        );
        manifest.status = "finished".to_owned();
        manifest.exit_code = Some(0);
        manifest.finished_at = Some(Utc::now());
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) =
            RunStore::create(&run, "openinference-run", CapturePolicy::default()).unwrap();
        let ids = EventIds {
            task_id: Some("task-1".to_owned()),
            session_id: Some("session-1".to_owned()),
            inference_id: Some("inference".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            ..EventIds::default()
        };
        let mut started = store.event("proxy", "transport_request_started");
        started.ids = ids.clone();
        started.normalized = Some(json!({
            "method": "POST",
            "uri": "/v1/messages",
            "upstream": "https://api.anthropic.com/v1/messages",
            "traffic_class": "model",
            "protocol": "http/1.1",
        }));
        store.append(started).await.unwrap();
        let mut summary = store.event("proxy", "logical_inference_request");
        summary.ids = ids.clone();
        summary.normalized = Some(json!({
            "path": "/v1/messages",
            "sha256": "sha256:request",
            "summary": {"model": "claude-test"},
        }));
        store.append(summary).await.unwrap();
        let raw = store
            .store_blob(
                br#"{"messages":[{"role":"user","content":"hello"}]}"#,
                Some("application/json"),
            )
            .await
            .unwrap();
        let mut request = store.event("proxy", "request_body_chunk");
        request.ids = ids.clone();
        request.raw = Some(raw);
        store.append(request).await.unwrap();
        let mut request_done = store.event("proxy", "request_body_finished");
        request_done.ids = ids.clone();
        request_done.terminal_state = Some(TerminalState::Complete);
        store.append(request_done).await.unwrap();
        let mut response = store.event("proxy", "transport_response_started");
        response.ids = ids.clone();
        response.normalized = Some(json!({"status": 200}));
        store.append(response).await.unwrap();
        let raw = store
            .store_blob(br#"{"content":"world"}"#, Some("application/json"))
            .await
            .unwrap();
        let mut chunk = store.event("proxy", "response_body_chunk");
        chunk.ids = ids.clone();
        chunk.raw = Some(raw);
        store.append(chunk).await.unwrap();
        let mut done = store.event("proxy", "transport_attempt_finished");
        done.ids = ids;
        done.terminal_state = Some(TerminalState::Complete);
        done.normalized = Some(json!({"status": 200}));
        store.append(done).await.unwrap();
        let mut spoofed = store.event("hook:test", "transport_request_started");
        spoofed.ids.attempt_id = Some("spoofed-attempt".to_owned());
        spoofed.ids.inference_id = Some("spoofed-inference".to_owned());
        store.append(spoofed).await.unwrap();
        store.shutdown().await.unwrap();

        let output = temporary.path().join("spans.jsonl");
        let report = export_openinference_with_key(&run, &output, None).unwrap();
        assert_eq!(report.spans, 2);
        assert_eq!(report.payloads_omitted, 0);
        let lines: Vec<Value> = fs::read_to_string(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            lines[0].pointer("/attributes/openinference.span.kind"),
            Some(&json!("AGENT"))
        );
        assert_eq!(
            lines[1].pointer("/attributes/openinference.span.kind"),
            Some(&json!("LLM"))
        );
        assert_eq!(
            lines[1].pointer("/attributes/llm.system"),
            Some(&json!("anthropic"))
        );
        assert_eq!(
            lines[1].pointer("/attributes/llm.model_name"),
            Some(&json!("claude-test"))
        );
        assert_eq!(
            lines[1].pointer("/attributes/iorec.task_id"),
            Some(&json!("task-1"))
        );
        assert_eq!(
            lines[1].pointer("/attributes/iorec.logical_task_id"),
            Some(&json!("task:task-1"))
        );
        assert!(lines[1].pointer("/attributes/input.value").is_some());
        assert!(export_openinference_with_key(&run, &output, None).is_err());
    }
}
