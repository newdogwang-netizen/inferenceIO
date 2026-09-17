use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{
    audit,
    blob_keys::read_blob_reference,
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    model::{EventEnvelope, PayloadRef, TerminalState},
    policy::is_secret_header,
    secure_fs::commit_path_noreplace,
    storage::{StorageError, for_each_run_event_with_key},
};

const MAX_ATTEMPTS: usize = 100_000;
const MAX_EVIDENCE_ITEMS_PER_ATTEMPT: usize = 100_000;

#[derive(Debug, Clone, Serialize)]
pub struct ReplayExportReport {
    pub run_id: String,
    pub output: PathBuf,
    pub format: &'static str,
    pub attempts: u64,
    pub request_replayable_attempts: u64,
    pub response_oracle_complete_attempts: u64,
    pub client_replay_complete: bool,
}

#[derive(Debug, Serialize)]
struct ReplayBundle {
    schema_version: u32,
    format: &'static str,
    run_id: String,
    created_at: chrono::DateTime<Utc>,
    manifest_claim: String,
    client_replay_complete: bool,
    credentials_included: bool,
    external_dependencies_verified: bool,
    requirements: Vec<&'static str>,
    limitations: Vec<String>,
    attempts: Vec<ReplayAttempt>,
}

#[derive(Debug, Serialize)]
struct ReplayAttempt {
    ordinal: u64,
    inference_id: Option<String>,
    attempt_id: String,
    logical_task_id: Option<String>,
    task_id: Option<String>,
    session_id: Option<String>,
    turn_id: Option<String>,
    protocol: Option<String>,
    method: Option<String>,
    target: Option<String>,
    headers: Map<String, Value>,
    excluded_header_names: Vec<String>,
    request: ReplayPayload,
    expected_response: ReplayPayload,
    response_status: Option<u16>,
    terminal_state: Option<TerminalState>,
    state_references: BTreeMap<String, String>,
    request_replayable: bool,
    response_oracle_complete: bool,
    limitations: Vec<String>,
    evidence_sequences: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct ReplayPayload {
    file: String,
    bytes: u64,
    sha256: String,
    media_types: Vec<String>,
    complete: bool,
    chunks: u64,
}

#[derive(Default)]
struct AttemptEvidence {
    inference_id: Option<String>,
    attempt_id: String,
    logical_task_id: Option<String>,
    task_id: Option<String>,
    session_id: Option<String>,
    turn_id: Option<String>,
    protocol: Option<String>,
    method: Option<String>,
    target: Option<String>,
    headers: Map<String, Value>,
    excluded_header_names: Vec<String>,
    request_chunks: Vec<ChunkEvidence>,
    response_chunks: Vec<ChunkEvidence>,
    request_terminal: Option<TerminalState>,
    response_terminal: Option<TerminalState>,
    response_status: Option<u16>,
    state_references: BTreeMap<String, String>,
    evidence_sequences: Vec<u64>,
    first_sequence: u64,
}

struct ChunkEvidence {
    sequence: u64,
    reference: Option<PayloadRef>,
    observed_size: Option<u64>,
    captured_size: Option<u64>,
}

pub fn export_replay_with_key(
    run_dir: &Path,
    output: &Path,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<ReplayExportReport> {
    let run_dir = run_dir.canonicalize()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let output_name = output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("replay export path has no file name"))?;
    let output = parent.join(output_name);
    anyhow::ensure!(
        !output.starts_with(&run_dir),
        "replay export must be outside the source run"
    );
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite existing replay export {}",
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
        "source run must pass event and blob integrity checks before replay export"
    );
    let audit_root = run_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("source run has no parent directory"))?;
    audit::append(
        audit_root,
        "export",
        "intent",
        &inspection.manifest.run_id,
        Some(json!({"format": "replay"})),
    )?;

    let attempts = collect_attempts(&run_dir, &inspection.manifest.run_id, key)?;
    let temporary = parent.join(format!(
        ".iorec-replay-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let prepared = (|| {
        let (bundle, report) = write_bundle(&temporary, &run_dir, key, &inspection, attempts)?;
        write_private_json(&temporary.join("replay.json"), &bundle)?;
        File::open(&temporary)?.sync_all()?;
        Ok::<_, anyhow::Error>((bundle, report))
    })();
    let (_bundle, report) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            return Err(error);
        }
    };
    if let Err(error) = commit_path_noreplace(&parent, &temporary, &output) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error.into());
    }
    File::open(&parent)?.sync_all()?;
    audit::append(
        audit_root,
        "export",
        "complete",
        &inspection.manifest.run_id,
        Some(json!({
            "format": "replay",
            "attempts": report.attempts,
            "client_replay_complete": report.client_replay_complete,
        })),
    )?;

    Ok(ReplayExportReport { output, ..report })
}

fn collect_attempts(
    run_dir: &Path,
    run_id: &str,
    key: Option<&EncryptionKey>,
) -> Result<BTreeMap<String, AttemptEvidence>, StorageError> {
    let mut attempts = BTreeMap::new();
    for_each_run_event_with_key(&run_dir.join("events.jsonl"), run_id, key, |event| {
        if event.source != "proxy" {
            return Ok(());
        }
        let Some(attempt_id) = event.ids.attempt_id.clone() else {
            return Ok(());
        };
        if attempts.len() >= MAX_ATTEMPTS && !attempts.contains_key(&attempt_id) {
            return Err(StorageError::AnalysisLimitExceeded {
                operation: "replay attempt index",
                limit: MAX_ATTEMPTS,
            });
        }
        let attempt = attempts
            .entry(attempt_id.clone())
            .or_insert_with(|| AttemptEvidence {
                attempt_id,
                ..AttemptEvidence::default()
            });
        if attempt.first_sequence == 0 {
            attempt.first_sequence = event.sequence;
        }
        push_bounded(
            &mut attempt.evidence_sequences,
            event.sequence,
            "replay attempt event sequence",
        )?;
        attempt.inference_id = event
            .ids
            .inference_id
            .clone()
            .or_else(|| attempt.inference_id.take());
        attempt.logical_task_id =
            crate::tasks::logical_task_id(&event.ids).or_else(|| attempt.logical_task_id.take());
        attempt.task_id = event.ids.task_id.clone().or_else(|| attempt.task_id.take());
        attempt.session_id = event
            .ids
            .session_id
            .clone()
            .or_else(|| attempt.session_id.take());
        attempt.turn_id = event.ids.turn_id.clone().or_else(|| attempt.turn_id.take());
        update_attempt(attempt, event)?;
        Ok(())
    })?;
    Ok(attempts)
}

fn update_attempt(attempt: &mut AttemptEvidence, event: EventEnvelope) -> Result<(), StorageError> {
    let normalized = event.normalized.as_ref();
    match event.event.as_str() {
        "transport_request_started" => {
            attempt.method = string_field(normalized, "method").or_else(|| attempt.method.take());
            attempt.target = target_field(normalized)
                .or_else(|| string_field(normalized, "uri"))
                .map(|target| sanitize_target(&target))
                .or_else(|| attempt.target.take());
            attempt.protocol =
                string_field(normalized, "protocol").or_else(|| attempt.protocol.take());
            if let Some(headers) = normalized
                .and_then(|value| value.get("headers"))
                .and_then(Value::as_object)
            {
                let (safe, excluded) = replay_headers(headers);
                attempt.headers = safe;
                attempt.excluded_header_names = excluded;
            }
        }
        "logical_inference_request" => {
            if attempt.target.is_none() {
                attempt.target = string_field(normalized, "path");
            }
            for (name, pointer) in [
                ("previous_response_id", "/summary/previous_response_id"),
                ("conversation", "/summary/conversation"),
                ("cached_content", "/summary/cached_content"),
            ] {
                if let Some(value) = normalized
                    .and_then(|value| value.pointer(pointer))
                    .and_then(Value::as_str)
                {
                    attempt
                        .state_references
                        .insert(name.to_owned(), value.to_owned());
                }
            }
        }
        "request_body_chunk" => push_bounded(
            &mut attempt.request_chunks,
            chunk_evidence(&event, normalized),
            "replay request chunk evidence",
        )?,
        "response_body_chunk" => push_bounded(
            &mut attempt.response_chunks,
            chunk_evidence(&event, normalized),
            "replay response chunk evidence",
        )?,
        "request_body_finished" => attempt.request_terminal = event.terminal_state,
        "transport_response_started" => {
            attempt.response_status = status_field(normalized).or(attempt.response_status);
        }
        "transport_attempt_finished" => {
            attempt.response_terminal = event.terminal_state;
            attempt.response_status = status_field(normalized).or(attempt.response_status);
        }
        "websocket_frame" => {
            let chunk = chunk_evidence(&event, normalized);
            match string_field(normalized, "direction").as_deref() {
                Some("client_to_upstream") => push_bounded(
                    &mut attempt.request_chunks,
                    chunk,
                    "replay request WebSocket frame evidence",
                )?,
                Some("upstream_to_client") => push_bounded(
                    &mut attempt.response_chunks,
                    chunk,
                    "replay response WebSocket frame evidence",
                )?,
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

fn push_bounded<T>(
    output: &mut Vec<T>,
    value: T,
    operation: &'static str,
) -> Result<(), StorageError> {
    if output.len() >= MAX_EVIDENCE_ITEMS_PER_ATTEMPT {
        return Err(StorageError::AnalysisLimitExceeded {
            operation,
            limit: MAX_EVIDENCE_ITEMS_PER_ATTEMPT,
        });
    }
    output.push(value);
    Ok(())
}

fn chunk_evidence(event: &EventEnvelope, normalized: Option<&Value>) -> ChunkEvidence {
    ChunkEvidence {
        sequence: event.sequence,
        reference: event.raw.clone(),
        observed_size: normalized
            .and_then(|value| value.get("observed_size"))
            .and_then(Value::as_u64),
        captured_size: normalized
            .and_then(|value| value.get("captured_size"))
            .and_then(Value::as_u64),
    }
}

fn write_bundle(
    target: &Path,
    run_dir: &Path,
    key: Option<&EncryptionKey>,
    inspection: &crate::inspect::Inspection,
    attempts: BTreeMap<String, AttemptEvidence>,
) -> anyhow::Result<(ReplayBundle, ReplayExportReport)> {
    let attempts_dir = target.join("attempts");
    fs::create_dir(&attempts_dir)?;
    fs::set_permissions(&attempts_dir, fs::Permissions::from_mode(0o700))?;
    let mut attempts: Vec<_> = attempts.into_values().collect();
    attempts.sort_by_key(|attempt| attempt.first_sequence);
    let mut output_attempts = Vec::with_capacity(attempts.len());
    let mut request_replayable_attempts = 0_u64;
    let mut response_oracle_complete_attempts = 0_u64;
    for (index, attempt) in attempts.into_iter().enumerate() {
        let ordinal = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        let request_name = format!("{ordinal:06}-request.bin");
        let response_name = format!("{ordinal:06}-response.bin");
        let request = write_payload(
            run_dir,
            key,
            &attempts_dir.join(&request_name),
            format!("attempts/{request_name}"),
            attempt.request_chunks,
            attempt.request_terminal == Some(TerminalState::Complete),
        )?;
        let response = write_payload(
            run_dir,
            key,
            &attempts_dir.join(&response_name),
            format!("attempts/{response_name}"),
            attempt.response_chunks,
            attempt.response_terminal == Some(TerminalState::Complete),
        )?;
        let is_http = attempt.protocol.as_deref() == Some("http/1.1");
        let request_replayable =
            is_http && attempt.method.is_some() && attempt.target.is_some() && request.complete;
        let response_oracle_complete = response.complete && attempt.response_status.is_some();
        let mut limitations = Vec::new();
        if !is_http {
            limitations.push("only HTTP/1.1 attempts are directly replayable".to_owned());
        }
        if attempt.method.is_none() || attempt.target.is_none() {
            limitations.push("request method or target is missing".to_owned());
        }
        if !request.complete {
            limitations.push("captured request bytes are incomplete".to_owned());
        }
        if !response_oracle_complete {
            limitations.push("expected response bytes or status are incomplete".to_owned());
        }
        if !attempt.state_references.is_empty() {
            limitations.push(
                "request references provider-side state that this bundle does not recreate"
                    .to_owned(),
            );
        }
        request_replayable_attempts =
            request_replayable_attempts.saturating_add(u64::from(request_replayable));
        response_oracle_complete_attempts =
            response_oracle_complete_attempts.saturating_add(u64::from(response_oracle_complete));
        output_attempts.push(ReplayAttempt {
            ordinal,
            inference_id: attempt.inference_id,
            attempt_id: attempt.attempt_id,
            logical_task_id: attempt.logical_task_id,
            task_id: attempt.task_id,
            session_id: attempt.session_id,
            turn_id: attempt.turn_id,
            protocol: attempt.protocol,
            method: attempt.method,
            target: attempt.target,
            headers: attempt.headers,
            excluded_header_names: attempt.excluded_header_names,
            request,
            expected_response: response,
            response_status: attempt.response_status,
            terminal_state: attempt.response_terminal,
            state_references: attempt.state_references,
            request_replayable,
            response_oracle_complete,
            limitations,
            evidence_sequences: attempt.evidence_sequences,
        });
    }
    File::open(&attempts_dir)?.sync_all()?;

    let attempt_count = u64::try_from(output_attempts.len()).unwrap_or(u64::MAX);
    let client_replay_complete = attempt_count > 0
        && request_replayable_attempts == attempt_count
        && response_oracle_complete_attempts == attempt_count
        && inspection.manifest.coverage.capture_drops == 0
        && inspection.manifest.coverage.unresolved_state_references == 0
        && inspection.manifest.coverage.unresolved_payload_references == 0
        && output_attempts
            .iter()
            .all(|attempt| attempt.state_references.is_empty());
    let mut limitations = vec![
        "provider credentials are deliberately excluded and must be injected at replay time"
            .to_owned(),
        "model generation is not made deterministic; complete responses are comparison oracles"
            .to_owned(),
        "external resources referenced by URL are not independently snapshotted".to_owned(),
    ];
    if inspection.manifest.coverage.capture_drops > 0 {
        limitations.push(format!(
            "the source run reports {} capture drops",
            inspection.manifest.coverage.capture_drops
        ));
    }
    if inspection.manifest.coverage.unresolved_state_references > 0 {
        limitations.push(format!(
            "the source run reports {} unresolved state references",
            inspection.manifest.coverage.unresolved_state_references
        ));
    }
    if inspection.manifest.coverage.unresolved_payload_references > 0 {
        limitations.push(format!(
            "the source run reports {} unresolved external payload references",
            inspection.manifest.coverage.unresolved_payload_references
        ));
    }
    let bundle = ReplayBundle {
        schema_version: 1,
        format: "iorec-replay-bundle-v1",
        run_id: inspection.manifest.run_id.clone(),
        created_at: Utc::now(),
        manifest_claim: inspection.manifest.coverage.claim.clone(),
        client_replay_complete,
        credentials_included: false,
        external_dependencies_verified: false,
        requirements: vec![
            "inject provider credentials outside the bundle",
            "review the target host before sending captured content",
            "treat expected responses as byte comparison oracles, not deterministic outputs",
        ],
        limitations,
        attempts: output_attempts,
    };
    let report = ReplayExportReport {
        run_id: inspection.manifest.run_id.clone(),
        output: PathBuf::new(),
        format: "iorec-replay-bundle-v1",
        attempts: attempt_count,
        request_replayable_attempts,
        response_oracle_complete_attempts,
        client_replay_complete,
    };
    Ok((bundle, report))
}

fn write_payload(
    run_dir: &Path,
    key: Option<&EncryptionKey>,
    output: &Path,
    relative_file: String,
    mut chunks: Vec<ChunkEvidence>,
    terminal_complete: bool,
) -> anyhow::Result<ReplayPayload> {
    chunks.sort_by_key(|chunk| chunk.sequence);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output)?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut complete = terminal_complete;
    let mut media_types = Vec::new();
    for chunk in &chunks {
        let observed = chunk.observed_size;
        let captured = chunk.captured_size;
        let chunk_complete = matches!((observed, captured), (Some(observed), Some(captured)) if observed == captured)
            && if captured == Some(0) {
                chunk.reference.is_none()
            } else {
                chunk.reference.as_ref().is_some_and(|reference| {
                    !reference.truncated && Some(reference.size) == captured
                })
            };
        complete &= chunk_complete;
        let Some(reference) = chunk.reference.as_ref() else {
            continue;
        };
        if let Some(media_type) = &reference.media_type
            && !media_types.contains(media_type)
        {
            media_types.push(media_type.clone());
        }
        let plaintext = load_blob(run_dir, reference, key)?;
        file.write_all(&plaintext)?;
        digest.update(&plaintext);
        bytes = bytes.saturating_add(u64::try_from(plaintext.len()).unwrap_or(u64::MAX));
    }
    file.sync_all()?;
    Ok(ReplayPayload {
        file: relative_file,
        bytes,
        sha256: format!("sha256:{}", hex::encode(digest.finalize())),
        media_types,
        complete,
        chunks: u64::try_from(chunks.len()).unwrap_or(u64::MAX),
    })
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

fn replay_headers(headers: &Map<String, Value>) -> (Map<String, Value>, Vec<String>) {
    let mut safe = Map::new();
    let mut excluded = Vec::new();
    let connection_nominated: std::collections::BTreeSet<String> = headers
        .get("connection")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    for (name, value) in headers {
        let lowercase = name.to_ascii_lowercase();
        if is_sensitive_header(&lowercase)
            || header_value_is_redacted(value)
            || connection_nominated.contains(&lowercase)
            || matches!(
                lowercase.as_str(),
                "connection"
                    | "content-length"
                    | "host"
                    | "keep-alive"
                    | "proxy-connection"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
            )
        {
            excluded.push(lowercase);
        } else {
            safe.insert(lowercase, value.clone());
        }
    }
    excluded.sort();
    excluded.dedup();
    (safe, excluded)
}

fn header_value_is_redacted(value: &Value) -> bool {
    value.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| value.as_str() == Some("[REDACTED]"))
    })
}

fn is_sensitive_header(name: &str) -> bool {
    is_secret_header(name)
}

fn sanitize_target(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "invalid-target".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn string_field(value: Option<&Value>, field: &str) -> Option<String> {
    value?.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn target_field(value: Option<&Value>) -> Option<String> {
    let upstream = value?.get("upstream")?;
    if let Some(target) = upstream.as_str() {
        return Some(target.to_owned());
    }
    let upstream = upstream.as_object()?;
    let scheme = upstream.get("scheme")?.as_str()?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let host = upstream.get("host")?.as_str()?;
    if host.is_empty() || host.chars().any(char::is_control) {
        return None;
    }
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let port = upstream.get("port").and_then(Value::as_u64);
    let authority = port.map_or(authority_host.clone(), |port| {
        format!("{authority_host}:{port}")
    });
    let mut target = Url::parse(&format!("{scheme}://{authority}")).ok()?;
    target.set_path(upstream.get("path").and_then(Value::as_str).unwrap_or("/"));
    Some(target.to_string())
}

fn status_field(value: Option<&Value>) -> Option<u16> {
    value?
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
}

fn write_private_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
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
    fn exact_replay_rejects_unbounded_per_attempt_evidence() {
        let mut evidence = vec![(); MAX_EVIDENCE_ITEMS_PER_ATTEMPT];
        assert!(matches!(
            push_bounded(&mut evidence, (), "test replay evidence"),
            Err(StorageError::AnalysisLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn exports_exact_replay_payloads_without_credentials() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run");
        let mut manifest = Manifest::new(
            "replay-run".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
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
        );
        manifest.status = "finished".to_owned();
        manifest.finished_at = Some(Utc::now());
        manifest.exit_code = Some(0);
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, "replay-run", CapturePolicy::default()).unwrap();
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
            "uri": "/v1/responses?secret=removed",
            "upstream": "https://user:secret@example.test/v1/responses?secret=removed",
            "protocol": "http/1.1",
            "headers": {
                "authorization": ["[REDACTED]"],
                "content-type": ["application/json"],
                "x-request-id": ["safe"]
            }
        }));
        store.append(started).await.unwrap();
        let request_bytes = br#"{"model":"test","input":"hello"}"#;
        let request_ref = store
            .store_blob(request_bytes, Some("application/json"))
            .await
            .unwrap();
        let mut request = store.event("proxy", "request_body_chunk");
        request.ids = ids.clone();
        request.raw = Some(request_ref);
        request.normalized = Some(json!({
            "observed_size": request_bytes.len(),
            "captured_size": request_bytes.len(),
        }));
        store.append(request).await.unwrap();
        let mut request_done = store.event("proxy", "request_body_finished");
        request_done.ids = ids.clone();
        request_done.terminal_state = Some(TerminalState::Complete);
        store.append(request_done).await.unwrap();
        let mut response_started = store.event("proxy", "transport_response_started");
        response_started.ids = ids.clone();
        response_started.normalized = Some(json!({"status": 200}));
        store.append(response_started).await.unwrap();
        let response_bytes = br#"{"output":"world"}"#;
        let response_ref = store
            .store_blob(response_bytes, Some("application/json"))
            .await
            .unwrap();
        let mut response = store.event("proxy", "response_body_chunk");
        response.ids = ids.clone();
        response.raw = Some(response_ref);
        response.normalized = Some(json!({
            "observed_size": response_bytes.len(),
            "captured_size": response_bytes.len(),
        }));
        store.append(response).await.unwrap();
        let mut finished = store.event("proxy", "transport_attempt_finished");
        finished.ids = ids;
        finished.terminal_state = Some(TerminalState::Complete);
        finished.normalized = Some(json!({"status": 200}));
        store.append(finished).await.unwrap();
        let mut spoofed = store.event("hook:test", "transport_request_started");
        spoofed.ids.attempt_id = Some("spoofed-attempt".to_owned());
        spoofed.ids.inference_id = Some("spoofed-inference".to_owned());
        store.append(spoofed).await.unwrap();
        store.shutdown().await.unwrap();

        let output = temporary.path().join("replay");
        let report = export_replay_with_key(&run, &output, None).unwrap();
        assert!(report.client_replay_complete);
        assert_eq!(report.attempts, 1);
        assert_eq!(
            fs::read(output.join("attempts/000001-request.bin")).unwrap(),
            request_bytes
        );
        assert_eq!(
            fs::read(output.join("attempts/000001-response.bin")).unwrap(),
            response_bytes
        );
        let replay: Value =
            serde_json::from_slice(&fs::read(output.join("replay.json")).unwrap()).unwrap();
        assert_eq!(
            replay.pointer("/attempts/0/target").and_then(Value::as_str),
            Some("https://example.test/v1/responses")
        );
        assert!(
            replay
                .pointer("/attempts/0/headers/authorization")
                .is_none()
        );
        assert_eq!(
            replay.pointer("/attempts/0/headers/x-request-id/0"),
            Some(&json!("safe"))
        );
        assert_eq!(
            replay.pointer("/attempts/0/logical_task_id"),
            Some(&json!("task:task-1"))
        );
        assert_eq!(
            replay.pointer("/attempts/0/task_id"),
            Some(&json!("task-1"))
        );
        assert!(!serde_json::to_string(&replay).unwrap().contains("secret"));
        assert!(export_replay_with_key(&run, &output, None).is_err());
    }

    #[test]
    fn replay_headers_remove_credentials_and_connection_nominated_fields() {
        let headers = serde_json::from_value::<Map<String, Value>>(json!({
            "connection": ["keep-alive, x-hop"],
            "x-hop": ["not-end-to-end"],
            "x-amz-security-token": ["[REDACTED]"],
            "x-custom-secret": ["[REDACTED]"],
            "x-request-id": ["safe"],
        }))
        .unwrap();
        let (safe, excluded) = replay_headers(&headers);
        assert_eq!(safe.get("x-request-id"), Some(&json!(["safe"])));
        assert!(!safe.contains_key("x-hop"));
        assert!(!safe.contains_key("x-amz-security-token"));
        assert!(!safe.contains_key("x-custom-secret"));
        assert!(excluded.contains(&"x-hop".to_owned()));
        assert_eq!(sanitize_target("not a URL?token=secret"), "invalid-target");
    }
}
