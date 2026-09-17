use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::warn;
use uuid::Uuid;

use crate::{
    adapter_sdk::{AdapterHost, AdapterHostError, ParseContext},
    input::validate_json_complexity,
    model::{EventIds, TerminalState},
    policy::BodyCaptureMode,
    storage::RunStore,
};

pub const SOCKET_ENV: &str = "IOREC_COLLECTOR_SOCKET";
pub const TOKEN_ENV: &str = "IOREC_COLLECTOR_TOKEN";
const MAX_SUBMISSION_BYTES: u64 = 16 * 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const COLLECTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_CONCURRENT_CONNECTIONS: usize = 8;
const FLUSH_BOUNDARY_OPERATION: &str = "flush_boundary";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSubmission {
    pub token: String,
    pub source: String,
    pub event: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub ids: EventIds,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<TerminalState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalControlRequest {
    control: String,
}

pub struct CollectorHandle {
    pub socket_path: PathBuf,
    pub token: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
    socket_device: u64,
    socket_inode: u64,
}

impl CollectorHandle {
    pub async fn stop(mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = if let Ok(result) =
            tokio::time::timeout(COLLECTOR_SHUTDOWN_TIMEOUT, &mut self.task).await
        {
            result.map_err(|error| io::Error::other(format!("collector task panicked: {error}")))?
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "collector did not drain before shutdown deadline",
            ))
        };
        let cleanup = remove_owned_socket(&self.socket_path, self.socket_device, self.socket_inode);
        task_result?;
        cleanup
    }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

pub fn start(run_dir: &Path, store: RunStore) -> io::Result<CollectorHandle> {
    start_with_adapter(run_dir, store, None)
}

pub fn start_with_adapter(
    run_dir: &Path,
    store: RunStore,
    adapter: Option<Arc<AdapterHost>>,
) -> io::Result<CollectorHandle> {
    let socket_path = run_dir.join("collector.sock");
    match fs::symlink_metadata(&socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&socket_path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "collector path exists and is not a Unix socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(&socket_path)?;
    if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&socket_path);
        return Err(error);
    }
    let socket_metadata = match fs::symlink_metadata(&socket_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = fs::remove_file(&socket_path);
            return Err(error);
        }
    };
    let socket_device = socket_metadata.dev();
    let socket_inode = socket_metadata.ino();
    let owner_uid = fs::metadata(run_dir)?.uid();
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let task_token = token.clone();
    let task_socket = socket_path.clone();
    let permits = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let (shutdown, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        store.note_capture_drop();
                        drop(stream);
                        continue;
                    };
                    let connection_store = store.clone();
                    let connection_token = task_token.clone();
                    let connection_adapter = adapter.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(
                            stream,
                            owner_uid,
                            &connection_token,
                            connection_store,
                            connection_adapter,
                        ).await {
                            warn!(
                                error_kind = ?error.kind(),
                                "hook collector rejected a submission"
                            );
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        warn!(
                            task_cancelled = error.is_cancelled(),
                            task_panicked = error.is_panic(),
                            "hook collector connection task failed"
                        );
                    }
                }
            }
        }
        drop(listener);
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                warn!(
                    task_cancelled = error.is_cancelled(),
                    task_panicked = error.is_panic(),
                    "hook collector connection task failed during drain"
                );
            }
        }
        remove_owned_socket(&task_socket, socket_device, socket_inode)
    });
    Ok(CollectorHandle {
        socket_path,
        token,
        shutdown: Some(shutdown),
        task,
        socket_device,
        socket_inode,
    })
}

fn remove_owned_socket(path: &Path, expected_device: u64, expected_inode: u64) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "collector path no longer identifies the socket created by this run",
        ));
    }
    fs::remove_file(path)
}

async fn handle_connection(
    mut stream: UnixStream,
    owner_uid: u32,
    expected_token: &str,
    store: RunStore,
    adapter: Option<Arc<AdapterHost>>,
) -> io::Result<()> {
    let peer = stream.peer_cred()?;
    if peer.uid() != owner_uid {
        write_response(
            &mut stream,
            &HookResponse {
                accepted: false,
                sequence: None,
                error: Some("peer UID does not own the run".to_owned()),
            },
        )
        .await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "collector peer UID mismatch",
        ));
    }

    let mut bytes = Vec::new();
    let read = tokio::time::timeout(CONNECTION_TIMEOUT, async {
        (&mut stream)
            .take(MAX_SUBMISSION_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "collector read timed out"))??;
    if u64::try_from(read).unwrap_or(u64::MAX) > MAX_SUBMISSION_BYTES {
        store.note_capture_drop();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hook submission exceeds size limit",
        ));
    }
    if let Err(error) = validate_json_complexity(&bytes) {
        store.note_capture_drop();
        return Err(error);
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if value.get("control").is_some() {
        let request: LocalControlRequest = serde_json::from_value(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if request.control != FLUSH_BOUNDARY_OPERATION {
            write_response(
                &mut stream,
                &HookResponse {
                    accepted: false,
                    sequence: None,
                    error: Some("unsupported local control operation".to_owned()),
                },
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported local control operation",
            ));
        }
        let boundary = store.durable_boundary().await.map_err(io::Error::other)?;
        return write_response(
            &mut stream,
            &HookResponse {
                accepted: true,
                sequence: Some(boundary.events),
                error: None,
            },
        )
        .await;
    }
    let submission: HookSubmission = serde_json::from_value(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if submission.token.len() != expected_token.len()
        || !bool::from(submission.token.as_bytes().ct_eq(expected_token.as_bytes()))
    {
        write_response(
            &mut stream,
            &HookResponse {
                accepted: false,
                sequence: None,
                error: Some("invalid collector token".to_owned()),
            },
        )
        .await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid collector token",
        ));
    }

    let parse_context = adapter.as_ref().map(|_| ParseContext {
        run_id: store.run_id().to_owned(),
        source: submission.source.clone(),
        event: submission_event_name(&submission),
        observed_at: Utc::now(),
        payload: submission.payload.clone(),
    });
    match persist_submission(&store, submission).await {
        Ok(sequence) => {
            if let (Some(adapter), Some(context)) = (adapter.as_ref(), parse_context.as_ref()) {
                match adapter.parse(context) {
                    Ok(events) => {
                        if persist_adapter_events(&store, sequence, events)
                            .await
                            .is_err()
                        {
                            store.note_capture_drop();
                            record_adapter_parse_error(&store, adapter, "persist_output").await;
                        }
                    }
                    Err(error) => {
                        store.note_capture_drop();
                        record_adapter_parse_error(&store, adapter, adapter_error_class(&error))
                            .await;
                    }
                }
            }
            write_response(
                &mut stream,
                &HookResponse {
                    accepted: true,
                    sequence: Some(sequence),
                    error: None,
                },
            )
            .await
        }
        Err(error) => {
            store.note_capture_drop();
            write_response(
                &mut stream,
                &HookResponse {
                    accepted: false,
                    sequence: None,
                    error: Some("hook submission rejected".to_owned()),
                },
            )
            .await?;
            Err(io::Error::other(error))
        }
    }
}

async fn persist_submission(
    store: &RunStore,
    mut submission: HookSubmission,
) -> anyhow::Result<u64> {
    validate_label("source", &submission.source)?;
    anyhow::ensure!(
        !is_reserved_source(&submission.source),
        "hook source collides with a recorder-reserved source"
    );
    let source = format!("hook:{}", submission.source);
    let event_name = submission_event_name(&submission);
    validate_label("event", &event_name)?;
    if matches!(
        submission.source.as_str(),
        "python-runtime" | "node-runtime"
    ) && event_name == "runtime_capture_gap"
    {
        let occurrences = submission
            .payload
            .get("occurrences")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, 10_000_000);
        store.note_capture_drops(occurrences);
    }
    for evidence in &submission.evidence {
        validate_label("evidence", evidence)?;
    }
    infer_ids(&submission.payload, &mut submission.ids);
    submission.ids.validate().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        submission.evidence.len() < 256,
        "hook evidence list has too many items"
    );
    if let Some(confidence) = submission.confidence {
        anyhow::ensure!(
            (0.0..=1.0).contains(&confidence),
            "hook confidence must be between zero and one"
        );
    }
    let (sanitized, mut redaction) = store
        .policy()
        .sanitize_json_owned(std::mem::take(&mut submission.payload));
    if !redaction.omitted.is_empty() {
        store.note_capture_drop();
    }
    let capture_body = store.policy().body_mode == BodyCaptureMode::Full;
    let raw = if capture_body {
        let bytes = serde_json::to_vec(&sanitized)?;
        Some(store.store_blob(&bytes, Some("application/json")).await?)
    } else {
        None
    };
    let normalized = if capture_body {
        sanitized
    } else {
        redaction
            .omitted
            .push("hook_payload_omitted_by_policy".to_owned());
        payload_shape_summary(&sanitized)
    };
    let mut event = store.event(source, event_name);
    event.ids = submission.ids;
    event.raw = raw;
    event.normalized = Some(normalized);
    event.redaction = redaction;
    event.confidence = submission.confidence.or(Some(1.0));
    event.evidence = vec!["hook_collector_token".to_owned()];
    event.evidence.extend(
        submission
            .evidence
            .into_iter()
            .map(|evidence| format!("hook_claim:{evidence}")),
    );
    event.terminal_state = submission
        .terminal_state
        .or_else(|| infer_terminal_state(&event.kind));
    store.append(event).await.map_err(Into::into)
}

fn submission_event_name(submission: &HookSubmission) -> String {
    if submission.event == "auto" {
        submission
            .payload
            .get("hook_event_name")
            .or_else(|| submission.payload.get("event_name"))
            .and_then(Value::as_str)
            .unwrap_or("unknown_hook")
            .to_owned()
    } else {
        submission.event.clone()
    }
}

async fn persist_adapter_events(
    store: &RunStore,
    native_sequence: u64,
    events: Vec<crate::model::PendingEvent>,
) -> anyhow::Result<()> {
    for mut event in events {
        let normalized = event
            .normalized
            .take()
            .ok_or_else(|| anyhow::anyhow!("adapter event has no normalized payload"))?;
        let (sanitized, mut redaction) = store.policy().sanitize_json_owned(normalized);
        if !redaction.omitted.is_empty() {
            store.note_capture_drop();
        }
        event.normalized = Some(if store.policy().body_mode == BodyCaptureMode::Full {
            sanitized
        } else {
            redaction
                .omitted
                .push("adapter_payload_omitted_by_policy".to_owned());
            payload_shape_summary(&sanitized)
        });
        event.redaction = redaction;
        event
            .evidence
            .push(format!("native_hook_sequence:{native_sequence}"));
        event.evidence.sort();
        event.evidence.dedup();
        store.append(event).await?;
    }
    Ok(())
}

async fn record_adapter_parse_error(
    store: &RunStore,
    adapter: &AdapterHost,
    error_class: &'static str,
) {
    let mut event = store.event("runner", "adapter_parse_error");
    event.terminal_state = Some(TerminalState::Error);
    event.normalized = Some(serde_json::json!({
        "adapter": adapter.name(),
        "adapter_release": adapter.adapter_release(),
        "error_class": error_class,
        "raw_hook_preserved": true,
    }));
    if store.append(event).await.is_err() {
        store.note_capture_drop();
    }
}

const fn adapter_error_class(error: &AdapterHostError) -> &'static str {
    match error {
        AdapterHostError::InvalidIdentity(_) => "invalid_identity",
        AdapterHostError::IncompatibleVersion { .. } => "incompatible_version",
        AdapterHostError::Adapter { .. } => "adapter_failure",
        AdapterHostError::Panicked(_) => "adapter_panic",
        AdapterHostError::InvalidOutput { .. } => "invalid_output",
        AdapterHostError::InvalidInput { .. } => "invalid_input",
    }
}

fn payload_shape_summary(value: &Value) -> Value {
    let (kind, top_level_items) = match value {
        Value::Null => ("null", 0),
        Value::Bool(_) => ("boolean", 0),
        Value::Number(_) => ("number", 0),
        Value::String(_) => ("string", 0),
        Value::Array(values) => ("array", values.len()),
        Value::Object(values) => ("object", values.len()),
    };
    serde_json::json!({
        "payload_type": kind,
        "top_level_items": top_level_items,
    })
}

fn is_reserved_source(source: &str) -> bool {
    [
        "runner",
        "proxy",
        "process",
        "correlation",
        "session",
        "pcap",
        "tls-keylog",
        "probe-helper",
    ]
    .iter()
    .any(|reserved| source.eq_ignore_ascii_case(reserved))
}

fn infer_ids(payload: &Value, ids: &mut EventIds) {
    let string = |name: &str| payload.get(name).and_then(Value::as_str).map(str::to_owned);
    ids.task_id = ids.task_id.take().or_else(|| string("task_id"));
    ids.session_id = ids.session_id.take().or_else(|| string("session_id"));
    ids.turn_id = ids.turn_id.take().or_else(|| string("turn_id"));
    ids.inference_id = ids.inference_id.take().or_else(|| string("inference_id"));
    ids.attempt_id = ids
        .attempt_id
        .take()
        .or_else(|| string("attempt_id"))
        .or_else(|| string("api_request_id"));
    ids.connection_id = ids.connection_id.take().or_else(|| string("connection_id"));
    ids.parent_id = ids
        .parent_id
        .take()
        .or_else(|| string("parent_id"))
        .or_else(|| string("parent_subagent_id"))
        .or_else(|| string("parent_tool_use_id"));

    if ids.inference_id.is_none()
        && let (Some(session), Some(turn), Some(call)) = (
            ids.session_id.as_deref(),
            ids.turn_id.as_deref(),
            payload.get("api_call_count").and_then(Value::as_u64),
        )
    {
        ids.inference_id = Some(format!("{session}:{turn}:{call}"));
    }
}

fn infer_terminal_state(event: &str) -> Option<TerminalState> {
    let lowercase = event.to_ascii_lowercase();
    if lowercase.contains("error") || lowercase.contains("failure") || lowercase.contains("failed")
    {
        Some(TerminalState::Error)
    } else if lowercase.starts_with("post_")
        || lowercase.starts_with("after")
        || lowercase.ends_with("_end")
        || lowercase.ends_with("_stop")
    {
        Some(TerminalState::Complete)
    } else {
        None
    }
}

fn validate_label(name: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 128,
        "invalid {name} length"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')),
        "invalid characters in {name}"
    );
    Ok(())
}

async fn write_response(stream: &mut UnixStream, response: &HookResponse) -> io::Result<()> {
    let bytes = serde_json::to_vec(response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await
}

pub async fn submit(socket: &Path, submission: &HookSubmission) -> io::Result<HookResponse> {
    let bytes = serde_json::to_vec(submission)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SUBMISSION_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hook submission exceeds size limit",
        ));
    }
    validate_json_complexity(&bytes)?;
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    (&mut stream)
        .take(64 * 1024)
        .read_to_end(&mut response)
        .await?;
    serde_json::from_slice(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Requests an exact, synced event prefix from the active run writer. Access
/// is restricted by the mode-0600 Unix socket and the existing same-UID peer
/// credential check; no recorder token is persisted for daemon use.
pub async fn request_flush_boundary(socket: &Path) -> io::Result<u64> {
    let request = LocalControlRequest {
        control: FLUSH_BOUNDARY_OPERATION.to_owned(),
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    (&mut stream)
        .take(64 * 1024)
        .read_to_end(&mut response)
        .await?;
    let response: HookResponse = serde_json::from_slice(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !response.accepted {
        return Err(io::Error::other(response.error.unwrap_or_else(|| {
            "flush boundary request was rejected".to_owned()
        })));
    }
    response
        .sequence
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "flush response has no boundary"))
}

pub async fn submit_from_environment(
    source: String,
    event: String,
    payload: Value,
) -> io::Result<()> {
    let socket = std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{SOCKET_ENV} is unset")))?;
    let token = std::env::var(TOKEN_ENV)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("{TOKEN_ENV} is unset")))?;
    let response = submit(
        &socket,
        &HookSubmission {
            token,
            source,
            event,
            payload,
            ids: EventIds::default(),
            confidence: None,
            evidence: Vec::new(),
            terminal_state: None,
        },
    )
    .await?;
    if response.accepted {
        Ok(())
    } else {
        Err(io::Error::other(
            response
                .error
                .unwrap_or_else(|| "submission rejected".to_owned()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter_sdk::{
            ADAPTER_SDK_VERSION, AdapterConfiguration, AdapterResult, AdapterSdk, ConfigureContext,
            CorrelateContext, Correlation, DetectContext, Detection, ParsedEvent,
        },
        policy::CapturePolicy,
        storage::for_each_event,
    };
    use serde_json::json;

    struct ParsingAdapter {
        panic_on_parse: bool,
    }

    impl AdapterSdk for ParsingAdapter {
        fn detect(&self, _context: &DetectContext) -> AdapterResult<Detection> {
            Ok(Detection::matched(1.0, "fixture"))
        }

        fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
            Ok(AdapterConfiguration::default())
        }

        fn parse(&self, context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
            assert!(!self.panic_on_parse, "adversarial parser panic");
            let mut event = ParsedEvent::new(
                "BeforeModel",
                json!({
                    "model": context.payload.get("model"),
                    "authorization": "adapter-secret",
                }),
            );
            event.evidence.push("fixture.native.v1".to_owned());
            Ok(vec![event])
        }

        fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
            Ok(Correlation::unresolved("not used by collector"))
        }
    }

    fn parsing_host(panic_on_parse: bool) -> Arc<AdapterHost> {
        Arc::new(
            AdapterHost::new(
                "fixture",
                "1.0.0",
                ADAPTER_SDK_VERSION,
                ParsingAdapter { panic_on_parse },
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn start_refuses_to_remove_a_non_socket_collision() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collision = temporary.path().join("collector.sock");
        fs::write(&collision, b"preserve-me").unwrap();

        let Err(error) = start(temporary.path(), store.clone()) else {
            panic!("collector unexpectedly replaced a non-socket path");
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&collision).unwrap(), b"preserve-me");
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn tokenless_same_uid_flush_returns_the_exact_durable_prefix() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        store.append(store.event("runner", "first")).await.unwrap();
        assert_eq!(
            request_flush_boundary(&collector.socket_path)
                .await
                .unwrap(),
            1
        );
        store.append(store.event("runner", "second")).await.unwrap();
        assert_eq!(
            request_flush_boundary(&collector.socket_path)
                .await
                .unwrap(),
            2
        );
        collector.stop().await.unwrap();
        assert_eq!(store.shutdown().await.unwrap().events, 2);
    }

    #[tokio::test]
    async fn authenticates_redacts_and_extracts_hook_ids() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: collector.token.clone(),
                source: "hermes".to_owned(),
                event: "pre_api_request".to_owned(),
                payload: json!({
                    "task_id": "task",
                    "session_id": "session",
                    "turn_id": "turn",
                    "api_request_id": "attempt",
                    "api_call_count": 3,
                    "headers": {"authorization": "secret"},
                }),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(response.accepted);
        collector.stop().await.unwrap();
        store.shutdown().await.unwrap();

        let text = fs::read_to_string(temporary.path().join("events.jsonl")).unwrap();
        assert!(!text.contains("secret"));
        let mut seen = false;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.source == "hook:hermes" {
                assert_eq!(event.ids.task_id.as_deref(), Some("task"));
                assert_eq!(event.ids.session_id.as_deref(), Some("session"));
                assert_eq!(event.ids.inference_id.as_deref(), Some("session:turn:3"));
                assert_eq!(event.ids.attempt_id.as_deref(), Some("attempt"));
                seen = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(seen);
    }

    #[tokio::test]
    async fn sdk_parser_runs_only_after_native_hook_is_durable_and_is_redacted() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector =
            start_with_adapter(temporary.path(), store.clone(), Some(parsing_host(false))).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: collector.token.clone(),
                source: "fixture-native".to_owned(),
                event: "raw_model_hook".to_owned(),
                payload: json!({"model": "example"}),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(response.accepted);
        collector.stop().await.unwrap();
        assert_eq!(store.shutdown().await.unwrap().capture_drops, 0);

        let text = fs::read_to_string(temporary.path().join("events.jsonl")).unwrap();
        assert!(!text.contains("adapter-secret"));
        let mut native_sequence = None;
        let mut parsed_sequence = None;
        let mut linked = false;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.source == "hook:fixture-native" {
                native_sequence = Some(event.sequence);
            }
            if event.source == "adapter:fixture" {
                parsed_sequence = Some(event.sequence);
                linked = event
                    .evidence
                    .iter()
                    .any(|value| value == "native_hook_sequence:1");
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(native_sequence, Some(1));
        assert!(parsed_sequence > native_sequence);
        assert!(linked);
    }

    #[tokio::test]
    async fn sdk_parser_panic_preserves_the_native_hook_and_records_loss() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector =
            start_with_adapter(temporary.path(), store.clone(), Some(parsing_host(true))).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: collector.token.clone(),
                source: "fixture-native".to_owned(),
                event: "raw_model_hook".to_owned(),
                payload: json!({"model": "example"}),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(response.accepted);
        collector.stop().await.unwrap();
        assert_eq!(store.shutdown().await.unwrap().capture_drops, 1);
        let text = fs::read_to_string(temporary.path().join("events.jsonl")).unwrap();
        assert!(text.contains("hook:fixture-native"));
        assert!(text.contains("adapter_parse_error"));
        assert!(text.contains("adapter_panic"));
    }

    #[tokio::test]
    async fn metadata_only_hooks_never_persist_payload_content() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = CapturePolicy {
            body_mode: BodyCaptureMode::MetadataOnly,
            ..CapturePolicy::default()
        };
        let (store, _) = RunStore::create(temporary.path(), "collector", policy).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: collector.token.clone(),
                source: "hermes".to_owned(),
                event: "pre_api_request".to_owned(),
                payload: json!({
                    "session_id": "session",
                    "messages": [{"role": "user", "content": "private-canary"}],
                }),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(response.accepted);
        collector.stop().await.unwrap();
        store.shutdown().await.unwrap();

        let text = fs::read_to_string(temporary.path().join("events.jsonl")).unwrap();
        assert!(!text.contains("private-canary"));
        assert!(text.contains("hook_payload_omitted_by_policy"));
        assert_eq!(
            fs::read_dir(temporary.path().join("blobs"))
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn accepted_but_safety_truncated_hooks_count_as_capture_loss() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: collector.token.clone(),
                source: "hermes".to_owned(),
                event: "pre_api_request".to_owned(),
                payload: json!({"items": (0..=10_000).collect::<Vec<_>>() }),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(response.accepted);
        collector.stop().await.unwrap();
        let stats = store.shutdown().await.unwrap();
        assert_eq!(stats.capture_drops, 1);

        let mut saw_limit = false;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.source == "hook:hermes" {
                saw_limit = event
                    .redaction
                    .omitted
                    .iter()
                    .any(|item| item == "json_payload_safety_limit");
            }
            Ok(())
        })
        .unwrap();
        assert!(saw_limit);
    }

    #[tokio::test]
    async fn runtime_self_reported_gaps_downgrade_capture() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        for source in ["python-runtime", "node-runtime"] {
            let response = submit(
                &collector.socket_path,
                &HookSubmission {
                    token: collector.token.clone(),
                    source: source.to_owned(),
                    event: "runtime_capture_gap".to_owned(),
                    payload: json!({"reason": "queue_full", "occurrences": 7}),
                    ids: EventIds::default(),
                    confidence: Some(1.0),
                    evidence: vec!["runtime_injection".to_owned()],
                    terminal_state: Some(TerminalState::Incomplete),
                },
            )
            .await
            .unwrap();
            assert!(response.accepted);
        }
        collector.stop().await.unwrap();
        assert_eq!(store.shutdown().await.unwrap().capture_drops, 14);
    }

    #[tokio::test]
    async fn rejects_recorder_reserved_hook_sources() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        for source in ["proxy", "probe-helper"] {
            let response = submit(
                &collector.socket_path,
                &HookSubmission {
                    token: collector.token.clone(),
                    source: source.to_owned(),
                    event: "transport_request_started".to_owned(),
                    payload: json!({"traffic_class": "model"}),
                    ids: EventIds::default(),
                    confidence: None,
                    evidence: Vec::new(),
                    terminal_state: None,
                },
            )
            .await
            .unwrap();
            assert!(!response.accepted);
        }
        collector.stop().await.unwrap();
        assert_eq!(store.shutdown().await.unwrap().events, 0);
    }

    #[tokio::test]
    async fn rejects_wrong_token() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: "wrong".to_owned(),
                source: "test".to_owned(),
                event: "event".to_owned(),
                payload: json!({}),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(!response.accepted);
        collector.stop().await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_metadata_before_storing_payload_blobs() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "collector", CapturePolicy::default()).unwrap();
        let collector = start(temporary.path(), store.clone()).unwrap();
        let response = submit(
            &collector.socket_path,
            &HookSubmission {
                token: collector.token.clone(),
                source: "hermes".to_owned(),
                event: "pre_api_request".to_owned(),
                payload: json!({
                    "session_id": "x".repeat(1025),
                    "messages": [{"role": "user", "content": "must-not-be-stored"}],
                }),
                ids: EventIds::default(),
                confidence: None,
                evidence: Vec::new(),
                terminal_state: None,
            },
        )
        .await
        .unwrap();
        assert!(!response.accepted);
        collector.stop().await.unwrap();
        assert_eq!(store.shutdown().await.unwrap().events, 0);
        assert_eq!(
            fs::read_dir(temporary.path().join("blobs"))
                .unwrap()
                .count(),
            0
        );
    }
}
