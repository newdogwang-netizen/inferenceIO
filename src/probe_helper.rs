use std::{
    fs, io,
    os::unix::{fs::MetadataExt, fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use nix::{
    errno::Errno,
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::{Child, Command},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use crate::{
    input::validate_json_complexity,
    model::{RedactionRecord, TerminalState},
    storage::RunStore,
};

pub const PROTOCOL_VERSION: u32 = 2;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const READER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_DECODED_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_MESSAGES: u64 = 10_000_000;
const MESSAGE_QUEUE_CAPACITY: usize = 256;
const STDERR_LIMIT: usize = 64 * 1024;
const MAX_CAPABILITIES: usize = 64;
const MAX_LABEL_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ProbeMessage {
    Ready {
        schema_version: u32,
        helper: String,
        helper_version: String,
        #[serde(default)]
        upstream_name: Option<String>,
        #[serde(default)]
        upstream_version: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
        target_pid: u32,
        target_executable_sha256: String,
        #[serde(default)]
        target_cgroup: Option<String>,
        filter_scope: String,
    },
    Evidence {
        schema_version: u32,
        event: String,
        pid: u32,
        #[serde(default)]
        tid: Option<u32>,
        #[serde(default)]
        connection_id: Option<String>,
        #[serde(default)]
        direction: Option<String>,
        #[serde(default)]
        protocol: Option<String>,
        #[serde(default)]
        media_type: Option<String>,
        #[serde(default)]
        payload_base64: Option<String>,
        #[serde(default)]
        payload_sha256: Option<String>,
        #[serde(default)]
        confidence: Option<f32>,
    },
    Gap {
        schema_version: u32,
        reason: String,
        occurrences: u64,
    },
    Final {
        schema_version: u32,
        captured_events: u64,
        dropped_events: u64,
        probe_hits: u64,
        complete: bool,
    },
}

impl ProbeMessage {
    const fn schema_version(&self) -> u32 {
        match self {
            Self::Ready { schema_version, .. }
            | Self::Evidence { schema_version, .. }
            | Self::Gap { schema_version, .. }
            | Self::Final { schema_version, .. } => *schema_version,
        }
    }
}

#[derive(Debug, Default)]
struct CaptureReport {
    messages: u64,
    ready_messages: u64,
    invalid_messages: u64,
    gap_occurrences: u64,
    helper_reported_drops: u64,
    captured_events: u64,
    helper_reported_events: u64,
    probe_hits: u64,
    saw_final: bool,
    final_complete: bool,
    persistence_failed: bool,
}

#[derive(Debug)]
struct StderrCapture {
    omitted: u64,
}

#[derive(Debug, Serialize)]
pub struct ProbeHelperReport {
    pub messages: u64,
    pub invalid_messages: u64,
    pub gap_occurrences: u64,
    pub helper_reported_drops: u64,
    pub queue_drops: u64,
    pub captured_events: u64,
    pub helper_reported_events: u64,
    pub probe_hits: u64,
    pub final_state: ProbeFinalState,
    pub persistence_failed: bool,
    pub exit_success: bool,
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
    pub forced_kill: bool,
    pub stderr_bytes_omitted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFinalState {
    Missing,
    Incomplete,
    Complete,
}

impl ProbeHelperReport {
    #[must_use]
    pub fn complete(&self) -> bool {
        self.invalid_messages == 0
            && self.gap_occurrences == 0
            && self.helper_reported_drops == 0
            && self.queue_drops == 0
            && self.captured_events == self.helper_reported_events
            && self.final_state == ProbeFinalState::Complete
            && !self.persistence_failed
            && self.exit_success
            && !self.forced_kill
            && self.stderr_bytes_omitted == 0
    }
}

pub struct ProbeHelperHandle {
    child: Child,
    process_group: u32,
    reader: JoinHandle<io::Result<()>>,
    capture: JoinHandle<io::Result<CaptureReport>>,
    stderr: JoinHandle<io::Result<StderrCapture>>,
    queue_drops: Arc<AtomicU64>,
    store: RunStore,
}

#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub pid: u32,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub cgroup: Option<PathBuf>,
}

impl ProbeTarget {
    pub fn new(
        pid: u32,
        executable: Option<&Path>,
        executable_sha256: Option<&str>,
        cgroup: Option<&Path>,
    ) -> io::Result<Self> {
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "probe target PID cannot be zero",
            ));
        }
        let executable = executable.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "privileged probing requires a resolved target executable",
            )
        })?;
        if !valid_absolute_protocol_path(executable) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "probe target executable must be a bounded absolute UTF-8 path",
            ));
        }
        let executable_sha256 = executable_sha256.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "privileged probing requires a target executable SHA-256",
            )
        })?;
        if !valid_sha256(executable_sha256) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "probe target executable SHA-256 is invalid",
            ));
        }
        if cgroup.is_some_and(|path| !valid_absolute_protocol_path(path)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "probe target cgroup must be a bounded absolute UTF-8 path",
            ));
        }
        Ok(Self {
            pid,
            executable: executable.to_path_buf(),
            executable_sha256: executable_sha256.to_owned(),
            cgroup: cgroup.map(Path::to_path_buf),
        })
    }

    fn filter_scope(&self) -> &'static str {
        if self.cgroup.is_some() {
            "cgroup"
        } else {
            "pid_tree"
        }
    }
}

impl ProbeHelperHandle {
    pub async fn stop(mut self) -> io::Result<ProbeHelperReport> {
        let mut forced_kill = false;
        let status = if let Some(status) = self.child.try_wait()? {
            status
        } else {
            if signal_process(self.process_group, Signal::SIGINT).is_err() {
                forced_kill = true;
                force_kill(&mut self.child, self.process_group).await;
            }
            if let Ok(status) = tokio::time::timeout(STOP_TIMEOUT, self.child.wait()).await {
                status?
            } else {
                forced_kill = true;
                force_kill(&mut self.child, self.process_group).await;
                self.child.wait().await?
            }
        };

        let readers = tokio::time::timeout(READER_STOP_TIMEOUT, async {
            tokio::join!(&mut self.reader, &mut self.capture, &mut self.stderr)
        })
        .await;
        let Ok((reader, capture, stderr)) = readers else {
            self.reader.abort();
            self.capture.abort();
            self.stderr.abort();
            let _ = tokio::join!(&mut self.reader, &mut self.capture, &mut self.stderr);
            self.store.note_capture_drop();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe helper output readers did not stop before their deadline",
            ));
        };
        reader.map_err(|error| join_error(&error))??;
        let capture = capture.map_err(|error| join_error(&error))??;
        let stderr = stderr.map_err(|error| join_error(&error))??;
        let queue_drops = self.queue_drops.load(Ordering::Relaxed);
        if queue_drops > 0 {
            self.store.note_capture_drops(queue_drops);
        }
        if forced_kill || !status.success() || stderr.omitted > 0 || !capture.saw_final {
            self.store.note_capture_drop();
        }
        let report = ProbeHelperReport {
            messages: capture.messages,
            invalid_messages: capture.invalid_messages,
            gap_occurrences: capture.gap_occurrences,
            helper_reported_drops: capture.helper_reported_drops,
            queue_drops,
            captured_events: capture.captured_events,
            helper_reported_events: capture.helper_reported_events,
            probe_hits: capture.probe_hits,
            final_state: if !capture.saw_final {
                ProbeFinalState::Missing
            } else if capture.final_complete {
                ProbeFinalState::Complete
            } else {
                ProbeFinalState::Incomplete
            },
            persistence_failed: capture.persistence_failed,
            exit_success: status.success(),
            exit_code: status.code(),
            termination_signal: status.signal(),
            forced_kill,
            stderr_bytes_omitted: stderr.omitted,
        };
        if !report.complete() {
            self.store.note_capture_drop();
        }
        Ok(report)
    }
}

impl Drop for ProbeHelperHandle {
    fn drop(&mut self) {
        let _ = signal_group(self.process_group, Signal::SIGKILL);
    }
}

pub async fn start(
    program: &Path,
    target: ProbeTarget,
    run_id: &str,
    store: RunStore,
) -> io::Result<ProbeHelperHandle> {
    let program = validate_helper(program)?;
    start_program(&program, target, run_id, store).await
}

async fn start_program(
    program: &Path,
    target: ProbeTarget,
    run_id: &str,
    store: RunStore,
) -> io::Result<ProbeHelperHandle> {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .arg("--iorec-probe-protocol")
        .arg(PROTOCOL_VERSION.to_string())
        .arg("--target-pid")
        .arg(target.pid.to_string())
        .arg("--target-executable")
        .arg(&target.executable)
        .arg("--target-executable-sha256")
        .arg(&target.executable_sha256)
        .arg("--filter-scope")
        .arg(target.filter_scope())
        .arg("--run-id")
        .arg(run_id)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if let Some(cgroup) = &target.cgroup {
        command.arg("--target-cgroup").arg(cgroup);
    }
    let mut child = command.spawn()?;
    let process_group = child
        .id()
        .ok_or_else(|| io::Error::other("probe helper has no PID"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe helper stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("probe helper stderr was not piped"))?;
    let (sender, receiver) = mpsc::channel(MESSAGE_QUEUE_CAPACITY);
    let queue_drops = Arc::new(AtomicU64::new(0));
    let (ready_tx, ready_rx) = oneshot::channel();
    let reader = tokio::spawn(read_messages(
        BufReader::new(stdout),
        sender,
        Arc::clone(&queue_drops),
        ready_tx,
        target,
    ));
    let capture = tokio::spawn(capture_messages(receiver, store.clone()));
    let stderr = tokio::spawn(capture_stderr(BufReader::new(stderr)));

    match tokio::time::timeout(READY_TIMEOUT, ready_rx).await {
        Ok(Ok(Ok(()))) => Ok(ProbeHelperHandle {
            child,
            process_group,
            reader,
            capture,
            stderr,
            queue_drops,
            store,
        }),
        Ok(Ok(Err(error))) => {
            cleanup_failed_start(&mut child, process_group, reader, capture, stderr).await;
            Err(error)
        }
        Ok(Err(_)) => {
            cleanup_failed_start(&mut child, process_group, reader, capture, stderr).await;
            Err(io::Error::other(
                "probe helper readiness channel closed unexpectedly",
            ))
        }
        Err(_) => {
            cleanup_failed_start(&mut child, process_group, reader, capture, stderr).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe helper did not send a valid ready message",
            ))
        }
    }
}

pub fn validate_helper(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe helper path must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe helper must be a regular non-symlink file",
        ));
    }
    let effective_uid = fs::metadata("/proc/self")?.uid();
    if !matches!(metadata.uid(), 0) && metadata.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe helper is not owned by root or the recorder user",
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe helper must be executable and not group/other writable",
        ));
    }
    let canonical = path.canonicalize()?;
    if canonical != path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe helper path must already be canonical",
        ));
    }
    let mut parent = canonical.parent();
    while let Some(directory) = parent {
        let metadata = fs::symlink_metadata(directory)?;
        let mode = metadata.permissions().mode();
        let root_owned_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe helper has a non-directory ancestor",
            ));
        }
        if !matches!(metadata.uid(), 0) && metadata.uid() != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe helper has an ancestor owned by another user",
            ));
        }
        if mode & 0o022 != 0 && !root_owned_sticky_directory {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe helper has a group/other-writable non-sticky ancestor",
            ));
        }
        parent = directory.parent();
    }
    Ok(canonical)
}

async fn cleanup_failed_start(
    child: &mut Child,
    process_group: u32,
    mut reader: JoinHandle<io::Result<()>>,
    mut capture: JoinHandle<io::Result<CaptureReport>>,
    mut stderr: JoinHandle<io::Result<StderrCapture>>,
) {
    force_kill(child, process_group).await;
    reader.abort();
    capture.abort();
    stderr.abort();
    let _ = tokio::join!(&mut reader, &mut capture, &mut stderr);
    let _ = child.wait().await;
}

async fn read_messages(
    mut input: impl AsyncBufRead + Unpin,
    sender: mpsc::Sender<Vec<u8>>,
    queue_drops: Arc<AtomicU64>,
    ready: oneshot::Sender<io::Result<()>>,
    target: ProbeTarget,
) -> io::Result<()> {
    let mut ready = Some(ready);
    let mut messages = 0_u64;
    loop {
        let mut line = Vec::new();
        let read = (&mut input)
            .take(u64::try_from(MAX_MESSAGE_BYTES).unwrap_or(u64::MAX) + 2)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "probe helper exited before its ready message",
                )));
            }
            break;
        }
        if !line.ends_with(b"\n") || line.len() > MAX_MESSAGE_BYTES + 1 {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                "probe helper message exceeded its byte limit",
            );
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
            }
            return Err(error);
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        messages = messages.saturating_add(1);
        if messages > MAX_MESSAGES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probe helper exceeded its message-count limit",
            ));
        }
        if let Some(ready) = ready.take() {
            match parse_message(&line) {
                Ok(message @ ProbeMessage::Ready { .. }) => {
                    match validate_ready_target(&message, &target) {
                        Ok(()) => {
                            let _ = ready.send(Ok(()));
                        }
                        Err(error) => {
                            let _ =
                                ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                            return Err(error);
                        }
                    }
                }
                Ok(_) => {
                    let error = io::Error::new(
                        io::ErrorKind::InvalidData,
                        "probe helper first message was not ready",
                    );
                    let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                    return Err(error);
                }
                Err(error) => {
                    let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
                    return Err(error);
                }
            }
        }
        match sender.try_send(line) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                queue_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "probe helper persistence channel closed",
                ));
            }
        }
    }
    Ok(())
}

async fn capture_messages(
    mut receiver: mpsc::Receiver<Vec<u8>>,
    store: RunStore,
) -> io::Result<CaptureReport> {
    let mut report = CaptureReport::default();
    let mut persistence_available = true;
    while let Some(line) = receiver.recv().await {
        report.messages = report.messages.saturating_add(1);
        if !persistence_available {
            continue;
        }
        if let Err(error) = persist_message(&store, &line, &mut report).await {
            store.note_capture_drop();
            report.persistence_failed = true;
            persistence_available = false;
            tracing::warn!(
                error_kind = ?error.kind(),
                "probe helper evidence persistence failed; continuing to drain output"
            );
        }
    }
    Ok(report)
}

async fn persist_message(
    store: &RunStore,
    line: &[u8],
    report: &mut CaptureReport,
) -> io::Result<()> {
    let raw = store
        .store_sensitive_blob(line, Some("application/vnd.iorec.probe+json"))
        .await
        .map_err(io::Error::other)?;
    let message = match parse_message(line) {
        Ok(message) => message,
        Err(error) => {
            report.invalid_messages = report.invalid_messages.saturating_add(1);
            store.note_capture_drop();
            persist_rejection(
                store,
                raw,
                line,
                "invalid_protocol_message",
                error_kind_name(error.kind()),
            )
            .await?;
            return Ok(());
        }
    };
    let duplicate_ready =
        matches!(&message, ProbeMessage::Ready { .. }) && report.ready_messages > 0;
    if report.saw_final || duplicate_ready {
        report.invalid_messages = report.invalid_messages.saturating_add(1);
        store.note_capture_drop();
        persist_rejection(
            store,
            raw,
            line,
            if report.saw_final {
                "message_after_final"
            } else {
                "duplicate_ready"
            },
            "invalid_data",
        )
        .await?;
        return Ok(());
    }
    let mut event = match message {
        ProbeMessage::Ready {
            helper,
            helper_version,
            upstream_name,
            upstream_version,
            capabilities,
            target_pid,
            target_executable_sha256,
            target_cgroup,
            filter_scope,
            ..
        } => {
            report.ready_messages = report.ready_messages.saturating_add(1);
            let mut event = store.event("probe-helper", "privileged_probe_ready");
            event.normalized = Some(json!({
                "helper": helper,
                "helper_version": helper_version,
                "upstream_name": upstream_name,
                "upstream_version": upstream_version,
                "capabilities": capabilities,
                "target_pid": target_pid,
                "target_executable_sha256": target_executable_sha256,
                "target_cgroup": target_cgroup,
                "filter_scope": filter_scope,
                "protocol_version": PROTOCOL_VERSION,
            }));
            event
        }
        ProbeMessage::Evidence {
            event: probe_event,
            pid,
            tid,
            connection_id,
            direction,
            protocol,
            media_type,
            payload_base64,
            payload_sha256,
            confidence,
            ..
        } => {
            let payload_bytes =
                validate_payload(payload_base64.as_deref(), payload_sha256.as_deref())?;
            report.captured_events = report.captured_events.saturating_add(1);
            let mut event = store.event("probe-helper", "privileged_probe_evidence");
            event.ids.connection_id = connection_id;
            event.confidence = confidence;
            event.normalized = Some(json!({
                "probe_event": probe_event,
                "pid": pid,
                "tid": tid,
                "direction": direction,
                "protocol": protocol,
                "media_type": media_type,
                "payload_bytes": payload_bytes,
                "payload_sha256": payload_sha256,
            }));
            event
        }
        ProbeMessage::Gap {
            reason,
            occurrences,
            ..
        } => {
            report.gap_occurrences = report.gap_occurrences.saturating_add(occurrences);
            store.note_capture_drops(occurrences);
            let mut event = store.event("probe-helper", "privileged_probe_gap");
            event.terminal_state = Some(TerminalState::Incomplete);
            event.normalized = Some(json!({
                "reason": reason,
                "occurrences": occurrences,
            }));
            event
        }
        ProbeMessage::Final {
            captured_events,
            dropped_events,
            probe_hits,
            complete,
            ..
        } => {
            report.saw_final = true;
            report.final_complete = complete;
            report.helper_reported_events = captured_events;
            report.helper_reported_drops = dropped_events;
            report.probe_hits = probe_hits;
            let drops_not_already_reported = dropped_events.saturating_sub(report.gap_occurrences);
            if drops_not_already_reported > 0 {
                store.note_capture_drops(drops_not_already_reported);
            }
            if !complete {
                store.note_capture_drop();
            }
            let mut event = store.event("probe-helper", "privileged_probe_final");
            event.terminal_state = Some(if complete && dropped_events == 0 {
                TerminalState::Complete
            } else {
                TerminalState::Incomplete
            });
            event.normalized = Some(json!({
                "captured_events": captured_events,
                "dropped_events": dropped_events,
                "probe_hits": probe_hits,
                "complete": complete,
            }));
            event
        }
    };
    event.raw = Some(raw);
    event.redaction = probe_redaction();
    event.evidence = vec!["versioned_privileged_probe_helper".to_owned()];
    store.append(event).await.map_err(io::Error::other)?;
    Ok(())
}

async fn persist_rejection(
    store: &RunStore,
    raw: crate::model::PayloadRef,
    line: &[u8],
    reason: &str,
    error_kind: &str,
) -> io::Result<()> {
    let mut event = store.event("probe-helper", "privileged_probe_message_rejected");
    event.raw = Some(raw);
    event.terminal_state = Some(TerminalState::Incomplete);
    event.normalized = Some(json!({
        "reason": reason,
        "error_kind": error_kind,
        "bytes": line.len(),
        "sha256": format!("sha256:{}", hex::encode(Sha256::digest(line))),
    }));
    event.redaction = probe_redaction();
    store.append(event).await.map_err(io::Error::other)?;
    Ok(())
}

fn parse_message(line: &[u8]) -> io::Result<ProbeMessage> {
    validate_json_complexity(line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let message: ProbeMessage = serde_json::from_slice(line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if message.schema_version() != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe helper protocol version is unsupported",
        ));
    }
    match &message {
        ProbeMessage::Ready {
            helper,
            helper_version,
            upstream_name,
            upstream_version,
            capabilities,
            target_pid,
            target_executable_sha256,
            target_cgroup,
            filter_scope,
            ..
        } => {
            validate_label("helper", helper)?;
            validate_label("helper version", helper_version)?;
            if upstream_name.is_some() != upstream_version.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe upstream name and version must be supplied together",
                ));
            }
            if let Some(upstream_name) = upstream_name {
                validate_label("upstream name", upstream_name)?;
            }
            if let Some(upstream_version) = upstream_version {
                validate_label("upstream version", upstream_version)?;
            }
            if capabilities.len() > MAX_CAPABILITIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe helper declared too many capabilities",
                ));
            }
            for capability in capabilities {
                validate_label("capability", capability)?;
            }
            if *target_pid == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe ready target PID cannot be zero",
                ));
            }
            if !valid_sha256(target_executable_sha256) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe ready target executable SHA-256 is invalid",
                ));
            }
            if target_cgroup.as_ref().is_some_and(|path| {
                path.is_empty()
                    || path.len() > MAX_PATH_BYTES
                    || !path.starts_with('/')
                    || path.chars().any(char::is_control)
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe ready target cgroup is invalid",
                ));
            }
            if !matches!(filter_scope.as_str(), "pid_tree" | "cgroup") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe ready filter scope is unsupported",
                ));
            }
            if (filter_scope == "cgroup") != target_cgroup.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe ready filter scope does not match its cgroup binding",
                ));
            }
        }
        ProbeMessage::Evidence {
            event,
            pid,
            connection_id,
            direction,
            protocol,
            media_type,
            payload_base64,
            payload_sha256,
            confidence,
            ..
        } => {
            validate_label("event", event)?;
            if *pid == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe evidence PID must be positive",
                ));
            }
            for (name, value) in [
                ("connection ID", connection_id.as_deref()),
                ("direction", direction.as_deref()),
                ("protocol", protocol.as_deref()),
                ("media type", media_type.as_deref()),
            ] {
                if let Some(value) = value {
                    validate_label(name, value)?;
                }
            }
            if payload_base64.is_some() != payload_sha256.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe payload and digest must be supplied together",
                ));
            }
            if let Some(confidence) = confidence
                && (!confidence.is_finite() || !(0.0..=1.0).contains(confidence))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe evidence confidence is outside zero to one",
                ));
            }
            let _ = validate_payload(payload_base64.as_deref(), payload_sha256.as_deref())?;
        }
        ProbeMessage::Gap {
            reason,
            occurrences,
            ..
        } => {
            validate_label("gap reason", reason)?;
            if *occurrences == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "probe gap occurrences must be positive",
                ));
            }
        }
        ProbeMessage::Final { .. } => {}
    }
    Ok(message)
}

fn validate_ready_target(message: &ProbeMessage, target: &ProbeTarget) -> io::Result<()> {
    let ProbeMessage::Ready {
        target_pid,
        target_executable_sha256,
        target_cgroup,
        filter_scope,
        ..
    } = message
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe readiness validation requires a ready message",
        ));
    };
    let expected_cgroup = target.cgroup.as_ref().and_then(|path| path.to_str());
    if *target_pid != target.pid
        || !target_executable_sha256.eq_ignore_ascii_case(&target.executable_sha256)
        || target_cgroup.as_deref() != expected_cgroup
        || filter_scope != target.filter_scope()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe helper ready message does not match the requested target binding",
        ));
    }
    Ok(())
}

fn validate_payload(payload: Option<&str>, digest: Option<&str>) -> io::Result<Option<usize>> {
    let (Some(payload), Some(digest)) = (payload, digest) else {
        return Ok(None);
    };
    let bytes = BASE64_STANDARD.decode(payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "probe evidence payload is not canonical base64",
        )
    })?;
    if bytes.len() > MAX_DECODED_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe evidence payload exceeded its decoded byte limit",
        ));
    }
    let expected = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        expected.as_bytes(),
        digest.as_bytes(),
    )) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe evidence payload digest did not match",
        ));
    }
    Ok(Some(bytes.len()))
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_absolute_protocol_path(path: &Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some_and(|value| {
            !value.is_empty()
                && value.len() <= MAX_PATH_BYTES
                && !value.chars().any(char::is_control)
        })
}

fn validate_label(name: &str, value: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("probe {name} is empty, too long, or contains controls"),
        ));
    }
    Ok(())
}

fn probe_redaction() -> RedactionRecord {
    RedactionRecord {
        policy: "encrypted-system-probe".to_owned(),
        fields: vec!["payload".to_owned()],
        omitted: Vec::new(),
    }
}

async fn capture_stderr(mut input: impl AsyncRead + Unpin) -> io::Result<StderrCapture> {
    let mut retained = 0_usize;
    let mut omitted = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let length = tokio::io::AsyncReadExt::read(&mut input, &mut buffer).await?;
        if length == 0 {
            break;
        }
        let available = STDERR_LIMIT.saturating_sub(retained);
        let kept = available.min(length);
        retained = retained.saturating_add(kept);
        omitted = omitted.saturating_add(u64::try_from(length - kept).unwrap_or(u64::MAX));
    }
    Ok(StderrCapture { omitted })
}

fn signal_group(process_group: u32, signal: Signal) -> io::Result<()> {
    let pid = i32::try_from(process_group)
        .map(Pid::from_raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "helper PID exceeds i32"))?;
    match killpg(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn signal_process(process: u32, signal: Signal) -> io::Result<()> {
    let process = i32::try_from(process)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process ID is invalid"))?;
    kill(Pid::from_raw(process), signal).map_err(|error| match error {
        Errno::ESRCH => io::Error::new(io::ErrorKind::NotFound, "process no longer exists"),
        other => io::Error::from_raw_os_error(other as i32),
    })
}

async fn force_kill(child: &mut Child, process_group: u32) {
    let _ = signal_group(process_group, Signal::SIGKILL);
    let _ = child.kill().await;
}

fn join_error(error: &tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("probe helper output task failed: {error}"))
}

const fn error_kind_name(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::OutOfMemory => "out_of_memory",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use crate::{crypto::EncryptionKey, policy::CapturePolicy, storage::for_each_event_with_key};

    use super::*;

    fn fixture_target() -> ProbeTarget {
        ProbeTarget::new(
            std::process::id(),
            Some(Path::new("/proc/self/exe")),
            Some(&format!("sha256:{}", "ab".repeat(32))),
            None,
        )
        .unwrap()
    }

    #[test]
    fn target_binding_rejects_ambiguous_inputs_and_mismatched_readiness() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        assert!(ProbeTarget::new(0, Some(Path::new("/bin/true")), Some(&digest), None).is_err());
        assert!(ProbeTarget::new(1, Some(Path::new("bin/true")), Some(&digest), None).is_err());
        assert!(
            ProbeTarget::new(1, Some(Path::new("/bin/true")), Some("sha256:abcd"), None).is_err()
        );
        assert!(
            ProbeTarget::new(
                1,
                Some(Path::new("/bin/true")),
                Some(&digest),
                Some(Path::new("relative/cgroup")),
            )
            .is_err()
        );

        let target = ProbeTarget::new(
            42,
            Some(Path::new("/bin/true")),
            Some(&digest),
            Some(Path::new("/sys/fs/cgroup/iorec-test")),
        )
        .unwrap();
        let ready = serde_json::to_vec(&json!({
            "type": "ready",
            "schema_version": PROTOCOL_VERSION,
            "helper": "fixture",
            "helper_version": "1.0.0",
            "capabilities": ["process"],
            "target_pid": 42,
            "target_executable_sha256": digest,
            "target_cgroup": "/sys/fs/cgroup/iorec-test",
            "filter_scope": "cgroup",
        }))
        .unwrap();
        let ready = parse_message(&ready).unwrap();
        validate_ready_target(&ready, &target).unwrap();

        let mismatched = serde_json::to_vec(&json!({
            "type": "ready",
            "schema_version": PROTOCOL_VERSION,
            "helper": "fixture",
            "helper_version": "1.0.0",
            "target_pid": 43,
            "target_executable_sha256": target.executable_sha256.clone(),
            "target_cgroup": "/sys/fs/cgroup/iorec-test",
            "filter_scope": "cgroup",
        }))
        .unwrap();
        assert!(validate_ready_target(&parse_message(&mismatched).unwrap(), &target).is_err());
    }

    #[test]
    fn protocol_rejects_wrong_order_tampered_payloads_and_unbounded_labels() {
        let payload = b"secret probe bytes";
        let encoded = BASE64_STANDARD.encode(payload);
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(payload)));
        let evidence = serde_json::to_vec(&json!({
            "type": "evidence",
            "schema_version": PROTOCOL_VERSION,
            "event": "tls_plaintext",
            "pid": 42,
            "payload_base64": encoded,
            "payload_sha256": digest,
            "confidence": 1.0,
        }))
        .unwrap();
        assert!(matches!(
            parse_message(&evidence).unwrap(),
            ProbeMessage::Evidence { .. }
        ));

        let tampered = serde_json::to_vec(&json!({
            "type": "evidence",
            "schema_version": PROTOCOL_VERSION,
            "event": "tls_plaintext",
            "pid": 42,
            "payload_base64": BASE64_STANDARD.encode(b"different"),
            "payload_sha256": digest,
        }))
        .unwrap();
        assert!(parse_message(&tampered).is_err());
        let oversized = serde_json::to_vec(&json!({
            "type": "ready",
            "schema_version": PROTOCOL_VERSION,
            "helper": "x".repeat(MAX_LABEL_BYTES + 1),
            "helper_version": "1.0.0",
            "target_pid": 42,
            "target_executable_sha256": format!("sha256:{}", "ab".repeat(32)),
            "filter_scope": "pid_tree",
        }))
        .unwrap();
        assert!(parse_message(&oversized).is_err());
    }

    #[tokio::test]
    async fn reader_requires_ready_as_the_first_message() {
        let input = br#"{"type":"final","schema_version":2,"captured_events":0,"dropped_events":0,"probe_hits":0,"complete":true}
"#;
        let (sender, _receiver) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();
        let result = read_messages(
            BufReader::new(&input[..]),
            sender,
            Arc::new(AtomicU64::new(0)),
            ready_tx,
            fixture_target(),
        )
        .await;
        assert!(result.is_err());
        assert!(ready_rx.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn real_helper_handshake_persists_only_encrypted_protocol_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let helper = temporary.path().join("probe-helper");
        let payload = b"authorization: never-on-disk";
        let payload_base64 = BASE64_STANDARD.encode(payload);
        let payload_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(payload)));
        let target = fixture_target();
        let ready = serde_json::to_string(&json!({
            "type": "ready",
            "schema_version": PROTOCOL_VERSION,
            "helper": "fixture",
            "helper_version": "1.0.0",
            "upstream_name": "fixture-probe",
            "upstream_version": "2.0.0",
            "capabilities": ["tls_plaintext"],
            "target_pid": target.pid,
            "target_executable_sha256": target.executable_sha256.clone(),
            "filter_scope": target.filter_scope(),
        }))
        .unwrap();
        let evidence = serde_json::to_string(&json!({
            "type": "evidence",
            "schema_version": PROTOCOL_VERSION,
            "event": "tls_plaintext",
            "pid": std::process::id(),
            "direction": "write",
            "protocol": "tls",
            "payload_base64": payload_base64,
            "payload_sha256": payload_sha256,
            "confidence": 1.0,
        }))
        .unwrap();
        let final_message = serde_json::to_string(&json!({
            "type": "final",
            "schema_version": PROTOCOL_VERSION,
            "captured_events": 1,
            "dropped_events": 0,
            "probe_hits": 1,
            "complete": true,
        }))
        .unwrap();
        let mut file = fs::File::create(&helper).unwrap();
        writeln!(file, "#!/bin/sh").unwrap();
        // The protocol fixture models a helper that drains and emits its final
        // record during shutdown instead of dying between ready and final.
        writeln!(file, "trap '' INT").unwrap();
        writeln!(file, "printf '%s\\n' '{}'", ready.replace('\'', "'\\''")).unwrap();
        writeln!(file, "printf '%s\\n' '{}'", evidence.replace('\'', "'\\''")).unwrap();
        writeln!(
            file,
            "printf '%s\\n' '{}'",
            final_message.replace('\'', "'\\''")
        )
        .unwrap();
        drop(file);
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();

        let run_dir = temporary.path().join("run");
        let key = EncryptionKey::new([91; 32]);
        let (store, _) = RunStore::create_with_encryption(
            &run_dir,
            "probe-test",
            CapturePolicy::default(),
            Some(key.clone()),
        )
        .unwrap();
        let handle = start_program(&helper, target, "probe-test", store.clone())
            .await
            .unwrap();
        let report = handle.stop().await.unwrap();
        assert!(report.complete());
        assert_eq!(report.captured_events, 1);
        store.shutdown().await.unwrap();

        let encoded_events = fs::read(run_dir.join("events.jsonl")).unwrap();
        assert!(
            !encoded_events
                .windows(payload.len())
                .any(|part| part == payload)
        );
        assert!(
            !encoded_events
                .windows(payload_base64.len())
                .any(|part| part == payload_base64.as_bytes())
        );
        let mut evidence_raw = None;
        for_each_event_with_key(&run_dir.join("events.jsonl"), Some(&key), |event| {
            if event.event == "privileged_probe_evidence" {
                evidence_raw = event.raw;
            }
            Ok(())
        })
        .unwrap();
        let raw = evidence_raw.unwrap();
        let encrypted = fs::read(crate::blob_keys::blob_path(&run_dir, &raw).unwrap()).unwrap();
        assert!(
            !encrypted
                .windows(payload_base64.len())
                .any(|part| part == payload_base64.as_bytes())
        );
        let plaintext = crate::blob_keys::read_blob_reference(
            &run_dir,
            &raw,
            Some(&key),
            crate::storage::MAX_SINGLE_BLOB_BYTES,
        )
        .unwrap();
        assert!(
            plaintext
                .windows(payload_base64.len())
                .any(|part| part == payload_base64.as_bytes())
        );
    }

    #[tokio::test]
    async fn messages_after_final_and_claimed_count_mismatches_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let helper = temporary.path().join("probe-helper");
        let target = fixture_target();
        let ready = json!({
            "type": "ready",
            "schema_version": PROTOCOL_VERSION,
            "helper": "fixture",
            "helper_version": "1.0.0",
            "capabilities": [],
            "target_pid": target.pid,
            "target_executable_sha256": target.executable_sha256.clone(),
            "filter_scope": target.filter_scope(),
        });
        let final_message = json!({
            "type": "final",
            "schema_version": PROTOCOL_VERSION,
            "captured_events": 1,
            "dropped_events": 0,
            "probe_hits": 1,
            "complete": true,
        });
        let after_final = json!({
            "type": "gap",
            "schema_version": PROTOCOL_VERSION,
            "reason": "late_gap",
            "occurrences": 1,
        });
        let script =
            format!("#!/bin/sh\nprintf '%s\\n' '{ready}' '{final_message}' '{after_final}'\n");
        fs::write(&helper, script).unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let key = EncryptionKey::new([94; 32]);
        let (store, _) = RunStore::create_with_encryption(
            temporary.path().join("run"),
            "probe-invalid-final",
            CapturePolicy::default(),
            Some(key),
        )
        .unwrap();
        let handle = start_program(&helper, target, "probe-invalid-final", store.clone())
            .await
            .unwrap();
        let report = handle.stop().await.unwrap();
        assert!(!report.complete());
        assert_eq!(report.invalid_messages, 1);
        assert_eq!(report.captured_events, 0);
        assert_eq!(report.helper_reported_events, 1);
        assert!(store.stats().capture_drops > 0);
        store.shutdown().await.unwrap();
    }
}
