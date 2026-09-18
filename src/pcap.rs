use std::{
    ffi::{OsStr, OsString},
    fs, io,
    net::SocketAddr,
    os::unix::{fs::MetadataExt, fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::Serialize;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, BufReader},
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
};

use crate::{model::RedactionRecord, storage::RunStore};

const START_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const READER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const STDERR_LIMIT: usize = 64 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const PCAP_GLOBAL_HEADER_BYTES: usize = 24;

#[derive(Debug, Clone, Serialize)]
pub struct PcapReport {
    pub bytes: u64,
    pub chunks: u64,
    pub limit_reached: bool,
    pub packets_captured: Option<u64>,
    pub packets_received: Option<u64>,
    pub packets_dropped: Option<u64>,
    pub packets_missed: Option<u64>,
    pub exit_success: bool,
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
    pub forced_kill: bool,
    pub stderr_bytes_omitted: u64,
}

#[derive(Debug, Default)]
struct CaptureReport {
    bytes: u64,
    chunks: u64,
    limit_reached: bool,
}

#[derive(Debug)]
struct StderrCapture {
    bytes: Vec<u8>,
    omitted: u64,
}

pub struct PcapHandle {
    child: Child,
    process_group: u32,
    capture: JoinHandle<io::Result<CaptureReport>>,
    stderr: JoinHandle<io::Result<StderrCapture>>,
    store: RunStore,
}

impl PcapHandle {
    #[must_use]
    pub fn namespace_anchor_pid(&self) -> u32 {
        self.process_group
    }

    pub async fn stop(mut self) -> io::Result<PcapReport> {
        let mut forced_kill = false;
        if signal_group(self.process_group, Signal::SIGINT).is_err() {
            forced_kill = true;
            force_kill(&mut self.child, self.process_group).await;
        }
        let status = if let Ok(status) = tokio::time::timeout(STOP_TIMEOUT, self.child.wait()).await
        {
            status?
        } else {
            forced_kill = true;
            force_kill(&mut self.child, self.process_group).await;
            self.child.wait().await?
        };
        let mut capture_task = self.capture;
        let mut stderr_task = self.stderr;
        let readers = tokio::time::timeout(READER_STOP_TIMEOUT, async {
            tokio::join!(&mut capture_task, &mut stderr_task)
        })
        .await;
        let Ok((capture, stderr)) = readers else {
            capture_task.abort();
            stderr_task.abort();
            let _ = tokio::join!(&mut capture_task, &mut stderr_task);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pcap output readers did not stop after the capture process exited",
            ));
        };
        let capture = capture
            .map_err(|error| io::Error::other(format!("pcap reader task panicked: {error}")))??;
        let stderr = stderr
            .map_err(|error| io::Error::other(format!("pcap stderr task panicked: {error}")))??;
        let statistics = parse_statistics(&String::from_utf8_lossy(&stderr.bytes));
        let packets_missed = statistics
            .captured
            .zip(statistics.received)
            .and_then(|(captured, received)| received.checked_sub(captured));
        let observed_packet_loss = statistics
            .dropped
            .unwrap_or(0)
            .max(packets_missed.unwrap_or(0));
        if observed_packet_loss > 0 {
            self.store.note_capture_drops(observed_packet_loss);
        }
        if stderr.omitted > 0 {
            self.store.note_capture_drop();
        }
        if forced_kill
            || !status.success()
            || statistics.dropped.is_none()
            || packets_missed.is_none()
        {
            self.store.note_capture_drop();
        }
        Ok(PcapReport {
            bytes: capture.bytes,
            chunks: capture.chunks,
            limit_reached: capture.limit_reached,
            packets_captured: statistics.captured,
            packets_received: statistics.received,
            packets_dropped: statistics.dropped,
            packets_missed,
            exit_success: status.success(),
            exit_code: status.code(),
            termination_signal: status.signal(),
            forced_kill,
            stderr_bytes_omitted: stderr.omitted,
        })
    }
}

pub async fn start(
    listener: SocketAddr,
    max_bytes: u64,
    store: RunStore,
) -> io::Result<PcapHandle> {
    let program = trusted_tcpdump_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no root-owned, non-writable tcpdump was found in a fixed system path",
        )
    })?;
    let interface = if listener.ip().is_loopback() {
        "lo"
    } else {
        "any"
    };
    let filter = format!("tcp port {}", listener.port());
    start_program(
        program.as_os_str(),
        &[],
        interface,
        filter,
        "tcpdump_listener_filter",
        max_bytes,
        store,
    )
    .await
}

pub async fn start_upstream(
    endpoints: &[SocketAddr],
    max_bytes: u64,
    store: RunStore,
) -> io::Result<PcapHandle> {
    let (interface, filter) = upstream_capture_spec(endpoints)?;
    let program = trusted_tcpdump_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no root-owned, non-writable tcpdump was found in a fixed system path",
        )
    })?;
    start_program(
        program.as_os_str(),
        &[],
        interface,
        filter,
        "tcpdump_upstream_address_filter",
        max_bytes,
        store,
    )
    .await
}

pub async fn start_task_namespace(
    target_pid: u32,
    proxy_port: u16,
    max_bytes: u64,
    store: RunStore,
) -> io::Result<PcapHandle> {
    if target_pid == 0 || proxy_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "task-network packet capture requires a target PID and proxy port",
        ));
    }
    let nsenter =
        trusted_root_executable(&["/usr/bin/nsenter", "/bin/nsenter"]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no trusted fixed-path nsenter executable was found",
            )
        })?;
    let tcpdump = trusted_tcpdump_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no root-owned, non-writable tcpdump was found in a fixed system path",
        )
    })?;
    let prefix = vec![
        OsString::from("--target"),
        OsString::from(target_pid.to_string()),
        OsString::from("--user"),
        OsString::from("--net"),
        OsString::from("--preserve-credentials"),
        OsString::from("--keep-caps"),
        tcpdump.into_os_string(),
    ];
    let (interface, filter) = task_namespace_capture_spec();
    start_program(
        nsenter.as_os_str(),
        &prefix,
        interface,
        filter.to_owned(),
        "tcpdump_task_netns_egress_filter",
        max_bytes,
        store,
    )
    .await
}

fn task_namespace_capture_spec() -> (&'static str, &'static str) {
    ("any", "(ip or ip6)")
}

fn upstream_capture_spec(endpoints: &[SocketAddr]) -> io::Result<(&'static str, String)> {
    if endpoints.is_empty() || endpoints.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream packet capture requires between 1 and 64 resolved endpoints",
        ));
    }
    let interface = if endpoints.iter().all(|endpoint| endpoint.ip().is_loopback()) {
        "lo"
    } else {
        "any"
    };
    let filter = endpoints
        .iter()
        .map(|endpoint| format!("(host {} and tcp port {})", endpoint.ip(), endpoint.port()))
        .collect::<Vec<_>>()
        .join(" or ");
    Ok((interface, filter))
}

#[must_use]
pub fn trusted_tcpdump_path() -> Option<PathBuf> {
    trusted_root_executable(&[
        "/usr/bin/tcpdump",
        "/usr/sbin/tcpdump",
        "/bin/tcpdump",
        "/sbin/tcpdump",
    ])
}

#[must_use]
pub(crate) fn trusted_root_executable(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .copied()
        .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
        .find(|candidate| validate_capture_helper(candidate, 0, Path::new("/")).is_ok())
}

fn validate_capture_helper(path: &Path, required_uid: u32, trust_root: &Path) -> io::Result<()> {
    if !path.starts_with(trust_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet capture helper is outside its trusted directory root",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet capture helper must be a regular non-symlink file",
        ));
    }
    if metadata.uid() != required_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "packet capture helper has an untrusted owner",
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "packet capture helper must be executable and not group/other writable",
        ));
    }
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != required_uid
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "packet capture helper has an untrusted writable parent directory",
            ));
        }
        if directory == trust_root {
            break;
        }
        parent = directory.parent();
    }
    Ok(())
}

async fn start_program(
    program: &OsStr,
    prefix_arguments: &[OsString],
    interface: &str,
    filter: String,
    evidence: &'static str,
    max_bytes: u64,
    store: RunStore,
) -> io::Result<PcapHandle> {
    if max_bytes < PCAP_GLOBAL_HEADER_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pcap byte limit must fit the 24-byte global header",
        ));
    }
    let arguments = capture_arguments(interface, filter);
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args(prefix_arguments)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command.spawn()?;
    let process_group = child
        .id()
        .ok_or_else(|| io::Error::other("pcap helper has no PID"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("pcap helper stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("pcap helper stderr was not piped"))?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let capture_store = store.clone();
    let capture = tokio::spawn(capture_stream(
        stdout,
        max_bytes,
        capture_store,
        ready_tx,
        evidence,
    ));
    let stderr = tokio::spawn(capture_stderr(BufReader::new(stderr)));

    match tokio::time::timeout(START_TIMEOUT, ready_rx).await {
        Ok(Ok(Ok(()))) => Ok(PcapHandle {
            child,
            process_group,
            capture,
            stderr,
            store,
        }),
        Ok(Ok(Err(error))) => {
            force_kill(&mut child, process_group).await;
            let _ = capture.await;
            let stderr_bytes = stderr
                .await
                .ok()
                .and_then(Result::ok)
                .map(|capture| capture.bytes)
                .unwrap_or_default();
            let detail = String::from_utf8_lossy(&stderr_bytes);
            Err(io::Error::new(
                error.kind(),
                format!("pcap helper did not start: {}; {}", error, detail.trim()),
            ))
        }
        Ok(Err(_)) => {
            force_kill(&mut child, process_group).await;
            let _ = capture.await;
            let _ = stderr.await;
            Err(io::Error::other(
                "pcap helper readiness channel closed unexpectedly",
            ))
        }
        Err(_) => {
            force_kill(&mut child, process_group).await;
            let _ = capture.await;
            let _ = stderr.await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pcap helper did not produce a capture header",
            ))
        }
    }
}

fn capture_arguments(interface: &str, filter: String) -> Vec<OsString> {
    vec![
        OsString::from("-i"),
        OsString::from(interface),
        OsString::from("--immediate-mode"),
        OsString::from("-U"),
        OsString::from("-s"),
        OsString::from("0"),
        OsString::from("-B"),
        OsString::from("4096"),
        OsString::from("-nn"),
        OsString::from("-w"),
        OsString::from("-"),
        OsString::from("--"),
        OsString::from(filter),
    ]
}

async fn capture_stderr(mut input: impl tokio::io::AsyncRead + Unpin) -> io::Result<StderrCapture> {
    let mut retained = Vec::with_capacity(STDERR_LIMIT);
    let mut buffer = [0_u8; 8 * 1024];
    let mut omitted = 0_u64;
    loop {
        let length = input.read(&mut buffer).await?;
        if length == 0 {
            break;
        }
        if length >= STDERR_LIMIT {
            omitted = omitted.saturating_add(
                u64::try_from(retained.len().saturating_add(length - STDERR_LIMIT))
                    .unwrap_or(u64::MAX),
            );
            retained.clear();
            retained.extend_from_slice(&buffer[length - STDERR_LIMIT..length]);
            continue;
        }
        let overflow = retained
            .len()
            .saturating_add(length)
            .saturating_sub(STDERR_LIMIT);
        if overflow > 0 {
            retained.copy_within(overflow.., 0);
            retained.truncate(retained.len() - overflow);
            omitted = omitted.saturating_add(u64::try_from(overflow).unwrap_or(u64::MAX));
        }
        retained.extend_from_slice(&buffer[..length]);
    }
    Ok(StderrCapture {
        bytes: retained,
        omitted,
    })
}

async fn capture_stream(
    mut input: impl tokio::io::AsyncRead + Unpin,
    max_bytes: u64,
    store: RunStore,
    ready: oneshot::Sender<io::Result<()>>,
    evidence: &'static str,
) -> io::Result<CaptureReport> {
    let mut ready = Some(ready);
    let mut report = CaptureReport::default();
    let mut buffer = vec![0_u8; CHUNK_BYTES].into_boxed_slice();
    let mut header = Vec::with_capacity(PCAP_GLOBAL_HEADER_BYTES);
    let mut pending = Vec::with_capacity(CHUNK_BYTES);
    let mut header_persisted = false;
    loop {
        let length = match input.read(&mut buffer).await {
            Ok(length) => length,
            Err(error) => {
                notify_ready_error(&mut ready, error.kind(), &error.to_string());
                return Err(error);
            }
        };
        if length == 0 {
            notify_ready_error(
                &mut ready,
                io::ErrorKind::UnexpectedEof,
                "pcap helper exited before writing a complete capture header",
            );
            if header_persisted && !pending.is_empty() {
                persist_capture_bytes(&pending, max_bytes, &store, &mut report, evidence).await?;
            }
            break;
        }

        let mut consumed = 0;
        if !header_persisted {
            let needed = PCAP_GLOBAL_HEADER_BYTES.saturating_sub(header.len());
            consumed = needed.min(length);
            header.extend_from_slice(&buffer[..consumed]);
            if header.len() < PCAP_GLOBAL_HEADER_BYTES {
                continue;
            }
            if let Err(error) = validate_pcap_header(&header) {
                notify_ready_error(&mut ready, error.kind(), &error.to_string());
                return Err(error);
            }
            if let Err(error) =
                persist_capture_bytes(&header, max_bytes, &store, &mut report, evidence).await
            {
                notify_ready_error(&mut ready, error.kind(), &error.to_string());
                return Err(error);
            }
            header_persisted = true;
            if let Some(ready) = ready.take() {
                let _ = ready.send(Ok(()));
            }
        }
        if consumed < length {
            let mut remaining = &buffer[consumed..length];
            while !remaining.is_empty() {
                let copied = remaining.len().min(CHUNK_BYTES - pending.len());
                pending.extend_from_slice(&remaining[..copied]);
                remaining = &remaining[copied..];
                if pending.len() == CHUNK_BYTES {
                    persist_capture_bytes(&pending, max_bytes, &store, &mut report, evidence)
                        .await?;
                    pending.clear();
                }
            }
        }
    }
    Ok(report)
}

async fn persist_capture_bytes(
    bytes: &[u8],
    max_bytes: u64,
    store: &RunStore,
    report: &mut CaptureReport,
    evidence: &'static str,
) -> io::Result<()> {
    let remaining = max_bytes.saturating_sub(report.bytes);
    if remaining == 0 {
        mark_limit_reached(report, store);
        return Ok(());
    }
    let captured = bytes
        .len()
        .min(usize::try_from(remaining).unwrap_or(usize::MAX));
    let raw = store
        .store_sensitive_blob(&bytes[..captured], Some("application/vnd.tcpdump.pcap"))
        .await
        .map_err(io::Error::other)?;
    report.chunks = report.chunks.saturating_add(1);
    let offset = report.bytes;
    report.bytes = report
        .bytes
        .saturating_add(u64::try_from(captured).unwrap_or(u64::MAX));
    let mut event = store.event("pcap", "pcap_capture_chunk");
    event.raw = Some(raw);
    event.normalized = Some(json!({
        "chunk_sequence": report.chunks,
        "offset": offset,
        "bytes": captured,
    }));
    event.redaction = RedactionRecord {
        policy: "encrypted-secret".to_owned(),
        fields: vec!["packet_payload".to_owned()],
        omitted: Vec::new(),
    };
    event.confidence = Some(1.0);
    event.evidence = vec![evidence.to_owned()];
    store.append(event).await.map_err(io::Error::other)?;
    if captured < bytes.len() {
        mark_limit_reached(report, store);
    }
    Ok(())
}

fn mark_limit_reached(report: &mut CaptureReport, store: &RunStore) {
    if !report.limit_reached {
        report.limit_reached = true;
        store.note_capture_drop();
    }
}

fn notify_ready_error(
    sender: &mut Option<oneshot::Sender<io::Result<()>>>,
    kind: io::ErrorKind,
    message: &str,
) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(Err(io::Error::new(kind, message.to_owned())));
    }
}

fn validate_pcap_header(header: &[u8]) -> io::Result<()> {
    if header.len() != PCAP_GLOBAL_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pcap global header has an invalid length",
        ));
    }
    let little_endian = match &header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pcap helper emitted an unknown capture format",
            ));
        }
    };
    let version_major = if little_endian {
        u16::from_le_bytes([header[4], header[5]])
    } else {
        u16::from_be_bytes([header[4], header[5]])
    };
    let version_minor = if little_endian {
        u16::from_le_bytes([header[6], header[7]])
    } else {
        u16::from_be_bytes([header[6], header[7]])
    };
    if (version_major, version_minor) != (2, 4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pcap helper emitted an unsupported capture version",
        ));
    }
    Ok(())
}

async fn force_kill(child: &mut Child, process_group: u32) {
    let _ = signal_group(process_group, Signal::SIGKILL);
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[derive(Default)]
struct PcapStatistics {
    captured: Option<u64>,
    received: Option<u64>,
    dropped: Option<u64>,
}

fn parse_statistics(stderr: &str) -> PcapStatistics {
    let mut output = PcapStatistics::default();
    for line in stderr.lines() {
        let number = line
            .split_ascii_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok());
        if line.contains("packets captured") {
            output.captured = number;
        } else if line.contains("packets received by filter") {
            output.received = number;
        } else if line.contains("packets dropped by kernel") {
            output.dropped = number;
        }
    }
    output
}

fn signal_group(pid: u32, signal: Signal) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .map(Pid::from_raw)
        .map_err(|_| io::Error::other("pcap helper PID exceeds platform range"))?;
    match killpg(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use crate::{crypto::EncryptionKey, policy::CapturePolicy, storage::for_each_event_with_key};

    use super::*;

    #[test]
    fn parses_tcpdump_packet_counters() {
        let parsed = parse_statistics(
            "12 packets captured\n14 packets received by filter\n2 packets dropped by kernel\n",
        );
        assert_eq!(parsed.captured, Some(12));
        assert_eq!(parsed.received, Some(14));
        assert_eq!(parsed.dropped, Some(2));
    }

    #[tokio::test]
    async fn stderr_is_continuously_drained_while_only_the_bounded_tail_is_retained() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, reader) = tokio::io::duplex(1024);
        let statistics =
            b"\n7 packets captured\n8 packets received by filter\n1 packets dropped by kernel\n";
        let writer = tokio::spawn(async move {
            writer.write_all(&vec![b'x'; STDERR_LIMIT + 1024]).await?;
            writer.write_all(statistics).await?;
            writer.shutdown().await
        });
        let captured = capture_stderr(reader).await.unwrap();
        writer.await.unwrap().unwrap();

        assert!(captured.omitted > 0);
        assert_eq!(captured.bytes.len(), STDERR_LIMIT);
        assert!(captured.bytes.ends_with(statistics));
        let parsed = parse_statistics(&String::from_utf8_lossy(&captured.bytes));
        assert_eq!(parsed.captured, Some(7));
        assert_eq!(parsed.received, Some(8));
        assert_eq!(parsed.dropped, Some(1));
    }

    #[test]
    fn production_capture_filter_has_no_user_controlled_expression() {
        let listener: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(listener.ip().is_loopback());
        assert_eq!(format!("tcp port {}", listener.port()), "tcp port 12345");
        assert!(!std::path::Path::new("capture.pcap").is_absolute());

        let endpoints = [
            "127.0.0.1:443".parse().unwrap(),
            "[::1]:8443".parse().unwrap(),
        ];
        let (interface, filter) = upstream_capture_spec(&endpoints).unwrap();
        assert_eq!(interface, "lo");
        assert_eq!(
            filter,
            "(host 127.0.0.1 and tcp port 443) or (host ::1 and tcp port 8443)"
        );
        assert!(upstream_capture_spec(&[]).is_err());

        assert_eq!(task_namespace_capture_spec(), ("any", "(ip or ip6)"));
        let arguments = capture_arguments("any", "(ip or ip6)".to_owned());
        let arguments = arguments
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(arguments.windows(2).any(|pair| pair == ["-i", "any"]));
        assert!(arguments.contains(&"--immediate-mode".to_owned()));
        assert!(arguments.contains(&"-U".to_owned()));
        assert_eq!(arguments.last().map(String::as_str), Some("(ip or ip6)"));
    }

    #[test]
    fn capture_helper_requires_trusted_ownership_permissions_and_parents() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::symlink_metadata(temporary.path()).unwrap().uid();
        let helper = temporary.path().join("tcpdump");
        fs::write(&helper, b"test helper").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let validation = validate_capture_helper(&helper, owner, temporary.path());
        assert!(validation.is_ok(), "{validation:?}");

        fs::set_permissions(&helper, fs::Permissions::from_mode(0o720)).unwrap();
        assert!(validate_capture_helper(&helper, owner, temporary.path()).is_err());
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let link = temporary.path().join("tcpdump-link");
        symlink(&helper, &link).unwrap();
        assert!(validate_capture_helper(&link, owner, temporary.path()).is_err());

        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o720)).unwrap();
        assert!(validate_capture_helper(&helper, owner, temporary.path()).is_err());
    }

    #[test]
    fn validates_complete_classic_pcap_headers() {
        assert!(validate_pcap_header(&pcap_header()).is_ok());
        assert!(validate_pcap_header(b"not a capture header!!!!").is_err());
    }

    #[tokio::test]
    async fn capture_stream_persists_only_encrypted_chunk_evidence() {
        use tokio::io::AsyncWriteExt;

        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([71; 32]);
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "pcap-test",
            CapturePolicy::default(),
            Some(key.clone()),
        )
        .unwrap();
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut capture = pcap_header().to_vec();
        capture.extend_from_slice(b"pcap-secret-canary");
        writer.write_all(&capture).await.unwrap();
        writer.shutdown().await.unwrap();
        let (ready, started) = oneshot::channel();
        let report = capture_stream(reader, 1024, store.clone(), ready, "test_filter")
            .await
            .unwrap();
        started.await.unwrap().unwrap();
        assert_eq!(report.chunks, 2);
        assert_eq!(report.bytes, capture.len() as u64);
        store.shutdown().await.unwrap();

        let encoded = std::fs::read(temporary.path().join("events.jsonl")).unwrap();
        assert!(
            !encoded
                .windows(18)
                .any(|window| window == b"pcap-secret-canary")
        );
        let mut found = false;
        for_each_event_with_key(
            &temporary.path().join("events.jsonl"),
            Some(&key),
            |event| {
                found |= event.event == "pcap_capture_chunk";
                Ok(())
            },
        )
        .unwrap();
        assert!(found);
    }

    #[tokio::test]
    async fn capture_stream_coalesces_fragmented_pipe_reads() {
        use tokio::io::AsyncWriteExt;

        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([74; 32]);
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "fragmented-pcap",
            CapturePolicy::default(),
            Some(key),
        )
        .unwrap();
        let (mut writer, reader) = tokio::io::duplex(127);
        let payload = vec![19_u8; CHUNK_BYTES + 17];
        let expected_bytes = PCAP_GLOBAL_HEADER_BYTES + payload.len();
        let writer_task = tokio::spawn(async move {
            writer.write_all(&pcap_header()).await.unwrap();
            for fragment in payload.chunks(31) {
                writer.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
            writer.shutdown().await.unwrap();
        });
        let (ready, started) = oneshot::channel();
        let report = capture_stream(
            reader,
            expected_bytes as u64,
            store.clone(),
            ready,
            "fragmented_test_filter",
        )
        .await
        .unwrap();
        started.await.unwrap().unwrap();
        writer_task.await.unwrap();
        assert_eq!(report.chunks, 3);
        assert_eq!(report.bytes, expected_bytes as u64);
        assert_eq!(store.shutdown().await.unwrap().events, 3);
    }

    #[tokio::test]
    async fn capture_stream_rejects_invalid_data_before_persistence() {
        use tokio::io::AsyncWriteExt;

        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([72; 32]);
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "invalid-pcap",
            CapturePolicy::default(),
            Some(key),
        )
        .unwrap();
        let (mut writer, reader) = tokio::io::duplex(128);
        writer
            .write_all(&[0; PCAP_GLOBAL_HEADER_BYTES])
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let (ready, started) = oneshot::channel();
        assert!(
            capture_stream(reader, 1024, store.clone(), ready, "test_filter")
                .await
                .is_err()
        );
        assert!(started.await.unwrap().is_err());
        assert_eq!(store.shutdown().await.unwrap().events, 0);
    }

    #[tokio::test]
    async fn capture_helper_does_not_inherit_the_callers_environment() {
        let temporary = tempfile::tempdir().unwrap();
        let helper = temporary.path().join("tcpdump-test-helper");
        fs::write(
            &helper,
            concat!(
                "#!/bin/sh\n",
                "if [ \"${HOME+x}\" = x ]; then exit 90; fi\n",
                "printf '\\324\\303\\262\\241\\002\\000\\004\\000",
                "\\000\\000\\000\\000\\000\\000\\000\\000",
                "\\377\\377\\000\\000\\001\\000\\000\\000'\n",
                "printf '0 packets captured\\n0 packets received by filter\\n",
                "0 packets dropped by kernel\\n' >&2\n",
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "sanitized-pcap-helper",
            CapturePolicy::default(),
            Some(EncryptionKey::new([73; 32])),
        )
        .unwrap();
        let handle = start_program(
            helper.as_os_str(),
            &[],
            "lo",
            "tcp port 12345".to_owned(),
            "test_filter",
            1024,
            store.clone(),
        )
        .await
        .unwrap();
        let report = handle.stop().await.unwrap();
        assert!(report.exit_success);
        assert_eq!(report.bytes, PCAP_GLOBAL_HEADER_BYTES as u64);
        assert_eq!(report.packets_dropped, Some(0));
        store.shutdown().await.unwrap();
    }

    fn pcap_header() -> [u8; PCAP_GLOBAL_HEADER_BYTES] {
        [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ]
    }
}
