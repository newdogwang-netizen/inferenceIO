use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::Context;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::Builder as TempBuilder;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::Command,
};
use uuid::Uuid;

use crate::{
    artifact_export::{ArtifactKind, export_optional_tls_keys, export_sensitive_artifact},
    audit,
    blob_keys::read_blob_reference,
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    model::{EventEnvelope, PayloadRef, TerminalState},
    secure_fs::{commit_path_noreplace, read_regular_limited},
    storage::{MAX_SINGLE_BLOB_BYTES, StorageError, for_each_run_event_with_key},
};

const REPORT_SCHEMA_VERSION: u32 = 3;
const COMPLETENESS_BOUNDARY: &str = "target-network-namespace-ip-transport";
const MIN_TSHARK_MAJOR: u64 = 4;
const MIN_TSHARK_MINOR: u64 = 4;
const MAX_TSHARK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TSHARK_VERSION_BYTES: usize = 64 * 1024;
const MAX_TSHARK_STDERR_TAIL: usize = 64 * 1024;
const MAX_TSHARK_LINE_BYTES: usize = 129 * 1024 * 1024;
const MAX_TSHARK_STDOUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_DECODED_ROWS: u64 = 10_000_000;
const MAX_DECODED_STREAMS: usize = 100_000;
const MAX_QUERY_KEYS: usize = 128;
const MAX_METHOD_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 16 * 1024;
const COLUMN_COUNT: usize = 22;

const TSHARK_FIELDS: [&str; COLUMN_COUNT] = [
    "frame.number",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "http.request.method",
    "http.request.uri",
    "http.response.code",
    "http.file_data",
    "http2.streamid",
    "http2.type",
    "http2.length",
    "http2.flags",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.status",
    "http2.data.data",
    "http2.pad_length",
    "tls.record.content_type",
];

#[derive(Debug, Clone, Serialize)]
pub struct TransportAuditReport {
    pub schema_version: u32,
    pub run_id: String,
    pub completeness_boundary: &'static str,
    pub tshark: TsharkReport,
    pub pcap_records: u64,
    pub pcap_bytes: u64,
    pub tls_key_records: u64,
    pub tls_key_bytes: u64,
    pub decoded_rows: u64,
    pub tcp_streams_observed: u64,
    pub tcp_streams_without_http_decode: u64,
    pub decoded_streams: u64,
    pub http1_streams: u64,
    pub http2_streams: u64,
    pub tls_decrypted_streams: u64,
    pub proxy_attempts: u64,
    pub proxy_attempts_non_model_excluded: u64,
    pub proxy_attempts_unknown_classification: u64,
    pub proxy_attempts_eligible: u64,
    pub matched_attempts: u64,
    pub missing_from_wire: u64,
    pub extra_on_wire: u64,
    pub ambiguous_signature_groups: u64,
    pub manifest_capture_drops: u64,
    pub source_coverage: SourceCoverageReport,
    pub streams: Vec<DecodedStream>,
    pub gaps: Vec<AuditGap>,
    pub payload_diff_passed: bool,
    pub complete: bool,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsharkReport {
    pub path: PathBuf,
    pub version: String,
    pub sha256: String,
    pub stderr_bytes: u64,
    pub stderr_sha256: String,
    pub stderr_tail_omitted_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SourceCoverageReport {
    pub manifest_claim: String,
    pub task_egress_pcap: bool,
    pub proxy_only_egress_enforced: bool,
    pub transparent_egress_enforced: bool,
    pub transparent_tls: bool,
    pub unknown_tls_surfaces: u64,
    pub unparsed_connections: u64,
    pub process_network_scan_gaps: u64,
    pub process_scan_failures: u64,
    pub processes_running_at_stop: u64,
    pub connections_open_at_stop: u64,
    pub unknown_egress: u64,
    pub task_netns_denied_packets: u64,
    pub blocked_unknown_egress_indicators: u64,
    pub process_observation_gaps_replaced_by_wire_boundary: u64,
    pub model_bypass_connections: u64,
    pub possible_quic_connections: u64,
    pub unresolved_correlations: u64,
    pub all_attempts_have_terminal_state: bool,
    pub captured_request_payloads_complete: bool,
    pub captured_response_payloads_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecodedStream {
    pub protocol: &'static str,
    pub tcp_stream: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http2_stream_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<SafeTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub request: BodyDigest,
    pub response: BodyDigest,
    pub tls_decrypted: bool,
    pub request_end_observed: bool,
    pub response_end_observed: bool,
    pub eligible_for_diff: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SafeTarget {
    pub path: String,
    pub query_keys: Vec<String>,
    pub query_parameter_count: u64,
    pub query_keys_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BodyDigest {
    pub bytes: u64,
    pub sha256: String,
    pub chunks: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditGap {
    pub reason: String,
    pub occurrences: u64,
}

#[derive(Default)]
struct BodyAccumulator {
    digest: Sha256,
    bytes: u64,
    chunks: u64,
}

impl BodyAccumulator {
    fn append_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("decoded body byte count overflow")?;
        self.chunks = self.chunks.saturating_add(1);
        self.digest.update(bytes);
        Ok(())
    }

    fn append_hex(&mut self, value: &str) -> anyhow::Result<u64> {
        let mut high = None;
        let mut decoded = vec![0_u8; 64 * 1024].into_boxed_slice();
        let mut used = 0_usize;
        let mut total = 0_u64;
        for byte in value.bytes() {
            if matches!(byte, b':' | b' ' | b'\r' | b'\n') {
                continue;
            }
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => anyhow::bail!("tshark emitted a non-hexadecimal body field"),
            };
            if let Some(high) = high.take() {
                decoded[used] = (high << 4) | nibble;
                used += 1;
                total = total.saturating_add(1);
                if used == decoded.len() {
                    self.digest.update(&decoded[..]);
                    used = 0;
                }
            } else {
                high = Some(nibble);
            }
        }
        anyhow::ensure!(
            high.is_none(),
            "tshark emitted an odd-length hexadecimal body field"
        );
        if used > 0 {
            self.digest.update(&decoded[..used]);
        }
        if total > 0 {
            self.bytes = self
                .bytes
                .checked_add(total)
                .context("decoded body byte count overflow")?;
            self.chunks = self.chunks.saturating_add(1);
        }
        Ok(total)
    }

    fn finish(&self) -> BodyDigest {
        BodyDigest {
            bytes: self.bytes,
            sha256: format!("sha256:{}", hex::encode(self.digest.clone().finalize())),
            chunks: self.chunks,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Endpoint(String);

#[derive(Default)]
struct StreamBuilder {
    method: Option<String>,
    target: Option<SafeTarget>,
    status: Option<u16>,
    bodies: BTreeMap<Endpoint, BodyAccumulator>,
    ended: BTreeSet<Endpoint>,
    tls_decrypted: bool,
    gaps: BTreeSet<String>,
}

#[derive(Default)]
struct Http1Connection {
    client: Option<Endpoint>,
    request_count: u64,
    response_count: u64,
}

#[derive(Default)]
struct Decoder {
    rows: u64,
    tcp_streams: BTreeSet<u64>,
    h1_connections: BTreeMap<u64, Http1Connection>,
    h1_streams: BTreeMap<(u64, u64), StreamBuilder>,
    h2_clients: BTreeMap<u64, Endpoint>,
    h2_streams: BTreeMap<(u64, u32), StreamBuilder>,
    gaps: BTreeMap<String, u64>,
}

#[derive(Default)]
struct ProxyAttempt {
    method: Option<String>,
    target: Option<SafeTarget>,
    status: Option<u16>,
    request: BodyAccumulator,
    response: BodyAccumulator,
    next_request_chunk: u64,
    next_response_chunk: u64,
    request_finished: bool,
    attempt_finished: bool,
    model_traffic: Option<bool>,
    gaps: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Signature {
    method: String,
    path: String,
    status: u16,
    request_bytes: u64,
    request_sha256: String,
    response_bytes: u64,
    response_sha256: String,
}

struct Comparison {
    proxy_attempts: u64,
    proxy_non_model_excluded: u64,
    proxy_unknown_classification: u64,
    proxy_eligible: u64,
    matched: u64,
    missing: u64,
    extra: u64,
    ambiguous: u64,
}

struct StderrReport {
    bytes: u64,
    sha256: String,
    omitted: u64,
}

struct DecodeResult {
    rows: u64,
    tcp_streams: u64,
    tcp_streams_without_http_decode: u64,
    streams: Vec<DecodedStream>,
    gaps: BTreeMap<String, u64>,
    stderr: StderrReport,
}

pub async fn audit_transport(
    run_dir: &Path,
    output: &Path,
    key: &EncryptionKey,
    timeout: Duration,
) -> anyhow::Result<TransportAuditReport> {
    anyhow::ensure!(
        !timeout.is_zero(),
        "transport audit timeout must be positive"
    );
    let run_dir = run_dir.canonicalize()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let output_name = output
        .file_name()
        .context("transport audit output has no file name")?;
    let output = parent.join(output_name);
    anyhow::ensure!(
        !output.starts_with(&run_dir),
        "transport audit output must be outside the source run"
    );
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite transport audit output"
    );

    let inspection = inspect_run_with_key(&run_dir, true, Some(key))?;
    anyhow::ensure!(
        inspection.manifest.status != "running",
        "refusing to audit a run that is still being recorded"
    );
    anyhow::ensure!(
        inspection.manifest_authenticated == Some(true),
        "transport audit requires an authenticated encrypted manifest"
    );
    anyhow::ensure!(
        inspection.log.discarded_tail_bytes == 0,
        "run has an uncommitted event tail"
    );
    anyhow::ensure!(
        inspection.missing_blobs.is_empty(),
        "run references missing blobs"
    );
    anyhow::ensure!(
        inspection.corrupt_blobs.is_empty(),
        "run contains corrupt blobs"
    );
    let effective_key = inspection
        .manifest
        .effective_encryption_key(Some(key))?
        .context("transport audit requires an encrypted run")?;
    let task_egress_enforced = inspection
        .manifest
        .coverage
        .capture_sources
        .iter()
        .any(|source| source == "pcap:task-egress")
        && inspection
            .manifest
            .coverage
            .capture_sources
            .iter()
            .any(|source| {
                matches!(
                    source.as_str(),
                    "network:task-netns-proxy-only" | "network:task-netns-transparent"
                )
            });
    let audit_root = run_dir
        .parent()
        .context("source run has no parent directory")?;
    audit::append(
        audit_root,
        "transport_audit",
        "intent",
        &inspection.manifest.run_id,
        None,
    )?;

    let temporary = TempBuilder::new()
        .prefix(".iorec-transport-audit-")
        .tempdir_in(&parent)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let pcap_path = temporary.path().join("capture.pcap");
    let keys_path = temporary.path().join("tls.keys");
    let pcap = export_sensitive_artifact(&run_dir, &pcap_path, key, ArtifactKind::Pcap)?;
    let keys = if task_egress_enforced {
        export_optional_tls_keys(&run_dir, &keys_path, key)?
    } else {
        export_sensitive_artifact(&run_dir, &keys_path, key, ArtifactKind::TlsKeys)?
    };
    let tshark_path = trusted_tshark_path().context("no trusted tshark executable is installed")?;
    let (version, executable_sha256) = inspect_tshark(&tshark_path, temporary.path()).await?;
    let decode = tokio::time::timeout(
        timeout,
        decode_capture(&tshark_path, &pcap_path, &keys_path, temporary.path()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("tshark decoding exceeded its deadline"))??;
    let proxy = collect_proxy_attempts(&run_dir, &inspection.manifest.run_id, &effective_key)?;
    let comparison = compare_attempts(&proxy, &decode.streams);
    let manifest_coverage = &inspection.manifest.coverage;
    let task_egress_pcap = manifest_coverage
        .capture_sources
        .iter()
        .any(|source| source == "pcap:task-egress");
    let proxy_only_egress_enforced = manifest_coverage
        .capture_sources
        .iter()
        .any(|source| source == "network:task-netns-proxy-only");
    let wire_boundary_replaces_polling = task_egress_pcap
        && proxy_only_egress_enforced
        && decode.tcp_streams > 0
        && decode.tcp_streams_without_http_decode == 0;
    let source_coverage = SourceCoverageReport {
        manifest_claim: manifest_coverage.claim.clone(),
        task_egress_pcap,
        proxy_only_egress_enforced,
        transparent_egress_enforced: manifest_coverage
            .capture_sources
            .iter()
            .any(|source| source == "network:task-netns-transparent"),
        transparent_tls: manifest_coverage
            .capture_sources
            .iter()
            .any(|source| source == "proxy:transparent-task-netns-tls"),
        unknown_tls_surfaces: manifest_coverage.unknown_tls_surfaces,
        unparsed_connections: manifest_coverage.unparsed_connections,
        process_network_scan_gaps: manifest_coverage.process_network_scan_gaps,
        process_scan_failures: manifest_coverage.process_scan_failures,
        processes_running_at_stop: manifest_coverage.processes_running_at_stop,
        connections_open_at_stop: manifest_coverage.connections_open_at_stop,
        unknown_egress: manifest_coverage.unknown_egress,
        task_netns_denied_packets: manifest_coverage.task_netns_denied_packets,
        blocked_unknown_egress_indicators: manifest_coverage.blocked_unknown_egress_indicators,
        process_observation_gaps_replaced_by_wire_boundary: if wire_boundary_replaces_polling {
            manifest_coverage
                .process_network_scan_gaps
                .saturating_add(manifest_coverage.process_scan_failures)
        } else {
            0
        },
        model_bypass_connections: manifest_coverage.model_bypass_connections,
        possible_quic_connections: manifest_coverage.possible_quic_connections,
        unresolved_correlations: manifest_coverage.unresolved_correlations,
        all_attempts_have_terminal_state: manifest_coverage.all_attempts_have_terminal_state,
        captured_request_payloads_complete: manifest_coverage.captured_request_payloads_complete,
        captured_response_payloads_complete: manifest_coverage.captured_response_payloads_complete,
    };

    let mut gaps = decode.gaps;
    if decode.stderr.bytes > 0 {
        add_gap(&mut gaps, "tshark_diagnostic_output", 1);
    }
    if inspection.manifest.coverage.capture_drops > 0 {
        add_gap(
            &mut gaps,
            "manifest_capture_drops",
            inspection.manifest.coverage.capture_drops,
        );
    }
    let proxy_ineligible = comparison
        .proxy_attempts
        .saturating_sub(comparison.proxy_eligible);
    if proxy_ineligible > 0 {
        add_gap(
            &mut gaps,
            "proxy_attempt_ineligible_for_diff",
            proxy_ineligible,
        );
    }
    if comparison.proxy_attempts == 0 {
        add_gap(&mut gaps, "no_proxy_attempts_for_diff", 1);
    }
    if comparison.ambiguous > 0 {
        add_gap(
            &mut gaps,
            "ambiguous_payload_signature_group",
            comparison.ambiguous,
        );
    }
    if comparison.proxy_unknown_classification > 0 {
        add_gap(
            &mut gaps,
            "proxy_attempt_traffic_class_unknown",
            comparison.proxy_unknown_classification,
        );
    }
    if comparison.missing > 0 {
        add_gap(
            &mut gaps,
            "proxy_attempt_missing_from_wire",
            comparison.missing,
        );
    }
    if comparison.extra > 0 {
        add_gap(
            &mut gaps,
            "decoded_wire_stream_without_proxy_match",
            comparison.extra,
        );
    }
    if decode.streams.is_empty() {
        add_gap(&mut gaps, "no_http_streams_decoded", 1);
    }
    let tls_decrypted_streams = decode
        .streams
        .iter()
        .filter(|stream| stream.tls_decrypted)
        .count();
    add_source_coverage_gaps(
        &mut gaps,
        &source_coverage,
        tls_decrypted_streams,
        decode.tcp_streams > 0 && decode.tcp_streams_without_http_decode == 0,
    );
    let payload_diff_passed = comparison.proxy_attempts > 0
        && comparison.proxy_attempts == comparison.proxy_eligible
        && comparison.missing == 0
        && comparison.extra == 0;
    let complete = payload_diff_passed && gaps.is_empty();
    let http1_streams = decode
        .streams
        .iter()
        .filter(|stream| stream.protocol == "http/1.1")
        .count();
    let http2_streams = decode.streams.len().saturating_sub(http1_streams);
    let report = TransportAuditReport {
        schema_version: REPORT_SCHEMA_VERSION,
        run_id: inspection.manifest.run_id.clone(),
        completeness_boundary: COMPLETENESS_BOUNDARY,
        tshark: TsharkReport {
            path: tshark_path,
            version,
            sha256: executable_sha256,
            stderr_bytes: decode.stderr.bytes,
            stderr_sha256: decode.stderr.sha256,
            stderr_tail_omitted_bytes: decode.stderr.omitted,
        },
        pcap_records: pcap.records,
        pcap_bytes: pcap.bytes,
        tls_key_records: keys.records,
        tls_key_bytes: keys.bytes,
        decoded_rows: decode.rows,
        tcp_streams_observed: decode.tcp_streams,
        tcp_streams_without_http_decode: decode.tcp_streams_without_http_decode,
        decoded_streams: u64::try_from(decode.streams.len()).unwrap_or(u64::MAX),
        http1_streams: u64::try_from(http1_streams).unwrap_or(u64::MAX),
        http2_streams: u64::try_from(http2_streams).unwrap_or(u64::MAX),
        tls_decrypted_streams: u64::try_from(tls_decrypted_streams).unwrap_or(u64::MAX),
        proxy_attempts: comparison.proxy_attempts,
        proxy_attempts_non_model_excluded: comparison.proxy_non_model_excluded,
        proxy_attempts_unknown_classification: comparison.proxy_unknown_classification,
        proxy_attempts_eligible: comparison.proxy_eligible,
        matched_attempts: comparison.matched,
        missing_from_wire: comparison.missing,
        extra_on_wire: comparison.extra,
        ambiguous_signature_groups: comparison.ambiguous,
        manifest_capture_drops: inspection.manifest.coverage.capture_drops,
        source_coverage,
        streams: decode.streams,
        gaps: gaps
            .into_iter()
            .map(|(reason, occurrences)| AuditGap {
                reason,
                occurrences,
            })
            .collect(),
        payload_diff_passed,
        complete,
        output: output.clone(),
    };
    write_report(&parent, &output, &report)?;
    audit::append(
        audit_root,
        "transport_audit",
        "complete",
        &inspection.manifest.run_id,
        Some(serde_json::json!({
            "decoded_streams": report.decoded_streams,
            "matched_attempts": report.matched_attempts,
            "payload_diff_passed": report.payload_diff_passed,
            "complete": report.complete,
        })),
    )?;
    Ok(report)
}

fn add_source_coverage_gaps(
    gaps: &mut BTreeMap<String, u64>,
    coverage: &SourceCoverageReport,
    tls_decrypted_streams: usize,
    all_tcp_streams_decoded: bool,
) {
    let model_egress_enforced =
        coverage.proxy_only_egress_enforced || coverage.transparent_egress_enforced;
    let cleartext_task_egress = coverage.proxy_only_egress_enforced
        || (coverage.transparent_egress_enforced && !coverage.transparent_tls);
    if tls_decrypted_streams == 0 && !(coverage.task_egress_pcap && cleartext_task_egress) {
        add_gap(gaps, "no_tls_streams_decrypted", 1);
    }
    if !coverage.task_egress_pcap {
        add_gap(gaps, "packet_capture_scope_not_task_egress", 1);
    }
    if !model_egress_enforced {
        add_gap(gaps, "model_egress_not_enforced", 1);
    }
    // Logical agent-to-inference correlation is reported in source_coverage but is
    // not a transport-integrity condition: this audit independently pairs the
    // complete proxy-attempt and wire-stream multisets by their body signatures.
    let wire_boundary_proves_no_unaccounted_traffic =
        coverage.task_egress_pcap && coverage.proxy_only_egress_enforced && all_tcp_streams_decoded;
    let unknown_tls_surfaces =
        if coverage.transparent_egress_enforced || wire_boundary_proves_no_unaccounted_traffic {
            0
        } else {
            coverage.unknown_tls_surfaces
        };
    let structured_unparsed = coverage
        .process_network_scan_gaps
        .saturating_add(coverage.process_scan_failures)
        .saturating_add(coverage.processes_running_at_stop)
        .saturating_add(coverage.connections_open_at_stop);
    // A complete proxy-only task-egress packet boundary replaces polling-based
    // process attribution, but it cannot extend the capture window past live
    // descendants or connections. Preserve any count not explained by the
    // structured fields as a blocking legacy/unknown gap.
    let unexplained_unparsed = coverage
        .unparsed_connections
        .saturating_sub(structured_unparsed);
    let blocking_unparsed = if wire_boundary_proves_no_unaccounted_traffic {
        coverage
            .processes_running_at_stop
            .saturating_add(coverage.connections_open_at_stop)
            .saturating_add(unexplained_unparsed)
    } else {
        coverage.unparsed_connections.max(structured_unparsed)
    };
    for (reason, occurrences) in [
        ("unknown_tls_surface", unknown_tls_surfaces),
        ("unparsed_connection", blocking_unparsed),
        ("unknown_egress", coverage.unknown_egress),
        ("model_bypass_connection", coverage.model_bypass_connections),
        (
            "possible_quic_connection",
            coverage.possible_quic_connections,
        ),
    ] {
        if occurrences > 0 {
            add_gap(gaps, reason, occurrences);
        }
    }
    if !coverage.all_attempts_have_terminal_state {
        add_gap(gaps, "transport_attempt_terminal_state_missing", 1);
    }
    if !coverage.captured_request_payloads_complete {
        add_gap(gaps, "proxy_request_payload_incomplete", 1);
    }
    if !coverage.captured_response_payloads_complete {
        add_gap(gaps, "proxy_response_payload_incomplete", 1);
    }
}

fn write_report(parent: &Path, output: &Path, report: &TransportAuditReport) -> anyhow::Result<()> {
    let temporary = parent.join(format!(
        ".iorec-transport-report-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> anyhow::Result<()> {
        serde_json::to_writer_pretty(&mut file, report)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = commit_path_noreplace(parent, &temporary, output) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("commit transport audit without overwriting destination");
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn trusted_tshark_path() -> Option<PathBuf> {
    [
        Path::new("/usr/bin/tshark"),
        Path::new("/usr/local/bin/tshark"),
    ]
    .into_iter()
    .find_map(|path| validate_root_executable(path).then(|| path.to_path_buf()))
}

fn validate_root_executable(path: &Path) -> bool {
    let Ok(metadata) = path.symlink_metadata() else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o100 == 0
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return false;
    }
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let Ok(metadata) = directory.symlink_metadata() else {
            return false;
        };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return false;
        }
        parent = directory.parent();
    }
    true
}

async fn inspect_tshark(path: &Path, private_home: &Path) -> anyhow::Result<(String, String)> {
    let bytes = read_regular_limited(
        path,
        usize::try_from(MAX_TSHARK_BYTES).unwrap_or(usize::MAX),
    )?;
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let mut child = Command::new(path);
    child
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", private_home)
        .env("XDG_CONFIG_HOME", private_home)
        .current_dir(private_home);
    let mut child = child.spawn().context("start tshark version inspection")?;
    let stdout = child
        .stdout
        .take()
        .context("tshark version stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("tshark version stderr is unavailable")?;
    let stdout_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout
            .take(u64::try_from(MAX_TSHARK_VERSION_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut output)
            .await?;
        Ok::<Vec<u8>, io::Error>(output)
    });
    let stderr_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr
            .take(u64::try_from(MAX_TSHARK_VERSION_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut output)
            .await?;
        Ok::<Vec<u8>, io::Error>(output)
    });
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let status = child.wait().await?;
        let stdout = stdout_task.await.map_err(io::Error::other)??;
        let stderr = stderr_task.await.map_err(io::Error::other)??;
        Ok::<_, io::Error>((status, stdout, stderr))
    })
    .await
    .map_err(|_| anyhow::anyhow!("tshark version inspection exceeded its deadline"))??;
    anyhow::ensure!(
        result.0.success(),
        "trusted tshark version inspection failed"
    );
    anyhow::ensure!(
        result.1.len() <= MAX_TSHARK_VERSION_BYTES,
        "tshark version output exceeded its limit"
    );
    anyhow::ensure!(
        result.2.len() <= MAX_TSHARK_VERSION_BYTES,
        "tshark version diagnostics exceeded their limit"
    );
    let first = std::str::from_utf8(&result.1)?
        .lines()
        .next()
        .context("tshark version output is empty")?;
    let prefix = "TShark (Wireshark) ";
    let number = first
        .strip_prefix(prefix)
        .context("tshark version output is unrecognized")?
        .trim_end_matches('.');
    let mut components = number.split('.');
    let major = components
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let minor = components
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    anyhow::ensure!(
        major.zip(minor).is_some_and(|(major, minor)| {
            major > MIN_TSHARK_MAJOR || (major == MIN_TSHARK_MAJOR && minor >= MIN_TSHARK_MINOR)
        }),
        "tshark 4.4 or newer is required"
    );
    Ok((first.to_owned(), sha256))
}

async fn decode_capture(
    tshark: &Path,
    pcap: &Path,
    keylog: &Path,
    private_home: &Path,
) -> anyhow::Result<DecodeResult> {
    let keylog_preference = format!("tls.keylog_file:{}", keylog.display());
    let mut command = Command::new(tshark);
    command
        .arg("-n")
        .arg("-2")
        .arg("-r")
        .arg(pcap)
        .arg("-o")
        .arg(keylog_preference)
        .arg("-Y")
        .arg("tcp")
        .arg("-T")
        .arg("fields")
        .arg("-E")
        .arg("separator=/t")
        .arg("-E")
        .arg("occurrence=a")
        .arg("-E")
        .arg("aggregator=|")
        .arg("-E")
        .arg("quote=n")
        .arg("-E")
        .arg("escape=y")
        .arg("--temp-dir")
        .arg(private_home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", private_home)
        .env("XDG_CONFIG_HOME", private_home)
        .current_dir(private_home);
    for field in TSHARK_FIELDS {
        command.arg("-e").arg(field);
    }
    let mut child = command.spawn().context("start trusted tshark decoder")?;
    let stdout = child
        .stdout
        .take()
        .context("tshark stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("tshark stderr is unavailable")?;
    let stderr_task = tokio::spawn(drain_stderr(stderr));
    let mut stdout = BufReader::new(stdout);
    let mut decoder = Decoder::default();
    let mut line = Vec::new();
    let mut stdout_bytes = 0_u64;
    loop {
        line.clear();
        let bytes = read_bounded_line(&mut stdout, &mut line, MAX_TSHARK_LINE_BYTES).await?;
        if bytes == 0 {
            break;
        }
        stdout_bytes = stdout_bytes
            .checked_add(u64::try_from(bytes).unwrap_or(u64::MAX))
            .context("tshark stdout byte count overflow")?;
        anyhow::ensure!(
            stdout_bytes <= MAX_TSHARK_STDOUT_BYTES,
            "tshark stdout exceeded its byte limit"
        );
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        decoder.process_line(std::str::from_utf8(&line)?)?;
    }
    let status = child.wait().await?;
    let stderr = stderr_task
        .await
        .context("tshark diagnostic task failed")??;
    anyhow::ensure!(
        status.success(),
        "trusted tshark decoder exited unsuccessfully"
    );
    let rows = decoder.rows;
    let (streams, gaps, tcp_streams, tcp_streams_without_http_decode) = decoder.finish();
    Ok(DecodeResult {
        rows,
        tcp_streams,
        tcp_streams_without_http_decode,
        streams,
        gaps,
        stderr,
    })
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    output: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    let mut total = 0_usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total);
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        total = total.checked_add(consumed).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "tshark line length overflow")
        })?;
        if output.len() < limit {
            let retained = consumed.min(limit - output.len());
            output.extend_from_slice(&available[..retained]);
        }
        let ended = available[..consumed].last() == Some(&b'\n');
        reader.consume(consumed);
        if total > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tshark output line exceeded its byte limit",
            ));
        }
        if ended {
            return Ok(total);
        }
    }
}

async fn drain_stderr<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<StderrReport> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut tail = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        digest.update(&buffer[..read]);
        if read >= MAX_TSHARK_STDERR_TAIL {
            tail.clear();
            tail.extend_from_slice(&buffer[read - MAX_TSHARK_STDERR_TAIL..read]);
        } else {
            let needed = tail.len().saturating_add(read);
            if needed > MAX_TSHARK_STDERR_TAIL {
                tail.drain(..needed - MAX_TSHARK_STDERR_TAIL);
            }
            tail.extend_from_slice(&buffer[..read]);
        }
    }
    Ok(StderrReport {
        bytes: total,
        sha256: format!("sha256:{}", hex::encode(digest.finalize())),
        omitted: total.saturating_sub(u64::try_from(tail.len()).unwrap_or(u64::MAX)),
    })
}

impl Decoder {
    fn process_line(&mut self, line: &str) -> anyhow::Result<()> {
        self.rows = self.rows.saturating_add(1);
        anyhow::ensure!(
            self.rows <= MAX_DECODED_ROWS,
            "decoded packet-row limit exceeded"
        );
        let columns: Vec<&str> = line.split('\t').collect();
        anyhow::ensure!(
            columns.len() == COLUMN_COUNT,
            "tshark output column count changed"
        );
        let frame =
            scalar_u64(columns[0], "frame number")?.context("tshark row has no frame number")?;
        let tcp_stream =
            scalar_u64(columns[1], "TCP stream")?.context("tshark row has no TCP stream")?;
        self.tcp_streams.insert(tcp_stream);
        let source = endpoint(columns[2], columns[3], columns[4])?;
        let destination = endpoint(columns[5], columns[6], columns[7])?;
        let tls_decrypted = !columns[21].is_empty();
        if tls_decrypted {
            let _ = multi_parse_u8(columns[21], "TLS record content type")?;
        }
        let has_h2 = !columns[12].is_empty();
        if has_h2 {
            self.process_h2(
                frame,
                tcp_stream,
                &source,
                &destination,
                &columns[12..21],
                tls_decrypted,
            )?;
        } else {
            self.process_h1(
                tcp_stream,
                &source,
                &destination,
                &columns[8..12],
                tls_decrypted,
            )?;
        }
        let total = self.h1_streams.len().saturating_add(self.h2_streams.len());
        anyhow::ensure!(
            total <= MAX_DECODED_STREAMS,
            "decoded HTTP stream limit exceeded"
        );
        Ok(())
    }

    fn process_h1(
        &mut self,
        tcp_stream: u64,
        source: &Endpoint,
        _destination: &Endpoint,
        columns: &[&str],
        tls_decrypted: bool,
    ) -> anyhow::Result<()> {
        let method = scalar_text(columns[0], "HTTP method", MAX_METHOD_BYTES)?;
        let target = (!columns[1].is_empty())
            .then(|| safe_target(columns[1]))
            .transpose()?;
        let status = scalar_u16(columns[2], "HTTP status")?;
        let mut selected = None;
        if let Some(method) = method {
            let (key, direction_conflict) = {
                let connection = self.h1_connections.entry(tcp_stream).or_default();
                connection.request_count = connection.request_count.saturating_add(1);
                connection.client.get_or_insert_with(|| source.clone());
                (
                    (tcp_stream, connection.request_count),
                    connection.client.as_ref() != Some(source),
                )
            };
            if direction_conflict {
                self.gap("http1_client_direction_conflict", 1);
            }
            let stream = self.h1_streams.entry(key).or_default();
            set_once(
                &mut stream.method,
                method,
                &mut stream.gaps,
                "method_conflict",
            );
            if let Some(target) = target {
                set_once(
                    &mut stream.target,
                    target,
                    &mut stream.gaps,
                    "target_conflict",
                );
            }
            stream.ended.insert(source.clone());
            stream.tls_decrypted |= tls_decrypted;
            selected = Some(key);
        }
        if let Some(status) = status {
            let key = {
                let connection = self.h1_connections.entry(tcp_stream).or_default();
                connection.response_count = connection.response_count.saturating_add(1);
                (tcp_stream, connection.response_count)
            };
            let stream = self.h1_streams.entry(key).or_default();
            set_once(
                &mut stream.status,
                status,
                &mut stream.gaps,
                "status_conflict",
            );
            stream.ended.insert(source.clone());
            stream.tls_decrypted |= tls_decrypted;
            selected = Some(key);
        }
        if !columns[3].is_empty() {
            let key = selected.or_else(|| {
                let connection = self.h1_connections.get(&tcp_stream)?;
                let client = connection.client.as_ref()?;
                let index = if client == source {
                    connection.request_count
                } else {
                    connection.response_count
                };
                (index > 0).then_some((tcp_stream, index))
            });
            if let Some(key) = key {
                let stream = self.h1_streams.entry(key).or_default();
                stream.tls_decrypted |= tls_decrypted;
                for value in multi(columns[3]) {
                    stream
                        .bodies
                        .entry(source.clone())
                        .or_default()
                        .append_hex(value)?;
                }
            } else {
                self.gap("http1_body_without_message", 1);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_h2(
        &mut self,
        _frame: u64,
        tcp_stream: u64,
        source: &Endpoint,
        destination: &Endpoint,
        columns: &[&str],
        tls_decrypted: bool,
    ) -> anyhow::Result<()> {
        let ids = multi_parse_u32(columns[0], "HTTP/2 stream ID")?;
        let types = multi_parse_u8(columns[1], "HTTP/2 frame type")?;
        let lengths = multi_parse_u64(columns[2], "HTTP/2 frame length")?;
        let flags = multi_parse_flags(columns[3])?;
        anyhow::ensure!(
            ids.len() == types.len() && ids.len() == lengths.len() && ids.len() == flags.len(),
            "HTTP/2 frame fields lost their occurrence alignment"
        );
        let header_positions: Vec<(usize, u32)> = ids
            .iter()
            .copied()
            .enumerate()
            .filter(|(index, id)| *id > 0 && types[*index] == 1)
            .collect();
        let methods = multi(columns[4]);
        let paths = multi(columns[5]);
        let statuses = multi(columns[6]);
        if !methods.is_empty() {
            if methods.len() == header_positions.len() && paths.len() == methods.len() {
                self.h2_clients
                    .entry(tcp_stream)
                    .or_insert_with(|| source.clone());
                if self.h2_clients.get(&tcp_stream) != Some(source) {
                    self.gap("http2_client_direction_conflict", 1);
                }
                for ((_, id), (method, path)) in header_positions
                    .iter()
                    .zip(methods.iter().zip(paths.iter()))
                {
                    let stream = self.h2_streams.entry((tcp_stream, *id)).or_default();
                    let method = bounded_text(method, "HTTP/2 method", MAX_METHOD_BYTES)?;
                    let target = safe_target(path)?;
                    set_once(
                        &mut stream.method,
                        method,
                        &mut stream.gaps,
                        "method_conflict",
                    );
                    set_once(
                        &mut stream.target,
                        target,
                        &mut stream.gaps,
                        "target_conflict",
                    );
                }
            } else {
                self.gap("http2_request_headers_ambiguous", 1);
            }
        }
        if !statuses.is_empty() {
            if statuses.len() == header_positions.len() {
                self.h2_clients
                    .entry(tcp_stream)
                    .or_insert_with(|| destination.clone());
                if self.h2_clients.get(&tcp_stream) != Some(destination) {
                    self.gap("http2_server_direction_conflict", 1);
                }
                for ((_, id), status) in header_positions.iter().zip(statuses.iter()) {
                    let status = status
                        .parse::<u16>()
                        .context("tshark emitted an invalid HTTP/2 status")?;
                    let stream = self.h2_streams.entry((tcp_stream, *id)).or_default();
                    set_once(
                        &mut stream.status,
                        status,
                        &mut stream.gaps,
                        "status_conflict",
                    );
                }
            } else {
                self.gap("http2_response_headers_ambiguous", 1);
            }
        }

        let data_positions: Vec<usize> = types
            .iter()
            .enumerate()
            .filter_map(|(index, kind)| (*kind == 0 && ids[index] > 0).then_some(index))
            .collect();
        let padding_positions: Vec<usize> = types
            .iter()
            .enumerate()
            .filter_map(|(index, kind)| matches!(*kind, 0 | 1 | 5).then_some(index))
            .collect();
        let padding = multi_parse_u64(columns[8], "HTTP/2 pad length")?;
        let padding_aligned = padding.len() == padding_positions.len();
        if !padding_aligned {
            self.gap("http2_padding_occurrence_alignment_failed", 1);
        }
        let padding_by_position: BTreeMap<usize, u64> = if padding_aligned {
            padding_positions.into_iter().zip(padding).collect()
        } else {
            BTreeMap::new()
        };
        if padding_by_position
            .iter()
            .any(|(index, padding)| flags[*index] & 0x8 == 0 && *padding != 0)
        {
            self.gap("http2_unpadded_frame_has_pad_length", 1);
        }
        let body_lengths: BTreeMap<usize, u64> = data_positions
            .iter()
            .copied()
            .map(|index| {
                let overhead = if flags[index] & 0x8 == 0 {
                    0
                } else {
                    padding_by_position
                        .get(&index)
                        .copied()
                        .unwrap_or(lengths[index])
                        .saturating_add(1)
                };
                (index, lengths[index].saturating_sub(overhead))
            })
            .collect();
        let body_positions: Vec<usize> = data_positions
            .iter()
            .copied()
            .filter(|index| body_lengths[index] > 0)
            .collect();
        let data = multi(columns[7]);
        let aligned_all = data.len() == data_positions.len();
        let aligned_body = data.len() == body_positions.len();
        if !data_positions.is_empty() && !aligned_all && !aligned_body {
            self.gap("http2_data_occurrence_alignment_failed", 1);
        } else {
            let mut all_index = 0_usize;
            let mut body_index = 0_usize;
            for index in data_positions {
                let value = if aligned_all {
                    let value = data[all_index];
                    all_index += 1;
                    Some(value)
                } else if body_lengths[&index] > 0 {
                    let value = data[body_index];
                    body_index += 1;
                    Some(value)
                } else {
                    None
                };
                if body_lengths[&index] > 0 {
                    let value = value.context("HTTP/2 positive DATA frame has no body field")?;
                    let stream = self.h2_streams.entry((tcp_stream, ids[index])).or_default();
                    let decoded = stream
                        .bodies
                        .entry(source.clone())
                        .or_default()
                        .append_hex(value)?;
                    if decoded != body_lengths[&index] {
                        stream.gaps.insert("data_length_mismatch".to_owned());
                        self.gap("http2_data_length_mismatch", 1);
                    }
                }
            }
        }
        for (index, id) in ids.iter().copied().enumerate() {
            if id == 0 {
                continue;
            }
            let stream = self.h2_streams.entry((tcp_stream, id)).or_default();
            stream.tls_decrypted |= tls_decrypted;
            if flags[index] & 0x1 != 0 {
                stream.ended.insert(source.clone());
            }
        }
        Ok(())
    }

    fn gap(&mut self, reason: &str, occurrences: u64) {
        add_gap(&mut self.gaps, reason, occurrences);
    }

    fn finish(mut self) -> (Vec<DecodedStream>, BTreeMap<String, u64>, u64, u64) {
        let mut streams = Vec::with_capacity(self.h1_streams.len() + self.h2_streams.len());
        for ((tcp_stream, _index), mut builder) in self.h1_streams {
            let client = self
                .h1_connections
                .get(&tcp_stream)
                .and_then(|connection| connection.client.clone());
            let stream = finish_stream("http/1.1", tcp_stream, None, client, &mut builder, false);
            for reason in &stream.gaps {
                add_gap(&mut self.gaps, reason, 1);
            }
            streams.push(stream);
        }
        for ((tcp_stream, stream_id), mut builder) in self.h2_streams {
            let client = self.h2_clients.get(&tcp_stream).cloned();
            let stream = finish_stream(
                "http/2",
                tcp_stream,
                Some(stream_id),
                client,
                &mut builder,
                true,
            );
            for reason in &stream.gaps {
                add_gap(&mut self.gaps, reason, 1);
            }
            streams.push(stream);
        }
        streams.sort_by_key(|stream| (stream.tcp_stream, stream.http2_stream_id.unwrap_or(0)));
        let decoded_tcp_streams: BTreeSet<u64> =
            streams.iter().map(|stream| stream.tcp_stream).collect();
        let tcp_streams_without_http_decode =
            self.tcp_streams.difference(&decoded_tcp_streams).count();
        if tcp_streams_without_http_decode > 0 {
            add_gap(
                &mut self.gaps,
                "tcp_stream_without_http_decode",
                u64::try_from(tcp_streams_without_http_decode).unwrap_or(u64::MAX),
            );
        }
        (
            streams,
            self.gaps,
            u64::try_from(self.tcp_streams.len()).unwrap_or(u64::MAX),
            u64::try_from(tcp_streams_without_http_decode).unwrap_or(u64::MAX),
        )
    }
}

fn finish_stream(
    protocol: &'static str,
    tcp_stream: u64,
    http2_stream_id: Option<u32>,
    client: Option<Endpoint>,
    builder: &mut StreamBuilder,
    require_end: bool,
) -> DecodedStream {
    let mut gaps = std::mem::take(&mut builder.gaps);
    let Some(client) = client else {
        gaps.insert("stream_client_direction_unknown".to_owned());
        if require_end {
            gaps.insert("http2_request_end_missing".to_owned());
            gaps.insert("http2_response_end_missing".to_owned());
        }
        return DecodedStream {
            protocol,
            tcp_stream,
            http2_stream_id,
            method: builder.method.take(),
            target: builder.target.take(),
            status: builder.status.take(),
            request: BodyAccumulator::default().finish(),
            response: BodyAccumulator::default().finish(),
            tls_decrypted: builder.tls_decrypted,
            request_end_observed: false,
            response_end_observed: false,
            eligible_for_diff: false,
            gaps: gaps.into_iter().collect(),
        };
    };
    let request = builder.bodies.remove(&client).unwrap_or_default();
    let request_end = builder.ended.contains(&client);
    let response_endpoints: Vec<Endpoint> = builder
        .bodies
        .keys()
        .chain(builder.ended.iter())
        .filter(|endpoint| *endpoint != &client)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if response_endpoints.len() > 1 {
        gaps.insert("stream_has_multiple_server_endpoints".to_owned());
    }
    let response_endpoint = response_endpoints.first();
    let response = response_endpoint
        .and_then(|endpoint| builder.bodies.remove(endpoint))
        .unwrap_or_default();
    let response_end = response_endpoint.is_some_and(|endpoint| builder.ended.contains(endpoint));
    if builder.method.is_none() {
        gaps.insert("stream_method_missing".to_owned());
    }
    if builder.target.is_none() {
        gaps.insert("stream_target_missing".to_owned());
    }
    if builder.status.is_none() {
        gaps.insert("stream_status_missing".to_owned());
    }
    if require_end && !request_end {
        gaps.insert("http2_request_end_missing".to_owned());
    }
    if require_end && !response_end {
        gaps.insert("http2_response_end_missing".to_owned());
    }
    let eligible = gaps.is_empty();
    DecodedStream {
        protocol,
        tcp_stream,
        http2_stream_id,
        method: builder.method.take(),
        target: builder.target.take(),
        status: builder.status.take(),
        request: request.finish(),
        response: response.finish(),
        tls_decrypted: builder.tls_decrypted,
        request_end_observed: request_end || !require_end,
        response_end_observed: response_end || !require_end,
        eligible_for_diff: eligible,
        gaps: gaps.into_iter().collect(),
    }
}

fn collect_proxy_attempts(
    run_dir: &Path,
    expected_run_id: &str,
    key: &EncryptionKey,
) -> Result<BTreeMap<String, ProxyAttempt>, StorageError> {
    let mut attempts = BTreeMap::new();
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        expected_run_id,
        Some(key),
        |event| {
            if event.source != "proxy" {
                return Ok(());
            }
            let Some(attempt_id) = event.ids.attempt_id.as_ref() else {
                return Ok(());
            };
            let attempt = attempts
                .entry(attempt_id.clone())
                .or_insert_with(|| ProxyAttempt {
                    next_request_chunk: 1,
                    next_response_chunk: 1,
                    ..ProxyAttempt::default()
                });
            match event.event.as_str() {
                "transport_request_started" => {
                    attempt.method = event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("method"))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    attempt.target = event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("uri"))
                        .and_then(safe_target_from_proxy);
                    attempt.model_traffic = event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("traffic_class"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| match value {
                            "model" => Some(true),
                            "other" => Some(false),
                            _ => None,
                        });
                }
                "transport_response_started" => {
                    attempt.status = event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("status"))
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|value| u16::try_from(value).ok());
                }
                "request_body_chunk" => append_proxy_chunk(
                    run_dir,
                    &event,
                    key,
                    &mut attempt.request,
                    &mut attempt.next_request_chunk,
                    &mut attempt.gaps,
                )?,
                "response_body_chunk" => append_proxy_chunk(
                    run_dir,
                    &event,
                    key,
                    &mut attempt.response,
                    &mut attempt.next_response_chunk,
                    &mut attempt.gaps,
                )?,
                "request_body_finished" => {
                    attempt.request_finished =
                        event.terminal_state == Some(TerminalState::Complete);
                    if !attempt.request_finished {
                        attempt.gaps.insert("proxy_request_incomplete".to_owned());
                    }
                }
                "transport_attempt_finished" => {
                    attempt.attempt_finished =
                        event.terminal_state == Some(TerminalState::Complete);
                    if !attempt.attempt_finished {
                        attempt.gaps.insert("proxy_response_incomplete".to_owned());
                    }
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    Ok(attempts)
}

fn append_proxy_chunk(
    run_dir: &Path,
    event: &EventEnvelope,
    key: &EncryptionKey,
    body: &mut BodyAccumulator,
    expected_sequence: &mut u64,
    gaps: &mut BTreeSet<String>,
) -> Result<(), StorageError> {
    let sequence = event
        .normalized
        .as_ref()
        .and_then(|value| value.get("chunk_sequence"))
        .and_then(serde_json::Value::as_u64);
    if sequence != Some(*expected_sequence) {
        gaps.insert("proxy_body_sequence_gap".to_owned());
    }
    *expected_sequence = expected_sequence.saturating_add(1);
    let Some(reference) = event.raw.as_ref() else {
        gaps.insert("proxy_body_chunk_not_captured".to_owned());
        return Ok(());
    };
    if reference.truncated {
        gaps.insert("proxy_body_chunk_truncated".to_owned());
        return Ok(());
    }
    let plaintext = load_blob(run_dir, reference, key)?;
    let observed = event
        .normalized
        .as_ref()
        .and_then(|value| value.get("observed_size"))
        .and_then(serde_json::Value::as_u64);
    if observed != Some(u64::try_from(plaintext.len()).unwrap_or(u64::MAX)) {
        gaps.insert("proxy_body_size_mismatch".to_owned());
        return Ok(());
    }
    body.append_bytes(&plaintext).map_err(|error| {
        StorageError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            error.to_string(),
        ))
    })?;
    Ok(())
}

fn load_blob(
    run_dir: &Path,
    reference: &PayloadRef,
    key: &EncryptionKey,
) -> Result<Vec<u8>, StorageError> {
    read_blob_reference(run_dir, reference, Some(key), MAX_SINGLE_BLOB_BYTES)
        .map_err(StorageError::Io)
}

fn compare_attempts(
    proxy: &BTreeMap<String, ProxyAttempt>,
    streams: &[DecodedStream],
) -> Comparison {
    let proxy_attempts = u64::try_from(
        proxy
            .values()
            .filter(|attempt| attempt.model_traffic == Some(true))
            .count(),
    )
    .unwrap_or(u64::MAX);
    let proxy_non_model_excluded = u64::try_from(
        proxy
            .values()
            .filter(|attempt| attempt.model_traffic == Some(false))
            .count(),
    )
    .unwrap_or(u64::MAX);
    let proxy_unknown_classification = u64::try_from(
        proxy
            .values()
            .filter(|attempt| attempt.model_traffic.is_none())
            .count(),
    )
    .unwrap_or(u64::MAX);
    let mut proxy_counts = BTreeMap::<Signature, u64>::new();
    let mut non_model_counts = BTreeMap::<Signature, u64>::new();
    let mut proxy_eligible = 0_u64;
    for attempt in proxy.values() {
        if attempt.model_traffic.is_none()
            || !attempt.request_finished
            || !attempt.attempt_finished
            || !attempt.gaps.is_empty()
        {
            continue;
        }
        let (Some(method), Some(target), Some(status)) = (
            attempt.method.as_ref(),
            attempt.target.as_ref(),
            attempt.status,
        ) else {
            continue;
        };
        let request = attempt.request.finish();
        let response = attempt.response.finish();
        let signature = Signature {
            method: method.clone(),
            path: target.path.clone(),
            status,
            request_bytes: request.bytes,
            request_sha256: request.sha256,
            response_bytes: response.bytes,
            response_sha256: response.sha256,
        };
        if attempt.model_traffic == Some(true) {
            *proxy_counts.entry(signature).or_default() += 1;
            proxy_eligible = proxy_eligible.saturating_add(1);
        } else {
            *non_model_counts.entry(signature).or_default() += 1;
        }
    }
    let mut wire_counts = BTreeMap::<Signature, u64>::new();
    for stream in streams.iter().filter(|stream| stream.eligible_for_diff) {
        let (Some(method), Some(target), Some(status)) = (
            stream.method.as_ref(),
            stream.target.as_ref(),
            stream.status,
        ) else {
            continue;
        };
        let signature = Signature {
            method: method.clone(),
            path: target.path.clone(),
            status,
            request_bytes: stream.request.bytes,
            request_sha256: stream.request.sha256.clone(),
            response_bytes: stream.response.bytes,
            response_sha256: stream.response.sha256.clone(),
        };
        *wire_counts.entry(signature).or_default() += 1;
    }
    for (signature, excluded) in non_model_counts {
        if let Some(observed) = wire_counts.get_mut(&signature) {
            *observed = observed.saturating_sub(excluded);
        }
    }
    let keys: BTreeSet<Signature> = proxy_counts
        .keys()
        .chain(wire_counts.keys())
        .cloned()
        .collect();
    let mut matched = 0_u64;
    let mut missing = 0_u64;
    let mut extra = 0_u64;
    let mut ambiguous = 0_u64;
    for key in keys {
        let proxy = proxy_counts.get(&key).copied().unwrap_or_default();
        let wire = wire_counts.get(&key).copied().unwrap_or_default();
        matched = matched.saturating_add(proxy.min(wire));
        missing = missing.saturating_add(proxy.saturating_sub(wire));
        extra = extra.saturating_add(wire.saturating_sub(proxy));
        if proxy > 1 || wire > 1 {
            ambiguous = ambiguous.saturating_add(1);
        }
    }
    Comparison {
        proxy_attempts,
        proxy_non_model_excluded,
        proxy_unknown_classification,
        proxy_eligible,
        matched,
        missing,
        extra,
        ambiguous,
    }
}

fn endpoint(ipv4: &str, ipv6: &str, port: &str) -> anyhow::Result<Endpoint> {
    let address = if ipv4.is_empty() { ipv6 } else { ipv4 };
    anyhow::ensure!(!address.is_empty(), "tshark row has no IP endpoint");
    let port = port
        .parse::<u16>()
        .context("tshark row has an invalid TCP port")?;
    let address = address
        .parse::<std::net::IpAddr>()
        .context("tshark row has an invalid IP address")?;
    Ok(Endpoint(
        std::net::SocketAddr::new(address, port).to_string(),
    ))
}

fn multi(value: &str) -> Vec<&str> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split('|').collect()
    }
}

fn scalar_u64(value: &str, name: &str) -> anyhow::Result<Option<u64>> {
    if value.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        !value.contains('|'),
        "tshark emitted multiple {name} values"
    );
    Ok(Some(value.parse().with_context(|| {
        format!("tshark emitted an invalid {name}")
    })?))
}

fn scalar_u16(value: &str, name: &str) -> anyhow::Result<Option<u16>> {
    scalar_u64(value, name)?
        .map(|value| u16::try_from(value).with_context(|| format!("tshark {name} is too large")))
        .transpose()
}

fn scalar_text(value: &str, name: &str, limit: usize) -> anyhow::Result<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        !value.contains('|'),
        "tshark emitted multiple {name} values"
    );
    bounded_text(value, name, limit).map(Some)
}

fn bounded_text(value: &str, name: &str, limit: usize) -> anyhow::Result<String> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control),
        "tshark {name} is empty, oversized, or control-bearing"
    );
    Ok(value.to_owned())
}

fn multi_parse_u8(value: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    multi(value)
        .into_iter()
        .map(|value| {
            value
                .parse::<u8>()
                .with_context(|| format!("invalid {name}"))
        })
        .collect()
}

fn multi_parse_u32(value: &str, name: &str) -> anyhow::Result<Vec<u32>> {
    multi(value)
        .into_iter()
        .map(|value| {
            value
                .parse::<u32>()
                .with_context(|| format!("invalid {name}"))
        })
        .collect()
}

fn multi_parse_u64(value: &str, name: &str) -> anyhow::Result<Vec<u64>> {
    multi(value)
        .into_iter()
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("invalid {name}"))
        })
        .collect()
}

fn multi_parse_flags(value: &str) -> anyhow::Result<Vec<u8>> {
    multi(value)
        .into_iter()
        .map(|value| {
            let value = value.strip_prefix("0x").unwrap_or(value);
            u8::from_str_radix(value, 16).context("invalid HTTP/2 flags")
        })
        .collect()
}

fn safe_target(value: &str) -> anyhow::Result<SafeTarget> {
    anyhow::ensure!(
        value.len() <= MAX_PATH_BYTES,
        "decoded request target exceeds its limit"
    );
    let (path, query) = value
        .split_once('?')
        .map_or((value, None), |(path, query)| (path, Some(query)));
    let path = bounded_text(path, "request path", MAX_PATH_BYTES)?;
    let mut query_keys = Vec::new();
    let mut query_parameter_count = 0_u64;
    if let Some(query) = query {
        for key in query
            .split('&')
            .filter_map(|pair| pair.split('=').next())
            .filter(|key| !key.is_empty())
        {
            query_parameter_count = query_parameter_count.saturating_add(1);
            if query_keys.len() < MAX_QUERY_KEYS {
                query_keys.push(safe_query_key(key));
            }
        }
    }
    Ok(SafeTarget {
        path,
        query_keys,
        query_parameter_count,
        query_keys_truncated: query_parameter_count
            > u64::try_from(MAX_QUERY_KEYS).unwrap_or(u64::MAX),
    })
}

fn safe_query_key(value: &str) -> String {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        format!(
            "sha256:{}:{}",
            hex::encode(Sha256::digest(value.as_bytes())),
            value.len()
        )
    } else {
        value.to_owned()
    }
}

fn safe_target_from_proxy(value: &serde_json::Value) -> Option<SafeTarget> {
    let path = value.get("path")?.as_str()?.to_owned();
    let query_keys = value
        .get("query_keys")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let query_parameter_count = value.get("query_parameter_count")?.as_u64()?;
    let query_keys_truncated = value.get("query_keys_truncated")?.as_bool()?;
    Some(SafeTarget {
        path,
        query_keys,
        query_parameter_count,
        query_keys_truncated,
    })
}

fn set_once<T: PartialEq>(
    slot: &mut Option<T>,
    value: T,
    gaps: &mut BTreeSet<String>,
    conflict: &str,
) {
    if slot.as_ref().is_some_and(|existing| existing != &value) {
        gaps.insert(conflict.to_owned());
    } else {
        slot.get_or_insert(value);
    }
}

fn add_gap(gaps: &mut BTreeMap<String, u64>, reason: &str, occurrences: u64) {
    let count = gaps.entry(reason.to_owned()).or_default();
    *count = count.saturating_add(occurrences.max(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(columns: &[&str; COLUMN_COUNT - 1]) -> String {
        let mut row = columns.join("\t");
        row.push('\t');
        row
    }

    #[test]
    fn reconstructs_http2_request_response_without_reassembly_echo() {
        let mut request = row(&[
            "4",
            "0",
            "127.0.0.1",
            "",
            "50000",
            "127.0.0.1",
            "",
            "8443",
            "",
            "",
            "",
            "",
            "0|0|1|1",
            "4|8|1|0",
            "18|4|20|5",
            "0x00|0x00|0x04|0x01",
            "POST",
            "/v1/responses?api_key=secret",
            "",
            "68656c6c6f",
            "0|0",
        ]);
        request.push_str("23");
        let response = row(&[
            "8",
            "0",
            "127.0.0.1",
            "",
            "8443",
            "127.0.0.1",
            "",
            "50000",
            "",
            "",
            "",
            "",
            "1|1|1|1",
            "1|0|0|0",
            "10|3|2|0",
            "0x04|0x00|0x00|0x01",
            "",
            "",
            "200",
            "776f72|6c64|776f726c64",
            "0|0|0|0",
        ]);
        let mut decoder = Decoder::default();
        decoder.process_line(&request).unwrap();
        decoder.process_line(&response).unwrap();
        let (streams, gaps, _, _) = decoder.finish();
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(streams.len(), 1);
        let stream = &streams[0];
        assert_eq!(stream.protocol, "http/2");
        assert_eq!(stream.http2_stream_id, Some(1));
        assert_eq!(stream.method.as_deref(), Some("POST"));
        assert_eq!(stream.target.as_ref().unwrap().path, "/v1/responses");
        assert_eq!(stream.target.as_ref().unwrap().query_keys, ["api_key"]);
        assert_eq!(stream.status, Some(200));
        assert_eq!(stream.request.bytes, 5);
        assert_eq!(stream.response.bytes, 5);
        assert!(stream.tls_decrypted);
        assert_eq!(
            stream.response.sha256,
            format!("sha256:{}", hex::encode(Sha256::digest(b"world")))
        );
        assert!(stream.eligible_for_diff);
    }

    #[test]
    fn marks_h2_occurrence_ambiguity_and_missing_ends_incomplete() {
        let value = row(&[
            "1",
            "0",
            "127.0.0.1",
            "",
            "50000",
            "127.0.0.1",
            "",
            "8443",
            "",
            "",
            "",
            "",
            "1|3",
            "1|1",
            "10|10",
            "0x04|0x04",
            "POST",
            "/one",
            "",
            "",
            "0|0",
        ]);
        let mut decoder = Decoder::default();
        decoder.process_line(&value).unwrap();
        let (streams, gaps, _, _) = decoder.finish();
        assert!(gaps.contains_key("http2_request_headers_ambiguous"));
        assert!(streams.iter().all(|stream| !stream.eligible_for_diff));
        assert!(streams.iter().all(|stream| {
            stream
                .gaps
                .contains(&"http2_request_end_missing".to_owned())
        }));
    }

    #[test]
    fn validates_http2_padded_data_length_without_hashing_padding() {
        let padded = row(&[
            "1",
            "0",
            "127.0.0.1",
            "",
            "50000",
            "127.0.0.1",
            "",
            "8443",
            "",
            "",
            "",
            "",
            "1|1",
            "1|0",
            "20|8",
            "0x04|0x09",
            "POST",
            "/padded",
            "",
            "68656c6c6f",
            "0|2",
        ]);
        let mut decoder = Decoder::default();
        decoder.process_line(&padded).unwrap();
        let (streams, gaps, _, _) = decoder.finish();
        assert!(!gaps.contains_key("http2_data_length_mismatch"));
        assert_eq!(streams[0].request.bytes, 5);
        assert_eq!(
            streams[0].request.sha256,
            format!("sha256:{}", hex::encode(Sha256::digest(b"hello")))
        );

        let short = padded.replace("68656c6c6f", "68656c6c");
        let mut decoder = Decoder::default();
        decoder.process_line(&short).unwrap();
        let (streams, gaps, _, _) = decoder.finish();
        assert_eq!(gaps.get("http2_data_length_mismatch"), Some(&1));
        assert!(streams[0].gaps.contains(&"data_length_mismatch".to_owned()));
    }

    #[test]
    fn reconstructs_http1_and_compares_signature_multiplicity() {
        let request = row(&[
            "4",
            "0",
            "127.0.0.1",
            "",
            "50000",
            "127.0.0.1",
            "",
            "8080",
            "POST",
            "/v1/chat?token=secret",
            "",
            "6869",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]);
        let response = row(&[
            "8",
            "0",
            "127.0.0.1",
            "",
            "8080",
            "127.0.0.1",
            "",
            "50000",
            "",
            "/v1/chat?token=secret",
            "200",
            "6f6b",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]);
        let mut decoder = Decoder::default();
        decoder.process_line(&request).unwrap();
        decoder.process_line(&response).unwrap();
        let (streams, gaps, _, _) = decoder.finish();
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(
            streams[0].request.sha256,
            format!("sha256:{}", hex::encode(Sha256::digest(b"hi")))
        );
        assert_eq!(streams[0].response.bytes, 2);

        let mut proxy = BTreeMap::new();
        let mut attempt = ProxyAttempt {
            method: Some("POST".to_owned()),
            target: Some(safe_target("/v1/chat?token=else").unwrap()),
            status: Some(200),
            next_request_chunk: 1,
            next_response_chunk: 1,
            request_finished: true,
            attempt_finished: true,
            model_traffic: Some(true),
            ..ProxyAttempt::default()
        };
        attempt.request.append_bytes(b"hi").unwrap();
        attempt.response.append_bytes(b"ok").unwrap();
        proxy.insert("attempt".to_owned(), attempt);
        let comparison = compare_attempts(&proxy, &streams);
        assert_eq!(comparison.matched, 1);
        assert_eq!(comparison.missing, 0);
        assert_eq!(comparison.extra, 0);
    }

    #[test]
    fn reports_tcp_streams_that_never_decode_as_http() {
        let opaque = row(&[
            "1",
            "7",
            "127.0.0.1",
            "",
            "50000",
            "127.0.0.1",
            "",
            "8080",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]);
        let mut decoder = Decoder::default();
        decoder.process_line(&opaque).unwrap();
        let (streams, gaps, tcp_streams, opaque_streams) = decoder.finish();
        assert!(streams.is_empty());
        assert_eq!(tcp_streams, 1);
        assert_eq!(opaque_streams, 1);
        assert_eq!(gaps.get("tcp_stream_without_http_decode"), Some(&1));
    }

    #[test]
    fn excludes_complete_non_model_proxy_traffic_from_wire_diff() {
        let target = safe_target("/health").unwrap();
        let stream = DecodedStream {
            protocol: "http/1.1",
            tcp_stream: 7,
            http2_stream_id: None,
            method: Some("GET".to_owned()),
            target: Some(target.clone()),
            status: Some(200),
            request: BodyAccumulator::default().finish(),
            response: BodyAccumulator::default().finish(),
            tls_decrypted: false,
            request_end_observed: true,
            response_end_observed: true,
            eligible_for_diff: true,
            gaps: Vec::new(),
        };
        let attempt = ProxyAttempt {
            method: Some("GET".to_owned()),
            target: Some(target),
            status: Some(200),
            next_request_chunk: 1,
            next_response_chunk: 1,
            request_finished: true,
            attempt_finished: true,
            model_traffic: Some(false),
            ..ProxyAttempt::default()
        };
        let comparison =
            compare_attempts(&BTreeMap::from([("health".to_owned(), attempt)]), &[stream]);
        assert_eq!(comparison.proxy_attempts, 0);
        assert_eq!(comparison.proxy_non_model_excluded, 1);
        assert_eq!(comparison.proxy_unknown_classification, 0);
        assert_eq!(comparison.extra, 0);
    }

    #[test]
    fn task_egress_policy_replaces_inactive_tls_markers_when_all_tcp_is_decoded() {
        let complete = SourceCoverageReport {
            manifest_claim: "best-effort".to_owned(),
            task_egress_pcap: true,
            proxy_only_egress_enforced: true,
            transparent_egress_enforced: false,
            transparent_tls: false,
            unknown_tls_surfaces: 3,
            unparsed_connections: 0,
            process_network_scan_gaps: 0,
            process_scan_failures: 0,
            processes_running_at_stop: 0,
            connections_open_at_stop: 0,
            unknown_egress: 0,
            task_netns_denied_packets: 0,
            blocked_unknown_egress_indicators: 0,
            process_observation_gaps_replaced_by_wire_boundary: 0,
            model_bypass_connections: 0,
            possible_quic_connections: 0,
            unresolved_correlations: 9,
            all_attempts_have_terminal_state: true,
            captured_request_payloads_complete: true,
            captured_response_payloads_complete: true,
        };
        let mut gaps = BTreeMap::new();
        add_source_coverage_gaps(&mut gaps, &complete, 0, true);
        assert!(gaps.is_empty());

        let mut opaque_stream = BTreeMap::new();
        add_source_coverage_gaps(&mut opaque_stream, &complete, 0, false);
        assert_eq!(opaque_stream.get("unknown_tls_surface"), Some(&3));

        let mut attribution_gap = complete.clone();
        attribution_gap.unparsed_connections = 1;
        attribution_gap.process_network_scan_gaps = 1;
        let mut attribution_gaps = BTreeMap::new();
        add_source_coverage_gaps(&mut attribution_gaps, &attribution_gap, 0, true);
        assert!(attribution_gaps.is_empty());

        attribution_gap.processes_running_at_stop = 1;
        attribution_gap.unparsed_connections = 2;
        add_source_coverage_gaps(&mut attribution_gaps, &attribution_gap, 0, true);
        assert_eq!(attribution_gaps.get("unparsed_connection"), Some(&1));

        let mut legacy_gap = complete.clone();
        legacy_gap.unparsed_connections = 1;
        let mut legacy_gaps = BTreeMap::new();
        add_source_coverage_gaps(&mut legacy_gaps, &legacy_gap, 0, true);
        assert_eq!(legacy_gaps.get("unparsed_connection"), Some(&1));

        let mut shared_listener = complete.clone();
        shared_listener.task_egress_pcap = false;
        shared_listener.proxy_only_egress_enforced = false;
        add_source_coverage_gaps(&mut gaps, &shared_listener, 1, true);
        assert_eq!(gaps.get("packet_capture_scope_not_task_egress"), Some(&1));
        assert_eq!(gaps.get("model_egress_not_enforced"), Some(&1));

        gaps.clear();
        let mut unknown = complete;
        unknown.unknown_egress = 2;
        add_source_coverage_gaps(&mut gaps, &unknown, 0, true);
        assert_eq!(gaps.get("unknown_egress"), Some(&2));

        gaps.clear();
        let mut transparent = unknown.clone();
        transparent.unknown_egress = 0;
        transparent.unknown_tls_surfaces = 3;
        transparent.proxy_only_egress_enforced = false;
        transparent.transparent_egress_enforced = true;
        transparent.transparent_tls = true;
        add_source_coverage_gaps(&mut gaps, &transparent, 1, true);
        assert!(gaps.is_empty());
        add_source_coverage_gaps(&mut gaps, &transparent, 0, true);
        assert_eq!(gaps.get("no_tls_streams_decrypted"), Some(&1));
    }

    #[tokio::test]
    async fn bounded_line_reader_rejects_oversized_unterminated_input() {
        let input = vec![b'x'; 32];
        let mut reader = BufReader::new(input.as_slice());
        let mut output = Vec::new();
        let error = read_bounded_line(&mut reader, &mut output, 16)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(output.len(), 16);
    }

    #[test]
    fn root_executable_trust_rejects_user_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tshark");
        fs::write(&path, b"fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!validate_root_executable(&path));
        assert!(validate_root_executable(Path::new("/usr/bin/tshark")));
    }
}
