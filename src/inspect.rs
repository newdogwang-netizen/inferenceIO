use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
};

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

use crate::{
    blob_keys::{self, load_class_key},
    crypto::{EncryptionKey, is_encrypted_blob},
    manifest::{self, CoverageCounts, Manifest},
    model::{EventEnvelope, TerminalState},
    secure_fs::{read_regular_limited, read_regular_prefix},
    state,
    storage::{
        MAX_ENCODED_BLOB_BYTES, MAX_SINGLE_BLOB_BYTES, RecoveryReport, StorageError,
        for_each_run_event_with_key, recover_events_with_key,
    },
};

const MAX_BLOB_DIRECTORY_ENTRIES: usize = 250_000;
const MAX_TRACKED_BLOB_REFERENCES: usize = 250_000;
const MAX_TRACKED_IDENTIFIERS: usize = 100_000;
const MAX_TRACKED_LABELS: usize = 1_024;
const MAX_TRACKED_PROTOCOLS: usize = 128;
const MAX_TRACKED_EGRESS_CLASSES: usize = 8;

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub manifest: Manifest,
    pub manifest_authenticated: Option<bool>,
    pub log: RecoveryReport,
    pub blob_files: u64,
    pub missing_blobs: Vec<String>,
    pub corrupt_blobs: Vec<String>,
    pub erased_blob_classes: Vec<String>,
    pub erased_blobs: Vec<String>,
    pub pending_erasure_classes: Vec<String>,
    pub pending_erasure_blobs: Vec<String>,
}

pub fn inspect_run(run_dir: &Path, verify_blobs: bool) -> Result<Inspection, StorageError> {
    inspect_run_with_key(run_dir, verify_blobs, None)
}

pub fn inspect_run_with_key(
    run_dir: &Path,
    verify_blobs: bool,
    encryption: Option<&EncryptionKey>,
) -> Result<Inspection, StorageError> {
    let provided_encryption = encryption;
    let mut manifest = manifest::read(&run_dir.join("manifest.json"))?;
    let class_keyed = blob_keys::has_keyring(run_dir)?;
    match manifest
        .storage
        .encryption
        .as_ref()
        .and_then(|metadata| metadata.blob_key_management.as_deref())
    {
        Some(blob_keys::BLOB_KEY_MANAGEMENT_V1) if !class_keyed => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "manifest requires class-keyed blobs but the key directory is absent",
            )
            .into());
        }
        None if class_keyed => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "class-keyed blob directory is not declared by the manifest",
            )
            .into());
        }
        _ => {}
    }
    let effective_encryption = manifest.effective_encryption_key(provided_encryption)?;
    let manifest_authenticated = manifest.verify_authentication(provided_encryption)?;
    let encryption = effective_encryption.as_ref();
    let mut erased_classes = BTreeSet::new();
    let mut pending_erasure_classes = BTreeSet::new();
    let mut pending_unavailable_classes = BTreeSet::new();
    if class_keyed {
        let run_key = encryption.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "class-keyed inspection requires the matching run key",
            )
        })?;
        for class in blob_keys::BlobClass::ALL {
            match blob_keys::read_erasure_state(run_dir, run_key, class)? {
                Some(state) if state.phase == blob_keys::ClassErasurePhase::Complete => {
                    match fs::symlink_metadata(blob_keys::envelope_path(run_dir, class)) {
                        Ok(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "completed class erasure retains a key-envelope path",
                            )
                            .into());
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                    erased_classes.insert(class);
                }
                Some(_) => {
                    pending_erasure_classes.insert(class);
                    match blob_keys::load_class_key(run_dir, run_key, class) {
                        Ok(Some(_)) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            pending_unavailable_classes.insert(class);
                        }
                        Ok(None) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "pending class erasure unexpectedly uses a legacy key",
                            )
                            .into());
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                None => {
                    blob_keys::load_class_key(run_dir, run_key, class)?.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "active blob class has no key envelope",
                        )
                    })?;
                }
            }
        }
    }
    // The inspection below derives fresh counts and coverage fields. The tag
    // authenticates the on-disk source manifest, not this derived view.
    manifest.authentication = None;
    if manifest_authenticated == Some(false) {
        manifest.coverage.known_gaps.push(
            "encrypted legacy manifest has no authenticator; event and blob AEAD remain independently verified"
                .to_owned(),
        );
    }
    let summary = summarize_events(run_dir, &manifest.run_id, encryption)?;
    manifest.counts = summary.counts;
    manifest.coverage.capture_sources.extend(summary.sources);
    manifest.coverage.capture_sources.sort();
    manifest.coverage.capture_sources.dedup();
    manifest.coverage.all_attempts_have_terminal_state =
        manifest.counts.transport_attempts == summary.terminal_attempts;
    manifest.coverage.observed_protocols = summary.protocols;
    if manifest
        .coverage
        .observed_protocols
        .contains_key("upstream:http/2")
    {
        manifest.coverage.known_gaps.push(
            "upstream HTTP/2 was observed through the endpoint client; wire stream IDs were not independently decoded"
                .to_owned(),
        );
    }
    if manifest
        .coverage
        .observed_protocols
        .contains_key("upstream:unknown")
    {
        manifest
            .coverage
            .known_gaps
            .push("an upstream HTTP protocol version was not recognized".to_owned());
    }
    let unknown_egress_indicators = u64::try_from(summary.unknown_egress.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(summary.task_netns_denied_packets > 0));
    let proxy_only_egress_enforced = manifest
        .coverage
        .capture_sources
        .iter()
        .any(|source| source == "network:task-netns-proxy-only");
    manifest.coverage.unknown_egress = if proxy_only_egress_enforced {
        0
    } else {
        unknown_egress_indicators
    };
    manifest.coverage.task_netns_denied_packets = summary.task_netns_denied_packets;
    manifest.coverage.blocked_unknown_egress_indicators = if proxy_only_egress_enforced {
        unknown_egress_indicators
    } else {
        0
    };
    manifest.coverage.model_bypass_connections =
        u64::try_from(summary.model_bypass_connections.len()).unwrap_or(u64::MAX);
    manifest.coverage.observed_egress_classes.clear();
    for (class, connections) in &summary.egress_classes {
        manifest.coverage.observed_egress_classes.insert(
            class.clone(),
            u64::try_from(connections.len()).unwrap_or(u64::MAX),
        );
    }
    manifest.coverage.possible_quic_connections =
        u64::try_from(summary.possible_quic_connections.len()).unwrap_or(u64::MAX);
    let mut observed_tls_instances = summary.tls_surfaces;
    for surface in &manifest.command.executable_tls_surfaces {
        observed_tls_instances.insert((0, 0, surface.clone()));
    }
    manifest.coverage.observed_tls_surfaces.clear();
    for (_, _, surface) in &observed_tls_instances {
        *manifest
            .coverage
            .observed_tls_surfaces
            .entry(surface.clone())
            .or_default() += 1;
    }
    manifest.coverage.unknown_tls_surfaces =
        u64::try_from(observed_tls_instances.len()).unwrap_or(u64::MAX);
    manifest.coverage.process_network_scan_gaps = summary
        .network_scan_gaps
        .values()
        .copied()
        .fold(0, u64::saturating_add);
    manifest.coverage.process_scan_failures = summary.process_scan_failures;
    manifest.coverage.processes_running_at_stop = summary.processes_running_at_stop;
    manifest.coverage.connections_open_at_stop = summary.connections_open_at_stop;
    manifest.coverage.unparsed_connections = summary
        .network_scan_gaps
        .iter()
        .filter(|((_, _, _, reason), _)| {
            reason.starts_with("socket_rows_unparsed")
                || reason.starts_with("socket_rows_omitted_at_connection_limit")
        })
        .map(|(_, occurrences)| *occurrences)
        .fold(0, u64::saturating_add);
    let state_graph = state::analyze_with_key(run_dir, provided_encryption)?;
    manifest.coverage.unresolved_state_references = state_graph.unresolved_count();
    if state_graph.analysis_truncated {
        manifest.coverage.known_gaps.push(format!(
            "state analysis reached its safety limit; {} observations were omitted",
            state_graph.omitted_observations
        ));
    }
    manifest.coverage.unresolved_payload_references = summary.unresolved_payload_references;
    manifest.coverage.unresolved_correlations = summary.unresolved_correlations;
    manifest.coverage.captured_request_payloads_complete = !summary.model_attempts.is_empty()
        && summary
            .model_attempts
            .is_subset(&summary.complete_request_payloads)
        && summary.incomplete_request_payloads.is_empty()
        && manifest.coverage.unresolved_payload_references == 0
        && manifest.coverage.capture_drops == 0;
    manifest.coverage.captured_response_payloads_complete = !summary.model_attempts.is_empty()
        && summary
            .model_attempts
            .is_subset(&summary.complete_response_payloads)
        && summary.incomplete_response_payloads.is_empty()
        && manifest.coverage.capture_drops == 0;
    if manifest.coverage.unresolved_payload_references > 0 {
        manifest.coverage.known_gaps.push(format!(
            "{} external payload references were not independently snapshotted",
            manifest.coverage.unresolved_payload_references
        ));
    }
    if manifest.coverage.unparsed_connections > 0 {
        manifest.coverage.known_gaps.push(format!(
            "{} process socket-table rows could not be parsed or were omitted at the connection limit",
            manifest.coverage.unparsed_connections
        ));
    }
    if manifest.coverage.process_network_scan_gaps > manifest.coverage.unparsed_connections {
        manifest.coverage.known_gaps.push(format!(
            "{} process network observations had polling or permission gaps; independently captured wire boundaries may replace these attribution-only gaps",
            manifest
                .coverage
                .process_network_scan_gaps
                .saturating_sub(manifest.coverage.unparsed_connections)
        ));
    }
    if manifest.coverage.possible_quic_connections > 0 {
        manifest.coverage.known_gaps.push(format!(
            "{} external UDP connections may carry unsupported QUIC/HTTP3 traffic",
            manifest.coverage.possible_quic_connections
        ));
    }
    if manifest.coverage.model_bypass_connections > 0 {
        manifest.coverage.known_gaps.push(format!(
            "{} target connections matched the configured model upstream while bypassing the recorder listener",
            manifest.coverage.model_bypass_connections
        ));
    }
    if summary.processes_running_at_stop > 0 {
        manifest.coverage.known_gaps.push(format!(
            "the run ended while {} target processes were still running; activity after the recorder boundary was not captured",
            summary.processes_running_at_stop
        ));
    }
    if summary.connections_open_at_stop > 0 {
        manifest.coverage.known_gaps.push(format!(
            "the run ended with {} target-process network connections still open",
            summary.connections_open_at_stop
        ));
    }
    if summary.task_cgroup_remaining > 0 {
        manifest.coverage.known_gaps.push(format!(
            "the task cgroup retained {} target processes at the recording boundary and could not be removed",
            summary.task_cgroup_remaining
        ));
    }
    if summary.task_cgroup_cleanup_errors > 0 {
        manifest.coverage.known_gaps.push(format!(
            "{} task-cgroup cleanup operations could not be verified",
            summary.task_cgroup_cleanup_errors
        ));
    }
    if summary.task_netns_denied_packets > 0 {
        manifest.coverage.known_gaps.push(format!(
            "the verified proxy-only task network policy blocked {} outbound packets; none crossed the enforced boundary, but their attempted application purpose is unknown",
            summary.task_netns_denied_packets
        ));
    }
    manifest.coverage.known_gaps.sort();
    manifest.coverage.known_gaps.dedup();

    let inventory = blob_inventory(
        run_dir,
        encryption.is_some(),
        encryption,
        verify_blobs,
        &erased_classes,
        &pending_unavailable_classes,
    )?;
    let mut missing_blobs = Vec::new();
    let mut corrupt_blobs = inventory.corrupt;
    manifest.counts.blob_bytes = summary
        .referenced_blobs
        .iter()
        .filter(|(identity, _)| {
            blob_keys::identity_class(identity).is_none_or(|class| !erased_classes.contains(&class))
        })
        .map(|(_, size)| *size)
        .fold(0_u64, u64::saturating_add);
    let mut erased_blobs = Vec::new();
    let mut pending_erasure_blobs = Vec::new();
    for (reference, expected_size) in &summary.referenced_blobs {
        if !inventory.hashes.contains(reference) {
            if blob_keys::identity_class(reference)
                .is_some_and(|class| erased_classes.contains(&class))
            {
                erased_blobs.push(reference.clone());
            } else if blob_keys::identity_class(reference)
                .is_some_and(|class| pending_unavailable_classes.contains(&class))
            {
                pending_erasure_blobs.push(reference.clone());
            } else {
                missing_blobs.push(reference.clone());
            }
        } else if inventory.unverified_pending.contains(reference) {
            pending_erasure_blobs.push(reference.clone());
        } else if verify_blobs && inventory.verified_sizes.get(reference) != Some(expected_size) {
            corrupt_blobs.insert(reference.clone());
        }
    }
    manifest.counts.blobs = inventory.files;
    manifest.counts.blob_storage_bytes = inventory.storage_bytes;
    let corrupt_blobs: Vec<String> = corrupt_blobs.into_iter().collect();
    if !missing_blobs.is_empty()
        || !corrupt_blobs.is_empty()
        || !erased_blobs.is_empty()
        || !pending_erasure_classes.is_empty()
        || !pending_erasure_blobs.is_empty()
    {
        manifest.coverage.captured_request_payloads_complete = false;
        manifest.coverage.captured_response_payloads_complete = false;
    }
    if !erased_blobs.is_empty() {
        manifest.coverage.known_gaps.push(format!(
            "{} payload references were intentionally made unavailable by authenticated class erasure",
            erased_blobs.len()
        ));
    }
    if !pending_erasure_classes.is_empty() {
        manifest.coverage.known_gaps.push(format!(
            "{} blob-class erasure operations require recovery",
            pending_erasure_classes.len()
        ));
    }
    manifest.coverage.known_gaps.sort();
    manifest.coverage.known_gaps.dedup();
    let log = recover_events_with_key(&run_dir.join("events.jsonl"), false, encryption)?;
    manifest.counts.event_storage_bytes = log.valid_bytes;
    Ok(Inspection {
        blob_files: manifest.counts.blobs,
        manifest,
        manifest_authenticated,
        log,
        missing_blobs,
        corrupt_blobs,
        erased_blob_classes: erased_classes
            .iter()
            .map(|class| class.as_str().to_owned())
            .collect(),
        erased_blobs,
        pending_erasure_classes: pending_erasure_classes
            .iter()
            .map(|class| class.as_str().to_owned())
            .collect(),
        pending_erasure_blobs,
    })
}

pub fn finalize_manifest(
    run_dir: &Path,
    exit_code: i32,
    capture_drops: u64,
    encryption: Option<&EncryptionKey>,
) -> Result<Manifest, StorageError> {
    let inspection = inspect_run_with_key(run_dir, false, encryption)?;
    let mut manifest = inspection.manifest;
    manifest.status = String::from(if exit_code == 0 { "finished" } else { "failed" });
    manifest.exit_code = Some(exit_code);
    manifest.finished_at = Some(Utc::now());
    manifest.coverage.capture_drops = manifest.coverage.capture_drops.max(capture_drops);
    if manifest.coverage.capture_drops > 0 {
        manifest.coverage.captured_request_payloads_complete = false;
        manifest.coverage.captured_response_payloads_complete = false;
    }
    if inspection.log.discarded_tail_bytes > 0 {
        manifest.coverage.known_gaps.push(format!(
            "{} uncommitted tail bytes require recovery",
            inspection.log.discarded_tail_bytes
        ));
    }
    if !inspection.missing_blobs.is_empty() {
        manifest.coverage.captured_request_payloads_complete = false;
        manifest.coverage.captured_response_payloads_complete = false;
        manifest.coverage.known_gaps.push(format!(
            "{} referenced blobs are missing",
            inspection.missing_blobs.len()
        ));
    }
    if !inspection.corrupt_blobs.is_empty() {
        manifest.coverage.captured_request_payloads_complete = false;
        manifest.coverage.captured_response_payloads_complete = false;
        manifest.coverage.known_gaps.push(format!(
            "{} blob files are corrupt or violate the encryption scope",
            inspection.corrupt_blobs.len()
        ));
    }
    manifest::write_atomic_authenticated(&run_dir.join("manifest.json"), &manifest, encryption)?;
    Ok(manifest)
}

pub fn repair_run(run_dir: &Path) -> Result<RecoveryReport, StorageError> {
    repair_run_with_key(run_dir, None)
}

pub fn repair_run_with_key(
    run_dir: &Path,
    encryption: Option<&EncryptionKey>,
) -> Result<RecoveryReport, StorageError> {
    let manifest_path = run_dir.join("manifest.json");
    let mut manifest = manifest::read(&manifest_path)?;
    let provided_encryption = encryption;
    let effective_encryption = manifest.effective_encryption_key(provided_encryption)?;
    manifest.verify_authentication(provided_encryption)?;
    let encryption = effective_encryption.as_ref();
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        &manifest.run_id,
        encryption,
        |_| Ok(()),
    )?;
    let report = recover_events_with_key(&run_dir.join("events.jsonl"), true, encryption)?;
    if report.discarded_tail_bytes > 0 {
        manifest.storage.recovered_tail_bytes = Some(report.discarded_tail_bytes);
        manifest.coverage.known_gaps.push(format!(
            "recovery isolated {} bytes from an incomplete final event",
            report.discarded_tail_bytes
        ));
        manifest::write_atomic_authenticated(&manifest_path, &manifest, provided_encryption)?;
    }
    Ok(report)
}

#[derive(Default)]
struct EventSummary {
    counts: CoverageCounts,
    logical_tasks: BTreeSet<String>,
    sources: BTreeSet<String>,
    referenced_blobs: BTreeMap<String, u64>,
    terminal_attempts: u64,
    model_attempts: BTreeSet<String>,
    complete_request_payloads: BTreeSet<String>,
    complete_response_payloads: BTreeSet<String>,
    incomplete_request_payloads: BTreeSet<String>,
    incomplete_response_payloads: BTreeSet<String>,
    protocols: BTreeMap<String, u64>,
    unknown_egress: BTreeSet<String>,
    model_bypass_connections: BTreeSet<String>,
    egress_classes: BTreeMap<String, BTreeSet<String>>,
    possible_quic_connections: BTreeSet<String>,
    tls_surfaces: BTreeSet<(u64, u64, String)>,
    network_scan_gaps: BTreeMap<(u64, u64, String, String), u64>,
    process_scan_failures: u64,
    processes_running_at_stop: u64,
    connections_open_at_stop: u64,
    task_cgroup_remaining: u64,
    task_cgroup_cleanup_errors: u64,
    task_netns_target_confined: bool,
    task_netns_denied_packets: u64,
    unresolved_correlations: u64,
    unresolved_payload_references: u64,
}

fn summarize_events(
    run_dir: &Path,
    expected_run_id: &str,
    encryption: Option<&EncryptionKey>,
) -> Result<EventSummary, StorageError> {
    let mut summary = EventSummary::default();
    let mut logical_inferences = BTreeSet::new();
    let mut inference_models = BTreeMap::new();
    let mut inference_aliases = BTreeMap::new();
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        expected_run_id,
        encryption,
        |event| {
            summary.counts.events = summary.counts.events.saturating_add(1);
            summary.sources.insert(event.source.clone());
            if event.source == "runner" {
                match event.event.as_str() {
                    "collector_started" => {
                        summary
                            .sources
                            .insert("collector:authenticated-hook".to_owned());
                    }
                    "tls_key_log_started" => {
                        summary.sources.insert("nss-sslkeylogfile".to_owned());
                    }
                    "pcap_capture_started" => {
                        let source = match event
                            .normalized
                            .as_ref()
                            .and_then(|value| value.get("scope"))
                            .and_then(Value::as_str)
                        {
                            Some("upstream_address_snapshot") => "pcap:upstream-address-snapshot",
                            Some("task_egress") => "pcap:task-egress",
                            _ => "pcap:proxy-listener",
                        };
                        summary.sources.insert(source.to_owned());
                    }
                    "task_cgroup_assigned" => {
                        summary.sources.insert("cgroup:v2-task".to_owned());
                    }
                    "task_cgroup_stopped" => {
                        summary.task_cgroup_remaining = summary.task_cgroup_remaining.max(
                            event
                                .normalized
                                .as_ref()
                                .and_then(|value| value.get("remaining_processes"))
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        );
                    }
                    "task_cgroup_cleanup_error" => {
                        summary.task_cgroup_cleanup_errors =
                            summary.task_cgroup_cleanup_errors.saturating_add(1);
                    }
                    "task_network_target_confined" => {
                        summary.task_netns_target_confined =
                            event.terminal_state == Some(TerminalState::Complete);
                    }
                    "task_network_isolation_finished" => {
                        let complete = event.terminal_state == Some(TerminalState::Complete)
                            && summary.task_netns_target_confined
                            && event
                                .normalized
                                .as_ref()
                                .and_then(|value| value.get("firewall_verified_at_stop"))
                                .and_then(Value::as_bool)
                                == Some(true);
                        if complete {
                            let source = if event
                                .normalized
                                .as_ref()
                                .and_then(|value| value.get("policy_mode"))
                                .and_then(Value::as_str)
                                == Some("transparent")
                            {
                                "network:task-netns-transparent"
                            } else {
                                "network:task-netns-proxy-only"
                            };
                            summary.sources.insert(source.to_owned());
                        }
                        summary.task_netns_denied_packets = summary
                            .task_netns_denied_packets
                            .saturating_add(
                                event
                                    .normalized
                                    .as_ref()
                                    .and_then(|value| value.get("firewall"))
                                    .and_then(|value| value.get("denied_packets"))
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0),
                            )
                            .saturating_add(
                                event
                                    .normalized
                                    .as_ref()
                                    .and_then(|value| value.get("post_target_firewall"))
                                    .and_then(|value| value.get("denied_packets"))
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0),
                            );
                    }
                    "egress_classification_snapshot" => {
                        summary
                            .sources
                            .insert("egress:configured-launch-time-dns".to_owned());
                    }
                    "transparent_interception_prepared" => {
                        let source = if event
                            .normalized
                            .as_ref()
                            .and_then(|value| value.get("downstream_tls"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        {
                            "proxy:transparent-task-netns-tls"
                        } else {
                            "proxy:transparent-task-netns-cleartext"
                        };
                        summary.sources.insert(source.to_owned());
                    }
                    "correlation_finished" => {
                        summary
                            .sources
                            .insert("correlator:bounded-unique".to_owned());
                    }
                    "adapter_configured" => {
                        if let Some(adapter) = event
                            .normalized
                            .as_ref()
                            .and_then(|value| value.get("adapter"))
                            .and_then(Value::as_str)
                            .filter(|adapter| {
                                !adapter.is_empty()
                                    && adapter.len() <= 128
                                    && !adapter.chars().any(char::is_control)
                            })
                        {
                            summary.sources.insert(format!("adapter:{adapter}"));
                            if event
                                .normalized
                                .as_ref()
                                .and_then(|value| value.get("session_reader"))
                                .and_then(Value::as_bool)
                                == Some(true)
                            {
                                summary.sources.insert(format!("session:{adapter}"));
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(raw) = &event.raw {
                let identity = blob_keys::reference_identity(run_dir, raw)?;
                summary
                    .referenced_blobs
                    .entry(identity)
                    .and_modify(|size| *size = (*size).max(raw.size))
                    .or_insert(raw.size);
            }
            if event.source == "proxy"
                && event.event == "proxy_started"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("upstream_tls_keylog"))
                    .and_then(Value::as_bool)
                    == Some(true)
            {
                summary.sources.insert("tls-keylog:proxy-rustls".to_owned());
            }
            if event.source == "proxy"
                && event.event == "transport_request_started"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("traffic_class"))
                    .and_then(|value| value.as_str())
                    == Some("model")
                && let Some(inference_id) = &event.ids.inference_id
            {
                logical_inferences.insert(inference_id.clone());
                if let Some(attempt_id) = &event.ids.attempt_id {
                    summary.model_attempts.insert(attempt_id.clone());
                    let protocol = event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("protocol"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    *summary.protocols.entry(protocol.to_owned()).or_default() += 1;
                }
            }
            if event.source.starts_with("hook:")
                && event.event == "model_call_started"
                && let Some(inference_id) = &event.ids.inference_id
            {
                logical_inferences.insert(inference_id.clone());
            }
            if event.source == "proxy"
                && event.event == "transport_response_started"
                && let Some(protocol) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("upstream_protocol"))
                    .and_then(Value::as_str)
                    .filter(|protocol| {
                        matches!(
                            *protocol,
                            "http/0.9" | "http/1.0" | "http/1.1" | "http/2" | "http/3" | "unknown"
                        )
                    })
            {
                *summary
                    .protocols
                    .entry(format!("upstream:{protocol}"))
                    .or_default() += 1;
            }
            if event.source == "proxy"
                && event.event == "logical_inference_request"
                && let Some(inference_id) = &event.ids.inference_id
                && let Some(model) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.pointer("/summary/model"))
                    .and_then(serde_json::Value::as_str)
            {
                inference_models
                    .entry(inference_id.clone())
                    .or_insert_with(|| model.to_owned());
            }
            if event.source == "proxy" && event.event == "logical_inference_request" {
                let unresolved = event
                    .normalized
                    .as_ref()
                    .and_then(|value| {
                        value.pointer("/summary/payload_dependencies/unresolved_references")
                    })
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let truncated = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.pointer("/summary/payload_dependencies/scan_truncated"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let inconclusive = event
                    .normalized
                    .as_ref()
                    .and_then(|value| {
                        value.pointer("/summary/payload_dependencies/scan_inconclusive")
                    })
                    .and_then(Value::as_bool)
                    // Older event schemas did not record dependency-scan
                    // evidence, so they must be treated as unknown rather
                    // than silently upgraded to complete.
                    .unwrap_or(true);
                summary.unresolved_payload_references = summary
                    .unresolved_payload_references
                    .saturating_add(unresolved)
                    .saturating_add(u64::from(truncated || inconclusive));
            }
            update_payload_coverage(&event, &mut summary);
            update_surface_coverage(&event, &mut summary);
            if let Some(task_id) = crate::tasks::logical_task_id(&event.ids) {
                summary.logical_tasks.insert(task_id);
            }
            update_counts(&mut summary.counts, &event, &mut summary.terminal_attempts);
            if event.source == "correlation" && event.event == "inference_correlation_unresolved" {
                summary.unresolved_correlations = summary.unresolved_correlations.saturating_add(1);
            }
            if event.source == "correlation"
                && event.event == "inference_correlation"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("method"))
                    .and_then(Value::as_str)
                    == Some("unique_retry_chain")
                && let Some(canonical) = event.ids.inference_id.as_ref()
                && let Some(members) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("transport_inference_ids"))
                    .and_then(Value::as_array)
            {
                for member in members.iter().filter_map(Value::as_str) {
                    inference_aliases.insert(member.to_owned(), canonical.clone());
                }
            }
            enforce_summary_limits(
                &summary,
                &logical_inferences,
                &inference_models,
                &inference_aliases,
            )?;
            Ok(())
        },
    )?;
    let canonical_inferences: BTreeSet<&str> = logical_inferences
        .iter()
        .map(|inference| {
            inference_aliases
                .get(inference)
                .map_or(inference.as_str(), String::as_str)
        })
        .collect();
    summary.counts.logical_inferences =
        u64::try_from(canonical_inferences.len()).unwrap_or(u64::MAX);
    summary.counts.logical_tasks = u64::try_from(summary.logical_tasks.len()).unwrap_or(u64::MAX);
    let canonical_models: BTreeMap<&str, &String> = inference_models
        .iter()
        .map(|(inference, model)| {
            (
                inference_aliases
                    .get(inference)
                    .map_or(inference.as_str(), String::as_str),
                model,
            )
        })
        .collect();
    for model in canonical_models.values() {
        *summary.counts.models.entry((*model).clone()).or_default() += 1;
    }
    Ok(summary)
}

fn enforce_summary_limits(
    summary: &EventSummary,
    logical_inferences: &BTreeSet<String>,
    inference_models: &BTreeMap<String, String>,
    inference_aliases: &BTreeMap<String, String>,
) -> Result<(), StorageError> {
    ensure_analysis_limit(
        summary.referenced_blobs.len(),
        MAX_TRACKED_BLOB_REFERENCES,
        "inspection blob-reference index",
    )?;
    ensure_analysis_limit(
        summary.logical_tasks.len(),
        MAX_TRACKED_LABELS,
        "inspection logical-task index",
    )?;
    ensure_analysis_limit(
        summary.sources.len(),
        MAX_TRACKED_LABELS,
        "inspection capture-source index",
    )?;
    ensure_analysis_limit(
        summary.protocols.len(),
        MAX_TRACKED_PROTOCOLS,
        "inspection protocol index",
    )?;
    ensure_analysis_limit(
        summary.egress_classes.len(),
        MAX_TRACKED_EGRESS_CLASSES,
        "inspection egress-class index",
    )?;
    ensure_analysis_limit(
        summary.egress_classes.values().map(BTreeSet::len).sum(),
        MAX_TRACKED_IDENTIFIERS,
        "inspection classified-egress index",
    )?;
    for (length, operation) in [
        (
            logical_inferences.len(),
            "inspection logical-inference index",
        ),
        (inference_models.len(), "inspection model index"),
        (inference_aliases.len(), "inspection correlation index"),
        (summary.model_attempts.len(), "inspection attempt index"),
        (
            summary.complete_request_payloads.len(),
            "inspection complete-request index",
        ),
        (
            summary.complete_response_payloads.len(),
            "inspection complete-response index",
        ),
        (
            summary.incomplete_request_payloads.len(),
            "inspection incomplete-request index",
        ),
        (
            summary.incomplete_response_payloads.len(),
            "inspection incomplete-response index",
        ),
        (summary.unknown_egress.len(), "inspection egress index"),
        (
            summary.model_bypass_connections.len(),
            "inspection model-bypass index",
        ),
        (
            summary.possible_quic_connections.len(),
            "inspection possible-QUIC index",
        ),
        (summary.tls_surfaces.len(), "inspection TLS-surface index"),
        (
            summary.network_scan_gaps.len(),
            "inspection network-gap index",
        ),
    ] {
        ensure_analysis_limit(length, MAX_TRACKED_IDENTIFIERS, operation)?;
    }
    Ok(())
}

fn ensure_analysis_limit(
    length: usize,
    limit: usize,
    operation: &'static str,
) -> Result<(), StorageError> {
    if length > limit {
        return Err(StorageError::AnalysisLimitExceeded { operation, limit });
    }
    Ok(())
}

fn update_surface_coverage(event: &EventEnvelope, summary: &mut EventSummary) {
    if event.source != "process" {
        return;
    }
    let Some(normalized) = event.normalized.as_ref() else {
        return;
    };
    if event.event == "network_connection_observed" {
        let connection_id = event
            .ids
            .connection_id
            .clone()
            .unwrap_or_else(|| format!("missing-connection-id-sequence-{}", event.sequence));
        let traffic_class = normalized
            .get("traffic_class")
            .and_then(serde_json::Value::as_str);
        let traffic_class = traffic_class
            .filter(|class| {
                matches!(
                    *class,
                    "model_recorder"
                        | "model_bypass"
                        | "local"
                        | "auth"
                        | "telemetry"
                        | "update"
                        | "other"
                        | "unknown_external"
                )
            })
            .unwrap_or("unknown_external");
        summary
            .egress_classes
            .entry(traffic_class.to_owned())
            .or_default()
            .insert(connection_id.clone());
        if traffic_class == "unknown_external" {
            summary.unknown_egress.insert(connection_id.clone());
        } else if traffic_class == "model_bypass" {
            summary
                .model_bypass_connections
                .insert(connection_id.clone());
        }
        if matches!(traffic_class, "unknown_external" | "model_bypass")
            && normalized
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|protocol| protocol.starts_with("udp"))
        {
            summary
                .possible_quic_connections
                .insert(connection_id.clone());
        }
    }
    if matches!(
        event.event.as_str(),
        "process_observed" | "process_tls_surfaces_changed"
    ) && let Some(pid) = normalized.get("pid").and_then(serde_json::Value::as_u64)
        && let Some(start_ticks) = normalized
            .get("start_ticks")
            .and_then(serde_json::Value::as_u64)
        && let Some(surfaces) = normalized
            .get("tls_surfaces")
            .and_then(serde_json::Value::as_array)
    {
        for surface in surfaces.iter().filter_map(serde_json::Value::as_str) {
            summary
                .tls_surfaces
                .insert((pid, start_ticks, surface.to_owned()));
        }
    }
    if event.event == "process_network_scan_gap"
        && let Some(pid) = normalized.get("pid").and_then(serde_json::Value::as_u64)
        && let Some(start_ticks) = normalized
            .get("process_start_ticks")
            .and_then(serde_json::Value::as_u64)
        && let Some(protocol) = normalized
            .get("protocol")
            .and_then(serde_json::Value::as_str)
        && let Some(reason) = normalized.get("reason").and_then(serde_json::Value::as_str)
    {
        let occurrences = normalized
            .get("occurrences")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1)
            .max(1);
        summary
            .network_scan_gaps
            .entry((pid, start_ticks, protocol.to_owned(), reason.to_owned()))
            .and_modify(|current| *current = (*current).max(occurrences))
            .or_insert(occurrences);
    }
    if event.event == "process_scan_failed" {
        summary.process_scan_failures = summary.process_scan_failures.max(
            normalized
                .get("failures_total")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1),
        );
    }
    if event.event == "process_tracker_stopped" {
        summary.process_scan_failures = summary.process_scan_failures.max(
            normalized
                .get("scan_failures")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        summary.processes_running_at_stop = summary.processes_running_at_stop.max(
            normalized
                .get("still_running_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        summary.connections_open_at_stop = summary.connections_open_at_stop.max(
            normalized
                .get("open_connections")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
    }
}

fn update_payload_coverage(event: &EventEnvelope, summary: &mut EventSummary) {
    if event.source != "proxy" {
        return;
    }
    let Some(attempt_id) = event.ids.attempt_id.as_ref() else {
        return;
    };
    if !summary.model_attempts.contains(attempt_id) {
        return;
    }
    match event.event.as_str() {
        "request_body_finished" => {
            match event.terminal_state {
                Some(TerminalState::Complete) => {
                    summary.complete_request_payloads.insert(attempt_id.clone());
                }
                _ => {
                    summary
                        .incomplete_request_payloads
                        .insert(attempt_id.clone());
                }
            }
            return;
        }
        "transport_attempt_finished" => {
            match event.terminal_state {
                Some(TerminalState::Complete) => {
                    summary
                        .complete_response_payloads
                        .insert(attempt_id.clone());
                }
                _ => {
                    summary
                        .incomplete_response_payloads
                        .insert(attempt_id.clone());
                }
            }
            return;
        }
        _ => {}
    }
    let Some(normalized) = event.normalized.as_ref() else {
        return;
    };
    let observed = normalized
        .get("observed_size")
        .and_then(serde_json::Value::as_u64);
    let captured = normalized
        .get("captured_size")
        .and_then(serde_json::Value::as_u64);
    let omitted =
        matches!((observed, captured), (Some(observed), Some(captured)) if observed != captured);
    match event.event.as_str() {
        "request_body_chunk" => {
            if omitted {
                summary
                    .incomplete_request_payloads
                    .insert(attempt_id.clone());
            }
        }
        "response_body_chunk" => {
            if omitted {
                summary
                    .incomplete_response_payloads
                    .insert(attempt_id.clone());
            }
        }
        "websocket_frame" => match normalized
            .get("direction")
            .and_then(serde_json::Value::as_str)
        {
            Some("client_to_upstream") if omitted => {
                summary
                    .incomplete_request_payloads
                    .insert(attempt_id.clone());
            }
            Some("upstream_to_client") if omitted => {
                summary
                    .incomplete_response_payloads
                    .insert(attempt_id.clone());
            }
            _ => {}
        },
        _ => {}
    }
}

fn update_counts(counts: &mut CoverageCounts, event: &EventEnvelope, terminal_attempts: &mut u64) {
    if event.source != "proxy" {
        if event.terminal_state == Some(TerminalState::Error) {
            counts.errors = counts.errors.saturating_add(1);
        }
        return;
    }
    if event.event == "transport_request_started" {
        counts.transport_attempts = counts.transport_attempts.saturating_add(1);
    }
    if event.event == "transport_response_started"
        && event
            .normalized
            .as_ref()
            .and_then(|value| value.get("status"))
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|status| status >= 400)
    {
        counts.errors = counts.errors.saturating_add(1);
    }
    if event.event == "sse_event" {
        let semantic = event
            .normalized
            .as_ref()
            .and_then(|value| value.get("semantic"));
        counts.input_tokens = counts.input_tokens.saturating_add(
            semantic
                .and_then(|value| value.get("input_tokens"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        counts.output_tokens = counts.output_tokens.saturating_add(
            semantic
                .and_then(|value| value.get("output_tokens"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
    }
    if event.event == "transport_attempt_finished" {
        *terminal_attempts = terminal_attempts.saturating_add(1);
        match event.terminal_state {
            Some(TerminalState::Complete) => {
                counts.completed_attempts = counts.completed_attempts.saturating_add(1);
            }
            Some(TerminalState::Error) => {
                counts.errors = counts.errors.saturating_add(1);
                counts.incomplete_attempts = counts.incomplete_attempts.saturating_add(1);
            }
            Some(TerminalState::Cancelled | TerminalState::Incomplete) | None => {
                counts.incomplete_attempts = counts.incomplete_attempts.saturating_add(1);
            }
        }
    } else if event.terminal_state == Some(TerminalState::Error) {
        counts.errors = counts.errors.saturating_add(1);
    }
}

#[derive(Default)]
struct BlobInventory {
    files: u64,
    storage_bytes: u64,
    hashes: BTreeSet<String>,
    verified_sizes: BTreeMap<String, u64>,
    corrupt: BTreeSet<String>,
    unverified_pending: BTreeSet<String>,
}

fn blob_inventory(
    run_dir: &Path,
    expect_encrypted: bool,
    encryption: Option<&EncryptionKey>,
    verify: bool,
    erased_classes: &BTreeSet<blob_keys::BlobClass>,
    pending_unavailable_classes: &BTreeSet<blob_keys::BlobClass>,
) -> Result<BlobInventory, StorageError> {
    let path = run_dir.join("blobs");
    if !path.try_exists()? {
        return Ok(BlobInventory::default());
    }
    if !fs::symlink_metadata(&path)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "blob store is not a real directory",
        )
        .into());
    }
    let mut inventory = BlobInventory::default();
    let mut entries = 0_usize;
    let class_keyed = blob_keys::has_keyring(run_dir)?;
    for entry in fs::read_dir(&path)? {
        let entry = entry?;
        entries = entries.saturating_add(1);
        if entries > MAX_BLOB_DIRECTORY_ENTRIES {
            return Err(StorageError::AnalysisLimitExceeded {
                operation: "inspection blob-directory inventory",
                limit: MAX_BLOB_DIRECTORY_ENTRIES,
            });
        }
        if !entry.file_type()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob directory contains a non-regular entry",
            )
            .into());
        }
        let storage_bytes = entry.metadata()?.len();
        inventory.storage_bytes = inventory
            .storage_bytes
            .checked_add(storage_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "blob directory size overflows u64",
                )
            })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let (class, hash) = match blob_keys::parse_blob_file_name(&name) {
            Ok(parsed) => parsed,
            Err(error)
                if name.starts_with("sha256-")
                    || name.starts_with("body-sha256-")
                    || name.starts_with("pcap-sha256-")
                    || name.starts_with("tls_secrets-sha256-") =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid content-addressed blob name {name}: {error}"),
                )
                .into());
            }
            Err(_) => continue,
        };
        let reference = blob_keys::file_identity(class, &hash);
        inventory.files = inventory.files.saturating_add(1);
        inventory.hashes.insert(reference.clone());
        if class_keyed != class.is_some() {
            inventory.corrupt.insert(reference);
            continue;
        }
        if class.is_some_and(|class| erased_classes.contains(&class)) {
            inventory.corrupt.insert(reference);
            continue;
        }
        let maximum_storage_bytes = if expect_encrypted {
            MAX_ENCODED_BLOB_BYTES
        } else {
            MAX_SINGLE_BLOB_BYTES
        };
        if storage_bytes > u64::try_from(maximum_storage_bytes).unwrap_or(u64::MAX) {
            inventory.corrupt.insert(reference);
            continue;
        }
        let encrypted = is_encrypted_blob(&read_regular_prefix(&entry.path(), 8)?);
        if encrypted != expect_encrypted {
            inventory.corrupt.insert(reference);
            continue;
        }
        if !verify {
            continue;
        }
        if class.is_some_and(|class| pending_unavailable_classes.contains(&class)) {
            inventory.unverified_pending.insert(reference);
            continue;
        }
        let encoded = read_regular_limited(&entry.path(), maximum_storage_bytes)?;
        let plaintext = if expect_encrypted {
            let Some(run_key) = encryption else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "encrypted blob verification requires the matching key",
                )
                .into());
            };
            let key = match class {
                Some(class) => load_class_key(run_dir, run_key, class)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "class-keyed blob has no class encryption key",
                    )
                })?,
                None => run_key.clone(),
            };
            let Ok(plaintext) = key.decrypt_blob(&encoded, &hash) else {
                inventory.corrupt.insert(reference);
                continue;
            };
            plaintext
        } else {
            encoded
        };
        if sha256(&plaintext) != hash {
            inventory.corrupt.insert(reference);
            continue;
        }
        inventory.verified_sizes.insert(
            reference,
            u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
        );
    }
    Ok(inventory)
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use serde_json::json;

    use crate::{
        crypto::EncryptionKey,
        manifest::{CommandMetadata, EncryptionMetadata, Manifest, write_atomic},
        model::{EventIds, PendingEvent, TerminalState},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[test]
    fn oversized_blob_is_corrupt_without_being_read_into_memory() {
        let temporary = tempfile::tempdir().unwrap();
        let blobs = temporary.path().join("blobs");
        fs::create_dir(&blobs).unwrap();
        let hash = "a".repeat(64);
        let path = blobs.join(format!("sha256-{hash}"));
        fs::File::create(&path)
            .unwrap()
            .set_len(u64::try_from(MAX_SINGLE_BLOB_BYTES).unwrap() + 1)
            .unwrap();

        let inventory = blob_inventory(
            temporary.path(),
            false,
            None,
            true,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(inventory.corrupt.contains(&format!("sha256:{hash}")));
    }

    #[test]
    fn inspection_cardinality_limits_fail_closed_instead_of_truncating_truth() {
        let summary = EventSummary {
            sources: (0..=MAX_TRACKED_LABELS)
                .map(|index| format!("source-{index}"))
                .collect(),
            ..EventSummary::default()
        };
        let result = enforce_summary_limits(
            &summary,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(matches!(
            result,
            Err(StorageError::AnalysisLimitExceeded {
                operation: "inspection capture-source index",
                limit: MAX_TRACKED_LABELS,
            })
        ));
    }

    #[test]
    fn tls_surface_coverage_keeps_late_load_history() {
        let mut summary = EventSummary::default();
        let mut observed = PendingEvent::new("run", "process", "process_observed");
        observed.normalized = Some(json!({
            "pid": 42,
            "start_ticks": 7,
            "tls_surfaces": ["nss-dynamic"],
        }));
        update_surface_coverage(&EventEnvelope::from_pending(1, observed), &mut summary);

        let mut changed = PendingEvent::new("run", "process", "process_tls_surfaces_changed");
        changed.normalized = Some(json!({
            "pid": 42,
            "start_ticks": 7,
            "tls_surfaces": ["openssl-dynamic"],
            "added": ["openssl-dynamic"],
            "removed": ["nss-dynamic"],
        }));
        update_surface_coverage(&EventEnvelope::from_pending(2, changed), &mut summary);

        assert_eq!(
            summary.tls_surfaces,
            BTreeSet::from([
                (42, 7, "nss-dynamic".to_owned()),
                (42, 7, "openssl-dynamic".to_owned()),
            ])
        );
    }

    #[test]
    fn process_network_gaps_are_deduplicated_and_counted_conservatively() {
        let mut summary = EventSummary::default();
        for (sequence, occurrences) in [(1, 2), (2, 5)] {
            let mut gap = PendingEvent::new("run", "process", "process_network_scan_gap");
            gap.normalized = Some(json!({
                "pid": 42,
                "process_start_ticks": 7,
                "protocol": "tcp",
                "reason": "socket_rows_unparsed",
                "occurrences": occurrences,
            }));
            update_surface_coverage(&EventEnvelope::from_pending(sequence, gap), &mut summary);
        }

        assert_eq!(summary.network_scan_gaps.len(), 1);
        assert_eq!(summary.network_scan_gaps.values().copied().sum::<u64>(), 5);

        let mut udp = PendingEvent::new("run", "process", "network_connection_observed");
        udp.ids.connection_id = Some("connection-udp".to_owned());
        udp.normalized = Some(json!({
            "traffic_class": "unknown_external",
            "protocol": "udp6",
            "remote_port": 443,
        }));
        update_surface_coverage(&EventEnvelope::from_pending(3, udp), &mut summary);
        assert_eq!(
            summary.possible_quic_connections,
            BTreeSet::from(["connection-udp".to_owned()])
        );
        assert_eq!(
            summary.egress_classes["unknown_external"],
            BTreeSet::from(["connection-udp".to_owned()])
        );

        let mut auth = PendingEvent::new("run", "process", "network_connection_observed");
        auth.ids.connection_id = Some("connection-auth".to_owned());
        auth.normalized = Some(json!({
            "traffic_class": "auth",
            "protocol": "tcp",
            "remote_port": 443,
        }));
        update_surface_coverage(&EventEnvelope::from_pending(4, auth), &mut summary);
        assert!(!summary.unknown_egress.contains("connection-auth"));
        assert_eq!(
            summary.egress_classes["auth"],
            BTreeSet::from(["connection-auth".to_owned()])
        );

        let mut forged = PendingEvent::new("run", "process", "network_connection_observed");
        forged.ids.connection_id = Some("connection-forged".to_owned());
        forged.normalized = Some(json!({
            "traffic_class": "definitely_safe",
            "protocol": "tcp",
            "remote_port": 443,
        }));
        update_surface_coverage(&EventEnvelope::from_pending(5, forged), &mut summary);
        assert!(summary.unknown_egress.contains("connection-forged"));
        assert!(summary.egress_classes["unknown_external"].contains("connection-forged"));

        let mut bypass = PendingEvent::new("run", "process", "network_connection_observed");
        bypass.ids.connection_id = Some("connection-bypass".to_owned());
        bypass.normalized = Some(json!({
            "traffic_class": "model_bypass",
            "protocol": "udp",
            "remote_port": 443,
        }));
        update_surface_coverage(&EventEnvelope::from_pending(6, bypass), &mut summary);
        assert_eq!(
            summary.model_bypass_connections,
            BTreeSet::from(["connection-bypass".to_owned()])
        );
        assert_eq!(
            summary.possible_quic_connections,
            BTreeSet::from(["connection-bypass".to_owned(), "connection-udp".to_owned(),])
        );

        let mut stopped = PendingEvent::new("run", "process", "process_tracker_stopped");
        stopped.normalized = Some(json!({
            "root_pid": 42,
            "scan_failures": 3,
            "still_running_count": 2,
            "open_connections": 1,
        }));
        update_surface_coverage(&EventEnvelope::from_pending(7, stopped), &mut summary);
        assert_eq!(summary.process_scan_failures, 3);
        assert_eq!(summary.processes_running_at_stop, 2);
        assert_eq!(summary.connections_open_at_stop, 1);
    }

    #[tokio::test]
    async fn finalization_counts_once_and_requires_payload_terminals() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "counting";
        let policy = CapturePolicy::default();
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
                    executable_tls_surfaces: vec!["rustls-binary-marker".to_owned()],
                    environment: BTreeMap::new(),
                },
                policy.clone(),
            ),
        )
        .unwrap();
        let (store, _) = RunStore::create(temporary.path(), run_id, policy).unwrap();
        let ids = EventIds {
            inference_id: Some("inference-1".to_owned()),
            attempt_id: Some("attempt-1".to_owned()),
            ..EventIds::default()
        };

        let mut started = store.event("proxy", "transport_request_started");
        started.ids = ids.clone();
        started.normalized = Some(json!({
            "traffic_class": "model",
            "protocol": "http/1.1",
        }));
        store.append(started).await.unwrap();

        let mut logical = store.event("proxy", "logical_inference_request");
        logical.ids = ids.clone();
        logical.normalized = Some(json!({
            "summary": {
                "model": "test-model",
                "payload_dependencies": {
                    "unresolved_references": 1,
                    "scan_truncated": false,
                    "scan_inconclusive": false,
                }
            }
        }));
        store.append(logical).await.unwrap();

        let mut request_finished = store.event("proxy", "request_body_finished");
        request_finished.ids = ids.clone();
        request_finished.terminal_state = Some(TerminalState::Complete);
        store.append(request_finished).await.unwrap();

        let mut response_started = store.event("proxy", "transport_response_started");
        response_started.ids = ids.clone();
        response_started.normalized = Some(json!({
            "status": 200,
            "upstream_protocol": "http/2",
        }));
        store.append(response_started).await.unwrap();

        let mut usage = store.event("proxy", "sse_event");
        usage.ids = ids.clone();
        usage.normalized = Some(json!({
            "semantic": {"input_tokens": 3, "output_tokens": 5},
        }));
        store.append(usage).await.unwrap();

        let mut response_finished = store.event("proxy", "transport_attempt_finished");
        response_finished.ids = ids;
        response_finished.terminal_state = Some(TerminalState::Complete);
        store.append(response_finished).await.unwrap();

        store
            .append(store.event("runner", "tls_key_log_started"))
            .await
            .unwrap();
        let mut pcap_started = store.event("runner", "pcap_capture_started");
        pcap_started.normalized = Some(json!({"scope": "upstream_address_snapshot"}));
        store.append(pcap_started).await.unwrap();
        let mut proxy_started = store.event("proxy", "proxy_started");
        proxy_started.normalized = Some(json!({"upstream_tls_keylog": true}));
        store.append(proxy_started).await.unwrap();
        store
            .append(store.event("runner", "collector_started"))
            .await
            .unwrap();
        let mut adapter = store.event("runner", "adapter_configured");
        adapter.normalized = Some(json!({
            "adapter": "codex",
            "session_reader": true,
        }));
        store.append(adapter).await.unwrap();
        store
            .append(store.event("runner", "correlation_finished"))
            .await
            .unwrap();
        store.shutdown().await.unwrap();

        let finalized = finalize_manifest(temporary.path(), 0, 0, None).unwrap();
        assert_eq!(finalized.counts.transport_attempts, 1);
        assert_eq!(finalized.counts.completed_attempts, 1);
        assert_eq!(finalized.counts.input_tokens, 3);
        assert_eq!(finalized.counts.output_tokens, 5);
        assert_eq!(finalized.coverage.unresolved_payload_references, 1);
        assert_eq!(finalized.coverage.unknown_tls_surfaces, 1);
        assert_eq!(
            finalized.coverage.observed_protocols.get("upstream:http/2"),
            Some(&1)
        );
        assert_eq!(
            finalized
                .coverage
                .observed_tls_surfaces
                .get("rustls-binary-marker"),
            Some(&1)
        );
        assert!(!finalized.coverage.captured_request_payloads_complete);
        assert!(finalized.coverage.captured_response_payloads_complete);
        assert!(
            finalized
                .coverage
                .capture_sources
                .contains(&"nss-sslkeylogfile".to_owned())
        );
        assert!(
            finalized
                .coverage
                .capture_sources
                .contains(&"pcap:upstream-address-snapshot".to_owned())
        );
        assert!(
            finalized
                .coverage
                .capture_sources
                .contains(&"tls-keylog:proxy-rustls".to_owned())
        );
        for source in [
            "collector:authenticated-hook",
            "adapter:codex",
            "session:codex",
            "correlator:bounded-unique",
        ] {
            assert!(
                finalized
                    .coverage
                    .capture_sources
                    .contains(&source.to_owned())
            );
        }
    }

    #[tokio::test]
    async fn hook_event_names_cannot_spoof_recorder_coverage() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "untrusted-hook";
        let policy = CapturePolicy::default();
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
                policy.clone(),
            ),
        )
        .unwrap();
        let (store, _) = RunStore::create(temporary.path(), run_id, policy).unwrap();

        store
            .append(store.event("hook:hermes", "pcap_capture_started"))
            .await
            .unwrap();
        let mut transport = store.event("hook:hermes", "transport_request_started");
        transport.ids.inference_id = Some("spoofed-inference".to_owned());
        transport.ids.attempt_id = Some("spoofed-attempt".to_owned());
        transport.normalized = Some(json!({
            "traffic_class": "model",
            "protocol": "http/1.1",
        }));
        store.append(transport).await.unwrap();
        let mut network = store.event("hook:hermes", "network_connection_observed");
        network.ids.connection_id = Some("spoofed-connection".to_owned());
        network.normalized = Some(json!({
            "traffic_class": "unknown_external",
            "protocol": "udp",
        }));
        store.append(network).await.unwrap();
        store
            .append(store.event("hook:hermes", "inference_correlation_unresolved"))
            .await
            .unwrap();
        store.shutdown().await.unwrap();

        let finalized = finalize_manifest(temporary.path(), 0, 0, None).unwrap();
        assert_eq!(finalized.counts.transport_attempts, 0);
        assert_eq!(finalized.counts.logical_inferences, 0);
        assert_eq!(finalized.coverage.unknown_egress, 0);
        assert_eq!(finalized.coverage.possible_quic_connections, 0);
        assert_eq!(finalized.coverage.unresolved_correlations, 0);
        assert!(
            finalized
                .coverage
                .capture_sources
                .contains(&"hook:hermes".to_owned())
        );
        assert!(
            !finalized
                .coverage
                .capture_sources
                .contains(&"pcap:proxy-listener".to_owned())
        );
    }

    #[tokio::test]
    async fn task_network_firewall_evidence_is_gated_and_counts_denials() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "task-netns-firewall";
        let policy = CapturePolicy::default();
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
                policy.clone(),
            ),
        )
        .unwrap();
        let (store, _) = RunStore::create(temporary.path(), run_id, policy).unwrap();
        let mut pcap = store.event("runner", "pcap_capture_started");
        pcap.normalized = Some(json!({"scope": "task_egress"}));
        store.append(pcap).await.unwrap();

        let mut confined = store.event("runner", "task_network_target_confined");
        confined.terminal_state = Some(TerminalState::Complete);
        store.append(confined).await.unwrap();

        let mut finished = store.event("runner", "task_network_isolation_finished");
        finished.terminal_state = Some(TerminalState::Complete);
        finished.normalized = Some(json!({
            "firewall_verified_at_stop": true,
            "firewall": {"denied_packets": 2},
            "post_target_firewall": {"denied_packets": 1},
        }));
        store.append(finished).await.unwrap();
        store.shutdown().await.unwrap();

        let finalized = finalize_manifest(temporary.path(), 0, 0, None).unwrap();
        assert!(
            finalized
                .coverage
                .capture_sources
                .contains(&"pcap:task-egress".to_owned())
        );
        assert!(
            finalized
                .coverage
                .capture_sources
                .contains(&"network:task-netns-proxy-only".to_owned())
        );
        assert_eq!(finalized.coverage.unknown_egress, 0);
        assert_eq!(finalized.coverage.task_netns_denied_packets, 3);
        assert_eq!(finalized.coverage.blocked_unknown_egress_indicators, 1);
        assert!(
            finalized
                .coverage
                .known_gaps
                .iter()
                .any(|gap| gap.contains("blocked 3 outbound packets"))
        );
    }

    #[tokio::test]
    async fn encrypted_manifest_rejects_a_plaintext_blob_substitution() {
        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([91; 32]);
        let policy = CapturePolicy::default();
        let mut manifest = Manifest::new(
            "encrypted-scope".to_owned(),
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
            policy.clone(),
        );
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: None,
            blob_key_management: Some(crate::blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        write_atomic(&temporary.path().join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "encrypted-scope",
            policy,
            Some(key.clone()),
        )
        .unwrap();
        let raw = store.store_blob(b"secret", None).await.unwrap();
        let mut event = store.event("test", "blob");
        event.raw = Some(raw.clone());
        store.append(event).await.unwrap();
        store.shutdown().await.unwrap();

        let hash = raw.sha256.trim_start_matches("sha256:");
        fs::write(
            temporary
                .path()
                .join("blobs")
                .join(format!("sha256-{hash}")),
            b"secret",
        )
        .unwrap();
        let inspection = inspect_run_with_key(temporary.path(), true, Some(&key)).unwrap();
        assert_eq!(inspection.corrupt_blobs, vec![raw.sha256]);
    }

    #[tokio::test]
    async fn orphan_files_count_toward_physical_blob_storage() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "orphan-storage";
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
        store.shutdown().await.unwrap();
        fs::write(temporary.path().join("blobs/.orphan"), b"orphan").unwrap();

        let inspection = inspect_run(temporary.path(), true).unwrap();
        assert_eq!(inspection.blob_files, 0);
        assert_eq!(inspection.manifest.counts.blob_storage_bytes, 6);
        assert!(inspection.missing_blobs.is_empty());
        assert!(inspection.corrupt_blobs.is_empty());
    }
}
