use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;

use crate::{crypto::EncryptionKey, inspect::inspect_run_with_key, storage::StorageError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationProfile {
    Integrity,
    Transport,
    Client,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub run_id: String,
    pub manifest_claim: String,
    pub profile: VerificationProfile,
    pub passed: bool,
    pub checks: Vec<VerificationCheck>,
}

pub fn verify_run_with_key(
    run_dir: &Path,
    profile: VerificationProfile,
    encryption: Option<&EncryptionKey>,
) -> Result<VerificationReport, StorageError> {
    let inspection = inspect_run_with_key(run_dir, true, encryption)?;
    let manifest = &inspection.manifest;
    let mut checks = vec![
        check(
            "run_finalized",
            matches!(manifest.status.as_str(), "finished" | "failed"),
            format!("status={}", manifest.status),
        ),
        check(
            "event_log_committed",
            inspection.log.discarded_tail_bytes == 0,
            format!(
                "discarded_tail_bytes={}",
                inspection.log.discarded_tail_bytes
            ),
        ),
        check(
            "referenced_blobs_present",
            inspection.missing_blobs.is_empty(),
            format!("missing={}", inspection.missing_blobs.len()),
        ),
        check(
            "blob_integrity",
            inspection.corrupt_blobs.is_empty(),
            format!("corrupt={}", inspection.corrupt_blobs.len()),
        ),
        check(
            "class_erasure_committed",
            inspection.pending_erasure_classes.is_empty()
                && inspection.pending_erasure_blobs.is_empty(),
            format!(
                "pending_classes={} pending_blobs={}",
                inspection.pending_erasure_classes.len(),
                inspection.pending_erasure_blobs.len()
            ),
        ),
    ];
    if inspection.manifest_authenticated.is_some() {
        checks.push(check(
            "manifest_authenticated",
            inspection.manifest_authenticated == Some(true),
            format!(
                "authenticated={}",
                inspection.manifest_authenticated == Some(true)
            ),
        ));
    }

    if matches!(
        profile,
        VerificationProfile::Transport | VerificationProfile::Client
    ) {
        checks.extend([
            check(
                "transport_observed",
                manifest.counts.transport_attempts > 0,
                format!("attempts={}", manifest.counts.transport_attempts),
            ),
            check(
                "known_tls_surfaces_covered",
                manifest.coverage.unknown_tls_surfaces == 0,
                format!(
                    "unknown_tls_surfaces={}",
                    manifest.coverage.unknown_tls_surfaces
                ),
            ),
            check(
                "connections_parsed",
                manifest.coverage.unparsed_connections == 0,
                format!(
                    "unparsed_connections={}",
                    manifest.coverage.unparsed_connections
                ),
            ),
            check(
                "process_network_observation_complete",
                manifest.coverage.process_network_scan_gaps == 0
                    && manifest.coverage.process_scan_failures == 0
                    && manifest.coverage.processes_running_at_stop == 0
                    && manifest.coverage.connections_open_at_stop == 0,
                format!(
                    "scan_gaps={} scan_failures={} processes_running_at_stop={} connections_open_at_stop={}",
                    manifest.coverage.process_network_scan_gaps,
                    manifest.coverage.process_scan_failures,
                    manifest.coverage.processes_running_at_stop,
                    manifest.coverage.connections_open_at_stop,
                ),
            ),
            check(
                "capture_loss_free",
                manifest.coverage.capture_drops == 0,
                format!("capture_drops={}", manifest.coverage.capture_drops),
            ),
            check(
                "egress_accounted_for",
                manifest.coverage.unknown_egress == 0,
                format!("unknown_egress={}", manifest.coverage.unknown_egress),
            ),
            check(
                "model_endpoint_not_bypassed",
                manifest.coverage.model_bypass_connections == 0,
                format!(
                    "model_bypass_connections={}",
                    manifest.coverage.model_bypass_connections
                ),
            ),
            check(
                "no_unsupported_quic",
                manifest.coverage.possible_quic_connections == 0,
                format!(
                    "possible_quic_connections={}",
                    manifest.coverage.possible_quic_connections
                ),
            ),
            check(
                "attempts_terminal",
                manifest.coverage.all_attempts_have_terminal_state,
                format!(
                    "attempts={} completed={} incomplete={}",
                    manifest.counts.transport_attempts,
                    manifest.counts.completed_attempts,
                    manifest.counts.incomplete_attempts
                ),
            ),
        ]);
    }

    if profile == VerificationProfile::Client {
        checks.extend([
            check(
                "request_payloads_complete",
                manifest.coverage.captured_request_payloads_complete,
                format!(
                    "captured_request_payloads_complete={}",
                    manifest.coverage.captured_request_payloads_complete
                ),
            ),
            check(
                "response_payloads_complete",
                manifest.coverage.captured_response_payloads_complete,
                format!(
                    "captured_response_payloads_complete={}",
                    manifest.coverage.captured_response_payloads_complete
                ),
            ),
            check(
                "server_state_references_resolved",
                manifest.coverage.unresolved_state_references == 0,
                format!(
                    "unresolved_state_references={}",
                    manifest.coverage.unresolved_state_references
                ),
            ),
            check(
                "payload_references_resolved",
                manifest.coverage.unresolved_payload_references == 0,
                format!(
                    "unresolved_payload_references={}",
                    manifest.coverage.unresolved_payload_references
                ),
            ),
            check(
                "cross_source_correlations_resolved",
                manifest.coverage.unresolved_correlations == 0,
                format!(
                    "unresolved_correlations={}",
                    manifest.coverage.unresolved_correlations
                ),
            ),
        ]);
    }

    let passed = checks.iter().all(|check| check.passed);
    Ok(VerificationReport {
        run_id: manifest.run_id.clone(),
        manifest_claim: manifest.coverage.claim.clone(),
        profile,
        passed,
        checks,
    })
}

fn check(name: &'static str, passed: bool, detail: String) -> VerificationCheck {
    VerificationCheck {
        name,
        passed,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        model::{EventIds, TerminalState},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn client_profile_passes_gates_without_upgrading_the_manifest_claim() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = CapturePolicy::default();
        let mut manifest = Manifest::new(
            "verified".to_owned(),
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
        manifest.status = "finished".to_owned();
        write_atomic(&temporary.path().join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(temporary.path(), "verified", policy).unwrap();
        let ids = EventIds {
            inference_id: Some("inference".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            ..EventIds::default()
        };
        let mut started = store.event("proxy", "transport_request_started");
        started.ids = ids.clone();
        started.normalized = Some(serde_json::json!({
            "traffic_class": "model",
            "protocol": "http/1.1",
        }));
        store.append(started).await.unwrap();
        let mut request = store.event("proxy", "request_body_finished");
        request.ids = ids.clone();
        request.terminal_state = Some(TerminalState::Complete);
        store.append(request).await.unwrap();
        let mut response = store.event("proxy", "transport_attempt_finished");
        response.ids = ids;
        response.terminal_state = Some(TerminalState::Complete);
        store.append(response).await.unwrap();
        store.shutdown().await.unwrap();

        let report =
            verify_run_with_key(temporary.path(), VerificationProfile::Client, None).unwrap();
        assert!(report.passed);
        assert_eq!(report.manifest_claim, "best-effort");

        let (store, _) =
            RunStore::create(temporary.path(), "verified", CapturePolicy::default()).unwrap();
        let mut bypass = store.event("process", "network_connection_observed");
        bypass.ids.connection_id = Some("bypass".to_owned());
        bypass.normalized = Some(serde_json::json!({
            "traffic_class": "model_bypass",
            "protocol": "tcp",
        }));
        store.append(bypass).await.unwrap();
        store.shutdown().await.unwrap();
        let report =
            verify_run_with_key(temporary.path(), VerificationProfile::Transport, None).unwrap();
        assert!(!report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| { check.name == "model_endpoint_not_bypassed" && !check.passed })
        );
    }
}
