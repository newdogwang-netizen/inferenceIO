use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    audit,
    blob_keys::read_blob_reference,
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    model::{EventEnvelope, PayloadRef},
    secure_fs::commit_path_noreplace,
    storage::{MAX_SINGLE_BLOB_BYTES, StorageError, for_each_run_event_with_key},
};

#[derive(Debug, Clone, Copy)]
pub enum ArtifactKind {
    Pcap,
    Probe,
    TlsKeys,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactExportReport {
    pub output: PathBuf,
    pub records: u64,
    pub bytes: u64,
    pub kind: &'static str,
}

pub fn export_sensitive_artifact(
    run_dir: &Path,
    output: &Path,
    key: &EncryptionKey,
    kind: ArtifactKind,
) -> anyhow::Result<ArtifactExportReport> {
    export_sensitive_artifact_inner(run_dir, output, key, kind, false)
}

pub fn export_optional_tls_keys(
    run_dir: &Path,
    output: &Path,
    key: &EncryptionKey,
) -> anyhow::Result<ArtifactExportReport> {
    export_sensitive_artifact_inner(run_dir, output, key, ArtifactKind::TlsKeys, true)
}

fn export_sensitive_artifact_inner(
    run_dir: &Path,
    output: &Path,
    key: &EncryptionKey,
    kind: ArtifactKind,
    allow_empty: bool,
) -> anyhow::Result<ArtifactExportReport> {
    let run_dir = run_dir.canonicalize()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let name = output
        .file_name()
        .context("artifact export path has no file name")?;
    let output = parent.join(name);
    anyhow::ensure!(
        !output.starts_with(&run_dir),
        "decrypted sensitive artifacts must be exported outside the source run"
    );
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite existing artifact {}",
        output.display()
    );
    let inspection = inspect_run_with_key(&run_dir, true, Some(key))?;
    let effective_key = inspection
        .manifest
        .effective_encryption_key(Some(key))?
        .ok_or_else(|| anyhow::anyhow!("sensitive artifact run is not encrypted"))?;
    anyhow::ensure!(
        inspection.manifest.status != "running",
        "refusing to export from a run that is still being recorded"
    );
    anyhow::ensure!(
        inspection.log.discarded_tail_bytes == 0,
        "run has an uncommitted event tail; recover it before export"
    );
    anyhow::ensure!(
        inspection.missing_blobs.is_empty(),
        "run references missing blobs"
    );
    anyhow::ensure!(
        inspection.corrupt_blobs.is_empty(),
        "run contains corrupt blobs"
    );
    let audit_root = run_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("source run has no parent directory"))?;
    audit::append(
        audit_root,
        "sensitive_export",
        "intent",
        &inspection.manifest.run_id,
        Some(serde_json::json!({"artifact": kind.name()})),
    )?;

    let temporary = parent.join(format!(
        ".iorec-artifact-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = write_artifact(
        &run_dir,
        &inspection.manifest.run_id,
        &mut file,
        &effective_key,
        kind,
        allow_empty,
    );
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    file.sync_all()?;
    drop(file);
    if let Err(error) = commit_path_noreplace(&parent, &temporary, &output) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("commit artifact without overwriting destination");
    }
    File::open(&parent)?.sync_all()?;
    audit::append(
        audit_root,
        "sensitive_export",
        "complete",
        &inspection.manifest.run_id,
        Some(serde_json::json!({"artifact": kind.name()})),
    )?;
    Ok(ArtifactExportReport {
        output,
        records: report.records,
        bytes: report.bytes,
        kind: kind.name(),
    })
}

#[derive(Default)]
struct WriteReport {
    records: u64,
    bytes: u64,
}

fn write_artifact(
    run_dir: &Path,
    expected_run_id: &str,
    output: &mut File,
    key: &EncryptionKey,
    kind: ArtifactKind,
    allow_empty: bool,
) -> anyhow::Result<WriteReport> {
    let mut report = WriteReport::default();
    let mut expected_pcap_offset = 0_u64;
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        expected_run_id,
        Some(key),
        |event| {
            if !kind.matches(&event) {
                return Ok(());
            }
            let reference = event.raw.as_ref().ok_or_else(|| {
                StorageError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sensitive artifact event has no raw blob",
                ))
            })?;
            if reference.truncated {
                return Err(StorageError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sensitive artifact blob is marked truncated",
                )));
            }
            let plaintext = load_blob(run_dir, reference, key)?;
            match kind {
                ArtifactKind::Pcap => {
                    validate_pcap_chunk(&event, &plaintext, expected_pcap_offset)?;
                    output.write_all(&plaintext)?;
                    expected_pcap_offset = expected_pcap_offset
                        .saturating_add(u64::try_from(plaintext.len()).unwrap_or(u64::MAX));
                }
                ArtifactKind::TlsKeys => {
                    output.write_all(&plaintext)?;
                    output.write_all(b"\n")?;
                }
                ArtifactKind::Probe => {
                    if reference.media_type.as_deref() != Some("application/vnd.iorec.probe+json") {
                        return Err(invalid_data("probe artifact has an unexpected media type"));
                    }
                    if plaintext.contains(&b'\n') || plaintext.contains(&b'\r') {
                        return Err(invalid_data(
                            "probe artifact record contains an embedded line ending",
                        ));
                    }
                    validate_probe_record(&event, &plaintext)?;
                    output.write_all(&plaintext)?;
                    output.write_all(b"\n")?;
                }
            }
            report.records = report.records.saturating_add(1);
            report.bytes = report.bytes.saturating_add(
                u64::try_from(plaintext.len()).unwrap_or(u64::MAX)
                    + u64::from(matches!(kind, ArtifactKind::Probe | ArtifactKind::TlsKeys)),
            );
            Ok(())
        },
    )?;
    anyhow::ensure!(
        allow_empty || report.records > 0,
        "run contains no {} records",
        kind.name()
    );
    Ok(report)
}

fn load_blob(
    run_dir: &Path,
    reference: &PayloadRef,
    key: &EncryptionKey,
) -> Result<Vec<u8>, StorageError> {
    read_blob_reference(run_dir, reference, Some(key), MAX_SINGLE_BLOB_BYTES)
        .map_err(StorageError::Io)
}

fn validate_pcap_chunk(
    event: &EventEnvelope,
    plaintext: &[u8],
    expected_offset: u64,
) -> Result<(), StorageError> {
    let offset = event
        .normalized
        .as_ref()
        .and_then(|value| value.get("offset"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid_data("pcap chunk is missing its offset"))?;
    let bytes = event
        .normalized
        .as_ref()
        .and_then(|value| value.get("bytes"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid_data("pcap chunk is missing its byte count"))?;
    if offset != expected_offset {
        return Err(invalid_data("pcap chunk offsets are not contiguous"));
    }
    if bytes != u64::try_from(plaintext.len()).unwrap_or(u64::MAX) {
        return Err(invalid_data(
            "pcap chunk byte count does not match its blob",
        ));
    }
    Ok(())
}

fn invalid_data(message: &str) -> StorageError {
    StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn validate_probe_record(event: &EventEnvelope, plaintext: &[u8]) -> Result<(), StorageError> {
    let expected_type = match event.event.as_str() {
        "privileged_probe_ready" => "ready",
        "privileged_probe_evidence" => "evidence",
        "privileged_probe_gap" => "gap",
        "privileged_probe_final" => "final",
        _ => return Err(invalid_data("probe artifact event is not exportable")),
    };
    let value: serde_json::Value = serde_json::from_slice(plaintext)
        .map_err(|_| invalid_data("probe artifact record is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_data("probe artifact record is not a JSON object"))?;
    if object.get("type").and_then(serde_json::Value::as_str) != Some(expected_type) {
        return Err(invalid_data(
            "probe artifact record type does not match its event envelope",
        ));
    }
    Ok(())
}

impl ArtifactKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::Probe => "probe-protocol-jsonl",
            Self::TlsKeys => "tls-key-log",
        }
    }

    fn matches(self, event: &EventEnvelope) -> bool {
        match self {
            Self::Pcap => event.source == "pcap" && event.event == "pcap_capture_chunk",
            Self::Probe => {
                event.source == "probe-helper"
                    && matches!(
                        event.event.as_str(),
                        "privileged_probe_ready"
                            | "privileged_probe_evidence"
                            | "privileged_probe_gap"
                            | "privileged_probe_final"
                    )
            }
            Self::TlsKeys => event.source == "tls-keylog" && event.event == "tls_key_log_secret",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    use serde_json::json;

    use crate::{
        manifest::{CommandMetadata, EncryptionMetadata, Manifest, write_atomic},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn reconstructs_contiguous_pcap_chunks_and_refuses_source_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run");
        let key = EncryptionKey::new([61; 32]);
        let mut manifest = Manifest::new(
            "pcap-run".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
                cwd: temporary.path().to_path_buf(),
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
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: None,
            blob_key_management: Some(crate::blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        manifest.status = "finished".to_owned();
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create_with_encryption(
            &run,
            "pcap-run",
            CapturePolicy::default(),
            Some(key.clone()),
        )
        .unwrap();
        store
            .append(store.event("hook:test", "pcap_capture_chunk"))
            .await
            .unwrap();
        let mut offset = 0_u64;
        for chunk in [b"pcap".as_slice(), b"-bytes".as_slice()] {
            let raw = store
                .store_sensitive_blob(chunk, Some("application/vnd.tcpdump.pcap"))
                .await
                .unwrap();
            let mut event = store.event("pcap", "pcap_capture_chunk");
            event.raw = Some(raw);
            event.normalized = Some(json!({"offset": offset, "bytes": chunk.len()}));
            store.append(event).await.unwrap();
            offset = offset.saturating_add(u64::try_from(chunk.len()).unwrap());
        }
        store.shutdown().await.unwrap();

        let output = temporary.path().join("capture.pcap");
        let report = export_sensitive_artifact(&run, &output, &key, ArtifactKind::Pcap).unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(fs::read(&output).unwrap(), b"pcap-bytes");
        assert!(
            export_sensitive_artifact(&run, &run.join("decrypted.pcap"), &key, ArtifactKind::Pcap,)
                .is_err()
        );
    }

    #[tokio::test]
    async fn exports_only_encrypted_probe_protocol_records_as_private_jsonl() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("probe-run");
        let key = EncryptionKey::new([62; 32]);
        let mut manifest = Manifest::new(
            "probe-run".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
                cwd: temporary.path().to_path_buf(),
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
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: None,
            blob_key_management: Some(crate::blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        manifest.status = "finished".to_owned();
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create_with_encryption(
            &run,
            "probe-run",
            CapturePolicy::default(),
            Some(key.clone()),
        )
        .unwrap();
        let records = [
            br#"{"type":"ready","schema_version":2}"#.as_slice(),
            br#"{"type":"evidence","schema_version":2,"payload_base64":"c2VjcmV0"}"#.as_slice(),
            br#"{"type":"gap","schema_version":2,"reason":"bounded_test_gap"}"#.as_slice(),
            br#"{"type":"final","schema_version":2}"#.as_slice(),
        ];
        for (index, record) in records.iter().enumerate() {
            let raw = store
                .store_sensitive_blob(record, Some("application/vnd.iorec.probe+json"))
                .await
                .unwrap();
            let mut event = store.event(
                "probe-helper",
                if index == 0 {
                    "privileged_probe_ready"
                } else if index == records.len() - 1 {
                    "privileged_probe_final"
                } else if index == records.len() - 2 {
                    "privileged_probe_gap"
                } else {
                    "privileged_probe_evidence"
                },
            );
            event.raw = Some(raw);
            store.append(event).await.unwrap();
        }
        let unrelated = store
            .store_sensitive_blob(br#"{"not":"probe evidence"}"#, Some("application/json"))
            .await
            .unwrap();
        let mut unrelated_event = store.event("hook:test", "privileged_probe_evidence");
        unrelated_event.raw = Some(unrelated);
        store.append(unrelated_event).await.unwrap();
        let rejected = store
            .store_sensitive_blob(b"{not-json", Some("application/vnd.iorec.probe+json"))
            .await
            .unwrap();
        let mut rejected_event = store.event("probe-helper", "privileged_probe_message_rejected");
        rejected_event.raw = Some(rejected);
        store.append(rejected_event).await.unwrap();
        let accepted_envelope = EventEnvelope::from_pending(
            1,
            store.event("probe-helper", "privileged_probe_evidence"),
        );
        assert!(validate_probe_record(&accepted_envelope, b"{not-json").is_err());
        assert!(validate_probe_record(&accepted_envelope, br#"{"type":"gap"}"#).is_err());
        store.shutdown().await.unwrap();

        let output = temporary.path().join("probe.jsonl");
        let report = export_sensitive_artifact(&run, &output, &key, ArtifactKind::Probe).unwrap();
        let expected = records
            .iter()
            .flat_map(|record| record.iter().copied().chain(std::iter::once(b'\n')))
            .collect::<Vec<_>>();
        assert_eq!(report.records, 4);
        assert_eq!(report.bytes, u64::try_from(expected.len()).unwrap());
        assert_eq!(fs::read(&output).unwrap(), expected);
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            export_sensitive_artifact(&run, &run.join("probe.jsonl"), &key, ArtifactKind::Probe)
                .is_err()
        );
    }
}
