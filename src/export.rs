use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    audit,
    blob_keys::{self, BlobClass},
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    manifest,
    secure_fs::{commit_path_noreplace, open_regular_read},
};

#[derive(Debug, Clone, Serialize)]
pub struct ExportReport {
    pub run_id: String,
    pub output: PathBuf,
    pub events: u64,
    pub blobs: u64,
    pub blob_bytes: u64,
    pub replay_feasible: bool,
}

#[derive(Serialize)]
struct ExportMetadata<'a> {
    schema_version: u32,
    format: &'static str,
    run_id: &'a str,
    created_at: chrono::DateTime<Utc>,
    events: u64,
    blobs: u64,
    blob_bytes: u64,
    replay_feasible: bool,
    replay_limitations: Vec<&'static str>,
}

pub fn export_raw(run_dir: &Path, output: &Path) -> anyhow::Result<ExportReport> {
    export_raw_with_key(run_dir, output, None)
}

pub fn export_raw_with_key(
    run_dir: &Path,
    output: &Path,
    encryption: Option<&EncryptionKey>,
) -> anyhow::Result<ExportReport> {
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite existing export {}",
        output.display()
    );
    let run_dir = run_dir.canonicalize()?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let output_name = output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("export path has no file name"))?;
    let final_path = parent.join(output_name);
    anyhow::ensure!(
        !final_path.starts_with(&run_dir),
        "export destination must be outside the source run"
    );

    let inspection = inspect_run_with_key(&run_dir, true, encryption)?;
    anyhow::ensure!(
        inspection.manifest.status != "running",
        "refusing to export a run that is still being recorded"
    );
    anyhow::ensure!(
        inspection.log.discarded_tail_bytes == 0,
        "run has an uncommitted event tail; run iorec recover first"
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
        "export",
        "intent",
        &inspection.manifest.run_id,
        Some(serde_json::json!({"format": "raw"})),
    )?;

    let temporary = parent.join(format!(
        ".iorec-export-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let result = write_export(&run_dir, &temporary, &inspection, encryption);
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    let validation = inspect_run_with_key(&temporary, true, encryption);
    match validation {
        Ok(validation)
            if validation.manifest.run_id == inspection.manifest.run_id
                && validation.manifest.counts.events == inspection.manifest.counts.events
                && validation.manifest.counts.blobs == inspection.manifest.counts.blobs
                && validation.log.discarded_tail_bytes == 0
                && validation.missing_blobs.is_empty()
                && validation.corrupt_blobs.is_empty() => {}
        Ok(_) => {
            let _ = fs::remove_dir_all(&temporary);
            anyhow::bail!("export snapshot changed or failed post-copy validation");
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            return Err(error.into());
        }
    }
    if let Err(error) = commit_path_noreplace(&parent, &temporary, &final_path) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error.into());
    }
    File::open(&parent)?.sync_all()?;
    audit::append(
        audit_root,
        "export",
        "complete",
        &inspection.manifest.run_id,
        Some(serde_json::json!({"format": "raw"})),
    )?;

    let feasible = replay_feasible(&inspection.manifest);
    Ok(ExportReport {
        run_id: inspection.manifest.run_id,
        output: final_path,
        events: inspection.manifest.counts.events,
        blobs: inspection.manifest.counts.blobs,
        blob_bytes: inspection.manifest.counts.blob_bytes,
        replay_feasible: feasible,
    })
}

fn write_export(
    run_dir: &Path,
    target: &Path,
    inspection: &crate::inspect::Inspection,
    encryption: Option<&EncryptionKey>,
) -> anyhow::Result<()> {
    manifest::write_atomic_authenticated(
        &target.join("manifest.json"),
        &inspection.manifest,
        encryption,
    )?;
    copy_private(&run_dir.join("events.jsonl"), &target.join("events.jsonl"))?;
    let blobs_target = target.join("blobs");
    fs::create_dir(&blobs_target)?;
    fs::set_permissions(&blobs_target, fs::Permissions::from_mode(0o700))?;

    for entry in fs::read_dir(run_dir.join("blobs"))? {
        let entry = entry?;
        if blob_keys::parse_blob_file_name(&entry.file_name().to_string_lossy()).is_ok() {
            let name = entry.file_name();
            copy_private(&run_dir.join("blobs").join(&name), &blobs_target.join(name))?;
        }
    }
    File::open(&blobs_target)?.sync_all()?;
    if blob_keys::has_keyring(run_dir)? {
        let keys_target = target.join(blob_keys::KEY_DIRECTORY_NAME);
        fs::create_dir(&keys_target)?;
        fs::set_permissions(&keys_target, fs::Permissions::from_mode(0o700))?;
        for class in BlobClass::ALL {
            copy_optional_private(
                &blob_keys::envelope_path(run_dir, class),
                &blob_keys::envelope_path(target, class),
            )?;
        }
        File::open(&keys_target)?.sync_all()?;

        let retention_target = target.join(blob_keys::RETENTION_DIRECTORY_NAME);
        let mut copied_retention = false;
        for class in BlobClass::ALL {
            let source = blob_keys::erasure_state_path(run_dir, class);
            match fs::symlink_metadata(&source) {
                Ok(_) => {
                    if !copied_retention {
                        fs::create_dir(&retention_target)?;
                        fs::set_permissions(&retention_target, fs::Permissions::from_mode(0o700))?;
                        copied_retention = true;
                    }
                    copy_private(&source, &blob_keys::erasure_state_path(target, class))?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if copied_retention {
            File::open(&retention_target)?.sync_all()?;
        }
        copy_optional_private(&run_dir.join(".writer.lock"), &target.join(".writer.lock"))?;
    }

    let replay_feasible = replay_feasible(&inspection.manifest);
    let mut replay_limitations = Vec::new();
    if inspection.manifest.counts.incomplete_attempts > 0 {
        replay_limitations.push("one or more transport attempts are incomplete");
    }
    if inspection.manifest.coverage.unresolved_state_references > 0 {
        replay_limitations.push("server-side state references are unresolved");
    }
    if inspection.manifest.coverage.unresolved_payload_references > 0 {
        replay_limitations.push("external payload references were not snapshotted");
    }
    if !inspection
        .manifest
        .coverage
        .captured_request_payloads_complete
    {
        replay_limitations
            .push("not all observed request bytes or referenced external inputs are present");
    }
    if !inspection
        .manifest
        .coverage
        .captured_response_payloads_complete
    {
        replay_limitations.push("not all observed response payload bytes are present");
    }
    let metadata = ExportMetadata {
        schema_version: 1,
        format: "iorec-raw-bundle",
        run_id: &inspection.manifest.run_id,
        created_at: Utc::now(),
        events: inspection.manifest.counts.events,
        blobs: inspection.manifest.counts.blobs,
        blob_bytes: inspection.manifest.counts.blob_bytes,
        replay_feasible,
        replay_limitations,
    };
    write_private_json(&target.join("export.json"), &metadata)?;
    File::open(target)?.sync_all()?;
    Ok(())
}

fn replay_feasible(manifest: &crate::manifest::Manifest) -> bool {
    manifest.counts.logical_inferences > 0
        && manifest.counts.incomplete_attempts == 0
        && manifest.coverage.capture_drops == 0
        && manifest.coverage.unresolved_state_references == 0
        && manifest.coverage.unresolved_payload_references == 0
        && manifest.coverage.captured_request_payloads_complete
        && manifest.coverage.captured_response_payloads_complete
}

fn copy_private(source: &Path, target: &Path) -> io::Result<()> {
    let mut input = open_regular_read(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(target)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()
}

fn copy_optional_private(source: &Path, target: &Path) -> io::Result<()> {
    match fs::symlink_metadata(source) {
        Ok(_) => copy_private(source, target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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

    use serde_json::json;

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        model::EventIds,
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn creates_an_independent_validated_bundle_and_refuses_overwrite() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run");
        let mut manifest = Manifest::new(
            "export-run".to_owned(),
            CommandMetadata {
                argv: vec!["test".to_owned()],
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
        manifest.status = "finished".to_owned();
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, "export-run", CapturePolicy::default()).unwrap();
        let raw = store
            .store_blob(b"payload", Some("text/plain"))
            .await
            .unwrap();
        let mut event = store.event("proxy", "request_body_chunk");
        event.ids = EventIds {
            inference_id: Some("inference".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            ..EventIds::default()
        };
        event.raw = Some(raw);
        event.normalized = Some(json!({"observed_size": 7, "captured_size": 7}));
        store.append(event).await.unwrap();
        store.shutdown().await.unwrap();

        let output = temporary.path().join("bundle");
        let report = export_raw(&run, &output).unwrap();
        assert_eq!(report.blobs, 1);
        assert_eq!(
            fs::read(output.join("events.jsonl")).unwrap(),
            fs::read(run.join("events.jsonl")).unwrap()
        );
        assert_eq!(
            fs::read(output.join(
                "blobs/sha256-239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
            ))
            .unwrap(),
            b"payload"
        );
        assert!(export_raw(&run, &output).is_err());
    }
}
