//! Platform-importable tar export.
//!
//! This is an explicit declassification boundary for encrypted local runs: the
//! resulting private bundle contains plaintext event envelopes and blobs so a
//! platform operator can import it without receiving the recorder master key.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    audit,
    blob_keys::{self, load_class_key},
    crypto::{EncryptionKey, is_encrypted_blob},
    inspect::inspect_run_with_key,
    manifest,
    secure_fs::{commit_path_noreplace, read_regular_limited},
    storage::{MAX_ENCODED_BLOB_BYTES, RunEventReader},
};

const MAX_BLOB_FILES: usize = 250_000;
const MAX_PLATFORM_BUNDLE_BYTES: u64 = 5 << 30;

struct BoundedFile {
    file: File,
    written: u64,
    max_bytes: u64,
}

impl BoundedFile {
    fn new(file: File, max_bytes: u64) -> Self {
        Self {
            file,
            written: 0,
            max_bytes,
        }
    }

    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

impl Write for BoundedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(requested) > self.max_bytes {
            return Err(io::Error::other(format!(
                "platform bundle exceeds the {}-byte import limit",
                self.max_bytes
            )));
        }
        let written = self.file.write(bytes)?;
        self.written = self
            .written
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformExportReport {
    pub run_id: String,
    pub output: PathBuf,
    pub events: u64,
    pub blobs: usize,
    pub bundle_bytes: u64,
    pub plaintext: bool,
}

pub fn export_platform_bundle_with_key(
    run_dir: &Path,
    output: &Path,
    encryption: Option<&EncryptionKey>,
) -> Result<PlatformExportReport> {
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite existing export {}",
        output.display()
    );
    let run_dir = run_dir.canonicalize()?;
    let parent = output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let output_name = output
        .file_name()
        .context("platform export path has no file name")?;
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
        "run has an incomplete event tail; run iorec recover first"
    );
    anyhow::ensure!(
        inspection.missing_blobs.is_empty(),
        "run references missing blobs"
    );
    anyhow::ensure!(
        inspection.corrupt_blobs.is_empty(),
        "run contains corrupt blobs"
    );
    anyhow::ensure!(
        inspection.erased_blobs.is_empty(),
        "platform plaintext export cannot represent intentionally erased payload references"
    );

    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(encryption)?;
    let effective_key = source_manifest.effective_encryption_key(encryption)?;
    let audit_root = run_dir
        .parent()
        .context("source run has no parent directory")?;
    audit::append(
        audit_root,
        "export",
        "intent",
        &inspection.manifest.run_id,
        Some(serde_json::json!({"format": "platform-tar", "plaintext": true})),
    )?;

    let mut plaintext_events = tempfile::NamedTempFile::new_in(&parent)?;
    plaintext_events
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    {
        let mut writer = BufWriter::new(plaintext_events.as_file_mut());
        let reader = RunEventReader::open(
            &run_dir.join("events.jsonl"),
            &inspection.manifest.run_id,
            effective_key.as_ref(),
        )?;
        for event in reader {
            serde_json::to_writer(&mut writer, &event?)?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
    }
    plaintext_events.as_file().sync_all()?;
    let event_bytes = plaintext_events.as_file().metadata()?.len();
    let blob_names = blob_names(&run_dir.join("blobs"))?;
    let (platform_blob_count, platform_blob_bytes) =
        platform_blob_metrics(&run_dir, &blob_names, effective_key.as_ref())?;

    let mut export_manifest = inspection.manifest.clone();
    export_manifest.authentication = None;
    export_manifest.storage.encryption = None;
    export_manifest.counts.event_storage_bytes = event_bytes;
    export_manifest.counts.blobs = u64::try_from(platform_blob_count).unwrap_or(u64::MAX);
    export_manifest.counts.blob_bytes = platform_blob_bytes;
    export_manifest.counts.blob_storage_bytes = platform_blob_bytes;
    "platform-import-bundle-v1".clone_into(&mut export_manifest.storage.durability);
    export_manifest.validate().map_err(anyhow::Error::msg)?;
    let manifest_bytes = serde_json::to_vec_pretty(&export_manifest)?;

    let temporary = parent.join(format!(
        ".iorec-platform-export-{}-{}.tmp",
        std::process::id(),
        Uuid::now_v7()
    ));
    let result = write_tar(
        &temporary,
        &run_dir,
        &mut plaintext_events,
        &manifest_bytes,
        &blob_names,
        effective_key.as_ref(),
        u64::try_from(export_manifest.started_at.timestamp().max(0)).unwrap_or(0),
    );
    let exported_blobs = match result {
        Ok(exported_blobs) => exported_blobs,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if let Err(error) = commit_path_noreplace(&parent, &temporary, &final_path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    File::open(&parent)?.sync_all()?;
    let bundle_bytes = fs::metadata(&final_path)?.len();
    audit::append(
        audit_root,
        "export",
        "complete",
        &inspection.manifest.run_id,
        Some(serde_json::json!({
            "format": "platform-tar",
            "plaintext": true,
            "bundle_bytes": bundle_bytes,
        })),
    )?;

    Ok(PlatformExportReport {
        run_id: inspection.manifest.run_id,
        output: final_path,
        events: inspection.log.valid_events,
        blobs: exported_blobs,
        bundle_bytes,
        plaintext: true,
    })
}

fn write_tar(
    path: &Path,
    run_dir: &Path,
    events: &mut tempfile::NamedTempFile,
    manifest: &[u8],
    blob_names: &[String],
    encryption: Option<&EncryptionKey>,
    modified: u64,
) -> Result<usize> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let writer = BufWriter::new(BoundedFile::new(file, MAX_PLATFORM_BUNDLE_BYTES));
    let mut archive = tar::Builder::new(writer);
    archive.mode(tar::HeaderMode::Deterministic);

    append_bytes(&mut archive, "manifest.json", manifest, modified)?;
    events.as_file_mut().seek(SeekFrom::Start(0))?;
    let size = events.as_file().metadata()?.len();
    append_reader(
        &mut archive,
        "events.jsonl",
        size,
        events.as_file_mut(),
        modified,
    )?;

    let mut exported = BTreeSet::new();
    for name in blob_names {
        let (hash, plaintext) = decode_platform_blob(run_dir, name, encryption)?;
        if exported.insert(hash.clone()) {
            append_bytes(
                &mut archive,
                &format!("blobs/sha256-{hash}"),
                &plaintext,
                modified,
            )?;
        }
    }
    archive.finish()?;
    let mut writer = archive.into_inner()?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(exported.len())
}

fn platform_blob_metrics(
    run_dir: &Path,
    blob_names: &[String],
    encryption: Option<&EncryptionKey>,
) -> Result<(usize, u64)> {
    let mut sizes = std::collections::BTreeMap::new();
    for name in blob_names {
        let (hash, plaintext) = decode_platform_blob(run_dir, name, encryption)?;
        let size = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
        if let Some(existing) = sizes.insert(hash, size) {
            anyhow::ensure!(
                existing == size,
                "equal blob digests have conflicting sizes"
            );
        }
    }
    let bytes = sizes.values().copied().try_fold(0_u64, |total, size| {
        total
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("platform blob bytes overflow u64"))
    })?;
    Ok((sizes.len(), bytes))
}

fn decode_platform_blob(
    run_dir: &Path,
    name: &str,
    encryption: Option<&EncryptionKey>,
) -> Result<(String, Vec<u8>)> {
    let (class, hash) = blob_keys::parse_blob_file_name(name)?;
    let encoded = read_regular_limited(&run_dir.join("blobs").join(name), MAX_ENCODED_BLOB_BYTES)?;
    let plaintext = if is_encrypted_blob(&encoded) {
        let run_key = encryption.context("encrypted blob has no effective run key")?;
        let key = match class {
            Some(class) => load_class_key(run_dir, run_key, class)?
                .context("class-keyed platform-export blob has no class encryption key")?,
            None => run_key.clone(),
        };
        key.decrypt_blob(&encoded, &hash)?
    } else {
        anyhow::ensure!(
            encryption.is_none(),
            "plaintext blob found in an encrypted run"
        );
        encoded
    };
    anyhow::ensure!(
        hex::encode(Sha256::digest(&plaintext)) == hash,
        "blob changed during platform export"
    );
    Ok((hash, plaintext))
}

fn append_bytes(
    archive: &mut tar::Builder<BufWriter<BoundedFile>>,
    path: &str,
    bytes: &[u8],
    modified: u64,
) -> io::Result<()> {
    append_reader(
        archive,
        path,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        bytes,
        modified,
    )
}

fn append_reader(
    archive: &mut tar::Builder<BufWriter<BoundedFile>>,
    path: &str,
    size: u64,
    reader: impl Read,
    modified: u64,
) -> io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(modified);
    header.set_cksum();
    archive.append_data(&mut header, path, reader)
}

fn blob_names(directory: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        anyhow::ensure!(
            file_type.is_file() && !file_type.is_symlink(),
            "blob entry is not a regular file"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("blob file name is not UTF-8"))?;
        if blob_keys::parse_blob_file_name(&name).is_err() {
            continue;
        }
        names.push(name);
        anyhow::ensure!(names.len() <= MAX_BLOB_FILES, "blob file limit exceeded");
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        manifest::{
            CommandMetadata, EncryptionMetadata, Manifest, RUN_KEY_DERIVATION_V1, write_atomic,
        },
        policy::{CapturePolicy, EventLogFormat},
        storage::RunStore,
    };

    use super::*;

    #[test]
    fn bounded_bundle_writer_refuses_to_cross_the_import_limit() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let file = temporary.reopen().unwrap();
        let mut writer = BoundedFile::new(file, 4);
        writer.write_all(b"1234").unwrap();
        let error = writer.write_all(b"5").unwrap_err();
        assert!(error.to_string().contains("4-byte import limit"));
        assert_eq!(temporary.as_file().metadata().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn encrypted_bundle_contains_plaintext_import_layout() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let run_id = "run-platform-export";
        let run = runs.join(run_id);
        let key = EncryptionKey::new([17; 32]);
        let derived = key.derive_run_key(run_id).unwrap();
        let policy = CapturePolicy {
            event_log_format: EventLogFormat::ZstdBlocks,
            ..CapturePolicy::default()
        };
        let mut manifest = Manifest::new(
            run_id.to_owned(),
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
            policy.clone(),
        );
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: Some(RUN_KEY_DERIVATION_V1.to_owned()),
            blob_key_management: Some(crate::blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) =
            RunStore::create_with_encryption(&run, run_id, policy, Some(derived)).unwrap();
        let raw = store
            .store_blob(b"sensitive payload", Some("text/plain"))
            .await
            .unwrap();
        let pcap = store
            .store_sensitive_blob(b"sensitive payload", Some("application/vnd.tcpdump.pcap"))
            .await
            .unwrap();
        let mut event = store.event("proxy", "request_body_chunk");
        event.raw = Some(raw);
        store.append(event).await.unwrap();
        let mut event = store.event("runner", "pcap_chunk");
        event.raw = Some(pcap);
        store.append(event).await.unwrap();
        let stats = store.shutdown().await.unwrap();
        manifest.status = "finished".to_owned();
        manifest.finished_at = Some(chrono::Utc::now());
        manifest.counts.events = stats.events;
        manifest.counts.blobs = stats.blobs;
        manifest.counts.blob_bytes = stats.blob_bytes;
        manifest.authenticate(&key).unwrap();
        manifest::write_atomic(&run.join("manifest.json"), &manifest).unwrap();

        let output = temporary.path().join("bundle.tar");
        let report = export_platform_bundle_with_key(&run, &output, Some(&key)).unwrap();
        assert_eq!(report.events, 2);
        assert_eq!(report.blobs, 1);
        let file = File::open(output).unwrap();
        let mut archive = tar::Archive::new(file);
        let mut names = Vec::new();
        let mut saw_payload = false;
        let mut manifest_blob_count = None;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            names.push(entry.path().unwrap().to_string_lossy().into_owned());
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if bytes == b"sensitive payload" {
                saw_payload = true;
            }
            if names.last().unwrap() == "manifest.json" {
                manifest_blob_count = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap()
                    .pointer("/counts/blobs")
                    .and_then(serde_json::Value::as_u64);
            }
            if names.last().unwrap() == "events.jsonl" {
                assert!(
                    !bytes
                        .windows(b"ciphertext".len())
                        .any(|part| part == b"ciphertext")
                );
            }
        }
        assert_eq!(names[0], "manifest.json");
        assert_eq!(manifest_blob_count, Some(1));
        assert!(names.contains(&"events.jsonl".to_owned()));
        assert_eq!(
            names
                .iter()
                .filter(|name| name.starts_with("blobs/sha256-"))
                .count(),
            1
        );
        assert!(saw_payload);
    }
}
