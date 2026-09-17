use std::{
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, Utc};
use nix::fcntl::{RenameFlags, renameat2};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    audit,
    blob_keys::{
        self, BlobClass, ClassErasurePhase, ClassErasureState, envelope_sha256, read_erasure_state,
        write_erasure_state,
    },
    crypto::EncryptionKey,
    manifest::{self, Manifest},
    secure_fs::{open_regular_read_write, read_regular_limited},
};

const MAX_RUN_ENTRIES: usize = 100_000;
const MAX_DIRECTORY_ENTRIES: usize = 1_000_000;
const MAX_BLOB_DIRECTORY_ENTRIES: usize = 250_000;
const MAX_WRAPPED_KEY_BYTES: usize = 1_024;

#[derive(Debug, Clone, Serialize)]
pub struct PruneCandidate {
    pub run_id: String,
    pub path: PathBuf,
    pub status: String,
    pub finished_at: DateTime<Utc>,
    pub storage_bytes: u64,
    pub final_seq: u64,
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PruneSkip {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PruneReport {
    pub runs_dir: PathBuf,
    pub cutoff: DateTime<Utc>,
    pub execute: bool,
    pub eligible: Vec<PruneCandidate>,
    pub skipped: Vec<PruneSkip>,
    pub deleted: u64,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteDeleteReport {
    pub run_id: String,
    pub request_id: Uuid,
    pub deleted: bool,
    pub recovered: bool,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
// These independent proof facts are intentionally explicit in the machine-
// readable deletion receipt instead of being collapsed into one status label.
#[allow(clippy::struct_excessive_bools)]
pub struct BlobClassErasureReport {
    pub run_id: String,
    pub class: BlobClass,
    pub operation_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    pub recovered: bool,
    pub already_complete: bool,
    pub key_envelope_absent: bool,
    pub ciphertext_files_remaining: u64,
    pub blob_files_erased: u64,
    pub blob_storage_bytes_reclaimed: u64,
    pub cryptographic_erasure_verified: bool,
    pub physical_media_erasure_guaranteed: bool,
    pub physical_media_caveat: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct BlobClassTtlPolicy {
    pub body: Option<Duration>,
    pub pcap: Option<Duration>,
    pub tls_secrets: Option<Duration>,
}

impl BlobClassTtlPolicy {
    fn ttl(self, class: BlobClass) -> Option<Duration> {
        match class {
            BlobClass::Body => self.body,
            BlobClass::Pcap => self.pcap,
            BlobClass::TlsSecrets => self.tls_secrets,
        }
    }

    fn validate(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            BlobClass::ALL
                .into_iter()
                .any(|class| self.ttl(class).is_some()),
            "at least one blob-class TTL is required"
        );
        anyhow::ensure!(
            BlobClass::ALL
                .into_iter()
                .filter_map(|class| self.ttl(class))
                .all(|ttl| !ttl.is_zero()),
            "blob-class TTLs must be greater than zero"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BlobClassExpiryCandidate {
    pub run_id: String,
    pub path: PathBuf,
    pub class: BlobClass,
    pub finished_at: DateTime<Utc>,
    pub cutoff: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlobClassExpirySkip {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<BlobClass>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlobClassExpiryReport {
    pub runs_dir: PathBuf,
    pub evaluated_at: DateTime<Utc>,
    pub execute: bool,
    pub eligible: Vec<BlobClassExpiryCandidate>,
    pub skipped: Vec<BlobClassExpirySkip>,
    pub erased: Vec<BlobClassErasureReport>,
}

#[derive(Debug)]
struct ClassBlobFile {
    path: PathBuf,
    storage_bytes: u64,
}

/// Cryptographically erase one evidence class from a finalized encrypted run.
///
/// The operation is crash-resumable. It first persists an authenticated intent,
/// removes the class DEK envelope, removes ciphertext files, then persists an
/// authenticated completion record and hash-chained operational audit entry.
/// It proves removal from the active key hierarchy; filesystems, snapshots,
/// SSD remapping, and backups can retain historical physical blocks.
pub fn erase_blob_class(
    run_dir: &Path,
    class: BlobClass,
    key: &EncryptionKey,
) -> anyhow::Result<BlobClassErasureReport> {
    erase_blob_class_inner(run_dir, class, key, None)
}

pub fn erase_blob_class_for_request(
    run_dir: &Path,
    class: BlobClass,
    key: &EncryptionKey,
    request_id: Uuid,
) -> anyhow::Result<BlobClassErasureReport> {
    anyhow::ensure!(!request_id.is_nil(), "class-erasure request ID is nil");
    erase_blob_class_inner(run_dir, class, key, Some(request_id))
}

fn erase_blob_class_inner(
    run_dir: &Path,
    class: BlobClass,
    key: &EncryptionKey,
    request_id: Option<Uuid>,
) -> anyhow::Result<BlobClassErasureReport> {
    let metadata = fs::symlink_metadata(run_dir)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "class erasure run path must be a real directory"
    );
    let run_dir = run_dir.canonicalize()?;
    let audit_root = run_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("class erasure run has no parent directory"))?;
    anyhow::ensure!(
        audit_root != Path::new("/"),
        "refusing to audit at filesystem root"
    );
    let audit_metadata = fs::symlink_metadata(audit_root)?;
    anyhow::ensure!(
        audit_metadata.file_type().is_dir() && !audit_metadata.file_type().is_symlink(),
        "class erasure audit root must be a real directory"
    );

    let manifest = manifest::read(&run_dir.join("manifest.json"))?;
    let directory_name = run_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("class erasure run directory name is not UTF-8"))?;
    anyhow::ensure!(
        manifest.run_id == directory_name,
        "manifest run ID does not match its directory"
    );
    anyhow::ensure!(
        manifest.status != "running" && manifest.finished_at.is_some(),
        "class erasure requires a finalized run"
    );
    anyhow::ensure!(
        manifest
            .storage
            .encryption
            .as_ref()
            .and_then(|metadata| metadata.blob_key_management.as_deref())
            == Some(blob_keys::BLOB_KEY_MANAGEMENT_V1),
        "class erasure requires a class-keyed encrypted run; legacy run-key blobs cannot be selectively erased"
    );
    anyhow::ensure!(
        manifest.verify_authentication(Some(key))? == Some(true),
        "class erasure requires an authenticated encrypted manifest"
    );
    let run_key = manifest
        .effective_encryption_key(Some(key))?
        .ok_or_else(|| anyhow::anyhow!("class erasure requires encrypted storage"))?;
    anyhow::ensure!(
        blob_keys::has_keyring(&run_dir)?,
        "blob key directory is absent"
    );
    crate::upload::verify_retention_gate(&run_dir, &manifest.run_id, manifest.counts.events)?;

    let writer_lock = open_regular_read_write(&run_dir.join(".writer.lock"))?;
    writer_lock
        .try_lock()
        .map_err(|error| anyhow::anyhow!("class erasure refuses an active writer: {error}"))?;

    let prior_state = read_erasure_state(&run_dir, &run_key, class)?;
    let recovered = prior_state.is_some();
    if let Some(state) = prior_state.as_ref()
        && state.phase == ClassErasurePhase::Complete
    {
        anyhow::ensure!(
            metadata_if_present(&blob_keys::envelope_path(&run_dir, class))?.is_none(),
            "completed class erasure unexpectedly retains its key envelope"
        );
        let remaining = class_blob_files(&run_dir, class)?;
        anyhow::ensure!(
            remaining.is_empty(),
            "completed class erasure retains ciphertext files"
        );
        ensure_erasure_audit(audit_root, "complete", &manifest.run_id, state, true)?;
        ensure_erasure_request_audit(audit_root, &manifest.run_id, state, request_id)?;
        return Ok(erasure_report(
            &manifest.run_id,
            state,
            request_id,
            true,
            true,
            0,
        ));
    }

    let mut state = if let Some(state) = prior_state {
        state
    } else {
        blob_keys::load_class_key(&run_dir, &run_key, class)?
            .ok_or_else(|| anyhow::anyhow!("class key envelope cannot be authenticated"))?;
        let envelope = read_regular_limited(
            &blob_keys::envelope_path(&run_dir, class),
            MAX_WRAPPED_KEY_BYTES,
        )?;
        let files = class_blob_files(&run_dir, class)?;
        let blob_storage_bytes = files.iter().try_fold(0_u64, |total, file| {
            total
                .checked_add(file.storage_bytes)
                .ok_or_else(|| anyhow::anyhow!("class blob storage size overflows u64"))
        })?;
        let state = ClassErasureState {
            schema_version: 1,
            class,
            phase: ClassErasurePhase::Intent,
            operation_id: request_id.unwrap_or_else(Uuid::now_v7),
            envelope_sha256: envelope_sha256(&envelope),
            blob_files: u64::try_from(files.len()).unwrap_or(u64::MAX),
            blob_storage_bytes,
            requested_at: Utc::now(),
            completed_at: None,
        };
        write_erasure_state(&run_dir, &run_key, &state)?;
        let persisted = read_erasure_state(&run_dir, &run_key, class)?
            .ok_or_else(|| anyhow::anyhow!("class erasure intent was not persisted"))?;
        anyhow::ensure!(
            persisted.operation_id == state.operation_id
                && persisted.envelope_sha256 == state.envelope_sha256,
            "persisted class erasure intent changed"
        );
        state
    };
    anyhow::ensure!(
        state.phase == ClassErasurePhase::Intent,
        "invalid class erasure phase"
    );
    ensure_erasure_audit(audit_root, "intent", &manifest.run_id, &state, recovered)?;

    let envelope_path = blob_keys::envelope_path(&run_dir, class);
    match read_regular_limited(&envelope_path, MAX_WRAPPED_KEY_BYTES) {
        Ok(envelope) => {
            anyhow::ensure!(
                envelope_sha256(&envelope) == state.envelope_sha256,
                "class key envelope changed after erasure intent"
            );
            fs::remove_file(&envelope_path)?;
            File::open(blob_keys::key_directory(&run_dir))?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    for file in class_blob_files(&run_dir, class)? {
        fs::remove_file(&file.path)?;
    }
    File::open(run_dir.join("blobs"))?.sync_all()?;
    let remaining = class_blob_files(&run_dir, class)?;
    anyhow::ensure!(
        remaining.is_empty(),
        "class ciphertext deletion did not converge"
    );
    anyhow::ensure!(
        metadata_if_present(&envelope_path)?.is_none(),
        "class key envelope deletion did not converge"
    );

    state.phase = ClassErasurePhase::Complete;
    state.completed_at = Some(Utc::now());
    write_erasure_state(&run_dir, &run_key, &state)?;
    let persisted = read_erasure_state(&run_dir, &run_key, class)?
        .ok_or_else(|| anyhow::anyhow!("class erasure completion was not persisted"))?;
    anyhow::ensure!(
        persisted.phase == ClassErasurePhase::Complete
            && persisted.operation_id == state.operation_id,
        "persisted class erasure completion changed"
    );
    ensure_erasure_audit(audit_root, "complete", &manifest.run_id, &state, recovered)?;
    ensure_erasure_request_audit(audit_root, &manifest.run_id, &state, request_id)?;
    Ok(erasure_report(
        &manifest.run_id,
        &state,
        request_id,
        recovered,
        false,
        0,
    ))
}

/// Preview or apply independent body, pcap, and TLS-secret retention periods.
/// Runs with configured uploads retain the same full-ACK-and-seal safety gate
/// used by whole-run pruning.
pub fn expire_blob_classes(
    runs_dir: &Path,
    evaluated_at: DateTime<Utc>,
    policy: BlobClassTtlPolicy,
    execute: bool,
    key: &EncryptionKey,
) -> anyhow::Result<BlobClassExpiryReport> {
    policy.validate()?;
    let metadata = fs::symlink_metadata(runs_dir)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "runs directory must be a real directory, not a symlink"
    );
    let runs_dir = runs_dir.canonicalize()?;
    anyhow::ensure!(
        runs_dir != Path::new("/"),
        "refusing to expire from filesystem root"
    );
    let mut eligible = Vec::new();
    let mut skipped = Vec::new();
    let mut seen = 0_usize;
    for entry in fs::read_dir(&runs_dir)? {
        let entry = entry?;
        seen = seen.saturating_add(1);
        anyhow::ensure!(
            seen <= MAX_RUN_ENTRIES,
            "runs directory exceeds the {MAX_RUN_ENTRIES}-entry safety limit"
        );
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("run-") {
            continue;
        }
        let path = entry.path();
        let candidate_result = (|| -> anyhow::Result<Vec<BlobClassExpiryCandidate>> {
            let manifest = manifest::read(&path.join("manifest.json"))?;
            anyhow::ensure!(
                manifest.run_id == name.to_string_lossy(),
                "manifest run ID does not match its directory"
            );
            if manifest.status == "running" || manifest.finished_at.is_none() {
                return Ok(Vec::new());
            }
            anyhow::ensure!(
                manifest
                    .storage
                    .encryption
                    .as_ref()
                    .and_then(|metadata| metadata.blob_key_management.as_deref())
                    == Some(blob_keys::BLOB_KEY_MANAGEMENT_V1),
                "run does not support independent class erasure"
            );
            anyhow::ensure!(
                manifest.verify_authentication(Some(key))? == Some(true),
                "class TTL requires an authenticated manifest"
            );
            let run_key = manifest
                .effective_encryption_key(Some(key))?
                .ok_or_else(|| anyhow::anyhow!("class TTL requires encrypted storage"))?;
            crate::upload::verify_retention_gate(&path, &manifest.run_id, manifest.counts.events)?;
            let finished_at = manifest.finished_at.expect("checked finalized timestamp");
            let mut candidates = Vec::new();
            for class in BlobClass::ALL {
                let Some(ttl) = policy.ttl(class) else {
                    continue;
                };
                if read_erasure_state(&path, &run_key, class)?
                    .is_some_and(|state| state.phase == ClassErasurePhase::Complete)
                {
                    continue;
                }
                let ttl = chrono::TimeDelta::from_std(ttl)
                    .map_err(|_| anyhow::anyhow!("blob-class TTL exceeds chrono range"))?;
                let cutoff = evaluated_at
                    .checked_sub_signed(ttl)
                    .ok_or_else(|| anyhow::anyhow!("blob-class TTL cutoff underflows"))?;
                if finished_at <= cutoff {
                    candidates.push(BlobClassExpiryCandidate {
                        run_id: manifest.run_id.clone(),
                        path: path.clone(),
                        class,
                        finished_at,
                        cutoff,
                    });
                }
            }
            Ok(candidates)
        })();
        match candidate_result {
            Ok(mut candidates) => eligible.append(&mut candidates),
            Err(error) => skipped.push(BlobClassExpirySkip {
                path,
                class: None,
                reason: error.to_string(),
            }),
        }
    }
    eligible.sort_by(|left, right| {
        left.finished_at
            .cmp(&right.finished_at)
            .then_with(|| left.run_id.cmp(&right.run_id))
            .then_with(|| left.class.cmp(&right.class))
    });
    skipped.sort_by(|left, right| left.path.cmp(&right.path));
    let mut report = BlobClassExpiryReport {
        runs_dir,
        evaluated_at,
        execute,
        eligible,
        skipped,
        erased: Vec::new(),
    };
    if execute {
        for candidate in &report.eligible {
            match erase_blob_class(&candidate.path, candidate.class, key) {
                Ok(erased) => report.erased.push(erased),
                Err(error) => report.skipped.push(BlobClassExpirySkip {
                    path: candidate.path.clone(),
                    class: Some(candidate.class),
                    reason: error.to_string(),
                }),
            }
        }
    }
    Ok(report)
}

fn class_blob_files(run_dir: &Path, class: BlobClass) -> anyhow::Result<Vec<ClassBlobFile>> {
    let directory = run_dir.join("blobs");
    let metadata = fs::symlink_metadata(&directory)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "blob store must be a real directory"
    );
    let mut files = Vec::new();
    let mut entries = 0_usize;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        entries = entries.saturating_add(1);
        anyhow::ensure!(
            entries <= MAX_BLOB_DIRECTORY_ENTRIES,
            "blob directory exceeds the {MAX_BLOB_DIRECTORY_ENTRIES}-entry erasure limit"
        );
        let file_type = entry.file_type()?;
        anyhow::ensure!(
            file_type.is_file() && !file_type.is_symlink(),
            "blob directory contains a non-regular entry"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("blob file name is not UTF-8"))?;
        let (entry_class, _) = blob_keys::parse_blob_file_name(&name).map_err(|error| {
            anyhow::anyhow!("unrecognized blob file blocks class erasure: {name}: {error}")
        })?;
        anyhow::ensure!(
            entry_class.is_some(),
            "legacy blob file blocks class erasure"
        );
        if entry_class == Some(class) {
            files.push(ClassBlobFile {
                path: entry.path(),
                storage_bytes: entry.metadata()?.len(),
            });
        }
    }
    Ok(files)
}

fn ensure_erasure_audit(
    audit_root: &Path,
    outcome: &str,
    run_id: &str,
    state: &ClassErasureState,
    recovered: bool,
) -> anyhow::Result<()> {
    let request_id = state.operation_id.to_string();
    if audit::has_request_record(audit_root, "blob_class_erasure", outcome, &request_id)? {
        return Ok(());
    }
    if outcome == "complete" {
        anyhow::ensure!(
            audit::has_request_record(audit_root, "blob_class_erasure", "intent", &request_id)?,
            "class erasure completion has no matching audit intent"
        );
    }
    audit::append(
        audit_root,
        "blob_class_erasure",
        outcome,
        run_id,
        Some(serde_json::json!({
            "request_id": state.operation_id,
            "class": state.class,
            "envelope_sha256": state.envelope_sha256,
            "blob_files": state.blob_files,
            "blob_storage_bytes": state.blob_storage_bytes,
            "recovered": recovered,
            "physical_media_erasure_guaranteed": false,
        })),
    )?;
    Ok(())
}

fn ensure_erasure_request_audit(
    audit_root: &Path,
    run_id: &str,
    state: &ClassErasureState,
    request_id: Option<Uuid>,
) -> anyhow::Result<()> {
    let Some(request_id) = request_id.filter(|request_id| *request_id != state.operation_id) else {
        return Ok(());
    };
    let request = request_id.to_string();
    if audit::has_request_record(
        audit_root,
        "blob_class_erasure_request",
        "complete",
        &request,
    )? {
        return Ok(());
    }
    audit::append(
        audit_root,
        "blob_class_erasure_request",
        "complete",
        run_id,
        Some(serde_json::json!({
            "request_id": request_id,
            "class": state.class,
            "original_operation_id": state.operation_id,
            "already_erased": true,
        })),
    )?;
    Ok(())
}

fn erasure_report(
    run_id: &str,
    state: &ClassErasureState,
    request_id: Option<Uuid>,
    recovered: bool,
    already_complete: bool,
    ciphertext_files_remaining: u64,
) -> BlobClassErasureReport {
    BlobClassErasureReport {
        run_id: run_id.to_owned(),
        class: state.class,
        operation_id: state.operation_id,
        request_id,
        recovered,
        already_complete,
        key_envelope_absent: true,
        ciphertext_files_remaining,
        blob_files_erased: state.blob_files,
        blob_storage_bytes_reclaimed: state.blob_storage_bytes,
        cryptographic_erasure_verified: true,
        physical_media_erasure_guaranteed: false,
        physical_media_caveat: "snapshots, backups, copy-on-write filesystems, and SSD remapping can retain historical physical blocks",
    }
}

/// Deletes one finalized run under an explicit remote request.
///
/// The request UUID names a deterministic quarantine directory and is written
/// into the hash-chained audit log. Repeating the same request safely resumes
/// after a crash at any point between intent, rename, removal, and completion.
/// Unlike automatic retention, this authenticated and locally policy-gated
/// user deletion deliberately overrides the upload-completion gate: requiring
/// a successful upload before erasure would make an offline partial run
/// impossible to delete.
pub fn delete_uploaded_run(
    runs_dir: &Path,
    run_id: &str,
    request_id: Uuid,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<RemoteDeleteReport> {
    anyhow::ensure!(
        run_id.starts_with("run-")
            && Path::new(run_id).components().count() == 1
            && Path::new(run_id)
                .file_name()
                .is_some_and(|name| name == run_id),
        "remote delete run ID is not a safe directory name"
    );
    let metadata = fs::symlink_metadata(runs_dir)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "runs directory must be a real directory, not a symlink"
    );
    let runs_dir = runs_dir.canonicalize()?;
    anyhow::ensure!(
        runs_dir != Path::new("/"),
        "refusing to delete from filesystem root"
    );
    let request = request_id.to_string();
    let target = runs_dir.join(run_id);
    let quarantine_name = format!(".iorec-remote-delete-{request_id}");
    let quarantine = runs_dir.join(&quarantine_name);

    if let Some(quarantine_metadata) = metadata_if_present(&quarantine)? {
        anyhow::ensure!(
            quarantine_metadata.file_type().is_dir()
                && !quarantine_metadata.file_type().is_symlink(),
            "remote delete quarantine is not a real directory"
        );
        anyhow::ensure!(
            metadata_if_present(&target)?.is_none(),
            "remote delete source and quarantine both exist"
        );
        let reclaimed_bytes = directory_size(&quarantine)?;
        fs::remove_dir_all(&quarantine)?;
        File::open(&runs_dir)?.sync_all()?;
        append_remote_delete_audit(
            &runs_dir,
            "complete",
            run_id,
            request_id,
            reclaimed_bytes,
            true,
        )?;
        return Ok(RemoteDeleteReport {
            run_id: run_id.to_owned(),
            request_id,
            deleted: true,
            recovered: true,
            reclaimed_bytes,
        });
    }

    if metadata_if_present(&target)?.is_none() {
        if audit::has_request_record(&runs_dir, "remote_delete", "complete", &request)? {
            return Ok(RemoteDeleteReport {
                run_id: run_id.to_owned(),
                request_id,
                deleted: false,
                recovered: true,
                reclaimed_bytes: 0,
            });
        }
        if audit::has_run_record(&runs_dir, "retention_delete", "complete", run_id)? {
            append_remote_delete_audit(&runs_dir, "complete", run_id, request_id, 0, true)?;
            return Ok(RemoteDeleteReport {
                run_id: run_id.to_owned(),
                request_id,
                deleted: false,
                recovered: true,
                reclaimed_bytes: 0,
            });
        }
        anyhow::ensure!(
            audit::has_request_record(&runs_dir, "remote_delete", "intent", &request)?,
            "remote delete recording is not present locally"
        );
        append_remote_delete_audit(&runs_dir, "complete", run_id, request_id, 0, true)?;
        return Ok(RemoteDeleteReport {
            run_id: run_id.to_owned(),
            request_id,
            deleted: false,
            recovered: true,
            reclaimed_bytes: 0,
        });
    }

    let candidate = inspect_candidate(&runs_dir, &target, DateTime::<Utc>::MAX_UTC, key, false)?
        .ok_or_else(|| anyhow::anyhow!("remote delete refuses a running recording"))?;
    append_remote_delete_audit(
        &runs_dir,
        "intent",
        run_id,
        request_id,
        candidate.storage_bytes,
        false,
    )?;
    rename_no_replace(&runs_dir, &target, Path::new(&quarantine_name))?;
    File::open(&runs_dir)?.sync_all()?;
    let quarantined_metadata = fs::symlink_metadata(&quarantine)?;
    anyhow::ensure!(
        quarantined_metadata.dev() == candidate.device
            && quarantined_metadata.ino() == candidate.inode,
        "remote delete quarantine identity mismatch"
    );
    fs::remove_dir_all(&quarantine)?;
    File::open(&runs_dir)?.sync_all()?;
    append_remote_delete_audit(
        &runs_dir,
        "complete",
        run_id,
        request_id,
        candidate.storage_bytes,
        false,
    )?;
    Ok(RemoteDeleteReport {
        run_id: run_id.to_owned(),
        request_id,
        deleted: true,
        recovered: false,
        reclaimed_bytes: candidate.storage_bytes,
    })
}

pub fn prune_runs(
    runs_dir: &Path,
    cutoff: DateTime<Utc>,
    execute: bool,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<PruneReport> {
    prune_runs_inner(runs_dir, cutoff, execute, key, false)
}

/// Applies a platform-configured TTL only to runs that have at least one
/// durable upload target and for which every target is fully `ACKed` and sealed.
pub fn prune_uploaded_runs(
    runs_dir: &Path,
    cutoff: DateTime<Utc>,
    execute: bool,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<PruneReport> {
    prune_runs_inner(runs_dir, cutoff, execute, key, true)
}

fn prune_runs_inner(
    runs_dir: &Path,
    cutoff: DateTime<Utc>,
    execute: bool,
    key: Option<&EncryptionKey>,
    require_uploaded: bool,
) -> anyhow::Result<PruneReport> {
    let metadata = fs::symlink_metadata(runs_dir)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "runs directory must be a real directory, not a symlink"
    );
    let runs_dir = runs_dir.canonicalize()?;
    anyhow::ensure!(
        runs_dir != Path::new("/"),
        "refusing to prune filesystem root"
    );

    let mut eligible = Vec::new();
    let mut skipped = Vec::new();
    let mut seen = 0_usize;
    for entry in fs::read_dir(&runs_dir)? {
        let entry = entry?;
        seen = seen.saturating_add(1);
        anyhow::ensure!(
            seen <= MAX_RUN_ENTRIES,
            "runs directory exceeds the {MAX_RUN_ENTRIES}-entry safety limit"
        );
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("run-") {
            continue;
        }
        match inspect_candidate(&runs_dir, &entry.path(), cutoff, key, true) {
            Ok(Some(candidate)) => {
                if require_uploaded {
                    match crate::upload::verify_uploaded_retention_gate(
                        &candidate.path,
                        &candidate.run_id,
                        candidate.final_seq,
                    ) {
                        Ok(()) => eligible.push(candidate),
                        Err(error) => skipped.push(PruneSkip {
                            path: candidate.path,
                            reason: error.to_string(),
                        }),
                    }
                } else {
                    eligible.push(candidate);
                }
            }
            Ok(None) => {}
            Err(error) => skipped.push(PruneSkip {
                path: entry.path(),
                reason: error.to_string(),
            }),
        }
    }
    eligible.sort_by_key(|candidate| candidate.finished_at);
    skipped.sort_by(|left, right| left.path.cmp(&right.path));

    let mut report = PruneReport {
        runs_dir: runs_dir.clone(),
        cutoff,
        execute,
        eligible,
        skipped,
        deleted: 0,
        reclaimed_bytes: 0,
    };
    if !execute {
        return Ok(report);
    }

    for candidate in &report.eligible {
        let revalidated = inspect_candidate(&runs_dir, &candidate.path, cutoff, key, true)?
            .ok_or_else(|| anyhow::anyhow!("run changed during prune: {}", candidate.run_id))?;
        if require_uploaded {
            crate::upload::verify_uploaded_retention_gate(
                &revalidated.path,
                &revalidated.run_id,
                revalidated.final_seq,
            )?;
        }
        anyhow::ensure!(
            revalidated.run_id == candidate.run_id
                && revalidated.finished_at == candidate.finished_at
                && revalidated.device == candidate.device
                && revalidated.inode == candidate.inode,
            "run changed during prune: {}",
            candidate.run_id
        );
        append_audit(&runs_dir, "intent", &revalidated)?;
        let quarantine_name = format!(".iorec-prune-{}-{}", candidate.run_id, Uuid::now_v7());
        rename_no_replace(&runs_dir, &candidate.path, Path::new(&quarantine_name))?;
        File::open(&runs_dir)?.sync_all()?;
        let quarantine = runs_dir.join(&quarantine_name);
        let quarantined_metadata = fs::symlink_metadata(&quarantine)?;
        if quarantined_metadata.dev() != revalidated.device
            || quarantined_metadata.ino() != revalidated.inode
        {
            let restore = rename_no_replace(
                &runs_dir,
                &quarantine,
                Path::new(candidate.path.file_name().ok_or_else(|| {
                    anyhow::anyhow!("run path has no name: {}", candidate.path.display())
                })?),
            );
            return Err(match restore {
                Ok(()) => anyhow::anyhow!(
                    "run identity changed during prune and was restored: {}",
                    candidate.run_id
                ),
                Err(error) => anyhow::anyhow!(
                    "run identity changed during prune; quarantined path was retained at {} because restore failed: {error}",
                    quarantine.display()
                ),
            });
        }
        fs::remove_dir_all(&quarantine)?;
        File::open(&runs_dir)?.sync_all()?;
        append_audit(&runs_dir, "complete", &revalidated)?;
        report.deleted = report.deleted.saturating_add(1);
        report.reclaimed_bytes = report
            .reclaimed_bytes
            .saturating_add(revalidated.storage_bytes);
    }
    Ok(report)
}

fn metadata_if_present(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn append_remote_delete_audit(
    runs_dir: &Path,
    outcome: &str,
    run_id: &str,
    request_id: Uuid,
    storage_bytes: u64,
    recovered: bool,
) -> anyhow::Result<()> {
    audit::append(
        runs_dir,
        "remote_delete",
        outcome,
        run_id,
        Some(serde_json::json!({
            "request_id": request_id,
            "storage_bytes": storage_bytes,
            "recovered": recovered,
        })),
    )?;
    Ok(())
}

fn inspect_candidate(
    runs_dir: &Path,
    path: &Path,
    cutoff: DateTime<Utc>,
    key: Option<&EncryptionKey>,
    require_upload_completion: bool,
) -> anyhow::Result<Option<PruneCandidate>> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "candidate is not a real directory"
    );
    let canonical = path.canonicalize()?;
    anyhow::ensure!(
        canonical.parent() == Some(runs_dir),
        "candidate is not an immediate child of the runs directory"
    );
    let manifest = manifest::read(&canonical.join("manifest.json"))?;
    let directory_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("candidate directory name is not UTF-8"))?;
    anyhow::ensure!(
        manifest.run_id == directory_name,
        "manifest run ID does not match its directory"
    );
    if manifest.status == "running" {
        return Ok(None);
    }
    let Some(finished_at) = manifest.finished_at else {
        return Ok(None);
    };
    if finished_at > cutoff {
        return Ok(None);
    }
    verify_manifest_for_prune(&manifest, key)?;
    if require_upload_completion {
        crate::upload::verify_retention_gate(&canonical, &manifest.run_id, manifest.counts.events)?;
    }
    let storage_bytes = directory_size(&canonical)?;
    Ok(Some(PruneCandidate {
        run_id: manifest.run_id,
        path: canonical,
        status: manifest.status,
        finished_at,
        storage_bytes,
        final_seq: manifest.counts.events,
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn verify_manifest_for_prune(
    manifest: &Manifest,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<()> {
    match manifest.verify_authentication(key)? {
        Some(true) | None => Ok(()),
        Some(false) => anyhow::bail!(
            "encrypted legacy manifest is unauthenticated; inspect and migrate it before pruning"
        ),
    }
}

fn directory_size(root: &Path) -> io::Result<u64> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            entries = entries.saturating_add(1);
            if entries > MAX_DIRECTORY_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "run exceeds the retention scan entry limit",
                ));
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                bytes = bytes.saturating_add(entry.metadata()?.len());
            }
        }
    }
    Ok(bytes)
}

fn rename_no_replace(runs_dir: &Path, source: &Path, target_name: &Path) -> io::Result<()> {
    let directory = File::open(runs_dir)?;
    let source_name = source
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "run path has no file name"))?;
    renameat2(
        &directory,
        Path::new(source_name),
        &directory,
        target_name,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(io::Error::other)
}

fn append_audit(runs_dir: &Path, outcome: &str, candidate: &PruneCandidate) -> anyhow::Result<()> {
    audit::append(
        runs_dir,
        "retention_delete",
        outcome,
        &candidate.run_id,
        Some(serde_json::json!({
            "status": candidate.status,
            "finished_at": candidate.finished_at,
            "storage_bytes": candidate.storage_bytes,
        })),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use crate::{
        blob_keys::{blob_path, read_blob_reference},
        inspect::{finalize_manifest, inspect_run_with_key},
        manifest::{CommandMetadata, EncryptionMetadata, write_atomic, write_atomic_authenticated},
        model::PayloadRef,
        policy::CapturePolicy,
        storage::{MAX_SINGLE_BLOB_BYTES, RunStore},
        verify::{VerificationProfile, verify_run_with_key},
    };

    use super::*;

    fn create_finished_run(runs: &Path, run_id: &str, finished_at: DateTime<Utc>) -> PathBuf {
        let path = runs.join(run_id);
        let mut manifest = Manifest::new(
            run_id.to_owned(),
            CommandMetadata {
                argv: vec!["true".to_owned()],
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
        manifest.finished_at = Some(finished_at);
        write_atomic(&path.join("manifest.json"), &manifest).unwrap();
        fs::write(path.join("events.jsonl"), b"evidence\n").unwrap();
        path
    }

    async fn create_finished_class_run(
        runs: &Path,
        run_id: &str,
        finished_at: DateTime<Utc>,
        key: &EncryptionKey,
    ) -> (PathBuf, [PayloadRef; 3]) {
        let path = runs.join(run_id);
        let policy = CapturePolicy::default();
        let mut manifest = Manifest::new(
            run_id.to_owned(),
            CommandMetadata {
                argv: vec!["true".to_owned()],
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
            blob_key_management: Some(blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        write_atomic(&path.join("manifest.json"), &manifest).unwrap();
        let (store, _) =
            RunStore::create_with_encryption(&path, run_id, policy, Some(key.clone())).unwrap();
        let body = store
            .store_blob(b"same retained plaintext", Some("application/json"))
            .await
            .unwrap();
        let pcap = store
            .store_sensitive_blob(
                b"same retained plaintext",
                Some("application/vnd.tcpdump.pcap"),
            )
            .await
            .unwrap();
        let tls = store
            .store_sensitive_blob(
                b"same retained plaintext",
                Some("application/x-nss-key-log"),
            )
            .await
            .unwrap();
        for (event_name, reference) in [
            ("body", body.clone()),
            ("pcap", pcap.clone()),
            ("tls", tls.clone()),
        ] {
            let mut event = store.event("test", event_name);
            event.raw = Some(reference);
            store.append(event).await.unwrap();
        }
        store.shutdown().await.unwrap();
        let mut manifest = finalize_manifest(&path, 0, 0, Some(key)).unwrap();
        manifest.finished_at = Some(finished_at);
        write_atomic_authenticated(&path.join("manifest.json"), &manifest, Some(key)).unwrap();
        (path, [body, pcap, tls])
    }

    #[tokio::test]
    async fn class_erasure_is_isolated_authenticated_and_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let key = EncryptionKey::new([61; 32]);
        let (run, [body, pcap, tls]) =
            create_finished_class_run(&runs, "run-class-erase", Utc::now(), &key).await;
        assert_eq!(body.sha256, pcap.sha256);
        assert_eq!(pcap.sha256, tls.sha256);
        assert_ne!(
            blob_path(&run, &body).unwrap(),
            blob_path(&run, &pcap).unwrap()
        );
        assert_ne!(
            blob_path(&run, &pcap).unwrap(),
            blob_path(&run, &tls).unwrap()
        );
        for reference in [&body, &pcap, &tls] {
            assert_eq!(
                read_blob_reference(&run, reference, Some(&key), MAX_SINGLE_BLOB_BYTES).unwrap(),
                b"same retained plaintext"
            );
        }

        let report = erase_blob_class(&run, BlobClass::Pcap, &key).unwrap();
        assert_eq!(report.run_id, "run-class-erase");
        assert_eq!(report.blob_files_erased, 1);
        assert!(report.cryptographic_erasure_verified);
        assert!(!report.physical_media_erasure_guaranteed);
        assert!(read_blob_reference(&run, &pcap, Some(&key), MAX_SINGLE_BLOB_BYTES).is_err());
        for reference in [&body, &tls] {
            assert_eq!(
                read_blob_reference(&run, reference, Some(&key), MAX_SINGLE_BLOB_BYTES).unwrap(),
                b"same retained plaintext"
            );
        }
        let inspection = inspect_run_with_key(&run, true, Some(&key)).unwrap();
        assert_eq!(inspection.erased_blob_classes, vec!["pcap"]);
        assert_eq!(inspection.erased_blobs.len(), 1);
        assert!(inspection.missing_blobs.is_empty());
        assert!(inspection.corrupt_blobs.is_empty());
        assert!(
            verify_run_with_key(&run, VerificationProfile::Integrity, Some(&key))
                .unwrap()
                .passed
        );
        assert_eq!(audit::verify(&runs).unwrap().records, 2);

        let repeated = erase_blob_class(&run, BlobClass::Pcap, &key).unwrap();
        assert!(repeated.already_complete);
        assert!(repeated.recovered);
        assert_eq!(repeated.operation_id, report.operation_id);
        assert_eq!(audit::verify(&runs).unwrap().records, 2);

        let request_id = Uuid::now_v7();
        let remote = erase_blob_class_for_request(&run, BlobClass::Body, &key, request_id).unwrap();
        assert_eq!(remote.operation_id, request_id);
        assert_eq!(remote.request_id, Some(request_id));
        assert_eq!(audit::verify(&runs).unwrap().records, 4);
    }

    #[tokio::test]
    async fn class_erasure_recovers_after_the_key_envelope_was_removed() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let key = EncryptionKey::new([62; 32]);
        let (run, [_body, pcap, _tls]) =
            create_finished_class_run(&runs, "run-class-recover", Utc::now(), &key).await;
        let envelope_path = blob_keys::envelope_path(&run, BlobClass::Pcap);
        let envelope = fs::read(&envelope_path).unwrap();
        let state = ClassErasureState {
            schema_version: 1,
            class: BlobClass::Pcap,
            phase: ClassErasurePhase::Intent,
            operation_id: Uuid::now_v7(),
            envelope_sha256: envelope_sha256(&envelope),
            blob_files: 1,
            blob_storage_bytes: fs::metadata(blob_path(&run, &pcap).unwrap()).unwrap().len(),
            requested_at: Utc::now(),
            completed_at: None,
        };
        write_erasure_state(&run, &key, &state).unwrap();
        fs::remove_file(envelope_path).unwrap();

        let pending = inspect_run_with_key(&run, true, Some(&key)).unwrap();
        assert_eq!(pending.pending_erasure_classes, vec!["pcap"]);
        assert_eq!(pending.pending_erasure_blobs.len(), 1);
        assert!(pending.missing_blobs.is_empty());
        assert!(pending.corrupt_blobs.is_empty());
        assert!(
            !verify_run_with_key(&run, VerificationProfile::Integrity, Some(&key))
                .unwrap()
                .passed
        );

        let report = erase_blob_class(&run, BlobClass::Pcap, &key).unwrap();
        assert!(report.recovered);
        assert!(!report.already_complete);
        assert_eq!(report.operation_id, state.operation_id);
        assert!(!blob_path(&run, &pcap).unwrap().exists());
        assert_eq!(
            read_erasure_state(&run, &key, BlobClass::Pcap)
                .unwrap()
                .unwrap()
                .phase,
            ClassErasurePhase::Complete
        );
        assert_eq!(audit::verify(&runs).unwrap().records, 2);
    }

    #[tokio::test]
    async fn independent_class_ttls_preview_then_erase_only_due_classes() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let key = EncryptionKey::new([63; 32]);
        let now = Utc::now();
        let finished_at = now - chrono::TimeDelta::minutes(150);
        let (run, [_body, _pcap, tls]) =
            create_finished_class_run(&runs, "run-class-ttl", finished_at, &key).await;
        let policy = BlobClassTtlPolicy {
            body: Some(Duration::from_secs(60 * 60)),
            pcap: Some(Duration::from_secs(2 * 60 * 60)),
            tls_secrets: Some(Duration::from_secs(3 * 60 * 60)),
        };
        let preview = expire_blob_classes(&runs, now, policy, false, &key).unwrap();
        assert_eq!(preview.eligible.len(), 2);
        assert!(preview.erased.is_empty());
        assert!(!runs.join(audit::AUDIT_FILE).exists());

        let executed = expire_blob_classes(&runs, now, policy, true, &key).unwrap();
        assert_eq!(executed.erased.len(), 2);
        let inspection = inspect_run_with_key(&run, true, Some(&key)).unwrap();
        assert_eq!(inspection.erased_blob_classes, vec!["body", "pcap"]);
        assert_eq!(inspection.erased_blobs.len(), 2);
        assert_eq!(
            read_blob_reference(&run, &tls, Some(&key), MAX_SINGLE_BLOB_BYTES).unwrap(),
            b"same retained plaintext"
        );
        assert_eq!(audit::verify(&runs).unwrap().records, 4);
    }

    #[tokio::test]
    async fn class_erasure_fails_closed_on_key_state_tampering_and_pending_uploads() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let key = EncryptionKey::new([64; 32]);
        let (tampered_key_run, _) =
            create_finished_class_run(&runs, "run-tampered-key", Utc::now(), &key).await;
        let envelope = blob_keys::envelope_path(&tampered_key_run, BlobClass::Body);
        let mut bytes = fs::read(&envelope).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&envelope, bytes).unwrap();
        assert!(erase_blob_class(&tampered_key_run, BlobClass::Body, &key).is_err());
        assert!(
            read_erasure_state(&tampered_key_run, &key, BlobClass::Body)
                .unwrap()
                .is_none()
        );

        let (tampered_state_run, _) =
            create_finished_class_run(&runs, "run-tampered-state", Utc::now(), &key).await;
        erase_blob_class(&tampered_state_run, BlobClass::Pcap, &key).unwrap();
        let state_path = blob_keys::erasure_state_path(&tampered_state_run, BlobClass::Pcap);
        let mut bytes = fs::read(&state_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(state_path, bytes).unwrap();
        assert!(inspect_run_with_key(&tampered_state_run, true, Some(&key)).is_err());
        assert!(erase_blob_class(&tampered_state_run, BlobClass::Pcap, &key).is_err());

        let (pending_upload_run, _) =
            create_finished_class_run(&runs, "run-pending-class-upload", Utc::now(), &key).await;
        fs::create_dir(pending_upload_run.join(".upload")).unwrap();
        assert!(erase_blob_class(&pending_upload_run, BlobClass::TlsSecrets, &key).is_err());
        assert!(blob_keys::envelope_path(&pending_upload_run, BlobClass::TlsSecrets).exists());
        assert!(
            read_erasure_state(&pending_upload_run, &key, BlobClass::TlsSecrets)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn selective_erasure_rejects_legacy_run_key_blob_layout() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        let run = runs.join("run-legacy-layout");
        fs::create_dir_all(&run).unwrap();
        let key = EncryptionKey::new([65; 32]);
        let mut manifest = Manifest::new(
            "run-legacy-layout".to_owned(),
            CommandMetadata {
                argv: vec!["true".to_owned()],
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
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: None,
            blob_key_management: None,
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        write_atomic_authenticated(&run.join("manifest.json"), &manifest, Some(&key)).unwrap();
        let error = erase_blob_class(&run, BlobClass::Body, &key).unwrap_err();
        assert!(error.to_string().contains("legacy run-key blobs"));
    }

    #[test]
    fn preview_is_non_destructive_and_execute_audits_then_deletes() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let cutoff = Utc::now() - chrono::TimeDelta::days(30);
        let old = create_finished_run(&runs, "run-old", cutoff - chrono::TimeDelta::seconds(1));
        let recent =
            create_finished_run(&runs, "run-recent", cutoff + chrono::TimeDelta::seconds(1));

        let preview = prune_runs(&runs, cutoff, false, None).unwrap();
        assert_eq!(preview.eligible.len(), 1);
        assert!(old.is_dir());
        assert!(recent.is_dir());
        assert!(!runs.join(audit::AUDIT_FILE).exists());

        let platform_ttl = prune_uploaded_runs(&runs, cutoff, true, None).unwrap();
        assert_eq!(platform_ttl.deleted, 0);
        assert_eq!(platform_ttl.skipped.len(), 1);
        assert!(old.is_dir());

        let executed = prune_runs(&runs, cutoff, true, None).unwrap();
        assert_eq!(executed.deleted, 1);
        assert!(!old.exists());
        assert!(recent.is_dir());
        let audit_text = fs::read_to_string(runs.join(audit::AUDIT_FILE)).unwrap();
        assert!(audit_text.contains("retention_delete"));
        assert!(audit_text.contains("intent"));
        assert!(audit_text.contains("complete"));
        assert!(audit_text.contains("run-old"));
        assert_eq!(audit::verify(&runs).unwrap().records, 2);
    }

    #[test]
    fn never_deletes_running_or_mismatched_runs() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let old = Utc::now() - chrono::TimeDelta::days(90);
        let running = create_finished_run(&runs, "run-active", old);
        let manifest_path = running.join("manifest.json");
        let mut manifest = manifest::read(&manifest_path).unwrap();
        manifest.status = "running".to_owned();
        manifest.finished_at = None;
        write_atomic(&manifest_path, &manifest).unwrap();
        let mismatched = create_finished_run(&runs, "run-mismatch", old);
        let mismatch_manifest = mismatched.join("manifest.json");
        let mut manifest = manifest::read(&mismatch_manifest).unwrap();
        manifest.run_id = "run-other".to_owned();
        write_atomic(&mismatch_manifest, &manifest).unwrap();

        let report = prune_runs(
            &runs,
            Utc::now() - chrono::TimeDelta::from_std(Duration::from_secs(1)).unwrap(),
            true,
            None,
        )
        .unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.skipped.len(), 1);
        assert!(running.is_dir());
        assert!(mismatched.is_dir());
    }

    #[test]
    fn configured_upload_must_be_fully_acked_before_prune() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let old = Utc::now() - chrono::TimeDelta::days(90);
        let run = create_finished_run(&runs, "run-pending-upload", old);
        let manifest_path = run.join("manifest.json");
        let mut manifest = manifest::read(&manifest_path).unwrap();
        manifest.counts.events = 1;
        write_atomic(&manifest_path, &manifest).unwrap();
        let spool = run.join(".upload");
        fs::create_dir(&spool).unwrap();
        let state = serde_json::json!({
            "schema_version": 1,
            "api_origin": "https://platform.example/",
            "run_id": "run-pending-upload",
            "recording_id": "run-pending-upload#0000",
            "segment_no": 0,
            "first_seq": 1,
            "batch_max_events": 2000,
            "batch_max_bytes": 4_194_304,
            "acked_seq": 0,
            "sealed": false,
            "batches": [{
                "first_seq": 1,
                "last_seq": 1,
                "event_count": 1,
                "byte_length": 9,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "blobs": [],
                "created_at": Utc::now()
            }],
            "created_at": Utc::now(),
            "updated_at": Utc::now()
        });
        fs::write(
            spool.join(
                "state-b412c66ca2fce72e80b4426448194a173b21410c7547f2ad8ed7134115dff3e0.json",
            ),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();

        let report = prune_runs(&runs, Utc::now(), true, None).unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("not acknowledged"));
        assert!(run.is_dir());
    }

    #[test]
    fn explicit_remote_delete_overrides_incomplete_upload_but_local_ttl_does_not() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let old = Utc::now() - chrono::TimeDelta::days(90);
        let run_id = "run-explicit-delete-pending-upload";
        let run = create_finished_run(&runs, run_id, old);
        let manifest_path = run.join("manifest.json");
        let mut manifest = manifest::read(&manifest_path).unwrap();
        manifest.counts.events = 1;
        write_atomic(&manifest_path, &manifest).unwrap();
        let spool = run.join(".upload");
        fs::create_dir(&spool).unwrap();
        let state = serde_json::json!({
            "schema_version": 1,
            "api_origin": "https://platform.example/",
            "run_id": run_id,
            "recording_id": format!("{run_id}#0000"),
            "segment_no": 0,
            "first_seq": 1,
            "batch_max_events": 2000,
            "batch_max_bytes": 4_194_304,
            "acked_seq": 0,
            "sealed": false,
            "batches": [{
                "first_seq": 1,
                "last_seq": 1,
                "event_count": 1,
                "byte_length": 9,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "blobs": [],
                "created_at": Utc::now()
            }],
            "created_at": Utc::now(),
            "updated_at": Utc::now()
        });
        fs::write(
            spool.join(
                "state-b412c66ca2fce72e80b4426448194a173b21410c7547f2ad8ed7134115dff3e0.json",
            ),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();

        let local = prune_runs(&runs, Utc::now(), true, None).unwrap();
        assert_eq!(local.deleted, 0);
        assert!(run.is_dir());
        let request_id = Uuid::now_v7();
        let report = delete_uploaded_run(&runs, run_id, request_id, None).unwrap();
        assert!(report.deleted);
        assert!(!report.recovered);
        assert!(!run.exists());
        assert!(
            audit::has_request_record(&runs, "remote_delete", "complete", &request_id.to_string())
                .unwrap()
        );
    }

    #[test]
    fn remote_delete_accepts_verified_prior_local_retention() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let run_id = "run-local-retention-before-remote";
        let run = create_finished_run(&runs, run_id, Utc::now() - chrono::TimeDelta::days(90));
        let local = prune_runs(&runs, Utc::now(), true, None).unwrap();
        assert_eq!(local.deleted, 1);
        assert!(!run.exists());

        let request_id = Uuid::now_v7();
        let report = delete_uploaded_run(&runs, run_id, request_id, None).unwrap();
        assert!(!report.deleted);
        assert!(report.recovered);
        assert!(
            audit::has_request_record(&runs, "remote_delete", "complete", &request_id.to_string())
                .unwrap()
        );
    }
}
