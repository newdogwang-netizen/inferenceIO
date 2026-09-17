use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    input::validate_json_complexity,
    secure_fs::{open_regular_append_create, open_regular_read},
};

pub const AUDIT_FILE: &str = ".iorec-audit.jsonl";
const MAX_AUDIT_RECORD_BYTES: usize = 16 * 1024;
const MAX_AUDIT_RECORDS: u64 = 10_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub event_id: Uuid,
    pub wall_time: DateTime<Utc>,
    pub effective_uid: u32,
    pub process_id: u32,
    pub action: String,
    pub outcome: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_sha256: Option<String>,
    pub record_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditVerification {
    pub path: PathBuf,
    pub valid: bool,
    pub records: u64,
    pub last_sequence: u64,
    pub last_sha256: Option<String>,
}

pub fn append(
    runs_dir: &Path,
    action: &str,
    outcome: &str,
    run_id: &str,
    details: Option<Value>,
) -> anyhow::Result<AuditRecord> {
    validate_label("action", action)?;
    validate_label("outcome", outcome)?;
    validate_label("run ID", run_id)?;
    let runs_dir = real_directory(runs_dir)?;
    let path = runs_dir.join(AUDIT_FILE);
    let file = open_regular_append_create(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut file =
        Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| io::Error::other(error))?;
    let scan = verify_locked_file(&mut file)?;
    let previous = scan.last_record;
    let sequence = previous.as_ref().map_or(Ok(1), |record| {
        record
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("audit sequence overflow"))
    })?;
    let mut record = AuditRecord {
        schema_version: 1,
        sequence,
        event_id: Uuid::now_v7(),
        wall_time: Utc::now(),
        effective_uid: fs::metadata("/proc/self")?.uid(),
        process_id: std::process::id(),
        action: action.to_owned(),
        outcome: outcome.to_owned(),
        run_id: run_id.to_owned(),
        details,
        previous_sha256: previous.map(|record| record.record_sha256),
        record_sha256: String::new(),
    };
    record.record_sha256 = record_hash(&record)?;
    validate_record(&record)?;
    let mut bytes = serde_json::to_vec(&record)?;
    validate_json_complexity(&bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_AUDIT_RECORD_BYTES,
        "audit record exceeds the {MAX_AUDIT_RECORD_BYTES}-byte safety limit"
    );
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(&runs_dir)?.sync_all()?;
    Ok(record)
}

pub fn verify(runs_dir: &Path) -> anyhow::Result<AuditVerification> {
    let runs_dir = real_directory(runs_dir)?;
    let path = runs_dir.join(AUDIT_FILE);
    let file = open_regular_read(&path)?;
    let mut file =
        Flock::lock(file, FlockArg::LockShared).map_err(|(_, error)| io::Error::other(error))?;
    let scan = verify_locked_file(&mut file)?;
    Ok(AuditVerification {
        path,
        valid: true,
        records: scan.records,
        last_sequence: scan.records,
        last_sha256: scan.last_record.map(|record| record.record_sha256),
    })
}

/// Searches a fully verified audit chain for a request-scoped operation. The
/// shared lock prevents a writer from changing the file between verification
/// and the match, so this can safely drive crash recovery for destructive
/// operations.
pub fn has_request_record(
    runs_dir: &Path,
    action: &str,
    outcome: &str,
    request_id: &str,
) -> anyhow::Result<bool> {
    validate_label("action", action)?;
    validate_label("outcome", outcome)?;
    validate_label("request ID", request_id)?;
    let runs_dir = real_directory(runs_dir)?;
    let path = runs_dir.join(AUDIT_FILE);
    let file = match open_regular_read(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut file =
        Flock::lock(file, FlockArg::LockShared).map_err(|(_, error)| io::Error::other(error))?;
    Ok(verify_locked_file_matching(
        &mut file,
        Some(&AuditMatch::Request {
            action,
            outcome,
            request_id,
        }),
    )?
    .1)
}

/// Searches a fully verified audit chain for a completed run-scoped action.
/// This lets a later remote-delete request prove that an already-absent run
/// was erased by local retention rather than silently accepting ambiguity.
pub fn has_run_record(
    runs_dir: &Path,
    action: &str,
    outcome: &str,
    run_id: &str,
) -> anyhow::Result<bool> {
    validate_label("action", action)?;
    validate_label("outcome", outcome)?;
    validate_label("run ID", run_id)?;
    let runs_dir = real_directory(runs_dir)?;
    let path = runs_dir.join(AUDIT_FILE);
    let file = match open_regular_read(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut file =
        Flock::lock(file, FlockArg::LockShared).map_err(|(_, error)| io::Error::other(error))?;
    Ok(verify_locked_file_matching(
        &mut file,
        Some(&AuditMatch::Run {
            action,
            outcome,
            run_id,
        }),
    )?
    .1)
}

struct AuditScan {
    records: u64,
    last_record: Option<AuditRecord>,
}

fn verify_locked_file(file: &mut File) -> anyhow::Result<AuditScan> {
    Ok(verify_locked_file_matching(file, None)?.0)
}

enum AuditMatch<'a> {
    Request {
        action: &'a str,
        outcome: &'a str,
        request_id: &'a str,
    },
    Run {
        action: &'a str,
        outcome: &'a str,
        run_id: &'a str,
    },
}

fn verify_locked_file_matching(
    file: &mut File,
    target: Option<&AuditMatch<'_>>,
) -> anyhow::Result<(AuditScan, bool)> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(&mut *file);
    let mut previous_hash = None;
    let mut records = 0_u64;
    let mut last_record = None;
    let mut matched = false;
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(u64::try_from(MAX_AUDIT_RECORD_BYTES).unwrap_or(u64::MAX) + 2)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        anyhow::ensure!(
            line.ends_with(b"\n"),
            "audit log ends with an incomplete record"
        );
        line.pop();
        anyhow::ensure!(
            !line.is_empty() && line.len() <= MAX_AUDIT_RECORD_BYTES,
            "audit record is empty or exceeds its safety limit"
        );
        validate_json_complexity(&line)?;
        let record: AuditRecord = serde_json::from_slice(&line)?;
        validate_record(&record)?;
        records = records.saturating_add(1);
        anyhow::ensure!(
            records <= MAX_AUDIT_RECORDS,
            "audit log exceeds the record-count safety limit"
        );
        anyhow::ensure!(
            record.sequence == records,
            "audit sequence is not contiguous"
        );
        anyhow::ensure!(
            record.previous_sha256 == previous_hash,
            "audit hash chain is broken at sequence {}",
            record.sequence
        );
        anyhow::ensure!(
            record.record_sha256 == record_hash(&record)?,
            "audit record hash mismatch at sequence {}",
            record.sequence
        );
        previous_hash = Some(record.record_sha256.clone());
        if let Some(target) = target {
            matched |=
                match target {
                    AuditMatch::Request {
                        action,
                        outcome,
                        request_id,
                    } => {
                        record.action == *action
                            && record.outcome == *outcome
                            && record.details.as_ref().and_then(|details| {
                                details.get("request_id").and_then(Value::as_str)
                            }) == Some(*request_id)
                    }
                    AuditMatch::Run {
                        action,
                        outcome,
                        run_id,
                    } => {
                        record.action == *action
                            && record.outcome == *outcome
                            && record.run_id == *run_id
                    }
                };
        }
        last_record = Some(record);
    }
    drop(reader);
    file.seek(SeekFrom::End(0))?;
    Ok((
        AuditScan {
            records,
            last_record,
        },
        matched,
    ))
}

fn record_hash(record: &AuditRecord) -> anyhow::Result<String> {
    let mut canonical = record.clone();
    canonical.record_sha256.clear();
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(serde_json::to_vec(&canonical)?))
    ))
}

fn validate_record(record: &AuditRecord) -> anyhow::Result<()> {
    anyhow::ensure!(record.schema_version == 1, "unsupported audit schema");
    anyhow::ensure!(record.sequence > 0, "audit sequence must be positive");
    anyhow::ensure!(!record.event_id.is_nil(), "audit event ID must not be nil");
    validate_label("action", &record.action)?;
    validate_label("outcome", &record.outcome)?;
    validate_label("run ID", &record.run_id)?;
    validate_hash(&record.record_sha256)?;
    if let Some(previous) = &record.previous_sha256 {
        validate_hash(previous)?;
    }
    Ok(())
}

fn validate_label(name: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 256 && !value.contains(['\0', '\r', '\n']),
        "audit {name} is empty, too long, or contains delimiters"
    );
    Ok(())
}

fn validate_hash(value: &str) -> anyhow::Result<()> {
    let Some(hash) = value.strip_prefix("sha256:") else {
        anyhow::bail!("audit hash has no sha256 prefix");
    };
    anyhow::ensure!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "audit hash is invalid"
    );
    Ok(())
}

fn real_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "audit root must be a real directory"
    );
    Ok(path.canonicalize()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_verifies_a_hash_chained_log() {
        let temporary = tempfile::tempdir().unwrap();
        let first = append(
            temporary.path(),
            "export",
            "intent",
            "run-1",
            Some(serde_json::json!({"format": "raw"})),
        )
        .unwrap();
        let second = append(temporary.path(), "export", "complete", "run-1", None).unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(second.previous_sha256, Some(first.record_sha256));
        let report = verify(temporary.path()).unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(report.last_sha256, Some(second.record_sha256));
    }

    #[test]
    fn detects_record_tampering_and_incomplete_tails() {
        let temporary = tempfile::tempdir().unwrap();
        append(
            temporary.path(),
            "sensitive_export",
            "intent",
            "run-1",
            None,
        )
        .unwrap();
        let path = temporary.path().join(AUDIT_FILE);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("intent", "failed")).unwrap();
        assert!(verify(temporary.path()).is_err());

        fs::write(&path, b"{\"incomplete\":true}").unwrap();
        assert!(verify(temporary.path()).is_err());
    }

    #[test]
    fn append_rejects_tampering_before_the_last_record() {
        let temporary = tempfile::tempdir().unwrap();
        append(temporary.path(), "export", "intent", "run-1", None).unwrap();
        append(temporary.path(), "export", "complete", "run-1", None).unwrap();

        let path = temporary.path().join(AUDIT_FILE);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replacen("intent", "failed", 1)).unwrap();

        assert!(append(temporary.path(), "run_start", "complete", "run-2", None).is_err());
        assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 2);
    }

    #[test]
    fn finds_request_record_only_after_verifying_the_chain() {
        let temporary = tempfile::tempdir().unwrap();
        append(
            temporary.path(),
            "remote_delete",
            "intent",
            "run-1",
            Some(serde_json::json!({"request_id": "request-1"})),
        )
        .unwrap();
        assert!(
            has_request_record(temporary.path(), "remote_delete", "intent", "request-1").unwrap()
        );
        assert!(
            !has_request_record(temporary.path(), "remote_delete", "complete", "request-1")
                .unwrap()
        );

        let path = temporary.path().join(AUDIT_FILE);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(path, text.replace("intent", "failed")).unwrap();
        assert!(
            has_request_record(temporary.path(), "remote_delete", "intent", "request-1").is_err()
        );
    }

    #[test]
    fn finds_run_record_only_after_verifying_the_chain() {
        let temporary = tempfile::tempdir().unwrap();
        append(
            temporary.path(),
            "retention_delete",
            "complete",
            "run-1",
            None,
        )
        .unwrap();
        assert!(has_run_record(temporary.path(), "retention_delete", "complete", "run-1").unwrap());
        assert!(
            !has_run_record(temporary.path(), "retention_delete", "complete", "run-2").unwrap()
        );

        let path = temporary.path().join(AUDIT_FILE);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(path, text.replace("complete", "failed")).unwrap();
        assert!(has_run_record(temporary.path(), "retention_delete", "complete", "run-1").is_err());
    }
}
