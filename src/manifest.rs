use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    RECORDER_VERSION, crypto::EncryptionKey, input::validate_stored_json_complexity,
    policy::CapturePolicy, secure_fs::read_regular_limited,
};

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const RUN_KEY_DERIVATION_V1: &str = "hkdf-sha256-run-id-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandMetadata {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executable_tls_surfaces: Vec<String>,
    #[serde(default)]
    pub environment: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CoverageCounts {
    pub events: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub event_storage_bytes: u64,
    pub blobs: u64,
    /// Total plaintext bytes represented by unique referenced blobs.
    pub blob_bytes: u64,
    /// Actual bytes occupied by blob files, including encryption framing.
    pub blob_storage_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub logical_tasks: u64,
    pub logical_inferences: u64,
    pub transport_attempts: u64,
    pub completed_attempts: u64,
    pub incomplete_attempts: u64,
    pub errors: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub models: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Coverage {
    /// v0.1 is intentionally incapable of producing a complete claim.
    pub claim: String,
    pub capture_sources: Vec<String>,
    pub known_gaps: Vec<String>,
    #[serde(default, skip_serializing_if = "is_empty_count_map")]
    pub observed_tls_surfaces: std::collections::BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "is_empty_count_map")]
    pub observed_egress_classes: std::collections::BTreeMap<String, u64>,
    pub unknown_tls_surfaces: u64,
    pub unparsed_connections: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub process_network_scan_gaps: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub process_scan_failures: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub processes_running_at_stop: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub connections_open_at_stop: u64,
    pub capture_drops: u64,
    pub unknown_egress: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub task_netns_denied_packets: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub blocked_unknown_egress_indicators: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub model_bypass_connections: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub possible_quic_connections: u64,
    pub all_attempts_have_terminal_state: bool,
    pub unresolved_state_references: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unresolved_payload_references: u64,
    pub unresolved_correlations: u64,
    pub captured_request_payloads_complete: bool,
    pub captured_response_payloads_complete: bool,
    pub observed_protocols: std::collections::BTreeMap<String, u64>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_empty_count_map(value: &std::collections::BTreeMap<String, u64>) -> bool {
    value.is_empty()
}

impl Default for Coverage {
    fn default() -> Self {
        Self {
            claim: "best-effort".to_owned(),
            capture_sources: Vec::new(),
            known_gaps: vec![
                "the manifest remains best-effort; transport completeness is established only by a separate successful offline transport-audit"
                    .to_owned(),
            ],
            observed_tls_surfaces: std::collections::BTreeMap::new(),
            observed_egress_classes: std::collections::BTreeMap::new(),
            unknown_tls_surfaces: 0,
            unparsed_connections: 0,
            process_network_scan_gaps: 0,
            process_scan_failures: 0,
            processes_running_at_stop: 0,
            connections_open_at_stop: 0,
            capture_drops: 0,
            unknown_egress: 0,
            task_netns_denied_packets: 0,
            blocked_unknown_egress_indicators: 0,
            model_bypass_connections: 0,
            possible_quic_connections: 0,
            all_attempts_have_terminal_state: false,
            unresolved_state_references: 0,
            unresolved_payload_references: 0,
            unresolved_correlations: 0,
            captured_request_payloads_complete: false,
            captured_response_payloads_complete: false,
            observed_protocols: std::collections::BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    pub events: String,
    pub blobs: String,
    pub durability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_tail_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_derivation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_key_management: Option<String>,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAuthentication {
    pub algorithm: String,
    pub key_id: String,
    pub nonce: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub recorder_version: String,
    pub run_id: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub command: CommandMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_plan: Option<crate::probe_plan::ProbePlan>,
    pub policy: CapturePolicy,
    pub counts: CoverageCounts,
    pub coverage: Coverage,
    pub storage: StorageMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ManifestAuthentication>,
}

impl Manifest {
    #[must_use]
    pub fn new(run_id: String, command: CommandMetadata, policy: CapturePolicy) -> Self {
        Self {
            schema_version: 1,
            recorder_version: RECORDER_VERSION.to_owned(),
            run_id,
            status: "running".to_owned(),
            started_at: Utc::now(),
            finished_at: None,
            exit_code: None,
            command,
            probe_plan: None,
            policy,
            counts: CoverageCounts::default(),
            coverage: Coverage::default(),
            storage: StorageMetadata {
                events: "events.jsonl".to_owned(),
                blobs: "blobs/".to_owned(),
                durability: "sync-data-before-ack-concurrent-batch-v1".to_owned(),
                recovered_tail_bytes: None,
                encryption: None,
            },
            authentication: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported manifest schema {}",
                self.schema_version
            ));
        }
        if self.coverage.claim != "best-effort" {
            return Err("v0.1 manifests may only claim best-effort coverage".to_owned());
        }
        validate_manifest_text("recorder version", &self.recorder_version, 128)?;
        validate_manifest_text("run ID", &self.run_id, 256)?;
        self.policy
            .validate()
            .map_err(|error| format!("manifest capture policy is invalid: {error}"))?;
        if !matches!(
            self.status.as_str(),
            "running" | "finished" | "failed" | "recorder_error"
        ) {
            return Err("manifest contains an invalid run status".to_owned());
        }
        if self.storage.events != "events.jsonl" || self.storage.blobs != "blobs/" {
            return Err("manifest storage paths are not supported".to_owned());
        }
        if self.command.argv.is_empty() {
            return Err("manifest command argv must not be empty".to_owned());
        }
        validate_optional_manifest_text("agent", self.command.agent.as_deref(), 128)?;
        validate_optional_manifest_text(
            "agent version",
            self.command.agent_version.as_deref(),
            256,
        )?;
        validate_optional_manifest_text("runtime", self.command.runtime.as_deref(), 128)?;
        if let Some(plan) = &self.probe_plan {
            plan.validate()?;
            let mut command_tls_surfaces = self.command.executable_tls_surfaces.clone();
            command_tls_surfaces.sort();
            command_tls_surfaces.dedup();
            if plan.runtime != self.command.runtime
                || plan.executable_tls_surfaces != command_tls_surfaces
            {
                return Err("probe plan does not match command discovery metadata".to_owned());
            }
        }
        validate_manifest_text_list(
            "executable TLS surface",
            &self.command.executable_tls_surfaces,
            128,
            1_024,
        )?;
        validate_manifest_text_list(
            "capture source",
            &self.coverage.capture_sources,
            1_024,
            1_024,
        )?;
        validate_manifest_text_list("known gap", &self.coverage.known_gaps, 10_000, 4_096)?;
        validate_manifest_count_map("model", &self.counts.models, 10_000, 1_024)?;
        validate_manifest_count_map(
            "observed TLS surface",
            &self.coverage.observed_tls_surfaces,
            1_024,
            1_024,
        )?;
        validate_manifest_count_map(
            "observed egress class",
            &self.coverage.observed_egress_classes,
            8,
            64,
        )?;
        if self.coverage.observed_egress_classes.keys().any(|class| {
            !matches!(
                class.as_str(),
                "model_recorder"
                    | "model_bypass"
                    | "local"
                    | "auth"
                    | "telemetry"
                    | "update"
                    | "other"
                    | "unknown_external"
            )
        }) {
            return Err("manifest contains an unsupported observed egress class".to_owned());
        }
        validate_manifest_count_map(
            "observed protocol",
            &self.coverage.observed_protocols,
            128,
            256,
        )?;
        if let Some(encryption) = &self.storage.encryption {
            if encryption.algorithm != "XChaCha20-Poly1305" {
                return Err("unsupported storage encryption algorithm".to_owned());
            }
            if encryption.key_id.len() != 64
                || !encryption
                    .key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("invalid storage encryption key ID".to_owned());
            }
            if encryption
                .key_derivation
                .as_deref()
                .is_some_and(|derivation| derivation != RUN_KEY_DERIVATION_V1)
            {
                return Err("unsupported storage key derivation".to_owned());
            }
            if encryption
                .blob_key_management
                .as_deref()
                .is_some_and(|management| management != crate::blob_keys::BLOB_KEY_MANAGEMENT_V1)
            {
                return Err("unsupported blob key management".to_owned());
            }
            if !encryption.scope.iter().any(|scope| scope == "events")
                || !encryption.scope.iter().any(|scope| scope == "blobs")
            {
                return Err("storage encryption must cover events and blobs".to_owned());
            }
        }
        if let Some(authentication) = &self.authentication {
            let encryption = self.storage.encryption.as_ref().ok_or_else(|| {
                "manifest authentication requires encrypted storage metadata".to_owned()
            })?;
            if authentication.algorithm != "XChaCha20-Poly1305-AAD" {
                return Err("unsupported manifest authentication algorithm".to_owned());
            }
            if authentication.key_id != encryption.key_id {
                return Err("manifest authentication key ID does not match storage".to_owned());
            }
            if authentication.nonce.len() > 128 || authentication.tag.len() > 128 {
                return Err("manifest authentication framing is too large".to_owned());
            }
        }
        Ok(())
    }

    pub fn authenticate(&mut self, key: &EncryptionKey) -> io::Result<()> {
        let encryption = self.storage.encryption.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot authenticate a manifest without encrypted storage metadata",
            )
        })?;
        if encryption.key_id != key.key_id() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "manifest authentication key does not match storage metadata",
            ));
        }
        let authentication_key_id = encryption.key_id.clone();
        let effective_key = self.effective_encryption_key(Some(key))?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "encrypted manifest has no key")
        })?;
        self.authentication = None;
        let canonical = serde_json::to_vec(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let (nonce, tag) = effective_key.authenticate_manifest(&canonical)?;
        self.authentication = Some(ManifestAuthentication {
            algorithm: "XChaCha20-Poly1305-AAD".to_owned(),
            key_id: authentication_key_id,
            nonce,
            tag,
        });
        Ok(())
    }

    /// Returns `false` for readable legacy encrypted manifests that predate
    /// manifest authentication. An invalid present authenticator is an error.
    pub fn verify_authentication(&self, key: Option<&EncryptionKey>) -> io::Result<Option<bool>> {
        if self.storage.encryption.is_none() {
            return Ok(None);
        }
        let key = self.effective_encryption_key(key)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encrypted run requires a key",
            )
        })?;
        let Some(authentication) = self.authentication.as_ref() else {
            return Ok(Some(false));
        };
        let mut canonical = self.clone();
        canonical.authentication = None;
        let canonical = serde_json::to_vec(&canonical)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        key.verify_manifest_authentication(&canonical, &authentication.nonce, &authentication.tag)?;
        Ok(Some(true))
    }

    pub fn effective_encryption_key(
        &self,
        provided: Option<&EncryptionKey>,
    ) -> io::Result<Option<EncryptionKey>> {
        let Some(metadata) = self.storage.encryption.as_ref() else {
            return Ok(None);
        };
        let key = provided.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "run is encrypted; provide --key-file",
            )
        })?;
        if key.key_id() != metadata.key_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encryption key ID does not match this run",
            ));
        }
        match metadata.key_derivation.as_deref() {
            None => Ok(Some(key.clone())),
            Some(RUN_KEY_DERIVATION_V1) => key.derive_run_key(&self.run_id).map(Some),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported storage key derivation",
            )),
        }
    }
}

fn validate_optional_manifest_text(
    name: &str,
    value: Option<&str>,
    maximum_bytes: usize,
) -> Result<(), String> {
    value.map_or(Ok(()), |value| {
        validate_manifest_text(name, value, maximum_bytes)
    })
}

fn validate_manifest_text(name: &str, value: &str, maximum_bytes: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(format!(
            "manifest {name} is empty, too long, or contains control characters"
        ));
    }
    Ok(())
}

fn validate_manifest_text_list(
    name: &str,
    values: &[String],
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<(), String> {
    if values.len() > maximum_items {
        return Err(format!("manifest {name} list has too many items"));
    }
    for value in values {
        validate_manifest_text(name, value, maximum_bytes)?;
    }
    Ok(())
}

fn validate_manifest_count_map(
    name: &str,
    values: &std::collections::BTreeMap<String, u64>,
    maximum_items: usize,
    maximum_key_bytes: usize,
) -> Result<(), String> {
    if values.len() > maximum_items {
        return Err(format!("manifest {name} map has too many items"));
    }
    for key in values.keys() {
        validate_manifest_text(name, key, maximum_key_bytes)?;
    }
    Ok(())
}

pub fn write_atomic(path: &Path, manifest: &Manifest) -> io::Result<()> {
    manifest
        .validate()
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    if !fs::symlink_metadata(parent)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest parent must be a real directory",
        ));
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(
        ".manifest-{}-{}.tmp",
        std::process::id(),
        Uuid::now_v7()
    ));
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_stored_json_complexity(&bytes)?;
    if bytes.len().saturating_add(1) > MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("manifest exceeds the {MAX_MANIFEST_BYTES}-byte safety limit"),
        ));
    }

    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn write_atomic_authenticated(
    path: &Path,
    manifest: &Manifest,
    key: Option<&EncryptionKey>,
) -> io::Result<()> {
    let mut manifest = manifest.clone();
    match manifest.storage.encryption.as_ref() {
        Some(_) => manifest.authenticate(key.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encrypted manifest writes require the matching key",
            )
        })?)?,
        None => manifest.authentication = None,
    }
    write_atomic(path, &manifest)
}

pub fn read(path: &Path) -> io::Result<Manifest> {
    let bytes = read_regular_limited(path, MAX_MANIFEST_BYTES)?;
    validate_stored_json_complexity(&bytes)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    manifest
        .validate()
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn unsupported_claims_and_terminal_control_metadata_are_rejected() {
        let mut manifest = Manifest::new(
            "run".to_owned(),
            CommandMetadata {
                argv: vec!["true".to_owned()],
                cwd: PathBuf::from("/tmp"),
                executable: None,
                executable_sha256: None,
                agent: None,
                agent_version: None,
                runtime: None,
                executable_tls_surfaces: Vec::new(),
                environment: BTreeMap::default(),
            },
            CapturePolicy::default(),
        );
        manifest.coverage.claim = "transport-complete".to_owned();
        assert!(manifest.validate().is_err());
        manifest.coverage.claim = "best-effort".to_owned();
        manifest.run_id = "run\u{1b}[31m".to_owned();
        assert!(manifest.validate().is_err());
        manifest.run_id = "run".to_owned();
        manifest.coverage.known_gaps = vec!["gap\nforged".to_owned()];
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn new_zero_coverage_fields_preserve_legacy_canonical_json() {
        let mut manifest = Manifest::new(
            "canonical".to_owned(),
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
        let encoded = serde_json::to_value(&manifest).unwrap();
        assert!(
            encoded
                .pointer("/coverage/unresolved_payload_references")
                .is_none()
        );
        assert!(encoded.pointer("/counts/event_storage_bytes").is_none());
        assert!(encoded.pointer("/coverage/observed_tls_surfaces").is_none());
        assert!(
            encoded
                .pointer("/coverage/observed_egress_classes")
                .is_none()
        );
        assert!(
            encoded
                .pointer("/command/executable_tls_surfaces")
                .is_none()
        );
        assert!(
            encoded
                .pointer("/coverage/possible_quic_connections")
                .is_none()
        );
        manifest.coverage.unresolved_payload_references = 1;
        manifest.counts.event_storage_bytes = 1;
        manifest.coverage.possible_quic_connections = 1;
        manifest
            .coverage
            .observed_tls_surfaces
            .insert("openssl-dynamic".to_owned(), 2);
        manifest
            .coverage
            .observed_egress_classes
            .insert("auth".to_owned(), 3);
        manifest.command.executable_tls_surfaces = vec!["rustls-binary-marker".to_owned()];
        let encoded = serde_json::to_value(&manifest).unwrap();
        assert_eq!(
            encoded.pointer("/coverage/unresolved_payload_references"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            encoded.pointer("/counts/event_storage_bytes"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            encoded.pointer("/coverage/observed_tls_surfaces/openssl-dynamic"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(
            encoded.pointer("/coverage/observed_egress_classes/auth"),
            Some(&serde_json::json!(3))
        );
        assert_eq!(
            encoded.pointer("/coverage/possible_quic_connections"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            encoded.pointer("/command/executable_tls_surfaces/0"),
            Some(&serde_json::json!("rustls-binary-marker"))
        );
    }

    #[test]
    fn atomic_write_replaces_a_symlink_without_touching_its_target() {
        let temporary = tempfile::tempdir().unwrap();
        let victim = temporary.path().join("victim");
        fs::write(&victim, b"do-not-touch").unwrap();
        let path = temporary.path().join("manifest.json");
        symlink(&victim, &path).unwrap();
        let manifest = Manifest::new(
            "safe-write".to_owned(),
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

        write_atomic(&path, &manifest).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"do-not-touch");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert_eq!(read(&path).unwrap().run_id, "safe-write");

        fs::remove_file(&path).unwrap();
        symlink(&victim, &path).unwrap();
        assert!(read(&path).is_err());
    }

    #[test]
    fn atomic_write_enforces_reader_limit_and_cleans_failed_temporary_files() {
        let temporary = tempfile::tempdir().unwrap();
        let mut manifest = Manifest::new(
            "bounded-write".to_owned(),
            CommandMetadata {
                argv: vec!["x".repeat(MAX_MANIFEST_BYTES)],
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
        let path = temporary.path().join("manifest.json");
        assert_eq!(
            write_atomic(&path, &manifest).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!path.exists());

        manifest.command.argv = vec!["true".to_owned()];
        fs::create_dir(&path).unwrap();
        assert!(write_atomic(&path, &manifest).is_err());
        assert!(fs::read_dir(temporary.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".manifest-")
        }));
    }

    #[test]
    fn encrypted_manifest_authentication_round_trips_and_detects_tampering() {
        let mut manifest = Manifest::new(
            "authenticated".to_owned(),
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
        let key = EncryptionKey::new([31; 32]);
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: None,
            blob_key_management: None,
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        manifest.authenticate(&key).unwrap();
        assert_eq!(
            manifest.verify_authentication(Some(&key)).unwrap(),
            Some(true)
        );
        manifest.status = "finished".to_owned();
        assert!(manifest.verify_authentication(Some(&key)).is_err());
    }

    #[test]
    fn derived_manifest_uses_master_identity_and_rejects_unknown_derivations() {
        let mut manifest = Manifest::new(
            "derived-run".to_owned(),
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
        let master = EncryptionKey::new([37; 32]);
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: master.key_id().to_owned(),
            key_derivation: Some(RUN_KEY_DERIVATION_V1.to_owned()),
            blob_key_management: None,
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        manifest.authenticate(&master).unwrap();
        assert_eq!(
            manifest
                .authentication
                .as_ref()
                .map(|auth| auth.key_id.as_str()),
            Some(master.key_id())
        );
        assert_eq!(
            manifest.verify_authentication(Some(&master)).unwrap(),
            Some(true)
        );
        let effective = manifest
            .effective_encryption_key(Some(&master))
            .unwrap()
            .unwrap();
        assert_ne!(effective.key_id(), master.key_id());
        assert!(manifest.verify_authentication(Some(&effective)).is_err());

        manifest.storage.encryption.as_mut().unwrap().key_derivation =
            Some("unknown-kdf".to_owned());
        assert!(manifest.validate().is_err());
    }
}
