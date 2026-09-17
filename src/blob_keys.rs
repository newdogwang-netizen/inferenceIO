use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use nix::fcntl::{RenameFlags, renameat2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{crypto::EncryptionKey, model::PayloadRef, secure_fs::read_regular_limited};

pub const BLOB_KEY_MANAGEMENT_V1: &str = "random-class-dek-wrapped-by-run-key-v1";
pub const KEY_DIRECTORY_NAME: &str = "blob-keys";
pub const RETENTION_DIRECTORY_NAME: &str = "retention";
const MAX_WRAPPED_KEY_BYTES: usize = 1024;
const MAX_RETENTION_STATE_BYTES: usize = 64 * 1024;
const ENCRYPTED_BLOB_OVERHEAD_BYTES: usize = 8 + 24 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobClass {
    Body,
    Pcap,
    TlsSecrets,
}

impl BlobClass {
    pub const ALL: [Self; 3] = [Self::Body, Self::Pcap, Self::TlsSecrets];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Pcap => "pcap",
            Self::TlsSecrets => "tls_secrets",
        }
    }

    #[must_use]
    pub fn from_media_type(media_type: Option<&str>) -> Self {
        match media_type {
            Some("application/vnd.tcpdump.pcap") => Self::Pcap,
            Some("application/x-nss-key-log") => Self::TlsSecrets,
            _ => Self::Body,
        }
    }

    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "body" => Ok(Self::Body),
            "pcap" => Ok(Self::Pcap),
            "tls_secrets" => Ok(Self::TlsSecrets),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported blob retention class",
            )),
        }
    }
}

#[derive(Clone)]
pub struct BlobKeyring {
    body: EncryptionKey,
    pcap: EncryptionKey,
    tls_secrets: EncryptionKey,
}

impl BlobKeyring {
    #[must_use]
    pub const fn key(&self, class: BlobClass) -> &EncryptionKey {
        match class {
            BlobClass::Body => &self.body,
            BlobClass::Pcap => &self.pcap,
            BlobClass::TlsSecrets => &self.tls_secrets,
        }
    }
}

impl std::fmt::Debug for BlobKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlobKeyring")
            .field("body_key_id", &self.body.key_id())
            .field("pcap_key_id", &self.pcap.key_id())
            .field("tls_secrets_key_id", &self.tls_secrets.key_id())
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassErasureState {
    pub schema_version: u32,
    pub class: BlobClass,
    pub phase: ClassErasurePhase,
    pub operation_id: Uuid,
    pub envelope_sha256: String,
    pub blob_files: u64,
    pub blob_storage_bytes: u64,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassErasurePhase {
    Intent,
    Complete,
}

pub fn prepare_for_writer(
    run_dir: &Path,
    run_key: Option<&EncryptionKey>,
    has_legacy_data: bool,
) -> io::Result<Option<BlobKeyring>> {
    let Some(run_key) = run_key else {
        return Ok(None);
    };
    if has_keyring(run_dir)? {
        return load_keyring(run_dir, run_key).map(Some);
    }
    if has_legacy_data {
        return Ok(None);
    }
    initialize_keyring(run_dir, run_key)?;
    load_keyring(run_dir, run_key).map(Some)
}

pub fn has_keyring(run_dir: &Path) -> io::Result<bool> {
    let directory = key_directory(run_dir);
    match fs::symlink_metadata(&directory) {
        Ok(_) => {
            require_private_directory(&directory, "blob key directory")?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn load_class_key(
    run_dir: &Path,
    run_key: &EncryptionKey,
    class: BlobClass,
) -> io::Result<Option<EncryptionKey>> {
    let directory = key_directory(run_dir);
    if !has_keyring(run_dir)? {
        return Ok(None);
    }
    require_private_directory(&directory, "blob key directory")?;
    let path = envelope_path(run_dir, class);
    match read_regular_limited(&path, MAX_WRAPPED_KEY_BYTES) {
        Ok(encoded) => run_key.unwrap_data_key(&encoded, class.as_str()).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if read_erasure_state(run_dir, run_key, class)?.is_some() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} blob class was cryptographically erased", class.as_str()),
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} blob class key envelope is missing", class.as_str()),
                ))
            }
        }
        Err(error) => Err(error),
    }
}

pub fn load_keyring(run_dir: &Path, run_key: &EncryptionKey) -> io::Result<BlobKeyring> {
    let body = require_active_key(load_class_key(run_dir, run_key, BlobClass::Body)?, "body")?;
    let pcap = require_active_key(load_class_key(run_dir, run_key, BlobClass::Pcap)?, "pcap")?;
    let tls_secrets = require_active_key(
        load_class_key(run_dir, run_key, BlobClass::TlsSecrets)?,
        "tls_secrets",
    )?;
    Ok(BlobKeyring {
        body,
        pcap,
        tls_secrets,
    })
}

fn require_active_key(key: Option<EncryptionKey>, class: &str) -> io::Result<EncryptionKey> {
    key.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{class} class key cannot be loaded from a legacy run"),
        )
    })
}

fn initialize_keyring(run_dir: &Path, run_key: &EncryptionKey) -> io::Result<()> {
    require_private_directory(run_dir, "run directory")?;
    let temporary_name = format!(".blob-keys-{}.tmp", Uuid::now_v7());
    let temporary = run_dir.join(&temporary_name);
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(&temporary)?;
    let result = (|| {
        for class in BlobClass::ALL {
            let (_, wrapped) = run_key.generate_wrapped_data_key(class.as_str())?;
            let path = temporary.join(envelope_file_name(class));
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&wrapped)?;
            file.sync_all()?;
        }
        File::open(&temporary)?.sync_all()?;
        let run_handle = File::open(run_dir)?;
        renameat2(
            &run_handle,
            Path::new(&temporary_name),
            &run_handle,
            Path::new(KEY_DIRECTORY_NAME),
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(io::Error::from)?;
        run_handle.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

pub fn blob_file_name(hash: &str, class: Option<BlobClass>) -> io::Result<String> {
    validate_hash(hash)?;
    Ok(class.map_or_else(
        || format!("sha256-{hash}"),
        |class| format!("{}-sha256-{hash}", class.as_str()),
    ))
}

pub fn blob_path(run_dir: &Path, reference: &PayloadRef) -> io::Result<PathBuf> {
    let hash = reference.sha256.strip_prefix("sha256:").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob reference has no SHA-256 prefix",
        )
    })?;
    let class =
        has_keyring(run_dir)?.then(|| BlobClass::from_media_type(reference.media_type.as_deref()));
    Ok(run_dir.join("blobs").join(blob_file_name(hash, class)?))
}

/// Read and authenticate one payload reference from either a legacy run-key
/// blob store or a class-keyed blob store. The caller supplies the effective
/// per-run key; plaintext runs must supply `None`.
pub fn read_blob_reference(
    run_dir: &Path,
    reference: &PayloadRef,
    run_key: Option<&EncryptionKey>,
    max_plaintext_bytes: usize,
) -> io::Result<Vec<u8>> {
    let hash = reference.sha256.strip_prefix("sha256:").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob reference has no SHA-256 prefix",
        )
    })?;
    validate_hash(hash)?;
    let reference_size = usize::try_from(reference.size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob reference size is too large for this platform",
        )
    })?;
    if reference_size > max_plaintext_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "blob reference exceeds the caller safety limit",
        ));
    }
    let class_keyed = has_keyring(run_dir)?;
    let path = run_dir.join("blobs").join(blob_file_name(
        hash,
        class_keyed.then(|| BlobClass::from_media_type(reference.media_type.as_deref())),
    )?);
    let encoded_limit = reference_size
        .checked_add(ENCRYPTED_BLOB_OVERHEAD_BYTES)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "blob size overflows usize"))?;
    let encoded = read_regular_limited(&path, encoded_limit)?;
    let plaintext = if crate::crypto::is_encrypted_blob(&encoded) {
        let run_key = run_key.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encrypted blob requires the matching effective run key",
            )
        })?;
        let key = if class_keyed {
            let class = BlobClass::from_media_type(reference.media_type.as_deref());
            load_class_key(run_dir, run_key, class)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "class-keyed blob has no class encryption key",
                )
            })?
        } else {
            run_key.clone()
        };
        key.decrypt_blob(&encoded, hash)?
    } else {
        if class_keyed || run_key.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "plaintext blob found in an encrypted run",
            ));
        }
        encoded
    };
    if plaintext.len() != reference_size || hex::encode(Sha256::digest(&plaintext)) != hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "blob content does not match its reference",
        ));
    }
    Ok(plaintext)
}

pub fn parse_blob_file_name(name: &str) -> io::Result<(Option<BlobClass>, String)> {
    if let Some(hash) = name.strip_prefix("sha256-") {
        validate_hash(hash)?;
        return Ok((None, hash.to_owned()));
    }
    for class in BlobClass::ALL {
        let prefix = format!("{}-sha256-", class.as_str());
        if let Some(hash) = name.strip_prefix(&prefix) {
            validate_hash(hash)?;
            return Ok((Some(class), hash.to_owned()));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "blob file name is not recognized",
    ))
}

pub fn reference_identity(run_dir: &Path, reference: &PayloadRef) -> io::Result<String> {
    if has_keyring(run_dir)? {
        let class = BlobClass::from_media_type(reference.media_type.as_deref());
        Ok(format!("{}:{}", class.as_str(), reference.sha256))
    } else {
        Ok(reference.sha256.clone())
    }
}

#[must_use]
pub fn file_identity(class: Option<BlobClass>, hash: &str) -> String {
    class.map_or_else(
        || format!("sha256:{hash}"),
        |class| format!("{}:sha256:{hash}", class.as_str()),
    )
}

#[must_use]
pub fn identity_class(identity: &str) -> Option<BlobClass> {
    BlobClass::ALL.into_iter().find(|class| {
        identity
            .strip_prefix(class.as_str())
            .is_some_and(|suffix| suffix.starts_with(":sha256:"))
    })
}

pub fn read_erasure_state(
    run_dir: &Path,
    run_key: &EncryptionKey,
    class: BlobClass,
) -> io::Result<Option<ClassErasureState>> {
    let path = erasure_state_path(run_dir, class);
    let encoded = match read_regular_limited(&path, MAX_RETENTION_STATE_BYTES) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let plaintext = run_key.decrypt_retention_state(&encoded)?;
    let state: ClassErasureState = serde_json::from_slice(&plaintext)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_erasure_state(&state, class)?;
    Ok(Some(state))
}

pub fn write_erasure_state(
    run_dir: &Path,
    run_key: &EncryptionKey,
    state: &ClassErasureState,
) -> io::Result<()> {
    validate_erasure_state(state, state.class)?;
    let directory = retention_directory(run_dir);
    if !directory.try_exists()? {
        let mut builder = fs::DirBuilder::new();
        match builder.mode(0o700).create(&directory) {
            Ok(()) => File::open(run_dir)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    require_private_directory(&directory, "retention directory")?;
    let plaintext = serde_json::to_vec(state)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let encoded = run_key.encrypt_retention_state(&plaintext)?;
    write_private_atomic(&erasure_state_path(run_dir, state.class), &encoded)
}

#[must_use]
pub fn key_directory(run_dir: &Path) -> PathBuf {
    run_dir.join(KEY_DIRECTORY_NAME)
}

#[must_use]
pub fn retention_directory(run_dir: &Path) -> PathBuf {
    run_dir.join(RETENTION_DIRECTORY_NAME)
}

#[must_use]
pub fn envelope_path(run_dir: &Path, class: BlobClass) -> PathBuf {
    key_directory(run_dir).join(envelope_file_name(class))
}

#[must_use]
pub fn erasure_state_path(run_dir: &Path, class: BlobClass) -> PathBuf {
    retention_directory(run_dir).join(format!("{}.state.enc", class.as_str()))
}

#[must_use]
pub fn envelope_sha256(encoded: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(encoded)))
}

fn envelope_file_name(class: BlobClass) -> String {
    format!("{}.key.enc", class.as_str())
}

fn validate_hash(hash: &str) -> io::Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "blob SHA-256 is invalid",
        ));
    }
    Ok(())
}

fn validate_erasure_state(state: &ClassErasureState, class: BlobClass) -> io::Result<()> {
    let envelope_hash = state
        .envelope_sha256
        .strip_prefix("sha256:")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid envelope SHA-256"))?;
    let timestamp_consistent = match (state.phase, state.completed_at) {
        (ClassErasurePhase::Intent, None) => true,
        (ClassErasurePhase::Complete, Some(completed)) => completed >= state.requested_at,
        _ => false,
    };
    if state.schema_version != 1
        || state.class != class
        || state.operation_id.is_nil()
        || !timestamp_consistent
        || validate_hash(envelope_hash).is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retention state is inconsistent",
        ));
    }
    Ok(())
}

fn require_private_directory(path: &Path, label: &str) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must be a private real directory"),
        ));
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "atomic output has no parent")
    })?;
    require_private_directory(parent, "atomic output directory")?;
    let output_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic output has no file name",
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        output_name.to_string_lossy(),
        Uuid::now_v7()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
