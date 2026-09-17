use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Cursor, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::Utc;
use nix::fcntl::{RenameFlags, renameat2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

use crate::{
    blob_keys::{self, BlobClass, BlobKeyring},
    crypto::{EncryptionKey, is_encrypted_event},
    input::validate_stored_json_complexity,
    model::{EventEnvelope, PayloadRef, PendingEvent},
    policy::{CapturePolicy, EventLogFormat, MAX_CAPTURE_BODY_BYTES},
    secure_fs::{
        open_regular_append_create, open_regular_create, open_regular_read,
        open_regular_read_write, read_regular_limited,
    },
};

const EVENT_QUEUE_CAPACITY: usize = 4096;
const MAX_EVENT_RECORD_BYTES: usize = 24 * 1024 * 1024;
const EVENT_BLOCK_HEADER: &[u8] = b"IOREC-EVENTS-ZSTD-BLOCKS-V1\n";
const EVENT_BLOCK_CODEC: &str = "zstd";
const EVENT_BLOCK_VERSION: u8 = 1;
const MAX_EVENT_BLOCK_EVENTS: usize = 1_024;
const MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MAX_EVENT_BLOCK_COMPRESSED_BYTES: usize = 32 * 1024 * 1024 + 64 * 1024;
const MAX_EVENT_BLOCK_RECORD_BYTES: usize = 48 * 1024 * 1024;
const EVENT_BLOCK_COMPRESSION_LEVEL: i32 = 3;
const MAX_BLOB_DIRECTORY_ENTRIES: usize = 250_000;
const ENCRYPTED_BLOB_OVERHEAD_BYTES: u64 = 8 + 24 + 16;
pub(crate) const MAX_SINGLE_BLOB_BYTES: usize = MAX_CAPTURE_BODY_BYTES;
pub(crate) const MAX_ENCODED_BLOB_BYTES: usize = MAX_SINGLE_BLOB_BYTES + 8 + 24 + 16;

#[derive(Debug)]
struct BlobPersistError {
    error: io::Error,
    storage_retained: bool,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("event serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("writer is unavailable: {0}")]
    Writer(String),
    #[error("event sequence is invalid: expected {expected}, found {found}")]
    InvalidSequence { expected: u64, found: u64 },
    #[error("event run ID is invalid at sequence {sequence}: expected {expected}, found {found}")]
    InvalidRunId {
        expected: String,
        found: String,
        sequence: u64,
    },
    #[error("event encryption scope is invalid at record {record}: expected {expected}")]
    InvalidEncryptionScope { expected: &'static str, record: u64 },
    #[error("event record {record} exceeds the {max_bytes}-byte limit")]
    EventRecordTooLarge { record: u64, max_bytes: usize },
    #[error("event block is invalid: {0}")]
    InvalidEventBlock(String),
    #[error(
        "run event storage budget exhausted: {used} bytes used, {requested} requested, {limit} allowed"
    )]
    EventStorageBudgetExceeded {
        used: u64,
        requested: u64,
        limit: u64,
    },
    #[error("event envelope is invalid: {0}")]
    InvalidEnvelope(String),
    #[error("duplicate event ID {event_id} at sequence {sequence}")]
    DuplicateEventId { event_id: Uuid, sequence: u64 },
    #[error("event ID order is invalid at sequence {sequence}: previous {previous}, found {found}")]
    InvalidEventIdOrder {
        previous: Uuid,
        found: Uuid,
        sequence: u64,
    },
    #[error("{operation} exceeds the in-memory safety limit of {limit} items")]
    AnalysisLimitExceeded {
        operation: &'static str,
        limit: usize,
    },
    #[error("capture policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error(
        "run blob storage budget exhausted: {used} bytes used, {requested} requested, {limit} allowed"
    )]
    BlobStorageBudgetExceeded {
        used: u64,
        requested: u64,
        limit: u64,
    },
    #[error("run blob file limit exhausted: {used} files used, {limit} allowed")]
    BlobFileLimitExceeded { used: u64, limit: u64 },
}

impl StorageError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Json(_) => "json",
            Self::Writer(_) => "writer",
            Self::InvalidSequence { .. } => "invalid_sequence",
            Self::InvalidRunId { .. } => "invalid_run_id",
            Self::InvalidEncryptionScope { .. } => "invalid_encryption_scope",
            Self::EventRecordTooLarge { .. } => "event_record_too_large",
            Self::InvalidEventBlock(_) => "invalid_event_block",
            Self::EventStorageBudgetExceeded { .. } => "event_storage_budget",
            Self::InvalidEnvelope(_) => "invalid_envelope",
            Self::DuplicateEventId { .. } => "duplicate_event_id",
            Self::InvalidEventIdOrder { .. } => "invalid_event_id_order",
            Self::AnalysisLimitExceeded { .. } => "analysis_limit",
            Self::InvalidPolicy(_) => "invalid_policy",
            Self::BlobStorageBudgetExceeded { .. } => "blob_storage_budget",
            Self::BlobFileLimitExceeded { .. } => "blob_file_limit",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WriterStats {
    pub events: u64,
    pub event_storage_bytes: u64,
    pub blobs: u64,
    pub blob_bytes: u64,
    pub queue_waits: u64,
    pub event_sync_batches: u64,
    pub capture_drops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub valid_events: u64,
    pub last_sequence: u64,
    pub valid_bytes: u64,
    pub discarded_tail_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventBlockRecord {
    version: u8,
    codec: String,
    run_id: String,
    first_sequence: u64,
    event_count: u64,
    uncompressed_bytes: u64,
    plaintext_sha256: String,
    encrypted: bool,
    payload: String,
}

struct DecodedEvent {
    envelope: EventEnvelope,
    encrypted: bool,
}

enum WriterCommand {
    Append {
        event: Box<PendingEvent>,
        reply: oneshot::Sender<Result<u64, String>>,
    },
    Flush {
        reply: oneshot::Sender<Result<WriterStats, String>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<WriterStats, String>>,
    },
}

type AppendReply = oneshot::Sender<Result<u64, String>>;
type EventBatch = Vec<(Box<PendingEvent>, AppendReply)>;

struct AtomicStats {
    events: AtomicU64,
    event_storage_bytes: AtomicU64,
    blobs: AtomicU64,
    blob_bytes: AtomicU64,
    queue_waits: AtomicU64,
    event_sync_batches: AtomicU64,
    capture_drops: AtomicU64,
}

impl AtomicStats {
    fn snapshot(&self) -> WriterStats {
        WriterStats {
            events: self.events.load(Ordering::Relaxed),
            event_storage_bytes: self.event_storage_bytes.load(Ordering::Relaxed),
            blobs: self.blobs.load(Ordering::Relaxed),
            blob_bytes: self.blob_bytes.load(Ordering::Relaxed),
            queue_waits: self.queue_waits.load(Ordering::Relaxed),
            event_sync_batches: self.event_sync_batches.load(Ordering::Relaxed),
            capture_drops: self.capture_drops.load(Ordering::Relaxed),
        }
    }
}

struct RunStoreInner {
    run_id: String,
    run_dir: PathBuf,
    blobs_dir: PathBuf,
    policy: CapturePolicy,
    started: Instant,
    sender: mpsc::Sender<WriterCommand>,
    writer: Mutex<Option<tokio::task::JoinHandle<Result<WriterStats, StorageError>>>>,
    stats: Arc<AtomicStats>,
    closed: AtomicBool,
    encryption: Option<EncryptionKey>,
    blob_keys: Option<BlobKeyring>,
    blob_files: AtomicU64,
    blob_storage_bytes: AtomicU64,
    blob_locks: Mutex<HashMap<String, Weak<Mutex<()>>>>,
}

/// Cloneable handle to one run's append-only evidence store.
#[derive(Clone)]
pub struct RunStore {
    inner: Arc<RunStoreInner>,
}

impl std::fmt::Debug for RunStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunStore")
            .field("run_id", &self.inner.run_id)
            .field("run_dir", &self.inner.run_dir)
            .finish_non_exhaustive()
    }
}

impl RunStore {
    pub fn create(
        run_dir: impl Into<PathBuf>,
        run_id: impl Into<String>,
        policy: CapturePolicy,
    ) -> Result<(Self, RecoveryReport), StorageError> {
        Self::create_with_encryption(run_dir, run_id, policy, None)
    }

    pub fn create_with_encryption(
        run_dir: impl Into<PathBuf>,
        run_id: impl Into<String>,
        policy: CapturePolicy,
        encryption: Option<EncryptionKey>,
    ) -> Result<(Self, RecoveryReport), StorageError> {
        let run_dir = run_dir.into();
        let run_id = run_id.into();
        if run_id.is_empty() || run_id.len() > 256 || run_id.chars().any(char::is_control) {
            return Err(StorageError::InvalidEnvelope(
                "run ID is empty, too long, or contains control characters".to_owned(),
            ));
        }
        policy.validate().map_err(StorageError::InvalidPolicy)?;
        fs::create_dir_all(&run_dir)?;
        require_real_directory(&run_dir, "run directory")?;
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))?;
        let blobs_dir = run_dir.join("blobs");
        fs::create_dir_all(&blobs_dir)?;
        require_real_directory(&blobs_dir, "blob directory")?;
        fs::set_permissions(&blobs_dir, fs::Permissions::from_mode(0o700))?;
        let (existing_blob_files, existing_blob_storage_bytes) =
            blob_directory_inventory(&blobs_dir)?;
        if existing_blob_storage_bytes > policy.max_run_blob_storage_bytes {
            return Err(StorageError::BlobStorageBudgetExceeded {
                used: existing_blob_storage_bytes,
                requested: 0,
                limit: policy.max_run_blob_storage_bytes,
            });
        }

        let events_path = run_dir.join("events.jsonl");
        if let Some(existing_format) = detect_event_log_format(&events_path)?
            && existing_format != policy.event_log_format
        {
            return Err(StorageError::InvalidPolicy(format!(
                "event log is {}, but capture policy requires {}",
                event_log_format_name(existing_format),
                event_log_format_name(policy.event_log_format)
            )));
        }
        let recovery = recover_events_with_key(&events_path, true, encryption.as_ref())?;
        if recovery.valid_bytes > policy.max_event_storage_bytes {
            return Err(StorageError::EventStorageBudgetExceeded {
                used: recovery.valid_bytes,
                requested: 0,
                limit: policy.max_event_storage_bytes,
            });
        }
        if recovery.valid_events > 0 {
            for_each_run_event_with_key(&events_path, &run_id, encryption.as_ref(), |_| Ok(()))?;
        }
        let has_legacy_data = existing_blob_files > 0 || recovery.valid_events > 0;
        let blob_keys =
            blob_keys::prepare_for_writer(&run_dir, encryption.as_ref(), has_legacy_data)?;
        let start_sequence = recovery.last_sequence.saturating_add(1);
        let lock_path = run_dir.join(".writer.lock");
        let stats = Arc::new(AtomicStats {
            events: AtomicU64::new(recovery.valid_events),
            event_storage_bytes: AtomicU64::new(recovery.valid_bytes),
            blobs: AtomicU64::new(0),
            blob_bytes: AtomicU64::new(0),
            queue_waits: AtomicU64::new(0),
            event_sync_batches: AtomicU64::new(0),
            capture_drops: AtomicU64::new(0),
        });
        let (sender, receiver) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let writer_stats = Arc::clone(&stats);
        let writer_encryption = encryption.clone();
        let existing_event_storage_bytes = recovery.valid_bytes;
        let max_event_storage_bytes = policy.max_event_storage_bytes;
        let event_log_format = policy.event_log_format;
        let writer = tokio::task::spawn_blocking(move || {
            writer_loop(
                &events_path,
                &lock_path,
                start_sequence,
                existing_event_storage_bytes,
                max_event_storage_bytes,
                receiver,
                &writer_stats,
                writer_encryption.as_ref(),
                event_log_format,
            )
        });

        Ok((
            Self {
                inner: Arc::new(RunStoreInner {
                    run_id,
                    run_dir,
                    blobs_dir,
                    policy,
                    started: Instant::now(),
                    sender,
                    writer: Mutex::new(Some(writer)),
                    stats,
                    closed: AtomicBool::new(false),
                    encryption,
                    blob_keys,
                    blob_files: AtomicU64::new(existing_blob_files),
                    blob_storage_bytes: AtomicU64::new(existing_blob_storage_bytes),
                    blob_locks: Mutex::new(HashMap::new()),
                }),
            },
            recovery,
        ))
    }

    #[must_use]
    pub fn run_dir(&self) -> &Path {
        &self.inner.run_dir
    }

    #[must_use]
    pub fn policy(&self) -> &CapturePolicy {
        &self.inner.policy
    }

    #[must_use]
    pub fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.inner.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn event(&self, source: impl Into<String>, kind: impl Into<String>) -> PendingEvent {
        let mut event = PendingEvent::new(self.run_id(), source, kind);
        event.monotonic_ns = self.elapsed_ns();
        event
    }

    pub async fn append(&self, mut event: PendingEvent) -> Result<u64, StorageError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(StorageError::Writer("writer has been shut down".to_owned()));
        }
        if event.run_id != self.run_id() {
            return Err(StorageError::Writer(format!(
                "event run_id {} does not match store {}",
                event.run_id,
                self.run_id()
            )));
        }
        if event.monotonic_ns == 0 {
            event.monotonic_ns = self.elapsed_ns();
        }

        let (reply, response) = oneshot::channel();
        if self.inner.sender.capacity() == 0 {
            self.inner.stats.queue_waits.fetch_add(1, Ordering::Relaxed);
        }
        if self
            .inner
            .sender
            .send(WriterCommand::Append {
                event: Box::new(event),
                reply,
            })
            .await
            .is_err()
        {
            self.note_capture_drop();
            return Err(StorageError::Writer(
                "writer command channel closed".to_owned(),
            ));
        }
        let Ok(result) = response.await else {
            self.note_capture_drop();
            return Err(StorageError::Writer(
                "writer dropped append acknowledgement".to_owned(),
            ));
        };
        if result.is_err() {
            self.note_capture_drop();
        }
        result.map_err(StorageError::Writer)
    }

    pub async fn flush(&self) -> Result<(), StorageError> {
        self.durable_boundary().await.map(|_| ())
    }

    /// Flush every event queued before this command and return the writer
    /// statistics captured at that exact durability boundary.
    pub async fn durable_boundary(&self) -> Result<WriterStats, StorageError> {
        let (reply, response) = oneshot::channel();
        self.inner
            .sender
            .send(WriterCommand::Flush { reply })
            .await
            .map_err(|_| StorageError::Writer("writer command channel closed".to_owned()))?;
        response
            .await
            .map_err(|_| StorageError::Writer("writer dropped flush acknowledgement".to_owned()))?
            .map_err(StorageError::Writer)
    }

    /// Stop the writer after all previously queued events have been synced.
    pub async fn shutdown(&self) -> Result<WriterStats, StorageError> {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(self.stats());
        }

        let (reply, response) = oneshot::channel();
        self.inner
            .sender
            .send(WriterCommand::Shutdown { reply })
            .await
            .map_err(|_| StorageError::Writer("writer command channel closed".to_owned()))?;
        let acknowledged = response
            .await
            .map_err(|_| {
                StorageError::Writer("writer dropped shutdown acknowledgement".to_owned())
            })?
            .map_err(StorageError::Writer)?;

        if let Some(writer) = self.inner.writer.lock().await.take() {
            let result = writer.await.map_err(|error| {
                StorageError::Writer(format!("writer task panicked: {error}"))
            })??;
            debug_assert_eq!(acknowledged.events, result.events);
            Ok(result)
        } else {
            Ok(acknowledged)
        }
    }

    #[must_use]
    pub fn stats(&self) -> WriterStats {
        self.inner.stats.snapshot()
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.inner.run_id
    }

    /// Register an observation that could not be represented durably. This is
    /// carried into the coverage manifest and permanently blocks completeness.
    pub fn note_capture_drop(&self) {
        self.note_capture_drops(1);
    }

    pub fn note_capture_drops(&self, count: u64) {
        self.inner
            .stats
            .capture_drops
            .fetch_add(count, Ordering::Relaxed);
    }

    pub async fn store_blob(
        &self,
        bytes: &[u8],
        media_type: Option<&str>,
    ) -> Result<PayloadRef, StorageError> {
        let limit = usize::try_from(self.inner.policy.max_blob_bytes).unwrap_or(usize::MAX);
        self.store_blob_with_limit(bytes, media_type, limit).await
    }

    /// Store security-sensitive transport evidence without applying the
    /// ordinary model-body size policy. Callers must enforce their own total
    /// limit; plaintext stores are rejected so secrets never land unencrypted.
    pub async fn store_sensitive_blob(
        &self,
        bytes: &[u8],
        media_type: Option<&str>,
    ) -> Result<PayloadRef, StorageError> {
        if self.inner.encryption.is_none() {
            return Err(StorageError::Writer(
                "sensitive evidence requires at-rest encryption".to_owned(),
            ));
        }
        self.store_blob_with_limit(bytes, media_type, bytes.len())
            .await
    }

    async fn store_blob_with_limit(
        &self,
        bytes: &[u8],
        media_type: Option<&str>,
        limit: usize,
    ) -> Result<PayloadRef, StorageError> {
        let limit = limit.min(MAX_SINGLE_BLOB_BYTES);
        let original_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let captured = if bytes.len() > limit {
            &bytes[..limit]
        } else {
            bytes
        };
        let truncated = captured.len() != bytes.len();
        let digest = Sha256::digest(captured);
        let hash = hex::encode(digest);
        let class = self
            .inner
            .blob_keys
            .as_ref()
            .map(|_| BlobClass::from_media_type(media_type));
        let path = self
            .inner
            .blobs_dir
            .join(blob_keys::blob_file_name(&hash, class)?);
        let blob_encryption = self
            .inner
            .blob_keys
            .as_ref()
            .map(|keys| {
                keys.key(class.expect("class-keyed store has a class"))
                    .clone()
            })
            .or_else(|| self.inner.encryption.clone());
        let expected_storage_bytes = original_blob_storage_bytes(
            u64::try_from(captured.len()).unwrap_or(u64::MAX),
            blob_encryption.is_some(),
        )?;
        let lock_identity = blob_keys::file_identity(class, &hash);
        let hash_lock = self.blob_lock(&lock_identity).await;
        let _hash_guard = hash_lock.lock().await;
        let existing_path = path.clone();
        let existing_plaintext = captured.to_vec();
        let existing_encryption = blob_encryption.clone();
        let existing_hash = hash.clone();
        let already_exists = tokio::task::spawn_blocking(move || {
            existing_blob_matches(
                &existing_path,
                &existing_plaintext,
                existing_encryption.as_ref(),
                &existing_hash,
                expected_storage_bytes,
            )
        })
        .await
        .map_err(|error| StorageError::Writer(format!("blob check task panicked: {error}")))??;
        if already_exists {
            return Ok(PayloadRef {
                sha256: format!("sha256:{hash}"),
                size: if truncated {
                    u64::try_from(captured.len()).unwrap_or(u64::MAX)
                } else {
                    original_size
                },
                media_type: media_type.map(str::to_owned),
                truncated,
            });
        }
        self.reserve_blob_file()?;
        if let Err(error) = self.reserve_blob_storage(expected_storage_bytes) {
            self.release_blob_file();
            return Err(error);
        }
        let directory = self.inner.blobs_dir.clone();
        let owned = captured.to_vec();
        let encryption = blob_encryption;
        let blob_hash = hash.clone();

        let persistence = tokio::task::spawn_blocking(move || {
            let persisted = if let Some(encryption) = encryption.as_ref() {
                encryption
                    .encrypt_blob(&owned, &blob_hash)
                    .map_err(|error| BlobPersistError {
                        error,
                        storage_retained: false,
                    })?
            } else {
                owned.clone()
            };
            debug_assert_eq!(
                u64::try_from(persisted.len()).unwrap_or(u64::MAX),
                expected_storage_bytes
            );
            persist_blob(
                &directory,
                &path,
                &persisted,
                &owned,
                encryption.as_ref(),
                &blob_hash,
            )
        })
        .await
        .map_err(|error| StorageError::Writer(format!("blob task panicked: {error}")))?;
        let created = match persistence {
            Ok(created) => created,
            Err(error) => {
                if !error.storage_retained {
                    self.release_blob_file();
                    self.release_blob_storage(expected_storage_bytes);
                }
                return Err(StorageError::Io(error.error));
            }
        };
        if created {
            self.inner.stats.blobs.fetch_add(1, Ordering::Relaxed);
            self.inner.stats.blob_bytes.fetch_add(
                u64::try_from(captured.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        } else {
            self.release_blob_file();
            self.release_blob_storage(expected_storage_bytes);
        }

        Ok(PayloadRef {
            sha256: format!("sha256:{hash}"),
            size: if truncated {
                u64::try_from(captured.len()).unwrap_or(u64::MAX)
            } else {
                original_size
            },
            media_type: media_type.map(str::to_owned),
            truncated,
        })
    }

    async fn blob_lock(&self, hash: &str) -> Arc<Mutex<()>> {
        let mut locks = self.inner.blob_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(hash).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(hash.to_owned(), Arc::downgrade(&lock));
        lock
    }

    fn reserve_blob_storage(&self, requested: u64) -> Result<(), StorageError> {
        let limit = self.inner.policy.max_run_blob_storage_bytes;
        let mut used = self.inner.blob_storage_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = used.checked_add(requested) else {
                return Err(StorageError::BlobStorageBudgetExceeded {
                    used,
                    requested,
                    limit,
                });
            };
            if next > limit {
                return Err(StorageError::BlobStorageBudgetExceeded {
                    used,
                    requested,
                    limit,
                });
            }
            match self.inner.blob_storage_bytes.compare_exchange_weak(
                used,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => used = current,
            }
        }
    }

    fn reserve_blob_file(&self) -> Result<(), StorageError> {
        let limit = u64::try_from(MAX_BLOB_DIRECTORY_ENTRIES).unwrap_or(u64::MAX);
        reserve_blob_file_count(&self.inner.blob_files, limit)
    }

    fn release_blob_file(&self) {
        let previous = self.inner.blob_files.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }

    fn release_blob_storage(&self, bytes: u64) {
        let previous = self
            .inner
            .blob_storage_bytes
            .fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
    }
}

fn reserve_blob_file_count(counter: &AtomicU64, limit: u64) -> Result<(), StorageError> {
    let mut used = counter.load(Ordering::Acquire);
    loop {
        if used >= limit {
            return Err(StorageError::BlobFileLimitExceeded { used, limit });
        }
        match counter.compare_exchange_weak(used, used + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(current) => used = current,
        }
    }
}

fn original_blob_storage_bytes(plaintext_bytes: u64, encrypted: bool) -> io::Result<u64> {
    plaintext_bytes
        .checked_add(if encrypted {
            ENCRYPTED_BLOB_OVERHEAD_BYTES
        } else {
            0
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "blob size overflows u64"))
}

fn existing_blob_matches(
    path: &Path,
    plaintext: &[u8],
    encryption: Option<&EncryptionKey>,
    hash: &str,
    expected_storage_bytes: u64,
) -> io::Result<bool> {
    let limit = usize::try_from(expected_storage_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob is too large for this platform",
        )
    })?;
    let encoded = match crate::secure_fs::read_regular_limited(path, limit) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) != expected_storage_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "existing content-addressed blob has an unexpected size",
        ));
    }
    let existing = if let Some(key) = encryption {
        key.decrypt_blob(&encoded, hash)?
    } else {
        encoded
    };
    if existing != plaintext {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "existing content-addressed blob does not match its digest",
        ));
    }
    Ok(true)
}

fn blob_directory_inventory(directory: &Path) -> io::Result<(u64, u64)> {
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        entries = entries.saturating_add(1);
        if entries > MAX_BLOB_DIRECTORY_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob directory exceeds its entry safety limit",
            ));
        }
        if !entry.file_type()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob directory contains a non-regular entry",
            ));
        }
        bytes = bytes.checked_add(entry.metadata()?.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob directory size overflows u64",
            )
        })?;
    }
    Ok((u64::try_from(entries).unwrap_or(u64::MAX), bytes))
}

fn require_real_directory(path: &Path, label: &str) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be a real directory: {}", path.display()),
        ))
    }
}

fn writer_loop(
    events_path: &Path,
    lock_path: &Path,
    mut sequence: u64,
    mut event_storage_bytes: u64,
    max_event_storage_bytes: u64,
    mut receiver: mpsc::Receiver<WriterCommand>,
    stats: &AtomicStats,
    encryption: Option<&EncryptionKey>,
    event_log_format: EventLogFormat,
) -> Result<WriterStats, StorageError> {
    let lock_file = open_regular_create(lock_path)?;
    lock_file.try_lock().map_err(|error| {
        StorageError::Writer(format!("another writer already owns this run: {error}"))
    })?;
    let existing_format = detect_event_log_format(events_path)?;
    if let Some(existing_format) = existing_format
        && existing_format != event_log_format
    {
        return Err(StorageError::InvalidPolicy(format!(
            "event log changed to {}, but writer requires {}",
            event_log_format_name(existing_format),
            event_log_format_name(event_log_format)
        )));
    }
    let mut events = open_regular_append_create(events_path)?;
    let events_parent = events_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "event log has no parent directory",
        )
    })?;
    File::open(events_parent)?.sync_all()?;
    if existing_format.is_none() && event_log_format == EventLogFormat::ZstdBlocks {
        let header_bytes = u64::try_from(EVENT_BLOCK_HEADER.len()).unwrap_or(u64::MAX);
        if header_bytes > max_event_storage_bytes {
            return Err(StorageError::EventStorageBudgetExceeded {
                used: event_storage_bytes,
                requested: header_bytes,
                limit: max_event_storage_bytes,
            });
        }
        events.write_all(EVENT_BLOCK_HEADER)?;
        events.sync_data()?;
        event_storage_bytes = event_storage_bytes.saturating_add(header_bytes);
        stats
            .event_storage_bytes
            .fetch_add(header_bytes, Ordering::Relaxed);
    }
    let mut deferred = None;

    loop {
        let command = match deferred.take() {
            Some(command) => Some(command),
            None => receiver.blocking_recv(),
        };
        let Some(command) = command else { break };
        match command {
            WriterCommand::Append { event, reply } => {
                let mut batch = vec![(event, reply)];
                loop {
                    match receiver.try_recv() {
                        Ok(WriterCommand::Append { event, reply }) => {
                            batch.push((event, reply));
                        }
                        Ok(command) => {
                            deferred = Some(command);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                append_batch(
                    &mut events,
                    &mut sequence,
                    &mut event_storage_bytes,
                    max_event_storage_bytes,
                    batch,
                    stats,
                    encryption,
                    event_log_format,
                )?;
            }
            WriterCommand::Flush { reply } => {
                let result = events
                    .sync_data()
                    .map(|()| stats.snapshot())
                    .map_err(|error| error.to_string());
                let should_stop = result.is_err();
                let _ = reply.send(result);
                if should_stop {
                    return Err(StorageError::Writer("event flush failed".to_owned()));
                }
            }
            WriterCommand::Shutdown { reply } => {
                let result = events
                    .sync_all()
                    .map(|()| stats.snapshot())
                    .map_err(|error| error.to_string());
                let should_stop = result.is_err();
                let returned = result.clone();
                let _ = reply.send(returned);
                if should_stop {
                    return Err(StorageError::Writer(
                        "event shutdown flush failed".to_owned(),
                    ));
                }
                drop(events);
                drop(lock_file);
                return result.map_err(StorageError::Writer);
            }
        }
    }

    events.sync_all()?;
    Ok(stats.snapshot())
}

fn append_batch(
    file: &mut File,
    sequence: &mut u64,
    event_storage_bytes: &mut u64,
    max_event_storage_bytes: u64,
    batch: EventBatch,
    stats: &AtomicStats,
    encryption: Option<&EncryptionKey>,
    event_log_format: EventLogFormat,
) -> Result<(), StorageError> {
    let mut prepared = Vec::new();
    prepared.try_reserve(batch.len()).map_err(|error| {
        StorageError::Writer(format!("cannot reserve event batch memory: {error}"))
    })?;
    for (index, (event, reply)) in batch.into_iter().enumerate() {
        let offset = u64::try_from(index)
            .map_err(|_| StorageError::Writer("event batch index overflows u64".to_owned()))?;
        let event_sequence = sequence
            .checked_add(offset)
            .ok_or_else(|| StorageError::Writer("event sequence overflow".to_owned()))?;
        prepared.push((EventEnvelope::from_pending(event_sequence, *event), reply));
    }

    let (persisted, persisted_bytes, failure) = match event_log_format {
        EventLogFormat::Jsonl => append_jsonl_records(
            file,
            &prepared,
            *event_storage_bytes,
            max_event_storage_bytes,
            encryption,
        ),
        EventLogFormat::ZstdBlocks => append_zstd_blocks(
            file,
            &prepared,
            *event_storage_bytes,
            max_event_storage_bytes,
            encryption,
        ),
    };
    if persisted > 0
        && let Err(error) = file.sync_data()
    {
        let message = error.to_string();
        for (_, reply) in prepared {
            let _ = reply.send(Err(message.clone()));
        }
        return Err(StorageError::Writer(format!(
            "durable event batch append failed; writer stopped to preserve ordering: {error}"
        )));
    }

    let written = u64::try_from(persisted)
        .map_err(|_| StorageError::Writer("event batch length overflows u64".to_owned()))?;
    *sequence = sequence
        .checked_add(written)
        .ok_or_else(|| StorageError::Writer("event sequence overflow".to_owned()))?;
    *event_storage_bytes = event_storage_bytes.saturating_add(persisted_bytes);
    stats.events.fetch_add(written, Ordering::Relaxed);
    stats
        .event_storage_bytes
        .fetch_add(persisted_bytes, Ordering::Relaxed);
    if persisted > 0 {
        stats.event_sync_batches.fetch_add(1, Ordering::Relaxed);
    }
    let failure_message = failure.as_ref().map(ToString::to_string);
    for (index, (envelope, reply)) in prepared.into_iter().enumerate() {
        if index < persisted {
            let _ = reply.send(Ok(envelope.sequence));
        } else {
            let _ = reply.send(Err(failure_message.clone().unwrap_or_else(|| {
                "event batch stopped before this event was persisted".to_owned()
            })));
        }
    }
    if let Some(error) = failure {
        return Err(StorageError::Writer(format!(
            "durable event batch append failed; writer stopped to preserve ordering: {error}"
        )));
    }
    Ok(())
}

type AppendResult = (usize, u64, Option<StorageError>);

fn append_jsonl_records(
    file: &mut File,
    prepared: &[(EventEnvelope, AppendReply)],
    event_storage_bytes: u64,
    max_event_storage_bytes: u64,
    encryption: Option<&EncryptionKey>,
) -> AppendResult {
    let mut persisted = 0_usize;
    let mut persisted_bytes = 0_u64;
    let mut failure = None;
    for (envelope, _) in prepared {
        let serialized = match encode_envelope(envelope, encryption) {
            Ok(serialized) => serialized,
            Err(error) => {
                failure = Some(error);
                break;
            }
        };
        let requested = u64::try_from(serialized.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let used = event_storage_bytes.saturating_add(persisted_bytes);
        let Some(next) = used.checked_add(requested) else {
            failure = Some(StorageError::EventStorageBudgetExceeded {
                used,
                requested,
                limit: max_event_storage_bytes,
            });
            break;
        };
        if next > max_event_storage_bytes {
            failure = Some(StorageError::EventStorageBudgetExceeded {
                used,
                requested,
                limit: max_event_storage_bytes,
            });
            break;
        }
        if let Err(error) = file
            .write_all(&serialized)
            .and_then(|()| file.write_all(b"\n"))
        {
            failure = Some(StorageError::Io(error));
            break;
        }
        persisted = persisted.saturating_add(1);
        persisted_bytes = persisted_bytes.saturating_add(requested);
    }
    (persisted, persisted_bytes, failure)
}

fn append_zstd_blocks(
    file: &mut File,
    prepared: &[(EventEnvelope, AppendReply)],
    event_storage_bytes: u64,
    max_event_storage_bytes: u64,
    encryption: Option<&EncryptionKey>,
) -> AppendResult {
    let mut persisted = 0_usize;
    let mut persisted_bytes = 0_u64;
    let mut failure = None;

    'blocks: while persisted < prepared.len() {
        let block_start = persisted;
        let mut plaintext = Vec::new();
        let mut block_end = block_start;
        while block_end < prepared.len()
            && block_end.saturating_sub(block_start) < MAX_EVENT_BLOCK_EVENTS
        {
            let serialized = match encode_plaintext_envelope(&prepared[block_end].0) {
                Ok(serialized) => serialized,
                Err(error) => {
                    failure = Some(error);
                    break 'blocks;
                }
            };
            let requested = serialized.len().saturating_add(1);
            if !plaintext.is_empty()
                && plaintext.len().saturating_add(requested) > MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES
            {
                break;
            }
            if requested > MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES {
                failure = Some(StorageError::InvalidEventBlock(format!(
                    "event {} cannot fit in the {}-byte uncompressed block limit",
                    prepared[block_end].0.sequence, MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES
                )));
                break 'blocks;
            }
            plaintext.extend_from_slice(&serialized);
            plaintext.push(b'\n');
            block_end = block_end.saturating_add(1);
        }

        let serialized = match encode_event_block(
            &plaintext,
            &prepared[block_start].0.run_id,
            prepared[block_start].0.sequence,
            block_end.saturating_sub(block_start),
            encryption,
        ) {
            Ok(serialized) => serialized,
            Err(error) => {
                failure = Some(error);
                break;
            }
        };
        let requested = u64::try_from(serialized.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let used = event_storage_bytes.saturating_add(persisted_bytes);
        let Some(next) = used.checked_add(requested) else {
            failure = Some(StorageError::EventStorageBudgetExceeded {
                used,
                requested,
                limit: max_event_storage_bytes,
            });
            break;
        };
        if next > max_event_storage_bytes {
            failure = Some(StorageError::EventStorageBudgetExceeded {
                used,
                requested,
                limit: max_event_storage_bytes,
            });
            break;
        }
        if let Err(error) = file
            .write_all(&serialized)
            .and_then(|()| file.write_all(b"\n"))
        {
            failure = Some(StorageError::Io(error));
            break;
        }
        persisted = block_end;
        persisted_bytes = persisted_bytes.saturating_add(requested);
    }

    (persisted, persisted_bytes, failure)
}

fn encode_plaintext_envelope(envelope: &EventEnvelope) -> Result<Vec<u8>, StorageError> {
    envelope.validate().map_err(StorageError::InvalidEnvelope)?;
    let plaintext = serde_json::to_vec(envelope)?;
    validate_stored_json_complexity(&plaintext)?;
    if plaintext.len().saturating_add(1) > MAX_EVENT_RECORD_BYTES {
        return Err(StorageError::EventRecordTooLarge {
            record: envelope.sequence,
            max_bytes: MAX_EVENT_RECORD_BYTES,
        });
    }
    Ok(plaintext)
}

fn encode_event_block(
    plaintext: &[u8],
    run_id: &str,
    first_sequence: u64,
    event_count: usize,
    encryption: Option<&EncryptionKey>,
) -> Result<Vec<u8>, StorageError> {
    if event_count == 0 || event_count > MAX_EVENT_BLOCK_EVENTS {
        return Err(StorageError::InvalidEventBlock(
            "event count is outside the block safety limit".to_owned(),
        ));
    }
    if plaintext.len() > MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES {
        return Err(StorageError::InvalidEventBlock(
            "uncompressed block exceeds its safety limit".to_owned(),
        ));
    }
    let compressed = zstd::bulk::compress(plaintext, EVENT_BLOCK_COMPRESSION_LEVEL)
        .map_err(|error| StorageError::Io(io::Error::other(error)))?;
    if compressed.len() > MAX_EVENT_BLOCK_COMPRESSED_BYTES {
        return Err(StorageError::InvalidEventBlock(
            "compressed block exceeds its safety limit".to_owned(),
        ));
    }
    let digest: [u8; 32] = Sha256::digest(plaintext).into();
    let event_count = u64::try_from(event_count)
        .map_err(|_| StorageError::InvalidEventBlock("event count overflows u64".to_owned()))?;
    let uncompressed_bytes = u64::try_from(plaintext.len()).map_err(|_| {
        StorageError::InvalidEventBlock("uncompressed byte count overflows u64".to_owned())
    })?;
    let (payload, encrypted) = if let Some(key) = encryption {
        (
            key.encrypt_event_block(
                &compressed,
                run_id,
                first_sequence,
                event_count,
                uncompressed_bytes,
                &digest,
            )?,
            true,
        )
    } else {
        (compressed, false)
    };
    let record = EventBlockRecord {
        version: EVENT_BLOCK_VERSION,
        codec: EVENT_BLOCK_CODEC.to_owned(),
        run_id: run_id.to_owned(),
        first_sequence,
        event_count,
        uncompressed_bytes,
        plaintext_sha256: hex::encode(digest),
        encrypted,
        payload: STANDARD_NO_PAD.encode(payload),
    };
    let serialized = serde_json::to_vec(&record)?;
    if serialized.len().saturating_add(1) > MAX_EVENT_BLOCK_RECORD_BYTES {
        return Err(StorageError::InvalidEventBlock(
            "encoded block exceeds its record safety limit".to_owned(),
        ));
    }
    Ok(serialized)
}

fn encode_envelope(
    envelope: &EventEnvelope,
    encryption: Option<&EncryptionKey>,
) -> Result<Vec<u8>, StorageError> {
    let plaintext = encode_plaintext_envelope(envelope)?;
    let serialized = if let Some(key) = encryption {
        key.encrypt_event_record(&plaintext, &envelope.run_id, envelope.sequence)?
    } else {
        plaintext
    };
    if serialized.len().saturating_add(1) > MAX_EVENT_RECORD_BYTES {
        return Err(StorageError::EventRecordTooLarge {
            record: envelope.sequence,
            max_bytes: MAX_EVENT_RECORD_BYTES,
        });
    }
    Ok(serialized)
}

fn persist_blob(
    directory: &Path,
    final_path: &Path,
    encoded: &[u8],
    plaintext: &[u8],
    encryption: Option<&EncryptionKey>,
    hash: &str,
) -> Result<bool, BlobPersistError> {
    let temporary = directory.join(format!(
        ".blob-{}-{}.tmp",
        std::process::id(),
        Uuid::new_v4()
    ));
    let mut committed = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(encoded)?;
        file.sync_all()?;
        drop(file);

        let directory_handle = File::open(directory)?;
        let temporary_name = temporary.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "temporary blob has no file name",
            )
        })?;
        let final_name = final_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "final blob has no file name")
        })?;
        match renameat2(
            &directory_handle,
            Path::new(temporary_name),
            &directory_handle,
            Path::new(final_name),
            RenameFlags::RENAME_NOREPLACE,
        ) {
            Ok(()) => {
                committed = true;
                Ok(true)
            }
            Err(nix::errno::Errno::EEXIST) => {
                let existing = read_regular_limited(final_path, encoded.len())?;
                if existing.len() != encoded.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "existing content-addressed blob has an unexpected size",
                    ));
                }
                let existing = if let Some(key) = encryption {
                    key.decrypt_blob(&existing, hash)?
                } else {
                    existing
                };
                if existing != plaintext {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "existing content-addressed blob does not match its digest",
                    ));
                }
                Ok(false)
            }
            Err(error) => Err(io::Error::from(error)),
        }
    })();
    if !committed && let Err(cleanup_error) = fs::remove_file(&temporary) {
        let error = match result {
            Ok(_) => cleanup_error,
            Err(error) => io::Error::new(
                error.kind(),
                format!("{error}; temporary blob cleanup also failed: {cleanup_error}"),
            ),
        };
        return Err(BlobPersistError {
            error,
            storage_retained: true,
        });
    }
    let created = result.map_err(|error| BlobPersistError {
        error,
        storage_retained: committed,
    })?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| BlobPersistError {
            error,
            storage_retained: committed,
        })?;
    Ok(created)
}

/// Validate an event log and optionally isolate an incomplete final line.
pub fn recover_events(path: &Path, repair: bool) -> Result<RecoveryReport, StorageError> {
    recover_events_with_key(path, repair, None)
}

fn event_log_format_name(format: EventLogFormat) -> &'static str {
    match format {
        EventLogFormat::Jsonl => "jsonl",
        EventLogFormat::ZstdBlocks => "zstd-blocks",
    }
}

fn detect_event_log_format(path: &Path) -> io::Result<Option<EventLogFormat>> {
    if !path.try_exists()? {
        return Ok(None);
    }
    let mut file = open_regular_read(path)?;
    if file.metadata()?.len() == 0 {
        return Ok(None);
    }
    let mut prefix = Vec::with_capacity(EVENT_BLOCK_HEADER.len());
    Read::by_ref(&mut file)
        .take(u64::try_from(EVENT_BLOCK_HEADER.len()).unwrap_or(u64::MAX))
        .read_to_end(&mut prefix)?;
    if EVENT_BLOCK_HEADER.starts_with(&prefix) {
        Ok(Some(EventLogFormat::ZstdBlocks))
    } else {
        Ok(Some(EventLogFormat::Jsonl))
    }
}

pub fn recover_events_with_key(
    path: &Path,
    repair: bool,
    encryption: Option<&EncryptionKey>,
) -> Result<RecoveryReport, StorageError> {
    if !path.try_exists()? {
        return Ok(RecoveryReport {
            valid_events: 0,
            last_sequence: 0,
            valid_bytes: 0,
            discarded_tail_bytes: 0,
            quarantine: None,
        });
    }

    let mut file = if repair {
        open_regular_read_write(path)?
    } else {
        open_regular_read(path)?
    };
    let total_bytes = file.metadata()?.len();
    let (count, last_sequence, valid_bytes) =
        match detect_event_log_format(path)?.unwrap_or(EventLogFormat::Jsonl) {
            EventLogFormat::Jsonl => recover_jsonl_records(&file, encryption)?,
            EventLogFormat::ZstdBlocks => recover_zstd_blocks(&file, encryption)?,
        };

    let discarded = total_bytes.saturating_sub(valid_bytes);
    let quarantine = if discarded > 0 && repair {
        file.seek(SeekFrom::Start(valid_bytes))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        let quarantine = path.with_file_name(format!(
            "events.tail-corrupt-{}.bin",
            Utc::now().format("%Y%m%dT%H%M%S%.fZ")
        ));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&quarantine)?;
        output.write_all(&tail)?;
        output.sync_all()?;
        file.set_len(valid_bytes)?;
        file.sync_all()?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "event log has no parent directory",
            )
        })?;
        File::open(parent)?.sync_all()?;
        Some(quarantine)
    } else {
        None
    };

    Ok(RecoveryReport {
        valid_events: count,
        last_sequence,
        valid_bytes,
        discarded_tail_bytes: discarded,
        quarantine,
    })
}

fn recover_jsonl_records(
    file: &File,
    encryption: Option<&EncryptionKey>,
) -> Result<(u64, u64, u64), StorageError> {
    let mut reader = BufReader::new(file.try_clone()?);
    let mut buffer = Vec::new();
    let mut valid_bytes = 0_u64;
    let mut count = 0_u64;
    let mut last_sequence = 0_u64;
    loop {
        buffer.clear();
        let bytes_read = (&mut reader)
            .take(u64::try_from(MAX_EVENT_RECORD_BYTES).unwrap_or(u64::MAX) + 1)
            .read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read > MAX_EVENT_RECORD_BYTES {
            return Err(StorageError::EventRecordTooLarge {
                record: count.saturating_add(1),
                max_bytes: MAX_EVENT_RECORD_BYTES,
            });
        }
        if buffer.last() != Some(&b'\n') {
            break;
        }
        let envelope = decode_event(&buffer, encryption)?;
        let expected = last_sequence.saturating_add(1);
        if envelope.sequence != expected {
            return Err(StorageError::InvalidSequence {
                expected,
                found: envelope.sequence,
            });
        }
        count = count.saturating_add(1);
        last_sequence = envelope.sequence;
        valid_bytes = valid_bytes.saturating_add(u64::try_from(bytes_read).unwrap_or(u64::MAX));
    }
    Ok((count, last_sequence, valid_bytes))
}

fn recover_zstd_blocks(
    file: &File,
    encryption: Option<&EncryptionKey>,
) -> Result<(u64, u64, u64), StorageError> {
    let mut reader = BufReader::new(file.try_clone()?);
    let mut buffer = Vec::new();
    let header_bytes = reader.read_until(b'\n', &mut buffer)?;
    if buffer.as_slice() != EVENT_BLOCK_HEADER {
        if buffer.last() == Some(&b'\n') {
            return Err(StorageError::InvalidEventBlock(
                "event-block header is invalid".to_owned(),
            ));
        }
        return Ok((0, 0, 0));
    }
    let mut valid_bytes = u64::try_from(header_bytes).unwrap_or(u64::MAX);
    let mut count = 0_u64;
    let mut last_sequence = 0_u64;
    let mut physical_block = 0_u64;
    loop {
        buffer.clear();
        let bytes_read = (&mut reader)
            .take(u64::try_from(MAX_EVENT_BLOCK_RECORD_BYTES).unwrap_or(u64::MAX) + 1)
            .read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        physical_block = physical_block.saturating_add(1);
        if bytes_read > MAX_EVENT_BLOCK_RECORD_BYTES {
            return Err(StorageError::InvalidEventBlock(format!(
                "physical block {physical_block} exceeds the {MAX_EVENT_BLOCK_RECORD_BYTES}-byte record limit"
            )));
        }
        if buffer.last() != Some(&b'\n') {
            break;
        }
        let decoded = decode_event_block(&buffer, encryption, physical_block)?;
        for event in decoded {
            let expected = last_sequence.saturating_add(1);
            if event.envelope.sequence != expected {
                return Err(StorageError::InvalidSequence {
                    expected,
                    found: event.envelope.sequence,
                });
            }
            count = count.saturating_add(1);
            last_sequence = event.envelope.sequence;
        }
        valid_bytes = valid_bytes.saturating_add(u64::try_from(bytes_read).unwrap_or(u64::MAX));
    }
    Ok((count, last_sequence, valid_bytes))
}

fn decode_event_block(
    encoded: &[u8],
    encryption: Option<&EncryptionKey>,
    physical_block: u64,
) -> Result<VecDeque<DecodedEvent>, StorageError> {
    validate_stored_json_complexity(encoded)?;
    let record: EventBlockRecord = serde_json::from_slice(encoded)?;
    if record.version != EVENT_BLOCK_VERSION || record.codec != EVENT_BLOCK_CODEC {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} uses an unsupported version or codec"
        )));
    }
    if record.run_id.is_empty()
        || record.run_id.len() > 256
        || record.run_id.chars().any(char::is_control)
        || record.first_sequence == 0
        || record.event_count == 0
        || record.event_count > u64::try_from(MAX_EVENT_BLOCK_EVENTS).unwrap_or(u64::MAX)
    {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} has invalid run or sequence metadata"
        )));
    }
    let uncompressed_bytes = usize::try_from(record.uncompressed_bytes).map_err(|_| {
        StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} has an overflowing uncompressed size"
        ))
    })?;
    if uncompressed_bytes == 0 || uncompressed_bytes > MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} exceeds the uncompressed safety limit"
        )));
    }
    if record.plaintext_sha256.len() != 64
        || !record
            .plaintext_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} has a non-canonical plaintext digest"
        )));
    }
    let digest_bytes = hex::decode(&record.plaintext_sha256).map_err(|error| {
        StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} has an invalid plaintext digest: {error}"
        ))
    })?;
    let digest: [u8; 32] = digest_bytes.try_into().map_err(|_| {
        StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} has an invalid plaintext digest length"
        ))
    })?;
    let payload = STANDARD_NO_PAD
        .decode(record.payload.as_bytes())
        .map_err(|error| {
            StorageError::InvalidEventBlock(format!(
                "physical block {physical_block} has invalid base64 payload: {error}"
            ))
        })?;
    let compressed = if record.encrypted {
        let key = encryption.ok_or_else(|| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encrypted event-block log requires the matching key",
            ))
        })?;
        key.decrypt_event_block(
            &payload,
            &record.run_id,
            record.first_sequence,
            record.event_count,
            record.uncompressed_bytes,
            &digest,
        )?
    } else {
        payload
    };
    if compressed.len() > MAX_EVENT_BLOCK_COMPRESSED_BYTES {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} exceeds the compressed safety limit"
        )));
    }
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
        .map_err(|error| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, error)))?;
    let mut plaintext = Vec::with_capacity(uncompressed_bytes.min(1024 * 1024));
    decoder
        .take(u64::try_from(uncompressed_bytes).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut plaintext)?;
    if plaintext.len() != uncompressed_bytes {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} decompressed to {} bytes, expected {uncompressed_bytes}",
            plaintext.len()
        )));
    }
    if <[u8; 32]>::from(Sha256::digest(&plaintext)) != digest {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} plaintext digest does not match"
        )));
    }

    let mut reader = BufReader::new(Cursor::new(plaintext));
    let mut event_bytes = Vec::new();
    let mut events = VecDeque::new();
    let event_count = usize::try_from(record.event_count).map_err(|_| {
        StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} event count overflows usize"
        ))
    })?;
    events.try_reserve(event_count).map_err(|error| {
        StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} cannot reserve event buffer: {error}"
        ))
    })?;
    for offset in 0..event_count {
        let logical_record = record
            .first_sequence
            .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
        read_event_record(&mut reader, &mut event_bytes, logical_record)?;
        if event_bytes.last() != Some(&b'\n') {
            return Err(StorageError::InvalidEventBlock(format!(
                "physical block {physical_block} has an incomplete embedded event"
            )));
        }
        let envelope = decode_event(&event_bytes, None)?;
        if envelope.sequence != logical_record {
            return Err(StorageError::InvalidSequence {
                expected: logical_record,
                found: envelope.sequence,
            });
        }
        if envelope.run_id != record.run_id {
            return Err(StorageError::InvalidRunId {
                expected: record.run_id.clone(),
                found: envelope.run_id,
                sequence: envelope.sequence,
            });
        }
        events.push_back(DecodedEvent {
            envelope,
            encrypted: record.encrypted,
        });
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(StorageError::InvalidEventBlock(format!(
            "physical block {physical_block} contains trailing plaintext"
        )));
    }
    Ok(events)
}

struct DecodedEventReader {
    reader: BufReader<File>,
    format: EventLogFormat,
    encryption: Option<EncryptionKey>,
    encoded: Vec<u8>,
    buffered: VecDeque<DecodedEvent>,
    physical_record: u64,
}

impl DecodedEventReader {
    fn open(path: &Path, encryption: Option<&EncryptionKey>) -> Result<Self, StorageError> {
        let format = detect_event_log_format(path)?.unwrap_or(EventLogFormat::Jsonl);
        let mut reader = BufReader::new(open_regular_read(path)?);
        if format == EventLogFormat::ZstdBlocks {
            let mut header = Vec::new();
            reader.read_until(b'\n', &mut header)?;
            if header.as_slice() != EVENT_BLOCK_HEADER {
                return Err(StorageError::InvalidEventBlock(
                    "event-block header is incomplete or invalid".to_owned(),
                ));
            }
        }
        Ok(Self {
            reader,
            format,
            encryption: encryption.cloned(),
            encoded: Vec::new(),
            buffered: VecDeque::new(),
            physical_record: 0,
        })
    }

    fn next_decoded(&mut self) -> Result<Option<DecodedEvent>, StorageError> {
        if let Some(event) = self.buffered.pop_front() {
            return Ok(Some(event));
        }
        self.physical_record = self.physical_record.saturating_add(1);
        match self.format {
            EventLogFormat::Jsonl => {
                let bytes = read_bounded_line(
                    &mut self.reader,
                    &mut self.encoded,
                    MAX_EVENT_RECORD_BYTES,
                    self.physical_record,
                )?;
                if bytes == 0 {
                    return Ok(None);
                }
                if self.encoded.last() != Some(&b'\n') {
                    return Err(StorageError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "event log changed while it was being read",
                    )));
                }
                let encrypted = is_encrypted_event(&self.encoded);
                let envelope = decode_event(&self.encoded, self.encryption.as_ref())?;
                Ok(Some(DecodedEvent {
                    envelope,
                    encrypted,
                }))
            }
            EventLogFormat::ZstdBlocks => {
                let bytes = read_bounded_line(
                    &mut self.reader,
                    &mut self.encoded,
                    MAX_EVENT_BLOCK_RECORD_BYTES,
                    self.physical_record,
                )?;
                if bytes == 0 {
                    return Ok(None);
                }
                if self.encoded.last() != Some(&b'\n') {
                    return Err(StorageError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "event-block log changed while it was being read",
                    )));
                }
                self.buffered = decode_event_block(
                    &self.encoded,
                    self.encryption.as_ref(),
                    self.physical_record,
                )?;
                self.buffered.pop_front().map_or_else(
                    || {
                        Err(StorageError::InvalidEventBlock(format!(
                            "physical block {} contains no events",
                            self.physical_record
                        )))
                    },
                    |event| Ok(Some(event)),
                )
            }
        }
    }
}

pub fn for_each_event(
    path: &Path,
    visitor: impl FnMut(EventEnvelope) -> Result<(), StorageError>,
) -> Result<RecoveryReport, StorageError> {
    for_each_event_with_key(path, None, visitor)
}

pub fn for_each_event_with_key(
    path: &Path,
    encryption: Option<&EncryptionKey>,
    mut visitor: impl FnMut(EventEnvelope) -> Result<(), StorageError>,
) -> Result<RecoveryReport, StorageError> {
    let report = recover_events_with_key(path, false, encryption)?;
    let mut reader = DecodedEventReader::open(path, encryption)?;
    for _ in 0..report.valid_events {
        let event = reader.next_decoded()?.ok_or_else(|| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "event log changed while it was being read",
            ))
        })?;
        visitor(event.envelope)?;
    }
    Ok(report)
}

pub fn for_each_run_event_with_key(
    path: &Path,
    expected_run_id: &str,
    encryption: Option<&EncryptionKey>,
    mut visitor: impl FnMut(EventEnvelope) -> Result<(), StorageError>,
) -> Result<RecoveryReport, StorageError> {
    let report = recover_events_with_key(path, false, encryption)?;
    let mut reader = DecodedEventReader::open(path, encryption)?;
    let mut previous_event_id = None;
    for record in 1..=report.valid_events {
        let event = reader.next_decoded()?.ok_or_else(|| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "event log changed while it was being read",
            ))
        })?;
        if event.encrypted != encryption.is_some() {
            return Err(StorageError::InvalidEncryptionScope {
                expected: if encryption.is_some() {
                    "encrypted event"
                } else {
                    "plaintext event"
                },
                record,
            });
        }
        let event = event.envelope;
        if event.run_id != expected_run_id {
            return Err(StorageError::InvalidRunId {
                expected: expected_run_id.to_owned(),
                found: event.run_id,
                sequence: event.sequence,
            });
        }
        if let Some(previous) = previous_event_id {
            if event.event_id == previous {
                return Err(StorageError::DuplicateEventId {
                    event_id: event.event_id,
                    sequence: event.sequence,
                });
            }
            if event.event_id < previous {
                return Err(StorageError::InvalidEventIdOrder {
                    previous,
                    found: event.event_id,
                    sequence: event.sequence,
                });
            }
        }
        previous_event_id = Some(event.event_id);
        visitor(event)?;
    }
    Ok(report)
}

/// Streaming reader for one authenticated run event log.
///
/// Construction verifies that the log has no incomplete tail. Iteration then
/// enforces the encryption scope, run identifier, sequence, and `UUIDv7` order
/// without retaining the whole recording in memory. This is used by bounded
/// exporters and uploaders that may pause between records for network I/O.
pub struct RunEventReader {
    reader: DecodedEventReader,
    expected_run_id: String,
    expect_encrypted: bool,
    report: RecoveryReport,
    next_record: u64,
    previous_event_id: Option<Uuid>,
    failed: bool,
}

impl RunEventReader {
    pub fn open(
        path: &Path,
        expected_run_id: &str,
        encryption: Option<&EncryptionKey>,
    ) -> Result<Self, StorageError> {
        let report = recover_events_with_key(path, false, encryption)?;
        if report.discarded_tail_bytes != 0 {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log has an incomplete final record; recover it before streaming",
            )));
        }
        Ok(Self {
            reader: DecodedEventReader::open(path, encryption)?,
            expected_run_id: expected_run_id.to_owned(),
            expect_encrypted: encryption.is_some(),
            report,
            next_record: 1,
            previous_event_id: None,
            failed: false,
        })
    }

    #[must_use]
    pub const fn report(&self) -> &RecoveryReport {
        &self.report
    }
}

impl Iterator for RunEventReader {
    type Item = Result<EventEnvelope, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.next_record > self.report.valid_events {
            return None;
        }
        let record = self.next_record;
        self.next_record = self.next_record.saturating_add(1);
        let result = (|| {
            let event = self.reader.next_decoded()?.ok_or_else(|| {
                StorageError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "event log changed while it was being read",
                ))
            })?;
            if event.encrypted != self.expect_encrypted {
                return Err(StorageError::InvalidEncryptionScope {
                    expected: if self.expect_encrypted {
                        "encrypted event"
                    } else {
                        "plaintext event"
                    },
                    record,
                });
            }
            let event = event.envelope;
            if event.run_id != self.expected_run_id {
                return Err(StorageError::InvalidRunId {
                    expected: self.expected_run_id.clone(),
                    found: event.run_id,
                    sequence: event.sequence,
                });
            }
            if event.sequence != record {
                return Err(StorageError::InvalidSequence {
                    expected: record,
                    found: event.sequence,
                });
            }
            if let Some(previous) = self.previous_event_id {
                if event.event_id == previous {
                    return Err(StorageError::DuplicateEventId {
                        event_id: event.event_id,
                        sequence: event.sequence,
                    });
                }
                if event.event_id < previous {
                    return Err(StorageError::InvalidEventIdOrder {
                        previous,
                        found: event.event_id,
                        sequence: event.sequence,
                    });
                }
            }
            self.previous_event_id = Some(event.event_id);
            Ok(event)
        })();
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}

fn decode_event(
    encoded: &[u8],
    encryption: Option<&EncryptionKey>,
) -> Result<EventEnvelope, StorageError> {
    validate_stored_json_complexity(encoded)?;
    let event = if is_encrypted_event(encoded) {
        let key = encryption.ok_or_else(|| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encrypted event log requires the matching key",
            ))
        })?;
        let plaintext = key.decrypt_event(encoded)?;
        validate_stored_json_complexity(&plaintext)?;
        serde_json::from_slice(&plaintext)?
    } else {
        serde_json::from_slice(encoded)?
    };
    let event: EventEnvelope = event;
    event.validate().map_err(StorageError::InvalidEnvelope)?;
    Ok(event)
}

fn read_event_record(
    reader: &mut impl BufRead,
    encoded: &mut Vec<u8>,
    record: u64,
) -> Result<(), StorageError> {
    let bytes = read_bounded_line(reader, encoded, MAX_EVENT_RECORD_BYTES, record)?;
    if bytes == 0 {
        return Err(StorageError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "event log changed while it was being read",
        )));
    }
    Ok(())
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    encoded: &mut Vec<u8>,
    limit: usize,
    record: u64,
) -> Result<usize, StorageError> {
    encoded.clear();
    let bytes = reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', encoded)?;
    if bytes > limit {
        return Err(StorageError::EventRecordTooLarge {
            record,
            max_bytes: limit,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[tokio::test]
    async fn appends_blobs_and_recovers_a_torn_tail() {
        let temporary = tempfile::tempdir().unwrap();
        let run_dir = temporary.path().join("run");
        let (store, recovery) =
            RunStore::create(&run_dir, "run-1", CapturePolicy::default()).unwrap();
        assert_eq!(recovery.valid_events, 0);

        let blob = store
            .store_blob(b"payload", Some("text/plain"))
            .await
            .unwrap();
        let mut event = store.event("test", "request");
        event.raw = Some(blob.clone());
        assert_eq!(store.append(event).await.unwrap(), 1);
        store.shutdown().await.unwrap();

        assert_eq!(
            fs::read(run_dir.join("blobs/sha256-").with_file_name(format!(
                "sha256-{}",
                blob.sha256.trim_start_matches("sha256:")
            )))
            .unwrap(),
            b"payload"
        );

        let mut events = OpenOptions::new()
            .append(true)
            .open(run_dir.join("events.jsonl"))
            .unwrap();
        events.write_all(b"{\"schema_version\":1").unwrap();
        events.sync_all().unwrap();
        let repaired = recover_events(&run_dir.join("events.jsonl"), true).unwrap();
        assert_eq!(repaired.valid_events, 1);
        assert!(repaired.discarded_tail_bytes > 0);
        assert!(repaired.quarantine.unwrap().exists());
    }

    #[tokio::test]
    async fn rejects_cross_run_events() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "expected", CapturePolicy::default()).unwrap();
        let event = PendingEvent::new("wrong", "test", "request");
        assert!(store.append(event).await.is_err());
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn reader_rejects_an_event_log_from_another_run() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "actual", CapturePolicy::default()).unwrap();
        store.append(store.event("test", "event")).await.unwrap();
        store.shutdown().await.unwrap();

        let error = for_each_run_event_with_key(
            &temporary.path().join("events.jsonl"),
            "expected",
            None,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, StorageError::InvalidRunId { .. }));
        assert!(RunStore::create(temporary.path(), "expected", CapturePolicy::default(),).is_err());
    }

    #[tokio::test]
    async fn checked_reader_rejects_plaintext_in_an_encrypted_event_log() {
        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([31; 32]);
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "scope",
            CapturePolicy::default(),
            Some(key.clone()),
        )
        .unwrap();
        store
            .append(store.event("test", "encrypted"))
            .await
            .unwrap();
        store.shutdown().await.unwrap();

        let plaintext = EventEnvelope::from_pending(
            2,
            PendingEvent::new("scope", "test", "plaintext-injection"),
        );
        let mut events = OpenOptions::new()
            .append(true)
            .open(temporary.path().join("events.jsonl"))
            .unwrap();
        serde_json::to_writer(&mut events, &plaintext).unwrap();
        events.write_all(b"\n").unwrap();
        events.sync_all().unwrap();

        let error = for_each_run_event_with_key(
            &temporary.path().join("events.jsonl"),
            "scope",
            Some(&key),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StorageError::InvalidEncryptionScope { record: 2, .. }
        ));
    }

    #[test]
    fn checked_reader_rejects_duplicate_event_ids() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("events.jsonl");
        let first = EventEnvelope::from_pending(1, PendingEvent::new("run", "test", "first"));
        let mut second = EventEnvelope::from_pending(2, PendingEvent::new("run", "test", "second"));
        second.event_id = first.event_id;
        let mut encoded = serde_json::to_vec(&first).unwrap();
        encoded.push(b'\n');
        encoded.extend_from_slice(&serde_json::to_vec(&second).unwrap());
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();

        let error = for_each_run_event_with_key(&path, "run", None, |_| Ok(())).unwrap_err();
        assert!(matches!(error, StorageError::DuplicateEventId { .. }));
    }

    #[test]
    fn checked_reader_rejects_decreasing_event_ids_without_a_global_id_set() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("events.jsonl");
        let mut first = EventEnvelope::from_pending(1, PendingEvent::new("run", "test", "first"));
        let mut second = EventEnvelope::from_pending(2, PendingEvent::new("run", "test", "second"));
        std::mem::swap(&mut first.event_id, &mut second.event_id);
        let mut encoded = serde_json::to_vec(&first).unwrap();
        encoded.push(b'\n');
        encoded.extend_from_slice(&serde_json::to_vec(&second).unwrap());
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();

        let error = for_each_run_event_with_key(&path, "run", None, |_| Ok(())).unwrap_err();
        assert!(matches!(error, StorageError::InvalidEventIdOrder { .. }));
    }

    #[test]
    fn recovery_rejects_an_oversized_event_without_unbounded_reading() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("events.jsonl");
        fs::write(&path, vec![b' '; MAX_EVENT_RECORD_BYTES + 1]).unwrap();
        let error = recover_events(&path, false).unwrap_err();
        assert!(matches!(error, StorageError::EventRecordTooLarge { .. }));
    }

    #[tokio::test]
    async fn capture_drop_counter_is_durable_for_manifest_finalization() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "drops", CapturePolicy::default()).unwrap();
        store.note_capture_drop();
        store.note_capture_drop();
        let stats = store.shutdown().await.unwrap();
        assert_eq!(stats.capture_drops, 2);
    }

    #[tokio::test]
    async fn prequeued_events_share_one_durable_sync_batch() {
        let temporary = tempfile::tempdir().unwrap();
        let events_path = temporary.path().join("events.jsonl");
        let lock_path = temporary.path().join("writer.lock");
        let stats = Arc::new(AtomicStats {
            events: AtomicU64::new(0),
            event_storage_bytes: AtomicU64::new(0),
            blobs: AtomicU64::new(0),
            blob_bytes: AtomicU64::new(0),
            queue_waits: AtomicU64::new(0),
            event_sync_batches: AtomicU64::new(0),
            capture_drops: AtomicU64::new(0),
        });
        let (sender, receiver) = mpsc::channel(4);
        let (first_reply, first_response) = oneshot::channel();
        let (second_reply, second_response) = oneshot::channel();
        sender
            .try_send(WriterCommand::Append {
                event: Box::new(PendingEvent::new("batch", "test", "first")),
                reply: first_reply,
            })
            .unwrap();
        sender
            .try_send(WriterCommand::Append {
                event: Box::new(PendingEvent::new("batch", "test", "second")),
                reply: second_reply,
            })
            .unwrap();
        drop(sender);

        let writer_stats = Arc::clone(&stats);
        let writer = tokio::task::spawn_blocking(move || {
            writer_loop(
                &events_path,
                &lock_path,
                1,
                0,
                u64::MAX,
                receiver,
                &writer_stats,
                None,
                EventLogFormat::Jsonl,
            )
        });
        assert_eq!(first_response.await.unwrap().unwrap(), 1);
        assert_eq!(second_response.await.unwrap().unwrap(), 2);
        let returned = writer.await.unwrap().unwrap();
        assert_eq!(returned.events, 2);
        assert_eq!(returned.event_sync_batches, 1);
        let recovery = recover_events(&temporary.path().join("events.jsonl"), false).unwrap();
        assert_eq!(recovery.valid_events, 2);
        assert_eq!(returned.event_storage_bytes, recovery.valid_bytes);
        assert_eq!(recovery.discarded_tail_bytes, 0);
    }

    #[tokio::test]
    async fn prequeued_events_share_one_authenticated_zstd_block() {
        let temporary = tempfile::tempdir().unwrap();
        let events_path = temporary.path().join("events.jsonl");
        let lock_path = temporary.path().join("writer.lock");
        let key = EncryptionKey::new([73; 32]);
        let stats = Arc::new(AtomicStats {
            events: AtomicU64::new(0),
            event_storage_bytes: AtomicU64::new(0),
            blobs: AtomicU64::new(0),
            blob_bytes: AtomicU64::new(0),
            queue_waits: AtomicU64::new(0),
            event_sync_batches: AtomicU64::new(0),
            capture_drops: AtomicU64::new(0),
        });
        let (sender, receiver) = mpsc::channel(4);
        let (first_reply, first_response) = oneshot::channel();
        let (second_reply, second_response) = oneshot::channel();
        for (name, reply) in [("first", first_reply), ("second", second_reply)] {
            let mut event = PendingEvent::new("compressed-batch", "test", name);
            event.normalized = Some(serde_json::json!({
                "repetitive": "evidence".repeat(8_192),
            }));
            sender
                .try_send(WriterCommand::Append {
                    event: Box::new(event),
                    reply,
                })
                .unwrap();
        }
        drop(sender);

        let writer_stats = Arc::clone(&stats);
        let writer_key = key.clone();
        let writer = tokio::task::spawn_blocking(move || {
            writer_loop(
                &events_path,
                &lock_path,
                1,
                0,
                u64::MAX,
                receiver,
                &writer_stats,
                Some(&writer_key),
                EventLogFormat::ZstdBlocks,
            )
        });
        assert_eq!(first_response.await.unwrap().unwrap(), 1);
        assert_eq!(second_response.await.unwrap().unwrap(), 2);
        let returned = writer.await.unwrap().unwrap();
        assert_eq!(returned.events, 2);
        assert_eq!(returned.event_sync_batches, 1);

        let bytes = fs::read(temporary.path().join("events.jsonl")).unwrap();
        assert!(bytes.starts_with(EVENT_BLOCK_HEADER));
        assert_eq!(bytes.split(|byte| *byte == b'\n').count(), 3);
        assert!(!bytes.windows(8).any(|window| window == b"evidence"));
        assert!(bytes.len() < 8_192);

        let report =
            recover_events_with_key(&temporary.path().join("events.jsonl"), false, Some(&key))
                .unwrap();
        assert_eq!(report.valid_events, 2);
        let events = RunEventReader::open(
            &temporary.path().join("events.jsonl"),
            "compressed-batch",
            Some(&key),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "first");
        assert_eq!(events[1].event, "second");
        assert!(recover_events(&temporary.path().join("events.jsonl"), false).is_err());
    }

    #[tokio::test]
    async fn zstd_block_logs_resume_recover_torn_tails_and_reject_format_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([74; 32]);
        let policy = CapturePolicy {
            event_log_format: EventLogFormat::ZstdBlocks,
            ..CapturePolicy::default()
        };
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "compressed-resume",
            policy.clone(),
            Some(key.clone()),
        )
        .unwrap();
        store.append(store.event("test", "first")).await.unwrap();
        store.shutdown().await.unwrap();

        let mut events = OpenOptions::new()
            .append(true)
            .open(temporary.path().join("events.jsonl"))
            .unwrap();
        events.write_all(b"{\"version\":1").unwrap();
        events.sync_all().unwrap();
        let repaired =
            recover_events_with_key(&temporary.path().join("events.jsonl"), true, Some(&key))
                .unwrap();
        assert_eq!(repaired.valid_events, 1);
        assert!(repaired.discarded_tail_bytes > 0);
        assert!(repaired.quarantine.unwrap().exists());

        let (resumed, recovery) = RunStore::create_with_encryption(
            temporary.path(),
            "compressed-resume",
            policy,
            Some(key.clone()),
        )
        .unwrap();
        assert_eq!(recovery.last_sequence, 1);
        assert_eq!(
            resumed
                .append(resumed.event("test", "second"))
                .await
                .unwrap(),
            2
        );
        resumed.shutdown().await.unwrap();
        assert_eq!(
            recover_events_with_key(&temporary.path().join("events.jsonl"), false, Some(&key))
                .unwrap()
                .valid_events,
            2
        );
        assert!(
            RunStore::create_with_encryption(
                temporary.path(),
                "compressed-resume",
                CapturePolicy::default(),
                Some(key)
            )
            .is_err()
        );
    }

    #[test]
    fn zstd_block_reader_rejects_declared_decompression_bombs_before_allocation() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("events.jsonl");
        let record = EventBlockRecord {
            version: EVENT_BLOCK_VERSION,
            codec: EVENT_BLOCK_CODEC.to_owned(),
            run_id: "bomb".to_owned(),
            first_sequence: 1,
            event_count: 1,
            uncompressed_bytes: u64::try_from(MAX_EVENT_BLOCK_UNCOMPRESSED_BYTES).unwrap() + 1,
            plaintext_sha256: "00".repeat(32),
            encrypted: false,
            payload: STANDARD_NO_PAD.encode(b"not-zstd"),
        };
        let mut bytes = EVENT_BLOCK_HEADER.to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&record).unwrap());
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            recover_events(&path, false),
            Err(StorageError::InvalidEventBlock(_))
        ));
    }

    #[tokio::test]
    async fn event_storage_budget_stops_before_exceeding_the_limit() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = CapturePolicy {
            max_event_storage_bytes: 1,
            ..CapturePolicy::default()
        };
        let (store, _) = RunStore::create(temporary.path(), "event-budget", policy).unwrap();

        assert!(store.append(store.event("test", "event")).await.is_err());
        assert_eq!(store.stats().capture_drops, 1);
        assert_eq!(
            fs::metadata(temporary.path().join("events.jsonl"))
                .unwrap()
                .len(),
            0
        );
        assert!(store.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn a_durable_batch_acknowledges_only_the_prefix_that_fits() {
        let temporary = tempfile::tempdir().unwrap();
        let events_path = temporary.path().join("events.jsonl");
        let mut file = open_regular_append_create(&events_path).unwrap();
        let first = PendingEvent::new("batch-budget", "test", "event");
        let first_size = encode_envelope(&EventEnvelope::from_pending(1, first.clone()), None)
            .unwrap()
            .len()
            .saturating_add(1);
        let second = PendingEvent::new("batch-budget", "test", "event");
        let (first_reply, first_response) = oneshot::channel();
        let (second_reply, second_response) = oneshot::channel();
        let stats = AtomicStats {
            events: AtomicU64::new(0),
            event_storage_bytes: AtomicU64::new(0),
            blobs: AtomicU64::new(0),
            blob_bytes: AtomicU64::new(0),
            queue_waits: AtomicU64::new(0),
            event_sync_batches: AtomicU64::new(0),
            capture_drops: AtomicU64::new(0),
        };
        let mut sequence = 1;
        let mut storage_bytes = 0;

        assert!(
            append_batch(
                &mut file,
                &mut sequence,
                &mut storage_bytes,
                u64::try_from(first_size).unwrap(),
                vec![
                    (Box::new(first), first_reply),
                    (Box::new(second), second_reply)
                ],
                &stats,
                None,
                EventLogFormat::Jsonl,
            )
            .is_err()
        );
        assert_eq!(first_response.await.unwrap().unwrap(), 1);
        assert!(second_response.await.unwrap().is_err());
        assert_eq!(sequence, 2);
        assert_eq!(stats.snapshot().events, 1);
        assert_eq!(stats.snapshot().event_sync_batches, 1);
        assert_eq!(recover_events(&events_path, false).unwrap().valid_events, 1);
    }

    #[test]
    fn writer_rejects_records_its_reader_cannot_recover() {
        let mut pending = PendingEvent::new("record-limit", "test", "oversized");
        pending.normalized = Some(serde_json::Value::String(
            "x".repeat(MAX_EVENT_RECORD_BYTES),
        ));
        let envelope = EventEnvelope::from_pending(1, pending);
        assert!(matches!(
            encode_envelope(&envelope, None),
            Err(StorageError::EventRecordTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn writer_and_reader_accept_the_external_json_depth_boundary() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "depth-boundary", CapturePolicy::default()).unwrap();
        let mut normalized = serde_json::Value::Null;
        for _ in 0..crate::input::MAX_JSON_NESTING_DEPTH {
            normalized = serde_json::Value::Array(vec![normalized]);
        }
        let mut event = store.event("test", "depth_boundary");
        event.normalized = Some(normalized);
        store.append(event).await.unwrap();
        store.shutdown().await.unwrap();

        let mut seen = false;
        for_each_run_event_with_key(
            &temporary.path().join("events.jsonl"),
            "depth-boundary",
            None,
            |event| {
                seen = event.event == "depth_boundary";
                Ok(())
            },
        )
        .unwrap();
        assert!(seen);
    }

    #[tokio::test]
    async fn encrypts_events_and_blobs_before_they_reach_disk() {
        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([9; 32]);
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "encrypted",
            CapturePolicy::default(),
            Some(key.clone()),
        )
        .unwrap();
        let raw = store
            .store_blob(b"secret-payload", Some("text/plain"))
            .await
            .unwrap();
        let mut event = store.event("test", "encrypted_event");
        event.raw = Some(raw.clone());
        event.normalized = Some(serde_json::json!({"secret": "event-secret"}));
        store.append(event).await.unwrap();
        store.shutdown().await.unwrap();

        let event_bytes = fs::read(temporary.path().join("events.jsonl")).unwrap();
        assert!(
            !event_bytes
                .windows(12)
                .any(|window| window == b"event-secret")
        );
        assert!(for_each_event(&temporary.path().join("events.jsonl"), |_| Ok(())).is_err());
        let mut seen = false;
        for_each_event_with_key(
            &temporary.path().join("events.jsonl"),
            Some(&key),
            |event| {
                seen = event.event == "encrypted_event";
                Ok(())
            },
        )
        .unwrap();
        assert!(seen);

        let hash = raw.sha256.trim_start_matches("sha256:");
        let encoded =
            fs::read(crate::blob_keys::blob_path(temporary.path(), &raw).unwrap()).unwrap();
        assert!(
            !encoded
                .windows(14)
                .any(|window| window == b"secret-payload")
        );
        assert!(key.decrypt_blob(&encoded, hash).is_err());
        assert_eq!(
            crate::blob_keys::read_blob_reference(
                temporary.path(),
                &raw,
                Some(&key),
                MAX_SINGLE_BLOB_BYTES,
            )
            .unwrap(),
            b"secret-payload"
        );
    }

    #[tokio::test]
    async fn sensitive_blobs_require_encryption_and_ignore_model_body_limit() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = CapturePolicy {
            max_blob_bytes: 1,
            ..CapturePolicy::default()
        };
        let (plaintext, _) =
            RunStore::create(temporary.path().join("plain"), "plain", policy.clone()).unwrap();
        assert!(
            plaintext
                .store_sensitive_blob(b"secret", None)
                .await
                .is_err()
        );
        plaintext.shutdown().await.unwrap();

        let key = EncryptionKey::new([44; 32]);
        let (encrypted, _) = RunStore::create_with_encryption(
            temporary.path().join("encrypted"),
            "encrypted",
            policy,
            Some(key),
        )
        .unwrap();
        let reference = encrypted
            .store_sensitive_blob(b"secret", None)
            .await
            .unwrap();
        assert_eq!(reference.size, 6);
        assert!(!reference.truncated);
        encrypted.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn whole_run_blob_budget_is_atomic_and_deduplicated() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = CapturePolicy {
            max_run_blob_storage_bytes: 3,
            ..CapturePolicy::default()
        };
        let (store, _) = RunStore::create(temporary.path(), "budget", policy.clone()).unwrap();
        let first = store.store_blob(b"abc", None).await.unwrap();
        let duplicate = store.store_blob(b"abc", None).await.unwrap();
        assert_eq!(first.sha256, duplicate.sha256);
        let error = store.store_blob(b"d", None).await.unwrap_err();
        assert!(matches!(
            error,
            StorageError::BlobStorageBudgetExceeded {
                used: 3,
                requested: 1,
                limit: 3,
            }
        ));
        store.shutdown().await.unwrap();

        let (resumed, _) = RunStore::create(temporary.path(), "budget", policy).unwrap();
        assert!(matches!(
            resumed.store_blob(b"e", None).await.unwrap_err(),
            StorageError::BlobStorageBudgetExceeded { .. }
        ));
        resumed.shutdown().await.unwrap();
    }

    #[test]
    fn blob_file_reservation_fails_before_exceeding_its_limit() {
        let files = AtomicU64::new(0);
        reserve_blob_file_count(&files, 1).unwrap();
        assert_eq!(files.load(Ordering::Relaxed), 1);
        assert!(matches!(
            reserve_blob_file_count(&files, 1),
            Err(StorageError::BlobFileLimitExceeded { used: 1, limit: 1 })
        ));
        assert_eq!(files.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn rejects_symlink_event_logs_and_conflicting_blob_files() {
        let temporary = tempfile::tempdir().unwrap();
        let victim = temporary.path().join("victim");
        fs::write(&victim, b"not-an-event-log").unwrap();
        let linked_run = temporary.path().join("linked-run");
        fs::create_dir(&linked_run).unwrap();
        symlink(&victim, linked_run.join("events.jsonl")).unwrap();
        assert!(RunStore::create(&linked_run, "linked", CapturePolicy::default()).is_err());

        let blob_target = temporary.path().join("blob-target");
        fs::create_dir(&blob_target).unwrap();
        let linked_blobs_run = temporary.path().join("linked-blobs-run");
        fs::create_dir(&linked_blobs_run).unwrap();
        symlink(&blob_target, linked_blobs_run.join("blobs")).unwrap();
        assert!(
            RunStore::create(&linked_blobs_run, "linked-blobs", CapturePolicy::default()).is_err()
        );

        let run = temporary.path().join("blob-run");
        let (store, _) = RunStore::create(&run, "blob", CapturePolicy::default()).unwrap();
        let hash = hex::encode(Sha256::digest(b"expected"));
        fs::write(run.join("blobs").join(format!("sha256-{hash}")), b"wrong").unwrap();
        assert!(store.store_blob(b"expected", None).await.is_err());
        store.shutdown().await.unwrap();
    }
}
