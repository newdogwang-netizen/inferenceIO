use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File},
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
    unistd::{mkfifo, read},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::oneshot,
    task::JoinHandle,
};
use tracing::warn;
use zeroize::Zeroizing;

use crate::{model::RedactionRecord, storage::RunStore};

const MAX_LINE_BYTES: usize = 4096;
const MAX_BUFFER_BYTES: usize = 64 * 1024;
const MAX_DEDUP_RECORDS: usize = 65_536;
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

pub struct TlsKeyLogHandle {
    pub path: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

pub struct RustlsKeyLogger {
    writer: Mutex<File>,
    store: RunStore,
}

impl fmt::Debug for RustlsKeyLogger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsKeyLogger")
            .field("writer", &"private-fifo")
            .finish_non_exhaustive()
    }
}

impl rustls::KeyLog for RustlsKeyLogger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if label.is_empty()
            || label.len() > 64
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !(32..=64).contains(&client_random.len())
            || !(16..=256).contains(&secret.len())
        {
            self.store.note_capture_drop();
            return;
        }
        let line = Zeroizing::new(format!(
            "{label} {} {}\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let Ok(mut writer) = self.writer.lock() else {
            self.store.note_capture_drop();
            return;
        };
        if writer.write_all(line.as_bytes()).is_err() {
            self.store.note_capture_drop();
        }
    }
}

pub fn rustls_key_logger(path: &Path, store: RunStore) -> io::Result<Arc<dyn rustls::KeyLog>> {
    let metadata = path.symlink_metadata()?;
    if !metadata.file_type().is_fifo()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != fs::metadata(path.parent().unwrap_or_else(|| Path::new(".")))?.uid()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TLS key-log transport is not a private owner-matched FIFO",
        ));
    }
    let descriptor = open(
        path,
        OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    Ok(Arc::new(RustlsKeyLogger {
        writer: Mutex::new(File::from(descriptor)),
        store,
    }))
}

impl TlsKeyLogHandle {
    pub async fn stop(mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = if let Ok(result) =
            tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut self.task).await
        {
            result
                .map_err(|error| io::Error::other(format!("TLS key-log task panicked: {error}")))?
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS key-log capture did not stop before its shutdown deadline",
            ))
        };
        let cleanup = remove_fifo(&self.path);
        task_result?;
        cleanup
    }
}

impl Drop for TlsKeyLogHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = remove_fifo(&self.path);
    }
}

pub fn start(run_dir: &Path, store: RunStore) -> io::Result<TlsKeyLogHandle> {
    let path = run_dir.join("tls-keylog.pipe");
    mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).map_err(io::Error::from)?;
    let descriptor = match open(
        &path,
        OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = fs::remove_file(&path);
            return Err(io::Error::from(error));
        }
    };
    let descriptor = match AsyncFd::with_interest(descriptor, Interest::READABLE) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
    };
    let (shutdown, stopped) = oneshot::channel();
    let task = tokio::spawn(capture(descriptor, stopped, store));
    Ok(TlsKeyLogHandle {
        path,
        shutdown: Some(shutdown),
        task,
    })
}

async fn capture(
    descriptor: AsyncFd<std::os::fd::OwnedFd>,
    mut shutdown: oneshot::Receiver<()>,
    store: RunStore,
) -> io::Result<()> {
    let mut buffered = Vec::new();
    let mut seen = BTreeSet::new();
    let mut persistence_available = true;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            ready = descriptor.readable() => {
                let mut guard = ready?;
                let mut chunk = [0_u8; 4096];
                let mut buffer_overflow = false;
                loop {
                    match guard.try_io(|inner| {
                        read(inner.get_ref(), &mut chunk).map_err(io::Error::from)
                    }) {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(length)) => {
                            let remaining = MAX_BUFFER_BYTES.saturating_sub(buffered.len());
                            let retained = remaining.min(length);
                            buffered.extend_from_slice(&chunk[..retained]);
                            if retained != length {
                                buffer_overflow = true;
                                break;
                            }
                            if buffered.len() == MAX_BUFFER_BYTES {
                                break;
                            }
                        }
                        Ok(Err(error)) => return Err(error),
                    }
                }
                if persistence_available
                    && let Err(error) = consume_lines(&store, &mut buffered, &mut seen).await
                {
                    store.note_capture_drop();
                    warn!(
                        error_kind = ?error.kind(),
                        "TLS key-log persistence failed; continuing to drain the FIFO"
                    );
                    persistence_available = false;
                }
                if !persistence_available {
                    buffered.clear();
                } else if buffer_overflow || buffered.len() >= MAX_BUFFER_BYTES {
                    if let Err(error) = record_rejected(&store, &buffered, "buffer_limit").await {
                        store.note_capture_drop();
                        warn!(
                            error_kind = ?error.kind(),
                            "TLS key-log rejection evidence could not be persisted; continuing to drain the FIFO"
                        );
                        persistence_available = false;
                    }
                    buffered.clear();
                    store.note_capture_drop();
                }
            }
        }
    }
    if persistence_available && !buffered.iter().all(u8::is_ascii_whitespace) {
        if let Err(error) = record_rejected(&store, &buffered, "unterminated_record").await {
            store.note_capture_drop();
            warn!(
                error_kind = ?error.kind(),
                "unterminated TLS key-log evidence could not be persisted"
            );
        }
        store.note_capture_drop();
    }
    Ok(())
}

async fn consume_lines(
    store: &RunStore,
    buffered: &mut Vec<u8>,
    seen: &mut BTreeSet<[u8; 32]>,
) -> io::Result<()> {
    while let Some(end) = buffered.iter().position(|byte| *byte == b'\n') {
        let mut record: Vec<u8> = buffered.drain(..=end).collect();
        while record
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            record.pop();
        }
        if record.is_empty() || record.first() == Some(&b'#') {
            continue;
        }
        if record.len() > MAX_LINE_BYTES {
            record_rejected(store, &record, "record_limit").await?;
            store.note_capture_drop();
            continue;
        }
        let Some(parsed) = parse_record(&record) else {
            record_rejected(store, &record, "invalid_format").await?;
            store.note_capture_drop();
            continue;
        };
        let digest: [u8; 32] = Sha256::digest(&record).into();
        if !record_digest_is_new(seen, digest) {
            continue;
        }
        let raw = store
            .store_sensitive_blob(&record, Some("application/x-nss-key-log"))
            .await
            .map_err(io::Error::other)?;
        if raw.truncated {
            record_rejected(store, &record, "storage_limit").await?;
            store.note_capture_drop();
            continue;
        }
        let mut event = store.event("tls-keylog", "tls_key_log_secret");
        event.raw = Some(raw);
        event.normalized = Some(json!({
            "label": parsed.label,
            "client_random_sha256": hex::encode(Sha256::digest(parsed.client_random)),
        }));
        event.redaction = RedactionRecord {
            policy: "encrypted-secret".to_owned(),
            fields: vec!["tls_secret".to_owned()],
            omitted: Vec::new(),
        };
        event.confidence = Some(1.0);
        event.evidence = vec!["nss_sslkeylogfile".to_owned()];
        store.append(event).await.map_err(io::Error::other)?;
    }
    Ok(())
}

fn record_digest_is_new(seen: &mut BTreeSet<[u8; 32]>, digest: [u8; 32]) -> bool {
    if seen.contains(&digest) {
        return false;
    }
    if seen.len() >= MAX_DEDUP_RECORDS {
        seen.clear();
    }
    seen.insert(digest)
}

struct ParsedRecord<'a> {
    label: &'a str,
    client_random: &'a [u8],
}

fn parse_record(record: &[u8]) -> Option<ParsedRecord<'_>> {
    let text = std::str::from_utf8(record).ok()?;
    let mut fields = text.split_ascii_whitespace();
    let label = fields.next()?;
    let client_random = fields.next()?;
    let secret = fields.next()?;
    if fields.next().is_some()
        || label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || !valid_hex(client_random, 64, 128)
        || !valid_hex(secret, 32, 512)
    {
        return None;
    }
    Some(ParsedRecord {
        label,
        client_random: client_random.as_bytes(),
    })
}

fn valid_hex(value: &str, minimum: usize, maximum: usize) -> bool {
    value.len() >= minimum
        && value.len() <= maximum
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn record_rejected(store: &RunStore, record: &[u8], reason: &str) -> io::Result<()> {
    let mut event = store.event("tls-keylog", "tls_key_log_record_rejected");
    event.normalized = Some(json!({
        "reason": reason,
        "bytes": record.len(),
        "sha256": hex::encode(Sha256::digest(record)),
    }));
    event.redaction = RedactionRecord {
        policy: "encrypted-secret".to_owned(),
        fields: vec!["tls_secret".to_owned()],
        omitted: vec!["record".to_owned()],
    };
    store.append(event).await.map_err(io::Error::other)?;
    Ok(())
}

fn remove_fifo(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, time::Duration};

    use crate::{crypto::EncryptionKey, policy::CapturePolicy};

    use super::*;

    #[test]
    fn accepts_standard_records_and_rejects_unbounded_or_ambiguous_input() {
        let random = "a".repeat(64);
        let secret = "b".repeat(96);
        let record = format!("CLIENT_HANDSHAKE_TRAFFIC_SECRET {random} {secret}");
        let parsed = parse_record(record.as_bytes()).unwrap();
        assert_eq!(parsed.label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        assert!(parse_record(format!("label {random} {secret}").as_bytes()).is_none());
        assert!(parse_record(format!("CLIENT_RANDOM bad {secret}").as_bytes()).is_none());
        assert!(
            parse_record(format!("CLIENT_RANDOM {random} {secret} extra").as_bytes()).is_none()
        );
    }

    #[tokio::test]
    async fn storage_failure_keeps_the_fifo_draining_for_target_non_interference() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = CapturePolicy {
            max_event_storage_bytes: 1,
            ..CapturePolicy::default()
        };
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "tls-keylog-drain",
            policy,
            Some(EncryptionKey::new([74; 32])),
        )
        .unwrap();
        let handle = start(temporary.path(), store.clone()).unwrap();
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .open(&handle.path)
            .unwrap();
        let record = format!("CLIENT_RANDOM {} {}\n", "a".repeat(64), "b".repeat(96));
        writer.write_all(record.as_bytes()).unwrap();
        writer.flush().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.task.is_finished());

        writer.write_all(record.as_bytes()).unwrap();
        writer.flush().unwrap();
        handle.stop().await.unwrap();
        assert!(store.stats().capture_drops > 0);
        assert!(store.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn recorder_rustls_writer_uses_the_same_encrypted_fifo_pipeline() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "rustls-keylog-writer",
            CapturePolicy::default(),
            Some(EncryptionKey::new([76; 32])),
        )
        .unwrap();
        let handle = start(temporary.path(), store.clone()).unwrap();
        let logger = rustls_key_logger(&handle.path, store.clone()).unwrap();
        logger.log("CLIENT_TRAFFIC_SECRET_0", &[0xaa; 32], &[0xbb; 48]);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(store.stats().capture_drops, 0);
        assert!(store.stats().events > 0);
        drop(logger);
        handle.stop().await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_fifo_input_is_bounded_and_shutdown_is_not_starved() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "tls-keylog-overflow",
            CapturePolicy::default(),
            Some(EncryptionKey::new([75; 32])),
        )
        .unwrap();
        let handle = start(temporary.path(), store.clone()).unwrap();
        let path = handle.path.clone();
        let writer = tokio::task::spawn_blocking(move || {
            let mut writer = fs::OpenOptions::new().write(true).open(path).unwrap();
            writer.write_all(&vec![b'x'; MAX_BUFFER_BYTES * 4]).unwrap();
            writer.flush().unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .unwrap()
            .unwrap();
        assert!(store.stats().capture_drops > 0);
        store.shutdown().await.unwrap();
    }

    #[test]
    fn tls_secret_deduplication_memory_is_bounded() {
        let mut seen = BTreeSet::new();
        for index in 0..MAX_DEDUP_RECORDS {
            let mut digest = [0_u8; 32];
            digest[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
            assert!(record_digest_is_new(&mut seen, digest));
        }
        assert_eq!(seen.len(), MAX_DEDUP_RECORDS);
        assert!(!record_digest_is_new(&mut seen, [0; 32]));
        assert!(record_digest_is_new(&mut seen, [0xff; 32]));
        assert_eq!(seen.len(), 1);
    }
}
