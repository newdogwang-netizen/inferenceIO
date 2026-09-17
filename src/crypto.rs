use std::{
    borrow::Cow,
    fmt, fs, io,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

use crate::input::{validate_json_complexity, validate_stored_json_complexity};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, Key, KeyInit, Payload},
};
use hkdf::Hkdf;
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const BLOB_MAGIC: &[u8] = b"IORECBL1";
const WRAPPED_KEY_MAGIC: &[u8] = b"IORECKY1";
const RETENTION_STATE_MAGIC: &[u8] = b"IORECRS1";
const EVENT_BLOCK_MAGIC: &[u8] = b"IORECEB1";
const EVENT_AAD_V1: &[u8] = b"iorec:event:v1";
const EVENT_AAD_V2: &[u8] = b"iorec:event:v2";
const EVENT_BLOCK_AAD_V1: &[u8] = b"iorec:event-block:v1";
const MANIFEST_AAD_V1: &[u8] = b"iorec:manifest:v1";
const RUN_KEY_SALT_V1: &[u8] = b"iorec:run-key:salt:v1";
const RUN_KEY_INFO_V1: &[u8] = b"iorec:run-key:info:v1";
const WRAPPED_KEY_AAD_V1: &[u8] = b"iorec:wrapped-blob-key:v1";
const RETENTION_STATE_AAD_V1: &[u8] = b"iorec:retention-state:v1";

#[derive(Clone)]
pub struct EncryptionKey {
    bytes: Arc<Zeroizing<[u8; 32]>>,
    key_id: String,
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl EncryptionKey {
    pub fn generate_file(path: &Path) -> io::Result<Self> {
        let generated = Key::<XChaCha20Poly1305>::generate();
        let bytes: [u8; 32] = generated.into();
        let key = Self::new(bytes);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex::encode(bytes).as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::File::open(parent_directory(path))?.sync_all()?;
        Ok(key)
    }

    pub fn from_file(path: &Path) -> io::Result<Self> {
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let mut file = fs::File::from(descriptor);
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encryption key path must be a regular file",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "encryption key file must not be accessible by group or other users",
            ));
        }
        if metadata.len() > 65 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encryption key file is too large",
            ));
        }
        let mut bytes = Vec::with_capacity(65);
        file.read_to_end(&mut bytes)?;
        let key = parse_key(&bytes)?;
        Ok(Self::new(key))
    }

    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        let key_id = hex::encode(Sha256::digest(bytes));
        Self {
            bytes: Arc::new(Zeroizing::new(bytes)),
            key_id,
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Derives a data-encryption key scoped to one immutable run identifier.
    /// The caller-supplied key remains the stable master-key identity recorded
    /// in the manifest; the returned key is used only for that run's AEAD.
    pub fn derive_run_key(&self, run_id: &str) -> io::Result<Self> {
        if run_id.is_empty() || run_id.len() > 256 || run_id.chars().any(char::is_control) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "run ID is invalid for key derivation",
            ));
        }
        let hkdf = Hkdf::<Sha256>::new(Some(RUN_KEY_SALT_V1), self.bytes.as_ref().as_ref());
        let run_id = run_id.as_bytes();
        let mut info = Vec::with_capacity(RUN_KEY_INFO_V1.len() + 8 + run_id.len());
        info.extend_from_slice(RUN_KEY_INFO_V1);
        info.extend_from_slice(
            &u64::try_from(run_id.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "run ID is too large"))?
                .to_be_bytes(),
        );
        info.extend_from_slice(run_id);
        let mut output = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, output.as_mut())
            .map_err(|_| io::Error::other("HKDF run-key derivation failed"))?;
        Ok(Self::new(*output))
    }

    pub fn encrypt_event_record(
        &self,
        plaintext: &[u8],
        run_id: &str,
        sequence: u64,
    ) -> io::Result<Vec<u8>> {
        let aad = event_aad_v2(run_id, sequence);
        let (nonce, ciphertext) = self.encrypt(plaintext, &aad)?;
        serde_json::to_vec(&EncryptedEvent {
            version: 2,
            run_id: Some(run_id.to_owned()),
            sequence: Some(sequence),
            nonce: STANDARD_NO_PAD.encode(nonce),
            ciphertext: STANDARD_NO_PAD.encode(ciphertext),
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn decrypt_event(&self, encoded: &[u8]) -> io::Result<Vec<u8>> {
        validate_json_complexity(encoded)?;
        let record: EncryptedEventRef<'_> = serde_json::from_slice(encoded)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let nonce = STANDARD_NO_PAD
            .decode(record.nonce.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let ciphertext = STANDARD_NO_PAD
            .decode(record.ciphertext.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        match record.version {
            1 => self.decrypt(&nonce, &ciphertext, EVENT_AAD_V1),
            2 => {
                let run_id = record.run_id.as_deref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "encrypted event has no run ID")
                })?;
                let sequence = record.sequence.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encrypted event has no sequence",
                    )
                })?;
                let plaintext =
                    self.decrypt(&nonce, &ciphertext, &event_aad_v2(run_id, sequence))?;
                validate_event_context(&plaintext, run_id, sequence)?;
                Ok(plaintext)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported encrypted event version",
            )),
        }
    }

    /// Encrypt one compressed event block while authenticating all framing
    /// fields needed to place it in a run and sequence range.
    pub(crate) fn encrypt_event_block(
        &self,
        compressed: &[u8],
        run_id: &str,
        first_sequence: u64,
        event_count: u64,
        uncompressed_bytes: u64,
        plaintext_sha256: &[u8; 32],
    ) -> io::Result<Vec<u8>> {
        let aad = event_block_aad_v1(
            run_id,
            first_sequence,
            event_count,
            uncompressed_bytes,
            plaintext_sha256,
        );
        let (nonce, ciphertext) = self.encrypt(compressed, &aad)?;
        let mut output =
            Vec::with_capacity(EVENT_BLOCK_MAGIC.len() + nonce.len() + ciphertext.len());
        output.extend_from_slice(EVENT_BLOCK_MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub(crate) fn decrypt_event_block(
        &self,
        encoded: &[u8],
        run_id: &str,
        first_sequence: u64,
        event_count: u64,
        uncompressed_bytes: u64,
        plaintext_sha256: &[u8; 32],
    ) -> io::Result<Vec<u8>> {
        if !encoded.starts_with(EVENT_BLOCK_MAGIC)
            || encoded.len() < EVENT_BLOCK_MAGIC.len() + 24 + 16
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid encrypted event-block framing",
            ));
        }
        let nonce_start = EVENT_BLOCK_MAGIC.len();
        let ciphertext_start = nonce_start + 24;
        let aad = event_block_aad_v1(
            run_id,
            first_sequence,
            event_count,
            uncompressed_bytes,
            plaintext_sha256,
        );
        self.decrypt(
            &encoded[nonce_start..ciphertext_start],
            &encoded[ciphertext_start..],
            &aad,
        )
    }

    #[cfg(test)]
    fn encrypt_legacy_event(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let (nonce, ciphertext) = self.encrypt(plaintext, EVENT_AAD_V1)?;
        serde_json::to_vec(&EncryptedEvent {
            version: 1,
            run_id: None,
            sequence: None,
            nonce: STANDARD_NO_PAD.encode(nonce),
            ciphertext: STANDARD_NO_PAD.encode(ciphertext),
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn encrypt_blob(&self, plaintext: &[u8], hash: &str) -> io::Result<Vec<u8>> {
        let aad = format!("iorec:blob:v1:{hash}");
        let (nonce, ciphertext) = self.encrypt(plaintext, aad.as_bytes())?;
        let mut output = Vec::with_capacity(BLOB_MAGIC.len() + nonce.len() + ciphertext.len());
        output.extend_from_slice(BLOB_MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn decrypt_blob(&self, encoded: &[u8], hash: &str) -> io::Result<Vec<u8>> {
        if !encoded.starts_with(BLOB_MAGIC) || encoded.len() < BLOB_MAGIC.len() + 24 + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid encrypted blob framing",
            ));
        }
        let nonce_start = BLOB_MAGIC.len();
        let ciphertext_start = nonce_start + 24;
        let aad = format!("iorec:blob:v1:{hash}");
        self.decrypt(
            &encoded[nonce_start..ciphertext_start],
            &encoded[ciphertext_start..],
            aad.as_bytes(),
        )
    }

    pub(crate) fn generate_wrapped_data_key(&self, context: &str) -> io::Result<(Self, Vec<u8>)> {
        validate_key_context(context)?;
        let generated: [u8; 32] = Key::<XChaCha20Poly1305>::generate().into();
        let aad = length_prefixed_aad(WRAPPED_KEY_AAD_V1, context.as_bytes());
        let (nonce, ciphertext) = self.encrypt(&generated, &aad)?;
        let mut output =
            Vec::with_capacity(WRAPPED_KEY_MAGIC.len() + nonce.len() + ciphertext.len());
        output.extend_from_slice(WRAPPED_KEY_MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok((Self::new(generated), output))
    }

    pub(crate) fn unwrap_data_key(&self, encoded: &[u8], context: &str) -> io::Result<Self> {
        validate_key_context(context)?;
        let plaintext = decrypt_framed(
            self,
            encoded,
            WRAPPED_KEY_MAGIC,
            &length_prefixed_aad(WRAPPED_KEY_AAD_V1, context.as_bytes()),
        )?;
        let bytes: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "wrapped data key has invalid length",
            )
        })?;
        Ok(Self::new(bytes))
    }

    pub(crate) fn encrypt_retention_state(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let (nonce, ciphertext) = self.encrypt(plaintext, RETENTION_STATE_AAD_V1)?;
        let mut output =
            Vec::with_capacity(RETENTION_STATE_MAGIC.len() + nonce.len() + ciphertext.len());
        output.extend_from_slice(RETENTION_STATE_MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub(crate) fn decrypt_retention_state(&self, encoded: &[u8]) -> io::Result<Vec<u8>> {
        decrypt_framed(self, encoded, RETENTION_STATE_MAGIC, RETENTION_STATE_AAD_V1)
    }

    pub fn authenticate_manifest(&self, canonical: &[u8]) -> io::Result<(String, String)> {
        let aad = length_prefixed_aad(MANIFEST_AAD_V1, canonical);
        let (nonce, tag) = self.encrypt(&[], &aad)?;
        Ok((STANDARD_NO_PAD.encode(nonce), STANDARD_NO_PAD.encode(tag)))
    }

    pub fn verify_manifest_authentication(
        &self,
        canonical: &[u8],
        nonce: &str,
        tag: &str,
    ) -> io::Result<()> {
        let nonce = STANDARD_NO_PAD
            .decode(nonce)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let tag = STANDARD_NO_PAD
            .decode(tag)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let aad = length_prefixed_aad(MANIFEST_AAD_V1, canonical);
        let plaintext = self.decrypt(&nonce, &tag, &aad)?;
        if plaintext.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "manifest authentication payload is not empty",
            ))
        }
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let key = Key::<XChaCha20Poly1305>::from(**self.bytes);
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = XNonce::generate();
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| io::Error::other("AEAD encryption failed"))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid AEAD nonce"))?;
        let key = Key::<XChaCha20Poly1305>::from(**self.bytes);
        XChaCha20Poly1305::new(&key)
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD authentication failed"))
    }
}

fn decrypt_framed(
    key: &EncryptionKey,
    encoded: &[u8],
    magic: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    if !encoded.starts_with(magic) || encoded.len() < magic.len() + 24 + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid encrypted key-state framing",
        ));
    }
    let nonce_start = magic.len();
    let ciphertext_start = nonce_start + 24;
    key.decrypt(
        &encoded[nonce_start..ciphertext_start],
        &encoded[ciphertext_start..],
        aad,
    )
}

fn validate_key_context(context: &str) -> io::Result<()> {
    if context.is_empty()
        || context.len() > 64
        || !context
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wrapped key context is invalid",
        ));
    }
    Ok(())
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[derive(Serialize, Deserialize)]
struct EncryptedEvent {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct EncryptedEventRef<'a> {
    version: u8,
    #[serde(default, borrow)]
    run_id: Option<Cow<'a, str>>,
    #[serde(default)]
    sequence: Option<u64>,
    #[serde(borrow)]
    nonce: Cow<'a, str>,
    #[serde(borrow)]
    ciphertext: Cow<'a, str>,
}

fn event_aad_v2(run_id: &str, sequence: u64) -> Vec<u8> {
    let run_id_bytes = run_id.as_bytes();
    let mut aad = Vec::with_capacity(EVENT_AAD_V2.len() + 16 + run_id_bytes.len());
    aad.extend_from_slice(EVENT_AAD_V2);
    aad.extend_from_slice(
        &u64::try_from(run_id_bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    aad.extend_from_slice(run_id_bytes);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn event_block_aad_v1(
    run_id: &str,
    first_sequence: u64,
    event_count: u64,
    uncompressed_bytes: u64,
    plaintext_sha256: &[u8; 32],
) -> Vec<u8> {
    let run_id_bytes = run_id.as_bytes();
    let mut aad = Vec::with_capacity(
        EVENT_BLOCK_AAD_V1.len() + 8 + run_id_bytes.len() + 8 * 3 + plaintext_sha256.len(),
    );
    aad.extend_from_slice(EVENT_BLOCK_AAD_V1);
    aad.extend_from_slice(
        &u64::try_from(run_id_bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    aad.extend_from_slice(run_id_bytes);
    aad.extend_from_slice(&first_sequence.to_be_bytes());
    aad.extend_from_slice(&event_count.to_be_bytes());
    aad.extend_from_slice(&uncompressed_bytes.to_be_bytes());
    aad.extend_from_slice(plaintext_sha256);
    aad
}

fn length_prefixed_aad(domain: &[u8], value: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + 8 + value.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    aad.extend_from_slice(value);
    aad
}

fn validate_event_context(plaintext: &[u8], run_id: &str, sequence: u64) -> io::Result<()> {
    validate_stored_json_complexity(plaintext)?;
    let event: serde_json::Value = serde_json::from_slice(plaintext)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if event.get("run_id").and_then(serde_json::Value::as_str) != Some(run_id)
        || event.get("sequence").and_then(serde_json::Value::as_u64) != Some(sequence)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted event context does not match its plaintext envelope",
        ));
    }
    Ok(())
}

#[must_use]
pub fn is_encrypted_event(encoded: &[u8]) -> bool {
    validate_json_complexity(encoded).is_ok()
        && serde_json::from_slice::<EncryptedEventRef<'_>>(encoded).is_ok()
}

#[must_use]
pub fn is_encrypted_blob(encoded: &[u8]) -> bool {
    encoded.starts_with(BLOB_MAGIC)
}

fn parse_key(bytes: &[u8]) -> io::Result<[u8; 32]> {
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid raw key"));
    }
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    if trimmed.len() == 32 {
        return trimmed
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid raw key"));
    }
    if trimmed.len() == 64 {
        let decoded = hex::decode(trimmed)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        return decoded
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hexadecimal key"));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "encryption key must contain 32 raw bytes or 64 hexadecimal characters",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_and_blob_domains_round_trip_and_authenticate() {
        let key = EncryptionKey::new([7; 32]);
        let plaintext = br#"{"run_id":"run-1","sequence":42,"event":"secret"}"#;
        let event = key.encrypt_event_record(plaintext, "run-1", 42).unwrap();
        assert!(!event.windows(6).any(|window| window == b"secret"));
        assert_eq!(key.decrypt_event(&event).unwrap(), plaintext);

        let blob = key.encrypt_blob(b"blob", "hash-1").unwrap();
        assert!(is_encrypted_blob(&blob));
        assert_eq!(key.decrypt_blob(&blob, "hash-1").unwrap(), b"blob");
        assert!(key.decrypt_blob(&blob, "hash-2").is_err());
        assert!(EncryptionKey::new([8; 32]).decrypt_event(&event).is_err());

        let digest: [u8; 32] = Sha256::digest(b"event block").into();
        let block = key
            .encrypt_event_block(b"compressed", "run-1", 1, 2, 128, &digest)
            .unwrap();
        assert_eq!(
            key.decrypt_event_block(&block, "run-1", 1, 2, 128, &digest)
                .unwrap(),
            b"compressed"
        );
        assert!(
            key.decrypt_event_block(&block, "run-1", 2, 2, 128, &digest)
                .is_err()
        );
    }

    #[test]
    fn per_run_keys_are_deterministic_isolated_and_context_bounded() {
        let master = EncryptionKey::new([9; 32]);
        let first = master.derive_run_key("run-first").unwrap();
        let first_again = master.derive_run_key("run-first").unwrap();
        let second = master.derive_run_key("run-second").unwrap();
        assert_eq!(first.key_id(), first_again.key_id());
        assert_ne!(first.key_id(), master.key_id());
        assert_ne!(first.key_id(), second.key_id());

        let blob = first.encrypt_blob(b"same-content", "same-hash").unwrap();
        assert_eq!(
            first_again.decrypt_blob(&blob, "same-hash").unwrap(),
            b"same-content"
        );
        assert!(master.decrypt_blob(&blob, "same-hash").is_err());
        assert!(second.decrypt_blob(&blob, "same-hash").is_err());
        assert!(master.derive_run_key("").is_err());
        assert!(master.derive_run_key("run\nforged").is_err());
    }

    #[test]
    fn wrapped_blob_keys_and_retention_state_are_domain_separated() {
        let run_key = EncryptionKey::new([31; 32]);
        let (body_key, wrapped) = run_key.generate_wrapped_data_key("body").unwrap();
        let unwrapped = run_key.unwrap_data_key(&wrapped, "body").unwrap();
        assert_eq!(body_key.key_id(), unwrapped.key_id());
        assert!(run_key.unwrap_data_key(&wrapped, "pcap").is_err());
        assert!(
            EncryptionKey::new([32; 32])
                .unwrap_data_key(&wrapped, "body")
                .is_err()
        );

        let state = run_key
            .encrypt_retention_state(br#"{"class":"body"}"#)
            .unwrap();
        assert_eq!(
            run_key.decrypt_retention_state(&state).unwrap(),
            br#"{"class":"body"}"#
        );
        assert!(run_key.unwrap_data_key(&state, "body").is_err());
    }

    #[test]
    fn event_context_is_authenticated_and_legacy_records_remain_readable() {
        let key = EncryptionKey::new([17; 32]);
        let plaintext = br#"{"run_id":"run-1","sequence":7}"#;
        let encoded = key.encrypt_event_record(plaintext, "run-1", 7).unwrap();
        let mut wrapper: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        wrapper["run_id"] = serde_json::json!("run-2");
        assert!(
            key.decrypt_event(&serde_json::to_vec(&wrapper).unwrap())
                .is_err()
        );

        let encoded = key.encrypt_event_record(plaintext, "run-1", 7).unwrap();
        let mut wrapper: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        wrapper["sequence"] = serde_json::json!(8);
        assert!(
            key.decrypt_event(&serde_json::to_vec(&wrapper).unwrap())
                .is_err()
        );

        let legacy = key.encrypt_legacy_event(b"legacy").unwrap();
        assert_eq!(key.decrypt_event(&legacy).unwrap(), b"legacy");
    }

    #[test]
    fn generated_key_file_is_private_and_never_overwritten() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("key");
        let generated = EncryptionKey::generate_file(&path).unwrap();
        let loaded = EncryptionKey::from_file(&path).unwrap();
        assert_eq!(generated.key_id(), loaded.key_id());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(EncryptionKey::generate_file(&path).is_err());
    }

    #[test]
    fn exact_raw_key_keeps_a_trailing_newline_byte() {
        let mut raw = [19_u8; 32];
        raw[31] = b'\n';
        assert_eq!(parse_key(&raw).unwrap(), raw);

        let mut with_text_newline = raw.to_vec();
        with_text_newline.push(b'\n');
        assert_eq!(parse_key(&with_text_newline).unwrap(), raw);
    }

    #[test]
    fn manifest_authentication_is_domain_separated_and_detects_changes() {
        let key = EncryptionKey::new([23; 32]);
        let canonical = br#"{"run_id":"run-1","status":"finished"}"#;
        let (nonce, tag) = key.authenticate_manifest(canonical).unwrap();
        key.verify_manifest_authentication(canonical, &nonce, &tag)
            .unwrap();
        assert!(
            key.verify_manifest_authentication(
                br#"{"run_id":"run-1","status":"running"}"#,
                &nonce,
                &tag,
            )
            .is_err()
        );
        assert!(
            EncryptionKey::new([24; 32])
                .verify_manifest_authentication(canonical, &nonce, &tag)
                .is_err()
        );
    }

    #[test]
    fn key_loader_rejects_symlinks_and_public_permissions() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("key");
        EncryptionKey::generate_file(&path).unwrap();
        let link = temporary.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(EncryptionKey::from_file(&link).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            EncryptionKey::from_file(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
