//! Bounded, resumable upload of finalized local recordings.
//!
//! The durable spool stores only immutable batch boundaries and digests. Batch
//! bodies are regenerated from the authenticated local evidence immediately
//! before transmission, so encrypted runs never acquire a plaintext spool.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use nix::fcntl::{Flock, FlockArg};
use reqwest::redirect::Policy as RedirectPolicy;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    RECORDER_VERSION,
    blob_keys::read_blob_reference,
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    manifest::{self, Manifest},
    model::PayloadRef,
    policy::BodyCaptureMode,
    secure_fs::{open_regular_create, open_regular_read, read_regular_limited},
    storage::{RunEventReader, recover_events_with_key},
};

const STATE_SCHEMA_VERSION: u32 = 1;
const MAX_RECORDING_SEGMENTS: u32 = 10_000;
const MAX_PLATFORM_SEQUENCE: u64 = 9_223_372_036_854_775_807;
const MAX_UPLOAD_TARGETS: usize = 128;
const MAX_TOTAL_UPLOAD_STATES: usize = 100_000;
const DEFAULT_BATCH_EVENTS: usize = 2_000;
const DEFAULT_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_WIRE_BATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BATCH_PLANS: usize = 100_000;
const MAX_BLOB_PLANS: usize = 250_000;
const MAX_TOKEN_BYTES: usize = 2_048;
const CONTENT_TYPE_BATCH: &str = "application/vnd.iorec.batch+zstd";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const PCAP_MEDIA_TYPE: &str = "application/vnd.tcpdump.pcap";
const TLS_SECRETS_MEDIA_TYPE: &str = "application/x-nss-key-log";

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub api: Url,
    pub token_file: PathBuf,
    pub encryption_key: Option<EncryptionKey>,
    pub allow_http: bool,
    pub retry_for: Duration,
    /// Optional work budget for incremental/cron operation. The recording is
    /// left open when more fixed batches remain.
    pub max_batches: Option<usize>,
    /// Stable daemon identity to associate with this upload. Standalone CLI
    /// uploads leave this unset and resume the identity already in the spool.
    pub collector_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadReport {
    pub run_id: String,
    pub recording_id: String,
    pub api_origin: String,
    pub events: u64,
    pub batches: usize,
    pub blobs_considered: usize,
    pub acked_seq: u64,
    pub sealed: bool,
    pub resumed_from_seq: u64,
    pub collector_id: Uuid,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackfillReport {
    pub run_id: String,
    pub recording_id: String,
    pub requested_first_seq: u64,
    pub requested_last_seq: u64,
    pub resent_first_seq: u64,
    pub resent_last_seq: u64,
    pub batches_resent: usize,
    pub blobs_repaired: usize,
    pub collector_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadState {
    schema_version: u32,
    api_origin: String,
    run_id: String,
    recording_id: String,
    #[serde(default)]
    segment_no: u32,
    #[serde(default = "first_sequence")]
    first_seq: u64,
    batch_max_events: usize,
    batch_max_bytes: usize,
    acked_seq: u64,
    sealed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collector_id: Option<Uuid>,
    #[serde(default)]
    config_version: i64,
    batches: Vec<BatchPlan>,
    #[serde(default = "utc_now")]
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchPlan {
    first_seq: u64,
    last_seq: u64,
    event_count: usize,
    byte_length: usize,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_sha256: Option<String>,
    blobs: Vec<BlobPlan>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BlobPlan {
    sha256: String,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchHeader<'a> {
    batch_id: String,
    recording_id: &'a str,
    schema_version: u32,
    first_seq: u64,
    last_seq: u64,
    event_count: usize,
    byte_length: usize,
    sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_sha256: Option<&'a str>,
    encoding: &'static str,
    blobs: Vec<WireBlobRef<'a>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct WireBlobRef<'a> {
    sha256: &'a str,
    size: u64,
}

#[derive(Debug, Serialize)]
struct CreateRecording<'a> {
    recording_id: &'a str,
    capture_run_id: &'a str,
    segment_no: u32,
    sequence_base: u64,
    schema_version: u32,
    run: RunMetadata<'a>,
}

#[derive(Debug, Serialize)]
struct RunMetadata<'a> {
    command: String,
    cwd: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_version: Option<&'a str>,
    started_at: DateTime<Utc>,
    metadata: RunUploadMetadata<'a>,
}

#[derive(Debug, Serialize)]
struct RunUploadMetadata<'a> {
    recorder_version: &'a str,
    runtime: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct SealRecording<'a> {
    final_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<&'a Manifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
    incomplete: bool,
    run_final: bool,
}

const fn first_sequence() -> u64 {
    1
}

fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Deserialize)]
struct RemoteRecording {
    state: String,
    segment_no: u32,
    sequence_base: u64,
    durable_seq: u64,
    #[serde(default)]
    final_seq: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct BatchAck {
    recording_id: String,
    durable_seq: u64,
    state: String,
    #[serde(default)]
    missing_blobs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RegisterCollector {
    #[serde(skip_serializing_if = "Option::is_none")]
    collector_id: Option<Uuid>,
    name: &'static str,
    version: String,
    hostname: &'static str,
    os: String,
    capabilities: CollectorCapabilities,
}

#[derive(Debug, Serialize)]
struct CollectorCapabilities {
    schema: &'static str,
    transport: serde_json::Value,
    sources: serde_json::Value,
    runtime_inventory: serde_json::Value,
    limits: serde_json::Value,
    privilege: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    collector_id: Uuid,
    session_token: String,
    expires_at: DateTime<Utc>,
    config_version: i64,
    config: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Heartbeat<'a> {
    status: &'static str,
    active_runs: u32,
    spool_bytes_used: u64,
    acked_lag_seconds: f64,
    last_error: Option<&'a str>,
    config_version: i64,
    effective_config: serde_json::Value,
    rejected: serde_json::Value,
}

struct PlatformClient {
    origin: Url,
    authorization: HeaderValue,
    http: reqwest::Client,
    retry_for: Duration,
}

struct StateLock {
    _file: Flock<File>,
}

/// Uploads one finalized run and seals its current recording segment.
///
/// This operation never mutates raw evidence. It creates a private upload
/// state file under the run directory, reconciles progress from the server's
/// `durable_seq`, and advances local `acked_seq` only after a server ACK.
pub async fn upload_run(run_dir: &Path, options: &UploadOptions) -> Result<UploadReport> {
    let run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("resolve run directory {}", run_dir.display()))?;
    validate_api(&options.api, options.allow_http)?;
    let api_origin = canonical_origin(&options.api);

    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(options.encryption_key.as_ref())?;
    let effective_key =
        source_manifest.effective_encryption_key(options.encryption_key.as_ref())?;
    let inspection = inspect_run_with_key(&run_dir, true, options.encryption_key.as_ref())?;
    anyhow::ensure!(
        inspection.manifest.status != "running",
        "refusing to upload a run that is still being recorded"
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
    anyhow::ensure!(inspection.log.valid_events > 0, "run contains no events");
    anyhow::ensure!(
        inspection.log.valid_events <= MAX_PLATFORM_SEQUENCE,
        "run event sequence exceeds the platform protocol limit"
    );

    let spool = prepare_spool(&run_dir)?;
    let _lock = lock_state(&spool)?;
    let (_segments, mut cursor) = select_segment_cursor(
        &spool,
        &api_origin,
        &inspection.manifest.run_id,
        inspection.log.valid_events,
    )?;
    let mut state_path = cursor.path.clone();
    let mut state = load_or_create_state(
        &state_path,
        &inspection.manifest.run_id,
        &cursor.recording_id,
        &api_origin,
        cursor.segment_no,
        cursor.first_seq,
        inspection.log.valid_events,
    )?;
    validate_state_prefix(
        &state,
        &inspection.manifest.run_id,
        &cursor.recording_id,
        &api_origin,
        inspection.log.valid_events,
    )?;
    if let Some(collector_id) = options.collector_id {
        state.collector_id = Some(collector_id);
    }

    let token = read_token(&options.token_file)?;
    let mut client = PlatformClient::new(options.api.clone(), &token, options.retry_for)?;
    drop(token);

    let registration = client
        .register(&inspection.manifest, state.collector_id)
        .await?;
    let rejected_config = config_rejections(&registration.config, &inspection.manifest)?;
    state.collector_id = Some(registration.collector_id);
    state.config_version = registration.config_version;
    state.updated_at = Utc::now();
    write_state(&state_path, &state)?;

    loop {
        client
            .create_recording(
                &inspection.manifest,
                &cursor.recording_id,
                cursor.segment_no,
                cursor.first_seq.saturating_sub(1),
            )
            .await?;
        let remote = client.get_recording(&cursor.recording_id).await?;
        reconcile_remote(&mut state, &remote)?;
        write_state(&state_path, &state)?;
        let planned_seq = planned_sequence(&state);
        if !state.sealed || planned_seq == inspection.log.valid_events {
            break;
        }
        anyhow::ensure!(
            planned_seq < inspection.log.valid_events,
            "sealed upload segment exceeds final local evidence"
        );
        let next_segment = state
            .segment_no
            .checked_add(1)
            .context("upload segment number overflow")?;
        anyhow::ensure!(
            next_segment < MAX_RECORDING_SEGMENTS,
            "upload recording segment limit exceeded"
        );
        let next_first = planned_seq
            .checked_add(1)
            .context("upload sequence overflow")?;
        cursor = SegmentCursor {
            path: segment_state_path(&spool, &api_origin, next_segment),
            recording_id: recording_id_for_segment(&inspection.manifest.run_id, next_segment),
            segment_no: next_segment,
            first_seq: next_first,
        };
        state_path.clone_from(&cursor.path);
        state = load_or_create_state(
            &state_path,
            &inspection.manifest.run_id,
            &cursor.recording_id,
            &api_origin,
            cursor.segment_no,
            cursor.first_seq,
            inspection.log.valid_events,
        )?;
        state.collector_id = Some(registration.collector_id);
        state.config_version = registration.config_version;
        state.updated_at = Utc::now();
        write_state(&state_path, &state)?;
    }
    if state.sealed {
        anyhow::ensure!(
            planned_sequence(&state) == inspection.log.valid_events,
            "sealed upload segment does not cover final local evidence"
        );
    } else {
        extend_state_to(
            &mut state,
            &run_dir,
            effective_key.as_ref(),
            inspection.log.valid_events,
        )?;
    }
    validate_state(
        &state,
        &inspection.manifest.run_id,
        &cursor.recording_id,
        &api_origin,
        inspection.log.valid_events,
    )?;
    write_state(&state_path, &state)?;
    let resumed_from_seq = state.acked_seq;

    let mut reader = RunEventReader::open(
        &run_dir.join("events.jsonl"),
        &inspection.manifest.run_id,
        effective_key.as_ref(),
    )?;
    let mut uploaded_blobs = BTreeSet::<String>::new();
    let mut batches_uploaded = 0_usize;
    let mut last_heartbeat = Instant::now();

    for batch in state.batches.clone() {
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            client
                .heartbeat(
                    registration.collector_id,
                    &state,
                    &inspection.manifest,
                    inspection.log.valid_events,
                    &rejected_config,
                )
                .await?;
            last_heartbeat = Instant::now();
        }
        let raw = read_batch(&mut reader, &batch)?;
        if batch.last_seq <= state.acked_seq {
            continue;
        }
        for blob in &batch.blobs {
            if uploaded_blobs.insert(blob.sha256.clone()) {
                client
                    .ensure_blob(&run_dir, blob, effective_key.as_ref(), false)
                    .await?;
            }
        }
        let body = encode_batch_body(&state.recording_id, &batch, &raw)?;
        let ack = client
            .upload_batch(&state.recording_id, &batch, body)
            .await?;
        validate_ack(&state, &batch, &ack)?;
        state.acked_seq = ack.durable_seq;
        state.sealed = ack.state == "sealed" && state.acked_seq == inspection.log.valid_events;
        state.updated_at = Utc::now();
        write_state(&state_path, &state)?;
        batches_uploaded = batches_uploaded.saturating_add(1);
        if options
            .max_batches
            .is_some_and(|maximum| batches_uploaded >= maximum)
        {
            break;
        }
    }
    let final_seq = inspection.log.valid_events;
    if state.acked_seq < final_seq {
        client
            .heartbeat(
                registration.collector_id,
                &state,
                &inspection.manifest,
                final_seq,
                &rejected_config,
            )
            .await?;
        return Ok(UploadReport {
            run_id: state.run_id,
            recording_id: state.recording_id,
            api_origin: state.api_origin,
            events: final_seq,
            batches: state.batches.len(),
            blobs_considered: uploaded_blobs.len(),
            acked_seq: state.acked_seq,
            sealed: false,
            resumed_from_seq,
            collector_id: registration.collector_id,
        });
    }
    anyhow::ensure!(
        reader.next().is_none(),
        "upload batch plan does not consume the full event log"
    );
    anyhow::ensure!(
        state.acked_seq == final_seq,
        "platform acknowledged sequence {}, expected {}",
        state.acked_seq,
        final_seq
    );

    client
        .seal_recording(&state.recording_id, final_seq, &inspection.manifest, true)
        .await?;
    let remote = client.get_recording(&state.recording_id).await?;
    anyhow::ensure!(
        remote.state == "sealed" && remote.durable_seq == final_seq,
        "platform did not confirm a fully durable sealed recording"
    );
    anyhow::ensure!(
        remote.final_seq == Some(final_seq),
        "platform sealed recording has an unexpected final sequence"
    );
    state.acked_seq = remote.durable_seq;
    state.sealed = true;
    state.updated_at = Utc::now();
    write_state(&state_path, &state)?;
    client
        .heartbeat(
            registration.collector_id,
            &state,
            &inspection.manifest,
            final_seq,
            &rejected_config,
        )
        .await?;

    Ok(UploadReport {
        run_id: state.run_id,
        recording_id: state.recording_id,
        api_origin: state.api_origin,
        events: final_seq,
        batches: state.batches.len(),
        blobs_considered: uploaded_blobs.len(),
        acked_seq: state.acked_seq,
        sealed: state.sealed,
        resumed_from_seq,
        collector_id: registration.collector_id,
    })
}

/// Uploads an exact durable prefix of a run that is still active without
/// sealing its platform recording. The supplied boundary must come from the
/// active writer's [`crate::storage::RunStore::durable_boundary`] (normally via
/// [`crate::collector::request_flush_boundary`]). Each flush closes an
/// immutable local batch at that boundary; later calls only append batches.
pub async fn flush_active_run(
    run_dir: &Path,
    durable_boundary: u64,
    options: &UploadOptions,
) -> Result<UploadReport> {
    upload_active_segment(run_dir, durable_boundary, options, false, None).await
}

pub(crate) async fn flush_active_run_for(
    run_dir: &Path,
    durable_boundary: u64,
    expected_recording_id: &str,
    options: &UploadOptions,
) -> Result<UploadReport> {
    upload_active_segment(
        run_dir,
        durable_boundary,
        options,
        false,
        Some(expected_recording_id),
    )
    .await
}

/// Uploads and seals an exact durable prefix while the local writer remains
/// active. A later flush starts a new immutable recording segment at the next
/// global event sequence.
pub async fn seal_active_run(
    run_dir: &Path,
    durable_boundary: u64,
    options: &UploadOptions,
) -> Result<UploadReport> {
    upload_active_segment(run_dir, durable_boundary, options, true, None).await
}

pub(crate) async fn seal_active_run_for(
    run_dir: &Path,
    durable_boundary: u64,
    expected_recording_id: &str,
    options: &UploadOptions,
) -> Result<UploadReport> {
    upload_active_segment(
        run_dir,
        durable_boundary,
        options,
        true,
        Some(expected_recording_id),
    )
    .await
}

async fn upload_active_segment(
    run_dir: &Path,
    durable_boundary: u64,
    options: &UploadOptions,
    seal_segment: bool,
    expected_recording_id: Option<&str>,
) -> Result<UploadReport> {
    anyhow::ensure!(
        durable_boundary > 0,
        "active run has no durable events to flush"
    );
    anyhow::ensure!(
        durable_boundary <= MAX_PLATFORM_SEQUENCE,
        "active durable boundary exceeds the platform protocol limit"
    );
    let run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("resolve run directory {}", run_dir.display()))?;
    validate_api(&options.api, options.allow_http)?;
    let api_origin = canonical_origin(&options.api);
    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(options.encryption_key.as_ref())?;
    anyhow::ensure!(
        source_manifest.status == "running" || expected_recording_id.is_some(),
        "active flush requires a running run or a persisted collector request boundary"
    );
    let effective_key =
        source_manifest.effective_encryption_key(options.encryption_key.as_ref())?;
    let spool = prepare_spool(&run_dir)?;
    let _lock = lock_state(&spool)?;
    let (_segments, mut cursor) = if let Some(expected) = expected_recording_id {
        let recovery =
            recover_events_with_key(&run_dir.join("events.jsonl"), false, effective_key.as_ref())?;
        select_expected_segment_cursor(
            &spool,
            &api_origin,
            &source_manifest.run_id,
            expected,
            durable_boundary,
            recovery.valid_events,
        )?
    } else {
        select_segment_cursor(
            &spool,
            &api_origin,
            &source_manifest.run_id,
            durable_boundary,
        )?
    };
    let mut state_path = cursor.path.clone();
    let mut state = load_or_create_state(
        &state_path,
        &source_manifest.run_id,
        &cursor.recording_id,
        &api_origin,
        cursor.segment_no,
        cursor.first_seq,
        durable_boundary,
    )?;
    if let Some(collector_id) = options.collector_id {
        state.collector_id = Some(collector_id);
    }

    let token = read_token(&options.token_file)?;
    let mut client = PlatformClient::new(options.api.clone(), &token, options.retry_for)?;
    drop(token);
    let registration = client
        .register(&source_manifest, state.collector_id)
        .await?;
    let rejected_config = config_rejections(&registration.config, &source_manifest)?;
    state.collector_id = Some(registration.collector_id);
    state.config_version = registration.config_version;
    state.updated_at = Utc::now();
    write_state(&state_path, &state)?;

    loop {
        client
            .create_recording(
                &source_manifest,
                &cursor.recording_id,
                cursor.segment_no,
                cursor.first_seq.saturating_sub(1),
            )
            .await?;
        let remote = client.get_recording(&cursor.recording_id).await?;
        reconcile_remote(&mut state, &remote)?;
        write_state(&state_path, &state)?;
        let planned_seq = planned_sequence(&state);
        if !state.sealed || planned_seq == durable_boundary {
            break;
        }
        anyhow::ensure!(
            planned_seq < durable_boundary,
            "sealed upload segment exceeds the active durable boundary"
        );
        let next_segment = state
            .segment_no
            .checked_add(1)
            .context("upload segment number overflow")?;
        anyhow::ensure!(
            next_segment < MAX_RECORDING_SEGMENTS,
            "upload recording segment limit exceeded"
        );
        let next_first = planned_seq
            .checked_add(1)
            .context("upload sequence overflow")?;
        cursor = SegmentCursor {
            path: segment_state_path(&spool, &api_origin, next_segment),
            recording_id: recording_id_for_segment(&source_manifest.run_id, next_segment),
            segment_no: next_segment,
            first_seq: next_first,
        };
        state_path.clone_from(&cursor.path);
        state = load_or_create_state(
            &state_path,
            &source_manifest.run_id,
            &cursor.recording_id,
            &api_origin,
            cursor.segment_no,
            cursor.first_seq,
            durable_boundary,
        )?;
        state.collector_id = Some(registration.collector_id);
        state.config_version = registration.config_version;
        state.updated_at = Utc::now();
        write_state(&state_path, &state)?;
    }
    if state.sealed {
        anyhow::ensure!(
            planned_sequence(&state) == durable_boundary,
            "sealed upload segment does not match the active durable boundary"
        );
    } else {
        extend_state_to(
            &mut state,
            &run_dir,
            effective_key.as_ref(),
            durable_boundary,
        )?;
    }
    validate_state(
        &state,
        &source_manifest.run_id,
        &cursor.recording_id,
        &api_origin,
        durable_boundary,
    )?;
    write_state(&state_path, &state)?;
    let resumed_from_seq = state.acked_seq;

    let mut reader = RunEventReader::open(
        &run_dir.join("events.jsonl"),
        &source_manifest.run_id,
        effective_key.as_ref(),
    )?;
    let mut uploaded_blobs = BTreeSet::<String>::new();
    let mut batches_uploaded = 0_usize;
    let mut last_heartbeat = Instant::now();
    for batch in state.batches.clone() {
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            client
                .heartbeat(
                    registration.collector_id,
                    &state,
                    &source_manifest,
                    durable_boundary,
                    &rejected_config,
                )
                .await?;
            last_heartbeat = Instant::now();
        }
        let raw = read_batch(&mut reader, &batch)?;
        if batch.last_seq <= state.acked_seq {
            continue;
        }
        for blob in &batch.blobs {
            if uploaded_blobs.insert(blob.sha256.clone()) {
                client
                    .ensure_blob(&run_dir, blob, effective_key.as_ref(), false)
                    .await?;
            }
        }
        let body = encode_batch_body(&state.recording_id, &batch, &raw)?;
        let ack = client
            .upload_batch(&state.recording_id, &batch, body)
            .await?;
        validate_ack(&state, &batch, &ack)?;
        state.acked_seq = ack.durable_seq;
        state.updated_at = Utc::now();
        write_state(&state_path, &state)?;
        batches_uploaded = batches_uploaded.saturating_add(1);
        if options
            .max_batches
            .is_some_and(|maximum| batches_uploaded >= maximum)
        {
            break;
        }
    }
    anyhow::ensure!(
        state.acked_seq <= durable_boundary,
        "platform durable sequence exceeds the active flush boundary"
    );
    if seal_segment && state.acked_seq == durable_boundary {
        client
            .seal_recording(
                &state.recording_id,
                durable_boundary,
                &source_manifest,
                false,
            )
            .await?;
        let remote = client.get_recording(&state.recording_id).await?;
        anyhow::ensure!(
            remote.state == "sealed"
                && remote.durable_seq == durable_boundary
                && remote.final_seq == Some(durable_boundary),
            "platform did not confirm the active recording segment seal"
        );
        state.acked_seq = remote.durable_seq;
        state.sealed = true;
        state.updated_at = Utc::now();
        write_state(&state_path, &state)?;
    }
    client
        .heartbeat(
            registration.collector_id,
            &state,
            &source_manifest,
            durable_boundary,
            &rejected_config,
        )
        .await?;
    Ok(UploadReport {
        run_id: state.run_id,
        recording_id: state.recording_id,
        api_origin: state.api_origin,
        events: durable_boundary,
        batches: state.batches.len(),
        blobs_considered: uploaded_blobs.len(),
        acked_seq: state.acked_seq,
        sealed: state.sealed,
        resumed_from_seq,
        collector_id: registration.collector_id,
    })
}

/// Re-sends every immutable local batch intersecting a requested sequence
/// range. A partial-range request expands to fixed batch boundaries; this
/// preserves idempotency and can repair a missing object even after sealing.
pub async fn backfill_run(
    run_dir: &Path,
    expected_recording_id: &str,
    first_seq: u64,
    last_seq: u64,
    options: &UploadOptions,
) -> Result<BackfillReport> {
    anyhow::ensure!(
        first_seq > 0 && last_seq >= first_seq && last_seq <= MAX_PLATFORM_SEQUENCE,
        "backfill sequence range is invalid"
    );
    let run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("resolve run directory {}", run_dir.display()))?;
    validate_api(&options.api, options.allow_http)?;
    let api_origin = canonical_origin(&options.api);
    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(options.encryption_key.as_ref())?;
    let effective_key =
        source_manifest.effective_encryption_key(options.encryption_key.as_ref())?;
    let available_seq = if source_manifest.status == "running" {
        u64::MAX
    } else {
        let inspection = inspect_run_with_key(&run_dir, true, options.encryption_key.as_ref())?;
        anyhow::ensure!(
            inspection.log.discarded_tail_bytes == 0
                && inspection.missing_blobs.is_empty()
                && inspection.corrupt_blobs.is_empty(),
            "backfill requires complete authenticated local evidence"
        );
        anyhow::ensure!(
            last_seq <= inspection.log.valid_events,
            "backfill range exceeds local evidence"
        );
        inspection.log.valid_events
    };

    let spool = prepare_spool(&run_dir)?;
    let _lock = lock_state(&spool)?;
    let segments = load_segment_chain(&spool, &api_origin, &source_manifest.run_id, available_seq)?;
    let selected_segment = segments
        .into_iter()
        .find(|item| item.state.recording_id == expected_recording_id)
        .context("backfill recording ID has no authenticated local upload state")?;
    let segment_planned_seq = selected_segment.planned_seq;
    let state_path = selected_segment.path;
    let mut state = selected_segment.state;
    anyhow::ensure!(
        first_seq >= state.first_seq && last_seq <= segment_planned_seq,
        "backfill range exceeds the selected recording segment"
    );
    if let Some(collector_id) = options.collector_id {
        state.collector_id = Some(collector_id);
    }

    let token = read_token(&options.token_file)?;
    let mut client = PlatformClient::new(options.api.clone(), &token, options.retry_for)?;
    drop(token);
    let registration = client
        .register(&source_manifest, state.collector_id)
        .await?;
    let rejected_config = config_rejections(&registration.config, &source_manifest)?;
    state.collector_id = Some(registration.collector_id);
    state.config_version = registration.config_version;
    client
        .create_recording(
            &source_manifest,
            &state.recording_id,
            state.segment_no,
            state.first_seq.saturating_sub(1),
        )
        .await?;
    let remote = client.get_recording(&state.recording_id).await?;
    reconcile_remote(&mut state, &remote)?;
    write_state(&state_path, &state)?;

    let selected: Vec<BatchPlan> = state
        .batches
        .iter()
        .filter(|batch| batch.first_seq <= last_seq && batch.last_seq >= first_seq)
        .cloned()
        .collect();
    anyhow::ensure!(
        !selected.is_empty(),
        "backfill range selects no local batch"
    );
    let resent_first_seq = selected.first().map_or(0, |batch| batch.first_seq);
    let resent_last_seq = selected.last().map_or(0, |batch| batch.last_seq);
    anyhow::ensure!(
        resent_first_seq <= first_seq && resent_last_seq >= last_seq,
        "backfill range is not covered by fixed local batches"
    );
    let selected_ranges: BTreeSet<(u64, u64)> = selected
        .iter()
        .map(|batch| (batch.first_seq, batch.last_seq))
        .collect();
    let mut reader = RunEventReader::open(
        &run_dir.join("events.jsonl"),
        &source_manifest.run_id,
        effective_key.as_ref(),
    )?;
    let mut repaired_blobs = BTreeSet::new();
    let mut batches_resent = 0_usize;
    for batch in &state.batches {
        let raw = read_batch(&mut reader, batch)?;
        if !selected_ranges.contains(&(batch.first_seq, batch.last_seq)) {
            continue;
        }
        for blob in &batch.blobs {
            if repaired_blobs.insert(blob.sha256.clone()) {
                client
                    .ensure_blob(&run_dir, blob, effective_key.as_ref(), true)
                    .await?;
            }
        }
        let body = encode_batch_body(&state.recording_id, batch, &raw)?;
        let ack = client
            .upload_batch(&state.recording_id, batch, body)
            .await?;
        validate_ack(&state, batch, &ack)?;
        batches_resent = batches_resent.saturating_add(1);
    }
    anyhow::ensure!(
        batches_resent == selected.len(),
        "backfill did not resend every selected batch"
    );
    client
        .heartbeat(
            registration.collector_id,
            &state,
            &source_manifest,
            segment_planned_seq,
            &rejected_config,
        )
        .await?;
    Ok(BackfillReport {
        run_id: source_manifest.run_id,
        recording_id: expected_recording_id.to_owned(),
        requested_first_seq: first_seq,
        requested_last_seq: last_seq,
        resent_first_seq,
        resent_last_seq,
        batches_resent,
        blobs_repaired: repaired_blobs.len(),
        collector_id: registration.collector_id,
    })
}

/// Enforces the uploader side of retention safety.
///
/// A run with no upload spool remains a local-only recording and is eligible
/// for the caller's normal retention policy. Once an upload spool exists,
/// every configured target must have acknowledged and sealed the full event
/// range before local evidence may be pruned.
pub fn verify_retention_gate(run_dir: &Path, run_id: &str, final_seq: u64) -> Result<()> {
    let spool = run_dir.join(".upload");
    let metadata = match fs::symlink_metadata(&spool) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "upload spool is not a real directory"
    );
    let origins = list_upload_origins(&spool, run_id)?;
    anyhow::ensure!(
        !origins.is_empty(),
        "upload spool exists without a durable target state"
    );
    for origin in origins {
        let states = load_segment_chain(&spool, &origin, run_id, final_seq)?;
        anyhow::ensure!(
            segment_chain_complete(&states, final_seq),
            "upload target has not acknowledged and sealed the full run"
        );
    }
    Ok(())
}

/// Full-upload gate used by automatic age-based retention. An explicit,
/// authenticated platform deletion intentionally bypasses this availability
/// safeguard so that a partially uploaded local run can still be erased.
pub fn verify_uploaded_retention_gate(run_dir: &Path, run_id: &str, final_seq: u64) -> Result<()> {
    let spool = run_dir.join(".upload");
    let metadata = fs::symlink_metadata(&spool)
        .context("remote deletion requires a fully acknowledged upload target")?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "upload spool is not a real directory"
    );
    verify_retention_gate(run_dir, run_id, final_seq)
}

pub(crate) fn validate_api(api: &Url, allow_http: bool) -> Result<()> {
    anyhow::ensure!(
        api.host_str().is_some(),
        "platform API URL must have a host"
    );
    anyhow::ensure!(
        api.username().is_empty() && api.password().is_none(),
        "platform API URL must not contain user information"
    );
    anyhow::ensure!(
        api.query().is_none() && api.fragment().is_none(),
        "platform API URL must not contain a query or fragment"
    );
    anyhow::ensure!(
        api.path().is_empty() || api.path() == "/",
        "platform API URL must not contain a path"
    );
    match api.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => anyhow::bail!("plain HTTP requires the explicit --allow-http option"),
        _ => anyhow::bail!("platform API URL must use https"),
    }
}

pub(crate) fn canonical_origin(api: &Url) -> String {
    let mut origin = api.clone();
    origin.set_path("/");
    origin.to_string()
}

#[must_use]
pub fn recording_id(run_id: &str) -> String {
    recording_id_for_segment(run_id, 0)
}

#[must_use]
pub fn recording_id_for_segment(run_id: &str, segment_no: u32) -> String {
    let direct = format!("{run_id}#{segment_no:04}");
    if direct.len() <= 240 {
        direct
    } else {
        format!(
            "run-{}#{segment_no:04}",
            hex::encode(Sha256::digest(run_id.as_bytes())),
        )
    }
}

/// Returns whether the current active recording segment reached either its
/// logical evidence-size or wall-clock age limit at an exact durable writer
/// boundary. This only inspects authenticated local evidence and never creates
/// upload state.
pub fn active_segment_roll_due(
    run_dir: &Path,
    durable_boundary: u64,
    api: &Url,
    allow_http: bool,
    encryption_key: Option<&EncryptionKey>,
    max_logical_bytes: u64,
    max_age: Duration,
) -> Result<bool> {
    anyhow::ensure!(
        max_logical_bytes > 0,
        "recording segment byte limit is zero"
    );
    anyhow::ensure!(!max_age.is_zero(), "recording segment age limit is zero");
    if durable_boundary == 0 {
        return Ok(false);
    }
    anyhow::ensure!(
        durable_boundary <= MAX_PLATFORM_SEQUENCE,
        "active durable boundary exceeds the platform protocol limit"
    );
    validate_api(api, allow_http)?;
    let run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("resolve run directory {}", run_dir.display()))?;
    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(encryption_key)?;
    anyhow::ensure!(
        source_manifest.status == "running",
        "recording segment roll check requires an active run"
    );
    let effective_key = source_manifest.effective_encryption_key(encryption_key)?;
    let api_origin = canonical_origin(api);
    let spool = run_dir.join(".upload");
    let states = match fs::symlink_metadata(&spool) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
                "upload spool is not a real directory"
            );
            load_segment_chain(
                &spool,
                &api_origin,
                &source_manifest.run_id,
                durable_boundary,
            )?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    if states
        .last()
        .is_some_and(|last| last.state.sealed && last.planned_seq == durable_boundary)
    {
        return Ok(false);
    }
    let (first_seq, planned_seq, opened_at, mut plans) = if let Some(last) = states.last() {
        if last.state.sealed {
            (
                last.planned_seq
                    .checked_add(1)
                    .context("upload sequence overflow")?,
                last.planned_seq,
                last.state.updated_at,
                Vec::new(),
            )
        } else {
            (
                last.state.first_seq,
                last.planned_seq,
                last.state.created_at,
                last.state.batches.clone(),
            )
        }
    } else {
        (1, 0, source_manifest.started_at, Vec::new())
    };
    anyhow::ensure!(
        first_seq <= durable_boundary && planned_seq <= durable_boundary,
        "active recording segment boundary precedes its first event"
    );
    if planned_seq < durable_boundary {
        let previous = plans.last().map(|batch| batch.sha256.as_str());
        let additional = build_batch_plans_range(
            &run_dir,
            &source_manifest.run_id,
            effective_key.as_ref(),
            planned_seq
                .checked_add(1)
                .context("upload sequence overflow")?,
            durable_boundary,
            previous,
        )?;
        plans.extend(additional);
    }
    anyhow::ensure!(
        plans
            .first()
            .is_some_and(|batch| batch.first_seq == first_seq)
            && plans
                .last()
                .is_some_and(|batch| batch.last_seq == durable_boundary),
        "active recording segment plan does not cover its durable range"
    );
    let logical_bytes = segment_logical_bytes(&plans)?;
    let age = Utc::now()
        .signed_duration_since(opened_at)
        .to_std()
        .unwrap_or_default();
    Ok(logical_bytes >= max_logical_bytes || age >= max_age)
}

pub(crate) fn active_recording_id_at_boundary(
    run_dir: &Path,
    durable_boundary: u64,
    api: &Url,
    allow_http: bool,
    encryption_key: Option<&EncryptionKey>,
) -> Result<String> {
    anyhow::ensure!(durable_boundary > 0, "active durable boundary is empty");
    anyhow::ensure!(
        durable_boundary <= MAX_PLATFORM_SEQUENCE,
        "active durable boundary exceeds the platform protocol limit"
    );
    validate_api(api, allow_http)?;
    let run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("resolve run directory {}", run_dir.display()))?;
    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(encryption_key)?;
    let api_origin = canonical_origin(api);
    let spool = run_dir.join(".upload");
    if !spool.try_exists()? {
        return Ok(recording_id_for_segment(&source_manifest.run_id, 0));
    }
    let metadata = fs::symlink_metadata(&spool)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "upload spool is not a real directory"
    );
    let (_, cursor) = select_segment_cursor(
        &spool,
        &api_origin,
        &source_manifest.run_id,
        durable_boundary,
    )?;
    Ok(cursor.recording_id)
}

fn segment_logical_bytes(plans: &[BatchPlan]) -> Result<u64> {
    let mut total = 0_u64;
    let mut blobs = BTreeSet::new();
    for batch in plans {
        total = total
            .checked_add(u64::try_from(batch.byte_length).context("batch length overflow")?)
            .context("recording segment size overflow")?;
        for blob in &batch.blobs {
            if blobs.insert(&blob.sha256) {
                total = total
                    .checked_add(blob.size)
                    .context("recording segment size overflow")?;
            }
        }
    }
    Ok(total)
}

/// Returns whether the local spool proves that this exact run was fully `ACKed`
/// and sealed at the selected platform origin. It never creates upload state.
pub fn upload_complete_for(
    run_dir: &Path,
    api: &Url,
    allow_http: bool,
    encryption_key: Option<&EncryptionKey>,
) -> Result<bool> {
    validate_api(api, allow_http)?;
    let run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("resolve run directory {}", run_dir.display()))?;
    let source_manifest = manifest::read(&run_dir.join("manifest.json"))?;
    source_manifest.verify_authentication(encryption_key)?;
    let inspection = inspect_run_with_key(&run_dir, false, encryption_key)?;
    if inspection.manifest.status == "running" || inspection.log.discarded_tail_bytes != 0 {
        return Ok(false);
    }
    let spool = run_dir.join(".upload");
    let spool_metadata = match fs::symlink_metadata(&spool) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        spool_metadata.file_type().is_dir() && !spool_metadata.file_type().is_symlink(),
        "upload spool is not a real directory"
    );
    let origin = canonical_origin(api);
    let states = load_segment_chain(
        &spool,
        &origin,
        &inspection.manifest.run_id,
        inspection.log.valid_events,
    )?;
    if states.is_empty() {
        return Ok(false);
    }
    Ok(segment_chain_complete(&states, inspection.log.valid_events))
}

fn prepare_spool(run_dir: &Path) -> io::Result<PathBuf> {
    let spool = run_dir.join(".upload");
    match fs::symlink_metadata(&spool) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "upload spool is not a real directory",
                ));
            }
            fs::set_permissions(&spool, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&spool)?;
            fs::set_permissions(&spool, fs::Permissions::from_mode(0o700))?;
            File::open(run_dir)?.sync_all()?;
        }
        Err(error) => return Err(error),
    }
    Ok(spool)
}

fn lock_state(spool: &Path) -> io::Result<StateLock> {
    let file = open_regular_create(&spool.join("upload.lock"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| io::Error::other(error))?;
    Ok(StateLock { _file: file })
}

fn segment_state_path(spool: &Path, api_origin: &str, segment_no: u32) -> PathBuf {
    let digest = hex::encode(Sha256::digest(api_origin.as_bytes()));
    if segment_no == 0 {
        spool.join(format!("state-{digest}.json"))
    } else {
        spool.join(format!("state-{digest}-segment-{segment_no:04}.json"))
    }
}

#[derive(Debug)]
struct SegmentState {
    path: PathBuf,
    state: UploadState,
    planned_seq: u64,
}

#[derive(Debug)]
struct SegmentCursor {
    path: PathBuf,
    recording_id: String,
    segment_no: u32,
    first_seq: u64,
}

fn load_segment_chain(
    spool: &Path,
    api_origin: &str,
    run_id: &str,
    available_seq: u64,
) -> Result<Vec<SegmentState>> {
    let digest = hex::encode(Sha256::digest(api_origin.as_bytes()));
    let legacy_name = format!("state-{digest}.json");
    let segment_prefix = format!("state-{digest}-segment-");
    let mut states = Vec::new();
    for entry in fs::read_dir(spool)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let segment_no = if name == legacy_name {
            Some(0)
        } else if let Some(value) = name
            .strip_prefix(&segment_prefix)
            .and_then(|value| value.strip_suffix(".json"))
        {
            let parsed = value
                .parse::<u32>()
                .context("upload state filename has an invalid segment number")?;
            anyhow::ensure!(
                parsed > 0 && parsed < MAX_RECORDING_SEGMENTS && value == format!("{parsed:04}"),
                "upload state filename has a non-canonical segment number"
            );
            Some(parsed)
        } else {
            None
        };
        let Some(segment_no) = segment_no else {
            continue;
        };
        anyhow::ensure!(
            states.len() < usize::try_from(MAX_RECORDING_SEGMENTS).unwrap_or(usize::MAX),
            "upload segment state limit exceeded"
        );
        let path = entry.path();
        let bytes = read_regular_limited(&path, MAX_STATE_BYTES)?;
        crate::input::validate_json_complexity(&bytes)?;
        let mut state: UploadState =
            serde_json::from_slice(&bytes).context("parse upload state")?;
        // Upgrade pre-policy spool files in memory before any upload or
        // backfill loop can consume them. Subsequent state writes persist the
        // filtered plan without changing immutable event batch boundaries.
        omit_sensitive_blob_plans(&mut state);
        let recording_id = recording_id_for_segment(run_id, segment_no);
        anyhow::ensure!(
            state.segment_no == segment_no,
            "upload state filename and segment identity disagree"
        );
        let planned_seq =
            validate_state_prefix(&state, run_id, &recording_id, api_origin, available_seq)?;
        anyhow::ensure!(
            path == segment_state_path(spool, api_origin, segment_no),
            "upload state path is not canonical"
        );
        states.push(SegmentState {
            path,
            state,
            planned_seq,
        });
    }
    states.sort_by_key(|item| item.state.segment_no);
    let mut expected_first = 1_u64;
    for (index, item) in states.iter().enumerate() {
        let expected_segment = u32::try_from(index).context("upload segment count overflow")?;
        anyhow::ensure!(
            item.state.segment_no == expected_segment,
            "upload segment chain has a gap or duplicate"
        );
        anyhow::ensure!(
            item.state.first_seq == expected_first,
            "upload segment chain has an event sequence gap or overlap"
        );
        if index + 1 < states.len() {
            anyhow::ensure!(
                item.state.sealed && item.state.acked_seq == item.planned_seq,
                "only the final upload segment may remain open"
            );
        }
        expected_first = item
            .planned_seq
            .checked_add(1)
            .context("upload sequence overflow")?;
    }
    Ok(states)
}

fn list_upload_origins(spool: &Path, run_id: &str) -> Result<BTreeSet<String>> {
    let mut origins = BTreeSet::new();
    let mut states = 0_usize;
    for entry in fs::read_dir(spool)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("state-") || !name.ends_with(".json") {
            continue;
        }
        states = states.saturating_add(1);
        anyhow::ensure!(
            states <= MAX_TOTAL_UPLOAD_STATES,
            "total upload state limit exceeded"
        );
        let path = entry.path();
        let bytes = read_regular_limited(&path, MAX_STATE_BYTES)?;
        crate::input::validate_json_complexity(&bytes)?;
        let state: UploadState = serde_json::from_slice(&bytes).context("parse upload state")?;
        anyhow::ensure!(state.run_id == run_id, "upload state run ID mismatch");
        anyhow::ensure!(
            state.segment_no < MAX_RECORDING_SEGMENTS,
            "upload state has an invalid segment number"
        );
        let parsed_origin = Url::parse(&state.api_origin).context("upload state API origin")?;
        validate_api(&parsed_origin, true)?;
        anyhow::ensure!(
            canonical_origin(&parsed_origin) == state.api_origin,
            "upload state API origin is not canonical"
        );
        anyhow::ensure!(
            path == segment_state_path(spool, &state.api_origin, state.segment_no),
            "upload state path is not canonical"
        );
        origins.insert(state.api_origin);
        anyhow::ensure!(
            origins.len() <= MAX_UPLOAD_TARGETS,
            "upload target state limit exceeded"
        );
    }
    Ok(origins)
}

fn segment_chain_complete(states: &[SegmentState], final_seq: u64) -> bool {
    let Some(last) = states.last() else {
        return false;
    };
    if last.planned_seq != final_seq {
        return false;
    }
    for state in states {
        if planned_sequence(&state.state) < state.state.first_seq {
            return false;
        }
        if !state.state.sealed || state.state.acked_seq != state.planned_seq {
            return false;
        }
    }
    true
}

fn select_segment_cursor(
    spool: &Path,
    api_origin: &str,
    run_id: &str,
    available_seq: u64,
) -> Result<(Vec<SegmentState>, SegmentCursor)> {
    let states = load_segment_chain(spool, api_origin, run_id, available_seq)?;
    let (segment_no, first_seq) = match states.last() {
        None => (0, 1),
        Some(last) if !last.state.sealed || last.planned_seq == available_seq => {
            (last.state.segment_no, last.state.first_seq)
        }
        Some(last) => {
            anyhow::ensure!(
                last.planned_seq < available_seq,
                "upload segment chain exceeds the requested durable boundary"
            );
            let segment_no = last
                .state
                .segment_no
                .checked_add(1)
                .context("upload segment number overflow")?;
            anyhow::ensure!(
                segment_no < MAX_RECORDING_SEGMENTS,
                "upload recording segment limit exceeded"
            );
            let first_seq = last
                .planned_seq
                .checked_add(1)
                .context("upload sequence overflow")?;
            (segment_no, first_seq)
        }
    };
    Ok((
        states,
        SegmentCursor {
            path: segment_state_path(spool, api_origin, segment_no),
            recording_id: recording_id_for_segment(run_id, segment_no),
            segment_no,
            first_seq,
        },
    ))
}

fn select_expected_segment_cursor(
    spool: &Path,
    api_origin: &str,
    run_id: &str,
    expected_recording_id: &str,
    durable_boundary: u64,
    available_seq: u64,
) -> Result<(Vec<SegmentState>, SegmentCursor)> {
    anyhow::ensure!(
        durable_boundary <= available_seq,
        "persisted collector request boundary exceeds durable local evidence"
    );
    let (_, suffix) = expected_recording_id
        .rsplit_once('#')
        .context("collector request recording ID has no segment suffix")?;
    anyhow::ensure!(
        suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit()),
        "collector request recording ID has an invalid segment suffix"
    );
    let segment_no = suffix
        .parse::<u32>()
        .context("collector request recording segment is invalid")?;
    anyhow::ensure!(
        segment_no < MAX_RECORDING_SEGMENTS
            && recording_id_for_segment(run_id, segment_no) == expected_recording_id,
        "collector request recording ID does not belong to the local run"
    );

    let states = load_segment_chain(spool, api_origin, run_id, available_seq)?;
    let index = usize::try_from(segment_no).context("recording segment number overflow")?;
    let cursor = if let Some(item) = states.get(index) {
        anyhow::ensure!(
            item.state.segment_no == segment_no,
            "collector request recording segment is not contiguous"
        );
        anyhow::ensure!(
            item.planned_seq <= durable_boundary,
            "collector request boundary was superseded inside an unsealed segment"
        );
        if item.state.sealed || index + 1 < states.len() {
            anyhow::ensure!(
                item.planned_seq == durable_boundary,
                "collector request boundary does not match the immutable segment seal"
            );
        }
        SegmentCursor {
            path: item.path.clone(),
            recording_id: item.state.recording_id.clone(),
            segment_no,
            first_seq: item.state.first_seq,
        }
    } else {
        anyhow::ensure!(
            index == states.len(),
            "collector request recording segment has a gap"
        );
        let first_seq = if let Some(last) = states.last() {
            anyhow::ensure!(
                last.state.sealed,
                "collector request cannot skip an open recording segment"
            );
            last.planned_seq
                .checked_add(1)
                .context("upload sequence overflow")?
        } else {
            1
        };
        anyhow::ensure!(
            first_seq <= durable_boundary,
            "collector request recording segment starts after its durable boundary"
        );
        SegmentCursor {
            path: segment_state_path(spool, api_origin, segment_no),
            recording_id: expected_recording_id.to_owned(),
            segment_no,
            first_seq,
        }
    };
    Ok((states, cursor))
}

fn load_or_create_state(
    path: &Path,
    run_id: &str,
    recording_id: &str,
    api_origin: &str,
    segment_no: u32,
    first_seq: u64,
    target_seq: u64,
) -> Result<UploadState> {
    let mut state = if path.try_exists()? {
        let bytes = read_regular_limited(path, MAX_STATE_BYTES)?;
        crate::input::validate_json_complexity(&bytes)?;
        serde_json::from_slice(&bytes).context("parse upload state")?
    } else {
        UploadState {
            schema_version: STATE_SCHEMA_VERSION,
            api_origin: api_origin.to_owned(),
            run_id: run_id.to_owned(),
            recording_id: recording_id.to_owned(),
            segment_no,
            first_seq,
            batch_max_events: DEFAULT_BATCH_EVENTS,
            batch_max_bytes: DEFAULT_BATCH_BYTES,
            acked_seq: first_seq.saturating_sub(1),
            sealed: false,
            collector_id: None,
            config_version: 0,
            batches: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    };
    omit_sensitive_blob_plans(&mut state);
    anyhow::ensure!(
        state.segment_no == segment_no && state.first_seq == first_seq,
        "upload state segment identity mismatch"
    );
    validate_state_prefix(&state, run_id, recording_id, api_origin, target_seq)?;
    write_state(path, &state)?;
    Ok(state)
}

fn planned_sequence(state: &UploadState) -> u64 {
    state
        .batches
        .last()
        .map_or(state.first_seq.saturating_sub(1), |batch| batch.last_seq)
}

fn extend_state_to(
    state: &mut UploadState,
    run_dir: &Path,
    encryption: Option<&EncryptionKey>,
    target_seq: u64,
) -> Result<()> {
    let planned_seq = planned_sequence(state);
    if planned_seq == target_seq {
        return Ok(());
    }
    anyhow::ensure!(
        planned_seq < target_seq,
        "upload state exceeds requested boundary"
    );
    anyhow::ensure!(!state.sealed, "sealed upload state cannot be extended");
    let first_seq = planned_seq
        .checked_add(1)
        .context("upload sequence overflow")?;
    let previous = state.batches.last().map(|batch| batch.sha256.as_str());
    let additional = build_batch_plans_range(
        run_dir,
        &state.run_id,
        encryption,
        first_seq,
        target_seq,
        previous,
    )?;
    state.batches.extend(additional);
    anyhow::ensure!(
        state.batches.len() <= MAX_BATCH_PLANS,
        "upload batch plan limit exceeded"
    );
    state.updated_at = Utc::now();
    Ok(())
}

#[cfg(test)]
fn build_batch_plans(
    run_dir: &Path,
    run_id: &str,
    encryption: Option<&EncryptionKey>,
) -> Result<Vec<BatchPlan>> {
    build_batch_plans_range(run_dir, run_id, encryption, 1, u64::MAX, None)
}

fn build_batch_plans_range(
    run_dir: &Path,
    run_id: &str,
    encryption: Option<&EncryptionKey>,
    requested_first_seq: u64,
    requested_last_seq: u64,
    previous_sha256: Option<&str>,
) -> Result<Vec<BatchPlan>> {
    anyhow::ensure!(
        requested_first_seq > 0 && requested_last_seq >= requested_first_seq,
        "invalid upload planning range"
    );
    let reader = RunEventReader::open(&run_dir.join("events.jsonl"), run_id, encryption)?;
    let mut batches = Vec::new();
    let mut raw = Vec::with_capacity(DEFAULT_BATCH_BYTES);
    let mut first_seq = 0;
    let mut last_seq = 0;
    let mut count = 0;
    let mut blobs = BTreeMap::<String, BlobPlan>::new();
    let mut previous = previous_sha256.map(str::to_owned);
    let mut expected = requested_first_seq;
    for event in reader {
        let event = event?;
        if event.sequence < requested_first_seq {
            continue;
        }
        if event.sequence > requested_last_seq {
            break;
        }
        anyhow::ensure!(
            event.sequence == expected,
            "event log does not cover the requested upload range"
        );
        expected = expected
            .checked_add(1)
            .context("upload sequence overflow")?;
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        anyhow::ensure!(
            line.len() <= DEFAULT_BATCH_BYTES,
            "event {} exceeds the upload inline limit; payloads must use raw blob references",
            event.sequence
        );
        if count > 0
            && (count == DEFAULT_BATCH_EVENTS || raw.len() + line.len() > DEFAULT_BATCH_BYTES)
        {
            let plan = finish_plan(
                first_seq,
                last_seq,
                count,
                &raw,
                &blobs,
                previous.as_deref(),
            )?;
            previous = Some(plan.sha256.clone());
            batches.push(plan);
            anyhow::ensure!(
                batches.len() <= MAX_BATCH_PLANS,
                "upload batch plan limit exceeded"
            );
            raw.clear();
            blobs.clear();
            count = 0;
        }
        if count == 0 {
            first_seq = event.sequence;
        }
        last_seq = event.sequence;
        add_blob_plan(&mut blobs, event.raw.as_ref())?;
        raw.extend_from_slice(&line);
        count += 1;
    }
    if count > 0 {
        batches.push(finish_plan(
            first_seq,
            last_seq,
            count,
            &raw,
            &blobs,
            previous.as_deref(),
        )?);
    }
    anyhow::ensure!(!batches.is_empty(), "cannot upload an empty event range");
    if requested_last_seq != u64::MAX {
        anyhow::ensure!(
            expected == requested_last_seq.saturating_add(1),
            "event log ends before the requested upload boundary"
        );
    }
    let blob_count = batches.iter().map(|batch| batch.blobs.len()).sum::<usize>();
    anyhow::ensure!(
        blob_count <= MAX_BLOB_PLANS,
        "upload blob plan limit exceeded"
    );
    Ok(batches)
}

fn add_blob_plan(
    blobs: &mut BTreeMap<String, BlobPlan>,
    reference: Option<&PayloadRef>,
) -> Result<()> {
    let Some(reference) = reference else {
        return Ok(());
    };
    // Packet captures and TLS traffic secrets are a separate, highest-
    // sensitivity tier. Ordinary upload and backfill must never declassify
    // them merely because an event references the local encrypted blob. They
    // can reach the platform only through a separately approved workflow or
    // the explicit plaintext platform-export boundary.
    if is_sensitive_upload_media_type(reference.media_type.as_deref()) {
        return Ok(());
    }
    let sha256 = reference
        .sha256
        .strip_prefix("sha256:")
        .context("raw payload reference has no sha256 prefix")?
        .to_owned();
    let candidate = BlobPlan {
        sha256: sha256.clone(),
        size: reference.size,
        media_type: reference.media_type.clone(),
    };
    if let Some(existing) = blobs.get(&sha256) {
        anyhow::ensure!(
            existing.size == candidate.size,
            "the same blob digest has conflicting sizes"
        );
    } else {
        blobs.insert(sha256, candidate);
    }
    Ok(())
}

fn is_sensitive_upload_media_type(media_type: Option<&str>) -> bool {
    matches!(media_type, Some(PCAP_MEDIA_TYPE | TLS_SECRETS_MEDIA_TYPE))
}

fn omit_sensitive_blob_plans(state: &mut UploadState) {
    for batch in &mut state.batches {
        batch
            .blobs
            .retain(|blob| !is_sensitive_upload_media_type(blob.media_type.as_deref()));
    }
}

fn finish_plan(
    first_seq: u64,
    last_seq: u64,
    event_count: usize,
    raw: &[u8],
    blobs: &BTreeMap<String, BlobPlan>,
    previous: Option<&str>,
) -> Result<BatchPlan> {
    anyhow::ensure!(
        first_seq > 0 && last_seq >= first_seq,
        "invalid batch sequence range"
    );
    anyhow::ensure!(event_count > 0, "empty batch plan");
    Ok(BatchPlan {
        first_seq,
        last_seq,
        event_count,
        byte_length: raw.len(),
        sha256: hex::encode(Sha256::digest(raw)),
        prev_sha256: previous.map(str::to_owned),
        blobs: blobs.values().cloned().collect(),
        created_at: Utc::now(),
    })
}

fn validate_state(
    state: &UploadState,
    run_id: &str,
    recording_id: &str,
    api_origin: &str,
    final_seq: u64,
) -> Result<()> {
    let planned_seq = validate_state_prefix(state, run_id, recording_id, api_origin, final_seq)?;
    anyhow::ensure!(
        planned_seq == final_seq,
        "upload state does not cover the event log"
    );
    Ok(())
}

fn validate_state_prefix(
    state: &UploadState,
    run_id: &str,
    recording_id: &str,
    api_origin: &str,
    available_seq: u64,
) -> Result<u64> {
    anyhow::ensure!(
        state.schema_version == STATE_SCHEMA_VERSION,
        "unsupported upload state"
    );
    anyhow::ensure!(
        state.api_origin == api_origin,
        "upload state API origin mismatch"
    );
    anyhow::ensure!(state.run_id == run_id, "upload state run ID mismatch");
    anyhow::ensure!(
        state.segment_no < MAX_RECORDING_SEGMENTS
            && state.first_seq > 0
            && state.first_seq <= MAX_PLATFORM_SEQUENCE,
        "upload state has an invalid segment identity"
    );
    anyhow::ensure!(
        state.created_at <= state.updated_at + chrono::TimeDelta::minutes(5),
        "upload state creation time is invalid"
    );
    anyhow::ensure!(
        state.recording_id == recording_id,
        "upload state recording ID mismatch"
    );
    anyhow::ensure!(
        state.batch_max_events == DEFAULT_BATCH_EVENTS
            && state.batch_max_bytes == DEFAULT_BATCH_BYTES,
        "upload state batch policy mismatch"
    );
    anyhow::ensure!(
        state.batches.len() <= MAX_BATCH_PLANS,
        "upload state has too many batches"
    );
    let mut next = state.first_seq;
    let mut previous: Option<&str> = None;
    let mut blob_count = 0_usize;
    for batch in &state.batches {
        anyhow::ensure!(batch.first_seq == next, "upload state has a sequence gap");
        anyhow::ensure!(
            batch.last_seq >= batch.first_seq
                && batch.last_seq <= MAX_PLATFORM_SEQUENCE
                && batch.event_count
                    == usize::try_from(batch.last_seq - batch.first_seq + 1).unwrap_or(usize::MAX),
            "upload state has an invalid batch range"
        );
        anyhow::ensure!(
            batch.byte_length > 0 && batch.byte_length <= DEFAULT_BATCH_BYTES,
            "upload state has an invalid batch size"
        );
        validate_sha(&batch.sha256)?;
        anyhow::ensure!(
            batch.prev_sha256.as_deref() == previous,
            "upload hash chain mismatch"
        );
        for blob in &batch.blobs {
            validate_sha(&blob.sha256)?;
            anyhow::ensure!(
                !is_sensitive_upload_media_type(blob.media_type.as_deref()),
                "ordinary upload state contains a sensitive-tier blob"
            );
        }
        blob_count = blob_count.saturating_add(batch.blobs.len());
        previous = Some(&batch.sha256);
        next = batch
            .last_seq
            .checked_add(1)
            .context("upload sequence overflow")?;
    }
    let planned_seq = next - 1;
    anyhow::ensure!(
        planned_seq <= available_seq,
        "upload state exceeds available local evidence"
    );
    anyhow::ensure!(
        blob_count <= MAX_BLOB_PLANS,
        "upload state has too many blob references"
    );
    anyhow::ensure!(
        state.acked_seq <= planned_seq && is_batch_boundary(state, state.acked_seq),
        "upload state acknowledged sequence is not a batch boundary"
    );
    anyhow::ensure!(
        !state.sealed || state.acked_seq == planned_seq,
        "sealed upload state is not fully acknowledged"
    );
    Ok(planned_seq)
}

fn validate_sha(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "upload state contains an invalid SHA-256 digest"
    );
    Ok(())
}

fn is_batch_boundary(state: &UploadState, sequence: u64) -> bool {
    sequence == state.first_seq.saturating_sub(1)
        || state.batches.iter().any(|batch| batch.last_seq == sequence)
}

fn write_state(path: &Path, state: &UploadState) -> Result<()> {
    let parent = path.parent().context("upload state has no parent")?;
    let temporary = parent.join(format!(
        ".state-{}-{}.tmp",
        std::process::id(),
        Uuid::now_v7()
    ));
    let result = (|| -> Result<()> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut writer = io::BufWriter::new(file);
        serde_json::to_writer(&mut writer, state)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_token(path: &Path) -> Result<Zeroizing<String>> {
    let mut file = open_regular_read(path).context("open platform token file")?;
    let metadata = file.metadata()?;
    let exposed_permission_bits = metadata.permissions().mode() & 0o077;
    anyhow::ensure!(
        exposed_permission_bits == 0,
        "platform token file must not be accessible by group or other users"
    );
    let mut bytes = Vec::with_capacity(
        MAX_TOKEN_BYTES.min(usize::try_from(metadata.len()).unwrap_or(MAX_TOKEN_BYTES)),
    );
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_TOKEN_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .context("read platform token file")?;
    anyhow::ensure!(
        bytes.len() <= MAX_TOKEN_BYTES,
        "platform token exceeds the safety limit"
    );
    let mut token =
        Zeroizing::new(String::from_utf8(bytes).context("platform token is not UTF-8")?);
    while token.ends_with(['\r', '\n']) {
        token.pop();
    }
    anyhow::ensure!(!token.is_empty(), "platform token file is empty");
    anyhow::ensure!(
        token.bytes().all(|byte| byte.is_ascii_graphic()),
        "platform token contains whitespace or control bytes"
    );
    Ok(token)
}

fn read_batch(reader: &mut RunEventReader, plan: &BatchPlan) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(plan.byte_length);
    for expected in plan.first_seq..=plan.last_seq {
        let event = loop {
            let event = reader
                .next()
                .context("event log ended before the upload plan")??;
            if event.sequence >= expected {
                break event;
            }
        };
        anyhow::ensure!(
            event.sequence == expected,
            "event sequence changed after spooling"
        );
        serde_json::to_writer(&mut raw, &event)?;
        raw.push(b'\n');
    }
    anyhow::ensure!(
        raw.len() == plan.byte_length,
        "batch byte length changed after spooling"
    );
    anyhow::ensure!(
        hex::encode(Sha256::digest(&raw)) == plan.sha256,
        "batch content changed after spooling"
    );
    Ok(raw)
}

fn encode_batch_body(recording_id: &str, plan: &BatchPlan, raw: &[u8]) -> Result<Bytes> {
    let compressed = zstd::bulk::compress(raw, 3).context("compress upload batch")?;
    let header = BatchHeader {
        batch_id: format!(
            "{recording_id}:{:012}-{:012}",
            plan.first_seq, plan.last_seq
        ),
        recording_id,
        schema_version: 1,
        first_seq: plan.first_seq,
        last_seq: plan.last_seq,
        event_count: plan.event_count,
        byte_length: plan.byte_length,
        sha256: &plan.sha256,
        prev_sha256: plan.prev_sha256.as_deref(),
        encoding: "ndjson+zstd",
        blobs: plan
            .blobs
            .iter()
            .map(|blob| WireBlobRef {
                sha256: &blob.sha256,
                size: blob.size,
            })
            .collect(),
        created_at: plan.created_at,
    };
    let header = serde_json::to_vec(&header)?;
    let length = header.len() + 1 + compressed.len();
    anyhow::ensure!(
        length <= MAX_WIRE_BATCH_BYTES,
        "compressed upload batch exceeds wire limit"
    );
    let mut body = Vec::with_capacity(length);
    body.extend_from_slice(&header);
    body.push(b'\n');
    body.extend_from_slice(&compressed);
    Ok(Bytes::from(body))
}

fn reconcile_remote(state: &mut UploadState, remote: &RemoteRecording) -> Result<()> {
    let sequence_base = state.first_seq.saturating_sub(1);
    let final_seq = state
        .batches
        .last()
        .map_or(sequence_base, |batch| batch.last_seq);
    anyhow::ensure!(
        remote.segment_no == state.segment_no && remote.sequence_base == sequence_base,
        "platform recording segment identity conflicts with local evidence"
    );
    anyhow::ensure!(
        remote.durable_seq >= sequence_base && remote.durable_seq <= final_seq,
        "platform durable sequence exceeds local evidence"
    );
    anyhow::ensure!(
        is_batch_boundary(state, remote.durable_seq),
        "platform durable sequence does not match the fixed local batch plan"
    );
    if remote.state == "sealed" {
        if let Some(remote_final) = remote.final_seq {
            anyhow::ensure!(
                remote_final == final_seq,
                "platform final sequence conflicts with local evidence"
            );
        }
    } else {
        anyhow::ensure!(
            remote.state == "open",
            "platform recording is not uploadable"
        );
    }
    state.acked_seq = remote.durable_seq;
    state.sealed = remote.state == "sealed" && remote.durable_seq == final_seq;
    state.updated_at = Utc::now();
    Ok(())
}

fn validate_ack(state: &UploadState, batch: &BatchPlan, ack: &BatchAck) -> Result<()> {
    anyhow::ensure!(
        ack.recording_id == state.recording_id,
        "platform acknowledged a different recording"
    );
    anyhow::ensure!(
        ack.state == "open" || ack.state == "sealed",
        "platform returned an invalid recording state"
    );
    anyhow::ensure!(
        ack.durable_seq >= batch.last_seq
            && ack.durable_seq
                <= state
                    .batches
                    .last()
                    .map_or(state.first_seq.saturating_sub(1), |item| item.last_seq)
            && is_batch_boundary(state, ack.durable_seq),
        "platform returned an invalid durable sequence"
    );
    anyhow::ensure!(
        ack.missing_blobs.is_empty(),
        "platform reports missing uploaded blobs"
    );
    Ok(())
}

impl PlatformClient {
    fn new(origin: Url, token: &str, retry_for: Duration) -> Result<Self> {
        let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("platform token cannot be represented as an HTTP header")?;
        let http = reqwest::Client::builder()
            .redirect(RedirectPolicy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .user_agent(format!("iorec/{RECORDER_VERSION}"))
            .build()?;
        Ok(Self {
            origin,
            authorization,
            http,
            retry_for,
        })
    }

    async fn register(
        &mut self,
        manifest: &Manifest,
        collector_id: Option<Uuid>,
    ) -> Result<RegisterResponse> {
        let body = serde_json::to_vec(&RegisterCollector {
            collector_id,
            name: "iorec",
            version: format!("iorec/{RECORDER_VERSION}"),
            // Avoid turning a data-plane credential into an implicit stable
            // machine-identity disclosure. Operators can name collectors in
            // the platform after registration.
            hostname: "redacted",
            os: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            capabilities: collector_capabilities(manifest),
        })?;
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "collectors:register"]),
                json_headers(),
                Bytes::from(body),
            )
            .await?;
        require_status(&response, &[StatusCode::OK])?;
        let mut registration: RegisterResponse = decode_json(&response.body)?;
        anyhow::ensure!(
            !registration.collector_id.is_nil(),
            "platform returned a nil collector ID"
        );
        anyhow::ensure!(
            registration.config_version >= 0,
            "platform returned an invalid config version"
        );
        anyhow::ensure!(
            registration.expires_at > Utc::now(),
            "platform returned an expired collector session"
        );
        anyhow::ensure!(
            registration.config.is_object(),
            "platform returned a non-object collector configuration"
        );
        anyhow::ensure!(
            !registration.session_token.is_empty()
                && registration.session_token.len() <= MAX_TOKEN_BYTES
                && registration
                    .session_token
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic()),
            "platform returned an invalid collector session token"
        );
        let authorization =
            HeaderValue::from_str(&format!("Bearer {}", registration.session_token))
                .context("collector session token cannot be represented as an HTTP header")?;
        registration.session_token.zeroize();
        self.authorization = authorization;
        Ok(registration)
    }

    async fn heartbeat(
        &self,
        collector_id: Uuid,
        state: &UploadState,
        manifest: &Manifest,
        final_seq: u64,
        rejected_config: &serde_json::Value,
    ) -> Result<()> {
        let lag = if state.acked_seq == final_seq {
            0.0
        } else {
            manifest.finished_at.map_or(0.0, |finished| {
                f64::from(
                    u32::try_from(
                        Utc::now()
                            .signed_duration_since(finished)
                            .num_seconds()
                            .max(0),
                    )
                    .unwrap_or(u32::MAX),
                )
            })
        };
        let spool_bytes = manifest
            .counts
            .event_storage_bytes
            .saturating_add(manifest.counts.blob_storage_bytes);
        let body = serde_json::to_vec(&Heartbeat {
            status: "healthy",
            active_runs: 0,
            spool_bytes_used: spool_bytes,
            acked_lag_seconds: lag,
            last_error: None,
            config_version: state.config_version,
            effective_config: serde_json::json!({
                "content_policy": {
                    "capture_bodies": manifest.policy.body_mode == BodyCaptureMode::Full,
                    "max_body_bytes": manifest.policy.max_blob_bytes,
                    "redact_fields": manifest.policy.redact_headers,
                },
                "upload": {
                    "batch_max_bytes": DEFAULT_BATCH_BYTES,
                    "batch_max_events": DEFAULT_BATCH_EVENTS,
                }
            }),
            rejected: rejected_config.clone(),
        })?;
        let segment = format!("{collector_id}:heartbeat");
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "collectors", &segment]),
                json_headers(),
                Bytes::from(body),
            )
            .await?;
        require_status(&response, &[StatusCode::OK])
    }

    async fn create_recording(
        &self,
        manifest: &Manifest,
        recording_id: &str,
        segment_no: u32,
        sequence_base: u64,
    ) -> Result<()> {
        let command = manifest.command.argv.join(" ");
        let body = serde_json::to_vec(&CreateRecording {
            recording_id,
            capture_run_id: &manifest.run_id,
            segment_no,
            sequence_base,
            schema_version: 1,
            run: RunMetadata {
                command,
                cwd: &manifest.command.cwd,
                agent_kind: manifest.command.agent.as_deref(),
                agent_version: manifest.command.agent_version.as_deref(),
                started_at: manifest.started_at,
                metadata: RunUploadMetadata {
                    recorder_version: &manifest.recorder_version,
                    runtime: manifest.command.runtime.as_deref(),
                },
            },
        })?;
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "recordings"]),
                json_headers(),
                Bytes::from(body),
            )
            .await?;
        require_status(&response, &[StatusCode::CREATED, StatusCode::OK])
    }

    async fn get_recording(&self, recording_id: &str) -> Result<RemoteRecording> {
        let response = self
            .request(
                Method::GET,
                self.endpoint(&["v1", "recordings", recording_id]),
                HeaderMap::new(),
                Bytes::new(),
            )
            .await?;
        require_status(&response, &[StatusCode::OK])?;
        decode_json(&response.body)
    }

    async fn ensure_blob(
        &self,
        run_dir: &Path,
        plan: &BlobPlan,
        encryption: Option<&EncryptionKey>,
        force: bool,
    ) -> Result<()> {
        let endpoint = self.endpoint(&["v1", "blobs", &plan.sha256]);
        if !force {
            let head = self
                .request(
                    Method::HEAD,
                    endpoint.clone(),
                    HeaderMap::new(),
                    Bytes::new(),
                )
                .await?;
            if head.status == StatusCode::OK {
                if let Some(length) = head.headers.get(header::CONTENT_LENGTH) {
                    let length = length.to_str()?.parse::<u64>()?;
                    anyhow::ensure!(
                        length == plan.size,
                        "platform blob size conflicts with local evidence"
                    );
                }
                return Ok(());
            }
            anyhow::ensure!(
                head.status == StatusCode::NOT_FOUND,
                "platform rejected blob lookup with HTTP {}",
                head.status.as_u16()
            );
        }

        let reference = PayloadRef {
            sha256: format!("sha256:{}", plan.sha256),
            size: plan.size,
            media_type: plan.media_type.clone(),
            truncated: false,
        };
        let bytes = read_blob_reference(
            run_dir,
            &reference,
            encryption,
            crate::storage::MAX_SINGLE_BLOB_BYTES,
        )?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(
                plan.media_type
                    .as_deref()
                    .unwrap_or("application/octet-stream"),
            )?,
        );
        let response = self
            .request(Method::PUT, endpoint, headers, Bytes::from(bytes))
            .await?;
        require_status(&response, &[StatusCode::CREATED, StatusCode::OK])
    }

    async fn upload_batch(
        &self,
        recording_id: &str,
        plan: &BatchPlan,
        body: Bytes,
    ) -> Result<BatchAck> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_BATCH),
        );
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&format!(
                "{recording_id}:{:012}-{:012}",
                plan.first_seq, plan.last_seq
            ))?,
        );
        headers.insert("x-batch-sha256", HeaderValue::from_str(&plan.sha256)?);
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "recordings", recording_id, "batches"]),
                headers,
                body,
            )
            .await?;
        require_status(&response, &[StatusCode::OK])?;
        decode_json(&response.body)
    }

    async fn seal_recording(
        &self,
        recording_id: &str,
        final_seq: u64,
        manifest: &Manifest,
        run_final: bool,
    ) -> Result<()> {
        let manifest_sha256 = if run_final {
            let manifest_bytes = serde_json::to_vec(manifest)?;
            Some(hex::encode(Sha256::digest(&manifest_bytes)))
        } else {
            None
        };
        let body = serde_json::to_vec(&SealRecording {
            final_seq,
            manifest: run_final.then_some(manifest),
            manifest_sha256,
            incomplete: false,
            run_final,
        })?;
        let segment = format!("{recording_id}:seal");
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "recordings", &segment]),
                json_headers(),
                Bytes::from(body),
            )
            .await?;
        require_status(&response, &[StatusCode::OK])
    }

    fn endpoint(&self, segments: &[&str]) -> Url {
        let mut endpoint = self.origin.clone();
        {
            let mut path = endpoint
                .path_segments_mut()
                .expect("validated HTTP URL supports path segments");
            path.clear();
            path.extend(segments);
        }
        endpoint
    }

    async fn request(
        &self,
        method: Method,
        endpoint: Url,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<HttpResponse> {
        let started = Instant::now();
        let mut attempt = 0_u32;
        loop {
            let result = self
                .http
                .request(method.clone(), endpoint.clone())
                .header(header::AUTHORIZATION, self.authorization.clone())
                .headers(headers.clone())
                .body(body.clone())
                .send()
                .await;
            match result {
                Ok(response) => {
                    let retry_after = retry_after(&response);
                    let response = read_response(response).await?;
                    if !retryable_status(response.status) {
                        return Ok(response);
                    }
                    if let Some(delay) = self.retry_delay(started, attempt, retry_after) {
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    if let Some(delay) = self.retry_delay(started, attempt, None) {
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Err(error).context("platform request failed after retry budget");
                }
            }
        }
    }

    fn retry_delay(
        &self,
        started: Instant,
        attempt: u32,
        retry_after: Option<Duration>,
    ) -> Option<Duration> {
        if self.retry_for.is_zero() {
            return None;
        }
        let shift = attempt.min(7);
        let exponential = Duration::from_millis(250_u64.saturating_mul(1_u64 << shift));
        let jitter = Duration::from_millis(u64::from((attempt.wrapping_mul(73) + 41) % 251));
        let delay = retry_after
            .unwrap_or(exponential + jitter)
            .min(Duration::from_secs(30));
        (started.elapsed() + delay <= self.retry_for).then_some(delay)
    }
}

fn collector_capabilities(manifest: &Manifest) -> CollectorCapabilities {
    let proxy = manifest
        .coverage
        .capture_sources
        .iter()
        .any(|source| source == "proxy");
    let pcap = manifest
        .coverage
        .capture_sources
        .iter()
        .any(|source| source.starts_with("pcap:"));
    let keylog = manifest
        .coverage
        .capture_sources
        .iter()
        .any(|source| source == "nss-sslkeylogfile");
    CollectorCapabilities {
        schema: "iorec.capabilities.v1",
        transport: serde_json::json!({
            "http_body": if proxy && manifest.policy.body_mode == BodyCaptureMode::Full { "visible" } else if proxy { "headers_only" } else { "absent" },
            "sse": if proxy { "visible" } else { "absent" },
            "websocket": if proxy { "visible" } else { "absent" },
            "http2_decode": "absent",
            "http3": "detect_only",
        }),
        sources: serde_json::json!({
            "proxy": proxy,
            "keylog": {"available": keylog},
            "pcap": {"available": pcap},
            "runtime_observer": manifest.coverage.capture_sources.iter().any(|source| source.starts_with("runtime:") || source.starts_with("hook:")),
        }),
        runtime_inventory: serde_json::json!({
            "agents_detected": manifest.command.agent.iter().map(|agent| serde_json::json!({"kind": agent, "version": manifest.command.agent_version})).collect::<Vec<_>>(),
            "tls_surfaces": manifest.command.executable_tls_surfaces.iter().map(|surface| serde_json::json!({"lib": surface, "status": "observed"})).collect::<Vec<_>>(),
            "unknown_tls_surfaces": manifest.coverage.unknown_tls_surfaces,
        }),
        limits: serde_json::json!({
            "max_blob_bytes": manifest.policy.max_blob_bytes,
            "spool_bytes": manifest.policy.max_event_storage_bytes.saturating_add(manifest.policy.max_run_blob_storage_bytes),
        }),
        privilege: serde_json::json!({"helper_running": false}),
    }
}

fn config_rejections(config: &serde_json::Value, manifest: &Manifest) -> Result<serde_json::Value> {
    let encoded = serde_json::to_vec(config)?;
    crate::input::validate_json_complexity(&encoded)?;
    let object = config
        .as_object()
        .context("platform collector configuration is not an object")?;
    anyhow::ensure!(
        object.len() <= 32,
        "platform collector configuration has too many sections"
    );
    let mut rejected = serde_json::Map::new();
    for (section, value) in object {
        anyhow::ensure!(
            !section.is_empty()
                && section.len() <= 128
                && section.bytes().all(|byte| byte.is_ascii_graphic()),
            "platform collector configuration has an invalid section name"
        );
        match section.as_str() {
            "content_policy" => {
                anyhow::ensure!(value.is_object(), "content_policy is not an object");
                rejected.insert(
                    section.clone(),
                    serde_json::json!({
                        "reason": "configuration applies only to new runs; this finalized run retains its authenticated local capture policy",
                        "effective_capture_bodies": manifest.policy.body_mode == BodyCaptureMode::Full,
                        "effective_max_body_bytes": manifest.policy.max_blob_bytes,
                    }),
                );
            }
            "upload" => {
                let upload = value
                    .as_object()
                    .context("upload config is not an object")?;
                if let Some(bytes) = upload.get("batch_max_bytes") {
                    let bytes = bytes
                        .as_u64()
                        .context("upload.batch_max_bytes is not an unsigned integer")?;
                    anyhow::ensure!(bytes > 0, "upload.batch_max_bytes is zero");
                    if bytes != u64::try_from(DEFAULT_BATCH_BYTES).unwrap_or(u64::MAX) {
                        rejected.insert(
                            "upload.batch_max_bytes".to_owned(),
                            serde_json::json!({
                                "reason": "fixed local batch plan takes precedence",
                                "effective": DEFAULT_BATCH_BYTES,
                            }),
                        );
                    }
                }
                for field in ["batch_max_age_ms", "rate_limit_bytes_per_s"] {
                    if upload.contains_key(field) {
                        rejected.insert(
                            format!("upload.{field}"),
                            serde_json::json!({
                                "reason": "single-shot finalized-run uploader does not apply this daemon setting",
                            }),
                        );
                    }
                }
            }
            "sensitive_tier_upload" => {
                anyhow::ensure!(value.is_object(), "sensitive_tier_upload is not an object");
                rejected.insert(
                    section.clone(),
                    serde_json::json!({
                        "reason": "sensitive tiers require an explicit local export and are never enabled by upload configuration",
                    }),
                );
            }
            "retention_local" => {
                anyhow::ensure!(value.is_object(), "retention_local is not an object");
                rejected.insert(
                    section.clone(),
                    serde_json::json!({
                        "reason": "automatic remote-configured deletion is not enabled; explicit authenticated prune policy takes precedence",
                    }),
                );
            }
            "egress_classification" => {
                anyhow::ensure!(value.is_object(), "egress_classification is not an object");
                rejected.insert(
                    section.clone(),
                    serde_json::json!({
                        "reason": "egress configuration applies only before a new run starts",
                    }),
                );
            }
            _ => {
                rejected.insert(
                    section.clone(),
                    serde_json::json!({"reason": "unknown configuration section"}),
                );
            }
        }
    }
    Ok(serde_json::Value::Object(rejected))
}

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers
}

struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn read_response(response: reqwest::Response) -> Result<HttpResponse> {
    let status = response.status();
    let headers = response.headers().clone();
    if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        return Ok(HttpResponse {
            status,
            headers,
            body: Bytes::new(),
        });
    }
    let mut stream = response.bytes_stream();
    let mut body = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            body.len() + chunk.len() <= MAX_RESPONSE_BYTES,
            "platform response exceeds safety limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.freeze(),
    })
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn require_status(response: &HttpResponse, accepted: &[StatusCode]) -> Result<()> {
    if accepted.contains(&response.status) {
        return Ok(());
    }
    let code = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| value.get("error")?.get("code")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unclassified".to_owned());
    anyhow::bail!(
        "platform returned HTTP {} ({code})",
        response.status.as_u16()
    )
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    crate::input::validate_json_complexity(bytes)?;
    serde_json::from_slice(bytes).context("decode platform response")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, Response},
        response::IntoResponse,
        routing::any,
    };
    use tokio::sync::Mutex;

    use crate::{
        inspect::finalize_manifest,
        manifest::{CommandMetadata, Manifest, write_atomic},
        model::EventIds,
        policy::{CapturePolicy, EventLogFormat},
        storage::RunStore,
    };

    use super::*;

    #[test]
    fn long_recording_ids_are_stable_and_bounded() {
        let run = "x".repeat(256);
        let first = recording_id(&run);
        assert_eq!(first, recording_id(&run));
        assert!(first.len() <= 240);
        assert!(first.ends_with("#0000"));
    }

    #[test]
    fn platform_url_requires_explicit_plain_http_and_has_no_secret_components() {
        let https = Url::parse("https://example.test").unwrap();
        validate_api(&https, false).unwrap();
        assert!(validate_api(&Url::parse("http://localhost:8080").unwrap(), false).is_err());
        validate_api(&Url::parse("http://localhost:8080").unwrap(), true).unwrap();
        assert!(validate_api(&Url::parse("https://user@example.test").unwrap(), false).is_err());
        assert!(validate_api(&Url::parse("https://example.test/base").unwrap(), false).is_err());
    }

    #[test]
    fn platform_config_is_bounded_and_reports_local_rejections_without_echoing_values() {
        let manifest = Manifest::new(
            "config-test".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
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
        let feedback = config_rejections(
            &serde_json::json!({
                "content_policy": {"capture_bodies": false},
                "upload": {"batch_max_bytes": 1, "rate_limit_bytes_per_s": 1},
                "unknown": {"token": "must-not-be-echoed"},
            }),
            &manifest,
        )
        .unwrap();
        let encoded = feedback.to_string();
        assert!(encoded.contains("fixed local batch plan"));
        assert!(!encoded.contains("must-not-be-echoed"));
        assert!(config_rejections(&serde_json::json!([]), &manifest).is_err());
    }

    #[tokio::test]
    async fn batch_plan_is_persistent_and_detects_evidence_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run");
        let run_id = "upload-test";
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
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, policy).unwrap();
        for index in 0..3 {
            let mut event = store.event("test", "event");
            event.ids = EventIds {
                attempt_id: Some(format!("attempt-{index}")),
                ..EventIds::default()
            };
            store.append(event).await.unwrap();
        }
        let stats = store.shutdown().await.unwrap();
        manifest.status = "finished".to_owned();
        manifest.counts.events = stats.events;
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();

        let plans = build_batch_plans(&run, run_id, None).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].first_seq, 1);
        assert_eq!(plans[0].last_seq, 3);
        let mut reader = RunEventReader::open(&run.join("events.jsonl"), run_id, None).unwrap();
        let raw = read_batch(&mut reader, &plans[0]).unwrap();
        let wire = encode_batch_body(&recording_id(run_id), &plans[0], &raw).unwrap();
        assert!(wire.len() < MAX_WIRE_BATCH_BYTES);
    }

    #[tokio::test]
    async fn ordinary_upload_plan_omits_pcap_and_tls_secrets() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run-sensitive-tier");
        let run_id = "upload-sensitive-tier-test";
        let policy = CapturePolicy::default();
        let (store, _) = RunStore::create(&run, run_id, policy).unwrap();
        for (bytes, media_type) in [
            (b"ordinary body".as_slice(), "application/json"),
            (b"pcap bytes".as_slice(), PCAP_MEDIA_TYPE),
            (b"CLIENT_RANDOM secret".as_slice(), TLS_SECRETS_MEDIA_TYPE),
        ] {
            let reference = store.store_blob(bytes, Some(media_type)).await.unwrap();
            let mut event = store.event("test", "evidence_chunk");
            event.raw = Some(reference);
            store.append(event).await.unwrap();
        }
        store.shutdown().await.unwrap();

        let plans = build_batch_plans(&run, run_id, None).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].event_count, 3);
        assert_eq!(plans[0].blobs.len(), 1);
        assert_eq!(
            plans[0].blobs[0].media_type.as_deref(),
            Some("application/json")
        );

        let mut legacy_state = UploadState {
            schema_version: STATE_SCHEMA_VERSION,
            api_origin: "https://example.test".to_owned(),
            run_id: run_id.to_owned(),
            recording_id: recording_id(run_id),
            segment_no: 0,
            first_seq: 1,
            batch_max_events: DEFAULT_BATCH_EVENTS,
            batch_max_bytes: DEFAULT_BATCH_BYTES,
            acked_seq: 0,
            sealed: false,
            collector_id: None,
            config_version: 0,
            batches: vec![BatchPlan {
                first_seq: 1,
                last_seq: 1,
                event_count: 1,
                byte_length: 1,
                sha256: "0".repeat(64),
                prev_sha256: None,
                blobs: vec![
                    BlobPlan {
                        sha256: "1".repeat(64),
                        size: 1,
                        media_type: Some(PCAP_MEDIA_TYPE.to_owned()),
                    },
                    BlobPlan {
                        sha256: "2".repeat(64),
                        size: 1,
                        media_type: Some(TLS_SECRETS_MEDIA_TYPE.to_owned()),
                    },
                ],
                created_at: Utc::now(),
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        omit_sensitive_blob_plans(&mut legacy_state);
        assert!(legacy_state.batches[0].blobs.is_empty());
    }

    #[test]
    fn token_file_must_be_private() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("token");
        fs::write(&path, b"token-value\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&path).unwrap().as_str(), "token-value");
    }

    #[derive(Default)]
    struct MockRecording {
        durable_seq: u64,
        final_seq: Option<u64>,
        sealed: bool,
        batches: BTreeSet<(u64, u64)>,
        sequence_base: u64,
        segment_no: u32,
    }

    #[derive(Default)]
    struct MockPlatformState {
        recordings: BTreeMap<String, MockRecording>,
        blobs: BTreeSet<String>,
        registrations: usize,
        heartbeats: usize,
        batch_uploads: usize,
        final_seals: usize,
    }

    async fn mock_platform(
        State(state): State<Arc<Mutex<MockPlatformState>>>,
        request: Request<Body>,
    ) -> Response<Body> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let body = to_bytes(request.into_body(), MAX_WIRE_BATCH_BYTES)
            .await
            .unwrap();
        let mut state = state.lock().await;
        let json_response = |status: StatusCode, value: serde_json::Value| {
            (status, axum::Json(value)).into_response()
        };
        if method == Method::POST && path == "/v1/collectors:register" {
            state.registrations += 1;
            return json_response(
                StatusCode::OK,
                serde_json::json!({
                    "collector_id": "018bcfe5-6800-7000-8000-000000000001",
                    "session_token": "iorc_mock_session",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "config_version": 0,
                    "config": {}
                }),
            );
        }
        if method == Method::POST && path == "/v1/recordings" {
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let recording_id = request["recording_id"].as_str().unwrap().to_owned();
            let sequence_base = request["sequence_base"].as_u64().unwrap();
            let segment_no = u32::try_from(request["segment_no"].as_u64().unwrap()).unwrap();
            let recording = state
                .recordings
                .entry(recording_id)
                .or_insert_with(|| MockRecording {
                    durable_seq: sequence_base,
                    sequence_base,
                    segment_no,
                    ..MockRecording::default()
                });
            assert_eq!(recording.sequence_base, sequence_base);
            assert_eq!(recording.segment_no, segment_no);
            return json_response(StatusCode::CREATED, serde_json::json!({"state":"open"}));
        }
        if method == Method::GET && path.starts_with("/v1/recordings/") {
            let encoded = path.trim_start_matches("/v1/recordings/");
            let recording_id = encoded.replace("%23", "#").replace("%2F", "/");
            let recording = state.recordings.get(&recording_id).unwrap();
            return json_response(
                StatusCode::OK,
                serde_json::json!({
                    "state": if recording.sealed { "sealed" } else { "open" },
                    "segment_no": recording.segment_no,
                    "sequence_base": recording.sequence_base,
                    "durable_seq": recording.durable_seq,
                    "final_seq": recording.final_seq,
                }),
            );
        }
        if method == Method::HEAD && path.starts_with("/v1/blobs/") {
            let sha = path.trim_start_matches("/v1/blobs/");
            return if state.blobs.contains(sha) {
                StatusCode::OK.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            };
        }
        if method == Method::PUT && path.starts_with("/v1/blobs/") {
            state
                .blobs
                .insert(path.trim_start_matches("/v1/blobs/").to_owned());
            return json_response(StatusCode::CREATED, serde_json::json!({"created":true}));
        }
        if method == Method::POST && path.ends_with("/batches") {
            let newline = body.iter().position(|byte| *byte == b'\n').unwrap();
            let header: serde_json::Value = serde_json::from_slice(&body[..newline]).unwrap();
            let recording_id = header["recording_id"].as_str().unwrap().to_owned();
            let first = header["first_seq"].as_u64().unwrap();
            let last = header["last_seq"].as_u64().unwrap();
            state.batch_uploads += 1;
            let recording = state.recordings.get_mut(&recording_id).unwrap();
            recording.batches.insert((first, last));
            recording.durable_seq = last;
            let response_state = if recording.sealed { "sealed" } else { "open" };
            return json_response(
                StatusCode::OK,
                serde_json::json!({"recording_id":recording_id,"durable_seq":last,"state":response_state,"missing_blobs":[]}),
            );
        }
        if method == Method::POST && path.ends_with(":seal") {
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let encoded = path
                .trim_start_matches("/v1/recordings/")
                .trim_end_matches(":seal");
            let recording_id = encoded.replace("%23", "#").replace("%2F", "/");
            let run_final = request["run_final"].as_bool().unwrap();
            if run_final {
                state.final_seals += 1;
                assert!(request.get("manifest").is_some());
                assert!(request.get("manifest_sha256").is_some());
            } else {
                assert!(request.get("manifest").is_none());
                assert!(request.get("manifest_sha256").is_none());
            }
            let recording = state.recordings.get_mut(&recording_id).unwrap();
            recording.final_seq = request["final_seq"].as_u64();
            recording.sealed = true;
            return json_response(StatusCode::OK, serde_json::json!({"state":"sealed"}));
        }
        if method == Method::POST && path.ends_with(":heartbeat") {
            state.heartbeats += 1;
            return json_response(StatusCode::OK, serde_json::json!({"config_version":0}));
        }
        StatusCode::NOT_FOUND.into_response()
    }

    #[tokio::test]
    async fn active_flush_appends_immutable_boundaries_then_final_upload_seals() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "run-active-upload";
        let run = temporary.path().join(run_id);
        let manifest = Manifest::new(
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
            CapturePolicy::default(),
        );
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, CapturePolicy::default()).unwrap();

        let token = temporary.path().join("token");
        fs::write(&token, b"iorp_project_token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockPlatformState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_platform))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let options = UploadOptions {
            api: Url::parse(&format!("http://{address}")).unwrap(),
            token_file: token,
            encryption_key: None,
            allow_http: true,
            retry_for: Duration::ZERO,
            max_batches: None,
            collector_id: None,
        };

        store.append(store.event("test", "first")).await.unwrap();
        let first_boundary = store.durable_boundary().await.unwrap().events;
        let first = flush_active_run(&run, first_boundary, &options)
            .await
            .unwrap();
        assert_eq!(first.acked_seq, 1);
        assert!(!first.sealed);

        store.append(store.event("test", "second")).await.unwrap();
        let second_boundary = store.durable_boundary().await.unwrap().events;
        let second = flush_active_run(&run, second_boundary, &options)
            .await
            .unwrap();
        assert_eq!(second.resumed_from_seq, 1);
        assert_eq!(second.acked_seq, 2);
        assert!(!second.sealed);
        {
            let state = mock.lock().await;
            let recording = &state.recordings[&recording_id(run_id)];
            assert_eq!(recording.batches, BTreeSet::from([(1, 1), (2, 2)]));
            assert!(!recording.sealed);
        }

        store.shutdown().await.unwrap();
        finalize_manifest(&run, 0, 0, None).unwrap();
        let finalized = upload_run(&run, &options).await.unwrap();
        assert_eq!(finalized.acked_seq, 2);
        assert!(finalized.sealed);
        let state = mock.lock().await;
        assert_eq!(state.batch_uploads, 2);
        let recording = &state.recordings[&recording_id(run_id)];
        assert_eq!(recording.batches, BTreeSet::from([(1, 1), (2, 2)]));
        assert!(recording.sealed);
        drop(state);
        server.abort();
    }

    #[tokio::test]
    async fn active_seals_form_a_contiguous_resumable_segment_chain() {
        let temporary = tempfile::tempdir().unwrap();
        let run_id = "run-active-segments";
        let run = temporary.path().join(run_id);
        let manifest = Manifest::new(
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
            CapturePolicy::default(),
        );
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, CapturePolicy::default()).unwrap();
        let token = temporary.path().join("token");
        fs::write(&token, b"iorp_project_token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockPlatformState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_platform))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let options = UploadOptions {
            api: Url::parse(&format!("http://{address}")).unwrap(),
            token_file: token,
            encryption_key: None,
            allow_http: true,
            retry_for: Duration::ZERO,
            max_batches: None,
            collector_id: None,
        };

        store.append(store.event("test", "first")).await.unwrap();
        let first_boundary = store.durable_boundary().await.unwrap().events;
        assert!(
            active_segment_roll_due(
                &run,
                first_boundary,
                &options.api,
                true,
                None,
                1,
                Duration::from_secs(3600),
            )
            .unwrap()
        );
        let first = seal_active_run(&run, first_boundary, &options)
            .await
            .unwrap();
        assert_eq!(first.recording_id, recording_id_for_segment(run_id, 0));
        assert!(first.sealed);
        let repeated = seal_active_run(&run, first_boundary, &options)
            .await
            .unwrap();
        assert_eq!(repeated.recording_id, first.recording_id);
        assert!(repeated.sealed);
        assert!(
            !active_segment_roll_due(
                &run,
                first_boundary,
                &options.api,
                true,
                None,
                1,
                Duration::from_nanos(1),
            )
            .unwrap()
        );

        // Simulate a crash after the remote seal but before the local sealed
        // flag became durable. The next flush must reconcile segment 0 and
        // continue in segment 1 without extending the sealed batch plan.
        let origin = canonical_origin(&options.api);
        let spool = run.join(".upload");
        let first_state_path = segment_state_path(&spool, &origin, 0);
        let bytes = read_regular_limited(&first_state_path, MAX_STATE_BYTES).unwrap();
        let mut first_state: UploadState = serde_json::from_slice(&bytes).unwrap();
        first_state.sealed = false;
        write_state(&first_state_path, &first_state).unwrap();

        store.append(store.event("test", "second")).await.unwrap();
        let second_boundary = store.durable_boundary().await.unwrap().events;
        assert!(
            active_segment_roll_due(
                &run,
                second_boundary,
                &options.api,
                true,
                None,
                u64::MAX,
                Duration::from_nanos(1),
            )
            .unwrap()
        );
        let second = flush_active_run(&run, second_boundary, &options)
            .await
            .unwrap();
        assert_eq!(second.recording_id, recording_id_for_segment(run_id, 1));
        assert_eq!(second.resumed_from_seq, 1);
        assert_eq!(second.acked_seq, 2);
        assert!(!second.sealed);
        let second_seal = seal_active_run(&run, second_boundary, &options)
            .await
            .unwrap();
        assert!(second_seal.sealed);
        let recovered_first = seal_active_run_for(
            &run,
            first_boundary,
            &recording_id_for_segment(run_id, 0),
            &options,
        )
        .await
        .unwrap();
        assert_eq!(
            recovered_first.recording_id,
            recording_id_for_segment(run_id, 0)
        );
        assert_eq!(recovered_first.acked_seq, first_boundary);
        assert!(recovered_first.sealed);
        let active_backfill =
            backfill_run(&run, &recording_id_for_segment(run_id, 0), 1, 1, &options)
                .await
                .unwrap();
        assert_eq!(active_backfill.batches_resent, 1);

        store.append(store.event("test", "third")).await.unwrap();
        let third_boundary = store.durable_boundary().await.unwrap().events;
        let third = flush_active_run(&run, third_boundary, &options)
            .await
            .unwrap();
        assert_eq!(third.recording_id, recording_id_for_segment(run_id, 2));
        assert_eq!(third.acked_seq, 3);
        store.shutdown().await.unwrap();
        finalize_manifest(&run, 0, 0, None).unwrap();
        let finalized = upload_run(&run, &options).await.unwrap();
        assert_eq!(finalized.recording_id, third.recording_id);
        assert!(finalized.sealed);

        {
            let state = mock.lock().await;
            assert_eq!(state.recordings.len(), 3);
            for segment_no in 0..3 {
                let id = recording_id_for_segment(run_id, segment_no);
                let recording = &state.recordings[&id];
                assert_eq!(recording.segment_no, segment_no);
                assert_eq!(recording.sequence_base, u64::from(segment_no));
                assert_eq!(
                    recording.batches,
                    BTreeSet::from([(u64::from(segment_no) + 1, u64::from(segment_no) + 1)])
                );
                assert!(recording.sealed);
            }
            assert_eq!(state.final_seals, 1);
        }
        assert!(upload_complete_for(&run, &options.api, true, None).unwrap());
        verify_retention_gate(&run, run_id, 3).unwrap();
        let backfill = backfill_run(&run, &recording_id_for_segment(run_id, 1), 2, 2, &options)
            .await
            .unwrap();
        assert_eq!(backfill.recording_id, recording_id_for_segment(run_id, 1));
        assert_eq!(backfill.batches_resent, 1);

        let origin = canonical_origin(&options.api);
        let spool = run.join(".upload");
        let middle_path = segment_state_path(&spool, &origin, 1);
        let held_path = spool.join("held-segment-0001");
        fs::rename(&middle_path, &held_path).unwrap();
        assert!(upload_complete_for(&run, &options.api, true, None).is_err());
        fs::rename(&held_path, &middle_path).unwrap();
        let bytes = read_regular_limited(&middle_path, MAX_STATE_BYTES).unwrap();
        let mut middle: UploadState = serde_json::from_slice(&bytes).unwrap();
        middle.sealed = false;
        write_state(&middle_path, &middle).unwrap();
        assert!(upload_complete_for(&run, &options.api, true, None).is_err());
        middle.sealed = true;
        write_state(&middle_path, &middle).unwrap();
        assert!(upload_complete_for(&run, &options.api, true, None).unwrap());
        server.abort();
    }

    #[tokio::test]
    async fn uploader_uses_remote_durable_sequence_on_idempotent_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let run_id = "run-upload-http-e2e";
        let run = runs.join(run_id);
        let manifest = Manifest::new(
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
            CapturePolicy::default(),
        );
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, CapturePolicy::default()).unwrap();
        let raw = store
            .store_blob(b"payload", Some("text/plain"))
            .await
            .unwrap();
        let mut event = store.event("proxy", "request_body_chunk");
        event.raw = Some(raw);
        store.append(event).await.unwrap();
        store.shutdown().await.unwrap();
        finalize_manifest(&run, 0, 0, None).unwrap();

        let token = temporary.path().join("token");
        fs::write(&token, b"iorp_project_token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockPlatformState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_platform))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let options = UploadOptions {
            api: Url::parse(&format!("http://{address}")).unwrap(),
            token_file: token,
            encryption_key: None,
            allow_http: true,
            retry_for: Duration::ZERO,
            max_batches: None,
            collector_id: None,
        };

        let first = upload_run(&run, &options).await.unwrap();
        assert_eq!(first.resumed_from_seq, 0);
        assert!(first.sealed);
        let second = upload_run(&run, &options).await.unwrap();
        assert_eq!(second.resumed_from_seq, 1);
        assert!(second.sealed);
        let backfill = backfill_run(&run, &recording_id(run_id), 1, 1, &options)
            .await
            .unwrap();
        assert_eq!(backfill.batches_resent, 1);
        assert_eq!(backfill.resent_first_seq, 1);
        assert_eq!(backfill.resent_last_seq, 1);
        let state = mock.lock().await;
        assert_eq!(state.recordings[&recording_id(run_id)].batches.len(), 1);
        assert_eq!(state.batch_uploads, 2);
        assert_eq!(state.blobs.len(), 1);
        assert_eq!(state.registrations, 3);
        assert_eq!(state.heartbeats, 3);
        drop(state);
        assert!(upload_complete_for(&run, &options.api, true, None).unwrap());
        let request_id = Uuid::now_v7();
        let deleted =
            crate::retention::delete_uploaded_run(&runs, run_id, request_id, None).unwrap();
        assert!(deleted.deleted);
        assert!(!run.exists());
        let repeated =
            crate::retention::delete_uploaded_run(&runs, run_id, request_id, None).unwrap();
        assert!(!repeated.deleted);
        assert!(repeated.recovered);
        assert_eq!(crate::audit::verify(&runs).unwrap().records, 2);
        server.abort();
    }
}
