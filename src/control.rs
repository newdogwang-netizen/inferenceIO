//! Persistent collector control plane.
//!
//! The daemon keeps credentials out of its state file, registers a stable
//! collector identity, reports health, applies bounded configuration only to
//! new runs, uploads finalized runs, and executes crash-recoverable work items.

use std::{
    collections::BTreeSet,
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
use serde_json::{Map, Value, json};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    RECORDER_VERSION, audit,
    blob_keys::BlobClass,
    collector,
    crypto::EncryptionKey,
    doctor,
    inspect::inspect_run_with_key,
    manifest,
    policy::{BodyCaptureMode, CapturePolicy},
    retention::{
        BlobClassTtlPolicy, delete_uploaded_run, erase_blob_class_for_request, expire_blob_classes,
        prune_uploaded_runs,
    },
    secure_fs::{open_regular_create, open_regular_read, read_regular_limited},
    upload::{
        UploadOptions, active_recording_id_at_boundary, active_segment_roll_due, backfill_run,
        canonical_origin, flush_active_run_for, recording_id_for_segment, seal_active_run,
        seal_active_run_for, upload_complete_for, upload_run, validate_api,
    },
};

const CONTROL_DIR: &str = ".iorec-control";
const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = "collector.lock";
const STATE_SCHEMA_VERSION: u32 = 1;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 2_048;
const MAX_REQUESTS_PER_POLL: usize = 50;
const MAX_RUNS: usize = 100_000;
const MAX_UPLOADS_PER_CYCLE: usize = 32;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_CONFIG_SECTIONS: usize = 32;
const MAX_REDACT_FIELDS: usize = 1_024;
const MAX_REASON_BYTES: usize = 2 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MIN_SESSION_REMAINING: chrono::TimeDelta = chrono::TimeDelta::minutes(2);
const DEFAULT_BATCH_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_BATCH_AGE_MS: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct CollectorOptions {
    pub api: Url,
    pub token_file: PathBuf,
    pub runs_dir: PathBuf,
    pub encryption_key: Option<EncryptionKey>,
    pub allow_http: bool,
    pub allow_remote_delete: bool,
    pub retry_for: Duration,
    pub poll_wait: Duration,
    pub local_max_body_bytes: u64,
    pub segment_max_logical_bytes: u64,
    pub segment_max_age: Duration,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CollectorReport {
    pub collector_id: Option<Uuid>,
    pub cycles: u64,
    pub uploaded_runs: u64,
    pub processed_requests: u64,
    pub deleted_runs: u64,
    pub erased_blob_classes: u64,
    pub paused: bool,
    pub config_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectorState {
    schema_version: u32,
    api_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collector_id: Option<Uuid>,
    config_version: i64,
    effective_config: Value,
    rejected_config: Value,
    paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inflight: Option<InflightRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InflightRequest {
    request: PendingRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation: Option<RequestOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<RequestOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestOperation {
    recording_id: String,
    durable_boundary: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRequest {
    id: Uuid,
    #[serde(rename = "type")]
    kind: String,
    payload: Value,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestOutcome {
    status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    reason: String,
    result: Value,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    collector_id: Uuid,
    session_token: String,
    expires_at: DateTime<Utc>,
    config_version: i64,
    config: Value,
}

#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    config_version: i64,
    session_expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    items: Vec<PendingRequest>,
}

#[derive(Debug, Clone, Copy)]
struct LocalPolicy {
    allow_remote_delete: bool,
    class_erasure_enabled: bool,
    max_body_bytes: u64,
}

struct CollectorLock {
    _file: Flock<File>,
}

struct ControlClient {
    origin: Url,
    bootstrap_authorization: HeaderValue,
    authorization: HeaderValue,
    http: reqwest::Client,
    retry_for: Duration,
}

struct CollectorDaemon {
    options: CollectorOptions,
    runs_dir: PathBuf,
    state_path: PathBuf,
    state: CollectorState,
    client: ControlClient,
    session_expires_at: Option<DateTime<Utc>>,
    last_heartbeat: Option<Instant>,
    _lock: CollectorLock,
}

#[derive(Debug, Default)]
struct CycleResult {
    uploaded_runs: u64,
    processed_requests: u64,
    deleted_runs: u64,
    erased_blob_classes: u64,
}

#[derive(Debug, Default)]
struct UploadCycle {
    uploaded: u64,
    session_rotated: bool,
}

#[derive(Debug, Default)]
struct RetentionCycle {
    deleted_runs: u64,
    erased_blob_classes: u64,
}

/// Applies the daemon's last accepted configuration as a restrictive overlay
/// to a newly starting run. Command-line/local policy can always be stricter.
pub fn apply_new_run_config(runs_dir: &Path, policy: &mut CapturePolicy) -> Result<bool> {
    let Some(state) = read_state_for_run(runs_dir)? else {
        return Ok(false);
    };
    let content = state
        .effective_config
        .get("content_policy")
        .and_then(Value::as_object)
        .context("collector effective content policy is missing")?;
    let capture_bodies = content
        .get("capture_bodies")
        .and_then(Value::as_bool)
        .context("collector capture_bodies is invalid")?;
    let maximum = content
        .get("max_body_bytes")
        .and_then(Value::as_u64)
        .context("collector max_body_bytes is invalid")?;
    if !capture_bodies {
        policy.body_mode = BodyCaptureMode::MetadataOnly;
    }
    policy.max_blob_bytes = policy.max_blob_bytes.min(maximum);
    let fields = content
        .get("redact_fields")
        .and_then(Value::as_array)
        .context("collector redact_fields is invalid")?;
    anyhow::ensure!(
        fields.len() <= MAX_REDACT_FIELDS,
        "collector redact field limit exceeded"
    );
    for field in fields {
        let field = field
            .as_str()
            .context("collector redaction field is not a string")?;
        validate_header_name(field)?;
        policy.redact_headers.insert(field.to_owned());
    }
    policy.validate().map_err(anyhow::Error::msg)?;
    Ok(true)
}

fn read_state_for_run(runs_dir: &Path) -> Result<Option<CollectorState>> {
    let control_dir = runs_dir.join(CONTROL_DIR);
    let metadata = match fs::symlink_metadata(&control_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "collector control path is not a real directory"
    );
    let exposed_permission_bits = metadata.permissions().mode() & 0o077;
    anyhow::ensure!(
        exposed_permission_bits == 0,
        "collector control directory must not be accessible by group or other users"
    );
    let state_path = control_dir.join(STATE_FILE);
    if !state_path.try_exists()? {
        return Ok(None);
    }
    let state = read_state(&state_path)?;
    validate_state(&state)?;
    Ok(Some(state))
}

fn default_effective_config(max_body_bytes: u64) -> Value {
    let defaults = CapturePolicy::default();
    json!({
        "content_policy": {
            "capture_bodies": true,
            "max_body_bytes": max_body_bytes,
            "redact_fields": defaults.redact_headers,
            "pty": false,
        },
        "upload": {
            "batch_max_bytes": DEFAULT_BATCH_BYTES,
            "batch_max_age_ms": DEFAULT_BATCH_AGE_MS,
        },
        "sensitive_tier_upload": {"pcap": false, "tls_keys": false},
        "retention_local": {"remote_delete": false},
    })
}

fn merge_remote_config(config: &Value, policy: LocalPolicy) -> Result<(Value, Value)> {
    let encoded = serde_json::to_vec(config)?;
    anyhow::ensure!(
        encoded.len() <= MAX_CONFIG_BYTES,
        "platform collector configuration exceeds safety limit"
    );
    crate::input::validate_json_complexity(&encoded)?;
    let sections = config
        .as_object()
        .context("platform collector configuration is not an object")?;
    anyhow::ensure!(
        sections.len() <= MAX_CONFIG_SECTIONS,
        "platform collector configuration has too many sections"
    );
    let mut effective = default_effective_config(policy.max_body_bytes);
    let mut rejected = Map::new();
    if let Some(content) = sections.get("content_policy") {
        merge_content_policy(content, policy, &mut effective, &mut rejected);
    }
    if let Some(upload) = sections.get("upload") {
        reject_unsupported_upload(upload, &mut rejected);
    }
    if let Some(sensitive) = sections.get("sensitive_tier_upload") {
        if sensitive.is_object() {
            rejected.insert(
                "sensitive_tier_upload".to_owned(),
                json!({"reason": "sensitive evidence remains disabled by local policy"}),
            );
        } else {
            rejected.insert(
                "sensitive_tier_upload".to_owned(),
                json!({"reason": "section is not an object"}),
            );
        }
    }
    if let Some(retention) = sections.get("retention_local") {
        merge_retention_policy(retention, policy, &mut effective, &mut rejected);
    }
    if sections.contains_key("egress_classification") {
        rejected.insert(
            "egress_classification".to_owned(),
            json!({"reason": "remote hostname classification is not applied without exact local socket policy"}),
        );
    }
    for name in sections.keys() {
        if ![
            "content_policy",
            "upload",
            "sensitive_tier_upload",
            "retention_local",
            "egress_classification",
            "scope",
            "config_version",
        ]
        .contains(&name.as_str())
        {
            rejected.insert(
                name.clone(),
                json!({"reason": "unknown configuration section"}),
            );
        }
    }
    Ok((effective, Value::Object(rejected)))
}

fn merge_content_policy(
    value: &Value,
    policy: LocalPolicy,
    effective: &mut Value,
    rejected: &mut Map<String, Value>,
) {
    let Some(content) = value.as_object() else {
        rejected.insert(
            "content_policy".to_owned(),
            json!({"reason": "section is not an object"}),
        );
        return;
    };
    let target = effective
        .get_mut("content_policy")
        .and_then(Value::as_object_mut)
        .expect("default content policy is an object");
    if let Some(value) = content.get("capture_bodies") {
        if let Some(enabled) = value.as_bool() {
            target.insert("capture_bodies".to_owned(), Value::Bool(enabled));
        } else {
            rejected.insert(
                "content_policy.capture_bodies".to_owned(),
                json!({"reason": "value is not a boolean"}),
            );
        }
    }
    if let Some(value) = content.get("max_body_bytes") {
        if let Some(maximum) = value.as_u64().filter(|value| *value > 0) {
            let bounded = maximum.min(policy.max_body_bytes);
            target.insert("max_body_bytes".to_owned(), json!(bounded));
            if bounded != maximum {
                rejected.insert(
                    "content_policy.max_body_bytes".to_owned(),
                    json!({"reason": "local maximum takes precedence", "effective": bounded}),
                );
            }
        } else {
            rejected.insert(
                "content_policy.max_body_bytes".to_owned(),
                json!({"reason": "value must be a positive integer"}),
            );
        }
    }
    if let Some(value) = content.get("redact_fields") {
        match parse_redact_fields(value) {
            Ok(fields) => {
                let mut merged = CapturePolicy::default().redact_headers;
                merged.extend(fields);
                target.insert("redact_fields".to_owned(), json!(merged));
            }
            Err(error) => {
                rejected.insert(
                    "content_policy.redact_fields".to_owned(),
                    json!({"reason": error.to_string()}),
                );
            }
        }
    }
    if content
        .get("pty")
        .is_some_and(|value| value != &Value::Bool(false))
    {
        rejected.insert(
            "content_policy.pty".to_owned(),
            json!({"reason": "PTY capture is disabled by local policy", "effective": false}),
        );
    }
    for name in content.keys() {
        if !["capture_bodies", "max_body_bytes", "redact_fields", "pty"].contains(&name.as_str()) {
            rejected.insert(
                format!("content_policy.{name}"),
                json!({"reason": "unknown content policy field"}),
            );
        }
    }
}

fn parse_redact_fields(value: &Value) -> Result<BTreeSet<String>> {
    let fields = value.as_array().context("value is not an array")?;
    anyhow::ensure!(
        fields.len() <= MAX_REDACT_FIELDS,
        "redaction field limit exceeded"
    );
    let mut output = BTreeSet::new();
    for value in fields {
        let name = value
            .as_str()
            .context("redaction field is not a string")?
            .to_ascii_lowercase();
        validate_header_name(&name)?;
        output.insert(name);
    }
    Ok(output)
}

fn validate_header_name(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 256
            && name.bytes().all(|byte| !byte.is_ascii_uppercase())
            && http::header::HeaderName::from_bytes(name.as_bytes()).is_ok(),
        "invalid HTTP header name"
    );
    Ok(())
}

fn reject_unsupported_upload(value: &Value, rejected: &mut Map<String, Value>) {
    let Some(upload) = value.as_object() else {
        rejected.insert(
            "upload".to_owned(),
            json!({"reason": "section is not an object"}),
        );
        return;
    };
    for (name, value) in upload {
        match name.as_str() {
            "batch_max_bytes" if value.as_u64() == Some(DEFAULT_BATCH_BYTES) => {}
            "batch_max_age_ms" if value.as_u64() == Some(DEFAULT_BATCH_AGE_MS) => {}
            _ => {
                rejected.insert(
                    format!("upload.{name}"),
                    json!({"reason": "fixed crash-safe local upload policy takes precedence"}),
                );
            }
        }
    }
}

fn merge_retention_policy(
    value: &Value,
    policy: LocalPolicy,
    effective: &mut Value,
    rejected: &mut Map<String, Value>,
) {
    let Some(retention) = value.as_object() else {
        rejected.insert(
            "retention_local".to_owned(),
            json!({"reason": "section is not an object"}),
        );
        return;
    };
    for (name, requires_class_keys) in [
        ("acked_events_ttl_hours", false),
        ("body_ttl_hours", true),
        ("pcap_ttl_hours", true),
        ("tls_secrets_ttl_hours", true),
    ] {
        let Some(value) = retention.get(name) else {
            continue;
        };
        let setting = format!("retention_local.{name}");
        let Some(hours) = value.as_u64().filter(|hours| (1..=8_760).contains(hours)) else {
            rejected.insert(
                setting,
                json!({"reason": "TTL must be an integer from 1 through 8760 hours"}),
            );
            continue;
        };
        let rejection = if !policy.allow_remote_delete {
            Some("remote deletion is disabled by local policy")
        } else if requires_class_keys && !policy.class_erasure_enabled {
            Some("class TTL requires a local encryption key")
        } else {
            None
        };
        if let Some(reason) = rejection {
            rejected.insert(setting, json!({"reason": reason}));
        } else {
            effective["retention_local"][name] = json!(hours);
            effective["retention_local"]["remote_delete"] = Value::Bool(true);
        }
    }
    for name in retention.keys() {
        if ![
            "acked_events_ttl_hours",
            "body_ttl_hours",
            "pcap_ttl_hours",
            "tls_secrets_ttl_hours",
        ]
        .contains(&name.as_str())
        {
            rejected.insert(
                format!("retention_local.{name}"),
                json!({"reason": "local spool safety policy takes precedence"}),
            );
        }
    }
}

/// Runs a collector until Ctrl-C. Connectivity failures are recorded and
/// retried without affecting local capture; `once` is a deterministic
/// scheduler/test mode that performs exactly one cycle and returns errors.
pub async fn run_collector(options: CollectorOptions, once: bool) -> Result<CollectorReport> {
    let mut daemon = CollectorDaemon::open(options)?;
    let mut report = CollectorReport::default();
    if once {
        let cycle = daemon.cycle(Duration::ZERO).await?;
        update_report(&mut report, &daemon, &cycle);
        return Ok(report);
    }

    loop {
        let cycle = tokio::select! {
            result = daemon.cycle(daemon.options.poll_wait) => Some(result),
            signal = tokio::signal::ctrl_c() => {
                signal.context("install collector shutdown signal")?;
                None
            }
        };
        let Some(cycle) = cycle else {
            update_report(&mut report, &daemon, &CycleResult::default());
            return Ok(report);
        };
        match cycle {
            Ok(cycle) => {
                update_report(&mut report, &daemon, &cycle);
            }
            Err(error) => {
                let summary = bounded_error(&error);
                tracing::warn!(error = %summary, "collector cycle failed; local capture remains available");
                daemon.state.last_error = Some(summary);
                daemon.state.updated_at = Utc::now();
                daemon.persist_state()?;
                daemon.invalidate_session();
                let delay = Duration::from_secs(5);
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    signal = tokio::signal::ctrl_c() => {
                        signal.context("install collector shutdown signal")?;
                        update_report(&mut report, &daemon, &CycleResult::default());
                        return Ok(report);
                    }
                }
            }
        }
    }
}

fn update_report(report: &mut CollectorReport, daemon: &CollectorDaemon, cycle: &CycleResult) {
    report.collector_id = daemon.state.collector_id;
    report.cycles = report.cycles.saturating_add(1);
    report.uploaded_runs = report.uploaded_runs.saturating_add(cycle.uploaded_runs);
    report.processed_requests = report
        .processed_requests
        .saturating_add(cycle.processed_requests);
    report.deleted_runs = report.deleted_runs.saturating_add(cycle.deleted_runs);
    report.erased_blob_classes = report
        .erased_blob_classes
        .saturating_add(cycle.erased_blob_classes);
    report.paused = daemon.state.paused;
    report.config_version = daemon.state.config_version;
}

impl CollectorDaemon {
    fn open(options: CollectorOptions) -> Result<Self> {
        validate_api(&options.api, options.allow_http)?;
        anyhow::ensure!(
            options.poll_wait <= Duration::from_secs(60),
            "collector poll wait exceeds 60 seconds"
        );
        anyhow::ensure!(
            options.local_max_body_bytes
                <= u64::try_from(crate::policy::MAX_CAPTURE_BODY_BYTES).unwrap_or(u64::MAX),
            "collector local body limit exceeds the writer limit"
        );
        anyhow::ensure!(
            options.segment_max_logical_bytes > 0,
            "collector recording segment byte limit is zero"
        );
        anyhow::ensure!(
            !options.segment_max_age.is_zero()
                && options.segment_max_age <= Duration::from_secs(24 * 60 * 60),
            "collector recording segment age must be between one second and 24 hours"
        );
        let (runs_dir, control_dir) = prepare_control_dir(&options.runs_dir)?;
        let lock = lock_collector(&control_dir)?;
        let state_path = control_dir.join(STATE_FILE);
        let origin = canonical_origin(&options.api);
        let state = if state_path.try_exists()? {
            let state = read_state(&state_path)?;
            validate_state(&state)?;
            anyhow::ensure!(
                state.api_origin == origin,
                "collector state belongs to a different platform origin"
            );
            state
        } else {
            CollectorState {
                schema_version: STATE_SCHEMA_VERSION,
                api_origin: origin,
                collector_id: None,
                config_version: 0,
                effective_config: default_effective_config(options.local_max_body_bytes),
                rejected_config: json!({}),
                paused: false,
                inflight: None,
                last_error: None,
                updated_at: Utc::now(),
            }
        };
        let token = read_token(&options.token_file)?;
        let client = ControlClient::new(options.api.clone(), &token, options.retry_for)?;
        drop(token);
        let daemon = Self {
            options,
            runs_dir,
            state_path,
            state,
            client,
            session_expires_at: None,
            last_heartbeat: None,
            _lock: lock,
        };
        daemon.persist_state()?;
        Ok(daemon)
    }

    async fn cycle(&mut self, poll_wait: Duration) -> Result<CycleResult> {
        self.ensure_registered().await?;
        self.state.last_error = None;
        let mut cycle = CycleResult::default();
        cycle.deleted_runs = cycle
            .deleted_runs
            .saturating_add(u64::from(self.resume_inflight().await?));

        if !self.state.paused {
            let uploads = self.upload_finalized_runs().await?;
            cycle.uploaded_runs = uploads.uploaded;
            if uploads.session_rotated {
                self.invalidate_session();
                self.ensure_registered().await?;
            }
            let rolls = self.roll_active_runs().await?;
            if rolls.session_rotated {
                self.invalidate_session();
                self.ensure_registered().await?;
            }
        }
        let retention = self.apply_retention_ttl()?;
        cycle.deleted_runs = cycle.deleted_runs.saturating_add(retention.deleted_runs);
        cycle.erased_blob_classes = cycle
            .erased_blob_classes
            .saturating_add(retention.erased_blob_classes);
        self.heartbeat().await?;

        let requests = self.client.poll(poll_wait).await?;
        anyhow::ensure!(
            requests.len() <= MAX_REQUESTS_PER_POLL,
            "platform returned too many collector requests"
        );
        for request in requests {
            let deleted = self.process_request(request).await?;
            cycle.processed_requests = cycle.processed_requests.saturating_add(1);
            cycle.deleted_runs = cycle.deleted_runs.saturating_add(u64::from(deleted));
        }
        if self
            .last_heartbeat
            .is_none_or(|last| last.elapsed() >= HEARTBEAT_INTERVAL)
        {
            self.ensure_registered().await?;
            self.heartbeat().await?;
        }
        Ok(cycle)
    }

    async fn ensure_registered(&mut self) -> Result<()> {
        if self
            .session_expires_at
            .is_some_and(|expires| expires > Utc::now() + MIN_SESSION_REMAINING)
        {
            return Ok(());
        }
        let capabilities = collector_capabilities(&self.options);
        let registration = self
            .client
            .register(self.state.collector_id, capabilities)
            .await?;
        anyhow::ensure!(
            !registration.collector_id.is_nil(),
            "platform returned a nil collector ID"
        );
        anyhow::ensure!(
            registration.config_version >= self.state.config_version,
            "platform collector configuration version moved backwards"
        );
        anyhow::ensure!(
            registration.expires_at > Utc::now(),
            "platform returned an expired collector session"
        );
        let local = LocalPolicy {
            allow_remote_delete: self.options.allow_remote_delete,
            class_erasure_enabled: self.options.encryption_key.is_some(),
            max_body_bytes: self.options.local_max_body_bytes,
        };
        let (effective, rejected) = merge_remote_config(&registration.config, local)?;
        self.state.collector_id = Some(registration.collector_id);
        self.state.config_version = registration.config_version;
        self.state.effective_config = effective;
        self.state.rejected_config = rejected;
        self.state.updated_at = Utc::now();
        self.session_expires_at = Some(registration.expires_at);
        self.persist_state()
    }

    fn invalidate_session(&mut self) {
        self.session_expires_at = None;
        self.client.use_bootstrap_authorization();
    }

    async fn heartbeat(&mut self) -> Result<()> {
        let collector_id = self
            .state
            .collector_id
            .context("collector is not registered")?;
        let health = scan_health(
            &self.runs_dir,
            &self.options.api,
            self.options.allow_http,
            self.options.encryption_key.as_ref(),
        )?;
        let body = json!({
            "status": if self.state.last_error.is_some() || health.errors > 0 { "degraded" } else { "healthy" },
            "active_runs": health.active_runs,
            "spool_bytes_used": health.spool_bytes,
            "acked_lag_seconds": health.acked_lag_seconds,
            "last_error": self.state.last_error,
            "config_version": self.state.config_version,
            "effective_config": self.state.effective_config,
            "rejected": self.state.rejected_config,
            "capabilities": collector_capabilities(&self.options),
        });
        let response = self.client.heartbeat(collector_id, body).await?;
        anyhow::ensure!(
            response.config_version >= self.state.config_version,
            "platform heartbeat returned a stale configuration version"
        );
        anyhow::ensure!(
            response.session_expires_at > Utc::now(),
            "platform heartbeat returned an expired collector session"
        );
        self.session_expires_at = Some(response.session_expires_at);
        self.last_heartbeat = Some(Instant::now());
        if response.config_version > self.state.config_version {
            self.invalidate_session();
            self.ensure_registered().await?;
        }
        Ok(())
    }

    async fn upload_finalized_runs(&mut self) -> Result<UploadCycle> {
        let runs = finalized_runs(&self.runs_dir)?;
        let mut cycle = UploadCycle::default();
        let mut first_error = None;
        for run in runs {
            if cycle.uploaded >= u64::try_from(MAX_UPLOADS_PER_CYCLE).unwrap_or(u64::MAX) {
                break;
            }
            let complete = upload_complete_for(
                &run,
                &self.options.api,
                self.options.allow_http,
                self.options.encryption_key.as_ref(),
            );
            match complete {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert_with(|| bounded_error(&error));
                    continue;
                }
            }
            let local_manifest = match manifest::read(&run.join("manifest.json")) {
                Ok(manifest) => manifest,
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    first_error.get_or_insert_with(|| bounded_error(&error));
                    continue;
                }
            };
            let run_id = local_manifest.run_id;
            audit::append(
                &self.runs_dir,
                "daemon_upload",
                "intent",
                &run_id,
                Some(json!({"api_origin": self.state.api_origin})),
            )?;
            let result = upload_run(
                &run,
                &UploadOptions {
                    api: self.options.api.clone(),
                    token_file: self.options.token_file.clone(),
                    encryption_key: self.options.encryption_key.clone(),
                    allow_http: self.options.allow_http,
                    retry_for: self.options.retry_for,
                    max_batches: None,
                    collector_id: self.state.collector_id,
                },
            )
            .await;
            // Upload registration rotates the platform's one active collector
            // session even when a later batch or seal operation fails.
            cycle.session_rotated = true;
            let report = match result {
                Ok(report) => report,
                Err(error) => {
                    audit::append(&self.runs_dir, "daemon_upload", "failed", &run_id, None)?;
                    first_error.get_or_insert_with(|| bounded_error(&error));
                    continue;
                }
            };
            if !report.sealed {
                audit::append(&self.runs_dir, "daemon_upload", "failed", &run_id, None)?;
                first_error
                    .get_or_insert_with(|| "daemon upload did not seal the recording".to_owned());
                continue;
            }
            audit::append(
                &self.runs_dir,
                "daemon_upload",
                "complete",
                &run_id,
                Some(json!({
                    "recording_id": report.recording_id,
                    "acked_seq": report.acked_seq,
                })),
            )?;
            cycle.uploaded = cycle.uploaded.saturating_add(1);
        }
        self.state.last_error = first_error;
        self.state.updated_at = Utc::now();
        self.persist_state()?;
        Ok(cycle)
    }

    async fn roll_active_runs(&mut self) -> Result<UploadCycle> {
        let runs = active_runs(&self.runs_dir)?;
        let mut cycle = UploadCycle::default();
        let mut first_error = None;
        for run in runs.into_iter().take(MAX_UPLOADS_PER_CYCLE) {
            let local_manifest = match manifest::read(&run.join("manifest.json")) {
                Ok(manifest) => manifest,
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    first_error.get_or_insert_with(|| bounded_error(&error));
                    continue;
                }
            };
            let run_id = local_manifest.run_id;
            let durable_boundary =
                match collector::request_flush_boundary(&run.join("collector.sock")).await {
                    Ok(boundary) => boundary,
                    Err(error) => {
                        let error = anyhow::Error::from(error);
                        first_error.get_or_insert_with(|| bounded_error(&error));
                        continue;
                    }
                };
            let due = match active_segment_roll_due(
                &run,
                durable_boundary,
                &self.options.api,
                self.options.allow_http,
                self.options.encryption_key.as_ref(),
                self.options.segment_max_logical_bytes,
                self.options.segment_max_age,
            ) {
                Ok(due) => due,
                Err(error) => {
                    first_error.get_or_insert_with(|| bounded_error(&error));
                    continue;
                }
            };
            if !due {
                continue;
            }
            audit::append(
                &self.runs_dir,
                "daemon_segment_roll",
                "intent",
                &run_id,
                Some(json!({"durable_boundary": durable_boundary})),
            )?;
            let result = seal_active_run(
                &run,
                durable_boundary,
                &UploadOptions {
                    api: self.options.api.clone(),
                    token_file: self.options.token_file.clone(),
                    encryption_key: self.options.encryption_key.clone(),
                    allow_http: self.options.allow_http,
                    retry_for: self.options.retry_for,
                    max_batches: None,
                    collector_id: self.state.collector_id,
                },
            )
            .await;
            cycle.session_rotated = true;
            match result {
                Ok(report) if report.sealed && report.acked_seq == durable_boundary => {
                    audit::append(
                        &self.runs_dir,
                        "daemon_segment_roll",
                        "complete",
                        &run_id,
                        Some(json!({
                            "recording_id": report.recording_id,
                            "acked_seq": report.acked_seq,
                        })),
                    )?;
                    cycle.uploaded = cycle.uploaded.saturating_add(1);
                }
                Ok(_) => {
                    audit::append(
                        &self.runs_dir,
                        "daemon_segment_roll",
                        "failed",
                        &run_id,
                        None,
                    )?;
                    first_error.get_or_insert_with(|| {
                        "active recording segment roll did not seal its durable boundary".to_owned()
                    });
                }
                Err(error) => {
                    audit::append(
                        &self.runs_dir,
                        "daemon_segment_roll",
                        "failed",
                        &run_id,
                        None,
                    )?;
                    first_error.get_or_insert_with(|| bounded_error(&error));
                }
            }
        }
        if first_error.is_some() {
            self.state.last_error = first_error;
            self.state.updated_at = Utc::now();
            self.persist_state()?;
        }
        Ok(cycle)
    }

    fn apply_retention_ttl(&self) -> Result<RetentionCycle> {
        if !self.options.allow_remote_delete {
            return Ok(RetentionCycle::default());
        }
        let whole_run_hours = self
            .state
            .effective_config
            .pointer("/retention_local/acked_events_ttl_hours")
            .and_then(Value::as_u64);
        let class_hours = |name: &str| {
            self.state
                .effective_config
                .pointer(&format!("/retention_local/{name}"))
                .and_then(Value::as_u64)
        };
        let duration = |hours: Option<u64>| -> Result<Option<Duration>> {
            hours
                .map(|hours| {
                    hours
                        .checked_mul(3_600)
                        .map(Duration::from_secs)
                        .context("retention TTL is too large")
                })
                .transpose()
        };
        let class_policy = BlobClassTtlPolicy {
            body: duration(class_hours("body_ttl_hours"))?,
            pcap: duration(class_hours("pcap_ttl_hours"))?,
            tls_secrets: duration(class_hours("tls_secrets_ttl_hours"))?,
        };
        let mut cycle = RetentionCycle::default();
        if class_policy.body.is_some()
            || class_policy.pcap.is_some()
            || class_policy.tls_secrets.is_some()
        {
            let key = self
                .options
                .encryption_key
                .as_ref()
                .context("accepted class TTL has no local encryption key")?;
            let report = expire_blob_classes(&self.runs_dir, Utc::now(), class_policy, true, key)?;
            let unexpected: Vec<_> = report
                .skipped
                .iter()
                .filter(|skip| {
                    !skip
                        .reason
                        .contains("does not support independent class erasure")
                })
                .collect();
            anyhow::ensure!(
                unexpected.is_empty(),
                "class TTL failed for {} run or class entries; first error: {}",
                unexpected.len(),
                unexpected
                    .first()
                    .map_or("none", |skip| skip.reason.as_str())
            );
            cycle.erased_blob_classes = u64::try_from(report.erased.len()).unwrap_or(u64::MAX);
        }
        if let Some(hours) = whole_run_hours {
            let hours = i64::try_from(hours).context("retention TTL is too large")?;
            let cutoff = Utc::now() - chrono::TimeDelta::hours(hours);
            let report = prune_uploaded_runs(
                &self.runs_dir,
                cutoff,
                true,
                self.options.encryption_key.as_ref(),
            )?;
            cycle.deleted_runs = report.deleted;
        }
        Ok(cycle)
    }

    fn persist_state(&self) -> Result<()> {
        validate_state(&self.state)?;
        write_state(&self.state_path, &self.state)
    }
}

#[derive(Debug, Default)]
struct HealthSnapshot {
    active_runs: u64,
    spool_bytes: u64,
    acked_lag_seconds: f64,
    errors: u64,
}

fn scan_health(
    runs_dir: &Path,
    api: &Url,
    allow_http: bool,
    encryption_key: Option<&EncryptionKey>,
) -> Result<HealthSnapshot> {
    let mut health = HealthSnapshot::default();
    let mut seen = 0_usize;
    for entry in fs::read_dir(runs_dir)? {
        let entry = entry?;
        seen = seen.saturating_add(1);
        anyhow::ensure!(seen <= MAX_RUNS, "runs directory entry limit exceeded");
        let file_type = entry.file_type()?;
        if !file_type.is_dir()
            || file_type.is_symlink()
            || !entry.file_name().to_string_lossy().starts_with("run-")
        {
            continue;
        }
        match manifest::read(&entry.path().join("manifest.json")) {
            Ok(manifest) => {
                health.spool_bytes = health
                    .spool_bytes
                    .saturating_add(manifest.counts.event_storage_bytes)
                    .saturating_add(manifest.counts.blob_storage_bytes);
                if manifest.status == "running" {
                    health.active_runs = health.active_runs.saturating_add(1);
                } else if let Some(finished) = manifest.finished_at {
                    match upload_complete_for(&entry.path(), api, allow_http, encryption_key) {
                        Ok(true) => {}
                        Ok(false) => {
                            let seconds = Utc::now()
                                .signed_duration_since(finished)
                                .num_seconds()
                                .max(0);
                            let lag = f64::from(u32::try_from(seconds).unwrap_or(u32::MAX));
                            health.acked_lag_seconds = health.acked_lag_seconds.max(lag);
                        }
                        Err(_) => health.errors = health.errors.saturating_add(1),
                    }
                }
            }
            Err(_) => health.errors = health.errors.saturating_add(1),
        }
    }
    Ok(health)
}

fn finalized_runs(runs_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut runs = Vec::new();
    let mut seen = 0_usize;
    for entry in fs::read_dir(runs_dir)? {
        let entry = entry?;
        seen = seen.saturating_add(1);
        anyhow::ensure!(seen <= MAX_RUNS, "runs directory entry limit exceeded");
        let file_type = entry.file_type()?;
        if !file_type.is_dir()
            || file_type.is_symlink()
            || !entry.file_name().to_string_lossy().starts_with("run-")
        {
            continue;
        }
        let Ok(manifest) = manifest::read(&entry.path().join("manifest.json")) else {
            continue;
        };
        if manifest.status != "running" && manifest.finished_at.is_some() {
            runs.push(entry.path());
        }
    }
    runs.sort();
    Ok(runs)
}

fn active_runs(runs_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut runs = Vec::new();
    let mut seen = 0_usize;
    for entry in fs::read_dir(runs_dir)? {
        let entry = entry?;
        seen = seen.saturating_add(1);
        anyhow::ensure!(seen <= MAX_RUNS, "runs directory entry limit exceeded");
        let file_type = entry.file_type()?;
        if !file_type.is_dir()
            || file_type.is_symlink()
            || !entry.file_name().to_string_lossy().starts_with("run-")
        {
            continue;
        }
        let Ok(manifest) = manifest::read(&entry.path().join("manifest.json")) else {
            continue;
        };
        if manifest.status == "running" {
            runs.push(entry.path());
        }
    }
    runs.sort();
    Ok(runs)
}

impl CollectorDaemon {
    fn request_operation(&self, request_id: Uuid) -> Result<Option<RequestOperation>> {
        let Some(inflight) = &self.state.inflight else {
            return Ok(None);
        };
        anyhow::ensure!(
            inflight.request.id == request_id,
            "collector inflight request changed during execution"
        );
        Ok(inflight.operation.clone())
    }

    async fn prepare_active_request_operation(
        &mut self,
        request: &PendingRequest,
        run: &Path,
        recording_id: &str,
    ) -> Result<Option<RequestOperation>> {
        if let Some(operation) = self.request_operation(request.id)? {
            anyhow::ensure!(
                operation.recording_id == recording_id,
                "persisted collector operation recording ID mismatch"
            );
            return Ok(Some(operation));
        }
        let durable_boundary = collector::request_flush_boundary(&run.join("collector.sock"))
            .await
            .context("request active-run durable flush boundary")?;
        if active_recording_id_at_boundary(
            run,
            durable_boundary,
            &self.options.api,
            self.options.allow_http,
            self.options.encryption_key.as_ref(),
        )? != recording_id
        {
            return Ok(None);
        }
        let operation = RequestOperation {
            recording_id: recording_id.to_owned(),
            durable_boundary,
        };
        let inflight = self
            .state
            .inflight
            .as_mut()
            .context("collector request is not durably inflight")?;
        anyhow::ensure!(
            inflight.request.id == request.id,
            "collector inflight request changed while preparing operation"
        );
        inflight.operation = Some(operation.clone());
        self.state.updated_at = Utc::now();
        self.persist_state()?;
        Ok(Some(operation))
    }

    async fn resume_inflight(&mut self) -> Result<bool> {
        let Some(inflight) = self.state.inflight.clone() else {
            return Ok(false);
        };
        let (outcome, deleted) = if let Some(outcome) = inflight.terminal {
            (outcome, false)
        } else {
            let (outcome, deleted) = self.execute_request(&inflight.request).await?;
            let current = self
                .state
                .inflight
                .as_mut()
                .context("collector inflight request disappeared during recovery")?;
            anyhow::ensure!(
                current.request.id == inflight.request.id,
                "collector inflight request changed during recovery"
            );
            current.terminal = Some(outcome.clone());
            self.state.updated_at = Utc::now();
            self.persist_state()?;
            (outcome, deleted)
        };
        self.ensure_registered().await?;
        self.client.report(inflight.request.id, &outcome).await?;
        self.audit_request_outcome(&inflight.request, &outcome)?;
        self.state.inflight = None;
        self.state.updated_at = Utc::now();
        self.persist_state()?;
        Ok(deleted)
    }

    async fn process_request(&mut self, request: PendingRequest) -> Result<bool> {
        validate_pending_request(&request)?;
        let accepted = RequestOutcome {
            status: "acked".to_owned(),
            reason: String::new(),
            result: json!({"accepted": true}),
        };
        self.client.report(request.id, &accepted).await?;
        self.state.inflight = Some(InflightRequest {
            request: request.clone(),
            operation: None,
            terminal: None,
        });
        self.state.updated_at = Utc::now();
        self.persist_state()?;

        let (outcome, deleted) = self.execute_request(&request).await?;
        let inflight = self
            .state
            .inflight
            .as_mut()
            .context("collector inflight request disappeared during execution")?;
        anyhow::ensure!(
            inflight.request.id == request.id,
            "collector inflight request changed during execution"
        );
        inflight.terminal = Some(outcome.clone());
        self.state.updated_at = Utc::now();
        self.persist_state()?;
        self.ensure_registered().await?;
        self.client.report(request.id, &outcome).await?;
        self.audit_request_outcome(&request, &outcome)?;
        self.state.inflight = None;
        self.state.updated_at = Utc::now();
        self.persist_state()?;
        Ok(deleted)
    }

    fn audit_request_outcome(
        &self,
        request: &PendingRequest,
        outcome: &RequestOutcome,
    ) -> Result<()> {
        let request_id = request.id.to_string();
        if audit::has_request_record(
            &self.runs_dir,
            "collector_request",
            &outcome.status,
            &request_id,
        )? {
            return Ok(());
        }
        audit::append(
            &self.runs_dir,
            "collector_request",
            &outcome.status,
            request_run_id(request).unwrap_or("collector"),
            Some(json!({
                "request_id": request.id,
                "type": request.kind,
                "reason": outcome.reason,
            })),
        )?;
        Ok(())
    }

    async fn execute_request(
        &mut self,
        request: &PendingRequest,
    ) -> Result<(RequestOutcome, bool)> {
        match request.kind.as_str() {
            "pause" => {
                self.state.paused = true;
                self.persist_state()?;
                Ok((done(json!({"paused": true})), false))
            }
            "resume" => {
                self.state.paused = false;
                self.persist_state()?;
                Ok((done(json!({"paused": false})), false))
            }
            "apply_config" => {
                let requested = request
                    .payload
                    .get("config_version")
                    .and_then(Value::as_i64)
                    .filter(|version| *version >= 0);
                let Some(requested) = requested else {
                    return Ok((rejected("invalid config_version"), false));
                };
                self.invalidate_session();
                self.ensure_registered().await?;
                if self.state.config_version != requested {
                    return Ok((
                        rejected(&format!(
                            "requested configuration version {requested} is unavailable; platform returned {}",
                            self.state.config_version
                        )),
                        false,
                    ));
                }
                Ok((
                    done(json!({
                        "config_version": self.state.config_version,
                        "effective_config": self.state.effective_config,
                        "rejected": self.state.rejected_config,
                    })),
                    false,
                ))
            }
            "flush" | "seal" => {
                if self.state.paused {
                    return Ok((rejected("uploads are paused by collector policy"), false));
                }
                let Some(recording) = payload_recording_id(&request.payload) else {
                    return Ok((rejected("invalid recording_id"), false));
                };
                let Some(run) = find_recording(&self.runs_dir, recording)? else {
                    return Ok((rejected("recording is not present locally"), false));
                };
                let local_manifest = manifest::read(&run.join("manifest.json"))?;
                let persisted_operation = self.request_operation(request.id)?;
                if local_manifest.status == "running" || persisted_operation.is_some() {
                    let Some(operation) = self
                        .prepare_active_request_operation(request, &run, recording)
                        .await?
                    else {
                        return Ok((rejected("recording_id is not the active segment"), false));
                    };
                    let upload_options = UploadOptions {
                        api: self.options.api.clone(),
                        token_file: self.options.token_file.clone(),
                        encryption_key: self.options.encryption_key.clone(),
                        allow_http: self.options.allow_http,
                        retry_for: self.options.retry_for,
                        max_batches: None,
                        collector_id: self.state.collector_id,
                    };
                    let report = if request.kind == "seal" {
                        seal_active_run_for(
                            &run,
                            operation.durable_boundary,
                            &operation.recording_id,
                            &upload_options,
                        )
                        .await
                    } else {
                        flush_active_run_for(
                            &run,
                            operation.durable_boundary,
                            &operation.recording_id,
                            &upload_options,
                        )
                        .await
                    };
                    self.invalidate_session();
                    let report = report?;
                    return Ok((
                        done(json!({
                            "recording_id": report.recording_id,
                            "durable_boundary": operation.durable_boundary,
                            "acked_seq": report.acked_seq,
                            "sealed": report.sealed,
                            "active": true,
                        })),
                        false,
                    ));
                }
                let inspection =
                    inspect_run_with_key(&run, false, self.options.encryption_key.as_ref())?;
                let current_recording = active_recording_id_at_boundary(
                    &run,
                    inspection.log.valid_events,
                    &self.options.api,
                    self.options.allow_http,
                    self.options.encryption_key.as_ref(),
                )?;
                if current_recording != recording {
                    return Ok((
                        rejected("recording_id is not the final upload segment"),
                        false,
                    ));
                }
                let report = upload_run(
                    &run,
                    &UploadOptions {
                        api: self.options.api.clone(),
                        token_file: self.options.token_file.clone(),
                        encryption_key: self.options.encryption_key.clone(),
                        allow_http: self.options.allow_http,
                        retry_for: self.options.retry_for,
                        max_batches: None,
                        collector_id: self.state.collector_id,
                    },
                )
                .await;
                self.invalidate_session();
                let report = report?;
                Ok((
                    done(json!({
                        "recording_id": report.recording_id,
                        "acked_seq": report.acked_seq,
                        "sealed": report.sealed,
                    })),
                    false,
                ))
            }
            "backfill" => {
                if self.state.paused {
                    return Ok((rejected("uploads are paused by collector policy"), false));
                }
                let Some(recording) = payload_recording_id(&request.payload) else {
                    return Ok((rejected("invalid recording_id"), false));
                };
                let first_seq = request.payload.get("first_seq").and_then(Value::as_u64);
                let last_seq = request.payload.get("last_seq").and_then(Value::as_u64);
                let (Some(first_seq), Some(last_seq)) = (first_seq, last_seq) else {
                    return Ok((rejected("invalid backfill sequence range"), false));
                };
                if first_seq == 0 || last_seq < first_seq {
                    return Ok((rejected("invalid backfill sequence range"), false));
                }
                let Some(run) = find_recording(&self.runs_dir, recording)? else {
                    return Ok((rejected("recording is not present locally"), false));
                };
                let local_manifest = manifest::read(&run.join("manifest.json"))?;
                if local_manifest.status == "running" {
                    return Ok((
                        rejected("backfill refuses a run that is still being recorded"),
                        false,
                    ));
                }
                let report = backfill_run(
                    &run,
                    recording,
                    first_seq,
                    last_seq,
                    &UploadOptions {
                        api: self.options.api.clone(),
                        token_file: self.options.token_file.clone(),
                        encryption_key: self.options.encryption_key.clone(),
                        allow_http: self.options.allow_http,
                        retry_for: self.options.retry_for,
                        max_batches: None,
                        collector_id: self.state.collector_id,
                    },
                )
                .await;
                self.invalidate_session();
                let report = report?;
                Ok((done(serde_json::to_value(report)?), false))
            }
            "delete_local" => {
                if !self.options.allow_remote_delete {
                    return Ok((
                        rejected("remote deletion is disabled by local policy"),
                        false,
                    ));
                }
                let Some(recording) = payload_recording_id(&request.payload) else {
                    return Ok((rejected("invalid recording_id"), false));
                };
                let class = match request.payload.get("class") {
                    Some(value) => {
                        let Some(value) = value.as_str() else {
                            return Ok((rejected("invalid blob class"), false));
                        };
                        match BlobClass::parse(value) {
                            Ok(class) => Some(class),
                            Err(_) => return Ok((rejected("invalid blob class"), false)),
                        }
                    }
                    None => None,
                };
                let Some(run) = find_recording(&self.runs_dir, recording)? else {
                    if class.is_some() {
                        return Ok((rejected("recording is not present locally"), false));
                    }
                    let Some((run_id, _)) = parse_recording_id(recording) else {
                        return Ok((rejected("invalid recording_id"), false));
                    };
                    if !remote_delete_was_started(&self.runs_dir, request.id)? {
                        return Ok((rejected("recording is not present locally"), false));
                    }
                    let report = delete_uploaded_run(
                        &self.runs_dir,
                        run_id,
                        request.id,
                        self.options.encryption_key.as_ref(),
                    )?;
                    return Ok((done(serde_json::to_value(report)?), false));
                };
                if let Some(class) = class {
                    let Some(key) = self.options.encryption_key.as_ref() else {
                        return Ok((
                            rejected("blob-class deletion requires a local encryption key"),
                            false,
                        ));
                    };
                    let report = erase_blob_class_for_request(&run, class, key, request.id)?;
                    return Ok((done(serde_json::to_value(report)?), false));
                }
                let run_id = manifest::read(&run.join("manifest.json"))?.run_id;
                let report = delete_uploaded_run(
                    &self.runs_dir,
                    &run_id,
                    request.id,
                    self.options.encryption_key.as_ref(),
                )?;
                let deleted = report.deleted;
                Ok((done(serde_json::to_value(report)?), deleted))
            }
            "upload_sensitive" => Ok((
                rejected("sensitive evidence upload is disabled by local policy"),
                false,
            )),
            _ => Ok((rejected("unsupported collector request type"), false)),
        }
    }
}

fn done(result: Value) -> RequestOutcome {
    RequestOutcome {
        status: "done".to_owned(),
        reason: String::new(),
        result,
    }
}

fn rejected(reason: &str) -> RequestOutcome {
    RequestOutcome {
        status: "rejected".to_owned(),
        reason: reason.chars().take(MAX_REASON_BYTES).collect(),
        result: json!({}),
    }
}

fn validate_pending_request(request: &PendingRequest) -> Result<()> {
    anyhow::ensure!(!request.id.is_nil(), "collector request has a nil ID");
    anyhow::ensure!(
        !request.kind.is_empty()
            && request.kind.len() <= 64
            && request.kind.bytes().all(|byte| byte.is_ascii_graphic()),
        "collector request type is invalid"
    );
    anyhow::ensure!(
        request.payload.is_object(),
        "collector request payload is not an object"
    );
    let encoded = serde_json::to_vec(&request.payload)?;
    anyhow::ensure!(
        encoded.len() <= MAX_RESULT_BYTES,
        "collector request payload exceeds safety limit"
    );
    crate::input::validate_json_complexity(&encoded)?;
    Ok(())
}

fn request_run_id(request: &PendingRequest) -> Option<&str> {
    request
        .payload
        .get("recording_id")
        .and_then(Value::as_str)
        .and_then(parse_recording_id)
        .map(|(run_id, _)| run_id)
}

fn payload_recording_id(payload: &Value) -> Option<&str> {
    let value = payload.get("recording_id")?.as_str()?;
    let (run_id, segment_no) = parse_recording_id(value)?;
    (value.len() <= 240
        && run_id.starts_with("run-")
        && Path::new(run_id).components().count() == 1
        && Path::new(run_id)
            .file_name()
            .is_some_and(|name| name == run_id)
        && recording_id_for_segment(run_id, segment_no) == value)
        .then_some(value)
}

fn parse_recording_id(value: &str) -> Option<(&str, u32)> {
    let (run_id, suffix) = value.rsplit_once('#')?;
    if suffix.len() != 4 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let segment_no = suffix.parse::<u32>().ok()?;
    (segment_no < 10_000).then_some((run_id, segment_no))
}

fn remote_delete_was_started(runs_dir: &Path, request_id: Uuid) -> Result<bool> {
    let quarantine = runs_dir.join(format!(".iorec-remote-delete-{request_id}"));
    match fs::symlink_metadata(quarantine) {
        Ok(_) => return Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let request_id = request_id.to_string();
    Ok(
        audit::has_request_record(runs_dir, "remote_delete", "intent", &request_id)?
            || audit::has_request_record(runs_dir, "remote_delete", "complete", &request_id)?,
    )
}

fn find_recording(runs_dir: &Path, expected: &str) -> Result<Option<PathBuf>> {
    let (_, segment_no) = parse_recording_id(expected).context("invalid recording ID")?;
    let mut seen = 0_usize;
    for entry in fs::read_dir(runs_dir)? {
        let entry = entry?;
        seen = seen.saturating_add(1);
        anyhow::ensure!(seen <= MAX_RUNS, "runs directory entry limit exceeded");
        let file_type = entry.file_type()?;
        if !file_type.is_dir()
            || file_type.is_symlink()
            || !entry.file_name().to_string_lossy().starts_with("run-")
        {
            continue;
        }
        let Ok(local_manifest) = manifest::read(&entry.path().join("manifest.json")) else {
            continue;
        };
        if recording_id_for_segment(&local_manifest.run_id, segment_no) == expected {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

impl ControlClient {
    fn new(origin: Url, token: &str, retry_for: Duration) -> Result<Self> {
        let authorization = bearer_header(token)?;
        let http = reqwest::Client::builder()
            .redirect(RedirectPolicy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .user_agent(format!("iorec/{RECORDER_VERSION}"))
            .build()?;
        Ok(Self {
            origin,
            bootstrap_authorization: authorization.clone(),
            authorization,
            http,
            retry_for,
        })
    }

    fn use_bootstrap_authorization(&mut self) {
        self.authorization = self.bootstrap_authorization.clone();
    }

    async fn register(
        &mut self,
        collector_id: Option<Uuid>,
        capabilities: Value,
    ) -> Result<RegisterResponse> {
        let body = json!({
            "collector_id": collector_id,
            "name": "iorec-daemon",
            "version": format!("iorec/{RECORDER_VERSION}"),
            "hostname": "redacted",
            "os": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            "capabilities": capabilities,
        });
        let response = self
            .request_with_authorization(
                Method::POST,
                self.endpoint(&["v1", "collectors:register"]),
                json_headers(),
                Bytes::from(serde_json::to_vec(&body)?),
                self.bootstrap_authorization.clone(),
            )
            .await?;
        require_status(&response, &[StatusCode::OK])?;
        let mut registration: RegisterResponse = decode_json(&response.body)?;
        anyhow::ensure!(
            !registration.session_token.is_empty()
                && registration.session_token.len() <= MAX_TOKEN_BYTES
                && registration
                    .session_token
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic()),
            "platform returned an invalid collector session"
        );
        self.authorization = bearer_header(&registration.session_token)?;
        registration.session_token.zeroize();
        Ok(registration)
    }

    async fn heartbeat(&self, collector_id: Uuid, body: Value) -> Result<HeartbeatResponse> {
        let segment = format!("{collector_id}:heartbeat");
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "collectors", &segment]),
                json_headers(),
                Bytes::from(serde_json::to_vec(&body)?),
            )
            .await?;
        require_status(&response, &[StatusCode::OK])?;
        decode_json(&response.body)
    }

    async fn poll(&self, wait: Duration) -> Result<Vec<PendingRequest>> {
        let mut endpoint = self.endpoint(&["v1", "collector-requests"]);
        if !wait.is_zero() {
            endpoint
                .query_pairs_mut()
                .append_pair("wait", &format!("{}s", wait.as_secs()));
        }
        let response = self
            .request(Method::GET, endpoint, HeaderMap::new(), Bytes::new())
            .await?;
        require_status(&response, &[StatusCode::OK])?;
        let poll: PollResponse = decode_json(&response.body)?;
        Ok(poll.items)
    }

    async fn report(&self, request_id: Uuid, outcome: &RequestOutcome) -> Result<()> {
        let segment = format!("{request_id}:result");
        let body = serde_json::to_vec(&json!({
            "status": outcome.status,
            "reason": outcome.reason,
            "result": outcome.result,
        }))?;
        anyhow::ensure!(
            body.len() <= MAX_RESULT_BYTES,
            "collector request result exceeds safety limit"
        );
        let response = self
            .request(
                Method::POST,
                self.endpoint(&["v1", "collector-requests", &segment]),
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
        self.request_with_authorization(method, endpoint, headers, body, self.authorization.clone())
            .await
    }

    async fn request_with_authorization(
        &self,
        method: Method,
        endpoint: Url,
        headers: HeaderMap,
        body: Bytes,
        authorization: HeaderValue,
    ) -> Result<HttpResponse> {
        let started = Instant::now();
        let mut attempt = 0_u32;
        loop {
            let result = self
                .http
                .request(method.clone(), endpoint.clone())
                .header(header::AUTHORIZATION, authorization.clone())
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
                    if let Some(delay) = retry_delay(self.retry_for, started, attempt, retry_after)
                    {
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    if let Some(delay) = retry_delay(self.retry_for, started, attempt, None) {
                        tokio::time::sleep(delay).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Err(error)
                        .context("collector platform request failed after retry budget");
                }
            }
        }
    }
}

fn collector_capabilities(options: &CollectorOptions) -> Value {
    let report = doctor::inspect();
    let pcap = report
        .capture_modes
        .get("pcap")
        .is_some_and(|mode| mode.status == "available");
    let task_netns = report
        .capture_modes
        .get("task_netns")
        .is_some_and(|mode| mode.status != "unavailable");
    let ebpf = report
        .capture_modes
        .get("ebpf")
        .is_some_and(|mode| mode.status != "unavailable");
    json!({
        "schema": "iorec.capabilities.v1",
        "transport": {
            "http_body": "visible",
            "sse": "visible",
            "websocket": "visible",
            "http2_decode": "native",
            "http3": "detect_only",
        },
        "sources": {
            "proxy": true,
            "runtime_observer": true,
            "keylog": {"available": true, "runtimes": ["node", "python"]},
            "pcap": {"available": pcap},
            "task_netns": {"available": task_netns},
            "ebpf": {"available": ebpf},
        },
        "runtime_inventory": {
            "agents_detected": [],
            "tls_surfaces": [],
            "unknown_tls_surfaces": 0,
        },
        "limits": {
            "max_blob_bytes": options.local_max_body_bytes,
            "spool_bytes": Value::Null,
            "recording_segment_logical_bytes": options.segment_max_logical_bytes,
            "recording_segment_age_seconds": options.segment_max_age.as_secs(),
        },
        "retention": {
            "whole_run_delete": options.allow_remote_delete,
            "class_keyed_encryption": options.encryption_key.is_some(),
            "independent_class_ttl": options.allow_remote_delete && options.encryption_key.is_some(),
            "class_delete_request": options.allow_remote_delete && options.encryption_key.is_some(),
            "classes": ["body", "pcap", "tls_secrets"],
        },
        "privilege": {
            "helper_running": false,
            "agent_uid": report.effective_uid,
        },
    })
}

fn prepare_control_dir(runs_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let metadata = fs::symlink_metadata(runs_dir)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "runs directory must be a real directory, not a symlink"
    );
    let runs_dir = runs_dir.canonicalize()?;
    anyhow::ensure!(
        runs_dir != Path::new("/"),
        "refusing filesystem root as runs directory"
    );
    let control_dir = runs_dir.join(CONTROL_DIR);
    match fs::symlink_metadata(&control_dir) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "collector control path is not a real directory"
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&control_dir)?;
            File::open(&runs_dir)?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(&control_dir, fs::Permissions::from_mode(0o700))?;
    Ok((runs_dir, control_dir))
}

fn lock_collector(control_dir: &Path) -> Result<CollectorLock> {
    let file = open_regular_create(&control_dir.join(LOCK_FILE))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| io::Error::other(error))?;
    Ok(CollectorLock { _file: file })
}

fn read_state(path: &Path) -> Result<CollectorState> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "collector state is not a regular file"
    );
    let exposed_permission_bits = metadata.permissions().mode() & 0o077;
    anyhow::ensure!(
        exposed_permission_bits == 0,
        "collector state must not be accessible by group or other users"
    );
    let bytes = read_regular_limited(path, MAX_STATE_BYTES)?;
    crate::input::validate_json_complexity(&bytes)?;
    serde_json::from_slice(&bytes).context("parse collector state")
}

fn validate_state(state: &CollectorState) -> Result<()> {
    anyhow::ensure!(
        state.schema_version == STATE_SCHEMA_VERSION,
        "unsupported collector state version"
    );
    let origin = Url::parse(&state.api_origin).context("collector state API origin is invalid")?;
    validate_api(&origin, origin.scheme() == "http")?;
    anyhow::ensure!(
        state.config_version >= 0,
        "collector config version is negative"
    );
    anyhow::ensure!(
        state.effective_config.is_object() && state.rejected_config.is_object(),
        "collector configuration state is invalid"
    );
    let bytes = serde_json::to_vec(state)?;
    anyhow::ensure!(
        bytes.len() <= MAX_STATE_BYTES,
        "collector state exceeds safety limit"
    );
    crate::input::validate_json_complexity(&bytes)?;
    if let Some(inflight) = &state.inflight {
        validate_pending_request(&inflight.request)?;
        if let Some(operation) = &inflight.operation {
            anyhow::ensure!(
                matches!(inflight.request.kind.as_str(), "flush" | "seal")
                    && operation.durable_boundary > 0
                    && payload_recording_id(&inflight.request.payload)
                        == Some(operation.recording_id.as_str()),
                "collector request operation state is invalid"
            );
        }
        if let Some(outcome) = &inflight.terminal {
            validate_outcome(outcome)?;
        }
    }
    Ok(())
}

fn validate_outcome(outcome: &RequestOutcome) -> Result<()> {
    anyhow::ensure!(
        ["acked", "done", "rejected"].contains(&outcome.status.as_str()),
        "collector request outcome status is invalid"
    );
    anyhow::ensure!(
        outcome.reason.len() <= MAX_REASON_BYTES && !outcome.reason.contains(['\0', '\r', '\n']),
        "collector request outcome reason is invalid"
    );
    let result = serde_json::to_vec(&outcome.result)?;
    anyhow::ensure!(
        result.len() <= MAX_RESULT_BYTES,
        "collector request result is too large"
    );
    crate::input::validate_json_complexity(&result)?;
    Ok(())
}

fn write_state(path: &Path, state: &CollectorState) -> Result<()> {
    validate_state(state)?;
    let parent = path.parent().context("collector state has no parent")?;
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
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_TOKEN_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_TOKEN_BYTES,
        "platform token exceeds safety limit"
    );
    let mut token =
        Zeroizing::new(String::from_utf8(bytes).context("platform token is not UTF-8")?);
    while token.ends_with(['\r', '\n']) {
        token.pop();
    }
    anyhow::ensure!(
        !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()),
        "platform token is empty or contains whitespace/control bytes"
    );
    Ok(token)
}

fn bearer_header(token: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .context("platform credential cannot be represented as an HTTP header")
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
    body: Bytes,
}

async fn read_response(response: reqwest::Response) -> Result<HttpResponse> {
    let status = response.status();
    if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        return Ok(HttpResponse {
            status,
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

fn retry_delay(
    retry_for: Duration,
    started: Instant,
    attempt: u32,
    retry_after: Option<Duration>,
) -> Option<Duration> {
    if retry_for.is_zero() {
        return None;
    }
    let shift = attempt.min(7);
    let exponential = Duration::from_millis(250_u64.saturating_mul(1_u64 << shift));
    let jitter = Duration::from_millis(u64::from((attempt.wrapping_mul(73) + 41) % 251));
    let delay = retry_after
        .unwrap_or(exponential + jitter)
        .min(Duration::from_secs(30));
    (started.elapsed() + delay <= retry_for).then_some(delay)
}

fn require_status(response: &HttpResponse, accepted: &[StatusCode]) -> Result<()> {
    if accepted.contains(&response.status) {
        return Ok(());
    }
    let code = serde_json::from_slice::<Value>(&response.body)
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

fn bounded_error(error: &anyhow::Error) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("token") || text.contains("://") {
        return "collector operation failed; sensitive diagnostic detail was suppressed".to_owned();
    }
    text.chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

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
        collector,
        manifest::{CommandMetadata, Manifest, write_atomic},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[test]
    fn remote_config_can_only_tighten_content_and_reports_local_rejections() {
        let remote = json!({
            "content_policy": {
                "capture_bodies": false,
                "max_body_bytes": 4096,
                "redact_fields": ["X-Custom-Secret"],
                "pty": true,
            },
            "upload": {"batch_max_bytes": 1, "rate_limit_bytes_per_s": 1},
            "sensitive_tier_upload": {"pcap": true},
            "retention_local": {"acked_events_ttl_hours": 12, "body_ttl_hours": 6},
            "unknown": {"secret": "must-not-be-echoed"},
        });
        let (effective, rejected) = merge_remote_config(
            &remote,
            LocalPolicy {
                allow_remote_delete: false,
                class_erasure_enabled: false,
                max_body_bytes: 2048,
            },
        )
        .unwrap();
        assert_eq!(
            effective.pointer("/content_policy/capture_bodies"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            effective.pointer("/content_policy/max_body_bytes"),
            Some(&json!(2048))
        );
        let redactions = effective
            .pointer("/content_policy/redact_fields")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(redactions.iter().any(|value| value == "x-custom-secret"));
        let feedback = rejected.to_string();
        assert!(feedback.contains("local maximum"));
        assert!(feedback.contains("remote deletion is disabled"));
        assert!(feedback.contains("sensitive evidence"));
        assert!(!feedback.contains("must-not-be-echoed"));
    }

    #[test]
    fn accepted_ttl_and_persisted_config_restrict_only_new_runs() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let (_, control_dir) = prepare_control_dir(&runs).unwrap();
        let (effective, rejected) = merge_remote_config(
            &json!({
                "content_policy": {
                    "capture_bodies": false,
                    "max_body_bytes": 1024,
                    "redact_fields": ["x-project-secret"],
                },
                "retention_local": {
                    "acked_events_ttl_hours": 24,
                    "body_ttl_hours": 6,
                    "pcap_ttl_hours": 2,
                    "tls_secrets_ttl_hours": 1
                },
            }),
            LocalPolicy {
                allow_remote_delete: true,
                class_erasure_enabled: true,
                max_body_bytes: 4096,
            },
        )
        .unwrap();
        assert_eq!(
            effective.pointer("/retention_local/acked_events_ttl_hours"),
            Some(&json!(24))
        );
        assert_eq!(
            effective.pointer("/retention_local/body_ttl_hours"),
            Some(&json!(6))
        );
        assert_eq!(
            effective.pointer("/retention_local/pcap_ttl_hours"),
            Some(&json!(2))
        );
        assert_eq!(
            effective.pointer("/retention_local/tls_secrets_ttl_hours"),
            Some(&json!(1))
        );
        let state = CollectorState {
            schema_version: STATE_SCHEMA_VERSION,
            api_origin: "https://platform.example/".to_owned(),
            collector_id: Some(Uuid::now_v7()),
            config_version: 7,
            effective_config: effective,
            rejected_config: rejected,
            paused: false,
            inflight: None,
            last_error: None,
            updated_at: Utc::now(),
        };
        write_state(&control_dir.join(STATE_FILE), &state).unwrap();

        let mut active_policy = CapturePolicy::default();
        let existing = active_policy.clone();
        apply_new_run_config(&runs, &mut active_policy).unwrap();
        assert_eq!(active_policy.body_mode, BodyCaptureMode::MetadataOnly);
        assert_eq!(active_policy.max_blob_bytes, 1024);
        assert!(active_policy.redact_headers.contains("x-project-secret"));
        assert_eq!(existing.body_mode, BodyCaptureMode::Full);
        assert_eq!(existing.max_blob_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn collector_state_and_request_inputs_are_bounded() {
        let temporary = tempfile::tempdir().unwrap();
        let token = temporary.path().join("token");
        fs::write(&token, b"project-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&token).is_err());
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&token).unwrap().as_str(), "project-token");

        let request = PendingRequest {
            id: Uuid::now_v7(),
            kind: "pause".to_owned(),
            payload: Value::Array(Vec::new()),
            expires_at: Utc::now(),
        };
        assert!(validate_pending_request(&request).is_err());
    }

    #[test]
    fn recording_ids_are_exact_and_remote_delete_recovery_verifies_audit() {
        assert_eq!(
            payload_recording_id(&json!({"recording_id": "run-example#0000"})),
            Some("run-example#0000")
        );
        assert_eq!(
            payload_recording_id(&json!({"recording_id": "run-example#0001"})),
            Some("run-example#0001")
        );
        for invalid in [
            "run-example#10000",
            "run-example#001",
            "../run-example#0000",
            "run-example/child#0000",
            "example#0000",
        ] {
            assert!(payload_recording_id(&json!({"recording_id": invalid})).is_none());
        }

        let temporary = tempfile::tempdir().unwrap();
        let request_id = Uuid::now_v7();
        assert!(!remote_delete_was_started(temporary.path(), request_id).unwrap());
        audit::append(
            temporary.path(),
            "remote_delete",
            "intent",
            "run-example",
            Some(json!({"request_id": request_id})),
        )
        .unwrap();
        assert!(remote_delete_was_started(temporary.path(), request_id).unwrap());

        fs::write(temporary.path().join(audit::AUDIT_FILE), b"corrupt\n").unwrap();
        assert!(remote_delete_was_started(temporary.path(), request_id).is_err());
    }

    #[derive(Default)]
    struct MockControlState {
        delivered: bool,
        registrations: usize,
        heartbeats: usize,
        results: Vec<Value>,
        recording_creates: usize,
        recording_durable: u64,
        recording_final: Option<u64>,
        recording_sealed: bool,
        recording_batches: BTreeSet<(u64, u64)>,
        fail_batches: bool,
    }

    async fn mock_control(
        State(state): State<Arc<Mutex<MockControlState>>>,
        request: Request<Body>,
    ) -> Response<Body> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = to_bytes(request.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let mut state = state.lock().await;
        let json_response =
            |status: StatusCode, value: Value| (status, axum::Json(value)).into_response();
        if method == Method::POST && path == "/v1/collectors:register" {
            if authorization != "Bearer project-token" {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            state.registrations += 1;
            return json_response(
                StatusCode::OK,
                json!({
                    "collector_id": "018bcfe5-6800-7000-8000-000000000010",
                    "session_token": "iorc_test_session",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "config_version": 3,
                    "config": {
                        "content_policy": {
                            "capture_bodies": false,
                            "max_body_bytes": 2048,
                            "redact_fields": ["x-project-secret"],
                            "pty": false
                        }
                    }
                }),
            );
        }
        if authorization != "Bearer iorc_test_session" {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if method == Method::POST && path == "/v1/recordings" {
            let request: Value = serde_json::from_slice(&body).unwrap();
            state.recording_creates += 1;
            state.recording_durable = request["sequence_base"].as_u64().unwrap();
            return json_response(StatusCode::CREATED, json!({"state": "open"}));
        }
        if method == Method::GET && path.starts_with("/v1/recordings/") {
            return json_response(
                StatusCode::OK,
                json!({
                    "state": if state.recording_sealed { "sealed" } else { "open" },
                    "segment_no": 0,
                    "sequence_base": 0,
                    "durable_seq": state.recording_durable,
                    "final_seq": state.recording_final,
                }),
            );
        }
        if method == Method::POST && path.ends_with("/batches") {
            if state.fail_batches {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let newline = body.iter().position(|byte| *byte == b'\n').unwrap();
            let header: Value = serde_json::from_slice(&body[..newline]).unwrap();
            let first = header["first_seq"].as_u64().unwrap();
            let last = header["last_seq"].as_u64().unwrap();
            state.recording_batches.insert((first, last));
            state.recording_durable = last;
            return json_response(
                StatusCode::OK,
                json!({"recording_id": header["recording_id"], "durable_seq": last, "state": "open", "missing_blobs": []}),
            );
        }
        if method == Method::POST && path.ends_with(":seal") {
            let request: Value = serde_json::from_slice(&body).unwrap();
            state.recording_final = request["final_seq"].as_u64();
            state.recording_sealed = true;
            return json_response(StatusCode::OK, json!({"state": "sealed"}));
        }
        if method == Method::POST && path.ends_with(":heartbeat") {
            state.heartbeats += 1;
            return json_response(
                StatusCode::OK,
                json!({
                    "config_version": 3,
                    "session_expires_at": "2099-01-01T00:00:00Z"
                }),
            );
        }
        if method == Method::GET && path == "/v1/collector-requests" {
            if state.delivered {
                return json_response(StatusCode::OK, json!({"items": []}));
            }
            state.delivered = true;
            return json_response(
                StatusCode::OK,
                json!({
                    "items": [{
                        "id": "018bcfe5-6800-7000-8000-000000000011",
                        "type": "pause",
                        "payload": {"reason": "maintenance"},
                        "expires_at": "2099-01-01T00:00:00Z"
                    }]
                }),
            );
        }
        if method == Method::POST
            && path.starts_with("/v1/collector-requests/")
            && path.ends_with(":result")
        {
            let result: Value = serde_json::from_slice(&body).unwrap();
            state.results.push(result.clone());
            return json_response(
                StatusCode::OK,
                json!({"id": "018bcfe5-6800-7000-8000-000000000011", "status": result["status"]}),
            );
        }
        StatusCode::NOT_FOUND.into_response()
    }

    #[tokio::test]
    async fn one_cycle_registers_heartbeats_applies_config_and_finishes_request() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let token = temporary.path().join("token");
        fs::write(&token, b"project-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockControlState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_control))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let report = run_collector(
            CollectorOptions {
                api: Url::parse(&format!("http://{address}")).unwrap(),
                token_file: token,
                runs_dir: runs.clone(),
                encryption_key: None,
                allow_http: true,
                allow_remote_delete: false,
                retry_for: Duration::ZERO,
                poll_wait: Duration::ZERO,
                local_max_body_bytes: 4096,
                segment_max_logical_bytes: 64 * 1024 * 1024,
                segment_max_age: Duration::from_secs(15 * 60),
            },
            true,
        )
        .await
        .unwrap();
        assert_eq!(report.cycles, 1);
        assert_eq!(report.processed_requests, 1);
        assert_eq!(report.config_version, 3);
        assert!(report.paused);

        let state = mock.lock().await;
        assert_eq!(state.registrations, 1);
        assert_eq!(state.heartbeats, 1);
        assert_eq!(state.results.len(), 2);
        assert_eq!(state.results[0]["status"], "acked");
        assert_eq!(state.results[1]["status"], "done");
        drop(state);

        let persisted = fs::read_to_string(runs.join(CONTROL_DIR).join(STATE_FILE)).unwrap();
        assert!(!persisted.contains("project-token"));
        assert!(!persisted.contains("iorc_test_session"));
        let mut new_policy = CapturePolicy::default();
        apply_new_run_config(&runs, &mut new_policy).unwrap();
        assert_eq!(new_policy.body_mode, BodyCaptureMode::MetadataOnly);
        assert_eq!(new_policy.max_blob_bytes, 2048);
        assert!(new_policy.redact_headers.contains("x-project-secret"));
        assert_eq!(audit::verify(&runs).unwrap().records, 1);
        server.abort();
    }

    #[tokio::test]
    async fn one_cycle_rolls_an_active_segment_when_the_local_size_limit_is_due() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let run_id = "run-daemon-roll";
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
                environment: std::collections::BTreeMap::new(),
            },
            CapturePolicy::default(),
        );
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, CapturePolicy::default()).unwrap();
        store.append(store.event("test", "event")).await.unwrap();
        let local_collector = collector::start(&run, store.clone()).unwrap();

        let token = temporary.path().join("token");
        fs::write(&token, b"project-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockControlState {
            delivered: true,
            ..MockControlState::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_control))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let report = run_collector(
            CollectorOptions {
                api: Url::parse(&format!("http://{address}")).unwrap(),
                token_file: token,
                runs_dir: runs,
                encryption_key: None,
                allow_http: true,
                allow_remote_delete: false,
                retry_for: Duration::ZERO,
                poll_wait: Duration::ZERO,
                local_max_body_bytes: 4096,
                segment_max_logical_bytes: 1,
                segment_max_age: Duration::from_secs(3600),
            },
            true,
        )
        .await
        .unwrap();
        assert_eq!(report.cycles, 1);
        let state = mock.lock().await;
        assert_eq!(state.recording_creates, 1);
        assert_eq!(state.recording_durable, 1);
        assert_eq!(state.recording_final, Some(1));
        assert!(state.recording_sealed);
        assert_eq!(state.recording_batches, BTreeSet::from([(1, 1)]));
        assert!(state.registrations >= 3);
        drop(state);

        local_collector.stop().await.unwrap();
        store.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn recovered_active_seal_reuses_its_persisted_boundary() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let run_id = "run-request-recovery";
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
                environment: std::collections::BTreeMap::new(),
            },
            CapturePolicy::default(),
        );
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, CapturePolicy::default()).unwrap();
        store.append(store.event("test", "first")).await.unwrap();
        let local_collector = collector::start(&run, store.clone()).unwrap();

        let token = temporary.path().join("token");
        fs::write(&token, b"project-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockControlState {
            delivered: true,
            ..MockControlState::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_control))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut daemon = CollectorDaemon::open(CollectorOptions {
            api: Url::parse(&format!("http://{address}")).unwrap(),
            token_file: token,
            runs_dir: runs,
            encryption_key: None,
            allow_http: true,
            allow_remote_delete: false,
            retry_for: Duration::ZERO,
            poll_wait: Duration::ZERO,
            local_max_body_bytes: 4096,
            segment_max_logical_bytes: u64::MAX,
            segment_max_age: Duration::from_secs(3600),
        })
        .unwrap();
        daemon.ensure_registered().await.unwrap();
        let request = PendingRequest {
            id: Uuid::now_v7(),
            kind: "seal".to_owned(),
            payload: json!({"recording_id": recording_id_for_segment(run_id, 0)}),
            expires_at: Utc::now() + chrono::TimeDelta::minutes(5),
        };
        daemon.state.inflight = Some(InflightRequest {
            request: request.clone(),
            operation: None,
            terminal: None,
        });
        daemon.persist_state().unwrap();
        let (first_outcome, _) = daemon.execute_request(&request).await.unwrap();
        assert_eq!(first_outcome.status, "done");
        assert_eq!(
            daemon
                .state
                .inflight
                .as_ref()
                .unwrap()
                .operation
                .as_ref()
                .unwrap()
                .durable_boundary,
            1
        );

        store.append(store.event("test", "second")).await.unwrap();
        assert!(!daemon.resume_inflight().await.unwrap());
        assert!(daemon.state.inflight.is_none());
        let state = mock.lock().await;
        assert_eq!(state.recording_durable, 1);
        assert_eq!(state.recording_final, Some(1));
        assert_eq!(state.recording_batches, BTreeSet::from([(1, 1)]));
        assert_eq!(state.results.len(), 1);
        drop(state);

        drop(daemon);
        local_collector.stop().await.unwrap();
        store.shutdown().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn failed_request_upload_invalidates_the_rotated_collector_session() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        fs::create_dir(&runs).unwrap();
        let run_id = "run-request-upload-failure";
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
                environment: std::collections::BTreeMap::new(),
            },
            CapturePolicy::default(),
        );
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, run_id, CapturePolicy::default()).unwrap();
        store.append(store.event("test", "event")).await.unwrap();
        let local_collector = collector::start(&run, store.clone()).unwrap();

        let token = temporary.path().join("token");
        fs::write(&token, b"project-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let mock = Arc::new(Mutex::new(MockControlState {
            delivered: true,
            fail_batches: true,
            ..MockControlState::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/{*path}", any(mock_control))
            .with_state(mock.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut daemon = CollectorDaemon::open(CollectorOptions {
            api: Url::parse(&format!("http://{address}")).unwrap(),
            token_file: token,
            runs_dir: runs,
            encryption_key: None,
            allow_http: true,
            allow_remote_delete: false,
            retry_for: Duration::ZERO,
            poll_wait: Duration::ZERO,
            local_max_body_bytes: 4096,
            segment_max_logical_bytes: u64::MAX,
            segment_max_age: Duration::from_secs(3600),
        })
        .unwrap();
        daemon.ensure_registered().await.unwrap();
        let request = PendingRequest {
            id: Uuid::now_v7(),
            kind: "flush".to_owned(),
            payload: json!({"recording_id": recording_id_for_segment(run_id, 0)}),
            expires_at: Utc::now() + chrono::TimeDelta::minutes(5),
        };
        daemon.state.inflight = Some(InflightRequest {
            request: request.clone(),
            operation: None,
            terminal: None,
        });
        daemon.persist_state().unwrap();

        assert!(daemon.execute_request(&request).await.is_err());
        assert!(daemon.session_expires_at.is_none());
        daemon.ensure_registered().await.unwrap();
        assert_eq!(mock.lock().await.registrations, 3);

        drop(daemon);
        local_collector.stop().await.unwrap();
        store.shutdown().await.unwrap();
        server.abort();
    }
}
