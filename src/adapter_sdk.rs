//! Versioned extension contract for third-party agent adapters.
//!
//! An adapter is deliberately limited to four operations: [`AdapterSdk::detect`],
//! [`AdapterSdk::configure`], [`AdapterSdk::parse`], and
//! [`AdapterSdk::correlate`]. The host owns evidence persistence, redaction,
//! transport capture, event sequencing, and completeness decisions. Adapter
//! output is therefore treated as untrusted metadata and validated before it
//! can enter the event stream.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    panic::{RefUnwindSafe, UnwindSafe, catch_unwind},
    path::PathBuf,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    input::validate_json_complexity,
    model::{EventEnvelope, EventIds, PendingEvent, RedactionRecord, TerminalState},
};

const MAX_COMMAND_ITEMS: usize = 4_096;
const MAX_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_ITEMS: usize = 2_048;
const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
const MAX_PLUGIN_EVENTS: usize = 1_024;
const MAX_PLUGIN_EVENT_BYTES: usize = 1024 * 1024;
const MAX_CORRELATION_CANDIDATES: usize = 1_024;
const MAX_LABEL_ITEMS: usize = 1_024;
const MAX_LABEL_BYTES: usize = 1_024;
const MAX_FAILURE_BYTES: usize = 512;

/// Adapter SDK compatibility version understood by this recorder.
///
/// A host accepts the same major version and a plugin minor version no newer
/// than its own. Additive contract changes increment `minor`; breaking changes
/// increment `major`.
pub const ADAPTER_SDK_VERSION: ApiVersion = ApiVersion { major: 1, minor: 0 };

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DetectContext {
    pub command: Vec<OsString>,
    pub detected_agent: Option<String>,
    pub executable_sha256: Option<String>,
}

impl DetectContext {
    #[must_use]
    pub fn new(command: Vec<OsString>) -> Self {
        Self {
            command,
            detected_agent: None,
            executable_sha256: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    pub matched: bool,
    pub confidence: f32,
    pub reason: String,
}

impl Detection {
    #[must_use]
    pub fn matched(confidence: f32, reason: impl Into<String>) -> Self {
        Self {
            matched: true,
            confidence,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn no_match(reason: impl Into<String>) -> Self {
        Self {
            matched: false,
            confidence: 0.0,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConfigureContext {
    pub command: Vec<OsString>,
    pub proxy_url: Option<String>,
    /// Private host-created directory in which the adapter may place ephemeral
    /// hook or settings files. It must not write outside this directory merely
    /// to configure the target.
    pub scratch_dir: PathBuf,
}

impl ConfigureContext {
    #[must_use]
    pub fn new(command: Vec<OsString>, scratch_dir: PathBuf) -> Self {
        Self {
            command,
            proxy_url: None,
            scratch_dir,
        }
    }
}

/// Requested target-process changes. Arguments are inserted immediately after
/// the executable so user arguments retain their original order.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AdapterConfiguration {
    pub arguments_before_user: Vec<OsString>,
    pub environment: BTreeMap<OsString, OsString>,
    pub remove_environment: BTreeSet<OsString>,
    pub known_gaps: Vec<String>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParseContext {
    pub run_id: String,
    pub source: String,
    pub event: String,
    pub observed_at: DateTime<Utc>,
    /// A bounded copy of the native hook/session record. The host must persist
    /// the original evidence independently before relying on parsed output.
    pub payload: Value,
}

impl ParseContext {
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        source: impl Into<String>,
        event: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            source: source.into(),
            event: event.into(),
            observed_at: Utc::now(),
            payload,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedEvent {
    pub event: String,
    pub ids: EventIds,
    pub normalized: Value,
    pub confidence: Option<f32>,
    pub evidence: Vec<String>,
    pub terminal_state: Option<TerminalState>,
}

impl ParsedEvent {
    #[must_use]
    pub fn new(event: impl Into<String>, normalized: Value) -> Self {
        Self {
            event: event.into(),
            ids: EventIds::default(),
            normalized,
            confidence: None,
            evidence: Vec::new(),
            terminal_state: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationCandidate {
    pub candidate_id: String,
    pub source: String,
    pub event: String,
    #[serde(default)]
    pub ids: EventIds,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CorrelateContext {
    pub parsed: ParsedEvent,
    pub candidates: Vec<CorrelationCandidate>,
    /// True when the host had more candidates than the bounded set supplied
    /// here. Adapters must not interpret an unresolved bounded set as proof
    /// that no relationship exists.
    pub candidates_truncated: bool,
}

impl CorrelateContext {
    #[must_use]
    pub const fn new(parsed: ParsedEvent, candidates: Vec<CorrelationCandidate>) -> Self {
        Self {
            parsed,
            candidates,
            candidates_truncated: false,
        }
    }
}

/// Evidence basis asserted by an adapter. The host caps confidence according
/// to this basis so a heuristic plugin cannot manufacture a high-confidence
/// task relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationBasis {
    ExactId,
    ParentId,
    Temporal,
    Heuristic,
    Unresolved,
}

impl CorrelationBasis {
    const fn confidence_ceiling(self) -> f32 {
        match self {
            Self::ExactId => 0.95,
            Self::ParentId => 0.85,
            Self::Temporal => 0.5,
            Self::Heuristic => 0.25,
            Self::Unresolved => 0.0,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Correlation {
    pub selected_candidate: Option<String>,
    pub ids: EventIds,
    pub basis: CorrelationBasis,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub unresolved_reason: Option<String>,
}

impl Correlation {
    #[must_use]
    pub fn unresolved(reason: impl Into<String>) -> Self {
        Self {
            selected_candidate: None,
            ids: EventIds::default(),
            basis: CorrelationBasis::Unresolved,
            confidence: 0.0,
            evidence: Vec::new(),
            unresolved_reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterFailureKind {
    Unsupported,
    InvalidInput,
    Internal,
}

#[derive(Debug, Clone, Error)]
#[error("{kind:?}: {summary}")]
pub struct AdapterFailure {
    pub kind: AdapterFailureKind,
    summary: String,
}

impl AdapterFailure {
    #[must_use]
    pub fn new(kind: AdapterFailureKind, summary: impl AsRef<str>) -> Self {
        Self {
            kind,
            summary: safe_failure_text(summary.as_ref()),
        }
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

pub type AdapterResult<T> = Result<T, AdapterFailure>;

/// The complete third-party adapter surface.
///
/// Implementations must be deterministic for the same immutable input and
/// must not perform transport capture or write recorder evidence themselves.
/// Panics are caught at the host boundary, but adapters should return a typed
/// [`AdapterFailure`] for expected failures.
pub trait AdapterSdk: Send + Sync + RefUnwindSafe {
    fn detect(&self, context: &DetectContext) -> AdapterResult<Detection>;

    fn configure(&self, context: &ConfigureContext) -> AdapterResult<AdapterConfiguration>;

    fn parse(&self, context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>>;

    fn correlate(&self, context: &CorrelateContext) -> AdapterResult<Correlation>;
}

#[derive(Debug, Error)]
pub enum AdapterHostError {
    #[error("adapter identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error(
        "adapter SDK {plugin_major}.{plugin_minor} is incompatible with host {host_major}.{host_minor}"
    )]
    IncompatibleVersion {
        plugin_major: u16,
        plugin_minor: u16,
        host_major: u16,
        host_minor: u16,
    },
    #[error("adapter {operation} failed: {failure}")]
    Adapter {
        operation: &'static str,
        failure: AdapterFailure,
    },
    #[error("adapter panicked during {0}")]
    Panicked(&'static str),
    #[error("adapter {operation} output is invalid: {reason}")]
    InvalidOutput {
        operation: &'static str,
        reason: String,
    },
    #[error("adapter {operation} input is invalid: {reason}")]
    InvalidInput {
        operation: &'static str,
        reason: String,
    },
}

/// Validated configuration that can be applied without exposing mutable SDK
/// output to the recorder runtime.
#[derive(Debug, Clone)]
pub struct ValidatedConfiguration {
    arguments_before_user: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    remove_environment: BTreeSet<OsString>,
    known_gaps: Vec<String>,
}

impl ValidatedConfiguration {
    pub fn apply_command(&self, command: &mut Vec<OsString>) -> Result<(), AdapterHostError> {
        validate_command(command, "configure")?;
        let mut configured = command.clone();
        configured.splice(1..1, self.arguments_before_user.clone());
        validate_command(&configured, "configure")?;
        *command = configured;
        Ok(())
    }

    pub fn apply_environment(&self, command: &mut tokio::process::Command) {
        command.envs(self.environment.iter());
        for name in &self.remove_environment {
            command.env_remove(name);
        }
    }

    #[must_use]
    pub fn known_gaps(&self) -> &[String] {
        &self.known_gaps
    }

    pub(crate) fn environment(&self) -> &BTreeMap<OsString, OsString> {
        &self.environment
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedCorrelation {
    pub selected_candidate: Option<String>,
    pub ids: EventIds,
    pub basis: CorrelationBasis,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub unresolved_reason: Option<String>,
}

/// Executes an adapter behind validation and panic-containment boundaries.
pub struct AdapterHost {
    name: String,
    adapter_release: String,
    implementation: Box<dyn AdapterSdk>,
}

impl AdapterHost {
    pub fn new<A: AdapterSdk + 'static>(
        name: impl Into<String>,
        adapter_release: impl Into<String>,
        sdk_version: ApiVersion,
        implementation: A,
    ) -> Result<Self, AdapterHostError> {
        let name = name.into();
        let adapter_release = adapter_release.into();
        validate_identity("name", &name)?;
        validate_identity("release", &adapter_release)?;
        if sdk_version.major != ADAPTER_SDK_VERSION.major
            || sdk_version.minor > ADAPTER_SDK_VERSION.minor
        {
            return Err(AdapterHostError::IncompatibleVersion {
                plugin_major: sdk_version.major,
                plugin_minor: sdk_version.minor,
                host_major: ADAPTER_SDK_VERSION.major,
                host_minor: ADAPTER_SDK_VERSION.minor,
            });
        }
        Ok(Self {
            name,
            adapter_release,
            implementation: Box::new(implementation),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn adapter_release(&self) -> &str {
        &self.adapter_release
    }

    pub fn detect(&self, context: &DetectContext) -> Result<Detection, AdapterHostError> {
        validate_command(&context.command, "detect")?;
        if let Some(agent) = context.detected_agent.as_deref() {
            validate_label("detected agent", agent, MAX_LABEL_BYTES).map_err(|reason| {
                AdapterHostError::InvalidInput {
                    operation: "detect",
                    reason,
                }
            })?;
        }
        if let Some(digest) = context.executable_sha256.as_deref()
            && {
                let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            }
        {
            return Err(AdapterHostError::InvalidInput {
                operation: "detect",
                reason: "executable SHA-256 must contain 64 lowercase hexadecimal bytes".to_owned(),
            });
        }
        let detection = Self::invoke("detect", || self.implementation.detect(context))?;
        validate_confidence(detection.confidence, "detect")?;
        validate_label("detection reason", &detection.reason, MAX_LABEL_BYTES).map_err(
            |reason| AdapterHostError::InvalidOutput {
                operation: "detect",
                reason,
            },
        )?;
        if !detection.matched && detection.confidence != 0.0 {
            return Err(AdapterHostError::InvalidOutput {
                operation: "detect",
                reason: "a non-match must have zero confidence".to_owned(),
            });
        }
        Ok(detection)
    }

    pub fn configure(
        &self,
        context: &ConfigureContext,
    ) -> Result<ValidatedConfiguration, AdapterHostError> {
        validate_command(&context.command, "configure")?;
        if let Some(proxy_url) = context.proxy_url.as_deref() {
            let parsed =
                url::Url::parse(proxy_url).map_err(|_| AdapterHostError::InvalidInput {
                    operation: "configure",
                    reason: "proxy URL is invalid".to_owned(),
                })?;
            if parsed.scheme() != "http"
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(AdapterHostError::InvalidInput {
                    operation: "configure",
                    reason: "proxy URL must be credential-free HTTP without query or fragment"
                        .to_owned(),
                });
            }
        }
        let output = Self::invoke("configure", || self.implementation.configure(context))?;
        validate_configuration(output)
    }

    pub fn parse(&self, context: &ParseContext) -> Result<Vec<PendingEvent>, AdapterHostError> {
        validate_label("run ID", &context.run_id, 256).map_err(|reason| {
            AdapterHostError::InvalidInput {
                operation: "parse",
                reason,
            }
        })?;
        validate_label("source", &context.source, 128).map_err(|reason| {
            AdapterHostError::InvalidInput {
                operation: "parse",
                reason,
            }
        })?;
        validate_label("event", &context.event, 256).map_err(|reason| {
            AdapterHostError::InvalidInput {
                operation: "parse",
                reason,
            }
        })?;
        validate_value(&context.payload, "parse", "payload", MAX_PLUGIN_EVENT_BYTES)?;
        let output = Self::invoke("parse", || self.implementation.parse(context))?;
        if output.len() > MAX_PLUGIN_EVENTS {
            return Err(AdapterHostError::InvalidOutput {
                operation: "parse",
                reason: format!("more than {MAX_PLUGIN_EVENTS} events were returned"),
            });
        }
        output
            .into_iter()
            .map(|event| self.validate_parsed_event(context, event))
            .collect()
    }

    pub fn correlate(
        &self,
        context: &CorrelateContext,
    ) -> Result<ValidatedCorrelation, AdapterHostError> {
        validate_parsed_shape(&context.parsed, "correlate", "input event")?;
        if context.candidates.len() > MAX_CORRELATION_CANDIDATES {
            return Err(AdapterHostError::InvalidInput {
                operation: "correlate",
                reason: format!("more than {MAX_CORRELATION_CANDIDATES} candidates were supplied"),
            });
        }
        let mut candidate_ids = BTreeSet::new();
        for candidate in &context.candidates {
            validate_label("candidate ID", &candidate.candidate_id, MAX_LABEL_BYTES).map_err(
                |reason| AdapterHostError::InvalidInput {
                    operation: "correlate",
                    reason,
                },
            )?;
            validate_label("candidate source", &candidate.source, 128).map_err(|reason| {
                AdapterHostError::InvalidInput {
                    operation: "correlate",
                    reason,
                }
            })?;
            validate_label("candidate event", &candidate.event, 256).map_err(|reason| {
                AdapterHostError::InvalidInput {
                    operation: "correlate",
                    reason,
                }
            })?;
            candidate
                .ids
                .validate()
                .map_err(|reason| AdapterHostError::InvalidInput {
                    operation: "correlate",
                    reason,
                })?;
            if !candidate_ids.insert(candidate.candidate_id.clone()) {
                return Err(AdapterHostError::InvalidInput {
                    operation: "correlate",
                    reason: "candidate IDs must be unique".to_owned(),
                });
            }
        }
        let mut output = Self::invoke("correlate", || self.implementation.correlate(context))?;
        output
            .ids
            .validate()
            .map_err(|reason| AdapterHostError::InvalidOutput {
                operation: "correlate",
                reason,
            })?;
        validate_labels("correlation evidence", &output.evidence)?;
        validate_confidence(output.confidence, "correlate")?;
        if output.basis == CorrelationBasis::Unresolved {
            if output.selected_candidate.is_some() || output.unresolved_reason.is_none() {
                return Err(AdapterHostError::InvalidOutput {
                    operation: "correlate",
                    reason: "an unresolved result needs a reason and cannot select a candidate"
                        .to_owned(),
                });
            }
        } else {
            let selected = output.selected_candidate.as_ref().ok_or_else(|| {
                AdapterHostError::InvalidOutput {
                    operation: "correlate",
                    reason: "a resolved result must select a supplied candidate".to_owned(),
                }
            })?;
            if !candidate_ids.contains(selected) {
                return Err(AdapterHostError::InvalidOutput {
                    operation: "correlate",
                    reason: "the selected candidate was not supplied by the host".to_owned(),
                });
            }
            if output.unresolved_reason.is_some() {
                return Err(AdapterHostError::InvalidOutput {
                    operation: "correlate",
                    reason: "a resolved result cannot include an unresolved reason".to_owned(),
                });
            }
        }
        if let Some(reason) = output.unresolved_reason.as_deref() {
            validate_label("unresolved reason", reason, MAX_LABEL_BYTES).map_err(|reason| {
                AdapterHostError::InvalidOutput {
                    operation: "correlate",
                    reason,
                }
            })?;
        }
        output.confidence = output.confidence.min(output.basis.confidence_ceiling());
        output.evidence.push(self.evidence_label());
        output.evidence.sort();
        output.evidence.dedup();
        validate_labels("correlation evidence", &output.evidence)?;
        Ok(ValidatedCorrelation {
            selected_candidate: output.selected_candidate,
            ids: output.ids,
            basis: output.basis,
            confidence: output.confidence,
            evidence: output.evidence,
            unresolved_reason: output.unresolved_reason,
        })
    }

    fn validate_parsed_event(
        &self,
        context: &ParseContext,
        event: ParsedEvent,
    ) -> Result<PendingEvent, AdapterHostError> {
        validate_parsed_shape(&event, "parse", "output event")?;
        let mut pending = PendingEvent {
            run_id: context.run_id.clone(),
            source: format!("adapter:{}", self.name),
            kind: event.event,
            ids: event.ids,
            observed_at: context.observed_at,
            monotonic_ns: 0,
            raw: None,
            normalized: Some(event.normalized),
            redaction: RedactionRecord {
                policy: "adapter-sdk-host-v1".to_owned(),
                ..RedactionRecord::default()
            },
            confidence: event.confidence,
            evidence: event.evidence,
            terminal_state: event.terminal_state,
        };
        pending.evidence.push(self.evidence_label());
        pending.evidence.sort();
        pending.evidence.dedup();
        EventEnvelope::from_pending(1, pending.clone())
            .validate()
            .map_err(|reason| AdapterHostError::InvalidOutput {
                operation: "parse",
                reason,
            })?;
        Ok(pending)
    }

    fn evidence_label(&self) -> String {
        format!(
            "adapter-sdk:{}@{};api={}.{}",
            self.name, self.adapter_release, ADAPTER_SDK_VERSION.major, ADAPTER_SDK_VERSION.minor
        )
    }

    fn invoke<T>(
        operation: &'static str,
        call: impl FnOnce() -> AdapterResult<T> + UnwindSafe,
    ) -> Result<T, AdapterHostError> {
        match catch_unwind(call) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(failure)) => Err(AdapterHostError::Adapter { operation, failure }),
            Err(_) => Err(AdapterHostError::Panicked(operation)),
        }
    }
}

fn validate_identity(label: &str, value: &str) -> Result<(), AdapterHostError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(AdapterHostError::InvalidIdentity(format!(
            "adapter {label} must be 1..=128 portable identifier bytes"
        )));
    }
    Ok(())
}

fn validate_configuration(
    output: AdapterConfiguration,
) -> Result<ValidatedConfiguration, AdapterHostError> {
    if output.arguments_before_user.len() > MAX_COMMAND_ITEMS {
        return invalid_output("configure", "too many inserted command arguments");
    }
    let argument_bytes = output
        .arguments_before_user
        .iter()
        .try_fold(0_usize, |total, value| {
            total.checked_add(value.as_bytes().len()).ok_or(())
        })
        .map_err(|()| AdapterHostError::InvalidOutput {
            operation: "configure",
            reason: "inserted command byte count overflowed".to_owned(),
        })?;
    if argument_bytes > MAX_COMMAND_BYTES {
        return invalid_output("configure", "inserted command arguments are too large");
    }
    if output
        .arguments_before_user
        .iter()
        .any(|value| value.as_bytes().contains(&0))
    {
        return invalid_output("configure", "an inserted command argument contains NUL");
    }
    if output.environment.len() + output.remove_environment.len() > MAX_ENVIRONMENT_ITEMS {
        return invalid_output("configure", "too many environment mutations");
    }
    let mut environment_bytes = 0_usize;
    for (name, value) in &output.environment {
        validate_environment_name(name)?;
        if output.remove_environment.contains(name) {
            return invalid_output(
                "configure",
                "an environment name cannot be both set and removed",
            );
        }
        if value.as_bytes().contains(&0) {
            return invalid_output("configure", "an environment value contains NUL");
        }
        environment_bytes = environment_bytes
            .checked_add(name.as_bytes().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .ok_or_else(|| AdapterHostError::InvalidOutput {
                operation: "configure",
                reason: "environment byte count overflowed".to_owned(),
            })?;
    }
    for name in &output.remove_environment {
        validate_environment_name(name)?;
        environment_bytes = environment_bytes
            .checked_add(name.as_bytes().len())
            .ok_or_else(|| AdapterHostError::InvalidOutput {
                operation: "configure",
                reason: "environment byte count overflowed".to_owned(),
            })?;
    }
    if environment_bytes > MAX_ENVIRONMENT_BYTES {
        return invalid_output("configure", "environment mutations are too large");
    }
    validate_labels("known gap", &output.known_gaps)?;
    Ok(ValidatedConfiguration {
        arguments_before_user: output.arguments_before_user,
        environment: output.environment,
        remove_environment: output.remove_environment,
        known_gaps: output.known_gaps,
    })
}

fn validate_environment_name(name: &OsStr) -> Result<(), AdapterHostError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.contains(&0)
        || bytes.contains(&b'=')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return invalid_output("configure", "an environment name is invalid");
    }
    if bytes
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"IOREC_"))
    {
        return invalid_output(
            "configure",
            "recorder-owned IOREC_ environment names are protected",
        );
    }
    Ok(())
}

fn validate_command(command: &[OsString], operation: &'static str) -> Result<(), AdapterHostError> {
    if command.is_empty() || command.len() > MAX_COMMAND_ITEMS {
        return Err(AdapterHostError::InvalidInput {
            operation,
            reason: "command must contain 1..=4096 items".to_owned(),
        });
    }
    let mut total = 0_usize;
    for item in command {
        if item.as_bytes().contains(&0) {
            return Err(AdapterHostError::InvalidInput {
                operation,
                reason: "command contains NUL".to_owned(),
            });
        }
        total = total.checked_add(item.as_bytes().len()).ok_or_else(|| {
            AdapterHostError::InvalidInput {
                operation,
                reason: "command byte count overflowed".to_owned(),
            }
        })?;
    }
    if total > MAX_COMMAND_BYTES {
        return Err(AdapterHostError::InvalidInput {
            operation,
            reason: "command is too large".to_owned(),
        });
    }
    Ok(())
}

fn validate_parsed_shape(
    event: &ParsedEvent,
    operation: &'static str,
    label: &str,
) -> Result<(), AdapterHostError> {
    validate_label(label, &event.event, 256)
        .map_err(|reason| AdapterHostError::InvalidOutput { operation, reason })?;
    event
        .ids
        .validate()
        .map_err(|reason| AdapterHostError::InvalidOutput { operation, reason })?;
    if let Some(confidence) = event.confidence {
        validate_confidence(confidence, operation)?;
    }
    validate_labels("event evidence", &event.evidence)?;
    validate_value(
        &event.normalized,
        operation,
        "normalized event",
        MAX_PLUGIN_EVENT_BYTES,
    )
}

fn validate_value(
    value: &Value,
    operation: &'static str,
    label: &str,
    maximum_bytes: usize,
) -> Result<(), AdapterHostError> {
    let bytes = serde_json::to_vec(value).map_err(|error| AdapterHostError::InvalidOutput {
        operation,
        reason: format!("{label} cannot be encoded: {error}"),
    })?;
    if bytes.len() > maximum_bytes {
        return Err(AdapterHostError::InvalidOutput {
            operation,
            reason: format!("{label} exceeds {maximum_bytes} encoded bytes"),
        });
    }
    validate_json_complexity(&bytes).map_err(|error| AdapterHostError::InvalidOutput {
        operation,
        reason: format!("{label} exceeds structural limits: {error}"),
    })
}

fn validate_confidence(confidence: f32, operation: &'static str) -> Result<(), AdapterHostError> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(AdapterHostError::InvalidOutput {
            operation,
            reason: "confidence must be a finite value between zero and one".to_owned(),
        });
    }
    Ok(())
}

fn validate_labels(label: &str, values: &[String]) -> Result<(), AdapterHostError> {
    if values.len() > MAX_LABEL_ITEMS {
        return invalid_output("adapter", &format!("too many {label} values"));
    }
    for value in values {
        validate_label(label, value, MAX_LABEL_BYTES).map_err(|reason| {
            AdapterHostError::InvalidOutput {
                operation: "adapter",
                reason,
            }
        })?;
    }
    Ok(())
}

fn validate_label(label: &str, value: &str, maximum_bytes: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} must be non-empty, bounded, and free of control characters"
        ));
    }
    Ok(())
}

fn invalid_output<T>(operation: &'static str, reason: &str) -> Result<T, AdapterHostError> {
    Err(AdapterHostError::InvalidOutput {
        operation,
        reason: reason.to_owned(),
    })
}

fn bounded_text(value: &str, maximum_bytes: usize) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let rendered = if character.is_control() {
            '�'
        } else {
            character
        };
        if output.len() + rendered.len_utf8() > maximum_bytes {
            break;
        }
        output.push(rendered);
    }
    if output.is_empty() {
        "adapter operation failed".to_owned()
    } else {
        output
    }
}

fn safe_failure_text(value: &str) -> String {
    let lowercase = value.to_ascii_lowercase();
    if [
        "authorization",
        "bearer",
        "cookie",
        "password",
        "secret",
        "token",
        "sk-",
    ]
    .iter()
    .any(|marker| lowercase.contains(marker))
    {
        "sensitive adapter failure detail suppressed".to_owned()
    } else {
        bounded_text(value, MAX_FAILURE_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct CompleteAdapter;

    impl AdapterSdk for CompleteAdapter {
        fn detect(&self, context: &DetectContext) -> AdapterResult<Detection> {
            Ok(if context.command[0] == OsStr::new("third-party-agent") {
                Detection::matched(1.0, "executable name matched")
            } else {
                Detection::no_match("executable name did not match")
            })
        }

        fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
            let mut output = AdapterConfiguration::default();
            output
                .arguments_before_user
                .push(OsString::from("--enable-recorder-hook"));
            output.environment.insert(
                OsString::from("THIRD_PARTY_OBSERVER"),
                OsString::from("enabled"),
            );
            output
                .known_gaps
                .push("native hook does not expose wire bytes".to_owned());
            Ok(output)
        }

        fn parse(&self, context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
            let mut event = ParsedEvent::new("model_request", context.payload.clone());
            event.ids.inference_id = Some("inference-1".to_owned());
            event.confidence = Some(0.8);
            event.evidence.push("third-party.native-hook.v1".to_owned());
            Ok(vec![event])
        }

        fn correlate(&self, context: &CorrelateContext) -> AdapterResult<Correlation> {
            let candidate = &context.candidates[0];
            Ok(Correlation {
                selected_candidate: Some(candidate.candidate_id.clone()),
                ids: candidate.ids.clone(),
                basis: CorrelationBasis::Temporal,
                confidence: 0.99,
                evidence: vec!["time-window".to_owned()],
                unresolved_reason: None,
            })
        }
    }

    fn host() -> AdapterHost {
        AdapterHost::new("third-party", "1.2.3", ADAPTER_SDK_VERSION, CompleteAdapter).unwrap()
    }

    #[test]
    fn third_party_implements_only_four_operations_end_to_end() {
        let host = host();
        let detect = DetectContext::new(vec![OsString::from("third-party-agent")]);
        assert!(host.detect(&detect).unwrap().matched);

        let temporary = tempfile::tempdir().unwrap();
        let configure = ConfigureContext::new(detect.command.clone(), temporary.path().to_owned());
        let configuration = host.configure(&configure).unwrap();
        let mut command = detect.command;
        configuration.apply_command(&mut command).unwrap();
        assert_eq!(command[1], OsStr::new("--enable-recorder-hook"));
        assert_eq!(configuration.known_gaps().len(), 1);

        let parse = ParseContext::new(
            "run-sdk",
            "native-hook",
            "BeforeModel",
            json!({"model": "example"}),
        );
        let parsed = host.parse(&parse).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].source, "adapter:third-party");
        assert!(
            parsed[0]
                .evidence
                .iter()
                .any(|value| value.contains("api=1.0"))
        );

        let correlate = CorrelateContext::new(
            ParsedEvent::new("model_request", json!({})),
            vec![CorrelationCandidate {
                candidate_id: "transport-1".to_owned(),
                source: "proxy".to_owned(),
                event: "logical_inference_request".to_owned(),
                ids: EventIds {
                    inference_id: Some("inference-1".to_owned()),
                    ..EventIds::default()
                },
                observed_at: Utc::now(),
            }],
        );
        let correlated = host.correlate(&correlate).unwrap();
        assert_eq!(
            correlated.selected_candidate.as_deref(),
            Some("transport-1")
        );
        assert!((correlated.confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn incompatible_versions_are_rejected_before_adapter_execution() {
        let error = AdapterHost::new(
            "third-party",
            "1.0.0",
            ApiVersion { major: 2, minor: 0 },
            CompleteAdapter,
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            AdapterHostError::IncompatibleVersion { .. }
        ));
    }

    struct ReservedEnvironmentAdapter;

    impl AdapterSdk for ReservedEnvironmentAdapter {
        fn detect(&self, _context: &DetectContext) -> AdapterResult<Detection> {
            Ok(Detection::matched(1.0, "match"))
        }

        fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
            let mut output = AdapterConfiguration::default();
            output.environment.insert(
                OsString::from("IOREC_COLLECTOR_TOKEN"),
                OsString::from("replacement"),
            );
            Ok(output)
        }

        fn parse(&self, _context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
            Ok(Vec::new())
        }

        fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
            Ok(Correlation::unresolved("no candidates"))
        }
    }

    #[test]
    fn adapter_cannot_replace_recorder_owned_environment() {
        let host = AdapterHost::new(
            "reserved-env",
            "1.0.0",
            ADAPTER_SDK_VERSION,
            ReservedEnvironmentAdapter,
        )
        .unwrap();
        let context = ConfigureContext::new(
            vec![OsString::from("agent")],
            PathBuf::from("/private/scratch"),
        );
        assert!(matches!(
            host.configure(&context),
            Err(AdapterHostError::InvalidOutput { .. })
        ));
    }

    struct OversizedParser;

    impl AdapterSdk for OversizedParser {
        fn detect(&self, _context: &DetectContext) -> AdapterResult<Detection> {
            Ok(Detection::matched(1.0, "match"))
        }

        fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
            Ok(AdapterConfiguration::default())
        }

        fn parse(&self, _context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
            Ok(vec![ParsedEvent::new(
                "too_large",
                Value::String("x".repeat(MAX_PLUGIN_EVENT_BYTES + 1)),
            )])
        }

        fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
            Ok(Correlation::unresolved("none"))
        }
    }

    #[test]
    fn oversized_parser_output_fails_closed() {
        let host =
            AdapterHost::new("oversized", "1.0.0", ADAPTER_SDK_VERSION, OversizedParser).unwrap();
        let context = ParseContext::new("run-sdk", "hook", "event", json!({}));
        assert!(matches!(
            host.parse(&context),
            Err(AdapterHostError::InvalidOutput { .. })
        ));
    }

    struct PanickingAdapter;

    impl AdapterSdk for PanickingAdapter {
        fn detect(&self, _context: &DetectContext) -> AdapterResult<Detection> {
            panic!("plugin panic must not cross host boundary")
        }

        fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
            unreachable!()
        }

        fn parse(&self, _context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
            unreachable!()
        }

        fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
            unreachable!()
        }
    }

    #[test]
    fn plugin_panic_is_contained() {
        let host =
            AdapterHost::new("panicker", "1.0.0", ADAPTER_SDK_VERSION, PanickingAdapter).unwrap();
        let error = host
            .detect(&DetectContext::new(vec![OsString::from("agent")]))
            .unwrap_err();
        assert!(matches!(error, AdapterHostError::Panicked("detect")));
    }

    struct UnknownCandidateAdapter;

    impl AdapterSdk for UnknownCandidateAdapter {
        fn detect(&self, _context: &DetectContext) -> AdapterResult<Detection> {
            Ok(Detection::no_match("irrelevant"))
        }

        fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
            Ok(AdapterConfiguration::default())
        }

        fn parse(&self, _context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
            Ok(Vec::new())
        }

        fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
            Ok(Correlation {
                selected_candidate: Some("invented".to_owned()),
                ids: EventIds::default(),
                basis: CorrelationBasis::Heuristic,
                confidence: 1.0,
                evidence: Vec::new(),
                unresolved_reason: None,
            })
        }
    }

    #[test]
    fn correlation_cannot_select_an_invented_candidate() {
        let host = AdapterHost::new(
            "inventor",
            "1.0.0",
            ADAPTER_SDK_VERSION,
            UnknownCandidateAdapter,
        )
        .unwrap();
        let context = CorrelateContext::new(
            ParsedEvent::new("event", json!({})),
            vec![CorrelationCandidate {
                candidate_id: "real".to_owned(),
                source: "proxy".to_owned(),
                event: "request".to_owned(),
                ids: EventIds::default(),
                observed_at: Utc::now(),
            }],
        );
        assert!(matches!(
            host.correlate(&context),
            Err(AdapterHostError::InvalidOutput { .. })
        ));
    }

    #[test]
    fn adapter_failure_summary_suppresses_credential_shaped_text() {
        let failure = AdapterFailure::new(
            AdapterFailureKind::Internal,
            "Authorization: Bearer diagnostic-secret-canary",
        );
        assert_eq!(
            failure.summary(),
            "sensitive adapter failure detail suppressed"
        );
        assert!(!failure.to_string().contains("diagnostic-secret-canary"));
    }
}
