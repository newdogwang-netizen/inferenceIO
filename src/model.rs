use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::SCHEMA_VERSION;

/// A stable reference to immutable content in the run's blob store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    pub sha256: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventIds {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}

impl EventIds {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("task ID", self.task_id.as_deref()),
            ("session ID", self.session_id.as_deref()),
            ("turn ID", self.turn_id.as_deref()),
            ("inference ID", self.inference_id.as_deref()),
            ("attempt ID", self.attempt_id.as_deref()),
            ("connection ID", self.connection_id.as_deref()),
            ("parent ID", self.parent_id.as_deref()),
            ("container ID", self.container_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_text(name, value, 1024)?;
            }
        }
        if self.pid == Some(0) {
            return Err("process ID must be positive".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalState {
    Complete,
    Error,
    Cancelled,
    Incomplete,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RedactionRecord {
    pub policy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<String>,
}

/// Input accepted by the durable writer. Sequence and event identity are
/// assigned at the single serialization point.
#[derive(Debug, Clone)]
pub struct PendingEvent {
    pub run_id: String,
    pub source: String,
    pub kind: String,
    pub ids: EventIds,
    pub observed_at: DateTime<Utc>,
    pub monotonic_ns: u64,
    pub raw: Option<PayloadRef>,
    pub normalized: Option<Value>,
    pub redaction: RedactionRecord,
    pub confidence: Option<f32>,
    pub evidence: Vec<String>,
    pub terminal_state: Option<TerminalState>,
}

impl PendingEvent {
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        source: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            source: source.into(),
            kind: kind.into(),
            ids: EventIds::default(),
            observed_at: Utc::now(),
            monotonic_ns: 0,
            raw: None,
            normalized: None,
            redaction: RedactionRecord {
                policy: "default".to_owned(),
                ..RedactionRecord::default()
            },
            confidence: None,
            evidence: Vec::new(),
            terminal_state: None,
        }
    }
}

/// Append-only evidence envelope. New schema versions must remain readable;
/// raw content is never rewritten during normalization or migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub event_id: Uuid,
    pub sequence: u64,
    pub run_id: String,
    #[serde(flatten)]
    pub ids: EventIds,
    pub source: String,
    pub event: String,
    pub monotonic_ns: u64,
    pub wall_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<PayloadRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<Value>,
    pub redaction: RedactionRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<TerminalState>,
}

impl EventEnvelope {
    #[must_use]
    pub fn from_pending(sequence: u64, event: PendingEvent) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            sequence,
            run_id: event.run_id,
            ids: event.ids,
            source: event.source,
            event: event.kind,
            monotonic_ns: event.monotonic_ns,
            wall_time: event.observed_at,
            raw: event.raw,
            normalized: event.normalized,
            redaction: event.redaction,
            confidence: event.confidence,
            evidence: event.evidence,
            terminal_state: event.terminal_state,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported event schema version {}",
                self.schema_version
            ));
        }
        if self.sequence == 0 {
            return Err("event sequence must be positive".to_owned());
        }
        if self.event_id.is_nil() {
            return Err("event ID must not be nil".to_owned());
        }
        if self.event_id.get_version_num() != 7 {
            return Err("event ID must be a time-ordered UUIDv7".to_owned());
        }
        validate_text("run ID", &self.run_id, 256)?;
        validate_text("event source", &self.source, 128)?;
        validate_text("event name", &self.event, 256)?;
        self.ids.validate()?;
        if let Some(confidence) = self.confidence
            && !(0.0..=1.0).contains(&confidence)
        {
            return Err("event confidence must be between zero and one".to_owned());
        }
        if let Some(raw) = self.raw.as_ref() {
            let hash = raw
                .sha256
                .strip_prefix("sha256:")
                .ok_or_else(|| "payload reference must use the sha256: prefix".to_owned())?;
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("payload reference contains an invalid SHA-256 digest".to_owned());
            }
            if let Some(media_type) = raw.media_type.as_deref()
                && (media_type.is_empty()
                    || media_type.len() > 1024
                    || media_type.contains(['\0', '\r', '\n']))
            {
                return Err("payload media type is too long or contains delimiters".to_owned());
            }
        }
        validate_text("redaction policy", &self.redaction.policy, 128)?;
        validate_text_list("redacted field", &self.redaction.fields, 1024, 1024)?;
        validate_text_list("omitted field", &self.redaction.omitted, 1024, 1024)?;
        validate_text_list("evidence label", &self.evidence, 256, 1024)?;
        Ok(())
    }
}

fn validate_text(name: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(format!(
            "{name} is empty, too long, or contains control characters"
        ));
    }
    Ok(())
}

fn validate_text_list(
    name: &str,
    values: &[String],
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<(), String> {
    if values.len() > maximum_items {
        return Err(format!("{name} list has too many items"));
    }
    for value in values {
        validate_text(name, value, maximum_bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_envelope_uses_only_shared_v1_properties() {
        let mut pending = PendingEvent::new("run", "hook:hermes", "transport_request_started");
        pending.ids = EventIds {
            task_id: Some("task".to_owned()),
            session_id: Some("session".to_owned()),
            turn_id: Some("turn".to_owned()),
            inference_id: Some("inference".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            connection_id: Some("connection".to_owned()),
            parent_id: Some("parent".to_owned()),
            pid: Some(42),
            container_id: Some("container".to_owned()),
        };
        pending.raw = Some(PayloadRef {
            sha256: "sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
                .to_owned(),
            size: 7,
            media_type: Some("text/plain".to_owned()),
            truncated: false,
        });
        let event = EventEnvelope::from_pending(1, pending);
        event.validate().unwrap();

        let schema: Value =
            serde_json::from_str(include_str!("../schemas/event.v1.schema.json")).unwrap();
        let properties = schema["properties"].as_object().unwrap();
        let required = schema["required"].as_array().unwrap();
        let encoded = serde_json::to_value(event).unwrap();
        let object = encoded.as_object().unwrap();
        for field in object.keys() {
            assert!(
                properties.contains_key(field),
                "serialized field {field} is absent from the shared schema"
            );
        }
        for field in required {
            let field = field.as_str().unwrap();
            assert!(
                object.contains_key(field),
                "required field {field} is absent"
            );
        }
        assert_eq!(encoded["task_id"], "task");
        assert_eq!(encoded["session_id"], "session");
        assert_eq!(encoded["pid"], 42);
        assert!(encoded.get("ids").is_none());
        assert!(encoded.get("seq").is_none());
        assert!(encoded.get("payload").is_none());
    }

    #[test]
    fn envelope_validation_rejects_unsupported_schema_and_bad_blob_references() {
        let mut event = EventEnvelope::from_pending(1, PendingEvent::new("run", "test", "event"));
        assert!(event.validate().is_ok());
        event.schema_version = SCHEMA_VERSION + 1;
        assert!(event.validate().is_err());
        event.schema_version = SCHEMA_VERSION;
        event.raw = Some(PayloadRef {
            sha256: "sha256:not-a-digest".to_owned(),
            size: 1,
            media_type: None,
            truncated: false,
        });
        assert!(event.validate().is_err());

        event.raw = Some(PayloadRef {
            sha256: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_owned(),
            size: 1,
            media_type: None,
            truncated: false,
        });
        assert!(event.validate().is_err());

        event.raw = None;
        event.evidence = vec!["invalid\nlabel".to_owned()];
        assert!(event.validate().is_err());
        event.evidence = vec!["evidence".to_owned(); 257];
        assert!(event.validate().is_err());

        event.evidence.clear();
        event.event_id = Uuid::from_u128(1);
        assert!(event.validate().is_err());
    }
}
