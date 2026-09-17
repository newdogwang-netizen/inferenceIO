use std::collections::BTreeSet;

use http::{HeaderMap, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::model::RedactionRecord;

const ALWAYS_SECRET_HEADERS: &[&str] = &[
    "authorization",
    "authentication-info",
    "proxy-authorization",
    "proxy-authentication-info",
    "cookie",
    "set-cookie",
    // URL-bearing response headers can contain presigned object URLs, OAuth
    // callback state, or userinfo. They are forwarded unchanged but never
    // copied into ordinary event metadata.
    "location",
    "content-location",
    "link",
    "refresh",
    "x-api-key",
    "x-goog-api-key",
    "x-amz-security-token",
    "x-auth-token",
    "x-access-token",
    "api-key",
    "authentication",
    "grpc-metadata-authorization",
];

const ALWAYS_SECRET_JSON_KEYS: &[&str] = &[
    "authorization",
    "proxy_authorization",
    "proxy-authorization",
    "cookie",
    "set_cookie",
    "set-cookie",
    "x_api_key",
    "x-api-key",
    "x_google_api_key",
    "x_goog_api_key",
    "x-goog-api-key",
    "x_amz_security_token",
    "x-amz-security-token",
    "api_key",
    "api-key",
    "access_token",
    "refresh_token",
    "client_secret",
    "password",
];

const MAX_SANITIZED_JSON_DEPTH: usize = 64;
const MAX_SANITIZED_JSON_NODES: usize = 100_000;
const MAX_SANITIZED_CONTAINER_ITEMS: usize = 10_000;
const MAX_RECORDED_REDACTION_FIELDS: usize = 1_024;
const JSON_TRUNCATION_MARKER: &str = "[IOREC_CAPTURE_TRUNCATED]";
pub const MAX_CAPTURE_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CAPTURE_BODY_BYTES_U64: u64 = 64 * 1024 * 1024;
const MAX_ALLOWED_PATHS: usize = 1_024;
const MAX_ALLOWED_PATH_BYTES: usize = 2_048;
const MAX_REDACT_HEADERS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyCaptureMode {
    Full,
    MetadataOnly,
}

/// Physical framing used for the append-only event log.
///
/// The default remains the original one-event-per-line representation so
/// existing manifests retain their canonical JSON representation. New runs
/// can opt into independently recoverable zstd blocks without changing any
/// logical event schema.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventLogFormat {
    #[default]
    Jsonl,
    ZstdBlocks,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_event_log_format(value: &EventLogFormat) -> bool {
    matches!(value, EventLogFormat::Jsonl)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturePolicy {
    pub name: String,
    pub body_mode: BodyCaptureMode,
    /// Compress bounded groups of event envelopes before optional at-rest
    /// encryption. Each block remains an independent durability/recovery unit.
    #[serde(default, skip_serializing_if = "is_default_event_log_format")]
    pub event_log_format: EventLogFormat,
    /// Maximum physical bytes retained in the append-only event log for the
    /// whole run, including encryption framing and line delimiters.
    #[serde(
        default = "default_max_event_storage_bytes",
        skip_serializing_if = "is_default_max_event_storage_bytes"
    )]
    pub max_event_storage_bytes: u64,
    /// Maximum plaintext bytes retained for any one request or response.
    pub max_blob_bytes: u64,
    /// Maximum physical bytes retained in the content-addressed blob store for
    /// the whole run. Existing and orphaned files count against the budget.
    #[serde(
        default = "default_max_run_blob_storage_bytes",
        skip_serializing_if = "is_default_max_run_blob_storage_bytes"
    )]
    pub max_run_blob_storage_bytes: u64,
    pub allowed_paths: Vec<String>,
    pub redact_headers: BTreeSet<String>,
}

const fn default_max_event_storage_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_max_event_storage_bytes(value: &u64) -> bool {
    *value == default_max_event_storage_bytes()
}

const fn default_max_run_blob_storage_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_max_run_blob_storage_bytes(value: &u64) -> bool {
    *value == default_max_run_blob_storage_bytes()
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            name: "default".to_owned(),
            body_mode: BodyCaptureMode::Full,
            event_log_format: EventLogFormat::Jsonl,
            max_event_storage_bytes: default_max_event_storage_bytes(),
            max_blob_bytes: 64 * 1024 * 1024,
            max_run_blob_storage_bytes: default_max_run_blob_storage_bytes(),
            allowed_paths: Vec::new(),
            redact_headers: ALWAYS_SECRET_HEADERS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }
}

impl CapturePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() || self.name.len() > 128 || self.name.chars().any(char::is_control)
        {
            return Err("capture policy name is invalid".to_owned());
        }
        if self.max_blob_bytes > MAX_CAPTURE_BODY_BYTES_U64 {
            return Err(format!(
                "capture body limit exceeds the {MAX_CAPTURE_BODY_BYTES_U64}-byte writer limit"
            ));
        }
        if self.allowed_paths.len() > MAX_ALLOWED_PATHS {
            return Err(format!(
                "capture policy has more than {MAX_ALLOWED_PATHS} allowed path prefixes"
            ));
        }
        for path in &self.allowed_paths {
            if !path.starts_with('/')
                || path.len() > MAX_ALLOWED_PATH_BYTES
                || path.chars().any(char::is_control)
            {
                return Err("capture policy contains an invalid allowed path prefix".to_owned());
            }
        }
        if self.redact_headers.len() > MAX_REDACT_HEADERS {
            return Err(format!(
                "capture policy has more than {MAX_REDACT_HEADERS} redacted headers"
            ));
        }
        for name in &self.redact_headers {
            if name.bytes().any(|byte| byte.is_ascii_uppercase())
                || http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            {
                return Err("capture policy contains an invalid header name".to_owned());
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn permits_body(&self, path: &str) -> bool {
        self.body_mode == BodyCaptureMode::Full
            && (self.allowed_paths.is_empty()
                || self
                    .allowed_paths
                    .iter()
                    .any(|prefix| path.starts_with(prefix)))
    }

    /// Produce a log-safe header representation. Secret values are never
    /// returned to the event pipeline, even when callers misconfigure policy.
    #[must_use]
    pub fn sanitize_headers(&self, headers: &HeaderMap) -> (Value, RedactionRecord) {
        let mut output = serde_json::Map::new();
        let mut redacted = BTreeSet::new();

        for name in headers.keys() {
            let canonical = name.as_str().to_ascii_lowercase();
            let is_secret =
                self.redact_headers.contains(&canonical) || is_secret_header(&canonical);
            let values = headers.get_all(name);

            if is_secret {
                output.insert(canonical.clone(), json!(["[REDACTED]"]));
                redacted.insert(canonical);
                continue;
            }

            let safe_values: Vec<String> = values
                .iter()
                .map(|value| match value.to_str() {
                    Ok(text) => text.to_owned(),
                    Err(_) => "[NON_UTF8]".to_owned(),
                })
                .collect();
            output.insert(canonical, json!(safe_values));
        }

        // Host is useful for correlation but must never be inferred from a
        // credential-bearing absolute URI.
        if !output.contains_key(header::HOST.as_str()) {
            output.insert(header::HOST.as_str().to_owned(), Value::Array(Vec::new()));
        }

        (
            Value::Object(output),
            RedactionRecord {
                policy: self.name.clone(),
                fields: redacted.into_iter().collect(),
                omitted: Vec::new(),
            },
        )
    }

    /// Recursively redact credential-shaped JSON fields before an adapter
    /// payload enters either the normalized event or blob store.
    #[must_use]
    pub fn sanitize_json(&self, value: &Value) -> (Value, RedactionRecord) {
        self.sanitize_json_owned(value.clone())
    }

    /// Consume and sanitize a JSON value without retaining a second copy of
    /// large hook or session payloads while the sanitized tree is built.
    #[must_use]
    pub fn sanitize_json_owned(&self, value: Value) -> (Value, RedactionRecord) {
        let limits = JsonSanitizerLimits {
            depth: MAX_SANITIZED_JSON_DEPTH,
            nodes: MAX_SANITIZED_JSON_NODES,
            container_items: MAX_SANITIZED_CONTAINER_ITEMS,
            redaction_fields: MAX_RECORDED_REDACTION_FIELDS,
        };
        let mut sanitizer = JsonSanitizer::new(limits);
        let output = sanitizer.sanitize(value, "$", 0);
        (
            output,
            RedactionRecord {
                policy: self.name.clone(),
                fields: sanitizer.fields,
                omitted: if sanitizer.truncated {
                    vec!["json_payload_safety_limit".to_owned()]
                } else {
                    Vec::new()
                },
            },
        )
    }
}

#[derive(Clone, Copy)]
struct JsonSanitizerLimits {
    depth: usize,
    nodes: usize,
    container_items: usize,
    redaction_fields: usize,
}

struct JsonSanitizer {
    limits: JsonSanitizerLimits,
    visited: usize,
    fields: Vec<String>,
    truncated: bool,
}

impl JsonSanitizer {
    fn new(limits: JsonSanitizerLimits) -> Self {
        Self {
            limits,
            visited: 0,
            fields: Vec::new(),
            truncated: false,
        }
    }

    fn sanitize(&mut self, value: Value, path: &str, depth: usize) -> Value {
        if self.visited >= self.limits.nodes {
            self.truncated = true;
            return Value::String(JSON_TRUNCATION_MARKER.to_owned());
        }
        self.visited = self.visited.saturating_add(1);
        match value {
            Value::Object(object) => {
                if depth >= self.limits.depth {
                    self.truncated = true;
                    return Value::String(JSON_TRUNCATION_MARKER.to_owned());
                }
                let mut output = serde_json::Map::new();
                for (index, (key, value)) in object.into_iter().enumerate() {
                    if index >= self.limits.container_items {
                        self.truncated = true;
                        break;
                    }
                    let child_path = json_child_path(path, &key);
                    if is_secret_json_key(&key) {
                        if self.fields.len() < self.limits.redaction_fields {
                            self.fields.push(child_path);
                        } else {
                            self.truncated = true;
                        }
                        output.insert(key, Value::String("[REDACTED]".to_owned()));
                    } else {
                        output.insert(key, self.sanitize(value, &child_path, depth + 1));
                    }
                }
                Value::Object(output)
            }
            Value::Array(values) => {
                if depth >= self.limits.depth {
                    self.truncated = true;
                    return Value::String(JSON_TRUNCATION_MARKER.to_owned());
                }
                let mut output = Vec::with_capacity(values.len().min(self.limits.container_items));
                for (index, value) in values.into_iter().enumerate() {
                    if index >= self.limits.container_items {
                        self.truncated = true;
                        break;
                    }
                    let child_path = crate::metadata::bounded_string(&format!("{path}[{index}]"));
                    output.push(self.sanitize(value, &child_path, depth + 1));
                }
                Value::Array(output)
            }
            scalar => scalar,
        }
    }
}

fn json_child_path(path: &str, key: &str) -> String {
    let key = crate::metadata::bounded_string(key);
    crate::metadata::bounded_string(&format!("{path}.{key}"))
}

pub(crate) fn is_secret_header(name: &str) -> bool {
    ALWAYS_SECRET_HEADERS.contains(&name)
        || name.ends_with("-api-key")
        || name.ends_with("-auth-token")
        || name.ends_with("-access-token")
        || name.ends_with("-security-token")
        || name.ends_with("-client-secret")
        || name.ends_with("-credential")
        || name.ends_with("-password")
        || name.ends_with("-signature")
}

fn is_secret_json_key(key: &str) -> bool {
    let lowercase = key.to_ascii_lowercase();
    let normalized = lowercase.replace('-', "_");
    ALWAYS_SECRET_JSON_KEYS.contains(&lowercase.as_str())
        || matches!(
            normalized.as_str(),
            "token" | "secret" | "password" | "apikey" | "api_key"
        )
        || normalized.ends_with("_access_token")
        || normalized.ends_with("_refresh_token")
        || normalized.ends_with("_security_token")
        || normalized.ends_with("_client_secret")
        || normalized.ends_with("_password")
        || normalized.ends_with("_api_key")
        || normalized.ends_with("apikey")
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn mandatory_secrets_cannot_be_unredacted() {
        let mut policy = CapturePolicy::default();
        policy.redact_headers.clear();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer do-not-log"),
        );
        headers.insert("x-request-id", HeaderValue::from_static("safe"));
        headers.insert(
            header::LOCATION,
            HeaderValue::from_static("https://objects.test/file?signature=do-not-log-either"),
        );
        headers.insert(
            "authentication-info",
            HeaderValue::from_static("nextnonce=private-nonce"),
        );
        headers.insert(
            "x-provider-signature",
            HeaderValue::from_static("private-signature"),
        );

        let (snapshot, record) = policy.sanitize_headers(&headers);
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("do-not-log"));
        assert!(!encoded.contains("private-nonce"));
        assert!(!encoded.contains("private-signature"));
        assert!(encoded.contains("safe"));
        assert_eq!(
            record.fields,
            vec![
                "authentication-info",
                "authorization",
                "location",
                "x-provider-signature",
            ]
        );
    }

    #[test]
    fn nested_json_credentials_are_removed() {
        let input = json!({
            "headers": {"Authorization": "secret", "x-safe": "value"},
            "items": [{"access_token": "also-secret"}],
            "googleApiKey": "camel-secret",
            "x_amz_security_token": "cloud-secret",
        });
        let (sanitized, record) = CapturePolicy::default().sanitize_json(&input);
        let encoded = sanitized.to_string();
        assert!(!encoded.contains("also-secret"));
        assert!(!encoded.contains("camel-secret"));
        assert!(!encoded.contains("cloud-secret"));
        assert!(!encoded.contains("\"secret\""));
        assert!(encoded.contains("value"));
        assert_eq!(record.fields.len(), 4);
    }

    #[test]
    fn json_sanitization_limits_are_explicit_and_keep_secrets_redacted() {
        let limits = JsonSanitizerLimits {
            depth: 2,
            nodes: 4,
            container_items: 2,
            redaction_fields: 1,
        };
        let mut sanitizer = JsonSanitizer::new(limits);
        let output = sanitizer.sanitize(
            json!({
                "access_token": "first-secret",
                "password": "second-secret",
                "tail": [1, 2, 3],
            }),
            "$",
            0,
        );
        let encoded = output.to_string();
        assert!(!encoded.contains("first-secret"));
        assert!(!encoded.contains("second-secret"));
        assert_eq!(sanitizer.fields.len(), 1);
        assert!(sanitizer.truncated);

        let (bounded, record) = CapturePolicy::default().sanitize_json_owned(json!({
            "items": (0..=MAX_SANITIZED_CONTAINER_ITEMS).collect::<Vec<_>>()
        }));
        assert_eq!(
            bounded["items"].as_array().map(Vec::len),
            Some(MAX_SANITIZED_CONTAINER_ITEMS)
        );
        assert_eq!(record.omitted, vec!["json_payload_safety_limit"]);
    }

    #[test]
    fn default_run_budget_is_backward_canonicalization_compatible() {
        let encoded = serde_json::to_value(CapturePolicy::default()).unwrap();
        assert!(encoded.get("max_event_storage_bytes").is_none());
        assert!(encoded.get("max_run_blob_storage_bytes").is_none());
        assert!(encoded.get("event_log_format").is_none());
        let decoded: CapturePolicy = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            decoded.max_event_storage_bytes,
            default_max_event_storage_bytes()
        );
        assert_eq!(
            decoded.max_run_blob_storage_bytes,
            default_max_run_blob_storage_bytes()
        );
        assert_eq!(decoded.event_log_format, EventLogFormat::Jsonl);
    }

    #[test]
    fn capture_policy_rejects_ambiguous_or_unenforceable_limits() {
        let mut policy = CapturePolicy {
            allowed_paths: vec![String::new()],
            ..CapturePolicy::default()
        };
        assert!(policy.validate().is_err());
        policy.allowed_paths = vec!["/v1/responses".to_owned()];
        policy.max_blob_bytes = MAX_CAPTURE_BODY_BYTES_U64 + 1;
        assert!(policy.validate().is_err());
        policy.max_blob_bytes = MAX_CAPTURE_BODY_BYTES_U64;
        policy.redact_headers.insert("bad header".to_owned());
        assert!(policy.validate().is_err());
    }
}
