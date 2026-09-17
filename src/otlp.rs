use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Timelike, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    RECORDER_VERSION, audit,
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    openinference::{BuiltSpans, SpanRecord, build_spans},
    secure_fs::commit_path_noreplace,
};

const OTLP_HTTP_TRACES_PATH: &str = "/v1/traces";
const OTLP_JSON_CONTENT_TYPE: &str = "application/json";
const MAX_ATTRIBUTE_DEPTH: usize = 64;
const MAX_ATTRIBUTE_NODES: usize = 1_000_000;

#[derive(Debug, Clone, Serialize)]
pub struct OtlpExportReport {
    pub run_id: String,
    pub output: PathBuf,
    pub format: &'static str,
    pub content_type: &'static str,
    pub endpoint_path: &'static str,
    pub spans: u64,
    pub attempts: u64,
    pub payloads_omitted: u64,
    pub bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportTraceServiceRequest {
    resource_spans: Vec<ResourceSpans>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceSpans {
    resource: Resource,
    scope_spans: Vec<ScopeSpans>,
}

#[derive(Serialize)]
struct Resource {
    attributes: Vec<KeyValue>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSpans {
    scope: InstrumentationScope,
    spans: Vec<OtlpSpan>,
}

#[derive(Serialize)]
struct InstrumentationScope {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpSpan {
    trace_id: String,
    span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_span_id: Option<String>,
    name: String,
    kind: u32,
    start_time_unix_nano: String,
    end_time_unix_nano: String,
    attributes: Vec<KeyValue>,
    status: OtlpStatus,
}

#[derive(Serialize)]
struct KeyValue {
    key: String,
    value: Value,
}

#[derive(Serialize)]
struct OtlpStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    code: u32,
}

struct ConversionBudget {
    remaining: usize,
}

pub fn export_otlp_with_key(
    run_dir: &Path,
    output: &Path,
    key: Option<&EncryptionKey>,
) -> anyhow::Result<OtlpExportReport> {
    let run_dir = run_dir.canonicalize()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let name = output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("OTLP export path has no file name"))?;
    let output = parent.join(name);
    anyhow::ensure!(
        !output.starts_with(&run_dir),
        "OTLP export must be outside the source run"
    );
    anyhow::ensure!(
        !output.try_exists()?,
        "refusing to overwrite existing OTLP export {}",
        output.display()
    );

    let inspection = inspect_run_with_key(&run_dir, true, key)?;
    let key = inspection.manifest.effective_encryption_key(key)?;
    let key = key.as_ref();
    anyhow::ensure!(
        inspection.manifest.status != "running",
        "refusing to export a run that is still being recorded"
    );
    anyhow::ensure!(
        inspection.log.discarded_tail_bytes == 0
            && inspection.missing_blobs.is_empty()
            && inspection.corrupt_blobs.is_empty(),
        "source run must pass event and blob integrity checks before OTLP export"
    );
    let audit_root = run_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("source run has no parent directory"))?;
    audit::append(
        audit_root,
        "export",
        "intent",
        &inspection.manifest.run_id,
        Some(json!({"format": "otlp"})),
    )?;

    let built = build_spans(&run_dir, key, &inspection)?;
    let request = build_request(&inspection.manifest.run_id, &built)?;
    let temporary = parent.join(format!(
        ".iorec-otlp-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    let write_result = (|| {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &request)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = commit_path_noreplace(&parent, &temporary, &output) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    File::open(&parent)?.sync_all()?;
    let metadata = fs::symlink_metadata(&output)?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "OTLP export is not a regular file"
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o777 == 0o600,
        "OTLP export permissions changed during commit"
    );
    audit::append(
        audit_root,
        "export",
        "complete",
        &inspection.manifest.run_id,
        Some(json!({
            "format": "otlp",
            "spans": built.spans.len(),
            "bytes": metadata.len(),
        })),
    )?;

    Ok(OtlpExportReport {
        run_id: inspection.manifest.run_id,
        output,
        format: "otlp-http-json-v1",
        content_type: OTLP_JSON_CONTENT_TYPE,
        endpoint_path: OTLP_HTTP_TRACES_PATH,
        spans: u64::try_from(built.spans.len()).unwrap_or(u64::MAX),
        attempts: built.attempts,
        payloads_omitted: built.payloads_omitted,
        bytes: metadata.len(),
    })
}

fn build_request(run_id: &str, built: &BuiltSpans) -> anyhow::Result<ExportTraceServiceRequest> {
    let mut budget = ConversionBudget {
        remaining: MAX_ATTRIBUTE_NODES,
    };
    let resource = Resource {
        attributes: vec![
            key_value("service.name", &json!("iorec"), &mut budget)?,
            key_value("service.version", &json!(RECORDER_VERSION), &mut budget)?,
            key_value("iorec.run_id", &json!(run_id), &mut budget)?,
        ],
    };
    let spans = built
        .spans
        .iter()
        .map(|span| otlp_span(span, &mut budget))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource,
            scope_spans: vec![ScopeSpans {
                scope: InstrumentationScope {
                    name: "io.inference.iorec",
                    version: RECORDER_VERSION,
                },
                spans,
            }],
        }],
    })
}

fn otlp_span(span: &SpanRecord, budget: &mut ConversionBudget) -> anyhow::Result<OtlpSpan> {
    anyhow::ensure!(
        span.trace_id.len() == 32 && span.trace_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid OTLP trace ID"
    );
    anyhow::ensure!(
        span.span_id.len() == 16 && span.span_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid OTLP span ID"
    );
    if let Some(parent) = &span.parent_span_id {
        anyhow::ensure!(
            parent.len() == 16 && parent.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid OTLP parent span ID"
        );
    }
    Ok(OtlpSpan {
        trace_id: span.trace_id.clone(),
        span_id: span.span_id.clone(),
        parent_span_id: span.parent_span_id.clone(),
        name: span.name.clone(),
        kind: if span.parent_span_id.is_some() { 3 } else { 1 },
        start_time_unix_nano: unix_nanos(span.start_time)?,
        end_time_unix_nano: unix_nanos(span.end_time)?,
        attributes: span
            .attributes
            .iter()
            .map(|(key, value)| key_value(key, value, budget))
            .collect::<anyhow::Result<Vec<_>>>()?,
        status: OtlpStatus {
            message: span.status.message.clone(),
            code: if span.status.code == "OK" { 1 } else { 2 },
        },
    })
}

fn unix_nanos(time: DateTime<Utc>) -> anyhow::Result<String> {
    let value = i128::from(time.timestamp())
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(i128::from(time.nanosecond())))
        .ok_or_else(|| anyhow::anyhow!("OTLP timestamp overflow"))?;
    let value = u64::try_from(value)
        .map_err(|_| anyhow::anyhow!("OTLP cannot encode a timestamp before the Unix epoch"))?;
    Ok(value.to_string())
}

fn key_value(key: &str, value: &Value, budget: &mut ConversionBudget) -> anyhow::Result<KeyValue> {
    anyhow::ensure!(!key.is_empty(), "OTLP attribute key must not be empty");
    Ok(KeyValue {
        key: key.to_owned(),
        value: any_value(value, 0, budget)?,
    })
}

fn any_value(value: &Value, depth: usize, budget: &mut ConversionBudget) -> anyhow::Result<Value> {
    anyhow::ensure!(
        depth <= MAX_ATTRIBUTE_DEPTH,
        "OTLP attribute nesting exceeds safety limit"
    );
    anyhow::ensure!(
        budget.remaining > 0,
        "OTLP attribute node count exceeds safety limit"
    );
    budget.remaining -= 1;
    match value {
        Value::Null => Ok(json!({})),
        Value::Bool(value) => Ok(json!({"boolValue": value})),
        Value::String(value) => Ok(json!({"stringValue": value})),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(json!({"intValue": value.to_string()}))
            } else if let Some(value) = value.as_u64() {
                if i64::try_from(value).is_ok() {
                    Ok(json!({"intValue": value.to_string()}))
                } else {
                    Ok(json!({"stringValue": value.to_string()}))
                }
            } else {
                Ok(json!({"doubleValue": value.as_f64().ok_or_else(||
                    anyhow::anyhow!("OTLP attribute number is not representable"))?}))
            }
        }
        Value::Array(values) => {
            let values = values
                .iter()
                .map(|value| any_value(value, depth + 1, budget))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(json!({"arrayValue": {"values": values}}))
        }
        Value::Object(values) => {
            let values = values
                .iter()
                .map(|(key, value)| key_value_nested(key, value, depth + 1, budget))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(json!({"kvlistValue": {"values": values}}))
        }
    }
}

fn key_value_nested(
    key: &str,
    value: &Value,
    depth: usize,
    budget: &mut ConversionBudget,
) -> anyhow::Result<KeyValue> {
    anyhow::ensure!(!key.is_empty(), "OTLP attribute key must not be empty");
    Ok(KeyValue {
        key: key.to_owned(),
        value: any_value(value, depth, budget)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    use crate::{
        manifest::{CommandMetadata, Manifest, write_atomic},
        model::{EventIds, TerminalState},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn exports_valid_otlp_http_json_request() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run");
        let mut manifest = Manifest::new(
            "otlp-run".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
                cwd: PathBuf::from("/tmp"),
                executable: None,
                executable_sha256: None,
                agent: Some("test-agent".to_owned()),
                agent_version: None,
                runtime: None,
                executable_tls_surfaces: Vec::new(),
                environment: BTreeMap::new(),
            },
            CapturePolicy::default(),
        );
        manifest.status = "finished".to_owned();
        manifest.exit_code = Some(0);
        manifest.finished_at = Some(Utc::now());
        write_atomic(&run.join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create(&run, "otlp-run", CapturePolicy::default()).unwrap();
        let ids = EventIds {
            task_id: Some("task-1".to_owned()),
            session_id: Some("session-1".to_owned()),
            inference_id: Some("inference".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            ..EventIds::default()
        };
        let mut started = store.event("proxy", "transport_request_started");
        started.ids = ids.clone();
        started.normalized = Some(json!({
            "method": "POST",
            "uri": "/v1/responses",
            "upstream": "https://api.openai.com/v1/responses",
        }));
        store.append(started).await.unwrap();
        let mut response = store.event("proxy", "transport_response_started");
        response.ids = ids.clone();
        response.normalized = Some(json!({"status": 200}));
        store.append(response).await.unwrap();
        let mut done = store.event("proxy", "transport_attempt_finished");
        done.ids = ids;
        done.terminal_state = Some(TerminalState::Complete);
        done.normalized = Some(json!({"status": 200}));
        store.append(done).await.unwrap();
        store.shutdown().await.unwrap();

        let output = temporary.path().join("traces.json");
        let report = export_otlp_with_key(&run, &output, None).unwrap();
        assert_eq!(report.format, "otlp-http-json-v1");
        assert_eq!(report.content_type, "application/json");
        assert_eq!(report.endpoint_path, "/v1/traces");
        assert_eq!(report.spans, 2);
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let request: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert!(request.get("resource_spans").is_none());
        let spans = request
            .pointer("/resourceSpans/0/scopeSpans/0/spans")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].get("kind"), Some(&json!(1)));
        assert_eq!(spans[1].get("kind"), Some(&json!(3)));
        assert_eq!(spans[1].get("parentSpanId"), spans[0].get("spanId"));
        assert_eq!(spans[0]["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(spans[0]["spanId"].as_str().unwrap().len(), 16);
        assert!(
            spans[0]["startTimeUnixNano"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .is_ok()
        );
        assert_eq!(spans[1]["status"]["code"], json!(1));
        let attributes = spans[1]["attributes"].as_array().unwrap();
        let status = attributes
            .iter()
            .find(|attribute| attribute["key"] == "http.response.status_code")
            .unwrap();
        assert_eq!(status["value"]["intValue"], json!("200"));
        let sequences = attributes
            .iter()
            .find(|attribute| attribute["key"] == "iorec.evidence.event_sequences")
            .unwrap();
        assert!(
            sequences["value"]["arrayValue"]["values"]
                .as_array()
                .unwrap()
                .iter()
                .all(|value| value["intValue"].is_string())
        );
        let logical_task = attributes
            .iter()
            .find(|attribute| attribute["key"] == "iorec.logical_task_id")
            .unwrap();
        assert_eq!(logical_task["value"]["stringValue"], json!("task:task-1"));
        assert!(export_otlp_with_key(&run, &output, None).is_err());
    }

    #[test]
    fn converts_nested_json_without_violating_int64_encoding() {
        let mut budget = ConversionBudget { remaining: 32 };
        let value = any_value(
            &json!({"items": [1, true, null], "too_large": u64::MAX}),
            0,
            &mut budget,
        )
        .unwrap();
        let values = value["kvlistValue"]["values"].as_array().unwrap();
        assert_eq!(
            values[0]["value"]["arrayValue"]["values"][0]["intValue"],
            "1"
        );
        assert_eq!(values[1]["value"]["stringValue"], u64::MAX.to_string());
    }
}
