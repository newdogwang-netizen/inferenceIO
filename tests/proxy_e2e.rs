use std::{collections::BTreeMap, fs, net::SocketAddr, path::Path, time::Duration};

use axum::{Json, Router, routing::post};
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use http::header;
use iorec::{
    fake_server::{FakeServerConfig, start as start_fake_server},
    inspect::inspect_run,
    manifest::{CommandMetadata, Manifest, write_atomic},
    model::{EventEnvelope, TerminalState},
    policy::CapturePolicy,
    proxy::{
        ProxyConfig, start as start_proxy, start_http2_prior_knowledge as start_http2_proxy,
        start_transparent_tls,
    },
    storage::{RunStore, for_each_event},
    transparent::TransparentArtifacts,
};
use rustls::pki_types::pem::PemObject as _;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_tungstenite::{
    Connector, client_async_tls_with_config, connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use url::Url;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn read_events(path: &Path) -> Vec<EventEnvelope> {
    let mut events = Vec::new();
    for_each_event(&path.join("events.jsonl"), |event| {
        events.push(event);
        Ok(())
    })
    .unwrap();
    events
}

fn blob(path: &Path, hash: &str) -> Vec<u8> {
    fs::read(
        path.join("blobs")
            .join(format!("sha256-{}", hash.trim_start_matches("sha256:"))),
    )
    .unwrap()
}

fn complete_responses_stream(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.ends_with("\n\n")
            && text.contains("event: response.completed\n")
            && text.contains("\"type\":\"response.completed\"")
    })
}

fn write_test_manifest(path: &Path, run_id: &str, policy: CapturePolicy) {
    let manifest = Manifest::new(
        run_id.to_owned(),
        CommandMetadata {
            argv: vec!["test".to_owned()],
            cwd: path.to_path_buf(),
            executable: None,
            executable_sha256: None,
            agent: None,
            agent_version: None,
            runtime: None,
            executable_tls_surfaces: Vec::new(),
            environment: BTreeMap::new(),
        },
        policy,
    );
    write_atomic(&path.join("manifest.json"), &manifest).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_version_prefix_overlap_forwards_to_exact_upstream_path() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, _) = RunStore::create(
        temporary.path(),
        "provider-prefix",
        CapturePolicy::default(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind(loopback()).await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/inference/v1/chat/completions",
                post(|| async { Json(json!({"id": "exact-provider-path"})) }),
            ),
        )
        .await
        .unwrap();
    });
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{upstream_address}/inference/v1")).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/chat/completions", proxy.address))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let response_body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(response_body["id"], "exact-provider-path");

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    store.shutdown().await.unwrap();
    upstream.abort();
    let _ = upstream.await;

    assert!(read_events(temporary.path()).iter().any(|event| {
        event.event == "transport_request_started"
            && event
                .normalized
                .as_ref()
                .and_then(|value| value.pointer("/upstream/path"))
                .and_then(serde_json::Value::as_str)
                == Some("/inference/v1/chat/completions")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_exact_stream_and_never_persists_authorization() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy {
        allowed_paths: vec!["/v1/responses".to_owned()],
        ..CapturePolicy::default()
    };
    let (store, _) = RunStore::create(temporary.path(), "e2e", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let request_body = vec![b'a'; 512 * 1024];
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .header("authorization", "Bearer must-never-reach-disk")
        .header("content-type", "application/json")
        .header("x-iorec-chunks", "5")
        .body(request_body.clone())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response_body = response.bytes().await.unwrap();
    assert!(complete_responses_stream(&response_body));

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();
    let events = read_events(temporary.path());
    let persisted_text = fs::read_to_string(temporary.path().join("events.jsonl")).unwrap();
    assert!(!persisted_text.contains("must-never-reach-disk"));
    assert!(persisted_text.contains("[REDACTED]"));

    let captured_request: Vec<u8> = events
        .iter()
        .filter(|event| event.event == "request_body_chunk")
        .filter_map(|event| event.raw.as_ref())
        .flat_map(|reference| blob(temporary.path(), &reference.sha256))
        .collect();
    assert_eq!(captured_request, request_body);

    let captured_response: Vec<u8> = events
        .iter()
        .filter(|event| event.event == "response_body_chunk")
        .filter_map(|event| event.raw.as_ref())
        .flat_map(|reference| blob(temporary.path(), &reference.sha256))
        .collect();
    assert_eq!(captured_response, response_body);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event == "sse_event")
            .count(),
        13
    );
    assert!(events.iter().any(|event| {
        event.event == "transport_attempt_finished"
            && event.terminal_state == Some(TerminalState::Complete)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_raw_events_cannot_bypass_the_response_body_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy {
        max_blob_bytes: 32,
        ..CapturePolicy::default()
    };
    let (store, _) = RunStore::create(temporary.path(), "sse-limit", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .header("x-iorec-chunks", "5")
        .body("request")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let _ = response.bytes().await.unwrap();
    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();

    let events = read_events(temporary.path());
    let response_captured: u64 = events
        .iter()
        .filter(|event| event.event == "response_body_chunk")
        .filter_map(|event| event.raw.as_ref())
        .map(|raw| raw.size)
        .sum();
    assert_eq!(response_captured, 32);
    let sse_events: Vec<_> = events
        .iter()
        .filter(|event| event.event == "sse_event")
        .collect();
    assert_eq!(sse_events.len(), 13);
    assert!(sse_events.iter().all(|event| event.raw.is_none()));
    assert!(sse_events.iter().all(|event| {
        event
            .redaction
            .omitted
            .iter()
            .any(|field| field == "sse_raw_bytes")
            && event.normalized.as_ref().is_some_and(|normalized| {
                normalized.get("raw_size").is_some() && normalized.get("raw_sha256").is_some()
            })
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_hundred_concurrent_streams_do_not_cross_or_truncate() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, _) =
        RunStore::create(temporary.path(), "stress", CapturePolicy::default()).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_http2_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let mut expected = BTreeMap::new();
    let mut requests = FuturesUnordered::new();
    for index in 0..100_u64 {
        let id = format!("inference-{index:03}");
        let mut body = format!("payload-{index:03}:").into_bytes();
        body.extend(std::iter::repeat_n(
            u8::try_from(index % 251).unwrap(),
            16 * 1024,
        ));
        expected.insert(id.clone(), body.clone());
        let client = client.clone();
        let url = format!("http://{}/v1/responses", proxy.address);
        requests.push(async move {
            let response = client
                .post(url)
                .header("x-iorec-inference-id", id.clone())
                .header("x-iorec-chunks", "1")
                .body(body)
                .send()
                .await?;
            let bytes = response.error_for_status()?.bytes().await?;
            anyhow::ensure!(complete_responses_stream(&bytes));
            Ok::<_, anyhow::Error>(id)
        });
    }
    let mut completed = 0;
    while let Some(result) = requests.next().await {
        result.unwrap();
        completed += 1;
    }
    assert_eq!(completed, 100);

    proxy.stop(Duration::from_secs(10)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();
    let events = read_events(temporary.path());
    let mut actual: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for event in &events {
        if event.event != "request_body_chunk" {
            continue;
        }
        let id = event.ids.inference_id.as_ref().unwrap();
        let reference = event.raw.as_ref().unwrap();
        actual
            .entry(id.clone())
            .or_default()
            .extend(blob(temporary.path(), &reference.sha256));
    }
    assert_eq!(actual, expected);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event == "transport_attempt_finished")
            .count(),
        100
    );
    assert!(
        events
            .iter()
            .filter(|event| event.event == "transport_attempt_finished")
            .all(|event| event.terminal_state == Some(TerminalState::Complete))
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.event == "transport_response_started"
                    && event
                        .normalized
                        .as_ref()
                        .and_then(|value| value.get("upstream_protocol"))
                        .and_then(serde_json::Value::as_str)
                        == Some("http/2")
            })
            .count(),
        100
    );

    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    assert_eq!(
        sequences,
        (1..=u64::try_from(events.len()).unwrap()).collect::<Vec<_>>()
    );
    for event in &events {
        if let Some(reference) = &event.raw {
            let bytes = blob(temporary.path(), &reference.sha256);
            assert_eq!(
                reference.sha256,
                format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_share_one_logical_inference_but_keep_both_attempts() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy::default();
    write_test_manifest(temporary.path(), "retry", policy.clone());
    let (store, _) = RunStore::create(temporary.path(), "retry", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();
    let client = reqwest::Client::new();
    let url = format!("http://{}/v1/responses", proxy.address);
    for (request_id, failure_status) in [("rate-limit", 429), ("server-error", 500)] {
        for expected_status in [failure_status, 200] {
            let response = client
                .post(&url)
                .header("x-iorec-inference-id", "logical-retry")
                .header("x-request-id", request_id)
                .header("x-iorec-status", failure_status.to_string())
                .header("x-iorec-fail-first", "1")
                .body("request")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected_status);
            let _ = response.bytes().await.unwrap();
        }
    }
    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();

    let inspection = inspect_run(temporary.path(), true).unwrap();
    assert_eq!(inspection.manifest.counts.logical_inferences, 1);
    assert_eq!(inspection.manifest.counts.transport_attempts, 4);
    assert_eq!(inspection.manifest.counts.completed_attempts, 4);
    assert_eq!(inspection.manifest.counts.errors, 2);
    assert!(
        inspection
            .manifest
            .coverage
            .all_attempts_have_terminal_state
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_reset_preserves_the_recorded_prefix_and_error_terminal() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy::default();
    write_test_manifest(temporary.path(), "stream-reset", policy.clone());
    let (store, _) = RunStore::create(temporary.path(), "stream-reset", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .header("x-iorec-chunks", "4")
        .header("x-iorec-chunk-bytes", "64")
        .header("x-iorec-delay-ms", "20")
        .header("x-iorec-interrupt-after", "2")
        .body("request")
        .send()
        .await
        .unwrap();
    assert!(response.bytes().await.is_err());
    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();

    let events = read_events(temporary.path());
    let chunks: Vec<_> = events
        .iter()
        .filter(|event| event.event == "response_body_chunk")
        .collect();
    assert_eq!(chunks.len(), 6);
    assert!(chunks.iter().all(|event| event.raw.is_some()));
    assert!(events.iter().any(|event| {
        event.event == "transport_attempt_finished"
            && event.terminal_state == Some(TerminalState::Error)
    }));
    let inspection = inspect_run(temporary.path(), true).unwrap();
    assert_eq!(inspection.manifest.counts.transport_attempts, 1);
    assert_eq!(inspection.manifest.counts.incomplete_attempts, 1);
    assert_eq!(inspection.manifest.counts.errors, 1);
    assert!(
        inspection
            .manifest
            .coverage
            .all_attempts_have_terminal_state
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unterminated_sse_is_explicitly_incomplete() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, _) =
        RunStore::create(temporary.path(), "incomplete", CapturePolicy::default()).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .header("x-iorec-unterminated", "true")
        .body("request")
        .send()
        .await
        .unwrap();
    let _ = response.bytes().await.unwrap();
    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();

    let events = read_events(temporary.path());
    assert!(events.iter().any(|event| {
        event.event == "transport_attempt_finished"
            && event.terminal_state == Some(TerminalState::Incomplete)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_reconnects_share_logical_id_and_preserve_both_directions() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy {
        allowed_paths: vec!["/v1/realtime".to_owned()],
        ..CapturePolicy::default()
    };
    write_test_manifest(temporary.path(), "websocket", policy.clone());
    let (store, _) = RunStore::create(temporary.path(), "websocket", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    for payload in ["first", "second"] {
        let mut request = format!("ws://{}/v1/realtime", proxy.address)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("x-iorec-inference-id", "logical-ws".parse().unwrap());
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            "iorec-test".parse().unwrap(),
        );
        let (mut socket, response) = connect_async(request).await.unwrap();
        assert_eq!(
            response.headers().get(header::SEC_WEBSOCKET_PROTOCOL),
            Some(&"iorec-test".parse().unwrap())
        );
        socket
            .send(Message::Text(payload.to_owned().into()))
            .await
            .unwrap();
        let echoed = socket.next().await.unwrap().unwrap();
        assert_eq!(echoed, Message::Text(payload.to_owned().into()));
        socket.close(None).await.unwrap();
    }

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();
    let events = read_events(temporary.path());
    let text_frames: Vec<_> = events
        .iter()
        .filter(|event| {
            event.event == "websocket_frame"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("opcode"))
                    .and_then(serde_json::Value::as_str)
                    == Some("text")
        })
        .collect();
    assert_eq!(text_frames.len(), 4);
    let mut payloads_and_directions: Vec<(Vec<u8>, String)> = text_frames
        .iter()
        .map(|event| {
            (
                blob(temporary.path(), &event.raw.as_ref().unwrap().sha256),
                event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("direction"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect();
    payloads_and_directions.sort();
    assert_eq!(
        payloads_and_directions,
        vec![
            (b"first".to_vec(), "client_to_upstream".to_owned()),
            (b"first".to_vec(), "upstream_to_client".to_owned()),
            (b"second".to_vec(), "client_to_upstream".to_owned()),
            (b"second".to_vec(), "upstream_to_client".to_owned()),
        ]
    );

    let inspection = inspect_run(temporary.path(), true).unwrap();
    assert_eq!(inspection.manifest.counts.logical_inferences, 1);
    assert_eq!(inspection.manifest.counts.transport_attempts, 2);
    assert_eq!(inspection.manifest.counts.completed_attempts, 2);
    assert!(
        inspection
            .manifest
            .coverage
            .all_attempts_have_terminal_state
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recording_failure_never_interrupts_the_http_data_path() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, _) = RunStore::create(
        temporary.path(),
        "non-interference",
        CapturePolicy::default(),
    )
    .unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();
    store.shutdown().await.unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .header("content-type", "application/json")
        .body(r#"{"model":"test-model","input":"still-forwarded"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response.bytes().await.unwrap();
    assert!(complete_responses_stream(&body));

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    assert!(store.stats().capture_drops > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whole_run_storage_budget_never_interrupts_the_http_data_path() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy {
        max_run_blob_storage_bytes: 1,
        ..CapturePolicy::default()
    };
    let (store, _) = RunStore::create(temporary.path(), "budget-non-interference", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .body("the budget is deliberately too small")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(complete_responses_stream(&response.bytes().await.unwrap()));

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();
    assert!(store.stats().capture_drops > 0);
    assert!(read_events(temporary.path()).iter().any(|event| {
        event.event == "transport_attempt_finished"
            && event.terminal_state == Some(TerminalState::Incomplete)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn event_log_budget_never_interrupts_the_http_data_path() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = CapturePolicy {
        max_event_storage_bytes: 1024,
        ..CapturePolicy::default()
    };
    let (store, _) = RunStore::create(temporary.path(), "event-budget", policy).unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/responses", proxy.address))
        .body("the event budget is deliberately too small")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(complete_responses_stream(&response.bytes().await.unwrap()));

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    assert!(store.shutdown().await.is_err());
    assert!(store.stats().capture_drops > 0);
    assert!(
        fs::metadata(temporary.path().join("events.jsonl"))
            .unwrap()
            .len()
            <= 1024
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recording_failure_never_interrupts_the_websocket_data_path() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, _) = RunStore::create(
        temporary.path(),
        "websocket-non-interference",
        CapturePolicy::default(),
    )
    .unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let proxy = start_proxy(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
    )
    .await
    .unwrap();
    store.shutdown().await.unwrap();

    let mut request = format!("ws://{}/v1/realtime", proxy.address)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        "iorec-test".parse().unwrap(),
    );
    let (mut socket, response) = connect_async(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    socket
        .send(Message::Text("still-forwarded".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("still-forwarded".into())
    );
    socket.close(None).await.unwrap();

    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    assert!(store.stats().capture_drops > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tls_negotiates_http2_while_slow_handshakes_are_pending() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, _) = RunStore::create(
        temporary.path(),
        "transparent-tls-http2",
        CapturePolicy::default(),
    )
    .unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let identity = TransparentArtifacts::prepare(
        temporary.path(),
        "transparent-tls-http2",
        &Url::parse("https://api.example.test").unwrap(),
        &["192.0.2.10:443".parse().unwrap()],
        false,
    )
    .unwrap();
    let ca = fs::read(identity.ca_path().unwrap()).unwrap();
    let proxy = start_transparent_tls(
        ProxyConfig {
            listen: loopback(),
            upstream: Url::parse(&format!("http://{}", fake.address)).unwrap(),
        },
        store.clone(),
        identity.server_config().unwrap(),
        false,
        None,
    )
    .await
    .unwrap();

    let mut stalled = Vec::new();
    for _ in 0..32 {
        stalled.push(tokio::net::TcpStream::connect(proxy.address).await.unwrap());
    }
    let certificate = reqwest::Certificate::from_pem(&ca).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(certificate)
        .resolve("api.example.test", proxy.address)
        .build()
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .post("https://api.example.test/v1/responses")
            .header("content-type", "application/json")
            .body(r#"{"model":"transparent-h2","input":"hello"}"#)
            .send(),
    )
    .await
    .expect("valid TLS client was blocked by stalled handshakes")
    .unwrap();
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert!(response.status().is_success());
    assert!(complete_responses_stream(&response.bytes().await.unwrap()));

    let root = rustls::pki_types::CertificateDer::from_pem_slice(&ca).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let mut websocket_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    websocket_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut request = "wss://api.example.test/v1/realtime"
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        "iorec-test".parse().unwrap(),
    );
    let tcp = tokio::net::TcpStream::connect(proxy.address).await.unwrap();
    let (mut socket, response) = client_async_tls_with_config(
        request,
        tcp,
        None,
        Some(Connector::Rustls(std::sync::Arc::new(websocket_tls))),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    socket
        .send(Message::Text("transparent-wss".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("transparent-wss".into())
    );
    socket.close(None).await.unwrap();

    drop(stalled);
    proxy.stop(Duration::from_secs(5)).await.unwrap();
    fake.stop().await.unwrap();
    store.shutdown().await.unwrap();
    let events = read_events(temporary.path());
    assert!(events.iter().any(|event| {
        event.event == "proxy_started"
            && event
                .normalized
                .as_ref()
                .and_then(|value| value.get("downstream_tls"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
    }));
    identity.cleanup().unwrap();
}
