use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{
        Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
    routing::any,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::JoinHandle,
};
use tokio_stream::wrappers::ReceiverStream;

const MAX_FAKE_REQUEST_BYTES: usize = 128 * 1024 * 1024;
const MAX_FAKE_RESPONSE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FAULT_CHUNKS: u64 = 100_000;
const MAX_FAULT_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_FAULT_DELAY_MS: u64 = 60_000;
const MAX_FAIL_FIRST: u64 = 1_000_000;
const MAX_FAULT_IDENTITIES: usize = 10_000;
const MAX_CONCURRENT_FAKE_REQUESTS: usize = 128;
const MAX_REQUEST_ID_BYTES: usize = 256;
const FAKE_RESPONSE_CHANNEL_CAPACITY: usize = 1;
const FAKE_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub struct FakeServerConfig {
    pub listen: SocketAddr,
}

#[derive(Clone)]
struct FakeState {
    attempts: Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
    request_slots: Arc<Semaphore>,
}

impl FakeState {
    fn new() -> Self {
        Self {
            attempts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            request_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_FAKE_REQUESTS)),
        }
    }
}

pub struct FakeServerHandle {
    pub address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl FakeServerHandle {
    pub async fn stop(mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Ok(result) = tokio::time::timeout(FAKE_SERVER_SHUTDOWN_TIMEOUT, &mut self.task).await
        {
            result
                .map_err(|error| io::Error::other(format!("fake server task panicked: {error}")))?
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fake server did not drain before shutdown deadline",
            ))
        }
    }
}

impl Drop for FakeServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

pub async fn start(config: FakeServerConfig) -> io::Result<FakeServerHandle> {
    if !config.listen.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fake model server must listen on a loopback address",
        ));
    }
    let app = Router::new()
        .route("/v1/realtime", any(handle_websocket))
        .fallback(handle)
        .with_state(FakeState::new());
    let listener = TcpListener::bind(config.listen).await?;
    let address = listener.local_addr()?;
    let (shutdown, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
    });
    Ok(FakeServerHandle {
        address,
        shutdown: Some(shutdown),
        task,
    })
}

async fn handle_websocket(State(state): State<FakeState>, websocket: WebSocketUpgrade) -> Response {
    let Ok(request_slot) = Arc::clone(&state.request_slots).try_acquire_owned() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": {"type": "fake_server_concurrency_limit"}}),
        );
    };
    websocket
        .protocols(["iorec-test"])
        .on_upgrade(|socket| async move {
            let _request_slot = request_slot;
            echo_websocket(socket).await;
        })
}

async fn echo_websocket(mut socket: WebSocket) {
    while let Some(message) = socket.next().await {
        let Ok(message) = message else {
            return;
        };
        match message {
            Message::Text(text) => {
                if socket.send(Message::Text(text)).await.is_err() {
                    return;
                }
            }
            Message::Binary(bytes) => {
                if socket.send(Message::Binary(bytes)).await.is_err() {
                    return;
                }
            }
            Message::Close(_) => {
                // The protocol implementation queues the acknowledgement;
                // dropping the socket before flushing loses it on the wire.
                let _ = socket.flush().await;
                return;
            }
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
}

async fn handle(State(state): State<FakeState>, request: Request) -> Response {
    let Ok(request_slot) = Arc::clone(&state.request_slots).try_acquire_owned() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": {"type": "fake_server_concurrency_limit"}}),
        );
    };
    let headers = request.headers().clone();
    let path = request.uri().path().to_owned();
    let protocol = StreamProtocol::from_path(&path);
    let stream = headers
        .get("x-iorec-stream")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value != "false")
        || matches!(
            protocol,
            StreamProtocol::Responses
                | StreamProtocol::ChatCompletions
                | StreamProtocol::AnthropicMessages
                | StreamProtocol::GeminiStreamGenerateContent
        );
    let fault = match Fault::from_headers(&headers) {
        Ok(fault) => fault,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": {"type": "invalid_fault_configuration", "message": error}}),
            );
        }
    };
    if fault.fail_first > 0 {
        let request_id = match fault_request_id(&headers) {
            Ok(request_id) => request_id,
            Err(error) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": {"type": "invalid_request_id", "message": error}}),
                );
            }
        };
        let mut attempts = state.attempts.lock().await;
        if !attempts.contains_key(&request_id) && attempts.len() >= MAX_FAULT_IDENTITIES {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": {"type": "fake_server_identity_limit"}}),
            );
        }
        let attempt = attempts.entry(request_id).or_default();
        *attempt = attempt.saturating_add(1);
        if *attempt <= fault.fail_first {
            return json_response(
                fault.status.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                &json!({"error": {"type": "injected_failure", "attempt": *attempt}}),
            );
        }
    } else if let Some(status) = fault.status {
        return json_response(status, &json!({"error": {"type": "injected_status"}}));
    }

    let (_, body) = request.into_parts();
    let request_hash = match hash_request_body(body).await {
        Ok(hash) => hash,
        Err(error) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &json!({"error": {"type": error}}),
            );
        }
    };
    if !stream {
        if protocol == StreamProtocol::GeminiGenerateContent {
            return json_response(
                StatusCode::OK,
                &gemini_generate_content_response(
                    &request_hash,
                    &"x".repeat(fault.chunk_bytes),
                    true,
                ),
            );
        }
        return json_response(
            StatusCode::OK,
            &json!({"id": "fake-response", "request_sha256": request_hash, "ok": true}),
        );
    }

    let (sender, receiver) =
        tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(FAKE_RESPONSE_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let _request_slot = request_slot;
        stream_fake_response(sender, protocol, fault, request_hash).await;
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(ReceiverStream::new(receiver)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamProtocol {
    Responses,
    ChatCompletions,
    AnthropicMessages,
    GeminiGenerateContent,
    GeminiStreamGenerateContent,
    Generic,
}

impl StreamProtocol {
    fn from_path(path: &str) -> Self {
        let lowercase = path.to_ascii_lowercase();
        if lowercase.ends_with("/responses") {
            Self::Responses
        } else if lowercase.ends_with("/chat/completions") || lowercase.ends_with("/completions") {
            Self::ChatCompletions
        } else if lowercase.ends_with("/messages") {
            Self::AnthropicMessages
        } else if lowercase.ends_with(":streamgeneratecontent") {
            Self::GeminiStreamGenerateContent
        } else if lowercase.ends_with(":generatecontent") {
            Self::GeminiGenerateContent
        } else {
            Self::Generic
        }
    }
}

async fn stream_fake_response(
    sender: tokio::sync::mpsc::Sender<Result<Bytes, io::Error>>,
    protocol: StreamProtocol,
    fault: Fault,
    request_hash: String,
) {
    let suffix = request_hash
        .strip_prefix("sha256:")
        .unwrap_or(&request_hash)
        .get(..16)
        .unwrap_or("0000000000000000");
    let response_id = format!("resp_iorec_{suffix}");
    let message_id = format!("msg_iorec_{suffix}");
    let model = "iorec-fake-model";
    let mut sequence = 0_u64;

    let started = match protocol {
        StreamProtocol::Responses => {
            let response =
                fake_response_object(&response_id, model, "in_progress", &json!([]), None);
            send_sse_json(
                &sender,
                "response.created",
                &json!({"type":"response.created","response":response,"sequence_number":sequence}),
            )
            .await
                && {
                    sequence += 1;
                    let response = fake_response_object(
                        &response_id,
                        model,
                        "in_progress",
                        &json!([]),
                        None,
                    );
                    send_sse_json(
                        &sender,
                        "response.in_progress",
                        &json!({"type":"response.in_progress","response":response,"sequence_number":sequence}),
                    )
                    .await
                }
                && {
                    sequence += 1;
                    send_sse_json(
                        &sender,
                        "response.output_item.added",
                        &json!({
                            "type":"response.output_item.added",
                            "output_index":0,
                            "item":{"id":message_id,"type":"message","status":"in_progress","role":"assistant","content":[]},
                            "sequence_number":sequence
                        }),
                    )
                    .await
                }
                && {
                    sequence += 1;
                    send_sse_json(
                        &sender,
                        "response.content_part.added",
                        &json!({
                            "type":"response.content_part.added",
                            "item_id":message_id,
                            "output_index":0,
                            "content_index":0,
                            "part":{"type":"output_text","text":"","annotations":[]},
                            "sequence_number":sequence
                        }),
                    )
                    .await
                }
        }
        StreamProtocol::AnthropicMessages => {
            send_sse_json(
                &sender,
                "message_start",
                &json!({
                    "type":"message_start",
                    "message":{"id":message_id,"type":"message","role":"assistant","model":model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}
                }),
            )
            .await
                && send_sse_json(
                    &sender,
                    "content_block_start",
                    &json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
                )
                .await
        }
        StreamProtocol::ChatCompletions
        | StreamProtocol::GeminiGenerateContent
        | StreamProtocol::GeminiStreamGenerateContent
        | StreamProtocol::Generic => true,
    };
    if !started {
        return;
    }

    let response_bytes = fault
        .chunks
        .saturating_mul(u64::try_from(fault.chunk_bytes).unwrap_or(u64::MAX));
    let mut completed_text = if protocol == StreamProtocol::Responses {
        String::with_capacity(usize::try_from(response_bytes).unwrap_or(0))
    } else {
        String::new()
    };
    for index in 0..fault.chunks {
        if fault.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(fault.delay_ms)).await;
        }
        if fault.interrupt_after == Some(index) {
            let _ = sender
                .send(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected stream reset",
                )))
                .await;
            return;
        }
        let padding = "x".repeat(fault.chunk_bytes);
        if protocol == StreamProtocol::Responses {
            completed_text.push_str(&padding);
        }
        let sent = match protocol {
            StreamProtocol::Responses => {
                sequence += 1;
                send_sse_json(
                    &sender,
                    "response.output_text.delta",
                    &json!({
                        "type":"response.output_text.delta",
                        "item_id":message_id,
                        "output_index":0,
                        "content_index":0,
                        "delta":padding,
                        "logprobs":[],
                        "sequence_number":sequence,
                        "request_sha256":request_hash
                    }),
                )
                .await
            }
            StreamProtocol::ChatCompletions => {
                send_sse_json(
                    &sender,
                    "",
                    &json!({
                        "id":response_id,
                        "object":"chat.completion.chunk",
                        "created":0,
                        "model":model,
                        "choices":[{"index":0,"delta":{"content":padding},"finish_reason":null}],
                        "request_sha256":request_hash
                    }),
                )
                .await
            }
            StreamProtocol::AnthropicMessages => {
                send_sse_json(
                    &sender,
                    "content_block_delta",
                    &json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":padding}}),
                )
                .await
            }
            StreamProtocol::GeminiStreamGenerateContent => {
                send_sse_json(
                    &sender,
                    "",
                    &gemini_generate_content_response(
                        &request_hash,
                        &padding,
                        index.saturating_add(1) == fault.chunks,
                    ),
                )
                .await
            }
            StreamProtocol::GeminiGenerateContent => false,
            StreamProtocol::Generic => {
                send_sse_json(
                    &sender,
                    "delta",
                    &json!({
                        "type":"response.output_text.delta",
                        "index":index,
                        "delta":padding,
                        "request_sha256":request_hash
                    }),
                )
                .await
            }
        };
        if !sent {
            return;
        }
    }
    if fault.unterminated {
        let _ = sender.send(Ok(Bytes::from_static(b"data: partial"))).await;
        return;
    }

    match protocol {
        StreamProtocol::Responses => {
            sequence += 1;
            if !send_sse_json(
                &sender,
                "response.output_text.done",
                &json!({
                    "type":"response.output_text.done",
                    "item_id":message_id,
                    "output_index":0,
                    "content_index":0,
                    "text":&completed_text,
                    "logprobs":[],
                    "sequence_number":sequence
                }),
            )
            .await
            {
                return;
            }
            sequence += 1;
            let part = json!({"type":"output_text","text":&completed_text,"annotations":[],"logprobs":[]});
            if !send_sse_json(
                &sender,
                "response.content_part.done",
                &json!({
                    "type":"response.content_part.done",
                    "item_id":message_id,
                    "output_index":0,
                    "content_index":0,
                    "part":part,
                    "sequence_number":sequence
                }),
            )
            .await
            {
                return;
            }
            sequence += 1;
            let item = json!({
                "id":message_id,
                "type":"message",
                "status":"completed",
                "role":"assistant",
                "content":[{"type":"output_text","text":&completed_text,"annotations":[],"logprobs":[]}]
            });
            if !send_sse_json(
                &sender,
                "response.output_item.done",
                &json!({"type":"response.output_item.done","output_index":0,"item":item,"sequence_number":sequence}),
            )
            .await
            {
                return;
            }
            sequence += 1;
            let output = json!([{
                "id":message_id,
                "type":"message",
                "status":"completed",
                "role":"assistant",
                "content":[{"type":"output_text","text":&completed_text,"annotations":[],"logprobs":[]}]
            }]);
            let response = fake_response_object(
                &response_id,
                model,
                "completed",
                &output,
                Some(&json!({
                    "input_tokens":1,
                    "input_tokens_details":{"cached_tokens":0},
                    "output_tokens":1,
                    "output_tokens_details":{"reasoning_tokens":0},
                    "total_tokens":2
                })),
            );
            let _ = send_sse_json(
                &sender,
                "response.completed",
                &json!({"type":"response.completed","response":response,"sequence_number":sequence}),
            )
            .await;
        }
        StreamProtocol::ChatCompletions => {
            if send_sse_json(
                &sender,
                "",
                &json!({
                    "id":response_id,
                    "object":"chat.completion.chunk",
                    "created":0,
                    "model":model,
                    "choices":[{"index":0,"delta":{},"finish_reason":"stop"}],
                    "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
                }),
            )
            .await
            {
                let _ = sender
                    .send(Ok(Bytes::from_static(b"data: [DONE]\n\n")))
                    .await;
            }
        }
        StreamProtocol::AnthropicMessages => {
            if send_sse_json(
                &sender,
                "content_block_stop",
                &json!({"type":"content_block_stop","index":0}),
            )
            .await
                && send_sse_json(
                    &sender,
                    "message_delta",
                    &json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}),
                )
                .await
            {
                let _ = send_sse_json(&sender, "message_stop", &json!({"type":"message_stop"})).await;
            }
        }
        StreamProtocol::GeminiGenerateContent | StreamProtocol::GeminiStreamGenerateContent => {}
        StreamProtocol::Generic => {
            let _ = sender
                .send(Ok(Bytes::from_static(b"data: [DONE]\n\n")))
                .await;
        }
    }
}

fn gemini_generate_content_response(
    request_hash: &str,
    text: &str,
    finished: bool,
) -> serde_json::Value {
    let mut candidate = json!({
        "content": {"role": "model", "parts": [{"text": text}]},
        "index": 0,
        "safetyRatings": []
    });
    if finished {
        candidate["finishReason"] = Value::String("STOP".to_owned());
    }
    json!({
        "candidates": [candidate],
        "usageMetadata": {
            "promptTokenCount": 1,
            "candidatesTokenCount": 1,
            "totalTokenCount": 2
        },
        "modelVersion": "iorec-fake-model",
        "responseId": "gemini-iorec-fake-response",
        "request_sha256": request_hash
    })
}

fn fake_response_object(
    response_id: &str,
    model: &str,
    status: &str,
    output: &serde_json::Value,
    usage: Option<&serde_json::Value>,
) -> serde_json::Value {
    json!({
        "id":response_id,
        "object":"response",
        "created_at":0,
        "completed_at":if status == "completed" { Some(0_u64) } else { None },
        "status":status,
        "background":false,
        "error":null,
        "incomplete_details":null,
        "instructions":null,
        "max_output_tokens":null,
        "max_tool_calls":null,
        "model":model,
        "output":output,
        "parallel_tool_calls":true,
        "previous_response_id":null,
        "prompt_cache_key":null,
        "reasoning":{"effort":null,"summary":null},
        "safety_identifier":null,
        "service_tier":"default",
        "store":false,
        "temperature":null,
        "text":{"format":{"type":"text"}},
        "tool_choice":"auto",
        "tools":[],
        "top_logprobs":0,
        "top_p":null,
        "truncation":"disabled",
        "usage":usage,
        "metadata":{}
    })
}

async fn send_sse_json(
    sender: &tokio::sync::mpsc::Sender<Result<Bytes, io::Error>>,
    event: &str,
    value: &serde_json::Value,
) -> bool {
    let frame = if event.is_empty() {
        format!("data: {value}\n\n")
    } else {
        format!("event: {event}\ndata: {value}\n\n")
    };
    sender.send(Ok(Bytes::from(frame))).await.is_ok()
}

async fn hash_request_body(body: Body) -> Result<String, &'static str> {
    let mut stream = body.into_data_stream();
    let mut observed = 0_usize;
    let mut digest = Sha256::new();
    while let Some(next) = stream.next().await {
        let bytes = next.map_err(|_| "request_body_read_failed")?;
        observed = observed
            .checked_add(bytes.len())
            .ok_or("request_body_too_large")?;
        if observed > MAX_FAKE_REQUEST_BYTES {
            return Err("request_body_too_large");
        }
        digest.update(&bytes);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn fault_request_id(headers: &http::HeaderMap) -> Result<String, &'static str> {
    let Some(value) = headers.get("x-request-id") else {
        return Ok("default".to_owned());
    };
    let value = value.to_str().map_err(|_| "x-request-id is not UTF-8")?;
    if value.is_empty() || value.len() > MAX_REQUEST_ID_BYTES {
        return Err("x-request-id is empty or too long");
    }
    Ok(value.to_owned())
}

#[derive(Debug, Clone)]
struct Fault {
    status: Option<StatusCode>,
    fail_first: u64,
    delay_ms: u64,
    chunks: u64,
    chunk_bytes: usize,
    interrupt_after: Option<u64>,
    unterminated: bool,
}

impl Fault {
    fn from_headers(headers: &http::HeaderMap) -> Result<Self, String> {
        let get = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
        let status = get("x-iorec-status")
            .map(|value| {
                value
                    .parse::<u16>()
                    .ok()
                    .and_then(|value| StatusCode::from_u16(value).ok())
                    .ok_or_else(|| "x-iorec-status must be a valid HTTP status".to_owned())
            })
            .transpose()?;
        let fail_first = parse_bounded_u64(
            get("x-iorec-fail-first"),
            "x-iorec-fail-first",
            0,
            MAX_FAIL_FIRST,
        )?;
        let delay_ms = parse_bounded_u64(
            get("x-iorec-delay-ms"),
            "x-iorec-delay-ms",
            0,
            MAX_FAULT_DELAY_MS,
        )?;
        let chunks =
            parse_bounded_u64(get("x-iorec-chunks"), "x-iorec-chunks", 3, MAX_FAULT_CHUNKS)?;
        let chunk_bytes_u64 = parse_bounded_u64(
            get("x-iorec-chunk-bytes"),
            "x-iorec-chunk-bytes",
            8,
            u64::try_from(MAX_FAULT_CHUNK_BYTES).unwrap_or(u64::MAX),
        )?;
        let chunk_bytes = usize::try_from(chunk_bytes_u64)
            .map_err(|_| "x-iorec-chunk-bytes does not fit this platform".to_owned())?;
        let response_bytes = chunks
            .checked_mul(chunk_bytes_u64)
            .ok_or_else(|| "configured fake response size overflows".to_owned())?;
        if response_bytes > u64::try_from(MAX_FAKE_RESPONSE_BYTES).unwrap_or(u64::MAX) {
            return Err(format!(
                "configured fake response exceeds {MAX_FAKE_RESPONSE_BYTES} bytes"
            ));
        }
        let interrupt_after = get("x-iorec-interrupt-after")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "x-iorec-interrupt-after must be an unsigned integer".to_owned())
            })
            .transpose()?;
        if interrupt_after.is_some_and(|index| index > chunks) {
            return Err("x-iorec-interrupt-after must not exceed x-iorec-chunks".to_owned());
        }
        Ok(Self {
            status,
            fail_first,
            delay_ms,
            chunks,
            chunk_bytes,
            interrupt_after,
            unterminated: get("x-iorec-unterminated").is_some_and(|value| value == "true"),
        })
    }
}

fn parse_bounded_u64(
    value: Option<&str>,
    name: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer"))?;
    if parsed > maximum {
        return Err(format!("{name} exceeds its maximum of {maximum}"));
    }
    Ok(parsed)
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn rejects_fault_settings_that_can_exhaust_memory_or_run_unbounded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iorec-chunk-bytes", HeaderValue::from_static("1048576"));
        headers.insert("x-iorec-chunks", HeaderValue::from_static("129"));
        assert!(Fault::from_headers(&headers).is_err());

        headers.clear();
        headers.insert("x-iorec-delay-ms", HeaderValue::from_static("60001"));
        assert!(Fault::from_headers(&headers).is_err());

        headers.clear();
        headers.insert("x-iorec-chunks", HeaderValue::from_static("not-a-number"));
        assert!(Fault::from_headers(&headers).is_err());
    }

    #[test]
    fn accepts_bounded_fault_configuration() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iorec-status", HeaderValue::from_static("429"));
        headers.insert("x-iorec-chunks", HeaderValue::from_static("4"));
        headers.insert("x-iorec-chunk-bytes", HeaderValue::from_static("1024"));
        headers.insert("x-iorec-interrupt-after", HeaderValue::from_static("2"));
        let fault = Fault::from_headers(&headers).unwrap();
        assert_eq!(fault.status, Some(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(fault.chunks, 4);
        assert_eq!(fault.chunk_bytes, 1024);
        assert_eq!(fault.interrupt_after, Some(2));
    }

    #[tokio::test]
    async fn fake_server_rejects_non_loopback_listeners() {
        let error = match start(FakeServerConfig {
            listen: "0.0.0.0:0".parse().unwrap(),
        })
        .await
        {
            Ok(server) => {
                server.stop().await.unwrap();
                panic!("non-loopback fake server unexpectedly started");
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn emits_protocol_specific_complete_streams() {
        let server = start(FakeServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        })
        .await
        .unwrap();
        let client = reqwest::Client::new();
        let cases = [
            (
                "/v1/responses",
                [
                    "event: response.output_item.added",
                    "event: response.content_part.added",
                    "event: response.output_text.delta",
                    "event: response.output_item.done",
                    "event: response.completed",
                ],
            ),
            (
                "/v1/chat/completions",
                [
                    "\"content\":\"xxx\"",
                    "\"request_sha256\":\"sha256:",
                    "\"finish_reason\":\"stop\"",
                    "\"total_tokens\":2",
                    "data: [DONE]",
                ],
            ),
            (
                "/v1/messages",
                [
                    "event: message_start",
                    "event: content_block_start",
                    "event: content_block_delta",
                    "event: message_delta",
                    "event: message_stop",
                ],
            ),
            (
                "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
                [
                    "\"candidates\"",
                    "\"text\":\"xxx\"",
                    "\"role\":\"model\"",
                    "\"finishReason\":\"STOP\"",
                    "\"request_sha256\":\"sha256:",
                ],
            ),
        ];
        for (path, expected) in cases {
            let response = client
                .post(format!("http://{}{path}", server.address))
                .header("x-iorec-chunks", "1")
                .header("x-iorec-chunk-bytes", "3")
                .header(header::CONTENT_TYPE, "application/json")
                .body(json!({"model":"fixture-model","stream":true,"input":"hello"}).to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.text().await.unwrap();
            let mut prior = 0;
            for marker in expected {
                let offset = body[prior..]
                    .find(marker)
                    .unwrap_or_else(|| panic!("{path} omitted {marker}: {body}"));
                prior += offset + marker.len();
            }
        }
        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn emits_gemini_non_stream_response_shape() {
        let server = start(FakeServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        })
        .await
        .unwrap();
        let response = reqwest::Client::new()
            .post(format!(
                "http://{}/v1beta/models/gemini-2.5-flash:generateContent",
                server.address
            ))
            .header("x-iorec-chunk-bytes", "3")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({"contents":[{"role":"user","parts":[{"text":"hello"}]}]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(body["candidates"][0]["content"]["role"], "model");
        assert_eq!(body["candidates"][0]["content"]["parts"][0]["text"], "xxx");
        assert_eq!(body["candidates"][0]["finishReason"], "STOP");
        assert_eq!(body["usageMetadata"]["totalTokenCount"], 2);
        server.stop().await.unwrap();
    }

    #[test]
    fn fault_request_ids_are_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("retry-1"));
        assert_eq!(fault_request_id(&headers).unwrap(), "retry-1");
        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&"x".repeat(MAX_REQUEST_ID_BYTES + 1)).unwrap(),
        );
        assert!(fault_request_id(&headers).is_err());
    }
}
