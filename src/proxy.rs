use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::{
        Request, State,
        ws::{
            CloseFrame as AxumCloseFrame, Message as AxumMessage, WebSocket, WebSocketUpgrade,
            rejection::WebSocketUpgradeRejection,
        },
    },
    response::Response,
    serve::Listener,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, StatusCode, Uri, header};
use reqwest::redirect;
use rustls_platform_verifier::BuilderVerifierExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message as TungsteniteMessage,
        client::IntoClientRequest,
        protocol::{CloseFrame as TungsteniteCloseFrame, frame::coding::CloseCode},
    },
};
use tracing::{error, warn};
use url::Url;
use uuid::Uuid;

use crate::{
    input::validate_json_complexity,
    metadata::{
        bounded_string as normalized_metadata_string, value_string as normalized_json_string,
    },
    model::{EventIds, PendingEvent, RedactionRecord, TerminalState},
    sse::{SseError, SseParser},
    storage::{RunStore, StorageError},
};

const BODY_CHANNEL_CAPACITY: usize = 16;
const WEBSOCKET_CLOSE_TIMEOUT: Duration = Duration::from_secs(3);
const WEBSOCKET_CAPTURE_MESSAGES: usize = 256;
const WEBSOCKET_CONNECTION_CAPTURE_BYTES: usize =
    64 * 1024 * 1024 + std::mem::size_of::<CapturedWebSocketMessage>();
const WEBSOCKET_PROXY_CAPTURE_BYTES: usize = 128 * 1024 * 1024;
const MAX_NORMALIZED_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONCURRENT_REQUEST_NORMALIZATIONS: usize = 16;
const MAX_PAYLOAD_DEPENDENCY_NODES: usize = 1_000_000;
const MAX_QUERY_METADATA_KEYS: usize = 128;
const MAX_PENDING_TLS_HANDSHAKES: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct PayloadDependencySummary {
    modalities: BTreeMap<&'static str, u64>,
    embedded_parts: u64,
    unresolved_references: u64,
    unresolved_kinds: BTreeMap<&'static str, u64>,
    scan_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: Url,
}

#[derive(Clone)]
struct ProxyState {
    store: RunStore,
    upstream: Url,
    client: reqwest::Client,
    connections: Arc<ConnectionTracker>,
    normalization_slots: Arc<Semaphore>,
    websocket_capture_bytes: Arc<Semaphore>,
}

#[derive(Default)]
struct ConnectionTracker {
    active: AtomicUsize,
    idle: Notify,
}

impl ConnectionTracker {
    fn register(self: &Arc<Self>) -> ConnectionGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        ConnectionGuard(Arc::clone(self))
    }

    async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct ConnectionGuard(Arc<ConnectionTracker>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

pub struct ProxyHandle {
    pub address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
    connections: Arc<ConnectionTracker>,
}

impl ProxyHandle {
    pub async fn stop(mut self, timeout: Duration) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let drained = tokio::time::timeout(timeout, async {
            (&mut self.task)
                .await
                .map_err(|error| io::Error::other(format!("proxy task panicked: {error}")))??;
            self.connections.wait_idle().await;
            Ok::<(), io::Error>(())
        })
        .await;
        if let Ok(result) = drained {
            result
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy did not drain before shutdown deadline",
            ))
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

pub async fn start(config: ProxyConfig, store: RunStore) -> anyhow::Result<ProxyHandle> {
    start_with_transport(config, store, false, None, None).await
}

pub async fn start_http2_prior_knowledge(
    config: ProxyConfig,
    store: RunStore,
) -> anyhow::Result<ProxyHandle> {
    start_with_transport(config, store, true, None, None).await
}

pub async fn start_with_key_log(
    config: ProxyConfig,
    store: RunStore,
    key_log: Arc<dyn rustls::KeyLog>,
) -> anyhow::Result<ProxyHandle> {
    start_with_transport(config, store, false, Some(key_log), None).await
}

pub async fn start_http2_prior_knowledge_with_key_log(
    config: ProxyConfig,
    store: RunStore,
    key_log: Arc<dyn rustls::KeyLog>,
) -> anyhow::Result<ProxyHandle> {
    start_with_transport(config, store, true, Some(key_log), None).await
}

pub async fn start_transparent_tls(
    config: ProxyConfig,
    store: RunStore,
    ingress_tls: Arc<rustls::ServerConfig>,
    upstream_http2_prior_knowledge: bool,
    key_log: Option<Arc<dyn rustls::KeyLog>>,
) -> anyhow::Result<ProxyHandle> {
    let ingress_tls = if let Some(key_log) = key_log.as_ref() {
        let mut configured = (*ingress_tls).clone();
        configured.key_log = Arc::clone(key_log);
        Arc::new(configured)
    } else {
        ingress_tls
    };
    start_with_transport(
        config,
        store,
        upstream_http2_prior_knowledge,
        key_log,
        Some(ingress_tls),
    )
    .await
}

async fn start_with_transport(
    config: ProxyConfig,
    store: RunStore,
    http2_prior_knowledge: bool,
    key_log: Option<Arc<dyn rustls::KeyLog>>,
    ingress_tls: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<ProxyHandle> {
    anyhow::ensure!(
        config.listen.ip().is_loopback(),
        "inference proxy must listen on a loopback address"
    );
    validate_upstream_base(&config.upstream)?;
    let mut client = reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .no_proxy();
    let key_log_enabled = key_log.is_some();
    if let Some(key_log) = key_log {
        let mut tls = rustls::ClientConfig::builder()
            .with_platform_verifier()
            .context("configure platform TLS certificate verifier")?
            .with_no_client_auth();
        tls.key_log = key_log;
        tls.alpn_protocols = if http2_prior_knowledge {
            vec![b"h2".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
        client = client.tls_backend_preconfigured(tls);
    }
    if http2_prior_knowledge {
        client = client.http2_prior_knowledge();
    }
    let client = client.build()?;
    let upstream_snapshot = config.upstream.clone();
    let connections = Arc::new(ConnectionTracker::default());
    let normalization_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUEST_NORMALIZATIONS));
    let state = ProxyState {
        store: store.clone(),
        upstream: config.upstream,
        client,
        connections: Arc::clone(&connections),
        normalization_slots,
        websocket_capture_bytes: Arc::new(Semaphore::new(WEBSOCKET_PROXY_CAPTURE_BYTES)),
    };
    let app = Router::new().fallback(forward).with_state(state);
    let listener = TcpListener::bind(config.listen).await?;
    let address = listener.local_addr()?;
    let (shutdown, stopped) = oneshot::channel();
    let downstream_tls = ingress_tls.is_some();

    let mut event = store.event("proxy", "proxy_started");
    event.normalized = Some(json!({
        "listen": address.to_string(),
        "upstream": safe_url(&upstream_snapshot, false),
        "client_protocol": if downstream_tls { "tls-http/1.1-or-h2" } else { "cleartext-http/1.1-or-h2" },
        "downstream_tls": downstream_tls,
        "downstream_tls_keylog": downstream_tls && key_log_enabled,
        "upstream_http2_prior_knowledge": http2_prior_knowledge,
        "upstream_tls_keylog": key_log_enabled,
    }));
    store
        .append(event)
        .await
        .context("persist proxy start evidence")?;

    let task = if let Some(ingress_tls) = ingress_tls {
        let listener = ConcurrentTlsListener::new(listener, ingress_tls);
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        })
    } else {
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        })
    };
    Ok(ProxyHandle {
        address,
        shutdown: Some(shutdown),
        task,
        connections,
    })
}

struct ConcurrentTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handshakes: JoinSet<io::Result<(TlsStream<TcpStream>, SocketAddr)>>,
}

impl ConcurrentTlsListener {
    fn new(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            handshakes: JoinSet::new(),
        }
    }

    fn start_handshake(&mut self, stream: TcpStream, address: SocketAddr) {
        let acceptor = self.acceptor.clone();
        self.handshakes.spawn(async move {
            let stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
                })??;
            Ok((stream, address))
        });
    }

    async fn next_handshake(&mut self) -> Option<(TlsStream<TcpStream>, SocketAddr)> {
        while let Some(result) = self.handshakes.join_next().await {
            match result {
                Ok(Ok(connection)) => return Some(connection),
                Ok(Err(error)) => {
                    warn!(error_kind = ?error.kind(), "transparent TLS handshake failed");
                }
                Err(error) => {
                    warn!(
                        task_cancelled = error.is_cancelled(),
                        task_panicked = error.is_panic(),
                        "transparent TLS handshake task failed"
                    );
                }
            }
        }
        None
    }
}

impl Listener for ConcurrentTlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.handshakes.len() >= MAX_PENDING_TLS_HANDSHAKES {
                if let Some(connection) = self.next_handshake().await {
                    return connection;
                }
                continue;
            }
            tokio::select! {
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, address)) => self.start_handshake(stream, address),
                        Err(error) => {
                            warn!(error_kind = ?error.kind(), "transparent TLS socket accept failed");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    match completed {
                        Some(Ok(Ok(connection))) => return connection,
                        Some(Ok(Err(error))) => {
                            warn!(error_kind = ?error.kind(), "transparent TLS handshake failed");
                        }
                        Some(Err(error)) => {
                            warn!(task_cancelled = error.is_cancelled(), task_panicked = error.is_panic(), "transparent TLS handshake task failed");
                        }
                        None => {}
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[axum::debug_handler]
async fn forward(
    State(state): State<ProxyState>,
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    request: Request,
) -> Response {
    let result = if let Ok(websocket) = websocket {
        forward_websocket(state, websocket, request).await
    } else {
        forward_inner(state, request).await
    };
    match result {
        Ok(response) => response,
        Err(_error) => {
            error!(error_kind = "proxy_request", "proxy request failed");
            plain_response(
                StatusCode::BAD_GATEWAY,
                "inference recorder proxy failure\n",
            )
        }
    }
}

async fn forward_websocket(
    state: ProxyState,
    websocket: WebSocketUpgrade,
    request: Request,
) -> anyhow::Result<Response> {
    let inference_id = request_inference_id(request.headers());
    let ids = EventIds {
        session_id: request_session_id(request.headers()),
        inference_id: Some(inference_id),
        attempt_id: Some(Uuid::now_v7().to_string()),
        connection_id: Some(Uuid::now_v7().to_string()),
        ..EventIds::default()
    };
    let target = websocket_target(&state.upstream, request.uri())?;
    let (sanitized_headers, mut redaction) =
        state.store.policy().sanitize_headers(request.headers());
    if request.uri().query().is_some() {
        redaction.omitted.push("query_values".to_owned());
    }
    let path = request.uri().path().to_owned();
    let is_model = classify_model_path(&path);
    let mut started = state.store.event("proxy", "transport_request_started");
    started.ids = ids.clone();
    started.redaction = redaction;
    started.normalized = Some(json!({
        "method": request.method().as_str(),
        "uri": safe_uri(request.uri()),
        "upstream": safe_url(&target, true),
        "headers": sanitized_headers,
        "traffic_class": if is_model { "model" } else { "other" },
        "protocol": "websocket",
    }));
    append_observation(&state.store, started, "transport_request_started").await;

    let mut upstream_request = target
        .as_str()
        .into_client_request()
        .context("build upstream WebSocket handshake")?;
    copy_websocket_headers(request.headers(), upstream_request.headers_mut());
    let connected = connect_async(upstream_request).await;
    let (upstream, response) = match connected {
        Ok(connected) => connected,
        Err(error) => {
            let mut terminal = state.store.event("proxy", "transport_attempt_finished");
            terminal.ids = ids;
            terminal.terminal_state = Some(TerminalState::Error);
            terminal.normalized = Some(json!({"error_kind": "websocket_handshake"}));
            append_observation(&state.store, terminal, "transport_attempt_finished").await;
            return Err(error).context("connect upstream WebSocket");
        }
    };
    let (response_headers, response_redaction) =
        state.store.policy().sanitize_headers(response.headers());
    let selected_protocol = response
        .headers()
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut connected_event = state.store.event("proxy", "websocket_connection_started");
    connected_event.ids = ids.clone();
    connected_event.redaction = response_redaction;
    connected_event.normalized = Some(json!({
        "status": response.status().as_u16(),
        "headers": response_headers,
        "subprotocol": selected_protocol.clone(),
    }));
    append_observation(
        &state.store,
        connected_event,
        "websocket_connection_started",
    )
    .await;

    let store = state.store;
    let capture_bytes = state.websocket_capture_bytes;
    let connection_guard = state.connections.register();
    let upgraded = move |socket| async move {
        let _connection_guard = connection_guard;
        bridge_websocket(socket, upstream, store, ids, path, capture_bytes).await;
    };
    Ok(if let Some(protocol) = selected_protocol {
        websocket.protocols([protocol]).on_upgrade(upgraded)
    } else {
        websocket.on_upgrade(upgraded)
    })
}

fn copy_websocket_headers(input: &HeaderMap, output: &mut HeaderMap) {
    const HANDSHAKE_HEADERS: &[&str] = &[
        "host",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
    ];
    let nominated = connection_nominated_headers(input);
    for (name, value) in input {
        if !HANDSHAKE_HEADERS.contains(&name.as_str())
            && name != header::CONTENT_LENGTH
            && !nominated.contains(name.as_str())
        {
            output.append(name, value.clone());
        }
    }
}

async fn bridge_websocket(
    downstream: WebSocket,
    upstream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    store: RunStore,
    ids: EventIds,
    path: String,
    capture_bytes: Arc<Semaphore>,
) {
    let (mut downstream_tx, mut downstream_rx) = downstream.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();
    let mut downstream_sequence = 0_u64;
    let mut upstream_sequence = 0_u64;
    let mut terminal = TerminalState::Incomplete;
    let mut reason = "connection_ended";
    let mut error_detail = None;
    let mut client_close_received = false;
    let mut upstream_close_received = false;
    let mut close_deadline = None;
    let capture_failed = Arc::new(AtomicBool::new(false));
    let capture_budget = WebSocketCaptureBudget {
        shared: capture_bytes,
        connection: Arc::new(Semaphore::new(WEBSOCKET_CONNECTION_CAPTURE_BYTES)),
    };
    let (capture_sender, capture_receiver) = tokio::sync::mpsc::channel(WEBSOCKET_CAPTURE_MESSAGES);
    let capture_task = tokio::spawn(capture_websocket_stream(
        capture_receiver,
        store.clone(),
        ids.clone(),
        path.clone(),
        Arc::clone(&capture_failed),
    ));

    loop {
        tokio::select! {
            () = async {
                match close_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                terminal = TerminalState::Incomplete;
                reason = "close_handshake_timeout";
                error_detail = Some(json!({"schema_version": 1, "category": "timeout"}));
                break;
            }
            next = downstream_rx.next(), if !client_close_received => {
                match next {
                    Some(Ok(message)) => {
                        downstream_sequence = downstream_sequence.saturating_add(1);
                        let (message, frame) = downstream_to_upstream(message);
                        let is_close = frame.opcode == "close";
                        if capture_budget.enqueue(&capture_sender,
                            "client_to_upstream", downstream_sequence, frame,
                        ).is_err() {
                            store.note_capture_drop();
                            capture_failed.store(true, Ordering::Release);
                        }
                        if is_close {
                            client_close_received = true;
                            if close_deadline.is_none() {
                                reason = "client_close";
                                close_deadline = Some(tokio::time::Instant::now() + WEBSOCKET_CLOSE_TIMEOUT);
                            }
                            // Receiving Close queues an automatic reply. It must
                            // reach the wire before dropping this endpoint.
                            if let Err(detail) = websocket_close_io(downstream_tx.flush()).await {
                                terminal = TerminalState::Error;
                                reason = "client_close_flush";
                                error_detail = Some(detail);
                                break;
                            }
                            if upstream_close_received {
                                terminal = TerminalState::Complete;
                                break;
                            }
                            if let Err(detail) = websocket_close_io(upstream_tx.send(message)).await {
                                terminal = TerminalState::Error;
                                reason = "upstream_close_write";
                                error_detail = Some(detail);
                                break;
                            }
                            continue;
                        }
                        // Closing endpoints cannot accept application messages.
                        // Still retain any already-in-flight peer messages as
                        // observations; do not claim they reached the client.
                        if close_deadline.is_some() {
                            continue;
                        }
                        if let Err(error) = upstream_tx.send(message).await {
                            terminal = TerminalState::Error;
                            reason = "upstream_write";
                            error_detail = Some(websocket_error_detail(&error));
                            break;
                        }
                    }
                    Some(Err(error)) => {
                        terminal = TerminalState::Error;
                        reason = "client_read";
                        error_detail = Some(websocket_error_detail(&error));
                        break;
                    }
                    None => break,
                }
            }
            next = upstream_rx.next(), if !upstream_close_received => {
                match next {
                    Some(Ok(message)) => {
                        upstream_sequence = upstream_sequence.saturating_add(1);
                        let Some((message, frame)) = upstream_to_downstream(message) else {
                            terminal = TerminalState::Error;
                            reason = "unsupported_raw_frame";
                            break;
                        };
                        let is_close = frame.opcode == "close";
                        if capture_budget.enqueue(&capture_sender,
                            "upstream_to_client", upstream_sequence, frame,
                        ).is_err() {
                            store.note_capture_drop();
                            capture_failed.store(true, Ordering::Release);
                        }
                        if is_close {
                            upstream_close_received = true;
                            if close_deadline.is_none() {
                                reason = "upstream_close";
                                close_deadline = Some(tokio::time::Instant::now() + WEBSOCKET_CLOSE_TIMEOUT);
                            }
                            if let Err(detail) = websocket_close_io(upstream_tx.flush()).await {
                                terminal = TerminalState::Error;
                                reason = "upstream_close_flush";
                                error_detail = Some(detail);
                                break;
                            }
                            if client_close_received {
                                terminal = TerminalState::Complete;
                                break;
                            }
                            if let Err(detail) = websocket_close_io(downstream_tx.send(message)).await {
                                terminal = TerminalState::Error;
                                reason = "client_close_write";
                                error_detail = Some(detail);
                                break;
                            }
                            continue;
                        }
                        if close_deadline.is_some() {
                            continue;
                        }
                        if let Err(error) = downstream_tx.send(message).await {
                            terminal = TerminalState::Cancelled;
                            reason = "client_write";
                            error_detail = Some(websocket_error_detail(&error));
                            break;
                        }
                    }
                    Some(Err(error)) => {
                        terminal = TerminalState::Error;
                        reason = "upstream_read";
                        error_detail = Some(websocket_error_detail(&error));
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    drop(capture_sender);
    if let Err(error) = capture_task.await {
        store.note_capture_drop();
        capture_failed.store(true, Ordering::Release);
        warn!(
            task_cancelled = error.is_cancelled(),
            task_panicked = error.is_panic(),
            "WebSocket capture task failed"
        );
    }

    let mut finished = store.event("proxy", "websocket_connection_finished");
    finished.ids = ids.clone();
    let capture_failed = capture_failed.load(Ordering::Acquire);
    let evidence_terminal = if capture_failed && terminal == TerminalState::Complete {
        TerminalState::Incomplete
    } else {
        terminal.clone()
    };
    finished.terminal_state = Some(evidence_terminal.clone());
    finished.normalized = Some(json!({
        "reason": reason,
        "error_detail": error_detail,
        "capture_failed": capture_failed,
        "client_close_received": client_close_received,
        "upstream_close_received": upstream_close_received,
        "client_messages": downstream_sequence,
        "upstream_messages": upstream_sequence,
    }));
    if store.append(finished).await.is_err() {
        store.note_capture_drop();
    }
    record_terminal(
        &store,
        ids,
        "transport_attempt_finished",
        evidence_terminal,
        json!({
            "protocol": "websocket",
            "reason": reason,
            "error_detail": error_detail,
            "capture_failed": capture_failed,
            "client_close_received": client_close_received,
            "upstream_close_received": upstream_close_received,
            "client_messages": downstream_sequence,
            "upstream_messages": upstream_sequence,
        }),
    )
    .await;
}

async fn websocket_close_io<F, E>(future: F) -> Result<(), Value>
where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::error::Error + 'static,
{
    match tokio::time::timeout(WEBSOCKET_CLOSE_TIMEOUT, future).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(websocket_error_detail(&error)),
        Err(_) => Err(json!({"schema_version": 1, "category": "timeout"})),
    }
}

// Never store Display/Debug of a provider error: it may contain URLs, headers,
// or payload bytes. Walk a bounded source chain and retain only typed labels.
fn websocket_error_detail(error: &(dyn std::error::Error + 'static)) -> Value {
    use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};
    let mut current = Some(error);
    for _ in 0..16 {
        let Some(error) = current else { break };
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return json!({"schema_version": 1, "category": "io", "io_kind": format!("{:?}", error.kind())});
        }
        if let Some(error) = error.downcast_ref::<Error>() {
            let category = match error {
                Error::Io(error) => {
                    return json!({"schema_version": 1, "category": "io", "io_kind": format!("{:?}", error.kind())});
                }
                Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                    return json!({"schema_version": 1, "category": "protocol", "protocol_kind": "reset_without_closing_handshake"});
                }
                Error::Protocol(_) => "protocol",
                Error::Tls(_) => "tls",
                Error::Capacity(_) => "capacity",
                Error::Utf8(_) => "utf8",
                Error::ConnectionClosed => "connection_closed",
                Error::AlreadyClosed => "already_closed",
                Error::WriteBufferFull(_) => "write_buffer_full",
                _ => "websocket_other",
            };
            return json!({"schema_version": 1, "category": category});
        }
        current = error.source();
    }
    json!({"schema_version": 1, "category": "unknown"})
}

async fn capture_websocket_stream(
    mut receiver: tokio::sync::mpsc::Receiver<CapturedWebSocketMessage>,
    store: RunStore,
    ids: EventIds,
    path: String,
    capture_failed: Arc<AtomicBool>,
) {
    let mut downstream_captured = 0_u64;
    let mut upstream_captured = 0_u64;
    let mut persistence_available = true;
    while let Some(message) = receiver.recv().await {
        if !persistence_available {
            continue;
        }
        let captured = if message.direction == "client_to_upstream" {
            &mut downstream_captured
        } else {
            &mut upstream_captured
        };
        if let Err(error) = record_websocket_frame(
            &store,
            &ids,
            message.direction,
            message.sequence,
            &message.frame,
            &path,
            captured,
        )
        .await
        {
            store.note_capture_drop();
            capture_failed.store(true, Ordering::Release);
            persistence_available = false;
            warn!(
                error_kind = error.category(),
                "failed to record WebSocket message; forwarding continues"
            );
        }
    }
}

struct CapturedWebSocketMessage {
    direction: &'static str,
    sequence: u64,
    frame: WebSocketFrame,
    // Keep both reservations until this message is persisted or discarded.
    _shared: OwnedSemaphorePermit,
    _connection: OwnedSemaphorePermit,
}

struct WebSocketCaptureBudget {
    shared: Arc<Semaphore>,
    connection: Arc<Semaphore>,
}

impl WebSocketCaptureBudget {
    fn enqueue(
        &self,
        sender: &tokio::sync::mpsc::Sender<CapturedWebSocketMessage>,
        direction: &'static str,
        sequence: u64,
        frame: WebSocketFrame,
    ) -> Result<(), ()> {
        // Charge queue metadata too: many empty control frames across many
        // connections must not evade the proxy-wide memory reservation.
        let size = frame
            .payload
            .len()
            .checked_add(std::mem::size_of::<CapturedWebSocketMessage>())
            .ok_or(())?;
        let size = u32::try_from(size).map_err(|_| ())?;
        let shared = Arc::clone(&self.shared)
            .try_acquire_many_owned(size)
            .map_err(|_| ())?;
        let connection = Arc::clone(&self.connection)
            .try_acquire_many_owned(size)
            .map_err(|_| ())?;
        sender
            .try_send(CapturedWebSocketMessage {
                direction,
                sequence,
                frame,
                _shared: shared,
                _connection: connection,
            })
            .map_err(|_| ())
    }
}

struct WebSocketFrame {
    opcode: &'static str,
    payload: Bytes,
    close_code: Option<u16>,
}

fn downstream_to_upstream(message: AxumMessage) -> (TungsteniteMessage, WebSocketFrame) {
    match message {
        AxumMessage::Text(text) => {
            let payload: Bytes = text.into();
            (
                TungsteniteMessage::Text(
                    payload.clone().try_into().expect("validated UTF-8 message"),
                ),
                WebSocketFrame {
                    opcode: "text",
                    payload,
                    close_code: None,
                },
            )
        }
        AxumMessage::Binary(payload) => (
            TungsteniteMessage::Binary(payload.clone()),
            WebSocketFrame {
                opcode: "binary",
                payload,
                close_code: None,
            },
        ),
        AxumMessage::Ping(payload) => (
            TungsteniteMessage::Ping(payload.clone()),
            WebSocketFrame {
                opcode: "ping",
                payload,
                close_code: None,
            },
        ),
        AxumMessage::Pong(payload) => (
            TungsteniteMessage::Pong(payload.clone()),
            WebSocketFrame {
                opcode: "pong",
                payload,
                close_code: None,
            },
        ),
        AxumMessage::Close(frame) => {
            let close_code = frame.as_ref().map(|frame| frame.code);
            let payload = frame.as_ref().map_or_else(Bytes::new, |frame| {
                Bytes::copy_from_slice(frame.reason.as_bytes())
            });
            let forwarded = frame.map(|frame| TungsteniteCloseFrame {
                code: CloseCode::from(frame.code),
                reason: frame.reason.to_string().into(),
            });
            (
                TungsteniteMessage::Close(forwarded),
                WebSocketFrame {
                    opcode: "close",
                    payload,
                    close_code,
                },
            )
        }
    }
}

fn upstream_to_downstream(message: TungsteniteMessage) -> Option<(AxumMessage, WebSocketFrame)> {
    match message {
        TungsteniteMessage::Text(text) => {
            let payload: Bytes = text.into();
            Some((
                AxumMessage::Text(payload.clone().try_into().expect("validated UTF-8 message")),
                WebSocketFrame {
                    opcode: "text",
                    payload,
                    close_code: None,
                },
            ))
        }
        TungsteniteMessage::Binary(payload) => Some((
            AxumMessage::Binary(payload.clone()),
            WebSocketFrame {
                opcode: "binary",
                payload,
                close_code: None,
            },
        )),
        TungsteniteMessage::Ping(payload) => Some((
            AxumMessage::Ping(payload.clone()),
            WebSocketFrame {
                opcode: "ping",
                payload,
                close_code: None,
            },
        )),
        TungsteniteMessage::Pong(payload) => Some((
            AxumMessage::Pong(payload.clone()),
            WebSocketFrame {
                opcode: "pong",
                payload,
                close_code: None,
            },
        )),
        TungsteniteMessage::Close(frame) => {
            let close_code = frame.as_ref().map(|frame| u16::from(frame.code));
            let payload = frame.as_ref().map_or_else(Bytes::new, |frame| {
                Bytes::copy_from_slice(frame.reason.as_bytes())
            });
            let forwarded = frame.map(|frame| AxumCloseFrame {
                code: u16::from(frame.code),
                reason: frame.reason.to_string().into(),
            });
            Some((
                AxumMessage::Close(forwarded),
                WebSocketFrame {
                    opcode: "close",
                    payload,
                    close_code,
                },
            ))
        }
        TungsteniteMessage::Frame(_) => None,
    }
}

async fn record_websocket_frame(
    store: &RunStore,
    ids: &EventIds,
    direction: &str,
    sequence: u64,
    frame: &WebSocketFrame,
    path: &str,
    captured_total: &mut u64,
) -> Result<(), StorageError> {
    let remaining = store
        .policy()
        .max_blob_bytes
        .saturating_sub(*captured_total);
    let capture_len = if store.policy().permits_body(path) {
        usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(frame.payload.len())
    } else {
        0
    };
    let raw = if capture_len == 0 {
        None
    } else {
        let mut reference = store
            .store_blob(
                &frame.payload[..capture_len],
                Some("application/websocket-frame"),
            )
            .await?;
        *captured_total = captured_total.saturating_add(reference.size);
        reference.truncated |= capture_len != frame.payload.len();
        Some(reference)
    };
    let captured_size = raw.as_ref().map_or(0, |reference| reference.size);
    let mut event = store.event("proxy", "websocket_frame");
    event.ids = ids.clone();
    event.raw = raw;
    event.normalized = Some(json!({
        "direction": direction,
        "message_sequence": sequence,
        "opcode": frame.opcode,
        "observed_size": frame.payload.len(),
        "captured_size": captured_size,
        "sha256": format!("sha256:{}", hex::encode(Sha256::digest(&frame.payload))),
        "close_code": frame.close_code,
    }));
    event.redaction = RedactionRecord {
        policy: store.policy().name.clone(),
        fields: Vec::new(),
        omitted: if captured_size == u64::try_from(frame.payload.len()).unwrap_or(u64::MAX) {
            Vec::new()
        } else {
            vec!["frame_payload".to_owned()]
        },
    };
    store.append(event).await?;
    Ok(())
}

async fn forward_inner(state: ProxyState, request: Request) -> anyhow::Result<Response> {
    let inference_id = request_inference_id(request.headers());
    let attempt_id = Uuid::now_v7().to_string();
    let ids = EventIds {
        session_id: request_session_id(request.headers()),
        inference_id: Some(inference_id),
        attempt_id: Some(attempt_id),
        connection_id: None,
        ..EventIds::default()
    };

    let (parts, body) = request.into_parts();
    let target = target_url(&state.upstream, &parts.uri)?;
    let (sanitized_headers, mut redaction) = state.store.policy().sanitize_headers(&parts.headers);
    if parts.uri.query().is_some() {
        redaction.omitted.push("query_values".to_owned());
    }
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let is_model = classify_model_path(parts.uri.path());

    let mut start_event = state.store.event("proxy", "transport_request_started");
    start_event.ids = ids.clone();
    start_event.redaction = redaction;
    start_event.normalized = Some(json!({
        "method": parts.method.as_str(),
        "uri": safe_uri(&parts.uri),
        "upstream": safe_url(&target, true),
        "headers": sanitized_headers,
        "traffic_class": if is_model { "model" } else { "other" },
        "protocol": http_protocol_label(parts.version),
    }));
    append_observation(&state.store, start_event, "transport_request_started").await;

    let forwarded_headers = forwarding_headers(&parts.headers, true);
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
    let request_store = state.store.clone();
    let request_ids = ids.clone();
    let request_path = parts.uri.path().to_owned();
    let incoming_path = request_path.clone();
    let request_type = content_type.clone();
    let request_guard = state.connections.register();
    let normalization_slot = Arc::clone(&state.normalization_slots)
        .try_acquire_owned()
        .ok();
    tokio::spawn(async move {
        let _request_guard = request_guard;
        pump_incoming_body(
            body,
            request_tx,
            request_store,
            request_ids,
            incoming_path,
            request_type,
            is_model,
            normalization_slot,
        )
        .await;
    });

    let outgoing_body = reqwest::Body::wrap_stream(ReceiverStream::new(request_rx));
    let upstream_response = state
        .client
        .request(parts.method.clone(), target.clone())
        .headers(forwarded_headers)
        .body(outgoing_body)
        .send()
        .await;

    let upstream_response = match upstream_response {
        Ok(response) => response,
        Err(error) => {
            let mut event = state.store.event("proxy", "transport_attempt_finished");
            event.ids = ids;
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(json!({
                "error_kind": classify_reqwest_error(&error),
            }));
            append_observation(&state.store, event, "transport_attempt_finished").await;
            return Err(error.into());
        }
    };

    let status = upstream_response.status();
    let upstream_protocol = http_protocol_label(upstream_response.version());
    let response_headers = upstream_response.headers().clone();
    let response_type = response_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let is_sse = response_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));
    let (sanitized_response_headers, response_redaction) =
        state.store.policy().sanitize_headers(&response_headers);
    let mut response_event = state.store.event("proxy", "transport_response_started");
    response_event.ids = ids.clone();
    response_event.redaction = response_redaction;
    response_event.normalized = Some(json!({
        "status": status.as_u16(),
        "headers": sanitized_response_headers,
        "sse": is_sse,
        "upstream_protocol": upstream_protocol,
    }));
    append_observation(&state.store, response_event, "transport_response_started").await;

    let output_headers = forwarding_headers(&response_headers, false);
    let (response_tx, response_rx) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
    let response_store = state.store;
    let response_guard = state.connections.register();
    tokio::spawn(async move {
        let _response_guard = response_guard;
        pump_upstream_body(
            upstream_response,
            response_tx,
            response_store,
            ids,
            request_path,
            response_type,
            is_sse,
            status,
        )
        .await;
    });

    let mut builder = Response::builder().status(status);
    for (name, value) in &output_headers {
        builder = builder.header(name, value);
    }
    Ok(builder
        .body(Body::from_stream(ReceiverStream::new(response_rx)))
        .unwrap_or_else(|_| {
            plain_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid response\n")
        }))
}

async fn pump_incoming_body(
    body: Body,
    sender: tokio::sync::mpsc::Sender<Result<Bytes, io::Error>>,
    store: RunStore,
    ids: EventIds,
    path: String,
    media_type: Option<String>,
    is_model: bool,
    normalization_slot: Option<OwnedSemaphorePermit>,
) {
    let mut stream = body.into_data_stream();
    let mut index = 0_u64;
    let mut observed = 0_u64;
    let mut normalized_body = Vec::new();
    let normalization_enabled = normalization_slot.is_some();
    let mut normalization_truncated = !normalization_enabled;
    let mut body_digest = Sha256::new();
    let capture_failed = Arc::new(AtomicBool::new(false));
    let (capture_sender, capture_receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
    let capture_task = tokio::spawn(capture_body_stream(
        capture_receiver,
        store.clone(),
        ids.clone(),
        path.clone(),
        media_type.clone(),
        "request_body_chunk",
        Arc::clone(&capture_failed),
    ));
    let mut terminal = TerminalState::Complete;
    let mut reason = None;
    while let Some(next) = stream.next().await {
        match next {
            Ok(bytes) => {
                index = index.saturating_add(1);
                observed = observed.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                body_digest.update(&bytes);
                if normalization_enabled {
                    let remaining =
                        MAX_NORMALIZED_REQUEST_BYTES.saturating_sub(normalized_body.len());
                    if bytes.len() <= remaining {
                        normalized_body.extend_from_slice(&bytes);
                    } else {
                        normalized_body.extend_from_slice(&bytes[..remaining]);
                        normalization_truncated = true;
                    }
                }
                if capture_sender.try_send((index, bytes.clone())).is_err() {
                    store.note_capture_drop();
                    capture_failed.store(true, Ordering::Release);
                }
                if forward_body_data(&sender, bytes).await.is_err() {
                    terminal = TerminalState::Cancelled;
                    reason = Some("upstream_stopped_reading");
                    break;
                }
            }
            Err(_error) => {
                let _ = sender
                    .send(Err(io::Error::other("downstream request body read failed")))
                    .await;
                terminal = TerminalState::Error;
                reason = Some("downstream_body");
                break;
            }
        }
    }
    drop(sender);
    drop(capture_sender);
    if let Err(error) = capture_task.await {
        store.note_capture_drop();
        capture_failed.store(true, Ordering::Release);
        warn!(
            task_cancelled = error.is_cancelled(),
            task_panicked = error.is_panic(),
            "request capture task failed"
        );
    }

    if is_model
        && terminal == TerminalState::Complete
        && let Err(error) = record_request_summary(
            &store,
            &ids,
            &path,
            media_type.as_deref(),
            &normalized_body,
            observed,
            normalization_truncated,
            body_digest,
        )
        .await
    {
        warn!(
            error_kind = error.category(),
            "failed to persist logical request summary"
        );
        store.note_capture_drop();
        capture_failed.store(true, Ordering::Release);
    }

    let capture_failed = capture_failed.load(Ordering::Acquire);
    record_terminal(
        &store,
        ids,
        "request_body_finished",
        if capture_failed && terminal == TerminalState::Complete {
            TerminalState::Incomplete
        } else {
            terminal
        },
        json!({"observed_bytes": observed, "chunks": index, "capture_failed": capture_failed, "reason": reason}),
    )
    .await;
}

async fn capture_body_stream(
    mut receiver: tokio::sync::mpsc::Receiver<(u64, Bytes)>,
    store: RunStore,
    ids: EventIds,
    path: String,
    media_type: Option<String>,
    kind: &'static str,
    capture_failed: Arc<AtomicBool>,
) {
    let mut captured = 0_u64;
    let mut persistence_available = true;
    while let Some((index, bytes)) = receiver.recv().await {
        if !persistence_available {
            continue;
        }
        if let Err(error) = record_body_chunk(
            &store,
            &ids,
            kind,
            index,
            &bytes,
            &path,
            media_type.as_deref(),
            &mut captured,
        )
        .await
        {
            store.note_capture_drop();
            capture_failed.store(true, Ordering::Release);
            persistence_available = false;
            warn!(
                error_kind = error.category(),
                kind, "failed to record body chunk; forwarding continues"
            );
        }
    }
}

async fn pump_upstream_body(
    response: reqwest::Response,
    sender: tokio::sync::mpsc::Sender<Result<Bytes, io::Error>>,
    store: RunStore,
    ids: EventIds,
    path: String,
    media_type: Option<String>,
    is_sse: bool,
    status: StatusCode,
) {
    let mut stream = response.bytes_stream();
    let mut index = 0_u64;
    let mut observed = 0_u64;
    let capture_failed = Arc::new(AtomicBool::new(false));
    let (capture_sender, capture_receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
    let capture_task = tokio::spawn(capture_response_stream(
        capture_receiver,
        store.clone(),
        ids.clone(),
        path.clone(),
        media_type.clone(),
        is_sse,
        Arc::clone(&capture_failed),
    ));
    let mut terminal = TerminalState::Complete;
    let mut reason = None;

    while let Some(next) = stream.next().await {
        match next {
            Ok(bytes) => {
                index = index.saturating_add(1);
                observed = observed.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                if capture_sender.try_send((index, bytes.clone())).is_err() {
                    store.note_capture_drop();
                    capture_failed.store(true, Ordering::Release);
                }

                if forward_body_data(&sender, bytes).await.is_err() {
                    terminal = TerminalState::Cancelled;
                    reason = Some("downstream_cancelled");
                    break;
                }
            }
            Err(_error) => {
                let _ = sender
                    .send(Err(io::Error::other("upstream response body read failed")))
                    .await;
                terminal = TerminalState::Error;
                reason = Some("upstream_body");
                break;
            }
        }
    }
    drop(sender);
    drop(capture_sender);
    let capture = match capture_task.await {
        Ok(capture) => capture,
        Err(error) => {
            store.note_capture_drop();
            capture_failed.store(true, Ordering::Release);
            warn!(
                task_cancelled = error.is_cancelled(),
                task_panicked = error.is_panic(),
                "response capture task failed"
            );
            ResponseCapture::default()
        }
    };

    let capture_failed = capture_failed.load(Ordering::Acquire);
    if terminal == TerminalState::Complete
        && (capture.incomplete_sse_bytes > 0 || capture.sse_parse_failed || capture_failed)
    {
        terminal = TerminalState::Incomplete;
    }
    record_terminal(
        &store,
        ids,
        "transport_attempt_finished",
        terminal,
        json!({
            "status": status.as_u16(),
            "observed_bytes": observed,
            "chunks": index,
            "sse_events": capture.sse_events,
            "incomplete_sse_bytes": capture.incomplete_sse_bytes,
            "sse_parse_failed": capture.sse_parse_failed,
            "capture_failed": capture_failed,
            "reason": reason,
        }),
    )
    .await;
}

async fn forward_body_data(
    sender: &tokio::sync::mpsc::Sender<Result<Bytes, io::Error>>,
    bytes: Bytes,
) -> Result<(), tokio::sync::mpsc::error::SendError<Result<Bytes, io::Error>>> {
    // Empty DATA frames carry no application bytes. Sending one after an SSE
    // consumer closes on [DONE] can fail even though every byte was forwarded.
    // Keep the captured chunk, but do not infer cancellation from an empty send.
    // The pump must still observe actual upstream EOF; later data/error is not
    // suppressed and still produces cancellation/error respectively.
    if bytes.is_empty() {
        return Ok(());
    }
    sender.send(Ok(bytes)).await
}

#[derive(Default)]
struct ResponseCapture {
    sse_events: u64,
    incomplete_sse_bytes: usize,
    sse_parse_failed: bool,
}

async fn capture_response_stream(
    mut receiver: tokio::sync::mpsc::Receiver<(u64, Bytes)>,
    store: RunStore,
    ids: EventIds,
    path: String,
    media_type: Option<String>,
    is_sse: bool,
    capture_failed: Arc<AtomicBool>,
) -> ResponseCapture {
    let mut captured = 0_u64;
    let mut parsed_stream_bytes = 0_u64;
    let mut parser = is_sse.then(SseParser::default);
    let mut result = ResponseCapture::default();
    let mut persistence_available = true;
    let mut expected_index = 1_u64;
    while let Some((index, bytes)) = receiver.recv().await {
        if !persistence_available {
            continue;
        }
        let stream_gap = index != expected_index;
        expected_index = index.saturating_add(1);
        if stream_gap {
            capture_failed.store(true, Ordering::Release);
        }
        if parser.is_some() && (stream_gap || capture_failed.load(Ordering::Acquire)) {
            result.sse_parse_failed = true;
            parser = None;
        }
        if let Err(error) = record_body_chunk(
            &store,
            &ids,
            "response_body_chunk",
            index,
            &bytes,
            &path,
            media_type.as_deref(),
            &mut captured,
        )
        .await
        {
            store.note_capture_drop();
            capture_failed.store(true, Ordering::Release);
            persistence_available = false;
            warn!(
                error_kind = error.category(),
                "failed to record response body; forwarding continues"
            );
            continue;
        }

        let Some(active_parser) = parser.as_mut() else {
            continue;
        };
        match active_parser.push(&bytes) {
            Ok(events) => {
                for event in events {
                    result.sse_events = result.sse_events.saturating_add(1);
                    parsed_stream_bytes = parsed_stream_bytes
                        .saturating_add(u64::try_from(event.raw.len()).unwrap_or(u64::MAX));
                    let raw_fully_captured = parsed_stream_bytes <= captured;
                    if let Err(error) = record_sse_event(
                        &store,
                        &ids,
                        result.sse_events,
                        event,
                        &path,
                        raw_fully_captured,
                    )
                    .await
                    {
                        warn!(
                            error_kind = error.category(),
                            "failed to persist parsed SSE event"
                        );
                        store.note_capture_drop();
                        capture_failed.store(true, Ordering::Release);
                        persistence_available = false;
                        break;
                    }
                }
            }
            Err(SseError::EventTooLarge { limit }) => {
                result.sse_parse_failed = true;
                let mut event = store.event("proxy", "sse_parse_error");
                event.ids = ids.clone();
                event.normalized = Some(json!({
                    "error_kind": "sse_event_too_large",
                    "limit": limit,
                    "detail_persisted": false,
                }));
                if store.append(event).await.is_err() {
                    store.note_capture_drop();
                    capture_failed.store(true, Ordering::Release);
                    persistence_available = false;
                }
                parser = None;
            }
        }
    }
    if parser.is_some() && capture_failed.load(Ordering::Acquire) {
        result.sse_parse_failed = true;
        parser = None;
    }
    result.incomplete_sse_bytes = parser
        .and_then(SseParser::finish)
        .map_or(0, |bytes| bytes.len());
    result
}

async fn record_body_chunk(
    store: &RunStore,
    ids: &EventIds,
    kind: &str,
    index: u64,
    bytes: &Bytes,
    path: &str,
    media_type: Option<&str>,
    captured_total: &mut u64,
) -> Result<(), StorageError> {
    let permits_body = store.policy().permits_body(path);
    let limit = store.policy().max_blob_bytes;
    let remaining = limit.saturating_sub(*captured_total);
    let capture_len = if permits_body {
        usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len())
    } else {
        0
    };
    let hash = hex::encode(Sha256::digest(bytes));
    let mut raw = None;
    let mut captured_size = 0_u64;
    if capture_len > 0 {
        let mut reference = store.store_blob(&bytes[..capture_len], media_type).await?;
        captured_size = reference.size;
        reference.truncated |= capture_len < bytes.len();
        raw = Some(reference);
        *captured_total = captured_total.saturating_add(captured_size);
    }

    let mut event = store.event("proxy", kind);
    event.ids = ids.clone();
    event.raw = raw;
    event.normalized = Some(json!({
        "chunk_sequence": index,
        "observed_size": bytes.len(),
        "captured_size": captured_size,
        "sha256": format!("sha256:{hash}"),
    }));
    event.redaction = RedactionRecord {
        policy: store.policy().name.clone(),
        fields: Vec::new(),
        omitted: if captured_size == u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
            Vec::new()
        } else {
            vec!["body_bytes".to_owned()]
        },
    };
    store.append(event).await?;
    Ok(())
}

async fn record_sse_event(
    store: &RunStore,
    ids: &EventIds,
    index: u64,
    parsed: crate::sse::SseEvent,
    path: &str,
    raw_fully_captured: bool,
) -> Result<(), StorageError> {
    let data_hash = hex::encode(Sha256::digest(&parsed.data));
    let raw_hash = hex::encode(Sha256::digest(&parsed.raw));
    let raw_size = parsed.raw.len();
    let raw = if raw_fully_captured && store.policy().permits_body(path) {
        Some(
            store
                .store_blob(&parsed.raw, Some("text/event-stream"))
                .await?,
        )
    } else {
        None
    };
    let mut event = store.event("proxy", "sse_event");
    event.ids = ids.clone();
    event.raw = raw;
    if event.raw.is_none() {
        event.redaction.omitted.push("sse_raw_bytes".to_owned());
    }
    let normalized_event = parsed.event.as_deref().map(normalized_metadata_string);
    let normalized_id = parsed.id.as_deref().map(normalized_metadata_string);
    let semantic = parse_sse_semantics(&parsed.data);
    event.normalized = Some(json!({
        "event_sequence": index,
        "event": normalized_event,
        "id": normalized_id,
        "retry_ms": parsed.retry_ms,
        "raw_size": raw_size,
        "raw_sha256": format!("sha256:{raw_hash}"),
        "data_size": parsed.data.len(),
        "data_sha256": format!("sha256:{data_hash}"),
        "valid_utf8": parsed.valid_utf8,
        "semantic": semantic,
    }));
    store.append(event).await?;
    Ok(())
}

async fn record_request_summary(
    store: &RunStore,
    ids: &EventIds,
    path: &str,
    media_type: Option<&str>,
    captured: &[u8],
    observed_size: u64,
    truncated: bool,
    digest: Sha256,
) -> Result<(), StorageError> {
    let hash = format!("sha256:{}", hex::encode(digest.finalize()));
    let parsed = (!truncated && validate_json_complexity(captured).is_ok())
        .then(|| serde_json::from_slice::<Value>(captured).ok())
        .flatten();
    let summary = parsed.as_ref().map_or_else(
        || {
            json!({
                "parsed": false,
                "normalization_truncated": truncated,
                "payload_dependencies": {
                    "modalities": {},
                    "embedded_parts": 0,
                    "unresolved_references": 0,
                    "unresolved_kinds": {},
                    "scan_truncated": truncated,
                    "scan_inconclusive": true,
                },
            })
        },
        |payload| {
            let message_count = payload
                .get("messages")
                .or_else(|| payload.get("input"))
                .and_then(Value::as_array)
                .map(Vec::len);
            let tool_count = payload.get("tools").and_then(Value::as_array).map(Vec::len);
            let dependencies = summarize_payload_dependencies(payload);
            json!({
                "parsed": true,
                "model": normalized_json_string(payload.get("model")),
                "stream": payload.get("stream").and_then(Value::as_bool),
                "message_count": message_count,
                "tool_count": tool_count,
                "previous_response_id": normalized_json_string(payload.get("previous_response_id")),
                "conversation": string_or_object_id(payload.get("conversation")),
                "cached_content": normalized_json_string(
                    payload.get("cachedContent").or_else(|| payload.get("cached_content"))
                ),
                "max_output_tokens": payload.get("max_output_tokens")
                    .or_else(|| payload.get("max_tokens"))
                    .and_then(Value::as_u64),
                "payload_dependencies": {
                    "modalities": dependencies.modalities,
                    "embedded_parts": dependencies.embedded_parts,
                    "unresolved_references": dependencies.unresolved_references,
                    "unresolved_kinds": dependencies.unresolved_kinds,
                    "scan_truncated": dependencies.scan_truncated,
                    "scan_inconclusive": false,
                },
            })
        },
    );
    let mut event = store.event("proxy", "logical_inference_request");
    event.ids = ids.clone();
    event.normalized = Some(json!({
        "path": normalized_metadata_string(path),
        "media_type": media_type.map(normalized_metadata_string),
        "observed_size": observed_size,
        "sha256": hash,
        "summary": summary,
    }));
    store.append(event).await?;
    Ok(())
}

fn summarize_payload_dependencies(payload: &Value) -> PayloadDependencySummary {
    let mut summary = PayloadDependencySummary::default();
    let mut pending = vec![payload];
    let mut visited = 0_usize;
    while let Some(value) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_PAYLOAD_DEPENDENCY_NODES {
            summary.scan_truncated = true;
            break;
        }
        match value {
            Value::Array(values) => {
                if visited
                    .saturating_add(pending.len())
                    .saturating_add(values.len())
                    > MAX_PAYLOAD_DEPENDENCY_NODES
                {
                    summary.scan_truncated = true;
                    break;
                }
                pending.extend(values);
            }
            Value::Object(object) => {
                let kind = object
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let media_type = object
                    .get("mime_type")
                    .or_else(|| object.get("mimeType"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let modality = payload_modality(&kind, &media_type, object);
                if let Some(modality) = modality {
                    *summary.modalities.entry(modality).or_default() += 1;
                }

                let mut embedded = false;
                let mut unresolved = Vec::new();
                for (field, label) in [
                    ("file_id", "file-id"),
                    ("fileId", "file-id"),
                    ("file_uri", "file-uri"),
                    ("fileUri", "file-uri"),
                    ("file_url", "file-url"),
                    ("fileUrl", "file-url"),
                    ("video_url", "video-url"),
                    ("videoUrl", "video-url"),
                    ("audio_url", "audio-url"),
                    ("audioUrl", "audio-url"),
                ] {
                    if object.get(field).is_some_and(nonempty_reference) {
                        unresolved.push(label);
                    }
                }
                if let Some(reference) = object.get("image_url").or_else(|| object.get("imageUrl"))
                {
                    let reference = reference
                        .as_str()
                        .or_else(|| reference.get("url").and_then(Value::as_str));
                    if reference.is_some_and(is_embedded_url) {
                        embedded = true;
                    } else if reference.is_some_and(|value| !value.is_empty()) {
                        unresolved.push("image-url");
                    }
                }
                if let Some(source) = object.get("source").and_then(Value::as_object) {
                    let source_type = source
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if source_type == "base64" && source.get("data").is_some_and(nonempty_reference)
                    {
                        embedded = true;
                    } else if source_type == "url"
                        && source.get("url").is_some_and(nonempty_reference)
                    {
                        unresolved.push("source-url");
                    }
                }
                if modality.is_some()
                    && object.get("data").is_some_and(nonempty_reference)
                    && !object.contains_key("file_uri")
                    && !object.contains_key("fileUri")
                {
                    embedded = true;
                }
                if embedded {
                    summary.embedded_parts = summary.embedded_parts.saturating_add(1);
                }
                unresolved.sort_unstable();
                unresolved.dedup();
                for kind in unresolved {
                    summary.unresolved_references = summary.unresolved_references.saturating_add(1);
                    *summary.unresolved_kinds.entry(kind).or_default() += 1;
                }
                if visited
                    .saturating_add(pending.len())
                    .saturating_add(object.len())
                    > MAX_PAYLOAD_DEPENDENCY_NODES
                {
                    summary.scan_truncated = true;
                    break;
                }
                pending.extend(object.values());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    summary
}

fn payload_modality(
    kind: &str,
    media_type: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<&'static str> {
    if kind.contains("image")
        || media_type.starts_with("image/")
        || object.contains_key("image_url")
    {
        Some("image")
    } else if kind.contains("audio") || media_type.starts_with("audio/") {
        Some("audio")
    } else if kind.contains("video") || media_type.starts_with("video/") {
        Some("video")
    } else if kind.contains("file")
        || kind.contains("document")
        || (!media_type.is_empty() && !media_type.starts_with("text/"))
    {
        Some("file")
    } else if kind.contains("text") || media_type.starts_with("text/") {
        Some("text")
    } else {
        None
    }
}

fn nonempty_reference(value: &Value) -> bool {
    value.as_str().is_some_and(|value| !value.is_empty())
}

fn is_embedded_url(value: &str) -> bool {
    value
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:"))
}

fn string_or_object_id(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("id").and_then(Value::as_str))
        })
        .map(normalized_metadata_string)
}

fn parse_sse_semantics(data: &[u8]) -> Value {
    if data == b"[DONE]" {
        return json!({"type": "done"});
    }
    if validate_json_complexity(data).is_err() {
        return json!({"type": "unparsed"});
    }
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return json!({"type": "unparsed"});
    };
    let response = value
        .get("response")
        .or_else(|| value.get("message"))
        .unwrap_or(&value);
    let usage = response.get("usage").or_else(|| value.get("usage"));
    json!({
        "type": normalized_json_string(value.get("type")),
        "response_id": normalized_json_string(response.get("id")),
        "model": normalized_json_string(response.get("model")),
        "status": normalized_json_string(response.get("status")),
        "input_tokens": usage.and_then(|value| value.get("input_tokens"))
            .and_then(Value::as_u64),
        "output_tokens": usage.and_then(|value| value.get("output_tokens"))
            .and_then(Value::as_u64),
        "previous_response_id": normalized_json_string(response.get("previous_response_id")),
    })
}

async fn record_terminal(
    store: &RunStore,
    ids: EventIds,
    kind: &str,
    terminal_state: TerminalState,
    normalized: Value,
) {
    let mut event = store.event("proxy", kind);
    event.ids = ids;
    event.terminal_state = Some(terminal_state);
    event.normalized = Some(normalized);
    if let Err(error) = store.append(event).await {
        store.note_capture_drop();
        error!(
            error_kind = error.category(),
            event = kind,
            "failed to persist terminal event"
        );
    }
}

async fn append_observation(store: &RunStore, event: PendingEvent, kind: &str) {
    if let Err(error) = store.append(event).await {
        store.note_capture_drop();
        warn!(
            error_kind = error.category(),
            event = kind,
            "failed to persist proxy observation"
        );
    }
}

fn forwarding_headers(input: &HeaderMap, request: bool) -> HeaderMap {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    let nominated = connection_nominated_headers(input);
    let mut output = HeaderMap::new();
    for (name, value) in input {
        if HOP_BY_HOP.contains(&name.as_str())
            || nominated.contains(name.as_str())
            || (request && (name == header::HOST || name == header::CONTENT_LENGTH))
        {
            continue;
        }
        output.append(name, value.clone());
    }
    output
}

fn connection_nominated_headers(input: &HeaderMap) -> BTreeSet<String> {
    input
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn target_url(base: &Url, uri: &Uri) -> anyhow::Result<Url> {
    let mut target = base.clone();
    let base_path = base.path().trim_end_matches('/');
    let uri_path = uri.path();
    let request_path = uri_path.trim_start_matches('/');
    let combined = if base_path.is_empty() || base_path == "/" {
        format!("/{request_path}")
    } else if uri_path == base_path || uri_path.starts_with(&format!("{base_path}/")) {
        uri_path.to_owned()
    } else if request_path.is_empty() {
        base_path.to_owned()
    } else {
        let overlap = overlapping_path_prefix_len(base_path, uri_path);
        if overlap == 0 {
            format!("{base_path}/{request_path}")
        } else {
            format!("{base_path}{}", &uri_path[overlap..])
        }
    };
    target.set_path(&combined);
    target.set_query(uri.query());
    target.set_fragment(None);
    if !matches!(target.scheme(), "http" | "https") {
        anyhow::bail!("unsupported upstream scheme {}", target.scheme());
    }
    Ok(target)
}

// Return the longest whole-segment request prefix already present at the end
// of the upstream base path. OpenAI-compatible clients commonly send `/v1/...`
// while provider bases already end in `/v1` (for example `/inference/v1`).
fn overlapping_path_prefix_len(base_path: &str, request_path: &str) -> usize {
    let mut end = request_path.len();
    loop {
        let prefix = &request_path[..end];
        if prefix.len() > 1 && base_path.ends_with(prefix) {
            return end;
        }
        let Some(previous_separator) = prefix.rfind('/') else {
            return 0;
        };
        if previous_separator == 0 {
            return 0;
        }
        end = previous_separator;
    }
}

fn validate_upstream_base(upstream: &Url) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(upstream.scheme(), "http" | "https") && upstream.host_str().is_some(),
        "upstream must be an absolute HTTP(S) URL"
    );
    anyhow::ensure!(
        upstream.username().is_empty() && upstream.password().is_none(),
        "upstream URL must not contain credentials; use provider authentication headers"
    );
    anyhow::ensure!(
        upstream.query().is_none() && upstream.fragment().is_none(),
        "upstream base URL must not contain a query or fragment"
    );
    Ok(())
}

fn websocket_target(base: &Url, uri: &Uri) -> anyhow::Result<Url> {
    let mut target = target_url(base, uri)?;
    let scheme = match target.scheme() {
        "http" => "ws",
        "https" => "wss",
        scheme => anyhow::bail!("unsupported WebSocket upstream scheme {scheme}"),
    };
    target
        .set_scheme(scheme)
        .map_err(|()| anyhow::anyhow!("cannot construct WebSocket upstream URL"))?;
    Ok(target)
}

fn safe_uri(uri: &Uri) -> Value {
    let mut query_parameter_count = 0_u64;
    let mut query_keys = Vec::new();
    if let Some(query) = uri.query() {
        for key in query
            .split('&')
            .filter_map(|pair| pair.split('=').next())
            .filter(|key| !key.is_empty())
        {
            query_parameter_count = query_parameter_count.saturating_add(1);
            if query_keys.len() < MAX_QUERY_METADATA_KEYS {
                query_keys.push(normalized_metadata_string(key));
            }
        }
    }
    json!({
        "path": normalized_metadata_string(uri.path()),
        "query_keys": query_keys,
        "query_parameter_count": query_parameter_count,
        "query_keys_truncated": query_parameter_count
            > u64::try_from(MAX_QUERY_METADATA_KEYS).unwrap_or(u64::MAX),
    })
}

fn safe_url(url: &Url, include_path: bool) -> Value {
    let mut query_parameter_count = 0_u64;
    let mut query_keys = Vec::new();
    for (key, _) in url.query_pairs() {
        query_parameter_count = query_parameter_count.saturating_add(1);
        if query_keys.len() < MAX_QUERY_METADATA_KEYS {
            query_keys.push(normalized_metadata_string(&key));
        }
    }
    json!({
        "scheme": url.scheme(),
        "host": url.host_str(),
        "port": url.port_or_known_default(),
        "path": include_path.then(|| normalized_metadata_string(url.path())),
        "query_keys": query_keys,
        "query_parameter_count": query_parameter_count,
        "query_keys_truncated": query_parameter_count
            > u64::try_from(MAX_QUERY_METADATA_KEYS).unwrap_or(u64::MAX),
    })
}

fn classify_model_path(path: &str) -> bool {
    let lowercase = path.to_ascii_lowercase();
    [
        "/chat/completions",
        "/responses",
        "/messages",
        "/realtime",
        ":generatecontent",
        ":streamgeneratecontent",
    ]
    .iter()
    .any(|suffix| lowercase.contains(suffix))
}

fn request_inference_id(headers: &HeaderMap) -> String {
    headers
        .get("x-iorec-inference-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .map_or_else(|| Uuid::now_v7().to_string(), str::to_owned)
}

fn request_session_id(headers: &HeaderMap) -> Option<String> {
    // Claude Code emits this identifier on every provider request, including
    // internal model calls that may not have a transcript assistant record.
    // Treat it as correlation metadata, never as authorization.
    headers
        .get("x-claude-code-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

fn http_protocol_label(version: http::Version) -> &'static str {
    if version == http::Version::HTTP_09 {
        "http/0.9"
    } else if version == http::Version::HTTP_10 {
        "http/1.0"
    } else if version == http::Version::HTTP_11 {
        "http/1.1"
    } else if version == http::Version::HTTP_2 {
        "http/2"
    } else if version == http::Version::HTTP_3 {
        "http/3"
    } else {
        "unknown"
    }
}

fn classify_reqwest_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_request() {
        "request"
    } else {
        "other"
    }
}

fn plain_response(status: StatusCode, message: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(message))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use crate::{policy::CapturePolicy, storage::for_each_event};

    use super::*;

    #[test]
    fn websocket_error_evidence_is_typed_bounded_and_secret_free() {
        use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};
        let io_error = Error::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "secret-token=https://private.invalid/?key=do-not-record",
        ));
        let wrapped = axum::Error::new(io_error);
        assert_eq!(
            websocket_error_detail(&wrapped),
            json!({"schema_version": 1, "category": "io", "io_kind": "ConnectionReset"})
        );
        let protocol = Error::Protocol(ProtocolError::ResetWithoutClosingHandshake);
        assert_eq!(
            websocket_error_detail(&protocol)["protocol_kind"],
            "reset_without_closing_handshake"
        );
        let other = anyhow::anyhow!("secret-token");
        let detail = websocket_error_detail(other.as_ref());
        assert_eq!(detail["category"], "unknown");
        assert!(!detail.to_string().contains("secret"));
    }

    #[test]
    fn websocket_capture_reservations_bound_bytes_and_release_on_every_exit() {
        let overhead = std::mem::size_of::<CapturedWebSocketMessage>();
        let total = 3 * overhead + 10;
        let shared = Arc::new(Semaphore::new(total));
        let a = WebSocketCaptureBudget {
            shared: Arc::clone(&shared),
            connection: Arc::new(Semaphore::new(2 * overhead + 5)),
        };
        let b = WebSocketCaptureBudget {
            shared: Arc::clone(&shared),
            connection: Arc::new(Semaphore::new(2 * overhead + 5)),
        };
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let frame = |bytes: usize| WebSocketFrame {
            opcode: "text",
            payload: Bytes::from(vec![b'x'; bytes]),
            close_code: None,
        };
        assert!(
            a.enqueue(&sender, "client_to_upstream", 1, frame(4))
                .is_ok()
        );
        assert!(
            a.enqueue(&sender, "client_to_upstream", 2, frame(2))
                .is_err()
        );
        assert_eq!(shared.available_permits(), 2 * overhead + 6); // Failed per-connection reservation was released.
        assert!(
            b.enqueue(&sender, "upstream_to_client", 1, frame(4))
                .is_ok()
        );
        assert!(
            b.enqueue(&sender, "upstream_to_client", 2, frame(3))
                .is_err()
        );
        assert_eq!(shared.available_permits(), overhead + 2);
        assert!(
            a.enqueue(&sender, "client_to_upstream", 3, frame(1))
                .is_err()
        ); // Full message queue.
        assert_eq!(shared.available_permits(), overhead + 2);
        let active = receiver.try_recv().unwrap();
        assert_eq!(shared.available_permits(), overhead + 2); // Still reserved during persistence.
        drop(active);
        assert_eq!(shared.available_permits(), 2 * overhead + 6);
        drop(receiver);
        assert_eq!(shared.available_permits(), total);
        assert!(
            a.enqueue(&sender, "client_to_upstream", 4, frame(1))
                .is_err()
        );
        assert_eq!(shared.available_permits(), total); // Closed receiver releases both permits.
    }

    #[test]
    fn websocket_text_forwarding_shares_validated_utf8_storage() {
        let input = AxumMessage::Text("中文🙂".into());
        let (forwarded, captured) = downstream_to_upstream(input);
        let TungsteniteMessage::Text(text) = forwarded else {
            panic!("text expected")
        };
        assert_eq!(text.as_ptr(), captured.payload.as_ptr());
        let (forwarded, captured) = upstream_to_downstream(TungsteniteMessage::Text(text)).unwrap();
        let AxumMessage::Text(text) = forwarded else {
            panic!("text expected")
        };
        assert_eq!(text.as_ptr(), captured.payload.as_ptr());
        assert_eq!(text.as_str(), "中文🙂");
    }

    #[test]
    fn protocol_versions_have_stable_evidence_labels() {
        assert_eq!(http_protocol_label(http::Version::HTTP_10), "http/1.0");
        assert_eq!(http_protocol_label(http::Version::HTTP_11), "http/1.1");
        assert_eq!(http_protocol_label(http::Version::HTTP_2), "http/2");
        assert_eq!(http_protocol_label(http::Version::HTTP_3), "http/3");
    }

    #[test]
    fn invalid_external_inference_ids_are_replaced_with_uuidv7() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-iorec-inference-id",
            http::HeaderValue::from_bytes(b"bad\tid").unwrap(),
        );
        let generated = Uuid::parse_str(&request_inference_id(&headers)).unwrap();
        assert_eq!(generated.get_version_num(), 7);

        headers.insert(
            "x-iorec-inference-id",
            http::HeaderValue::from_static("caller-inference"),
        );
        assert_eq!(request_inference_id(&headers), "caller-inference");
    }

    #[test]
    fn accepts_only_bounded_textual_claude_session_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-claude-code-session-id",
            http::HeaderValue::from_static("session-1"),
        );
        assert_eq!(request_session_id(&headers).as_deref(), Some("session-1"));

        headers.insert(
            "x-claude-code-session-id",
            http::HeaderValue::from_str(&"x".repeat(257)).unwrap(),
        );
        assert_eq!(request_session_id(&headers), None);
    }

    #[tokio::test]
    async fn proxy_rejects_non_loopback_listeners() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "proxy-listen", CapturePolicy::default()).unwrap();
        let result = start(
            ProxyConfig {
                listen: "0.0.0.0:0".parse().unwrap(),
                upstream: Url::parse("https://example.test").unwrap(),
            },
            store.clone(),
        )
        .await;
        assert!(result.is_err());
        store.shutdown().await.unwrap();
    }

    #[test]
    fn joins_upstream_prefix_and_redacts_query_values() {
        let target = target_url(
            &Url::parse("https://example.test/gateway").unwrap(),
            &"/v1/responses?api_key=secret&stream=true".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            target.as_str(),
            "https://example.test/gateway/v1/responses?api_key=secret&stream=true"
        );
        let safe = safe_url(&target, true).to_string();
        assert!(!safe.contains("secret"));
        assert!(safe.contains("api_key"));
    }

    #[test]
    fn avoids_duplicate_upstream_api_prefix() {
        let target = target_url(
            &Url::parse("https://example.test/v1").unwrap(),
            &"/v1/responses".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(target.as_str(), "https://example.test/v1/responses");
    }

    #[test]
    fn deduplicates_version_suffix_after_provider_prefix() {
        let target = target_url(
            &Url::parse("https://api.fireworks.ai/inference/v1").unwrap(),
            &"/v1/chat/completions?stream=true".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            target.as_str(),
            "https://api.fireworks.ai/inference/v1/chat/completions?stream=true"
        );

        let longest = target_url(
            &Url::parse("https://example.test/proxy/openai/v1").unwrap(),
            &"/openai/v1/responses".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            longest.as_str(),
            "https://example.test/proxy/openai/v1/responses"
        );

        let segment_boundary = target_url(
            &Url::parse("https://example.test/inference/v10").unwrap(),
            &"/v1/chat/completions".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            segment_boundary.as_str(),
            "https://example.test/inference/v10/v1/chat/completions"
        );
    }

    #[test]
    fn rejects_credential_bearing_or_ambiguous_upstream_bases() {
        assert!(validate_upstream_base(&Url::parse("https://example.test/v1").unwrap()).is_ok());
        assert!(
            validate_upstream_base(&Url::parse("https://user:secret@example.test/v1").unwrap())
                .is_err()
        );
        assert!(
            validate_upstream_base(&Url::parse("https://example.test/v1?key=secret").unwrap())
                .is_err()
        );
        assert!(validate_upstream_base(&Url::parse("file:///tmp/socket").unwrap()).is_err());
    }

    #[test]
    fn extracts_sse_usage_without_copying_content() {
        let summary = parse_sse_semantics(
            br#"{"type":"response.completed","response":{"id":"resp_1","model":"test","usage":{"input_tokens":4,"output_tokens":2}}}"#,
        );
        assert_eq!(summary["response_id"], "resp_1");
        assert_eq!(summary["input_tokens"], 4);
        assert!(summary.get("output").is_none());
    }

    #[test]
    fn extracts_anthropic_message_start_identity() {
        let summary = parse_sse_semantics(
            br#"{"type":"message_start","message":{"id":"msg_1","model":"claude-test","usage":{"input_tokens":4,"output_tokens":0}}}"#,
        );
        assert_eq!(summary["response_id"], "msg_1");
        assert_eq!(summary["model"], "claude-test");
        assert_eq!(summary["input_tokens"], 4);
    }

    #[test]
    fn normalized_metadata_is_bounded_and_query_cardinality_is_explicit() {
        let oversized = "sensitive".repeat(129);
        let normalized = normalized_metadata_string(&oversized);
        assert!(normalized.starts_with("[HASHED_METADATA sha256:"));

        let payload = json!({"response": {"id": oversized}}).to_string();
        let semantics = parse_sse_semantics(payload.as_bytes());
        assert!(
            semantics["response_id"]
                .as_str()
                .unwrap()
                .starts_with("[HASHED_METADATA sha256:")
        );

        let query = (0..MAX_QUERY_METADATA_KEYS + 2)
            .map(|index| format!("key{index}=value"))
            .collect::<Vec<_>>()
            .join("&");
        let uri: Uri = format!("/v1/responses?{query}").parse().unwrap();
        let safe = safe_uri(&uri);
        assert_eq!(safe["query_parameter_count"], MAX_QUERY_METADATA_KEYS + 2);
        assert_eq!(
            safe["query_keys"].as_array().unwrap().len(),
            MAX_QUERY_METADATA_KEYS
        );
        assert_eq!(safe["query_keys_truncated"], true);
    }

    #[test]
    fn summarizes_multimodal_dependencies_without_leaking_reference_values() {
        let payload = json!({
            "input": [
                {"type": "input_image", "image_url": "data:image/png;base64,aGVsbG8="},
                {"type": "input_image", "image_url": "https://private.test/a.png?token=secret"},
                {"type": "input_file", "file_id": "file-secret-id"},
                {"inlineData": {"mimeType": "audio/wav", "data": "aGVsbG8="}},
                {"fileData": {"mimeType": "application/pdf", "fileUri": "gs://private/secret.pdf"}}
            ]
        });
        let summary = summarize_payload_dependencies(&payload);
        assert_eq!(summary.embedded_parts, 2);
        assert_eq!(summary.unresolved_references, 3);
        assert_eq!(summary.unresolved_kinds.get("image-url"), Some(&1));
        assert_eq!(summary.unresolved_kinds.get("file-id"), Some(&1));
        assert_eq!(summary.unresolved_kinds.get("file-uri"), Some(&1));
        let safe = json!({
            "modalities": summary.modalities,
            "unresolved_kinds": summary.unresolved_kinds,
        })
        .to_string();
        assert!(!safe.contains("private.test"));
        assert!(!safe.contains("file-secret-id"));
        assert!(!safe.contains("gs://"));
    }

    #[test]
    fn strips_hop_by_hop_headers_without_stripping_auth() {
        let mut input = HeaderMap::new();
        input.insert(
            header::CONNECTION,
            "keep-alive, x-private-hop".parse().unwrap(),
        );
        input.insert("x-private-hop", "remove-me".parse().unwrap());
        input.insert("proxy-connection", "keep-alive".parse().unwrap());
        input.insert(header::AUTHORIZATION, "Bearer forwarded".parse().unwrap());
        let output = forwarding_headers(&input, true);
        assert!(!output.contains_key(header::CONNECTION));
        assert!(!output.contains_key("x-private-hop"));
        assert!(!output.contains_key("proxy-connection"));
        assert_eq!(output[header::AUTHORIZATION], "Bearer forwarded");
    }

    #[tokio::test]
    async fn unavailable_normalization_capacity_downgrades_semantics_without_body_loss() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create(
            temporary.path(),
            "normalization-budget",
            CapturePolicy::default(),
        )
        .unwrap();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
        let ids = EventIds {
            inference_id: Some("inference".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            ..EventIds::default()
        };
        pump_incoming_body(
            Body::from(r#"{"model":"test","input":"hello"}"#),
            sender,
            store.clone(),
            ids,
            "/v1/responses".to_owned(),
            Some("application/json".to_owned()),
            true,
            None,
        )
        .await;
        assert!(!receiver.recv().await.unwrap().unwrap().is_empty());
        store.shutdown().await.unwrap();

        let mut found = false;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.source == "proxy" && event.event == "logical_inference_request" {
                found = true;
                assert_eq!(
                    event
                        .normalized
                        .as_ref()
                        .and_then(|value| {
                            value.pointer("/summary/payload_dependencies/scan_inconclusive")
                        })
                        .and_then(Value::as_bool),
                    Some(true)
                );
            }
            Ok(())
        })
        .unwrap();
        assert!(found);
    }

    #[tokio::test]
    async fn non_model_request_does_not_create_logical_inference() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) = RunStore::create(
            temporary.path(),
            "non-model-request",
            CapturePolicy::default(),
        )
        .unwrap();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
        let ids = EventIds {
            inference_id: Some("transport-only".to_owned()),
            attempt_id: Some("attempt".to_owned()),
            ..EventIds::default()
        };
        pump_incoming_body(
            Body::from(r#"{"probe":true}"#),
            sender,
            store.clone(),
            ids,
            "/v1/models".to_owned(),
            Some("application/json".to_owned()),
            false,
            None,
        )
        .await;
        assert!(!receiver.recv().await.unwrap().unwrap().is_empty());
        store.shutdown().await.unwrap();

        let mut logical_requests = 0;
        for_each_event(&temporary.path().join("events.jsonl"), |event| {
            if event.source == "proxy" && event.event == "logical_inference_request" {
                logical_requests += 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(logical_requests, 0);
    }

    #[tokio::test]
    async fn sse_parser_stops_at_a_capture_sequence_gap() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, _) =
            RunStore::create(temporary.path(), "sse-gap", CapturePolicy::default()).unwrap();
        let (sender, receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
        sender
            .send((1, Bytes::from_static(b"data: first\n\n")))
            .await
            .unwrap();
        sender
            .send((3, Bytes::from_static(b"data: misleading\n\n")))
            .await
            .unwrap();
        drop(sender);
        let capture_failed = Arc::new(AtomicBool::new(false));
        let result = capture_response_stream(
            receiver,
            store.clone(),
            EventIds {
                inference_id: Some("inference".to_owned()),
                attempt_id: Some("attempt".to_owned()),
                ..EventIds::default()
            },
            "/v1/responses".to_owned(),
            Some("text/event-stream".to_owned()),
            true,
            Arc::clone(&capture_failed),
        )
        .await;
        assert!(result.sse_parse_failed);
        assert_eq!(result.sse_events, 1);
        assert!(capture_failed.load(Ordering::Acquire));
        store.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn empty_tail_after_sse_close_does_not_mask_later_data_or_upstream_error() {
        for scenario in ["eof", "more_data", "upstream_error"] {
            let temporary = tempfile::tempdir().unwrap();
            let (store, _) =
                RunStore::create(temporary.path(), "empty-tail", CapturePolicy::default()).unwrap();
            let (upstream, input) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(4);
            let response = reqwest::Response::from(http::Response::new(
                reqwest::Body::wrap_stream(ReceiverStream::new(input)),
            ));
            let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
            let pump = tokio::spawn(pump_upstream_body(
                response,
                sender,
                store.clone(),
                EventIds::default(),
                "/v1/chat/completions".into(),
                Some("text/event-stream".into()),
                true,
                StatusCode::OK,
            ));
            upstream
                .send(Ok(Bytes::from_static(b"data: [DONE]\n\n")))
                .await
                .unwrap();
            assert_eq!(receiver.recv().await.unwrap().unwrap(), "data: [DONE]\n\n");
            drop(receiver);
            upstream.send(Ok(Bytes::new())).await.unwrap();
            // A zero-byte frame is not proof of EOF. Leave the upstream open.
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(!pump.is_finished(), "{scenario}");
            match scenario {
                "more_data" => upstream
                    .send(Ok(Bytes::from_static(b"data: later\n\n")))
                    .await
                    .unwrap(),
                "upstream_error" => upstream
                    .send(Err(io::Error::other("fixture")))
                    .await
                    .unwrap(),
                _ => {}
            }
            drop(upstream);
            tokio::time::timeout(Duration::from_secs(2), pump)
                .await
                .unwrap()
                .unwrap();
            store.shutdown().await.unwrap();
            let mut terminals = Vec::new();
            for_each_event(&temporary.path().join("events.jsonl"), |event| {
                if event.event == "transport_attempt_finished" {
                    terminals.push(event);
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(terminals.len(), 1);
            let expected = match scenario {
                "eof" => TerminalState::Complete,
                "more_data" => TerminalState::Cancelled,
                _ => TerminalState::Error,
            };
            assert_eq!(terminals[0].terminal_state, Some(expected), "{scenario}");
        }
    }
}
