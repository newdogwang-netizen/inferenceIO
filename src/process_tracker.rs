use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    fs,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Serialize;
use serde_json::json;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::warn;

use crate::{egress::EndpointClassification, model::TerminalState, storage::RunStore};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_PROCESSES: usize = 65_536;
const MAX_PROCESS_MAP_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROCESS_NET_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROCESS_FDS: usize = 262_144;
const MAX_CGROUP_BYTES: usize = 64 * 1024;
const MAX_PROCESS_STATUS_BYTES: usize = 256 * 1024;
const MAX_REPORTED_RUNNING_PIDS: usize = 1_024;
const MAX_CONNECTIONS_PER_SCAN: usize = 262_144;
const MAX_NETWORK_GAPS_PER_SCAN: usize = 65_536;
const MAX_REPORTED_NETWORK_GAPS: usize = 10_000;
const TRACKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessKey {
    pid: u32,
    start_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    pid: u32,
    process_start_ticks: u64,
    inode: u64,
    protocol: String,
    remote_address: IpAddr,
    remote_port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct NetworkConnection {
    pid: u32,
    process_start_ticks: u64,
    inode: u64,
    protocol: String,
    local_address: IpAddr,
    local_port: u16,
    remote_address: IpAddr,
    remote_port: u16,
    state: String,
    traffic_class: String,
    classification_basis: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    egress_rule_ids: Vec<u32>,
}

impl NetworkConnection {
    fn key(&self) -> ConnectionKey {
        ConnectionKey {
            pid: self.pid,
            process_start_ticks: self.process_start_ticks,
            inode: self.inode,
            protocol: self.protocol.clone(),
            remote_address: self.remote_address,
            remote_port: self.remote_port,
        }
    }
}

struct ScanResult {
    processes: Vec<ProcessSnapshot>,
    connections: Vec<NetworkConnection>,
    network_gaps: Vec<NetworkScanGap>,
}

struct ConnectionScanResult {
    connections: Vec<NetworkConnection>,
    gaps: Vec<NetworkScanGap>,
}

struct ModelEndpoints {
    exact: HashSet<SocketAddr>,
    intercepted: bool,
}

impl ModelEndpoints {
    fn new(endpoints: impl IntoIterator<Item = SocketAddr>, intercepted: bool) -> Self {
        Self {
            exact: endpoints.into_iter().collect(),
            intercepted,
        }
    }
}

struct SocketInodeScan {
    inodes: HashSet<u64>,
    unreadable_entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
struct NetworkScanGap {
    pid: u32,
    process_start_ticks: u64,
    protocol: String,
    reason: String,
    occurrences: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NetworkScanGapKey {
    pid: u32,
    process_start_ticks: u64,
    protocol: String,
    reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkGapDisposition {
    AlreadyReported,
    Record,
    LimitReached,
    Omitted,
}

impl NetworkScanGap {
    fn key(&self) -> NetworkScanGapKey {
        NetworkScanGapKey {
            pid: self.pid,
            process_start_ticks: self.process_start_ticks,
            protocol: self.protocol.clone(),
            reason: self.reason.clone(),
        }
    }
}

struct ProcessIdentity {
    pid: u32,
    parent_pid: u32,
    start_ticks: u64,
    name: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessSnapshot {
    pid: u32,
    host_pid: u32,
    namespace_pid: Option<u32>,
    parent_pid: u32,
    start_ticks: u64,
    name: String,
    executable: Option<PathBuf>,
    pid_namespace: Option<String>,
    network_namespace: Option<String>,
    cgroup: Option<String>,
    container_id: Option<String>,
    tls_surfaces: Vec<String>,
}

impl ProcessSnapshot {
    fn key(&self) -> ProcessKey {
        ProcessKey {
            pid: self.pid,
            start_ticks: self.start_ticks,
        }
    }
}

pub struct ProcessTrackerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl ProcessTrackerHandle {
    pub async fn stop(mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Ok(result) = tokio::time::timeout(TRACKER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            result.map_err(|error| {
                io::Error::other(format!("process tracker task panicked: {error}"))
            })?
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process tracker did not stop before its shutdown deadline",
            ))
        }
    }
}

impl Drop for ProcessTrackerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[must_use]
pub fn start(
    root_pid: u32,
    recorder_endpoint: Option<SocketAddr>,
    model_upstream_endpoints: Vec<SocketAddr>,
    model_endpoints_intercepted: bool,
    configured_egress_endpoints: impl IntoIterator<Item = (SocketAddr, EndpointClassification)>,
    store: RunStore,
) -> ProcessTrackerHandle {
    let model_upstream_endpoints = Arc::new(ModelEndpoints::new(
        model_upstream_endpoints,
        model_endpoints_intercepted,
    ));
    let configured_egress_endpoints = Arc::new(configured_egress_endpoints.into_iter().collect());
    let (shutdown, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut known: HashMap<ProcessKey, ProcessSnapshot> = HashMap::new();
        let mut known_connections: HashMap<ConnectionKey, NetworkConnection> = HashMap::new();
        let mut reported_network_gaps: HashSet<NetworkScanGapKey> = HashSet::new();
        let mut network_gap_tracking_exhausted = false;
        let mut unreported_network_gap_observations = 0_u64;
        let mut scan_failures = 0_u64;
        let mut reported_scan_failures: HashSet<(String, String)> = HashSet::new();
        let mut interval = tokio::time::interval(POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = poll(
                        root_pid,
                        recorder_endpoint,
                        Arc::clone(&model_upstream_endpoints),
                        Arc::clone(&configured_egress_endpoints),
                        &store,
                        &mut known,
                        &mut known_connections,
                        &mut reported_network_gaps,
                        &mut network_gap_tracking_exhausted,
                        &mut unreported_network_gap_observations,
                    ).await {
                        record_scan_failure(
                            &store,
                            root_pid,
                            "periodic",
                            &error,
                            &mut scan_failures,
                            &mut reported_scan_failures,
                        ).await;
                    }
                }
                _ = &mut stopped => break,
            }
        }
        if let Err(error) = poll(
            root_pid,
            recorder_endpoint,
            Arc::clone(&model_upstream_endpoints),
            Arc::clone(&configured_egress_endpoints),
            &store,
            &mut known,
            &mut known_connections,
            &mut reported_network_gaps,
            &mut network_gap_tracking_exhausted,
            &mut unreported_network_gap_observations,
        )
        .await
        {
            record_scan_failure(
                &store,
                root_pid,
                "final",
                &error,
                &mut scan_failures,
                &mut reported_scan_failures,
            )
            .await;
        }
        let (still_running, still_running_count) =
            bounded_sorted_pids(known.values().map(|process| process.pid));
        let open_connections = u64::try_from(known_connections.len()).unwrap_or(u64::MAX);
        if still_running_count > 0 || open_connections > 0 {
            store.note_capture_drop();
        }
        let mut event = store.event("process", "process_tracker_stopped");
        event.terminal_state = Some(if still_running_count > 0 || open_connections > 0 {
            TerminalState::Incomplete
        } else {
            TerminalState::Complete
        });
        event.normalized = Some(json!({
            "root_pid": root_pid,
            "still_running": still_running,
            "still_running_count": still_running_count,
            "still_running_truncated": still_running_count > u64::try_from(MAX_REPORTED_RUNNING_PIDS).unwrap_or(u64::MAX),
            "open_connections": open_connections,
            "poll_interval_ms": POLL_INTERVAL.as_millis(),
            "scan_failures": scan_failures,
            "network_gap_tracking_exhausted": network_gap_tracking_exhausted,
            "unreported_network_gap_observations": unreported_network_gap_observations,
        }));
        store
            .append(event)
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    });
    ProcessTrackerHandle {
        shutdown: Some(shutdown),
        task,
    }
}

fn bounded_sorted_pids(pids: impl IntoIterator<Item = u32>) -> (Vec<u32>, u64) {
    let mut smallest = BinaryHeap::with_capacity(MAX_REPORTED_RUNNING_PIDS);
    let mut count = 0_u64;
    for pid in pids {
        count = count.saturating_add(1);
        if smallest.len() < MAX_REPORTED_RUNNING_PIDS {
            smallest.push(pid);
        } else if smallest.peek().is_some_and(|largest| pid < *largest) {
            smallest.pop();
            smallest.push(pid);
        }
    }
    let mut pids = smallest.into_vec();
    pids.sort_unstable();
    (pids, count)
}

async fn record_scan_failure(
    store: &RunStore,
    root_pid: u32,
    phase: &str,
    error: &io::Error,
    total: &mut u64,
    reported: &mut HashSet<(String, String)>,
) {
    *total = total.saturating_add(1);
    store.note_capture_drop();
    let error_kind = error_kind_name(error.kind()).to_owned();
    if reported.insert((phase.to_owned(), error_kind.clone())) {
        let mut event = store.event("process", "process_scan_failed");
        event.normalized = Some(json!({
            "root_pid": root_pid,
            "phase": phase,
            "error_kind": error_kind,
            "failures_total": *total,
        }));
        if let Err(append_error) = store.append(event).await {
            warn!(
                error_kind = append_error.category(),
                "could not persist process scan failure evidence"
            );
        }
    }
    warn!(
        error_kind = ?error.kind(),
        phase,
        failures_total = *total,
        "process tree poll failed"
    );
}

async fn poll(
    root_pid: u32,
    recorder_endpoint: Option<SocketAddr>,
    model_upstream_endpoints: Arc<ModelEndpoints>,
    configured_egress_endpoints: Arc<HashMap<SocketAddr, EndpointClassification>>,
    store: &RunStore,
    known: &mut HashMap<ProcessKey, ProcessSnapshot>,
    known_connections: &mut HashMap<ConnectionKey, NetworkConnection>,
    reported_network_gaps: &mut HashSet<NetworkScanGapKey>,
    network_gap_tracking_exhausted: &mut bool,
    unreported_network_gap_observations: &mut u64,
) -> io::Result<()> {
    let known_keys: HashSet<ProcessKey> = known.keys().cloned().collect();
    let scan = tokio::task::spawn_blocking(move || {
        scan_descendants(
            root_pid,
            &known_keys,
            recorder_endpoint,
            &model_upstream_endpoints,
            &configured_egress_endpoints,
        )
    })
    .await
    .map_err(|error| io::Error::other(format!("process scan task panicked: {error}")))??;
    let ScanResult {
        processes,
        connections,
        network_gaps,
    } = scan;
    let current: HashMap<ProcessKey, ProcessSnapshot> = processes
        .into_iter()
        .map(|snapshot| (snapshot.key(), snapshot))
        .collect();
    let current_connections: HashMap<ConnectionKey, NetworkConnection> = connections
        .into_iter()
        .map(|connection| (connection.key(), connection))
        .collect();

    for gap in network_gaps {
        match remember_network_gap(
            reported_network_gaps,
            gap.key(),
            MAX_REPORTED_NETWORK_GAPS,
            network_gap_tracking_exhausted,
            unreported_network_gap_observations,
        ) {
            NetworkGapDisposition::Record => {
                let mut event = store.event("process", "process_network_scan_gap");
                event.normalized = Some(serde_json::to_value(gap).map_err(io::Error::other)?);
                store
                    .append(event)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            NetworkGapDisposition::LimitReached => {
                store.note_capture_drop();
                let mut event = store.event("process", "process_network_gap_limit_reached");
                event.terminal_state = Some(TerminalState::Incomplete);
                event.normalized = Some(json!({
                    "reported_gap_limit": MAX_REPORTED_NETWORK_GAPS,
                    "unreported_network_gap_observations": *unreported_network_gap_observations,
                }));
                store
                    .append(event)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            NetworkGapDisposition::AlreadyReported | NetworkGapDisposition::Omitted => {}
        }
    }

    for (key, snapshot) in &current {
        if let Some(previous) = known.get(key) {
            if process_identity_changed(previous, snapshot) {
                let mut event = store.event("process", "process_exec_observed");
                event.normalized = Some(json!({
                    "pid": snapshot.pid,
                    "start_ticks": snapshot.start_ticks,
                    "previous_name": previous.name,
                    "name": snapshot.name,
                    "previous_executable": previous.executable,
                    "executable": snapshot.executable,
                }));
                store
                    .append(event)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            if previous.tls_surfaces != snapshot.tls_surfaces {
                let (added, removed) = tls_surface_delta(previous, snapshot);
                let mut event = store.event("process", "process_tls_surfaces_changed");
                event.normalized = Some(json!({
                    "pid": snapshot.pid,
                    "start_ticks": snapshot.start_ticks,
                    "tls_surfaces": snapshot.tls_surfaces,
                    "added": added,
                    "removed": removed,
                }));
                store
                    .append(event)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
        } else {
            let mut event = store.event("process", "process_observed");
            event.normalized = Some(serde_json::to_value(snapshot).map_err(io::Error::other)?);
            store
                .append(event)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
    }
    for (key, snapshot) in known.iter() {
        if !current.contains_key(key) {
            let mut event = store.event("process", "process_exited");
            event.terminal_state = Some(TerminalState::Complete);
            event.normalized = Some(json!({
                "pid": snapshot.pid,
                "parent_pid": snapshot.parent_pid,
                "start_ticks": snapshot.start_ticks,
            }));
            store
                .append(event)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
    }
    for (key, connection) in &current_connections {
        if !known_connections.contains_key(key) {
            let mut event = store.event("process", "network_connection_observed");
            event.ids.connection_id = Some(connection_id(key));
            event.confidence = Some(1.0);
            event.evidence = vec!["proc_socket_inode".to_owned()];
            event.normalized = Some(serde_json::to_value(connection).map_err(io::Error::other)?);
            store
                .append(event)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
    }
    for (key, connection) in known_connections.iter() {
        if !current_connections.contains_key(key) {
            let mut event = store.event("process", "network_connection_closed");
            event.ids.connection_id = Some(connection_id(key));
            event.terminal_state = Some(TerminalState::Complete);
            event.normalized = Some(json!({
                "pid": connection.pid,
                "inode": connection.inode,
                "protocol": connection.protocol,
                "remote_address": connection.remote_address,
                "remote_port": connection.remote_port,
            }));
            store
                .append(event)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
    }
    *known = current;
    *known_connections = current_connections;
    Ok(())
}

fn process_identity_changed(previous: &ProcessSnapshot, current: &ProcessSnapshot) -> bool {
    previous.name != current.name || previous.executable != current.executable
}

fn remember_network_gap(
    reported: &mut HashSet<NetworkScanGapKey>,
    key: NetworkScanGapKey,
    limit: usize,
    exhausted: &mut bool,
    omitted_observations: &mut u64,
) -> NetworkGapDisposition {
    if reported.contains(&key) {
        return NetworkGapDisposition::AlreadyReported;
    }
    if reported.len() < limit {
        reported.insert(key);
        return NetworkGapDisposition::Record;
    }
    *omitted_observations = omitted_observations.saturating_add(1);
    if *exhausted {
        NetworkGapDisposition::Omitted
    } else {
        *exhausted = true;
        NetworkGapDisposition::LimitReached
    }
}

fn tls_surface_delta(
    previous: &ProcessSnapshot,
    current: &ProcessSnapshot,
) -> (Vec<String>, Vec<String>) {
    let added = current
        .tls_surfaces
        .iter()
        .filter(|surface| !previous.tls_surfaces.contains(surface))
        .cloned()
        .collect();
    let removed = previous
        .tls_surfaces
        .iter()
        .filter(|surface| !current.tls_surfaces.contains(surface))
        .cloned()
        .collect();
    (added, removed)
}

fn scan_descendants(
    root_pid: u32,
    known: &HashSet<ProcessKey>,
    recorder_endpoint: Option<SocketAddr>,
    model_upstream_endpoints: &ModelEndpoints,
    configured_egress_endpoints: &HashMap<SocketAddr, EndpointClassification>,
) -> io::Result<ScanResult> {
    let mut all = HashMap::new();
    let mut process_entries = 0_usize;
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        process_entries = process_entries.saturating_add(1);
        if process_entries > MAX_PROCESSES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process scan exceeded its PID safety limit",
            ));
        }
        if let Ok(process) = read_process_identity(pid) {
            all.insert(pid, process);
        }
    }

    let mut target_pids = HashSet::from([root_pid]);
    for key in known {
        if all
            .get(&key.pid)
            .is_some_and(|process| process.start_ticks == key.start_ticks)
        {
            target_pids.insert(key.pid);
        }
    }
    loop {
        let before = target_pids.len();
        for process in all.values() {
            if target_pids.contains(&process.parent_pid) {
                target_pids.insert(process.pid);
            }
        }
        if target_pids.len() == before {
            break;
        }
    }
    let processes: Vec<ProcessSnapshot> = target_pids
        .into_iter()
        .filter_map(|pid| all.remove(&pid))
        .filter_map(|identity| enrich_process(identity).ok())
        .collect();
    let mut connections = Vec::new();
    let mut network_gaps = Vec::new();
    for process in &processes {
        let scan = read_connections(
            process,
            recorder_endpoint,
            model_upstream_endpoints,
            configured_egress_endpoints,
        )?;
        if connections.len().saturating_add(scan.connections.len()) > MAX_CONNECTIONS_PER_SCAN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process scan exceeded its connection safety limit",
            ));
        }
        if network_gaps.len().saturating_add(scan.gaps.len()) > MAX_NETWORK_GAPS_PER_SCAN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process scan exceeded its network-gap safety limit",
            ));
        }
        connections.extend(scan.connections);
        network_gaps.extend(scan.gaps);
    }
    Ok(ScanResult {
        processes,
        connections,
        network_gaps,
    })
}

fn read_connections(
    process: &ProcessSnapshot,
    recorder_endpoint: Option<SocketAddr>,
    model_upstream_endpoints: &ModelEndpoints,
    configured_egress_endpoints: &HashMap<SocketAddr, EndpointClassification>,
) -> io::Result<ConnectionScanResult> {
    let root = PathBuf::from(format!("/proc/{}", process.pid));
    let inode_scan = match socket_inodes(&root.join("fd")) {
        Ok(scan) => scan,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ConnectionScanResult {
                connections: Vec::new(),
                gaps: Vec::new(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
        Err(error) => {
            return Ok(ConnectionScanResult {
                connections: Vec::new(),
                gaps: vec![network_gap(
                    process,
                    "fd",
                    "fd_directory_read_failed",
                    1,
                    Some(&error),
                )],
            });
        }
    };
    let mut gaps = Vec::new();
    if inode_scan.unreadable_entries > 0 {
        gaps.push(network_gap(
            process,
            "fd",
            "fd_entries_unreadable",
            inode_scan.unreadable_entries,
            None,
        ));
    }
    if inode_scan.inodes.is_empty() {
        return Ok(ConnectionScanResult {
            connections: Vec::new(),
            gaps,
        });
    }
    let mut connections = Vec::new();
    for (table, protocol) in [
        ("tcp", "tcp"),
        ("tcp6", "tcp6"),
        ("udp", "udp"),
        ("udp6", "udp6"),
    ] {
        let text = match read_text_limited(&root.join("net").join(table), MAX_PROCESS_NET_BYTES) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                gaps.push(network_gap(
                    process,
                    protocol,
                    "socket_table_read_failed",
                    1,
                    Some(&error),
                ));
                continue;
            }
        };
        let (mut parsed, malformed_rows, omitted_rows) = parse_socket_table(
            &text,
            protocol,
            process,
            &inode_scan.inodes,
            recorder_endpoint,
            model_upstream_endpoints,
            configured_egress_endpoints,
        );
        if connections.len().saturating_add(parsed.len()) > MAX_CONNECTIONS_PER_SCAN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process connection scan exceeded its safety limit",
            ));
        }
        connections.append(&mut parsed);
        if malformed_rows > 0 {
            gaps.push(network_gap(
                process,
                protocol,
                "socket_rows_unparsed",
                malformed_rows,
                None,
            ));
        }
        if omitted_rows > 0 {
            gaps.push(network_gap(
                process,
                protocol,
                "socket_rows_omitted_at_connection_limit",
                omitted_rows,
                None,
            ));
        }
    }
    Ok(ConnectionScanResult { connections, gaps })
}

fn network_gap(
    process: &ProcessSnapshot,
    protocol: &str,
    reason: &str,
    occurrences: u64,
    error: Option<&io::Error>,
) -> NetworkScanGap {
    let reason = error.map_or_else(
        || reason.to_owned(),
        |error| format!("{reason}:{}", error_kind_name(error.kind())),
    );
    NetworkScanGap {
        pid: process.pid,
        process_start_ticks: process.start_ticks,
        protocol: protocol.to_owned(),
        reason,
        occurrences,
    }
}

const fn error_kind_name(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::Interrupted => "interrupted",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::OutOfMemory => "out_of_memory",
        _ => "other",
    }
}

fn socket_inodes(path: &Path) -> io::Result<SocketInodeScan> {
    let entries = fs::read_dir(path)?;
    let mut inodes = HashSet::new();
    let mut unreadable_entries = 0_u64;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PROCESS_FDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process fd scan exceeded its safety limit",
            ));
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                unreadable_entries = unreadable_entries.saturating_add(1);
                continue;
            }
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                unreadable_entries = unreadable_entries.saturating_add(1);
                continue;
            }
        };
        let inode = {
            let text = target.to_string_lossy();
            text.strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse().ok())
        };
        if let Some(inode) = inode {
            inodes.insert(inode);
        }
    }
    Ok(SocketInodeScan {
        inodes,
        unreadable_entries,
    })
}

fn parse_socket_table(
    text: &str,
    protocol: &str,
    process: &ProcessSnapshot,
    inodes: &HashSet<u64>,
    recorder_endpoint: Option<SocketAddr>,
    model_upstream_endpoints: &ModelEndpoints,
    configured_egress_endpoints: &HashMap<SocketAddr, EndpointClassification>,
) -> (Vec<NetworkConnection>, u64, u64) {
    let mut connections = Vec::new();
    let mut malformed_rows = 0_u64;
    let mut omitted_rows = 0_u64;
    for line in text.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let Some(mut connection) = parse_socket_row(line, protocol) else {
            malformed_rows = malformed_rows.saturating_add(1);
            continue;
        };
        if connection.remote_port == 0 || !inodes.contains(&connection.inode) {
            continue;
        }
        if connections.len() >= MAX_CONNECTIONS_PER_SCAN {
            omitted_rows = omitted_rows.saturating_add(1);
            continue;
        }
        connection.pid = process.pid;
        connection.process_start_ticks = process.start_ticks;
        let classification = classify_egress(
            &connection,
            recorder_endpoint,
            model_upstream_endpoints,
            configured_egress_endpoints,
        );
        classification
            .traffic_class
            .clone_into(&mut connection.traffic_class);
        classification
            .basis
            .clone_into(&mut connection.classification_basis);
        connection
            .egress_rule_ids
            .extend_from_slice(classification.rule_ids);
        connections.push(connection);
    }
    (connections, malformed_rows, omitted_rows)
}

fn parse_socket_row(line: &str, protocol: &str) -> Option<NetworkConnection> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (local_address, local_port) = parse_proc_endpoint(fields.get(1)?)?;
    let (remote_address, remote_port) = parse_proc_endpoint(fields.get(2)?)?;
    Some(NetworkConnection {
        pid: 0,
        process_start_ticks: 0,
        inode: fields.get(9)?.parse().ok()?,
        protocol: protocol.to_owned(),
        local_address,
        local_port,
        remote_address,
        remote_port,
        state: (*fields.get(3)?).to_owned(),
        traffic_class: "unknown".to_owned(),
        classification_basis: "unclassified".to_owned(),
        egress_rule_ids: Vec::new(),
    })
}

fn parse_proc_endpoint(value: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = match address.len() {
        8 => {
            let number = u32::from_str_radix(address, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(number.to_le_bytes()))
        }
        32 => {
            let mut bytes = [0_u8; 16];
            for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
                let chunk = std::str::from_utf8(chunk).ok()?;
                let number = u32::from_str_radix(chunk, 16).ok()?;
                bytes[index * 4..index * 4 + 4].copy_from_slice(&number.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((address, port))
}

struct TrafficClassification<'a> {
    traffic_class: &'static str,
    basis: &'static str,
    rule_ids: &'a [u32],
}

fn classify_egress<'a>(
    connection: &NetworkConnection,
    recorder_endpoint: Option<SocketAddr>,
    model_upstream_endpoints: &ModelEndpoints,
    configured_egress_endpoints: &'a HashMap<SocketAddr, EndpointClassification>,
) -> TrafficClassification<'a> {
    let remote = SocketAddr::new(connection.remote_address, connection.remote_port);
    if recorder_endpoint == Some(remote) {
        TrafficClassification {
            traffic_class: "model_recorder",
            basis: "exact_recorder_socket",
            rule_ids: &[],
        }
    } else if model_upstream_endpoints.exact.contains(&remote) {
        TrafficClassification {
            traffic_class: if model_upstream_endpoints.intercepted {
                "model_recorder"
            } else {
                "model_bypass"
            },
            basis: if model_upstream_endpoints.intercepted {
                "transparent_task_netns_exact_socket"
            } else {
                "configured_model_launch_time_dns"
            },
            rule_ids: &[],
        }
    } else if let Some(classification) = configured_egress_endpoints.get(&remote) {
        TrafficClassification {
            traffic_class: classification.class.as_str(),
            basis: "configured_egress_launch_time_dns",
            rule_ids: &classification.rule_ids,
        }
    } else if connection.remote_address.is_loopback() {
        TrafficClassification {
            traffic_class: "local",
            basis: "loopback_address",
            rule_ids: &[],
        }
    } else {
        TrafficClassification {
            traffic_class: "unknown_external",
            basis: "no_exact_rule_match",
            rule_ids: &[],
        }
    }
}

fn connection_id(key: &ConnectionKey) -> String {
    format!(
        "proc-{}-{}-{}-{}",
        key.pid, key.process_start_ticks, key.inode, key.protocol
    )
}

#[cfg(test)]
fn read_process(pid: u32) -> io::Result<ProcessSnapshot> {
    enrich_process(read_process_identity(pid)?)
}

fn read_process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = read_text_limited(&root.join("stat"), 64 * 1024)?;
    let close = stat.rfind(')').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "process stat has no name end")
    })?;
    let name = stat
        .get(stat.find('(').unwrap_or(0) + 1..close)
        .unwrap_or_default()
        .to_owned();
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let parent_pid = parse_stat_field(&fields, 1, "parent PID")?;
    let start_ticks = parse_stat_field(&fields, 19, "start ticks")?;
    Ok(ProcessIdentity {
        pid,
        parent_pid,
        start_ticks,
        name,
    })
}

fn enrich_process(identity: ProcessIdentity) -> io::Result<ProcessSnapshot> {
    let root = PathBuf::from(format!("/proc/{}", identity.pid));
    let executable = fs::read_link(root.join("exe")).ok();
    let namespace_pid = read_text_limited(&root.join("status"), MAX_PROCESS_STATUS_BYTES)
        .ok()
        .and_then(|status| namespace_pid_from_status(&status));
    let cgroup_text = read_text_limited(&root.join("cgroup"), MAX_CGROUP_BYTES).ok();
    let cgroup = cgroup_text
        .as_deref()
        .and_then(|text| text.lines().next().map(str::to_owned));
    let container_id = cgroup_text.as_deref().and_then(container_id_from_cgroup);
    let mut tls_surfaces = match read_text_limited(&root.join("maps"), MAX_PROCESS_MAP_BYTES) {
        Ok(maps) => detect_tls_surfaces(&maps),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(error),
        Err(error) => vec![format!("unknown-proc-maps:{}", error.kind())],
    };
    tls_surfaces.sort();
    tls_surfaces.dedup();
    Ok(ProcessSnapshot {
        pid: identity.pid,
        host_pid: identity.pid,
        namespace_pid,
        parent_pid: identity.parent_pid,
        start_ticks: identity.start_ticks,
        name: identity.name,
        executable,
        pid_namespace: read_link_string(&root.join("ns/pid")),
        network_namespace: read_link_string(&root.join("ns/net")),
        cgroup,
        container_id,
        tls_surfaces,
    })
}

fn namespace_pid_from_status(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_ascii_whitespace()
        .next_back()?
        .parse()
        .ok()
}

fn container_id_from_cgroup(cgroup: &str) -> Option<String> {
    let bytes = cgroup.as_bytes();
    for (start, window) in bytes.windows(64).enumerate() {
        if window.iter().all(u8::is_ascii_hexdigit) {
            let before_is_hex = start > 0 && bytes[start - 1].is_ascii_hexdigit();
            let after = start + 64;
            let after_is_hex = after < bytes.len() && bytes[after].is_ascii_hexdigit();
            if !before_is_hex && !after_is_hex {
                return std::str::from_utf8(window)
                    .ok()
                    .map(str::to_ascii_lowercase);
            }
        }
    }
    None
}

fn read_text_limited(path: &Path, limit: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("proc file exceeds its {limit}-byte safety limit"),
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn parse_stat_field<T: std::str::FromStr>(
    fields: &[&str],
    index: usize,
    name: &str,
) -> io::Result<T> {
    fields
        .get(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {name}")))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid {name}")))
}

fn read_link_string(path: &Path) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|target| target.to_string_lossy().into_owned())
}

fn detect_tls_surfaces(maps: &str) -> Vec<String> {
    let lowercase = maps.to_ascii_lowercase();
    let mut surfaces = Vec::new();
    if lowercase.contains("libssl.so") || lowercase.contains("libcrypto.so") {
        surfaces.push("openssl-dynamic".to_owned());
    }
    if lowercase.contains("boringssl") {
        surfaces.push("boringssl-dynamic".to_owned());
    }
    if lowercase.contains("libgnutls") {
        surfaces.push("gnutls-dynamic".to_owned());
    }
    if lowercase.contains("libnss3") {
        surfaces.push("nss-dynamic".to_owned());
    }
    surfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_endpoints(endpoints: &[&str], intercepted: bool) -> ModelEndpoints {
        ModelEndpoints::new(
            endpoints
                .iter()
                .map(|endpoint| endpoint.parse::<SocketAddr>().unwrap()),
            intercepted,
        )
    }

    #[test]
    fn stopped_process_pid_sample_is_sorted_bounded_and_counted() {
        let total = MAX_REPORTED_RUNNING_PIDS + 37;
        let (pids, count) =
            bounded_sorted_pids((0..total).rev().map(|pid| u32::try_from(pid).unwrap()));
        assert_eq!(pids.len(), MAX_REPORTED_RUNNING_PIDS);
        assert_eq!(pids.first(), Some(&0));
        assert_eq!(
            pids.last(),
            Some(&u32::try_from(MAX_REPORTED_RUNNING_PIDS - 1).unwrap())
        );
        assert_eq!(count, u64::try_from(total).unwrap());
    }

    #[test]
    fn reads_current_process_without_command_line() {
        let process = read_process(std::process::id()).unwrap();
        assert_eq!(process.pid, std::process::id());
        assert!(process.start_ticks > 0);
        let encoded = serde_json::to_string(&process).unwrap();
        assert!(!encoded.contains("cmdline"));
    }

    #[test]
    fn recognizes_dynamic_tls_libraries() {
        let surfaces =
            detect_tls_surfaces("7f r-x /usr/lib/libssl.so.3\n8f r-x /usr/lib/libcrypto.so.3\n");
        assert_eq!(surfaces, vec!["openssl-dynamic"]);
    }

    #[test]
    fn reports_tls_libraries_loaded_after_process_discovery() {
        let base = ProcessSnapshot {
            pid: 42,
            host_pid: 42,
            namespace_pid: None,
            parent_pid: 1,
            start_ticks: 7,
            name: "agent".to_owned(),
            executable: None,
            pid_namespace: None,
            network_namespace: None,
            cgroup: None,
            container_id: None,
            tls_surfaces: vec!["nss-dynamic".to_owned()],
        };
        let mut changed = base.clone();
        changed.tls_surfaces = vec!["openssl-dynamic".to_owned()];
        let (added, removed) = tls_surface_delta(&base, &changed);
        assert_eq!(added, vec!["openssl-dynamic"]);
        assert_eq!(removed, vec!["nss-dynamic"]);
    }

    #[test]
    fn recognizes_exec_without_treating_the_reused_pid_as_a_new_process() {
        let previous = ProcessSnapshot {
            pid: 42,
            host_pid: 42,
            namespace_pid: None,
            parent_pid: 1,
            start_ticks: 7,
            name: "sh".to_owned(),
            executable: Some(PathBuf::from("/bin/sh")),
            pid_namespace: None,
            network_namespace: None,
            cgroup: None,
            container_id: None,
            tls_surfaces: Vec::new(),
        };
        let mut current = previous.clone();
        current.name = "agent".to_owned();
        current.executable = Some(PathBuf::from("/usr/bin/agent"));
        assert_eq!(previous.key(), current.key());
        assert!(process_identity_changed(&previous, &current));
        assert!(!process_identity_changed(&current, &current));
    }

    #[test]
    fn extracts_namespace_pid_and_full_container_id_conservatively() {
        assert_eq!(
            namespace_pid_from_status("Name:\ttest\nNSpid:\t1234\t42\n"),
            Some(42)
        );
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            container_id_from_cgroup(&format!("0::/kubepods.slice/cri-containerd-{id}.scope\n"))
                .as_deref(),
            Some(id)
        );
        assert_eq!(container_id_from_cgroup("0::/docker/0123456789ab\n"), None);
    }

    #[test]
    fn parses_proc_ipv4_and_classifies_the_recorder_endpoint() {
        let row = "0: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 1000 0 4242 1";
        let mut connection = parse_socket_row(row, "tcp").unwrap();
        assert_eq!(
            connection.local_address,
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(connection.local_port, 50_000);
        assert_eq!(connection.remote_port, 8080);
        assert_eq!(connection.inode, 4242);
        connection.pid = 1;
        assert_eq!(
            classify_egress(
                &connection,
                Some("127.0.0.1:8080".parse().unwrap()),
                &model_endpoints(&[], false),
                &HashMap::new(),
            )
            .traffic_class,
            "model_recorder"
        );
        assert_eq!(
            classify_egress(
                &connection,
                None,
                &model_endpoints(&["127.0.0.1:8080"], false),
                &HashMap::new(),
            )
            .traffic_class,
            "model_bypass"
        );
        let empty_egress = HashMap::new();
        let intercepted = classify_egress(
            &connection,
            None,
            &model_endpoints(&["127.0.0.1:8080"], true),
            &empty_egress,
        );
        assert_eq!(intercepted.traffic_class, "model_recorder");
        assert_eq!(intercepted.basis, "transparent_task_netns_exact_socket");

        connection.remote_address = "10.0.2.2".parse().unwrap();
        assert_eq!(
            classify_egress(
                &connection,
                Some("10.0.2.2:8080".parse().unwrap()),
                &model_endpoints(&[], false),
                &HashMap::new(),
            )
            .traffic_class,
            "model_recorder"
        );
        connection.remote_address = "10.0.2.3".parse().unwrap();
        let configured = HashMap::from([(
            "10.0.2.3:8080".parse().unwrap(),
            EndpointClassification {
                class: crate::egress::EgressClass::Auth,
                rule_ids: vec![7],
            },
        )]);
        let classification = classify_egress(
            &connection,
            Some("10.0.2.2:8080".parse().unwrap()),
            &model_endpoints(&[], false),
            &configured,
        );
        assert_eq!(classification.traffic_class, "auth");
        assert_eq!(classification.basis, "configured_egress_launch_time_dns");
        assert_eq!(classification.rule_ids, &[7]);

        connection.remote_address = "10.0.2.4".parse().unwrap();
        assert_eq!(
            classify_egress(
                &connection,
                Some("10.0.2.2:8080".parse().unwrap()),
                &model_endpoints(&[], false),
                &configured,
            )
            .traffic_class,
            "unknown_external"
        );
    }

    #[test]
    fn malformed_socket_rows_become_a_counted_gap_without_raw_contents() {
        let process = ProcessSnapshot {
            pid: 42,
            host_pid: 42,
            namespace_pid: None,
            parent_pid: 1,
            start_ticks: 7,
            name: "agent".to_owned(),
            executable: None,
            pid_namespace: None,
            network_namespace: None,
            cgroup: None,
            container_id: None,
            tls_surfaces: Vec::new(),
        };
        let row = "0: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 1000 0 4242 1";
        let table = format!("header\n{row}\ncredential-shaped-canary\n");
        let (connections, malformed, omitted) = parse_socket_table(
            &table,
            "tcp",
            &process,
            &HashSet::from([4242]),
            Some("127.0.0.1:8080".parse().unwrap()),
            &model_endpoints(&[], false),
            &HashMap::new(),
        );
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].traffic_class, "model_recorder");
        assert_eq!(malformed, 1);
        assert_eq!(omitted, 0);
        let gap = network_gap(&process, "tcp", "socket_rows_unparsed", malformed, None);
        let encoded = serde_json::to_string(&gap).unwrap();
        assert!(encoded.contains("socket_rows_unparsed"));
        assert!(!encoded.contains("credential-shaped-canary"));
    }

    #[test]
    fn network_gap_history_is_bounded_and_reports_exhaustion_once() {
        let gap_key = |pid| NetworkScanGapKey {
            pid,
            process_start_ticks: 7,
            protocol: "tcp".to_owned(),
            reason: "socket_rows_unparsed".to_owned(),
        };
        let mut reported = HashSet::new();
        let mut exhausted = false;
        let mut omitted = 0;

        assert_eq!(
            remember_network_gap(&mut reported, gap_key(1), 1, &mut exhausted, &mut omitted,),
            NetworkGapDisposition::Record
        );
        assert_eq!(
            remember_network_gap(&mut reported, gap_key(1), 1, &mut exhausted, &mut omitted,),
            NetworkGapDisposition::AlreadyReported
        );
        assert_eq!(
            remember_network_gap(&mut reported, gap_key(2), 1, &mut exhausted, &mut omitted,),
            NetworkGapDisposition::LimitReached
        );
        assert_eq!(
            remember_network_gap(&mut reported, gap_key(3), 1, &mut exhausted, &mut omitted,),
            NetworkGapDisposition::Omitted
        );
        assert_eq!(reported.len(), 1);
        assert!(exhausted);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn parses_proc_ipv6_word_endianness() {
        let (address, port) = parse_proc_endpoint("00000000000000000000000001000000:01BB").unwrap();
        assert_eq!(address, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }
}
