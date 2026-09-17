use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::ValueEnum;
use nix::{
    errno::Errno,
    sys::signal::{SigSet, SigmaskHow, Signal, killpg, pthread_sigmask},
    unistd::{Pid, getpgrp, isatty, tcgetpgrp, tcsetpgrp},
};
use serde_json::{Value, json};
use tokio::{process::Command, signal::unix::SignalKind};
use tracing::warn;
use url::Url;
use uuid::Uuid;

use crate::{
    adapter::{AdapterPlan, AdapterSelection, prepare as prepare_adapter},
    adapter_sdk::{
        AdapterHost, ConfigureContext, CorrelateContext, CorrelationCandidate, DetectContext,
        ParsedEvent, ValidatedConfiguration,
    },
    audit,
    cgroup::{TaskCgroup, TaskCgroupReport},
    collector::{self, CollectorHandle},
    correlation,
    crypto::EncryptionKey,
    discovery::discover_command,
    doctor,
    egress::{self, EgressRuleSpec},
    inspect::finalize_manifest,
    manifest::{Manifest, RUN_KEY_DERIVATION_V1, write_atomic_authenticated},
    model::{EventEnvelope, TerminalState},
    pcap::{self, PcapHandle},
    policy::CapturePolicy,
    probe_helper::{self, ProbeHelperHandle},
    probe_plan::{ProbePlan, ProbePlannerConfig},
    probe_policy::{ProbeHelperSelection, inspect_explicit_helper},
    process_tracker::{self, ProcessTrackerHandle},
    proxy::{
        ProxyConfig, ProxyHandle, start as start_proxy,
        start_http2_prior_knowledge as start_http2_proxy,
        start_http2_prior_knowledge_with_key_log as start_http2_proxy_with_key_log,
        start_transparent_tls, start_with_key_log as start_proxy_with_key_log,
    },
    runtime_injection::{NodeInjection, PythonInjection},
    session::SessionReader,
    storage::{RunStore, StorageError, for_each_run_event_with_key},
    task_netns::{self, TaskNetnsHandle, TaskNetnsPolicy, TaskNetnsTools},
    tls_keylog::{self, TlsKeyLogHandle},
    transparent::TransparentArtifacts,
};

struct ProcessGroupGuard {
    pid: u32,
    armed: bool,
}

struct TerminalForegroundGuard {
    original_process_group: Pid,
}

impl TerminalForegroundGuard {
    fn handoff(target_pid: u32) -> Result<Option<Self>> {
        let stdin = std::io::stdin();
        if !isatty(&stdin).context("inspect target stdin terminal")? {
            return Ok(None);
        }
        let original_process_group = tcgetpgrp(&stdin).context("read terminal foreground group")?;
        if original_process_group != getpgrp() {
            return Ok(None);
        }
        let target_process_group =
            Pid::from_raw(i32::try_from(target_pid).context("target PID exceeds platform range")?);
        set_terminal_process_group(target_process_group)
            .context("give target process group control of the terminal")?;
        Ok(Some(Self {
            original_process_group,
        }))
    }

    fn restore(mut self) -> Result<()> {
        let result = set_terminal_process_group(self.original_process_group)
            .context("restore recorder terminal foreground group");
        self.original_process_group = Pid::from_raw(0);
        result
    }
}

impl Drop for TerminalForegroundGuard {
    fn drop(&mut self) {
        if self.original_process_group.as_raw() > 0 {
            let _ = set_terminal_process_group(self.original_process_group);
        }
    }
}

fn set_terminal_process_group(process_group: Pid) -> nix::Result<()> {
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut previous))?;
    let result = tcsetpgrp(std::io::stdin(), process_group);
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
    result?;
    restored
}

#[derive(Default)]
struct RuntimeServices {
    collector: Option<CollectorHandle>,
    tls_keylog: Option<TlsKeyLogHandle>,
    proxy: Option<ProxyHandle>,
    pcap: Option<PcapHandle>,
    task_netns: Option<TaskNetnsHandle>,
    transparent: Option<TransparentArtifacts>,
}

enum PreparedAdapter {
    BuiltIn(AdapterPlan),
    Sdk {
        host: Arc<AdapterHost>,
        configuration: ValidatedConfiguration,
        scratch: Option<tempfile::TempDir>,
    },
}

impl PreparedAdapter {
    fn name(&self) -> &str {
        match self {
            Self::BuiltIn(plan) => &plan.name,
            Self::Sdk { host, .. } => host.name(),
        }
    }

    fn known_gaps(&self) -> &[String] {
        match self {
            Self::BuiltIn(plan) => &plan.known_gaps,
            Self::Sdk { configuration, .. } => configuration.known_gaps(),
        }
    }

    fn apply_environment(&self, command: &mut Command) {
        match self {
            Self::BuiltIn(plan) => plan.apply_environment(command),
            Self::Sdk { configuration, .. } => configuration.apply_environment(command),
        }
    }

    fn environment(&self) -> &BTreeMap<OsString, OsString> {
        match self {
            Self::BuiltIn(plan) => &plan.environment,
            Self::Sdk { configuration, .. } => configuration.environment(),
        }
    }

    fn sdk_release(&self) -> Option<&str> {
        match self {
            Self::BuiltIn(_) => None,
            Self::Sdk { host, .. } => Some(host.adapter_release()),
        }
    }

    fn sdk_host(&self) -> Option<&AdapterHost> {
        match self {
            Self::BuiltIn(_) => None,
            Self::Sdk { host, .. } => Some(host),
        }
    }

    fn close_scratch(&mut self) -> io::Result<()> {
        match self {
            Self::BuiltIn(_) => Ok(()),
            Self::Sdk { scratch, .. } => {
                let Some(scratch) = scratch.take() else {
                    return Ok(());
                };
                scratch.close()
            }
        }
    }
}

impl RuntimeServices {
    async fn stop_all(mut self, store: &RunStore) {
        stop_proxy(self.proxy.take(), store).await;
        let namespace_anchor = self.pcap.as_ref().map(PcapHandle::namespace_anchor_pid);
        stop_task_netns(self.task_netns.take(), namespace_anchor, store).await;
        stop_pcap(self.pcap.take(), store).await;
        stop_tls_keylog(self.tls_keylog.take(), store).await;
        stop_collector(self.collector.take(), store).await;
        cleanup_transparent(self.transparent.take(), store).await;
    }
}

impl ProcessGroupGuard {
    fn new(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            let Ok(pid) = i32::try_from(self.pid) else {
                return;
            };
            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProviderSelection {
    Auto,
    Openai,
    Anthropic,
    Gemini,
    None,
}

#[derive(Debug)]
// These booleans are independent CLI switches, not one shared state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct RunOptions {
    pub command: Vec<OsString>,
    pub runs_dir: PathBuf,
    pub listen: SocketAddr,
    pub upstream: Option<Url>,
    pub upstream_http2_prior_knowledge: bool,
    pub provider: ProviderSelection,
    pub adapter: AdapterSelection,
    pub policy: CapturePolicy,
    pub encryption_key: Option<EncryptionKey>,
    pub allow_plaintext: bool,
    pub tls_keylog: bool,
    pub pcap: bool,
    pub pcap_max_bytes: u64,
    pub task_cgroup: bool,
    pub task_netns: bool,
    pub transparent_proxy: bool,
    pub egress_rules: Vec<EgressRuleSpec>,
    pub python_inject: bool,
    pub node_inject: bool,
    pub probe_helper: Option<PathBuf>,
    pub probe_policy_selection: Option<ProbeHelperSelection>,
}

#[derive(Debug)]
pub struct RunOutcome {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub exit_code: i32,
}

#[must_use]
pub fn run(options: RunOptions) -> Pin<Box<dyn Future<Output = Result<RunOutcome>> + Send>> {
    Box::pin(run_inner(options, None))
}

/// Run with a statically linked third-party adapter SDK implementation.
///
/// The SDK adapter replaces built-in auto-selection. Its native hook records
/// are still persisted independently before host-validated parsed events.
#[must_use]
pub fn run_with_adapter(
    options: RunOptions,
    adapter: AdapterHost,
) -> Pin<Box<dyn Future<Output = Result<RunOutcome>> + Send>> {
    Box::pin(run_inner(options, Some(Arc::new(adapter))))
}

async fn run_inner(options: RunOptions, adapter: Option<Arc<AdapterHost>>) -> Result<RunOutcome> {
    let run_id = format!("run-{}", Uuid::now_v7());
    let run_dir = options.runs_dir.join(&run_id);
    let failure_key = options.encryption_key.clone();
    match Box::pin(run_with_id(options, run_id, run_dir.clone(), adapter)).await {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            mark_failed_manifest(&run_dir, failure_key.as_ref());
            Err(error)
        }
    }
}

async fn run_with_id(
    options: RunOptions,
    run_id: String,
    run_dir: PathBuf,
    sdk_adapter: Option<Arc<AdapterHost>>,
) -> Result<RunOutcome> {
    anyhow::ensure!(
        !options.command.is_empty(),
        "a command is required after --"
    );
    anyhow::ensure!(
        options.encryption_key.is_some() || options.allow_plaintext,
        "recording requires --key-file by default; use --allow-plaintext only for an explicitly accepted plaintext evidence store"
    );
    anyhow::ensure!(
        options.encryption_key.is_none() || !options.allow_plaintext,
        "--allow-plaintext conflicts with --key-file"
    );
    anyhow::ensure!(
        !options.tls_keylog || options.encryption_key.is_some(),
        "--tls-keylog requires --key-file so TLS secrets are encrypted before persistence"
    );
    anyhow::ensure!(
        !options.pcap || options.encryption_key.is_some(),
        "--pcap requires --key-file so packet payloads are encrypted before persistence"
    );
    anyhow::ensure!(
        (options.probe_helper.is_none() && options.probe_policy_selection.is_none())
            || options.encryption_key.is_some(),
        "privileged probe selection requires --key-file so helper evidence is encrypted before persistence"
    );
    anyhow::ensure!(
        options.probe_helper.is_none() || options.probe_policy_selection.is_none(),
        "explicit and policy-selected probe helpers conflict"
    );
    anyhow::ensure!(
        !options.upstream_http2_prior_knowledge || options.upstream.is_some(),
        "--upstream-http2-prior-knowledge requires --upstream"
    );
    anyhow::ensure!(
        !options.pcap || options.upstream.is_some(),
        "--pcap requires --upstream so provider endpoints can be resolved into a fixed capture filter"
    );
    anyhow::ensure!(
        !options.task_netns || options.pcap,
        "--task-netns requires --pcap so the isolated task-to-proxy transport is independently recorded"
    );
    anyhow::ensure!(
        !options.task_netns || options.listen.ip().is_ipv4(),
        "--task-netns currently requires an IPv4 loopback --listen address"
    );
    anyhow::ensure!(
        !options.transparent_proxy || options.task_netns,
        "--transparent-proxy requires --task-netns"
    );
    anyhow::ensure!(
        !options.task_netns || options.egress_rules.is_empty(),
        "--egress-rule conflicts with proxy-only --task-netns; task-network policy does not permit auxiliary egress"
    );
    anyhow::ensure!(
        options.upstream.is_none() || options.listen.ip().is_loopback(),
        "--listen must be a loopback address when the inference proxy is enabled"
    );
    let probe_helper_selection = if let Some(selection) = &options.probe_policy_selection {
        selection.revalidate()?;
        Some(selection.clone())
    } else {
        options
            .probe_helper
            .as_deref()
            .map(inspect_explicit_helper)
            .transpose()?
    };
    let probe_helper_path = probe_helper_selection
        .as_ref()
        .map(|selection| selection.path().to_path_buf());
    let task_netns_tools = options
        .task_netns
        .then(TaskNetnsTools::discover)
        .transpose()
        .context("validate rootless task-network isolation prerequisites")?;
    let recorder_identity = fs::metadata("/proc/self")?;
    let recorder_user_id = recorder_identity.uid();
    let recorder_group_id = recorder_identity.gid();
    let mut task_cgroup = options
        .task_cgroup
        .then(|| TaskCgroup::create_current(&run_id))
        .transpose()
        .context("create delegated cgroup-v2 task boundary")?;
    let launch_paused = probe_helper_path.is_some()
        || task_cgroup.is_some()
        || task_netns_tools.is_some()
        || !options.egress_rules.is_empty();
    let cwd = std::env::current_dir().context("read current directory")?;
    let command_metadata = discover_command(&options.command, &cwd)
        .await
        .context("inspect target command")?;
    let doctor_report = doctor::inspect();
    if let Some(selection) = &probe_helper_selection {
        selection.revalidate_for(&command_metadata, &doctor_report, task_cgroup.is_some())?;
    }
    if let Some(adapter) = sdk_adapter.as_ref() {
        anyhow::ensure!(
            matches!(
                options.adapter,
                AdapterSelection::Auto | AdapterSelection::Generic | AdapterSelection::None
            ),
            "a third-party SDK adapter conflicts with an explicit built-in --adapter"
        );
        let mut detect = DetectContext::new(options.command.clone());
        detect.detected_agent.clone_from(&command_metadata.agent);
        detect
            .executable_sha256
            .clone_from(&command_metadata.executable_sha256);
        let detection = adapter
            .detect(&detect)
            .context("third-party adapter detection")?;
        anyhow::ensure!(
            detection.matched,
            "third-party adapter did not match the target command"
        );
    }
    anyhow::ensure!(
        !options.python_inject || command_metadata.runtime.as_deref() == Some("python"),
        "--python-inject requires a passively detected Python target"
    );
    anyhow::ensure!(
        !options.node_inject || command_metadata.runtime.as_deref() == Some("node"),
        "--node-inject requires a passively detected Node.js target; Bun binaries do not honor this mechanism"
    );
    let mut manifest = Manifest::new(run_id.clone(), command_metadata, options.policy.clone());
    manifest.probe_plan = Some(ProbePlan::build(
        &manifest.command,
        &ProbePlannerConfig {
            endpoint_proxy: options.upstream.is_some(),
            http2_prior_knowledge: options.upstream_http2_prior_knowledge,
            tls_keylog: options.tls_keylog,
            pcap: options.pcap,
            python_injection: options.python_inject,
            node_injection: options.node_inject,
            privileged_helper: probe_helper_path.is_some(),
            helper_selection: probe_helper_selection
                .as_ref()
                .map(|selection| selection.evidence().clone()),
            task_cgroup: task_cgroup.is_some(),
            task_netns: task_netns_tools.is_some(),
            transparent_proxy: options.transparent_proxy,
        },
        &doctor_report,
    ));
    let (model_upstream_endpoints, model_upstream_endpoints_truncated) = if let Some(upstream) =
        options.upstream.as_ref()
    {
        match resolve_upstream_endpoints(upstream).await {
            Ok((endpoints, truncated)) => {
                if !options.task_netns {
                    manifest.coverage.known_gaps.push(
                        "model-bypass classification uses a launch-time upstream address snapshot; later DNS changes and unmatched provider addresses remain unknown"
                            .to_owned(),
                    );
                }
                if truncated && !options.task_netns {
                    manifest.coverage.known_gaps.push(
                        "upstream DNS returned more than 64 unique socket addresses; bypass classification retained only the first 64"
                            .to_owned(),
                    );
                }
                (endpoints, truncated)
            }
            Err(error) if !options.egress_rules.is_empty() || options.transparent_proxy => {
                return Err(error).context(
                    "resolve configured model upstream before configuring exact interception or egress rules",
                );
            }
            Err(error) => {
                warn!(
                    error_kind = ?error.kind(),
                    "upstream address snapshot failed; direct model bypasses remain unknown"
                );
                manifest.coverage.known_gaps.push(
                    "upstream address snapshot failed; direct connections to the configured model endpoint cannot be classified separately from unknown egress"
                        .to_owned(),
                );
                (Vec::new(), false)
            }
        }
    } else {
        (Vec::new(), false)
    };
    let configured_egress = egress::resolve(&options.egress_rules, &model_upstream_endpoints)
        .await
        .context("resolve configured egress rules")?;
    if !configured_egress.rules.is_empty() {
        manifest.coverage.known_gaps.push(
            "configured egress classes use exact IP-and-port matches from a launch-time DNS snapshot; DNS churn, SNI, proxies, and shared-CDN ambiguity remain unknown rather than being inferred"
                .to_owned(),
        );
        if configured_egress.was_truncated() {
            manifest.coverage.known_gaps.push(format!(
                "one or more egress rules resolved beyond the per-rule limit of {}; omitted addresses remain unknown egress",
                egress::MAX_ENDPOINTS_PER_RULE
            ));
        }
    }
    if manifest.command.agent.is_some() && manifest.command.agent_version.is_none() {
        manifest.coverage.known_gaps.push(
            "agent version was not available from passive metadata; the recorder never executes the target a second time for version discovery"
                .to_owned(),
        );
    }
    if manifest.command.executable.is_some() && manifest.command.executable_sha256.is_none() {
        manifest.coverage.known_gaps.push(
            "target executable fingerprint was unavailable or unstable; SHA-256 and static TLS markers are unknown"
                .to_owned(),
        );
    } else if manifest.command.executable.is_none() {
        manifest.coverage.known_gaps.push(
            "target executable was not resolved before spawn; binary identity and static TLS markers are unknown"
                .to_owned(),
        );
    }
    if let Some(key) = &options.encryption_key {
        manifest.storage.encryption = Some(crate::manifest::EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: Some(RUN_KEY_DERIVATION_V1.to_owned()),
            blob_key_management: Some(crate::blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
    } else {
        manifest.coverage.known_gaps.push(
            "events and payload blobs are stored in plaintext; use --key-file for at-rest encryption"
                .to_owned(),
        );
    }
    manifest.coverage.capture_sources.push("runner".to_owned());
    manifest.coverage.known_gaps.push(
        "cross-source inference links are emitted only for exact IDs or a unique bounded temporal/model candidate; ambiguous links remain unresolved"
            .to_owned(),
    );
    if options.tls_keylog {
        match manifest.command.runtime.as_deref() {
            Some("node") => manifest.coverage.known_gaps.push(
                "Node TLS key logging uses NODE_OPTIONS --tls-keylog; a target command-line override can invalidate capture and is rejected when visible"
                    .to_owned(),
            ),
            Some("python") => manifest.coverage.known_gaps.push(
                "Python SSLKEYLOGFILE capture applies to supported default contexts; custom SSLContext construction may bypass it"
                    .to_owned(),
            ),
            Some("bun") => manifest.coverage.known_gaps.push(
                "Bun does not use the Node TLS key-log injection path; TLS coverage remains unknown"
                    .to_owned(),
            ),
            _ => manifest.coverage.known_gaps.push(
                "the detected runtime is not verified to honor SSLKEYLOGFILE; TLS coverage remains unknown"
                    .to_owned(),
            ),
        }
    }
    if options.pcap {
        manifest.coverage.known_gaps.push(if options.task_netns {
            "task-network pcap observes only the isolated target-to-recorder proxy leg; the recorder-to-provider leg is outside that pcap, and --tls-keylog adds encrypted upstream TLS diagnostics when enabled"
                .to_owned()
        } else {
            "pcap uses a launch-time upstream address snapshot; unrelated host traffic to the same endpoint can be included, while DNS changes and other provider endpoints can be missed"
                .to_owned()
        });
    }
    if let Some(selection) = &probe_helper_selection {
        manifest.coverage.known_gaps.push(
            "privileged probe coverage is supplied by an external versioned helper; its ready/final/drop evidence is verified, but bridge-specific kernel and TLS support remain independently testable claims"
                .to_owned(),
        );
        if selection.evidence().mode == "policy" {
            manifest.coverage.known_gaps.push(format!(
                "privileged probe helper was selected by trusted policy rule {}; this binds launch to the recorded helper and target fingerprints but does not broaden its qualified support matrix",
                selection.evidence().rule_id.as_deref().unwrap_or("unknown")
            ));
        }
    }
    if task_cgroup.is_some() {
        manifest.coverage.known_gaps.push(
            "cgroup-v2 membership establishes a task boundary but does not by itself enforce an egress policy"
                .to_owned(),
        );
    }
    if options.task_netns {
        manifest.coverage.known_gaps.push(if options.transparent_proxy {
            "transparent task-network interception pins the launch-time IPv4 model address snapshot in a private read-only /etc/hosts mount and blocks DNS/other egress; custom resolvers, certificate pinning, DNS churn, auth, telemetry, update, or unrelated network dependencies can fail"
                .to_owned()
        } else {
            "rootless task-network isolation deliberately blocks DNS and every non-loopback destination except the recorder proxy; applications that require auth, telemetry, update, or unrelated network services can fail"
                .to_owned()
        });
    }
    if options.python_inject {
        manifest.coverage.known_gaps.push(
            "Python runtime injection is process-local evidence: interpreter isolation flags, target mutation, unsupported SDK versions, or non-Python descendants can bypass it; a startup event proves loading but not complete call coverage"
                .to_owned(),
        );
    }
    if options.node_inject {
        manifest.coverage.known_gaps.push(
            "Node.js runtime injection is target-controlled evidence: target mutation, unsupported SDK/module formats, explicit environment removal, or native/non-Node descendants can bypass it; readiness proves preload execution but not complete call coverage"
                .to_owned(),
        );
    }
    manifest.coverage.known_gaps.push(
        "process discovery polls /proc every 100 ms and may miss very short-lived descendants"
            .to_owned(),
    );
    if options.upstream.is_none() {
        manifest.coverage.known_gaps.push(
            "no reverse-proxy upstream configured; transport payloads are not captured".to_owned(),
        );
    } else {
        manifest.coverage.known_gaps.push(if options.pcap && options.tls_keylog {
            if options.task_netns {
                "task-egress pcap and endpoint-proxy bodies require a successful offline transport-audit before their payload agreement can be claimed"
                    .to_owned()
            } else {
                "upstream pcap and recorder TLS secrets require a successful offline transport-audit before their payload agreement can be claimed"
                    .to_owned()
            }
        } else {
            "endpoint proxy is not independently cross-checked against decrypted upstream network traffic"
                .to_owned()
        });
        manifest.coverage.known_gaps.extend([
            "WebSocket events represent reassembled messages; original wire fragmentation is not preserved"
                .to_owned(),
            "pooled HTTP/2 upstream connection and stream identifiers are not exposed by the endpoint proxy"
                .to_owned(),
        ]);
    }
    let run_encryption_key = options
        .encryption_key
        .as_ref()
        .map(|key| key.derive_run_key(&run_id))
        .transpose()
        .context("derive per-run data-encryption key")?;
    write_atomic_authenticated(
        &run_dir.join("manifest.json"),
        &manifest,
        options.encryption_key.as_ref(),
    )
    .context("write initial manifest")?;
    audit::append(
        run_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("run directory has no parent"))?,
        "run_start",
        "complete",
        &run_id,
        Some(json!({
            "recorder_version": crate::RECORDER_VERSION,
            "encrypted": options.encryption_key.is_some(),
        })),
    )
    .context("append run-start audit record")?;

    let (store, recovery) = RunStore::create_with_encryption(
        &run_dir,
        &run_id,
        options.policy,
        run_encryption_key.clone(),
    )?;
    if recovery.discarded_tail_bytes > 0 {
        anyhow::bail!("new run unexpectedly contained a damaged event tail");
    }
    let mut services = RuntimeServices::default();
    let setup = async {
        let mut started = store.event("runner", "run_started");
        started.normalized = Some(json!({
            "command": manifest.command.argv,
            "cwd": manifest.command.cwd,
            "executable": manifest.command.executable,
            "executable_sha256": manifest.command.executable_sha256,
            "executable_tls_surfaces": manifest.command.executable_tls_surfaces,
            "runtime": manifest.command.runtime,
            "agent": manifest.command.agent,
            "agent_version": manifest.command.agent_version,
        }));
        store.append(started).await?;
        if let Some(plan) = manifest.probe_plan.as_ref() {
            let mut event = store.event("runner", "probe_plan_created");
            event.normalized = Some(json!({
                "schema_version": plan.schema_version,
                "selected": plan.selected,
                "independent_observer_selected": plan.independent_observer_selected,
                "candidate_count": plan.candidates.len(),
                "limitation_count": plan.limitations.len(),
                "detail": "manifest.probe_plan",
            }));
            store.append(event).await?;
        }
        if options.transparent_proxy {
            let upstream = options
                .upstream
                .as_ref()
                .context("transparent interception requires an upstream")?;
            let artifacts = TransparentArtifacts::prepare(
                &run_dir,
                &run_id,
                upstream,
                &model_upstream_endpoints,
                model_upstream_endpoints_truncated,
            )?;
            let mut event = store.event("runner", "transparent_interception_prepared");
            event.normalized = Some(json!({
                "schema_version": 1,
                "upstream_host": artifacts.upstream_host(),
                "upstream_port": artifacts.upstream_port(),
                "endpoint_count": artifacts.endpoints().len(),
                "address_basis": "launch_time_dns_ipv4_exact_socket",
                "dns_enabled": false,
                "hosts_snapshot": "private_read_only_bind_mount",
                "inherited_proxy_environment_removed": true,
                "downstream_tls": artifacts.server_config().is_some(),
                "ca_public_certificate_sha256": artifacts.ca_sha256(),
                "ca_private_key_persisted": false,
                "certificate_lifetime_days": 7,
            }));
            store.append(event).await?;
            manifest
                .coverage
                .capture_sources
                .push(if artifacts.server_config().is_some() {
                    "proxy:transparent-task-netns-tls".to_owned()
                } else {
                    "proxy:transparent-task-netns-cleartext".to_owned()
                });
            services.transparent = Some(artifacts);
        }
        if !configured_egress.rules.is_empty() {
            let mut event = store.event("runner", "egress_classification_snapshot");
            event.normalized = Some(json!({
                "schema_version": 1,
                "basis": "configured_launch_time_dns_exact_socket",
                "rules": configured_egress.rules,
                "input_rule_count": options.egress_rules.len(),
                "unique_selector_count": configured_egress.rules.len(),
                "endpoint_count": configured_egress.endpoint_count(),
                "per_rule_endpoint_limit": egress::MAX_ENDPOINTS_PER_RULE,
                "global_endpoint_limit": egress::MAX_EGRESS_ENDPOINTS,
                "resolution_timeout_ms": 5_000,
                "sni_verified": false,
            }));
            store.append(event).await?;
        }
        services.collector = Some(
            collector::start_with_adapter(&run_dir, store.clone(), sdk_adapter.clone())
                .context("start hook collector")?,
        );
        let mut collector_event = store.event("runner", "collector_started");
        collector_event.normalized =
            Some(json!({"socket": "collector.sock", "peer_scope": "same_uid"}));
        store.append(collector_event).await?;

        if options.tls_keylog {
            services.tls_keylog = Some(
                tls_keylog::start(&run_dir, store.clone()).context("start TLS key-log FIFO")?,
            );
            let mut event = store.event("runner", "tls_key_log_started");
            event.normalized = Some(json!({"transport": "fifo", "at_rest": "encrypted"}));
            store.append(event).await?;
            manifest
                .coverage
                .capture_sources
                .push("nss-sslkeylogfile".to_owned());
        }

        if let Some(upstream) = options.upstream.clone() {
            let config = ProxyConfig {
                listen: options.listen,
                upstream,
            };
            let proxy_key_log = services
                .tls_keylog
                .as_ref()
                .map(|handle| tls_keylog::rustls_key_logger(&handle.path, store.clone()))
                .transpose()
                .context("open recorder TLS key-log writer")?;
            let proxy = if let Some(ingress_tls) = services
                .transparent
                .as_ref()
                .and_then(TransparentArtifacts::server_config)
            {
                start_transparent_tls(
                    config,
                    store.clone(),
                    ingress_tls,
                    options.upstream_http2_prior_knowledge,
                    proxy_key_log,
                )
                .await
            } else {
                match (options.upstream_http2_prior_knowledge, proxy_key_log) {
                    (true, Some(key_log)) => {
                        start_http2_proxy_with_key_log(config, store.clone(), key_log).await
                    }
                    (false, Some(key_log)) => {
                        start_proxy_with_key_log(config, store.clone(), key_log).await
                    }
                    (true, None) => start_http2_proxy(config, store.clone()).await,
                    (false, None) => start_proxy(config, store.clone()).await,
                }
            };
            services.proxy = Some(proxy.context("start inference proxy")?);
            if options.tls_keylog {
                manifest
                    .coverage
                    .capture_sources
                    .push("tls-keylog:proxy-rustls".to_owned());
            }
        }
        if options.pcap && !options.task_netns {
            services.pcap = Some(
                pcap::start_upstream(
                    &model_upstream_endpoints,
                    options.pcap_max_bytes,
                    store.clone(),
                )
                    .await
                    .context("start upstream-filtered pcap helper")?,
            );
            let mut event = store.event("runner", "pcap_capture_started");
            event.normalized = Some(json!({
                "scope": "upstream_address_snapshot",
                "endpoints": model_upstream_endpoints.len(),
                "max_bytes": options.pcap_max_bytes,
                "at_rest": "encrypted",
            }));
            store.append(event).await?;
            manifest
                .coverage
                .capture_sources
                .push("pcap:upstream-address-snapshot".to_owned());
        }

        let proxy_url = services
            .proxy
            .as_ref()
            .filter(|_| !options.transparent_proxy)
            .map(|proxy| target_proxy_url(proxy, options.task_netns));
        let mut effective_command = options.command.clone();
        let adapter = if let Some(host) = sdk_adapter.clone() {
            let scratch = tempfile::Builder::new()
                .prefix(".adapter-sdk-")
                .tempdir_in(&run_dir)
                .context("create private adapter SDK directory")?;
            fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700))
                .context("protect adapter SDK directory")?;
            let mut context =
                ConfigureContext::new(effective_command.clone(), scratch.path().to_owned());
            context.proxy_url.clone_from(&proxy_url);
            let configuration = host
                .configure(&context)
                .context("configure third-party adapter")?;
            configuration
                .apply_command(&mut effective_command)
                .context("apply third-party adapter command configuration")?;
            PreparedAdapter::Sdk {
                host,
                configuration,
                scratch: Some(scratch),
            }
        } else {
            PreparedAdapter::BuiltIn(
                prepare_adapter(
                    options.adapter,
                    manifest.command.agent.as_deref(),
                    &mut effective_command,
                    proxy_url.as_deref(),
                )
                .context("prepare agent adapter")?,
            )
        };
        let session_reader = SessionReader::snapshot_with_environment(
            adapter.name(),
            &cwd,
            adapter.environment(),
        )
        .context("snapshot agent session files")?;
        let python_injection = options
            .python_inject
            .then(|| PythonInjection::prepare(&run_dir, &effective_command))
            .transpose()
            .context("prepare Python runtime injection")?;
        let node_injection = options
            .node_inject
            .then(|| NodeInjection::prepare(&run_dir))
            .transpose()
            .context("prepare Node.js runtime injection")?;
        manifest
            .coverage
            .known_gaps
            .extend(adapter.known_gaps().iter().cloned());
        if session_reader.is_some() {
            manifest.coverage.known_gaps.push(
                "agent session files are imported after target exit; abrupt recorder termination can miss their final records"
                    .to_owned(),
            );
        }
        write_atomic_authenticated(
            &run_dir.join("manifest.json"),
            &manifest,
            options.encryption_key.as_ref(),
        )
            .context("update adapter manifest")?;
        let mut adapter_event = store.event("runner", "adapter_configured");
        adapter_event.normalized = Some(json!({
            "adapter": adapter.name(),
            "adapter_sdk_release": adapter.sdk_release(),
            "session_reader": session_reader.is_some(),
            "known_gaps": adapter.known_gaps(),
        }));
        store.append(adapter_event).await?;
        if let Some(injection) = python_injection.as_ref() {
            let mut event = store.event("runner", "python_runtime_injection_configured");
            event.normalized = Some(json!({
                "mechanism": "sitecustomize",
                "shim_sha256": injection.sha256(),
                "fail_open": true,
            }));
            store.append(event).await?;
        }
        if let Some(injection) = node_injection.as_ref() {
            let mut event = store.event("runner", "node_runtime_injection_configured");
            event.normalized = Some(json!({
                "mechanism": "node_options_require",
                "shim_sha256": injection.sha256(),
                "fail_open": true,
            }));
            store.append(event).await?;
        }
        Ok::<_, anyhow::Error>((
            effective_command,
            adapter,
            session_reader,
            python_injection,
            node_injection,
        ))
    }
    .await;
    let (effective_command, mut adapter, session_reader, python_injection, node_injection) =
        match setup {
            Ok(setup) => setup,
            Err(error) => {
                finalize_failed_run(
                    &run_dir,
                    options.encryption_key.as_ref(),
                    &store,
                    services,
                    125,
                    "setup_failed",
                )
                .await;
                return Err(error);
            }
        };
    let spawn_environment = (|| {
        let collector = services
            .collector
            .as_ref()
            .context("collector disappeared before spawn")?;
        let node_options = if manifest.command.runtime.as_deref() == Some("node")
            && (options.tls_keylog || node_injection.is_some())
        {
            let keylog_path = if options.tls_keylog {
                Some(
                    &services
                        .tls_keylog
                        .as_ref()
                        .context("Node TLS key logging requested without an active key-log FIFO")?
                        .path,
                )
            } else {
                None
            };
            Some(node_options_with_instrumentation(
                &effective_command,
                keylog_path,
                node_injection.as_ref(),
            )?)
        } else {
            None
        };
        Ok::<_, anyhow::Error>((
            collector.socket_path.clone(),
            collector.token.clone(),
            node_options,
        ))
    })();
    let (collector_socket, collector_token, node_options) = match spawn_environment {
        Ok(environment) => environment,
        Err(error) => {
            finalize_failed_run(
                &run_dir,
                options.encryption_key.as_ref(),
                &store,
                services,
                125,
                "spawn_environment_configuration_failed",
            )
            .await;
            return Err(error);
        }
    };

    let task_netns_policy = if options.transparent_proxy {
        services
            .transparent
            .as_ref()
            .context("transparent interception artifacts disappeared before target spawn")
            .and_then(|artifacts| {
                TaskNetnsPolicy::transparent(artifacts.endpoints(), artifacts.hosts_path())
                    .context("construct transparent task-network policy")
            })
    } else {
        Ok(TaskNetnsPolicy::ProxyOnly)
    };
    let task_netns_policy = match task_netns_policy {
        Ok(policy) => policy,
        Err(error) => {
            finalize_failed_run(
                &run_dir,
                options.encryption_key.as_ref(),
                &store,
                services,
                125,
                "task_network_policy_configuration_failed",
            )
            .await;
            return Err(error);
        }
    };

    let mut command = if let Some(tools) = task_netns_tools.as_ref() {
        match tools.target_command(&effective_command, &task_netns_policy) {
            Ok(command) => command,
            Err(error) => {
                finalize_failed_run(
                    &run_dir,
                    options.encryption_key.as_ref(),
                    &store,
                    services,
                    125,
                    "task_network_launcher_configuration_failed",
                )
                .await;
                return Err(error).context("build task-network target launcher");
            }
        }
    } else if launch_paused {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("kill -STOP $$ || exit 125; exec \"$@\"")
            .arg("iorec-target")
            .args(&effective_command);
        command
    } else {
        let mut command = Command::new(&effective_command[0]);
        command.args(&effective_command[1..]);
        command
    };
    command
        .current_dir(&cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("IOREC_RUN_ID", &run_id)
        .env("IOREC_RUN_DIR", &run_dir)
        .env(collector::SOCKET_ENV, collector_socket)
        .env(collector::TOKEN_ENV, collector_token);
    if options.task_netns {
        command.env("PATH", "/usr/bin:/bin");
    }
    if options.transparent_proxy {
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            command.env_remove(name);
        }
    }
    if let Some(ca_path) = services
        .transparent
        .as_ref()
        .and_then(TransparentArtifacts::ca_path)
    {
        command
            .env("SSL_CERT_FILE", ca_path)
            .env("REQUESTS_CA_BUNDLE", ca_path)
            .env("CURL_CA_BUNDLE", ca_path)
            .env("NODE_EXTRA_CA_CERTS", ca_path)
            .env("AWS_CA_BUNDLE", ca_path);
    }
    if let Some(tls_keylog) = &services.tls_keylog {
        command.env("SSLKEYLOGFILE", &tls_keylog.path);
    }
    if let Some(node_options) = node_options {
        command.env("NODE_OPTIONS", node_options);
    }
    adapter.apply_environment(&mut command);
    if let Some(injection) = python_injection.as_ref()
        && let Err(error) = injection.apply(&mut command)
    {
        finalize_failed_run(
            &run_dir,
            options.encryption_key.as_ref(),
            &store,
            services,
            125,
            "python_runtime_environment_failed",
        )
        .await;
        return Err(error).context("configure Python runtime injection environment");
    }
    if let Some(injection) = node_injection.as_ref() {
        injection.apply(&mut command);
    }
    command.process_group(0);
    command.kill_on_drop(true);
    if let Some(proxy) = &services.proxy
        && !options.transparent_proxy
    {
        let proxy_url = target_proxy_url(proxy, options.task_netns);
        command.env("IOREC_PROXY_URL", &proxy_url);
        inject_provider_environment(
            &mut command,
            options.provider,
            manifest.command.agent.as_deref(),
            &proxy_url,
        );
    }

    let signal_handlers = (|| {
        Ok::<_, std::io::Error>((
            tokio::signal::unix::signal(SignalKind::interrupt())?,
            tokio::signal::unix::signal(SignalKind::terminate())?,
        ))
    })();
    let (mut interrupt, mut terminate) = match signal_handlers {
        Ok(handlers) => handlers,
        Err(error) => {
            finalize_failed_run(
                &run_dir,
                options.encryption_key.as_ref(),
                &store,
                services,
                125,
                "signal_handler_configuration_failed",
            )
            .await;
            return Err(error).context("configure target signal forwarding");
        }
    };

    let spawn_result = command.spawn();
    let mut child = match spawn_result {
        Ok(child) => child,
        Err(error) => {
            finalize_failed_run(
                &run_dir,
                options.encryption_key.as_ref(),
                &store,
                services,
                127,
                "process_spawn_failed",
            )
            .await;
            return Err(error).context("spawn target command");
        }
    };
    let Some(child_pid) = child.id() else {
        let error = anyhow::anyhow!("target process has no PID");
        let _ = child.kill().await;
        let _ = child.wait().await;
        finalize_failed_run(
            &run_dir,
            options.encryption_key.as_ref(),
            &store,
            services,
            125,
            "process_tracking_failed",
        )
        .await;
        return Err(error);
    };
    let mut process_group_guard = ProcessGroupGuard::new(child_pid);
    let mut terminal_foreground = None;
    if !launch_paused {
        match TerminalForegroundGuard::handoff(child_pid) {
            Ok(guard) => {
                terminal_foreground = guard;
                if terminal_foreground.is_some() {
                    let _ = forward_signal(child_pid, Signal::SIGCONT);
                }
            }
            Err(error) => {
                if terminate_target(&mut child, child_pid).await {
                    process_group_guard.disarm();
                }
                finalize_failed_run(
                    &run_dir,
                    options.encryption_key.as_ref(),
                    &store,
                    services,
                    125,
                    "terminal_foreground_handoff_failed",
                )
                .await;
                return Err(error);
            }
        }
    }
    if launch_paused && let Err(error) = wait_for_target_stop(&mut child, child_pid).await {
        store.note_capture_drop();
        if terminate_target(&mut child, child_pid).await {
            process_group_guard.disarm();
        }
        finalize_failed_run(
            &run_dir,
            options.encryption_key.as_ref(),
            &store,
            services,
            125,
            "target_launch_barrier_failed",
        )
        .await;
        return Err(error).context("wait for target launch barrier");
    }
    if let Some(cgroup) = task_cgroup.as_ref() {
        if let Err(error) = cgroup.assign(child_pid) {
            store.note_capture_drop();
            warn!(
                error_kind = ?error.kind(),
                raw_os_error = ?error.raw_os_error(),
                "stopped target could not be assigned to its cgroup-v2 boundary"
            );
            if terminate_target(&mut child, child_pid).await {
                process_group_guard.disarm();
            }
            finalize_failed_run(
                &run_dir,
                options.encryption_key.as_ref(),
                &store,
                services,
                125,
                "task_cgroup_assignment_failed",
            )
            .await;
            return Err(error).context("assign stopped target to its cgroup-v2 boundary");
        }
        let mut event = store.event("runner", "task_cgroup_assigned");
        event.normalized = Some(json!({
            "version": 2,
            "path": cgroup.path(),
            "target_pid": child_pid,
            "inherited_by_descendants": true,
        }));
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    }
    let task_netns_setup = async {
        let Some(tools) = task_netns_tools.as_ref() else {
            return Ok::<(), anyhow::Error>(());
        };
        let proxy_port = services
            .proxy
            .as_ref()
            .context("task network isolation requires an active recorder proxy")?
            .address
            .port();
        let handle = TaskNetnsHandle::start(
            tools.clone(),
            child_pid,
            proxy_port,
            task_netns_policy.clone(),
        )
        .await
        .context("configure rootless task network namespace")?;
        let user_namespace = handle.user_namespace();
        let network_namespace = handle.network_namespace();
        let mount_namespace = handle.mount_namespace();
        services.task_netns = Some(handle);
        let mut event = store.event("runner", "task_network_isolation_configured");
        event.normalized = Some(json!({
            "version": 2,
            "backend": "rootless-user-netns-slirp4netns-nftables-v2",
            "target_pid": child_pid,
            "user_namespace": user_namespace,
            "network_namespace": network_namespace,
            "mount_namespace": mount_namespace,
            "cidr": "10.0.2.0/24",
            "guest_address": task_netns::GUEST_ADDRESS,
            "host_gateway": task_netns::HOST_GATEWAY,
            "proxy_port": proxy_port,
            "dns_enabled": false,
            "ipv6_enabled": false,
            "default_egress_policy": "drop",
            "policy_mode": task_netns_policy.mode(),
            "transparent_endpoint_count": task_netns_policy.endpoints().len(),
        }));
        store.append(event).await?;

        services.pcap = Some(
            pcap::start_task_namespace(
                child_pid,
                proxy_port,
                options.pcap_max_bytes,
                store.clone(),
            )
            .await
            .context("start task-network pcap helper")?,
        );
        let mut event = store.event("runner", "pcap_capture_started");
        event.normalized = Some(json!({
            "scope": "task_egress",
            "egress_policy": task_netns_policy.mode(),
            "network_namespace": network_namespace,
            "proxy_gateway": task_netns::HOST_GATEWAY,
            "proxy_port": proxy_port,
            "max_bytes": options.pcap_max_bytes,
            "at_rest": "encrypted",
        }));
        store.append(event).await?;

        forward_signal(child_pid, Signal::SIGCONT)
            .context("release task namespace configuration barrier")?;
        wait_for_target_stop(&mut child, child_pid)
            .await
            .context("wait for post-privilege-drop launch barrier")?;
        let confinement = task_netns::verify_confined_target(
            child_pid,
            recorder_user_id,
            recorder_group_id,
            user_namespace,
            network_namespace,
            mount_namespace,
            services
                .task_netns
                .as_ref()
                .and_then(TaskNetnsHandle::hosts_path),
        )
        .context("verify target privileges and namespace identity")?;
        let task_netns_handle = services
            .task_netns
            .as_mut()
            .context("task-network helper disappeared before target launch")?;
        task_netns_handle.ensure_running()?;
        let firewall_before_target = task_netns_handle
            .seal_target_start()
            .await
            .context("seal task-network counters before target launch")?;
        let mut event = store.event("runner", "task_network_target_confined");
        event.terminal_state = Some(TerminalState::Complete);
        event.normalized = Some(json!({
            "effective_uid": confinement.effective_uid,
            "effective_gid": confinement.effective_gid,
            "capabilities_zero": confinement.capabilities_zero,
            "bounding_capabilities_zero": confinement.bounding_capabilities_zero,
            "no_new_privileges": confinement.no_new_privileges,
            "user_namespace": confinement.user_namespace,
            "network_namespace": confinement.network_namespace,
            "mount_namespace": confinement.mount_namespace,
            "hosts_snapshot_read_only": confinement.hosts_snapshot_read_only,
            "firewall_before_target": firewall_before_target,
        }));
        store.append(event).await?;
        Ok(())
    }
    .await;
    if let Err(error) = task_netns_setup {
        store.note_capture_drop();
        if terminate_target(&mut child, child_pid).await {
            process_group_guard.disarm();
        }
        stop_task_cgroup(task_cgroup.take(), &store).await;
        finalize_failed_run(
            &run_dir,
            options.encryption_key.as_ref(),
            &store,
            services,
            125,
            "task_network_isolation_failed",
        )
        .await;
        return Err(error);
    }
    let mut probe_helper = if let Some(path) = probe_helper_path.as_deref() {
        let target = probe_helper::ProbeTarget::new(
            child_pid,
            manifest.command.executable.as_deref(),
            manifest.command.executable_sha256.as_deref(),
            task_cgroup.as_ref().map(TaskCgroup::path),
        );
        let started = match target {
            Ok(target) => probe_helper::start(path, target, &run_id, store.clone()).await,
            Err(error) => Err(error),
        };
        match started {
            Ok(handle) => Some(handle),
            Err(error) => {
                store.note_capture_drop();
                if terminate_target(&mut child, child_pid).await {
                    process_group_guard.disarm();
                }
                finalize_failed_run(
                    &run_dir,
                    options.encryption_key.as_ref(),
                    &store,
                    services,
                    125,
                    "probe_helper_start_failed",
                )
                .await;
                return Err(error).context("start privileged probe helper");
            }
        }
    } else {
        None
    };
    let recorder_endpoint = services.proxy.as_ref().map(|handle| {
        if options.task_netns {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)),
                handle.address.port(),
            )
        } else {
            handle.address
        }
    });
    let process_tracker = process_tracker::start(
        child_pid,
        recorder_endpoint,
        model_upstream_endpoints,
        options.transparent_proxy,
        configured_egress.endpoints,
        store.clone(),
    );
    if probe_helper.is_some() {
        let mut event = store.event("runner", "privileged_probe_started");
        event.normalized = Some(json!({
            "protocol_version": probe_helper::PROTOCOL_VERSION,
            "selection": probe_helper_selection.as_ref().map(ProbeHelperSelection::evidence),
            "target_pid": child_pid,
            "target_executable_sha256": manifest.command.executable_sha256,
            "filter_scope": if task_cgroup.is_some() { "cgroup" } else { "pid_tree" },
            "target_cgroup": task_cgroup.as_ref().map(TaskCgroup::path),
            "at_rest": "encrypted",
        }));
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    }
    if launch_paused {
        match TerminalForegroundGuard::handoff(child_pid) {
            Ok(guard) => terminal_foreground = guard,
            Err(error) => {
                store.note_capture_drop();
                stop_probe_helper(probe_helper.take(), &store).await;
                if terminate_target(&mut child, child_pid).await {
                    process_group_guard.disarm();
                }
                stop_process_tracker(process_tracker, &store).await;
                stop_task_cgroup(task_cgroup.take(), &store).await;
                finalize_failed_run(
                    &run_dir,
                    options.encryption_key.as_ref(),
                    &store,
                    services,
                    125,
                    "terminal_foreground_handoff_failed",
                )
                .await;
                return Err(error);
            }
        }
    }
    if launch_paused && let Err(error) = forward_signal(child_pid, Signal::SIGCONT) {
        store.note_capture_drop();
        stop_probe_helper(probe_helper.take(), &store).await;
        if terminate_target(&mut child, child_pid).await {
            process_group_guard.disarm();
        }
        stop_process_tracker(process_tracker, &store).await;
        stop_task_cgroup(task_cgroup.take(), &store).await;
        finalize_failed_run(
            &run_dir,
            options.encryption_key.as_ref(),
            &store,
            services,
            125,
            "target_launch_barrier_release_failed",
        )
        .await;
        return Err(error).context("continue target after launch-boundary setup");
    }
    let execution = async {
        let mut spawned = store.event("runner", "process_started");
        spawned.normalized = Some(json!({"pid": child_pid, "parent_pid": std::process::id()}));
        if let Err(error) = store.append(spawned).await {
            store.note_capture_drop();
            warn!(
                error_kind = error.category(),
                "failed to persist target process start; target continues"
            );
        }
        loop {
            tokio::select! {
                result = child.wait() => break result.context("wait for target process"),
                signal = interrupt.recv() => {
                    if signal.is_some() {
                        forward_signal(child_pid, Signal::SIGINT)?;
                        let mut event = store.event("runner", "signal_forwarded");
                        event.normalized = Some(json!({"signal": "SIGINT", "pid": child_pid}));
                        if let Err(error) = store.append(event).await {
                            store.note_capture_drop();
                            warn!(
                                error_kind = error.category(),
                                "failed to persist forwarded SIGINT; target continues"
                            );
                        }
                    }
                }
                signal = terminate.recv() => {
                    if signal.is_some() {
                        forward_signal(child_pid, Signal::SIGTERM)?;
                        let mut event = store.event("runner", "signal_forwarded");
                        event.normalized = Some(json!({"signal": "SIGTERM", "pid": child_pid}));
                        if let Err(error) = store.append(event).await {
                            store.note_capture_drop();
                            warn!(
                                error_kind = error.category(),
                                "failed to persist forwarded SIGTERM; target continues"
                            );
                        }
                    }
                }
            }
        }
    }
    .await;
    if let Some(guard) = terminal_foreground.take()
        && guard.restore().is_err()
    {
        warn!("failed to restore terminal foreground group");
    }
    let status = match execution {
        Ok(status) => status,
        Err(error) => {
            store.note_capture_drop();
            if terminate_target(&mut child, child_pid).await {
                process_group_guard.disarm();
            }
            stop_probe_helper(probe_helper.take(), &store).await;
            stop_process_tracker(process_tracker, &store).await;
            stop_task_cgroup(task_cgroup.take(), &store).await;
            stop_tls_keylog(services.tls_keylog.take(), &store).await;
            import_session(session_reader, &store).await;
            finalize_failed_run(
                &run_dir,
                options.encryption_key.as_ref(),
                &store,
                services,
                125,
                "runner_failure",
            )
            .await;
            return Err(error);
        }
    };
    let exit_code = exit_status_code(status);
    process_group_guard.disarm();
    stop_probe_helper(probe_helper.take(), &store).await;
    stop_task_cgroup(task_cgroup.take(), &store).await;
    stop_process_tracker(process_tracker, &store).await;
    let namespace_anchor = services.pcap.as_ref().map(PcapHandle::namespace_anchor_pid);
    seal_task_netns_target_end(services.task_netns.as_mut(), namespace_anchor, &store).await;
    stop_tls_keylog(services.tls_keylog.take(), &store).await;
    import_session(session_reader, &store).await;
    let mut exited = store.event("runner", "process_finished");
    exited.terminal_state = Some(if exit_code == 0 {
        TerminalState::Complete
    } else {
        TerminalState::Error
    });
    exited.normalized = Some(json!({"pid": child_pid, "exit_code": exit_code}));
    if let Err(error) = store.append(exited).await {
        warn!(
            error_kind = error.category(),
            "failed to persist target process completion"
        );
    }

    stop_proxy(services.proxy.take(), &store).await;
    stop_task_netns(services.task_netns.take(), namespace_anchor, &store).await;
    stop_pcap(services.pcap.take(), &store).await;
    stop_collector(services.collector.take(), &store).await;
    cleanup_transparent(services.transparent.take(), &store).await;
    cleanup_adapter_scratch(&mut adapter, &store).await;
    derive_adapter_correlations(
        adapter.sdk_host(),
        &run_dir,
        run_encryption_key.as_ref(),
        &store,
    )
    .await;
    derive_correlations(&run_dir, run_encryption_key.as_ref(), &store).await;
    let mut finished = store.event("runner", "run_finished");
    finished.terminal_state = Some(if exit_code == 0 {
        TerminalState::Complete
    } else {
        TerminalState::Error
    });
    let storage_stats = store.stats();
    finished.normalized = Some(json!({
        "exit_code": exit_code,
        "storage": {
            "events_before_finish": storage_stats.events,
            "event_storage_bytes_before_finish": storage_stats.event_storage_bytes,
            "queue_waits": storage_stats.queue_waits,
            "event_sync_batches": storage_stats.event_sync_batches,
            "capture_drops": storage_stats.capture_drops,
        }
    }));
    if let Err(error) = store.append(finished).await {
        warn!(
            error_kind = error.category(),
            "failed to persist run completion"
        );
    }
    let (writer_stats, writer_shutdown_clean) = match store.shutdown().await {
        Ok(writer) => (writer, true),
        Err(error) => {
            warn!(
                error_kind = error.category(),
                "event writer was unavailable during final shutdown"
            );
            (store.stats(), false)
        }
    };
    let mut finalized = finalize_manifest(
        &run_dir,
        exit_code,
        writer_stats.capture_drops,
        options.encryption_key.as_ref(),
    )
    .context("rebuild final manifest from durable evidence")?;
    if !writer_shutdown_clean {
        finalized.coverage.known_gaps.push(
            "durable event writer became unavailable before final shutdown; only its validated persisted prefix is represented"
                .to_owned(),
        );
        finalized.coverage.known_gaps.sort();
        finalized.coverage.known_gaps.dedup();
        write_atomic_authenticated(
            &run_dir.join("manifest.json"),
            &finalized,
            options.encryption_key.as_ref(),
        )?;
    }

    Ok(RunOutcome {
        run_id,
        run_dir,
        exit_code,
    })
}

const MAX_UPSTREAM_ENDPOINTS: usize = 64;

fn target_proxy_url(proxy: &ProxyHandle, task_netns: bool) -> String {
    if task_netns {
        format!(
            "http://{}:{}",
            task_netns::HOST_GATEWAY,
            proxy.address.port()
        )
    } else {
        format!("http://{}", proxy.address)
    }
}

async fn resolve_upstream_endpoints(upstream: &Url) -> io::Result<(Vec<SocketAddr>, bool)> {
    let host = upstream
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream URL has no host"))?;
    let port = upstream.port_or_known_default().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream URL has no effective port",
        )
    })?;
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok((vec![SocketAddr::new(address, port)], false));
    }
    let resolved = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream DNS lookup timed out"))??;
    let mut unique = BTreeSet::new();
    let mut truncated = false;
    for address in resolved {
        if unique.len() >= MAX_UPSTREAM_ENDPOINTS && !unique.contains(&address) {
            truncated = true;
            continue;
        }
        unique.insert(address);
    }
    if unique.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "upstream DNS lookup returned no addresses",
        ));
    }
    Ok((unique.into_iter().collect(), truncated))
}

async fn import_session(reader: Option<SessionReader>, store: &RunStore) {
    let Some(reader) = reader else {
        return;
    };
    match reader.import(store).await {
        Ok(report) => {
            let evidence_losses = report
                .omitted_records
                .saturating_add(report.malformed_records)
                .saturating_add(report.incomplete_tails);
            if report.limit_reached || evidence_losses > 0 {
                store.note_capture_drops(evidence_losses.max(1));
            }
            let mut event = store.event("session", "session_import_finished");
            event.terminal_state = Some(TerminalState::Complete);
            event.normalized = serde_json::to_value(report).ok();
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(error) => {
            store.note_capture_drop();
            warn!(error_kind = ?error.kind(), "agent session import failed");
            let mut event = store.event("session", "session_import_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(json!({"error_kind": error.kind().to_string()}));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

fn mark_failed_manifest(run_dir: &std::path::Path, encryption: Option<&EncryptionKey>) {
    let path = run_dir.join("manifest.json");
    let Ok(mut manifest) = crate::manifest::read(&path) else {
        return;
    };
    if manifest.verify_authentication(encryption).is_err() {
        return;
    }
    if manifest.status == "running" {
        "recorder_error".clone_into(&mut manifest.status);
        manifest.finished_at = Some(chrono::Utc::now());
        manifest.coverage.known_gaps.push(
            "recorder exited before clean finalization; inspect durable events before relying on counts"
                .to_owned(),
        );
        let _ = write_atomic_authenticated(&path, &manifest, encryption);
    }
}

async fn finalize_failed_run(
    run_dir: &std::path::Path,
    encryption: Option<&EncryptionKey>,
    store: &RunStore,
    services: RuntimeServices,
    exit_code: i32,
    event_name: &str,
) {
    let mut event = store.event("runner", event_name);
    event.terminal_state = Some(TerminalState::Error);
    event.normalized = Some(opaque_error_metadata(event_name));
    if store.append(event).await.is_err() {
        store.note_capture_drop();
    }
    services.stop_all(store).await;
    let mut finished = store.event("runner", "run_finished");
    finished.terminal_state = Some(TerminalState::Error);
    finished.normalized = Some(json!({"exit_code": exit_code, "reason": event_name}));
    if store.append(finished).await.is_err() {
        store.note_capture_drop();
    }
    let capture_drops = store
        .shutdown()
        .await
        .map_or_else(|_| store.stats().capture_drops, |stats| stats.capture_drops);
    let _ = finalize_manifest(run_dir, exit_code, capture_drops, encryption);
}

async fn terminate_target(child: &mut tokio::process::Child, pid: u32) -> bool {
    let _ = forward_signal(pid, Signal::SIGKILL);
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await,
        Ok(Ok(_))
    )
}

async fn wait_for_target_stop(child: &mut tokio::process::Child, pid: u32) -> io::Result<()> {
    const BARRIER_TIMEOUT: Duration = Duration::from_secs(2);
    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    let deadline = tokio::time::Instant::now() + BARRIER_TIMEOUT;
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    loop {
        if child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "target exited before entering its launch barrier",
            ));
        }
        if let Ok(status) = std::fs::read_to_string(&status_path)
            && status.lines().any(|line| {
                line.strip_prefix("State:").is_some_and(|state| {
                    matches!(state.trim().as_bytes().first(), Some(b'T' | b't'))
                })
            })
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "target did not enter its launch barrier before the deadline",
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn inject_provider_environment(
    command: &mut Command,
    selected: ProviderSelection,
    detected_agent: Option<&str>,
    proxy_url: &str,
) {
    let resolved = match selected {
        ProviderSelection::Auto => match detected_agent {
            Some("claude-code") => ProviderSelection::Anthropic,
            Some("gemini-cli") => ProviderSelection::Gemini,
            Some("hermes" | "codex") => ProviderSelection::Openai,
            _ => ProviderSelection::None,
        },
        explicit => explicit,
    };
    match resolved {
        ProviderSelection::Openai => {
            command.env(
                "OPENAI_BASE_URL",
                format!("{}/v1", proxy_url.trim_end_matches('/')),
            );
        }
        ProviderSelection::Anthropic => {
            command.env("ANTHROPIC_BASE_URL", proxy_url);
        }
        ProviderSelection::Gemini => {
            command.env("GOOGLE_GEMINI_BASE_URL", proxy_url);
        }
        ProviderSelection::Auto | ProviderSelection::None => {}
    }
}

#[cfg(test)]
fn merge_node_options_with_tls_keylog(
    command: &[OsString],
    existing: &std::ffi::OsStr,
    keylog_path: &std::path::Path,
) -> Result<OsString> {
    merge_node_options(command, existing, Some(keylog_path), None)
}

fn node_options_with_instrumentation(
    command: &[OsString],
    keylog_path: Option<&std::path::PathBuf>,
    node_injection: Option<&NodeInjection>,
) -> Result<OsString> {
    let preload = node_injection
        .map(NodeInjection::node_option)
        .transpose()
        .context("construct Node.js preload option")?;
    merge_node_options(
        command,
        &std::env::var_os("NODE_OPTIONS").unwrap_or_default(),
        keylog_path.map(PathBuf::as_path),
        preload.as_deref(),
    )
}

fn merge_node_options(
    command: &[OsString],
    existing: &std::ffi::OsStr,
    keylog_path: Option<&std::path::Path>,
    preload: Option<&str>,
) -> Result<OsString> {
    if keylog_path.is_some() {
        anyhow::ensure!(
            !command
                .iter()
                .skip(1)
                .any(|argument| argument.to_string_lossy().starts_with("--tls-keylog")),
            "target command overrides the recorder-controlled Node TLS key-log destination"
        );
    }
    let existing = existing
        .to_str()
        .context("NODE_OPTIONS is not valid UTF-8")?;
    if keylog_path.is_some() {
        anyhow::ensure!(
            !existing.contains("--tls-keylog"),
            "NODE_OPTIONS overrides the recorder-controlled Node TLS key-log destination"
        );
    }
    let mut options = existing.trim().to_owned();
    if let Some(keylog_path) = keylog_path {
        let path = keylog_path
            .to_str()
            .context("Node TLS key-log path is not valid UTF-8")?;
        let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
        append_node_option(&mut options, &format!("--tls-keylog=\"{escaped}\""));
    }
    if let Some(preload) = preload {
        append_node_option(&mut options, preload);
    }
    Ok(OsString::from(options))
}

fn append_node_option(options: &mut String, option: &str) {
    if !options.is_empty() {
        options.push(' ');
    }
    options.push_str(option);
}

fn forward_signal(pid: u32, signal: Signal) -> Result<()> {
    let raw_pid = i32::try_from(pid).context("target PID exceeds platform range")?;
    match killpg(Pid::from_raw(raw_pid), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).context("forward signal to target process group"),
    }
}

fn opaque_error_metadata(error_kind: &str) -> serde_json::Value {
    json!({
        "error_kind": error_kind,
        "detail_persisted": false,
    })
}

fn io_error_metadata(error_kind: &str, error: &std::io::Error) -> serde_json::Value {
    json!({
        "error_kind": error_kind,
        "io_error_kind": format!("{:?}", error.kind()),
        "detail_persisted": false,
    })
}

async fn stop_proxy(proxy: Option<ProxyHandle>, store: &RunStore) {
    if let Some(proxy) = proxy {
        if let Err(error) = proxy.stop(Duration::from_secs(5)).await {
            store.note_capture_drop();
            warn!(error_kind = ?error.kind(), "proxy shutdown was not clean");
            let mut event = store.event("runner", "proxy_shutdown_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(io_error_metadata("proxy_shutdown", &error));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        } else {
            let mut event = store.event("runner", "proxy_stopped");
            event.terminal_state = Some(TerminalState::Complete);
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn cleanup_transparent(artifacts: Option<TransparentArtifacts>, store: &RunStore) {
    let Some(artifacts) = artifacts else {
        return;
    };
    let result = artifacts.cleanup();
    let mut event = store.event(
        "runner",
        if result.is_ok() {
            "transparent_interception_material_removed"
        } else {
            "transparent_interception_material_removal_error"
        },
    );
    if let Err(error) = result {
        store.note_capture_drop();
        event.terminal_state = Some(TerminalState::Error);
        event.normalized = Some(io_error_metadata("transparent_material_cleanup", &error));
    } else {
        event.terminal_state = Some(TerminalState::Complete);
        event.normalized = Some(json!({
            "private_key_persisted": false,
            "temporary_public_ca_removed": true,
            "temporary_hosts_snapshot_removed": true,
        }));
    }
    if store.append(event).await.is_err() {
        store.note_capture_drop();
    }
}

async fn stop_collector(collector: Option<CollectorHandle>, store: &RunStore) {
    let Some(collector) = collector else {
        return;
    };
    if let Err(error) = collector.stop().await {
        store.note_capture_drop();
        warn!(
            error_kind = ?error.kind(),
            "hook collector shutdown was not clean"
        );
        let mut event = store.event("runner", "collector_shutdown_error");
        event.terminal_state = Some(TerminalState::Error);
        event.normalized = Some(io_error_metadata("collector_shutdown", &error));
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    } else {
        let mut event = store.event("runner", "collector_stopped");
        event.terminal_state = Some(TerminalState::Complete);
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    }
}

async fn stop_tls_keylog(handle: Option<TlsKeyLogHandle>, store: &RunStore) {
    let Some(handle) = handle else {
        return;
    };
    if let Err(error) = handle.stop().await {
        store.note_capture_drop();
        warn!(
            error_kind = ?error.kind(),
            "TLS key-log shutdown was not clean"
        );
        let mut event = store.event("runner", "tls_key_log_shutdown_error");
        event.terminal_state = Some(TerminalState::Error);
        event.normalized = Some(io_error_metadata("tls_key_log_shutdown", &error));
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    } else {
        let mut event = store.event("runner", "tls_key_log_stopped");
        event.terminal_state = Some(TerminalState::Complete);
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    }
}

async fn seal_task_netns_target_end(
    handle: Option<&mut TaskNetnsHandle>,
    namespace_anchor_pid: Option<u32>,
    store: &RunStore,
) {
    let Some(handle) = handle else {
        return;
    };
    match handle.seal_target_end(namespace_anchor_pid).await {
        Ok(firewall_after_target) => {
            let mut event = store.event("runner", "task_network_target_window_closed");
            event.terminal_state = Some(TerminalState::Complete);
            event.normalized = Some(json!({
                "firewall_after_target": firewall_after_target,
            }));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(error) => {
            store.note_capture_drop();
            warn!(
                error_kind = ?error.kind(),
                "task-network target window could not be sealed"
            );
            let mut event = store.event("runner", "task_network_target_window_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(io_error_metadata("task_network_target_window", &error));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn stop_task_netns(
    handle: Option<TaskNetnsHandle>,
    namespace_anchor_pid: Option<u32>,
    store: &RunStore,
) {
    let Some(handle) = handle else {
        return;
    };
    match handle.stop(namespace_anchor_pid).await {
        Ok(report) => {
            let complete = report.complete();
            if !complete {
                store.note_capture_drop();
            }
            let mut event = store.event("runner", "task_network_isolation_finished");
            event.terminal_state = Some(if complete {
                TerminalState::Complete
            } else {
                TerminalState::Incomplete
            });
            event.normalized = serde_json::to_value(report).ok();
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(error) => {
            store.note_capture_drop();
            warn!(
                error_kind = ?error.kind(),
                "task-network isolation shutdown was not verifiable"
            );
            let mut event = store.event("runner", "task_network_isolation_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(io_error_metadata("task_network_isolation", &error));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn stop_pcap(handle: Option<PcapHandle>, store: &RunStore) {
    let Some(handle) = handle else {
        return;
    };
    match handle.stop().await {
        Ok(report) => {
            let complete = !report.limit_reached
                && report.packets_dropped == Some(0)
                && report.packets_missed == Some(0)
                && report.exit_success
                && !report.forced_kill
                && report.stderr_bytes_omitted == 0;
            let mut event = store.event("runner", "pcap_capture_finished");
            event.terminal_state = Some(if complete {
                TerminalState::Complete
            } else {
                TerminalState::Incomplete
            });
            event.normalized = serde_json::to_value(report).ok();
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(error) => {
            store.note_capture_drop();
            warn!(
                error_kind = ?error.kind(),
                "pcap helper shutdown was not clean"
            );
            let mut event = store.event("runner", "pcap_capture_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(io_error_metadata("pcap_capture", &error));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn stop_process_tracker(tracker: ProcessTrackerHandle, store: &RunStore) {
    if let Err(error) = tracker.stop().await {
        store.note_capture_drop();
        warn!(
            error_kind = ?error.kind(),
            "process tracker shutdown was not clean"
        );
        let mut event = store.event("runner", "process_tracker_error");
        event.terminal_state = Some(TerminalState::Error);
        event.normalized = Some(io_error_metadata("process_tracker", &error));
        if store.append(event).await.is_err() {
            store.note_capture_drop();
        }
    }
}

async fn stop_probe_helper(handle: Option<ProbeHelperHandle>, store: &RunStore) {
    let Some(handle) = handle else {
        return;
    };
    match handle.stop().await {
        Ok(report) => {
            let complete = report.complete();
            let mut event = store.event("runner", "privileged_probe_stopped");
            event.terminal_state = Some(if complete {
                TerminalState::Complete
            } else {
                TerminalState::Incomplete
            });
            event.normalized = serde_json::to_value(report).ok();
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(error) => {
            store.note_capture_drop();
            warn!(
                error_kind = ?error.kind(),
                "privileged probe helper shutdown was not clean"
            );
            let mut event = store.event("runner", "privileged_probe_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(io_error_metadata("privileged_probe", &error));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn stop_task_cgroup(cgroup: Option<TaskCgroup>, store: &RunStore) {
    let Some(cgroup) = cgroup else {
        return;
    };
    match cgroup.finish() {
        Ok(report) => persist_task_cgroup_report(store, report).await,
        Err(error) => {
            store.note_capture_drop();
            warn!(error_kind = ?error.kind(), "task cgroup cleanup was not verifiable");
            let mut event = store.event("runner", "task_cgroup_cleanup_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(io_error_metadata("task_cgroup", &error));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn persist_task_cgroup_report(store: &RunStore, report: TaskCgroupReport) {
    let complete = report.removed && report.remaining_processes == 0;
    if !complete {
        store.note_capture_drop();
    }
    let mut event = store.event("runner", "task_cgroup_stopped");
    event.terminal_state = Some(if complete {
        TerminalState::Complete
    } else {
        TerminalState::Incomplete
    });
    event.normalized = serde_json::to_value(report).ok();
    if store.append(event).await.is_err() {
        store.note_capture_drop();
    }
}

const MAX_SDK_CORRELATION_ITEMS: usize = 100_000;
const MAX_SDK_CORRELATION_CANDIDATES: usize = 1_024;

async fn cleanup_adapter_scratch(adapter: &mut PreparedAdapter, store: &RunStore) {
    if adapter.sdk_host().is_none() {
        return;
    }
    let result = adapter.close_scratch();
    if result.is_err() {
        store.note_capture_drop();
    }
    let mut event = store.event("runner", "adapter_scratch_removed");
    event.terminal_state = Some(if result.is_ok() {
        TerminalState::Complete
    } else {
        TerminalState::Error
    });
    event.normalized = Some(json!({
        "removed": result.is_ok(),
        "detail_persisted": false,
    }));
    if store.append(event).await.is_err() {
        store.note_capture_drop();
    }
}

async fn derive_adapter_correlations(
    adapter: Option<&AdapterHost>,
    run_dir: &std::path::Path,
    encryption: Option<&EncryptionKey>,
    store: &RunStore,
) {
    let Some(adapter) = adapter else {
        return;
    };
    match derive_adapter_correlations_inner(adapter, run_dir, encryption, store).await {
        Ok((resolved, unresolved)) => {
            let mut event = store.event("runner", "adapter_correlation_finished");
            event.terminal_state = Some(TerminalState::Complete);
            event.normalized = Some(json!({
                "adapter": adapter.name(),
                "adapter_release": adapter.adapter_release(),
                "resolved": resolved,
                "unresolved": unresolved,
            }));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(_error) => {
            store.note_capture_drop();
            warn!("third-party adapter correlation failed");
            let mut event = store.event("runner", "adapter_correlation_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(opaque_error_metadata("adapter_correlation"));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

async fn derive_adapter_correlations_inner(
    adapter: &AdapterHost,
    run_dir: &std::path::Path,
    encryption: Option<&EncryptionKey>,
    store: &RunStore,
) -> Result<(u64, u64)> {
    store.flush().await?;
    let adapter_source = format!("adapter:{}", adapter.name());
    let mut anchors = Vec::<EventEnvelope>::new();
    let mut transports = Vec::<EventEnvelope>::new();
    for_each_run_event_with_key(
        &run_dir.join("events.jsonl"),
        store.run_id(),
        encryption,
        |event| {
            if event.source == adapter_source && event.event != "adapter_correlation" {
                anchors.push(event.clone());
            }
            if event.source == "proxy" && event.event == "logical_inference_request" {
                transports.push(event);
            }
            if anchors.len() > MAX_SDK_CORRELATION_ITEMS {
                return Err(StorageError::AnalysisLimitExceeded {
                    operation: "adapter SDK correlation anchor index",
                    limit: MAX_SDK_CORRELATION_ITEMS,
                });
            }
            if transports.len() > MAX_SDK_CORRELATION_ITEMS {
                return Err(StorageError::AnalysisLimitExceeded {
                    operation: "adapter SDK correlation transport index",
                    limit: MAX_SDK_CORRELATION_ITEMS,
                });
            }
            Ok(())
        },
    )?;
    transports.sort_by_key(|event| (event.wall_time, event.sequence));
    let mut transports_by_inference = BTreeMap::<String, Vec<usize>>::new();
    for (index, event) in transports.iter().enumerate() {
        if let Some(inference_id) = event.ids.inference_id.as_ref() {
            transports_by_inference
                .entry(inference_id.clone())
                .or_default()
                .push(index);
        }
    }

    let mut resolved = 0_u64;
    let mut unresolved = 0_u64;
    for anchor in anchors {
        let (candidates, candidates_truncated) =
            sdk_correlation_candidates(&anchor, &transports, &transports_by_inference);
        let parsed = ParsedEvent {
            event: anchor.event.clone(),
            ids: anchor.ids.clone(),
            normalized: anchor.normalized.clone().unwrap_or(Value::Null),
            confidence: anchor.confidence,
            evidence: anchor.evidence.clone(),
            terminal_state: anchor.terminal_state.clone(),
        };
        let mut context = CorrelateContext::new(parsed, candidates);
        context.candidates_truncated = candidates_truncated;
        let result = adapter
            .correlate(&context)
            .context("third-party adapter correlate operation")?;
        let is_resolved = result.selected_candidate.is_some();
        if is_resolved {
            resolved = resolved.saturating_add(1);
        } else {
            unresolved = unresolved.saturating_add(1);
        }
        let mut event = store.event(&adapter_source, "adapter_correlation");
        event.ids = result.ids;
        event.confidence = Some(result.confidence);
        event.evidence = result.evidence;
        event.terminal_state = Some(if is_resolved {
            TerminalState::Complete
        } else {
            TerminalState::Incomplete
        });
        event.normalized = Some(json!({
            "anchor_sequence": anchor.sequence,
            "selected_candidate": result.selected_candidate,
            "basis": result.basis,
            "candidates_supplied": context.candidates.len(),
            "candidates_truncated": context.candidates_truncated,
            "unresolved_reason": result.unresolved_reason,
        }));
        store.append(event).await?;
    }
    Ok((resolved, unresolved))
}

fn sdk_correlation_candidates(
    anchor: &EventEnvelope,
    transports: &[EventEnvelope],
    transports_by_inference: &BTreeMap<String, Vec<usize>>,
) -> (Vec<CorrelationCandidate>, bool) {
    let mut selected = BTreeSet::new();
    if let Some(inference_id) = anchor.ids.inference_id.as_ref()
        && let Some(exact) = transports_by_inference.get(inference_id)
    {
        selected.extend(exact.iter().copied().take(MAX_SDK_CORRELATION_CANDIDATES));
    }
    let pivot = transports.partition_point(|event| event.wall_time <= anchor.wall_time);
    let mut left = pivot.checked_sub(1);
    let mut right = pivot;
    while selected.len() < MAX_SDK_CORRELATION_CANDIDATES
        && (left.is_some() || right < transports.len())
    {
        let take_left = match (left, transports.get(right)) {
            (Some(left_index), Some(right_event)) => {
                let left_distance = anchor
                    .wall_time
                    .signed_duration_since(transports[left_index].wall_time)
                    .num_milliseconds()
                    .unsigned_abs();
                let right_distance = right_event
                    .wall_time
                    .signed_duration_since(anchor.wall_time)
                    .num_milliseconds()
                    .unsigned_abs();
                left_distance <= right_distance
            }
            (Some(_), None) => true,
            (None, _) => false,
        };
        let index = if take_left {
            let index = left.expect("left candidate exists when selected");
            left = index.checked_sub(1);
            index
        } else {
            let index = right;
            right = right.saturating_add(1);
            index
        };
        selected.insert(index);
    }
    let mut selected: Vec<usize> = selected.into_iter().collect();
    selected.sort_by_key(|index| transports[*index].sequence);
    let candidates = selected
        .into_iter()
        .map(|index| {
            let event = &transports[index];
            CorrelationCandidate {
                candidate_id: event.event_id.to_string(),
                source: event.source.clone(),
                event: event.event.clone(),
                ids: event.ids.clone(),
                observed_at: event.wall_time,
            }
        })
        .collect::<Vec<_>>();
    let truncated = candidates.len() < transports.len();
    (candidates, truncated)
}

async fn derive_correlations(
    run_dir: &std::path::Path,
    encryption: Option<&EncryptionKey>,
    store: &RunStore,
) {
    match correlation::derive(store, run_dir, encryption).await {
        Ok(report) => {
            let mut event = store.event("runner", "correlation_finished");
            event.terminal_state = Some(TerminalState::Complete);
            event.normalized = serde_json::to_value(report).ok();
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
        Err(error) => {
            store.note_capture_drop();
            warn!(
                error_kind = error.category(),
                "cross-source correlation failed"
            );
            let mut event = store.event("runner", "correlation_error");
            event.terminal_state = Some(TerminalState::Error);
            event.normalized = Some(opaque_error_metadata("correlation"));
            if store.append(event).await.is_err() {
                store.note_capture_drop();
            }
        }
    }
}

fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn launch_barrier_observes_stopped_target_before_release() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("kill -STOP $$ || exit 125; exec /bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn().expect("spawn launch-barrier target");
        let pid = child.id().expect("child pid");

        wait_for_target_stop(&mut child, pid)
            .await
            .expect("observe stopped target");
        forward_signal(pid, Signal::SIGCONT).expect("release stopped target");

        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("released target must exit before timeout")
            .expect("wait for released target");
        assert!(status.success());
    }

    #[test]
    fn persisted_diagnostics_never_copy_error_messages() {
        let secret = "Bearer diagnostic-secret-canary";
        let error = std::io::Error::other(secret);
        let safe = io_error_metadata("service_shutdown", &error).to_string();
        assert!(safe.contains("service_shutdown"));
        assert!(safe.contains("detail_persisted"));
        assert!(!safe.contains(secret));
        assert_eq!(
            opaque_error_metadata("setup_failed")["detail_persisted"],
            false
        );
    }

    #[test]
    fn node_tls_options_preserve_existing_flags_and_quote_the_fifo() {
        let command = vec![OsString::from("node"), OsString::from("agent.js")];
        assert_eq!(
            merge_node_options_with_tls_keylog(
                &command,
                std::ffi::OsStr::new(""),
                std::path::Path::new("/tmp/iorec keylog.pipe"),
            )
            .unwrap()
            .to_string_lossy(),
            "--tls-keylog=\"/tmp/iorec keylog.pipe\""
        );

        let conflicting = vec![
            OsString::from("node"),
            OsString::from("--tls-keylog=other"),
            OsString::from("agent.js"),
        ];
        assert!(
            merge_node_options_with_tls_keylog(
                &conflicting,
                std::ffi::OsStr::new(""),
                std::path::Path::new("/tmp/keylog"),
            )
            .is_err()
        );

        assert_eq!(
            merge_node_options(
                &command,
                std::ffi::OsStr::new("--trace-warnings"),
                Some(std::path::Path::new("/tmp/keylog")),
                Some("--require=\"/tmp/iorec preload.cjs\""),
            )
            .unwrap()
            .to_string_lossy(),
            "--trace-warnings --tls-keylog=\"/tmp/keylog\" --require=\"/tmp/iorec preload.cjs\""
        );
    }

    #[test]
    fn sdk_candidate_bound_keeps_an_exact_id_and_reports_truncation() {
        let base = chrono::Utc::now();
        let mut transports = Vec::new();
        for index in 0..=MAX_SDK_CORRELATION_CANDIDATES {
            let mut pending =
                crate::model::PendingEvent::new("run-sdk", "proxy", "logical_inference_request");
            pending.observed_at = base
                + chrono::TimeDelta::milliseconds(i64::try_from(index).expect("bounded index"));
            pending.ids.inference_id = Some(if index == MAX_SDK_CORRELATION_CANDIDATES {
                "exact-id".to_owned()
            } else {
                format!("other-{index}")
            });
            transports.push(EventEnvelope::from_pending(
                u64::try_from(index + 1).expect("bounded sequence"),
                pending,
            ));
        }
        let mut anchor_pending =
            crate::model::PendingEvent::new("run-sdk", "adapter:fixture", "BeforeModel");
        anchor_pending.observed_at = base;
        anchor_pending.ids.inference_id = Some("exact-id".to_owned());
        let anchor = EventEnvelope::from_pending(2_000, anchor_pending);
        let mut by_inference = BTreeMap::<String, Vec<usize>>::new();
        for (index, event) in transports.iter().enumerate() {
            by_inference
                .entry(event.ids.inference_id.clone().expect("fixture ID"))
                .or_default()
                .push(index);
        }

        let exact_event_id = transports[MAX_SDK_CORRELATION_CANDIDATES]
            .event_id
            .to_string();
        let (candidates, truncated) =
            sdk_correlation_candidates(&anchor, &transports, &by_inference);
        assert_eq!(candidates.len(), MAX_SDK_CORRELATION_CANDIDATES);
        assert!(truncated);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.candidate_id == exact_event_id)
        );
    }
}
