use std::{
    ffi::OsString,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use iorec::{
    adapter::AdapterSelection,
    artifact_export::{ArtifactKind, export_sensitive_artifact},
    audit,
    blob_keys::BlobClass,
    collector,
    control::{CollectorOptions, apply_new_run_config, run_collector},
    crypto::EncryptionKey,
    discovery::discover_command,
    doctor,
    egress::EgressRuleSpec,
    export::export_raw_with_key,
    fake_server::{FakeServerConfig, start as start_fake_server},
    inspect::{inspect_run_with_key, repair_run_with_key},
    migration::migrate_run,
    openinference::export_openinference_with_key,
    otlp::export_otlp_with_key,
    platform_export::export_platform_bundle_with_key,
    policy::{BodyCaptureMode, CapturePolicy, EventLogFormat},
    probe_plan::{self, ProbePlan, ProbePlannerConfig},
    probe_policy::{inspect_explicit_helper, select_probe_helper},
    replay::export_replay_with_key,
    retention::{BlobClassTtlPolicy, erase_blob_class, expire_blob_classes, prune_runs},
    runner::{ProviderSelection, RunOptions, run},
    runtime_injection::PythonInjection,
    state::analyze_with_key as analyze_state,
    tasks::load_with_key as load_tasks,
    timeline::{
        DEFAULT_TIMELINE_PAGE_SIZE, TimelineFilter, load_page_with_key as load_timeline_page,
    },
    transport_audit::audit_transport,
    upload::{UploadOptions, upload_run},
    verify::{VerificationProfile, verify_run_with_key},
};
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "iorec", version, about = "Agent inference flight recorder")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Record one command and transparently preserve its exit semantics.
    Run(RunArgs),
    /// Start the controllable OpenAI/Anthropic-compatible test server.
    FakeServer(FakeServerArgs),
    /// Report capture prerequisites without changing system state.
    Doctor(DoctorArgs),
    /// Build a read-only preflight capture plan for a target command.
    Plan(PlanArgs),
    /// Summarize and optionally verify a completed or interrupted run.
    Inspect(InspectArgs),
    /// Evaluate explicit integrity, transport, or client-side coverage gates.
    Verify(VerifyArgs),
    /// Decrypt captured TLS traffic, reconstruct HTTP streams, and compare proxy bodies.
    TransportAudit(TransportAuditArgs),
    /// Show ordered runner, lifecycle, inference, and transport events.
    Timeline(TimelineArgs),
    /// List logical tasks split inside one physical capture run.
    Tasks(TasksArgs),
    /// Show the exact-cell compatibility matrix and evidence status.
    Support(SupportArgs),
    /// Show response, conversation, and cached-content state references.
    State(StateArgs),
    /// Export a validated, self-contained copy of raw evidence.
    Export(ExportArgs),
    /// Upload a finalized run with durable, idempotent resume semantics.
    Upload(UploadArgs),
    /// Run the persistent platform collector, uploader, and control executor.
    Collector(CollectorArgs),
    /// Explicitly decrypt the captured packet stream into a private pcap file.
    PcapExport(SensitiveExportArgs),
    /// Explicitly decrypt captured NSS-format TLS secrets into a private key-log file.
    TlsKeysExport(SensitiveExportArgs),
    /// Explicitly decrypt privileged-probe protocol records into a private JSONL file.
    ProbeExport(SensitiveExportArgs),
    /// Generate a new private at-rest encryption key file.
    Keygen(KeygenArgs),
    /// Isolate an incomplete final event after an unclean recorder exit.
    Recover(RecoverArgs),
    /// Preview or execute age-based deletion of finalized runs.
    Prune(PruneArgs),
    /// Irreversibly erase one encrypted evidence class from a finalized run.
    EraseClass(EraseClassArgs),
    /// Preview or apply independent body, pcap, and TLS-secret TTLs.
    ExpireClasses(ExpireClassesArgs),
    /// Verify the ordered hash chain for operational audit records.
    AuditVerify(AuditVerifyArgs),
    /// Authenticate readable legacy metadata without rewriting raw evidence.
    Migrate(MigrateArgs),
    #[command(hide = true)]
    Hook(HookArgs),
}

#[derive(Debug, Args)]
// Clap exposes independent switches here; they retain clearer validation and
// error messages as separate flags rather than an artificial state machine.
#[allow(clippy::struct_excessive_bools)]
struct RunArgs {
    /// Directory under which a unique run directory is created.
    #[arg(long, default_value = "./runs", env = "IOREC_RUNS_DIR")]
    runs_dir: PathBuf,
    /// Real provider base URL. When absent, only runner lifecycle is recorded.
    #[arg(long)]
    upstream: Option<Url>,
    /// Require HTTP/2 for the upstream connection (including h2c test servers).
    #[arg(long, requires = "upstream")]
    upstream_http2_prior_knowledge: bool,
    /// Loopback proxy address. Port zero asks the OS for an unused port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Provider endpoint environment variable to inject into the target.
    #[arg(long, value_enum, default_value_t = ProviderSelection::Auto)]
    provider: ProviderSelection,
    /// Agent-specific ephemeral configuration and lifecycle hooks.
    #[arg(long, value_enum, default_value_t = AdapterSelection::Auto)]
    adapter: AdapterSelection,
    /// Whether request and response bodies are persisted.
    #[arg(long, value_enum, default_value_t = BodyModeArg::Full)]
    body: BodyModeArg,
    /// Maximum captured body bytes per request or response.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_body_bytes: u64,
    /// Maximum physical bytes retained in the append-only event log.
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024)]
    max_event_storage_bytes: u64,
    /// Physical event-log framing. zstd-blocks compresses before optional encryption.
    #[arg(long, value_enum, default_value_t = EventLogFormatArg::Jsonl)]
    event_log_format: EventLogFormatArg,
    /// Maximum physical blob-store bytes retained across the whole run.
    #[arg(long, default_value_t = 2 * 1024 * 1024 * 1024)]
    max_run_blob_storage_bytes: u64,
    /// 0600 file containing 32 raw bytes or 64 hex characters.
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
    /// Explicitly permit plaintext evidence at rest when no key file is supplied.
    #[arg(long, conflicts_with = "key_file")]
    allow_plaintext: bool,
    /// Capture NSS-format target and recorder-upstream TLS secrets (requires --key-file).
    #[arg(long)]
    tls_keylog: bool,
    /// Capture a launch-time snapshot of configured upstream endpoints into encrypted blobs.
    #[arg(long)]
    pcap: bool,
    /// Maximum encrypted pcap plaintext bytes retained for this run.
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    pcap_max_bytes: u64,
    /// Place the stopped target and inherited descendants in a new delegated cgroup-v2 child.
    #[arg(long)]
    task_cgroup: bool,
    /// Run the target in a rootless proxy-only network namespace and capture that task egress.
    #[arg(long, requires_all = ["upstream", "pcap"])]
    task_netns: bool,
    /// Intercept the original model socket inside --task-netns without endpoint rewrites.
    #[arg(long, requires = "task_netns")]
    transparent_proxy: bool,
    /// Classify an exact launch-time HOST:PORT snapshot as auth, telemetry, update, or other.
    #[arg(
        long = "egress-rule",
        value_name = "CLASS=HOST:PORT",
        conflicts_with = "task_netns"
    )]
    egress_rules: Vec<EgressRuleSpec>,
    /// Inject a bounded fail-open `OpenAI` SDK observer through Python sitecustomize.
    #[arg(long)]
    python_inject: bool,
    /// Inject bounded fail-open `OpenAI`, fetch, and undici observers through `NODE_OPTIONS`.
    #[arg(long)]
    node_inject: bool,
    /// Versioned privileged capture helper (requires --key-file).
    #[arg(long, conflicts_with = "probe_policy")]
    probe_helper: Option<PathBuf>,
    /// Trusted JSON policy for fingerprint-driven privileged-helper selection.
    #[arg(long, conflicts_with = "probe_helper")]
    probe_policy: Option<PathBuf>,
    /// Only capture bodies for paths with one of these prefixes.
    #[arg(long)]
    allow_path: Vec<String>,
    /// Target command and arguments.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BodyModeArg {
    Full,
    MetadataOnly,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EventLogFormatArg {
    Jsonl,
    ZstdBlocks,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BlobClassArg {
    Body,
    Pcap,
    TlsSecrets,
}

impl From<BlobClassArg> for BlobClass {
    fn from(value: BlobClassArg) -> Self {
        match value {
            BlobClassArg::Body => Self::Body,
            BlobClassArg::Pcap => Self::Pcap,
            BlobClassArg::TlsSecrets => Self::TlsSecrets,
        }
    }
}

impl From<EventLogFormatArg> for EventLogFormat {
    fn from(value: EventLogFormatArg) -> Self {
        match value {
            EventLogFormatArg::Jsonl => Self::Jsonl,
            EventLogFormatArg::ZstdBlocks => Self::ZstdBlocks,
        }
    }
}

#[derive(Debug, Args)]
struct FakeServerArgs {
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
// These switches describe independent candidate capabilities; keeping them as
// flags makes the read-only plan command mirror `run` and preserves Clap's
// per-flag validation.
#[allow(clippy::struct_excessive_bools)]
struct PlanArgs {
    /// Real provider base URL; enables the endpoint-proxy candidate.
    #[arg(long)]
    upstream: Option<Url>,
    /// Plan for an HTTP/2 prior-knowledge upstream.
    #[arg(long, requires = "upstream")]
    upstream_http2_prior_knowledge: bool,
    /// Select the NSS TLS key-log candidate.
    #[arg(long)]
    tls_keylog: bool,
    /// Select the filtered packet-capture candidate.
    #[arg(long)]
    pcap: bool,
    /// Select the Python runtime observer candidate.
    #[arg(long, conflicts_with = "node_inject")]
    python_inject: bool,
    /// Select the Node.js runtime observer candidate.
    #[arg(long, conflicts_with = "python_inject")]
    node_inject: bool,
    /// Select and validate a privileged-helper bridge candidate.
    #[arg(long, conflicts_with = "probe_policy")]
    probe_helper: Option<PathBuf>,
    /// Evaluate a trusted automatic probe-selection policy without launching the target.
    #[arg(long, conflicts_with = "probe_helper")]
    probe_policy: Option<PathBuf>,
    /// Include the cgroup-v2 task-boundary selection.
    #[arg(long)]
    task_cgroup: bool,
    /// Select rootless proxy-only task network isolation.
    #[arg(long, requires_all = ["upstream", "pcap"])]
    task_netns: bool,
    /// Include rootless transparent model-socket interception in the plan.
    #[arg(long, requires = "task_netns")]
    transparent_proxy: bool,
    #[arg(long)]
    json: bool,
    /// Target command and arguments; it is inspected but never executed.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct InspectArgs {
    run: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    verify_blobs: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    run: PathBuf,
    #[arg(long, value_enum, default_value_t = VerificationProfile::Integrity)]
    profile: VerificationProfile,
    #[arg(long)]
    json: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TransportAuditArgs {
    /// Finalized encrypted run containing both pcap and TLS key-log artifacts.
    run: PathBuf,
    /// New private JSON report path outside the source run.
    #[arg(long)]
    output: PathBuf,
    /// Required key for authenticating and decrypting the source run.
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: PathBuf,
    /// Maximum `TShark` decode time in seconds.
    #[arg(
        long,
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct TimelineArgs {
    run: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    task: Option<String>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    turn: Option<String>,
    #[arg(long)]
    inference: Option<String>,
    #[arg(long)]
    after_sequence: Option<u64>,
    #[arg(long, default_value_t = DEFAULT_TIMELINE_PAGE_SIZE)]
    limit: usize,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TasksArgs {
    run: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SupportArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StateArgs {
    run: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ExportArgs {
    run: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ExportFormatArg::Raw)]
    format: ExportFormatArg,
}

#[derive(Debug, Args)]
struct UploadArgs {
    /// Finalized run directory or its manifest.json.
    run: PathBuf,
    /// Platform API origin. Paths, user information, queries, and fragments are rejected.
    #[arg(long, env = "IOREC_PLATFORM_API")]
    api: Url,
    /// Private 0600 file containing a project or collector token.
    #[arg(long, env = "IOREC_PLATFORM_TOKEN_FILE")]
    token_file: PathBuf,
    /// Key for an encrypted local run.
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
    /// Explicitly permit a plaintext HTTP platform connection.
    #[arg(long)]
    allow_http: bool,
    /// Retry transient network, 408, 425, 429, and selected 5xx failures for this many seconds.
    #[arg(long, default_value_t = 900)]
    retry_seconds: u64,
    /// Upload at most this many new batches, leaving the recording resumable and open.
    #[arg(long)]
    max_batches: Option<std::num::NonZeroUsize>,
}

#[derive(Debug, Args)]
struct CollectorArgs {
    /// Directory containing local run-* recordings and private collector state.
    #[arg(long, default_value = "./runs", env = "IOREC_RUNS_DIR")]
    runs_dir: PathBuf,
    /// Platform API origin. HTTPS is required outside explicitly controlled tests.
    #[arg(long, env = "IOREC_PLATFORM_API")]
    api: Url,
    /// Private 0600 file containing the project registration credential.
    #[arg(long, env = "IOREC_PLATFORM_TOKEN_FILE")]
    token_file: PathBuf,
    /// Key used to authenticate encrypted recordings before upload or deletion.
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
    /// Explicitly permit plaintext HTTP for a controlled local platform.
    #[arg(long)]
    allow_http: bool,
    /// Permit platform requests and accepted TTL policy to delete fully uploaded runs.
    #[arg(long)]
    allow_remote_delete: bool,
    /// Retry transient network and service failures within each operation.
    #[arg(long, default_value_t = 30)]
    retry_seconds: u64,
    /// Long-poll duration; the daemon still heartbeats at least every 30 seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(0..=60))]
    poll_seconds: u64,
    /// Local upper bound that remote configuration can only reduce.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    local_max_body_bytes: u64,
    /// Seal an active Recording segment after this much logical event/blob evidence.
    #[arg(long, default_value_t = 64 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..))]
    segment_max_bytes: u64,
    /// Seal an active Recording segment after this wall-clock age.
    #[arg(long, default_value_t = 15 * 60, value_parser = clap::value_parser!(u64).range(1..=86400))]
    segment_max_seconds: u64,
    /// Perform one non-blocking scheduler/control cycle and exit.
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormatArg {
    Raw,
    Platform,
    Openinference,
    Otlp,
    Replay,
}

#[derive(Debug, Args)]
struct SensitiveExportArgs {
    run: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: PathBuf,
}

#[derive(Debug, Args)]
struct KeygenArgs {
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    run: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct PruneArgs {
    /// Directory containing immediate run-* children.
    #[arg(long, default_value = "./runs", env = "IOREC_RUNS_DIR")]
    runs_dir: PathBuf,
    /// Select runs finalized at least this many days ago.
    #[arg(long)]
    older_than_days: u64,
    /// Actually delete eligible runs; omission is a non-destructive preview.
    #[arg(long)]
    execute: bool,
    /// Key used to authenticate encrypted manifests before deletion.
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct EraseClassArgs {
    /// Finalized class-keyed encrypted run.
    run: PathBuf,
    #[arg(long, value_enum)]
    class: BlobClassArg,
    /// Required second confirmation for this irreversible operation.
    #[arg(long)]
    execute: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ExpireClassesArgs {
    #[arg(long, default_value = "./runs", env = "IOREC_RUNS_DIR")]
    runs_dir: PathBuf,
    /// Erase body blobs from runs finalized at least this many hours ago.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    body_ttl_hours: Option<u64>,
    /// Erase pcap blobs from runs finalized at least this many hours ago.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pcap_ttl_hours: Option<u64>,
    /// Erase TLS-secret blobs from runs finalized at least this many hours ago.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    tls_secrets_ttl_hours: Option<u64>,
    /// Apply eligible erasures; omission is a non-destructive preview.
    #[arg(long)]
    execute: bool,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AuditVerifyArgs {
    #[arg(long, default_value = "./runs", env = "IOREC_RUNS_DIR")]
    runs_dir: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MigrateArgs {
    run: PathBuf,
    #[arg(long, env = "IOREC_KEY_FILE")]
    key_file: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HookArgs {
    #[arg(long)]
    source: String,
    #[arg(long, default_value = "auto")]
    event: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    match Box::pin(execute(Cli::parse())).await {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err(error) => {
            eprintln!("iorec: {}", safe_error_summary(&error));
            ExitCode::FAILURE
        }
    }
}

fn safe_error_summary(error: &anyhow::Error) -> String {
    const MAX_ERROR_SUMMARY_CHARS: usize = 512;
    const SENSITIVE_MARKERS: &[&str] = &[
        "://",
        "authorization",
        "bearer ",
        "api-key",
        "api_key",
        "cookie",
        "password",
        "secret",
        "token",
        "sk-",
    ];
    let message = error.to_string();
    let lowercase = message.to_ascii_lowercase();
    if SENSITIVE_MARKERS
        .iter()
        .any(|marker| lowercase.contains(marker))
    {
        return "operation failed; sensitive diagnostic detail was suppressed".to_owned();
    }
    let mut safe = String::new();
    for character in message.chars().take(MAX_ERROR_SUMMARY_CHARS) {
        if character.is_control() {
            safe.push('�');
        } else {
            safe.push(character);
        }
    }
    if safe.is_empty() {
        "operation failed without a printable diagnostic".to_owned()
    } else {
        safe
    }
}

async fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Run(arguments) => {
            let encryption_key = load_key(arguments.key_file.as_deref())?;
            let probe_policy_selection = if let Some(policy_path) =
                arguments.probe_policy.as_deref()
            {
                anyhow::ensure!(
                    encryption_key.is_some(),
                    "--probe-policy requires --key-file so privileged evidence is encrypted before persistence"
                );
                let cwd = std::env::current_dir().context("read current directory")?;
                let command = discover_command(&arguments.command, &cwd)
                    .await
                    .context("inspect target command for automatic probe selection")?;
                Some(select_probe_helper(
                    policy_path,
                    &command,
                    &doctor::inspect(),
                    arguments.task_cgroup,
                )?)
            } else {
                None
            };
            let mut policy = CapturePolicy {
                body_mode: match arguments.body {
                    BodyModeArg::Full => BodyCaptureMode::Full,
                    BodyModeArg::MetadataOnly => BodyCaptureMode::MetadataOnly,
                },
                event_log_format: arguments.event_log_format.into(),
                max_event_storage_bytes: arguments.max_event_storage_bytes,
                max_blob_bytes: arguments.max_body_bytes,
                max_run_blob_storage_bytes: arguments.max_run_blob_storage_bytes,
                allowed_paths: arguments.allow_path,
                ..CapturePolicy::default()
            };
            apply_new_run_config(&arguments.runs_dir, &mut policy)
                .context("apply persistent collector policy to new run")?;
            let outcome = run(RunOptions {
                command: arguments.command,
                runs_dir: arguments.runs_dir,
                listen: arguments.listen,
                upstream: arguments.upstream,
                upstream_http2_prior_knowledge: arguments.upstream_http2_prior_knowledge,
                provider: arguments.provider,
                adapter: arguments.adapter,
                policy,
                encryption_key,
                allow_plaintext: arguments.allow_plaintext,
                tls_keylog: arguments.tls_keylog,
                pcap: arguments.pcap,
                pcap_max_bytes: arguments.pcap_max_bytes,
                task_cgroup: arguments.task_cgroup,
                task_netns: arguments.task_netns,
                transparent_proxy: arguments.transparent_proxy,
                egress_rules: arguments.egress_rules,
                python_inject: arguments.python_inject,
                node_inject: arguments.node_inject,
                probe_helper: arguments.probe_helper,
                probe_policy_selection,
            })
            .await?;
            eprintln!(
                "iorec: run {} saved to {}",
                outcome.run_id,
                terminal_path(&outcome.run_dir)
            );
            Ok(outcome.exit_code)
        }
        Commands::FakeServer(arguments) => {
            let server = start_fake_server(FakeServerConfig {
                listen: arguments.listen,
            })
            .await?;
            println!("http://{}", server.address);
            tokio::signal::ctrl_c().await?;
            server.stop().await?;
            Ok(0)
        }
        Commands::Doctor(arguments) => {
            let report = doctor::inspect();
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                doctor::write_human(&report, std::io::stdout())?;
            }
            Ok(0)
        }
        Commands::Plan(arguments) => {
            let cwd = std::env::current_dir().context("read current directory")?;
            let command = discover_command(&arguments.command, &cwd)
                .await
                .context("inspect target command")?;
            anyhow::ensure!(
                !arguments.python_inject || command.runtime.as_deref() == Some("python"),
                "--python-inject requires a passively detected Python target"
            );
            if arguments.python_inject {
                PythonInjection::validate_command(&arguments.command)
                    .context("validate Python runtime injection")?;
            }
            anyhow::ensure!(
                !arguments.node_inject || command.runtime.as_deref() == Some("node"),
                "--node-inject requires a passively detected Node.js target; Bun binaries do not honor this mechanism"
            );
            let doctor = doctor::inspect();
            let helper_selection = if let Some(policy_path) = arguments.probe_policy.as_deref() {
                Some(select_probe_helper(
                    policy_path,
                    &command,
                    &doctor,
                    arguments.task_cgroup,
                )?)
            } else {
                arguments
                    .probe_helper
                    .as_deref()
                    .map(inspect_explicit_helper)
                    .transpose()
                    .context("validate privileged probe helper")?
            };
            let plan = ProbePlan::build(
                &command,
                &ProbePlannerConfig {
                    endpoint_proxy: arguments.upstream.is_some(),
                    http2_prior_knowledge: arguments.upstream_http2_prior_knowledge,
                    tls_keylog: arguments.tls_keylog,
                    pcap: arguments.pcap,
                    python_injection: arguments.python_inject,
                    node_injection: arguments.node_inject,
                    privileged_helper: helper_selection.is_some(),
                    helper_selection: helper_selection
                        .as_ref()
                        .map(|selection| selection.evidence().clone()),
                    task_cgroup: arguments.task_cgroup,
                    task_netns: arguments.task_netns,
                    transparent_proxy: arguments.transparent_proxy,
                },
                &doctor,
            );
            plan.validate().map_err(anyhow::Error::msg)?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                probe_plan::write_human(&plan, std::io::stdout())?;
            }
            Ok(0)
        }
        Commands::Inspect(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let inspection = inspect_run_with_key(&run_dir, arguments.verify_blobs, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "inspect",
                "complete",
                &inspection.manifest.run_id,
                Some(serde_json::json!({"verify_blobs": arguments.verify_blobs})),
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&inspection)?);
            } else {
                print_inspection(&run_dir, &inspection);
            }
            Ok(
                if inspection.missing_blobs.is_empty()
                    && inspection.corrupt_blobs.is_empty()
                    && inspection.log.discarded_tail_bytes == 0
                {
                    0
                } else {
                    2
                },
            )
        }
        Commands::Verify(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let report = verify_run_with_key(&run_dir, arguments.profile, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "verify",
                "complete",
                &report.run_id,
                Some(serde_json::json!({"profile": arguments.profile})),
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("run:      {}", report.run_id);
                println!("profile:  {:?}", report.profile);
                println!("claim:    {}", report.manifest_claim);
                println!("result:   {}", if report.passed { "PASS" } else { "FAIL" });
                for check in &report.checks {
                    println!(
                        "{} {:<38} {}",
                        if check.passed { "PASS" } else { "FAIL" },
                        check.name,
                        check.detail
                    );
                }
            }
            Ok(if report.passed { 0 } else { 3 })
        }
        Commands::TransportAudit(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = EncryptionKey::from_file(&arguments.key_file)
                .context("load transport audit encryption key")?;
            let report = audit_transport(
                &run_dir,
                &arguments.output,
                &key,
                std::time::Duration::from_secs(arguments.timeout_seconds),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.complete { 0 } else { 3 })
        }
        Commands::Timeline(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let page = load_timeline_page(
                &run_dir,
                &TimelineFilter {
                    logical_task_id: arguments.task,
                    session_id: arguments.session,
                    turn_id: arguments.turn,
                    inference_id: arguments.inference,
                },
                arguments.after_sequence,
                arguments.limit,
                key.as_ref(),
            )?;
            let run_id = authenticated_run_id(&run_dir, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "timeline",
                "complete",
                &run_id,
                Some(serde_json::json!({
                    "entries": page.entries.len(),
                    "truncated": page.truncated,
                    "next_after_sequence": page.next_after_sequence,
                })),
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                for entry in page.entries {
                    let state = entry
                        .terminal_state
                        .as_ref()
                        .map(|value| format!(" [{value:?}]"))
                        .unwrap_or_default();
                    let summary = entry
                        .summary
                        .as_ref()
                        .map(|value| format!(" {value}"))
                        .unwrap_or_default();
                    println!(
                        "{:>6} {:>18} {:<10} {}{}{}",
                        entry.sequence,
                        format_elapsed(entry.elapsed_ns),
                        entry.source,
                        entry.event,
                        state,
                        summary
                    );
                }
                if let Some(sequence) = page.next_after_sequence {
                    println!("more entries available; continue with --after-sequence {sequence}");
                }
            }
            Ok(0)
        }
        Commands::Tasks(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let index = load_tasks(&run_dir, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "tasks",
                "complete",
                &index.run_id,
                Some(serde_json::json!({
                    "split_policy": index.split_policy,
                    "tasks": index.tasks.len(),
                    "unassigned_events": index.unassigned_events,
                })),
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&index)?);
            } else {
                println!("split policy: {}", index.split_policy);
                for task in index.tasks {
                    println!(
                        "{:<32} {:<13} events={} seq={}..{} sessions={}",
                        terminal_safe(&task.logical_task_id),
                        format!("{:?}", task.boundary_kind),
                        task.event_count,
                        task.first_sequence,
                        task.last_sequence,
                        task.session_ids.len(),
                    );
                }
                println!("unassigned events: {}", index.unassigned_events);
            }
            Ok(0)
        }
        Commands::Support(arguments) => {
            let matrix = iorec::support_matrix::load().map_err(anyhow::Error::msg)?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&matrix)?);
            } else {
                println!("claim policy:  {}", matrix.claim_policy);
                println!("default:       {:?}", matrix.default_status);
                for cell in matrix.cells {
                    println!(
                        "{:<40} {:<12?} {} / {} / {} / {}",
                        terminal_safe(&cell.id),
                        cell.status,
                        terminal_safe(&cell.agent),
                        terminal_safe(&cell.runtime),
                        terminal_safe(&cell.tls),
                        cell.protocols.join(","),
                    );
                }
            }
            Ok(0)
        }
        Commands::State(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let graph = analyze_state(&run_dir, key.as_ref())?;
            let run_id = authenticated_run_id(&run_dir, key.as_ref())?;
            append_run_audit(&run_dir, "state", "complete", &run_id, None)?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&graph)?);
            } else {
                for edge in &graph.edges {
                    println!("{} --{}--> {}", edge.from, edge.relation, edge.to);
                }
                if !graph.unresolved.is_empty() {
                    println!("unresolved:");
                    for reference in &graph.unresolved {
                        println!("  - {reference}");
                    }
                }
                if graph.analysis_truncated {
                    println!(
                        "state analysis truncated: {} observations omitted",
                        graph.omitted_observations
                    );
                }
            }
            Ok(if graph.unresolved_count() == 0 { 0 } else { 2 })
        }
        Commands::Export(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            match arguments.format {
                ExportFormatArg::Raw => {
                    let report = export_raw_with_key(&run_dir, &arguments.output, key.as_ref())?;
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                ExportFormatArg::Platform => {
                    let report =
                        export_platform_bundle_with_key(&run_dir, &arguments.output, key.as_ref())?;
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                ExportFormatArg::Openinference => {
                    let report =
                        export_openinference_with_key(&run_dir, &arguments.output, key.as_ref())?;
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                ExportFormatArg::Otlp => {
                    let report = export_otlp_with_key(&run_dir, &arguments.output, key.as_ref())?;
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                ExportFormatArg::Replay => {
                    let report = export_replay_with_key(&run_dir, &arguments.output, key.as_ref())?;
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
            }
            Ok(0)
        }
        Commands::Upload(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let run_id = authenticated_run_id(&run_dir, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "upload",
                "intent",
                &run_id,
                Some(
                    serde_json::json!({"api_origin": arguments.api.origin().ascii_serialization()}),
                ),
            )?;
            let report = upload_run(
                &run_dir,
                &UploadOptions {
                    api: arguments.api,
                    token_file: arguments.token_file,
                    encryption_key: key,
                    allow_http: arguments.allow_http,
                    retry_for: std::time::Duration::from_secs(arguments.retry_seconds),
                    max_batches: arguments.max_batches.map(std::num::NonZeroUsize::get),
                    collector_id: None,
                },
            )
            .await?;
            append_run_audit(
                &run_dir,
                "upload",
                "complete",
                &run_id,
                Some(serde_json::json!({
                    "recording_id": report.recording_id,
                    "acked_seq": report.acked_seq,
                    "sealed": report.sealed,
                })),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        Commands::Collector(arguments) => {
            let encryption_key = load_key(arguments.key_file.as_deref())?;
            let report = run_collector(
                CollectorOptions {
                    api: arguments.api,
                    token_file: arguments.token_file,
                    runs_dir: arguments.runs_dir,
                    encryption_key,
                    allow_http: arguments.allow_http,
                    allow_remote_delete: arguments.allow_remote_delete,
                    retry_for: std::time::Duration::from_secs(arguments.retry_seconds),
                    poll_wait: std::time::Duration::from_secs(arguments.poll_seconds),
                    local_max_body_bytes: arguments.local_max_body_bytes,
                    segment_max_logical_bytes: arguments.segment_max_bytes,
                    segment_max_age: std::time::Duration::from_secs(arguments.segment_max_seconds),
                },
                arguments.once,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        Commands::PcapExport(arguments) => export_artifact_command(&arguments, ArtifactKind::Pcap),
        Commands::TlsKeysExport(arguments) => {
            export_artifact_command(&arguments, ArtifactKind::TlsKeys)
        }
        Commands::ProbeExport(arguments) => {
            export_artifact_command(&arguments, ArtifactKind::Probe)
        }
        Commands::Keygen(arguments) => {
            let key = EncryptionKey::generate_file(&arguments.output)
                .context("generate encryption key")?;
            println!("key_id: {}", key.key_id());
            Ok(0)
        }
        Commands::Recover(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let run_id = authenticated_run_id(&run_dir, key.as_ref())?;
            append_run_audit(&run_dir, "recover", "intent", &run_id, None)?;
            let report = repair_run_with_key(&run_dir, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "recover",
                "complete",
                &run_id,
                Some(serde_json::json!({
                    "discarded_tail_bytes": report.discarded_tail_bytes,
                })),
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "recovered {} valid events; isolated {} tail bytes{}",
                    report.valid_events,
                    report.discarded_tail_bytes,
                    report
                        .quarantine
                        .as_ref()
                        .map(|path| format!(" in {}", terminal_path(path)))
                        .unwrap_or_default()
                );
            }
            Ok(0)
        }
        Commands::Prune(arguments) => {
            let key = load_key(arguments.key_file.as_deref())?;
            let days = i64::try_from(arguments.older_than_days)
                .context("--older-than-days is too large")?;
            let age = chrono::TimeDelta::try_days(days)
                .context("--older-than-days is outside the supported duration range")?;
            let cutoff = chrono::Utc::now()
                .checked_sub_signed(age)
                .context("--older-than-days is outside the supported timestamp range")?;
            let report = prune_runs(&arguments.runs_dir, cutoff, arguments.execute, key.as_ref())?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "mode:       {}",
                    if report.execute { "execute" } else { "preview" }
                );
                println!("cutoff:     {}", report.cutoff);
                println!("eligible:   {}", report.eligible.len());
                println!("skipped:    {}", report.skipped.len());
                println!("deleted:    {}", report.deleted);
                println!("reclaimed:  {} bytes", report.reclaimed_bytes);
                for candidate in &report.eligible {
                    println!(
                        "  {} {} bytes finished {}",
                        candidate.run_id, candidate.storage_bytes, candidate.finished_at
                    );
                }
                for skipped in &report.skipped {
                    eprintln!(
                        "skip {}: {}",
                        terminal_path(&skipped.path),
                        terminal_safe(&skipped.reason)
                    );
                }
            }
            Ok(0)
        }
        Commands::EraseClass(arguments) => {
            anyhow::ensure!(
                arguments.execute,
                "class erasure is irreversible; repeat with --execute after reviewing the run and class"
            );
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = EncryptionKey::from_file(&arguments.key_file)
                .context("load class-erasure encryption key")?;
            let report = erase_blob_class(&run_dir, arguments.class.into(), &key)?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("run:                    {}", report.run_id);
                println!("class:                  {}", report.class.as_str());
                println!("operation:              {}", report.operation_id);
                println!("recovered:              {}", report.recovered);
                println!("already complete:       {}", report.already_complete);
                println!("key envelope absent:    {}", report.key_envelope_absent);
                println!(
                    "ciphertext remaining:   {}",
                    report.ciphertext_files_remaining
                );
                println!("blob files erased:      {}", report.blob_files_erased);
                println!(
                    "reclaimed:              {} bytes",
                    report.blob_storage_bytes_reclaimed
                );
                println!(
                    "cryptographic erasure:  {}",
                    report.cryptographic_erasure_verified
                );
                println!("physical media erasure: not guaranteed");
                println!("caveat:                 {}", report.physical_media_caveat);
            }
            Ok(0)
        }
        Commands::ExpireClasses(arguments) => {
            let hours = |value: Option<u64>| -> Result<Option<std::time::Duration>> {
                value
                    .map(|hours| {
                        hours
                            .checked_mul(3_600)
                            .map(std::time::Duration::from_secs)
                            .context("class TTL hours overflow seconds")
                    })
                    .transpose()
            };
            let policy = BlobClassTtlPolicy {
                body: hours(arguments.body_ttl_hours)?,
                pcap: hours(arguments.pcap_ttl_hours)?,
                tls_secrets: hours(arguments.tls_secrets_ttl_hours)?,
            };
            let key = EncryptionKey::from_file(&arguments.key_file)
                .context("load class-TTL encryption key")?;
            let report = expire_blob_classes(
                &arguments.runs_dir,
                chrono::Utc::now(),
                policy,
                arguments.execute,
                &key,
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "mode:       {}",
                    if report.execute { "execute" } else { "preview" }
                );
                println!("evaluated:  {}", report.evaluated_at);
                println!("eligible:   {}", report.eligible.len());
                println!("erased:     {}", report.erased.len());
                println!("skipped:    {}", report.skipped.len());
                for candidate in &report.eligible {
                    println!(
                        "  {} {} finished {} cutoff {}",
                        candidate.run_id,
                        candidate.class.as_str(),
                        candidate.finished_at,
                        candidate.cutoff
                    );
                }
                for skipped in &report.skipped {
                    eprintln!(
                        "skip {}{}: {}",
                        terminal_path(&skipped.path),
                        skipped
                            .class
                            .map(|class| format!(" {}", class.as_str()))
                            .unwrap_or_default(),
                        terminal_safe(&skipped.reason)
                    );
                }
            }
            Ok(0)
        }
        Commands::AuditVerify(arguments) => {
            let report = audit::verify(&arguments.runs_dir)?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path:          {}", terminal_path(&report.path));
                println!("valid:         {}", report.valid);
                println!("records:       {}", report.records);
                println!("last sequence: {}", report.last_sequence);
                println!(
                    "last hash:     {}",
                    report.last_sha256.as_deref().unwrap_or("none")
                );
            }
            Ok(0)
        }
        Commands::Migrate(arguments) => {
            let run_dir = resolve_run_dir(&arguments.run)?;
            let key = load_key(arguments.key_file.as_deref())?;
            let run_id = authenticated_or_legacy_run_id(&run_dir, key.as_ref())?;
            append_run_audit(&run_dir, "migrate", "intent", &run_id, None)?;
            let report = migrate_run(&run_dir, key.as_ref())?;
            append_run_audit(
                &run_dir,
                "migrate",
                "complete",
                &report.run_id,
                Some(serde_json::json!({"changed": report.changed})),
            )?;
            if arguments.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("run:                    {}", report.run_id);
                println!("changed:                {}", report.changed);
                println!(
                    "manifest authenticated:  {}",
                    report
                        .manifest_authenticated
                        .map_or("not-applicable", |value| if value { "yes" } else { "no" })
                );
                println!("manifest schema:        {}", report.manifest_schema);
                println!("event schema:           {}", report.event_schema);
            }
            Ok(0)
        }
        Commands::Hook(arguments) => {
            use tokio::io::AsyncReadExt;

            let mut bytes = Vec::new();
            tokio::io::stdin()
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .await?;
            anyhow::ensure!(bytes.len() <= 16 * 1024 * 1024, "hook input is too large");
            iorec::input::validate_json_complexity(&bytes)?;
            let payload = if bytes.iter().all(u8::is_ascii_whitespace) {
                serde_json::json!({})
            } else {
                serde_json::from_slice(&bytes).context("parse hook JSON input")?
            };
            collector::submit_from_environment(arguments.source, arguments.event, payload).await?;
            println!("{{}}");
            Ok(0)
        }
    }
}

fn export_artifact_command(arguments: &SensitiveExportArgs, kind: ArtifactKind) -> Result<i32> {
    let run_dir = resolve_run_dir(&arguments.run)?;
    let key = EncryptionKey::from_file(&arguments.key_file).context("load encryption key")?;
    let report = export_sensitive_artifact(&run_dir, &arguments.output, &key, kind)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(0)
}

fn format_elapsed(elapsed_ns: u64) -> String {
    let whole_ms = elapsed_ns / 1_000_000;
    let fractional_ns = elapsed_ns % 1_000_000;
    format!("{whole_ms}.{fractional_ns:06}ms")
}

fn terminal_path(path: &Path) -> String {
    terminal_safe(&path.display().to_string())
}

fn terminal_safe(value: &str) -> String {
    const MAX_TERMINAL_CHARS: usize = 4_096;
    value
        .chars()
        .take(MAX_TERMINAL_CHARS)
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn load_key(path: Option<&Path>) -> Result<Option<EncryptionKey>> {
    path.map(EncryptionKey::from_file)
        .transpose()
        .context("load encryption key")
}

fn resolve_run_dir(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("resolve {}", path.display()))?;
    if path.is_file() && path.file_name().is_some_and(|name| name == "manifest.json") {
        return path
            .parent()
            .map(Path::to_path_buf)
            .context("manifest has no parent directory");
    }
    anyhow::ensure!(
        path.join("manifest.json").is_file(),
        "{} is not an iorec run",
        path.display()
    );
    Ok(path)
}

fn authenticated_run_id(run_dir: &Path, key: Option<&EncryptionKey>) -> Result<String> {
    let manifest = iorec::manifest::read(&run_dir.join("manifest.json"))?;
    manifest.verify_authentication(key)?;
    Ok(manifest.run_id)
}

fn authenticated_or_legacy_run_id(run_dir: &Path, key: Option<&EncryptionKey>) -> Result<String> {
    let manifest = iorec::manifest::read(&run_dir.join("manifest.json"))?;
    manifest.verify_authentication(key)?;
    Ok(manifest.run_id)
}

fn append_run_audit(
    run_dir: &Path,
    action: &str,
    outcome: &str,
    run_id: &str,
    details: Option<serde_json::Value>,
) -> Result<()> {
    let parent = run_dir
        .parent()
        .context("run directory has no audit root")?;
    audit::append(parent, action, outcome, run_id, details)?;
    Ok(())
}

fn print_inspection(run_dir: &Path, inspection: &iorec::inspect::Inspection) {
    let manifest = &inspection.manifest;
    println!("run:              {}", manifest.run_id);
    println!("status:           {}", manifest.status);
    println!("claim:            {}", manifest.coverage.claim);
    println!("events:           {}", manifest.counts.events);
    println!("logical tasks:    {}", manifest.counts.logical_tasks);
    println!("event bytes:      {}", manifest.counts.event_storage_bytes);
    println!("logical calls:    {}", manifest.counts.logical_inferences);
    println!("attempts:         {}", manifest.counts.transport_attempts);
    println!("complete:         {}", manifest.counts.completed_attempts);
    println!("incomplete:       {}", manifest.counts.incomplete_attempts);
    println!("input tokens:     {}", manifest.counts.input_tokens);
    println!("output tokens:    {}", manifest.counts.output_tokens);
    if !manifest.counts.models.is_empty() {
        println!("models:           {:?}", manifest.counts.models);
    }
    println!("blobs:            {}", inspection.blob_files);
    println!("missing blobs:    {}", inspection.missing_blobs.len());
    println!("corrupt blobs:    {}", inspection.corrupt_blobs.len());
    println!("erased blobs:     {}", inspection.erased_blobs.len());
    if !inspection.erased_blob_classes.is_empty() {
        println!("erased classes:   {:?}", inspection.erased_blob_classes);
    }
    if !inspection.pending_erasure_classes.is_empty() {
        println!("pending erasure:  {:?}", inspection.pending_erasure_classes);
    }
    if !inspection.pending_erasure_blobs.is_empty() {
        println!(
            "pending blobs:    {}",
            inspection.pending_erasure_blobs.len()
        );
    }
    println!(
        "model bypasses:   {}",
        manifest.coverage.model_bypass_connections
    );
    if !manifest.coverage.observed_egress_classes.is_empty() {
        println!(
            "egress classes:   {:?}",
            manifest.coverage.observed_egress_classes
        );
    }
    println!(
        "request payloads: {}",
        manifest.coverage.captured_request_payloads_complete
    );
    println!(
        "response payloads:{}",
        manifest.coverage.captured_response_payloads_complete
    );
    println!(
        "unresolved state: {}",
        manifest.coverage.unresolved_state_references
    );
    println!(
        "unresolved data:  {}",
        manifest.coverage.unresolved_payload_references
    );
    println!(
        "unresolved links: {}",
        manifest.coverage.unresolved_correlations
    );
    println!(
        "uncommitted tail: {} bytes",
        inspection.log.discarded_tail_bytes
    );
    println!("location:         {}", terminal_path(run_dir));
    if !manifest.coverage.known_gaps.is_empty() {
        println!("known gaps:");
        for gap in &manifest.coverage.known_gaps {
            println!("  - {gap}");
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use clap::Parser;

    use super::{
        BlobClassArg, Cli, Commands, EventLogFormatArg, safe_error_summary, terminal_safe,
    };

    #[test]
    fn top_level_diagnostics_suppress_credentials_and_terminal_controls() {
        let credential = anyhow::anyhow!(
            "request failed at https://user:password@example.test/v1?token=private"
        );
        let rendered = safe_error_summary(&credential);
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("password"));

        let control = anyhow::anyhow!("invalid\u{1b}[31m input");
        let rendered = safe_error_summary(&control);
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains('�'));

        let terminal = terminal_safe("name\u{1b}[31m\nnext");
        assert!(!terminal.chars().any(char::is_control));
    }

    #[test]
    fn plan_cli_keeps_target_flags_after_the_separator() {
        let cli = Cli::try_parse_from([
            "iorec",
            "plan",
            "--json",
            "--python-inject",
            "--",
            "/usr/bin/python3",
            "-I-am-target-data",
        ])
        .unwrap();
        let Commands::Plan(arguments) = cli.command else {
            panic!("expected plan command");
        };
        assert!(arguments.json);
        assert!(arguments.python_inject);
        assert_eq!(arguments.command[1], "-I-am-target-data");
    }

    #[test]
    fn automatic_probe_policy_conflicts_with_an_explicit_helper() {
        assert!(
            Cli::try_parse_from([
                "iorec",
                "run",
                "--probe-policy",
                "/etc/iorec/probe-policy.json",
                "--probe-helper",
                "/usr/local/libexec/iorec/ecapture-bridge",
                "--",
                "/bin/true",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "iorec",
            "plan",
            "--probe-policy",
            "/etc/iorec/probe-policy.json",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let Commands::Plan(arguments) = cli.command else {
            panic!("expected plan command");
        };
        assert_eq!(
            arguments.probe_policy.as_deref(),
            Some(std::path::Path::new("/etc/iorec/probe-policy.json"))
        );
    }

    #[test]
    fn run_cli_accepts_bounded_zstd_event_blocks() {
        let cli = Cli::try_parse_from([
            "iorec",
            "run",
            "--event-log-format",
            "zstd-blocks",
            "--allow-plaintext",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let Commands::Run(arguments) = cli.command else {
            panic!("expected run command");
        };
        assert!(matches!(
            arguments.event_log_format,
            EventLogFormatArg::ZstdBlocks
        ));
    }

    #[test]
    fn class_retention_cli_requires_keys_and_bounds_ttls() {
        let cli = Cli::try_parse_from([
            "iorec",
            "erase-class",
            "/tmp/run",
            "--class",
            "tls-secrets",
            "--execute",
            "--key-file",
            "/tmp/key",
        ])
        .unwrap();
        let Commands::EraseClass(arguments) = cli.command else {
            panic!("expected erase-class command");
        };
        assert!(matches!(arguments.class, BlobClassArg::TlsSecrets));
        assert!(arguments.execute);
        assert!(
            Cli::try_parse_from(["iorec", "erase-class", "/tmp/run", "--class", "body",]).is_err()
        );

        let cli = Cli::try_parse_from([
            "iorec",
            "expire-classes",
            "--body-ttl-hours",
            "24",
            "--pcap-ttl-hours",
            "2",
            "--key-file",
            "/tmp/key",
        ])
        .unwrap();
        let Commands::ExpireClasses(arguments) = cli.command else {
            panic!("expected expire-classes command");
        };
        assert_eq!(arguments.body_ttl_hours, Some(24));
        assert_eq!(arguments.pcap_ttl_hours, Some(2));
        assert!(
            Cli::try_parse_from([
                "iorec",
                "expire-classes",
                "--body-ttl-hours",
                "0",
                "--key-file",
                "/tmp/key",
            ])
            .is_err()
        );
    }

    #[test]
    fn logical_task_cli_supports_index_and_filtered_timeline() {
        let cli = Cli::try_parse_from(["iorec", "tasks", "/tmp/run", "--json"]).unwrap();
        let Commands::Tasks(arguments) = cli.command else {
            panic!("expected tasks command");
        };
        assert_eq!(arguments.run, std::path::PathBuf::from("/tmp/run"));
        assert!(arguments.json);

        let cli = Cli::try_parse_from([
            "iorec",
            "timeline",
            "/tmp/run",
            "--task",
            "task:cron-a",
            "--after-sequence",
            "42",
            "--limit",
            "100",
        ])
        .unwrap();
        let Commands::Timeline(arguments) = cli.command else {
            panic!("expected timeline command");
        };
        assert_eq!(arguments.task.as_deref(), Some("task:cron-a"));
        assert_eq!(arguments.after_sequence, Some(42));
        assert_eq!(arguments.limit, 100);

        let cli = Cli::try_parse_from(["iorec", "support", "--json"]).unwrap();
        let Commands::Support(arguments) = cli.command else {
            panic!("expected support command");
        };
        assert!(arguments.json);
    }

    #[test]
    fn transport_audit_cli_requires_a_bounded_timeout_and_key() {
        let cli = Cli::try_parse_from([
            "iorec",
            "transport-audit",
            "/tmp/run",
            "--output",
            "/tmp/report.json",
            "--key-file",
            "/tmp/key",
        ])
        .unwrap();
        let Commands::TransportAudit(arguments) = cli.command else {
            panic!("expected transport-audit command");
        };
        assert_eq!(arguments.timeout_seconds, 300);

        assert!(
            Cli::try_parse_from([
                "iorec",
                "transport-audit",
                "/tmp/run",
                "--output",
                "/tmp/report.json",
                "--key-file",
                "/tmp/key",
                "--timeout-seconds",
                "0",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "iorec",
                "transport-audit",
                "/tmp/run",
                "--output",
                "/tmp/report.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn task_network_cli_requires_upstream_and_packet_evidence() {
        let valid = Cli::try_parse_from([
            "iorec",
            "run",
            "--upstream",
            "https://provider.test",
            "--pcap",
            "--task-netns",
            "--",
            "/bin/true",
        ]);
        assert!(valid.is_ok());
        assert!(
            Cli::try_parse_from([
                "iorec",
                "run",
                "--upstream",
                "https://provider.test",
                "--pcap",
                "--task-netns",
                "--transparent-proxy",
                "--",
                "/bin/true",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iorec",
                "run",
                "--upstream",
                "https://provider.test",
                "--pcap",
                "--transparent-proxy",
                "--",
                "/bin/true",
            ])
            .is_err()
        );

        for missing in ["--upstream", "--pcap"] {
            let mut arguments = vec![
                "iorec",
                "run",
                "--upstream",
                "https://provider.test",
                "--pcap",
                "--task-netns",
                "--",
                "/bin/true",
            ];
            let position = arguments
                .iter()
                .position(|argument| *argument == missing)
                .unwrap();
            arguments.remove(position);
            if missing == "--upstream" {
                arguments.remove(position);
            }
            assert!(Cli::try_parse_from(arguments).is_err(), "missing {missing}");
        }
    }

    #[test]
    fn egress_rule_cli_is_typed_repeatable_and_conflicts_with_proxy_only_network() {
        let cli = Cli::try_parse_from([
            "iorec",
            "run",
            "--egress-rule",
            "auth=192.0.2.10:443",
            "--egress-rule",
            "telemetry=[2001:db8::10]:4318",
            "--allow-plaintext",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let Commands::Run(arguments) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(arguments.egress_rules.len(), 2);
        assert_eq!(arguments.egress_rules[0].to_string(), "auth=192.0.2.10:443");

        for invalid in ["model=192.0.2.10:443", "auth=example.test"] {
            assert!(
                Cli::try_parse_from([
                    "iorec",
                    "run",
                    "--egress-rule",
                    invalid,
                    "--allow-plaintext",
                    "--",
                    "/bin/true",
                ])
                .is_err(),
                "accepted invalid rule {invalid}"
            );
        }
        assert!(
            Cli::try_parse_from([
                "iorec",
                "run",
                "--upstream",
                "https://provider.test",
                "--pcap",
                "--task-netns",
                "--egress-rule",
                "auth=192.0.2.10:443",
                "--",
                "/bin/true",
            ])
            .is_err()
        );
    }
}
