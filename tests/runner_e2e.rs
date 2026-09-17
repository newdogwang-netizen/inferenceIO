use std::{
    ffi::OsString, net::SocketAddr, os::unix::fs::PermissionsExt, process::Stdio, time::Duration,
};

use iorec::{
    adapter::AdapterSelection,
    adapter_sdk::{
        ADAPTER_SDK_VERSION, AdapterConfiguration, AdapterHost, AdapterResult, AdapterSdk,
        ConfigureContext, CorrelateContext, Correlation, DetectContext, Detection, ParseContext,
        ParsedEvent,
    },
    artifact_export::{ArtifactKind, export_sensitive_artifact},
    crypto::EncryptionKey,
    discovery::discover_command,
    doctor,
    export::export_raw_with_key,
    fake_server::{FakeServerConfig, start as start_fake_server},
    inspect::{inspect_run, inspect_run_with_key},
    openinference::export_openinference_with_key,
    otlp::export_otlp_with_key,
    policy::{CapturePolicy, EventLogFormat},
    probe_policy::select_probe_helper,
    replay::export_replay_with_key,
    runner::{ProviderSelection, RunOptions, run, run_with_adapter},
    state::analyze_with_key,
    storage::for_each_event_with_key,
    task_netns::TaskNetnsTools,
    tasks::load_with_key as load_tasks,
    timeline::{TimelineFilter, load_with_key},
    transparent::TransparentArtifacts,
    transport_audit::audit_transport,
    verify::{VerificationProfile, verify_run_with_key},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

// These tests exercise host namespace/capture helpers and can otherwise make
// each other's short-lived process/packet observations look like real loss.
static PRIVILEGED_CAPTURE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn run_directories(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("run-"))
        })
        .collect()
}

fn derived_run_key(run_dir: &std::path::Path, master: &EncryptionKey) -> EncryptionKey {
    iorec::manifest::read(&run_dir.join("manifest.json"))
        .unwrap()
        .effective_encryption_key(Some(master))
        .unwrap()
        .unwrap()
}

struct RunnerSdkAdapter;

impl AdapterSdk for RunnerSdkAdapter {
    fn detect(&self, context: &DetectContext) -> AdapterResult<Detection> {
        Ok(if context.command[0] == std::ffi::OsStr::new("/bin/sh") {
            Detection::matched(1.0, "test shell target")
        } else {
            Detection::no_match("not the test shell target")
        })
    }

    fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
        let mut configuration = AdapterConfiguration::default();
        configuration
            .environment
            .insert(OsString::from("SDK_ADAPTER_ENABLED"), OsString::from("yes"));
        configuration
            .known_gaps
            .push("fixture hook is lifecycle-only".to_owned());
        Ok(configuration)
    }

    fn parse(&self, context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
        let mut event = ParsedEvent::new("BeforeModel", context.payload.clone());
        event.ids.inference_id = Some("sdk-inference-1".to_owned());
        event.confidence = Some(0.8);
        event.evidence.push("fixture.sdk-hook.v1".to_owned());
        Ok(vec![event])
    }

    fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
        Ok(Correlation::unresolved("no proxy candidate in fixture"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn statically_linked_adapter_sdk_configures_and_parses_a_real_run() {
    let temporary = tempfile::tempdir().unwrap();
    let master_key = EncryptionKey::new([101; 32]);
    let script = concat!(
        "test \"$SDK_ADAPTER_ENABLED\" = yes || exit 91; ",
        "printf '%s' '{\"model\":\"fixture-model\"}' | ",
        "\"$1\" hook --source fixture-sdk --event native_model_start"
    );
    let outcome = run_with_adapter(
        RunOptions {
            command: vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("sdk-target"),
                OsString::from(env!("CARGO_BIN_EXE_iorec")),
            ],
            runs_dir: temporary.path().to_path_buf(),
            listen: loopback(),
            upstream: None,
            upstream_http2_prior_knowledge: false,
            provider: ProviderSelection::None,
            adapter: AdapterSelection::Auto,
            policy: CapturePolicy::default(),
            encryption_key: Some(master_key.clone()),
            allow_plaintext: false,
            tls_keylog: false,
            pcap: false,
            pcap_max_bytes: 1024 * 1024,
            task_cgroup: false,
            task_netns: false,
            transparent_proxy: false,
            egress_rules: Vec::new(),
            python_inject: false,
            node_inject: false,
            probe_helper: None,
            probe_policy_selection: None,
        },
        AdapterHost::new(
            "fixture-sdk",
            "1.0.0",
            ADAPTER_SDK_VERSION,
            RunnerSdkAdapter,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);
    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&master_key)).unwrap();
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert!(
        inspection
            .manifest
            .coverage
            .known_gaps
            .iter()
            .any(|gap| gap == "fixture hook is lifecycle-only")
    );
    let mut native_sequence = None;
    let mut parsed_sequence = None;
    let mut correlation_seen = false;
    let run_key = derived_run_key(&outcome.run_dir, &master_key);
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |event| {
            if event.source == "hook:fixture-sdk" {
                native_sequence = Some(event.sequence);
            }
            if event.source == "adapter:fixture-sdk" && event.event == "BeforeModel" {
                assert_eq!(event.ids.inference_id.as_deref(), Some("sdk-inference-1"));
                parsed_sequence = Some(event.sequence);
            }
            if event.source == "adapter:fixture-sdk" && event.event == "adapter_correlation" {
                correlation_seen = true;
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(native_sequence.is_some());
    assert!(parsed_sequence > native_sequence);
    assert!(correlation_seen);
    assert!(
        std::fs::read_dir(&outcome.run_dir)
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".adapter-sdk-"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_forwards_sigint_and_preserves_the_target_exit_code() {
    let temporary = tempfile::tempdir().unwrap();
    let mut recorder = tokio::process::Command::new(env!("CARGO_BIN_EXE_iorec"));
    recorder
        .arg("run")
        .arg("--allow-plaintext")
        .arg("--runs-dir")
        .arg(temporary.path())
        .arg("--provider")
        .arg("none")
        .arg("--adapter")
        .arg("none")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("trap 'exit 77' INT; while :; do sleep 1; done")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut recorder = recorder.spawn().unwrap();
    let recorder_pid = recorder.id().unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let run_dir = loop {
        if let Some(path) = run_directories(temporary.path()).into_iter().next()
            && std::fs::read_to_string(path.join("events.jsonl"))
                .is_ok_and(|events| events.contains("process_started"))
        {
            break path;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "recorder did not start target in time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(recorder_pid).unwrap()),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), recorder.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    let inspection = inspect_run(&run_dir, true).unwrap();
    assert_eq!(inspection.manifest.exit_code, Some(77));
    let events = std::fs::read_to_string(run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("signal_forwarded"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signal_forwarding_preserves_exit_after_event_writer_exhaustion() {
    let temporary = tempfile::tempdir().unwrap();
    let ready = temporary.path().join("writer-exhausted");
    let script = format!(
        "trap 'exit 78' INT; n=0; while [ $n -lt 100 ]; do if ! printf '%s' '{{\"hook_event_name\":\"Test\"}}' | '{}' hook --source test-agent --event auto >/dev/null 2>&1; then break; fi; n=$((n + 1)); done; touch '{}'; while :; do sleep 1; done",
        env!("CARGO_BIN_EXE_iorec"),
        ready.display(),
    );
    let mut recorder = tokio::process::Command::new(env!("CARGO_BIN_EXE_iorec"));
    recorder
        .arg("run")
        .arg("--allow-plaintext")
        .arg("--runs-dir")
        .arg(temporary.path())
        .arg("--max-event-storage-bytes")
        .arg("4096")
        .arg("--provider")
        .arg("none")
        .arg("--adapter")
        .arg("none")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut recorder = recorder.spawn().unwrap();
    let recorder_pid = recorder.id().unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "target did not exhaust the event writer in time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let run_dir = run_directories(temporary.path())
        .into_iter()
        .next()
        .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(recorder_pid).unwrap()),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), recorder.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.code(), Some(78));
    let inspection = inspect_run(&run_dir, true).unwrap();
    assert_eq!(inspection.manifest.exit_code, Some(78));
    assert!(inspection.manifest.coverage.capture_drops > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runner_preserves_exit_code_and_finalizes_manifest() {
    let temporary = tempfile::tempdir().unwrap();
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("exit 42"),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 42);
    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(inspection.manifest.exit_code, Some(42));
    assert_eq!(inspection.manifest.status, "failed");
    assert_eq!(inspection.log.discarded_tail_bytes, 0);
    let plan = inspection.manifest.probe_plan.as_ref().unwrap();
    assert!(plan.selected.is_empty());
    assert!(!plan.independent_observer_selected);
    assert!(
        plan.limitations
            .iter()
            .any(|limitation| limitation.contains("no independent packet"))
    );
    let events = std::fs::read_to_string(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("probe_plan_created"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_egress_rule_classifies_exact_socket_without_downgrading_coverage() {
    let temporary = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(socket);
    });
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{}; /bin/sleep 1",
        endpoint.port()
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/bash"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: vec![
            format!("auth=127.0.0.1:{}", endpoint.port())
                .parse()
                .unwrap(),
        ],
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    accepted.await.unwrap();

    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(inspection.manifest.coverage.unknown_egress, 0);
    assert!(
        inspection
            .manifest
            .coverage
            .observed_egress_classes
            .get("auth")
            .is_some_and(|count| *count >= 1)
    );
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"egress:configured-launch-time-dns".to_owned())
    );
    let events = std::fs::read_to_string(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("egress_classification_snapshot"));
    assert!(events.contains("configured_egress_launch_time_dns"));
    assert!(events.contains("\"egress_rule_ids\":[1]"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn python_runtime_injection_loads_before_target_code_and_records_readiness() {
    let python = std::path::Path::new("/usr/bin/python3");
    assert!(
        python.is_file(),
        "Linux support gate requires /usr/bin/python3"
    );
    let temporary = tempfile::tempdir().unwrap();
    let fixture = temporary.path().join("fixture");
    let completions = fixture.join("openai/resources/chat/completions");
    let responses = fixture.join("openai/resources/responses");
    std::fs::create_dir_all(&completions).unwrap();
    std::fs::create_dir_all(&responses).unwrap();
    for package in [
        fixture.join("openai/__init__.py"),
        fixture.join("openai/resources/__init__.py"),
        fixture.join("openai/resources/chat/__init__.py"),
        completions.join("__init__.py"),
        responses.join("__init__.py"),
    ] {
        std::fs::write(package, b"").unwrap();
    }
    std::fs::write(
        fixture.join("openai/_streaming.py"),
        concat!(
            "class Stream:\n",
            "    def __init__(self):\n",
            "        self.index = 0\n",
            "    def __iter__(self):\n",
            "        return self\n",
            "    def __next__(self):\n",
            "        if self.index == 2:\n",
            "            raise StopIteration\n",
            "        self.index += 1\n",
            "        return {'delta': self.index}\n",
            "class AsyncStream:\n",
            "    def __init__(self):\n",
            "        self.index = 0\n",
            "    def __aiter__(self):\n",
            "        return self\n",
            "    async def __anext__(self):\n",
            "        if self.index == 2:\n",
            "            raise StopAsyncIteration\n",
            "        self.index += 1\n",
            "        return {'delta': self.index}\n",
        ),
    )
    .unwrap();
    std::fs::write(
        completions.join("completions.py"),
        concat!(
            "from openai._streaming import AsyncStream, Stream\n",
            "class Completions:\n",
            "    def create(self, *args, **kwargs):\n",
            "        return Stream()\n",
            "class AsyncCompletions:\n",
            "    async def create(self, *args, **kwargs):\n",
            "        return AsyncStream()\n",
        ),
    )
    .unwrap();
    std::fs::write(
        responses.join("responses.py"),
        concat!(
            "from openai._streaming import AsyncStream, Stream\n",
            "class Responses:\n",
            "    def create(self, *args, **kwargs):\n",
            "        return Stream()\n",
            "class AsyncResponses:\n",
            "    async def create(self, *args, **kwargs):\n",
            "        return AsyncStream()\n",
        ),
    )
    .unwrap();
    std::fs::write(
        fixture.join("httpx.py"),
        concat!(
            "class Request:\n",
            "    def __init__(self, method, url, headers=None):\n",
            "        self.method = method\n",
            "        self.url = url\n",
            "        self.headers = headers or {}\n",
            "class Response:\n",
            "    def __init__(self, loaded=False):\n",
            "        self.status_code = 200\n",
            "        self.headers = {'content-type': 'application/octet-stream'}\n",
            "        self._chunks = [b'one', b'two']\n",
            "        if loaded:\n",
            "            self.content = b'loaded'\n",
            "    def iter_raw(self):\n",
            "        yield from self._chunks\n",
            "    async def aiter_raw(self):\n",
            "        for chunk in self._chunks:\n",
            "            yield chunk\n",
            "class Client:\n",
            "    def send(self, request, *args, **kwargs):\n",
            "        if '/error' in request.url:\n",
            "            raise RuntimeError('fixture transport error')\n",
            "        return Response(not kwargs.get('stream', False))\n",
            "class AsyncClient:\n",
            "    async def send(self, request, *args, **kwargs):\n",
            "        return Response(not kwargs.get('stream', False))\n",
        ),
    )
    .unwrap();
    std::fs::write(
        fixture.join("requests.py"),
        concat!(
            "class Request:\n",
            "    def __init__(self, method, url, headers=None):\n",
            "        self.method = method\n",
            "        self.url = url\n",
            "        self.headers = headers or {}\n",
            "class Response:\n",
            "    def __init__(self):\n",
            "        self.status_code = 200\n",
            "        self.headers = {'content-type': 'application/octet-stream'}\n",
            "    def iter_content(self):\n",
            "        yield b'three'\n",
            "        yield b'four'\n",
            "class Session:\n",
            "    def send(self, request, *args, **kwargs):\n",
            "        return Response()\n",
        ),
    )
    .unwrap();
    let target = fixture.join("target.py");
    std::fs::write(
        &target,
        concat!(
            "import time\n",
            "import os\n",
            "import sys\n",
            "import asyncio\n",
            "import httpx\n",
            "import requests\n",
            "import warnings\n",
            "warnings.filterwarnings('ignore', category=DeprecationWarning)\n",
            "from openai.resources.chat.completions.completions import AsyncCompletions, Completions\n",
            "from openai.resources.responses.responses import AsyncResponses, Responses\n",
            "assert getattr(Completions.create, '_iorec_wrapped', False)\n",
            "def call(content):\n",
            "    chunks = list(Completions().create(model='fixture-model', messages=[{'role': 'user', 'content': content}], max_tokens=123, api_key='must-be-redacted'))\n",
            "    assert chunks == [{'delta': 1}, {'delta': 2}]\n",
            "async def async_http():\n",
            "    request = httpx.Request('POST', 'https://model.invalid/v1/responses?api_key=must-not-persist', {'Authorization': 'Bearer transport-secret'})\n",
            "    response = await httpx.AsyncClient().send(request, stream=True)\n",
            "    assert [chunk async for chunk in response.aiter_raw()] == [b'one', b'two']\n",
            "async def async_call(resource):\n",
            "    stream = await resource.create(model='fixture-model', input='async-runtime-canary')\n",
            "    chunks = [chunk async for chunk in stream]\n",
            "    assert chunks == [{'delta': 1}, {'delta': 2}]\n",
            "child = os.fork()\n",
            "if child == 0:\n",
            "    call('python-runtime-child-canary')\n",
            "    time.sleep(0.15)\n",
            "    sys.exit(0)\n",
            "_, status = os.waitpid(child, 0)\n",
            "assert os.waitstatus_to_exitcode(status) == 0\n",
            "call('python-runtime-canary')\n",
            "list(Responses().create(model='fixture-model', input='responses-runtime-canary'))\n",
            "asyncio.run(async_call(AsyncCompletions()))\n",
            "asyncio.run(async_call(AsyncResponses()))\n",
            "request = httpx.Request('POST', 'https://model.invalid/v1/chat?api_key=must-not-persist', {'Authorization': 'Bearer transport-secret'})\n",
            "assert list(httpx.Client().send(request, stream=True).iter_raw()) == [b'one', b'two']\n",
            "assert httpx.Client().send(request, stream=False).content == b'loaded'\n",
            "cancelled = httpx.Client().send(request, stream=True).iter_raw()\n",
            "assert next(cancelled) == b'one'\n",
            "cancelled.close()\n",
            "try:\n",
            "    httpx.Client().send(httpx.Request('POST', 'https://model.invalid/error'), stream=True)\n",
            "except RuntimeError:\n",
            "    pass\n",
            "else:\n",
            "    raise AssertionError('transport exception was not preserved')\n",
            "request = requests.Request('POST', 'https://model.invalid/v1/messages?token=must-not-persist', {'Authorization': 'Bearer transport-secret'})\n",
            "assert list(requests.Session().send(request, stream=True).iter_content()) == [b'three', b'four']\n",
            "asyncio.run(async_http())\n",
            "time.sleep(0.15)\n",
        ),
    )
    .unwrap();
    let runs = temporary.path().join("runs");
    std::fs::create_dir(&runs).unwrap();
    let master = EncryptionKey::new([84; 32]);
    let outcome = run(RunOptions {
        command: vec![OsString::from(python), target.into_os_string()],
        runs_dir: runs,
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(master.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: true,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);

    let run_key = derived_run_key(&outcome.run_dir, &master);
    let mut configured = false;
    let mut ready_pids = std::collections::BTreeSet::new();
    let mut started = false;
    let mut sampling_parameter_preserved = false;
    let mut credential_redacted = false;
    let mut stream_events = 0_u64;
    let mut completed = 0_u64;
    let mut http_body_chunks = 0_u64;
    let mut http_body_completed = 0_u64;
    let mut http_body_cancelled = 0_u64;
    let mut http_request_errors = 0_u64;
    let mut http_credential_redacted = false;
    let mut query_secret_persisted = false;
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |event| {
            configured |= event.event == "python_runtime_injection_configured";
            if event.source == "hook:python-runtime"
                && event.event == "python_runtime_ready"
                && let Some(pid) = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("_iorec_runtime_pid"))
                    .and_then(serde_json::Value::as_u64)
            {
                ready_pids.insert(pid);
            }
            started |= event.source == "hook:python-runtime"
                && event.event == "model_call_started"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.pointer("/kwargs/messages/0/content"))
                    .and_then(serde_json::Value::as_str)
                    == Some("python-runtime-canary");
            sampling_parameter_preserved |= event.source == "hook:python-runtime"
                && event.event == "model_call_started"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.pointer("/kwargs/max_tokens"))
                    .and_then(serde_json::Value::as_u64)
                    == Some(123);
            credential_redacted |= event.source == "hook:python-runtime"
                && event.event == "model_call_started"
                && event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.pointer("/kwargs/api_key"))
                    .and_then(serde_json::Value::as_str)
                    == Some("[REDACTED]");
            if event.source == "hook:python-runtime" && event.event == "model_stream_event" {
                stream_events = stream_events.saturating_add(1);
            }
            if event.source == "hook:python-runtime"
                && event.event == "model_stream_completed"
                && event.terminal_state == Some(iorec::model::TerminalState::Complete)
            {
                completed = completed.saturating_add(1);
            }
            if event.source == "hook:python-runtime"
                && event.event == "runtime_http_response_body_chunk"
            {
                http_body_chunks = http_body_chunks.saturating_add(1);
            }
            if event.source == "hook:python-runtime"
                && event.event == "runtime_http_response_body_completed"
            {
                http_body_completed = http_body_completed.saturating_add(1);
            }
            if event.source == "hook:python-runtime"
                && event.event == "runtime_http_response_body_cancelled"
            {
                http_body_cancelled = http_body_cancelled.saturating_add(1);
            }
            if event.source == "hook:python-runtime" && event.event == "runtime_http_request_error"
            {
                http_request_errors = http_request_errors.saturating_add(1);
            }
            if event.source == "hook:python-runtime"
                && event.event == "runtime_http_request_started"
                && let Some(normalized) = event.normalized.as_ref()
            {
                http_credential_redacted |= normalized
                    .pointer("/headers/Authorization")
                    .and_then(serde_json::Value::as_str)
                    == Some("[REDACTED]");
                query_secret_persisted |= serde_json::to_string(normalized)
                    .unwrap()
                    .contains("must-not-persist");
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(configured);
    assert_eq!(ready_pids.len(), 2);
    assert!(started);
    assert!(sampling_parameter_preserved);
    assert!(credential_redacted);
    assert_eq!(stream_events, 10);
    assert_eq!(completed, 5);
    assert_eq!(http_body_chunks, 7);
    assert_eq!(http_body_completed, 3);
    assert_eq!(http_body_cancelled, 1);
    assert_eq!(http_request_errors, 1);
    assert!(http_credential_redacted);
    assert!(!query_secret_persisted);

    let injection = outcome.run_dir.join("runtime-python");
    assert_eq!(
        std::fs::metadata(&injection).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(injection.join("sitecustomize.py"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&master)).unwrap();
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"hook:python-runtime".to_owned())
    );
    assert!(inspection.missing_blobs.is_empty());
    assert!(inspection.corrupt_blobs.is_empty());
    assert_eq!(inspection.manifest.counts.logical_inferences, 5);
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert!(
        inspection
            .manifest
            .probe_plan
            .as_ref()
            .unwrap()
            .selected
            .contains(&"python_runtime".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_runtime_injection_covers_sdk_fetch_worker_and_fork() {
    let node = std::path::Path::new("/usr/bin/node");
    assert!(node.is_file(), "Linux support gate requires /usr/bin/node");
    let temporary = tempfile::tempdir().unwrap();
    let fixture = temporary.path().join("fixture");
    let openai = fixture.join("node_modules/openai");
    std::fs::create_dir_all(&openai).unwrap();
    std::fs::write(
        openai.join("index.js"),
        r"
class Stream {
  constructor(label) { this.label = label; this.index = 0; }
  [Symbol.asyncIterator]() { return this; }
  next() {
    this.index += 1;
    if (this.index <= 2) return Promise.resolve({done: false, value: {delta: this.index, label: this.label}});
    return Promise.resolve({done: true});
  }
  return() { return Promise.resolve({done: true}); }
}
class OpenAI {
  constructor() {
    this.chat = {completions: {create: (options) => options.fail
      ? {then: (_resolve, reject) => queueMicrotask(() => reject(new TypeError('fixture rejection')))}
      : new Stream(options.messages[0].content)}};
    this.responses = {create: (options) => new Stream(options.input)};
  }
}
module.exports = OpenAI;
module.exports.default = OpenAI;
module.exports.OpenAI = OpenAI;
",
    )
    .unwrap();
    std::fs::write(
        openai.join("index.mjs"),
        r"
class Stream {
  constructor(label) { this.label = label; this.index = 0; }
  [Symbol.asyncIterator]() { return this; }
  next() {
    this.index += 1;
    if (this.index <= 2) return Promise.resolve({done: false, value: {delta: this.index, label: this.label}});
    return Promise.resolve({done: true});
  }
  return() { return Promise.resolve({done: true}); }
}
class OpenAI {
  constructor() {
    this.chat = {completions: {create: (options) => options.fail
      ? {then: (_resolve, reject) => queueMicrotask(() => reject(new TypeError('fixture rejection')))}
      : new Stream(options.messages[0].content)}};
    this.responses = {create: (options) => new Stream(options.input)};
  }
}
export {OpenAI};
export default OpenAI;
",
    )
    .unwrap();
    std::fs::write(
        openai.join("package.json"),
        r#"{"name":"openai","version":"0.0.0-fixture","exports":{"import":"./index.mjs","require":"./index.js"}}"#,
    )
    .unwrap();
    let target = fixture.join("target.js");
    std::fs::write(
        &target,
        r"
'use strict';
const assert = require('node:assert');
const {fork} = require('node:child_process');
const {Worker, isMainThread, workerData} = require('node:worker_threads');
const OpenAI = require('openai');

async function invoke(label, esm = false) {
  const Client = esm ? (await import('openai')).default : OpenAI;
  const client = new Client({apiKey: 'constructor-secret'});
  const chat = client.chat.completions.create({
    model: 'fixture-model',
    messages: [{role: 'user', content: label}],
    maxTokens: 123,
    apiKey: 'must-be-redacted',
  });
  const chatChunks = [];
  for await (const chunk of chat) chatChunks.push(chunk);
  assert.deepStrictEqual(chatChunks.map((chunk) => chunk.delta), [1, 2]);
  const responseChunks = [];
  for await (const chunk of client.responses.create({model: 'fixture-model', input: `${label}-responses`})) {
    responseChunks.push(chunk);
  }
  assert.deepStrictEqual(responseChunks.map((chunk) => chunk.delta), [1, 2]);
  const response = await fetch(`data:text/plain,${label}`);
  assert.strictEqual(await response.text(), label);
  if (label === 'node-runtime-main-canary') {
    let observed = 0;
    for await (const _chunk of client.chat.completions.create({
      model: 'fixture-model',
      messages: [{role: 'user', content: 'node-runtime-cancel-canary'}],
    })) {
      observed += 1;
      break;
    }
    assert.strictEqual(observed, 1);
    let rejected = false;
    try {
      await client.chat.completions.create({model: 'fixture-model', messages: [], fail: true});
    } catch (error) {
      assert(error instanceof TypeError);
      rejected = true;
    }
    assert.strictEqual(rejected, true);
  }
}

async function childProcess() {
  await invoke('node-runtime-fork-canary');
  await new Promise((resolve) => setTimeout(resolve, 150));
}

async function main() {
  if (!isMainThread) {
    await invoke(workerData, true);
    await new Promise((resolve) => setTimeout(resolve, 150));
    return;
  }
  if (process.env.IOREC_NODE_TEST_CHILD === '1') {
    await childProcess();
    return;
  }
  await invoke('node-runtime-main-canary');
  await Promise.all([
    new Promise((resolve, reject) => {
      const child = fork(__filename, [], {
        env: {...process.env, IOREC_NODE_TEST_CHILD: '1'},
        stdio: 'inherit',
      });
      child.once('error', reject);
      child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`fork exited ${code}`)));
    }),
    new Promise((resolve, reject) => {
      const worker = new Worker(__filename, {workerData: 'node-runtime-worker-canary'});
      worker.once('error', reject);
      worker.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`worker exited ${code}`)));
    }),
  ]);
  await new Promise((resolve) => setTimeout(resolve, 200));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
",
    )
    .unwrap();
    let runs = temporary.path().join("runs");
    std::fs::create_dir(&runs).unwrap();
    let master = EncryptionKey::new([85; 32]);
    let outcome = run(RunOptions {
        command: vec![OsString::from(node), target.into_os_string()],
        runs_dir: runs,
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(master.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: true,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);

    let run_key = derived_run_key(&outcome.run_dir, &master);
    let mut configured = false;
    let mut ready_runtimes = std::collections::BTreeSet::new();
    let mut esm_loader_ready = 0_u64;
    let mut main_started = false;
    let mut sampling_parameter_preserved = false;
    let mut credential_redacted = false;
    let mut stream_events = 0_u64;
    let mut stream_completed = 0_u64;
    let mut stream_cancelled = 0_u64;
    let mut model_errors = 0_u64;
    let mut fetch_completed = 0_u64;
    let mut response_body_chunks = 0_u64;
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |event| {
            configured |= event.event == "node_runtime_injection_configured";
            if event.source == "hook:node-runtime" && event.event == "node_runtime_ready" {
                let normalized = event.normalized.as_ref().unwrap();
                let pid = normalized
                    .get("_iorec_runtime_pid")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap();
                let thread = normalized
                    .get("_iorec_runtime_thread_id")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap();
                ready_runtimes.insert((pid, thread));
                if normalized
                    .get("esm_loader_registered")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    esm_loader_ready = esm_loader_ready.saturating_add(1);
                }
            }
            if event.source == "hook:node-runtime" && event.event == "model_call_started" {
                let normalized = event.normalized.as_ref().unwrap();
                main_started |= normalized
                    .pointer("/args/0/messages/0/content")
                    .and_then(serde_json::Value::as_str)
                    == Some("node-runtime-main-canary");
                sampling_parameter_preserved |= normalized
                    .pointer("/args/0/maxTokens")
                    .and_then(serde_json::Value::as_u64)
                    == Some(123);
                credential_redacted |= normalized
                    .pointer("/args/0/apiKey")
                    .and_then(serde_json::Value::as_str)
                    == Some("[REDACTED]");
            }
            if event.source == "hook:node-runtime" && event.event == "model_stream_event" {
                stream_events = stream_events.saturating_add(1);
            }
            if event.source == "hook:node-runtime" && event.event == "model_stream_completed" {
                stream_completed = stream_completed.saturating_add(1);
            }
            if event.source == "hook:node-runtime" && event.event == "model_stream_cancelled" {
                stream_cancelled = stream_cancelled.saturating_add(1);
            }
            if event.source == "hook:node-runtime" && event.event == "model_call_error" {
                model_errors = model_errors.saturating_add(1);
            }
            if event.source == "hook:node-runtime"
                && event.event == "runtime_http_request_completed"
            {
                fetch_completed = fetch_completed.saturating_add(1);
            }
            if event.source == "hook:node-runtime"
                && event.event == "runtime_http_response_body_chunk"
            {
                response_body_chunks = response_body_chunks.saturating_add(1);
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(configured);
    assert_eq!(ready_runtimes.len(), 3);
    assert_eq!(esm_loader_ready, 3);
    assert!(main_started);
    assert!(sampling_parameter_preserved);
    assert!(credential_redacted);
    assert_eq!(stream_events, 13);
    assert_eq!(stream_completed, 6);
    assert_eq!(stream_cancelled, 1);
    assert_eq!(model_errors, 1);
    assert_eq!(fetch_completed, 3);
    assert_eq!(response_body_chunks, 3);

    let injection = outcome.run_dir.join("runtime-node");
    assert_eq!(
        std::fs::metadata(&injection).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(injection.join("preload.cjs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(injection.join("loader.mjs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&master)).unwrap();
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"hook:node-runtime".to_owned())
    );
    assert!(inspection.missing_blobs.is_empty());
    assert!(inspection.corrupt_blobs.is_empty());
    assert_eq!(inspection.manifest.counts.logical_inferences, 8);
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert!(
        inspection
            .manifest
            .probe_plan
            .as_ref()
            .unwrap()
            .selected
            .contains(&"node_runtime".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn surviving_descendants_make_the_finished_run_explicitly_incomplete() {
    let temporary = tempfile::tempdir().unwrap();
    let pid_file = temporary.path().join("background.pid");
    let script = format!(
        "sleep 30 & printf '%s' \"$!\" > '{}'; sleep 0.5",
        pid_file.display()
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    let background_pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(background_pid),
        nix::sys::signal::Signal::SIGKILL,
    );

    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert!(inspection.manifest.coverage.capture_drops > 0);
    assert!(
        inspection
            .manifest
            .coverage
            .known_gaps
            .iter()
            .any(|gap| { gap.contains("target processes were still running") })
    );
    let events = std::fs::read_to_string(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("\"process_tracker_stopped\""));
    assert!(events.contains("\"terminal_state\":\"incomplete\""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runner_proxy_records_a_real_child_request() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(
                "curl --silent --show-error --fail -H 'content-type: application/json' -H 'x-iorec-chunks: 2' -H 'x-iorec-delay-ms: 100' --data '{\"model\":\"test-model\",\"input\":[{\"role\":\"user\",\"content\":\"hello\"}]}' \"$IOREC_PROXY_URL/v1/responses\" >/dev/null",
            ),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();
    assert_eq!(outcome.exit_code, 0);
    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(inspection.manifest.status, "finished");
    assert_eq!(inspection.manifest.counts.logical_inferences, 1);
    assert_eq!(inspection.manifest.counts.transport_attempts, 1);
    assert_eq!(inspection.manifest.counts.completed_attempts, 1);
    assert!(
        inspection
            .manifest
            .coverage
            .captured_request_payloads_complete
    );
    assert!(
        inspection
            .manifest
            .coverage
            .captured_response_payloads_complete
    );
    assert_eq!(
        inspection.manifest.counts.models.get("test-model"),
        Some(&1)
    );
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"adapter:none".to_owned())
    );
    assert!(inspection.missing_blobs.is_empty());
    assert!(inspection.corrupt_blobs.is_empty());
    assert_eq!(inspection.manifest.coverage.unknown_egress, 0);
    let events = std::fs::read_to_string(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("network_connection_observed"));
    assert!(events.contains("model_recorder"));
    assert!(events.contains("event_sync_batches"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rootless_task_network_proves_plaintext_transport_completeness() {
    let _capture_guard = PRIVILEGED_CAPTURE_TEST_LOCK.lock().await;
    if TaskNetnsTools::discover().is_err() || !std::path::Path::new("/usr/bin/tshark").is_file() {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let key = EncryptionKey::new([88; 32]);
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/bash"),
            OsString::from("-c"),
            OsString::from(
                "url=$IOREC_PROXY_URL; endpoint=${url#http://}; host=${endpoint%:*}; port=${endpoint##*:}; payload='{\"model\":\"task-netns-e2e\",\"input\":\"hello\"}'; exec 3<>/dev/tcp/$host/$port; printf 'POST /v1/responses HTTP/1.1\\r\\nHost: task.test\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s' \"${#payload}\" \"$payload\" >&3; /bin/cat <&3 >/dev/null",
            ),
        ],
        runs_dir: temporary.path().join("runs"),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: true,
        pcap_max_bytes: 8 * 1024 * 1024,
        task_cgroup: false,
        task_netns: true,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();

    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.status, "finished");
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert_eq!(inspection.manifest.coverage.unknown_egress, 0);
    assert_eq!(inspection.manifest.coverage.unparsed_connections, 0);
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"network:task-netns-proxy-only".to_owned())
    );
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"pcap:task-egress".to_owned())
    );

    let audit = audit_transport(
        &outcome.run_dir,
        &temporary.path().join("transport-audit.json"),
        &key,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(audit.tls_key_records, 0);
    assert_eq!(
        audit.completeness_boundary,
        "target-network-namespace-ip-transport"
    );
    assert_eq!(audit.proxy_attempts, 1);
    assert_eq!(audit.matched_attempts, 1);
    assert!(audit.payload_diff_passed);
    assert!(audit.complete, "{:?}", audit.gaps);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rootless_transparent_http_intercepts_original_socket_without_endpoint_injection() {
    let _capture_guard = PRIVILEGED_CAPTURE_TEST_LOCK.lock().await;
    if TaskNetnsTools::discover().is_err() || !std::path::Path::new("/usr/bin/tshark").is_file() {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let route_probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    route_probe.connect("192.0.2.1:9").unwrap();
    let host_address = route_probe.local_addr().unwrap().ip();
    assert!(!host_address.is_loopback() && host_address.is_ipv4());
    let upstream_listener = tokio::net::TcpListener::bind(SocketAddr::new(host_address, 0))
        .await
        .unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request
            .windows(b"transparent-http-e2e".len())
            .any(|window| window == b"transparent-http-e2e")
        {
            let length = stream.read(&mut buffer).await.unwrap();
            assert!(length > 0 && request.len() < 64 * 1024);
            request.extend_from_slice(&buffer[..length]);
        }
        let body = b"{\"id\":\"transparent-response\",\"output_text\":\"ok\"}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let target = format!(
        "test -z \"${{IOREC_PROXY_URL+x}}\"; host={}; port={}; payload='{{\"model\":\"transparent-http-e2e\",\"input\":\"hello\"}}'; exec 3<>/dev/tcp/$host/$port; printf 'POST /v1/responses HTTP/1.1\\r\\nHost: original.test\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s' \"${{#payload}}\" \"$payload\" >&3; /bin/cat <&3 >/dev/null",
        upstream_address.ip(),
        upstream_address.port(),
    );
    let key = EncryptionKey::new([91; 32]);
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/bash"),
            OsString::from("-c"),
            OsString::from(target),
        ],
        runs_dir: temporary.path().join("runs"),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{upstream_address}")).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: true,
        pcap_max_bytes: 8 * 1024 * 1024,
        task_cgroup: false,
        task_netns: true,
        transparent_proxy: true,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    upstream_task.await.unwrap();
    assert_eq!(outcome.exit_code, 0);

    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.status, "finished");
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert_eq!(inspection.manifest.coverage.unknown_egress, 0);
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"network:task-netns-transparent".to_owned())
    );
    assert!(!outcome.run_dir.join(".transparent-hosts").exists());

    let run_key = derived_run_key(&outcome.run_dir, &key);
    let mut prepared = false;
    let mut request_captured = false;
    let mut redirected_packets = 0_u64;
    let mut cleanup = false;
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |event| {
            prepared |= event.event == "transparent_interception_prepared";
            request_captured |= event.event == "transport_request_started";
            cleanup |= event.event == "transparent_interception_material_removed";
            if event.event == "task_network_isolation_finished" {
                redirected_packets = event
                    .normalized
                    .as_ref()
                    .and_then(|value| value.get("firewall"))
                    .and_then(|value| value.get("transparent_packets"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(prepared);
    assert!(request_captured);
    assert!(cleanup);
    assert!(redirected_packets > 0);

    let audit = audit_transport(
        &outcome.run_dir,
        &temporary.path().join("transparent-transport-audit.json"),
        &key,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert!(audit.complete, "{:?}", audit.gaps);
    assert_eq!(audit.proxy_attempts, 1);
    assert_eq!(audit.matched_attempts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rootless_transparent_https_uses_ephemeral_ca_and_keeps_private_key_in_memory() {
    let _capture_guard = PRIVILEGED_CAPTURE_TEST_LOCK.lock().await;
    if TaskNetnsTools::discover().is_err()
        || !std::path::Path::new("/usr/bin/tshark").is_file()
        || !std::path::Path::new("/usr/bin/curl").is_file()
    {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let route_probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    route_probe.connect("192.0.2.1:9").unwrap();
    let host_address = route_probe.local_addr().unwrap().ip();
    assert!(!host_address.is_loopback() && host_address.is_ipv4());
    let upstream_listener = tokio::net::TcpListener::bind(SocketAddr::new(host_address, 0))
        .await
        .unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_url = Url::parse(&format!("https://{upstream_address}")).unwrap();
    let upstream_material = TransparentArtifacts::prepare(
        temporary.path(),
        "upstream-test-server",
        &upstream_url,
        &[upstream_address],
        false,
    )
    .unwrap();
    let upstream_ca = upstream_material.ca_path().unwrap().to_owned();
    let mut upstream_tls = (*upstream_material.server_config().unwrap()).clone();
    upstream_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let upstream_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(upstream_tls));
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let mut stream = upstream_acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request
            .windows(b"transparent-https-e2e".len())
            .any(|window| window == b"transparent-https-e2e")
        {
            let length = stream.read(&mut buffer).await.unwrap();
            assert!(length > 0 && request.len() < 64 * 1024);
            request.extend_from_slice(&buffer[..length]);
        }
        let body = b"{\"id\":\"transparent-tls-response\",\"output_text\":\"ok\"}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let key_file = temporary.path().join("key.hex");
    let key = EncryptionKey::generate_file(&key_file).unwrap();
    let runs_root = temporary.path().join("runs");
    let mut recorder = tokio::process::Command::new(env!("CARGO_BIN_EXE_iorec"));
    recorder
        .env("SSL_CERT_FILE", &upstream_ca)
        .env_remove("SSL_CERT_DIR")
        .arg("run")
        .arg("--runs-dir")
        .arg(&runs_root)
        .arg("--key-file")
        .arg(&key_file)
        .arg("--upstream")
        .arg(upstream_url.as_str())
        .arg("--pcap")
        .arg("--tls-keylog")
        .arg("--task-netns")
        .arg("--transparent-proxy")
        .arg("--provider")
        .arg("none")
        .arg("--adapter")
        .arg("none")
        .arg("--")
        .arg("/usr/bin/curl")
        .arg("--http1.1")
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("--header")
        .arg("Content-Type: application/json")
        .arg("--data")
        .arg("{\"model\":\"transparent-https-e2e\",\"input\":\"hello\"}")
        .arg(format!("{upstream_url}v1/responses"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(45), recorder.output())
        .await
        .expect("transparent HTTPS recorder timed out")
        .unwrap();
    assert!(
        output.status.success(),
        "recorder stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await
        .expect("upstream TLS server did not finish")
        .unwrap();

    let run_path = run_directories(&runs_root).pop().unwrap();
    let inspection = inspect_run_with_key(&run_path, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert_eq!(inspection.manifest.coverage.unknown_egress, 0);
    assert!(
        inspection
            .manifest
            .coverage
            .capture_sources
            .contains(&"network:task-netns-transparent".to_owned())
    );
    assert!(!run_path.join(".transparent-ca.pem").exists());
    assert!(!run_path.join(".transparent-hosts").exists());
    let run_key = derived_run_key(&run_path, &key);
    let mut downstream_tls = false;
    let mut private_key_persisted = true;
    let mut redirected_packets = 0_u64;
    for_each_event_with_key(&run_path.join("events.jsonl"), Some(&run_key), |event| {
        if event.event == "transparent_interception_prepared" {
            downstream_tls = event
                .normalized
                .as_ref()
                .and_then(|value| value.get("downstream_tls"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            private_key_persisted = event
                .normalized
                .as_ref()
                .and_then(|value| value.get("ca_private_key_persisted"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
        }
        if event.event == "task_network_isolation_finished" {
            redirected_packets = event
                .normalized
                .as_ref()
                .and_then(|value| value.get("firewall"))
                .and_then(|value| value.get("transparent_packets"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
        }
        Ok(())
    })
    .unwrap();
    assert!(downstream_tls);
    assert!(!private_key_persisted);
    assert!(redirected_packets > 0);
    let audit = audit_transport(
        &run_path,
        &temporary
            .path()
            .join("transparent-tls-transport-audit.json"),
        &key,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert!(audit.tls_key_records > 0);
    assert!(audit.complete, "{:?}", audit.gaps);
    assert_eq!(audit.proxy_attempts, 1);
    assert_eq!(audit.matched_attempts, 1);
    upstream_material.cleanup().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rootless_task_network_blocks_bypass_without_reporting_crossed_egress() {
    let _capture_guard = PRIVILEGED_CAPTURE_TEST_LOCK.lock().await;
    if TaskNetnsTools::discover().is_err() || !std::path::Path::new("/usr/bin/tshark").is_file() {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let key = EncryptionKey::new([89; 32]);
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/bash"),
            OsString::from("-c"),
            OsString::from(
                "url=$IOREC_PROXY_URL; endpoint=${url#http://}; host=${endpoint%:*}; port=${endpoint##*:}; payload='{\"model\":\"task-netns-bypass\",\"input\":\"hello\"}'; exec 3<>/dev/tcp/$host/$port; printf 'POST /v1/responses HTTP/1.1\\r\\nHost: task.test\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s' \"${#payload}\" \"$payload\" >&3; /bin/cat <&3 >/dev/null; /usr/bin/timeout 1 /bin/bash -c 'exec 9<>/dev/tcp/1.1.1.1/80' 2>/dev/null || true",
            ),
        ],
        runs_dir: temporary.path().join("runs"),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: true,
        pcap_max_bytes: 8 * 1024 * 1024,
        task_cgroup: false,
        task_netns: true,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();

    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.status, "finished");
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert_eq!(inspection.manifest.coverage.unknown_egress, 0);
    assert!(inspection.manifest.coverage.task_netns_denied_packets > 0);
    assert!(
        inspection
            .manifest
            .coverage
            .blocked_unknown_egress_indicators
            > 0
    );

    let audit = audit_transport(
        &outcome.run_dir,
        &temporary.path().join("transport-audit.json"),
        &key,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(audit.proxy_attempts, 1);
    assert_eq!(audit.matched_attempts, 1);
    assert!(audit.payload_diff_passed);
    assert!(audit.source_coverage.task_netns_denied_packets > 0);
    assert!(audit.source_coverage.blocked_unknown_egress_indicators > 0);
    assert!(audit.complete, "{:?}", audit.gaps);
    assert!(audit.gaps.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn event_budget_exhaustion_still_finalizes_and_preserves_target_exit() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let policy = CapturePolicy {
        max_event_storage_bytes: 4096,
        ..CapturePolicy::default()
    };
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(
                "curl --silent --show-error --fail -H 'content-type: application/json' -H 'x-iorec-chunks: 8' --data '{\"model\":\"test-model\",\"input\":\"fill-event-budget\"}' \"$IOREC_PROXY_URL/v1/responses\" >/dev/null",
            ),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy,
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();

    assert_eq!(outcome.exit_code, 0);
    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(inspection.manifest.status, "finished");
    assert_eq!(inspection.manifest.exit_code, Some(0));
    assert!(inspection.manifest.coverage.capture_drops > 0);
    assert!(inspection.manifest.counts.event_storage_bytes <= 4096);
    assert!(inspection.manifest.coverage.known_gaps.iter().any(|gap| {
        gap.contains("durable event writer became unavailable before final shutdown")
    }));
    assert_eq!(inspection.log.discarded_tail_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_multimodal_references_downgrade_client_verification() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(
                "curl --silent --show-error --fail -H 'content-type: application/json' --data '{\"model\":\"test-model\",\"input\":[{\"type\":\"input_image\",\"image_url\":\"https://private.test/image.png?token=secret\"}]}' \"$IOREC_PROXY_URL/v1/responses\" >/dev/null",
            ),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();

    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(
        inspection.manifest.coverage.unresolved_payload_references,
        1
    );
    assert!(
        !inspection
            .manifest
            .coverage
            .captured_request_payloads_complete
    );
    let verification =
        verify_run_with_key(&outcome.run_dir, VerificationProfile::Client, None).unwrap();
    assert!(!verification.passed);
    assert!(
        verification
            .checks
            .iter()
            .any(|check| { check.name == "payload_references_resolved" && !check.passed })
    );
    let events = std::fs::read_to_string(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(!events.contains("private.test"));
    assert!(!events.contains("token=secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_run_never_persists_events_or_payloads_in_plaintext() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let key = EncryptionKey::new([23; 32]);
    let secret = "encryption-e2e-canary-4d51144d";
    let script = format!(
        "curl --silent --show-error --fail -H 'content-type: application/json' --data '{{\"model\":\"test-model\",\"input\":\"{secret}\"}}' \"$IOREC_PROXY_URL/v1/responses\" >/dev/null"
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();
    assert_eq!(outcome.exit_code, 0);

    assert!(inspect_run(&outcome.run_dir, true).is_err());
    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest_authenticated, Some(true));
    assert_eq!(inspection.manifest.counts.logical_inferences, 1);
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    assert_eq!(
        inspection
            .manifest
            .storage
            .encryption
            .as_ref()
            .map(|metadata| metadata.key_id.as_str()),
        Some(key.key_id())
    );
    assert_eq!(
        inspection
            .manifest
            .storage
            .encryption
            .as_ref()
            .and_then(|metadata| metadata.key_derivation.as_deref()),
        Some(iorec::manifest::RUN_KEY_DERIVATION_V1)
    );
    assert!(inspection.missing_blobs.is_empty());
    assert!(inspection.corrupt_blobs.is_empty());
    assert!(inspection.manifest.counts.blob_storage_bytes > inspection.manifest.counts.blob_bytes);

    let events = std::fs::read(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(
        !events
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    assert!(!events.windows(11).any(|window| window == b"run_started"));
    assert!(
        for_each_event_with_key(
            &outcome.run_dir.join("events.jsonl"),
            Some(&key),
            |_| Ok(())
        )
        .is_err()
    );
    let run_key = derived_run_key(&outcome.run_dir, &key);
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |_| Ok(()),
    )
    .unwrap();
    for entry in std::fs::read_dir(outcome.run_dir.join("blobs")).unwrap() {
        let blob = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !blob
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }
    assert!(
        !load_with_key(&outcome.run_dir, &TimelineFilter::default(), Some(&key))
            .unwrap()
            .is_empty()
    );
    analyze_with_key(&outcome.run_dir, Some(&key)).unwrap();
    export_raw_with_key(
        &outcome.run_dir,
        &temporary.path().join("raw-export"),
        Some(&key),
    )
    .unwrap();
    export_openinference_with_key(
        &outcome.run_dir,
        &temporary.path().join("openinference.jsonl"),
        Some(&key),
    )
    .unwrap();
    export_otlp_with_key(
        &outcome.run_dir,
        &temporary.path().join("otlp.json"),
        Some(&key),
    )
    .unwrap();
    export_replay_with_key(
        &outcome.run_dir,
        &temporary.path().join("replay-export"),
        Some(&key),
    )
    .unwrap();
    let manifest = std::fs::read_to_string(outcome.run_dir.join("manifest.json")).unwrap();
    assert!(!manifest.contains(secret));
    assert!(manifest.contains("XChaCha20-Poly1305-AAD"));

    let mut tampered: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    tampered["status"] = serde_json::json!("failed");
    std::fs::write(
        outcome.run_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    assert!(inspect_run_with_key(&outcome.run_dir, true, Some(&key)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_keylog_fifo_encrypts_secrets_before_disk() {
    let temporary = tempfile::tempdir().unwrap();
    let key = EncryptionKey::new([41; 32]);
    let random = "a".repeat(64);
    let secret = "b".repeat(96);
    let key_line = format!("CLIENT_HANDSHAKE_TRAFFIC_SECRET {random} {secret}");
    let script = format!("printf '%s\\n' '{key_line}' >\"$SSLKEYLOGFILE\"");
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: true,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);
    assert!(!outcome.run_dir.join("tls-keylog.pipe").exists());

    let encoded_events = std::fs::read(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(
        !encoded_events
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    let mut key_blob = None;
    let run_key = derived_run_key(&outcome.run_dir, &key);
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |event| {
            if event.event == "tls_key_log_secret" {
                key_blob = event.raw;
            }
            Ok(())
        },
    )
    .unwrap();
    let reference = key_blob.expect("TLS key-log event");
    let encoded_blob =
        std::fs::read(iorec::blob_keys::blob_path(&outcome.run_dir, &reference).unwrap()).unwrap();
    assert!(
        !encoded_blob
            .windows(key_line.len())
            .any(|window| window == key_line.as_bytes())
    );
    assert_eq!(
        iorec::blob_keys::read_blob_reference(
            &outcome.run_dir,
            &reference,
            Some(&run_key),
            64 * 1024 * 1024,
        )
        .unwrap(),
        key_line.as_bytes()
    );
    let exported = temporary.path().join("tls.keys");
    let report =
        export_sensitive_artifact(&outcome.run_dir, &exported, &key, ArtifactKind::TlsKeys)
            .unwrap();
    assert_eq!(report.records, 1);
    assert_eq!(
        std::fs::read(&exported).unwrap(),
        format!("{key_line}\n").as_bytes()
    );
    assert_eq!(
        std::fs::metadata(exported).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spawn_failure_still_finalizes_the_manifest_and_services() {
    let temporary = tempfile::tempdir().unwrap();
    let result = run(RunOptions {
        command: vec![OsString::from("/definitely/missing/iorec-target")],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await;
    assert!(result.is_err());

    let entries = run_directories(temporary.path());
    assert_eq!(entries.len(), 1);
    let inspection = inspect_run(&entries[0], true).unwrap();
    assert_eq!(inspection.manifest.status, "failed");
    assert_eq!(inspection.manifest.exit_code, Some(127));
    assert!(!entries[0].join("collector.sock").exists());
    let events = std::fs::read_to_string(entries[0].join("events.jsonl")).unwrap();
    assert!(events.contains("process_spawn_failed"));
    assert!(events.contains("run_finished"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_failure_explicitly_stops_services_and_finalizes_manifest() {
    let temporary = tempfile::tempdir().unwrap();
    let result = run(RunOptions {
        command: vec![OsString::from("/bin/true"), OsString::from("--oss")],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse("http://127.0.0.1:9").unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::Codex,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await;
    assert!(result.is_err());

    let run_dir = run_directories(temporary.path()).pop().unwrap();
    let inspection = inspect_run(&run_dir, true).unwrap();
    assert_eq!(inspection.manifest.status, "failed");
    assert_eq!(inspection.manifest.exit_code, Some(125));
    assert!(!run_dir.join("collector.sock").exists());
    assert!(!run_dir.join("tls-keylog.pipe").exists());
    let events = std::fs::read_to_string(run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("setup_failed"));
    assert!(events.contains("proxy_stopped"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_loopback_upstream_fails_before_target_release() {
    let _capture_guard = PRIVILEGED_CAPTURE_TEST_LOCK.lock().await;
    let temporary = tempfile::tempdir().unwrap();
    let marker = temporary.path().join("target-executed");
    let key = EncryptionKey::new([94; 32]);
    let result = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!(": > '{}'", marker.display())),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse("http://127.0.0.1:9").unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: true,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: true,
        transparent_proxy: true,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await;
    assert!(result.is_err());
    assert!(!marker.exists());

    let run_dir = run_directories(temporary.path()).pop().unwrap();
    let inspection = inspect_run_with_key(&run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.status, "failed");
    assert_eq!(inspection.manifest.exit_code, Some(125));
    assert!(!run_dir.join(".transparent-hosts").exists());
    assert!(!run_dir.join(".transparent-ca.pem").exists());
    let run_key = derived_run_key(&run_dir, &key);
    let mut saw_setup_failure = false;
    for_each_event_with_key(&run_dir.join("events.jsonl"), Some(&run_key), |event| {
        saw_setup_failure |= event.event == "setup_failed";
        Ok(())
    })
    .unwrap();
    assert!(saw_setup_failure);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_hook_reaches_authenticated_collector_and_is_redacted() {
    let temporary = tempfile::tempdir().unwrap();
    let iorec = env!("CARGO_BIN_EXE_iorec");
    let script = format!(
        "printf '%s' '{{\"hook_event_name\":\"SessionStart\",\"session_id\":\"session-1\",\"authorization\":\"never-persist\"}}' | '{}' hook --source test-agent --event auto",
        iorec.replace('\'', "'\\''")
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);
    let events = std::fs::read_to_string(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("SessionStart"));
    assert!(events.contains("session-1"));
    assert!(!events.contains("never-persist"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unique_model_hook_is_correlated_with_the_proxy_inference() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let iorec = env!("CARGO_BIN_EXE_iorec");
    let script = format!(
        "printf '%s' '{{\"hook_event_name\":\"BeforeModel\",\"session_id\":\"session-g\",\"llm_request\":{{\"model\":\"test-model\"}}}}' | '{}' hook --source gemini --event auto >/dev/null && curl --silent --show-error --fail -H 'content-type: application/json' --data '{{\"model\":\"test-model\",\"input\":\"hello\"}}' \"$IOREC_PROXY_URL/v1/responses\" >/dev/null",
        iorec.replace('\'', "'\\''")
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();

    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(inspection.manifest.coverage.unresolved_correlations, 0);
    let mut correlation = None;
    for_each_event_with_key(&outcome.run_dir.join("events.jsonl"), None, |event| {
        if event.event == "inference_correlation" {
            correlation = Some(event);
        }
        Ok(())
    })
    .unwrap();
    let correlation = correlation.unwrap();
    assert_eq!(correlation.ids.session_id.as_deref(), Some("session-g"));
    assert_eq!(correlation.confidence, Some(0.9));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_anchor_collapses_implicit_sdk_retry_ids() {
    let temporary = tempfile::tempdir().unwrap();
    let fake = start_fake_server(FakeServerConfig { listen: loopback() })
        .await
        .unwrap();
    let iorec = env!("CARGO_BIN_EXE_iorec");
    let script = format!(
        "printf '%s' '{{\"hook_event_name\":\"BeforeModel\",\"session_id\":\"session-r\",\"llm_request\":{{\"model\":\"test-model\"}}}}' | '{}' hook --source gemini --event auto >/dev/null && for n in 1 2; do curl --silent --show-error -H 'content-type: application/json' -H 'x-request-id: implicit-retry' -H 'x-iorec-fail-first: 1' --data '{{\"model\":\"test-model\",\"input\":\"same\"}}' \"$IOREC_PROXY_URL/v1/responses\" >/dev/null; done",
        iorec.replace('\'', "'\\''")
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: Some(Url::parse(&format!("http://{}", fake.address)).unwrap()),
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    fake.stop().await.unwrap();

    let inspection = inspect_run(&outcome.run_dir, true).unwrap();
    assert_eq!(inspection.manifest.counts.logical_inferences, 1);
    assert_eq!(inspection.manifest.counts.transport_attempts, 2);
    assert_eq!(inspection.manifest.counts.errors, 1);
    assert_eq!(inspection.manifest.coverage.unresolved_correlations, 0);
    let mut found_retry_group = false;
    for_each_event_with_key(&outcome.run_dir.join("events.jsonl"), None, |event| {
        found_retry_group |= event.event == "inference_correlation"
            && event
                .normalized
                .as_ref()
                .and_then(|value| value.get("method"))
                .and_then(serde_json::Value::as_str)
                == Some("unique_retry_chain");
        Ok(())
    })
    .unwrap();
    assert!(found_retry_group);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_selected_probe_ready_precedes_target_and_preserves_exit_semantics() {
    let _capture_guard = PRIVILEGED_CAPTURE_TEST_LOCK.lock().await;
    let temporary = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = temporary.path().join("probe-ready");
    let helper = temporary.path().join("probe-helper");
    let ready = serde_json::json!({
        "type": "ready",
        "schema_version": iorec::probe_helper::PROTOCOL_VERSION,
        "helper": "runner-fixture",
        "helper_version": "1.0.0",
        "upstream_name": "fixture-probe",
        "upstream_version": "2.0.0",
        "capabilities": ["process"],
    })
    .to_string();
    let final_message = serde_json::json!({
        "type": "final",
        "schema_version": iorec::probe_helper::PROTOCOL_VERSION,
        "captured_events": 0,
        "dropped_events": 0,
        "probe_hits": 1,
        "complete": true,
    })
    .to_string();
    std::fs::write(
        &helper,
        format!(
            "#!/usr/bin/python3\nimport json, pathlib, signal, sys\nargs = dict(zip(sys.argv[1::2], sys.argv[2::2]))\nready = json.loads({ready:?})\nready.update({{\n    'target_pid': int(args['--target-pid']),\n    'target_executable_sha256': args['--target-executable-sha256'],\n    'target_cgroup': args.get('--target-cgroup'),\n    'filter_scope': args['--filter-scope'],\n}})\ndef stop(_signal, _frame):\n    print({final_message:?}, flush=True)\n    sys.exit(0)\nsignal.signal(signal.SIGINT, stop)\nsignal.signal(signal.SIGTERM, stop)\npathlib.Path({marker:?}).touch()\nprint(json.dumps(ready, separators=(',', ':')), flush=True)\nsignal.pause()\n",
            marker = marker.as_os_str(),
            ready = ready,
            final_message = final_message,
        ),
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let helper = helper.canonicalize().unwrap();
    let helper_digest = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(std::fs::read(&helper).unwrap()))
    };
    let command = vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(format!("test -f '{}'", marker.display())),
    ];
    let discovered = discover_command(&command, &std::env::current_dir().unwrap())
        .await
        .unwrap();
    let doctor = doctor::inspect();
    let policy_path = temporary.path().join("probe-policy.json");
    std::fs::write(
        &policy_path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "rules": [{
                "id": "exact-shell-fixture",
                "priority": 1,
                "helper_kind": "external",
                "helper_path": helper,
                "helper_sha256": helper_digest,
                "os": doctor.os,
                "architecture": doctor.architecture,
                "target_executable_sha256": discovered.executable_sha256,
                "require_ebpf": false,
                "require_task_cgroup": false
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let selection = select_probe_helper(
        &policy_path.canonicalize().unwrap(),
        &discovered,
        &doctor,
        false,
    )
    .unwrap();
    let key = EncryptionKey::new([92; 32]);
    let outcome = run(RunOptions {
        command,
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: Some(selection),
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);
    assert!(marker.is_file());
    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.coverage.capture_drops, 0);
    let helper_selection = inspection
        .manifest
        .probe_plan
        .as_ref()
        .and_then(|plan| plan.helper_selection.as_ref())
        .unwrap();
    assert_eq!(helper_selection.mode, "policy");
    assert_eq!(
        helper_selection.rule_id.as_deref(),
        Some("exact-shell-fixture")
    );
    let mut saw_ready = false;
    let mut saw_stopped = false;
    let run_key = derived_run_key(&outcome.run_dir, &key);
    for_each_event_with_key(
        &outcome.run_dir.join("events.jsonl"),
        Some(&run_key),
        |event| {
            saw_ready |= event.event == "privileged_probe_ready";
            saw_stopped |= event.event == "privileged_probe_stopped"
                && event.terminal_state == Some(iorec::model::TerminalState::Complete);
            Ok(())
        },
    )
    .unwrap();
    assert!(saw_ready);
    assert!(saw_stopped);
}

#[tokio::test]
async fn privileged_probe_requires_encryption_before_creating_a_run() {
    let temporary = tempfile::tempdir().unwrap();
    let result = run(RunOptions {
        command: vec![OsString::from("/bin/true")],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: true,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: Some(std::path::PathBuf::from("/usr/bin/true")),
        probe_policy_selection: None,
    })
    .await;
    assert!(result.is_err());
    assert!(run_directories(temporary.path()).is_empty());
}

#[tokio::test]
async fn plaintext_recording_requires_explicit_opt_in_before_creating_a_run() {
    let temporary = tempfile::tempdir().unwrap();
    let result = run(RunOptions {
        command: vec![OsString::from("/bin/true")],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: None,
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await;
    assert!(result.is_err());
    assert!(run_directories(temporary.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_start_failure_never_continues_the_paused_target() {
    let temporary = tempfile::tempdir().unwrap();
    let marker = temporary.path().join("target-executed");
    let key = EncryptionKey::new([93; 32]);
    let result = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!(": > '{}'", marker.display())),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy: CapturePolicy::default(),
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: Some(std::path::PathBuf::from("/usr/bin/true")),
        probe_policy_selection: None,
    })
    .await;
    assert!(result.is_err());
    assert!(!marker.exists());

    let run_dir = run_directories(temporary.path()).pop().unwrap();
    let inspection = inspect_run_with_key(&run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.status, "failed");
    assert_eq!(inspection.manifest.exit_code, Some(125));
    assert!(inspection.manifest.coverage.capture_drops > 0);
    let mut saw_start_failure = false;
    let run_key = derived_run_key(&run_dir, &key);
    for_each_event_with_key(&run_dir.join("events.jsonl"), Some(&run_key), |event| {
        saw_start_failure |= event.event == "probe_helper_start_failed";
        Ok(())
    })
    .unwrap();
    assert!(saw_start_failure);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_zstd_event_blocks_are_transparent_to_inspect_timeline_and_verify() {
    let temporary = tempfile::tempdir().unwrap();
    let key = EncryptionKey::new([94; 32]);
    let policy = CapturePolicy {
        event_log_format: EventLogFormat::ZstdBlocks,
        ..CapturePolicy::default()
    };
    let outcome = run(RunOptions {
        command: vec![OsString::from("/bin/true")],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::None,
        policy,
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);

    let bytes = std::fs::read(outcome.run_dir.join("events.jsonl")).unwrap();
    assert!(bytes.starts_with(b"IOREC-EVENTS-ZSTD-BLOCKS-V1\n"));
    let inspection = inspect_run_with_key(&outcome.run_dir, true, Some(&key)).unwrap();
    assert_eq!(inspection.manifest.status, "finished");
    assert_eq!(
        inspection.log.valid_events,
        inspection.manifest.counts.events
    );
    let timeline = load_with_key(&outcome.run_dir, &TimelineFilter::default(), Some(&key)).unwrap();
    assert_eq!(
        u64::try_from(timeline.len()).unwrap(),
        inspection.log.valid_events
    );
    let verification =
        verify_run_with_key(&outcome.run_dir, VerificationProfile::Integrity, Some(&key)).unwrap();
    assert!(verification.passed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_lived_hermes_gateway_splits_interleaved_tasks_inside_one_run() {
    let temporary = tempfile::tempdir().unwrap();
    let key = EncryptionKey::new([95; 32]);
    let iorec = env!("CARGO_BIN_EXE_iorec").replace('\'', "'\\''");
    let script = format!(
        r#"i=0
while [ "$i" -lt 64 ]; do
  printf '{{"task_id":"cron-a","session_id":"gateway-session","turn_id":"a-%s","api_request_id":"a-%s","api_call_count":%s}}' "$i" "$i" "$i" | '{iorec}' hook --source hermes --event pre_api_request >/dev/null
  printf '{{"task_id":"message-b","session_id":"gateway-session","turn_id":"b-%s","api_request_id":"b-%s","api_call_count":%s}}' "$i" "$i" "$i" | '{iorec}' hook --source hermes --event pre_api_request >/dev/null
  printf '{{"task_id":"message-b","session_id":"gateway-session","turn_id":"b-%s","api_request_id":"b-%s"}}' "$i" "$i" | '{iorec}' hook --source hermes --event post_api_request >/dev/null
  printf '{{"task_id":"cron-a","session_id":"gateway-session","turn_id":"a-%s","api_request_id":"a-%s"}}' "$i" "$i" | '{iorec}' hook --source hermes --event post_api_request >/dev/null
  i=$((i + 1))
done"#,
    );
    let outcome = run(RunOptions {
        command: vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        runs_dir: temporary.path().to_path_buf(),
        listen: loopback(),
        upstream: None,
        upstream_http2_prior_knowledge: false,
        provider: ProviderSelection::None,
        adapter: AdapterSelection::Hermes,
        policy: CapturePolicy {
            event_log_format: EventLogFormat::ZstdBlocks,
            ..CapturePolicy::default()
        },
        encryption_key: Some(key.clone()),
        allow_plaintext: false,
        tls_keylog: false,
        pcap: false,
        pcap_max_bytes: 1024 * 1024,
        task_cgroup: false,
        task_netns: false,
        transparent_proxy: false,
        egress_rules: Vec::new(),
        python_inject: false,
        node_inject: false,
        probe_helper: None,
        probe_policy_selection: None,
    })
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, 0);

    let index = load_tasks(&outcome.run_dir, Some(&key)).unwrap();
    assert_eq!(index.run_id, outcome.run_id);
    assert_eq!(index.tasks.len(), 2);
    assert!(index.unassigned_events > 0);
    for task in &index.tasks {
        assert!(task.event_count >= 128);
        assert_eq!(task.session_ids, vec!["gateway-session"]);
    }

    let cron = load_with_key(
        &outcome.run_dir,
        &TimelineFilter {
            logical_task_id: Some("task:cron-a".to_owned()),
            ..TimelineFilter::default()
        },
        Some(&key),
    )
    .unwrap();
    let message = load_with_key(
        &outcome.run_dir,
        &TimelineFilter {
            logical_task_id: Some("task:message-b".to_owned()),
            ..TimelineFilter::default()
        },
        Some(&key),
    )
    .unwrap();
    let cron_count = index
        .tasks
        .iter()
        .find(|task| task.logical_task_id == "task:cron-a")
        .map(|task| usize::try_from(task.event_count).unwrap())
        .unwrap();
    let message_count = index
        .tasks
        .iter()
        .find(|task| task.logical_task_id == "task:message-b")
        .map(|task| usize::try_from(task.event_count).unwrap())
        .unwrap();
    assert_eq!(cron.len(), cron_count);
    assert_eq!(message.len(), message_count);
    assert_eq!(
        cron.iter()
            .filter(|event| event.source == "hook:hermes")
            .count(),
        128
    );
    assert_eq!(
        message
            .iter()
            .filter(|event| event.source == "hook:hermes")
            .count(),
        128
    );
    assert!(
        cron.iter()
            .all(|event| event.task_id.as_deref() == Some("cron-a"))
    );
    assert!(
        message
            .iter()
            .all(|event| event.task_id.as_deref() == Some("message-b"))
    );
    assert!(
        cron.iter()
            .all(|event| event.logical_task_id.as_deref() == Some("task:cron-a"))
    );
    assert!(
        message
            .iter()
            .all(|event| event.logical_task_id.as_deref() == Some("task:message-b"))
    );
}
