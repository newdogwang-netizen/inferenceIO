# iorec

`iorec` is a local, auditable flight recorder for agent inference I/O. It wraps one command, records lifecycle and process evidence, tees supported model HTTP/SSE/WebSocket traffic, imports supported agent session files, and produces an explicit coverage manifest.

[Project blog](https://newdogwang-netizen.github.io/inferenceIO/) | [Production readiness](PRODUCTION_READINESS.md) | [Support matrix](SUPPORT.md) | [Harbor / Terminal-Bench audit runbook](docs/harbor-terminal-bench-audit.md)

The current release deliberately reports `claim: "best-effort"`. A successful run means the recorder completed cleanly; it does not mean every model call on the host was observed.

## Current development qualification (2026-09-18)

The real Harbor WebSocket capture now has 19 separately traceable calls on one
connection; see the [M1 qualification](benchmarks/2026-09-18-websocket-call-projection-linux-x86_64.json).
M2 adds paginated evidence views, explicit proof boundaries, external benchmark
annotations, worker liveness, and a resumable controlled audit command; see its
[scoped qualification](benchmarks/2026-09-18-m2-evidence-workflow-linux-x86_64.json). M2's
fresh-trial gate and the M3 real-agent matrix/final-candidate five-hour soak are
not yet qualified. Historical release and soak reports qualify their own exact
artifacts, not every newer worktree.

For the **local development** platform (unauthenticated, loopback-only, with
development database durability settings):

```bash
python3 tools/local_platform.py start --build
python3 tools/local_platform.py status
```

On the host running iorec, the stable Web URL is `http://127.0.0.1:8088` and the
API is `http://127.0.0.1:18080`. A desktop/SSH forwarded port is a separate,
possibly temporary address. The launcher preserves existing credentials in an
owner-only state file and refuses to downgrade an authenticated deployment.
Worker heartbeat health checks process/database liveness; processing success
and queue drain are reported separately.

See the [one-command Harbor workflow](docs/harbor-terminal-bench-audit.md#controlled-one-command-workflow)
for record → verify → independent audit → import → proof, safe retry behavior,
and plaintext staging cleanup.

## Build

Linux x86-64 and Rust 1.89 or newer are the supported build baseline.

```bash
cargo build --release --locked
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

## Quick start

Production runs are encrypted by default. Create a private key once, then record lifecycle and session evidence:

```bash
target/release/iorec keygen --output ./iorec.key
target/release/iorec run --key-file ./iorec.key -- your-agent-command
```

The key file is a master key, not a data key reused verbatim across recordings. New encrypted runs derive an independent 256-bit run key with HKDF-SHA256 over the manifest `run_id`; the resulting manifest authenticator prevents that ID or derivation metadata from being changed undetected. The manifest records the master-key ID and derivation version so readers reproduce the run key only after matching the supplied master key. The run key encrypts events and authenticates the manifest, and wraps three random per-run data-encryption keys for `body`, `pcap`, and `tls_secrets`; those class keys encrypt their respective blobs. Body includes ordinary payload and privileged-probe blobs that are not pcap or NSS key-log material. Use a distinct master key per tenant or security domain, rotate by using a newly generated key for new runs, and retain every old master key needed to read immutable historical runs. Legacy encrypted runs remain readable with their original direct/run-key blob layout, but cannot be selectively erased because their blobs do not have independent class keys.

Record a supported endpoint through the streaming reverse proxy:

```bash
target/release/iorec run \
  --key-file ./iorec.key \
  --upstream https://api.openai.com \
  --provider openai \
  -- your-agent-command
```

For a controlled h2c endpoint or an upstream that explicitly requires HTTP/2 prior knowledge, add `--upstream-http2-prior-knowledge`. This forces the recorder-to-upstream leg to HTTP/2; it is not an auto-detection switch and should not be used for an HTTP/1-only provider.

On a cgroup-v2 host with a delegated current scope, `--task-cgroup` creates a unique child boundary and moves the target into it while the target is stopped, before its real executable runs. Descendants inherit that membership; shutdown records remaining PIDs and removes only the exact child when empty. The option fails before target execution when delegation is unavailable. One way to request a transient user delegation on systemd hosts is:

```bash
systemd-run --user --scope -p Delegate=yes \
  target/release/iorec run --task-cgroup --key-file ./iorec.key -- your-agent-command
```

This establishes process ownership for capture helpers; it is not an egress firewall or network namespace.

For ordinary shared-host runs, explicitly classify expected non-model destinations with repeatable `--egress-rule CLASS=HOST:PORT` options:

```bash
target/release/iorec run --key-file ./iorec.key \
  --upstream https://api.openai.com \
  --egress-rule auth=login.example.com:443 \
  --egress-rule telemetry=otel.example.com:4318 \
  -- your-agent-command
```

The supported non-model classes are `auth`, `telemetry`, `update`, and `other`; the configured `--upstream` supplies the `model` identity. Before releasing the stopped target, the recorder resolves all rules concurrently under one five-second deadline and records the canonical rules, exact socket addresses, rule IDs, bounds, and truncation state in `egress_classification_snapshot`. A target socket is treated as expected only when both its address and port exactly match that snapshot. DNS failure aborts launch; a rule that collides with the model endpoint or assigns one socket to different classes is rejected. At most 256 rules, 64 addresses per rule, and 4,096 distinct classified sockets are admitted. `inspect` rebuilds `observed_egress_classes` from durable connection events; `unknown_external`, malformed labels, and `model_bypass` still downgrade verification, while explicit auth/telemetry/update/other traffic does not.

This is conservative discovery evidence, not an egress firewall or hostname proof. DNS changes after launch, SNI, proxy tunnels, connections shorter than the 100 ms process poll, and shared-CDN addresses remain limitations. `--egress-rule` therefore cannot be combined with proxy-only `--task-netns`; that mode deliberately permits no auxiliary IP endpoint.

For a fail-closed task-egress boundary, use the rootless network namespace mode:

```bash
target/release/iorec run --task-netns --pcap --key-file ./iorec.key \
  --upstream https://api.openai.com --provider openai -- your-agent-command
```

`--task-netns` preserves the target's original UID/GID but launches it in distinct user and network namespaces with an empty capability/bounding set and `NoNewPrivs`. It disables DNS and IPv6, permits loopback, and applies an nftables output policy that permits only IPv4 TCP to the recorder gateway and its exact random proxy port. The recorder captures all task-namespace IP traffic with immediate-mode tcpdump, verifies the fixed firewall and sysctl policy before target release and again at shutdown, and records counter deltas only for the target window. A direct-IP attempt is blocked and makes `unknown_egress` nonzero; packet loss, policy mutation, helper failure, late namespace traffic, or unclosed descendants prevents transport completeness. Applications that require separate auth, telemetry, update, or arbitrary network endpoints will fail in this mode.

For an Agent that cannot honor endpoint or proxy configuration, add transparent interception:

```bash
target/release/iorec run --task-netns --transparent-proxy --pcap --tls-keylog \
  --key-file ./iorec.key --upstream https://api.openai.com --provider none -- your-agent-command
```

`--transparent-proxy` leaves the Agent's model URL unchanged. Before target release, the recorder requires a complete launch-time, non-loopback IPv4 upstream snapshot, creates a separate mount namespace, installs that snapshot as a read-only private `/etc/hosts`, and applies exact nftables DNAT rules from the original model sockets to the random recorder gateway port. Loopback endpoints are rejected before launch because Linux loopback output DNAT does not traverse this rootless slirp path reliably. DNS, IPv6, inherited generic proxy variables, and all other egress remain disabled. HTTPS uses a seven-day, per-run CA and matching leaf certificate; both private keys exist only in recorder memory, while the public CA is exposed to common Python, Node, Go, curl, and AWS trust variables for the target window. The public CA and hosts snapshot are mode `0600` and removed after namespace shutdown. The ingress supports HTTP/1.1, HTTP/2 ALPN, SSE, and WSS; bounded concurrent TLS handshakes prevent a slow client from serializing acceptance. With `--tls-keylog`, the recorder logs both ingress and upstream rustls secrets into the encrypted key-log stream so the task pcap can be independently decoded.

This mode is still experimental. It fails closed on truncated/no-IPv4 DNS results and exact-rule mutation. Custom DNS resolvers that ignore `/etc/hosts`, certificate pinning, unrecognized trust configuration, DNS changes after launch, QUIC/HTTP/3, auxiliary auth/telemetry/update traffic, and background descendants outside the root-command lifetime are not claimed. A failure to trust the temporary CA is visible as a failed model call; it is not silently counted as captured traffic.

This mode is Linux-only and must run as a non-root account with enabled unprivileged user namespaces, subordinate UID/GID ranges, setuid-root `newuidmap`/`newgidmap`, and trusted fixed-path `unshare`, `setpriv`, `mount`, `slirp4netns`, `nsenter`, `nft`, `sysctl`, and `tcpdump`. On Debian-family systems those tools normally come from `uidmap`, `util-linux`, `slirp4netns`, `nftables`, `procps`, and `tcpdump`. `iorec doctor` reports the exact prerequisite failure. TShark 4.4+ is additionally required for offline transport audit. Add `--tls-keylog` for encrypted recorder TLS diagnostics; controlled plaintext fake-server tests do not create a meaningless empty TLS secret record.

Every run stores a versioned `manifest.probe_plan` before target launch. The preflight planner combines passive runtime/TLS markers, intended proxy protocol paths, current packet/eBPF prerequisites, and the selected proxy, runtime, key-log, pcap, cgroup, and helper options. Each candidate has a stable ID, status, priority, selection bit, independent-observer bit, and bounded reason; the event log keeps a compact lifecycle pointer while the manifest retains the full plan. Static TLS strings and tool presence remain hints. A helper stays `bridge_required` unless it was selected explicitly or by a trusted `--probe-policy`; the recorded selection includes its exact path, SHA-256, kind, mode, and policy rule ID. Observed protocols/TLS surfaces are still finalized separately from runtime evidence.

Inspect the same plan without creating a run or executing the target:

```bash
target/release/iorec plan --json --python-inject --tls-keylog \
  --upstream https://api.example.invalid -- /usr/bin/python3 agent.py

target/release/iorec plan --json \
  --probe-policy /etc/iorec/probe-policy.json -- /usr/bin/python3 agent.py
```

For a passively detected Python target, `--python-inject` materializes a private, content-hashed `sitecustomize` shim and prepends only its directory to `PYTHONPATH`. The shim observes synchronous and asynchronous OpenAI Python SDK Chat Completions and Responses calls, including stream events, without changing the SDK package on disk. It also wraps sync/async `httpx` sends and response-byte iterators plus `requests.Session.send`/`Response.iter_content`, preserving transport exceptions and consumer cancellation:

```bash
target/release/iorec run --python-inject --key-file ./iorec.key -- hermes
```

The shim submits through a bounded 256-entry background queue and never raises an instrumentation failure into target code. It limits recursion, item count, strings, each encoded submission, transport headers, query-key reporting, and streamed response capture (64 MiB/100,000 chunks); URL userinfo and query values are never submitted. Credentials receive an extra in-process redaction pass before the collector's mandatory policy. Queue loss, truncation, submission failure, and stream-correlation failure produce a capture-gap event and downgrade the run. Python `-S`, `-I`, and `-E` modes are rejected when visible because they bypass `sitecustomize`; unsupported SDK versions, target mutation, alternate HTTP methods, non-Python descendants, and an absent startup event remain explicit gaps. Forked Python children create a fresh sender and readiness event. This is an L2 semantic copy, not independent transport proof.

For a passively detected Node.js target, `--node-inject` materializes private CommonJS-preload and ESM-loader modules and appends a quoted `--require` to the existing `NODE_OPTIONS`. The preload observes CommonJS and ESM OpenAI SDK Chat Completions and Responses calls, including stream completion, error, and consumer cancellation; it also wraps global `fetch` plus CommonJS `undici` fetch/request/stream entry points. The ESM model wrapper is registered before the entry module on Node versions exposing `node:module.register`:

```bash
target/release/iorec run --node-inject --key-file ./iorec.key -- node agent.mjs
```

The Node observer applies the same target-controlled evidence boundary and a 256-entry queue, 0.5-second socket timeout, bounded sender deadline, structural/string/binary/record limits, and exact credential-key redaction before collector policy. Fetch response clones stop at 64 MiB or 100,000 chunks and record loss rather than buffering without limit. `NODE_OPTIONS` inheritance covers worker threads and forked Node children; a child that removes the environment, an older runtime without ESM loader registration, direct ESM `undici` imports, frozen or mutated SDK objects, unsupported SDKs, native addons, non-Node descendants, and Bun remain explicit gaps. `--node-inject` rejects a detected Bun target. This layer never upgrades transport coverage.

Third-party Rust integrations use the versioned [Adapter SDK](ADAPTER_SDK.md).
An adapter implements only `detect`, `configure`, `parse`, and `correlate`, then
passes its validated host to `runner::run_with_adapter`. Native hook evidence is
durable before parsing, parsed output is bounded and redacted again, and SDK
correlation confidence is capped by evidence basis. The v1 interface is
statically linked and process-local; reviewed adapter code is part of the
recorder trust boundary, and the ordinary CLI exposes only built-in adapters.

Plaintext evidence requires an explicit risk acknowledgement. Metadata-only mode is the least sensitive plaintext option:

```bash
target/release/iorec run --allow-plaintext --body metadata-only -- your-agent-command
```

Inspect and export a completed run:

```bash
target/release/iorec inspect ./runs/<run-id> --verify-blobs --key-file ./iorec.key
target/release/iorec verify ./runs/<run-id> --profile client --key-file ./iorec.key
target/release/iorec support --json
target/release/iorec tasks ./runs/<run-id> --key-file ./iorec.key
target/release/iorec timeline ./runs/<run-id> --key-file ./iorec.key
target/release/iorec state ./runs/<run-id> --key-file ./iorec.key
target/release/iorec export ./runs/<run-id> --format raw --output ./bundle --key-file ./iorec.key
target/release/iorec export ./runs/<run-id> --format openinference --output ./trace.jsonl --key-file ./iorec.key
target/release/iorec export ./runs/<run-id> --format otlp --output ./traces.otlp.json --key-file ./iorec.key
target/release/iorec export ./runs/<run-id> --format replay --output ./replay --key-file ./iorec.key
target/release/iorec export ./runs/<run-id> --format platform --output ./platform-import.tar --key-file ./iorec.key
target/release/iorec probe-export ./runs/<run-id> --output ./probe.jsonl --key-file ./iorec.key
```

The platform export is an explicit plaintext declassification boundary for an encrypted run. It verifies the full run, decrypts into private temporary storage, creates a deterministic mode-`0600` tar accepted by `POST /v1/recordings:import`, refuses overwrite, and never publishes a bundle above the platform's 5 GiB import limit. Protect and delete this plaintext artifact according to your evidence policy.

The embedded [`support-matrix.v1.json`](support-matrix.v1.json) is the machine-readable compatibility contract. `iorec support` reports exact Agent/runtime/TLS/protocol/capture-path cells; combinations not listed default to `unknown`. A verified cell cannot contain wildcard dimensions and must point to an executable regression or a SHA-256-pinned artifact. Experimental and unknown cells retain explicit limitations, so a narrow qualification never becomes a broader coverage claim.

Upload a finalized run directly to an `iorec-platform` API using a private mode-`0600` token file:

```bash
target/release/iorec upload ./runs/<run-id> \
  --api https://iorec.example.com \
  --token-file ./platform.token \
  --key-file ./iorec.key
```

The uploader registers a collector, keeps its one-hour session token only in memory, uploads immutable SHA-256 body blobs and fixed 2,000-event/4 MiB zstd batches, reconciles the server's durable sequence, and seals with the authenticated manifest. Ordinary upload and backfill always omit pcap and TLS-secret blobs; old spool plans are sanitized before use, so those tiers require an explicit controlled platform-bundle import and cannot leak through routine synchronization. A local run may span a contiguous chain of platform Recording segments while retaining one global event sequence; only the last segment finalizes the capture run. Its private `.upload/` spool stores no credentials or plaintext evidence and resumes idempotently after restart. Transient failures use bounded exponential retry; `--max-batches N` provides a resumable scheduler budget. HTTPS is mandatory unless `--allow-http` is explicitly supplied for a controlled local environment. Once an upload target exists, pruning refuses the run until every segment for every target is fully acknowledged and sealed.

For continuous operation, run `iorec collector --runs-dir ./runs --api https://iorec.example.com --token-file ./platform.token --key-file ./iorec.key`. The collector stores no credential or session token in its private state, maintains a stable identity and 30-second health/config loop, automatically uploads finalized runs, and long-polls platform requests. Accepted content configuration is persisted as a restrictive overlay for new runs only; local limits and mandatory redaction always win. Active `flush` and `seal` first persist an exact writer-confirmed durable boundary; crash recovery replays that same boundary, and a seal starts the next segment at the following global sequence. The daemon also seals active segments automatically at `--segment-max-bytes` logical evidence bytes (default 64 MiB) or `--segment-max-seconds` age (default 900 seconds). Sequence-range `backfill` expands to immutable local batch boundaries and force-republishes both batch and referenced blob objects, including after seal. `retention_local.acked_events_ttl_hours` controls whole-run retention; `body_ttl_hours`, `pcap_ttl_hours`, and `tls_secrets_ttl_hours` independently erase class keys and ciphertext. The class settings require both `--allow-remote-delete` and a local key. A `delete_local` request may likewise include `class: body|pcap|tls_secrets`; its platform request UUID becomes the recoverable erasure operation ID. Automatic TTL/pruning and class-only deletion remain gated on a fully ACKed, sealed segment chain. An authenticated whole-run `delete_local` still requires explicit local enablement but intentionally overrides upload completion, so an offline or partially uploaded sensitive run cannot become undeletable. Sensitive upload remains locally rejected. `--once` performs one non-blocking scheduler cycle for cron and diagnostics.

One physical run may contain many logical tasks when a long-lived Agent process serves concurrent sessions or cron work. The versioned `agent-task-or-session-v1` policy uses an explicit native `task_id` first and otherwise falls back conservatively to `session_id`; run-scoped recorder events remain unassigned. `iorec tasks` reports bounded task summaries and `iorec timeline --task task:<native-id>` selects one task without changing the immutable evidence. Task identity also survives correlation, Replay, OpenInference/OTLP export, multi-segment upload, platform reprocessing, timeline queries, and the Web console. The task and task/session-association indexes each fail explicitly at 100,000 entries rather than silently merging or truncating work.

Timeline output is cursor-paged to keep long runs memory-safe: the default page contains at most 10,000 matching events and the hard per-page limit is 100,000. JSON output includes `truncated` and `next_after_sequence`; continue with `--after-sequence <n>`, and use `--task`, `--session`, `--turn`, or `--inference` to narrow the scan. Every page still validates the complete event log before returning. State analysis tracks at most 100,000 response observations, inference targets, and state references per category; reaching that bound is explicit in the graph and adds a nonzero unresolved count to the manifest instead of aborting run finalization.

The OpenInference export is `iorec-openinference-jsonl-v1`: OpenInference semantic attributes represented as local JSONL. Per-attempt prompt/response attributes are omitted with an explicit captured-byte count after 16 MiB or 100,000 chunks; evidence sequence arrays retain at most 100,000 values and carry the full count plus a truncation flag. The OTLP export is an `otlp-http-json-v1` `ExportTraceServiceRequest` using protobuf JSON encoding and the same semantic attributes. It is suitable as the body of an `application/json` POST to an OTLP/HTTP `/v1/traces` endpoint. `iorec` writes the request body locally and does not send it over the network; the output is private mode `0600` because span attributes can contain captured prompts and responses.

The replay export is a private `iorec-replay-bundle-v1` directory. It reconstructs exact captured HTTP request bytes and complete response bytes as comparison oracles, but never includes provider credentials or claims deterministic model generation. Because exactness is required, an attempt with more than 100,000 evidence records or request/response chunks is rejected explicitly rather than partially exported. Inspect `client_replay_complete` and every attempt's limitations before use.

Run `iorec doctor` before requesting packet capture. Without `--task-netns`, `--pcap` needs a root-owned, executable, group/other-nonwritable `tcpdump` in a fixed system path plus host packet-capture privilege, `--upstream`, and `--key-file`; caller-controlled `PATH` is never used and the helper receives a cleared environment with only a fixed locale. Capture is filtered to at most 64 numeric upstream endpoints resolved before launch, on loopback when every endpoint is local and otherwise on `any`. This shared-host snapshot can include unrelated traffic to the same addresses and miss later DNS changes. With `--task-netns`, tcpdump runs inside the isolated user/network namespace and does not require host `CAP_NET_RAW`; it captures the full IP task egress rather than an upstream-address snapshot. Both paths stream stdout under the pcap byte quota, use immediate capture to avoid losing very short exchanges, and continuously drain stderr while retaining only a bounded tail. `--tls-keylog` injects `NODE_OPTIONS=--tls-keylog=...` for detected Node commands and `SSLKEYLOGFILE` for supported runtimes; the recorder's certificate-validating rustls upstream client and transparent rustls ingress write their TLS secrets to the same private FIFO. Secrets are persisted only as encrypted blobs and deduplicated through a rotating 65,536-digest memory window. Shutdown is prioritized over a continuously readable FIFO; oversized input and persistence failure keep draining without retaining further secrets so the target cannot be blocked by recorder storage failure. Bun, custom Python SSL contexts, target-owned rustls clients, and unknown runtimes remain explicit coverage gaps outside recorder-terminated transparent TLS.

Privileged system capture uses the versioned external-helper contract. The repository includes digest-pinned bridge implementations and example configurations for eCapture TLS plaintext and AgentSight process events:

```bash
iorec run --key-file ./iorec.key --task-cgroup \
  --probe-helper /usr/local/libexec/iorec/ecapture-bridge -- your-agent-command

iorec run --key-file ./iorec.key --task-cgroup \
  --probe-helper /usr/local/libexec/iorec/agentsight-bridge -- your-agent-command

iorec run --key-file ./iorec.key --task-cgroup \
  --probe-policy /etc/iorec/probe-policy.json -- your-agent-command
```

Automatic selection never executes a tool merely because it appears on `PATH`. The bounded, strict-schema policy must live at a canonical non-symlink path under protected ancestors and binds each rule to an exact helper SHA-256, OS/architecture, and at least one exact target-executable or TLS-surface fingerprint. Equal-priority matches fail as ambiguous; missing eBPF/cgroup prerequisites, mismatched fingerprints, helper replacement, and unknown fields fail before target launch with rule-scoped reasons. Start from [`tools/probe-policy.example.json`](tools/probe-policy.example.json), replace the all-zero digest, and keep each rule no broader than its qualified support cell.

The target is stopped before `exec` and continues only after a valid helper `ready` record. Protocol v2 supplies the target PID, canonical executable path and SHA-256, requested PID-tree/cgroup filter, run ID, fixed locale, and an otherwise empty environment. Both bridges independently verify the executable and upstream digests, require cgroup scope, retain bounded cgroup-member history, and translate known loss or limit signals into gaps. The eCapture bridge supports configured OpenSSL `tls` and static Go `gotls` modes; GoTLS binds `--elfpath` to the recorder-verified target binary and normalizes reversed READ/WRITE tuples into one connection. It emits nonempty TLS bytes from the synchronous text/hex stream and gives the upstream a bounded quiescence interval. The AgentSight bridge emits exact upstream JSON for process, file, network, coordination, and memory events. Input, queues, diagnostics, identities, and event counts have explicit ceilings; zero hits, schema drift, overflow, tracking failure, or missing shutdown evidence downgrade coverage. The recorder signals only the bridge during graceful stop; its fixed deadline still kills the whole helper process group.

The committed [eCapture OpenSSL qualification](benchmarks/2026-09-16-ecapture-bridge-linux-x86_64.json) passes exact-byte, descendant, outside-cgroup isolation, four-connection, 1 MiB aggregate long-payload, shutdown, encryption, and integrity checks for one Debian 13 x86-64/kernel 6.12/curl OpenSSL 3.5.7/HTTP/1.1 cell. The separate [GoTLS qualification](benchmarks/2026-09-16-ecapture-gotls-linux-x86_64.json) verifies exact Go 1.24.13 and Go 1.25.13 cells: each captures four concurrent 64 KiB request/response bodies, preserves four bidirectional connection IDs, reports zero drops, excludes two concurrent same-binary requests outside the target cgroup, and passes authenticated-manifest plus independent decrypted-export verification. The [AgentSight qualification](benchmarks/2026-09-16-agentsight-bridge-linux-x86_64.json) preserves encrypted process/file/network evidence and excludes a concurrent outside-cgroup marker for its pinned v1.0.25 build. AgentSight v1.0.25 does not count process ring-buffer reservation failures, so the bridge always emits a loss-observability gap and never reports a complete final. Its high-level shutdown also omitted the raw end anchor during both live runs. GnuTLS, NSS, BoringSSL, HTTP/2 GoTLS interpretation, other Go patch releases, named Go Agents, arm64, containers, and other kernels remain unqualified. See [PROBE_HELPER_PROTOCOL.md](PROBE_HELPER_PROTOCOL.md) for installation and fail-closed rules.

The committed [offline transport qualification](benchmarks/2026-09-16-transport-audit-linux-x86_64.json) exercises real local TLS with certificate validation. One HTTP/1.1 stream and two concurrent, padded HTTP/2 streams were decrypted and reconstructed from encrypted pcap/key-log evidence; every eligible request and response body matched the proxy capture by exact byte length and SHA-256. Both reports deliberately remain incomplete because the upstream-address snapshot is not a task-egress capture, executable TLS surfaces remain conservatively unknown, and the run has no one-to-one transport correlations.

The [rootless task-network qualification](benchmarks/2026-09-16-task-netns-transport-linux-x86_64.json) records a qualified-candidate positive/negative pair. The positive certificate-validating HTTPS run captured 14/14 task packets, matched its complete request/response bodies, had zero drop/unknown/bypass/parser counts, and returned schema-v2 audit `complete: true` for the named network-namespace IP boundary. The paired direct-IP attempt was denied by nftables; its model payload still matched, but `unknown_egress` correctly forced audit status 3 and `complete: false`. Transparent-network and schema-v3 changes postdate that report, so it is historical evidence rather than qualification of the current release binary.

The [schema-v3 platform transport qualification](benchmarks/2026-09-16-platform-transport-audit-linux-x86_64.json) closes that schema gap for one proxy-only HTTP/1.1 cell. Its report-bound bundles were imported through the authenticated production API image and processed by the pinned, non-root TShark Worker. The clean run reached platform `client-complete`; the paired blocked direct-IP attempt retained exact proxy/wire payload agreement but `unknown_egress=2` kept final platform coverage at `best-effort`. The artifact also records that both historical schema-v2 bundles fail closed under the current source-boundary contract. Those report-bound image IDs predate the final images; the named transport/coverage, Dockerfile, and proof-migration inputs remain byte-identical, and later surrounding changes are covered by current tests and final-image E2E rather than represented as a replay of this artifact.

The [real Agent CLI transport qualification](benchmarks/2026-09-16-real-agent-cli-transport-linux-x86_64.json) pins exact Gemini CLI 0.60.0, Codex 0.154.0, Claude Code 2.1.273, Hermes 0.19.0, and `iorec` executable hashes. All four real CLIs completed inside the rootless proxy-only task network. Independent schema-v3 audits reconstructed five model attempts and seven semantically excluded non-model requests, matched all five model request/response body pairs exactly, and found no missing, extra, ambiguous, unresolved-correlation, capture-drop, or successful-unknown-egress evidence. The qualification uses a controlled loopback provider and claims only the named target-network-namespace IP boundary; it is not a public-provider availability or host-wide completeness claim.

The [Harbor / Terminal-Bench WebSocket qualification](benchmarks/2026-09-18-harbor-websocket-transport-linux-x86_64.json) wraps one real Harbor-managed Codex 0.154.0 `html-js-filter` trial. Schema-v4 independently decrypted the WSS connection, reconstructed 54 client and 13,726 server messages, matched 105,775 request bytes and 4,641,287 response bytes against proxy evidence, and reported zero kernel drops, missing/extra/ambiguous attempts, or audit gaps. The local platform repeated the proof and populated the normalized response view. Harbor's separate task-correctness reward was `0.0`; it does not weaken the passing capture-integrity result.

Decryption is always an explicit operation:

```bash
iorec pcap-export <run> --output ./capture.pcap --key-file ./iorec.key
iorec tls-keys-export <run> --output ./tls.keys --key-file ./iorec.key
iorec probe-export <run> --output ./probe.jsonl --key-file ./iorec.key
iorec transport-audit <run> --output ./transport-audit.json --key-file ./iorec.key
```

All four commands refuse to overwrite files, refuse destinations inside the source run, validate all source evidence, and create mode `0600` output. Probe export includes only accepted protocol records and revalidates that each plaintext JSON object type matches its event envelope; rejected malformed messages remain encrypted in the run. Probe JSONL contains decrypted TLS plaintext and must be protected like pcap plus TLS keys. `transport-audit` additionally requires a root-owned, non-writable fixed-path TShark 4.4 or newer. Its schema-v4 report names the exact completeness boundary as `target-network-namespace-ip-transport`; it is not a claim about same-user Unix-socket daemons, Agent lifecycle semantics, server-hidden context, or host-wide traffic. The command decrypts pcap and keys only inside a private temporary directory, bounds decoder time and output, reconstructs HTTP/1.1 bodies, multiplexed HTTP/2 DATA bodies, and fragmented WebSocket messages, then publishes only lengths, hashes, methods, status codes, sanitized paths, and query-key names. Proxy-only task-egress runs may legitimately have zero TLS-key records because the captured target-to-proxy leg is plaintext; HTTPS transparent runs require successfully decrypted TLS streams. Exit status is zero only when the exact proxy/wire body multiset agrees and task-egress scope, enforced model routing, terminal/payload coverage, and every drop/unknown/bypass/QUIC/parser gate pass. Unknown target TLS libraries do not weaken a transparent result only when recorder-side TLS keys actually decrypt the task pcap; missing decryption remains a hard gap. Logical agent-anchor correlation remains reported separately because it is not used to pair the independently compared transport bodies. A useful payload match with remaining transport gaps writes its report and returns status 3.

## Evidence layout

Each run is a private directory containing:

- `manifest.json`: command metadata, capture policy, counts, capture sources, known gaps, coverage state, master-key ID, and key-derivation version. Encrypted runs authenticate its canonical content with the derived run key.
- `events.jsonl`: monotonic append-only event envelopes. The default legacy framing stores one envelope per line; `--event-log-format zstd-blocks` stores independently recoverable zstd blocks before optional encryption. Encrypted legacy records bind `run_id` and `sequence`; encrypted blocks authenticate the run ID, first sequence, event count, uncompressed size, and plaintext SHA-256.
- `blobs/sha256-*`: immutable content-addressed payloads.

The writer durably creates the event-log directory entry and acknowledges an event only after `sync_data`. Concurrent events that are already queued can share one sync batch, but every caller is acknowledged only after that shared durability boundary; if a capacity boundary falls inside a batch, only its synced prefix is acknowledged. Writer and reader enforce the same 24 MiB physical event-record and 8 MiB manifest limits. Untrusted JSON is preflighted before deserialization with a 64-level nesting and 100,000 structural-token ceiling, including session files, adapter settings, proxy semantics, and helper messages. Stored envelopes reserve another fixed 16 nesting levels and 4,096 structural tokens only for recorder-owned wrappers; writers and readers enforce the same stored limits. Events use UUIDv7 IDs created at the single serialization point; checked readers require them to increase with sequence, detecting duplicates and reordering in constant memory. Recovery accepts a contiguous sequence from 1 and can quarantine only an incomplete final tail; the quarantine, truncated log, and parent directory are synced before success. Authentication failures, sequence gaps, cross-run events, mixed encryption scope, symlinks, and hash/size mismatches are hard errors or explicit corruption. SSE semantic parsing stops at the first capture-queue sequence gap, preventing noncontiguous bytes from being synthesized into an apparently valid event. Correlation uses indexed status/terminal lookup and time-indexed candidates; it accepts at most 100,000 anchors/transports, and an ambiguous decision retains the exact candidate count but serializes at most 1,024 candidate IDs. Inspection and exact exports fail with a structured `analysis_limit` instead of silently truncating high-cardinality truth.

Process discovery records the names and process-instance counts of observed TLS surfaces, including same-PID executable/name changes across `exec`. The command executable's existing full-file SHA-256 pass also scans conservative BoringSSL, rustls, Go `crypto/tls`, OpenSSL, GnuTLS, and NSS markers across read boundaries; these are labeled as binary markers/dependencies and remain unknown coverage, not verified probes. Permission failures, unreadable descriptor entries, malformed or safety-omitted `/proc/<pid>/net` rows, and socket-table read failures are emitted as deduplicated `process_network_scan_gap` evidence; inspection rolls their conservative lower-bound counts into `unparsed_connections` instead of treating absent connection events as proof of no egress. A scan admits at most 65,536 processes, 262,144 descriptors per process, 262,144 connections, and 65,536 gap observations. Cross-run gap identities retain at most 10,000 entries; reaching that limit creates one incomplete terminal and counts all further unreported observations without growing the set. Optional cgroup-v2 assignment adds a kernel-enforced membership boundary before target `exec`; unreadable membership, failed assignment, surviving members, or unverifiable cleanup are explicit capture loss.

At launch, the recorder resolves at most 64 unique socket addresses for the configured upstream. A target-process connection to one of those addresses that does not terminate at the recorder listener is labeled `model_bypass`, counted separately, and fails transport verification. Explicit auxiliary egress rules use the same exact-address-and-port principle and never override the model classification. This is a conservative launch-time snapshot: later DNS changes and unmatched provider addresses remain unknown egress rather than being treated as safe.

Agent version discovery is passive: Codex standalone `releases` and Claude native `versions` paths use constrained install anchors; npm-style Codex/Claude/Gemini installs require a bounded local `package.json` whose package name exactly matches the supported Agent; Hermes requires an unambiguous `hermes-agent` distribution inside a validated venv layout. Untrusted numeric path components and mismatched packages are ignored; the target is never invoked a second time for discovery.

Native hook events are an explicitly untrusted evidence tier because the target receives the collector token. They are stored under `hook:<source>` and cannot use recorder-reserved sources; transport counts, network/TLS coverage, correlation results, and sensitive-artifact exports are derived only from recorder-owned event sources. Capture-source entries for collectors, adapters, session readers, packet/TLS capture, and correlation are activated by durable lifecycle evidence rather than configuration intent.

The optional Python and Node.js runtime shims use that same target-controlled tier. Their `model_call_started` IDs contribute observed logical-call counts and bounded correlation candidates, but can never establish transport coverage. A runtime-reported gap may only downgrade coverage.

External UDP connections are reported separately as `possible_quic_connections`. They fail the transport verification profile because this release cannot decode QUIC/HTTP3; the label is deliberately “possible” because ports and transport alone cannot prove that a connection carried model traffic.

## Capture policy

`--body metadata-only` keeps hashes, sizes, headers after credential filtering, and normalized metadata without payload blobs. Hook payloads are reduced to type and top-level item count; session records retain only their bounded lifecycle summary. Full payload values do not leak through `normalized` events in this mode. `--allow-path` restricts body capture to selected absolute path prefixes; policies accept at most 1,024 path/header entries and reject a per-blob limit above the 64 MiB writer ceiling. `--max-body-bytes` is enforced independently for every request or response direction, including secondary SSE-event raw references: an event outside the captured response prefix retains size/hash/semantics but cannot create another body blob. A stream may span many content-addressed blobs, but each physical blob has a 64 MiB writer/reader safety limit and a run may contain at most 250,000 blob-directory entries. File-count and byte reservations are atomic. Request JSON normalization is capped at 8 MiB each and 16 concurrent normalizations (128 MiB total reservation); requests beyond that concurrency continue streaming and hashing but are conservatively marked semantically inconclusive. Sanitized JSON retains at most 64 levels, 100,000 nodes, 10,000 items per container, and 1,024 redaction paths; safety truncation is explicit and increments capture loss. The authenticated hook collector accepts 16 MiB per submission and at most eight concurrent connections. `--max-event-storage-bytes` bounds the physical append-only log (default 4 GiB), while `--max-run-blob-storage-bytes` bounds the physical content store (default 2 GiB); encryption framing and pre-existing/orphan files count toward their respective budgets. `zstd-blocks` groups at most 1,024 events and 32 MiB of plaintext per durability unit, caps encoded records at 48 MiB, validates decompressed length and SHA-256, and rejects decompression bombs before allocation. A torn final block is quarantined by the existing recovery flow; legacy JSONL remains readable, and a nonempty run cannot silently change formats on resume. Exhaustion marks capture incomplete without interrupting proxied HTTP or WebSocket traffic. Signal forwarding, target exit-code preservation, cleanup, and final manifest reconstruction remain operational after the event writer stops, although the unavailable evidence is truthfully counted as capture loss.

For recognized multimodal request parts, the recorder counts modalities and distinguishes inline data/base64 content from external image URLs, file IDs, and file URIs. Reference values never enter normalized summaries. Any detected external payload reference that was not independently snapshotted increments `unresolved_payload_references` and prevents the client-evidence verifier and replay feasibility checks from reporting success.

Authorization, cookie, API-key, authentication-info, proxy-credential, credential/signature-suffixed, and URL-bearing redirect/link headers never enter ordinary events. They are still forwarded unchanged. Normalized model/state/SSE/URL metadata strings are limited to 1 KiB and replaced by a length-bearing SHA-256 placeholder if oversized or control-bearing; query-key lists are capped at 128 while preserving the full parameter count and a truncation flag. This does not sanitize packet captures or exported TLS secrets; those artifacts can reveal credentials and full payloads.

## Operations and audit

Operational reads, exports, recovery, migration, run starts, and deletions append to `runs/.iorec-audit.jsonl`. Verify its ordered SHA-256 chain with:

```bash
iorec audit-verify --runs-dir ./runs
```

The chain detects edits, reordering, truncation, and incomplete tails relative to the local file. It is not signed or externally anchored, so a same-user attacker can replace the entire chain.

Pruning is preview-only unless `--execute` is supplied. It deletes only finalized immediate `run-*` children after validating directory identity and encrypted manifest authentication:

```bash
iorec prune --runs-dir ./runs --older-than-days 30
iorec prune --runs-dir ./runs --older-than-days 30 --execute --key-file ./iorec.key
```

Class retention is independently previewable and executable for new class-keyed encrypted runs:

```bash
iorec expire-classes --runs-dir ./runs --body-ttl-hours 72 \
  --pcap-ttl-hours 24 --tls-secrets-ttl-hours 24 --key-file ./iorec.key
iorec expire-classes --runs-dir ./runs --body-ttl-hours 72 \
  --pcap-ttl-hours 24 --tls-secrets-ttl-hours 24 --key-file ./iorec.key --execute
iorec erase-class ./runs/<run-id> --class tls-secrets \
  --key-file ./iorec.key --execute
```

Before erasing a class, `iorec` authenticates the finalized manifest and class-key envelope, verifies any configured upload target is fully ACKed and sealed, and refuses an active writer. It durably records an authenticated intent, appends the local hash-chain audit, removes that class's wrapped key and ciphertext, verifies convergence, and records completion. Repeating the operation resumes an interrupted intent or returns the authenticated completed receipt. `inspect` reports erased and pending classes explicitly; a pending operation fails the integrity profile, while a completed operation preserves integrity verification for retained evidence and truthfully downgrades payload completeness. This is verifiable cryptographic erasure from the live run namespace, not proof that old physical blocks disappeared from snapshots, backups, copy-on-write filesystems, or SSD remapping.

`iorec migrate <run> --key-file ...` authenticates a readable legacy encrypted manifest without rewriting event or blob evidence.

## Current boundaries

- The endpoint proxy is the verified client transport path for HTTP/1.1, SSE, and reassembled WebSocket messages. A controlled 100-stream h2c test and a real local TLS/ALPN audit verify that concurrent HTTP/2 bodies do not cross between attempts. `transport-audit` independently reconstructs HTTP/2 stream IDs, exact DATA bodies, and canonical WebSocket messages, but the endpoint proxy still does not expose upstream HTTP/2 connection/stream IDs for one-to-one event correlation.
- Shared-host packet capture is filtered to at most 64 numeric upstream endpoints resolved before target launch and does not prove absence of bypass. The opt-in Linux `--task-netns` path enforces either a proxy-only boundary or experimental exact-socket transparent DNAT; current live regressions cover rootless Linux x86-64, not containers, macOS, arm64, custom resolvers, pinned certificates, or arbitrary multi-endpoint applications.
- Whole-run age pruning, optional event-block compression, and independent `body`/`pcap`/`tls_secrets` TTLs are shipped. New encrypted runs use wrapped per-class keys and retain authenticated intent/completion receipts, so key-envelope removal plus ciphertext convergence is verifiable cryptographic erasure. Physical-media erasure and deletion from external snapshots/backups are not claimed.
- HTTP/1.1, multiplexed HTTP/2, and WebSocket offline reconstruction with exact proxy-to-wire body comparison are shipped. Rootless proxy-only and experimental transparent task egress automatically test cleartext/TLS interception, HTTP/2 ALPN, WSS, encrypted TLS-key/pcap audit, and a blocked direct-IP bypass. QUIC/HTTP3 decoding, broad OS/container/AgentSight/eCapture matrices, active OTLP upload/binary protobuf export, and deterministic model generation are not yet shipped. The bounded encrypted privileged-helper protocol and limited-matrix AgentSight process and eCapture TLS bridges are shipped, but neither makes an untested runtime/kernel combination complete. External UDP is surfaced as a conservative QUIC possibility. Offline OTLP/HTTP protobuf-JSON request bodies and replay bundles are available.
- Agent adapters are version-sensitive. Inspect `known_gaps` and `unresolved_correlations` for every run.
- The root command's exit defines the run boundary. Surviving background descendants are not killed automatically, but their count and open connections are recorded, capture loss becomes nonzero, and activity after that boundary is explicitly uncovered.
- Encrypted manifests are atomically written and AEAD-authenticated, but are not digitally signed. Plaintext-run manifests and the local audit chain are not protected against same-user rewriting.

See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md), [PERFORMANCE.md](PERFORMANCE.md), [SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md), [PROBE_HELPER_PROTOCOL.md](PROBE_HELPER_PROTOCOL.md), the [feature roadmap](agent-inference-flight-recorder-feature-roadmap.md), and the [capture research](agent-inference-io-capture-research.md).

## License

Licensed under either Apache-2.0 or MIT, at your option.
