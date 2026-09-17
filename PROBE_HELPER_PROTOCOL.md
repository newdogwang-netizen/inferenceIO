# Privileged probe helper protocol

`iorec run --probe-helper /absolute/path --key-file key -- <command>` starts an external capture helper before the target command executes. The helper path must be canonical, executable, owned by root or the recorder user, and protected by non-writable ancestors (a root-owned sticky directory such as `/tmp` is allowed). A key is mandatory because probe output can contain plaintext credentials and model payloads.

The target initially runs through a fixed shell trampoline that stops itself before `exec`. `iorec` starts the helper with an empty environment:

```text
HELPER --iorec-probe-protocol 2 \
  --target-pid PID \
  --target-executable /CANONICAL/TARGET \
  --target-executable-sha256 sha256:LOWERCASE_HEX \
  --filter-scope pid_tree|cgroup \
  --run-id RUN_ID \
  [--target-cgroup /sys/fs/cgroup/DELEGATED_CHILD]
```

The target receives `SIGCONT` only after the helper writes a valid, matching `ready` record. The helper must independently hash the executable at the supplied path, compare it with the supplied digest, activate the requested PID-tree or cgroup filter, and echo that binding in `ready`. If validation, binding, or readiness fails, the stopped target process group is killed without executing the target command.

## Transport

The helper writes newline-delimited JSON to stdout and diagnostics to stderr. Stdout is a machine protocol; stderr is continuously drained but never copied into events. Limits in protocol v2 are:

- 1 MiB per JSON record and 10,000,000 records per run.
- 256 queued records between pipe drain and encrypted persistence.
- 512 KiB decoded payload per evidence record.
- 64 capabilities and 256 bytes per metadata label.
- 4,096 bytes per target path.
- 64 KiB retained stderr accounting; excess bytes make the helper result incomplete.

Queue overflow, malformed records, persistence failure, helper-reported gaps or drops, an absent/incomplete `final`, count disagreement, non-zero exit, or forced termination increments `capture_drops`. All raw protocol records are stored only as encrypted `application/vnd.iorec.probe+json` blobs.

## Records

Every record contains `schema_version: 2`. Unknown fields are rejected. Protocol v1 is deliberately rejected because it cannot prove which executable and filter a `ready` record describes.

The first non-empty record must be `ready`:

```json
{"type":"ready","schema_version":2,"helper":"ecapture-bridge","helper_version":"1.0.0","upstream_name":"ecapture","upstream_version":"2.0.2","capabilities":["tls_plaintext","process"],"target_pid":1234,"target_executable_sha256":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","target_cgroup":"/sys/fs/cgroup/user.slice/iorec-run","filter_scope":"cgroup"}
```

Evidence metadata is normalized, while the exact record—including optional payload—is encrypted as raw evidence. `payload_base64` and `payload_sha256` must appear together; the digest uses the `sha256:<lowercase hex>` form.

```json
{"type":"evidence","schema_version":2,"event":"tls_plaintext","pid":1234,"tid":1235,"connection_id":"socket-42","direction":"write","protocol":"tls","media_type":"application/octet-stream","payload_base64":"aGVsbG8=","payload_sha256":"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","confidence":1.0}
```

A known loss is reported immediately. `occurrences` is added to the run capture-drop gate.

```json
{"type":"gap","schema_version":2,"reason":"ring_buffer_samples_lost","occurrences":3}
```

Exactly one `final` must be the last record. `dropped_events` is the total loss count, including preceding gap occurrences. `captured_events` must equal the number of accepted evidence records.

```json
{"type":"final","schema_version":2,"captured_events":1,"dropped_events":0,"probe_hits":2,"complete":true}
```

`iorec` sends the graceful stop signal to the helper process only. The helper owns source quiescence and shutdown; if it does not exit within ten seconds, `iorec` kills the complete helper process group and marks the result incomplete. This distinction prevents a child probe from losing buffered tail data merely because the target exited.

## Bundled eCapture bridge

`tools/ecapture_bridge.py` implements protocol v2 for the eCapture OpenSSL TLS and GoTLS text/hex streams. Install the script and a private adjacent `ecapture-bridge.json` under protected ancestors, using `tools/ecapture-bridge.example.json` for `module: "tls"` or `tools/ecapture-bridge-gotls.example.json` for `module: "gotls"`. The configuration must name a canonical eCapture executable and its uncompressed SHA-256; a release label alone is not trusted. `libssl` is accepted only by the TLS module. GoTLS passes the recorder-verified target executable path to eCapture as `--elfpath`; it never accepts a second, unbound ELF path from configuration. The bridge supports cgroup scope only, so invoke `iorec run` with both `--task-cgroup` and `--probe-helper` from a delegated cgroup-v2 scope.

The bridge consumes `--debug --hex` output synchronously, converts perf-buffer loss and known decode/dispatch failures into `gap`, validates declared lengths and either offset-based TLS hex dumps or bounded contiguous GoTLS hex, verifies live or previously sampled cgroup membership for every event PID, and emits nonempty TLS bytes with their digest. GoTLS source/destination tuples are direction-normalized so READ and WRITE segments retain one connection identity. Its upstream queue is capped at 1,024 lines; a line is capped at 4,259,840 bytes; per-event hex text is capped at 3,149,824 bytes; cgroup PID history and connection identities are each capped at 1,000,000 entries; and cgroup membership is sampled every 10 ms. Crossing a boundary becomes an explicit gap rather than silent truncation. It waits the configured `shutdown_drain_seconds` before stopping eCapture; zero-byte SSL calls count as probe hits but not payload records. A sampling failure, PID/connection-history overflow, parse/binding failure, oversized line or diagnostic stream, nonzero upstream exit, upstream-reported loss, or zero probe hits makes `final.complete` false.

The supported privilege mechanism is deployment-specific. Keep `iorec`, the Python bridge, and the Agent unprivileged; make only the reviewed upstream executable or its service privileged. The Debian 13 qualification host required a broad file-capability set including `CAP_SYS_ADMIN`. The committed evidence therefore applies only to the exact OpenSSL cell in [the TLS qualification](benchmarks/2026-09-16-ecapture-bridge-linux-x86_64.json) and the Go 1.24.13/1.25.13 cells in [the GoTLS qualification](benchmarks/2026-09-16-ecapture-gotls-linux-x86_64.json). Do not infer support for a different kernel, TLS library, Go patch release, architecture, protocol, Agent, or eCapture build.

## Bundled AgentSight bridge

`tools/agentsight_bridge.py` implements protocol v2 for AgentSight `debug process`. Install the script and a private adjacent `agentsight-bridge.json` under protected ancestors, using `tools/agentsight-bridge.example.json` as the schema. The configuration pins the canonical upstream executable and SHA-256. Its `none` mode runs an already privileged upstream directly; `sudo-noninteractive` additionally requires both `sudo` and AgentSight to be root-owned beneath an entirely root-owned, non-writable path and never permits prompting. The bridge and target remain unprivileged. Deployment policy must separately constrain the privileged command.

The bridge fixes AgentSight arguments to cgroup subtree filtering, trace-all, one-second aggregation, and the supplied target PID seed. It waits for the upstream `CLOCK_SYNC start` anchor before `ready`, independently validates every accepted positive event PID against live or sampled target-cgroup membership, and encrypts the exact AgentSight JSON as process, filesystem, network, coordination, or memory evidence. It caps configuration at 64 KiB, each input event at 512 KiB, retained diagnostic accounting at 64 KiB, the stdout queue at 1,024 records, PID history at 1,000,000, and evidence at 10,000,000 events; cgroup membership is sampled every 10 ms. Parse/schema changes, out-of-cgroup events, aggregate-map overflow, file-rate limiting, diagnostics, missing anchors, nonzero exit, tracker/queue/line limits, and zero hits become gaps.

AgentSight v1.0.25 has a material upstream limitation: `process.bpf.c` returns silently when ring-buffer reservation fails and exposes no loss counter. The bridge therefore emits `upstream_ring_buffer_loss_unobservable` immediately after every valid `ready`, making `final.complete` false for every run with this upstream. The high-level shutdown also omitted the raw collector's end anchor in both qualification runs, which is reported separately. The [limited qualification](benchmarks/2026-09-16-agentsight-bridge-linux-x86_64.json) proves encrypted process/file/network capture and outside-cgroup exclusion on one Debian 13 x86-64/kernel 6.12 cell; it does not qualify TLS plaintext or complete process capture.

Captured probe records remain encrypted in the run. Explicit inspection uses a new private destination:

```bash
iorec probe-export <run> --output ./probe.jsonl --key-file ./iorec.key
```

The command verifies the finalized run and every referenced blob, refuses overwrite and destinations inside the source run, appends audit intent/completion records, and writes mode `0600`. It exports only accepted `ready`, `evidence`, `gap`, and `final` protocol records, validates that every plaintext blob is a JSON object whose `type` matches its authenticated event envelope, and excludes rejected/malformed-message evidence. The output contains plaintext application traffic.

## Bridge qualification

The protocol deliberately does not treat discovery of `agentsight` or `ecapture` on `PATH` as proof of capture. A bridge must additionally prove, for every supported runtime/TLS/kernel combination:

1. it independently verifies the supplied target executable SHA-256 and emits `ready` only after probes and the requested PID-tree/cgroup filter are active;
2. its `ready` target PID, executable digest, cgroup, and filter scope exactly match the requested binding;
3. it reports the exact bridge and wrapped upstream versions in `ready`;
4. it converts all source drop counters into `gap` and `final.dropped_events`;
5. it sends `final` after its source has drained;
6. it preserves raw payload bytes and connection/process identity; and
7. it has fault, long-payload, concurrency, shutdown, and bypass tests for the pinned upstream version.

Until a bridge passes that matrix, its evidence remains an additional best-effort source and never upgrades the manifest claim.

## Policy-driven selection

`iorec run --probe-policy /absolute/protected/policy.json` binds the preflight planner to a reviewed helper without trusting executable discovery on `PATH`. Policy schema v1 accepts at most 128 strict rules. Every rule pins the helper's canonical path and SHA-256, OS and architecture, and at least one exact target executable SHA-256 or observed TLS-surface label; it may additionally require a runtime, eBPF prerequisites, and task-cgroup isolation. The selected helper is revalidated immediately before launch, and its mode, rule ID, kind, path, and digest are stored in `manifest.probe_plan.helper_selection` and the helper-start event.

Selection is deterministic by numeric priority. Equal-priority matches are rejected as ambiguous, and a no-match error reports bounded per-rule reasons before the target is spawned. The policy and helper must both be regular non-symlink files owned by root or the recorder user, non-writable by group/other, and beneath protected ancestors. [`tools/probe-policy.example.json`](tools/probe-policy.example.json) is a template; its all-zero digest is intentionally unusable until replaced.
