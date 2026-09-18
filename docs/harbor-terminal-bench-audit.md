# Harbor / Terminal-Bench independent transport audit

This runbook records the method used to capture a real Harbor-managed Codex
attempt with iorec. It is an **audit profile**, not a leaderboard-compatible
replacement for the normal Harbor sandbox.

## What is independently observed

The same `codex exec` process launched by Harbor is wrapped with:

```text
Harbor task container (audit-only privileged envelope)
  -> iorec as UID 10001
     -> nested user + mount + network namespace
        -> Codex as UID 10001, CapBnd=0, CapEff=0, NoNewPrivs=1
           -> original api.openai.com socket transparently redirected to iorec
```

iorec records three complementary evidence layers:

1. normalized proxy request/response events and full allowed bodies;
2. encrypted task-network pcap captured by `tcpdump`;
3. encrypted NSS TLS key-log material for post-run decryption.

`iorec transport-audit` decrypts the captured traffic with TShark and compares
the reconstructed HTTP bodies with the proxy evidence. Codex's own session log
is useful for semantics, but it is not treated as independent transport proof.

## Why the outer container is privileged

Docker's default seccomp/AppArmor profile blocks creation and configuration of
the nested namespace used by `--task-netns`. The compose overlay in
`examples/harbor-audit-compose.yaml` grants the outer, disposable Harbor task
container the setup capability. iorec then verifies the actual agent process is
non-root, has an empty capability bounding set, and has `no_new_privs=1` before
releasing its launch barrier.

Use this profile only on an isolated local benchmark worker. Keep the normal
Harbor configuration as the canonical benchmark run.

## Debian 12 compatibility

Terminal-Bench's Debian 12 image ships util-linux 2.38.1. That version cannot
express the two UID/GID mappings needed to preserve agent UID 10001 inside a
rootless namespace, and its `nsenter` lacks `--keep-caps`. The audit agent
uploads the worker's util-linux 2.41 binaries plus their glibc runtime into a
root-owned, non-writable directory and exposes fixed-path wrappers. This is why
the worker paths are explicit inputs and why the helper ownership checks must
remain enabled.

Docker also presents `/etc/hosts` as a mount beneath iorec's private read-only
snapshot. Verification must follow `/proc/self/fdinfo/<fd>`'s effective
`mnt_id`; rejecting any lower writable mount creates a false positive even
though the effective snapshot is read-only.

## Prerequisites

- Docker and Harbor 0.22 or later;
- a release build of iorec;
- a real Codex binary and adjacent `codex-code-mode-host`;
- a private 32-byte or 64-hex-character iorec key with mode `0600`;
- root-owned worker `unshare`, `nsenter`, and TShark binaries.

The example resolves these defaults and accepts overrides:

| Variable | Default |
| --- | --- |
| `IOREC_HARBOR_BIN` | repository `target/release/iorec` |
| `IOREC_HARBOR_KEY_FILE` | `/tmp/iorec-tbench/master.key` |
| `IOREC_HARBOR_CODEX_BIN` | `codex` from worker `PATH` |
| `IOREC_HARBOR_CODE_MODE_BIN` | sibling of the Codex binary |
| `IOREC_HARBOR_UNSHARE_BIN` | `/usr/bin/unshare` |
| `IOREC_HARBOR_NSENTER_BIN` | `/usr/bin/nsenter` |

## Run the audit attempt

Build iorec and first inspect the resolved Harbor configuration:

```bash
cargo build --release

PYTHONPATH="$PWD/examples" harbor run --print-config \
  --job-name iorec-tbench-html-js-filter-audit \
  --jobs-dir /tmp/iorec-tbench/jobs \
  --n-concurrent 1 --max-retries 0 \
  --agent harbor_iorec_codex_audit:IorecCodexAudit \
  --model openai/gpt-6-astra \
  --ak reasoning_effort=high --ak web_search=disabled \
  --path /path/to/terminal-bench/html-js-filter \
  --extra-docker-compose "$PWD/examples/harbor-audit-compose.yaml" \
  --yes
```

Remove `--print-config` to execute. Keep one attempt and no retries so the
benchmark result, agent session, iorec run, and transport report have an
unambiguous one-to-one relationship.

## Qualify the evidence

Locate the downloaded iorec run below the Harbor trial's `agent` directory,
then run all three gates:

```bash
iorec inspect --json --verify-blobs --key-file "$IOREC_HARBOR_KEY_FILE" RUN_DIR
iorec verify --profile integrity --json --key-file "$IOREC_HARBOR_KEY_FILE" RUN_DIR
iorec transport-audit --key-file "$IOREC_HARBOR_KEY_FILE" \
  --output /tmp/iorec-tbench/transport-audit.json RUN_DIR
```

Accept the run only when:

- Harbor's hidden verifier completed and reports its score separately;
- the iorec manifest is finalized rather than interrupted;
- encrypted blob authentication and the event hash chain pass;
- pcap and TLS key-log artifacts are present and not truncated;
- transport reconstruction reports no unexplained body mismatch;
- the target attestation reports UID/GID 10001, zero capabilities, and
  `no_new_privs`.

## Qualification result: 2026-09-18

The first real `html-js-filter` audit run produced capture run
`run-01a0b25e-602b-7448-92e0-39096eda7045`:

- Codex 0.154.0 ran for about 12 minutes as UID/GID 10001 and exited zero;
- all 35,714 events and 35,472 encrypted blobs authenticated, with no missing
  or corrupt objects;
- task pcap contained 22,708 records / 6,666,632 bytes and five TLS key
  records; TShark 4.4.18 decrypted the one observed TLS stream;
- the enforced boundary reported zero unknown egress and zero model-bypass
  connections;
- Harbor preserved all 12 clean HTML fixtures, but one XSS family executed, so
  the benchmark reward was correctly reported as `0.0`.

This run is deliberately classified **incomplete**, not transport-complete.
Codex 0.154.0 negotiated an HTTP `101` WebSocket connection. The current
transport audit reconstructs HTTP/1.1 and HTTP/2 bodies but does not yet pair
wire-level WebSocket messages with proxy-reassembled messages. The capture also
reported 120 kernel packet drops. It therefore proves that the model connection
used the enforced, decryptable path, but not that every WebSocket payload byte
was independently accounted for.

The run exposed a capture-pressure issue as well: immediate-mode tcpdump pipe
reads were being persisted as individual encrypted blobs, often one per packet.
The recorder now coalesces those reads into 64 KiB evidence chunks before
encryption and append, reducing object count and writer backpressure. A future
qualification must still demonstrate zero drops and implement wire-level
WebSocket framing/correlation before this Codex cell can be promoted beyond
best-effort.

## Handling and cleanup

Pcap, TLS secrets, request bodies, Codex credentials, and plaintext transport
reports are sensitive. Keep raw evidence encrypted at rest. Do not publish it
to GitHub Pages or attach it to public benchmark results. If a controlled
plaintext platform import is required, create it with mode `0600`, import it
only into the trusted local platform, verify the imported proof, and delete the
temporary bundle immediately.

Remove disposable preflight containers and plaintext audit reports after the
result has been qualified. Retain the encrypted run, its key under separate
access control, the Harbor verifier result, and a non-sensitive summary.
