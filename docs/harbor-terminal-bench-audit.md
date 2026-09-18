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

`iorec transport-audit` decrypts the captured traffic with TShark, reconstructs
HTTP/1.1, HTTP/2, and WebSocket application messages, and compares their
canonical byte streams with the proxy evidence. Codex's own session log is
useful for semantics, but it is not treated as independent transport proof.

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

The final `html-js-filter` qualification produced capture run
`run-01a0b3b8-621f-7335-a60b-1c0f2056fa48`:

- Codex 0.154.0 ran for 12 minutes as UID/GID 10001 and exited zero;
- all 14,093 events and 13,929 encrypted blobs authenticated, with no missing
  or corrupt objects;
- the task pcap was 7,327,049 bytes in eight encrypted evidence chunks, and the
  run contained five TLS key records / 938 bytes;
- pinned TShark 4.4.18 decrypted one TLS stream and decoded 13,780 WebSocket
  wire rows without decoder stderr;
- 54 client messages / 105,775 bytes and 13,726 server messages / 4,641,287
  bytes matched the proxy-reassembled streams exactly by canonical length and
  SHA-256, with no missing, extra, or ambiguous attempt;
- task-network enforcement reported zero kernel drops, unknown egress, model
  bypass, parser gap, or QUIC possibility; schema-v4 transport audit returned
  `complete: true` with an empty gap list;
- the controlled platform import independently repeated the audit as
  `transport-audit-v2=verified`, normalized 24 semantic messages, retained a
  1,478-character response text, and reported `body_unavailable=0`;
- Harbor's verifier completed independently and awarded `0.0`. That score is
  the agent's task-correctness result, not a transport-capture result.

The final capture uses a 32 MiB tcpdump buffer and coalesces the capture pipe
into 1 MiB encrypted chunks. `tcpdump` reported 29,082 captured, 29,202
received-by-filter, and zero dropped packets. The 120-packet diagnostic
`received_minus_captured` is deliberately not interpreted as loss: the
received counter has operating-system and filter-dependent semantics, while
the explicit dropped counter is the capture-loss signal documented by the
[tcpdump manual](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in).

This result qualifies only the named target-network-namespace IP boundary and
the pinned Linux x86-64/Codex/TShark cell. It does not claim visibility into
provider-hidden state, same-user Unix IPC, other agent versions, other
operating systems, or HTTP/3.

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
