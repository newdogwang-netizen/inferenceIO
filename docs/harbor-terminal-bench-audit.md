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

## Controlled one-command workflow

The new controller `tools/harbor_audit_workflow.py` performs explicit stages:
preflight → Harbor trial → encrypted integrity → independent transport audit →
trusted local import → platform proof and benchmark annotation. It accepts
only explicit loopback HTTP origins, does not use HTTP proxies or redirects,
and never gives the recorder master key to the platform.

First start/check the local **development** platform and build the recorder:

```bash
python3 tools/local_platform.py start --build
cargo build --release --locked
```

Then use an empty, private work directory and a pre-existing private recorder
key. Agent/provider credentials remain in the operator environment, not command
arguments, the job config, or the public summary:

```bash
python3 tools/harbor_audit_workflow.py \
  --work-dir /tmp/iorec-harbor-new-audit \
  --task /path/to/terminal-bench/html-js-filter \
  --model openai/YOUR_MODEL \
  --agent-timeout 900 \
  --key-file /private/iorec/master.key
```

The default wrapper is Codex. A native Claude Code profile is also available
with `--agent claude --claude /path/to/pinned/claude --model anthropic/YOUR_MODEL`;
it does not use Harbor's floating curl/npm installer. Hermes is available with
`--agent hermes --hermes-bundle /private/hermes-runtime.tar.gz --model openai/YOUR_MODEL`;
see the installed-runtime preparation below. All profiles use one trial, one concurrent agent, no
automatic retries, a Harbor-enforced agent timeout and bounded verifier/setup
timeouts. The timeout is **not a hard monetary limit**; provision appropriate
provider-side spending limits before a fresh paid experiment. The M3 matrix
must separately record and enforce its chosen budget/stop policy.

`--upstream https://YOUR_HOST/provider-prefix` explicitly selects the matching
provider-protocol endpoint and pins it with the trial inputs. Credentials in
URLs, query strings, non-HTTPS and literal non-global IP endpoints are rejected;
the recorder also checks resolved addresses when creating the task namespace.
Bedrock/Vertex are not covered by the Claude profile. `--agent-budget-usd N`
passes Claude's own budget flag; it is not a provider-enforced spending cap and
does not implement the total M3 budget.

The container's `/usr/local/bin/codex`, `/usr/local/bin/claude` or `/usr/local/bin/hermes` is a root-owned
wrapper around the pinned binary in `/opt/iorec-agent/`. Prompt strings are
never searched or replaced. Only an exact single informational argument such
as `--version` bypasses recording; regular arguments, stdin and exit status
are preserved. Claude auto-updates and nonessential traffic are disabled.
Hermes also bypasses recording for its exact `version` command and Harbor's
exact local session-export command; exporting after a chat must not create a
second recorded agent run.

### Pinned Hermes runtime (no personal state)

Do not copy the venv launcher alone: its absolute Python shebang is not portable.
Do not assume an adjacent source checkout is the code actually loaded by the
installed CLI. On this host the wheel is 0.19.0 while that checkout is 0.16.0.
Explicitly select the actual standalone Python 3.11 prefix and installed venv
`site-packages`. Build into a **new private directory**, outside both sources:

```bash
mkdir -m 700 /private/hermes-runtime
python3 examples/hermes_runtime_bundle.py build \
  --python-prefix /path/to/standalone-cpython-3.11 \
  --site-packages /path/to/installed-hermes-venv/lib/python3.11/site-packages \
  --archive /private/hermes-runtime/runtime.tar.gz
python3 examples/hermes_runtime_bundle.py verify \
  --archive /private/hermes-runtime/runtime.tar.gz
```

This freezes the installed wheel, Python and transitive installed dependencies,
with per-file SHA-256 and distribution versions. It excludes bytecode caches,
dereferences internal file aliases, rejects editable installations and escaping
or directory symlinks, and never copies `~/.hermes` configuration or sessions.
Only regular files, declared directories and bounded GNU longname headers are
accepted; links, device files, PAX/sparse extensions, undeclared payloads and
digest changes fail validation. The archive is private and contains executable
third-party code: hashes detect drift, not a malicious host or package origin.

The workflow binds the archive, fixed launcher and validator. Installation
checks the uploaded archive hash before extraction into a fresh root-owned
`/opt/iorec-hermes`; the non-root agent uses isolated Python (`-I -B`) and a
fresh `/tmp/hermes` home. No floating Hermes installer is run. Version output
must agree with the bundled distribution. This profile currently accepts
explicit `openai/...` models with `OPENAI_API_KEY`; it refuses Harbor's implicit
OpenRouter fallback and pins the configured endpoint even in per-command env.
The native Hermes config has a 60-turn limit, in addition to Harbor's timeout.
Neither is a provider-side monetary cap.

Use `--preflight-only` first. An installation-only or version check is **not**
proof of a real provider call, lifecycle/session capture or benchmark success;
those remain part of the M3 real-agent matrix. The validated local runtime is
Hermes 0.19.0, Python 3.11.15, OpenAI SDK 2.24.0 on Linux x86-64 / Debian 12.

### Native recorder compatibility

**Claude additionally requires a recorder that runs natively in the task
container.** Explicit `ld-linux ... iorec` startup changes Linux `current_exe()`
to the loader and breaks the lifecycle hook's self-exec command. The profile
therefore starts iorec directly and checks a synthetic `SessionStart` hook in
installation, before any model call. The host-built candidate requiring glibc
2.38/2.39 is correctly rejected by Debian 12; select a recorder built against
the task container's compatible baseline and qualify that exact binary. A CLI
version smoke alone is not sufficient. The probe uses no real agent/model,
keeps its small encrypted recording under `agent/iorec-preflight`, and is not
counted as a matrix trial.

For the local Debian 12 compatibility check, the same recorder Rust sources
were rebuilt offline with Rust 1.97.1 inside the pinned Bookworm build image
`golang:1.25.13-bookworm@sha256:e401dae1bf814e29204a8cb7915682e1780951e609ca0dd8865ee1937f510c48`.
The host Rust toolchain was mounted read-only, Cargo used the existing dependency
cache with `--release --locked --offline`, and a separate external target directory
kept the running candidate untouched. The resulting SHA-256 is
`b54b88d6cfc1c7fdb4f88bfcbff9f4c04d400a4828cb06c2a1f171e4e9c05da7`;
its highest linked glibc requirement is 2.34. This is a distinct build artifact,
not a patched copy of the old binary, and requires its own mixed-load/steady-state
qualification. Do not reuse the old binary's five-hour report for it.

Before authorizing a paid run, append `--preflight-only` to that fresh-trial
command. It checks platform health, pins the task and upload inputs, and asks
the installed Harbor CLI to validate its resolved configuration with
`--print-config`. It does not install or run an agent. Its report is explicitly
`preflight_only` with `qualification_passed=false`, not a successful recording.
Keep the same chosen model and paths for the eventual run; a placeholder model
is suitable only for a disposable preflight directory, not the experiment plan.

Fresh inputs now include the profile's actual upload set: Codex and its helper,
recorder, util-linux helpers/wrappers, and all six uploaded runtime libraries.
The key is checked separately and is excluded from the public input identity.
The Harbor launcher, its explicit Python interpreter, Harbor package content
(excluding bytecode caches), task tree and workflow/profile code are also
fingerprinted. Inherited `PYTHONPATH`, Python overrides and `IOREC_HARBOR_*`
overrides cannot silently select another installation; the controlled workflow
sets only its documented inputs and invokes the pinned absolute launcher.
Harbor launchers with an ambiguous `env`/shell shebang are rejected.

These identities are checked again immediately before launch and after the
trial. Drift prevents launch or qualification; a completed but invalidated
trial is retained and never automatically rerun. This is drift detection on a
trusted worker, not adversarial host attestation. In particular it does **not**
freeze all transitive Python packages, apt-installed container tools or the
Docker daemon. Exact container installation and agent/runtime dependency
qualification remain separate M3 gates.

To validate the downstream stages using an already finished trial without
starting or paying for another agent run:

```bash
python3 tools/harbor_audit_workflow.py \
  --work-dir /tmp/iorec-harbor-existing-audit \
  --from-trial /path/to/harbor/job/task__trial \
  --key-file /private/iorec/master.key
```

For authenticated local platforms, pass an owner-only `--token-file` containing
an operator token. `--api` and `--web` default to the actual host listeners
`http://127.0.0.1:18080` and `http://127.0.0.1:8088`; they are not temporary
desktop forwarding ports. The emitted recording URL uses that stable Web origin.

Repeat **exactly the same command and work directory** to recover. The controller
pins recorder/key/task inputs and source evidence, authenticates evidence again,
uses the platform's idempotent import, and attaches an immutable, project-scoped
benchmark annotation. Changed inputs require another work directory. An already
launched but incomplete Harbor job is never silently resubmitted. A child-held
workspace lock prevents concurrent controllers from deleting an active export
or starting a duplicate paid trial. An observation timeout does not mean the
Harbor process has stopped; inspect its existing process/job, and do not start
a second job merely because a wait expired.

`state.json` gives stage status and bounded failure codes. `report.json` contains
selected counts, artifact digests, provenance and the recording link; no payload,
TLS keys, verifier logs or raw exception messages. Review identifiers before
publication. The Harbor reward stays separate from capture qualification: reward
zero does not fail a clean recording, and a verified recording does not mean the
agent solved the task. The platform labels the attached score as externally
reported, not independently recomputed correctness.

Temporary plaintext exports and transport reports live only under the owned
`scratch` directory and are removed on success and ordinary failure, including
import failure. After SIGKILL/power loss, they can remain mode-0700 protected;
the next invocation removes that exact staging directory after obtaining the
child-held lock. This is deletion, **not secure erasure**. Encrypted original
runs, the separately held key and private Harbor logs are preserved. Do not
publish the entire work directory.

The existing September 18 recording has since been reprocessed by M1 into 19
individual calls and 18 resolved state references. Its original connection
`client_read` and unknown static TLS indicators remain visible. The older
24-message aggregate above describes the historical transport qualification,
not the current call-level semantic projection. See
[next-stage acceptance](next-stage-goals.md) for the pending fresh-trial/M3 gates.
