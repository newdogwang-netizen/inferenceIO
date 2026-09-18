# Mixed HTTP/SSE and Responses-WebSocket qualification

This is an unpaid, synthetic transport/application workload. It does not replace
the 12 real-agent experiments, Harbor task scoring, or independent pcap/TLS audit.
Use it to qualify a **frozen** recorder and platform candidate, not a changing
worktree. A short successful calibration is never a five-hour acceptance report.

## Isolation and prerequisites

Build the intended `target/release/iorec` and the platform API/worker/web images
first. The qualification launcher pins the current local `iorec/*:0.1` images by
immutable image ID. It does not build or pull images during a run.

Use a separate Compose project, database, object volume, ports and credentials.
The launcher accepts only `iorec-qual-*` project names and refuses pre-existing
resources on initialization. It generates private, owner-only credentials, uses
token authentication, discards inherited development/database overrides and
publishes only loopback ports. It does not touch `iorec-local` or the user's
recordings. PostgreSQL uses the normal durable Compose configuration, not the
development override.

```bash
python3 tools/qualification_platform.py init \
  --state /var/tmp/iorec-qualification-candidate \
  --project iorec-qual-candidate --api-port 48481 --web-port 48482
python3 tools/qualification_platform.py start \
  --state /var/tmp/iorec-qualification-candidate
python3 tools/qualification_platform.py status \
  --state /var/tmp/iorec-qualification-candidate
```

Never commit the private state directory or print its settings/token files.
The `status` operation reports worker liveness and queue status, not correctness.

## Short calibration

The work directory and output file must be new. Keep work paths short enough
for recorder Unix sockets. The following run deliberately stops and restores
the **qualification instance's** API and workers and restarts its collectors.

Before reusing an isolated calibration instance, require zero online collectors,
active/dead jobs, open recordings and parse lag. A stopped collector can remain
`online` until the 90-second stale window and the next status sweep. The current
frozen harness compares the online-collector count with its initial baseline;
starting another run before previous collectors age out can therefore fail the
final delta gate even after all uploads/processors have drained. Prefer a fresh
instance or wait for the exact baseline to settle. Never bypass the count gate
or reclassify the timed-out report as passing. Do not alter a harness bound to
an ongoing five-hour qualification.

```bash
python3 tools/qualification_platform.py soak \
  --state /var/tmp/iorec-qualification-candidate \
  --iorec /home/Admin/inferenceIO/target/release/iorec \
  --work-dir /tmp/iorec-ws-cal \
  --output /var/tmp/iorec-qualification-candidate/calibration.json \
  --duration-seconds 90 --collectors 4 \
  --request-interval-seconds 2 --segment-seconds 15 --drain-seconds 300
```

Half the collectors record HTTP/SSE; half record real WebSocket connections to a
loopback fixture. WebSocket calls include fragmented Unicode deltas, 32-KiB text
bursts, final snapshots, custom tool calls/results, usage, previous-response
links, ping/pong and clean reconnects every 11 calls. Connections cross rolling
recording segments. The separate client validates its received content and
produces an expected-call ledger; it does not use the platform normalizer as its
oracle.

The harness requires:

- unchanged recorder/harness/Node hashes, running recorder executable hashes,
  pinned platform image IDs, hardened containers and loopback exposure;
- exact local event/blob integrity and contiguous, acknowledged, sealed upload
  segments, including recording progress during API outage;
- stable collector identities after restart, worker restart and queue drain;
- one physical connection per handshake and one logical call per request;
- exact per-call text digests, tool payloads, usage, completion, state references
  and request/final-response blobs;
- each recorded message owned exactly once or explicitly classified as a control
  message, no unaccounted messages, and bidirectional close evidence.

Closing follows the [WebSocket closing handshake](https://www.rfc-editor.org/rfc/rfc6455.html#section-7.1.2):
flush queued acknowledgements and observe both peers' Close messages before
reporting completion. A missing acknowledgement has a bounded timeout and cannot
be promoted to complete. The regression suite also exercises abrupt TCP reset.

The final deletion-propagation check **irreversibly deletes one newly generated
synthetic HTTP/SSE recording** locally and in the test platform. The other runs,
private key and report remain available. No old or real-agent run is selected.

## Five-hour candidate gate

After successful calibration and candidate freeze, use a fresh work path/report:

```bash
python3 tools/qualification_platform.py soak \
  --state /var/tmp/iorec-qualification-candidate \
  --iorec /home/Admin/inferenceIO/target/release/iorec \
  --work-dir /tmp/iorec-ws-5h \
  --output /var/tmp/iorec-qualification-candidate/five-hour.json \
  --duration-seconds 18000 --collectors 20 \
  --request-interval-seconds 60 --segment-seconds 300 --drain-seconds 900
```

Qualification requires **20 collectors and at least 18,000 measured seconds for
every client**, plus every integrity, reconciliation, outage/recovery, deletion
and provenance gate. `passed=true` for a shorter run still has `qualified=false`.
Changes to the recorder, relevant images or harness invalidate the corresponding
frozen-candidate claim. A failure report cannot be reused as a success report;
retain it and start a new explicitly named calibration after diagnosis.

Do not restart a live job merely because an observation call timed out. Check its
actual process/session first. A process lock prevents simultaneous launcher
operations but is not proof a workload is still progressing.
