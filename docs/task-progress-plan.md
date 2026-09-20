# Task progress and long-horizon recording

Status: progress UI and the declared long-horizon experiment are complete
(2026-09-20). One Codex trial is a capture-qualified baseline and meets the
predeclared trajectory criterion. One Hermes trial passed the benchmark and is
retained as diagnostic-only because its independent pcap evidence dropped packets.
No automatic paid retry was performed. Changed artifacts do not inherit the
previous frozen recorder/platform qualification.

## Acceptance requirements

1. Recording lists and task details separate model calls, observed tool execution,
   connections, Hook observations and streaming events. A transport parent, a Hook
   copy, a discovery request or a repeated context message is never another model
   round. Count scopes and unknown/unavailable values are explicit.
2. A task-level progress view spans recording segments. It shows the task input,
   ordered model calls, tool requests and returned results, continuation evidence,
   interruptions and final benchmark outcome. Every item links to retained source
   evidence. Chronological succession is not presented as proven causality.
3. Repeated tool results in accumulated model context are not counted repeatedly.
   Missing IDs, conflicting results, ambiguous producers and absent results remain
   visible. A model-requested tool invocation alone does not prove execution or
   success. Hook observations stay separate when cross-source identity is uncertain.
4. Existing Codex/Hermes recordings exercise the view, including the historical
   failed samples. Authorization, deletion fencing, pagination, malformed inputs,
   cross-segment processing and bounded responses have regression coverage.
5. After the UI is verified, run real long-horizon Harbor tasks (not synthetic
   traffic or padded waits). Pin task/model/runtime inputs, preserve task/verifier
   instructions, use independent pcap/TLS evidence, retain failed attempts and
   import both the recording and benchmark result. No automatic paid retries.
   Stay inside the user's existing approximately USD 1000 total budget; each new
   launch gets a separate bounded experiment declaration and rough cost record.
6. Demonstrate an actual extended task trajectory in the rendered platform with
   a meaningful sequence of investigation, edits, execution/testing and results.
   Report observed duration, model/tool counts and outcome separately; a short
   successful task is not renamed a long-horizon qualification. Raw evidence,
   missing coverage and task-score limitations remain visible.

## Implementation sequence

- Define and test a project-scoped task activity/progress read model.
- Replace mixed attempt totals in the list/detail UI; add a paged progress chain.
- Verify against existing real recordings and failure fixtures in a real browser.
- Select and declare genuinely long-form tasks, then run/import/inspect them.
- Publish reproducible evidence and the updated UI; complete only after all six
  requirements have current-state evidence.

## Initial evidence

- Codex merger r1: 7 attempt rows = 1 WebSocket connection + 6 model calls;
  2366 raw events and 2258 WebSocket messages. Its native trajectory contains
  4 tool executions and a final assistant response; agent execution was ~55 s.
- Hermes merger r1: 18 rows = 6 model requests + 6 Hook observations + 6 other
  HTTP requests; 6427 raw events and 4027 SSE events. Agent execution was ~59 s.
- Hermes cancellation r1: 32 rows = 13 model requests + 13 Hook observations +
  6 other HTTP requests; 9309 raw events. Its strict transport failure is retained.

These are short-task baselines, not long-horizon results. Source recordings and
their historical reports must not be overwritten to manufacture completion.

## Phase 1 evidence (2026-09-20)

- Default detail tab now presents a cross-segment progress chain, with explicit
  model-call, result-observed tool, WebSocket-parent, Hook and streaming metrics.
  The list separates the per-segment counts; tool results require cross-segment
  identity matching and link to the task view rather than displaying a fabricated
  per-segment number. The legacy attribution tree is fetched only on demand.
- Each call exposes task/input and response previews, expandable operation
  arguments/results, explicit-ID continuation links and source evidence links.
  Benchmark outcome appears after the final page. Pagination is snapshot-bound;
  previews are bounded and never claim to contain the complete body.
- `normalizer-v5` retains Chat/SSE tool arguments. Reprocessing all 9 recorded M3
  cases preserved manifest/batch hashes, durable sequence numbers, all 64 model
  calls, and every transport status (including the two incomplete recordings).
  All parsed tool arguments in those nine samples are available after reprocessing.
  Original evidence and historical reports are unchanged.
- Real Chromium checks passed for Codex merger (6 calls / 4 observed tools),
  Hermes merger (6 / 8), and the failed Hermes cancellation (13 / 11). Verified
  five separate metrics, evidence links, tool expansion, recording-list headers,
  desktop and 390-pixel mobile widths, and no runtime errors. Temporary browser
  profiles are removed; screenshots remain private because they contain bodies.
- Go race tests for all packages, `go vet ./...`, and the TypeScript/Vite build
  passed. Regression cases cover 42-call pagination, cross-segment results,
  repeated-context deduplication, native versus inferred sessions, ambiguous IDs,
  conflicting results, project/role boundaries, deletion/expiry, changing snapshots,
  missing/malformed normalization and explicit byte/graph work ceilings.
- A pre-existing flaky ingest test was corrected: replacing a hash prefix with
  `00` did not necessarily change it. The fixture now guarantees corruption;
  ingestion behavior was not changed.

This phase was subsequently completed by the real trials documented below. None
of the Phase 1 checks is retroactively treated as long-horizon evidence.

## New long-horizon declaration

This is a new goal stage, not a restart of the exhausted M3 ledger. Two cases,
serial, one trial each, no automatic paid retry, with a separate private declaration
and once-only launch receipts. Claude remains excluded. Costs are estimates, not
a provider-enforced hard cap; unknown amounts remain unknown.

- Official TB2 task: [`make-mips-interpreter`](https://github.com/harbor-framework/terminal-bench-2/tree/main/make-mips-interpreter),
  implementing a JavaScript MIPS interpreter, system calls and rendered frames.
  Expected to require iterative implementation/debugging; length is an observation,
  not a fact inferred from the task's difficulty label.
- Registry dataset digest: `c6fc2e2382c1dbae99b2d5ecd2f4f4a60c3c01e0d84642d69b4afd92e99d078b`
  (89 tasks); downloaded task content independently recomputed as
  `608e82ecd67ce469824a34181b580cbd0e1096cdfc05fe40edda3e6bfada9773`.
- Task image: `alexgshaw/make-mips-interpreter@sha256:082fc8821b317f30fdfbf8d08d528874ce331c03e8083aef0406d48cdd7132a2`.
  Original instruction, verifier and 1800-second agent/verifier limits unchanged.
- Case order: `codex-mips-r1` (`openai/gpt-5.6-sol`, Codex 0.154.0, high reasoning),
  then `hermes-mips-r1` (`openai/accounts/fireworks/models/deepseek-v4-pro-0813`,
  frozen Hermes 0.19 runtime, 60-turn limit).
- Recorder SHA-256: `59a10e9fcd944b8961dbf8458a4fe572241f9beac76419ab2139b190a8f8eaee`;
  full encrypted capture plus independent task-network-namespace pcap/TLS audit.
  The controlled privileged outer container/non-root agent profile is not claimed
  to be leaderboard-equivalent. No user home or project workspace is mounted.
- Predeclared observation criterion: at least one actual trajectory with **26+
  model requests and 20+ uniquely observed tool results**, including investigation,
  implementation and execution/debugging. Duration, capture qualification and
  benchmark reward remain separate. No padded waits, prompt changes or silent
  reruns to manufacture this criterion. If neither task reaches it, report that
  honestly and leave the long-horizon requirement open.

### First launch failure (10:57 UTC)

Both input-only preflights passed, but Docker could not create the task network:
`all predefined address pools have been fully subnetted`. Harbor's trial ended
before agent setup/execution; there was no agent result, measurement or recording.
The workflow correctly remained incomplete instead of claiming a zero-call capture
or successful long-horizon run. The original result and once-only launch receipt
are retained; the failed trial is not restarted automatically.

Read-only checks found many old networks but did not establish that the empty ones
belong to this project. None were removed; running platform services were not
stopped. A task-scoped explicit subnet is a possible remedy without changing global
Docker configuration. Replacement approval was requested. The long-horizon goal
remains open, and no new benchmark score or capture qualification is claimed.

### Prepared remediation, not yet exercised by a real trial

The workflow now has an optional, input-bound `--task-network-subnet` overlay and
an allocation preflight that precedes the model launch marker. It rejects route
overlaps, non-private/broad subnets, remote Docker endpoints and unsupported task
topologies. Only its own labelled empty probe can be removed; no global cleanup
or daemon reconfiguration is used. This is a new controller version, not a change
to frozen historical qualification artifacts.

Read-only inspection found no overlap for `10.203.240.0/24` among 33 Docker
networks and 639 IPv4 routes, and `docker compose config` accepted the generated
overlay. These are **not** successful network-allocation or agent-execution
evidence. No live network was created/removed and no replacement agent was
started while waiting for approval. Offline tests cover successful and failed
probes, cleanup ownership/in-use fences, input drift, preflight failure before
launch, and no reallocation during evidence-only recovery.

After the remediation, the Python suite reported **200 tests: 199 passed, 1
explicit capture-dependent test skipped**. No model call is part of that suite.

### Browser pagination regression (synthetic, not long-horizon evidence)

The isolated Chromium verifier can inject 53 fake calls into its own `fetch`
responses, without adding anything to the platform database. It exercises three
pages, final-page outcome placement, a mid-pagination snapshot change (409),
refresh back to page one, and no eager legacy-tree fetch. A refresh bug that
unnecessarily refetched the stale old page was corrected. This mode is explicitly
labelled `synthetic_browser_only_not_a_real_benchmark` in its output.

```bash
node tools/verify_task_progress_ui.mjs http://127.0.0.1:8088 \
  browser-pagination-fixture 53 0 --pagination-fixture
```

This check and the existing real Codex/Hermes browser checks passed after the
refresh change. They validate UI mechanics, **not** a 53-call agent experiment.
At that point the long-horizon requirement remained open; the later approved
replacement and its real results are recorded next.

## Final long-horizon result (2026-09-20)

The approved replacement used the scoped `10.203.240.0/24` task network. Both
agents ran the unchanged official `terminal-bench/make-mips-interpreter` task and
both received reward 1. Benchmark correctness, task length and capture evidence
remain separate verdicts.

### Codex: qualified baseline

- Run `run-01a0be8e-ba36-72f9-ac36-2d1ed31bcf16` completed in 193.98 seconds
  of measured agent execution at a Harbor-reported approximate cost of USD 1.4034.
- The rendered chain contains 27 model calls, 25 requested tools and 25 uniquely
  observed tool results. It therefore meets the predeclared 26-call/20-result
  criterion without padding or a silent retry.
- The sealed import contains 10,600 events and 10,498 blobs. Platform processing
  reached 10,600/10,600 with zero active or failed jobs.
- Integrity passed 6 checks. The independent task-network transport audit matched
  the eligible proxy attempt with zero missing/extra wire attempts, zero capture
  drops, 10,300 WebSocket rows and a passing payload diff.
- Real Chromium verification covered multi-page progress, evidence links, tool
  expansion, final benchmark placement and a 390-pixel mobile viewport.

This is the phase's qualified long-trajectory baseline. Its workflow report hash
is `857e89f6a8d5885eaf74259fc2ff4ae727e13510f78961592d18d47aee965453`.

### Hermes: long diagnostic, not capture-qualified

- The main invocation ran for 1,661.27 seconds at a Harbor-reported approximate
  cost of USD 1.1595. The rendered diagnostic chain contains 61 model calls,
  67 requested/observed tool results, 60 Hook observations and 88,843 SSE events.
- Hermes invoked the recorded CLI twice. The controller now retains both and
  selects the main capture only under a declared rule: its measured duration must
  be at least four times the longest auxiliary. The 1.25-second auxiliary run and
  its hashes remain in the source identity; nothing is silently discarded.
- The benchmark reward is 1 and integrity passed, but the task-namespace pcap
  reported 3,573 drops. The independent audit matched only 29 of 57 eligible proxy
  attempts, with 28 missing from wire, one extra on wire and 11 gap categories.
  Payload agreement therefore failed. This recording is diagnostic-only.
- The diagnostic import reached 130,725/130,725 parsed events with zero active or
  failed jobs after normalization was hardened. Its progress UI passed the same
  read-only browser checks, but the UI result does not upgrade transport evidence.

### Repairs learned from the real evidence

- WebSocket JSON containing `U+0000` remains immutable in content-addressed raw
  evidence; only PostgreSQL query projections replace it with `U+FFFD` and record
  the replacement count (`normalizer-v6`).
- A known response-body chunk sequence gap now yields `body_unavailable` and a
  terminal parsed job. Corrupt metadata/digests remain hard failures.
- Pcap pipe drainage is separated from encrypted persistence by a bounded,
  memory-only 32 MiB queue. This addresses the observed durability backpressure
  without writing plaintext packets to disk. The fix has automated stress coverage,
  but no additional paid provider trial was authorized, so no post-fix zero-drop
  claim is made for Hermes.
- The Harbor controller accepts at most 16 invocations, pairs measurements and
  encrypted captures by bounded start-time/exit-code evidence, rejects ambiguity,
  and retains auxiliary identities and hashes.

Model-free validation passed 328 Rust tests, all Go packages including PostgreSQL
integration, and 204 Python tests (one explicitly capture-dependent test skipped).
The original Hermes trial was replayed offline: primary selection and 6/6 integrity
passed, then the known incomplete transport audit failed as expected. No model was
called during this replay.

The redacted public result is
[`benchmarks/2026-09-20-long-horizon-task-progress-linux-x86_64.json`](../benchmarks/2026-09-20-long-horizon-task-progress-linux-x86_64.json).
Prompts, responses, pcap, TLS secrets, plaintext bundles and browser screenshots
remain private.
