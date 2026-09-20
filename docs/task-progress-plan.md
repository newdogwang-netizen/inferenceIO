# Task progress and long-horizon recording

Status: progress UI implemented and locally verified; first long-horizon case
failed during Docker environment creation, before agent execution (2026-09-20).
No automatic retry; Hermes case not started. This stage does not inherit
the previous frozen recorder/platform qualification for changed artifacts.

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

Remaining: independently recorded long-horizon real tasks and browser checks of
their actual multi-page progress, then a reproducible outcome report. None of the
above claims a new five-hour qualification or converts a short task into a long one.

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
