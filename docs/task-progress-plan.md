# Task progress and long-horizon recording

Status: progress UI implemented and locally verified; long-horizon experiments
not yet started (2026-09-20). This stage does not inherit
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
