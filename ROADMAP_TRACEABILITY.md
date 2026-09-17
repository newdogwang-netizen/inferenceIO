# Roadmap traceability and release closure

Assessment date: 2026-09-16. This is an implementation audit of
`agent-inference-flight-recorder-feature-roadmap.md`; it does not modify or
narrow that input. The release evidence named here has been checked against the
frozen v1.0 artifacts.

## Current verified implementation groups

The source roadmap contains 109 unique feature IDs. The grouped rows below
cover all 101 IDs assigned through the v1.0/M7/P4 release; the remaining eight
IDs are the explicitly labelled `v1.x` items listed separately at the end.
Release gates and cross-cutting platform milestones are audited independently
after the ID-level mapping so a feature row cannot substitute for duration or
fault-injection evidence.

| Roadmap IDs | Current evidence |
|---|---|
| RUN-001–005, RUN-007 | `src/runner.rs`, `src/cgroup.rs`, `src/process_tracker.rs`, and `src/tasks.rs`; launch/signal/cgroup/namespace tests plus a long-lived encrypted/compressed Hermes gateway regression that splits interleaved native task IDs inside one physical run. The same versioned `agent-task-or-session-v1` boundary is rebuilt across platform Recording segments. |
| DISC-001–006, DISC-008 | passive executable/runtime/TLS discovery, probe plan, connection classification, fail-closed inspection tests |
| EVT-001–008 | shared v1 schema, bounded append-only encrypted writer, backward-readable zstd event blocks, blob CAS, crash recovery, legacy migration tests, byte/entry budgets, and whole-run pruning |
| NET-001–009 | streaming H1/SSE/WS proxy, H2 ingress/upstream and offline decode, retries, rootless proxy-only and transparent task-network tests |
| ADP-001–008, VER-010 exact Agent cells | Ephemeral Gemini/Claude/Codex/Hermes adapters, authenticated hook protocol, session readers and fixtures; versioned statically linked Adapter SDK with the four-method contract, bounded host validation, confidence ceilings, panic containment, durable-native-first parsing, cleanup, compatibility/adversarial tests, and encrypted real-run integration. The final compatibility report binds frozen recorder SHA-256 `9844f977…` and qualifies exact Gemini CLI 0.60.0, Codex 0.154.0, native Claude Code 2.1.273, and Hermes 0.19.0 executables against the controlled provider: five of five model attempts match independent task-egress transport evidence, seven non-model requests are excluded by protocol semantics, and all four schema-v3 audits are complete. Unlisted versions/providers remain `unknown`; Bedrock, Vertex, OAuth, and public-provider availability are not inherited from these cells. |
| INJ-001–004 | bounded Python/Node observers and TLS-keylog injection with subprocess integration tests |
| BPF-001–006, BPF-008 | versioned helper protocol plus limited AgentSight/eCapture bridges; trusted strict-schema policy rules bind OS/architecture and target/TLS fingerprints to a digest-pinned helper, fail closed on no-match/ambiguity/change, and persist selection evidence. GoTLS qualification pins Go 1.24.13 and 1.25.13, reassembles four concurrent 64 KiB bidirectional streams per version, excludes same-binary outside-cgroup traffic, and independently verifies every payload digest. The matrix remains experimental where upstream loss is unobservable. |
| TLS-001–006 | encrypted pcap/key logs, trusted TShark decode, H1/H2 reconstruction and exact multiset payload audit; random wrapped per-class keys plus authenticated, crash-resumable TLS-secret cryptographic erasure |
| COR-001–005 | ID hierarchy, retry grouping, process connections, conservative multi-source correlation and confidence evidence |
| STATE-001–004 | response/cached-content reference analysis and unresolved gates |
| TEST-001, VER-000–009 | bounded fake server, manifest/inspect/verify gates, fault/cancellation/multimodal/drop/egress/payload-diff regressions |
| SEC-001–007 | mandatory credential filtering, capture policy, per-run and per-class encryption, separated helpers, task/key boundaries, local/platform audits, independent body/pcap/TLS-secret TTLs and honest physical-media limits |
| VIEW-001–006 | inspect, timeline, raw/OpenInference/OTLP/replay exports and replay limitations |
| UP-000–011 | shared schemas, encrypted local spool, deterministic zstd upload/resume, persistent identity/heartbeat, restrictive new-run config, policy-gated audited remote TTL/delete, active exact-boundary flush/seal with crash replay, size/time Recording segmentation, global sequence continuity, segment-chain backfill/retention, run-scoped platform reassembly/query tests, and platform tar import |
| P0–P4 platform path | Go API/worker/query/control implementation; project-default plus collector-scoped monotonic configuration; versioned platform-owned transport audit with strict task-egress terminal evidence, bounded object validation, TShark H1/H2 reconstruction, exact body multiset comparison, persisted proof and fail-closed coverage consumption; bounded asynchronous normalized-JSONL export with authenticated integrity-checked download; durable remote deletion/TTL propagation with immediate read/control fencing, shared-blob reference safety, crash-orphan recovery, and minimal tombstones; hardened non-root API/Worker/Web images; PostgreSQL integration tests, fresh migrations, Web production build, Go race and vulnerability scans. Current API/Worker/Web image IDs and executable hashes are recorded in `PRODUCTION_READINESS.md`; independent live inspection and the full-duration connected qualification pass every duration, fault, sequence, integrity, deletion, provenance, and hardening gate. |

## Release-gate evidence

| Gate | Authoritative coverage |
|---|---|
| v0.1: 100 HTTP/SSE calls, cancellation, crash recovery, no credential leakage | `tests/proxy_e2e.rs` runs `one_hundred_concurrent_streams_do_not_cross_or_truncate`, `stream_reset_preserves_the_recorded_prefix_and_error_terminal`, and `records_exact_stream_and_never_persists_authorization`; `src/storage.rs` exercises torn-tail recovery and durable-prefix acknowledgement; policy/discovery/CLI tests reject or redact credential-bearing metadata. |
| v0.3: H2, retry/reset, WS reconnect, proxy/pcap diff, upload recovery | Proxy and transport-audit suites cover concurrent H2, 429/500/reset attempts, reconnect-preserving bidirectional WebSocket capture, and exact H1/H2 body multisets. `src/upload.rs`, collector control tests, and PostgreSQL integration tests cover immutable batches, server `durable_seq`, idempotent restart, active segment chains, and crash replay. The final connected gate injects a 900-second platform outage, exceeding the roadmap's ten-minute outage case. |
| v0.4: fail-closed completeness vector | `src/manifest.rs`, `src/verify.rs`, `src/inspect.rs`, `src/transport_audit.rs`, and platform coverage tests independently recompute TLS/parser/drop/egress/terminal/payload gates and reject unsupported claims. Positive proxy-only/transparent task-egress cells complete; bypass, unknown, loss, missing end, ambiguity, and malformed-proof negatives remain incomplete. |
| v1.0: exact support cells, performance, manifest truthfulness | `support-matrix.v1.json` is embedded and defaults unlisted cells to `unknown`; `src/support_matrix.rs` validates evidence and the four exact real-Agent cells. `PERFORMANCE.md` and machine-readable reports bind overhead to the frozen binary. Every run finalizes a bounded coverage manifest whose claim remains `best-effort`; narrower completeness is emitted only by a separate successful audit. Both exact-current five-hour gates, the final-hash performance rerun, and the exact real-Agent rerun passed. |
| P4/M7 connected release | Shared schemas, uploader/control client, platform import/export, Compose hardening, rolling Recording chains, fault recovery, remote/local erasure, and independent platform release provenance are implemented and verified. The final 20-collector duration/fault qualification passed. |

## Closed release evidence

| Roadmap item or gate | Final evidence | Closure |
|---|---|---|
| M5/M6 final freeze | Recorder SHA-256 `9844f977fc3f4b4f466dac8fb1ec8495d835da38e6aaa4aaeb083fb57e873869` is frozen. It passes 308/308 Rust tests, formatting, Clippy with warnings denied, MSRV check, RustSec audit, locked release build, exact real-Agent qualification, explicit-delete/TTL separation, and tamper-aware recovery. | Closed; deterministic rebuild retained the exact binary hash. |
| Final-candidate performance | The final 5 × 400-request benchmark completed both 2,000-request paths without error; all five encrypted recorder rounds passed validation. Recorded throughput was 85.112 requests/second (-5.02%), and TTFT p50/p95 overhead was +8.78%/+0.14%. | Closed by report SHA-256 `099e8980124453ed208fcc578902fd0cf6d108a134726d3113e14bf5d0227a33`. |
| Operator steady-state override | The fresh exact-hash core report covers 18,000.003 measured seconds, 18,000/18,000 attempts, 522,023 events, and 216,000 blobs with zero client error, incomplete attempt, capture drop, event tail, missing blob, or corrupt blob. Independent blob and integrity verification passed. | Closed by report SHA-256 `b00c9b725d37d08332661fbadadb3f065f83be44bc9feb6fc859272552243632`; aborted historical attempts were not reused. |
| P3/P4/M7 connected gate | Twenty collectors each exceeded 18,000 seconds and completed 6,000/6,000 attempts, 174,346 local events, and 1,137 server segments. API outage, collector/Worker restart, identity, local/spool/server/global-sequence, drain, runtime provenance, and remote-plus-local deletion checks all passed. Independent provenance binds the exact platform tree and images. | Closed by connected report SHA-256 `4ae2969d9ae0c78209d48c9a75488b9391597cf524b193a9957045c816899352` and provenance SHA-256 `c63f63ae17491bad6b3fdb0c2682182ce8fbf3c73efa598732b401aca0d662e6`. |

## Post-v1.0 items retained from the roadmap

RUN-006, DISC-007, NET-010, INJ-005, INJ-006, BPF-007, COR-006, and
STATE-005 are explicitly labelled `v1.x` in the source roadmap. They remain in
scope for that later milestone and must stay `unsupported` or `unknown` in a
v1.0 manifest; they are not silently treated as implemented.
