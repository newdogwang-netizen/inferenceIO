# M1–M3 acceptance: 2026-09-19

Local technical acceptance is complete for the user-amended scope. Publication
of these final commits and the updated GitHub Pages site is still pending
repository write access; no successful remote CI/deployment is claimed here.

This is not universal production certification. The accepted boundary is Linux
x86-64, the exact recorder/platform artifacts below, the declared Codex/Hermes
experiments, and the synthetic recovery workload. Claude was explicitly excluded,
not qualified. Historical failures, unknown coverage and unresolved associations
remain visible.

## Requirement-by-requirement result

| Requirement | Verified evidence and boundary |
| --- | --- |
| M1: separate calls from their WebSocket connection | The original real Harbor connection has 19 separately traceable calls, 13,780 messages, 13,710 assigned messages and 70 controls; no unresolved message ownership. |
| M1: inputs, outputs, tools, usage, previous-response links | Per-call projection verifies 17 tool calls/results, terminal snapshots and usage without double-counting; the retained M1 audit checks all 18 previous-response links. |
| M1: independent call/transport/capture/benchmark states | Completion, cancellation intent/confirmation, errors, ambiguous/interleaved messages, gaps and reconnect identities have regression coverage. Historical `client_read` and absent low-level error detail remain unknown, not rewritten. |
| M1: immutable evidence and repeatable derivation | Original encrypted manifests/events are unchanged. The real 19-call projection hash remains `97b65376…f6b54`; repeated fresh-trial imports retain the same six-call projection and original evidence. |
| M2: navigable and explainable evidence | Current Chromium checks pass for the 19-call list, child views, two 100-event pages, independent benchmark score and TLS/proof boundaries; no runtime errors. Transport verified and overall unknown remain separate. |
| M2: a documented fresh-trial workflow and safe recovery | New paid Harbor trials exercised the complete workflow. Two subsequent resumptions of the same new trial preserve six calls, original hashes and cleanup; failure/SIGKILL cleanup and admission-lock regressions also pass. No new model run is launched by replay. |
| M2: stable local access and health | Host Web is `http://127.0.0.1:8088`; API is `http://127.0.0.1:18080`. API, web and all eight worker pools are healthy. Browser-forwarded ports are temporary aliases. This loopback development instance is separate from the fault-injection platform. |
| M2: current documentation and machine evidence | README, SUPPORT, PRODUCTION_READINESS, this acceptance record and the machine-readable reports agree on artifact identities and limits. Local blog rendering/navigation and mobile layout are checked; remote publication is pending. |
| M3: amended real-agent matrix and paired observations | All 8 matrix cases and both extra off/on cases have terminal results. Six matrix captures qualify (Codex 4/4, Hermes 2/4); five have benchmark reward 1. Both paired tasks score 1. Agent/model/task/recorder/decoder inputs and hashes are retained in the experiment report. |
| M3: traceability and truthful failure handling | All 64 real model calls remain traceable. All 66 unresolved cross-source associations are enumerated with evidence and reasons. Two selected Hermes captures remain strict failures; complete SSE text is not sufficient for complete HTTP transport. |
| M3: error-path and native-session validation | Controlled socket/cancellation/queue/failure fixtures cover nondeterministic paths. The final recorder's local native Hermes CLI fixture matches its exported session, hook, assistant text and 1/1 independent transport audit. This single-call temporal match does not resolve historical multi-call ambiguity. |
| M3: paired resource observations | Off/on agent wall times are 33.94 / 46.36 seconds; CPU/RSS and confinement differences are retained. One nondeterministic pair does not establish causal recorder overhead. Cost is approximate, not provider billing verification. |
| M3: freeze and five-hour recovery/integrity gate | The final 20-collector workload passed with each client exceeding 18,000 seconds, 6000/6000 successful calls, all required fault recovery, contiguous local/platform sequences, complete blob integrity and empty processing queues. The independent final report checks reject changed artifacts or incomplete duration. |

## Final frozen five-hour result

- Recorder SHA-256: `59a10e9fcd944b8961dbf8458a4fe572241f9beac76419ab2139b190a8f8eaee`.
- Worker image: `sha256:ad510437ad083973948c870be19498a8f977b1450755790ce3d3e9c55b79515c`.
- API image: `sha256:ea7556877c74697f3049c549431b4cdadda4139a32f83216072a3799ecb981f3`.
- Web image: `sha256:9884e3ada730c6126a98e2c5dc1739988063610654ea7ccc999be08e678981d5`.
- Full report SHA-256: `28f2d1cb367fd2877a35c5f6e4ded217911dca48dc991475236858788cb44f78`.
- 112,647 local events, 1140 recording segments, 3280 physical transport attempts.
- 6000 model-call workload successes, including 3000 projected WebSocket calls
  across 280 connections, 1500 tool-call/result pairs and 270 cross-segment connections.
- API outage lasted the declared 15-minute window; all 20 local logs advanced.
  Collector identities remained stable after restart; worker restart recovered.
- Final reconciliation: no active/dead jobs, open recordings or parse lag;
  every local/spool/platform sequence and recording/blob check passed.
- The report retains 30 open coverage findings. Passing this gate does not
  erase them or constitute independent pcap/TLS proof of real-provider traffic.

The deletion-propagation test irreversibly erased only its newly generated
synthetic run `run-01a0b9b3-f393-7748-bbc6-986bcf1f506e`. Real-agent recordings
were not selected. The prior one-hour failed attempt remains failed; its time
was not accumulated into this fresh five-hour run. Its raw recordings, reports,
database/object volumes and captured service logs remain preserved.

## Evidence and reproduction

- [Final five-hour report and requirement summary](../benchmarks/2026-09-19-m3-final-connected-5h-linux-x86_64.json)
- [Completed real experiments](../benchmarks/2026-09-19-m3-completed-experiments-linux-x86_64.json)
- [Per-call inventory and pre-soak acceptance](../benchmarks/2026-09-19-m3-final-candidate-pre-soak-audit-linux-x86_64.json)
- [Retained live-inspection failure, fix and replacement checks](../benchmarks/2026-09-19-m3-live-inspection-race-linux-x86_64.json)
- [Hermes HTTP framing diagnosis](hermes-http-framing-diagnostic.md)
- [Harbor workflow and independent pcap/TLS methodology](harbor-terminal-bench-audit.md)
- [Mixed-protocol calibration and five-hour reproduction](mixed-protocol-qualification.md)

Historical reports are immutable snapshots, so their earlier incomplete status
and older binary identities are not edited to manufacture final acceptance.
Future changes affecting these paths need their own applicable qualification.
Private credentials, raw model payloads, TLS secrets and operator approvals are
not publication artifacts.
