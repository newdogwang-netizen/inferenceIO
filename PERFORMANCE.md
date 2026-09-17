# Performance evidence

Performance numbers are observations for one binary and environment, not universal guarantees. The repeatable harness is `tools/perf_harness.py`; it refuses non-loopback destinations, uses the same client and fake server for both paths, alternates round order, enables full-body capture plus at-rest encryption, and validates every recorded run afterward.

## 2026-09-15 baseline

Binary SHA-256: `d1c57ac789b5f461cd91b7574a02bce348e6952b186139cc5569f3f6b7923890`

Environment: Linux 6.12.94 x86-64, 16 logical CPUs, Intel Xeon Platinum 8581C, Python 3.13.5. Workload: five rounds, four concurrent persistent clients, 400 measured plus 20 warmup requests per round, 1 KiB request payloads, and three 256-byte SSE chunks with 5 ms delay per chunk.

| Metric | Direct | Encrypted recorder | Change |
|---|---:|---:|---:|
| Requests | 2,000 | 2,000 | — |
| Errors | 0 | 0 | — |
| Requests/second | 89.864 | 85.372 | -5.00% |
| TTFT p50 | 43.963 ms | 47.713 ms | +8.53% |
| TTFT p95 | 47.965 ms | 48.070 ms | +0.22% |
| CPU/request | 0.524 ms | 4.510 ms | +3.986 ms (+761%) |

All five recorder runs contained exactly 420 attempts and 6,329 events, with zero capture drops, zero incomplete attempts, no missing/corrupt blobs, and a passing integrity verifier. The machine-readable report is [benchmarks/2026-09-15-linux-x86_64.json](benchmarks/2026-09-15-linux-x86_64.json), SHA-256 `8dac9ac7af6b59827d8f8cbfac4230f9074b86287a1768886644e5b276515d52`.

## Soak calibration

A 60-second encrypted run at 10 requests/second completed 600 requests and 9,021 events with no client errors, capture drops, incomplete attempts, missing/corrupt blobs, or count mismatch. Its TTFT p50/p95 was 6.484/7.155 ms. The machine-readable report is [benchmarks/2026-09-15-soak-60s-linux-x86_64.json](benchmarks/2026-09-15-soak-60s-linux-x86_64.json), SHA-256 `50e6bd0c4e826949134e070f6b4c5bfd191f59ffe13add928f7da9b68eebb8a2`.

## 2026-09-16 final-freeze benchmark

The same five-round workload passed against frozen release SHA-256 `9844f977fc3f4b4f466dac8fb1ec8495d835da38e6aaa4aaeb083fb57e873869`. Both paths completed 2,000/2,000 measured requests with zero errors. Direct versus recorded throughput was 89.607 versus 85.112 requests/second (-5.02%); TTFT p50 was 43.915 versus 47.771 ms (+8.78%), and TTFT p95 was 47.958 versus 48.023 ms (+0.14%). Recorded child CPU was 8.629 ms/request versus 0.549 ms/request for the intentionally cheap direct loopback path. All five encrypted recorder runs passed attempt/count/storage/blob/integrity validation.

The machine-readable report is [benchmarks/2026-09-16-performance-final-9844f977-linux-x86_64.json](benchmarks/2026-09-16-performance-final-9844f977-linux-x86_64.json), SHA-256 `099e8980124453ed208fcc578902fd0cf6d108a134726d3113e14bf5d0227a33`.

## Five-hour core-candidate soak

The operator-approved steady-state duration passed against release binary SHA-256 `1e77919322cad1ece9840a85de713e6837049a6ef21024df651a3b668f5a5cd7`. Over 18,000.003 measured seconds, the encrypted recorder completed 9,000 requests at 0.5 requests/second with zero client errors. The finalized run contains 9,000 logical inferences and transport attempts, 135,023 events, and 36,001 blobs. Capture drops, incomplete attempts, discarded event-log tail, missing blobs, and corrupt blobs are all zero; the manifest is authenticated and finished with exit code zero.

The machine-readable report is [benchmarks/2026-09-15-soak-5h-final-linux-x86_64.json](benchmarks/2026-09-15-soak-5h-final-linux-x86_64.json), SHA-256 `8b2c769695f9900660908fe62c02814e4c25cb99d011b9e06d052aa82e104798`. After the harness passed, the same frozen binary independently passed `inspect --verify-blobs` and `verify --profile integrity` over the finalized run. The 18,000-second duration supersedes the draft roadmap's 24-hour duration by operator decision.

## Five-hour final-freeze soak

The release-closing run passed against frozen SHA-256 `9844f977fc3f4b4f466dac8fb1ec8495d835da38e6aaa4aaeb083fb57e873869`. Over 18,000.003 measured seconds it completed 18,000/18,000 requests and transport attempts, 522,023 events, and 216,000 encrypted blobs. Client errors, capture drops, incomplete attempts, discarded event-log tail, missing blobs, and corrupt blobs were all zero. The manifest was authenticated and finished with exit code zero; the harness and independent post-run `inspect --verify-blobs` and `verify --profile integrity` checks passed.

The machine-readable report is [benchmarks/2026-09-16-soak-5h-final-9844f977-linux-x86_64.json](benchmarks/2026-09-16-soak-5h-final-9844f977-linux-x86_64.json), SHA-256 `b00c9b725d37d08332661fbadadb3f065f83be44bc9feb6fc859272552243632`. At process start the harness SHA-256 was `3f96783f43f0648c3cf4f08ae0b598384d31275c12f40d2798808f2fb0b56259`; during the run an unused `statistics` import was removed, producing current SHA-256 `2629a866ef5154b082a05183d2623290399cb5e1d5abd99e1333151d77ed230a`. The removed line was not referenced and did not alter workload, timing, validation, or report generation; reinserting it exactly reconstructs the start digest.

## Interpretation and remaining scope

The relative CPU percentage is large because the direct loopback baseline is very cheap; the absolute recorder increment is about 4 ms/request in this workload. The benchmark includes recorder startup/finalization in outer wall and child CPU figures, while request throughput and TTFT use the client's measured interval. Fake-server CPU is excluded from both paths.

The five-hour steady-state and repeatable performance gates are closed for the frozen final binary and documented environment above. These results do not establish production-provider, cross-host, arm64, macOS, container, HTTP/2, or WebSocket performance; those require separately identified matrix evidence and must not inherit this result.
