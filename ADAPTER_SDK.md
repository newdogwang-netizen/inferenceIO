# Adapter SDK v1

The public `iorec::adapter_sdk` module is the versioned extension boundary for
third-party Agent adapters. An adapter implements exactly four methods:

1. `detect` identifies a target from passive command metadata.
2. `configure` requests bounded argument and environment changes and may write
   ephemeral hook settings only inside the supplied private scratch directory.
3. `parse` converts an already captured native hook/session record into one or
   more normalized events.
4. `correlate` proposes a relationship to a host-supplied bounded candidate
   set and states its evidence basis.

See [`examples/adapter_sdk.rs`](examples/adapter_sdk.rs) for a complete minimal
implementation. A custom statically linked recorder calls
`iorec::runner::run_with_adapter`; the ordinary `run` entry point and CLI keep
using the built-in adapters.

## Compatibility

The adapter API version is independent from the crate release version. The
host accepts an adapter with the same API major and an API minor no newer than
its own. Breaking changes require a new major version. An adapter also declares
a portable name and its own release identifier; both are attached to derived
event evidence.

The v1 host validates command and environment sizes, protects every `IOREC_`
environment name, bounds JSON size/structure and output cardinality, validates
IDs/labels/confidence, rejects invented correlation candidates, and catches an
adapter panic at each call boundary. Correlation confidence is capped by basis:
exact ID 0.95, parent ID 0.85, temporal 0.50, heuristic 0.25, and unresolved
0.00. These values intentionally prevent adapter claims from becoming recorder
proof.

## Evidence and security contract

SDK adapters are process-local, statically linked code and therefore share the
recorder process trust boundary. Only ship reviewed adapter code. Panic
containment prevents stack unwinding into the recorder, but Rust cannot stop an
in-process adapter that blocks forever or terminates the process.

The native hook submission is authenticated, redacted, and durably appended
before `parse` runs. Parsed output is then independently validated and redacted,
uses a host-controlled `adapter:<name>` source, and carries both the SDK release
label and native hook sequence. A parse failure or panic preserves the native
record, increments capture loss, and emits a non-sensitive error-class event.
The host removes and records removal of the private configuration scratch
directory before finalizing a successful run.
SDK events never activate packet/TLS coverage and never by themselves upgrade a
run beyond `best-effort`.

Adapters must not:

- implement transport capture, event sequencing, storage, or completeness
  decisions;
- copy credentials into identifiers, labels, error summaries, or normalized
  fields;
- modify recorder-owned `IOREC_` environment variables;
- treat lifecycle/model hooks as independent wire evidence;
- write outside the supplied scratch directory during configuration.

Run the contract and real-run integration gates with:

```bash
cargo test --lib adapter_sdk::tests --locked
cargo test --lib collector::tests --locked
cargo test --test runner_e2e statically_linked_adapter_sdk_configures_and_parses_a_real_run --locked
cargo test --example adapter_sdk --locked
```
