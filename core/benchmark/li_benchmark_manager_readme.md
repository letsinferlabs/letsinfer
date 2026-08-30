# BenchmarkManager

`li_benchmark_manager` owns one durable benchmark job from admission through
restoration and immutable evidence sealing. It is an in-process Core manager,
not another daemon. `li_node` supplies its persistence and schedules its
restart-safe `poll` calls; the CLI only starts, follows, or stops jobs through
the node API.

The manager is model- and Engine-agnostic. It binds an exact runtime execution,
benchmark contract, target contract, placement group, and optional community
verification subject by digest. Runtime-owned ranks, stages, flags, cache
formats, and Engine behavior never enter this crate.

External mechanisms are narrow injected capabilities:

- `BenchmarkAuthorizationProvider` admits local or community-verification work;
- `BenchmarkExecutionProvider` prepares, starts, observes, stops, and restores
  one opaque execution;
- `BenchmarkTelemetryProvider` persists the schema-owned timeline and returns
  one immutable receipt;
- `BenchmarkEvidenceProvider` materializes and semantically verifies schema-7
  OCI or schema-8 native evidence; and
- `BenchmarkSigningProvider` signs and verifies the exact immutable evidence.

`BoundBenchmarkAuthorizationProvider` first verifies the exact active local
main. Local jobs never consult community state. Community verification then
binds the exact pull request, head, candidate, verifier, device, baseline,
readiness, and verified finalizer bundle into an opaque receipt. Qualification
is a label and never an authorization or execution gate.

`ResolvedBenchmarkRunPlanProvider` resolves only the typed Runtime installation
and Placement group named by the request. It rebinds every Core, Runtime,
logical-model, Placement-group, execution, benchmark-contract, and target
identity; selects only declared cells; requires the exact token-count endpoint;
and preserves OCI schema 7 versus native schema 8. It has no Engine rank, flag,
topology, or command vocabulary.

Every mutating provider call is keyed by the benchmark operation identity and
must be idempotent. The journal records each receipt before advancing. A
restart therefore resumes `requested`, `prepared`, `running`, `stopping`,
`restoring`, or `finalizing` work without inventing a second execution or
forgetting the resident-service restoration obligation.

`DatabaseBenchmarkStore` is the production persistence adapter. It uses the
dedicated DatabaseManager `Benchmarks` collection and one closed record union,
so a typed collection read can decode both journals and the sole-active
pointer without mixing unrelated record shapes. Journal creation, revision
replacement, active-pointer advancement, and terminal release each use one
atomic database transaction. The pointer revision advances in lockstep with
the journal; missing, duplicated, stale, malformed, or semantically corrupt
records fail closed. OCI execution-payload schema 7 and native
execution-payload schema 8 remain distinct exact identities after restart.

`FilesystemBenchmarkEvidenceProvider` is the production local evidence
adapter. It accepts only bounded Python-canonical schema-7 OCI or schema-8
native records under owner-only directory chains, validates the complete
schema-8 contract, result, telemetry-maxima, optional TTFT-cache, and identity
semantics, and atomically publishes one owner-only, no-follow, single-link
record by its SHA-256 identity. Exact replays succeed; unsafe metadata,
partial I/O, changed bytes, conflicting publications, and failed durability
boundaries fail closed with attempt-owned cleanup.

Failed or cancelled post-preparation work never impersonates a successful
schema-7 or schema-8 record. The same provider instead materializes the closed
`li_benchmark_core_local_failure` schema 1, binding the exact request, outcome,
raw-evidence identity when present, telemetry receipt, and restoration receipt
into deterministic SHA-256 identities. This signed record is Core-local
terminal evidence and is intentionally not compatible with public benchmark
publication.

`OpensslBenchmarkSigningProvider` implements the established Ed25519 contract
through explicit absolute OpenSSL configuration and fixed shell-free `pkey`
and `pkeyutl` argv. Public-key DER identifies the signer; signatures use
unpadded base64url. Keys, evidence, and temporary message/signature files are
owner-only and single-link, command output and runtime are bounded, temporary
state is synchronized and removed on every completed or failed attempt, and
provider failures never expose paths, key material, stdout, or stderr.

`CoordinatedBenchmarkExecutionProvider` is the production manager adapter for
one exact model-neutral run plan. Its single `BenchmarkExecutionScheduler`
port is composed externally over Placement, Gateway, Watchdog, and the native
task runner; this crate imports none of those managers. Preparation, launch,
observation, cancellation, timeout containment, and restoration use bounded
typed commands, deterministic receipts, fixed immutable contract/result
identities, and no shell. Replays reissue the same command identity, malformed
progress or result identities are contained, and scheduler failures are
redacted.

`WindowedBenchmarkTelemetryProvider` is the corresponding production adapter
for one persistent `BenchmarkTelemetryPort`. The port materializes contiguous
one-second Watchdog/Gateway observation windows and retains the timeline across
Core restart. The provider rejects gaps, backwards clocks, progress regression,
identity drift, oversized duration, zero-sample success, and changed sealed
state. A delayed replay returns the original closing window and receipt rather
than extending immutable evidence.

Application composition supplies the narrow execution scheduler and telemetry
ports. Cleanup failure still attempts resident restoration. Telemetry persists
contiguous one-second windows with optimistic replacement. Neither adapter
calls another manager.

Node composition owns `DatabaseBenchmarkStore`, the sole-active schedule, and
restart polling. Its private API exposes exact start/read/stop commands and a
secret-free status projection. The resident daemon treats a failed benchmark
poll as independent from hardware and outbox work. No benchmark component
publishes to the network.

Local cell selection is diagnostic evidence only. Community verification
always consumes the complete declared contract, and every crash, OOM,
protection trip, output failure, incomplete workload, or restoration failure
remains an explicit signed failure rather than a performance sample.

The crate runs 45 deterministic CI contracts: 17 manager lifecycle tests with
mocked authority, execution, telemetry, evidence, signing, persistence, and
time boundaries; seven real DatabaseManager adapter tests for both evidence
schema identities plus Core-local failure evidence, replay, global active exclusion, optimistic revision
conflict, corruption, ambiguous ownership, and bounded storage failure; eight
native-I/O and command-boundary adapter tests plus one Core-local terminal
evidence test; five execution/telemetry adapter tests; one Python-canonical
JSON compatibility test; and six authorization/run-plan composition tests.
Application and Node integration have separate deterministic scheduler,
telemetry, private-wire, restart, cancellation, restoration, and nonfatal-daemon
tests. Network publication and live benchmark execution are intentionally not
part of these adapters or tests.
