# Native Benchmark Worker

`li_benchmark_worker` owns the model- and Engine-agnostic execution of one
already-authorized, immutable benchmark run plan. It does not choose runtimes,
placements, credentials, benchmark contracts, or verification proposals.

The worker accepts exactly one absolute owner-only `0600` input file through
`--input`. That document binds the job, run-plan, Core installation, runtime
execution, benchmark contract, physical target, public record subject, local
HTTPS placement endpoint, credential file references, selected cells, and
owner-private output paths. Linux inputs additionally bind the explicit
loopback Watchdog port, TLS server name, pinned CA, controller certificate,
controller private key, and operation timeout. The worker performs no endpoint,
certificate, or service discovery. The input descriptor remains exclusively
locked for the worker lifetime so Node restart polling can distinguish a live
worker from a stale task without trusting a reusable PID.

The worker embeds the schema-8 prompt templates and native Rust generator. It
uses the existing Gateway native HTTPS client for both exact Engine-rendered
token counting and streaming OpenAI requests. It never starts a shell, Python,
an Engine, a placement, or a service. Concurrent streams launch behind one
barrier and retain only exact usage, TTFT, cache, completion, and bounded
response evidence.

Each cell records its exact wall-clock measurement interval through an injected
clock. The worker preserves the existing two-second minimum observation and
500-millisecond ring-settlement contract, then queries Watchdog protocol v3
over TLS 1.3 mutual authentication for retained raw one-second samples. Empty,
gapped, duplicate, out-of-range, misordered, incomplete, or foreign-request
history fails the cell. Successful schema-8 results contain the non-empty
oracle-compatible compact timeline and maxima; the worker never substitutes
nullable placeholders for unavailable history. The same exported source and
transport are reusable by Application telemetry-window composition, so Core has
one authenticated Watchdog history implementation.

For schema-8 `fresh-context`, the worker partitions the canonical cells into
one short group, one group per declared long-context tier, and one cold/warm
TTFT group. Before the first cell of each group it publishes an ordered
`awaiting_rotation` request and blocks. Only a closed PlacementManager receipt
with exact job, plan, group, aggregate revisions, fresh prefix-store generation,
fresh native process generation, completion time, and receipt digest releases
the group. An earlier exact receipt is ignored while Application replaces it;
foreign, future, malformed, or drifted receipts fail closed. The worker never
implements or substitutes the Placement reset itself.

Successful evidence is compact canonical JSON with one trailing newline. It
is published as a new `0600` file through a create-exclusive hard link and is
never replaced by differing bytes. Restart status and cancellation use
separate owner-only files bound to the same job and plan. All paths reject
symbolic links, traversal, unsafe ownership, modes, and ambiguous identities.

Tests cover Python-oracle prompt byte hashes without invoking Python, the
closed schema-8 mutation matrix, exact token-count injection, concurrent local
execution, exact context grouping, complete process/store rotation receipts,
hash-bound schema-8 records, TTFT cold/warm identity, transport and natural-stop
failure, partial-cache refusal, no-follow input metadata, and atomic
non-replacing publication. Focused Watchdog tests cover exact timeline/maxima
projection, provider failure, gaps, duplicates, empty/out-of-range history,
retained-range bounds, settlement, and deterministic absolute-time replay.
Production tests do not contact an Engine or Watchdog, mutate services, or
publish benchmark evidence.
