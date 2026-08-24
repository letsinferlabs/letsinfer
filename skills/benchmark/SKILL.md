---
name: benchmark
description: Design, run, resume, audit, or report reproducible Let's Infer runtime benchmarks and qualification. Use for prompts, context ladders, TPS, TTFT, cache cold/hot/restart tests, concurrency, pressure, soak, telemetry, evidence hashes, or target benchmark.json results.
---

# Benchmark a Let's Infer runtime

Prove performance, cache correctness, capacity, stability, and safety for one exact runtime identity. Never transfer evidence across a model revision, engine, target, recipe, image, source commit, or cache format.

## Select prompts and context lengths

Read [`../../benchmarks/prompts/PROTOCOL.md`](../../benchmarks/prompts/PROTOCOL.md)
and the versioned generator. Declare only the standard suite, cases, request
settings, seeds, and exact tokenizer/render identity under
`runtime.json.benchmark`. Do not add prompt files, plans, scripts, or arbitrary
commands to the runtime.

Use `letsinfer benchmark` to materialize official prompts into a new evidence
directory. It calibrates the complete rendered request through the exact
tokenizer-count capability supplied by the selected engine adapter. Never send
an unmaterialized template or accept an approximate count.

For a new runtime, cover every supported point from the standard ladder: 1,024; 4,096; 16,384; 65,536; 131,072; 262,144; and 524,288 prompt tokens, stopping only where the exact prompt plus output/template reserve exceeds the qualified context or the hardware safety envelope. Add the largest calibrated prompt that safely fits the declared context. Also preserve every previously benchmarked successful context and its exact historical prompt/method as a separate parity lane. Keep failed/infeasible contexts documented but not runnable as successful cells.

Declare distinct deterministic seeds and let the generator create one prompt
per client through the manifest's declared standard concurrency ceiling. Never
reuse a prompt merely to reach C16. Connection capacity and active engine
concurrency are separate: test the declared connection count even when the
engine queues overflow because memory cannot safely run every request at once.

## Run the declared production matrix

Use `letsinfer benchmark` for the exact domains, contexts, concurrencies, and
execution policy declared by the installed immutable runtime candidate. It is
the only serving configuration. The command has no engine-argument surface
because the runtime owns the command, environment, scheduler, cache, and
safety recipe.

- Run `--list` first to validate the runtime contract, capacity, tokenizer
  identity, and selected cross-product without inference.
- With no selectors, run every declared cell. Combine one concurrency selector
  and one context selector for a narrow diagnostic cell, such as `--c4 --64k`.
- Use distinct generated and hash-pinned prompts for every concurrent stream.
  Compare results only when their exact prompt identity and method match.
- For schema-2 cold contracts, run one isolated cell at a time and require a
  new managed container plus empty dedicated prefix store for every cell.
  Reject nonzero cached prompt tokens.
- For schema-3 shared contracts, require exactly one fresh managed container
  and store for the complete matrix, one sample per cell, deterministic
  ascending concurrency/context order, and explicitly shared prefix state.
  Treat this as cache-aware progression, never cold per-cell evidence.
- For schema-4 prefix-shared contracts, additionally require a complete common
  ledger prefix followed by a distinct stream suffix and C1/C2/C4 adjacency
  within each context. Verify reported cached tokens rather than inferring reuse
  from timing.
- If a cell fails correctness, admission, health, memory, or protection, stop
  and fix that boundary before advancing.
- Use the telemetry sampling interval declared by the runtime contract. Reject
  a different CLI interval instead of changing polling overhead mid-comparison.
- Treat queueing as valid only when every admitted request completes and the
  engine remains healthy, trip-clear, OOM-clear, and restart-clear. Do not
  lower concurrency or publish a separately qualified runtime release to turn
  a failure into a pass.

The declared production matrix supplements rather than replaces the standard
context ladder, cache lifecycle, historical parity, pressure, crash, and any
other gates declared by the release.

## Seal inputs before measurement

1. Start from a clean named Git commit. Record its full commit and tree.
2. Bind the exact runtime configuration, generated private execution view, runtime descriptor/archive, Engine OCI, model and tokenizer revisions, command/environment, benchmark contract, generator/templates, materialized prompt set and plan, runners, and cache namespace.
3. Preserve the best accepted pre-Let's Infer or predecessor result for each exactly comparable row. Reject comparisons with different prompts, roles, output limits, sampling, cache state, engine recipe, or hardware.
4. Use a new immutable evidence directory. Never overwrite, splice, or combine evidence from different identities or lifecycles.

## Run the qualification lanes

Run the narrowest parity screen first, then the complete contract only if it passes:

1. Historical solo and long-context parity, using the final production recipe. Every comparable row must meet or beat both prior decode/aggregate throughput and TTFT by default.
2. Isolated context ladder. For each context, start with a dedicated clean cache namespace and guarded lifecycle; retain the cold miss, immediate hot hit, graceful restart, two restored hits, and replay seal.
   For a runtime declaring persistent cache, verify that the restored hit comes
   from its Core-mounted NVMe store rather than an engine-process RAM cache,
   and include an incompatible or corrupt record check that must become a miss.
3. Output correctness. Preserve full requests, SSE events, token IDs where available, finish reasons, usage/cache counters, and outputs. Enforce the runtime's declared equality oracle; never hide allowed numerical divergence.
4. Admission through the runtime's declared connection ceiling and its
   measured scheduling or queueing behavior.
5. Memory-pressure, graceful protection, ordinary crash restart, OOM-latch,
   and reboot recovery gates without weakening Watchdog thresholds.
6. Run soak or other sustained-load plans only when the release contract
   explicitly requires them, and then run their full committed form.

Use the canonical runners in `benchmarks/`. Do not shorten plans, force favorable output, reuse warmed fixtures as cold, ignore failures, or start the next lane while an unrelated workload is active.

## Capture evidence

Use the exact committed sampling interval for every comparison arm and retain
raw plus summarized evidence. Keep the independent safety recorder/guard at
one-second resolution or faster; do not increase benchmark telemetry frequency
mid-campaign because polling overhead becomes part of the measured workload.

- prompt/completion/cached tokens, TTFT, wall latency, decode TPS, aggregate TPS, and cache write/reuse;
- CPU busy/load, GPU utilization/memory/power/temperature, and all thermal zones;
- host available memory, swap use/delta, PSI and cgroup OOM state;
- NVMe temperature, bytes, operations, and I/O time deltas;
- Docker CPU/memory/block/network/PIDs, health, restart count, and OOMKilled;
- Watchdog state, trip record, current/peak memory, and protection action;
- cold/hot/restored output hashes and engine-specific cache/speculation metrics.

Keep every raw request and telemetry stream. Hash `results.json`, the complete evidence tree, or both according to the runner contract.

## Decide and report

Fail closed when any correctness, safety, identity, cache, stability, capacity, or performance gate fails. A performance fix requires a new runtime identity/checkpoint and fresh evidence; never edit a result into a pass.

An ordinary or verifier run produces a validated local `benchmark.json` in its
immutable evidence directory. Do not treat one author's checked-in result as
qualification. For a runtime PR that has passed `benchmark-ready`, use:

```bash
letsinfer benchmark verify https://github.com/letsinferlabs/runtimes/pull/123
```

This command permits no workload/configuration overrides. It benchmarks the
current recommendation and exact trusted-finalizer bundle with the same
contract. It never downloads or packages PR source. For a changed Engine it
validates the bundle's OCI descriptors and rootfs diff IDs, converts the layout
to a temporary Docker-load archive, and removes that archive plus only the
image it introduced. It requires GitHub CLI 2.97.0 or newer and verifies build
provenance for every bundle file against the trusted main-branch finalizer.
It restores the previous runtime and local Engine state on every terminal path
and posts the complete signed record through GitHub CLI. Ctrl-C detaches; use
`letsinfer benchmark verify status` to reattach and
`letsinfer benchmark verify stop` to cancel and restore.

Before sealing or transporting a record, run:

```bash
python3 benchmarks/benchmark_record.py /path/to/runtime/benchmark.json
```

`letsinfer pack` runs the same validator again and rejects `benchmark.md`.
Schema-5 records for schema-3 through schema-6 shared matrices embed the
complete declarative benchmark contract, and the validator recomputes its
canonical SHA-256 before accepting `benchmark_contract_sha256`. Legacy schema-2
cold matrices retain the schema-4 record form.
Every result must use a neutral `ppN,tgN,cN` workload and report aggregate TPS,
decode TPS, TTFT and its statistic, `is_prefix_cached`, maximum GPU and CPU
utilization, maximum GPU and CPU temperature, CPU/GPU/VRAM/system-RAM clocks
and their maxima, and the fixed-schema one-second Watchdog telemetry timeline.
Record an unavailable clock as `-1` in the timeline and maximum. Use JSON
`null` only when historical evidence did not capture another optional metric;
never infer it. The cache field is
always a boolean and comes from reported cached prompt tokens, not timing.

The record ID is a SHA-256 bound to the private installation ID, benchmark
timestamp, benchmark-contract digest, and the complete results/timeline digest.
The installation ID is itself bound
to a hashed host/physical-GPU fingerprint, the immutable runtime digest, and
its install timestamp. Never publish the raw host machine ID or GPU UUIDs.

Use Watchdog's independent raw one-second ring for the public timeline; do not
increase runner-side polling or derive the timeline from a post-run snapshot.
The validator must enforce the fixed column order, monotonic elapsed times,
numeric bounds, and equality between each published maximum and its timeline.

The bot accepts one slot per GitHub account and pseudonymous device and
requires two successful independent non-author verifiers. Rerunning does not
create a second slot. Any accepted correctness, safety, crash, OOM,
incomplete-workload, or restoration failure blocks that exact execution
subject and cannot be rerun away. Performance differences remain visible but
do not create a disagreement state or expand the verifier count. The bot
writes the full records plus aggregate into bot-owned
`benchmark.consensus.json`. Do not upload community evidence to an OCI,
hand-edit consensus, or add qualification state to a runtime manifest.

Keep generated prompts, plans, complete outputs, private evidence, and
machine-specific details in ignored evidence storage; generic runners and
templates remain in Let's Infer core. Keep full immutable identities, hashes,
failures, evidence paths, and comparison details in Let's Infer's durable
technical record rather than adding prose to `benchmark.json`.
