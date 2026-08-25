# Benchmark and qualification framework

Let's Infer core owns benchmark transport, canonical prompts, workload
generation, isolation, safety checks, telemetry capture, and evidence. Your
runtime declares only its benchmark contract in `runtime.json` and retains the
validated public `benchmark.json`.

## Features

- **One command** — run a complete standard matrix or select exact context and
  concurrency cells from the CLI.
- **Apples-to-apples prompts** — every model receives the same canonical code
  and prose tasks, rendered and counted by its own Engine adapter.
- **Sealed isolation** — schema-2 contracts give every cell a fresh process and
  empty prefix state. Schema-3 contracts may instead seal one fresh process and
  store for the complete matrix, one sample per cell, and explicitly shared
  prefix state. Schema-4 contracts additionally give distinct streams one
  shared ledger prefix and keep C1/C2/C4 adjacent per context; the evidence
  records which policy ran. Schema-5 contracts prepend fixed short-code and
  short-prose C1 workloads with 512-token completions before the declared
  context matrix. Schema-6 expands both short domains to C1, C2, and C4.
  Schema-7 adds a dedicated 64K cold/warm TTFT pair that reloads one exact
  prompt with a one-token response budget.
- **Durable jobs** — Ctrl-C detaches, `letsinfer benchmark` reattaches to live
  progress, and an explicit stop safely restores prior inference.
- **Full-system evidence** — JSON records throughput, TTFT, prefix state,
  clocks, utilization, temperatures, memory, NVMe, power, network, and a
  telemetry timeline.
- **Cryptographic identity** — results bind the installation, hardware,
  runtime, model, Engine OCI, prompt set, and benchmark contract.
- **Fail-closed validation** — unsafe memory headroom, unsupported workloads,
  incomplete output, and unavailable required metrics invalidate the run.

## Run a benchmark

Use the CLI:

```bash
letsinfer benchmark qwen3.8-27b --c1
```

With no selectors, the runner executes exactly the contexts, concurrencies, and
domains declared by the installed runtime contract. Select a smaller supported
cross-product with flags such as `--32k`, `--64k`, `--c1`, or `--c4`.

The benchmark is a durable job:

```bash
letsinfer benchmark          # attach to live progress
letsinfer benchmark stop     # cancel and restore prior inference state
letsinfer benchmark clean    # remove local generated benchmark data
```

Ctrl-C detaches. It does not cancel the worker.

## Isolation

Schema-2 contracts give each measured cell a fresh Let's Infer-managed runtime
instance and empty prefix state. Schema-3 shared-matrix contracts launch one
fresh instance and store, run every declared cell once in deterministic order,
and intentionally retain prefix state between cells. That mode measures the
declared cache-aware progression and is a different benchmark identity; its
results are never compared as cold per-cell evidence. Schema-4 prefix-shared
contracts also place the immutable ledger before each stream-specific suffix
and run C1/C2/C4 together per context, making reuse directly measurable without
turning distinct requests into duplicates. Schema-5 keeps that policy and adds
one fixed short code C1 and one fixed short prose C1 before the long-context
cells. Their request settings are independently sealed in the contract and
prompt plan. Schema-6 runs those same fixed prompts at C1, C2, and C4 before
the long matrix. Schema-7 runs one unique 64K prompt twice after the long
matrix and requires the reload to report a larger prefix-cache hit. The resident Watchdog
stays active while the worker temporarily owns inference. On success, failure,
cancellation, or terminal disconnect, the worker restores the prior service
state.

The runner rejects runtime, model, Engine OCI, tokenizer, prompt, source,
container, cache, or sampling drift. It also rejects unsafe launch headroom and
workloads that exceed the runtime's declared envelope.

## Canonical prompts

[`prompts/PROTOCOL.md`](prompts/PROTOCOL.md) defines the model-neutral code and
prose templates and stream order. [`prompt_generator.py`](prompt_generator.py)
generates fixed bytes without consulting a tokenizer. The Engine adapter counts
the complete rendered request; it never resizes the prompt.

Generated prompts and plans live only in evidence. Do not copy them into a
runtime pack or substitute runtime-provided prompts.

## Public record

The worker writes a validated `benchmark.json`. Each result row includes:

- neutral `ppN,tgN,cN` workload;
- code or prose domain, prompt suite, and prompt-set SHA-256;
- actual rendered prompt tokens per stream;
- aggregate and decode throughput;
- TTFT and its statistic;
- prefix-cache state;
- utilization, clock, temperature, memory, NVMe, power, and network maxima;
- a fixed-schema Watchdog telemetry timeline; and
- immutable runtime, installation, contract, and result identities.

For C1, `decode_tps` is the single stream's decode rate. For concurrent cells,
it is the p50 stream rate; aggregate throughput remains the batch-wide rate.
The immutable private evidence retains every per-stream value and distribution.

Schema-5 `benchmark.json` records produced by schema-3 through schema-7 shared
contracts also
embed the complete declarative benchmark contract. Its canonical SHA-256 must
match `benchmark_contract_sha256`, so domains, cells, one-sample policy,
isolation, stream-prefix, and prefix-state semantics are directly inspectable
rather than represented only by a digest. Legacy cold-cell records remain
schema 4. A complete schema-7 run produces benchmark-record schema 6 and adds
a hash-bound `ttft_cache` section containing the exact prompt hash, cold and
warm TTFT, cold and warm cached-token counts, speedup ratio, and reduction
percentage.

Unavailable clocks are `-1`. Other unavailable optional telemetry is `null`.
Validate a record independently with:

```bash
python3 benchmarks/benchmark_record.py /path/to/benchmark.json
```

## Lower-level runners

`runtime_matrix.py` implements the public CLI matrix.
`openai_matrix.py`, `openai_load.py`, and `cache_replay.py` implement common
qualification gates. They consume the private installed
`runtime-execution.json` plus the authoritative runtime configuration supplied
by core. Runtime candidates do not invoke them directly or carry custom
benchmark commands.

Persistent-cache verification uses the runtime's declarative
`all-phases-exact` or `restored-repeat-exact` policy. Cache reuse must be
reported by the Engine adapter; timing alone is not evidence.

## Tests

```bash
python3 -m unittest discover -s tests/benchmarks -p 'test_*.py'
```
