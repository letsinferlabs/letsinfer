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
- **Real isolation** — every cell gets a fresh process and empty prefix state;
  the runner rejects identity, configuration, prompt, cache, or sampling drift.
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

With no selectors, the standard contract runs 32K, 64K, 128K, and 256K at C1,
C2, C4, C8, and C16 for both code and prose. Select only the cells you need
with flags such as `--32k`, `--64k`, `--c1`, or `--c8`.

The benchmark is a durable job:

```bash
letsinfer benchmark          # attach to live progress
letsinfer benchmark stop     # cancel and restore prior inference state
letsinfer benchmark clean    # remove local generated benchmark data
```

Ctrl-C detaches. It does not cancel the worker.

## Isolation

Each measured cell gets a fresh Let's Infer-managed runtime instance and empty
prefix state. The resident Watchdog stays active while the worker temporarily
owns inference. On success, failure, cancellation, or terminal disconnect, the
worker restores the exact prior service state.

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
