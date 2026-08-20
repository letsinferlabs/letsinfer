# Benchmark and qualification runners

Let's Infer owns the engine-neutral benchmark transport, workload generator,
isolation, safety, and evidence contracts. A runtime declares only its
versioned benchmark configuration in `runtime.json`; it does not ship prompt
files, plans, or benchmark code.

## Runners

### `openai_matrix.py`

The common OpenAI-v1 gate works with any registered engine adapter.
It verifies the release and container identity, authenticated TLS endpoint,
model identity, prompt hashes and observed token counts, concurrent request
behavior, output requirements, container health, restarts, OOM state, host and
GPU telemetry, and the measured source identity.

It writes immutable request evidence, `results.json`, `results.sha256`, and a
short `bench-block.md`. It rejects HTTP endpoints, dirty or unidentified
source, unpinned prompts, token drift, unhealthy or replaced containers, and
an existing evidence directory.

The lower-level runner still accepts an explicit fixture manifest for
benchmark development and specialized qualification gates. Those inputs are
evidence-bound development inputs, not runtime-pack contents.

```bash
python3 benchmarks/openai_matrix.py \
  --release-manifest /path/to/runtime/release.json \
  --fixture-manifest /path/to/runtime/fixtures.json \
  --output-directory ~/.cache/letsinfer/results/<run-id> \
  --api-key-file ~/.config/letsinfer/api-key \
  --ca-cert-file ~/.config/letsinfer/tls/server.crt \
  --container letsinfer-<engine> \
  --measured-commit <full-commit>
```

### `runtime_matrix.py`

The public `letsinfer benchmark` command uses this runner to execute a runtime
pack's declared standard matrix without exposing engine flags:

```bash
letsinfer benchmark MODEL --c1 --c2 --c4 --c8
```

The CLI starts one durable benchmark worker per node and attaches to its live
phase, workload, elapsed time, and expected duration. Ctrl-C only detaches;
`letsinfer benchmark` reconnects to status and `letsinfer benchmark stop`
explicitly cancels the worker. The worker retains exclusive ownership of its
temporary container and service restoration, including after the launching
terminal exits.

With no selectors, the current standard contract runs the complete
32K/64K/128K/256K by C1/C2/C4/C8/C16 cross-product for both code and prose.
The versioned core generator owns fixed model-neutral bytes and stream order;
the registered adapter counts each complete rendered request without resizing
it. Generated prompts and the derived plan live under the new evidence
directory.

Every measured cell receives a fresh Let's Infer-managed container and empty
prefix store. The runner rejects cache reuse, identity drift, tokenizer/model/
image mismatch, invalid prompt counts, unsafe post-load headroom, and any
mismatch between a CLI sampling override and the declared contract.

On a service host, the worker temporarily stops the recovery timer and active
engine unit before inference. The resident Watchdog stays active. Let's Infer
restores the exact prior engine and timer state after success, failure, or
explicit cancellation. When an active qualification candidate owned the
inference slot, the worker instead rearms the final isolated candidate before
it exits. A host that had no active inference returns to that state. Operators
therefore do not manually stop or restart inference around a benchmark.

An installed hash-addressed control bundle is a verified source identity. A
developer checkout must be clean and match the measured commit, or provide a
source attestation copied from the exact clean checkpoint.

The command writes a validated `benchmark.json` beside the complete evidence.
Each flat row reports the neutral workload, code/prose domain, suite and
prompt-set identities, per-stream actual prompt counts, aggregate/decode throughput, TTFT,
whether any prompt prefix was cached, maximum GPU/CPU utilization and
temperature, CPU/GPU/VRAM/system-RAM clocks, NVMe temperature, root-storage
usage, NVMe read/write throughput and their maxima, and a compact fixed-schema
timeline from Watchdog's independent one-second ring. An unavailable clock or
NVMe metric is `-1`. Root-storage usage is capacity consumed, not I/O busy
time. Its cryptographic ID binds the runtime installation, benchmark
contract, timestamp, and complete results/timeline digest. Validate a retained
or merged record independently with:

```bash
python3 benchmarks/benchmark_record.py /path/to/benchmark.json
```

### `openai_load.py` and `cache_replay.py`

`openai_load.py` runs crash-safe, resumable single- and concurrent-stream
waves. The reusable plans in [`load-plans/`](load-plans/) define short load and
soak shapes; a runtime supplies the exact prompts and cells. Every wave and
attempt is written atomically and hashed before state advances. Resume is
accepted only for the same release, source, plan, container lifecycle,
endpoint, command, and runner.

The runner retains raw SSE output and OpenAI usage together with TTFT,
latency, decode and aggregate throughput, cache counters, host memory/swap,
CPU, thermals, NVIDIA state, NVMe counters, Docker state, and Watchdog state.

`cache_replay.py` compares a completed cold/hot population run with a
completed post-restart run. It requires a changed container lifecycle and an
unchanged source, release, image, fixture, and command identity. Cache reuse
must be reported by the engine; timing alone is not evidence. A persistent
runtime declaratively chooses `all-phases-exact` or
`restored-repeat-exact` as its output policy. The generic runner contains no
engine/provider branches or executable runtime hooks.

```bash
python3 benchmarks/openai_load.py \
  --release-manifest /path/to/runtime/release.json \
  --plan benchmarks/load-plans/<plan>.json \
  --fixture-manifest /path/to/runtime/fixtures.json \
  --output-directory ~/.cache/letsinfer/results/<run-id> \
  --api-key-file ~/.config/letsinfer/api-key \
  --ca-cert-file ~/.config/letsinfer/tls/server.crt \
  --container letsinfer-<engine> \
  --measured-commit <full-commit>
```

## Standard prompt generation

[`prompts/PROTOCOL.md`](prompts/PROTOCOL.md) defines the standard model-neutral
code/prose templates and stream ordering. [`prompt_generator.py`](prompt_generator.py)
deterministically creates fixed bytes without consulting a tokenizer. The
runtime's exact tokenizer capability only records rendered counts; a request
that does not fit fails closed instead of being resized.

The runtime contract pins the suite and generator versions, model and engine
image identities, rendered-chat contract, request settings, cases, and
concurrencies. Evidence pins the runtime contract, generator source,
templates, generated prompt set, derived plan, and exact tokenizer identity.
Materialized prompts are evidence—not source, runtime-pack content, or reusable
inputs for another runtime identity.

## Tests

Runner unit tests live under the repository's test tree and load these scripts
without installing a Python package:

```bash
python3 -m unittest discover -s tests/benchmarks -p 'test_*.py'
```

The root [`tests/fixtures/`](../tests/fixtures/) tree contains only small,
synthetic inputs for core contract tests. It is not searched by runtime
discovery or included in production packs.
