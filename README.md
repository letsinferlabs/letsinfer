# Let's Infer

Let's Infer installs and serves the best qualified local inference runtime for
your model and hardware. You choose the model you want to run:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
letsinfer install qwen3.8-27b
```

Let's Infer detects the target, verifies the signed catalog, selects the
recommended qualified runtime, downloads its exact model revision and Engine
OCI, installs the runtime pack, and exposes one OpenAI-compatible API. You do
not need to select an engine, find model files, or write a hardware-specific path.

## Architecture

Let's Infer has four independently versioned parts:

- **Core** provides the CLI, site state, target detection, admission, gateway,
  Watchdog, benchmark orchestration, OCI verification, and update state. It
  contains no model or upstream-engine implementation.
- An **Engine OCI** contains one upstream engine version and its matching
  adapter. The adapter implements Let's Infer Engine protocol v1 for launch,
  health, exact token counting, normalized telemetry, and inference.
- A **runtime pack** binds one logical model to exact Hugging Face revisions,
  one digest-pinned Engine OCI, one hardware target, engine arguments, kernels,
  patches, capacity limits, safety policy, and benchmark evidence.
- The signed **catalog** maps a logical model and detected target to the best
  qualified runtime candidate.

Engine and adapter ship together because their internal APIs change together.
Core knows only the stable Engine protocol. A new engine version therefore does
not require a core release unless the protocol itself changes.

## Runtime identity

Runtime sources are flat directories in the public runtimes repository:

```text
<engine>--<hf-owner>--<hf-model>--<target>/
├── runtime.json
├── adapter/
├── engine/
├── image/
├── kernels/
├── patches/
├── scripts/
├── tests/
└── benchmark.json
```

Only `runtime.json` is mandatory. A candidate may include any model- or
target-specific implementation needed to reproduce it. The runtime declares
the model URI and immutable revision, so installation downloads the model
automatically. Multiple quantizations or independently optimized checkpoints
are separate candidates, for example:

```text
sglang--qwen--qwen3.8-27b--dgx-spark/
sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark/
sglang--unsloth--qwen3.8-27b-nvfp4--dgx-spark/
```

The generated runtimes `manifest.json` contains all candidates and the
qualified recommendation for each model/target. Production clients consume
the separately published, signed catalog rather than trusting the source repo.

## Commands

```bash
letsinfer setup
letsinfer hardware
letsinfer install qwen3.8-27b
letsinfer install qwen3.8-27b --runtime <exact-candidate-id>
letsinfer status
letsinfer benchmark qwen3.8-27b --c1
letsinfer update check
letsinfer update
letsinfer upgrade qwen3.8-27b
letsinfer verify qwen3.8-27b
letsinfer doctor
```

`--runtime` is an exact advanced pin. There is no user-facing engine selector.
Changing an engine, model source, quantization, kernel, patch, or recipe creates
a new immutable runtime candidate and requires fresh qualification.

`letsinfer update` changes core only. `letsinfer upgrade` changes the selected
runtime only. Neither operation silently changes the other component.

## Local data

All durable and rebuildable data lives below one user-owned directory:

```text
$LETSINFER_HOME/
├── core/
│   ├── current
│   └── versions/
├── config/
├── secrets/
├── models/
│   └── <hf-owner>--<hf-model>/<revision>/
├── runtimes/
├── oci/
├── state/
├── benchmarks/
├── logs/
└── cache/
```

The default is `~/.local/share/letsinfer`. `LETSINFER_HOME` must be an absolute
path you own and cannot be `/` or your home directory itself. Equal
Hugging Face revisions and OCI content deduplicate across runtimes.

`letsinfer uninstall` asks for confirmation and removes the managed home.
`letsinfer uninstall --keep-models` preserves only the model store.

## Site and API

`letsinfer setup` creates a logical site. The first machine is its coordinator
and owns the API-key registry, audit chain, scheduling, and stable gateway.
Members can provide independent runtimes, replicas, or roles in a
runtime-qualified distributed placement. Clients still use one local endpoint:

```text
http://<coordinator>.local:8000/v1
```

The gateway requires a scoped API key, queues admission when a runtime is under
pressure, and returns a structured request error when a request can never fit.
Watchdog remains independent of the engine and supplies normalized safety and
telemetry state to the CLI and other consumers.

## Security and reproducibility

- Remote catalogs require an exact-byte Ed25519 signature before parsing.
- Engine and runtime OCI references are immutable registry digests.
- Model artifacts use exact 40-hex Hugging Face revisions; GGUF files also pin
  their file SHA-256.
- Runtime packs are deterministic archives whose descriptor hashes every file,
  byte length, mode, and path.
- Runtime containers use read-only model mounts and are isolated from core
  secrets.
- Qualification is bound to the exact model, Engine OCI, runtime pack, target,
  recipe, benchmark contract, and result record.
- Core never silently falls back to another engine, checkpoint, quantization,
  kernel, cache format, or recipe.

## Development

Public architecture and command references live in [documentation](documentation/README.md).
If you are building a runtime, read [the runtime skill](skills/runtime/SKILL.md)
and [benchmark skill](skills/benchmark/SKILL.md).

Run the core suite with:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Let's Infer is licensed under AGPL-3.0-only.
