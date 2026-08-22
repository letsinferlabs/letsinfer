---
name: runtime
description: Create, port, optimize, qualify, or publish a Let's Infer runtime candidate with runtime.json, exact model artifacts, a digest-pinned Engine OCI, target-specific kernels or patches, and benchmark evidence.
---

# Build a Let's Infer runtime

Create one immutable candidate without moving model- or engine-specific
behavior into core.

## Read the contracts

Read:

1. `documentation/reference/runtime-format.md`;
2. `documentation/concepts/runtime-packs.md`;
3. `documentation/concepts/engine-adapters.md`; and
4. [the benchmark skill](../benchmark/SKILL.md) before measuring or claiming
   qualification.

Recover the exact prior setup before changing it: model and tokenizer revision,
Engine OCI, upstream engine version, image, arguments, environment, target,
context and capacity envelope, prompts, cache state, and measurement method.

## Create the flat candidate

Use:

```text
<engine>--<lowercase-hf-owner>--<lowercase-hf-model>--<target>/
```

The directory ID and `runtime.id` must match. Put `runtime.json` at its root.
You may add `adapter/`, `engine/`, `image/`, `kernels/`, `patches/`,
`scripts/`, `tests/`, provenance, and licenses as needed.

Do not add nested candidate hierarchies. Do not author a second
execution manifest. Do not copy core's CLI, gateway, Watchdog, benchmark
runners, prompts, site orchestration, or generic state plane.

## Pin the model

Declare the primary `hf://owner/repository` and exact 40-hex revision in
`model` and `artifacts`. Put the primary artifact first and sort additional
artifacts by name. For GGUF, pin the exact filename and SHA-256.

The runtime downloads every declared artifact. Do not require an operator to
preinstall weights or invent a runtime-specific model cache.

Create a root `README.md` that links the primary model—and every additional
declared Hugging Face artifact—as
`https://huggingface.co/<owner>/<repository>`, derived directly from each
`hf://` URI. Put the primary model link near the top so you can inspect the
checkpoint without decoding `runtime.json`. Keep the exact revision, filename,
size, and checksum authority in `runtime.json`; a repository link never
replaces an immutable pin.

Use complete-token `${artifact:name}` references for additional artifacts.
Core assigns no semantics to those names.

## Pin the Engine OCI

The Engine OCI contains one upstream engine version and the matching adapter.
Its adapter must implement Engine protocol 1. Pin both the OCI manifest digest
and image configuration digest.

Keep tokenizer logic, exact token counting, native cache integration,
normalized engine telemetry, parsers, upstream flags, engine patches, and
compiled kernels in the Engine OCI or candidate source—not core.

Put native upstream options in `engine.arguments` and non-protocol environment
in `engine.environment`. Never use a `LETSINFER_*` name. Core owns listeners,
model mounts, authentication, protocol endpoints, admission, and safety.

Changing the Engine OCI invalidates prior qualification.

## Define one measured recipe

Publish one recipe per candidate. Declare the target capability contract,
container bounds, maximum connections, active requests, context, cache
behavior, safety floor, and benchmark matrix that were measured together.

Never silently fall back to another checkpoint, quantization, engine, kernel,
attention backend, cache format, or recipe.

## Validate and package

1. Validate runtime schema 3 and the generated root manifest.
2. Run `engine-adapter verify --protocol 1` in the exact Engine OCI.
3. Run every patch, kernel, model, and target-specific test.
4. Verify every external image and model reference is immutable and every
   declared Hugging Face artifact has the matching repository link in the
   candidate README.
5. Run `letsinfer pack` twice and require byte-identical archives.
6. Verify the OCI plan matches the exact candidate source digest.
7. Import the candidate without activation and verify model, engine, target,
   arguments, mounts, and receipts.
8. Launch an unqualified candidate only in qualification mode with new
   evidence.

## Qualify

Run the standard code/prose benchmark through `letsinfer benchmark` without
changing core prompts or selecting favorable runs. Verify API, exact token
counting, telemetry, scheduler capacity, queuing, pressure, too-large requests,
crash/OOM protection, recovery, restart, reboot persistence, cache behavior,
and any declared target-specific gate.

Store the validated public results in `benchmark.json` and bind its path,
SHA-256, and ID in `runtime.json`. Mark the candidate qualified only when every
gate passes on the exact model, Engine OCI, runtime bytes, target, and recipe.

## Publish

Engine or adapter changes first publish a new immutable Engine OCI and update
the candidate pin, which resets qualification. After qualification, release
automation publishes the deterministic runtime OCI, regenerates schema-4
recommendations, signs the catalog, and verifies the public trust root.

Do not manually edit the root `manifest.json` or production catalog.
