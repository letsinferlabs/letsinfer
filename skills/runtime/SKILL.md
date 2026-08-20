---
name: runtime
description: Create, port, fork, or update a production Let's Infer runtime pack for a specific model, inference engine, and hardware target. Use for runtime repositories, runtime.json or release.json manifests, engine patches, kernels, image recipes, target compatibility, deterministic packaging, or runtime qualification work.
---

# Create a Let's Infer runtime

Build one immutable `model/engine/target` implementation without moving engine-specific behavior into Let's Infer core.

## Establish the contract

1. Read `documentation/concepts/runtime-packs.md`,
   `documentation/reference/runtime-format.md`, the closest release and runtime
   target, and any local repository policy supplied by the runtime author.
2. Read [`../benchmark/SKILL.md`](../benchmark/SKILL.md) in full before creating fixtures, measuring performance, or claiming qualification.
3. Recover the exact prior production setup and best comparable evidence. Record model revision, tokenizer/chat template, engine revision, image, command, environment, cache format, context envelope, hardware, prompts, and measurement method. Do not compare unmatched workloads.
4. Define the stable target by capabilities: platform, accelerator architecture/count/partitioning, memory topology, and minimum capacity. Do not key compatibility to hostname.

## Build the target source

Use `runtimes/<model>/<engine>/targets/<target>/` when several targets share a development repository. The target root must contain `runtime.json`, its declared release manifest, and the public `benchmark.json` once results are sealed.

Keep only the implementation closure there:

- exact model and tokenizer revisions;
- exact engine source, target-specific patches, plugins, or kernels;
- build-time verifiers for every patch;
- `image/Dockerfile` and arbitrary sibling inputs when custom packages or engine changes are needed;
- concise provenance and license metadata.

Do not vendor Let's Infer's CLI, Watchdog, gateway, benchmark runners, prompts,
plans, evidence, or engine-neutral prefix store. Declare the standard suite,
cases, request settings, and tokenizer/render identity under
`runtime.json.benchmark`; never add runtime-provided benchmark commands. Keep
only small engine-native shims needed to implement Let's Infer's versioned cache or
exact rendered-chat token-count capability. Keep the validated public result
record at the standalone runtime target root as `benchmark.json`.

Run the complete standard code/prose matrix through `letsinfer benchmark`.
Never modify or replace core's canonical prompt bytes for a runtime. Confirm
that every result contains `prompt_domain`, `prompt_suite`,
`prompt_set_sha256`, and one `actual_prompt_tokens` entry per stream, then run
`python3 benchmarks/benchmark_record.py <runtime-root>/benchmark.json` before
sealing or publishing it.

Pin every external image by digest. Build containers offline at runtime, read-only, non-root where the engine allows it, and without package installation after launch. Runtime authors may name build-input directories freely; only `image/Dockerfile` is special. The final manifest must pin the exact resulting image digest or immutable local image ID.

Declare every required artifact so `letsinfer install` can resolve a qualified
runtime completely. Models belong in the shared Hugging Face blob/snapshot
cache, runtime packs in Let's Infer's immutable object store, OCI layers in
Docker's content store, and language/system/CUDA packages inside the immutable
image. Do not create a runtime-specific download cache or install packages into
the host. Exact identities provide cross-runtime deduplication; missing
dependencies download by default and `--no-download` makes their absence an
error.

Use the closed named-artifact contract: `model.artifact` selects the primary
served model, while top-level `artifacts` lists the primary first and every
additional exact dependency in deterministic name order. Give each dependency
a runtime-defined portable name and immutable Hugging Face revision; GGUF
entries also pin the contained filename and SHA-256. Bind non-primary artifacts
to native engine options only with whole-token `${artifact:name}` values in
`engine.arguments`. Do not add semantic fields such as `drafter` to `model` or
teach core what an artifact role means.

Scrub nested Git metadata, credentials, private prompts, machine paths, generated evidence, weights, caches, and unrelated upstream documentation. Preserve all source and licenses necessary to modify and rebuild the customized engine.

## Define one production recipe

Expose one qualified recipe per manifest, not selectable profiles. Declare the maximum context, accepted connections, active requests, scheduler capacity, cache limits, admission floors, and safety envelope actually measured together.

Let Let's Infer's adapter own model paths, listeners, TLS, authentication, and mandatory safety arguments. Put model/target-specific engine settings in the runtime manifest or engine source. A user who only changes upstream flags should use `letsinfer derive`; a user changing packages, kernels, engine code, plugins, or cache ABI should fork the runtime.

Put native upstream options in the release manifest's flat
`engine.arguments` array. Let's Infer replaces matching non-protected options
and appends unknown options without owning their schema. Put non-core engine
variables in `engine.environment`; never encode model parsers, chat defaults,
generation policy, speculative configuration, or performance tuning in core.

Never silently fall back to another model, engine, image, kernel, quantization, attention backend, cache format, or recipe.

## Verify and package

1. Run source-only manifest verification and every patch/build verifier.
2. Build the image twice under the exact Let's Infer `SOURCE_DATE_EPOCH=0` contract and require identical final image IDs and important binary hashes.
3. Run `letsinfer pack` twice and require identical descriptor and archive SHA-256 values.
4. If `benchmark.json` is present, run `python3 benchmarks/benchmark_record.py <runtime-root>/benchmark.json`; packaging must independently validate it.
5. Import the candidate without activation. Verify descriptor, source revision, image identity, target compatibility, resolved argv, protected arguments, and privacy/license scans.
6. Start only through explicit qualification mode with a new evidence directory. Keep Watchdog and all admission gates active.

## Qualify and promote

Follow [`../benchmark/SKILL.md`](../benchmark/SKILL.md) completely. The final
single recipe must pass historical performance parity, the official prompt
suite, cold/hot/restart cache proof, connection capacity, pressure, crash/OOM,
reboot persistence, and every additional gate explicitly declared by the
release. Do not invent a soak requirement when the release contract does not
have one. A comparable row passes only when throughput matches or beats the
best accepted prior result and TTFT matches or beats it. Treat measurement
noise honestly; do not lower gates, change prompts, or select favorable runs.

Write the structured public results to the standalone runtime target's
`benchmark.json`, validate it, and keep the immutable evidence identity and
complete audit in Let's Infer's durable technical record. Mark the release qualified only after
every declared gate passes on the exact source, artifact, image, model
revision, target, command, and cache format. Publishing additionally requires
a pullable registry digest; local image identity is not a public release.
