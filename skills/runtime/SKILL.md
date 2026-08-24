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

If the candidate changes `engine/`, `adapter/`, `image/`, or any executable
Engine input, also read [the Engine-authoring skill](../engine-authoring/SKILL.md).
Use [the runtime-review skill](../runtime-review/SKILL.md) only for maintainer
review and `/shipit`; authors never need publication credentials.

Recover the exact prior setup before changing it: model and tokenizer revision,
Engine OCI, upstream engine version, image, arguments, environment, target,
context and capacity envelope, prompts, cache state, and measurement method.

## Create the flat candidate

Use:

```text
<engine>--<lowercase-hf-owner>--<lowercase-hf-model>--<target>/
```

The directory ID and `runtime.id` must match. Put `runtime.json` at its root.
Add a root `release.json` with schema version 2, a non-empty structured
`authors` array, the SPDX license, and `provenance: null`. Every author records
the visible GitHub login, immutable numeric GitHub ID, and actor type. Use
stable GitHub identities for upstream and Let's Infer
authors who materially contributed to the runtime; do not credit model authors
as runtime authors unless they also worked on the serving candidate.
You may add `adapter/`, `engine/`, `image/`, `kernels/`, `patches/`,
`scripts/`, `tests/`, provenance, and licenses as needed. Keep the complete
reviewable source and build recipe for any changed Engine in this same
candidate directory. Do not commit generated build output, container layers,
model weights, caches, or local evidence.

Do not add nested candidate hierarchies. Do not author a second
execution manifest. Do not copy core's CLI, gateway, Watchdog, benchmark
runners, prompts, site orchestration, or generic state plane.

## Pin the model

Declare the primary `hf://owner/repository` and exact 40-hex revision in
`model` and `artifacts`. Put the primary artifact first and sort additional
artifacts by name. For GGUF, pin the exact filename and SHA-256.

The runtime downloads every declared artifact. Do not require an operator to
preinstall weights or invent a runtime-specific model cache.

The first visible content in `README.md` must be this launch block, using the
runtime's exact `logical_model` value:

````markdown
> **Run this model with [Let's Infer](https://letsinfer.ai/).**
>
> Install Let's Infer first:
>
> ```sh
> curl -fsSL https://letsinfer.ai/install.sh | sh
> ```
>
> Then install this model:
>
> ```sh
> letsinfer install <logical-model>
> ```
````

When a README already exists, prepend the block and preserve all existing
content below it. In the runtimes repository, use
`python3 tools/readme_onboarding.py --candidate <candidate> --write`; do not
maintain a handwritten variant.

The README also links the primary model—and every additional
declared Hugging Face artifact—as
`https://huggingface.co/<owner>/<repository>`, derived directly from each
`hf://` URI. Put the primary model link near the top so you can inspect the
checkpoint without decoding `runtime.json`. Keep the exact revision, filename,
size, and checksum authority in `runtime.json`; a repository link never
replaces an immutable pin.

Add a `## Reproduce this` section with the exact `letsinfer benchmark
<logical-model>` command and selectors that produce a verifier's benchmark
record. Use the friendly logical model name, explain that Let's Infer
materializes the standard prompts and collects Watchdog telemetry, and never
claim selectors or rows that are absent from the sealed record. For an
unqualified candidate, label the command as the planned qualification run
rather than implying that evidence already exists.

Use complete-token `${artifact:name}` references for additional artifacts.
Core assigns no semantics to those names.

## Pin the Engine OCI

The Engine OCI contains one upstream engine version and the matching adapter.
Its adapter must implement Engine protocol 2. Pin both the OCI manifest digest
and image configuration digest.

Keep tokenizer logic, exact token counting, native cache integration,
normalized engine telemetry, parsers, upstream flags, engine patches, and
compiled kernels in the Engine OCI or candidate source—not core.

Put native upstream options in `engine.arguments` and non-protocol environment
in `engine.environment`. Never use a `LETSINFER_*` name. Core owns listeners,
model mounts, authentication, protocol endpoints, admission, and safety.

Changing the Engine OCI invalidates prior qualification.

Classify the Engine path before editing:

- **Reuse:** if no Engine executable input changes, keep the existing exact
  manifest and configuration digests. Engine source is not required in a new
  runtime merely because that runtime uses the Engine.
- **Changed or new Engine:** keep its source, adapter, image recipe, patches,
  tests, and license material in the candidate. Develop and validate locally,
  calculate its deterministic future production digest without publishing,
  and submit everything in the same runtime PR. Pull-request automation
  independently rebuilds the verifier Engine artifact; a differing pin yields
  a mechanical patch and blocks verification for that head. Do not publish an
  unofficial Engine OCI or split the work into a preliminary Engine PR.

## Define one measured recipe

Publish one recipe per candidate. Declare the target capability contract,
container bounds, maximum connections, active requests, context, cache
behavior, safety floor, and benchmark matrix that were measured together.

Never silently fall back to another checkpoint, quantization, engine, kernel,
attention backend, cache format, or recipe.

For a parallel target, set `target.placement.strategy` to `parallel`, declare
the exact `node_count`, GPUs per node, memory, and interconnect, then add a
schema-3 `orchestration` contract. Declare one generic `task-N` per node, one
endpoint owner, phased startup order, bounded ports, shell-free argv,
environment, and readiness. Do not put TP/PP ranks, collective names,
rendezvous schemes, or engine semantics in core-facing fields. Map task IDs to
all private roles, ranks, stages, transports, and engine flags inside the
runtime and Engine OCI. One-node parallel candidates can consume multiple
assigned GPU UUIDs through `task-0`.

## Validate and package

Use the repository-owned tools described by the runtimes repository and this
skill. Do not invent a parallel `letsinfer runtime ...` command family.

1. Generate or validate the canonical README launch block.
2. Validate runtime schema 5 and the generated root manifest.
3. Run `engine-adapter verify --protocol 2` in the exact Engine OCI.
4. Run every patch, kernel, model, and target-specific test.
5. Verify every external image and model reference is immutable and the
   candidate README contains every declared Hugging Face artifact link plus an
   exact reproduction command matching its qualification state and benchmark
   record.
6. Run `letsinfer pack` twice and require byte-identical archives.
7. Verify the OCI plan matches the exact candidate source digest.
8. Import the candidate without activation and verify model, engine, target,
   arguments, mounts, and receipts.
9. Launch an unqualified candidate only in qualification mode with new
   evidence.
10. For a parallel candidate, verify exact allocation, simultaneous task-phase
   startup, complete-group readiness, one endpoint, atomic failure/recovery,
   restart reconstruction, and replication of the complete group.

## Qualify

Run the standard code/prose benchmark through `letsinfer benchmark` without
changing core prompts or selecting favorable runs. Verify API, exact token
counting, telemetry, scheduler capacity, queuing, pressure, too-large requests,
crash/OOM protection, recovery, restart, reboot persistence, cache behavior,
and any declared target-specific gate.

Open the candidate PR without a generated consensus file or self-authored
provenance. After source and supply-chain review adds the `benchmark-ready`
gate, independent users run:

```bash
letsinfer benchmark verify <pull-request-url>
```

Two eligible users on distinct account and device identities qualify the exact
execution subject. A reviewer can occupy only one slot, even after rerunning.
Author and PR-author runs remain visible but do not count. A correctness,
safety, crash, OOM, incomplete-workload, or restoration failure blocks that
subject and cannot be replaced by a later success. Performance differences are
reported but never increase the verifier count. The trusted
bot owns `benchmark.consensus.json`, `release.json.provenance`, canonical
evidence comments, and the generated catalog projection. Never hand-author or
copy those fields, and never add a qualification/status flag to `runtime.json`.

## Publish

Opening or updating a finalized PR runs a no-code sentinel, a secretless
default-branch builder for the exact head, and a separate trusted
default-branch finalizer. Contributor changes cannot replace either trusted
workflow.
Reviewers run those artifacts through `letsinfer benchmark verify`, which never
downloads or repacks the proposal source.
After qualification, an authorized maintainer comments `/shipit`. Trusted
automation promotes the exact verified Engine OCI when the Engine changed,
reuses an existing Engine OCI when it did not, and always publishes the exact
verified runtime OCI. It anonymously verifies both public objects and merges
only the reviewed head. The later protected release lane verifies—not
republishes—those objects, then signs the append-only schema-6 catalog and
separate revocation ledger. Community verification evidence is not
copied to OCI; full accepted records remain in canonical bot comments and
`benchmark.consensus.json`.

For a brand-new candidate, plan its runtime OCI in the pre-provisioned public
`ghcr.io/letsinferlabs/runtime-artifacts` package. Existing candidates retain
their current public package. New Engine builds use
`ghcr.io/letsinferlabs/engine-images`. All references remain digest-pinned;
authors never create packages, set visibility, or receive registry credentials.

Do not manually edit the root `manifest.json` or production catalog, publish
official OCI objects, or merge the PR yourself unless you are following the
maintainer-only runtime-review workflow.
