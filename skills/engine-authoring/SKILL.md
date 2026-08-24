---
name: engine-authoring
description: Develop or review a changed or entirely new inference Engine inside a Let's Infer runtime candidate, including its adapter, deterministic OCI recipe, protocol telemetry, tests, and PR verifier artifact. Do not use when a runtime only reuses an unchanged Engine OCI.
---

# Author a Let's Infer Engine

Use this skill only when the proposal changes an Engine executable input or
introduces an Engine Let's Infer does not yet support. Keep the work inside the
runtime candidate; a preliminary Engine publication PR is not required.

## Preserve the boundary

Read:

1. `documentation/concepts/engine-adapters.md`;
2. `documentation/reference/runtime-format.md`; and
3. [the runtime skill](../runtime/SKILL.md).

Core remains engine- and model-agnostic. A new Engine does not need a core
change while Engine protocol 2 can express its inference, health, exact token
counting, telemetry, and lifecycle behavior. Propose a protocol change only
for a genuinely cross-engine capability, never for one upstream flag or
metric.

## Keep one reviewable source closure

Place the complete Engine source or immutable source acquisition, matching
adapter, digest-pinned base image, deterministic image recipe, patches,
plugins, kernels, tests, inventory/SBOM inputs, licenses, and notices in the
candidate directory. Pin every remote input by digest or cryptographic hash.

Do not commit model weights, generated binaries, container layers, caches,
credentials, local benchmark evidence, or other build output. Do not require
authors to log in to the production registry.

## Implement protocol 2

The image exposes `/opt/letsinfer/bin/engine-adapter` and provides:

- OpenAI-compatible inference;
- `/health` and `/v1/models`;
- `/v1/letsinfer/token-count` with exact engine-rendered chat counting; and
- `/v1/letsinfer/telemetry` with normalized request, queue, token, context,
  prefix-cache, and KV-cache state.

The adapter is the telemetry hook into radical Engine internals. Translate
native counters and state into the protocol; do not add engine-specific probes,
flags, ranks, or metric schemas to core. Report unavailable optional metrics as
unavailable, never zero.

Protect core-owned listeners, mounts, authentication, safety, and protocol
values from runtime overrides. Keep upstream flags and non-protocol environment
inside the runtime and adapter.

## Iterate without cloud publication

Use the runtimes repository's versioned validation, Engine build, SBOM, pin,
OCI-plan, and packing tools. Produce local images or OCI layouts outside Git,
run `engine-adapter verify --protocol 2`, exercise target-specific tests, and
launch only in explicit development or qualification mode. Repack unchanged
source twice and require identical bytes.

Calculate and place the deterministic future production Engine manifest and
configuration digests in `runtime.json` before requesting human verification.
This calculation needs no registry access. Trusted CI independently rebuilds
the recipe; if the pins differ it uploads an `engine-pin-pr-*` patch and does
not create a benchmarkable artifact for that head.

Do not invent a `letsinfer runtime ...` command family. `letsinfer pack`, local
qualification, and the repository tools are the supported building blocks.

## Submit and qualify

Submit the Engine and runtime together in one candidate PR. A no-code PR
sentinel triggers a read-only, secretless default-branch builder for the exact
head; contributor changes cannot replace that build workflow. A second
default-branch `workflow_run` finalizer re-audits and repacks the raw outputs
without executing proposal code. The final
verifier bundle binds the PR head, complete source,
Engine manifest and configuration digests, runtime pack and planned OCI digest,
model revisions, target, benchmark contract, SBOM, and build provenance.

Reviewers run the exact bundle through `letsinfer benchmark verify`; the command
does not download or pack PR source. After two eligible independent passes, an
authorized maintainer uses `/shipit` to promote
the exact verified Engine and runtime objects. Any changed byte creates a new
subject and requires fresh verification.

Use the pre-provisioned public
`ghcr.io/letsinferlabs/engine-images` repository for every new Engine build.
Multiple manifests share that package safely because `runtime.json`, the
verifier subject, and publication all bind the exact manifest and configuration
digests. Never create or change a GHCR package's visibility from contributor
automation.
