# Runtime candidates

[Back to documentation](../README.md)

A runtime candidate is the complete, reproducible way to run one exact model
artifact with one exact Engine OCI on one hardware target. You can change
model revisions, quantizations, engine arguments, kernels, patches, cache
configuration, and capacity limits inside a runtime without changing core.

## What you install

When you run:

```bash
letsinfer install qwen3.8-27b
```

Let's Infer:

1. detects your hardware target;
2. verifies the signed catalog;
3. selects the recommended qualified candidate;
4. downloads the immutable runtime pack;
5. downloads every model artifact declared by that runtime;
6. pulls the digest-pinned Engine OCI;
7. verifies all identities and compatibility; and
8. starts the runtime behind your node's OpenAI-compatible gateway.

You may select an exact candidate with `--runtime`. You never need to supply an
engine name or a `targets/...` path.

## Candidate source

Each candidate is one top-level directory in the runtimes repository:

```text
<engine>--<hf-owner>--<hf-model>--<target>/
```

This flat identity keeps checkpoint authors and quantizations distinct:

```text
sglang--qwen--qwen3.8-27b--dgx-spark
sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark
sglang--unsloth--qwen3.8-27b-nvfp4--dgx-spark
```

All three can serve the same model name. Qualification determines which one
the catalog recommends for your target.

The candidate directory contains `runtime.json`, `release.json`, and its
README. `release.json` records a non-empty array of runtime authors plus the
SPDX license. Those values are versioned in the signed catalog and shown by
`letsinfer list`. The directory may also contain `engine/`, `adapter/`, `image/`,
`kernels/`, `patches/`, `scripts/`, and `tests/` beside `runtime.json`.
Keep only the candidate's implementation closure there. Shared gateway,
Watchdog, benchmark, prompt, and node-orchestration code stays in core.

## Engine independence

The Engine OCI combines an upstream engine version and the adapter for that
version. The runtime pins the OCI by digest and supplies opaque native
arguments. Core speaks only Engine protocol v2.

You need a new Engine OCI when the upstream engine or its adapter changes. You
need a core change only when the stable Let's Infer Engine protocol itself
changes.

A radical runtime does not wait on a preliminary Engine publication PR. It
keeps the complete changed or new Engine implementation in the runtime
candidate, builds locally without registry writes, and submits the whole
reviewable source closure in one PR. A no-code PR sentinel triggers a
secretless default-branch builder, and a separate trusted default-branch
finalizer gives verifiers the exact Engine and runtime bytes without executing
proposal code.
`letsinfer benchmark verify` downloads that head-bound artifact, not the PR
source tree. A runtime that does not change Engine inputs
simply reuses the existing immutable Engine pin and publishes no duplicate
Engine object.

## Parallel candidates

Parallelism stays inside an exact runtime. The target declares its required
node count, GPUs per node, memory, and verified interconnect. Its optional
orchestration contract declares generic node tasks, startup phases, readiness,
and one endpoint owner. Core allocates authenticated resources and manages the
group atomically; the Engine OCI privately turns those tasks into ranks,
pipeline stages, collectives, and engine commands.

This keeps power with runtime authors: a new TP degree, PP schedule, GPU count,
transport, kernel, or engine configuration is a new runtime candidate, not a
core feature. Core changes only when a genuinely new generic resource or
secure orchestration primitive is required. The gateway routes complete group
endpoints and can replicate a complete parallel group without rewriting it.

## Qualification and recommendations

A candidate becomes qualified only after the exact model revision, Engine OCI,
runtime bytes, target contract, recipe, safety envelope, and benchmark record
pass their declared gates. Evidence does not transfer across a changed Engine
OCI, model revision, or runtime pack.

The generated root `manifest.json` is an append-only versioned release index.
It retains every published candidate version, authors, license, immutable
runtime OCI, optional benchmark score, structured verifier list, and consensus digest.
Complete accepted evidence remains in canonical bot comments and the generated
`benchmark.consensus.json`; it is not duplicated into an evidence OCI. Release
automation selects one qualified recommendation for each logical model and
target, signs the exact projection and separate revocation ledger, and
publishes them together from the runtimes repository.

Discover compatible releases before installing:

```bash
letsinfer list
letsinfer list qwen3.8-27b --versions
```

Catalog changes do not silently alter a running installation:

- `letsinfer update` updates core only;
- `letsinfer upgrade MODEL` explicitly updates the installed runtime;
- `letsinfer rollback MODEL` reinstalls its retained previous runtime.

## Storage

Installed packs are content-addressed below
`$LETSINFER_HOME/runtimes/objects/`. Model snapshots live below
`$LETSINFER_HOME/models/<owner>--<repository>/<revision>/`. OCI download state
lives below `$LETSINFER_HOME/oci/`, while the container runtime retains its
native content store. The last verified signed catalog lives below
`$LETSINFER_HOME/state/catalog/` and is shared by list, install, upgrade, and
update checks.

Receipts bind the candidate ID, version, pack digest, target contract, model,
Engine OCI, installation identity, and selection policy. A bounded history
supports explicit rollback.

## Building a candidate

Validate and package your source with:

```bash
python3 tools/generate_manifest.py --validate-only
python3 tools/readme_onboarding.py --candidate <candidate> --write
letsinfer pack <candidate-directory> --output /tmp/runtime.letsinfer
```

Pack the same source twice and require byte-identical output. After engine,
safety, restart, pressure, crash, and API review, wait for the PR's
`benchmark-ready` gate. Independent users then run:

```bash
letsinfer benchmark verify <runtime-pr-url>
```

Two eligible independent reviewers must pass the exact PR artifact. One
reviewer always occupies one slot, and a blocking failure is terminal for that
subject; performance variance does not change quorum. The verification bot
owns `benchmark.consensus.json`, qualification provenance, and the catalog
projection. An authorized maintainer then uses `/shipit` to promote the exact
reviewed Engine and runtime objects, anonymously reverify both, and merge the
checked head. Runtime source cannot mark itself qualified. A post-release
invalidation enters the separate signed revocation ledger; it does not rewrite
the immutable release or add a status field to the manifest.
