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

## Qualification and recommendations

A candidate becomes qualified only after the exact model revision, Engine OCI,
runtime bytes, target contract, recipe, safety envelope, and benchmark record
pass their declared gates. Evidence does not transfer across a changed Engine
OCI, model revision, or runtime pack.

The generated root `manifest.json` is an append-only versioned release index.
It retains every qualified candidate version, authors, license, immutable
runtime OCI, benchmark summary, and full benchmark-evidence OCI reference.
Release automation selects one qualified recommendation for each logical model
and target, signs the exact projection, and publishes it directly as the latest
release of the runtimes repository.

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
letsinfer pack <candidate-directory> --output /tmp/runtime.letsinfer
```

Pack the same source twice and require byte-identical output. After engine
protocol, safety, restart, pressure, crash, API, and benchmark gates pass,
commit the exact `benchmark.json` and mark the candidate qualified.
