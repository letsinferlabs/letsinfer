# Runtime format

[Back to documentation](../README.md)

A runtime source repository contains `runtime.json`, its release manifest, and
any model/engine-specific source needed to reproduce the runtime image. A
sealed runtime also contains its machine-readable public `benchmark.json`.

Package the smallest complete target implementation. Do not copy Let's Infer's
benchmark framework, Watchdog, gateways, operational scripts, or
engine-neutral cache/store into a runtime repository. Those are supplied and
versioned by Let's Infer core. A target may include only the thin engine-specific
adapter needed to expose native state through Let's Infer's cache ABI.

```json
{
  "schema_version": 2,
  "name": "example-model/vllm/dgx-spark",
  "version": "0.2.0",
  "model": "example-model",
  "engine": "vllm",
  "target": "dgx-spark",
  "status": "candidate",
  "release_manifest": "release.json",
  "core_compatibility": {"api": 2}
}
```

`name` must equal `model/engine/target`. Versions use semantic-version syntax.
Paths must be relative and contained; source symlinks are rejected. Let's Infer
accepts only schema 2 runtime sources and three-part runtime identities. The
source object accepts only the fields shown above plus `benchmark`,
`orchestration`, and the exact `parent` identity on a CLI-created derivation;
unknown metadata is rejected. Engine provenance belongs in immutable packed
files and the digest-pinned image, not in core-interpreted extension fields.
Compatibility API 2 is the named multi-artifact release contract; API 1
runtimes are rejected before their release manifest is installed or launched.

`letsinfer pack` adds `letsinfer-runtime.json` using artifact schema 2. It records
every packaged file's relative path, byte length, SHA-256, and normalized mode
(`0644` or `0755`). The descriptor's canonical JSON SHA-256 is the Let's Infer
runtime digest. Archive
entries are sorted with fixed ownership and timestamps, making repeated builds
from identical source byte-for-byte reproducible. Built artifacts reject
undeclared files, missing files, links, path traversal, tampered contents or
modes, more than 10,000 files, and payloads larger than 1 GiB.

Only artifact schema 2 is accepted; every other descriptor fails closed.

## Runtime-owned image

A runtime may include an optional conventional image build context:

```text
image/
  Dockerfile
engine/                  # optional author-chosen name
packages.lock            # optional author-chosen name
...any other build inputs...
```

This is the engine-agnostic extension point for extra Python packages, system
libraries, CUDA components, kernels, or an entirely custom engine build. The
Dockerfile location is conventional; every other folder and filename is the
runtime author's choice. The build context is the complete immutable runtime
root, so the Dockerfile may `COPY engine`, `COPY patches`, or any other packed
path. Every context file is covered by the runtime-pack digest. Let's Infer does
not model or translate package-manager choices. It supplies
`SOURCE_DATE_EPOCH=0` to normalize the timestamps of new OCI layers and image
configuration across otherwise identical builds.

Every external `FROM` reference must use an exact registry digest. `scratch`
and earlier named stages are allowed. The release manifest must use
`image.distribution: local-image-id` and pin the expected immutable image ID.
During installation, or an explicit candidate qualification launch, Let's Infer
builds the context only when that exact image is absent and rejects any result
whose image ID differs from the manifest. `--no-build-image` requires the image
to exist already.

Packages are never installed into a running engine container. Serving retains
the read-only, non-root, capability-dropped security boundary, and rollback
continues to select an immutable runtime and image pair. Published runtimes
should normally replace the local image ID with a registry digest and distribute
the already-built image; the Dockerfile remains source and reproducibility
evidence.

The corresponding release manifest continues to pin:

- every exact model dependency and the primary served-model artifact;
- engine, model format, API, and cache identities;
- runtime-owned native engine arguments and environment where needed;
- the digest-pinned runtime and acquisition images;
- runtime integration artifacts;
- one serving recipe and capacity envelope;
- Watchdog safety thresholds; and
- qualification evidence.

It does not enumerate or hash-pin Let's Infer core files. The runtime declares
only `core_compatibility.api`; core verifies its own complete source manifest.
At activation, Let's Infer combines the independently verified core identity
and runtime-manifest identity into an immutable service-bundle identity. A core
update therefore creates a new service bundle without changing the runtime
pack, image, benchmark record, or catalog entry.

A persistent-cache release declares `cache.replay_output_policy` as either
`all-phases-exact` or `restored-repeat-exact`. This tells the generic replay
verifier whether cold, hot, and restored outputs must all match, or whether
repeat restores alone are the exact comparison. It is declarative data, not an
engine hook.

## Named model artifacts

Model dependencies use one engine-neutral, closed contract. `model.artifact`
names the primary artifact that the adapter passes as its protected model path;
`artifacts` may contain any number of additional runtime-defined roles:

```json
{
  "model": {
    "alias": "example-model",
    "id": "owner/example-model",
    "artifact": "model",
    "acquisition_image": "registry.example/acquirer@sha256:..."
  },
  "artifacts": [
    {
      "name": "model",
      "format": "huggingface-snapshot",
      "repository": "owner/example-model",
      "revision": "0123456789abcdef0123456789abcdef01234567"
    },
    {
      "name": "draft",
      "format": "huggingface-snapshot",
      "repository": "owner/example-draft",
      "revision": "89abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

The primary artifact must be first. Remaining entries are sorted by name;
names are unique lowercase portable identifiers. A `huggingface-snapshot`
pins an owner/repository and exact 40-hex revision. A `gguf-file` additionally
pins one contained `.gguf` filename and lowercase SHA-256, with an optional
positive byte length. Cache directory names are derived rather than repeated
in the manifest. Acquisition uses the digest-pinned helper image and the
shared Hugging Face store, so equal repository objects deduplicate naturally.
Every declared artifact is verified before launch, and the shared hub is
mounted read-only.

Runtime-owned engine arguments reference another artifact only as a complete
token, `${artifact:name}`. Core resolves that token to the verified read-only
container path. Unknown names, embedded or malformed references, unsafe
filenames, mutable revisions, duplicate names, unknown fields, and
non-deterministic ordering fail closed. Core assigns no semantics to names
such as `draft`, `lora`, or `vision`; the runtime supplies the corresponding
upstream engine option:

```json
"engine": {
  "arguments": [
    "--speculative-draft-model-path",
    "${artifact:draft}"
  ]
}
```

`engine.arguments` is an optional flat array of native engine option tokens.
Let's Infer overlays matching options onto its engine adapter command and
passes unknown options through unchanged, without maintaining an upstream flag
schema. The runtime therefore owns model parsers, chat behavior, generation
defaults, speculative settings, and future engine flags. Listener, model path,
served identity, TLS, authentication, safety, and declared cache-integration
options remain core-owned and cannot be replaced. `engine.environment`
provides the same runtime-owned extension point for non-core environment
variables. The release manifest accepts no `runtime` tuning object,
structured engine-option object, or engine-specific fields under `serving`.
`serving` contains only qualification state/evidence and the engine-neutral
connection, active-request, and context admission envelope.

Target-specific CPU affinity belongs in optional `container.cpuset_cpus`, for
example `"5-9,15-19"`. The value must use ascending, non-overlapping canonical
Docker CPU-set ranges and is emitted directly as `--cpuset-cpus`. Omitting it
leaves CPU placement to the host; core never guesses an affinity mask.

Installed objects live below `~/.local/share/letsinfer/runtimes/objects/` by
runtime digest. Private selection receipts record the chosen model/engine/target,
version, digest, canonical target-contract SHA-256, immutable core bundle,
source policy, install timestamp, hashed hardware fingerprint, cryptographic
installation ID, and up to 20 prior receipts for rollback. The fingerprint
hashes the host machine ID and physical NVIDIA GPU UUIDs; their raw values are
never stored in the receipt. Receipts never contain registry credentials.

## Public benchmark record

`benchmark.json` contains no prose or executable hooks. Its top-level ID is a
SHA-256 bound to the private installation ID, benchmark timestamp, and exact
`runtime.json.benchmark` digest. Each result identifies a neutral
`ppN,tgN,cN` workload. Code and prose are flat sibling rows distinguished by
`prompt_domain`; each also pins `prompt_suite`, the ordered
`prompt_set_sha256`, and one `actual_prompt_tokens` count per stream. Rows
record aggregate/decode TPS, TTFT, TTFT statistic, prefix-cache state, maximum GPU/CPU utilization and temperature, maximum CPU,
GPU, VRAM, and system-RAM clocks, and a compact fixed-schema one-second
Watchdog timeline. Published maxima must equal their timeline maxima. A clock
that the target cannot expose is recorded as `-1` in every sample and maximum.
Unavailable optional non-clock telemetry is JSON `null`; `is_prefix_cached`
is always a boolean derived from reported cached prompt tokens.

The benchmark ID also binds the complete results/timeline digest, making later
edits detectable. It is not remote attestation: authenticity still depends on
the evidence publisher or a future signing/attestation layer.

`letsinfer benchmark` writes and validates this record with the complete
private evidence. `letsinfer pack` validates a retained structured record
again.

## Catalog format

```json
{
  "schema_version": 3,
  "targets": {
    "dgx-spark": {
      "match": {
        "id": "dgx-spark",
        "platform": "linux/arm64",
        "accelerator": {
          "vendor": "nvidia",
          "architecture": "sm_121",
          "count": 1,
          "partitioning": "full-device"
        },
        "memory": {
          "topology": "unified",
          "minimum_total_gib": 118
        }
      }
    }
  },
  "models": {
    "example-model": {
      "targets": {
        "dgx-spark": {
          "recommended": "vllm",
          "engines": {
            "vllm": {
              "version": "1.1.0",
              "source": "ghcr.io/letsinfer/example-model-vllm-dgx-spark@sha256:..."
            }
          }
        }
      }
    }
  }
}
```

Remote catalogs must use HTTPS, publish an exact-byte Ed25519 sidecar at
`<catalog-url>.sig`, and verify against the locally installed catalog trust
key. Every runtime source must be an OCI digest. Schema 3 declares every
hardware target once at the top level; model entries
reference those canonical target IDs. Automatic resolution matches the probed
platform, accelerator architecture, count and partitioning, memory topology,
and minimum capacities. Zero matches fail closed. Multiple matches are a
catalog ambiguity and fail closed instead of asking an ordinary user to choose
a target. An explicit development override still cannot force incompatible
hardware. The selected target contract's canonical SHA-256 is verified against
the runtime manifest and retained in the installation receipt.
Core uses the signed production catalog and bundled public trust key by
default. Set `LETSINFER_CATALOG`, install
`~/.config/letsinfer/catalog.json`, or pass `--catalog` explicitly only to
override that production source.
