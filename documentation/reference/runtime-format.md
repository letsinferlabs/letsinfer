# Runtime format

[Back to documentation](../README.md)

A runtime candidate is one flat source directory named:

```text
<engine>--<lowercase-hf-owner>--<lowercase-hf-model>--<target>/
```

Create one `runtime.json` and one publication-only `release.json` in that
directory, then keep any source needed to reproduce the candidate beside them.
You do not maintain a second execution
manifest. After verification and installation, core generates its private
`runtime-execution.json` view automatically.

The candidate `README.md` begins with the canonical Let's Infer link,
installer command, and `letsinfer model install <logical_model>` command. Prepend
that block to an existing README without replacing its content; the runtimes
repository's `tools/readme_onboarding.py` owns the exact template.

## Required schema

Only runtime schema 6 is accepted. The top-level fields are:

```json
{
  "schema_version": 6,
  "id": "sglang--owner--model--dgx-spark",
  "version": "1.0.0",
  "logical_model": "model",
  "target": {},
  "engine": {},
  "model": {},
  "artifacts": [],
  "container": {},
  "cache": {},
  "serving": {},
  "benchmark": {},
  "orchestration": {}
}
```

`orchestration` is optional. Unknown fields fail closed. Derive `id` exactly
from `engine.id`, the primary Hugging Face URI, and `target.id`. Executable
runtime source contains no qualification or publication status. A release is
qualified only by inclusion in the signed catalog. Qualification affects
evidence claims and catalog recommendation, not whether an operator-selected
runtime receives managed placement, lifecycle, status, or routing.

`release.json` is deliberately small and is not included in the executable
runtime pack:

```json
{
  "schema_version": 2,
  "authors": [
    {"github_login": "github-name", "github_id": 123, "github_type": "User"}
  ],
  "license": "AGPL-3.0-only",
  "provenance": null
}
```

List every person or organization that materially authored the runtime. The
numeric GitHub ID is authoritative across account renames. Authors leave
`provenance` null; trusted qualification automation owns that field. The signed
catalog versions this metadata with the runtime release, and `letsinfer model list`
shows the authors.

## Model artifacts

Your runtime owns model acquisition:

```json
{
  "model": {
    "uri": "hf://owner/repository",
    "artifact": "model",
    "acquisition": {
      "kind": "oci-container",
      "image": "registry/acquirer@sha256:<digest>"
    }
  },
  "artifacts": [
    {
      "name": "model",
      "uri": "hf://owner/repository",
      "format": "huggingface-snapshot",
      "revision": "<exact 40-hex commit>"
    }
  ]
}
```

Put the primary artifact first and sort additional artifacts by name. You may
choose names such as `draft` or `vision`; core does not assign meaning to
them. A `gguf-file` also pins one contained filename and SHA-256. Reference an
artifact from an engine argument only as a complete token such as
`${artifact:draft}`.

Downloaded models live at:

```text
$LETSINFER_HOME/models/<lowercase-owner>--<lowercase-repository>/<revision>/
```

The path comes from the Hugging Face URI. Equal revisions deduplicate across
runtime candidates.

An OCI Engine uses `oci-container` acquisition. A native Apple Engine instead
uses the dependency-free exact-revision client:

```json
{"kind": "huggingface-http", "client": "huggingface-http-v1"}
```

The native client enumerates a full 40-hex Hugging Face revision over HTTPS,
enforces bounded paths, counts, and sizes, verifies declared LFS and GGUF
SHA-256 identities, and never executes repository code.

## Engine distribution

`engine.distribution` is a closed union. Linux runtimes normally use an OCI
distribution:

```json
{
  "engine": {
    "id": "sglang",
    "protocol": {"version": 2},
    "distribution": {
      "kind": "oci-container",
      "reference": "ghcr.io/org/image@sha256:<manifest-digest>",
      "immutable_id": "sha256:<image-config-digest>",
      "payload_id": "sha256:<normalized-execution-payload>",
      "base": "registry/base@sha256:<digest>"
    },
    "model_format": "huggingface-snapshot",
    "cache_provider": "sglang-radix-v1",
    "arguments": [],
    "environment": {}
  }
}
```

The Engine distribution contains the upstream engine and its matching adapter.
`arguments` and `environment` pass through after protocol-owned values are
protected. `LETSINFER_*` environment names are reserved. Core has no
engine-version registry or upstream flag schema.

The manifest and configuration digests identify the distributed OCI object.
The payload ID identifies the pinned base, normalized final overlay files, and
runtime-relevant container configuration. Packaging-only OCI changes preserve
benchmark evidence when the payload ID is unchanged; changing executable
payload invalidates qualification.

A macOS archive distribution pins an official archive and the complete
runtime-owned adapter closure:

```json
{
  "kind": "native-archive",
  "platform": "macos/arm64",
  "payload_id": "sha256:<payload>",
  "source_revision": "<40-hex upstream commit>",
  "entrypoint": "adapter/engine-adapter",
  "port_count": 2,
  "archive": {
    "url": "https://example.invalid/engine.tar.gz",
    "sha256": "<archive sha256>",
    "bytes": 123,
    "format": "tar.gz",
    "strip_prefix": "engine-release"
  },
  "upstream_executable": "bin/engine"
}
```

`python-standalone` has the same common identity but replaces `archive` and
`upstream_executable` with an exact CPython archive and a hash-locked
`requirements_lock`. Core installs the complete lock into an isolated,
relocatable package directory; it does not use the host Python environment.

An iOS runtime uses `embedded-application`. It pins the application bundle ID,
minimum app version, embedded Engine name, upstream source revision, and a
deterministic payload ID. Its signing policy is `deployment-managed`; signing
team identities and certificates are never runtime inputs. The app validates
the exact candidate and payload before accepting a group job.

## Target, capacity, and cache

Describe your target by capabilities: platform, accelerator vendor and
architecture, device count and partitioning, memory topology and minimum, and
placement/interconnect requirements. Do not use a hostname as a target.

```json
{
  "placement": {
    "strategy": "parallel",
    "node_count": 2,
    "interconnect": {
      "kind": "connectx",
      "rdma_required": true,
      "minimum_speed_mbps": 100000,
      "minimum_mtu": 9000
    }
  }
}
```

Set `target.placement.strategy` to `single` for an independent group. Core may
replicate that group across compatible nodes and load-balance the resulting
endpoints. Set it to `parallel` only when this runtime qualifies an exact TP/PP
topology. In that case the runtime owns rank layout, engine configuration,
interconnect requirements, kernels, and adapter inputs; core allocates the
declared devices and treats the complete group as one endpoint.

Use `container` for the measured resource and startup envelope even for a
native distribution; native runtimes set `shm_bytes` to zero. Use `serving` for
the measured maximum connections, active requests, and context. Use `cache`
for the selected provider and
replay contract; its implementation stays inside the Engine distribution.

## Parallel execution

An independent `single` target omits `orchestration`. A `parallel` target
declares one bounded generic task per required node:

```json
{
  "orchestration": {
    "schema_version": 3,
    "failure_policy": "whole-group",
    "endpoint_owner": "task-0",
    "startup_order": [["task-1"], ["task-0"]],
    "tasks": [
      {
        "task_id": "task-0",
        "launcher": "runtime-command",
        "port_count": 4,
        "command": ["/opt/runtime/launch", "task-0"],
        "environment": {},
        "readiness": {
          "kind": "exec",
          "command": ["/opt/runtime/ready"],
          "interval_seconds": 2,
          "timeout_seconds": 3,
          "retries": 90
        }
      }
    ]
  }
}
```

For a real two-node candidate, include both `task-0` and `task-1`. Core maps
tasks deterministically to authenticated nodes, allocates exact GPU UUIDs and
ports, and supplies verified addresses and connection facts. Tasks in one
startup phase launch concurrently; later phases wait for complete readiness.
The endpoint is published only after every required task is ready.

The task identifier is deliberately opaque. Your Engine distribution maps it to any TP,
PP, expert, sequence, data, or hybrid strategy; ranks, stages, rendezvous,
collectives, and engine flags never enter core schemas. A one-node parallel
runtime may receive multiple GPU UUIDs in `task-0`. Complete parallel placement
groups may be replicated behind the gateway like independent placement groups.

When `target.placement.interconnect.rdma_required` is true, core assigns the
endpoint-owner task to the main node, seals one verified interface into every
task resource, and revalidates the direct route, HCA, link floor, and exact
userspace verbs devices immediately before launch. The Engine container
receives only those `/dev/infiniband` character devices and a memlock limit
bounded by its declared container memory. Core exports the selected interface
and HCA as protected resource values; the runtime maps them to its private
collective configuration and must fail readiness if the Engine falls back to
a non-RDMA transport.

## Benchmark record

`benchmark.contract` selects the standard core-owned workload and request
matrix. Prompts and runners stay in core, so every model receives the same
benchmark bytes and measurement rules. Native payloads produce schema-8 records
that bind their distribution kind and payload SHA-256. The trusted bot aggregates accepted records into
`benchmark.consensus.json`, which is excluded from executable pack bytes.

## Deterministic runtime artifact

The public `letsinfer-runtime-authoring` skill creates a deterministic artifact
through the exact checked-out Core packing contract, using
runtime artifact schema 6 and media type
`application/vnd.letsinfer.runtime.v6+tar`. The generated
`letsinfer-runtime.json` descriptor records every path, byte length, normalized
mode, and SHA-256. Paths are sorted; ownership and timestamps are normalized.

Symlinks, traversal, unlisted files, unsafe modes, more than 10,000 files, and
payloads larger than 1 GiB fail closed. Repacking unchanged source must produce
identical descriptor and archive bytes.

Publish the pack as a digest-pinned OCI artifact. Complete community evidence
stays in canonical bot comments and `benchmark.consensus.json`; do not publish
it as a second OCI or embed it, model weights, or publication metadata in the
runtime pack.

## Source layout

Keep candidate-specific kernels, patches, engine source, image recipes,
adapters, tests, and qualification helpers beside `runtime.json`. Generic CLI,
gateway, Watchdog, benchmark runners, prompts, and node orchestration belong to
core and must not be copied into your candidate.

Engine source is required only when the proposal changes or introduces that
Engine. Existing-Engine runtimes preserve the exact distribution identity
without copying upstream source. Never commit generated image layers, native
archives, static libraries, model weights, build caches, signing identities,
or private benchmark evidence.

The root runtimes `manifest.json` is generated from candidates. Do not edit it
as a second source of truth.
