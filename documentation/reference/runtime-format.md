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

## Required schema

Only runtime schema 4 is accepted. The top-level fields are:

```json
{
  "schema_version": 4,
  "id": "sglang--owner--model--dgx-spark",
  "version": "1.0.0",
  "logical_model": "model",
  "status": "candidate",
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
from `engine.id`, the primary Hugging Face URI, and `target.id`. Set `status`
to `candidate` or `qualified` and keep it consistent with
`serving.qualified`.

`release.json` is deliberately small and is not included in the executable
runtime pack:

```json
{
  "schema_version": 1,
  "authors": ["github-name", "organization-name"],
  "license": "AGPL-3.0-only"
}
```

List every person or organization that materially authored the runtime. Use
stable GitHub identities when one exists. The signed catalog versions this
metadata with the runtime release, and `letsinfer list` shows the authors.

## Model artifacts

Your runtime owns model acquisition:

```json
{
  "model": {
    "uri": "hf://owner/repository",
    "artifact": "model",
    "acquisition": {
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

## Engine OCI

Pin one Engine OCI and provide its opaque upstream settings:

```json
{
  "engine": {
    "id": "sglang",
    "protocol": {"version": 2},
    "oci": {
      "reference": "ghcr.io/org/image@sha256:<manifest-digest>",
      "immutable_id": "sha256:<image-config-digest>",
      "base": "registry/base@sha256:<digest>"
    },
    "model_format": "huggingface-snapshot",
    "cache_provider": "sglang-radix-v1",
    "arguments": [],
    "environment": {}
  }
}
```

The Engine OCI contains the upstream engine and its matching adapter.
`arguments` and `environment` pass through after protocol-owned values are
protected. `LETSINFER_*` environment names are reserved. Core has no
engine-version registry or upstream flag schema.

Changing the Engine OCI identity invalidates qualification.

## Target, capacity, and cache

Describe your target by capabilities: platform, accelerator vendor and
architecture, device count and partitioning, memory topology and minimum, and
placement/interconnect requirements. Do not use a hostname as a target.

Set `target.placement.strategy` to `single` for an independent group. Core may
replicate that group across compatible nodes and load-balance the resulting
endpoints. Set it to `parallel` only when this runtime qualifies an exact TP/PP
topology. In that case the runtime owns rank layout, engine configuration,
interconnect requirements, kernels, and adapter inputs; core allocates the
declared devices and treats the complete group as one endpoint.

Use `container` for measured resource and startup bounds. Use `serving` for
the measured maximum connections, active requests, context, qualification
gate, and optional orchestration. Use `cache` for the selected provider and
replay contract; its implementation stays inside the Engine OCI.

## Benchmark record

`benchmark.contract` selects the standard core-owned workload and request
matrix. A qualified runtime binds a validated `benchmark.json` by path,
SHA-256, and benchmark ID. Prompts and runners stay in core, so every model
receives the same benchmark bytes and measurement rules.

## Deterministic runtime artifact

`letsinfer pack CANDIDATE --output FILE` creates a deterministic artifact using
runtime artifact schema 4 and media type
`application/vnd.letsinfer.runtime.v4+tar`. The generated
`letsinfer-runtime.json` descriptor records every path, byte length, normalized
mode, and SHA-256. Paths are sorted; ownership and timestamps are normalized.

Symlinks, traversal, unlisted files, unsafe modes, more than 10,000 files, and
payloads larger than 1 GiB fail closed. Repacking unchanged source must produce
identical descriptor and archive bytes.

Publish the pack as a digest-pinned OCI artifact. The full qualified
`benchmark.json` is a separate immutable OCI evidence artifact bound to that
runtime OCI. Do not embed model weights or publication metadata in the runtime
pack.

## Source layout

Keep candidate-specific kernels, patches, engine source, image recipes,
adapters, tests, and qualification helpers beside `runtime.json`. Generic CLI,
gateway, Watchdog, benchmark runners, prompts, and node orchestration belong to
core and must not be copied into your candidate.

The root runtimes `manifest.json` is generated from candidates. Do not edit it
as a second source of truth.
