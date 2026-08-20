# Runtime packs

[Back to documentation](../README.md)

A runtime pack is the installable implementation of one model on one engine
and one hardware target. Its exact identity is `model/engine/target`, for
example `example-model/vllm/dgx-spark`. Each target variant owns its
exact engine revision and image, patches, kernels or plugins, Let's Infer release
configuration, named model artifacts, compatibility limits, and qualification
evidence. A target repository has full freedom to specialize all of those
pieces; evidence never transfers to another target.

The source form is a Git repository. The distribution form is a deterministic
`.letsinfer` archive or the same payload published as an OCI artifact. Git is for
development and review; Let's Infer installs immutable content and records its
descriptor SHA-256. Model weights and generated inference caches are not part
of the pack.

The source repository should contain only the target's implementation closure:
its descriptors, engine or patches, target-specific kernels, optional image
recipe, concise provenance, and result summary. Shared benchmark runners,
prompt templates and generators, generic operational scripts, Watchdog,
gateways, and Let's Infer's engine-neutral prefix store stay in Let's Infer core. The
runtime declares a standard benchmark contract under `runtime.json.benchmark`;
it does not carry scripts, plans, or materialized prompts. An engine-specific
shim that exports native cache state or exact rendered-chat token counting can
remain with the engine, but it implements a versioned Let's Infer capability.

At benchmark time, core deterministically generates the same versioned code and
prose bytes for every model. The adapter counts the complete rendered requests
but never changes their bytes. Generated prompts and the derived plan live only
in evidence. Their hashes are bound to the runtime contract, core generator and
templates, model, engine image, and render contract; per-stream actual token
counts make tokenizer differences explicit.

Sealed public results live at the target root as structured `benchmark.json`,
not prose or runtime-provided benchmark code. Let's Infer creates a private
installation identity from the runtime digest, install time, and a hashed
host/physical-GPU fingerprint. Each benchmark ID binds that installation ID,
the benchmark timestamp, and the exact declared benchmark contract. Result
rows state their prefix-cache condition explicitly, include utilization and
temperature maxima, and carry a compact timeline from Watchdog's independent
one-second telemetry ring. The benchmark ID also binds the results digest.

Every runtime must pin one exact image. The image recipe is optional because
published runtimes normally pull an already-built OCI image by digest. A local
or forked runtime can include `image/Dockerfile` plus arbitrary build inputs
when it needs extra packages, libraries, kernels, patches, or a custom engine.
`image/Dockerfile` is the only special build path; sibling directories may use
any names and are available to Docker through the immutable runtime-root build
context. Let's Infer does not add a package schema: it passes that context to
Docker, requires every external base to be digest-pinned, fixes new OCI
layer/config timestamps through the standard `SOURCE_DATE_EPOCH` build
argument, and verifies that the result has the manifest's exact local image
ID. This keeps the extension point universal without weakening
serving-container isolation.

When several runtime repositories are kept in one development tree, use
`runtimes/<model>/<engine>/targets/<target>/`. The `targets` directory is only
source organization; the installed identity remains `model/engine/target`.

`letsinfer pack --output PATH` writes the build artifact at exactly `PATH`.
Release automation should publish that payload to an OCI registry; it does not
belong in the runtime source tree. A project may attach the same file to a Git
hosting release for convenience, but Let's Infer's production identity is the OCI
digest, not a release-page URL. Installation copies verified contents into
`~/.local/share/letsinfer/runtimes/objects/<runtime-digest>`.

Each variant has one qualified serving recipe with a declared connection,
active-request, and context envelope. There are no user-facing profiles.
Connection concurrency is handled by the runtime's measured scheduler and
bounded admission behavior. The exact native recipe is the runtime-owned
argument/environment pair; core rejects structured engine settings instead of
keeping a second representation.

## Recommendations and choices

A schema-3 catalog declares canonical hardware target contracts once, then
maps each model's engine variants to those targets. Let's Infer probes the host,
selects its compatible target, and installs the catalog's recommended stable
engine without exposing the target in the normal command. Zero matches fail
closed; multiple matches are a catalog error rather than a choice delegated to
the user. A development-only explicit target remains compatibility-checked.
Installing without `--engine` records a `recommended` policy. Installing with
`--engine vllm` records an engine-pinned policy. An exact OCI digest records
`pinned`; a local repository or archive records `local`. Neither moves without
an explicit `upgrade --to`.

Changing a catalog recommendation never changes a running installation.
`letsinfer upgrade MODEL` is the explicit transition and shows both immutable
identities before activation.

## Derivation

Use a derivation for native engine configuration changes:

```bash
letsinfer derive example-model/vllm/dgx-spark \
  --name my-vllm \
  --without=--enable-prefix-caching \
  -- \
  --max-model-len 65536 \
  --max-num-seqs 4 \
  --new-upstream-flag
```

Let's Infer matches long- and short-option names exactly. Matching clauses replace inherited
clauses, repeated options are replaced as a group, new options append in the
order supplied, and `--without` removes inherited options. Values that begin
with `--` should use the upstream `--option=--value` form.

Let's Infer does not maintain upstream flag schemas. Negative numeric values are
kept as values; an option-looking value should use the upstream
`--option=--value` form. The fully resolved argv is stored and hashed without a
shell. Model identity, listener, authentication, TLS, and mandatory safety
arguments remain Let's Infer-owned and cannot be overridden.

Every derivation is a new immutable, unqualified local candidate. It inherits
implementation provenance, not the parent's performance, capacity, stability,
or cache-compatibility claims. Fork the runtime repository instead when
changing kernels, engine code, plugins, the container, or cache ABI.
