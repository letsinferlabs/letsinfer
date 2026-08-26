# Engine distribution and adapter protocol

[Back to documentation](../README.md)

An Engine distribution binds one upstream inference engine version together
with the adapter written for that version. It may be a Linux OCI, a verified
macOS native archive, a standalone Python environment, or an Engine embedded in
the signed iOS application. Keeping the pair together lets the adapter follow
upstream internal changes without coupling them to core.

## The boundary

Core does not import SGLang, vLLM, DwarfStar, llama.cpp, MLX-LM, MLC LLM, or
their Python packages. An OCI launches the fixed executable:

```text
/opt/letsinfer/bin/engine-adapter
```

A macOS runtime declares a contained adapter entrypoint. An iOS runtime uses
the equivalent adapter compiled into the application. Every variant receives
the same verified private execution view and implements Engine protocol 2.

Core owns:

- target detection and runtime selection;
- Engine-distribution and model acquisition and verification;
- secrets, API keys, gateway, and node topology;
- admission, queuing, pressure state, and safety policy;
- Watchdog and normalized node telemetry;
- benchmark orchestration and evidence;
- lifecycle, update, rollback, and audit.

The Engine distribution owns:

- the exact upstream engine and matching dependencies;
- upstream command construction and version-specific flags;
- tokenizer and rendered-chat behavior;
- exact token counting;
- engine-native cache integration and metrics;
- engine telemetry translation;
- model-specific parsers and generation behavior;
- engine patches, plugins, and compiled kernels.

## Protocol 2

The adapter must expose:

- OpenAI-compatible inference;
- `/health`;
- `/v1/models`;
- `/v1/letsinfer/token-count` using
  `engine-rendered-chat-count-v1`;
- `/v1/letsinfer/telemetry` with normalized request, queue, token, context,
  prefix-cache, and KV-cache fields.

During a long startup, an adapter may also expose the authenticated optional
`/v1/letsinfer/progress` endpoint. It returns one bounded schema-1 object with
exact fields `schema_version`, `state`, `detail`, and `updated_unix_ms`.
`state` is one of `acquiring-inputs`, `preparing-cache`,
`building-auxiliary`, `loading-model`, `warming-kernels`,
`materializing-prompts`, `measuring`, `finalizing-evidence`, or
`restoring-service`. `detail` is a concise engine-neutral explanation, never a
model path, command line, credential, or log stream. Core treats an absent,
stale, malformed, oversized, or unreachable endpoint as unavailable and
continues with its own generic phase.

Core treats unavailable optional metrics as unavailable, never as zero. The
adapter must keep lifecycle and telemetry state monotonic enough for Watchdog,
the status CLI, and the Mac app to consume the same state plane.

The runtime declares requirements by selecting an Engine distribution that implements
the protocol. It does not redefine telemetry capabilities. If an engine cannot
provide a mandatory protocol field, fix or replace its adapter before
qualifying a runtime.

## Runtime arguments

Your `runtime.json` supplies native `engine.arguments` and
`engine.environment`. Core protects listener, model mounts, authentication,
Engine protocol, and safety values, then passes the rest to the adapter. This
keeps model and performance tuning inside the runtime without teaching core an
upstream flag schema.

Additional artifacts use complete-token references such as
`${artifact:draft}`. Core resolves each reference to a verified, read-only
model mount before launch.

## Versioning

Publish a new Engine distribution identity whenever the upstream engine or
adapter changes. OCI variants pin manifest and configuration digests. Native
variants pin the upstream revision, external archive or standalone-Python
inputs, complete adapter closure, and calculated payload SHA-256. An embedded
iOS variant also pins its app-owned Engine payload without including a signing
identity. Any executable payload change invalidates prior qualification.

If Protocol 2 remains sufficient, you can develop and qualify that Engine
without a core release. If the engine genuinely needs a new cross-engine
capability, design the next protocol version in core, update every supported
adapter, and migrate all runtimes in one clean release. Do not add per-version
compatibility branches to core.

Runtime authors do not need registry publication access. Keep the complete
Engine source, adapter, deterministic recipe, patches, tests, licenses, and
SBOM inputs in the same runtime candidate PR. A no-code PR sentinel starts a
secretless default-branch builder and a separate trusted finalizer validates
the exact verifier artifact without executing proposal code. OCI builds are
reproduced twice. Native verifier bundles bind the source revision and payload;
their actual benchmark still runs on the declared Apple target. After
qualification, `/shipit` publishes the runtime that already pins those exact
inputs; external native archives and app signing material are never uploaded
as runtime layers.

If a runtime only changes model configuration, kernels outside the Engine,
capacity, or its serving recipe, it can reuse an existing digest-pinned Engine
without copying that Engine's source into the new candidate.

## Verification

Before you qualify a runtime:

1. run `engine-adapter verify --protocol 2` in the exact distribution;
2. verify exact model identity and token counting;
3. verify health and normalized telemetry through capture and replay;
4. verify admission and structured too-large-request errors;
5. verify restart, crash, pressure, and protection behavior;
6. verify runtime arguments cannot replace protocol-owned values; and
7. bind the immutable Engine distribution identity into runtime and evidence.

An adapter is infrastructure, not a model runtime. Model revisions,
quantizations, kernels, recipes, target limits, and benchmark evidence still
belong to runtime candidates.
