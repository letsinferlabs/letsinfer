# Engine adapter contract

The Let's Infer release-manifest contract separates shared deployment policy
from inference-engine behavior. The registered engines are `vllm`, `sglang`, `llama.cpp`,
and `dwarfstar`.
Adding an adapter does not qualify a release: every engine/model/serving
combination still needs its own immutable image, exact model artifacts, safety
settings, benchmark evidence, and qualification result.

## Shared contract

Every release declares:

```json
"target": {
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
},
"engine": {
  "name": "vllm",
  "model_format": "huggingface-snapshot",
  "api_protocol": "openai-v1",
  "cache_provider": "letsinfer-prefix-v1",
  "arguments": ["--reasoning-parser", "runtime-parser"]
}
```

These values are the current DGX Spark target contract. New manifests state a
structured capability contract explicitly. The core can represent unified or
discrete memory and one or more homogeneous NVIDIA GPUs; each target supplies
its own capacity floors and qualification. DGX Spark is the first implemented
target contract, but core publishes no model runtime. A 5090, multi-GPU
workstation, or MIG target requires a distinct external runtime target and
evidence.

Let's Infer probes the host rather than matching a hostname. Catalog resolution
compares platform, NVIDIA compute capability, device count and partitioning,
memory topology, and capacity. Zero matches fail closed; multiple matches are
rejected as a catalog ambiguity instead of being delegated to the user. An
explicit development target must still match. The resolved target and its
canonical contract SHA-256 are carried through the descriptor, receipt,
release, container labels, upgrade, inspection, and doctor checks.

The core validates the engine name against the adapter registry and requires
the adapter's exact model format and cache provider. It also pins separate
runtime and model-acquisition images, source files, named model artifacts,
the serving recipe and capacity, gates, and result hashes. Separating the
acquisition image prevents
an engine image without Python or `huggingface_hub` from breaking automatic
install-time model acquisition. The core supplies the LAN gateway, API-key handling,
private engine TLS, a read-only model mount,
non-root execution, a read-only container root, dropped capabilities, health
and `/v1/models` identity checks, topology-aware memory admission, restart
policy, systemd integration, and evidence capture. Runtime and acquisition
images are requested at the exact target platform. Native vLLM wheel names
must match that architecture, and containers carry target-platform,
memory-model, and GPU-count labels so a mismatched container is never adopted.

`model.artifact` selects the primary served-model dependency. The closed
top-level `artifacts` array supports any number of runtime-named exact Hugging
Face snapshots or hash-pinned GGUF files. Core derives their shared-store
paths, acquires and verifies them, mounts the hub read-only, and expands only
whole-token `${artifact:name}` references in `engine.arguments`. It does not
interpret names or add engine flags for drafts, adapters, encoders, or other
roles. Those semantics remain entirely in the runtime recipe.

`min_available_gib` and `runtime_min_available_gib` are floors on a unified
host/device memory pool. Separate GPU-memory floors are rejected for unified
targets. Discrete targets must instead declare positive launch and runtime GPU
free-memory floors in addition to host-memory admission.
An optional target-scoped `container.cpuset_cpus` uses canonical Docker CPU-set
syntax. Ranges must be ascending and non-overlapping. It is part of the exact
target recipe and is passed unchanged as `docker run --cpuset-cpus`; core does
not infer a CPU topology or apply affinity to another target.

Aliases may exist in more than one engine. In that case the CLI fails closed
until `--engine` is supplied. It never falls back to another engine, image,
model artifact, quantization, cache provider, or serving recipe.

## Public request and measurement boundary

Every adapter presents an authenticated OpenAI-v1 engine boundary to the
coordinator. The coordinator gateway is the one stable client endpoint and
records bounded engine-neutral request telemetry without storing prompts or
responses. vLLM, SGLang, and llama.cpp provide their native boundary;
DwarfStar listens on private loopback behind a small runtime gateway because
its native server does not provide the required private TLS/authentication contract.
Watchdog remains outside the inference path.

For streaming requests the gateway enables each engine's native exact usage
extension behind the adapter boundary. SGLang and vLLM provide cumulative
continuous usage, so exact input, cached, and output-token counters advance
while a response is still streaming. DwarfStar and llama.cpp are requested to
include their native final usage record; their token rates remain unavailable
until that record arrives when the selected build does not expose continuous
usage. A bounded incremental SSE parser accepts fragmented events, reconciles
cumulative counts with the final record, and accounts cancellation or a
missing tail only from exact observations already received. Non-streaming
usage, exact pre-dispatch prompt counts, and final stream usage share one
reconciler, so counters cannot be double-counted. Missing or malformed usage
is never estimated from response text.

The generic benchmark runner sends the same OpenAI-v1 requests through the
site gateway for any runtime and measures TTFT, decode and aggregate token
throughput, latency, cache reports, health, OOM, restart, and telemetry under
one engine-neutral evidence contract.

An adapter may also expose Let's Infer's internal
`engine-rendered-chat-count-v1` capability. It accepts the standard chat
request and returns only the exact rendered prompt-token count and served model
identity. Let's Infer uses it to calibrate generated benchmark prompts against the
runtime's actual tokenizer and chat renderer. The operation must cross the
same authenticated boundary as inference and must not run inference, return
token IDs, or mutate cache state. Runtimes without the capability fail closed
for generated-suite execution; Let's Infer never substitutes an approximate
tokenizer.

## vLLM

- Model format: `huggingface-snapshot`
- Cache provider: `letsinfer-prefix-v1`
- Persistent cache: required and supported
- Runtime extension: a manifest-pinned Python connector and reproducible Rust
  wheel

The vLLM adapter installs its wheel into a private container tmpfs, reads the
API key from the mounted secret into the server environment, and launches only
the exact qualified vLLM arguments from `engine.arguments`. Core supplies the
model path, served identity, private listener, TLS/authentication, and declared
prefix-connector configuration. Tensor/pipeline parallelism, attention,
memory, context, batching, speculative behavior, and target environment remain
opaque runtime-owned settings.

## SGLang

- Model format: `huggingface-snapshot`
- Cache provider: `sglang-hicache-file-v1`
- Persistent cache: required and supported through file-backed HiCache
- Runtime extension: none

The SGLang adapter writes its API key to a mode-0600 YAML file in container
tmpfs and passes only that path to SGLang, keeping the value out of Docker
metadata and process arguments. It enables RadixAttention/HiCache with a
private mounted storage root. The cache object configures the declared HiCache
provider. All native context, tensor-parallel, attention, memory, scheduler,
trust, and prefill flags pass unchanged from the runtime-owned argument array
and are qualified as part of that exact recipe.
Speculative decoding is no exception: a runtime declares its draft dependency
as a named artifact and owns both `--speculative-draft-model-path` and its
`${artifact:name}` value. The adapter has no draft-model field or behavior.
For exact context admission and generated benchmarks, the adapter translates
the supported OpenAI chat request into SGLang's authenticated, non-generating
`/v1/messages/count_tokens` operation and accepts only its exact
`input_tokens` response. System content, images, function tools, assistant tool
calls, and tool results are translated without model-specific logic. When a
valid OpenAI history cannot be represented losslessly in the Anthropic count
schema—such as an assistant turn containing `reasoning_content`—the core
adapter automatically uses SGLang's authenticated `/v1/tokenize` operation.
That fallback applies SGLang's own OpenAI request model and the identical chat
template used by inference. Core validates its token-ID response while
streaming it in bounded memory. Invalid or inexact shapes still fail closed
before inference. This behavior belongs to the core SGLang adapter, so runtimes
do not carry counting patches or model-specific translations.
The adapter also enables SGLang's exact cumulative stream-usage mode, so future
SGLang runtimes inherit live engine-neutral throughput without adding a
runtime patch or configuration field.

## llama.cpp

- Model format: `gguf-file`
- Cache provider: `native-prompt-v1`
- Persistent cache: not yet supported by this adapter
- Runtime extension: none

The primary named artifact must identify one off-the-shelf `.gguf` file, an exact 40-hex
repository revision, and the file's SHA-256. Let's Infer does not convert or
requantize a checkpoint. The adapter passes the API-key file directly to
`llama-server`, enables TLS, and controls model and served identity. Context,
GPU-layer, slot, batch, microbatch, Flash Attention, Jinja, and future native
options belong only to the runtime-owned argument array.

llama.cpp candidate releases can run and be qualified, but schema validation
rejects promotion to `stable` while the adapter lacks restart-persistent cache
semantics. This is an explicit capability gap, not a fallback to another
engine's cache.

## DwarfStar

- Model format: `gguf-file`
- Cache provider: `dwarfstar-letsinfer-prefix-v1`
- Persistent cache: supported through native bank-payload records and the
  engine-neutral Let's Infer store
- Runtime extension: manifest-pinned standard-library Python TLS/auth gateway
- Token counting: exact GGUF-backed rendered-chat count through the
  authenticated gateway

The runtime selects its base GGUF as `model.artifact` and declares its DSpark
GGUF as another named `gguf-file`. Its runtime-owned arguments bind
`--dspark` to `${artifact:drafter}`. Core has no DwarfStar pair or drafter
schema: both files use the same arbitrary artifact contract as any other
engine dependency. Each artifact pins its own repository, 40-hex revision,
filename, optional byte length, and SHA-256. Acquisition downloads both
through the release's pinned helper image and verification checks both before
launch.

DwarfStar itself listens only on a dynamically selected loopback port. The
gateway owns the public manifest port, TLS certificate, API-key check,
unauthenticated `/health`, exact backend-model health check, bounded client
connections, and the manifest's maximum active inference requests. It strips
the client credential before proxying OpenAI requests and forwards shutdown to
the native server so persistent-cache writes can drain. The gateway adds no
profile selector. `serving` declares only the public connection,
active-request, and context admission envelope. DwarfStar context, internal
batching, prefill, memory, speculative behavior, kernels, and target tuning are
opaque runtime-owned native arguments and environment. Core neither interprets
those settings nor imposes a DwarfStar performance schema.

The runtime image contract requires Python 3 and
`/opt/dwarfstar/ds4-server`. Let's Infer builds its native cache bridge from
pinned core source and mounts it read-only at
`/plugins/libletsinfer_prefix_capi.so`. The runtime repository owns the exact
forkable DwarfStar source, target-specific kernels and configuration, image,
network-update policy, and evidence. Those details are never promoted into
core or silently reused by another target. An unqualified manifest may run
only through explicit qualification mode; normal serving and installation
remain fail-closed.

## Qualification boundary

Each manifest has one `serving` object containing the tested
`max_connections`, `max_active_requests`, and `max_context_tokens` envelope,
qualification state, and evidence reference. The native recipe lives in
`engine.arguments` and `engine.environment`. `manifest.runtime`,
structured engine options, and engine-specific fields under `serving` are
rejected rather than translated. A recipe qualified under vLLM
says nothing about SGLang or llama.cpp. Stable releases also require a pullable
registry digest, persistent cache support, and the serving gate to pass.

Each stable serving gate contains two separately source-pinned records:

- `common`, with contract `letsinfer-openai-v1-common`; and
- `engine`, with the adapter contract `vllm-letsinfer-prefix-v1`,
  `sglang-hicache-file-v1`, `llama.cpp-native-prompt-v1`, or
  `dwarfstar-letsinfer-prefix-v1`.

Both records must use portable `evidence/` paths whose exact result hashes are
listed in `source_artifacts`. They must identify the same full 40-hex measured
commit as the serving gate, and the two lane references must be distinct.
Stable validation fails closed when either layer is absent or inconsistent.
Candidate manifests may keep incomplete or blocked gates while qualification
work is still explicit.

The common gate is
[`benchmarks/openai_matrix.py`](../../benchmarks/openai_matrix.py).
It uses only the authenticated OpenAI-v1 contract and therefore runs
unchanged against vLLM, SGLang, llama.cpp, and DwarfStar. It verifies exact release,
container, image, engine, and served-model identity; hashes engine-
specific tokenizer fixtures; runs simultaneous first/immediate-repeat cells;
retains complete streamed outputs; measures TTFT and throughput; and fails on
auth, transport, output-equality, restart, OOM, or health regressions.

The sustained load monitor samples Spark's shared available memory, records
NVIDIA state, and disables Docker restart and stops the engine if the runtime
floor is crossed.

Authentication is checked on `/v1/chat/completions`, not by assuming model
discovery is private. An empty malformed request produces no tokens:
anonymous access must return 401, while the configured key must pass auth and
reach validation (400 or 422). Authenticated `/v1/models` independently proves
the exact served model. This keeps inference protected on llama.cpp builds
whose model list is intentionally public.

OpenAI-v1 has no portable cache-hit, reused-token, scheduler, or speculative-
acceptance interface. Those facts remain mandatory engine-specific evidence
obtained through a versioned adapter capability; they are never inferred by a
model-specific core runner. Core contains no per-model or per-engine benchmark
scripts.

## Upstream image compatibility

Every release must probe its digest-pinned engine image on the declared target
without loading a model. The probe verifies platform and accelerator
visibility under the non-root, read-only container policy plus every
manifest-used TLS, authentication, cache, context, batching, and serving flag.
An adapter probe is not model or performance qualification.
