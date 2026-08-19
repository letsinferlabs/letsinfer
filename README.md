# Let's Infer

Let's Infer is an engine-agnostic inference distribution and runtime manager. It
packages each supported model, inference engine, and hardware target as a
verified, reproducible runtime. One logical site may contain one machine,
replicas, or a runtime-qualified distributed group, while clients retain one
OpenAI-compatible endpoint and one site identity. NVIDIA DGX Spark is the first
implemented qualification target; the first public runtime is not yet sealed.

A Let's Infer release brings together:

- an exact model checkpoint revision;
- an exact hardware capability contract: platform, accelerator architecture,
  device count and partitioning, memory topology, and minimum capacity;
- a digest-pinned inference runtime and immutable image;
- verified integration patches and plugins;
- one measured production serving configuration and capacity envelope;
- unified-memory admission and launch safety checks;
- persistent long-context cache state; and
- reproducible benchmark results and release evidence.

Let's Infer is not an inference engine, a model format, or merely a prefix cache.
Its unit of delivery is the complete, tested combination of model, engine,
configuration, cache compatibility, and evidence required to serve a model
reliably on a compatible target.

Install and initialize the latest stable core release on Linux or macOS with:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
```

The signed bootstrap selects Linux or macOS and x86_64 or arm64, installs the
immutable core under `/opt/letsinfer`, exposes `letsinfer` in
`/usr/local/bin`, and runs `letsinfer setup`. Use `--user` for `~/.local` or
`--no-setup` when preparing files without creating a site.

The bootstrap verifies a signed checksum and the archive's complete source
manifest before installing the immutable core.

## Why Let's Infer

General-purpose model runners optimize for broad model coverage and quick
experimentation. Let's Infer focuses on the fastest *safe, measured* recipe for
each supported model and qualified hardware target.

The current release work remains focused on one 128 GB GB10/SM121 Spark. That
means immutable identities instead of mutable tags, one manifest-selected
serving recipe instead of user-tuned modes, and fail-closed launch gates
instead of silent fallback. Let's Infer will not quietly substitute a different
checkpoint, quantization, image, attention backend, cache format, or serving
configuration.

Before serving, Let's Infer verifies the release and deployed artifacts, confirms
the exact model snapshot and image identity, probes stable host capabilities,
and verifies that they satisfy the selected runtime target. The current
`dgx-spark` target requires `linux/arm64`, one full SM121 GPU, at least 118 GiB
of unified memory, and no MIG partitioning. Let's Infer gates the target's memory
pool and preserves the release's runtime emergency
reserves during startup and sustained
qualification, prevents conflicting containers, waits for the runtime health
check, verifies the served model identity, prewarms compatible cache records,
and records the resolved launch state and logs. The coordinator gateway
advertises its LAN HTTP endpoint with mDNS, requires a scoped API key, and routes only to qualified engine
placements. Engine containers mount checkpoints read-only, use read-only root
filesystems, and drop all Linux capabilities.
Model acquisition uses its own digest-pinned helper image at the release's
exact target platform, so an engine runtime is not required to contain Python
or Hugging Face tooling.

## One logical site

`letsinfer setup` creates a cryptographic site identity and makes the first
machine its coordinator. The coordinator owns membership, API keys, the audit
chain, target placement, aggregate telemetry, and the stable inference
gateway. It is still an inference-capable member. Additional machines join as
members and may run an independent model, a replica, or one role in a
runtime-qualified distributed engine group.

Discovery and authorization stay separate. A pristine Spark on a verified
direct ConnectX link appears in the Mac app as **Add to Home**; the click binds
the exact peer route, certificates, site keys, and one-use invitation without
asking for a code. LAN and remote members require the short-lived setup-code
and human-comparison flow. An already configured machine is never silently
merged: the app offers either **Connect to this site** or an explicit,
rollback-safe **Move into Home**.

The coordinator advertises one LAN HTTP `/v1` endpoint over mDNS. Its SQLite key registry
supports model scopes, expiry, request/token rates, concurrency, maximum
context, tenant, application, rotation, and revocation. Replica routing uses
health, pressure, capacity, queue depth, prefix locality, and temperature;
distributed requests go only to the runtime-declared engine coordinator.
Requests may retry elsewhere only before response output starts.
Health, pressure, and temperature are overlaid from fresh signed member facts,
and distributed admission requires continuously renewed bidirectional link
proofs that still satisfy the runtime's interconnect contract.

Every CLI leaf declares a `coordinator`, `member`, or `all` execution scope.
Site mutations and sensitive reads are coordinator-only and recorded in a
tamper-evident SQLite audit chain. A member never proxies a coordinator command.
See [Sites, members, and trust](documentation/concepts/sites.md).

## Persistent long-context reuse

Let's Infer's prefix cache persists model inference state across requests and
runtime restarts. For long conversations and agent workloads, this can avoid
recomputing a large shared context and substantially reduce time to first
token.

The cache stores inference state—not chat histories or user-facing
conversation objects. Compatibility is tied to the exact model, tokenizer,
template, token sequence, runtime layout, KV representation, adapters, and
hybrid-model state. Corrupt, incomplete, stale, or incompatible records are
treated as cache misses; partial restoration is never allowed.

Large captures use reclaimable same-filesystem file mappings; commits still
use fsync plus atomic rename. Large durable restores validate every region
with bounded aligned direct-I/O buffers, discard those pages, and only then
expose a lazy immutable mapping to the engine. This avoids anonymous or
page-cache-resident record-sized copies of inference state competing with the
engine for unified memory while preserving the same record format, CRC
validation, and restart semantics.

The vLLM adapter can use Let's Infer's engine-neutral Rust store through a Python
KV connector. The SGLang adapter uses RadixAttention with file-backed HiCache and
declares persistent-cache capability, but it still needs an independently
qualified model release. The llama.cpp adapter uses its native prompt cache,
which is not restart-persistent, so a llama.cpp release cannot be promoted to
`stable` until a persistent-cache adapter is qualified. DwarfStar restores
native bank payloads through the same engine-neutral Rust store. Adapter or
cache capability is never silently substituted for a qualified model runtime;
core contains no registered model candidate.

## Runtime packs

Each runtime identity is `model/engine/target`, such as
`example-model/vllm/dgx-spark`. A target owns the exact engine
revision, patches, kernels, configuration, and evidence for that device class.
A trusted schema-3 catalog declares each hardware target once and recommends
one qualified engine independently for each model and target. Let's Infer uses
the signed `letsinferlabs/catalog` catalog and its built-in public trust key by
default. Remote catalogs must ship an exact-byte Ed25519 sidecar at
`<catalog-url>.sig`; `~/.config/letsinfer/catalog-public-key.pem` and
`LETSINFER_CATALOG_PUBLIC_KEY` are explicit trust-root overrides. Signature
verification happens before parsing any target or runtime choice.
An explicitly selected unsigned local file is a development trust boundary,
not a remotely trusted catalog. The ordinary user chooses only the model;
`--engine` remains available to power users.
Existing runtime installations remain locked to immutable content until the
user runs `letsinfer upgrade`. Core updates are independent:
`letsinfer update` installs a signed core release and rebinds services without
changing runtime selections, models, caches, or evidence.

Let's Infer maps targets by capabilities, not hostnames. `letsinfer hardware` probes
platform, NVIDIA compute capability, GPU count and partitioning, memory
topology, and capacity. Automatic selection must produce exactly one match;
no match fails closed, and multiple matches are rejected as a catalog error
instead of asking the user to select a target. An explicit development target
is still verified and cannot bypass compatibility checks. The canonical target
contract SHA-256 is bound into the runtime receipt. This permits many identical
Sparks to use the same target and allows future discrete-GPU or multi-GPU
targets without transferring Spark qualification to them.

A runtime is developed in a Git repository containing `runtime.json`, its
release manifest, and any model-specific engine, kernel, or integration
source. `letsinfer pack` turns that source into a deterministic artifact whose
schema-v2 descriptor pins every file by byte length, SHA-256, and normalized
mode. Production artifacts are designed for OCI distribution by digest; model
weights remain in their exact upstream repository and Let's Infer's NVMe cache.

Keep that repository to the runtime's real implementation and qualification
closure. Generic benchmark runners, workload templates and generators,
operational scripts, Watchdog, gateways, and Let's Infer's engine-neutral
cache/store belong to Let's Infer core and must not be copied into each runtime.
`runtime.json` declares the standard benchmark suite, cases, request settings,
seeds, and exact tokenizer/render identity. Let's Infer generates exact prompts
into evidence through the selected engine adapter; prompt files, plans, and
benchmark code never enter the runtime pack. A runtime may retain a small
engine-specific cache or tokenizer shim when it must expose native state, but
Let's Infer supplies the common interface and implementation.

Sealed results live beside `runtime.json` as validated `benchmark.json`, not
prose. Every row names a neutral `ppN,tgN,cN` workload and records aggregate
and decode TPS, TTFT, prefix-cache state, utilization/temperature maxima, CPU,
GPU, VRAM, and system-RAM clocks and maxima, and a compact timeline from
Watchdog's independent one-second ring. Unavailable clocks are `-1`. Install receipts
hold a private cryptographic installation ID bound to the runtime digest,
install time, and hashed host/physical-GPU identity. Benchmark IDs bind that
installation, the benchmark contract, timestamp, and complete results digest;
raw machine and GPU identifiers are never published.

The exact runtime image is mandatory; its build recipe is not. Published
runtimes normally point at a prebuilt OCI image by digest. A local or forked
runtime may instead include `image/Dockerfile` and arbitrary build inputs for
extra packages, libraries, kernels, or engine changes. Let's Infer passes that
Dockerfile the entire immutable runtime root as its build context, requires
digest-pinned external base images, and
accepts the build only when its immutable image ID matches the manifest.
Packages are never added to a running container.

Native engine flags do not need a Let's Infer schema. `letsinfer derive` starts with
the packaged command, replaces matching long or short options, appends new options,
and removes inherited options with `--without`. The resolved argv is stored
and hashed without shell evaluation. Model identity, listener, TLS,
authentication, and safety arguments remain controlled by Let's Infer. A derived
runtime is always a new unqualified candidate until it earns its own evidence.

## Engine adapters

Let's Infer currently registers `vllm`, `sglang`, `llama.cpp`, and `dwarfstar`
adapters. The
shared control plane owns release identity, exact model acquisition, topology-
aware memory admission, Docker/systemd lifecycle, TLS and authentication, health and
model-identity checks, evidence, and restart behavior. An adapter owns only its
model format, protected invocation skeleton, and cache integration.

Core does not carry performance recipes or an upstream option schema.
`engine.arguments` and `engine.environment` are the runtime's sole native
configuration surface for context, parallelism, batching, attention,
speculation, kernels, and target tuning. `serving` is deliberately limited to
the qualified connection, active-request, and context admission envelope;
parallel structured engine settings are rejected.
The release names one primary model artifact and may declare any number of
additional exact dependencies. Runtime arguments bind those dependencies to
upstream flags with whole-token `${artifact:name}` references; core only
acquires, verifies, deduplicates, mounts, and resolves their paths.

- vLLM consumes exact Hugging Face snapshots and can use Let's Infer's durable
  prefix store and verified connector.
- SGLang consumes exact Hugging Face snapshots, can use file-backed HiCache,
  and normalizes its non-generating rendered-chat token counter for exact
  gateway admission and generic benchmarks.
- llama.cpp consumes an off-the-shelf GGUF from an exact repository revision
  and verifies the GGUF SHA-256 before launch.
- DwarfStar selects exact named GGUF artifacts through its runtime recipe,
  runs its native server only on container loopback, and uses a small
  manifest-pinned gateway for Let's Infer TLS, API-key enforcement, health,
  and bounded request admission.

Serving configurations and evidence are engine-specific. A checkpoint and
recipe qualified for one engine are not considered qualified for another, and
selecting an engine never permits fallback to another runtime or model format. See
the [engine adapter contract](documentation/concepts/engine-adapters.md).

The coordinator gateway is the stable authenticated OpenAI-v1 boundary for
every placement. Engine endpoints remain private implementation details: vLLM,
SGLang, and llama.cpp expose their native boundary to the coordinator, while
DwarfStar uses its small runtime gateway. `letsinfer benchmark` measures TTFT,
decode and aggregate token throughput, latency, cache reports, and safety
telemetry through the same site endpoint without depending on the engine. It
queries Watchdog over the authenticated private telemetry plane for each exact
workload window, so public one-second timelines do not add inference-path
polling.

## Watchdog

Watchdog is Let's Infer's resident Linux/NVIDIA telemetry, crash-recording, and
engine-protection process. It samples host and NVIDIA state once per second,
including aggregate and per-core CPU, memory, load, filesystem use, disk and
network rates, temperatures, power, GPU utilization, GPU engines, and GPU
memory. It stores CRC-protected fixed-size records in bounded rings:
one-second history for one day, one-minute
rollups for 30 days, and 15-minute rollups for one year. Incomplete or corrupt
records are not returned as valid telemetry.

Watchdog protocol v3 records CPU, GPU, VRAM, and system-RAM clock MHz in every
durable sample. Unsupported clocks use the explicit `4294967295` native
sentinel and are published as `-1`. Only the current protocol and ring schema
are accepted.

The same sample carries the complete gateway counter set: active and queued
requests; received, admitted, completed, failed, cancelled, and retried
requests; exact input, output, and cached tokens; queue, TTFT, and decode time;
prefix hits; and telemetry-write failures. Controller telemetry schema 2
derives one-second request and aggregate token rates from counter deltas and
weighted per-request prefill/decode rates from exact token and timing deltas.
Rates remain unavailable until two valid samples exist and exact-dependent
rates remain `null` when exact token evidence is unavailable. The Mac app
decodes the complete native and aggregate contracts rather than estimating
tokens from streamed text.

Clients use a small length-framed protobuf protocol over mutual TLS. They can
query capabilities, latest state, bounded history, live subscriptions, and
typed Let's Infer runtime/protection status. The static status descriptor is
owner-only and manifest-addressed; Watchdog derives live engine, trip, and
protection state from its own safety state. Authenticated connections expire
after 30 seconds without a complete valid request, including when a peer sends
only a partial frame.
Connections, frames, query scans, and pending samples are all bounded; slow
subscribers receive an explicit gap instead of growing an unbounded queue.
The protocol is engine-neutral, so the same watchdog observes vLLM, SGLang,
llama.cpp, DwarfStar, or a Spark with no running model engine.

The guarded launcher and Watchdog use a private, acknowledged state file to
bind the exact managed container process by container ID, PID, process start
time, host boot ID, and cgroup. Watchdog then holds a Linux pidfd, so a safety
action cannot drift to a replacement process or a different engine. It records
and flushes the current flight data before containment. The release manifest
sets target-specific warning, graceful-stop, and emergency-kill floors, plus
the swap ceiling, PSI stall limits, and cgroup OOM/limit-event actions. The
ordered thresholds are mandatory; core does not supply an implicit runtime
default.
A trip is durably latched; automatic recovery, `start`, and `restart` refuse to
recreate the engine until an operator inspects the record and runs
`letsinfer recover`. Recovery is the only lifecycle action that acknowledges a
protection trip.

`letsinfer.service` is the always-running watchdog. The inference engine is
launched through the separate `letsinfer-engine.service`, while
`letsinfer-recovery.timer` periodically repairs an ordinary missing, exited, or
unhealthy managed container. Docker auto-restart is disabled, leaving systemd
as the single restart authority; OOM and safety-trip states stay stopped. The
watchdog starts independently so it also records engine startup, failure, and
periods when no model runtime is active. It runs as the service account with
systemd hardening, a 24 MiB soft memory threshold, a strict 30 MiB cgroup
limit, no swap, and restart-on-failure. The user unit deliberately stays in
the host user namespace instead of enabling systemd filesystem namespacing;
this is required for its exact same-UID pidfd containment signal to reach the
engine. Other process, syscall, network, privilege, and cgroup hardening
remains enabled. The Python engine launch path is transient and belongs to the
engine unit, so it is not charged to Watchdog's 30 MiB resident budget.

## CLI

After [installing the CLI](documentation/getting-started/installation.md):

```bash
letsinfer setup --name Home
letsinfer site status
letsinfer member list
letsinfer member drain MEMBER_ID
letsinfer member resume MEMBER_ID
letsinfer key create app --model example-model --concurrency 4
letsinfer audit verify
letsinfer pack ./my-runtime --output /tmp/my-runtime.letsinfer
letsinfer hardware --json
letsinfer runtimes
letsinfer install ./my-runtime
letsinfer derive example-model/vllm/dgx-spark --name my-vllm -- --max-num-seqs 4
letsinfer inspect my-vllm --command
letsinfer inspect my-vllm --diff
letsinfer upgrade example-model --dry-run
letsinfer rollback example-model --dry-run
letsinfer engines
letsinfer releases
letsinfer install example-model --catalog ./catalog.json
letsinfer acquire example-model --engine vllm
letsinfer verify example-model --engine vllm
letsinfer status
letsinfer doctor
letsinfer logs --tail 200
letsinfer start
letsinfer restart
letsinfer recover
letsinfer exposure
letsinfer serve example-model --engine vllm --dry-run
letsinfer stop
```

Local runtime repositories are the development path. Published OCI runtime
references must be pinned by digest and require `oras`; mutable tags are
rejected. Model names resolve from installed runtime receipts or an explicit
trusted local catalog or signature-verified remote catalog; Let's Infer core
does not ship a hidden model registry. Importing
an unqualified candidate succeeds without making it the boot service.
Candidate execution remains restricted to explicit
`serve --qualification-mode --evidence-dir ...` launches.

`install` resolves every missing dependency for a qualified or candidate runtime by
default. It downloads and verifies exact manifest-selected model artifacts,
pulls the exact registry image or builds the declared local image, and installs
pinned integration artifacts before activation. `--no-download` makes missing
model artifacts or registry image layers a fail-closed error. `acquire`
remains available for explicit model prefetch without requiring a qualified
serving recipe.

Dependencies stay in their native shared content stores: model revisions and
blobs use the Hugging Face cache, runtime packs use Let's Infer's immutable object
store, verified native integration artifacts use
`~/.local/share/letsinfer/artifacts/sha256`, and image layers use Docker's
content store. Python, system, CUDA, and other engine packages remain inside
the immutable runtime image and never pollute host package managers. Another
runtime referencing the same exact content verifies and reuses it instead of
downloading or rebuilding a copy.

Installation still refuses to activate an unqualified serving configuration.
When the exact image is absent, it can build a packaged runtime-owned `image/`
context at the declared platform; `--no-build-image` requires the image to
exist already. Unqualified import may download or build its isolated, exact
dependencies and creates private local API/TLS material, but remains
non-serving: it creates no systemd units and launches only through explicit
qualification. Let's Infer refuses mutable external base images
and any final image identity mismatch,
reproducibly builds and verifies the architecture-matched Rust wheel from the
pinned Cargo lock and builder image, atomically installs only
manifest-pinned runtime artifacts, creates local TLS/API credentials, writes
private service configuration, builds and tests the core-release Watchdog,
and enables the user systemd services. The
complete core source manifest and exact runtime manifest are independently
validated and atomically staged under a service-bundle identity derived from
both digests in `~/.local/share/letsinfer/control/`; runtime plugins are staged
under a release-and-manifest-specific path. The systemd units execute that
immutable bundle rather than the development checkout.
Python bytecode generation is disabled in both the controller and service unit,
so normal execution does not add cache files to the hash-addressed tree.
The native build requires CMake, a C17 compiler, and OpenSSL 3 development
headers; a missing dependency fails before the active service is replaced.

Reinstall and upgrade replace the configuration and all user units as one
transaction. If activation, health, or the below-30-MiB resident watchdog
check fails, Let's Infer restores the exact prior configuration schema, units,
enablement, and retained bundle before restarting it. `--no-start` refuses to
replace an active service. Hash-addressed bundles make source rollout part of
the guarded install instead of a separate in-place deployment transaction.

The engine unit performs guarded launch and cache prewarm. Docker restart is
set to `no`; the systemd engine unit and recovery timer are the only restart
authority. Ordinary crashes and unhealthy states recover, while an OOM flag or
durable protection trip requires explicit acknowledgement through
`letsinfer recover`. Watchdog
remains resident to capture Spark state independently of engine health. Enable
systemd lingering for the service account so its user service starts without
an interactive login:

```bash
sudo loginctl enable-linger "$USER"
```

`install` checks this before staging or changing service state and fails with
that command when lingering is disabled. Full-device releases also reject a
MIG-partitioned host rather than silently changing which accelerators Docker
exposes.

The engine unit is `Type=oneshot`; after the endpoint becomes healthy its
Python launcher exits. The watchdog unit is `Type=simple` and stays active.
The model server and configured cache tiers remain inside the selected engine
container and are excluded from Let's Infer's 30 MiB resident watchdog budget.

### Inference API access

Installation creates these credentials with private permissions:

- `~/.config/letsinfer/api-key`
- `~/.config/letsinfer/tls/server.key`
- `~/.config/letsinfer/tls/server.crt`
- `~/.config/letsinfer/watchdog/server.crt` and `server.key`
- `~/.config/letsinfer/watchdog/controller-ca.crt` and `controller-ca.key`
- `~/.config/letsinfer/watchdog/local-controller.crt` and `local-controller.key`
- `~/.config/letsinfer/watchdog/controllers.allow`
- `~/.config/letsinfer/site/identity.json` and the coordinator's private
  SQLite authority
- `~/.config/letsinfer/installation.json`

The inference gateway is immediately reachable on the local network at the
coordinator's `.local` name. It uses HTTP on the LAN so OpenAI-compatible
clients need only the endpoint and a site API key; private control, Watchdog,
and engine traffic continue to use TLS or mutual TLS. For example:

```bash
curl \
  -H "Authorization: Bearer $(<~/.config/letsinfer/api-key)" \
  http://homeai.local:8000/v1/models
```

LAN HTTP does not encrypt prompts or bearer keys. Use it only on a trusted
local network. `letsinfer expose` terminates trusted public HTTPS when remote
access is explicitly enabled.

Do not copy an API key into source, manifests, command-line arguments, logs, or
benchmark evidence. `letsinfer key create`, `rotate`, `policy`, and `revoke`
are coordinator-only; a new secret is shown once and only a salted hash is
stored. Revocation takes effect without restarting an engine.

### Controllers

A controller is an app or local tool authorized to observe or manage one
logical site according to its viewer, operator, or administrator role. Pair
the macOS menu-bar controller
without exporting a shared private key:

```bash
letsinfer pair
letsinfer controllers list
letsinfer controllers forget "Desk Mac"
```

`pair` opens one TLS 1.3 listener on port 9769 for at most three minutes and
prints an eight-digit setup code. The Mac creates a non-exportable P-256 key,
then both sides show a second six-digit verification code bound to that exact
key. Let's Infer issues a unique controller certificate only after the user
confirms the codes match. The controller CA key never leaves the Let's Infer host,
and the Mac private key never leaves Keychain or Secure Enclave. The Mac pins
the exact CA-validated server certificate seen during pairing and requires it
on every later Watchdog connection, so changing LAN routes does not change the
installation's security identity.

Controller certificates are operationally non-expiring; X.509 requires a
finite date, so Let's Infer issues them for 100 years and uses the owner-only
controller registry as the real authorization boundary. Re-pairing the same
Mac retains its controller ID, replaces its certificate fingerprint, reloads
Watchdog authorization, and disconnects the old
connection. The Mac's **Forget** action removes its local key and certificate
but retains that stable controller ID for a later re-pair. Use `letsinfer
controllers forget` when immediate server-side revocation is required.

Viewer controllers are read-only. Operators can start, stop, restart, and
explicitly recover placements. Administrators can additionally install
runtimes, create topology plans, manage membership, enable or disable public
inference exposure, and create, edit, rotate, or revoke scoped inference keys.
The native app uses only these bounded controller routes; it has no remote
shell or arbitrary command channel. Create and rotate tokens are displayed
once from ephemeral app memory and are never stored in site views or logs.

`verify` checks control-plane and build-source hashes, the exact model
snapshot, deployed plugin and wheel hashes, and immutable image identity. For
source development on a machine without the installed runtime, use
`--source-only`. `status` reports TLS, authentication, Docker health, restart
policy, Watchdog protection/engine/recovery state, serving capacity, trip latch,
and watchdog memory.
`doctor` performs the stricter operational readiness audit and separately
reports whether the candidate is publishable as a stable release. `logs`,
`start`, `restart`, `recover`, `stop`, and `uninstall` cover the service
lifecycle. `restart` never clears a safety trip; `recover` is the explicit
trip acknowledgement and recovery action.
`stop --name <container>` removes only that managed qualification container
and leaves the resident Watchdog running, while `stop` without a name stops
the configured service lifecycle.
uninstall preserves models, prefix state, runtime caches, evidence, and
control bundles unless an explicit purge option is given. Use
`uninstall --purge-control-bundle` only when the configured release no longer
needs to be retained for rollback.

Release qualification has a separate, explicit launch mode:

```bash
letsinfer serve <model> --engine <engine> \
  --qualification-mode --evidence-dir <new-private-evidence-directory>
```

This is the only path that may launch an unqualified serving configuration. It requires a
caller-selected new evidence directory, records the launch as qualification,
and does not change the manifest's qualified state. Normal `serve` and
`install` remain fail-closed.

The current interface is:

```text
letsinfer setup [--name NAME]
letsinfer site status
letsinfer member list|prepare|join|invite|approve|sync|drain|resume|remove
letsinfer topology show|probe|plan
letsinfer key create|list|show|rotate|revoke|policy
letsinfer audit list|show|verify|export
letsinfer alias list|set|remove
letsinfer pair [--role viewer|operator|administrator]
letsinfer controllers list|forget
letsinfer exposure
letsinfer expose
letsinfer unexpose
letsinfer pack <runtime-repository> --output <artifact.letsinfer>
letsinfer runtimes
letsinfer install <model>
letsinfer derive <runtime> --name <name> [--without=--flag] -- [engine arguments]
letsinfer inspect <runtime> [--command] [--diff]
letsinfer upgrade <runtime> [--dry-run]
letsinfer rollback <runtime> [--dry-run]
letsinfer acquire <model> [--engine vllm|sglang|llama.cpp|dwarfstar]
letsinfer benchmark <runtime> [--c1|--c2|--c4|--c8|--c16] [--32k|--64k|--128k|--256k]
letsinfer benchmark [--json]
letsinfer benchmark stop
letsinfer update [--version <version>]
letsinfer engines
letsinfer releases
letsinfer verify <model> [--engine vllm|sglang|llama.cpp|dwarfstar]
letsinfer serve <model> [--engine vllm|sglang|llama.cpp|dwarfstar]
letsinfer status
letsinfer doctor
letsinfer logs
letsinfer start
letsinfer restart
letsinfer recover
letsinfer stop
letsinfer uninstall
```

## Documentation

The [documentation index](documentation/README.md) covers installation,
runtime-pack design, engine adapters, the runtime and catalog formats, public
CLI workflows, transactional upgrade and rollback behavior, and the resident
Watchdog safety contract.

The first public runtime is DeepSeek V4 Flash with DwarfStar on DGX Spark.
`letsinfer install deepseek-v4-flash` resolves it through the built-in signed
catalog and installs the immutable runtime and engine-image identities.

## Repository layout

- [`core/`](core/) owns the CLI, logical site, gateway, target resolution, and
  runtime orchestration. Focused `site/`, `gateway/`, and `orchestration/`
  subpackages keep those responsibilities separate.
- [`bin/letsinfer-install`](bin/letsinfer-install) installs the immutable
  user-local CLI; [`bin/letsinfer`](bin/letsinfer) is the source-tree launcher.
- [`tools/`](tools/) contains deterministic public-source packaging,
  verification, namespace-audit, and CLI-install release tooling.
- [`documentation/`](documentation/) contains the user, runtime-author, and
  operations guides.
- [`connectors/`](connectors/) contains optional engine-facing integrations.
- [`cache/`](cache/) contains the engine-neutral persistent prefix store and
  cache utilities.
- [`adapters/`](adapters/) contains engine-specific adapters and thin bridges.
- [`benchmarks/`](benchmarks/) contains the engine-neutral authenticated
  OpenAI-v1 matrix, deterministic standard prompt generator/templates, and a
  crash-safe resumable load/soak runner. The selected immutable runtime
  declares the workload; exact prompts and a plan are materialized into each
  evidence directory through its exact tokenizer-count capability. The
  load runner schedules exact
  warmup and measured waves at single or concurrent stream counts, saves each
  wave atomically, keeps immutable per-attempt telemetry, resumes only an
  identical source/manifest/plan/container, and retains percentile latency,
  throughput, full SSE output, host/GPU state, watchdog state, restart,
  health, and OOM evidence. Reusable checked-in plans cover 1K/16K/64K
  single-stream work, 2/4/8-stream concurrency, and sustained soak runs across
  every registered engine. Lower-level development fixtures remain explicit
  inputs and are never packaged as model-specific core assets. Manifest
  connection and context capacities are enforced before a workload starts.
- [`watchdog/`](watchdog/) contains the bounded native telemetry sampler,
  crash recorder, exact-process safety controller, durable ring format,
  rollups, protobuf/mTLS server, and unit tests.
- [`adapters/dwarfstar/`](adapters/dwarfstar/) contains the DwarfStar native
  cache bridge contract and its provenance.
- [`tests/fixtures/`](tests/fixtures/) contains small synthetic contract
  fixtures used only by tests; production discovery never reads them. Release
  manifests, custom images, engine forks, kernels, prompts, and patches belong
  to independent runtime repositories and installable packs.

## Project status

The current source is `0.11.0-rc.8`. The logical-site, gateway, membership,
orchestration, benchmark, Watchdog, and native Mac source suites pass on their
applicable platforms. Core ships no model runtime. DeepSeek V4 Flash with
DwarfStar is the first external, publicly installable DGX Spark runtime; its
runtime pack, engine image, and signed catalog entry use immutable OCI
identities. Qualification and benchmark evidence remain owned by that runtime.
Live replicated or distributed execution requires a second physical member;
evidence never transfers between topology targets.

## License

Let's Infer-authored source code is licensed under `AGPL-3.0-only`; see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Pinned images, model checkpoints,
patched upstream files, and third-party dependencies retain their own licenses
and are not redistributed by this repository.
