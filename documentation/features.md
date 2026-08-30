# Features

[Back to documentation](README.md)

Let's Infer turns local AI hardware into a dependable inference service. You
choose a model; Let's Infer handles the hardware match, exact artifacts,
engine, lifecycle, API, safety, telemetry, and updates.

## Install a model, not a deployment stack

- **Model-first installation.** Run `letsinfer model install MODEL`. You never need
  to choose an engine, locate weights, or write a hardware-specific launch
  command.
- **Automatic hardware matching.** Let's Infer identifies the local target and
  selects the fastest qualified runtime from the signed catalog. Use
  `--runtime` when you want to pin an exact candidate.
- **Exact, deduplicated downloads.** The selected runtime brings its pinned
  model revision, Engine distribution, adapter, dependencies, and optional sidecars.
  Content-addressed stores avoid downloading identical content twice.
- **Ready means ready.** A normal install starts inference and waits for the
  API to become usable. Pause and resume are explicit model lifecycle actions.
- **One home directory.** Core releases, configuration, secrets, runtime
  packs, models, benchmark evidence, and rebuildable caches live below
  `$LETSINFER_HOME` (normally `~/.local/share/letsinfer`).
- **Auditable storage cleanup.** `letsinfer node usage` breaks down owned space
  and can remove only reviewed inactive models, rebuildable caches, and
  completed benchmark data. Running models and rollback inputs stay protected;
  a cleaned model is downloaded and verified again on each replica or parallel
  runtime task before that runtime starts.

## One stable API

- **OpenAI-compatible gateway.** Every supported engine is served through
  `http://<hostname>.local:8000/v1` on your LAN.
- **Engine-independent clients.** Changing from SGLang to DwarfStar—or to a
  future engine—does not change the client endpoint.
- **Local discovery.** The main node advertises itself with mDNS, so clients
  and the macOS controller can find it without a hand-maintained IP address.
- **Scoped API keys.** Create, rotate, revoke, expire, and restrict keys by
  model, tenant, application, request rate, token rate, concurrency, and
  context policy.
- **Admission instead of overload.** The gateway and runtime coordinate
  connection limits, dynamic admission, memory pressure, and FIFO queueing.
  By default, a request that can eventually fit waits until capacity becomes
  available or its client disconnects. A request that can never fit receives
  a structured error instead of crashing the runtime.

## Starts automatically. Recovers deliberately.

- **Reboot persistence.** Linux user services restore `li_node`, `li_gateway`,
  and `li_watchdog`; NodeManager's recovery journal and PlacementManager
  restore selected runtime tasks.
- **Ordinary crash recovery.** Node-owned recovery can restart a failed Engine
  and rebind the stable gateway without a separate recovery resident or an
  unbounded Docker restart loop.
- **Safety stays authoritative.** OOM and protection trips remain latched.
  They are never hidden by an automatic restart; inspect the cause and run
  `letsinfer model recover MODEL` when it is safe to continue.
- **Atomic lifecycle changes.** Pause, resume, restart, recover, install,
  update, and rollback use one state model rather than competing scripts.
- **Clean uninstall.** `letsinfer uninstall` previews and confirms removal of
  the complete Let's Infer home. `--keep-models` preserves downloaded weights.

## Live, normalized observability

`letsinfer status` is a continuously refreshed view of the whole request path,
not a container snapshot. It combines the main and child nodes, hardware,
links, every logical model and placement group, gateway, Engine adapters, and
Watchdog into one state plane.

Depending on what the Engine adapter and hardware expose, it shows:

- node, lifecycle, runtime, engine, target, API, and guard state;
- active and queued requests, admission capacity, and live context use;
- aggregate, decode, and prefill throughput, TTFT, and prefix-cache state;
- GPU, physically unified memory or separate VRAM and system RAM, CPU, NVMe,
  power, and network activity;
- clocks and GPU, CPU, and NVMe temperatures; and
- bounded recent history without inventing unavailable values.

Engine-specific metrics enter through the versioned Engine protocol. Core and
the UI consume the same normalized meanings, regardless of the engine.

`letsinfer topology` provides the companion live graph for multi-node systems.
It renders the main-and-child membership tree using each child's authenticated
control-network transport as one continuous trunk whose pulse visits every
child before repeating, then shows model placement groups without exposing a manual
link-probe control. Membership changes appear on the next frame, online/offline
state follows signed fact freshness, interface changes publish each second,
and direct-link evidence refreshes every two seconds.

Platform network setup is provider-owned rather than embedded in topology or
orchestration. The DGX Spark provider prepares NVIDIA-compatible ConnectX
link-local profiles, while future hardware adds independent providers behind
the same generic boundary. If a verified physical link disappears, Core pauses
only placement groups whose immutable plans require that link; unrelated local
models, replicas, children, and gateway routes continue serving. Link evidence
must be restored before an operator can resume the affected placement group, so reconnect
never causes a silent model restart.

## Protection that understands unified memory

Watchdog is an independent, bounded-memory native service. It monitors the
exact protected process and its cgroup rather than guessing from a container
name. Its safety inputs include:

- process identity, health, exit state, and OOM events;
- available and committed unified memory;
- cgroup memory, swap, and pressure-stall information;
- runtime-declared warning and stop thresholds; and
- GPU, CPU, NVMe, thermal, power, and network telemetry.

Normal pressure reduces admission and queues new work. A terminal condition
trips protection, stops unsafe work, records the evidence, and requires an
explicit recovery.

## Reproducible from model to benchmark

- **Signed catalog.** Runtime selection begins from an exact-byte Ed25519-
  signed catalog.
- **Immutable identities.** Runtimes pin the Hugging Face revision, Engine distribution
  digest and configuration, runtime-pack OCI, tokenizer identity, serving
  recipe, and qualification evidence.
- **Deterministic runtime packs.** The release pipeline builds twice and
  requires byte-identical output.
- **No silent fallback.** Unsupported schemas, changed digests, missing
  artifacts, and identity drift fail closed.
- **Traceable releases.** Source manifests, checksums, package inventories,
  SBOM attestations, and benchmark identities bind the installed bytes to the
  reviewed source.

## Core and runtimes update independently

- `letsinfer update check` checks core and all distinct installed placement-group
  releases.
- `letsinfer update core` changes Core without silently moving your runtime or
  model.
- `letsinfer update model MODEL` installs a newer qualified runtime without changing
  core.
- `letsinfer model rollback MODEL` restores the retained previous runtime.

Every CLI command can surface a cached update notice. Online checks update one
durable update state; transient network failures do not erase the last known
result. After a verified handoff, obsolete core payloads are pruned while
models and the active rollback target remain intact.

## Benchmarks are a product feature

`letsinfer benchmark run MODEL` runs the same model-neutral workload contract for
every runtime:

- canonical code and prose prompts at fixed context and concurrency cells;
- exact Engine-rendered token counting;
- a fresh runtime lifecycle and empty prefix state for every measured cell;
- active progress available through `letsinfer benchmark status` after the run
  command returns;
- safe cancellation and restoration of the prior inference state; and
- validated JSON with throughput, TTFT, cache state, utilization, clocks,
  temperatures, memory, NVMe, power, network, and a telemetry timeline.

Benchmark records are bound to the runtime, model, Engine distribution, target,
installation, prompt set, and contract. They are evidence, not a prose claim.

## Nodes, replication, controllers, and exposure

- **One main node.** The main node owns the public gateway, replica placement,
  keys, audit log, and controller policy.
- **Mixed-hardware replication.** Install the same logical model on every
  compatible node. Each node resolves its own qualified runtime while clients
  continue using one endpoint.
- **Capacity-aware routing.** The gateway selects healthy placement groups,
  queues when every replica is full, and retries another placement group only before streaming.
- **Rolling runtime changes.** Upgrade and rollback proceed placement group by placement group and
  restore the exact prior signed release if a replacement fails.
- **Secure controller pairing.** Private controller operations use a
  comparison-code flow, pinned node CA, mTLS identity, and role enforcement.
- **Node-level audit.** Mutating CLI and controller actions carry an explicit
  main, child, or all scope and enter the tamper-evident audit
  log.
- **Optional public inference.** Tailscale Funnel can expose only the inference
  gateway while private control and Watchdog surfaces remain private.

Replication reuses independently qualified target runtimes. Distributed TP/PP
execution requires a runtime that explicitly qualifies the complete topology;
Let's Infer never reinterprets a single-device benchmark as a parallel result.
Core supplies generic allocation, verified connection facts, phased launch,
atomic recovery, and one endpoint per complete group. Runtime authors retain
full control over ranks, stages, transports, kernels, and engine configuration.

## A runtime platform, not an engine fork

Core owns the stable gateway, lifecycle, catalog, stores, benchmarking,
security, and Engine protocol. An Engine distribution contains one engine version and
its matching adapter. A runtime candidate can then supply the exact model,
target configuration, kernels, patches, sidecars, cache integration, and
benchmark evidence.

This separation lets runtime authors do deep model and kernel work without
putting model-specific behavior into core. Engine and runtime releases can
move independently whenever the Engine protocol remains compatible.

## Native macOS control

The macOS menu-bar controller discovers nearby nodes, securely pairs without
SSH, shows topology and live telemetry, controls lifecycle actions according
to its role, and manages API keys. It is a true telemetry consumer: it keeps
only the bounded window visible in the UI and never persists telemetry history
to disk.

## Next steps

- [Install Let's Infer](getting-started/installation.md)
- [Use the CLI](reference/cli.md)
- [Understand runtime candidates](concepts/runtime-packs.md)
- [Develop an Engine distribution](concepts/engine-adapters.md)
- [Operate Watchdog](operations/watchdog.md)
- [Run benchmarks](../benchmarks/README.md)
- [Use the macOS controller](../apps/macos/README.md)
