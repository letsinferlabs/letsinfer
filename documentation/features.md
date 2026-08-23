# Features

[Back to documentation](README.md)

Let's Infer turns local AI hardware into a dependable inference service. You
choose a model; Let's Infer handles the hardware match, exact artifacts,
engine, lifecycle, API, safety, telemetry, and updates.

## Install a model, not a deployment stack

- **Model-first installation.** Run `letsinfer install MODEL`. You never need
  to choose an engine, locate weights, or write a hardware-specific launch
  command.
- **Automatic hardware matching.** Let's Infer identifies the local target and
  selects the fastest qualified runtime from the signed catalog. Use
  `--runtime` when you want to pin an exact candidate.
- **Exact, deduplicated downloads.** The selected runtime brings its pinned
  model revision, Engine OCI, adapter, dependencies, and optional sidecars.
  Content-addressed stores avoid downloading identical content twice.
- **Ready means ready.** A normal install starts inference and waits for the
  API to become usable. `--no-start` is available for staged deployments.
- **One home directory.** Core releases, configuration, secrets, runtime
  packs, models, benchmark evidence, and rebuildable caches live below
  `$LETSINFER_HOME` (normally `~/.local/share/letsinfer`).

## One stable API

- **OpenAI-compatible gateway.** Every supported engine is served through
  `http://<hostname>.local:8000/v1` on your LAN.
- **Engine-independent clients.** Changing from SGLang to DwarfStar—or to a
  future engine—does not change the client endpoint.
- **Local discovery.** The coordinator advertises itself with mDNS, so clients
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

- **Reboot persistence.** Linux user services restore the site, gateway,
  Watchdog, recovery controller, and selected runtime after reboot.
- **Ordinary crash recovery.** The recovery controller can restart a failed
  engine and rebind the stable gateway without relying on an unbounded Docker
  restart loop.
- **Safety stays authoritative.** OOM and protection trips remain latched.
  They are never hidden by an automatic restart; inspect the cause and run
  `letsinfer recover` when it is safe to continue.
- **Atomic lifecycle changes.** Start, stop, restart, recover, install, update,
  upgrade, and rollback use one state model rather than competing scripts.
- **Clean uninstall.** `letsinfer uninstall` previews and confirms removal of
  the complete Let's Infer home. `--keep-models` preserves downloaded weights.

## Live, normalized observability

`letsinfer status` is a continuously refreshed view of the whole request path,
not a container snapshot. It combines the coordinator, gateway, Engine
adapter, and Watchdog into one state plane.

Depending on what the Engine adapter and hardware expose, it shows:

- site, lifecycle, runtime, engine, target, API, and guard state;
- active and queued requests, admission capacity, and live context use;
- aggregate, decode, and prefill throughput, TTFT, and prefix-cache state;
- GPU, unified memory, CPU, NVMe, power, and network activity;
- clocks and GPU, CPU, and NVMe temperatures; and
- bounded recent history without inventing unavailable values.

Engine-specific metrics enter through the versioned Engine protocol. Core and
the UI consume the same normalized meanings, regardless of the engine.

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
- **Immutable identities.** Runtimes pin the Hugging Face revision, Engine OCI
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

- `letsinfer update check` checks core and the selected runtime.
- `letsinfer update` changes core without silently moving your runtime or
  model.
- `letsinfer upgrade MODEL` installs a newer qualified runtime without changing
  core.
- `letsinfer rollback MODEL` restores the retained previous runtime.

Every CLI command can surface a cached update notice. Online checks update one
durable update state; transient network failures do not erase the last known
result. After a verified handoff, obsolete core payloads are pruned while
models and the active rollback target remain intact.

## Benchmarks are a product feature

`letsinfer benchmark MODEL` runs the same model-neutral workload contract for
every runtime:

- canonical code and prose prompts at fixed context and concurrency cells;
- exact Engine-rendered token counting;
- a fresh runtime lifecycle and empty prefix state for every measured cell;
- live progress that survives terminal detachment;
- safe cancellation and restoration of the prior inference state; and
- validated JSON with throughput, TTFT, cache state, utilization, clocks,
  temperatures, memory, NVMe, power, network, and a telemetry timeline.

Benchmark records are bound to the runtime, model, Engine OCI, target,
installation, prompt set, and contract. They are evidence, not a prose claim.

## Sites, controllers, and exposure

- **One coordinator per site.** The coordinator owns the public gateway,
  runtime placement, keys, audit log, and controller policy.
- **Secure controller pairing.** Private controller operations use a
  comparison-code flow, pinned site CA, mTLS identity, and role enforcement.
- **Site-level audit.** Mutating CLI and controller actions carry an explicit
  coordinator, worker, or all-member scope and enter the tamper-evident audit
  log.
- **Optional public inference.** Tailscale Funnel can expose only the inference
  gateway while private control and Watchdog surfaces remain private.

The catalog currently qualifies single-node DGX Spark candidates. Replication
and distributed execution are selected only when a runtime explicitly
qualifies that topology; Let's Infer does not silently reinterpret a
single-device benchmark as a multi-device result.

## A runtime platform, not an engine fork

Core owns the stable gateway, lifecycle, catalog, stores, benchmarking,
security, and Engine protocol. An Engine OCI contains one engine version and
its matching adapter. A runtime candidate can then supply the exact model,
target configuration, kernels, patches, sidecars, cache integration, and
benchmark evidence.

This separation lets runtime authors do deep model and kernel work without
putting model-specific behavior into core. Engine and runtime releases can
move independently whenever the Engine protocol remains compatible.

## Native macOS control

The macOS menu-bar controller discovers nearby sites, securely pairs without
SSH, shows topology and live telemetry, controls lifecycle actions according
to its role, and manages API keys. It is a true telemetry consumer: it keeps
only the bounded window visible in the UI and never persists telemetry history
to disk.

## Next steps

- [Install Let's Infer](getting-started/installation.md)
- [Use the CLI](reference/cli.md)
- [Understand runtime candidates](concepts/runtime-packs.md)
- [Develop an Engine OCI](concepts/engine-adapters.md)
- [Operate Watchdog](operations/watchdog.md)
- [Run benchmarks](../benchmarks/README.md)
- [Use the macOS controller](../apps/macos/README.md)
