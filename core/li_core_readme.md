# Rust Core

The Rust Core replaces the pre-launch Python implementation directly. There is
no legacy persistence migration or Python execution fallback because no user
state exists to preserve.

The workspace currently contains:

```text
core/
├── interface/       li_core_interface
├── database/        li_database
├── authentication/  li_authentication_manager
├── pairing/         li_pairing_manager
├── hardware/        li_hardware_manager
├── runtime/         li_runtime_manager
├── placement/       li_placement_manager
├── node/            li_node_manager
├── gateway/         li_gateway_manager
├── watchdog/        li_watchdog_manager
├── benchmark/       li_benchmark_manager
├── audit/           li_audit_manager
├── update/          li_core_update_manager
├── cli/             li_core_cli
└── application/     li_core_application
```

The final manager ownership is:

```text
li_core_application
├── NodeManager
│   ├── DatabaseManager
│   ├── AuthenticationManager
│   ├── AuditManager
│   ├── PairingManager
│   ├── HardwareManager
│   ├── RuntimeManager
│   ├── PlacementManager
│   ├── BenchmarkManager
│   └── CoreUpdateManager
├── GatewayManager
├── WatchdogManager (Linux)
└── Rust CLI
```

`li_core_application` is the executable composition boundary; it is not
another manager. `NodeManager` is the domain orchestrator. It owns local
identity, configuration, operations, main/child coordination, the private API,
and durable cross-manager commit ordering. Managers receive immutable context
and narrow capabilities; they do not inspect `NodeManager` or call one another.
Gateway and Watchdog remain independent resident lifecycles and receive only
the narrow owner-authenticated Node-local IPC projections their contracts
require. Neither resident opens the primary Node database or another manager's
store.

The persistent services are `li_node`, `li_gateway`, and Linux `li_watchdog`.
Every node runs `li_gateway`: main mode exposes the public inference API, while
child mode exposes only the authenticated private relay consumed by the main
Gateway. macOS uses launchd instead of a separate Watchdog daemon.

Every workspace manager must enter source with deterministic ordinary,
failure, replay, concurrency, restart, corruption, and rollback coverage as
applicable. The Core release workflow builds and tests the complete workspace
with warnings denied on Linux and macOS. A manager is not considered complete
until its contract has focused deterministic Rust tests or a reviewed contract
change.

PlacementManager now owns exact accelerator, port, and RDMA allocation plus
the atomic stage/start/stop/recover/remove/reconcile lifecycle. It executes
opaque runtime phases concurrently, publishes one endpoint only after every
placement is ready, and contains no rank, TP, PP, collective, rendezvous, or
engine-flag vocabulary. Linux execution additionally binds exact container,
PID, start-tick, boot, and cgroup identity to the resident Watchdog, with
durable trip acknowledgement and disarmed-slot retirement kept inside the
placement lifecycle. Linux container work uses sealed Docker/procfs contracts;
macOS native work uses a separate deterministic launchd contract. Neither path
invokes a shell or lets runtime environment override Core-owned values. Both
plans persist atomically with an independently durable digest and may contain
credential references, never secret material. Placement-scoped secret files
provision and clean up atomically; runtime execution resolves against their
references without moving Engine semantics into Core. TLS generation is a
shell-free OpenSSL provider with private workspaces and bounded PEM contracts.

RuntimeManager now verifies exact schema-6 `runtime.json` and execution-
contract identities from Available installations before exposing typed opaque
tasks. PlacementManager consumes that result through a narrow adapter and
creates platform-specific plans without reading runtime storage or learning
rank, TP, PP, collective, or engine-option semantics. The complete workspace
runs its deterministic manager and composition suites in the ordinary CI
matrix with warnings denied on Linux and macOS.

Runtime installation now has production Rust acquisition mechanisms for public
OCI runtime packs, exact Hugging Face snapshots/GGUF files, and Docker OCI
Engines. Each external operation is shell-free, bounded, explicitly injected,
digest verified, and exercised through deterministic success, authentication,
redirect, corruption, failure, and rollback mocks. Different-version updates
return a typed handoff and keep the previous Available installation authoritative
until NodeManager moves its references.

The public benchmark boundary now has centralized `li_benchmark_` JSON Schemas
for schema-8 contracts, schema-7 OCI records, schema-8 native records, workload
results, and telemetry timelines. Existing wire versions remain unchanged;
canonical hashes, identity, ordered uniqueness, telemetry maxima, and other
cross-field invariants remain enforced by the semantic Core validators.

NodeManager now owns main-authorized child enrollment and the complete
activate/pause/resume/offline/remove state machine. Node, machine, Core
installation, and control-address identities remain globally unique; every
mutation is optimistic and replay-safe, local-main mutation is prohibited, and
concurrent transitions produce exactly one durable winner.

Local main/child reconfiguration requires an injected readiness proof bound to
the exact local identity, previous and target roles, authority identity, and a
five-minute validity window. The local role, counterpart authority, and one
outbox event commit in a single database transaction. Restart, idempotence,
stale time, proof corruption, whole-transaction rollback, and concurrent
one-winner changes are covered.

Every NodeManager entity mutation now commits its secret-free outbox intent in
the same DatabaseManager transaction. Delivery survives restart, replay never
duplicates it, acknowledgment is durable and non-self-emitting, and stale
entity mutations leave no orphan event. The typed private API consumes a narrow
authorization capability and authorizes before dispatching ordinary manager
code; transport serialization remains independently owned.

The private node transport now has one closed `li_node_private_api` schema and
bidirectional bounded JSON codec. One endpoint owns decode, authorization,
ordinary typed dispatch, stable error projection, and response encoding; the
future TLS listener supplies only an authenticated principal and document
bytes. Ten deterministic contracts cover every request and response variant,
real manager mutation/outbox flows, schema identity, unknown-field and value
mutations, duplicate/trailing JSON, size limits, and remote-error bounds.

CoreUpdateManager journals signed Core handoff through prepare, service
snapshot, activation, rebind, stable readiness, commit, and pruning. External
operations are update-ID idempotent, rollback intent is durable before
compensation, journal-write interruption resumes safely, and post-commit prune
failure keeps the verified new Core active as cleanup-pending. Focused
deterministic lifecycle tests and real DatabaseManager adapter tests cover every
provider boundary, rollback failure, restart, conflict, corruption, cleanup
retry, and concurrent exclusion. Production artifact and platform service
providers remain part of daemon/CLI composition.

GatewayManager now owns public-main/private-child admission, authenticated
relay scope, live API-key request/token/concurrency reservations, exact context
gates, deterministic placement-group load balancing, and bounded per-model
FIFO queues. Focused deterministic tests cover durable one-minute usage
reconstruction, prefix/capacity/temperature selection, queue expiry and
cancellation, pre-output sibling retry without double charging, post-output
non-replay, bounded cooldown and learned prefix affinity, every policy limit,
provider failure, corrupt usage, completion cleanup, and concurrent one-winner
capacity. The native `li_gateway` resident now composes the HTTP/TLS listeners,
Engine forwarding, exact token counting, the owner-authenticated local Node
Gateway API for usage, authentication, routes, models, and relay trust, and
atomic Watchdog telemetry-v2 publication from one strict `--configuration`
document. It installs native signal control before worker creation, interrupts
queued waits on shutdown, retains and joins every listener and cadence worker,
and has no Python fallback. Core setup generates the closed configuration and
atomically activates the platform service set; qualified-host evidence remains
a release-lane responsibility.
