# PlacementManager

`li_placement_manager` owns exact resource allocation and the complete atomic
lifecycle of one placement group. It maps opaque `task-N` requirements onto
authenticated nodes, accelerator identities, ports, and an optional verified
RDMA interface without interpreting ranks, stages, TP, PP, or engine flags.

The manager reserves every resource in one optimistic store transaction,
stages each placement, starts runtime-declared phases concurrently, and
publishes exactly one endpoint only after every required placement is ready.
Failure preempts the complete group and follows the symmetric stop, removal,
resource-release, or recovery path.

Schema-8 benchmark context isolation is a Placement lifecycle operation, not a
worker or Application filesystem shortcut. Every runtime launch plan now uses
one stable cache root scoped by exact runtime installation and placement. The
filesystem reset provider snapshots the original owner-only root inode
generation, atomically renames only those group-owned roots, creates empty
roots at the same sealed launch paths, and preserves the original roots for
terminal restoration. It never renames or clears the shared runtime-cache
root. Linux generations reuse protected container PID/start/boot/cgroup
observations; macOS generations reuse exact sealed plist, loaded launchd job,
executable digest, PID, and process-start admission.

`prepare_benchmark_isolation`, `reset_for_benchmark`, and
`restore_benchmark_isolation` form one restart-safe transaction. Reset receipts
bind the reset id, group, ordered context, expected/previous/next aggregate
revisions, store/process generations, completion time, and digest. Restoration
requires the original store inode generation and a fresh complete resident
process before it commits. Store failure leaves the group stopped; start,
process-observation, clock, receipt-drift, or commit failure contains the
unproven group. Exact prepare, reset, and restoration receipts replay after a
Node restart, including cancellation and failed-restoration retry.

NodeManager supplies immutable runtime, node, topology, and credential context.
Each node envelope binds one exact HardwareManager observation ID, boot ID, and
observation time. An explicit bounded admission policy uses the injected clock
to reject future or expired resource and mutable-link facts before identity
generation, reservation, or native staging. That provenance remains on every
durable placement assignment. The executor, store, identity source, clock, and
admission policy are narrow injected capabilities. Deterministic mocks exercise
every lifecycle result in CI; the
NodeManager-owned `DatabasePlacementStore` persists the aggregate and global
resource index atomically. `LinuxPlacementExecutor` orders exact process and
protection transitions, while `FilesystemLinuxPlacementProtectionProvider`
speaks the resident Rust Watchdog descriptor/acknowledgement contract through
owner-checked no-follow files.

Placement also exposes one narrow protected-target capability for Node-owned
Watchdog controller sessions. It returns only an explicitly supplied
placement's acknowledged starting or armed descriptor, including protection
generation and complete PID-reuse-safe process identity. It never selects a
placement group, controller, or session and never returns a tripped or
unbound process.

The Linux process provider now seals Docker argv, environment ownership,
container/image/label identity, endpoint or exec readiness, and procfs
PID/start/boot/cgroup identity before the protected executor runs it. The
separate macOS provider emits an owner-only deterministic plist and uses only
fixed launchctl bootstrap, kickstart, print, and bootout argv. Runtime-specific
plans now enter an atomic private material store with independent durable digest
binding and plaintext-secret exclusion.

Typed runtime execution now resolves exact resource counts into sealed Linux or
macOS plans. Placement credentials live in a separate atomic owner-only store;
only credential IDs, certificate digest, and file paths enter the plan. Engine
credential and private-key buffers redact diagnostics and zero before release.
TLS generation uses fixed shell-free OpenSSL argv, exact DNS/IP SANs, bounded
PEM validation, and private workspace rollback. The RuntimeManager execution-
manifest adapter now consumes only RuntimeManager's verified typed result and
maps it into exact Linux OCI or macOS native inputs. It binds installation,
task, port, device, endpoint-owner, startup timeout, serving, immutable roots,
and protected Engine-protocol environment before the existing sealed-plan
resolver runs. Nine deterministic adapter tests cover both platforms, manifest
and runtime-command launchers, endpoint and exec readiness, long bounded
startup, every task/resource mismatch, missing composition, provider failure,
unsafe platform options, and unsupported embedded-app execution.
