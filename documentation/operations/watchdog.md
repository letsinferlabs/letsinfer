# Watchdog

[Back to documentation](../README.md)

Watchdog is Let's Infer's always-running native telemetry, crash-recording, and
engine-protection process. It remains active while an engine starts, serves,
fails, or is absent. The selected runtime does not add another resident
protector.

The launcher binds Watchdog to the exact engine PID, process start time, boot
ID, container ID, and cgroup. Watchdog holds a Linux pidfd, records and flushes
flight data before containment, and cannot drift to a replacement process.
OOM/limit events. The Engine container and every helper started inside it share
one hard memory/swap boundary, an earlier soft pressure boundary, and a higher
OOM score than the host control plane.

Core owns the warning, graceful-reserve, critical-pressure, swap, PSI, and
containment thresholds. Runtime manifests may require more launch or steady-
state headroom, but they cannot reduce Core's 16 GiB host reserve. Before launch
Core also proves that the Engine's hard limit fits below total host memory minus
the effective reserve. This applies identically to qualification and installed
service launches, so a runtime helper or privileged `docker exec` remains inside
the Engine boundary even though that use is unsupported.

The gateway queues new work at the warning floor. Watchdog stops the Engine if
available memory crosses the lower graceful floor, or warning-floor pressure is
combined with swap growth, full PSI, or Engine cgroup allocation pressure. The
emergency floor triggers immediate kill containment without waiting for a
kernel OOM. An observed cgroup OOM kill remains terminal. These conditions do
not treat high utilization by itself as failure: the Engine can use its full
declared budget while the host reserve remains intact. Repeated loss or corruption of
the private protection
descriptor emits one degraded guard event while Watchdog continues monitoring
the already-bound pidfd and cgroup; metadata loss alone neither stops nor trips
a healthy runtime. Every deliberate process exit—including stop, restart,
candidate replacement, benchmark isolation, core rebind, and uninstall—is
gated on an acknowledged disarmed generation. A missing descriptor is rebuilt
as a fresh disarmed generation and acknowledged before the exit proceeds.
A trip and its full last-incident snapshot are synchronously persisted before
containment. The snapshot includes boot/process/cgroup identity, host memory,
swap and PSI, cgroup memory limits and event deltas, process count, and
active/queued requests. It survives Watchdog and host restart; acknowledging a
trip preserves the last incident for `letsinfer status` and `letsinfer doctor`.
Automatic recovery
handles ordinary crashes and unhealthy containers but refuses an OOM or safety
trip until an operator inspects it and runs `letsinfer recover`. `start` and
`restart` never clear a trip. `recover` explicitly clears the safety latch and
starts the affected placement again; controller UIs show that action only when
a trip is actually latched.

`letsinfer.service` owns Watchdog, `letsinfer-engine.service` owns the transient
guarded launch, and `letsinfer-recovery.timer` repairs ordinary engine failures.
Docker auto-restart remains disabled so there is one recovery authority.
The resident binary and its memory/PSI containment policy belong to Core. The
selected runtime contributes measured resource requirements but cannot weaken
that policy.

Watchdog has a protected 24 MiB memory floor/soft threshold, a strict 30 MiB
cgroup limit, and no swap. The node agent and gateway have equivalent bounded
MemoryMin/MemoryLow envelopes. The Engine and transient Python launcher are
outside that resident budget. Telemetry uses bounded CRC-protected rings and a bounded mutual-TLS
protobuf endpoint; slow controllers receive an explicit gap rather than unbounded
buffering.

Core owns a floor and hard limit of 16 concurrent Watchdog telemetry/control
streams. An older runtime declaration such as `max_controllers: 2` therefore
renders as 16 without changing the runtime pack. Each client has two fixed
approximately 65 KiB frames, so the 16-slot table adds about 2.1 MiB plus TLS
state. Against the current 19–22 MiB resident baseline, that bounded table and
16 TLS sessions retain headroom below the strict 30 MiB gate. These are
control-plane streams, not the 128 (or other) inference API connections
declared by a runtime.

Protocol v3 exposes capabilities, latest state, bounded history, live
subscriptions, and typed Let's Infer status over that same authenticated endpoint.
The typed status includes the manifest-bound release, model, engine, runtime,
cache, API port, serving capacity, and live lifecycle/protection state. Static
fields have a manifest-addressed evidence copy plus an atomically replaced
owner-only active projection. Watchdog reloads that projection for each typed
status request, so a runtime switch updates model, engine, version, and capacity
without restarting the resident protector. The installation identity must
remain unchanged, and Watchdog remains authoritative for engine, trip,
container, and protection state. A ready non-subscribed controller must
complete a valid request at least every 30 seconds. A live subscription
refreshes that activity deadline on each successful telemetry write; healthy
listeners therefore stay connected while stalled, half-open, and partial-frame
peers still expire without retaining a bounded slot indefinitely.

Host/cgroup safety checks run every 100 ms; the telemetry/history contract
remains one sample per second. This lets the emergency reserve act without
changing public history resolution or generating unbounded records.

Every one-second sample also carries the complete engine-neutral inference
counter contract: active/queued requests; received, admitted, completed,
failed, cancelled, and retried requests; input/output/cached tokens; queue,
TTFT, and decode time; exact-token coverage; prefix hits; and dropped/failed
usage writes. The main node accepts only signed telemetry schema 2 and
derives aggregate wall throughput plus exact service-time prefill/decode rates
from successive counter windows. During a request, native cumulative usage can
also produce live wall-clock prefill/decode rates before the final timing
record arrives. `aggregate_tokens_per_second` is the normalized node-wide
output rate; `decode_tokens_per_second` retains exact service-time decode when
available. It returns `null` when no exact engine token observation
exists. The Mac decodes all native fields and the full main-node aggregate;
the controller's current group overrides any stale core/node baseline
identity, and historical placements stay collapsed to the newest record per
model. It never estimates token counts from response text.

The node agent feeds the main node from one authenticated native Watchdog
live subscription, so the ten-second durable-ring flush remains a crash/history
boundary rather than a live-visibility gate. The local CLI reads the node
agent's current private aggregate instead of consuming another Watchdog stream
or transferring unused history on every refresh. That controller listener has
eight bounded concurrent request workers, and a slow TLS peer cannot block
other monitoring clients. The live terminal keeps one last verified aggregate
for at most three seconds during a transient reconnect, labels longer outages
as unavailable, records each Watchdog sequence once, and draws complete frames
without a clear-before-draw blank. The Mac keeps a newer direct sample when a
delayed controller aggregate arrives.

Each installation has a random 256-bit installation ID and an owner-only
controller registry. Watchdog accepts a certificate only when both normal CA
validation and the registry's exact SHA-256 fingerprint succeed. `SIGHUP`
reloads the registry and closes connections whose fingerprints were removed.
The registry installation ID must also match the manifest-addressed Watchdog
state descriptor; Watchdog fails closed before listening when either file is
invalid, mismatched, symlinked, non-private, or not owned by the service user.

`letsinfer pair` is a transient enrollment path, not another resident service.
It uses a one-use eight-digit code, a public-key proof, and a separate
six-digit comparison code that binds the human confirmation to the Mac's exact
P-256 key. The setup listener is TLS 1.3, single-worker, size bounded, and
short-lived. It never returns the controller CA key or a controller private
key. Re-pair replaces the prior fingerprint for that stable controller ID;
`letsinfer controllers forget` revokes a controller explicitly.

The installed runtime manifest, Watchdog server, and controller must declare
the same exact protocol version. Any protocol change creates new Watchdog and
control-bundle identities and requires a new release build plus normal
qualification before deployment.
