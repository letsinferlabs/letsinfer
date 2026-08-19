# Watchdog

[Back to documentation](../README.md)

Watchdog is Let's Infer's always-running native telemetry, crash-recording, and
engine-protection process. It remains active while an engine starts, serves,
fails, or is absent. The selected runtime does not add another resident
protector.

The launcher binds Watchdog to the exact engine PID, process start time, boot
ID, container ID, and cgroup. Watchdog holds a Linux pidfd, records and flushes
flight data before containment, and cannot drift to a replacement process.
It monitors Spark's unified-memory availability, swap, memory PSI, and cgroup
OOM/limit events.

Every runtime manifest must declare its target-specific warning,
graceful-stop, emergency-kill, swap, PSI, and containment thresholds. Core
requires the warning floor to cover the runtime admission reserve and requires
strictly ordered warning, graceful, and emergency floors; it does not infer a
missing runtime threshold. The native executable likewise has no threshold
defaults and refuses to start unless all manifest-derived memory, swap, PSI,
state-failure, and containment values are supplied. A trip is durably latched. Automatic recovery
handles ordinary crashes and unhealthy containers but refuses an OOM or safety
trip until an operator inspects it and runs `letsinfer recover`. `start` and
`restart` never clear a trip. `recover` explicitly clears the safety latch and
starts the affected placement again; controller UIs show that action only when
a trip is actually latched.

`letsinfer.service` owns Watchdog, `letsinfer-engine.service` owns the transient
guarded launch, and `letsinfer-recovery.timer` repairs ordinary engine failures.
Docker auto-restart remains disabled so there is one recovery authority.
The resident binary belongs to core, while its active memory/PSI containment
thresholds come from the selected immutable runtime. Core updates preserve
those exact thresholds for compatible runtimes; they never replace them with a
generic model-independent memory floor while inference is restored.

Watchdog has a 24 MiB soft memory threshold, a strict 30 MiB cgroup limit, and
no swap. The engine and transient Python launcher are outside that resident
budget. Telemetry uses bounded CRC-protected rings and a bounded mutual-TLS
protobuf endpoint; slow controllers receive an explicit gap rather than unbounded
buffering.

Protocol v3 exposes capabilities, latest state, bounded history, live
subscriptions, and typed Let's Infer status over that same authenticated endpoint.
The typed status includes the manifest-bound release, model, engine, runtime,
cache, API port, serving capacity, and live lifecycle/protection state. Static
fields come from an owner-only manifest-addressed descriptor; Watchdog remains
authoritative for engine, trip, container, and protection state. A ready controller
must complete a valid request at least every 30 seconds, so a half-open or
partial-frame connection cannot retain a bounded controller slot indefinitely.

Every one-second sample also carries the complete engine-neutral inference
counter contract: active/queued requests; received, admitted, completed,
failed, cancelled, and retried requests; input/output/cached tokens; queue,
TTFT, and decode time; exact-token coverage; prefix hits; and dropped/failed
usage writes. The coordinator accepts only signed telemetry schema 2 and
derives aggregate wall throughput plus weighted exact prefill/decode rates from
successive counter windows. It returns `null` until the necessary interval or
exact-token evidence exists. The Mac decodes all native fields and the full
coordinator aggregate; it never estimates token counts from response text.

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
