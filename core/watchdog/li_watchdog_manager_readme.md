# WatchdogManager

`li_watchdog_manager` is the current Rust ownership slice of the Linux resident
Watchdog. It preserves the existing protection and storage contracts instead
of wrapping the C process. Watchdog remains a daemon because sampling, crash
recording, and pidfd/cgroup containment must survive every CLI caller and
Engine process.

The manager owns durable sample sequence, exact descriptor judgment, warning
deduplication, trip ordering, and containment orchestration. Platform providers
own host sampling, pidfd/cgroup observations and signals, and descriptor,
acknowledgment, and trip files. The manager never infers thresholds and never
turns low memory, swap, PSI, `memory.max`, or an ordinary cgroup OOM counter
into a destructive gate. Only an observed kernel OOM kill or exit of the exact
bound process creates a trip.

Every trip flushes flight data, writes its durable latch, contains the exact
pidfd/cgroup, records the containment result, and flushes again. Disarmed
generations are acknowledged without containment. Samples and events are
idempotent provider records so a failure before the manager advances its
sequence can replay safely.

The Linux sampler now reads bounded procfs and sysfs inputs through injected
native file, clock, filesystem-capacity, and GPU capabilities. It preserves
the version-two record's unknown percentage, temperature, and clock sentinels;
an unsupported optional capability never becomes zero utilization. CPU,
memory, load, root-filesystem, disk, network, cpufreq, system thermal, NVMe
thermal, and interval baselines are implemented. Baselines commit only after
the complete sample succeeds. The GPU boundary accepts one validated aggregate
from a device-specific provider.

The concrete NVML provider loads `libnvidia-ml.so.1` dynamically and never adds
a static NVIDIA link. It negotiates the exact versioned initialization,
enumeration, handle, shutdown, and UUID symbols before initialization; missing
libraries remain explicitly unsupported, while a present library with a
missing required symbol or failed device call fails closed. At most 64 unique
GPU UUIDs are sampled transactionally. Utilization and engine percentages,
temperature, summed power, throttle reasons, graphics clock, and memory clock
retain native unknown sentinels whenever an optional API reports no value;
multi-device aggregation cannot publish a partial or invented-zero sample.

The gateway telemetry provider reads the unchanged version-two C counter
record through an injected owner-only file port. The system port uses a
bounded no-follow descriptor and verifies one regular link, owner-private
mode, descriptor stability, and exact modification identity. Missing and stale
records remain explicitly unavailable. Complete records preserve all 19
fields; duplicate, unknown, malformed, partially replaced, or same-file
counter-regressing records fail closed. A changed device/inode identity is the
explicit gateway-restart boundary and permits counters to restart from zero.

The Linux protection provider discovers at most 64 owner-only slots, parses the
unchanged version-one descriptor, and verifies process start ticks, boot ID,
and cgroup before and after pidfd acquisition. Unsupported pidfd is an explicit
failure and never falls back to signaling a numeric PID. Active slots remain
bound through a transient directory omission. PSI and cgroup event baselines
are transactional; unsupported PSI remains non-destructive, while malformed or
missing required memory and cgroup counters fail closed. Acknowledgements and
trip files retain the exact C bytes. Containment signals the exact pidfd,
escalates once, then revalidates and kills only members of the descriptor-bound
cgroup under fixed polling bounds. A pidfd error cannot skip the final cgroup
containment attempt.

The dependency-free protocol codec owns the exact protobuf-equivalent
Watchdog protocol version three field identities and the existing four-byte
big-endian, 65,536-byte frame bound. Requests and responses are typed, and the
telemetry mapping remains byte-exact with a fixture emitted by the C encoder.
The decoder rejects field zero, unknown fields, duplicate singular fields,
wrong wire types, non-canonical or oversized varints, invalid closed enums,
truncation, trailing frame bytes, excessive batch sizes, and oversized
payloads. History samples and the three declared resolutions are the only
closed repeated fields.

The controller registry parses the unchanged version-one C allowlist, binds an
authorized controller ID and certificate fingerprint to a monotonic session
generation and exact active protection descriptor, and rejects stale,
conflicting, unauthorized, duplicate-process, and over-capacity mutations.
Optimistic revisions serialize future listener writers. Retirement retains a
generation tombstone, so the same session cannot be recreated after a normal
restart. Canonical controller-sorted snapshots include the installation ID,
active bindings, tombstones, revision, and CRC-32; reconstruction rejects
corruption, reordering, unknown fields, identity drift, non-canonical
descriptors, and bound violations.

Production registry construction now loads that exact snapshot before it can
be passed to the native listener. Every create, advance, and retirement first
commits a canonical successor under optimistic predecessor-byte identity; a
failed or conflicting replacement leaves in-memory state unchanged. The
filesystem provider requires an owner-matching, mode-0600, single-link regular
file opened with no-follow. It writes a private create-new temporary file,
synchronizes it, renames it atomically, synchronizes the parent directory, and
reads the final bytes back before the mutation becomes visible. The Rustls/TCP
listener refuses a registry without this restart-safe provider.

Controller trust now sits behind one atomic last-good registry store. Reload
parses the exact owner-only C allowlist, requires the unchanged installation
identity and controller bound, filters sessions whose ID/certificate pair is
no longer trusted, commits the successor restart snapshot, and only then swaps
the live registry generation. Invalid input, identity drift, or persistence
failure leaves both the live pointer and durable bytes unchanged. Listener and
fanout leases revalidate that store generation on every operation, so a valid
reload closes revoked sessions while new connections see only replacement
trust.

The protocol dispatcher now owns every request family in one path: latest,
bounded retained history, initial subscription history, capabilities, ping,
site status, and idle-safe resident status. Resident status is one
authenticated closed projection of the configured Node ID, Core release,
immutable Core source identity, installation ID, and ready lifecycle; it never
requires or exposes a placement, controller, or session. History is emitted
directly in protocol-sized batches through
a cursor instead of accumulating a full response. The concrete filesystem
adapter reads the existing raw, minute, and quarter-hour rings and preserves
their interval and capacity contracts. Absent data, expired ranges, and native
provider failures use closed redacted 404, 413, and 503 responses.

The concrete protocol identity provider derives sampling and flush
capabilities from the exact loaded configuration and uses the initialized
physical-GPU count supplied by the NVML composition. Its public-state adapter
preserves every field in the established version-one C descriptor under the
unchanged 2,047-byte payload bound. The system reader opens the final path with
no-follow, requires the configured owner, private mode, one regular link, and
proves both descriptor and path identity across the complete read. Stale
installation identity, unsafe ownership or links, in-read replacement,
malformed framing, and any unknown, duplicate, missing, or invalid field fail
closed. Live service, engine, protection, trip, and container fields come from
one injected coherent safety snapshot; the identity provider never invents
lifecycle defaults.

The concrete native listener now loads its server certificate, private key,
and controller CA from owner-matching, mode-0600, single-link regular files.
The system provider opens the final path component with no-follow and reads a
fixed maximum from the already-open descriptor. The immutable Rustls policy
allows only TLS 1.3 and requires a CA-verified client certificate; the exact
accepted peer-leaf DER SHA-256 then enters the unchanged controller allowlist
and session-binding path.

The TCP accept loop is nonblocking and owns at most 16 registered worker
sockets and live worker routines. Every handshake has one absolute deadline of at
most ten seconds that progress cannot extend. Capacity rejection, handshake
failure, malformed protocol input, authorization failure, peer closure, and
shutdown all close the exact socket and release its worker, listener, and
controller-registry slots. Explicit shutdown interrupts half-open handshakes
and protocol reads before joining every worker. Native and TLS errors remain
redacted. After authentication the existing listener applies its protocol
read and write deadlines, rejects active-session replay, reads one bounded
frame at a time, and retires the session on every terminal path. Live
subscription leases retain both bounds, revalidate the certificate and
generation before every sample or gap, and reject superseded sessions.
`WatchdogProtocolService` composes this listener with the existing resident
`WatchdogManager` without merging their responsibilities.

The shared resident fanout receives a sample only after a complete manager
tick succeeds. Publication performs no network I/O: it appends to at most 16
independent bounded subscriber mailboxes and coalesces an overflow into one
explicit sequence gap plus the newest sample. Exact sequence replay is
suppressed and backwards sequence publication fails. Each TLS worker drains a
fixed work batch, revalidates its immutable leaf digest and current registry
generation before every gap or sample, and writes under the existing socket
deadline. Slow, failed, unwakeable, closed, and revoked subscribers release
only their own mailbox and lease; they never block sampling or another sink.
Shutdown closes and wakes every mailbox before joining the TLS workers.

Resident startup now reads a bounded JSON configuration with the exact nested
`li_watchdog_configuration` version-two identity. The parser and published
JSON Schema deny unknown or missing fields, require literal bind addresses,
normalized distinct absolute paths, explicit NVML and gateway-telemetry-v2
providers, the fixed one-second sample cadence, bounded flush/controller
limits, and every safety threshold. The same closed document binds the local
Node identity, Core release, immutable Core source identity, and dedicated
owner-authenticated Node protection socket. After beginning one exact session,
Watchdog resolves controller bindings and target-keyed public status only over
that local Node-owned IPC contract; it never opens the Node database, placement
store, or runtime store. The system loader opens the owner-only
mode-0600 single-link regular file with no-follow and proves descriptor
stability across the complete read.

The injected resident cadence samples immediately, advances monotonic
deadlines without catch-up bursts, flushes periodically and on every terminal
path, and rejects early deadline wakes. SIGTERM and SIGINT request one clean
final flush. SIGHUP reloads the complete owner-validated configuration,
requires every immutable value to remain equal, and then invokes the explicit
controller-registry reload capability; configuration drift or reload failure
terminates fail-closed after a flush. Signal callbacks themselves perform no
resident work, and coalesced stop signals retain priority over reload.

The native signal adapter blocks SIGTERM, SIGINT, and SIGHUP before resident
workers start, then owns one named `sigwait` worker. Because signal receipt is
synchronous, no async handler performs locks, allocation, or application work.
The worker coalesces flags and interrupts absolute monotonic waits; stop joins
the exact worker and restores the installing thread's prior signal mask.

The filesystem storage provider owns the existing three fixed rings:
`raw.ring` at one second, `minute.ring` at one minute, and
`quarter-hour.ring` at fifteen minutes. Their production capacities remain
86,400, 43,200, and 35,040 records. Every record is the exact 284-byte,
little-endian version-two C layout with the same reflected IEEE CRC-32. The
checked-in fixture was emitted by the C encoder and is decoded and reproduced
byte for byte in CI. Partial and torn I/O, corrupt CRCs, misplaced records,
wrap gaps, synchronization failures, replay conflicts, and restart recovery
are deterministic test paths. Restart also reconstructs the active minute and
quarter-hour accumulator from retained raw samples so an ordinary daemon
restart does not abandon a partial rollup.

Safety events use the Watchdog-owned `events.ring`, not SQLite or a general
workload database. Its fixed 64-byte records contain only the manager's closed
warning/trip identity, append ordinal, publication marker, and CRC-32. One spare
physical slot lets an interrupted wrapped append preserve the complete logical
replay window. The bounded journal suppresses exact replay across restart,
wraps at its fixed logical capacity, and rejects any nonzero corrupt or
misplaced retained record without rewriting it. Every spare-slot clear,
CRC-valid preparing record, and CRC-valid committed record synchronization
boundary is restart-tested while empty, non-full, and wrapped. Partial writes
do not advance in-memory identity, and an uncertain final commit is
reconstructed before any later replay lookup or append. The obsolete workload
and general metadata API is removed rather than migrated.

The protection provider's durable trip latch is the authoritative safety
state. Watchdog writes it before containment, while `events.ring` is a bounded
diagnostic history. If event publication fails after containment, the tick
fails; the next live observation sees the latch and neither contains the target
again nor invents an event that was not durably published. This exact failure
and restart relationship is deterministic manager-test coverage.
The storage directory and every ring file require the service owner, exact
private modes, a single regular-file link, and no followed final symlink.
Deterministic storage contracts cover creation, replay, restart, capacity wrap,
committed-record and retained-marker corruption, interrupted-candidate
recovery, all three publication synchronization boundaries, final-commit
reconciliation, partial and no-progress writes, unsafe paths, modes, and links.
They run with the existing manager-policy, sampler, protection, protocol,
listener, configuration, telemetry, NVML, and resident-lifecycle suites.

The Linux `li_watchdog` binary is now composed in `li_core_application`. It
accepts only `--configuration <absolute-path>`, loads the strict owner-only
document, begins one local protection session, and delegates controller and
placement/runtime status reads to Node over that socket. It independently
initializes NVML sampling, Watchdog storage and protection, gateway counters,
registry reload, TLS 1.3 mTLS, and resident signal cadence, then runs the
listener and resident together. Either terminal path stops the other owner;
shutdown interrupts and joins the listener, native signal stop performs the
resident's final flush, and no Python or C fallback is available. Linux
platform compilation and installed-service execution remain release-lane
verification responsibilities.
