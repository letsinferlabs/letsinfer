# NodeManager

`li_node_manager` is the Rust Core composition owner for local identity,
configuration, operations, node coordination, and the private control API.
The current slice implements immutable local-identity initialization, the
complete pending/running/terminal operation lifecycle, and main-owned child
enrollment plus activate/pause/resume/offline/remove transitions over
`DatabaseManager`.

Persistence records are private adapters. Shared snapshots remain in
`li_core_interface`. A state change returns a domain event only after a new
database commit; idempotent replays return the original revision without a
duplicate event.

Model updates and rollbacks retain the exact displaced runtime installations.
The durable lifecycle journal binds removed source groups, deterministic
restoration groups, exact node/install assignments, and pre-command intent.
User rollback selects the latest successful same-node, same-candidate,
same-target predecessor with different immutable source/version bytes and
never re-resolves the catalog. Failed replacement activation reconstructs the
current runtime first; incomplete compensation is retried by resident recovery,
not exposed as a user rollback mode.

Pairing application composition may pass one caller-owned `DatabaseTransaction`
to child enrollment. NodeManager verifies the exact shared database authority,
main/child identity, pending state, global uniqueness, and replay identity, then
appends its private Node record and one outbox event before the single commit.
It never persists pairing or authentication records through a second path.

Eight focused coordination contracts prove main-only authority, global node,
machine, installation and address uniqueness, replay, restart reconstruction,
every valid/invalid transition, local-main protection, and concurrent
optimistic conflict. Six durable-outbox contracts atomically bind entity state
and event intent, suppress replay duplicates, reconstruct after restart,
acknowledge without self-emission, and roll back stale paired writes. Five
private-API contracts prove authorize-before-dispatch ordering, every typed read
and mutation, outbox delivery, generic denial, replay, and exact manager-error
preservation. Eight local-role contracts prove exact readiness binding, atomic
main/child authority replacement, restart, stale-time rejection, idempotence,
rollback, invalid destinations, and concurrent one-winner mutation. Three
CoreUpdateStore contracts add complete journal persistence, replay/conflict,
restart, and semantic-corruption rejection. Eight local-listener contracts add
the exact native
frame, fragmentation, truncation, timeout, zero-progress, oversized-document,
UID, endpoint-failure, worker-bound, socket-safety, cleanup, restart, and
redaction boundaries. Together with the audit composition below, NodeManager
has focused deterministic coverage across its native boundaries.

Pairing-owned trust resolution remains behind narrow injected capabilities;
NodeManager never reads PairingManager or application implementation types.

`DatabaseAuthenticationStore` is the first composition adapter. It persists
only salted verifier and policy records, uses atomic database rotation, and
never writes the bearer secret.

`DatabaseRuntimeInstallationStore` round-trips the complete runtime, model,
Engine, evidence, lifecycle, and failure identity. `DatabasePlacementStore`
commits each placement aggregate together with one optimistic resource index,
so GPUs, ports, and RDMA interfaces cannot be double-allocated across
concurrent groups or process restarts.
`NodeGatewayNativeTargetProvider` closes the selected-route-to-transport
boundary for local Engines. It reloads the exact running placement aggregate,
requires the route endpoint to remain unchanged, verifies the endpoint
placement's provisioned bearer and CA credential identities, and returns only
reference paths plus the endpoint-owned token-count contract. Remote routes
delegate exact group, child-node, and address identity to
`PersistedNodeGatewayRelayTargetProvider`. It requires live active main/child
NodeManager state to match one monotonic, unexpired, non-revoked pairing-trust
generation in `DatabaseManager`; full node, machine, installation, address,
membership-receipt, bearer, CA, main leaf, and child leaf identities are bound
before any native file is read. The database stores paths and public digests,
never bearer or private-key bytes. The child relay always replaces the
Engine-owned token path with Core's fixed private `/li/token-count` contract.
Four deterministic contracts cover the ordinary persisted path, exact replay
and terminal revocation, ambiguous references, and the meaningful stale,
foreign, changed, inactive, missing, and revision-replay failures.

The Node relay result retains the expected child leaf certificate reference
and DER SHA-256. `GatewayNativeTarget` carries that digest through the native
client, which completes TLS 1.3 authentication and verifies the exact peer leaf
before sending HTTP request bytes. The site CA proves membership authority;
the leaf pin proves the selected child identity.

`DatabaseCoreUpdateStore` reconstructs the complete resumable Core handoff
journal and rejects incomplete phase/receipt combinations.
`DatabaseCoreUpdateServiceSnapshotStore` separately persists the complete
pre-mutation resident-service and runtime-control snapshot. Its content-bound
receipt reconstructs across restart, divergent concurrent snapshots have one
winner, semantic corruption fails closed, and native database failures cross
the manager boundary only as a redacted availability error. The dedicated
homogeneous collection avoids decoding update journals and service snapshots
through the same record type.

`NodeGatewayModelInventoryProvider` projects only active-main model services
that are running and still pass GatewayManager's exact health, memory-pressure,
cooldown, and immediate-capacity gates. It does not duplicate admission policy,
invent aliases, or reserve capacity. Three deterministic contracts cover the
ordinary projection, child/provider/time failures, and ambiguous persisted
model identities before any Gateway call.

NodeManager now accepts the narrow `NodeHardwareObservationProvider` result
from HardwareManager, persists one bounded latest observation per node, and
atomically advances the local node pointer plus one outbox event. The private
record round-trips every accelerator vendor, memory, compute, telemetry, and
mutable interconnect union; foreign identity, backward time, stale revision,
and semantic corruption fail closed. Seven focused contracts cover full
roundtrip/replacement, restart, replay, provider failure, closed unions,
concurrent one-winner mutation, and corrupt persistence.

`NodeDaemon` is the first resident composition slice. One tick treats hardware,
benchmark polling, and durable delivery independently, delivers pending events
at least once by deterministic event ID, and acknowledges only after the
injected provider succeeds. Failure leaves exact state pending for a later tick
instead of terminating the control plane. Five focused tests cover ordinary
ordering, independent hardware and benchmark failure, delivery retry, and
private-outbox ownership.

`NodeConfiguration` loads the closed `li_node_configuration` version-2 JSON
document through one bounded no-follow descriptor. The source must be an
owner-matching `0600`, single-link regular file whose identity remains stable
through the read. The document fixes the shared database, platform-native
hardware inputs, NodeDaemon cadence, the local Unix socket, the remote TCP bind,
worker limits, operation deadlines, and exact owner-only TLS input paths.
Unknown fields, alternate schema identities, unsupported platform/architecture
combinations, relative paths, zero ports, and values outside native listener
bounds fail closed. Five focused contracts cover exact mapping, closed document
and semantic mutations, every unsafe metadata class, real symlink/hard-link
rejection, and the checked-in JSON Schema.

`NodeResident` owns one complete local listener, remote listener, and bounded
NodeDaemon cadence thread. Start acquisition is ordered and partial failure is
rolled back in reverse order. Its handle retains every native lifecycle owner,
uses one injected wakeable run-control signal, joins the cadence thread, and
attempts both listener shutdowns even after an earlier failure. Four focused
contracts cover main and child roles, durable restart reconstruction, each
partial-start boundary, overlap rejection, signal shutdown, loop failure, and
complete cleanup after listener failures.

Logical model services are now NodeManager-owned durable state rather than a
Gateway or PlacementManager projection. Main-only creation starts stopped and
empty; explicit attach/detach operations own independent placement-group
membership; running requires a group; removal requires every group detached;
and removed services are terminal. Six focused tests cover creation/restart,
logical-model uniqueness, complete lifecycle ordering, invalid/stale changes,
concurrent one-winner attachment, and corrupt persistence.

`NodePrivateEndpoint` owns the closed `li_node_private_api` v2 wire boundary.
It decodes bounded documents, authorizes before ordinary typed dispatch, and
encodes success or stable remote failure responses. The listener does not own
manager policy and the in-process manager API does not serialize.

Version 2 nests the eight atomic Gateway capabilities under one local-only
request. Gateway state and credential references remain local because Node is
their sole database owner; controller and paired-node transports reject the
whole nested request before authorization. Bearers are accepted only as
bounded request inputs and never appear in responses, ordinary debug output,
or error language.

The same pre-release private API exposes four authenticated, active-main-only
pairing actions: open, enroll, approve, and status. `NodePairingApiPort` is the
only dependency; its request and response values close mode, identity,
lifetime, proof, approval, public credential, validity, and lifecycle shapes
without importing PairingManager. Binary values use canonical bounded base64,
and diagnostics redact proof, setup/comparison codes, certificates, and
signatures. Four API contracts prove complete routing, authorize-before-port
ordering, role denial, and stable redacted failures. The private transport
matrix covers every closed request and response variant plus malformed,
alternate binary, benchmark selection/plan/lifecycle, and secret-bearing
mutations. The checked-in private API schema owns the same closed union.

The private API also exposes active-main-only benchmark preview, start,
active/read, and stop commands through `NodeBenchmarkApiPort`. Preview and
start accept only one logical model and canonical public workload axes;
Application resolves immutable runtime, placement, and contract identities
before `BenchmarkManager` can mutate state. `NodeBenchmarkCoordinator` owns the
real `DatabaseBenchmarkStore`, sole-active exclusion, restart polling, and
secret-free plan/status projection. The resident loop consumes only
`NodeBenchmarkPollingPort`, so benchmark work cannot acquire hardware or outbox
ownership. Restart tests prove exact subject binding, replay-secret exclusion,
progress continuation, cancellation, restoration, telemetry sealing, and
one-active-job behavior.

Community verification uses a separate Node-owned candidate handoff journal.
It acquires only the preparation-verified resident `RuntimeCandidate` closure,
persists no artifact paths, and commits a durable phase before every baseline
resource mutation. The candidate group has a deterministic private identity
and is never attached to `ModelService`, so Gateway cannot publish it. After
exact acquisition, `prepared_subject` resolves the candidate execution,
benchmark, and target contract digests from its verified runtime manifest while
the baseline remains authoritative. Activation revalidates that same subject
against the running private group and exposes only its endpoint. Every success,
failure, cancellation, and restart path removes the candidate group, restores
the original node/device/port/runtime assignment under a distinct deterministic
group identity, preserves stopped intent, updates the service only after the
restored group is authoritative, and retries candidate-byte cleanup. The
current native request provider is single-node; multi-node handoff fails closed
until Core persists the exact verified mutable-link facts needed to prove the
restored topology.

The existing remote private listener intentionally admits only an already
paired mTLS leaf, so it cannot bootstrap an unpaired candidate. Production
composition adapts the application pairing owner to `NodePairingApiPort` and
starts a separate transient pairing listener on the discovery port. That
pre-authenticated boundary validates the live invitation, observed peer
address, and candidate proof before invoking `enroll`; it remains separate
from and never weakens the remote leaf-to-credential resolver.

`NodePrivateLocalServer` is the separate owner-only native path for a process on
the same node. Its Unix-domain socket requires an owner-controlled directory,
is installed with mode `0600`, authenticates the kernel peer UID, and maps only
that UID to the manager's exact local `NodeId`. It never substitutes local UID
authentication for the separate remote mTLS and pairing boundary. A local
connection carries exactly one request and one response before close. Each
frame is a four-byte unsigned big-endian document length followed by one
compact `li_node_private_api` schema-version-2 JSON document. Lengths `1`
through `1,048,576` are accepted; zero, larger, incomplete, slow, or
zero-progress frames fail closed. Complete-frame read and write deadlines,
bounded workers, nonblocking acceptance, clean shutdown, exact stale-socket
checks, and device/inode-bound cleanup prevent an individual local connection
from taking listener ownership.

`NodePrivateRemoteServer` is the distinct TCP path for authenticated child/main
traffic. It admits only TLS 1.3 connections carrying a client certificate under
the configured client authority, hashes the authenticated peer leaf, and asks
an injected pairing-owned resolver for the one exact `CredentialId` before it
reads or dispatches a request. A different certificate under the same authority
has no credential fallback. The existing `NodePrivateEndpoint` remains the sole
v2 document decoder, authorization owner, and manager dispatcher. Remote frames
reuse the local contract exactly: one four-byte unsigned big-endian length and
one `1..=1,048,576` byte compact JSON document in each direction, then close.
Handshake, complete-frame read, complete-frame write, and close-notify use hard
absolute deadlines; the nonblocking listener has a fixed worker bound and joins
its workers during clean shutdown. Server certificate, private-key, and client
authority inputs must be owner-only `0600`, no-follow, single-link regular files
whose descriptor identity remains stable across a bounded read. Diagnostics
retain only closed transport error classes.

Production daemon composition supplies the bind address, private TLS file
references, time and worker bounds, and one tagged principal resolver. The TLS
root set accepts the distinct paired-Node and controller authorities without
merging their stores or identities. Peer requests retain relationship-scoped
authorization; controller requests retain exact certificate, active-state,
lifetime, role, and local-only action checks.

`NodeWatchdogSessionAuthority` now implements Watchdog's concrete
`WatchdogControllerSessionProvider`. It atomically persists one controller
record and one direct certificate index through the shared DatabaseManager.
Every active replacement advances the nonzero session generation by exactly
one; certificate rotation terminally retires the old digest in the same
transaction; revocation advances one final generation and cannot be reversed.
The session selects one exact placement-group and placement pair and pins the
SHA-256 of its complete process-bound protection descriptor. Resolution re-reads both durable indexes,
the exact Placement aggregate, the acknowledged protection descriptor, and the
live process identity before returning `WatchdogProtectedEngine`. Missing or
mismatched placement identities, inactive group/task state, durable trips, PID reuse,
process replacement, stale generation, and optimistic conflicts fail closed.
No active placement group is selected by convention. Eleven focused contracts
cover restart, exact binding, certificate rotation, revocation and replay,
generation replay, concurrent one-winner advancement, target failure classes,
stopped/replaced processes, the checked-in persistence schema, and the exact
binding-keyed protocol identity projection.

`NodeWatchdogProtocolIdentityProvider` revalidates that same target, its running
aggregate, healthy endpoint, current protection phase, and RuntimeManager
projection before returning `site_status`. RuntimeManager supplies the verified
bounded Engine ID explicitly; Node never parses the opaque candidate name.
Provider failure, runtime disagreement, or a changed target fails closed, and
multiple running groups never create a global "first active" status.

The local `li_node_protection_api` schema version 2 adds exactly two
Watchdog-executable-only reads over the existing owner-authenticated protection
socket: `resolve_controller_binding` accepts one controller certificate
SHA-256, and `read_site_status` accepts the resulting complete process-bound
binding. Node remains the sole owner of session, placement, runtime, and
protection state; the IPC contract exposes only the validated binding and
public site-status projections. It does not expose a database, accept a Node
identity from either new request, or provide a schema-version-1 compatibility
path. Gateway-role connections remain confined to `read_gateway_snapshot`.

`DatabaseAuditStore` maps the native audit chain onto four explicit database
collections for state, events, checkpoints, and replay identities. One
optimistic transaction commits the head, event, optional checkpoint, and
replay receipt. Reads sort by
event sequence rather than record identity and fail closed on missing, orphaned,
revised, duplicated, or semantically inconsistent records. NodeManager supplies
its local node identity to `AuditManager`; the OpenSSL checkpoint provider keeps
only private/public key paths and passes signing to a narrow native capability,
so private key bytes never enter NodeManager or the database.

Domain managers currently commit through their own DatabaseManager calls, so a
later AuditManager call cannot honestly share the same SQLite transaction.
`NodeAuditComposition` therefore declares
`IndependentDatabaseCommit` and returns a typed recovery error when an already
committed domain mutation cannot be audited. Full command-handler composition
must either pass a shared transaction fragment through the owning manager or
recover that explicit gap; it must not report cross-manager atomicity. Twelve
focused deterministic contracts cover append/checkpoint/replay/restart,
optimistic and replay conflicts, semantic corruption, local-identity
composition, the explicit audit gap, reference-only key use, shell-free native
execution and cleanup, and hard-link rejection.
