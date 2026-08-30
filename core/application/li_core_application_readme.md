# Core application

`li_core_application` is the process-composition boundary for the Rust Core.
It does not create another manager. It supplies native process dependencies to
the existing managers, CLI, and resident daemons.

The first completed slice is `CoreCommandAuditPort`. It binds the CLI's
pre-execution and terminal hooks to the local node's `AuditManager`, checks the
complete ledger before a manager may execute, opens one unpredictable
process-local marker, and appends one secret-free terminal event according to
the command registry's audit policy. A failed append remains open and fails
the command instead of claiming that the mutation and audit record committed
atomically.

`CoreProcessLayout` defines the stable process boundary shared by installation,
Core update, and native service generation. Linux owns `li_node`, `li_gateway`,
and `li_watchdog`; macOS owns `li_node` and `li_gateway` under launchd. Every
resident receives exactly `--configuration <absolute-path>`. Binary paths are
resolved only beneath one immutable Core installation, mutable configuration
stays under a distinct private root, and neither resolution nor service
generation may discover a fallback executable.

`CoreServiceDefinitionProvider` projects that same command into deterministic
owner-only systemd user units or launchd agents. It escapes systemd specifiers
and XML text, emits argument arrays rather than shell commands, fixes restart
and privilege boundaries in one place, and returns the SHA-256 identity used
by service snapshots and readiness verification. Linux residents restart
independently without `Requires`, `PartOf`, or `BindsTo` coupling. Startup is
ordered Node, Watchdog, then Gateway through `Wants` and `After`, so the public
listener is last without turning one resident restart into a group restart.
The established Node, Gateway, and Watchdog memory, task, descriptor, restart,
stop, and scheduling envelopes remain explicit per-process profiles. Only Node
receives netlink access. macOS agents are always resident, explicitly
re-enabled during replacement, and write to the exact log paths supplied by
`CoreProcessLayout`. Native plist syntax is checked with Apple's verifier on
macOS, and systemd syntax is checked by the Linux test lane.

`ApplicationCoreUpdateServiceControl` supplies caller-selected native service
facts and mechanics over those exact definitions. It observes resident state,
applies requested bindings and activity, verifies loaded and active definition
identities within the caller's deadline, and reconstructs the exact previous
definition during rollback. `PlatformCoreUpdateServiceProvider` combines that
control with durable snapshot receipts. CoreUpdateManager owns the
role-appropriate service set, main/child Gateway mode, Linux Watchdog policy,
and stable-readiness decision. The control intentionally has no
runtime-execution port: RuntimeManager owns installations, PlacementManager
owns execution, and candidate compatibility belongs in pre-mutation admission.
The native supervisor remains an explicit injected port, so every forward,
readiness, failure, and restoration path is deterministic in CI without
weakening production behavior.

`DatabasePeerCredentialStore` composes AuthenticationManager's exact
certificate-leaf resolver with the same `DatabaseManager` owned by the Node
process. Peer credentials have their own `peer_credentials` collection and a
closed schema keyed by the exact lowercase leaf SHA-256; they never share the
API-key record collection. Reads address one digest directly and admit at most
one credential plus one duplicate sentinel, so lookup never scans an unbounded
collection. Creation and replacement preserve DatabaseManager idempotency and
optimistic revisions, re-read the current record before reporting success, and
fail closed on duplicate, mismatched, malformed, or divergent replay state.

`CoreNodePrincipalResolver` is the only bridge into Node's mTLS transport.
It delegates the complete active/revoked/expired/rotated decision to
AuthenticationManager and returns only the exact active `CredentialId`; every
denial and provider failure becomes Node's fixed redacted peer rejection. Five
focused composition tests cover active resolution, idempotent replay and
restart, missing and unavailable state, duplicate/corrupt persistence,
lifecycle denial, revision conflict, and preservation of the prior identity.

Native Node composition also supplies AuthenticationManager's durable
`DatabaseControllerStore`. Linux loads the existing dedicated Watchdog
controller authority through owner-only, no-follow, single-link files and
proves that its certificate and private key form a currently valid client
chain before enrollment is available. Controller leaves retain canonical DER
identity, exact P-256 public-key binding, client-auth usage, controller URI,
and an authority-bounded lifetime. The CLI constructs the short-lived TLS
pairing provider only for a main with that complete authority; macOS and child
nodes fail closed without probing unrelated commands.

Controller activation is a serialized two-phase boundary: persist issued
state, atomically project the complete active authorization set, reload the
Watchdog's last-good registry, then activate the durable controller. Revocation
removes live authorization first and restores it if durable revocation fails.
Exact retries heal an interrupted projection without duplicating controller
state. The remote TLS root set keeps the paired-Node and controller authorities
separate; `CoreNodePrincipalResolver` returns a tagged peer or controller,
revalidates the exact active DER fingerprint on every request, and never falls
back from a recognized but invalid peer credential to controller authority.

`DatabasePairingStore` persists PairingManager's versioned invitation, failed
attempt, verified child, exact leaf digest and validity, and approval state in
the dedicated `pairings` collection. `CorePairingEnrollmentCoordinator` is the one
cross-manager commit owner. LAN and ConnectX atomically replace the open pairing,
create the active peer credential, create the pending child Node, and append its
outbox event. Remote proof atomically stores only pending pairing and pending
credential state; that credential is unauthorized and no child Node exists.
Explicit approval atomically activates both records and creates the Node/outbox.
Every path uses the exact same `DatabaseManager` instance, preserves optimistic
revisions and database replay, and rejects expired, revoked, rotated, foreign,
or divergent material without a partial enrollment. Four focused real-database
contracts cover active apply/replay, restart-safe pending approval, concurrent
approval replay without a duplicate outbox event, terminal lifecycle denial,
expiry, and late-transaction conflict rollback across every staged record.

`SystemCoreNativeServiceSupervisor` implements the resident-service port with
the canonical `/usr/bin/systemctl` or `/bin/launchctl` and fixed shell-free
arguments. Linux receives only the generated current-user runtime and D-Bus
addresses after the inherited environment is cleared. The supervisor reads and
atomically replaces only owner-bound `0600`, single-link, no-follow definitions,
bounds time and combined output, parses a closed state vocabulary, and retries
only launchd's exact transient bootstrap diagnostic within a fixed injected
wait bound. Missing restoration is idempotent; inconsistent
definition/supervisor state fails closed instead of being normalized silently.

Initial Rust service activation remains intentionally separate from ordinary
CoreUpdate and uses one crash-safe transaction. Linux snapshots only the
current Rust Node, Watchdog, and Gateway service identities; macOS snapshots
only the current Rust Node and Gateway launchd identities. Definition bytes,
modes, and enablement or load state are restored exactly if that same setup
attempt fails. Linux preserves the observed `failed` fact in its durable
snapshot, but restoration maps both prior inactive and failed units to safe
non-running intent; only services that were active before the attempt restart
in dependency order. There is no Python/C Core migration or legacy service
adoption path.

Before snapshot authority exists, setup proves the source-manifest identity and
exact owner, mode, and hash of every resident binary. It loads each process's
closed configuration through its production parser, validates the canonical
native service directory, and requires the effective user's systemd bus plus
lingering or launchd GUI domain. The production composition creates only
missing private canonical service and cutover directories, then wires the
native supervisor, durable store, cutover host, preflight, and readiness
capabilities together. Readiness has one injected monotonic 90-second deadline
including command time, requires five complete observations, binds the native
manager's loaded executable and arguments to the exact definition, and requires
a concrete role-health adapter. Linux compares `MemoryCurrent` strictly below
the same `MemoryMax` used to emit the unit. Unsupported resident health never
commits a cutover.

The owner-private cutover record uses the closed
`li_core_service_cutover` version-one schema and the crash-safe phases
`prepared`, `restoring`, `restored`, and `committed`. Restoration intent is
durable before native mutation. Replay from `restoring` completes restoration;
replay from `restored` performs cleanup only; neither path retires restored
services. A matching committed replay verifies readiness without reinstalling
anything. Store writes reconcile the authoritative record after errors around
atomic activation or directory synchronization, and exact-record cleanup is
required before rollback reports completion.

`li_watchdog` is the fully composed Linux safety resident. Its executable
accepts exactly `--configuration <absolute-path>` from `CoreProcessLayout` and
has no Python or C fallback. Composition loads the strict Watchdog document,
the owner-authenticated local Node protection API for its exact session and
public status, explicit verified Engine and cache identity, NVML, gateway
telemetry, storage, protection, persistent controller registry, TLS 1.3 mTLS,
and the native signal cadence. It never opens the Node database or another
manager's store. The listener and resident have one symmetric lifecycle:
either terminal path requests the other's stop, listener shutdown interrupts
active work, every worker is joined, and signal-driven resident termination
performs the final flush. Node, Gateway, Watchdog, and the public CLI all have
complete native entrypoints; installer-driven Core setup generates their
closed configuration and owns atomic service activation.

`CoreWatchdogServiceHealth` is the concrete Linux setup-readiness adapter. It
loads a distinct owner-only server CA, controller certificate, and controller
private key, permits only TLS 1.3 mutual authentication, and sends the closed
protocol-v3 resident-status request to the exact configured Watchdog endpoint.
One absolute deadline, capped at ten seconds, covers connect, handshake, frame
write, and frame read without retry or replay. Readiness succeeds while idle
only when the response repeats the exact configured Node ID, Core release,
immutable Core source identity, installation ID, and ready lifecycle. Wrong
identity and bounded server errors remain not ready; malformed, authentication,
deadline, and transport failures use fixed redacted diagnostics.
