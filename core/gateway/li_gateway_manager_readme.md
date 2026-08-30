# GatewayManager

`li_gateway_manager` owns live inference admission, API-key rate/token/
concurrency reservations, placement-group load balancing, bounded FIFO queues,
and active request capacity. AuthenticationManager supplies verified durable
key identity and configured limits; Gateway never retains bearer material.

A main gateway alone exposes public inference. A child gateway accepts only an
authenticated relay from its configured main and may route only to its local
Engine endpoint. Route providers supply current placement/topology facts while
Gateway makes the policy decision. Memory pressure is an admission gate, not
merely telemetry. Selection prefers exact prefix locality,
then normalized active capacity, lower known temperature, and stable node
identity. Qualification evidence is not an admission gate.

Only failures before output begins can move to a sibling placement group. The
retry retains its original API-key reservation, applies bounded exponential
cooldown to the failed group, and never repeats authentication or RPM charging.
After output begins, failure releases capacity without replay. Successful
requests learn bounded one-hour prefix affinity; exact route-advertised prefix
identity remains equivalent evidence.

`GatewayExecution` composes those decisions with two injected mechanisms:
`GatewayExecutionProvider` forwards one attempt to a local Engine or child
relay, while `GatewayQueueWaiter` supplies native blocking without owning FIFO
policy. The execution boundary forwards only `/v1/chat/completions`, caps
normalized request bodies at 32 MiB and streamed response bodies at 64 MiB,
filters unsafe response headers, and observes the exact point at which response
headers become visible. A retryable provider failure can move to a sibling
only before that point. Client-output failures never cool a healthy route.

Every completed attempt must return exact prompt, completion, and cached-token
usage. Prompt usage must match the admitted count and completion usage cannot
exceed its reservation. The manager replaces the live worst-case reservation
with this exact total once, including for the authenticated child-relay path.
The concrete native provider loads exact owner-bound, mode-0600, single-link
bearer and TLS files through no-follow descriptors. Local Engines use a pinned
CA, exact hostname, and TLS 1.3; child relays additionally require mTLS. It
sends no HTTP bytes until the handshake completes and the child peer leaf DER
SHA-256 matches the Node-owned pairing pin. It
sends a fixed HTTP/1.1 header set, never follows redirects, parses bounded JSON
or arbitrarily fragmented SSE cumulative usage, and clears loaded private
material. Exact counting uses the selected placement endpoint's declared path
only when its protocol is `letsinfer-token-count-v1`. Model alias
normalization remains outside execution orchestration.

Completed API-key usage is written through an injected store so the one-minute
window reconstructs after daemon restart. Active and queued reservations are
process-owned; restart closes their client connections and therefore begins
with zero live concurrency.

GatewayManager also owns schema-2 lifecycle, gauge, exact-token, cache, queue,
TTFT, and decode counters. Immutable snapshots contain no request bodies,
responses, bearer values, or per-request history. Placement-group activity is
limited to 4,096 identities, recent token-rate samples are limited to 16,384
entries and five seconds, and cumulative aggregate counters remain exact when
the activity-detail bound is reached. The production publisher combines that
snapshot with an injected resident-listener/usage-writer counter observation
and emits the unchanged Watchdog telemetry-v2 field set. It requires one
absolute traversal-free path under an owner-only real directory, rejects
unsafe existing modes, ownership, symlinks, and hard links, writes a bounded
mode-0600 file under a random same-directory identity, syncs it, atomically
replaces the stable path, and syncs the directory. Process-local counter and
clock regressions fail closed; a new publisher process may reset counters and
changes the inode identity exactly as Watchdog's restart judgment expects.

`GatewayHttpHandler` is the one protocol boundary above those managers. It
accepts only bounded unambiguous HTTP metadata, normalizes model aliases before
exact token counting, requires a positive output-token reservation, derives
the same prefix identity used by route facts, and selects exactly one public
or private-relay execution surface. Stable client failures contain no provider
or credential detail. Once response output begins, the handler closes on
failure and never appends a second JSON response.

The public handler also owns the fixed `/health` and authenticated `/v1/models`
read surfaces. Readiness is fail-closed and emits only `ok` or `degraded`.
Model discovery receives an already policy-filtered snapshot from one injected
provider, enforces a 4,096-name unique bound, and emits canonical models and
authorized aliases in stable OpenAI-compatible order. Neither read surface is
available on a child listener.
The production model-list adapter verifies bearer identity once through
AuthenticationManager, then filters a globally unique healthy inventory using
the returned durable scope: selecting a canonical model exposes its aliases,
while selecting only an alias does not broaden access to its canonical model.
GatewayManager directly supplies the readiness capability from its fail-closed
telemetry publication state.

The production main-node listener is a bounded plaintext LAN HTTP/1.1 server,
matching the existing public endpoint contract. It accepts one request per
connection, rejects ambiguous framing before body allocation, caps workers at
256, applies native timeouts, and owns connection-close chunked response
framing. One nonblocking supervisor polls accept at a fixed bound, restores
accepted sockets to blocking timeout-bounded worker I/O, rejects saturation by
closing the excess socket, and never detaches a worker. Its restart-safe handle
actively interrupts every registered socket and joins the supervisor plus all
workers across repeated stop/join calls. Binding fails unless both mandatory
public read capabilities are present. The same deterministic connection server
can run over an already authenticated private TLS stream without duplicating
protocol policy.

The child listener wraps that same connection server in mandatory TLS 1.3
mutual authentication. Its server identity and pinned main-node CA come from
owner-only, single-link, no-follow files. The exact main-node leaf certificate
is pinned in addition to its CA, so another valid node certificate cannot use
the relay surface. The bounded handshake reaches an authenticated terminal
state and verifies that exact leaf before HTTP parsing can begin. Certificate
and key PEM input is closed to exact item kinds, anonymous clients are rejected
during the handshake, temporary private-file copies are cleared, and plaintext
can never bind the private-relay handler. A completed request sends TLS
`close_notify` before closing its socket. The private API also exposes one
fixed `/li/token-count` path. It authenticates the configured main, normalizes
the logical model, invokes the child local exact-count provider, and returns
the same closed token-count response understood by the main Gateway. It does
not acquire inference capacity or expose an Engine-declared path publicly.

The resident process boundary loads
`li_gateway_configuration` schema 5 from one no-follow, owner-only, mode-0600,
single-link JSON file capped at 64 KiB. Unknown or duplicate fields, DNS bind
names, ambiguous listener addresses, mismatched mode/listener sets, unbounded
workers, and non-absolute or overlapping TLS file roles fail before startup.
The document binds one owner-authenticated `node_socket_path`, Watchdog
telemetry path and cadence, maximum queue wait, exact Node/Core identity, and a
separate owner-authenticated local health socket. Node owns the database,
Authentication, Placement, and runtime state and exposes only the bounded
typed capabilities Gateway consumes through that local socket.
The matching public JSON Schema lives at
`schemas/gateway/li_gateway_configuration_v5.schema.json`. This pre-launch
cutover has no configuration migration or compatibility reader.

A main process owns one public and one private listener; a child owns only one
private listener. Route, target, authentication, token, readiness, inventory,
and execution capabilities arrive only through already-composed handlers. The
process preloads private TLS identity before binding, retains every resident
handle, rolls back and joins a partially started main, and always stops and
joins every listener after injected signal/run control returns or fails.
Repeated stop and join are safe, and dropping the process cannot detach its
listeners. The application-owned `li_gateway --configuration ABSOLUTE_PATH`
binary composes one owner-authenticated Node client plus Gateway-owned network,
clock, telemetry, and run-control providers. It does not open `DatabaseManager`
or compose Authentication or Placement stores; those capabilities arrive
through typed Node IPC. Main mode binds both listeners; child mode binds only
the private listener. Role, trust, configuration, startup, and initial telemetry
mismatch fail closed without a Python fallback.

The local health socket is mode 0600 inside an owner-only directory and never
uses the public or main-to-child mTLS surfaces. Both peers verify the effective
user, the client revalidates an unchanged socket identity, and one absolute
deadline bounds connect plus the framed exchange. Its closed response binds
Node ID, main/child mode, Core release, immutable Core source digest, and fresh
successful telemetry readiness. Health starts only after inference listeners
and initial telemetry are live; every later failure stops and joins it with
the other resident resources.

Gateway now provides its own production wall/monotonic clock, short bounded
interruptible queue waiter, domain-separated CSPRNG request identities, and
native process run control. Run control blocks `SIGTERM`, `SIGINT`, and
`SIGHUP`, consumes them on one joinable `sigwait` worker, coalesces repeated
stops with native-signal precedence, wakes the process without a signal
handler, and restores the installing thread's signal mask after idempotent
join.

Queued execution checks native socket liveness before each bounded wait and
cancels the exact FIFO ticket when the client disconnects. Periodic telemetry
uses an interruptible production cadence boundary; deterministic tests inject
explicit scheduling decisions and never sleep. A later publication failure
wakes the process run control and is returned by the joined telemetry worker,
so Watchdog never observes silently stale readiness. Runtime counters combine
weakly retained listener gauges with Database usage-write health and cannot
publish readiness until the process is fully bound.

The 112 deterministic Gateway Rust contracts comprise 20 manager-policy tests,
ten execution-boundary tests, 13 HTTP-boundary tests, ten native-client tests,
eight native-server tests, nine private-listener tests, five focused
telemetry tests, three authenticated public-read adapter tests, and two shared
resident-lifecycle tests, plus four process-lifecycle, five configuration,
four telemetry-resident, and 19 system/provider tests. They cover the ordinary lifecycle, every
meaningful retry / failure /
cancellation branch, fixed request and TLS identity, exact token count and JSON
/ SSE parsing, private-file safety, bounded native framing, saturation,
stalled-I/O interruption, worker cleanup, redacted accept failure, startup
rollback, process restart, repeated shutdown, non-underflowing gauges, exact
tokens and durations, publisher recovery, and bounded activity without
duplicating the execution matrix. Four additional Node tests cover durable
usage creation, exact replay, conflict, corruption, and storage loss;
application tests prove the exact `CoreProcessLayout` argument contract.
Installer and Core setup now own production configuration generation. The
remaining cross-daemon work is qualified-host evidence for the native
Node/Watchdog/Gateway service set.
