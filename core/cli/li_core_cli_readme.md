# Rust Core CLI

`li_core_cli` owns the declarative command registry, typed argument parsing,
role authorization, native application lifecycle, presentation contracts,
plain stream rendering, progress relay, and mandatory command-audit boundary
for the Rust Core rewrite. It does not own manager state, persistence, native
service composition, or daemon supervision.

The registry is the closed public Rust command surface. Every leaf has one
explicit scope, mutation class, audit policy, and configured-node requirement.
Setup and resident processes use their dedicated native binaries and never
re-enter hidden `letsinfer` compatibility commands. The parser has no aliases
and never supplies a default command or execution scope.

The application resolves immutable node context, authorizes the leaf, proves
mandatory audit availability, dispatches exactly once, records the terminal
result, and only then publishes the returned human or JSON document. All
visible language and stream selection remain inside the display component.
Handlers return composable presentation blocks plus a separately constructed
machine value; JSON is never derived from terminal text, and progress never
contaminates machine output.

Eight typed capability groups cover host, node, model, benchmark,
authentication, exposure, audit, and update lifecycles. Their exhaustive
router contains every registered action and never invokes a shell or Python.

The native process consumes the existing
`li_node_private_api` version 2 codec. `NodePrivateClient` owns a fresh
correlation identity, a maximum five-second request by default, a maximum
one-megabyte reply, closed transport errors, response decoding, and exact
request/response correlation. The composition root injects the complete
document exchange; neither the typed client nor its mock tests discover a
socket, invoke a command, or copy raw provider errors. The system identity
source reads exact entropy from one explicitly supplied absolute path without
fallback.

`SystemNodePrivateDocumentExchange` now closes the production local transport
gap. It validates one explicit owner-only Unix socket, opens it through a
nonblocking shell-free connector, and completes exactly one request and one
response without retry or replay. The frame is the Node-owned four-byte
unsigned big-endian length followed by one `li_node_private_api` version-2 JSON
document. Request and response lengths never exceed `1,048,576` bytes, and a
smaller configured response bound is enforced from the header before
allocation. Connect, write, and read share one absolute deadline that cannot be
extended by fragmentation or interrupted I/O. Errors retain no native text,
path, document, or unrecognized server code. The socket and byte-I/O boundary
remains injectable for deterministic contract tests.

`NativeNodeCliProcess` shares that client only between local-role resolution
and typed dispatch, then enters the ordinary authorization, audit, display,
and exit lifecycle. The current wire contract and Application composition
provide production adapters for all 47 registered leaves: Node and host reads,
main- and child-side lifecycle, pairing, controller and inference-key
lifecycles, model installation and lifecycle, storage usage, benchmark and
verification lifecycles, exposure, audit, signed updates, and uninstall. Host
status, topology, and doctor compose those same typed reads;
`doctor --require-stable` makes qualified publication evidence a requested
readiness check without turning the label into an execution gate. Node
transitions read one exact optimistic revision, use an injected wall clock,
require `--yes`, and never guess an omitted child. Secret-bearing
authentication results retain their one-time presentation boundary.

Role-specific operations remain fail closed. Child lifecycle commands require
the exact configured paired-main mTLS authority; pairing and uninstall require
their owner-only installation inputs; manager or resident unavailability is
reported as failure and never routed to Python or treated as success.

`compose_system_native_node_cli` wires the ordinary local socket and entropy
source into the existing process lifecycle. The Application-owned public
`li_letsinfer` binary now accepts exactly
`--configuration ABSOLUTE_PATH -- COMMAND...`. The installed public
`letsinfer` launcher supplies that hidden path and forwards user arguments.
The native installer installs the launcher before Core setup atomically
activates the platform residents. The owner-only closed
`li_core_cli_configuration` version-4 document binds the local Node socket,
entropy and request bounds, pairing installation, uninstall launcher,
platform-specific Watchdog health inputs, and an optional exact paired-main
mTLS endpoint. It enters the ordinary command parser without a Python, shell,
direct-database, or discovered-path fallback.

The production process opens and completes every required command-audit
lifecycle through the resident Node owner. A missing role-specific authority,
resident, or local Node capability returns the closed unavailable result
without bypassing authorization or audit.

The deterministic crate suite uses one table for the complete surface. It proves exact
registry/parser equality, typed representative values and defaults,
authorization before dispatch, rejection of retired vocabulary, and one
dispatcher call for every leaf. Focused application tests prove every
capability group, human and JSON output separation, audit ordering and
fail-closed behavior, manager denial/failure/cancellation exits, progress
relay, deterministic JSON escaping, and stable stream bytes without repeating
the 47-leaf parser table. The native-client matrix additionally proves request
routing, response correlation, bounds, timeout, malformed/truncated/oversized
replies, remote denial redaction, injected entropy, local and targeted info,
stable listing, unexpected response shapes, and the audited unsupported-action
boundary through real Node codecs. Six native exchange contracts add exact
framing, fragmented I/O, complete deadlines, size and malformed-frame bounds,
single-attempt connection failures, and server-error redaction. One bounded
real Unix process test proves explicit system composition through context,
dispatch, JSON display, and two correlated connections.
