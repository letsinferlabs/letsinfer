# Node schemas

`li_node_private_api_v2.schema.json` defines the new Rust private node request
and response boundary. Its required nested identity is
`schema.name=li_node_private_api` and `schema.version=2`.
Version 2 adds one nested local-only union for the eight atomic Gateway
capabilities owned by Node. Remote controller and paired-node paths reject the
entire union before authorization; bearer material never appears in a response
or ordinary debug and error output.
The same closed union carries active-main benchmark preview, start,
active/read, and stop commands plus secret-free plans and durable status. The
CLI sends only one logical model and canonical public context/concurrency axes.
Application resolves those values to an exact Core installation, Runtime
installation, Placement group, execution, benchmark contract, target contract,
and complete or selected local scope. Resolved manager identities return in a
preview response; callers cannot submit or override them. Neither request nor
response contains Engine flags, ranks, repository credentials, prompts,
outputs, signing keys, or publication action.

Benchmark status exposes only journal phase, optimistic revision, exact
identity and receipt digests, bounded progress counts, and timestamps. The
schema requires telemetry identity/count and evidence/result/signer identity
sets to be complete or absent together. Rust constructors additionally enforce
request mode/scope, progress, lifecycle receipt, phase, and timestamp
invariants before a private document reaches Node-owned scheduling.

The same private API carries one typed host inventory for CLI status,
topology, doctor, and node reads. Hardware, placement groups, verified links,
protection, Gateway, Watchdog, and model services retain separate `available`,
`unavailable`, and `not_applicable` states. Rollback requests select a logical
service plus an optional target; previews return exact current and retained
group/runtime identities rather than the retired cleanup-operation selector.

`li_node_configuration_v4.schema.json` defines the only accepted strict
owner-only resident configuration document. This pre-launch cutover has no
configuration migration or compatibility reader. Its nested identity is
`schema.name=li_node_configuration` and `schema.version=4`.

`li_node_watchdog_session_record_v1.schema.json` defines the closed payload
stored under DatabaseManager record version 1 for controller authority and its
direct certificate index. The database envelope owns collection, record
version, revision, and optimistic transaction metadata; the payload schema
owns controller, leaf digest, nonzero generation, exact placement-group and
placement target, exact protected-target digest, and active/revoked state.

The schema owns closed JSON shape, field types, bounded strings, identifiers,
and action/response unions. Rust constructors retain semantic ownership of
timestamp ordering, role/state transitions, outbox acknowledgement coherence,
authorization, benchmark lifecycle coherence, optimistic revisions, and
manager invariants. In-process NodeManager calls continue to use typed Rust
values and do not serialize.
