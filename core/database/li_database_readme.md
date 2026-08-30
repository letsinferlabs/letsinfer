# Core DatabaseManager

`DatabaseManager` is the Rust node agent's sole SQLite owner. It is a library,
not a service.

Its public boundary accepts typed `DatabaseRecord` commands and queries. SQL,
table names, record encoding, schema initialization, and connection ownership
remain private. A blank database is created at the exact current schema. An
existing database opens only when its application identity, schema version,
tables, columns, constraints, and indexes exactly match this Core build. Older,
newer, foreign, and partial schemas fail closed without migration or rewrite.
One bounded writer queue serializes mutations while independent read-only WAL
connections observe committed state.

Each mutation is atomic and carries an idempotency key plus an explicit revision
condition. Successful new commits return a revision and timestamp and produce
one post-commit event. Replays return the original commit without producing a
second event.

`DatabaseTransaction` applies up to 256 unique typed record targets in caller
order under one SQLite transaction and replay identity. Any later conflict
rolls back every earlier mutation. Authentication rotation uses this boundary
to revoke the prior key and create its replacement atomically.

Audit persistence uses explicit `AuditState`, `AuditEvents`,
`AuditCheckpoints`, and `AuditReplays` collections. The NodeManager-owned
adapter uses one `DatabaseTransaction` for the optimistic head, append-only
event, optional checkpoint, and replay index. These collections do not imply
that an already-completed domain-manager call can join a later audit call;
cross-manager atomicity still requires the caller to supply one shared
transaction composition boundary.

Benchmark journals use the dedicated homogeneous `Benchmarks` collection.
They never share `Configuration`, because a typed collection-wide read must be
able to decode every row through one closed record contract.

Core update journals and their pre-mutation service snapshots use separate
`CoreUpdates` and `CoreUpdateServiceSnapshots` collections. A process restart
can therefore reconstruct exact restoration state without mixing two record
shapes in one collection.

Pairing invitations and peer credentials likewise use separate `Pairings` and
`PeerCredentials` collections. Application composition can place their exact
optimistic mutations beside NodeManager's child and outbox records in one
`DatabaseTransaction`; no component opens a second database or claims atomicity
across separate writes.

The node agent will own one manager instance. The CLI and gateway must use the
node agent API and must never open this database directly.
