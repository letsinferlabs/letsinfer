# Core interface

`li_core_interface` is the shared vocabulary of the Rust Core. It contains
validated identities, bounded value types, and immutable entity snapshots for
nodes, hardware observations, runtime installations, model services, placement
groups, placements, resource leases, and operations.

The component has no persistence, serialization, networking, platform,
execution, or lifecycle-manager dependency. Its fields are private. Callers
construct values through explicit validation boundaries and consume them
through read-only accessors.

`EvidenceLabel` is descriptive metadata. Qualified, unqualified, and unknown
installations use the same entity shape; the label does not decide whether an
installation may be placed, started, or routed.

Database records, API documents, and manager commands remain separate adapters
or interfaces owned by their respective components. They will be added only
after those manager contracts are designed.
