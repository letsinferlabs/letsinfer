# AuditManager

`li_audit_manager` owns the node audit chain as an in-process library under
NodeManager. It is not a daemon and does not own node identity, authorization,
or private key material.

The manager appends bounded secret-free action summaries to one optimistic
append-only store. Each event hashes the raw bytes of its previous SHA-256
value followed by sorted canonical event JSON and a trailing newline. Every
100th production event receives a signature over the lowercase event-hash
text. The event and its checkpoint commit atomically.

NodeManager supplies local identity, validated action context, the store, a
clock, event identities, and narrow signing and verification capabilities.
The same injected contracts provide deterministic CI tests without replacing
manager behavior.

The manager supports bounded recent-event listing, exact event lookup,
complete bounded export, and fail-closed verification of every sequence,
previous hash, event hash, required checkpoint, checkpoint event identity, and
checkpoint signature. Prompts, responses, bearer tokens, private keys,
arbitrary before/after values, multiline text, and unbounded reasons have no
representable event field.

`DatabaseAuditStore` now maps that port onto explicit state, event,
checkpoint, and replay collections. One optimistic transaction
commits the event, optional checkpoint, replay binding, and new chain head.
NodeManager supplies local identity and key-reference-only OpenSSL signing.

Domain mutations and AuditManager appends are independent database commits.
Node composition reports that boundary and a typed recovery condition until
domain managers expose shared transaction fragments; it does not claim
cross-manager atomicity.
