# AuthenticationManager

`li_authentication_manager` owns inference API-key identity, policy,
generation, authentication, rotation, and revocation. It also owns the durable
authorization decision for exact peer-certificate credentials used by the
private Node transport. It does not own Gateway request-rate, token,
concurrency, or context counters. Authentication returns the durable policy
that the Gateway enforces against live traffic.
`authenticate_identity` verifies the same bearer, expiry, and revocation
contract once for model discovery, then returns the exact model scope for the
Gateway to filter; it never treats discovery as permission to execute a model.

Bearer tokens use the `li_<key-id>_<secret>` namespace. Secrets contain 256
bits from an injected CSPRNG, are returned through a one-time presentation
owner, never enter stored records or debug output, and are cleared from owned
buffers. Stored verification uses a random salt, domain-separated SHA-256, and
constant-time comparison.

The manager depends on a narrow `AuthenticationStore`. Node-daemon composition
implements that store over `DatabaseManager`; atomic key rotation uses one
multi-record transaction. Private records carry the nested
`li_authentication_record` schema identity at version `1`, reject
unknown fields, and fail closed on invalid revisions or mutation results that
differ from the proposed verifier and metadata. The Gateway calls the private
authentication API and never opens durable key storage.

`PeerCredentialStore` is a separate read capability because a peer certificate
is not an inference API key. One bounded lookup asks for at most two records:
one exact match plus one duplicate sentinel. AuthenticationManager requires a
positive persisted revision and the exact queried leaf SHA-256, rejects missing
or duplicate state, and distinguishes pending approval, not-yet-valid, expired,
revoked, and rotated records internally. Pending certificate material is
durable but cannot authorize. Rotation metadata is never followed as an identity
fallback; only the replacement certificate's own exact active digest can
resolve its `CredentialId`. Fixed presentation keeps all rejection details and
identities out of diagnostics.

Application composition implements `PeerCredentialStore` over the shared
`DatabaseManager` authority and adapts `resolve_peer_credential` to NodeManager's
transport-local resolver trait. AuthenticationManager deliberately does not
depend on NodeManager or open a second persistence path.

Controller trust is a third, isolated authentication capability. A controller
has one validated 32-hex identity, display name, viewer/operator/administrator
role, public certificate fingerprint and public-key fingerprint, and an
issued/active/revoked lifecycle. Certificate issuance and import go through an
injected `ControllerCertificateProvider`; private keys never enter the manager,
its store port, persisted records, errors, or debug output. Registration is
replay-safe and rejects implicit divergence. Replacing or rotating a controller
certificate is an explicit operation that atomically restores active state.
Authorization re-reads durable state and checks the exact controller identity,
certificate fingerprint, current lifetime, active state, and minimum role.

`ControllerStore` is implemented by Node composition over the isolated
`controllers` DatabaseManager collection. Version-1 `li_controller_record`
documents contain only public certificate material and lifecycle metadata,
reject unknown fields, reconstruct every typed invariant after restart, and
use optimistic revisions for concurrent activation, replacement, and
revocation.

Focused deterministic tests cover API-key lifecycle, concurrent rotation and
revocation, exact persistence responses, restart, schema and semantic tampering,
Gateway redaction, plus peer model invariants, lifetime and pending-approval
decisions, rotation non-fallback, bounded lookup, duplicate and corrupt records,
store failures, and unavailable composition.
Controller coverage additionally includes issuance, import, role policy,
explicit replacement, exact replay versus divergence, concurrent idempotent
revocation, provider and store rollback, malformed and expired certificates,
real-database restart, persisted corruption, and absence of provider-private
material from database files. Application provider tests separately prove the
production authority/key match, exact P-256 client profile, DER fingerprint,
owner-only file boundary, and unavailable-platform rejection.
