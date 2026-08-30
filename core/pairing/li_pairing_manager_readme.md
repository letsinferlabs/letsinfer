# PairingManager

`li_pairing_manager` owns bounded one-use child invitations from discovery
publication through candidate proof and validated trust result. It receives
local identity explicitly from NodeManager and narrow discovery, direct-link,
trust, entropy, clock, and `PairingStore` providers. It never reads NodeManager
or opens persistence itself. Invitations, failed-attempt bounds, verified child
identity, certificate identity, and remote approval state are versioned durable
records rather than process memory.

LAN and remote invitations use an eight-digit setup code retained only as a
salted verifier. Remote pairing returns a separate six-digit human comparison
code and pending membership. ConnectX pairing accepts no code and binds the
preapproved public-key fingerprint, direct interface, and observed peer route.
Every mode enforces 30–600 second expiry, five failed attempts, one-use
consumption, proof-of-key possession, bounded inputs, and advertisement cleanup.
Remote proof completion proposes a persisted pending result; only explicit
approval proposes the active transition. PairingManager never turns pending
material into authorization itself.

The native provider now owns shell-free Avahi and Bonjour publisher processes,
bounded browser/resolve commands, strict credential-free TXT parsing,
cross-address deduplication, and exact process retirement. Linux direct-link
proof reads injected sysfs facts, requires a live RDMA-bound `mlx5_core`
interface, and accepts only one gateway-free `ip route get` result through the
approved interface. Production and all 30 deterministic contracts use the same
command, process, and native-I/O interfaces; CI substitutes only those narrow
boundaries.

The OpenSSL trust provider snapshots owner-only site identity files into a
fresh private workspace, canonicalizes exact P-256 SPKI DER, verifies the
candidate signature over the manager's unchanged enrollment transcript, and
returns the DER fingerprint. Membership issuance proves the site signing key,
site public key, CA, and pinned local control certificate identities before it
issues a dual-purpose node certificate. The certificate is reverified against
the CA, candidate key, URI SAN, and freshness horizon. A domain-separated
membership transcript binds both public-key and certificate fingerprints
before the site key signs it. The issued package also carries the SHA-256 of the
exact leaf DER and exact parsed `notBefore` / `notAfter` boundaries; downstream
code never guesses certificate lifetime. All native calls use fixed shell-free argv;
stderr, paths, proofs, and private material collapse to one redacted trust
failure. Exact closed-file cleanup runs after success and every failure.

Five focused trust contracts cover proof and issuance success, invalid proof,
curve and fingerprint identity, unsafe key/certificate/workspace state,
redacted command failure, rollback, and idempotent cleanup. Pairing now has 30
deterministic contracts in total. The application boundary composes its
versioned result with peer authorization, Node enrollment, and the durable
outbox. Production Node composition now requires one strict platform-closed
configuration containing the setup-secret reference, native discovery command,
OpenSSL command, private trust workspace, exact identity files and fingerprints,
and Linux-only sysfs and `ip` inputs. macOS fails closed for ConnectX direct-link
proof. No path, executable, certificate identity, or discovery provider is
discovered or synthesized by the resident process; the private TLS listener
remains a separate transport owner.
