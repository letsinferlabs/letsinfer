# RuntimeManager

`li_runtime_manager` owns signed-catalog selection and static installability
judgment. It compares exact runtime target requirements with a current
HardwareObservation and rejects revoked, platform-incompatible, memory-
incompatible, accelerator-incompatible, or Engine-protocol-incompatible
candidates.

Community verification may call the resident-only exact-candidate acquisition
entry point with a preparation-trusted `RuntimeCandidate`. That path preserves
revocation, target, hardware, and Engine-protocol admission plus the ordinary
artifact acquisition/verification lifecycle, but performs no mutable catalog
lookup and is not exposed through the CLI or private wire API.

Evidence qualification is returned as a label and is never consulted as an
installation gate. Live free GPUs, ports, memory pressure, node reachability,
and interconnect allocation remain PlacementManager responsibilities.

RuntimeManager stages durable state before acquisition, verifies immutable
bytes, records Available or Failed state, compensates exact artifacts, removes
through Removing/Removed, and prunes only installations absent from the
NodeManager-supplied retained-reference set.

An Available installation can now expose one typed execution manifest through
an injected narrow provider. The filesystem implementation reads bounded
no-follow `runtime.json` bytes, verifies their exact manifest SHA-256, matches
schema-6 runtime, target, Engine distribution, and model-artifact identities
against persisted installation state, verifies the canonical execution
contract digest, and preserves only opaque `task-N` launch, environment,
readiness, endpoint-owner, and startup-phase values. The typed result also
retains the manifest's bounded verified Engine ID and cache-provider identity;
consumers never recover either value from the opaque runtime candidate name.
It does not allocate live resources or read PlacementManager state.

One production signed-catalog provider now downloads the exact catalog and
revocation assets through the shared bounded HTTP transport, verifies both
Ed25519 envelopes against the Core-owned trust root before parsing, rejects
duplicate JSON keys and every unsupported schema shape, applies exact
runtime-digest plus consensus revocations, and uses the same target matcher and
active view for list and install. Ordered structured authors remain ordered.
The immutable filesystem cache re-verifies every replay and permits stale use
only when a fresh network request is unavailable; signature, schema, digest,
source, and corruption failures never fall back. Catalog schema 7 deliberately
omits model revisions, runtime-manifest digest, and execution-contract digest.
The production OCI hydrator therefore acquires the digest-pinned pack into one
unpredictable owner-only workspace, verifies its complete descriptor/file
closure, parses the full schema-6 execution contract, and cross-checks every
runtime, Engine, model, static target, and placement field against the signed
catalog before RuntimeManager can consume it. Every success and failure path
clears the exact pack bytes and removes only the now-empty workspace. Automatic
selection never falls back to an unscored release.

A separate source-keyed revocation anchor retains the highest verified ledger
sequence and exact same-sequence document digest independently of the current
cache pointer. Cache rollback and equivocation therefore fail closed across
process restart. Owner-only advisory locking makes concurrent refreshes
converge on the highest sequence instead of allowing a late lower-sequence
rename.

Deterministic RuntimeManager tests cover selection, lifecycle, execution, and
immutable acquisition. The real
acquisition composition now has
one shell-free bounded curl transport, public bearer-authenticated OCI runtime-
pack acquisition with complete descriptor/file verification, direct Hugging
Face snapshot and GGUF acquisition, and Docker OCI Engine pull/inspect/platform
verification. Bearer bytes live only in private temporary configuration files
and are never forwarded across redirects or placed in argv.

The resident benchmark-verification entry point is separate from catalog
selection. It accepts a deterministic installation identity plus one typed
preparation-trusted runtime pack/Engine closure, reuses the ordinary revocation,
compatibility, Engine-protocol, lifecycle, and offline verification gates, and
never resolves mutable catalog state. A finalized built OCI Engine is loaded
from its retained owner-private archive, checked against the exact configuration
digest, platform, and local tag, then bound to the candidate reference without
a public pull fallback. Relative paths, Engine-mode drift, digest mismatch,
ambiguous provider success, and ordinary acquisition fallback fail closed.
RuntimeManager retains a path-free owner-only cleanup marker before loading a
built image; restart cleanup verifies and removes only its exact candidate
reference and local tag, never invokes a broad Docker prune, and retains the
marker for retry if either tag still resolves.

The matrices cover Linux, macOS, parallel tasks, different-version ready and
failed handoff, store/native-I/O/process/network failure, corruption, every
identity and policy mismatch, unsafe paths and commands, protected environment,
pagination, redirects, replay, rollback, and real no-follow filesystem reads.
Native macOS archives and Python standalone distributions now reproduce the
existing payload-ID algorithm, resolve safe archive links as regular files,
verify staged CPython and hash-locked dependencies, and write exact tree
receipts. The final offline verifier rechecks runtime descriptors, model
receipts and bytes, OCI/native Engine receipts, native payload identity, and
the closed installation layout without network access. Embedded applications
now use one explicit injected provider for both acquisition and execution
handoff. RuntimeManager carries the exact payload, source revision, minimum app
version, runtime-owned entrypoint, and observed app version through that
handoff; validates every returned bundle, Engine, payload, version, and
installation identity; records only an app-owned receipt; and has no host-
materialization or process fallback. Both tar.gz and ZIP native archives use
separately tested bounded safe extractors.
