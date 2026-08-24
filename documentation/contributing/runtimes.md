# Developing and publishing runtimes

[Back to documentation](../README.md)

A runtime pull request is the complete review boundary. It may reuse an
existing Engine OCI, change an Engine deeply, or introduce an Engine Let's
Infer has never supported. Authors do not need access to the production
registry.

## Start locally

Use the repository's [runtime skill](../../skills/runtime/SKILL.md). If any
Engine executable input changes, it routes you to the
[Engine-authoring skill](../../skills/engine-authoring/SKILL.md). Those skills
use versioned repository tools for README generation, schema validation,
Engine conformance, deterministic packing, OCI planning, and local
qualification. There is no separate `letsinfer runtime ...` development
namespace.

Every candidate README starts with the canonical Let's Infer link and these
commands:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
letsinfer install <logical-model>
```

If a README already exists, the onboarding helper prepends the block and
preserves the original content.

For a reused Engine, retain its exact manifest and configuration digests and
omit Engine source directories; CI classifies it as `reuse-engine`. Do not copy
its source merely to create a new runtime. For a changed or new
Engine, include its complete source, adapter, image recipe, patches, tests,
licenses, and deterministic build inputs in the candidate directory. Keep
generated layers, binaries, model weights, caches, and evidence out of Git.
Calculate the deterministic future production Engine manifest/configuration
digests locally and pin them before verification; this does not publish them.

## Pull-request verification

Opening or updating a finalized candidate PR runs a no-code sentinel. That
sentinel triggers a secretless, read-only default-branch builder for the exact
head; contributor changes cannot replace the build workflow. A separate
default-branch finalizer reclassifies, re-audits, and repacks the proposal as
data without executing it. It creates the exact downloadable verifier bundle
with runtime pack, one OCI Engine layout, checksums, SPDX, provenance, and
immutable subject. Core converts that validated OCI layout to Docker format
only on the verifier machine. If the independently calculated Engine pin
differs, CI uploads a deterministic patch and creates no verifier bundle for
that head. Neither stage can publish production packages.

After source and supply-chain review marks the subject `benchmark-ready`, two
eligible independent reviewers run:

```bash
letsinfer benchmark verify <pull-request-url>
```

The command resolves the finalizer artifact for that exact PR head. It never
downloads or packs PR source. A changed Engine is loaded by exact local image
configuration digest and removed after restoration unless it pre-existed.

Each GitHub account and device can occupy only one slot. Author results are
informational. A blocking correctness, safety, crash, OOM, incomplete-workload,
or restoration failure is terminal for those exact bytes. Performance
differences remain visible but do not add a disagreement state or expand the
reviewer count.

## Publication

After qualification, an authorized repository maintainer comments exactly
`/shipit`.
Trusted automation verifies the current head, reviews, checks, subject,
attestations, SBOM, and public identities. It promotes the exact verified
Engine object only when the Engine changed, always publishes the exact runtime
object, anonymously verifies both digest pulls, records a publication receipt,
and merges only that checked head. The protected catalog-signing lane later
reverifies the public objects but does not republish them. A publication
mismatch fails closed and never merges the PR.

After one independent successful verification and no blocking failure, a
configured maintainer may replace only the second verifier with:

```text
/shipit --bypass-verifiers
Reason: <required auditable reason>
```

The actor must currently have `maintain` or `admin` permission and their
immutable numeric GitHub ID must be in the trusted repository variable
`LETSINFER_VERIFIER_BYPASS_GITHUB_IDS`. This never bypasses code review, failed
checks, source/SBOM/protocol gates, digest matching, public pulls, or exact-head
merge protection.

The immutable Engine pin in `runtime.json` is the link between the production
runtime and Engine. There is no last-minute engine selection or mutable tag.

New candidates use the pre-provisioned public
`ghcr.io/letsinferlabs/runtime-artifacts` package; changed/new Engines use
`ghcr.io/letsinferlabs/engine-images`. Existing candidates retain their public
runtime package. Shared package names do not weaken identity: every runtime and
Engine reference remains an exact manifest digest, and `/shipit` requires an
anonymous digest pull before merge.
