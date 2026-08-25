---
name: runtime-review
description: Review and publish a Let's Infer runtime pull request as an authorized repository maintainer, including exact PR artifacts, ordinary two-verifier qualification, the allowlisted maintainer override, Engine reuse or promotion, and /shipit. Do not use for ordinary runtime authoring.
---

# Review and ship a Let's Infer runtime

Use trusted default-branch tooling. Never execute a pull request's command
parser with maintainer credentials and never expose package, App, or catalog
signing credentials to candidate code.

## Review the exact subject

Confirm the PR targets the protected branch and changes the expected candidate.
Review the complete source closure, licenses, immutable dependencies, Engine
protocol conformance, deterministic runtime pack, OCI plan, SBOM, provenance,
target contract, model pins, README onboarding block, and absence of generated
layers, weights, caches, credentials, or evidence.

For Engine reuse, reverify the existing manifest and configuration digests and
publish no duplicate Engine. For a changed or new Engine, require the exact
attested OCI layout and final pin in the verifier subject. The runtime pack
reviewers run must already contain that production Engine identity.

## Require simple independent verification

Ordinary `/shipit` requires two successful eligible reviewers with distinct
GitHub numeric account IDs and device identities. One reviewer always occupies
one slot, regardless of reruns. Authors are informational. Performance
differences are reported but do not create disagreement mechanics or increase
quorum. Any accepted blocking failure is terminal for the subject.

An explicitly allowlisted maintainer may bypass the independent verifier quorum:

```text
/shipit --bypass-verifiers
Reason: <required non-empty explanation>
```

Trusted code must find the actor's immutable numeric GitHub ID in
`LETSINFER_VERIFIER_BYPASS_GITHUB_IDS` and independently confirm live
`maintain` or `admin` permission. The command is the maintainer's release
authorization, so this path does not require an independent benchmark result
or a second non-author maintainer approval. Accepted correctness, safety, and
restoration failures remain blocking. It never waives failed checks, source
and license audits, protocol, determinism, SBOM, attestations, digest matching,
public pull verification, or exact-head protection. Record the actor ID,
command, reason, subject, time, and bypassed quorum in bot-owned consensus and
the publication receipt. If there is no measured evidence, publish the release
without a score and keep it ineligible for automatic recommendation.

## Process `/shipit`

Bind the command to the current PR head, current blocking review state and checks,
`benchmark-ready`, exact subject, accepted evidence, and only trusted bot-owned
metadata commits after the executable proposal. Recheck authorization through
the GitHub API at execution time.

Promote, do not unconstrainedly rebuild:

1. Revalidate every retained artifact and digest.
2. If the Engine changed, push the exact verified OCI layout and verify an
   anonymous pull; otherwise reverify and reuse its public digest.
3. Push the exact deterministic runtime pack and verify byte identity through
   an anonymous pull.
4. Materialize only bot-owned consensus, provenance, and catalog projection.
5. Post the exact publication receipt and merge through protected-branch
   controls with the checked head SHA.
6. Let the protected release lane anonymously reverify objects before catalog
   signing; it must not republish Engine or runtime objects.

Before enabling `/shipit`, maintainers pre-provision public
`ghcr.io/letsinferlabs/runtime-artifacts` and
`ghcr.io/letsinferlabs/engine-images` packages linked to the public runtimes
repository. Existing candidates retain their current public package. Treat an
anonymous-pull failure after promotion as terminal: never merge and never
weaken visibility verification.

If retained artifacts expired, a rebuild is only a reproducibility check and
may proceed solely when every digest matches the verified subject. A mismatch
creates a new subject. Partial publication is safe but never mergeable; retry
idempotently and never delete a possibly referenced digest.
