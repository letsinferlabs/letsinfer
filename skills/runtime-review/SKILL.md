---
name: runtime-review
description: Review and publish a Let's Infer runtime pull request as an authorized repository maintainer, including exact PR artifacts, two-verifier qualification, Engine reuse or promotion, and /shipit. Do not use for ordinary runtime authoring.
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

The configured Taimur bypass is intentionally narrow:

```text
/shipit --bypass-verifiers
Reason: <required non-empty explanation>
```

Trusted code must match the immutable configured numeric GitHub user ID and
current maintainer permission. It still requires one complete successful run
for the current subject. It waives only the second verifier and a non-blocking
performance warning; it never waives source review, required checks, protocol,
determinism, licensing, SBOM, public pull verification, or blocking evidence.
Record the actor ID, command, reason, subject, time, and waived requirement in
bot-owned provenance.

## Process `/shipit`

Bind the command to the current PR head, current reviews and checks,
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
5. Mark the exact head shippable and merge through protected-branch controls.
6. Continue through the protected catalog-signing and release lane.

If retained artifacts expired, a rebuild is only a reproducibility check and
may proceed solely when every digest matches the verified subject. A mismatch
creates a new subject. Partial publication is safe but never mergeable; retry
idempotently and never delete a possibly referenced digest.
