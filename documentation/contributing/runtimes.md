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
do not copy its source merely to create a new runtime. For a changed or new
Engine, include its complete source, adapter, image recipe, patches, tests,
licenses, and deterministic build inputs in the candidate directory. Keep
generated layers, binaries, model weights, caches, and evidence out of Git.

## Pull-request verification

Opening or updating a finalized candidate PR automatically creates the exact
downloadable verifier bundle. It contains the deterministic runtime pack and,
when needed, the Engine OCI layout plus the final Engine pin and immutable
subject document. The build has no production publication credential.

After source and supply-chain review marks the subject `benchmark-ready`, two
eligible independent reviewers run:

```bash
letsinfer benchmark verify <pull-request-url>
```

Each GitHub account and device can occupy only one slot. Author results are
informational. A blocking correctness, safety, crash, OOM, incomplete-workload,
or restoration failure is terminal for those exact bytes. Performance
differences remain visible but do not add a disagreement state or expand the
reviewer count.

## Publication

After qualification, an authorized repository maintainer comments `/shipit`.
Trusted automation verifies the current head, reviews, checks, subject,
attestations, SBOM, and public identities. It promotes the exact verified
Engine object only when the Engine changed, always publishes the exact runtime
object, records bot-owned provenance, and proceeds through the protected
catalog-signing lane. A publication mismatch fails closed and never merges the
PR.

The immutable Engine pin in `runtime.json` is the link between the production
runtime and Engine. There is no last-minute engine selection or mutable tag.
