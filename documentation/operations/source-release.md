# Source release

[Back to documentation](../README.md)

Let's Infer core source releases are built from an explicit public allowlist.
The independently released macOS application is not a core archive or install
input. Local agent policy, handoff state, context, scratchpads, credentials,
evidence, caches, nested Git metadata, and generated output are never
publication inputs.

Build twice and require byte equality:

```bash
bin/letsinfer-source-archive build --source . --output /tmp/letsinfer-a.tar.gz
bin/letsinfer-source-archive build --source . --output /tmp/letsinfer-b.tar.gz
cmp /tmp/letsinfer-a.tar.gz /tmp/letsinfer-b.tar.gz
bin/letsinfer-source-archive verify /tmp/letsinfer-a.tar.gz
```

Each archive has one `letsinfer/` root and an embedded
`SOURCE-MANIFEST.json`. The manifest records every file's normalized mode,
byte length, and SHA-256. The verifier rejects duplicate or unsafe paths,
links, special members, metadata drift, unmanifested files, missing files, and
content mismatches.

Before publication, scan the complete working tree and the unpacked public
tree for every retired namespace or prohibited release term. Repeat
`--forbid` for each term; the tool reports only term hashes so release logs do
not reintroduce retired names:

```bash
bin/letsinfer-release-audit --forbid RETIRED_TERM . --json
bin/letsinfer-release-audit --forbid RETIRED_TERM /tmp/unpacked/letsinfer --json
```

Create the public repository from the verified unpacked tree. Initialize it as
a new repository and make its first commit there; never push or graft the
private experimental repository's history. Publication additionally requires
the normal test, license/privacy, runtime OCI, signed-catalog, and portable
evidence gates.

## Automated core releases

Core releases use the protected `release` branch as their publication
boundary. A pull request targeting `release` runs the complete core tests,
builds and tests Watchdog, and verifies two byte-identical public archives. A
merge to `release` repeats those gates and then:

1. reads `PRODUCT_VERSION` and refuses an existing `vVERSION` tag;
2. builds the public archive twice and requires byte equality;
3. signs the four platform archives' canonical `SHA256SUMS` as an SSHSIG with
   the protected Ed25519 release key;
4. verifies the signing key against `core/trust/release-public-key.pem`;
5. installs the signed local assets into a temporary prefix;
6. creates provenance attestations and an immutable GitHub Release; and
7. downloads every published asset, verifies exact bytes, signature and
   attestation, and performs a second clean-prefix installation.

The `publish` job is bound to the protected `production-release` GitHub
environment. Store the base64-encoded PKCS#8 Ed25519 private key there as
`LETSINFER_RELEASE_SIGNING_KEY_B64`. The workflow never prints or publishes
the private key, and publication fails if its public half differs from the
committed trust root.

Versions containing `-rc.` become GitHub prereleases. Other versions become
the latest stable release. Every release contains exactly:

```text
letsinfer-linux-x86_64.tar.gz
letsinfer-linux-arm64.tar.gz
letsinfer-macos-x86_64.tar.gz
letsinfer-macos-arm64.tar.gz
SHA256SUMS
SHA256SUMS.sig
install.sh
```

Stable users install through the website's reviewed bootstrap, which then
fetches signed immutable GitHub Release assets:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
```

An RC or historical release uses its explicit version:

```bash
curl -fsSL https://letsinfer.ai/install.sh \
  | sh -s -- --version 0.11.0-rc.16
```

`install.sh` supports Linux and macOS on x86_64 and arm64. The default system
layout is `/opt/letsinfer` plus `/usr/local/bin` launchers and it runs
`letsinfer setup`; `--user`, `--prefix`, and `--no-setup` provide explicit
alternatives. `--no-progress` lets the `letsinfer update` command own its
three-stage TTY display; a direct curl install retains the single percentage
indicator. The website build emits the reviewed core installer byte for
byte rather than maintaining another implementation.

The macOS application has separate version/build metadata, a protected
`macos-release` branch, namespaced tags, signing, notarization, and release
assets. See [macOS release](macos-release.md).
