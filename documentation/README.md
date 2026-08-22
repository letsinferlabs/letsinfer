# Let's Infer documentation

Tell Let's Infer which model you want to run. It detects your hardware,
resolves the best qualified runtime, and serves it through one
OpenAI-compatible site gateway.

## Start here

- [Installation](getting-started/installation.md)
- [CLI reference](reference/cli.md)
- [Runtime format](reference/runtime-format.md)
- [Runtime candidates](concepts/runtime-packs.md)
- [Engine protocol and Engine OCI](concepts/engine-adapters.md)
- [Sites, members, and trust](concepts/sites.md)

## Operations

- [Core and runtime updates](operations/upgrades-and-rollback.md)
- [Watchdog](operations/watchdog.md)
- [Core release process](operations/source-release.md)
- [macOS app release process](operations/macos-release.md)

The public contract is runtime schema 3, runtime artifact schema 3, catalog
schema 4, and Engine protocol 1. Unsupported schemas fail closed.
