# Let's Infer documentation

Let's Infer turns local AI hardware into one reliable, OpenAI-compatible
inference service. Start with a model name; Let's Infer handles the target,
runtime, model artifacts, engine, lifecycle, safety, and telemetry.

## Features at a glance

- one-command, hardware-aware model installation;
- automatic start, reboot persistence, and ordinary crash recovery;
- one stable OpenAI-compatible API across engines;
- dynamic request admission and memory-aware queueing;
- live throughput, request, cache, temperature, power, and system telemetry;
- independent Watchdog protection with explicit safety recovery;
- signed, digest-pinned, reproducible runtimes and benchmarks;
- independent core/runtime updates with runtime rollback; and
- secure mDNS discovery, scoped API keys, controller pairing, and audit.

[Explore every feature](features.md)

## Start here

- [Installation](getting-started/installation.md)
- [Features](features.md)
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
