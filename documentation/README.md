# Let's Infer documentation

Let's Infer installs exact model/engine/target runtimes and serves them through one
guarded, OpenAI-compatible endpoint. NVIDIA DGX Spark is the first supported
hardware target. Start with the
[installation guide](getting-started/installation.md), then use these references
when you need more detail:

- [Runtime packs](concepts/runtime-packs.md) explains the model/engine/target package
  boundary and why each installed artifact is immutable.
- [Sites, members, and trust](concepts/sites.md) explains coordinator authority,
  discovery, membership, topology, the unified gateway, and security planes.
- [Engine adapters](concepts/engine-adapters.md) defines what Let's Infer owns and
  what an inference engine owns.
- [Runtime format](reference/runtime-format.md) documents `runtime.json`, built
  artifacts, catalogs, and receipts.
- [CLI reference](reference/cli.md) lists the public commands and important
  options.
- [Upgrades and rollback](operations/upgrades-and-rollback.md) describes update
  policies and failure recovery.
- [Source release](operations/source-release.md) defines the deterministic
  public archive and clean-history boundary.
- [macOS release](operations/macos-release.md) defines the app-owned version,
  signing, notarization, and namespaced publication lifecycle.
- [Watchdog](operations/watchdog.md) covers the always-running telemetry and
  crash/OOM protection service.

Let's Infer currently implements its first target contract for a 128 GB
GB10/SM121 DGX Spark. The external signed catalog publishes the first qualified
runtime, DeepSeek V4 Flash with DwarfStar, for that target; core itself
publishes none. The core maps runtimes
through stable device capabilities and can
represent future discrete or multi-GPU targets, but each requires independent
runtime contents and qualification. Engine agnosticism means that vLLM,
SGLang, llama.cpp, and DwarfStar share the same control and safety boundary; it
does not transfer evidence across engines or targets.
