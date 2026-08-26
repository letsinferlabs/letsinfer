# Let's Infer

> Local AI, installed like software.

[![Release](https://img.shields.io/github/v/release/letsinferlabs/letsinfer?include_prereleases&label=release)](https://github.com/letsinferlabs/letsinfer/releases)
[![Core release](https://github.com/letsinferlabs/letsinfer/actions/workflows/release-core.yml/badge.svg?branch=release)](https://github.com/letsinferlabs/letsinfer/actions/workflows/release-core.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

Let's Infer turns local AI hardware into one reliable, OpenAI-compatible
inference service. Tell it which model you want. It detects your hardware,
selects the fastest qualified runtime, downloads the exact model and engine,
starts the service, and keeps it running.

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
```

No engine hunting. No model-file plumbing. No hardware-specific install path.

## Features

- **One-command installs** — resolve the exact model, runtime, engine, adapter,
  and dependencies from a model name.
- **Hardware-aware speed** — signed benchmarks select the fastest qualified
  runtime for your target; `--runtime` pins an exact candidate.
- **Automatic lifecycle** — start immediately, wait for API readiness, restore
  after reboot, and recover ordinary engine failures.
- **One API, every engine** — keep the same OpenAI-compatible endpoint while
  Let's Infer handles concurrency, backpressure, and memory-aware queueing.
- **Replication across your hardware** — run one model on compatible main and
  child nodes, with target-specific runtimes behind one load-balanced API.
- **Runtime-owned parallelism** — qualify exact multi-GPU or multi-node
  runtimes while core handles generic allocation, lifecycle, recovery, and one
  endpoint per complete group.
- **Live observability** — watch requests, throughput, context, cache,
  utilization, temperatures, power, network, and lifecycle in one command.
- **Built-in protection** — Watchdog tracks the exact engine process, unified
  memory, PSI, swap, cgroup events, and crashes without hiding safety trips.
- **Verifiable supply chain** — signed catalogs, exact Hugging Face revisions,
  digest-pinned OCI images, deterministic packs, and bound benchmark evidence.
- **Independent updates** — update core, upgrade a runtime, or roll back one
  without silently changing the others.
- **Reproducible benchmarks** — durable, isolated code-and-prose runs capture
  TTFT, throughput, cache state, hardware telemetry, and validated JSON.
- **Community-qualified runtimes** — independent users can verify an exact
  runtime PR; signed full evidence, transparent consensus, and verifier
  identities determine qualification without granting upload credentials.
- **Secure by default** — scoped API keys, audit records, mDNS discovery,
  private controller mTLS, and optional inference-only public exposure.

[Explore every feature →](documentation/features.md)

## Quick start

Install Let's Infer and initialize your local node:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
```

Install a model:

```bash
letsinfer model install MODEL
```

Create an API key and inspect the live service:

```bash
letsinfer auth key create my-app
letsinfer status
```

Your stable local endpoint is:

```text
http://<hostname>.local:8000/v1
```

Use it like any OpenAI-compatible API:

```bash
curl http://<hostname>.local:8000/v1/chat/completions \
  -H "Authorization: Bearer $LETSINFER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3.8-27b",
    "messages": [{"role": "user", "content": "Why is the sky blue?"}]
  }'
```

## Supported today

NVIDIA DGX Spark is the first qualified target. The signed production catalog
currently includes qualified Qwen3.8 27B NVFP4 and DeepSeek V4 Flash runtimes.
New models, quantizations, engines, kernels, and hardware targets ship as
independent runtime candidates—without adding model-specific code to core.

## Common commands

| Task | Command |
| --- | --- |
| Inspect a node and its hardware | `letsinfer node info [NODE]` |
| List catalog and installed models | `letsinfer model list` |
| Install a model | `letsinfer model install MODEL` |
| Assign models interactively | `letsinfer model install` |
| Add a child node | `letsinfer node add` |
| Pause work on a node | `letsinfer node pause [NODE]` |
| Watch live status | `letsinfer status` |
| Watch live topology and traffic | `letsinfer topology` |
| Create an API key | `letsinfer auth key create my-app` |
| Check for updates | `letsinfer update check` |
| Update Core | `letsinfer update core` |
| Update a model | `letsinfer update model MODEL` |
| Roll back a model | `letsinfer model rollback MODEL` |
| Run the C1 benchmark | `letsinfer benchmark run MODEL --c1` |
| Verify a runtime PR | `letsinfer benchmark verification run PR_URL` |
| Verify an installation | `letsinfer doctor` |
| Remove everything | `letsinfer uninstall` |

Core and runtime updates are deliberately independent. A catalog change never
silently moves a running model.

## How it works

```text
model name + verified node topology
              │
              ▼
       signed runtime catalog
              │
              ▼
 exact model + runtime pack + Engine OCI
              │
              ▼
 OpenAI-compatible gateway + Watchdog
```

Each immutable runtime binds an exact model, Engine OCI, hardware target,
serving recipe, optional optimizations, and benchmark evidence. Core stays
model- and engine-agnostic.

## Documentation

- [Features](documentation/features.md)
- [Installation](documentation/getting-started/installation.md)
- [CLI reference](documentation/reference/cli.md)
- [Nodes, replication, and trust](documentation/concepts/sites.md)
- [Runtime development](documentation/reference/runtime-format.md)
- [Updates and rollback](documentation/operations/upgrades-and-rollback.md)
- [Watchdog](documentation/operations/watchdog.md)
- [Benchmark framework](benchmarks/README.md)
- [macOS controller](apps/macos/README.md)

## Contributing

Install the official, portable
[Let’s Infer agent skills](https://github.com/letsinferlabs/skills) with:

```bash
npx skills add letsinferlabs/skills
```

Runtime authors use
[`letsinfer-runtime-authoring`](https://github.com/letsinferlabs/skills/blob/main/skills/letsinfer-runtime-authoring/SKILL.md),
radical or new Engine work uses
[`letsinfer-engine-authoring`](https://github.com/letsinferlabs/skills/blob/main/skills/letsinfer-engine-authoring/SKILL.md),
and qualification uses
[`letsinfer-benchmark`](https://github.com/letsinferlabs/skills/blob/main/skills/letsinfer-benchmark/SKILL.md).
Run the core tests with:

```bash
python3 -m tools.core_regression
```

The same complete suite and native Watchdog tests are required on every core
pull request. See [Testing and pull-request gates](documentation/contributing/testing.md).

Let's Infer is licensed under [AGPL-3.0-only](LICENSE).
