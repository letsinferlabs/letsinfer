# CLI reference

[Back to documentation](../README.md)

Run `letsinfer COMMAND --help` for the exact options in your installed version.
The commands below describe the stable public workflow.

## Set up your node

```bash
letsinfer setup
letsinfer node status
letsinfer hardware
```

The first machine becomes the main node. It owns the stable inference gateway,
runtime selection, API-key registry, audit chain, and replica scheduling.

Use `topology` and `child` to inspect or manage additional nodes. Every
command has an execution scope: `main`, `child`, or `all`.

## Install a model

```bash
letsinfer list
letsinfer install qwen3.8-27b
```

`letsinfer list` shows every qualified runtime compatible with your hardware,
including all runtime authors and the recommended candidate. Use
`letsinfer list MODEL --versions` to see retained releases, `--all-targets` to
inspect other hardware, `--refresh` to require a fresh signed catalog, and
`--json` for structured output.

Let's Infer detects your target and installs the recommended qualified
candidate from the signed catalog. The runtime downloads its exact model and
Engine OCI automatically.

On a main node with children, an interactive install can offer to replicate
the model. You can also select nodes explicitly:

```bash
letsinfer install qwen3.8-27b --node Home --node Workshop
letsinfer install qwen3.8-27b --all-nodes
letsinfer scale qwen3.8-27b --replicas 3
```

Each selected node independently resolves the fastest qualified runtime for
its hardware. Let's Infer shows incompatible nodes and replacement impact
before making changes. Use `--replace-existing` only after reviewing that
impact.

To pin one exact candidate:

```bash
letsinfer install qwen3.8-27b \
  --runtime sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark
```

There is no engine selector. If you want a different engine, checkpoint,
quantization, or recipe, choose or build a different runtime candidate.

Useful development controls:

- `--catalog LOCATION` uses an explicit catalog.
- `--no-download` requires every model and OCI blob to exist already.
- `--no-start` installs and enables services without starting inference.
- `--no-service` skips user-service installation.

## Run and inspect

```bash
letsinfer status
letsinfer status --json
letsinfer runtimes
letsinfer inspect qwen3.8-27b
letsinfer verify qwen3.8-27b
letsinfer doctor
letsinfer logs
```

Interactive `status` refreshes until you press Ctrl-C. Its API, runtime,
admission, throughput, Watchdog, system, and temperature sections come from the
same normalized state plane used by other consumers.

`letsinfer list` is discovery from the signed public catalog. `letsinfer
runtimes` shows only immutable packs already installed on your machine.

Lifecycle commands:

```bash
letsinfer start
letsinfer restart
letsinfer stop
letsinfer recover
```

`recover` is an explicit acknowledgement after you inspect a protection trip.
Ordinary start or restart does not erase safety history.

## API keys

```bash
letsinfer key create my-app
letsinfer key list
letsinfer key rotate KEY_ID
letsinfer key revoke KEY_ID
```

Key mutations are main-only and enter the node audit chain. Secret key
material is shown once. Do not place it in source, logs, benchmark evidence, or
shell history.

## Benchmark

```bash
letsinfer benchmark qwen3.8-27b --c1
letsinfer benchmark
letsinfer benchmark stop
letsinfer benchmark clean
```

Starting a benchmark creates a durable job. Ctrl-C detaches; it does not cancel
the job. Running `letsinfer benchmark` attaches to live progress, and
`benchmark stop` cancels the active job. Use context and concurrency switches
such as `--32k`, `--64k`, `--c1`, or `--c8` to select cells.

`benchmark clean` asks for confirmation and removes only locally generated
benchmark data.

## Core and runtime updates

```bash
letsinfer update check
letsinfer update
letsinfer upgrade qwen3.8-27b
letsinfer rollback qwen3.8-27b
```

`update check` refreshes core and active-runtime availability. Every
interactive command can show the cached update notice without blocking on the
network.

`update` changes core and leaves installed runtimes unchanged. `upgrade`
changes the runtime and leaves core unchanged. `rollback` reinstalls the
retained previous runtime. No catalog change silently moves a running model.

Use `--dry-run` on upgrade or rollback to inspect the transition first.

## Runtime development

```bash
letsinfer pack ./candidate --output /tmp/candidate.letsinfer
letsinfer install /tmp/candidate.letsinfer
letsinfer inspect <candidate-id> --json
letsinfer serve <candidate-id> --qualification-mode \
  --evidence-dir /new/empty/evidence
```

Local candidates are unqualified. Qualification mode never promotes a
candidate automatically or makes it boot-persistent.

## Local data and removal

```bash
letsinfer uninstall
letsinfer uninstall --keep-models
```

Uninstall asks for confirmation, removes Let's Infer-managed services and
containers by exact identity, and removes `$LETSINFER_HOME`.
`--keep-models` preserves only the model directory.

## Public exposure

Your LAN endpoint is advertised through mDNS. Use `exposure` to inspect public
state, `expose` to publish only the inference gateway through the configured
secure transport, and `unexpose` to disable it. Public exposure never publishes
the controller or Watchdog endpoints.

## Machine-readable output

Prefer `--json` for automation. Human output, progress animation, and update
notices may evolve; JSON fields and exit status are the automation contract.
