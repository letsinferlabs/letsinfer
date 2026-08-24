# Let's Infer command surface

Always confirm exact options with `letsinfer COMMAND --help`.

## Site and topology

- `letsinfer setup`
- `letsinfer site status`
- `letsinfer topology [--json]`
- `letsinfer member ...`
- `letsinfer alias ...`
- `letsinfer hardware [--catalog LOCATION] [--json]`

## Runtime installation and lifecycle

- `letsinfer install MODEL [--runtime CANDIDATE_ID] [--catalog LOCATION]`
- `letsinfer runtimes`
- `letsinfer inspect RUNTIME [--target TARGET] [--port PORT] [--command] [--json]`
- `letsinfer acquire MODEL [--target TARGET] [--model-cache PATH]`
- `letsinfer verify MODEL [--target TARGET] [--model-cache PATH] [--source-only]`
- `letsinfer serve MODEL [--target TARGET] [--qualification-mode --evidence-dir PATH] [--dry-run]`
- `letsinfer start`
- `letsinfer restart`
- `letsinfer recover`
- `letsinfer stop [--name CONTAINER]`

Pass the model you want to the install command. `--runtime` pins one exact
candidate. You never need to select an engine.

## Runtime development

- `letsinfer pack SOURCE --output FILE`

Install a local directory, `.letsinfer` archive, or digest-pinned runtime OCI by
passing that source as the positional `MODEL` value to `install`. Local
candidates do not become qualified automatically.

There is no `letsinfer runtime init`, `runtime validate`, `runtime build`, or
`runtime test` command family. Contributor agents use the runtimes repository's
versioned tools and skills for those operations; the installed product CLI
keeps only the generic pack, install, inspect, qualification, and benchmark
surfaces.

## Benchmark

- `letsinfer benchmark RUNTIME [--c1|--c2|--c4|--c8|--c16] [--32k|--64k|--128k|--256k]`
- `letsinfer benchmark`
- `letsinfer benchmark stop`
- `letsinfer benchmark clean [--yes]`
- `letsinfer benchmark RUNTIME --list ...`
- `letsinfer benchmark verify PULL_REQUEST_URL`
- `letsinfer benchmark verify status`
- `letsinfer benchmark verify stop`

Ctrl-C detaches from an active benchmark. It does not stop the worker.

## Updates

- `letsinfer update check [--json]`
- `letsinfer update [--version VERSION]`
- `letsinfer upgrade RUNTIME [--target TARGET] [--catalog LOCATION] [--to SOURCE] [--dry-run]`
- `letsinfer rollback RUNTIME [--target TARGET] [--dry-run]`

Core update never changes runtimes. Runtime upgrade never changes core.

## Status and diagnostics

- `letsinfer status [--json]`
- `letsinfer doctor [--json]`
- `letsinfer logs ...`

Interactive status refreshes until Ctrl-C. Use JSON for automation.

## Keys, controllers, and audit

- `letsinfer key create|list|rotate|revoke ...`
- `letsinfer pair ...`
- `letsinfer controllers ...`
- `letsinfer audit ...`

Key and controller mutations are coordinator-only and audited.

## Exposure

- `letsinfer exposure`
- `letsinfer expose ...`
- `letsinfer unexpose`

Only the inference gateway may be published. Controller and Watchdog endpoints
remain private.

## Removal

- `letsinfer uninstall [--keep-models]`

Uninstall requires interactive confirmation and removes the managed Let's
Infer home. `--keep-models` preserves only downloaded model snapshots.
