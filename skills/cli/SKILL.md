---
name: cli
description: Use and troubleshoot the Let's Infer CLI for setup, signed runtime installation, model acquisition, serving, benchmarks, updates, rollback, site administration, keys, telemetry, and removal.
---

# Use the Let's Infer CLI

Read [`references/commands.md`](references/commands.md) before constructing a
command. Prefer the installed `letsinfer`. Use the source-tree launcher only
while developing core.

## Preserve the architecture

- Install the model you want with `letsinfer install MODEL`.
- Use `--runtime CANDIDATE_ID` only to pin one exact candidate.
- Never ask the operator to select an engine or enter a target source path.
- Let the signed catalog and detected hardware choose the qualified candidate.
- Treat core updates and runtime upgrades as independent operations.
- Treat a local runtime directory, archive, or OCI digest as an unqualified
  source until its complete qualification contract passes.

## Work safely

1. Inspect `hardware --json`, `status --json`, `doctor --json`, and
   `inspect --json` before a mutation.
2. Use `--dry-run` on upgrade and rollback when available.
3. Keep API keys, TLS material, controller credentials, and registry tokens out
   of commands, logs, manifests, and evidence.
4. Do not bypass target compatibility, Engine OCI identity, model revision,
   runtime digest, or catalog signature checks.
5. Do not clear a protection trip with start or restart. Inspect it and use
   `recover` only after explicit acknowledgement.
6. Respect the `coordinator`, `member`, or `all` scope printed in command help.
   A member never proxies a coordinator-only command.

## Choose the operation

- Site: `setup`, `site`, `topology`, `member`.
- Discover: `hardware`, `runtimes`, `inspect`.
- Install: `install`, `acquire`, `verify`, `pack`.
- Run: `serve`, `status`, `doctor`, `logs`, `start`, `restart`,
  `recover`, `stop`.
- Benchmark: `benchmark`, `benchmark stop`, `benchmark clean`.
- Update: `update check`, `update`, `upgrade`, `rollback`.
- Access and trust: `key`, `pair`, `controllers`, `alias`, `audit`,
  `exposure`, `expose`, `unexpose`.
- Remove: `uninstall`, optionally `--keep-models`.

Do not invoke internal service commands directly.

## Local candidates

Package a candidate with:

```bash
letsinfer pack ./candidate --output /tmp/candidate.letsinfer
```

Install the archive as a local source. An unqualified runtime remains blocked
for ordinary activation. Launch it only through explicit qualification mode
with a new evidence directory. Qualification mode does not promote it or make
it boot-persistent.

## Benchmarks

`letsinfer benchmark MODEL` starts a durable job. Ctrl-C detaches. Running
`letsinfer benchmark` with no model attaches to live progress.
`letsinfer benchmark stop` cancels the active job. Do not run a second
benchmark while one is active.

## Updates

`letsinfer update` installs signed core bytes and leaves runtime selections,
models, and benchmark evidence unchanged. `letsinfer upgrade MODEL` moves the
runtime according to its recorded policy and retains bounded rollback history.
Never claim an update succeeded until the new launcher, services, API, and
runtime identity all verify.

After any mutation, inspect machine-readable state and verify the exact runtime,
Engine OCI, model revision, service lifecycle, Watchdog state, and API.
