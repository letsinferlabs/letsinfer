# Upgrades and rollback

[Back to documentation](../README.md)

Check both independently distributed layers without changing either one:

```bash
letsinfer update check
```

Core availability is advertised by the GitHub release channel and runtime
availability by the signed catalog's immutable OCI digest for the selected
model/engine/target. The site agent refreshes this state hourly. Normal
CLI commands only read the local identity-bound snapshot, so an unavailable
registry or catalog cannot delay inference administration. The notice tells
the user what can move; it never applies an update automatically. The core
installer still verifies checksums and the release signature before applying.
The advisory snapshot is the private node-local database
`$LETSINFER_HOME/state/updates.sqlite3`; it contains component identities,
versions, immutable sources, and verification timestamps, never credentials.

Update core without changing runtime selection:

```bash
letsinfer update
```

Core update installs the new immutable identity beside the active one, rebinds
the existing services and runtime, and verifies the new launcher. Only after
those checks pass does it remove superseded validated core identities, stale
unreferenced control bundles, and old Watchdog builds. A failed handoff keeps
the previous core bytes available for recovery. Runtime objects, models,
benchmark evidence, and runtime rollback history are never part of core
garbage collection.

Upgrade follows the policy recorded at installation:

- `recommended` follows the catalog's current recommended engine;
- `engine:NAME` stays on that engine's release line;
- `pinned`, `local`, and `derived` do not move without `--to`.

Preview an upgrade:

```bash
letsinfer upgrade example-model --dry-run
```

Apply it:

```bash
letsinfer upgrade example-model
```

Select an explicit immutable artifact instead of the recorded policy:

```bash
letsinfer upgrade example-model \
  --to ghcr.io/example/runtime@sha256:...
```

Let's Infer verifies and stages the new runtime before stopping the old service.
It then performs the same transactional service replacement as installation:
exact artifacts, model, image, target, memory, Watchdog, health, authentication,
and model identity must pass. A failed activation restores the prior config,
units, immutable core/runtime service bundle, and running service.

Successful selections retain the previous runtime object and receipt:

```bash
letsinfer rollback example-model --dry-run
letsinfer rollback example-model
```

Rollback reuses the retained immutable object; it does not resolve a mutable
tag or reinterpret the prior catalog. Derived candidates do not automatically
rebase when their parent is upgraded. Create a new derivation and inspect its
resolved diff instead.
