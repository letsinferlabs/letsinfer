# Core and runtime updates

[Back to documentation](../README.md)

Check core and runtime availability without changing either one:

```bash
letsinfer update check
```

Core availability comes from the signed GitHub release channel. Runtime
availability comes from the signed catalog and immutable OCI digest for every
distinct installed engine-group release. Exact replicas are deduplicated;
mixed target-specific or temporarily mixed-version groups remain separate.
The node agent refreshes this state periodically, and
interactive commands read the local snapshot without delaying administration
on a network request.

The private update database is
`$LETSINFER_HOME/state/updates.sqlite3`. It stores component identities,
versions, immutable sources, results, and verification times—never
credentials. Every catalog consumer shares the last verified immutable
snapshot below `$LETSINFER_HOME/state/catalog/`; a damaged cache is replaced by
a fresh signature-verified download and a temporary network failure may use the
last verified snapshot without changing a running runtime.

## Update core

```bash
letsinfer update core
```

Core update installs the new immutable version beside the active one, rebinds
your existing services and unchanged runtime, and verifies the launcher and
service handoff. Only then does it remove superseded validated core versions,
unreferenced control bundles, and old Watchdog builds.

If the handoff fails, the previous core remains available. Core cleanup never
removes runtime rollback objects, models, benchmark evidence, or runtime
selection history.

## Update a model runtime

Your installation records one policy:

- `recommended` follows the current catalog recommendation;
- `runtime:CANDIDATE_ID` stays on that exact candidate line;
- pinned or local development artifacts are not updated by the product CLI.

Preview and apply:

```bash
letsinfer update model qwen3.8-27b --dry-run
letsinfer update model qwen3.8-27b
```

Let's Infer verifies and stages the candidate before replacing the active
service. Model, Engine distribution, runtime pack, target, memory, Watchdog, health,
authentication, and served identity must all pass. A failed activation restores
the previous configuration and running service.

## Roll back

```bash
letsinfer model rollback qwen3.8-27b --dry-run
letsinfer model rollback qwen3.8-27b
```

Rollback uses the retained immutable object and receipt. It never resolves a
mutable tag or reinterprets the old catalog entry.

Core update, runtime upgrade, and rollback are explicit independent actions.
None silently changes the other component.
