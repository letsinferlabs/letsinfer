# CLI reference

[Back to documentation](../README.md)

The installer initializes the node automatically. Run `letsinfer --help` to
list the public command groups; retired pre-launch command paths have no
aliases. `letsinfer --version` reports the shared Rust Core workspace version
without requiring initialized node state.

All 47 registered command leaves dispatch through typed Rust capabilities.
Benchmark commands execute the native `li_benchmark_worker`; neither Core nor
the worker requires host Python. An exact runtime may carry its own pinned
standalone CPython.

## Complete command tree

The following tree is the complete public command surface. Each command has
one responsibility and a two-sentence explanation directly beneath it.

### `letsinfer status`

Shows the complete node, service, hardware, model, placement-group, protection,
and telemetry state. Physically shared memory is shown as unified memory, while
discrete hosts report GPU VRAM and installed system RAM separately; use
`--json` when another program needs the result.

### `letsinfer topology`

Shows the authenticated main-and-child graph with verified links, node health,
model placements, and current host network traffic. Its live terminal view
animates one continuous main-to-child trunk independently of one-second state
polling, flows through every child before repeating, reports standalone and
placement-group placements, and pauses only placement groups that depend on a lost verified
link, while `--json` returns one exact snapshot.

### `letsinfer doctor`

Audits operational and publication readiness without changing state. Its
checks explain what is healthy, degraded, or blocking and support `--json`.

```text
letsinfer node
├── info [NODE]
├── list
├── usage
├── add
├── pause [NODE]
├── resume [NODE]
└── remove [NODE]
```

### `letsinfer node info [NODE]`

Shows a selected node's identity, role, online state, hardware, compatible
targets, and observed links. Omit `NODE` for the role-aware selector, or use
`--json` without a target to retain local-node automation.

### `letsinfer node list`

Lists the main and every child with role, availability, placement, and health
state. Use `--json` to consume the topology without parsing the human table.

### `letsinfer node usage`

Shows local Let’s Infer storage by category, filesystem free space, and the
exact inactive data that can be reclaimed. Use `--clean` to remove reviewed
completed benchmarks, inactive model data, and rebuildable caches; `--category`
limits the plan, `--yes` enables non-interactive cleanup, and removed model data
is downloaded and verified again before any affected runtime starts.

### `letsinfer node add`

Opens, joins, or approves one certificate-bound child-pairing workflow. LAN and
remote invitations present one eight-digit setup code; the joining Node reads
it from the controlling terminal rather than argv or environment. Remote mode
then presents the same six-digit comparison code on both Nodes: the child must
confirm the match locally and the main must run `--approve INVITATION --yes`
before activation completes. ConnectX mode binds the preapproved key,
interface, and direct route without overwriting an external network plan. The
final child activation or standalone restoration is one atomic Node-owned
operation and fails closed if the owner-authenticated local `li_node` socket is
unavailable.

### `letsinfer node pause [NODE]`

Stops assigning new work to the selected node while retaining membership and
placement records. Omit `NODE` for the selector; a child can pause itself
through the main, and self/main targets require interactive confirmation.

### `letsinfer node resume [NODE]`

Restores new-work admission to a paused selected node without recreating
membership or model state. A child can resume itself through the main, and an
explicit node keeps automation deterministic.

### `letsinfer node remove [NODE]`

On a main, removes a selected child after confirmation and refuses while a
live placement depends on it. On a child, removes itself through authenticated
coordinated detach and becomes a standalone addable main.

```text
letsinfer model
├── list [MODEL]
├── install [MODEL]
├── remove MODEL
├── pause MODEL
├── resume MODEL
├── restart MODEL
├── recover MODEL
├── rollback MODEL
└── logs MODEL
```

### `letsinfer model list [MODEL]`

Shows the signed catalog and installed models in one view, with installed and
recommended versions clearly marked. Filters expose installed entries, exact
versions, compatible targets, refreshed catalog state, and JSON output.

### `letsinfer model install [MODEL]`

Installs a named model through the signed catalog and target matcher, accepts
an explicit local runtime directory, archive, or digest-pinned runtime OCI, or
opens the node/model selector when `MODEL` is omitted. Assigning the same model
to multiple compatible nodes creates replicas automatically, while an exact
operator-selected source remains unqualified but receives the ordinary
managed group and route; use `--node` to bind a compatible node, and use OCI
when a content-addressed local object is not already present on a remote child.

### `letsinfer model remove MODEL`

Removes the selected model from one node or, with explicit confirmation, from
all nodes that host it. Safety checks prevent ambiguous or dependency-breaking
removal.

### `letsinfer model pause MODEL`

Stops admitting new inference work for the selected logical model without
deleting its immutable runtime or placement. The paused model remains visible
in status and can be resumed later.

### `letsinfer model resume MODEL`

Returns a paused logical model to service after its existing safety checks
pass. Resume does not clear a protection trip or replace recovery.

### `letsinfer model restart MODEL`

Restarts the selected model's placement groups while preserving its chosen
runtime and safety history. Use it for ordinary lifecycle recovery, not as an
acknowledgement of a Watchdog protection event.

### `letsinfer model recover MODEL`

Explicitly acknowledges a protection trip and attempts recovery after its
cause has been corrected. This is the only lifecycle command permitted to
clear that protected state.

### `letsinfer model rollback MODEL`

Plans or applies a rollback to the retained prior immutable runtime for the
selected model. Use `--target TARGET` to restrict one target, `--dry-run` to
review every exact current-to-previous group and version change, and `--yes`
to confirm mutation; rollback reuses retained installation identities without
catalog resolution, and an activation failure reconstructs the current runtime
before returning failure.

### `letsinfer model logs MODEL`

Streams or tails logs for the selected model's local placement group. Specify a
placement group with `--placement-group PLACEMENT_GROUP_ID` only when multiple
local placement groups make selection ambiguous.

```text
letsinfer benchmark
├── run MODEL
├── list MODEL
├── status
├── stop
├── clean
└── verification
    ├── run PULL_REQUEST_URL
    ├── status
    └── stop
```

### `letsinfer benchmark run MODEL`

Starts the canonical benchmark matrix for an installed model and returns after
the durable job is accepted. The resident Node continues the work;
`benchmark status` monitors it and `benchmark stop` requests cancellation.

### `letsinfer benchmark list MODEL`

Lists the benchmark cells that would run for the selected model and workload
options. It is a read-only way to inspect the matrix before consuming runtime
capacity.

### `letsinfer benchmark status`

Shows the active ordinary benchmark job, progress, workload, and durable state,
or reports that no ordinary benchmark is active. Use `--json` for monitoring
and CI integrations.

### `letsinfer benchmark stop`

Requests durable cancellation of the active ordinary benchmark and returns its
current stopping state. The resident Node completes worker exit and serving
restoration asynchronously.

### `letsinfer benchmark clean`

Removes completed local benchmark working data after explicit confirmation.
It does not delete installed models or reinterpret failed evidence as a pass.

### `letsinfer benchmark verification run PULL_REQUEST_URL`

Runs the public verification contract against the exact finalized artifact for
an eligible runtimes pull request and returns after the durable job is accepted.
`--detach` changes only the start message because execution is always
resident-owned; Core never executes pull-request source or promotes an author's
local result into qualification.

### `letsinfer benchmark verification status`

Shows progress and outcome for the active pull-request verification job, or
reports that no verification is active. Its JSON form is suitable for durable
monitoring.

### `letsinfer benchmark verification stop`

Requests durable cancellation of the active verification job and returns its
current stopping state. The resident Node restores prior serving state
asynchronously and does not edit the pull request or publish evidence.

```text
letsinfer auth
├── controller
│   ├── add
│   ├── list
│   └── revoke CONTROLLER
└── key
    ├── create NAME
    ├── list
    ├── show KEY
    ├── rotate KEY
    ├── revoke KEY
    └── update KEY
```

### `letsinfer auth controller add`

Opens the transient TLS pairing listener and displays the human comparison
code for one controller. Ctrl-C closes the listener and reports `Pairing
cancelled` without persisting an unfinished enrollment.

### `letsinfer auth controller list`

Lists enrolled controllers and their non-secret identity and policy state.
This sensitive read is audited and supports machine-readable output.

### `letsinfer auth controller revoke CONTROLLER`

Revokes the selected controller's authority to manage the main. The operation
is audited and does not affect unrelated inference API keys.

### `letsinfer auth key create NAME`

Creates an inference API key and optional policy for the named application.
The plaintext secret is shown exactly once and is never written to the audit
chain.

### `letsinfer auth key list`

Lists API-key identities, policy summaries, and lifecycle state without
revealing plaintext secrets. This sensitive read is audited and supports
JSON.

### `letsinfer auth key show KEY`

Shows one key's metadata and effective policy without recovering its original
secret. Use the key identifier or unambiguous name reported by `auth key
list`.

### `letsinfer auth key rotate KEY`

Replaces a key's secret while preserving its application identity and current
policy. The replacement secret is displayed once and the prior secret becomes
invalid.

### `letsinfer auth key revoke KEY`

Permanently disables the selected inference API key. The audited revocation
does not expose the key's plaintext value.

### `letsinfer auth key update KEY`

Updates the selected key's model scope, expiry, rate, concurrency, context,
tenant, or application policy. Unspecified policy fields retain their current
values rather than being silently reset.

```text
letsinfer exposure
├── status
├── enable
└── disable
```

### `letsinfer exposure status`

Shows whether the authenticated inference gateway is exposed beyond its local
network boundary and reports the effective endpoint state. The command is
read-only and supports JSON.

### `letsinfer exposure enable`

Enables the configured public exposure path for the authenticated inference
gateway after readiness checks pass. It does not make node-control or pairing
interfaces public.

### `letsinfer exposure disable`

Disables the configured public inference exposure while leaving local serving
and model placement intact. The audited change does not revoke existing API
keys.

```text
letsinfer audit
├── list
├── show EVENT
├── verify
└── export --output FILE
```

### `letsinfer audit list`

Lists audit events in chain order with their non-secret summaries. Filters and
JSON output support bounded operational review.

### `letsinfer audit show EVENT`

Shows the complete recorded fields for one audit event without exposing
plaintext credentials, prompts, or responses. The event identifier comes from
`audit list`.

### `letsinfer audit verify`

Verifies the append-only audit chain and reports the first integrity failure
if one exists. It performs no repair or mutation.

### `letsinfer audit export --output FILE`

Writes the bounded audit export to the explicitly selected file. Exported
records preserve chain evidence while excluding prompts, responses, and
plaintext credentials.

```text
letsinfer update
├── check
├── core [VERSION]
└── model [MODEL]
```

### `letsinfer update check`

Checks Core and installed-model update availability without applying changes.
It works before full node initialization and supports JSON.

### `letsinfer update core [VERSION]`

Stages, verifies, and activates the recommended Core release or the explicitly
selected version. Core updates do not silently change installed model
runtimes.

### `letsinfer update model [MODEL]`

Plans or applies a qualified runtime update for one installed model, or opens
the installed-model selector when `MODEL` is omitted. Use `--dry-run` to
inspect every affected placement group before activation.

### `letsinfer uninstall`

Removes Let’s Infer-owned services, containers, images, and data after explicit
confirmation. Use `--keep-models` to preserve model storage within the stated
uninstall boundary. Before retiring services, uninstall asks local `li_node` to
enumerate and remove exact runtime installations; it never opens the primary
database and fails closed when the `li_node` socket is unavailable.

## Machine-readable output

Use `--json` where declared for automation. Human presentation may evolve,
while JSON documents, raw log streams, exported artifacts, and exit status are
the durable contracts.

Runtime development and deterministic pack authoring are intentionally absent
from the product CLI. Those workflows live in the public
`letsinfer-runtime-authoring` skill.
