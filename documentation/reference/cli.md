# CLI reference

[Back to documentation](../README.md)

The installer initializes the node automatically. Run `letsinfer COMMAND
--help` for exact options in the installed release; retired pre-launch command
paths have no aliases.

## Complete command tree

The following tree is the complete public command surface. Each command has
one responsibility and a two-sentence explanation directly beneath it.

### `letsinfer status`

Shows the complete node, service, hardware, model, engine-group, protection,
and telemetry state. Use `--json` when another program needs the result.

### `letsinfer topology`

Shows the authenticated main-and-child graph with verified links, node health,
model placements, and current host network traffic. Its live terminal view
animates independently of one-second state polling, reports standalone and
engine-group placements, and pauses only groups that depend on a lost verified
link, while `--json` returns one exact snapshot.

### `letsinfer doctor`

Audits operational and publication readiness without changing state. Its
checks explain what is healthy, degraded, or blocking and support `--json`.

```text
letsinfer node
├── info [NODE]
├── list
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

### `letsinfer node add`

Shows incoming requests and discovers certificate-identified nodes that can be
adopted as children. The main selects the pinned node and the candidate accepts
that exact request locally, which activates the child without a second code;
provider-owned high-speed networking is prepared without overwriting an
external plan, while child invocation confirms coordinated detach and returns
the machine to standalone discovery.

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

Installs a named model through the signed catalog and target matcher, or opens
the node/model selector when `MODEL` is omitted. Assigning the same model to
multiple compatible nodes creates replicas automatically, while different
selections create independent services.

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

Restarts the selected model's engine groups while preserving its chosen
runtime and safety history. Use it for ordinary lifecycle recovery, not as an
acknowledgement of a Watchdog protection event.

### `letsinfer model recover MODEL`

Explicitly acknowledges a protection trip and attempts recovery after its
cause has been corrected. This is the only lifecycle command permitted to
clear that protected state.

### `letsinfer model rollback MODEL`

Plans or applies a rollback to the retained prior immutable runtime for the
selected model. Use `--dry-run` to review the exact groups and version change
before mutation.

### `letsinfer model logs MODEL`

Streams or tails logs for the selected model's local engine group. Specify a
group only when more than one local group makes the model selection ambiguous.

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

Starts or resumes the canonical benchmark matrix for an installed model and
the requested workload options. The job is durable, so Ctrl-C detaches while
`benchmark stop` performs cancellation.

### `letsinfer benchmark list MODEL`

Lists the benchmark cells that would run for the selected model and workload
options. It is a read-only way to inspect the matrix before consuming runtime
capacity.

### `letsinfer benchmark status`

Shows the active or most recent benchmark job, progress, workload, and durable
result state. Use `--json` for monitoring and CI integrations.

### `letsinfer benchmark stop`

Requests durable cancellation of the active ordinary benchmark and waits for
its restoration boundary. It is distinct from Ctrl-C, which only detaches the
terminal.

### `letsinfer benchmark clean`

Removes completed local benchmark working data after explicit confirmation.
It does not delete installed models or reinterpret failed evidence as a pass.

### `letsinfer benchmark verification run PULL_REQUEST_URL`

Runs the public verification contract against the exact finalized artifact
for an eligible runtimes pull request. It never executes pull-request source
or promotes an author's local result into qualification.

### `letsinfer benchmark verification status`

Shows progress and outcome for the active or most recent pull-request
verification job. Its JSON form is suitable for durable monitoring.

### `letsinfer benchmark verification stop`

Requests durable cancellation of the active verification job and restores the
prior serving state. It does not edit the pull request or publish evidence.

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
inspect every affected engine group before activation.

### `letsinfer uninstall`

Removes Let’s Infer-owned services, containers, images, and data after explicit
confirmation. Use `--keep-models` to preserve model storage within the stated
uninstall boundary.

## Machine-readable output

Use `--json` where declared for automation. Human presentation may evolve,
while JSON documents, raw log streams, exported artifacts, and exit status are
the durable contracts.

Runtime development and deterministic pack authoring are intentionally absent
from the product CLI. Those workflows live in the public
`letsinfer-runtime-authoring` skill.
