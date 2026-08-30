# Nodes, replication, and trust

[Back to documentation](../README.md)

A Let's Infer node is one managed inference environment. The first node you
set up becomes the **main** node. Any machines you join to it become **child**
nodes. Together they present one stable OpenAI-compatible endpoint even when
the machines use different GPUs or different target-specific runtimes.

## Main authority

Each `li_node` resident exclusively owns its local primary database. The main
node's NodeManager owns cluster membership, child enrollment, controller
roles, API-key policy, audit chain, topology, model services, aggregate
telemetry, and routing authority. It can also serve inference itself. There
is one explicit main node; Let's Infer does not silently elect another or
forward mutating CLI commands from a child.

Every CLI leaf declares one execution scope:

- `main` runs only on the main node;
- `child` runs only on a child node; and
- `all` runs in either role.

Scope is checked before a handler or side effect runs. Rejected commands tell
you where the main node is. Mutations and denials enter the tamper-evident
audit chain without recording secrets, prompts, or responses.

## Discovery is not authorization

The node service advertises `_letsinfer._tcp` with public identity and pairing
hints only. It never advertises credentials, models, telemetry, or private
administrative state. Trust is established separately:

- On an active main, `letsinfer node add` opens one bounded invitation and
  shows its eight-digit setup code once. A standalone joining Node runs
  `letsinfer node add --join` and reads that setup code from its controlling
  terminal rather than argv or environment.
- Remote pairing also presents the same six-digit comparison code on both
  Nodes. The child confirms the match locally, and the main activates the
  pending child only through `letsinfer node add --approve INVITATION --yes`.
  A configured Node is never adopted silently, and invalid role or lifecycle
  state fails before membership changes.

The Mac app creates a non-exportable P-256 controller key. Pairing issues a
node-scoped certificate after code and human-comparison checks. Viewer,
operator, and administrator roles control telemetry, lifecycle, and sensitive
administration. The private controller API exposes fixed typed operations;
there is no arbitrary shell route.

## Physical link lifecycle

Core treats node membership and placement-group data links as separate scopes.
Platform providers may prepare addressing for supported high-speed hardware,
but generic topology accepts a link only after mutual certificate and direct
route proof. Losing that proof pauses only placement groups whose immutable connection
plans require the link. The nodes remain online over their management network,
the gateway keeps routing unaffected placement groups, and reconnection requires an
explicit model resume rather than silently restarting work.

## Replication

A model service is the logical model your clients request. It may contain one
or more independent placement groups. Each placement group has its own immutable
runtime release, target, assigned GPU UUIDs, endpoint, health, capacity, and
telemetry. This lets the same model run across mixed hardware as long as the
catalog contains a qualified runtime for every selected node.

From the main node, install on one or more exact nodes:

```text
letsinfer model install MODEL --node NODE
letsinfer model install MODEL --node NODE_A --node NODE_B
letsinfer model install
```

An interactive install can offer replication across active nodes. Before an
installed model changes runtime, `letsinfer update model` shows which nodes are
compatible and which exact runtime each one resolves to. Incompatible nodes
are reported with a reason, and the update requires explicit confirmation.

Each physical GPU can belong to only one active placement group. Allocations are sealed
by exact GPU UUID and only those devices are exposed to the Engine container.
Starting, stopping, or failing one replica does not implicitly stop the other
replicas.

## Local storage lifecycle

`letsinfer node usage` runs on either role and accounts only for the local
node’s Let’s Infer home. Cleanup never crosses into a child remotely, follows a
symlink, removes active model data, or invokes a broad Docker prune.

Stopped replicas and stopped placements within a parallel runtime may release
their local model snapshots and rebuildable caches after an explicit cleanup
review.
Their sealed runtime plans remain installed; the next start downloads and
verifies the exact declared revisions on each affected node before admitting
the placement group, and the lifecycle result names every node that downloaded data
again.

The main gateway chooses a healthy replica using capacity, queue depth,
pressure, temperature, and bounded prefix-affinity hints. It retries another
placement group only before response streaming begins. If every compatible placement group is
temporarily full, the request waits in the shared admission queue instead of
overloading a runtime.

Runtime upgrades roll one placement group at a time. A failed replacement is removed and
the exact prior signed release is restored for that placement group before the upgrade
stops. Rollback likewise reinstalls retained immutable release identities
rather than re-resolving the latest catalog.

## Parallel runtimes

Replication and tensor/pipeline parallelism are different. Core owns replica
placement and load balancing. A runtime owns TP/PP topology, private ranks,
interconnect requirements, kernels, and engine configuration. Core assigns
only generic task IDs, exact node and GPU UUIDs, ports, addresses, credentials,
and verified connection facts. A parallel runtime may consume multiple
machines or GPUs as one atomic placement group; the gateway publishes its single
endpoint only after every required task is ready. Complete parallel placement groups can
also be replicated. Core never invents parallelism from a single-device
runtime.

## Health and maintenance

Every node signs bounded hardware, capacity, health, and link facts. The main
node verifies certificate identity, freshness, and physical-link proofs before
using those facts. Routing health comes from fresh state, not a static install
record.

You can pause the main, a child, or the current node for maintenance. Pausing
stops new admission while in-flight work finishes; it does not implicitly stop
the Engine. A child sends its own pause/resume request to the authenticated
main, healthy replicas continue serving, and resuming restores admission
without changing runtime configuration.

## Network planes

The control and inference planes stay separate:

- The private control plane carries pairing, topology, Watchdog telemetry,
  administration, and orchestration over provisioned mutual TLS. It is never
  public.
- The inference plane advertises `http://<main>.local:8000/v1` through mDNS
  and exposes only the OpenAI-compatible gateway plus health.

Every child keeps its `li_gateway` resident for the authenticated private relay
consumed by the main gateway. Child mode does not bind or advertise the public
inference endpoint on port 8000.

LAN inference uses HTTP for compatibility with standard clients, so use it on
a trusted local network. `letsinfer exposure enable` can publish only the inference
gateway through the configured secure transport; it never publishes the
controller, Watchdog, or Engine ports.

## Commands

```text
letsinfer node info
letsinfer node list
letsinfer node add
letsinfer node pause [NODE]
letsinfer node resume [NODE]
letsinfer node remove [NODE]
letsinfer topology
letsinfer model install
letsinfer auth controller add --role administrator
letsinfer auth key create NAME --model MODEL --concurrency N
letsinfer audit verify
```

The Mac app drives the same strict discovery, pairing, adoption, replication,
and lifecycle primitives without requiring SSH.
