# Nodes, replication, and trust

[Back to documentation](../README.md)

A Let's Infer node is one managed inference environment. The first node you
set up becomes the **main** node. Any machines you join to it become **child**
nodes. Together they present one stable OpenAI-compatible endpoint even when
the machines use different GPUs or different target-specific runtimes.

## Main authority

The main node owns the node key, SQLite authority, child enrollment,
controller roles, API-key policy, audit chain, topology, model services,
aggregate telemetry, and gateway. It can also serve inference itself. There is
one explicit main node; Let's Infer does not silently elect another or forward
mutating CLI commands from a child.

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

- A fresh machine on a verified direct ConnectX route can be added from the
  Mac app with **Add to Home**. Both sides bind the exact route, certificates,
  signed adoption document, lifetime, and one-use nonce.
- A LAN or remote child uses a short-lived eight-digit invite followed by a
  separate six-digit human comparison.
- An already configured node is never adopted silently. The app offers
  **Connect to this node** or an explicit **Move into Home** transaction. A
  move preserves model and cache data but replaces node authority,
  controllers, API credentials, and service state. Active work or attached
  children block the move.

The Mac app creates a non-exportable P-256 controller key. Pairing issues a
node-scoped certificate after code and human-comparison checks. Viewer,
operator, and administrator roles control telemetry, lifecycle, and sensitive
administration. The private controller API exposes fixed typed operations;
there is no arbitrary shell route.

## Replication

A model service is the logical model your clients request. It may contain one
or more independent engine groups. Each replica group has its own immutable
runtime release, target, assigned GPU UUIDs, endpoint, health, capacity, and
telemetry. This lets the same model run across mixed hardware as long as the
catalog contains a qualified runtime for every selected node.

From the main node, install on one or more exact nodes:

```text
letsinfer install MODEL --node NODE
letsinfer install MODEL --node NODE_A --node NODE_B
letsinfer install MODEL --all-nodes
letsinfer scale MODEL --replicas 3
```

An interactive install can offer replication across active nodes. Before any
replacement, Let's Infer shows which nodes are compatible, which runtime each
one resolves to, and which existing model would be replaced. Incompatible
nodes are skipped with a reason. Replacement requires explicit confirmation
or `--replace-existing`.

Each physical GPU can belong to only one active group. Allocations are sealed
by exact GPU UUID and only those devices are exposed to the Engine container.
Starting, stopping, or failing one replica does not implicitly stop the other
replicas.

The main gateway chooses a healthy replica using capacity, queue depth,
pressure, temperature, and bounded prefix-affinity hints. It retries another
group only before response streaming begins. If every compatible group is
temporarily full, the request waits in the shared admission queue instead of
overloading a runtime.

Runtime upgrades roll one group at a time. A failed replacement is removed and
the exact prior signed release is restored for that group before the upgrade
stops. Rollback likewise reinstalls retained immutable release identities
rather than re-resolving the latest catalog.

## Parallel runtimes

Replication and tensor/pipeline parallelism are different. Core owns replica
placement and load balancing. A runtime owns TP/PP topology, private ranks,
interconnect requirements, kernels, and engine configuration. Core assigns
only generic task IDs, exact node and GPU UUIDs, ports, addresses, credentials,
and verified connection facts. A parallel runtime may consume multiple
machines or GPUs as one atomic engine group; the gateway publishes its single
endpoint only after every required task is ready. Complete parallel groups can
also be replicated. Core never invents parallelism from a single-device
runtime.

## Health and maintenance

Every node signs bounded hardware, capacity, health, and link facts. The main
node verifies certificate identity, freshness, and physical-link proofs before
using those facts. Routing health comes from fresh state, not a static install
record.

You can drain a child for maintenance. Draining stops new admission to its
groups while in-flight work finishes; it does not implicitly stop the Engine.
Healthy replicas continue serving. Resuming the child restores admission
without changing its runtime configuration.

## Network planes

The control and inference planes stay separate:

- The private control plane carries pairing, topology, Watchdog telemetry,
  administration, and orchestration over provisioned mutual TLS. It is never
  public.
- The inference plane advertises `http://<main>.local:8000/v1` through mDNS
  and exposes only the OpenAI-compatible gateway plus health.

LAN inference uses HTTP for compatibility with standard clients, so use it on
a trusted local network. `letsinfer expose` can publish only the inference
gateway through the configured secure transport; it never publishes the
controller, Watchdog, or Engine ports.

## Commands

```text
letsinfer setup --name Home
letsinfer node status
letsinfer child list
letsinfer child invite --mode lan
letsinfer child approve CHILD_ID COMPARISON_CODE
letsinfer child sync
letsinfer child drain CHILD_ID
letsinfer child resume CHILD_ID
letsinfer topology show
letsinfer install MODEL --all-nodes
letsinfer scale MODEL --replicas N
letsinfer pair --role administrator
letsinfer key create NAME --model MODEL --concurrency N
letsinfer audit verify
```

The Mac app drives the same strict discovery, pairing, adoption, replication,
and lifecycle primitives without requiring SSH.
