# Let's Infer for macOS

The native menu-bar app is a provisioned controller for one or more Let's
Infer nodes. A node can contain a main machine, child machines, independent
replicas, or a runtime-qualified parallel engine group.

## Features

- **AirDrop-like discovery** — nearby nodes appear automatically through
  DNS-SD, with custom configuration when discovery is unavailable.
- **Secure pairing without SSH** — verify a short comparison code while the
  app keeps its non-exportable controller identity in Keychain.
- **Topology-first control** — see the main node, children, model services,
  replica groups, targets, links, and health as one system.
- **One model, many groups** — each model appears once and expands to its
  independently routed replica or parallel groups.
- **Live inference visibility** — inspect active and queued requests,
  throughput, context, cache state, utilization, temperatures, power, network,
  and recent history from the same normalized state plane as the CLI.
- **Role-aware actions** — start, stop, restart, recover, install, replicate,
  expose, and manage keys only when the paired controller role permits it.
- **No telemetry database on your Mac** — the app requests the visible bounded
  window, keeps it in memory, and never writes telemetry history to disk.
- **One-time secrets stay one-time** — newly created API keys exist only in
  ephemeral UI state until copied or dismissed.

## Connection model

- Browse credential-free `_letsinfer._tcp` DNS-SD records grouped by logical
  node identity. The record carries the main node's LAN inference scheme and
  port, never an API key.
- Pair through `letsinfer auth controller add`. The Mac creates a non-exportable P-256 key,
  proves possession, verifies the displayed comparison code, and stores the
  issued controller certificate in Keychain.
- Use the pinned private CA, exact server leaf, and controller certificate for
  Watchdog telemetry and the main node's private controller API.
- Read signed node inventory, topology, services, groups, controller role, and
  bounded aggregate telemetry from the main node. Read one-second machine
  telemetry from Watchdog. The app keeps at most 1,801 presentation points per
  node in memory and never writes telemetry or history to disk.
- Preserve a newer direct Watchdog inference sample when a delayed aggregate
  arrives; stale data cannot erase active requests or rates.
- Display engine-neutral aggregate throughput plus decode/prefill rates from
  exact gateway counters. Unsupported metrics remain unavailable rather than
  being estimated from streamed text.
- Never send arbitrary shell commands or expose controller credentials to the
  inference API.
- Offer **Add to Home** only for a pristine node reached over a verified direct
  ConnectX route. For a configured node, keep **Connect as separate node** and
  **Move into Home** explicit.
- Enforce controller roles in the UI. Operators control lifecycle;
  administrators can also install runtimes, manage children and replicas,
  configure exposure, and manage inference keys.

The menu presents the logical node first, then model services, expandable
engine groups, aggregate requests, topology, and main-machine detail.
Unavailable measurements stay explicit.

## Source layout

- `LetsInfer/DataSources/Controller/` — typed private controller API and mTLS.
- `LetsInfer/DataSources/Watchdog/` — bounded protobuf telemetry and status.
- `LetsInfer/DataSources/SSH/` — unpaired-node diagnostics only.
- `LetsInfer/Discovery/` — node DNS-SD discovery.
- `LetsInfer/Pairing/` — code comparison and Keychain controller identity.
- `LetsInfer/Domain/` and `LetsInfer/Models/` — node and machine view models.
- `LetsInfer/Monitoring/` — independent node monitoring and bounded history.
- `LetsInfer/Views/` — menu, onboarding, topology, services, and detail.
- `LetsInferTests/` — protocol, persistence, mapping, and UI-model tests.

## Build and test

```sh
xcodegen generate
xcodebuild -project LetsInfer.xcodeproj -scheme LetsInfer \
  -destination 'platform=macOS' test
```

The production app uses bundle identifier `ai.letsinfer.macos`, targets macOS
14 or newer, enables the hardened runtime, and has no Dock icon.

## Release identity

The app owns `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION`; neither is
derived from core's `PRODUCT_VERSION`. App releases use
`macos-vVERSION-build.BUILD` tags and a separate signed/notarized pipeline.
See [the release contract](../../documentation/operations/macos-release.md).
