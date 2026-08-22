# Let's Infer for macOS

The native macOS menu-bar app is a provisioned controller for one or more
logical Let's Infer sites. A site may contain one machine, replicas, or a
distributed engine group; the app does not model a site as one DGX Spark.

## Connection model

- Browse the credential-free `_letsinfer._tcp` DNS-SD service and group records
  by logical site identity. The same record carries the coordinator's
  certificate-free LAN inference scheme and port, never an API key.
- Pair through `letsinfer pair`. The Mac creates a non-exportable P-256 key,
  proves possession, verifies the displayed comparison code, and stores the
  issued controller certificate in Keychain.
- Use the same pinned private CA, exact server leaf, and controller certificate
  for Watchdog telemetry and the coordinator's private controller API.
- Read topology, signed member inventory, placements, controller role, and
  bounded aggregate telemetry from the coordinator. Read one-second machine
  telemetry from Watchdog. The app requests only the 30-minute window visible
  in the UI, keeps at most 1,801 presentation points per site in memory, and
  never writes telemetry or history to disk. A paired site never invokes SSH.
- Preserve a newer direct Watchdog inference sample when a delayed coordinator
  aggregate arrives; a stale aggregate cannot erase active requests or rates.
- Treat the controller's newest placement as the active inference identity.
  Watchdog refreshes its atomic runtime descriptor in place, and the placement
  overlay prevents a stale `core/site` baseline from replacing the active
  model, engine, version, context, or capacity while that refresh propagates.
- Display engine-neutral aggregate throughput plus decode/prefill rates from
  exact gateway counters. Unsupported live engine usage remains unavailable;
  the app never estimates tokens from streamed text.
- Never send arbitrary shell commands or expose controller credentials to the
  inference API.
- Offer **Add to Home** only for a pristine site reached over a verified direct
  ConnectX route; the administrator-paired Home controller completes the
  signed no-code adoption transaction.
- For a configured site, keep **Connect to this site** and **Move into Home**
  explicit. A move never silently combines site keys, controllers, API keys,
  or active work.
- Enforce the paired controller role in the UI. Operators can start, stop,
  restart, and explicitly recover placements. Administrators can additionally
  install runtimes, plan placement when multiple members are active, manage
  exposure and membership, and create, edit, rotate, or revoke inference keys.
- Keep one-time key secrets only in ephemeral view state until the user copies
  or dismisses them. Never persist or log them.

The menu presents the logical site first, followed by active model placements,
aggregate request state, member topology, and coordinator machine detail.
Unavailable measurements remain explicit rather than being estimated.

## Source layout

- `LetsInfer/DataSources/Controller/` — typed private controller API and mTLS.
- `LetsInfer/DataSources/Watchdog/` — bounded protobuf telemetry and status.
- `LetsInfer/DataSources/SSH/` — legacy unpaired-site compatibility only.
- `LetsInfer/Discovery/` — logical-site DNS-SD discovery.
- `LetsInfer/Pairing/` — code comparison and Keychain controller identity.
- `LetsInfer/Domain/` and `LetsInfer/Models/` — site/member view models.
- `LetsInfer/Monitoring/` — independent site monitoring and bounded history.
- `LetsInfer/Views/` — menu, onboarding, topology, and machine detail.
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
