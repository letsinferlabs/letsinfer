# CLI reference

[Back to documentation](../README.md)

Every leaf command has an enforced execution scope. `coordinator` commands run
only on the site's coordinator, `member` commands run only on a joined
non-coordinator member, and `all` commands run in either role. Invalid scope is
rejected before the command handler or any side effect. Site mutations are
coordinator-only and audited.

Interactive terminals use the full Let's Infer mark and type treatment only for
root help, command help, and site/runtime status cards. Running `letsinfer`
without a command shows root help. Mutating commands use only a compact progress
and success line on standard error; read and list results stay unadorned on
standard output. Errors use one concise standard-error label and never repeat
the banner. One-time API-key secrets and all durable command results remain on
standard output. Redirected output, `TERM=dumb`, and JSON modes stay plain and
byte-clean. Set `NO_COLOR` to keep the interactive layout while disabling
color.

## Site, membership, and policy

```text
letsinfer setup [--name NAME]
letsinfer site status [--json]
letsinfer member list [--json]
letsinfer member prepare [--json]
letsinfer member join ENDPOINT --invite ID --coordinator-certificate-sha256 SHA256
letsinfer member invite --mode lan|remote|connectx [OPTIONS]
letsinfer member approve MEMBER_ID COMPARISON_CODE
letsinfer member sync [--json]
letsinfer member drain MEMBER_ID [--json]
letsinfer member resume MEMBER_ID [--json]
letsinfer member remove MEMBER_ID
letsinfer topology show [--json]
letsinfer topology probe LEFT_MEMBER RIGHT_MEMBER --kind connectx|lan
letsinfer topology plan MODEL --catalog LOCATION
letsinfer alias list
letsinfer alias set ALIAS MODEL
letsinfer alias remove ALIAS
letsinfer pair [--role viewer|operator|administrator]
letsinfer controllers list [--json]
letsinfer controllers forget NAME_OR_ID
letsinfer key create NAME [POLICY]
letsinfer key list [--json]
letsinfer key show NAME_OR_ID [--json]
letsinfer key rotate NAME_OR_ID [--json]
letsinfer key revoke NAME_OR_ID [--json]
letsinfer key policy NAME_OR_ID [POLICY]
letsinfer audit list|show|verify|export
letsinfer exposure [--json]
letsinfer expose [--json]
letsinfer unexpose [--json]
```

`setup` is the only site mutation permitted before a site exists. The first
machine becomes coordinator and provisions the private site services and
default local inference key. Linux installs persistent systemd services and
the native Watchdog; macOS installs per-user launchd agents for the site and
unified gateway without claiming Linux/NVIDIA protection or local runtime
placement. `letsinfer status` reports a healthy control plane even before a
model runtime is installed. A fresh direct-ConnectX machine is normally added
through the Mac app. For direct CLI enrollment, a ConnectX invite requires
`--candidate-endpoint`, `--candidate-fingerprint`, and `--interface`; the
coordinator verifies the exact direct route and emits its address on that same
link. LAN and remote invites use the eight-digit code and subsequent six-digit
human comparison.

`member drain` is an admission operation: it immediately stops the gateway
from assigning new requests to that member without interrupting requests
already in flight or stopping its engine. `member resume` restores admission.
Replica placements continue on active members. A distributed placement admits
no new work while any required member is not active. Both operations are
coordinator-only, idempotent, and atomically audited.

Key policy options are `--model` (repeatable), `--expires-at`,
`--requests-per-minute`, `--tokens-per-minute`, `--concurrency`,
`--max-context`, `--tenant`, and `--application`. A create or rotate secret is
shown once. Only its salted hash is stored. All key and audit commands are
coordinator-only.

`expose` publishes only the active local inference gateway through an exact,
hash-bound Tailscale Funnel configuration. It refuses existing or ambiguous
provider state. `unexpose` removes only the exact configuration Let's Infer
recorded. Neither command exposes the private site, controller, Watchdog, or
engine ports.

## Runtime distribution

```text
letsinfer pack SOURCE --output ARTIFACT
letsinfer hardware [--json] [--catalog PATH_OR_HTTPS_URL]
letsinfer runtimes
letsinfer install MODEL [--engine ENGINE] [--catalog PATH_OR_HTTPS_URL] [--no-download]
letsinfer install DIRECTORY_OR_DIGEST [--no-download]
letsinfer derive RUNTIME [--target TARGET] --name NAME [--without=--FLAG] -- [ENGINE_ARGS]
letsinfer inspect RUNTIME [--target TARGET] [--command] [--diff] [--json]
letsinfer upgrade RUNTIME [--target TARGET] [--catalog LOCATION] [--to SOURCE] [--dry-run]
letsinfer rollback RUNTIME [--target TARGET] [--dry-run]
letsinfer update [--version VERSION]
```

`pack` creates a deterministic `.letsinfer` artifact. `install` accepts local
runtime repositories, local `.letsinfer` archives, trusted catalog models, and
digest-pinned OCI artifacts. An already installed runtime can also be selected
by model or runtime identity. Core embeds no model runtime; its default signed
catalog only resolves model names to external immutable OCI artifacts. An
imported candidate remains blocked
from service activation until its serving gate is qualified.

Remote catalogs require HTTPS and an exact-byte Ed25519 signature at
`<catalog-url>.sig`. The production catalog and its public trust key are
built-in defaults; `~/.config/letsinfer/catalog-public-key.pem` and
`LETSINFER_CATALOG_PUBLIC_KEY` override the trust root. A signature binds the
catalog SHA-256 and trusted public-key fingerprint. An explicitly selected
unsigned local catalog is supported only as a development trust boundary.

For a qualified or candidate runtime, `install` automatically acquires every missing exact
model artifact and registry image layer. The Hugging Face
cache deduplicates model blobs and snapshots, Let's Infer's immutable object store
deduplicates runtime packs, Let's Infer's SHA-256 artifact store deduplicates
verified native integration artifacts, and Docker's content store deduplicates
image layers. Engine package-manager dependencies belong inside the immutable
image, not in a parallel Let's Infer or host package environment. `--no-download`
requires the exact model and registry image content to exist already.

If a local runtime pins a local image ID and contains
`image/Dockerfile`, `install` builds the packed runtime-root context only when the exact
image is absent. Importing an unqualified candidate remains non-serving even
though its dependencies are prepared; only an explicit
`serve --qualification-mode` launch may execute it. Build
inputs and package choices belong to the runtime. Let's Infer requires
digest-pinned external bases and verifies the final image ID.
`--no-build-image` disables installation-time image builds and requires the
exact image to exist already. Registry-distributed runtimes pull their exact
image digest instead of rebuilding it.

`hardware` prints the stable capability fingerprint used for target mapping.
With a configured catalog it also reports all compatible target IDs and the
selected target when the match is unique. Catalog installation selects the
target automatically; multiple matches are rejected as a catalog ambiguity.
The CLI retains `--target` only for explicit development and diagnostics, and
it never disables compatibility verification.

`derive` accepts Let's Infer options before `--` and unmodified upstream engine
arguments after it. `--without=--FLAG` removes an inherited option and may be
repeated; short options use the same form, such as `--without=-fa`.
`inspect --command` prints shell-quoted display text, but Let's Infer
stores and launches the command as argv rather than evaluating that text.

`update` installs the latest signed stable core release, or the exact release
named by `--version`, and rebinds the core-owned services to it. When inference
is active, the handoff stops recovery, drains the engine while the existing
Watchdog is still armed, replaces the site/Watchdog/gateway services, and then
restores the engine and recovery timer. The runtime's own immutable control
bundle is not rebound. `update` never resolves, downloads, upgrades, rolls
back, or changes a runtime. Installed runtime
receipts, model snapshots, caches, evidence, API keys, and service placement
remain unchanged. An active benchmark must be stopped before updating core.

## Model and service lifecycle

```text
letsinfer engines
letsinfer releases
letsinfer acquire MODEL [--engine ENGINE] [--target TARGET]
letsinfer benchmark RUNTIME [--c1|--c2|--c4|--c8|--c16] [--32k|--64k|--128k|--256k]
letsinfer benchmark [--json]
letsinfer benchmark stop
letsinfer verify MODEL [--engine ENGINE] [--target TARGET] [--source-only]
letsinfer serve MODEL [--engine ENGINE] [--target TARGET] [--dry-run]
letsinfer status [--json]
letsinfer doctor [--json] [--require-stable]
letsinfer logs [--tail N] [--follow]
letsinfer start [MODEL]
letsinfer restart
letsinfer recover [MODEL]
letsinfer pair [--timeout SECONDS] [--role viewer|operator|administrator]
letsinfer controllers list [--json]
letsinfer controllers forget NAME_OR_ID
letsinfer stop
letsinfer uninstall
```

`start` and `restart` fail closed while Watchdog has a durable protection trip.
`recover` is the only lifecycle command that acknowledges that trip before
starting the protected runtime. The same distinction applies to one-member,
replicated, and distributed placements.

`status --json` includes one derived `lifecycle` object. Its state is one of
`starting`, `ready`, `stopping`, `stopped`, `blocked`, `degraded`, or `failed`,
with a stable machine reason and the observed ready-service count. Transitional
states are successful status observations, not health failures. The interactive
card renders startup as `STARTING`: the gateway waits for model identity, the
engine runs health checks, protection arms after readiness, and the remaining
unit is described as activating. A protection trip always takes precedence and
renders `BLOCKED`; terminal engine or Docker health failures render `FAILED`.

`releases` lists installed runtime manifests, not test fixtures or a bundled
model catalog.

`benchmark` runs the standard suite declared by the installed immutable
runtime without accepting engine flags or runtime-provided code. Selectors form
a cross product; with no selectors it runs every declared standard context and
concurrency cell. Let's Infer calibrates deterministic synthetic prompts through
the exact runtime tokenizer-count capability and writes prompts, their derived
plan, identity hashes, and a validated `benchmark.json` into evidence. Every measured cell uses a fresh
managed container and an empty prefix store. The output directory defaults to
a timestamped path under `~/.cache/letsinfer/benchmarks/`. `--list` validates the
declarative contract and prints selected cells without starting inference.

The benchmark is one durable node job. The launch command attaches to live
phase, workload, elapsed-time, and expected-duration progress by default;
`--detach` returns immediately. Ctrl-C detaches the terminal and leaves the
benchmark running. `letsinfer benchmark` shows the active or most recent job,
its progress, evidence directory, and recent log output, while
`letsinfer benchmark stop` is the explicit cancellation path. A second
benchmark is rejected until the active worker finishes or is stopped. The
worker owns temporary-container cleanup and restoration of the prior engine
and recovery-timer state.

The public JSON includes a cryptographic benchmark ID and per-workload
aggregate/decode TPS, TTFT, prefix-cache state, maximum GPU/CPU temperature,
maximum GPU/CPU usage, and Watchdog's compact one-second timeline. The
benchmark ID binds the private installation identity, exact benchmark contract,
run timestamp, and complete results/timeline digest; raw host and GPU
identifiers are never published.

`serve --qualification-mode --evidence-dir PATH` is the only path that permits
an unqualified recipe. It is explicit, evidence-bound, and does not promote or
make the candidate boot-persistent.

`pair` opens one temporary TLS 1.3 enrollment session on fixed port 9769 and
prints an eight-digit setup code. Pairing completes only after the terminal and
Mac show the same key-bound six-digit verification code. `controllers` lists
the authorized controller registry. `controllers forget` immediately removes
the named controller fingerprint, reloads Watchdog, and disconnects any open
connection; the protected local controller cannot be removed. Pairing timeouts
are bounded to 30–180 seconds; the default is 180 seconds.

Run `letsinfer COMMAND --help` for path, credential, cache, port, and service
options intended mainly for deployment automation.
