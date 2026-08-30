# CoreUpdateManager

`li_core_update_manager` owns one signed Core release handoff from admission
through immutable activation, role-appropriate service rebind, bounded stable
readiness, commit, and exact pruning. It never owns runtime installation or
placement execution.

Every external mechanism is injected: a global admission lease, signed artifact acquisition,
active-pointer mutation, platform service control, pruning, and optimistic
journal persistence. The lease spans the complete mutating handoff, including
service cutover and pruning, and terminal replay does not reacquire it. Each
provider operation receives the deterministic update
identity and must be idempotent, so a journal-write failure or process restart
resumes the same operation rather than fabricating a second handoff.
Journal reads and writes reject zero revisions, foreign identities, altered
records, and non-advancing revisions. An unavailable replace result is treated
as an ambiguous postcommit only when a fresh read returns the exact proposed
record at a newer revision. A definitive revision conflict is never mistaken
for another manager's identical mutation.

`FilesystemCoreUpdateArtifactProvider` now owns the production immutable Core
layout beneath `LETSINFER_HOME/core`. It validates the exact
`versions/<version>/<release-manifest-sha256>` shape, the owner and permission
boundary, the closed `li_core_release_manifest_v1.json`, exact native binary
inventory, and the no-symlink
tree before trusting `current`. An injected native installer can only
materialize a signed candidate into the provider-selected private workspace.
The provider then installs that tree atomically, switches the managed symlink,
persists commit, restores the exact previous target on rollback, and removes
only the replay identity's staging tree. Receipt identities bind the update,
version, release-manifest identity, and reversible handoff without adding another
durable schema.

`GithubCoreUpdateCandidateInstaller` now implements the injected acquisition
capability against the official `letsinferlabs/letsinfer` GitHub release lane.
It preserves the active stable or prerelease SemVer channel unless the caller
pins an exact version, downloads only the platform's
`letsinfer-<os>-<architecture>.tar.gz`, authenticates `SHA256SUMS` through the
configured `letsinfer-release` SSH signer and namespace, and requires its exact
archive checksum record. The filesystem provider holds a crash-releasing
exclusive workspace lock, rejects links and foreign ownership, extracts only
normalized files and directories, closes archive membership against
`li_core_release_manifest_v1.json`, requires its selected version and native
platform, rejects old source-manifest layouts, and publishes a private replay
receipt only after the complete manifest and binary closure verifies. Curl and
ssh-keygen remain narrow injected
shell-free argv adapters; candidate preparation never changes `core/current`.

Failures before commit restore the exact service snapshot and previous active
Core. An incomplete rollback becomes `RecoveryRequired`. Pruning begins only
after the verified handoff commits; prune failure leaves the working new Core
active as `CleanupPending` and retries without rebinding services.

`CoreUpdateManager` owns the production cross-platform service policy. It
selects the exact Linux or macOS resident set, chooses public-main or
private-child Gateway mode, admits only loaded and active prior services, and
requires bounded consecutive readiness observations before completion.
`PlatformCoreUpdateServiceProvider` only joins durable native-state receipts to
the injected service control; it returns platform facts and performs the exact
manager-selected mutation without service-set, role-mode, admission, or
completion judgment. Linux adds `li_watchdog`; macOS relies on launchd
supervision without a separate Watchdog. RuntimeManager and PlacementManager
remain independent owners; Core candidate compatibility is an admission
decision before service or active-pointer mutation.
`SystemCoreUpdateReadinessClock` uses process-monotonic time and rejects zero or
globally unbounded waits. The manager rejects clock regression at every
observation boundary and attempts every exact prior service state before
reporting incomplete recovery. Fixed-argument systemd and launchd mechanics
remain behind the injected service-control interface.

The exact reference-aware prune provider is implemented over separate
reference and native-I/O capabilities. It
verifies the active pointer and every immutable Core identity, retains exact
Core-update journals provide exact immutable-installation and update-recovery
references. Pruning removes only named stale Core identities, update workspaces,
and their resulting empty version roots.
Its deterministic plan and receipt support dry-run inspection, replay, and
whole-target retry after partial cleanup without entering model, runtime,
evidence, credential, or Watchdog stores.

The 60 deterministic update contracts comprise 25 manager lifecycle and policy
tests, 13 artifact-provider tests, 14 signed-candidate tests, two mechanism-only
platform-service-provider tests, and six prune-provider tests. They cover
ordinary and current
releases, exact pins, stable and prerelease channels, signature/checksum/source
and archive rejection, bounded network failures, single-winner replay, every pre- and post-
activation failure, rollback, restart, conflict, immutable-layout validation,
all four platform/role modes, exact wrong/missing/extra service-set rejection,
stable-readiness reset, deadline and monotonic-clock faults, exact all-service
restoration, global lease lifetime, cross-manager compare-and-swap, untrusted
store results, and postcommit reconciliation. The
prune matrix covers active and recovery retention, exact
stale selection, content and link corruption, reference failure before
mutation, partial deletion retry, and stable empty replay. `li_node` still
persists strict nested `li_core_update_record` version 1 and
`li_core_update_service_snapshot` version 2 documents under Update-owned
schemas. `li_core_application` composes production update handling inside the
resident `li_node`. `compose_system_core_update` receives release transport,
release signature trust, a cross-process global lease, active-service cutover,
prune-reference authority, and the database, then exposes the resulting
coordinator through the typed Node API. No process-local mutex, empty reference
set, implicit network, or implicit trust fallback is used.
