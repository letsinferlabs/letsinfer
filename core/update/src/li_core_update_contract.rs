// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::time::Duration;

use li_core_interface::{FailureDescription, Sha256Digest};

use crate::{CoreUpdateError, CoreUpdateStoreError};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
const MAX_CORE_VERSION_BYTES: usize = 128;

// Identifies one validated Core release version without selecting a release source.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoreVersion(String);

impl CoreVersion {
    // Parses one canonical semantic version accepted by Core release tooling.
    pub fn parse(value: &str) -> Result<Self, CoreUpdateError> {
        validate_semantic_version(value)?;
        Ok(Self(value.to_string()))
    }

    // Returns the canonical version text without a leading release-tag prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CoreVersion {
    // Presents the exact validated Core release version.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

// Identifies one immutable verified Core installation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoreInstallation {
    version: CoreVersion,
    source_identity: Sha256Digest,
}

impl CoreInstallation {
    // Creates one installation from an exact version and native release-manifest identity.
    pub const fn new(version: CoreVersion, source_identity: Sha256Digest) -> Self {
        Self {
            version,
            source_identity,
        }
    }

    // Returns the installed Core release version.
    pub const fn version(&self) -> &CoreVersion {
        &self.version
    }

    // Returns the immutable native release-manifest identity.
    pub const fn source_identity(&self) -> &Sha256Digest {
        &self.source_identity
    }
}

// Carries one verified staged release through its provider-owned workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCoreUpdate {
    receipt_id: Sha256Digest,
    installation: CoreInstallation,
}

impl PreparedCoreUpdate {
    // Creates one prepared receipt after release verification succeeds.
    pub const fn new(receipt_id: Sha256Digest, installation: CoreInstallation) -> Self {
        Self {
            receipt_id,
            installation,
        }
    }

    // Returns the opaque provider receipt used for idempotent cleanup.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the exact verified candidate installation.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }
}

// Carries one exact pre-handoff service snapshot through rebind or restoration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceSnapshot {
    receipt_id: Sha256Digest,
}

impl CoreServiceSnapshot {
    // Creates one opaque snapshot receipt owned by the platform service provider.
    pub const fn new(receipt_id: Sha256Digest) -> Self {
        Self { receipt_id }
    }

    // Returns the exact provider receipt required for restoration.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }
}

// Carries one reversible active-pointer handoff until service verification commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedCoreUpdate {
    receipt_id: Sha256Digest,
    previous: CoreInstallation,
    installation: CoreInstallation,
}

impl ActivatedCoreUpdate {
    // Creates one activation receipt bound to exact previous and candidate installations.
    pub fn new(
        receipt_id: Sha256Digest,
        previous: CoreInstallation,
        installation: CoreInstallation,
    ) -> Result<Self, CoreUpdateError> {
        if previous == installation {
            return Err(CoreUpdateError::InvalidContract {
                reason: "activation cannot replace an installation with itself",
            });
        }
        Ok(Self {
            receipt_id,
            previous,
            installation,
        })
    }

    // Returns the provider receipt required for commit or rollback.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the installation that must be restored on rollback.
    pub const fn previous(&self) -> &CoreInstallation {
        &self.previous
    }

    // Returns the newly active candidate installation.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }
}

// Describes the durable progress of one exact Core handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdatePhase {
    Requested,
    Prepared,
    ServicesSnapshotted,
    Activated,
    ServicesRebound,
    Verified,
    Committed,
    RollingBack,
    Current,
    CleanupPending,
    Succeeded,
    RolledBack,
    RecoveryRequired,
}

impl CoreUpdatePhase {
    // Returns whether this phase completes all ordinary forward mutation.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Current
                | Self::CleanupPending
                | Self::Succeeded
                | Self::RolledBack
                | Self::RecoveryRequired
        )
    }
}

// Stores one complete resumable Core update journal projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateRecord {
    pub(crate) update_id: Sha256Digest,
    pub(crate) idempotency_key: String,
    pub(crate) requested_version: Option<CoreVersion>,
    pub(crate) phase: CoreUpdatePhase,
    pub(crate) current: Option<CoreInstallation>,
    pub(crate) prepared: Option<PreparedCoreUpdate>,
    pub(crate) service_snapshot: Option<CoreServiceSnapshot>,
    pub(crate) activation: Option<ActivatedCoreUpdate>,
    pub(crate) failure: Option<FailureDescription>,
}

impl CoreUpdateRecord {
    // Creates one empty requested journal after validating its replay identity.
    pub(crate) fn requested(
        update_id: Sha256Digest,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
    ) -> Result<Self, CoreUpdateError> {
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core update idempotency key is empty or exceeds its bound",
            });
        }
        Self::restore(
            update_id,
            idempotency_key,
            requested_version,
            CoreUpdatePhase::Requested,
            None,
            None,
            None,
            None,
            None,
        )
    }

    // Reconstructs one validated journal from a persistence boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        update_id: Sha256Digest,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
        phase: CoreUpdatePhase,
        current: Option<CoreInstallation>,
        prepared: Option<PreparedCoreUpdate>,
        service_snapshot: Option<CoreServiceSnapshot>,
        activation: Option<ActivatedCoreUpdate>,
        failure: Option<FailureDescription>,
    ) -> Result<Self, CoreUpdateError> {
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core update idempotency key is empty or exceeds its bound",
            });
        }
        if crate::update_identity(idempotency_key)? != update_id {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core update identity does not match its replay key",
            });
        }
        let record = Self {
            update_id,
            idempotency_key: idempotency_key.to_string(),
            requested_version,
            phase,
            current,
            prepared,
            service_snapshot,
            activation,
            failure,
        };
        validate_update_record(&record)?;
        Ok(record)
    }

    // Returns the deterministic update identity shared with every provider.
    pub const fn update_id(&self) -> &Sha256Digest {
        &self.update_id
    }

    // Returns the caller-owned replay key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the exact requested release version when one was pinned.
    pub const fn requested_version(&self) -> Option<&CoreVersion> {
        self.requested_version.as_ref()
    }

    // Returns the durable lifecycle phase.
    pub const fn phase(&self) -> CoreUpdatePhase {
        self.phase
    }

    // Returns the installation observed before mutation when available.
    pub const fn current(&self) -> Option<&CoreInstallation> {
        self.current.as_ref()
    }

    // Returns the prepared candidate when acquisition completed.
    pub const fn prepared(&self) -> Option<&PreparedCoreUpdate> {
        self.prepared.as_ref()
    }

    // Returns the pre-handoff service snapshot when captured.
    pub const fn service_snapshot(&self) -> Option<&CoreServiceSnapshot> {
        self.service_snapshot.as_ref()
    }

    // Returns the reversible activation receipt when active mutation began.
    pub const fn activation(&self) -> Option<&ActivatedCoreUpdate> {
        self.activation.as_ref()
    }

    // Returns the latest stable redacted failure when one exists.
    pub const fn failure(&self) -> Option<&FailureDescription> {
        self.failure.as_ref()
    }
}

// Requires persisted receipts and failures to match one exact lifecycle phase.
fn validate_update_record(record: &CoreUpdateRecord) -> Result<(), CoreUpdateError> {
    let current = record.current.is_some();
    let prepared = record.prepared.is_some();
    let snapshot = record.service_snapshot.is_some();
    let activation = record.activation.is_some();
    let failure = record.failure.is_some();
    let structure_is_valid = match record.phase {
        CoreUpdatePhase::Requested => !current && !prepared && !snapshot && !activation && !failure,
        CoreUpdatePhase::Prepared => current && prepared && !snapshot && !activation && !failure,
        CoreUpdatePhase::ServicesSnapshotted => {
            current && prepared && snapshot && !activation && !failure
        }
        CoreUpdatePhase::Activated
        | CoreUpdatePhase::ServicesRebound
        | CoreUpdatePhase::Verified
        | CoreUpdatePhase::Committed
        | CoreUpdatePhase::Succeeded => current && prepared && snapshot && activation && !failure,
        CoreUpdatePhase::RollingBack => failure,
        CoreUpdatePhase::Current => current && !prepared && !snapshot && !activation && !failure,
        CoreUpdatePhase::CleanupPending => current && prepared && snapshot && activation && failure,
        CoreUpdatePhase::RolledBack | CoreUpdatePhase::RecoveryRequired => failure,
    };
    if !structure_is_valid {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core update journal receipts do not match its phase",
        });
    }
    if snapshot && (!current || !prepared) {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core service snapshot has no prepared handoff",
        });
    }
    if let Some(activation) = record.activation.as_ref() {
        let current = record
            .current
            .as_ref()
            .ok_or(CoreUpdateError::InvalidContract {
                reason: "Core activation has no previous installation",
            })?;
        let prepared = record
            .prepared
            .as_ref()
            .ok_or(CoreUpdateError::InvalidContract {
                reason: "Core activation has no prepared installation",
            })?;
        if activation.previous() != current || activation.installation() != prepared.installation()
        {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core activation does not match persisted handoff identities",
            });
        }
    }
    Ok(())
}

// Adds the optimistic revision required for one journal replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedCoreUpdateRecord {
    record: CoreUpdateRecord,
    revision: u64,
}

impl VersionedCoreUpdateRecord {
    // Creates one exact store result.
    pub const fn new(record: CoreUpdateRecord, revision: u64) -> Self {
        Self { record, revision }
    }

    // Returns the complete durable update journal.
    pub const fn record(&self) -> &CoreUpdateRecord {
        &self.record
    }

    // Returns the revision required by the next lifecycle transition.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines optimistic durable storage for resumable update journals.
pub trait CoreUpdateStore: Send + Sync {
    // Returns one replay-key record when it exists.
    fn read(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VersionedCoreUpdateRecord>, CoreUpdateStoreError>;

    // Creates one requested update exactly once.
    fn create(
        &self,
        record: CoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateStoreError>;

    // Replaces one exact journal revision.
    fn replace(
        &self,
        record: CoreUpdateRecord,
        expected_revision: u64,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateStoreError>;
}

// Holds exclusive cross-process Core-update ownership until one lifecycle call returns.
pub trait CoreUpdateAdmissionLease: Send {}

// Defines the cross-manager ownership and admission decision required before Core mutation.
pub trait CoreUpdateAdmissionProvider: Send + Sync {
    // Acquires exclusive update ownership and rejects unsafe installation or operation state.
    fn acquire(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError>;
}

// Owns signed Core acquisition and immutable active-pointer mutation.
pub trait CoreUpdateArtifactProvider: Send + Sync {
    // Returns the exact active immutable Core installation.
    fn current(&self, update_id: &Sha256Digest) -> Result<CoreInstallation, CoreUpdateError>;

    // Acquires and verifies one requested or latest compatible release idempotently.
    fn prepare(
        &self,
        update_id: &Sha256Digest,
        requested_version: Option<&CoreVersion>,
        current: &CoreInstallation,
    ) -> Result<PreparedCoreUpdate, CoreUpdateError>;

    // Discards only the exact prepared workspace after pre-activation failure or no-op.
    fn discard(
        &self,
        update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
    ) -> Result<(), CoreUpdateError>;

    // Moves the immutable active pointer and returns one reversible receipt.
    fn activate(
        &self,
        update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
        current: &CoreInstallation,
    ) -> Result<ActivatedCoreUpdate, CoreUpdateError>;

    // Restores the previous active pointer and removes only this candidate's staging state.
    fn rollback(
        &self,
        update_id: &Sha256Digest,
        activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError>;

    // Makes a verified active-pointer handoff non-reversible before pruning.
    fn commit(
        &self,
        update_id: &Sha256Digest,
        activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError>;
}

// Isolates durable service receipts and native facts or mutations from update policy.
pub trait CoreUpdateServiceProvider: Send + Sync {
    // Returns the immutable native platform and local node-role facts.
    fn context(&self) -> Result<crate::CoreUpdateServiceContext, CoreUpdateError>;

    // Returns one previously stored native service-state receipt when present.
    fn snapshot_record(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<crate::CoreUpdateServiceSnapshotRecord>, CoreUpdateError>;

    // Stores one exact native service-state receipt and returns its durable value.
    fn store_snapshot_record(
        &self,
        snapshot: crate::CoreUpdateServiceSnapshotRecord,
    ) -> Result<crate::CoreUpdateServiceSnapshotRecord, CoreUpdateError>;

    // Observes one caller-selected resident service without changing it.
    fn observe_service(
        &self,
        service: crate::CoreUpdateResidentService,
    ) -> Result<crate::CoreUpdateServiceState, CoreUpdateError>;

    // Applies one manager-selected resident binding through the native supervisor.
    fn rebind_service(
        &self,
        service: crate::CoreUpdateResidentService,
        mode: crate::CoreUpdateServiceMode,
        installation: &CoreInstallation,
        active: bool,
    ) -> Result<(), CoreUpdateError>;

    // Returns one native readiness fact within the manager-owned remaining deadline.
    fn service_is_ready_with_timeout(
        &self,
        service: crate::CoreUpdateResidentService,
        mode: crate::CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError>;

    // Applies one exact prior native state selected from the manager-owned receipt.
    fn restore_service(
        &self,
        state: &crate::CoreUpdateServiceState,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError>;
}

// Owns deletion of superseded Core identities after a verified commit.
pub trait CoreUpdatePruneProvider: Send + Sync {
    // Removes only verified unreferenced Core installations and update workspaces.
    fn prune(
        &self,
        update_id: &Sha256Digest,
        active: &CoreInstallation,
    ) -> Result<(), CoreUpdateError>;
}

// Describes one terminal successful Core update disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdateDisposition {
    Current,
    Updated,
    CleanupPending,
}

// Describes one completed CoreUpdateManager domain event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreUpdateEvent {
    CoreCurrent { source_identity: Sha256Digest },
    CoreUpdated { source_identity: Sha256Digest },
    CoreCleanupPending { source_identity: Sha256Digest },
}

// Returns the active installation and terminal successful lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateChange {
    installation: CoreInstallation,
    disposition: CoreUpdateDisposition,
    event: Option<CoreUpdateEvent>,
}

impl CoreUpdateChange {
    // Creates one exact terminal manager result.
    pub(crate) const fn new(
        installation: CoreInstallation,
        disposition: CoreUpdateDisposition,
        event: Option<CoreUpdateEvent>,
    ) -> Self {
        Self {
            installation,
            disposition,
            event,
        }
    }

    // Returns the active immutable Core installation.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }

    // Returns whether the Core was current, updated, or awaits cleanup retry.
    pub const fn disposition(&self) -> CoreUpdateDisposition {
        self.disposition
    }

    // Returns a domain event only when this call completed a new terminal transition.
    pub const fn event(&self) -> Option<&CoreUpdateEvent> {
        self.event.as_ref()
    }
}

// Validates the canonical SemVer subset used by Core releases.
fn validate_semantic_version(value: &str) -> Result<(), CoreUpdateError> {
    if value.is_empty()
        || value.len() > MAX_CORE_VERSION_BYTES
        || value.starts_with('v')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core version is not canonical semantic version text",
        });
    }
    let (without_build, build) = split_build(value)?;
    if let Some(build) = build {
        validate_identifiers(build, false)?;
    }
    let (base, prerelease) = split_prerelease(without_build)?;
    if let Some(prerelease) = prerelease {
        validate_identifiers(prerelease, true)?;
    }
    let components = base.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components
            .iter()
            .any(|component| !is_canonical_number(component))
    {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core version requires three canonical numeric components",
        });
    }
    Ok(())
}

// Splits optional build metadata while rejecting repeated separators.
fn split_build(value: &str) -> Result<(&str, Option<&str>), CoreUpdateError> {
    let Some((base, build)) = value.split_once('+') else {
        return Ok((value, None));
    };
    if base.is_empty() || build.is_empty() || build.contains('+') {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core version contains an invalid optional section",
        });
    }
    Ok((base, Some(build)))
}

// Splits optional prerelease text while preserving valid hyphens inside it.
fn split_prerelease(value: &str) -> Result<(&str, Option<&str>), CoreUpdateError> {
    let Some((base, prerelease)) = value.split_once('-') else {
        return Ok((value, None));
    };
    if base.is_empty() || prerelease.is_empty() {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core version contains an invalid optional section",
        });
    }
    Ok((base, Some(prerelease)))
}

// Validates dot-separated prerelease or build identifiers.
fn validate_identifiers(
    value: &str,
    reject_numeric_leading_zero: bool,
) -> Result<(), CoreUpdateError> {
    if value.split('.').any(|identifier| {
        identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || (reject_numeric_leading_zero
                && identifier.len() > 1
                && identifier.bytes().all(|byte| byte.is_ascii_digit())
                && identifier.starts_with('0'))
    }) {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core version contains an invalid identifier",
        });
    }
    Ok(())
}

// Returns whether one numeric SemVer component is canonical.
fn is_canonical_number(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}
