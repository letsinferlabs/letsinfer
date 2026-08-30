// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use getrandom::fill;
use li_core_interface::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{
    CoreUninstallBoundary, CoreUninstallBoundaryReceipt, CoreUninstallModelDisposition,
    CoreUninstallOwnedTarget, CoreUninstallPlan, CoreUninstallTargetKind,
};

const JOURNAL_FILENAME: &str = "li_core_uninstall_session_v1.json";
const LOCK_FILENAME: &str = ".li_core_uninstall_session.lock";
const TEMPORARY_FILENAME: &str = ".li_core_uninstall_session_v1.tmp";
const JOURNAL_SCHEMA_NAME: &str = "li_core_uninstall_session";
const JOURNAL_SCHEMA_VERSION: u64 = 1;
const MAXIMUM_JOURNAL_BYTES: usize = 16 * 1_024 * 1_024;
const MAXIMUM_UNINSTALL_TARGETS: usize = 4_096;
const MAXIMUM_BOUNDARY_RECEIPTS: usize = 7;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

// Supplies one caller-independent identity before any Node exchange can begin.
pub trait CoreUninstallSessionIdSource: Send + Sync {
    // Returns one fresh cryptographic identity for a newly durable uninstall session.
    fn next_session_id(&self) -> Result<Sha256Digest, CoreUninstallSessionError>;
}

// Reads one unpredictable uninstall-session identity from the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreUninstallSessionIdSource;

impl CoreUninstallSessionIdSource for SystemCoreUninstallSessionIdSource {
    // Returns one canonical SHA-256-sized identity without persisting random source material.
    fn next_session_id(&self) -> Result<Sha256Digest, CoreUninstallSessionError> {
        let mut bytes = [0_u8; 32];
        fill(&mut bytes).map_err(|_| CoreUninstallSessionError::IdentityUnavailable)?;
        let identity = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        bytes.fill(0);
        Sha256Digest::parse(&identity).map_err(|_| CoreUninstallSessionError::IdentityUnavailable)
    }
}

// Binds one durable session to the exact model-retention policy accepted by Node.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreUninstallSessionRetention {
    KeepModels,
    RemoveModels,
}

// Distinguishes a newly durable session from one recovered after process interruption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUninstallSessionDisposition {
    Applied,
    Reopened,
}

// Names the smallest durable phases needed to resume beyond the Node resident lifetime.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreUninstallSessionPhase {
    Admitting,
    Planned,
    ServicesRetiring,
    ServicesRetired,
    CoreRetiring,
}

// Exposes one fully validated recovery projection without exposing its wire representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUninstallSessionRecoveryState {
    session_id: Sha256Digest,
    retention: CoreUninstallSessionRetention,
    phase: CoreUninstallSessionPhase,
    plan: Option<CoreUninstallPlan>,
    receipts: Vec<CoreUninstallBoundaryReceipt>,
}

impl CoreUninstallSessionRecoveryState {
    // Creates the sole empty state used before a fresh session binds its ownership plan.
    pub const fn admitting(
        session_id: Sha256Digest,
        retention: CoreUninstallSessionRetention,
    ) -> Self {
        Self {
            session_id,
            retention,
            phase: CoreUninstallSessionPhase::Admitting,
            plan: None,
            receipts: Vec::new(),
        }
    }

    // Returns the exact identity shared by the durable application and Node leases.
    pub const fn session_id(&self) -> &Sha256Digest {
        &self.session_id
    }

    // Returns the immutable model policy accepted before any uninstall mutation.
    pub const fn retention(&self) -> CoreUninstallSessionRetention {
        self.retention
    }

    // Returns the last durably validated orchestration phase.
    pub const fn phase(&self) -> CoreUninstallSessionPhase {
        self.phase
    }

    // Returns the exact preflight ownership plan when preflight completed durably.
    pub const fn plan(&self) -> Option<&CoreUninstallPlan> {
        self.plan.as_ref()
    }

    // Returns the exact contiguous prefix of completed mutation receipts.
    pub fn receipts(&self) -> &[CoreUninstallBoundaryReceipt] {
        &self.receipts
    }
}

// Names closed identity, policy, concurrency, and owner-private persistence failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUninstallSessionError {
    IdentityUnavailable,
    InvalidStateRoot,
    InvalidJournal,
    OperationConflict,
    PersistenceUnavailable,
}

impl fmt::Display for CoreUninstallSessionError {
    // Presents stable application language without exposing owner paths or native diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityUnavailable => {
                formatter.write_str("uninstall session identity is unavailable")
            }
            Self::InvalidStateRoot => formatter.write_str("uninstall session state root is unsafe"),
            Self::InvalidJournal => formatter.write_str("uninstall session journal is invalid"),
            Self::OperationConflict => {
                formatter.write_str("another uninstall session owns this installation")
            }
            Self::PersistenceUnavailable => {
                formatter.write_str("uninstall session persistence is unavailable")
            }
        }
    }
}

impl Error for CoreUninstallSessionError {}

// Owns the explicit state root and fresh-identity source for durable uninstall admission.
pub struct FilesystemCoreUninstallSessionOwner {
    state_root: PathBuf,
    owner_user_id: u32,
    session_ids: Arc<dyn CoreUninstallSessionIdSource>,
}

impl FilesystemCoreUninstallSessionOwner {
    // Creates one owner only after its existing absolute state root passes every safety check.
    pub fn new(
        state_root: PathBuf,
        owner_user_id: u32,
        session_ids: Arc<dyn CoreUninstallSessionIdSource>,
    ) -> Result<Self, CoreUninstallSessionError> {
        require_safe_absolute_path(&state_root)?;
        require_no_symbolic_link_ancestors(&state_root)?;
        require_private_directory_path(&state_root, owner_user_id)?;
        Ok(Self {
            state_root,
            owner_user_id,
            session_ids,
        })
    }

    // Locks the installation nonblockingly, then creates or reopens its exact durable session.
    pub fn begin(
        &self,
        retention: CoreUninstallSessionRetention,
    ) -> Result<CoreUninstallSession, CoreUninstallSessionError> {
        let root = open_private_directory(&self.state_root, self.owner_user_id)?;
        let root_identity = FileIdentity::from_metadata(&root.metadata().map_err(unavailable)?);
        let lock = acquire_lock(&self.state_root, self.owner_user_id, &root, root_identity)?;
        verify_root_identity(&self.state_root, self.owner_user_id, &root, root_identity)?;
        root.sync_all().map_err(unavailable)?;
        remove_safe_temporary_file(&self.state_root, self.owner_user_id)?;
        root.sync_all().map_err(unavailable)?;

        let (journal, disposition) = match read_journal(&self.state_root, self.owner_user_id)? {
            Some(journal) => {
                if journal.retention != retention {
                    return Err(CoreUninstallSessionError::OperationConflict);
                }
                (journal, CoreUninstallSessionDisposition::Reopened)
            }
            None => {
                let session_id = self.session_ids.next_session_id()?;
                let journal = UninstallSessionJournal::new(session_id, retention);
                write_journal(
                    &self.state_root,
                    self.owner_user_id,
                    &root,
                    root_identity,
                    &journal,
                )?;
                (journal, CoreUninstallSessionDisposition::Applied)
            }
        };
        if !read_journal(&self.state_root, self.owner_user_id)?
            .as_ref()
            .is_some_and(|observed| observed == &journal)
        {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        Ok(CoreUninstallSession {
            state_root: self.state_root.clone(),
            owner_user_id: self.owner_user_id,
            root,
            root_identity,
            lock,
            journal,
            disposition,
        })
    }

    // Returns the exact durable journal path for composition diagnostics and closed tests.
    pub fn journal_path(&self) -> PathBuf {
        self.state_root.join(JOURNAL_FILENAME)
    }
}

// Retains the process lock and exact durable identity for one complete CLI operation.
pub struct CoreUninstallSession {
    state_root: PathBuf,
    owner_user_id: u32,
    root: File,
    root_identity: FileIdentity,
    lock: CoreUninstallSessionLock,
    journal: UninstallSessionJournal,
    disposition: CoreUninstallSessionDisposition,
}

impl CoreUninstallSession {
    // Returns the identity that must be used for Begin, every leased cleanup, and Cancel.
    pub const fn session_id(&self) -> &Sha256Digest {
        &self.journal.session_id
    }

    // Returns the immutable model-retention policy persisted before Node admission.
    pub const fn retention(&self) -> CoreUninstallSessionRetention {
        self.journal.retention
    }

    // Returns whether this operation created or recovered the durable session.
    pub const fn disposition(&self) -> CoreUninstallSessionDisposition {
        self.disposition
    }

    // Returns one reconstructed and fully validated recovery state from the retained journal.
    pub fn recovery_state(
        &self,
    ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallSessionError> {
        self.journal.recovery_state()
    }

    // Publishes the exact ownership plan before the first uninstall mutation can begin.
    pub fn persist_plan(
        &mut self,
        plan: &CoreUninstallPlan,
    ) -> Result<(), CoreUninstallSessionError> {
        plan.validate().map_err(invalid_domain)?;
        if retention_disposition(self.journal.retention) != plan.model_disposition() {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let wire = WireUninstallPlan::from_plan(plan)?;
        if let Some(current) = self.journal.plan.as_ref() {
            return (current == &wire)
                .then_some(())
                .ok_or(CoreUninstallSessionError::InvalidJournal);
        }
        if self.journal.phase != CoreUninstallSessionPhase::Admitting
            || !self.journal.receipts.is_empty()
        {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let mut next = self.journal.clone();
        next.plan = Some(wire);
        next.phase = CoreUninstallSessionPhase::Planned;
        self.rewrite(next)
    }

    // Appends only the next exact boundary receipt or accepts its exact durable replay.
    pub fn append_receipt(
        &mut self,
        receipt: &CoreUninstallBoundaryReceipt,
    ) -> Result<(), CoreUninstallSessionError> {
        let state = self.journal.recovery_state()?;
        let plan = state
            .plan()
            .ok_or(CoreUninstallSessionError::InvalidJournal)?;
        let index =
            boundary_index(receipt.boundary()).ok_or(CoreUninstallSessionError::InvalidJournal)?;
        if index < state.receipts().len() {
            return (state.receipts()[index] == *receipt)
                .then_some(())
                .ok_or(CoreUninstallSessionError::InvalidJournal);
        }
        if index != state.receipts().len()
            || !phase_accepts_boundary(self.journal.phase, receipt.boundary())
        {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let mut next = self.journal.clone();
        next.receipts
            .push(WireBoundaryReceipt::from_receipt(plan, receipt)?);
        self.rewrite(next)
    }

    // Advances exactly one phase after its required receipt prefix is durable.
    pub fn advance_phase(
        &mut self,
        phase: CoreUninstallSessionPhase,
    ) -> Result<(), CoreUninstallSessionError> {
        if self.journal.phase == phase {
            return Ok(());
        }
        let expected = match self.journal.phase {
            CoreUninstallSessionPhase::Planned => CoreUninstallSessionPhase::ServicesRetiring,
            CoreUninstallSessionPhase::ServicesRetiring => {
                CoreUninstallSessionPhase::ServicesRetired
            }
            CoreUninstallSessionPhase::ServicesRetired => CoreUninstallSessionPhase::CoreRetiring,
            CoreUninstallSessionPhase::Admitting | CoreUninstallSessionPhase::CoreRetiring => {
                return Err(CoreUninstallSessionError::InvalidJournal);
            }
        };
        if phase != expected {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let mut next = self.journal.clone();
        next.phase = phase;
        self.rewrite(next)
    }

    // Deletes only an admission journal before any recoverable ownership plan is bound.
    pub fn retire_after_node_cancel(self) -> Result<(), CoreUninstallSessionError> {
        if self.journal.phase != CoreUninstallSessionPhase::Admitting {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        verify_root_identity(
            &self.state_root,
            self.owner_user_id,
            &self.root,
            self.root_identity,
        )?;
        let observed = read_journal(&self.state_root, self.owner_user_id)?
            .ok_or(CoreUninstallSessionError::InvalidJournal)?;
        if observed != self.journal {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        fs::remove_file(self.state_root.join(JOURNAL_FILENAME)).map_err(unavailable)?;
        self.root.sync_all().map_err(unavailable)?;
        if read_journal(&self.state_root, self.owner_user_id)?.is_some() {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        Ok(())
    }

    // Releases only the process lock while keeping the journal for exact service recovery.
    pub fn preserve_for_service_recovery(self) {}

    // Keeps the lock descriptor observably owned for the entire RAII session lifetime.
    pub const fn owns_process_lock(&self) -> bool {
        let _ = &self.lock;
        true
    }

    // Atomically replaces only the exact journal currently owned by this locked session.
    fn rewrite(&mut self, next: UninstallSessionJournal) -> Result<(), CoreUninstallSessionError> {
        verify_root_identity(
            &self.state_root,
            self.owner_user_id,
            &self.root,
            self.root_identity,
        )?;
        let observed = read_journal(&self.state_root, self.owner_user_id)?
            .ok_or(CoreUninstallSessionError::InvalidJournal)?;
        if observed != self.journal {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        next.validate()?;
        let publication = write_journal(
            &self.state_root,
            self.owner_user_id,
            &self.root,
            self.root_identity,
            &next,
        );
        if publication.is_ok() {
            self.journal = next;
            return Ok(());
        }
        if read_journal(&self.state_root, self.owner_user_id)?.as_ref() == Some(&next) {
            self.journal = next;
        }
        publication
    }
}

// Stores the repository-wide nested schema identity without accepting extra fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalSchema {
    name: String,
    version: u64,
}

// Stores the closed recovery identity, phase, plan, and contiguous receipt prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UninstallSessionJournal {
    schema: JournalSchema,
    #[serde(with = "journal_digest")]
    session_id: Sha256Digest,
    retention: CoreUninstallSessionRetention,
    phase: CoreUninstallSessionPhase,
    plan: Option<WireUninstallPlan>,
    receipts: Vec<WireBoundaryReceipt>,
}

impl UninstallSessionJournal {
    // Creates one current-schema document from already validated domain values.
    fn new(session_id: Sha256Digest, retention: CoreUninstallSessionRetention) -> Self {
        Self {
            schema: JournalSchema {
                name: JOURNAL_SCHEMA_NAME.to_string(),
                version: JOURNAL_SCHEMA_VERSION,
            },
            session_id,
            retention,
            phase: CoreUninstallSessionPhase::Admitting,
            plan: None,
            receipts: Vec::new(),
        }
    }

    // Rejects every foreign schema or inconsistent recovery projection before use.
    fn validate(&self) -> Result<(), CoreUninstallSessionError> {
        if self.schema.name != JOURNAL_SCHEMA_NAME || self.schema.version != JOURNAL_SCHEMA_VERSION
        {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        self.recovery_state().map(|_| ())
    }

    // Reconstructs domain values and validates exact policy, order, digest, and phase binding.
    fn recovery_state(
        &self,
    ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallSessionError> {
        if self.receipts.len() > MAXIMUM_BOUNDARY_RECEIPTS {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let plan = self
            .plan
            .as_ref()
            .map(WireUninstallPlan::to_plan)
            .transpose()?;
        if plan
            .as_ref()
            .is_some_and(|plan| retention_disposition(self.retention) != plan.model_disposition())
        {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let receipts = match plan.as_ref() {
            Some(plan) => self
                .receipts
                .iter()
                .enumerate()
                .map(|(index, receipt)| {
                    let expected = UNINSTALL_BOUNDARY_ORDER
                        .get(index)
                        .copied()
                        .ok_or(CoreUninstallSessionError::InvalidJournal)?;
                    let receipt = receipt.to_receipt(plan)?;
                    if receipt.boundary() != expected {
                        return Err(CoreUninstallSessionError::InvalidJournal);
                    }
                    Ok(receipt)
                })
                .collect::<Result<Vec<_>, _>>()?,
            None if self.receipts.is_empty() => Vec::new(),
            None => return Err(CoreUninstallSessionError::InvalidJournal),
        };
        validate_phase(self.phase, plan.as_ref(), receipts.len())?;
        Ok(CoreUninstallSessionRecoveryState {
            session_id: self.session_id.clone(),
            retention: self.retention,
            phase: self.phase,
            plan,
            receipts,
        })
    }
}

// Stores one explicit model policy without serializing a domain implementation detail.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireModelDisposition {
    KeepModels,
    RemoveModels,
}

// Stores one explicit target kind without deriving serialization on the domain enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireTargetKind {
    ActiveBenchmark,
    PublicExposure,
    PlacementGroup,
    ModelService,
    PlatformService,
    RuntimeInstallation,
    ManagedContainer,
    ManagedImage,
    OwnerRoot,
    ModelRoot,
    CoreConfiguration,
    CoreInstallation,
    Launcher,
}

// Stores one exact owned target using only canonical public domain projections.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireUninstallTarget {
    kind: WireTargetKind,
    identity: String,
    #[serde(with = "journal_digest")]
    ownership_sha256: Sha256Digest,
}

// Stores the complete bounded preflight plan without coupling serde to domain structs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireUninstallPlan {
    #[serde(with = "journal_digest")]
    plan_id: Sha256Digest,
    #[serde(with = "journal_digest")]
    ownership_plan_sha256: Sha256Digest,
    model_disposition: WireModelDisposition,
    benchmark_stop_wait_seconds: u64,
    benchmark_stop_wait_nanoseconds: u32,
    targets: Vec<WireUninstallTarget>,
}

impl WireUninstallPlan {
    // Projects one validated plan into the closed recovery document.
    fn from_plan(plan: &CoreUninstallPlan) -> Result<Self, CoreUninstallSessionError> {
        plan.validate().map_err(invalid_domain)?;
        if plan.targets().len() > MAXIMUM_UNINSTALL_TARGETS {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        Ok(Self {
            plan_id: plan.plan_id().clone(),
            ownership_plan_sha256: plan.ownership_plan_sha256().clone(),
            model_disposition: WireModelDisposition::from_domain(plan.model_disposition()),
            benchmark_stop_wait_seconds: plan.benchmark_stop_wait().as_secs(),
            benchmark_stop_wait_nanoseconds: plan.benchmark_stop_wait().subsec_nanos(),
            targets: plan
                .targets()
                .iter()
                .map(WireUninstallTarget::from_target)
                .collect(),
        })
    }

    // Reconstructs one exact canonical plan and rejects alternate wire order or digest drift.
    fn to_plan(&self) -> Result<CoreUninstallPlan, CoreUninstallSessionError> {
        if self.targets.len() > MAXIMUM_UNINSTALL_TARGETS
            || self.benchmark_stop_wait_nanoseconds >= 1_000_000_000
        {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let targets = self
            .targets
            .iter()
            .map(WireUninstallTarget::to_target)
            .collect::<Result<Vec<_>, _>>()?;
        let plan = CoreUninstallPlan::new(
            self.ownership_plan_sha256.clone(),
            self.model_disposition.to_domain(),
            Duration::new(
                self.benchmark_stop_wait_seconds,
                self.benchmark_stop_wait_nanoseconds,
            ),
            targets,
        )
        .map_err(invalid_domain)?;
        if plan.plan_id() != &self.plan_id || Self::from_plan(&plan)? != *self {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        Ok(plan)
    }
}

impl WireUninstallTarget {
    // Projects one target from already validated public domain fields.
    fn from_target(target: &CoreUninstallOwnedTarget) -> Self {
        Self {
            kind: WireTargetKind::from_domain(target.kind()),
            identity: target.identity().to_string(),
            ownership_sha256: target.ownership_sha256().clone(),
        }
    }

    // Reconstructs one target through its domain constructor.
    fn to_target(&self) -> Result<CoreUninstallOwnedTarget, CoreUninstallSessionError> {
        CoreUninstallOwnedTarget::new(
            self.kind.to_domain(),
            self.identity.clone(),
            self.ownership_sha256.clone(),
        )
        .map_err(invalid_domain)
    }
}

impl WireModelDisposition {
    // Projects one domain policy into its closed wire identity.
    const fn from_domain(disposition: CoreUninstallModelDisposition) -> Self {
        match disposition {
            CoreUninstallModelDisposition::KeepModels => Self::KeepModels,
            CoreUninstallModelDisposition::RemoveModels => Self::RemoveModels,
        }
    }

    // Restores one wire policy into the domain enum.
    const fn to_domain(self) -> CoreUninstallModelDisposition {
        match self {
            Self::KeepModels => CoreUninstallModelDisposition::KeepModels,
            Self::RemoveModels => CoreUninstallModelDisposition::RemoveModels,
        }
    }
}

impl WireTargetKind {
    // Projects one domain target kind into its closed wire identity.
    const fn from_domain(kind: CoreUninstallTargetKind) -> Self {
        match kind {
            CoreUninstallTargetKind::ActiveBenchmark => Self::ActiveBenchmark,
            CoreUninstallTargetKind::PublicExposure => Self::PublicExposure,
            CoreUninstallTargetKind::PlacementGroup => Self::PlacementGroup,
            CoreUninstallTargetKind::ModelService => Self::ModelService,
            CoreUninstallTargetKind::PlatformService => Self::PlatformService,
            CoreUninstallTargetKind::RuntimeInstallation => Self::RuntimeInstallation,
            CoreUninstallTargetKind::ManagedContainer => Self::ManagedContainer,
            CoreUninstallTargetKind::ManagedImage => Self::ManagedImage,
            CoreUninstallTargetKind::OwnerRoot => Self::OwnerRoot,
            CoreUninstallTargetKind::ModelRoot => Self::ModelRoot,
            CoreUninstallTargetKind::CoreConfiguration => Self::CoreConfiguration,
            CoreUninstallTargetKind::CoreInstallation => Self::CoreInstallation,
            CoreUninstallTargetKind::Launcher => Self::Launcher,
        }
    }

    // Restores one wire target kind into the domain enum.
    const fn to_domain(self) -> CoreUninstallTargetKind {
        match self {
            Self::ActiveBenchmark => CoreUninstallTargetKind::ActiveBenchmark,
            Self::PublicExposure => CoreUninstallTargetKind::PublicExposure,
            Self::PlacementGroup => CoreUninstallTargetKind::PlacementGroup,
            Self::ModelService => CoreUninstallTargetKind::ModelService,
            Self::PlatformService => CoreUninstallTargetKind::PlatformService,
            Self::RuntimeInstallation => CoreUninstallTargetKind::RuntimeInstallation,
            Self::ManagedContainer => CoreUninstallTargetKind::ManagedContainer,
            Self::ManagedImage => CoreUninstallTargetKind::ManagedImage,
            Self::OwnerRoot => CoreUninstallTargetKind::OwnerRoot,
            Self::ModelRoot => CoreUninstallTargetKind::ModelRoot,
            Self::CoreConfiguration => CoreUninstallTargetKind::CoreConfiguration,
            Self::CoreInstallation => CoreUninstallTargetKind::CoreInstallation,
            Self::Launcher => CoreUninstallTargetKind::Launcher,
        }
    }
}

// Stores one reconstructable boundary receipt with every exact public domain identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBoundaryReceipt {
    #[serde(with = "journal_digest")]
    plan_id: Sha256Digest,
    boundary: WireBoundary,
    target_count: usize,
    #[serde(with = "journal_digest")]
    target_set_sha256: Sha256Digest,
}

// Stores one exact boundary identity without deriving serialization on the domain enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireBoundary {
    BenchmarkExit,
    PublicExposure,
    Workloads,
    RuntimeArtifacts,
    PlatformServices,
    OwnerData,
    ImmutableCore,
}

impl WireBoundaryReceipt {
    // Projects only an exact receipt reconstructed from the supplied ownership plan.
    fn from_receipt(
        plan: &CoreUninstallPlan,
        receipt: &CoreUninstallBoundaryReceipt,
    ) -> Result<Self, CoreUninstallSessionError> {
        let expected = CoreUninstallBoundaryReceipt::completed(plan, receipt.boundary())
            .map_err(invalid_domain)?;
        if &expected != receipt {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        let boundary = WireBoundary::from_domain(receipt.boundary())?;
        Ok(Self {
            plan_id: receipt.plan_id().clone(),
            boundary,
            target_count: receipt.target_count(),
            target_set_sha256: receipt.target_set_sha256().clone(),
        })
    }

    // Reconstructs the exact domain receipt and rejects every alternate wire projection.
    fn to_receipt(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallSessionError> {
        let receipt = CoreUninstallBoundaryReceipt::completed(plan, self.boundary.to_domain())
            .map_err(invalid_domain)?;
        if Self::from_receipt(plan, &receipt)? != *self {
            return Err(CoreUninstallSessionError::InvalidJournal);
        }
        Ok(receipt)
    }
}

impl WireBoundary {
    // Projects one mutation boundary into the closed receipt grammar.
    const fn from_domain(
        boundary: CoreUninstallBoundary,
    ) -> Result<Self, CoreUninstallSessionError> {
        match boundary {
            CoreUninstallBoundary::BenchmarkExit => Ok(Self::BenchmarkExit),
            CoreUninstallBoundary::PublicExposure => Ok(Self::PublicExposure),
            CoreUninstallBoundary::Workloads => Ok(Self::Workloads),
            CoreUninstallBoundary::RuntimeArtifacts => Ok(Self::RuntimeArtifacts),
            CoreUninstallBoundary::PlatformServices => Ok(Self::PlatformServices),
            CoreUninstallBoundary::OwnerData => Ok(Self::OwnerData),
            CoreUninstallBoundary::ImmutableCore => Ok(Self::ImmutableCore),
            CoreUninstallBoundary::Preflight => Err(CoreUninstallSessionError::InvalidJournal),
        }
    }

    // Restores one wire boundary into the domain enum.
    const fn to_domain(self) -> CoreUninstallBoundary {
        match self {
            Self::BenchmarkExit => CoreUninstallBoundary::BenchmarkExit,
            Self::PublicExposure => CoreUninstallBoundary::PublicExposure,
            Self::Workloads => CoreUninstallBoundary::Workloads,
            Self::RuntimeArtifacts => CoreUninstallBoundary::RuntimeArtifacts,
            Self::PlatformServices => CoreUninstallBoundary::PlatformServices,
            Self::OwnerData => CoreUninstallBoundary::OwnerData,
            Self::ImmutableCore => CoreUninstallBoundary::ImmutableCore,
        }
    }
}

const UNINSTALL_BOUNDARY_ORDER: [CoreUninstallBoundary; MAXIMUM_BOUNDARY_RECEIPTS] = [
    CoreUninstallBoundary::BenchmarkExit,
    CoreUninstallBoundary::PublicExposure,
    CoreUninstallBoundary::Workloads,
    CoreUninstallBoundary::RuntimeArtifacts,
    CoreUninstallBoundary::PlatformServices,
    CoreUninstallBoundary::OwnerData,
    CoreUninstallBoundary::ImmutableCore,
];

// Maps one retained-model policy to the exact domain policy bound into a plan.
const fn retention_disposition(
    retention: CoreUninstallSessionRetention,
) -> CoreUninstallModelDisposition {
    match retention {
        CoreUninstallSessionRetention::KeepModels => CoreUninstallModelDisposition::KeepModels,
        CoreUninstallSessionRetention::RemoveModels => CoreUninstallModelDisposition::RemoveModels,
    }
}

// Returns one boundary's fixed contiguous-prefix index without accepting preflight.
fn boundary_index(boundary: CoreUninstallBoundary) -> Option<usize> {
    UNINSTALL_BOUNDARY_ORDER
        .iter()
        .position(|candidate| *candidate == boundary)
}

// Restricts receipt publication to the phase that owns its irreversible boundary.
const fn phase_accepts_boundary(
    phase: CoreUninstallSessionPhase,
    boundary: CoreUninstallBoundary,
) -> bool {
    match phase {
        CoreUninstallSessionPhase::Planned => matches!(
            boundary,
            CoreUninstallBoundary::BenchmarkExit
                | CoreUninstallBoundary::PublicExposure
                | CoreUninstallBoundary::Workloads
                | CoreUninstallBoundary::RuntimeArtifacts
        ),
        CoreUninstallSessionPhase::ServicesRetiring => {
            matches!(boundary, CoreUninstallBoundary::PlatformServices)
        }
        CoreUninstallSessionPhase::CoreRetiring => matches!(
            boundary,
            CoreUninstallBoundary::OwnerData | CoreUninstallBoundary::ImmutableCore
        ),
        CoreUninstallSessionPhase::Admitting | CoreUninstallSessionPhase::ServicesRetired => false,
    }
}

// Requires one phase's exact plan presence and allowed contiguous receipt prefix.
fn validate_phase(
    phase: CoreUninstallSessionPhase,
    plan: Option<&CoreUninstallPlan>,
    receipt_count: usize,
) -> Result<(), CoreUninstallSessionError> {
    let valid = match phase {
        CoreUninstallSessionPhase::Admitting => plan.is_none() && receipt_count == 0,
        CoreUninstallSessionPhase::Planned => plan.is_some() && receipt_count <= 4,
        CoreUninstallSessionPhase::ServicesRetiring => {
            plan.is_some() && (4..=5).contains(&receipt_count)
        }
        CoreUninstallSessionPhase::ServicesRetired => plan.is_some() && receipt_count == 5,
        CoreUninstallSessionPhase::CoreRetiring => {
            plan.is_some() && (5..=MAXIMUM_BOUNDARY_RECEIPTS).contains(&receipt_count)
        }
    };
    valid
        .then_some(())
        .ok_or(CoreUninstallSessionError::InvalidJournal)
}

// Closes every domain reconstruction failure into the durable journal boundary.
fn invalid_domain<T>(_error: T) -> CoreUninstallSessionError {
    CoreUninstallSessionError::InvalidJournal
}

// Captures the stable native identity required across every path-based root operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    // Projects only device and inode identity from one no-follow descriptor.
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

// Owns one nonblocking OS file lock until the exact CLI operation releases it.
struct CoreUninstallSessionLock {
    file: File,
}

impl Drop for CoreUninstallSessionLock {
    // Releases the native lock without converting cleanup into a panic path.
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

// Acquires and revalidates one owner-only lock without waiting behind another CLI process.
fn acquire_lock(
    root_path: &Path,
    owner_user_id: u32,
    root: &File,
    root_identity: FileIdentity,
) -> Result<CoreUninstallSessionLock, CoreUninstallSessionError> {
    let lock_path = root_path.join(LOCK_FILENAME);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(unavailable)?;
    require_private_file_metadata(
        &file.metadata().map_err(unavailable)?,
        owner_user_id,
        true,
        0,
    )?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(CoreUninstallSessionError::OperationConflict);
    }
    verify_root_identity(root_path, owner_user_id, root, root_identity)?;
    let observed = fs::symlink_metadata(&lock_path).map_err(unavailable)?;
    let opened = file.metadata().map_err(unavailable)?;
    require_private_file_metadata(&observed, owner_user_id, true, 0)?;
    if FileIdentity::from_metadata(&observed) != FileIdentity::from_metadata(&opened) {
        return Err(CoreUninstallSessionError::InvalidStateRoot);
    }
    Ok(CoreUninstallSessionLock { file })
}

// Writes, synchronizes, atomically publishes, and rereads one exact private journal.
fn write_journal(
    root_path: &Path,
    owner_user_id: u32,
    root: &File,
    root_identity: FileIdentity,
    journal: &UninstallSessionJournal,
) -> Result<(), CoreUninstallSessionError> {
    journal.validate()?;
    let mut bytes =
        serde_json::to_vec(journal).map_err(|_| CoreUninstallSessionError::InvalidJournal)?;
    bytes.push(b'\n');
    if bytes.len() > MAXIMUM_JOURNAL_BYTES {
        return Err(CoreUninstallSessionError::InvalidJournal);
    }
    verify_root_identity(root_path, owner_user_id, root, root_identity)?;
    remove_safe_temporary_file(root_path, owner_user_id)?;
    root.sync_all().map_err(unavailable)?;
    let temporary = root_path.join(TEMPORARY_FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(unavailable)?;
    require_private_file_metadata(
        &file.metadata().map_err(unavailable)?,
        owner_user_id,
        true,
        MAXIMUM_JOURNAL_BYTES as u64,
    )?;
    file.write_all(&bytes).map_err(unavailable)?;
    file.sync_all().map_err(unavailable)?;
    require_private_file_metadata(
        &file.metadata().map_err(unavailable)?,
        owner_user_id,
        false,
        MAXIMUM_JOURNAL_BYTES as u64,
    )?;
    verify_root_identity(root_path, owner_user_id, root, root_identity)?;
    fs::rename(&temporary, root_path.join(JOURNAL_FILENAME)).map_err(unavailable)?;
    root.sync_all().map_err(unavailable)?;
    let observed =
        read_journal(root_path, owner_user_id)?.ok_or(CoreUninstallSessionError::InvalidJournal)?;
    if &observed != journal {
        return Err(CoreUninstallSessionError::InvalidJournal);
    }
    Ok(())
}

// Reads one bounded owner-only journal without following or racing a replaced file identity.
fn read_journal(
    root: &Path,
    owner_user_id: u32,
) -> Result<Option<UninstallSessionJournal>, CoreUninstallSessionError> {
    let path = root.join(JOURNAL_FILENAME);
    let observed = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CoreUninstallSessionError::PersistenceUnavailable),
    };
    require_private_file_metadata(
        &observed,
        owner_user_id,
        false,
        MAXIMUM_JOURNAL_BYTES as u64,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CoreUninstallSessionError::InvalidJournal)?;
    let opened = file.metadata().map_err(unavailable)?;
    require_private_file_metadata(&opened, owner_user_id, false, MAXIMUM_JOURNAL_BYTES as u64)?;
    if FileIdentity::from_metadata(&observed) != FileIdentity::from_metadata(&opened) {
        return Err(CoreUninstallSessionError::InvalidJournal);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((MAXIMUM_JOURNAL_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() as u64 != opened.len() || bytes.len() > MAXIMUM_JOURNAL_BYTES {
        return Err(CoreUninstallSessionError::InvalidJournal);
    }
    let journal: UninstallSessionJournal =
        serde_json::from_slice(&bytes).map_err(|_| CoreUninstallSessionError::InvalidJournal)?;
    journal.validate()?;
    Ok(Some(journal))
}

// Encodes one validated digest as its canonical lowercase hexadecimal journal value.
mod journal_digest {
    use li_core_interface::Sha256Digest;
    use serde::{Deserialize, Deserializer, Serializer};

    // Serializes only the canonical domain string without exposing its representation.
    pub fn serialize<SerializerType>(
        value: &Sha256Digest,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    // Parses the canonical domain value before the journal can authorize recovery.
    pub fn deserialize<'de, DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Sha256Digest, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Sha256Digest::parse(&value).map_err(serde::de::Error::custom)
    }
}

// Removes only a safe incomplete publication left before any Node exchange was authorized.
fn remove_safe_temporary_file(
    root: &Path,
    owner_user_id: u32,
) -> Result<(), CoreUninstallSessionError> {
    let path = root.join(TEMPORARY_FILENAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CoreUninstallSessionError::PersistenceUnavailable),
    };
    require_private_file_metadata(&metadata, owner_user_id, true, MAXIMUM_JOURNAL_BYTES as u64)?;
    fs::remove_file(path).map_err(unavailable)
}

// Opens one exact owner-private state directory without following its terminal component.
fn open_private_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<File, CoreUninstallSessionError> {
    require_no_symbolic_link_ancestors(path)?;
    require_private_directory_path(path, owner_user_id)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(unavailable)?;
    require_private_directory_metadata(&file.metadata().map_err(unavailable)?, owner_user_id)?;
    Ok(file)
}

// Revalidates both pathname and descriptor identity before every namespace mutation.
fn verify_root_identity(
    path: &Path,
    owner_user_id: u32,
    root: &File,
    expected: FileIdentity,
) -> Result<(), CoreUninstallSessionError> {
    require_no_symbolic_link_ancestors(path)?;
    let observed =
        fs::symlink_metadata(path).map_err(|_| CoreUninstallSessionError::InvalidStateRoot)?;
    let opened = root.metadata().map_err(unavailable)?;
    require_private_directory_metadata(&observed, owner_user_id)?;
    require_private_directory_metadata(&opened, owner_user_id)?;
    if FileIdentity::from_metadata(&observed) != expected
        || FileIdentity::from_metadata(&opened) != expected
    {
        return Err(CoreUninstallSessionError::InvalidStateRoot);
    }
    Ok(())
}

// Requires a canonical absolute component grammar without parent or current aliases.
fn require_safe_absolute_path(path: &Path) -> Result<(), CoreUninstallSessionError> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.clone().next().is_none()
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CoreUninstallSessionError::InvalidStateRoot);
    }
    Ok(())
}

// Rejects a symbolic link in every existing component of the explicit absolute root.
fn require_no_symbolic_link_ancestors(path: &Path) -> Result<(), CoreUninstallSessionError> {
    require_safe_absolute_path(path)?;
    let mut observed = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(component) = component else {
            return Err(CoreUninstallSessionError::InvalidStateRoot);
        };
        observed.push(component);
        let metadata = fs::symlink_metadata(&observed)
            .map_err(|_| CoreUninstallSessionError::InvalidStateRoot)?;
        if metadata.file_type().is_symlink() {
            return Err(CoreUninstallSessionError::InvalidStateRoot);
        }
    }
    Ok(())
}

// Requires one existing exact-mode owner directory without accepting a symbolic link.
fn require_private_directory_path(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreUninstallSessionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CoreUninstallSessionError::InvalidStateRoot)?;
    require_private_directory_metadata(&metadata, owner_user_id)
}

// Requires one owner-only native directory metadata snapshot.
fn require_private_directory_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), CoreUninstallSessionError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(CoreUninstallSessionError::InvalidStateRoot);
    }
    Ok(())
}

// Requires one owner-only, single-link, regular private file under its exact byte bound.
fn require_private_file_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    allow_empty: bool,
    maximum_bytes: u64,
) -> Result<(), CoreUninstallSessionError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
        || (!allow_empty && metadata.len() == 0)
        || metadata.len() > maximum_bytes
    {
        return Err(CoreUninstallSessionError::InvalidJournal);
    }
    Ok(())
}

// Maps native persistence failures into one stable application boundary.
fn unavailable(_error: std::io::Error) -> CoreUninstallSessionError {
    CoreUninstallSessionError::PersistenceUnavailable
}
