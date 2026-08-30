// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::li_core_uninstall_session::{
    CoreUninstallSessionPhase, CoreUninstallSessionRecoveryState, CoreUninstallSessionRetention,
};

const MAXIMUM_TARGET_IDENTITY_BYTES: usize = 1024;
const MAXIMUM_UNINSTALL_TARGETS: usize = 4096;
const MAXIMUM_BENCHMARK_STOP_WAIT: Duration = Duration::from_secs(3600);

// Selects whether locally managed model bytes survive owner-data cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUninstallModelDisposition {
    KeepModels,
    RemoveModels,
}

// Carries the caller's explicit destructive-action decision into orchestration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUninstallConfirmation {
    Confirmed,
    Declined,
}

// Names each kind of exact owned target discovered before uninstall mutation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoreUninstallTargetKind {
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

impl CoreUninstallTargetKind {
    pub const ALL: [Self; 13] = [
        Self::ActiveBenchmark,
        Self::PublicExposure,
        Self::PlacementGroup,
        Self::ModelService,
        Self::PlatformService,
        Self::RuntimeInstallation,
        Self::ManagedContainer,
        Self::ManagedImage,
        Self::OwnerRoot,
        Self::ModelRoot,
        Self::CoreConfiguration,
        Self::CoreInstallation,
        Self::Launcher,
    ];

    // Returns the canonical identity fragment used by plan and receipt digests.
    const fn identity(self) -> &'static str {
        match self {
            Self::ActiveBenchmark => "active_benchmark",
            Self::PublicExposure => "public_exposure",
            Self::PlacementGroup => "placement_group",
            Self::ModelService => "model_service",
            Self::PlatformService => "platform_service",
            Self::RuntimeInstallation => "runtime_installation",
            Self::ManagedContainer => "managed_container",
            Self::ManagedImage => "managed_image",
            Self::OwnerRoot => "owner_root",
            Self::ModelRoot => "model_root",
            Self::CoreConfiguration => "core_configuration",
            Self::CoreInstallation => "core_installation",
            Self::Launcher => "launcher",
        }
    }

    // Returns the fixed summary slot for this closed target kind.
    const fn summary_index(self) -> usize {
        match self {
            Self::ActiveBenchmark => 0,
            Self::PublicExposure => 1,
            Self::PlacementGroup => 2,
            Self::ModelService => 3,
            Self::PlatformService => 4,
            Self::RuntimeInstallation => 5,
            Self::ManagedContainer => 6,
            Self::ManagedImage => 7,
            Self::OwnerRoot => 8,
            Self::ModelRoot => 9,
            Self::CoreConfiguration => 10,
            Self::CoreInstallation => 11,
            Self::Launcher => 12,
        }
    }
}

// Binds one non-secret target identity to the ownership proof verified during preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUninstallOwnedTarget {
    kind: CoreUninstallTargetKind,
    identity: String,
    ownership_sha256: Sha256Digest,
}

impl CoreUninstallOwnedTarget {
    // Creates one bounded canonical target without accepting ambiguous or control-bearing text.
    pub fn new(
        kind: CoreUninstallTargetKind,
        identity: impl Into<String>,
        ownership_sha256: Sha256Digest,
    ) -> Result<Self, CoreUninstallError> {
        let identity = identity.into();
        if identity.is_empty()
            || identity.len() > MAXIMUM_TARGET_IDENTITY_BYTES
            || identity.trim() != identity
            || identity.chars().any(char::is_control)
        {
            return Err(CoreUninstallError::InvalidPlan);
        }
        Ok(Self {
            kind,
            identity,
            ownership_sha256,
        })
    }

    // Returns the lifecycle category that owns mutation of this target.
    pub const fn kind(&self) -> CoreUninstallTargetKind {
        self.kind
    }

    // Returns the exact non-secret identity resolved by preflight.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    // Returns the proof that preflight verified ownership before mutation.
    pub const fn ownership_sha256(&self) -> &Sha256Digest {
        &self.ownership_sha256
    }
}

// Names each external uninstall boundary in its irreversible execution order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoreUninstallBoundary {
    Preflight,
    BenchmarkExit,
    PublicExposure,
    Workloads,
    RuntimeArtifacts,
    PlatformServices,
    OwnerData,
    ImmutableCore,
}

impl CoreUninstallBoundary {
    const MUTATION_ORDER: [Self; 7] = [
        Self::BenchmarkExit,
        Self::PublicExposure,
        Self::Workloads,
        Self::RuntimeArtifacts,
        Self::PlatformServices,
        Self::OwnerData,
        Self::ImmutableCore,
    ];

    // Returns the canonical identity fragment used by plan and receipt digests.
    const fn identity(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::BenchmarkExit => "benchmark_exit",
            Self::PublicExposure => "public_exposure",
            Self::Workloads => "workloads",
            Self::PlatformServices => "platform_services",
            Self::RuntimeArtifacts => "runtime_artifacts",
            Self::OwnerData => "owner_data",
            Self::ImmutableCore => "immutable_core",
        }
    }

    // Returns whether one target kind belongs to this mutation boundary.
    const fn contains(self, kind: CoreUninstallTargetKind) -> bool {
        match self {
            Self::Preflight => false,
            Self::BenchmarkExit => matches!(kind, CoreUninstallTargetKind::ActiveBenchmark),
            Self::PublicExposure => matches!(kind, CoreUninstallTargetKind::PublicExposure),
            Self::Workloads => matches!(
                kind,
                CoreUninstallTargetKind::PlacementGroup | CoreUninstallTargetKind::ModelService
            ),
            Self::PlatformServices => matches!(kind, CoreUninstallTargetKind::PlatformService),
            Self::RuntimeArtifacts => matches!(
                kind,
                CoreUninstallTargetKind::RuntimeInstallation
                    | CoreUninstallTargetKind::ManagedContainer
                    | CoreUninstallTargetKind::ManagedImage
            ),
            Self::OwnerData => matches!(
                kind,
                CoreUninstallTargetKind::OwnerRoot | CoreUninstallTargetKind::ModelRoot
            ),
            Self::ImmutableCore => matches!(
                kind,
                CoreUninstallTargetKind::CoreConfiguration
                    | CoreUninstallTargetKind::CoreInstallation
                    | CoreUninstallTargetKind::Launcher
            ),
        }
    }
}

// Carries only validated caller policy; target discovery remains preflight-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreUninstallRequest {
    confirmation: CoreUninstallConfirmation,
    model_disposition: CoreUninstallModelDisposition,
}

impl CoreUninstallRequest {
    // Creates one request without treating a declined confirmation as an implicit success.
    pub const fn new(
        confirmation: CoreUninstallConfirmation,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Self {
        Self {
            confirmation,
            model_disposition,
        }
    }

    // Returns the caller's explicit destructive-action decision.
    pub const fn confirmation(&self) -> CoreUninstallConfirmation {
        self.confirmation
    }

    // Returns whether model roots are preserved or removed during owner cleanup.
    pub const fn model_disposition(&self) -> CoreUninstallModelDisposition {
        self.model_disposition
    }
}

// Binds the complete ownership scan and every target before the first mutation begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUninstallPlan {
    plan_id: Sha256Digest,
    ownership_plan_sha256: Sha256Digest,
    model_disposition: CoreUninstallModelDisposition,
    benchmark_stop_wait: Duration,
    targets: Vec<CoreUninstallOwnedTarget>,
}

impl CoreUninstallPlan {
    // Creates one canonical plan after validating every target and bounded benchmark wait.
    pub fn new(
        ownership_plan_sha256: Sha256Digest,
        model_disposition: CoreUninstallModelDisposition,
        benchmark_stop_wait: Duration,
        mut targets: Vec<CoreUninstallOwnedTarget>,
    ) -> Result<Self, CoreUninstallError> {
        if benchmark_stop_wait.is_zero()
            || benchmark_stop_wait > MAXIMUM_BENCHMARK_STOP_WAIT
            || targets.len() > MAXIMUM_UNINSTALL_TARGETS
        {
            return Err(CoreUninstallError::InvalidPlan);
        }
        targets.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.identity.cmp(&right.identity))
        });
        validate_targets(&targets)?;
        validate_model_disposition_targets(model_disposition, &targets)?;
        let plan_id = plan_identity(
            &ownership_plan_sha256,
            model_disposition,
            benchmark_stop_wait,
            &targets,
        )?;
        Ok(Self {
            plan_id,
            ownership_plan_sha256,
            model_disposition,
            benchmark_stop_wait,
            targets,
        })
    }

    // Returns the canonical identity of this exact verified ownership plan.
    pub const fn plan_id(&self) -> &Sha256Digest {
        &self.plan_id
    }

    // Returns the preflight provider's digest of its complete ownership scan.
    pub const fn ownership_plan_sha256(&self) -> &Sha256Digest {
        &self.ownership_plan_sha256
    }

    // Returns whether owner cleanup preserves or removes managed model roots.
    pub const fn model_disposition(&self) -> CoreUninstallModelDisposition {
        self.model_disposition
    }

    // Returns the complete bounded exit wait for an active benchmark process.
    pub const fn benchmark_stop_wait(&self) -> Duration {
        self.benchmark_stop_wait
    }

    // Returns every exact target in canonical kind and identity order.
    pub fn targets(&self) -> &[CoreUninstallOwnedTarget] {
        &self.targets
    }

    // Returns the number of exact targets assigned to one mutation boundary.
    pub fn target_count(&self, boundary: CoreUninstallBoundary) -> usize {
        self.targets
            .iter()
            .filter(|target| boundary.contains(target.kind))
            .count()
    }

    // Returns the number of exact targets of one closed kind.
    pub fn target_kind_count(&self, kind: CoreUninstallTargetKind) -> usize {
        self.targets
            .iter()
            .filter(|target| target.kind == kind)
            .count()
    }

    // Recomputes every structural identity before orchestration trusts a preflight result.
    pub fn validate(&self) -> Result<(), CoreUninstallError> {
        if self.benchmark_stop_wait.is_zero()
            || self.benchmark_stop_wait > MAXIMUM_BENCHMARK_STOP_WAIT
            || self.targets.len() > MAXIMUM_UNINSTALL_TARGETS
        {
            return Err(CoreUninstallError::InvalidPlan);
        }
        validate_targets(&self.targets)?;
        validate_model_disposition_targets(self.model_disposition, &self.targets)?;
        let expected = plan_identity(
            &self.ownership_plan_sha256,
            self.model_disposition,
            self.benchmark_stop_wait,
            &self.targets,
        )?;
        if expected != self.plan_id {
            return Err(CoreUninstallError::InvalidPlan);
        }
        Ok(())
    }

    // Returns the exact content identity a successful boundary receipt must carry.
    fn boundary_identity(
        &self,
        boundary: CoreUninstallBoundary,
    ) -> Result<Sha256Digest, CoreUninstallError> {
        if boundary == CoreUninstallBoundary::Preflight {
            return Err(CoreUninstallError::InvalidPlan);
        }
        let mut hasher = Sha256::new();
        append_text(&mut hasher, "li_core_uninstall_boundary_v1");
        append_text(&mut hasher, self.plan_id.as_str());
        append_text(&mut hasher, boundary.identity());
        for target in self
            .targets
            .iter()
            .filter(|target| boundary.contains(target.kind))
        {
            append_target(&mut hasher, target);
        }
        parsed_digest(hasher.finalize())
    }

    // Returns a fixed summary used to make final receipts self-describing.
    fn target_summary(&self) -> [usize; 13] {
        let mut summary = [0; 13];
        for target in &self.targets {
            summary[target.kind.summary_index()] += 1;
        }
        summary
    }
}

// Proves one external boundary completed against the exact preflight plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUninstallBoundaryReceipt {
    plan_id: Sha256Digest,
    boundary: CoreUninstallBoundary,
    target_set_sha256: Sha256Digest,
    target_count: usize,
}

impl CoreUninstallBoundaryReceipt {
    // Creates the receipt an adapter returns only after completing its entire boundary.
    pub fn completed(
        plan: &CoreUninstallPlan,
        boundary: CoreUninstallBoundary,
    ) -> Result<Self, CoreUninstallError> {
        Ok(Self {
            plan_id: plan.plan_id.clone(),
            boundary,
            target_set_sha256: plan.boundary_identity(boundary)?,
            target_count: plan.target_count(boundary),
        })
    }

    // Returns the exact preflight plan identity consumed by this boundary.
    pub const fn plan_id(&self) -> &Sha256Digest {
        &self.plan_id
    }

    // Returns the irreversible lifecycle boundary that completed.
    pub const fn boundary(&self) -> CoreUninstallBoundary {
        self.boundary
    }

    // Returns the number of plan targets handled by this boundary.
    pub const fn target_count(&self) -> usize {
        self.target_count
    }

    // Returns the canonical digest of the exact target subset owned by this boundary.
    pub const fn target_set_sha256(&self) -> &Sha256Digest {
        &self.target_set_sha256
    }

    // Rejects a receipt from another plan, boundary, or incomplete target set.
    fn validate(
        &self,
        plan: &CoreUninstallPlan,
        expected_boundary: CoreUninstallBoundary,
    ) -> Result<(), CoreUninstallError> {
        if self.plan_id != plan.plan_id
            || self.boundary != expected_boundary
            || self.target_count != plan.target_count(expected_boundary)
            || self.target_set_sha256 != plan.boundary_identity(expected_boundary)?
        {
            return Err(CoreUninstallError::InvalidReceipt(expected_boundary));
        }
        Ok(())
    }
}

// Returns one stable complete receipt without claiming rollback of destructive teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUninstallReceipt {
    receipt_id: Sha256Digest,
    plan_id: Sha256Digest,
    model_disposition: CoreUninstallModelDisposition,
    target_summary: [usize; 13],
    boundaries: [CoreUninstallBoundaryReceipt; 7],
}

impl CoreUninstallReceipt {
    // Creates one terminal receipt only from all seven exact boundary receipts in order.
    pub fn completed(
        plan: &CoreUninstallPlan,
        boundaries: [CoreUninstallBoundaryReceipt; 7],
    ) -> Result<Self, CoreUninstallError> {
        for (index, boundary) in boundaries.iter().enumerate() {
            boundary.validate(plan, CoreUninstallBoundary::MUTATION_ORDER[index])?;
        }
        let target_summary = plan.target_summary();
        let receipt_id = receipt_identity(
            plan.plan_id(),
            plan.model_disposition,
            &target_summary,
            &boundaries,
        )?;
        Ok(Self {
            receipt_id,
            plan_id: plan.plan_id.clone(),
            model_disposition: plan.model_disposition,
            target_summary,
            boundaries,
        })
    }

    // Returns the stable terminal identity shared by ordinary and replayed results.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the exact ownership plan completed by this receipt.
    pub const fn plan_id(&self) -> &Sha256Digest {
        &self.plan_id
    }

    // Returns the exact model-root policy bound into this terminal receipt.
    pub const fn model_disposition(&self) -> CoreUninstallModelDisposition {
        self.model_disposition
    }

    // Returns whether this terminal removal preserved managed model roots.
    pub const fn models_preserved(&self) -> bool {
        matches!(
            self.model_disposition,
            CoreUninstallModelDisposition::KeepModels
        )
    }

    // Returns the target count for one closed ownership category.
    pub const fn target_count(&self, kind: CoreUninstallTargetKind) -> usize {
        self.target_summary[kind.summary_index()]
    }

    // Returns every successful boundary receipt in irreversible execution order.
    pub fn boundaries(&self) -> &[CoreUninstallBoundaryReceipt; 7] {
        &self.boundaries
    }

    // Recomputes the terminal receipt identity before accepting an idempotent replay.
    pub fn validate(&self) -> Result<(), CoreUninstallError> {
        for (index, boundary) in self.boundaries.iter().enumerate() {
            if boundary.plan_id != self.plan_id
                || boundary.boundary != CoreUninstallBoundary::MUTATION_ORDER[index]
            {
                return Err(CoreUninstallError::InvalidReceipt(boundary.boundary));
            }
        }
        let expected = receipt_identity(
            &self.plan_id,
            self.model_disposition,
            &self.target_summary,
            &self.boundaries,
        )?;
        if expected != self.receipt_id {
            return Err(CoreUninstallError::InvalidReceipt(
                CoreUninstallBoundary::ImmutableCore,
            ));
        }
        Ok(())
    }
}

// Distinguishes a newly completed uninstall from an exact terminal replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUninstallResult {
    receipt: CoreUninstallReceipt,
    replayed: bool,
}

impl CoreUninstallResult {
    // Returns the stable receipt produced by the original complete teardown.
    pub const fn receipt(&self) -> &CoreUninstallReceipt {
        &self.receipt
    }

    // Returns whether preflight observed an already completed exact request.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

// Returns either a fully verified mutation plan or its already completed receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreUninstallPreflight {
    Ready(CoreUninstallPlan),
    Replayed(CoreUninstallReceipt),
}

// Resolves and verifies every ownership target before any destructive port is called.
pub trait CoreUninstallPreflightPort: Send + Sync {
    // Produces one exact all-target plan or the stable receipt for an identical replay.
    fn preflight(
        &self,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Result<CoreUninstallPreflight, CoreUninstallError>;
}

// Excludes new Node mutations while one uninstall inventories and retires exact owner state.
pub trait CoreUninstallMutationBarrierPort: Send + Sync {
    // Waits for earlier mutations, then returns the exact Node-owned uninstall session.
    fn begin(
        &self,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Result<Sha256Digest, CoreUninstallError>;

    // Returns the exact durable plan, phase, and contiguous receipt prefix for this session.
    fn recovery_state(
        &self,
        session_id: &Sha256Digest,
    ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallError>;

    // Persists the validated ownership plan before the first mutation can begin.
    fn persist_plan(
        &self,
        session_id: &Sha256Digest,
        plan: &CoreUninstallPlan,
    ) -> Result<(), CoreUninstallError>;

    // Persists one validated next boundary receipt before any later boundary can begin.
    fn append_receipt(
        &self,
        session_id: &Sha256Digest,
        receipt: &CoreUninstallBoundaryReceipt,
    ) -> Result<(), CoreUninstallError>;

    // Advances one exact durable phase before or after resident retirement.
    fn advance_phase(
        &self,
        session_id: &Sha256Digest,
        phase: CoreUninstallSessionPhase,
    ) -> Result<(), CoreUninstallError>;

    // Releases one matching session when teardown stops before the Node resident retires.
    fn cancel(&self, session_id: &Sha256Digest) -> Result<(), CoreUninstallError>;
}

// Stops an active benchmark and proves its process exited within the plan's fixed bound.
pub trait CoreUninstallBenchmarkPort: Send + Sync {
    // Completes the benchmark-exit boundary without extending its preflight timeout.
    fn stop_and_wait(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Disables the exact verified public inference exposure before local workloads stop.
pub trait CoreUninstallExposurePort: Send + Sync {
    // Completes the public-exposure boundary for every target in the plan.
    fn disable(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Stops and removes exact model services and placement groups through their existing owners.
pub trait CoreUninstallWorkloadPort: Send + Sync {
    // Completes placement and model shutdown before platform services retire.
    fn shutdown(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Retires the existing Linux or macOS resident service set after workload shutdown.
pub trait CoreUninstallServicePort: Send + Sync {
    // Completes platform service retirement against the exact preflight inventory.
    fn retire(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Cleans only verified managed runtime installations, containers, and images.
pub trait CoreUninstallRuntimePort: Send + Sync {
    // Completes managed runtime cleanup without selecting unowned native objects.
    fn clean(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Cleans verified owner data while preserving active Core bytes and requested model roots.
pub trait CoreUninstallOwnerDataPort: Send + Sync {
    // Completes owner-root cleanup under the plan's explicit model disposition.
    fn clean(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Retires the immutable Core store and every verified launcher as the final boundary.
pub trait CoreUninstallImmutableCorePort: Send + Sync {
    // Completes final Core and launcher retirement after all other owned state is gone.
    fn retire(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>;
}

// Names stable caller, plan, receipt, concurrency, and external-boundary failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUninstallError {
    ConfirmationRequired,
    PreflightRejected,
    InvalidPlan,
    InvalidReceipt(CoreUninstallBoundary),
    OperationConflict,
    BoundaryFailed(CoreUninstallBoundary),
}

impl fmt::Display for CoreUninstallError {
    // Presents stable recovery language without claiming destructive rollback occurred.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfirmationRequired => {
                formatter.write_str("uninstall requires explicit confirmation")
            }
            Self::PreflightRejected => formatter.write_str("uninstall preflight rejected the host"),
            Self::InvalidPlan => formatter.write_str("uninstall ownership plan is invalid"),
            Self::InvalidReceipt(boundary) => write!(
                formatter,
                "uninstall {} receipt is invalid",
                boundary.identity()
            ),
            Self::OperationConflict => {
                formatter.write_str("another uninstall operation owns this process")
            }
            Self::BoundaryFailed(boundary) => write!(
                formatter,
                "uninstall stopped at the {} boundary",
                boundary.identity()
            ),
        }
    }
}

impl Error for CoreUninstallError {}

// Coordinates the existing owners through one validated, linear, irreversible teardown.
pub struct CoreUninstallCoordinator {
    mutation_barrier: Arc<dyn CoreUninstallMutationBarrierPort>,
    preflight: Arc<dyn CoreUninstallPreflightPort>,
    benchmark: Arc<dyn CoreUninstallBenchmarkPort>,
    exposure: Arc<dyn CoreUninstallExposurePort>,
    workloads: Arc<dyn CoreUninstallWorkloadPort>,
    services: Arc<dyn CoreUninstallServicePort>,
    runtimes: Arc<dyn CoreUninstallRuntimePort>,
    owner_data: Arc<dyn CoreUninstallOwnerDataPort>,
    immutable_core: Arc<dyn CoreUninstallImmutableCorePort>,
    operation_lock: Mutex<()>,
}

impl CoreUninstallCoordinator {
    // Creates one application coordinator from the narrow ports owned by existing managers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mutation_barrier: Arc<dyn CoreUninstallMutationBarrierPort>,
        preflight: Arc<dyn CoreUninstallPreflightPort>,
        benchmark: Arc<dyn CoreUninstallBenchmarkPort>,
        exposure: Arc<dyn CoreUninstallExposurePort>,
        workloads: Arc<dyn CoreUninstallWorkloadPort>,
        services: Arc<dyn CoreUninstallServicePort>,
        runtimes: Arc<dyn CoreUninstallRuntimePort>,
        owner_data: Arc<dyn CoreUninstallOwnerDataPort>,
        immutable_core: Arc<dyn CoreUninstallImmutableCorePort>,
    ) -> Self {
        Self {
            mutation_barrier,
            preflight,
            benchmark,
            exposure,
            workloads,
            services,
            runtimes,
            owner_data,
            immutable_core,
            operation_lock: Mutex::new(()),
        }
    }

    // Executes each destructive boundary once and stops immediately at the first failure.
    pub fn uninstall(
        &self,
        request: &CoreUninstallRequest,
    ) -> Result<CoreUninstallResult, CoreUninstallError> {
        if request.confirmation != CoreUninstallConfirmation::Confirmed {
            return Err(CoreUninstallError::ConfirmationRequired);
        }
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let session_id = self.mutation_barrier.begin(request.model_disposition)?;
        let recovery = match self.mutation_barrier.recovery_state(&session_id) {
            Ok(recovery) => recovery,
            Err(error) => {
                self.mutation_barrier.cancel(&session_id)?;
                return Err(error);
            }
        };
        let retention_matches = matches!(
            (recovery.retention(), request.model_disposition),
            (
                CoreUninstallSessionRetention::KeepModels,
                CoreUninstallModelDisposition::KeepModels
            ) | (
                CoreUninstallSessionRetention::RemoveModels,
                CoreUninstallModelDisposition::RemoveModels
            )
        );
        if recovery.session_id() != &session_id || !retention_matches {
            if recovery.plan().is_none() {
                self.mutation_barrier.cancel(&session_id)?;
            }
            return Err(CoreUninstallError::PreflightRejected);
        }
        let mut plan_bound = recovery.plan().is_some();
        let mut phase = recovery.phase();
        let terminal_replay =
            recovery.receipts().len() == CoreUninstallBoundary::MUTATION_ORDER.len();
        let result = (|| {
            let plan = match recovery.plan() {
                Some(plan) => plan.clone(),
                None => match self.preflight.preflight(request.model_disposition)? {
                    CoreUninstallPreflight::Ready(plan) => {
                        // Once publication begins, preserve the lease on every ambiguous outcome.
                        // A retry can recover either the admitting or the fully planned journal.
                        plan_bound = true;
                        if let Err(error) = self.mutation_barrier.persist_plan(&session_id, &plan) {
                            let observed = self.mutation_barrier.recovery_state(&session_id)?;
                            if observed.phase() != CoreUninstallSessionPhase::Planned
                                || observed.plan() != Some(&plan)
                                || !observed.receipts().is_empty()
                            {
                                return Err(error);
                            }
                        }
                        phase = CoreUninstallSessionPhase::Planned;
                        plan
                    }
                    CoreUninstallPreflight::Replayed(receipt) => {
                        receipt.validate()?;
                        if receipt.model_disposition != request.model_disposition {
                            return Err(CoreUninstallError::PreflightRejected);
                        }
                        return Ok(CoreUninstallResult {
                            receipt,
                            replayed: true,
                        });
                    }
                },
            };
            plan.validate()?;
            if plan.model_disposition != request.model_disposition {
                return Err(CoreUninstallError::PreflightRejected);
            }
            let mut receipts = recovery.receipts().to_vec();
            let benchmark = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::BenchmarkExit,
                true,
                || self.benchmark.stop_and_wait(&plan),
            )?;
            let exposure = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::PublicExposure,
                true,
                || self.exposure.disable(&plan),
            )?;
            let workloads = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::Workloads,
                true,
                || self.workloads.shutdown(&plan),
            )?;
            let runtimes = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::RuntimeArtifacts,
                true,
                || self.runtimes.clean(&plan),
            )?;
            if phase == CoreUninstallSessionPhase::Planned {
                self.mutation_barrier
                    .advance_phase(&session_id, CoreUninstallSessionPhase::ServicesRetiring)?;
                phase = CoreUninstallSessionPhase::ServicesRetiring;
            }
            let services = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::PlatformServices,
                true,
                || self.services.retire(&plan),
            )?;
            if phase == CoreUninstallSessionPhase::ServicesRetiring {
                self.mutation_barrier
                    .advance_phase(&session_id, CoreUninstallSessionPhase::ServicesRetired)?;
                phase = CoreUninstallSessionPhase::ServicesRetired;
            }
            if phase != CoreUninstallSessionPhase::CoreRetiring {
                self.mutation_barrier
                    .advance_phase(&session_id, CoreUninstallSessionPhase::CoreRetiring)?;
                phase = CoreUninstallSessionPhase::CoreRetiring;
            }
            let owner_data = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::OwnerData,
                true,
                || self.owner_data.clean(&plan),
            )?;
            let immutable_core = recover_or_execute_boundary(
                self.mutation_barrier.as_ref(),
                &session_id,
                &plan,
                &mut receipts,
                CoreUninstallBoundary::ImmutableCore,
                false,
                || self.immutable_core.retire(&plan),
            )?;

            let receipt = CoreUninstallReceipt::completed(
                &plan,
                [
                    benchmark,
                    exposure,
                    workloads,
                    runtimes,
                    services,
                    owner_data,
                    immutable_core,
                ],
            )?;
            Ok(CoreUninstallResult {
                receipt,
                replayed: terminal_replay,
            })
        })();
        if !plan_bound {
            self.mutation_barrier.cancel(&session_id)?;
        }
        result
    }
}

// Reuses one durable receipt or executes and checkpoints exactly the next boundary.
#[allow(clippy::too_many_arguments)]
fn recover_or_execute_boundary<Operation>(
    barrier: &dyn CoreUninstallMutationBarrierPort,
    session_id: &Sha256Digest,
    plan: &CoreUninstallPlan,
    receipts: &mut Vec<CoreUninstallBoundaryReceipt>,
    boundary: CoreUninstallBoundary,
    persist: bool,
    operation: Operation,
) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>
where
    Operation: FnOnce() -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError>,
{
    let index = CoreUninstallBoundary::MUTATION_ORDER
        .iter()
        .position(|candidate| *candidate == boundary)
        .ok_or(CoreUninstallError::InvalidPlan)?;
    if let Some(receipt) = receipts.get(index) {
        receipt.validate(plan, boundary)?;
        return Ok(receipt.clone());
    }
    if receipts.len() != index {
        return Err(CoreUninstallError::InvalidReceipt(boundary));
    }
    let receipt = operation()?;
    receipt.validate(plan, boundary)?;
    if persist {
        barrier.append_receipt(session_id, &receipt)?;
    }
    receipts.push(receipt.clone());
    Ok(receipt)
}

// Rejects duplicate or ambiguous target inventories before any port can mutate the host.
fn validate_targets(targets: &[CoreUninstallOwnedTarget]) -> Result<(), CoreUninstallError> {
    let mut identities = BTreeSet::new();
    for target in targets {
        if target.identity.is_empty()
            || target.identity.len() > MAXIMUM_TARGET_IDENTITY_BYTES
            || target.identity.trim() != target.identity
            || target.identity.chars().any(char::is_control)
            || !identities.insert(target.identity.as_str())
        {
            return Err(CoreUninstallError::InvalidPlan);
        }
    }
    if targets
        .iter()
        .filter(|target| target.kind == CoreUninstallTargetKind::ActiveBenchmark)
        .count()
        > 1
        || targets
            .iter()
            .filter(|target| target.kind == CoreUninstallTargetKind::PublicExposure)
            .count()
            > 1
        || targets
            .iter()
            .filter(|target| target.kind == CoreUninstallTargetKind::CoreInstallation)
            .count()
            > 1
        || targets
            .iter()
            .filter(|target| target.kind == CoreUninstallTargetKind::CoreConfiguration)
            .count()
            > 1
    {
        return Err(CoreUninstallError::InvalidPlan);
    }
    Ok(())
}

// Rejects any preservation plan that would authorize deletion of downloaded model closures.
fn validate_model_disposition_targets(
    model_disposition: CoreUninstallModelDisposition,
    targets: &[CoreUninstallOwnedTarget],
) -> Result<(), CoreUninstallError> {
    if model_disposition == CoreUninstallModelDisposition::KeepModels
        && targets
            .iter()
            .any(|target| target.kind == CoreUninstallTargetKind::ModelRoot)
    {
        return Err(CoreUninstallError::InvalidPlan);
    }
    Ok(())
}

// Computes the canonical identity of one complete verified preflight plan.
fn plan_identity(
    ownership_plan_sha256: &Sha256Digest,
    model_disposition: CoreUninstallModelDisposition,
    benchmark_stop_wait: Duration,
    targets: &[CoreUninstallOwnedTarget],
) -> Result<Sha256Digest, CoreUninstallError> {
    let mut hasher = Sha256::new();
    append_text(&mut hasher, "li_core_uninstall_plan_v1");
    append_text(&mut hasher, ownership_plan_sha256.as_str());
    append_text(
        &mut hasher,
        match model_disposition {
            CoreUninstallModelDisposition::KeepModels => "keep_models",
            CoreUninstallModelDisposition::RemoveModels => "remove_models",
        },
    );
    hasher.update(benchmark_stop_wait.as_secs().to_be_bytes());
    hasher.update(benchmark_stop_wait.subsec_nanos().to_be_bytes());
    for target in targets {
        append_target(&mut hasher, target);
    }
    parsed_digest(hasher.finalize())
}

// Computes one stable terminal receipt identity from its plan, summary, and boundaries.
fn receipt_identity(
    plan_id: &Sha256Digest,
    model_disposition: CoreUninstallModelDisposition,
    target_summary: &[usize; 13],
    boundaries: &[CoreUninstallBoundaryReceipt; 7],
) -> Result<Sha256Digest, CoreUninstallError> {
    let mut hasher = Sha256::new();
    append_text(&mut hasher, "li_core_uninstall_receipt_v1");
    append_text(&mut hasher, plan_id.as_str());
    append_text(
        &mut hasher,
        match model_disposition {
            CoreUninstallModelDisposition::KeepModels => "keep_models",
            CoreUninstallModelDisposition::RemoveModels => "remove_models",
        },
    );
    for kind in CoreUninstallTargetKind::ALL {
        append_text(&mut hasher, kind.identity());
        hasher.update((target_summary[kind.summary_index()] as u64).to_be_bytes());
    }
    for boundary in boundaries {
        append_text(&mut hasher, boundary.boundary.identity());
        append_text(&mut hasher, boundary.target_set_sha256.as_str());
        hasher.update((boundary.target_count as u64).to_be_bytes());
    }
    parsed_digest(hasher.finalize())
}

// Adds one length-delimited target record to a canonical SHA-256 transcript.
fn append_target(hasher: &mut Sha256, target: &CoreUninstallOwnedTarget) {
    append_text(hasher, target.kind.identity());
    append_text(hasher, &target.identity);
    append_text(hasher, target.ownership_sha256.as_str());
}

// Adds one length-delimited UTF-8 value without transcript concatenation ambiguity.
fn append_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

// Parses one SHA-256 result through the shared canonical digest value type.
fn parsed_digest(bytes: impl AsRef<[u8]>) -> Result<Sha256Digest, CoreUninstallError> {
    Sha256Digest::parse(&hexadecimal(bytes.as_ref())).map_err(|_| CoreUninstallError::InvalidPlan)
}

// Encodes binary digest output without introducing another serialization dependency.
fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}
