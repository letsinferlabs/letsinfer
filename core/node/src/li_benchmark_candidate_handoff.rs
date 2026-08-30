// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, TryLockError};

use li_benchmark_manager::BenchmarkSubject;
use li_core_interface::{
    HardwareObservation, NodeId, OperationId, PlacementEndpoint, PlacementGroupId,
    PlacementGroupState, RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState,
    Sha256Digest,
};
use li_placement_manager::{PlacementRecord, PlacementRequest, VersionedPlacementRecord};
use li_runtime_manager::{
    RuntimeCandidate, RuntimeExactCandidateArtifacts, VersionedRuntimeInstallation,
};
use sha2::{Digest, Sha256};

use crate::{
    NodeModelClock, NodeModelHardwareProvider, NodeModelPlacementPort,
    NodeModelPlacementRequestProvider, NodeModelRuntimePort, NodeModelStatePort,
};

// Identifies one durable cross-manager benchmark candidate handoff boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeBenchmarkCandidateHandoffPhase {
    Prepared,
    CandidateAcquired,
    BaselineActivated,
    BaselineReleasing,
    BaselineReleased,
    CandidateStaged,
    CandidateRunning,
    Restoring,
    BaselineRestored,
    Completed,
}

impl NodeBenchmarkCandidateHandoffPhase {
    // Returns whether the transaction no longer owns candidate runtime or placement resources.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed)
    }
}

// Carries the resident-only trusted closure into NodeManager before an outer benchmark job exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkCandidateHandoffRequest {
    transaction_id: OperationId,
    baseline: BenchmarkSubject,
    candidate: RuntimeCandidate,
    artifacts: RuntimeExactCandidateArtifacts,
    runtime_execution_sha256: Sha256Digest,
}

impl NodeBenchmarkCandidateHandoffRequest {
    // Creates one exact private transaction from preparation-verified candidate inputs.
    pub fn new(
        transaction_id: OperationId,
        baseline: BenchmarkSubject,
        candidate: RuntimeCandidate,
        artifacts: RuntimeExactCandidateArtifacts,
        runtime_execution_sha256: Sha256Digest,
    ) -> Result<Self, NodeBenchmarkCandidateHandoffError> {
        if candidate.logical_model() != baseline.model()
            || candidate.runtime().execution_contract_digest() != &runtime_execution_sha256
        {
            return Err(NodeBenchmarkCandidateHandoffError::InvalidRequest);
        }
        Ok(Self {
            transaction_id,
            baseline,
            candidate,
            artifacts,
            runtime_execution_sha256,
        })
    }

    // Returns the deterministic verification transaction identity chosen before Node admission.
    pub const fn transaction_id(&self) -> &OperationId {
        &self.transaction_id
    }

    // Returns the exact resident baseline subject.
    pub const fn baseline(&self) -> &BenchmarkSubject {
        &self.baseline
    }

    // Returns the typed candidate reconstructed by the trusted preparation boundary.
    pub const fn candidate(&self) -> &RuntimeCandidate {
        &self.candidate
    }

    // Returns the retained preparation-verified artifact closure.
    pub const fn artifacts(&self) -> &RuntimeExactCandidateArtifacts {
        &self.artifacts
    }
}

// Stores one replay-safe Node-owned transaction without persisting trusted artifact paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkCandidateHandoffRecord {
    transaction_id: OperationId,
    request_sha256: Sha256Digest,
    baseline: BenchmarkSubject,
    baseline_record_sha256: Sha256Digest,
    baseline_initial_state: PlacementGroupState,
    candidate_installation_id: RuntimeInstallationId,
    candidate_group_id: PlacementGroupId,
    restoration_group_id: PlacementGroupId,
    runtime_execution_sha256: Sha256Digest,
    phase: NodeBenchmarkCandidateHandoffPhase,
}

impl NodeBenchmarkCandidateHandoffRecord {
    // Restores one persisted record while rechecking identities and legal phase state.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        transaction_id: OperationId,
        request_sha256: Sha256Digest,
        baseline: BenchmarkSubject,
        baseline_record_sha256: Sha256Digest,
        baseline_initial_state: PlacementGroupState,
        candidate_installation_id: RuntimeInstallationId,
        candidate_group_id: PlacementGroupId,
        restoration_group_id: PlacementGroupId,
        runtime_execution_sha256: Sha256Digest,
        phase: NodeBenchmarkCandidateHandoffPhase,
    ) -> Result<Self, NodeBenchmarkCandidateHandoffError> {
        if candidate_installation_id != deterministic_runtime_installation_id(&transaction_id)?
            || candidate_group_id != deterministic_placement_group_id("candidate", &transaction_id)?
            || restoration_group_id
                != deterministic_placement_group_id("baseline-restoration", &transaction_id)?
            || candidate_group_id == restoration_group_id
            || !matches!(
                baseline_initial_state,
                PlacementGroupState::Running | PlacementGroupState::Stopped
            )
        {
            return Err(NodeBenchmarkCandidateHandoffError::InvalidRequest);
        }
        Ok(Self {
            transaction_id,
            request_sha256,
            baseline,
            baseline_record_sha256,
            baseline_initial_state,
            candidate_installation_id,
            candidate_group_id,
            restoration_group_id,
            runtime_execution_sha256,
            phase,
        })
    }

    // Returns the transaction identity used by the paired verification journal.
    pub const fn transaction_id(&self) -> &OperationId {
        &self.transaction_id
    }

    // Returns the exact immutable replay fingerprint.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the baseline subject captured before resource release.
    pub const fn baseline(&self) -> &BenchmarkSubject {
        &self.baseline
    }

    // Returns the baseline placement aggregate identity captured before mutation.
    pub const fn baseline_record_sha256(&self) -> &Sha256Digest {
        &self.baseline_record_sha256
    }

    // Returns whether restoration must restart or retain stopped intent.
    pub const fn baseline_initial_state(&self) -> PlacementGroupState {
        self.baseline_initial_state
    }

    // Returns the deterministic candidate installation identity.
    pub const fn candidate_installation_id(&self) -> &RuntimeInstallationId {
        &self.candidate_installation_id
    }

    // Returns the private candidate placement-group identity never attached to ModelService.
    pub const fn candidate_group_id(&self) -> &PlacementGroupId {
        &self.candidate_group_id
    }

    // Returns the deterministic baseline-restoration group identity.
    pub const fn restoration_group_id(&self) -> &PlacementGroupId {
        &self.restoration_group_id
    }

    // Returns the candidate Runtime execution-contract identity used by the native run plan.
    pub const fn runtime_execution_sha256(&self) -> &Sha256Digest {
        &self.runtime_execution_sha256
    }

    // Returns the last durably completed lifecycle phase.
    pub const fn phase(&self) -> NodeBenchmarkCandidateHandoffPhase {
        self.phase
    }

    // Advances one durable phase without changing immutable transaction identity.
    fn advancing(mut self, phase: NodeBenchmarkCandidateHandoffPhase) -> Self {
        self.phase = phase;
        self
    }
}

// Returns one handoff record with its optimistic store revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeBenchmarkCandidateHandoff {
    record: NodeBenchmarkCandidateHandoffRecord,
    revision: u64,
}

impl VersionedNodeBenchmarkCandidateHandoff {
    // Creates one exact versioned record for persistence adapters and deterministic mocks.
    pub const fn new(record: NodeBenchmarkCandidateHandoffRecord, revision: u64) -> Self {
        Self { record, revision }
    }

    // Returns the complete durable transaction snapshot.
    pub const fn record(&self) -> &NodeBenchmarkCandidateHandoffRecord {
        &self.record
    }

    // Returns the optimistic revision required by the next phase commit.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines the narrow DatabaseManager-backed journal consumed by NodeManager.
pub trait NodeBenchmarkCandidateHandoffStore: Send + Sync {
    // Reads one transaction by its deterministic identity.
    fn read(
        &self,
        transaction_id: &OperationId,
    ) -> Result<Option<VersionedNodeBenchmarkCandidateHandoff>, NodeBenchmarkCandidateHandoffError>;

    // Creates one immutable transaction before any Runtime or Placement mutation.
    fn create(
        &self,
        record: NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError>;

    // Commits one exact next phase under optimistic concurrency.
    fn replace(
        &self,
        record: NodeBenchmarkCandidateHandoffRecord,
        expected_revision: u64,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError>;
}

// Adds the preparation-trusted acquisition entry point to Node's existing Runtime port.
pub trait NodeBenchmarkCandidateRuntimePort: NodeModelRuntimePort {
    // Installs one exact retained closure under its precommitted deterministic identity.
    fn install_exact_candidate(
        &self,
        node_id: NodeId,
        installation_id: RuntimeInstallationId,
        candidate: RuntimeCandidate,
        artifacts: RuntimeExactCandidateArtifacts,
        hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, NodeBenchmarkCandidateHandoffError>;

    // Resolves the acquired candidate's exact verified benchmark subject before placement starts.
    fn benchmark_subject(
        &self,
        core_installation_id: &li_core_interface::InstallationId,
        candidate_installation_id: &RuntimeInstallationId,
        candidate_group_id: &PlacementGroupId,
        expected_execution_sha256: &Sha256Digest,
    ) -> Result<BenchmarkSubject, NodeBenchmarkCandidateHandoffError>;
}

// Returns one private candidate endpoint and exact subject without publishing it to Gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkCandidateHandoffReceipt {
    transaction_id: OperationId,
    subject: BenchmarkSubject,
    endpoint: PlacementEndpoint,
}

impl NodeBenchmarkCandidateHandoffReceipt {
    // Returns the unchanged verification transaction identity.
    pub const fn transaction_id(&self) -> &OperationId {
        &self.transaction_id
    }

    // Returns the candidate-only benchmark execution subject.
    pub const fn subject(&self) -> &BenchmarkSubject {
        &self.subject
    }

    // Returns only the exact endpoint owned by the private candidate group.
    pub const fn endpoint(&self) -> &PlacementEndpoint {
        &self.endpoint
    }
}

// Names one stable fail-closed candidate handoff failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeBenchmarkCandidateHandoffError {
    InvalidRequest,
    Busy,
    NotFound,
    Conflict,
    RuntimeUnavailable,
    PlacementUnavailable,
    HardwareDrift,
    TopologyUnavailable,
    ActivationFailed,
    RestorationRequired,
    StoreUnavailable,
}

impl fmt::Display for NodeBenchmarkCandidateHandoffError {
    // Presents bounded lifecycle language without paths, provider details, or candidate bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRequest => "benchmark candidate handoff request is invalid",
            Self::Busy => "benchmark candidate handoff is busy",
            Self::NotFound => "benchmark candidate handoff was not found",
            Self::Conflict => "benchmark candidate handoff changed concurrently",
            Self::RuntimeUnavailable => "benchmark candidate runtime is unavailable",
            Self::PlacementUnavailable => "benchmark candidate placement is unavailable",
            Self::HardwareDrift => "benchmark candidate hardware identity changed",
            Self::TopologyUnavailable => "benchmark candidate topology is unavailable",
            Self::ActivationFailed => "benchmark candidate activation failed",
            Self::RestorationRequired => "benchmark baseline restoration is required",
            Self::StoreUnavailable => "benchmark candidate handoff storage is unavailable",
        };
        formatter.write_str(message)
    }
}

impl Error for NodeBenchmarkCandidateHandoffError {}

// Owns durable ordering across RuntimeManager, PlacementManager, and Node service attachment.
pub struct NodeBenchmarkCandidateHandoffCoordinator {
    store: Arc<dyn NodeBenchmarkCandidateHandoffStore>,
    runtime: Arc<dyn NodeBenchmarkCandidateRuntimePort>,
    placement: Arc<dyn NodeModelPlacementPort>,
    requests: Arc<dyn NodeModelPlacementRequestProvider>,
    hardware: Arc<dyn NodeModelHardwareProvider>,
    state: Arc<dyn NodeModelStatePort>,
    clock: Arc<dyn NodeModelClock>,
    mutation: Mutex<()>,
}

impl NodeBenchmarkCandidateHandoffCoordinator {
    // Creates one Node-owned lifecycle from explicit existing manager and persistence ports.
    pub const fn new(
        store: Arc<dyn NodeBenchmarkCandidateHandoffStore>,
        runtime: Arc<dyn NodeBenchmarkCandidateRuntimePort>,
        placement: Arc<dyn NodeModelPlacementPort>,
        requests: Arc<dyn NodeModelPlacementRequestProvider>,
        hardware: Arc<dyn NodeModelHardwareProvider>,
        state: Arc<dyn NodeModelStatePort>,
        clock: Arc<dyn NodeModelClock>,
    ) -> Self {
        Self {
            store,
            runtime,
            placement,
            requests,
            hardware,
            state,
            clock,
            mutation: Mutex::new(()),
        }
    }

    // Captures the resident baseline and acquires candidate bytes without releasing service resources.
    pub fn prepare(
        &self,
        request: NodeBenchmarkCandidateHandoffRequest,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError> {
        let _guard = self.mutation_guard()?;
        let request_sha256 = request_sha256(&request)?;
        let mut versioned = match self.store.read(request.transaction_id())? {
            Some(existing) => {
                if existing.record().request_sha256() != &request_sha256 {
                    return Err(NodeBenchmarkCandidateHandoffError::Conflict);
                }
                existing
            }
            None => {
                let baseline = self.baseline_record(request.baseline())?;
                self.require_baseline_service(request.baseline(), baseline.record())?;
                let record = prepare_record(&request, request_sha256, baseline.record())?;
                self.store.create(record)?
            }
        };
        if versioned.record().phase() == NodeBenchmarkCandidateHandoffPhase::Prepared {
            let baseline = self.baseline_record(versioned.record().baseline())?;
            require_baseline_unchanged(versioned.record(), baseline.record())?;
            let assignment = single_assignment(baseline.record())?;
            let hardware = self
                .hardware
                .observation(assignment.node_id())
                .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?;
            if hardware.observation_id() != assignment.hardware_observation_id()
                || hardware.boot_id() != assignment.hardware_boot_id()
            {
                return Err(NodeBenchmarkCandidateHandoffError::HardwareDrift);
            }
            let installed = self.runtime.install_exact_candidate(
                assignment.node_id().clone(),
                versioned.record().candidate_installation_id().clone(),
                request.candidate,
                request.artifacts,
                &hardware,
            )?;
            if installed.installation().state() != RuntimeInstallationState::Available
                || installed.installation().installation_id()
                    != versioned.record().candidate_installation_id()
                || installed.installation().node_id() != assignment.node_id()
            {
                return Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable);
            }
            versioned = self.advance(
                versioned,
                NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
            )?;
        }
        if versioned.record().phase() == NodeBenchmarkCandidateHandoffPhase::CandidateAcquired
            && versioned.record().baseline_initial_state() == PlacementGroupState::Stopped
        {
            let baseline = self.baseline_record(versioned.record().baseline())?;
            require_baseline_unchanged(versioned.record(), baseline.record())?;
            match baseline.record().group().state() {
                PlacementGroupState::Stopped => {
                    let running = self
                        .placement
                        .start(versioned.record().baseline().placement_group_id())
                        .map_err(|_| NodeBenchmarkCandidateHandoffError::ActivationFailed)?;
                    if running.record().group().state() != PlacementGroupState::Running {
                        return Err(NodeBenchmarkCandidateHandoffError::ActivationFailed);
                    }
                }
                PlacementGroupState::Running => {}
                _ => return Err(NodeBenchmarkCandidateHandoffError::RestorationRequired),
            }
            versioned = self.advance(
                versioned,
                NodeBenchmarkCandidateHandoffPhase::BaselineActivated,
            )?;
        }
        Ok(versioned)
    }

    // Releases the completed baseline arm and starts one private candidate group on exact resources.
    pub fn activate(
        &self,
        transaction_id: &OperationId,
    ) -> Result<NodeBenchmarkCandidateHandoffReceipt, NodeBenchmarkCandidateHandoffError> {
        let _guard = self.mutation_guard()?;
        match self.activate_inner(transaction_id) {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                let phase = self
                    .store
                    .read(transaction_id)?
                    .ok_or(NodeBenchmarkCandidateHandoffError::NotFound)?
                    .record()
                    .phase();
                if matches!(
                    phase,
                    NodeBenchmarkCandidateHandoffPhase::BaselineActivated
                        | NodeBenchmarkCandidateHandoffPhase::BaselineReleasing
                        | NodeBenchmarkCandidateHandoffPhase::BaselineReleased
                        | NodeBenchmarkCandidateHandoffPhase::CandidateStaged
                        | NodeBenchmarkCandidateHandoffPhase::Restoring
                ) {
                    self.restore_inner(transaction_id)
                        .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
                }
                Err(error)
            }
        }
    }

    // Restores the exact resident service intent and removes only handoff-owned candidate state.
    pub fn restore(
        &self,
        transaction_id: &OperationId,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError> {
        let _guard = self.mutation_guard()?;
        self.restore_inner(transaction_id)
    }

    // Returns one durable record without invoking any lifecycle provider.
    pub fn record(
        &self,
        transaction_id: &OperationId,
    ) -> Result<Option<VersionedNodeBenchmarkCandidateHandoff>, NodeBenchmarkCandidateHandoffError>
    {
        self.store.read(transaction_id)
    }

    // Returns the exact acquired candidate subject while the resident baseline remains authoritative.
    pub fn prepared_subject(
        &self,
        transaction_id: &OperationId,
    ) -> Result<BenchmarkSubject, NodeBenchmarkCandidateHandoffError> {
        let record = self
            .store
            .read(transaction_id)?
            .ok_or(NodeBenchmarkCandidateHandoffError::NotFound)?;
        if !matches!(
            record.record().phase(),
            NodeBenchmarkCandidateHandoffPhase::CandidateAcquired
                | NodeBenchmarkCandidateHandoffPhase::BaselineActivated
                | NodeBenchmarkCandidateHandoffPhase::BaselineReleasing
                | NodeBenchmarkCandidateHandoffPhase::BaselineReleased
                | NodeBenchmarkCandidateHandoffPhase::CandidateStaged
                | NodeBenchmarkCandidateHandoffPhase::CandidateRunning
                | NodeBenchmarkCandidateHandoffPhase::Restoring
                | NodeBenchmarkCandidateHandoffPhase::BaselineRestored
        ) {
            return Err(NodeBenchmarkCandidateHandoffError::Conflict);
        }
        self.candidate_subject(record.record())
    }

    // Performs the private candidate activation through restart-safe phase boundaries.
    fn activate_inner(
        &self,
        transaction_id: &OperationId,
    ) -> Result<NodeBenchmarkCandidateHandoffReceipt, NodeBenchmarkCandidateHandoffError> {
        let mut versioned = self
            .store
            .read(transaction_id)?
            .ok_or(NodeBenchmarkCandidateHandoffError::NotFound)?;
        if versioned.record().phase() == NodeBenchmarkCandidateHandoffPhase::CandidateRunning {
            return self.candidate_receipt(versioned.record());
        }
        let expected_phase = match versioned.record().baseline_initial_state() {
            PlacementGroupState::Running => NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
            PlacementGroupState::Stopped => NodeBenchmarkCandidateHandoffPhase::BaselineActivated,
            _ => return Err(NodeBenchmarkCandidateHandoffError::Conflict),
        };
        if versioned.record().phase() != expected_phase {
            return Err(NodeBenchmarkCandidateHandoffError::Conflict);
        }
        let baseline = self.baseline_record(versioned.record().baseline())?;
        require_baseline_unchanged(versioned.record(), baseline.record())?;
        let installation = self.candidate_installation(versioned.record())?;
        let request =
            self.candidate_request(versioned.record(), baseline.record(), &installation)?;
        versioned = self.advance(
            versioned,
            NodeBenchmarkCandidateHandoffPhase::BaselineReleasing,
        )?;
        if baseline.record().group().state() == PlacementGroupState::Running {
            self.placement
                .stop(baseline.record().group().placement_group_id())
                .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?;
        }
        self.placement
            .remove(baseline.record().group().placement_group_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?;
        versioned = self.advance(
            versioned,
            NodeBenchmarkCandidateHandoffPhase::BaselineReleased,
        )?;
        let staged = self
            .placement
            .stage(request)
            .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?;
        if staged.record().group().state() != PlacementGroupState::Staged {
            return Err(NodeBenchmarkCandidateHandoffError::ActivationFailed);
        }
        versioned = self.advance(
            versioned,
            NodeBenchmarkCandidateHandoffPhase::CandidateStaged,
        )?;
        let running = self
            .placement
            .start(versioned.record().candidate_group_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::ActivationFailed)?;
        if running.record().group().state() != PlacementGroupState::Running
            || running.record().group().endpoint().is_none()
        {
            return Err(NodeBenchmarkCandidateHandoffError::ActivationFailed);
        }
        versioned = self.advance(
            versioned,
            NodeBenchmarkCandidateHandoffPhase::CandidateRunning,
        )?;
        self.candidate_receipt(versioned.record())
    }

    // Replays candidate cleanup and baseline reconstruction from every durable boundary.
    fn restore_inner(
        &self,
        transaction_id: &OperationId,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError> {
        let mut versioned = self
            .store
            .read(transaction_id)?
            .ok_or(NodeBenchmarkCandidateHandoffError::NotFound)?;
        if versioned.record().phase().is_terminal() {
            return Ok(versioned);
        }
        if matches!(
            versioned.record().phase(),
            NodeBenchmarkCandidateHandoffPhase::Prepared
                | NodeBenchmarkCandidateHandoffPhase::CandidateAcquired
                | NodeBenchmarkCandidateHandoffPhase::BaselineActivated
        ) {
            self.restore_unreleased_baseline(versioned.record())?;
            self.remove_candidate_runtime(versioned.record())?;
            return self.advance(versioned, NodeBenchmarkCandidateHandoffPhase::Completed);
        }
        if versioned.record().phase() != NodeBenchmarkCandidateHandoffPhase::BaselineRestored {
            versioned = self.advance(versioned, NodeBenchmarkCandidateHandoffPhase::Restoring)?;
            self.remove_candidate_group(versioned.record())?;
            let baseline = self.baseline_record(versioned.record().baseline())?;
            match baseline.record().group().state() {
                PlacementGroupState::Running
                    if versioned.record().baseline_initial_state()
                        == PlacementGroupState::Running => {}
                PlacementGroupState::Stopped
                    if versioned.record().baseline_initial_state()
                        == PlacementGroupState::Stopped => {}
                PlacementGroupState::Stopped
                    if versioned.record().baseline_initial_state()
                        == PlacementGroupState::Running =>
                {
                    self.placement
                        .start(versioned.record().baseline().placement_group_id())
                        .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
                }
                PlacementGroupState::Removed => {
                    let installation =
                        self.baseline_installation(versioned.record(), baseline.record())?;
                    let request = self.restoration_request(
                        versioned.record(),
                        baseline.record(),
                        &installation,
                    )?;
                    let restored = match self
                        .placement
                        .record(versioned.record().restoration_group_id())
                        .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?
                    {
                        Some(existing) => existing,
                        None => self
                            .placement
                            .stage(request)
                            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?,
                    };
                    if versioned.record().baseline_initial_state() == PlacementGroupState::Running
                        && restored.record().group().state() != PlacementGroupState::Running
                    {
                        self.placement
                            .start(versioned.record().restoration_group_id())
                            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
                    } else if versioned.record().baseline_initial_state()
                        == PlacementGroupState::Stopped
                        && restored.record().group().state() != PlacementGroupState::Stopped
                    {
                        self.placement
                            .stop(versioned.record().restoration_group_id())
                            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
                    }
                    self.attach_restoration(versioned.record())?;
                }
                _ => return Err(NodeBenchmarkCandidateHandoffError::RestorationRequired),
            }
            versioned = self.advance(
                versioned,
                NodeBenchmarkCandidateHandoffPhase::BaselineRestored,
            )?;
        }
        self.remove_candidate_runtime(versioned.record())?;
        self.advance(versioned, NodeBenchmarkCandidateHandoffPhase::Completed)
    }

    // Reads and validates the exact baseline aggregate selected by the verification request.
    fn baseline_record(
        &self,
        baseline: &BenchmarkSubject,
    ) -> Result<VersionedPlacementRecord, NodeBenchmarkCandidateHandoffError> {
        let record = self
            .placement
            .record(baseline.placement_group_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?
            .ok_or(NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?;
        if record
            .record()
            .group()
            .runtime()
            .execution_contract_digest()
            != baseline.execution_sha256()
            || !record.record().placements().iter().any(|placement| {
                placement.assignment().runtime_installation_id()
                    == baseline.runtime_installation_id()
            })
        {
            return Err(NodeBenchmarkCandidateHandoffError::InvalidRequest);
        }
        Ok(record)
    }

    // Requires the baseline group to remain attached to its exact logical model service.
    fn require_baseline_service(
        &self,
        baseline: &BenchmarkSubject,
        record: &PlacementRecord,
    ) -> Result<(), NodeBenchmarkCandidateHandoffError> {
        let service = self
            .state
            .service(record.group().service_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::InvalidRequest)?;
        if service.service().logical_model() != baseline.model()
            || !service
                .service()
                .placement_group_ids()
                .contains(baseline.placement_group_id())
        {
            return Err(NodeBenchmarkCandidateHandoffError::InvalidRequest);
        }
        Ok(())
    }

    // Reads the deterministic candidate installation only after exact acquisition completed.
    fn candidate_installation(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<RuntimeInstallation, NodeBenchmarkCandidateHandoffError> {
        self.runtime
            .installation(record.candidate_installation_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?
            .filter(|versioned| {
                versioned.installation().state() == RuntimeInstallationState::Available
            })
            .map(|versioned| versioned.installation().clone())
            .ok_or(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)
    }

    // Reads the retained baseline installation and verifies it still matches the removed group.
    fn baseline_installation(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
        baseline: &PlacementRecord,
    ) -> Result<RuntimeInstallation, NodeBenchmarkCandidateHandoffError> {
        let installation_id = single_assignment(baseline)?.runtime_installation_id();
        if installation_id != record.baseline().runtime_installation_id() {
            return Err(NodeBenchmarkCandidateHandoffError::Conflict);
        }
        self.runtime
            .installation(installation_id)
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?
            .filter(|versioned| {
                versioned.installation().state() == RuntimeInstallationState::Available
            })
            .map(|versioned| versioned.installation().clone())
            .ok_or(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)
    }

    // Builds and checks the private candidate request before the baseline releases any resource.
    fn candidate_request(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
        baseline: &PlacementRecord,
        installation: &RuntimeInstallation,
    ) -> Result<PlacementRequest, NodeBenchmarkCandidateHandoffError> {
        let request = self
            .requests
            .request(
                baseline.group().service_id(),
                0,
                record.candidate_group_id(),
                std::slice::from_ref(installation),
            )
            .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?;
        require_exact_resource_request(&request, baseline, installation)?;
        Ok(request)
    }

    // Rebuilds the baseline under its deterministic restoration identity and exact retained runtime.
    fn restoration_request(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
        baseline: &PlacementRecord,
        installation: &RuntimeInstallation,
    ) -> Result<PlacementRequest, NodeBenchmarkCandidateHandoffError> {
        let request = self
            .requests
            .request(
                baseline.group().service_id(),
                0,
                record.restoration_group_id(),
                std::slice::from_ref(installation),
            )
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
        require_exact_resource_request(&request, baseline, installation)?;
        Ok(request)
    }

    // Removes only the private candidate group when it reached a materialized state.
    fn remove_candidate_group(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<(), NodeBenchmarkCandidateHandoffError> {
        let Some(group) = self
            .placement
            .record(record.candidate_group_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?
        else {
            return Ok(());
        };
        if group.record().group().state() == PlacementGroupState::Removed {
            return Ok(());
        }
        if group.record().group().state() == PlacementGroupState::Running {
            self.placement
                .stop(record.candidate_group_id())
                .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
        }
        self.placement
            .remove(record.candidate_group_id())
            .map(|_| ())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)
    }

    // Removes only the deterministic candidate installation after baseline authority returns.
    fn remove_candidate_runtime(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<(), NodeBenchmarkCandidateHandoffError> {
        let Some(installation) = self
            .runtime
            .installation(record.candidate_installation_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?
        else {
            return Ok(());
        };
        if installation.installation().state() == RuntimeInstallationState::Removed {
            return Ok(());
        }
        self.runtime
            .remove(record.candidate_installation_id())
            .map(|_| ())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)
    }

    // Restores a temporarily started baseline before the resource-release boundary.
    fn restore_unreleased_baseline(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<(), NodeBenchmarkCandidateHandoffError> {
        let baseline = self.baseline_record(record.baseline())?;
        require_baseline_unchanged(record, baseline.record())?;
        match (
            record.baseline_initial_state(),
            baseline.record().group().state(),
        ) {
            (PlacementGroupState::Running, PlacementGroupState::Running)
            | (PlacementGroupState::Stopped, PlacementGroupState::Stopped) => Ok(()),
            (PlacementGroupState::Stopped, PlacementGroupState::Running) => self
                .placement
                .stop(record.baseline().placement_group_id())
                .map(|_| ())
                .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired),
            _ => Err(NodeBenchmarkCandidateHandoffError::RestorationRequired),
        }
    }

    // Attaches only the restored baseline group and then retires the removed original reference.
    fn attach_restoration(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<(), NodeBenchmarkCandidateHandoffError> {
        let service_id = self
            .baseline_record(record.baseline())?
            .record()
            .group()
            .service_id()
            .clone();
        let now = self
            .clock
            .now()
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
        let current = self
            .state
            .service(&service_id)
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
        let attached = self
            .state
            .attach_group(
                &format!(
                    "benchmark-handoff:{}:attach",
                    record.transaction_id().as_str()
                ),
                &service_id,
                record.restoration_group_id().clone(),
                current.revision(),
                now,
            )
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)?;
        self.state
            .detach_group(
                &format!(
                    "benchmark-handoff:{}:detach",
                    record.transaction_id().as_str()
                ),
                &service_id,
                record.baseline().placement_group_id(),
                attached.revision(),
                now,
            )
            .map(|_| ())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RestorationRequired)
    }

    // Returns the exact private endpoint and candidate subject after complete startup.
    fn candidate_receipt(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<NodeBenchmarkCandidateHandoffReceipt, NodeBenchmarkCandidateHandoffError> {
        let group = self
            .placement
            .record(record.candidate_group_id())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?
            .ok_or(NodeBenchmarkCandidateHandoffError::PlacementUnavailable)?;
        let subject = self.candidate_subject(record)?;
        if group.record().group().state() != PlacementGroupState::Running
            || group.record().group().placement_group_id() != subject.placement_group_id()
            || group.record().group().runtime().execution_contract_digest()
                != subject.execution_sha256()
            || group.record().placements().iter().any(|placement| {
                placement.assignment().runtime_installation_id()
                    != subject.runtime_installation_id()
            })
        {
            return Err(NodeBenchmarkCandidateHandoffError::ActivationFailed);
        }
        let endpoint = group
            .record()
            .group()
            .endpoint()
            .cloned()
            .ok_or(NodeBenchmarkCandidateHandoffError::ActivationFailed)?;
        Ok(NodeBenchmarkCandidateHandoffReceipt {
            transaction_id: record.transaction_id().clone(),
            subject,
            endpoint,
        })
    }

    // Resolves the candidate subject only from acquired installation and verified execution bytes.
    fn candidate_subject(
        &self,
        record: &NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<BenchmarkSubject, NodeBenchmarkCandidateHandoffError> {
        let subject = self.runtime.benchmark_subject(
            record.baseline().installation_id(),
            record.candidate_installation_id(),
            record.candidate_group_id(),
            record.runtime_execution_sha256(),
        )?;
        if subject.runtime_installation_id() != record.candidate_installation_id()
            || subject.placement_group_id() != record.candidate_group_id()
            || subject.execution_sha256() != record.runtime_execution_sha256()
        {
            return Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable);
        }
        Ok(subject)
    }

    // Commits one exact phase transition under the current optimistic revision.
    fn advance(
        &self,
        current: VersionedNodeBenchmarkCandidateHandoff,
        phase: NodeBenchmarkCandidateHandoffPhase,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError> {
        self.store.replace(
            current.record().clone().advancing(phase),
            current.revision(),
        )
    }

    // Acquires exclusive in-process ownership without waiting behind another mutation.
    fn mutation_guard(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, ()>, NodeBenchmarkCandidateHandoffError> {
        match self.mutation.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(NodeBenchmarkCandidateHandoffError::Busy),
            Err(TryLockError::Poisoned(_)) => {
                Err(NodeBenchmarkCandidateHandoffError::StoreUnavailable)
            }
        }
    }
}

// Creates the immutable durable transaction before acquisition starts.
fn prepare_record(
    request: &NodeBenchmarkCandidateHandoffRequest,
    request_sha256: Sha256Digest,
    baseline: &PlacementRecord,
) -> Result<NodeBenchmarkCandidateHandoffRecord, NodeBenchmarkCandidateHandoffError> {
    if !matches!(
        baseline.group().state(),
        PlacementGroupState::Running | PlacementGroupState::Stopped
    ) {
        return Err(NodeBenchmarkCandidateHandoffError::InvalidRequest);
    }
    single_assignment(baseline)?;
    Ok(NodeBenchmarkCandidateHandoffRecord {
        transaction_id: request.transaction_id.clone(),
        request_sha256,
        baseline: request.baseline.clone(),
        baseline_record_sha256: placement_record_sha256(baseline)?,
        baseline_initial_state: baseline.group().state(),
        candidate_installation_id: deterministic_runtime_installation_id(request.transaction_id())?,
        candidate_group_id: deterministic_placement_group_id(
            "candidate",
            request.transaction_id(),
        )?,
        restoration_group_id: deterministic_placement_group_id(
            "baseline-restoration",
            request.transaction_id(),
        )?,
        runtime_execution_sha256: request.runtime_execution_sha256.clone(),
        phase: NodeBenchmarkCandidateHandoffPhase::Prepared,
    })
}

// Requires the baseline aggregate to retain exactly the boot-scoped assignment captured at prepare.
fn require_baseline_unchanged(
    record: &NodeBenchmarkCandidateHandoffRecord,
    baseline: &PlacementRecord,
) -> Result<(), NodeBenchmarkCandidateHandoffError> {
    if &placement_record_sha256(baseline)? != record.baseline_record_sha256() {
        return Err(NodeBenchmarkCandidateHandoffError::HardwareDrift);
    }
    Ok(())
}

// Requires the current production single-node boundary without inventing missing link proof.
fn single_assignment(
    record: &PlacementRecord,
) -> Result<&li_core_interface::PlacementAssignment, NodeBenchmarkCandidateHandoffError> {
    if record.placements().len() != 1 {
        return Err(NodeBenchmarkCandidateHandoffError::TopologyUnavailable);
    }
    Ok(record.placements()[0].assignment())
}

// Requires request planning to preserve node, boot, address, devices, ports, and task topology.
fn require_exact_resource_request(
    request: &PlacementRequest,
    baseline: &PlacementRecord,
    installation: &RuntimeInstallation,
) -> Result<(), NodeBenchmarkCandidateHandoffError> {
    let assignment = single_assignment(baseline)?;
    if request.nodes().len() != 1
        || request.tasks().len() != 1
        || request.links().len() != 0
        || request.runtime() != installation.runtime()
        || request.nodes()[0].node_id() != assignment.node_id()
        || request.nodes()[0].runtime_installation_id() != installation.installation_id()
        || request.nodes()[0].hardware_observation_id() != assignment.hardware_observation_id()
        || request.nodes()[0].boot_id() != assignment.hardware_boot_id()
        || request.nodes()[0].address() != assignment.address()
        || request.nodes()[0].device_ids() != assignment.resources().device_ids()
        || request.nodes()[0].ports().base() != assignment.resources().ports().base()
        || request.tasks()[0].task_id() != assignment.task_id()
        || request.tasks()[0].device_count() as usize != assignment.resources().device_ids().len()
        || request.tasks()[0].port_count() != assignment.resources().ports().count()
    {
        return Err(NodeBenchmarkCandidateHandoffError::HardwareDrift);
    }
    Ok(())
}

// Returns the stable replay fingerprint without persisting resident artifact paths.
fn request_sha256(
    request: &NodeBenchmarkCandidateHandoffRequest,
) -> Result<Sha256Digest, NodeBenchmarkCandidateHandoffError> {
    let mut digest = Sha256::new();
    framed(
        &mut digest,
        "li-node-benchmark-candidate-handoff-request-v1",
    );
    framed(&mut digest, request.transaction_id.as_str());
    framed(&mut digest, request.baseline.installation_id().as_str());
    framed(
        &mut digest,
        request.baseline.runtime_installation_id().as_str(),
    );
    framed(&mut digest, request.baseline.model().as_str());
    framed(&mut digest, request.baseline.placement_group_id().as_str());
    framed(&mut digest, request.baseline.execution_sha256().as_str());
    framed(
        &mut digest,
        request.baseline.benchmark_contract_sha256().as_str(),
    );
    framed(
        &mut digest,
        request.baseline.target_contract_sha256().as_str(),
    );
    framed(
        &mut digest,
        request.candidate.runtime().candidate_id().as_str(),
    );
    framed(&mut digest, request.candidate.runtime().version().as_str());
    framed(
        &mut digest,
        request.candidate.runtime().target_id().as_str(),
    );
    framed(&mut digest, request.candidate.runtime().source().as_str());
    framed(
        &mut digest,
        request.candidate.runtime().runtime_digest().as_str(),
    );
    framed(&mut digest, request.artifacts.closure_sha256().as_str());
    framed(&mut digest, request.runtime_execution_sha256.as_str());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeBenchmarkCandidateHandoffError::InvalidRequest)
}

// Returns a stable digest of the exact baseline assignment and immutable runtime identity.
fn placement_record_sha256(
    record: &PlacementRecord,
) -> Result<Sha256Digest, NodeBenchmarkCandidateHandoffError> {
    let mut digest = Sha256::new();
    framed(&mut digest, "li-node-benchmark-baseline-record-v1");
    framed(&mut digest, record.group().placement_group_id().as_str());
    framed(&mut digest, record.group().service_id().as_str());
    framed(
        &mut digest,
        record.group().runtime().candidate_id().as_str(),
    );
    framed(&mut digest, record.group().runtime().version().as_str());
    framed(&mut digest, record.group().runtime().target_id().as_str());
    framed(&mut digest, record.group().runtime().source().as_str());
    for placement in record.placements() {
        let assignment = placement.assignment();
        framed(&mut digest, placement.placement_id().as_str());
        framed(&mut digest, assignment.node_id().as_str());
        framed(&mut digest, assignment.runtime_installation_id().as_str());
        framed(&mut digest, assignment.hardware_observation_id().as_str());
        framed(&mut digest, assignment.hardware_boot_id().as_str());
        framed(
            &mut digest,
            &assignment.hardware_observed_at().value().to_string(),
        );
        framed(&mut digest, assignment.task_id().as_str());
        framed(&mut digest, assignment.address().as_str());
        framed(
            &mut digest,
            &assignment.resources().ports().base().to_string(),
        );
        framed(
            &mut digest,
            &assignment.resources().ports().count().to_string(),
        );
        for device_id in assignment.resources().device_ids() {
            framed(&mut digest, device_id.as_str());
        }
        framed(
            &mut digest,
            assignment
                .resources()
                .rdma_interface()
                .map_or("", |interface| interface.as_str()),
        );
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeBenchmarkCandidateHandoffError::InvalidRequest)
}

// Derives one deterministic runtime installation identity from the durable transaction.
fn deterministic_runtime_installation_id(
    transaction_id: &OperationId,
) -> Result<RuntimeInstallationId, NodeBenchmarkCandidateHandoffError> {
    RuntimeInstallationId::parse(&deterministic_identity(
        "runtime-installation",
        transaction_id,
    ))
    .map_err(|_| NodeBenchmarkCandidateHandoffError::InvalidRequest)
}

// Derives one deterministic private or restoration placement-group identity.
fn deterministic_placement_group_id(
    role: &str,
    transaction_id: &OperationId,
) -> Result<PlacementGroupId, NodeBenchmarkCandidateHandoffError> {
    PlacementGroupId::parse(&deterministic_identity(role, transaction_id))
        .map_err(|_| NodeBenchmarkCandidateHandoffError::InvalidRequest)
}

// Returns the first 128 bits of one domain-separated SHA-256 identity.
fn deterministic_identity(role: &str, transaction_id: &OperationId) -> String {
    let mut digest = Sha256::new();
    framed(
        &mut digest,
        "li-node-benchmark-candidate-handoff-identity-v1",
    );
    framed(&mut digest, role);
    framed(&mut digest, transaction_id.as_str());
    format!("{:x}", digest.finalize())[..32].to_string()
}

// Adds one unambiguous length-framed value to a canonical SHA-256 input.
fn framed(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}
