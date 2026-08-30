// SPDX-License-Identifier: AGPL-3.0-only

// This test-only fixture exposes independent seams used by different owning test crates.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_benchmark_manager::BenchmarkSubject;
use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorVendor, ArtifactName, ArtifactRevision, ArtifactUri,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, CredentialId, DeviceId, DisplayName,
    EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme, EngineDistribution,
    EntityTimestamps, EvidenceLabel, HardwareObservation, HardwareObservationId, InstallationId,
    InterconnectKind, InterconnectRequirement, LogicalModelName, MachineId, MemoryTopology,
    ModelArtifact, ModelArtifactFormat, ModelService, ModelServiceDesiredState, ModelServiceId,
    NetworkPort, Node, NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, OperatingSystem,
    OperationId, Placement, PlacementAssignment, PlacementEndpoint, PlacementGroup,
    PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources,
    PlacementState, PlatformIdentity, PortRange, ProcessorObservation, ResourceIdentity,
    ResourceLease, ResourceLeaseId, ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity,
    RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TaskId, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    DatabaseNodeBenchmarkCandidateHandoffStore, NodeBenchmarkCandidateHandoffCoordinator,
    NodeBenchmarkCandidateHandoffError, NodeBenchmarkCandidateHandoffPhase,
    NodeBenchmarkCandidateHandoffRecord, NodeBenchmarkCandidateHandoffRequest,
    NodeBenchmarkCandidateHandoffStore, NodeBenchmarkCandidateRuntimePort, NodeManager,
    NodeModelClock, NodeModelError, NodeModelHardwareProvider, NodeModelPlacementPort,
    NodeModelPlacementRequestProvider, NodeModelRuntimePort, VersionedNodeModelService,
};
use li_placement_manager::{
    PlacementError, PlacementNodeResources, PlacementRecord, PlacementRequest, PlacementTask,
    VersionedPlacementRecord,
};
use li_runtime_manager::{
    RuntimeAcceleratorVendor, RuntimeCandidate, RuntimeError, RuntimeExactCandidateArtifacts,
    RuntimeExactEngineArtifact, RuntimeTarget, VersionedRuntimeInstallation,
};
use tempfile::TempDir;

// Returns one repeated canonical identity.
pub fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns the one authenticated node used by the handoff fixtures.
pub fn node_id() -> NodeId {
    NodeId::parse(&identity('2')).expect("node")
}

// Returns the logical service identity retained across restoration.
pub fn service_id() -> ModelServiceId {
    ModelServiceId::parse(&identity('4')).expect("service")
}

// Returns the user-facing model selected by both benchmark arms.
pub fn model() -> LogicalModelName {
    LogicalModelName::parse("qwen3.8").expect("model")
}

// Returns one exact baseline runtime identity.
pub fn baseline_runtime() -> RuntimeIdentity {
    runtime_identity("1.0.0", 'a', 'e')
}

// Returns one exact candidate runtime identity with a distinct immutable execution.
pub fn candidate_runtime() -> RuntimeIdentity {
    runtime_identity("1.1.0", 'f', '8')
}

// Returns one fully closed runtime identity fixture.
pub fn runtime_identity(version: &str, digest: char, execution: char) -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse(version).expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!(
            "ghcr.io/runtime/qwen@sha256:{}",
            digest.to_string().repeat(64)
        ))
        .expect("source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                .expect("Engine source"),
            Sha256Digest::parse(&"c".repeat(64)).expect("Engine identity"),
            None,
            None,
        ),
        Sha256Digest::parse(&digest.to_string().repeat(64)).expect("runtime"),
        Sha256Digest::parse(&"d".repeat(64)).expect("manifest"),
        Sha256Digest::parse(&execution.to_string().repeat(64)).expect("execution"),
    )
    .expect("runtime")
}

// Returns one model artifact shared by both immutable runtime arms.
pub fn artifacts() -> Vec<ModelArtifact> {
    vec![ModelArtifact::new(
        ArtifactName::parse("model").expect("artifact"),
        ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("URI"),
        ArtifactRevision::parse(&"c".repeat(40)).expect("revision"),
        ModelArtifactFormat::HuggingFaceSnapshot,
    )]
}

// Returns one compatible preparation-trusted candidate.
pub fn candidate() -> RuntimeCandidate {
    RuntimeCandidate::new(
        model(),
        candidate_runtime(),
        artifacts(),
        RuntimeTarget::new(
            OperatingSystem::Linux,
            CpuArchitecture::Arm64,
            RuntimeAcceleratorVendor::Nvidia,
            TechnicalName::parse("sm_121").expect("architecture"),
            1,
            MemoryTopology::Unified,
            None,
            ByteCount::new(64 * 1024 * 1024 * 1024).expect("memory"),
        )
        .expect("target"),
        EvidenceLabel::Unqualified,
        2,
        false,
        false,
    )
    .expect("candidate")
}

// Returns one current boot-scoped hardware observation.
pub fn hardware(observation_character: char) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&identity(observation_character)).expect("observation"),
        node_id(),
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Grace CPU").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        vec![Accelerator::new(
            DeviceId::parse("GPU-fixture").expect("device"),
            AcceleratorVendor::Nvidia,
            DisplayName::parse("NVIDIA GB10").expect("GPU"),
            AcceleratorMemory::new(MemoryTopology::Unified, None, None).expect("memory"),
            ComputeCapability::Cuda {
                architecture: TechnicalName::parse("sm_121").expect("architecture"),
                maximum_version: Some(TechnicalName::parse("cuda_13.0").expect("CUDA")),
            },
        )],
        Vec::new(),
        UnixMilliseconds::new(1_000),
    )
    .expect("hardware")
}

// Returns one available baseline or candidate runtime installation.
pub fn installation(
    installation_id: RuntimeInstallationId,
    runtime: RuntimeIdentity,
    state: RuntimeInstallationState,
) -> RuntimeInstallation {
    RuntimeInstallation::new(
        installation_id,
        node_id(),
        model(),
        runtime,
        artifacts(),
        EvidenceLabel::Unqualified,
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("installation")
}

// Supplies deterministic increasing database commit timestamps.
struct TestDatabaseClock(AtomicI64);

impl DatabaseClock for TestDatabaseClock {
    // Returns one unique deterministic commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic increasing Node lifecycle timestamps.
struct TestNodeClock(AtomicU64);

impl NodeModelClock for TestNodeClock {
    // Returns one unique deterministic lifecycle timestamp.
    fn now(&self) -> Result<UnixMilliseconds, NodeModelError> {
        Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Supplies either the exact captured observation or deliberate drift.
pub struct TestHardware {
    pub drift: AtomicBool,
}

impl NodeModelHardwareProvider for TestHardware {
    // Returns one injected current hardware observation for the exact node.
    fn observation(&self, requested: &NodeId) -> Result<HardwareObservation, NodeModelError> {
        if requested != &node_id() {
            return Err(NodeModelError::ProviderUnavailable);
        }
        Ok(hardware(if self.drift.load(Ordering::SeqCst) {
            '7'
        } else {
            '1'
        }))
    }
}

// Stores runtime projections and deterministic exact-acquisition failures.
pub struct TestRuntime {
    installations: Mutex<BTreeMap<String, VersionedRuntimeInstallation>>,
    benchmark_contract_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
    pub fail_acquisition: AtomicBool,
    pub ambiguous_success: AtomicBool,
    pub fail_remove: AtomicBool,
}

impl TestRuntime {
    // Creates one runtime port containing the resident baseline installation.
    fn new(
        baseline: RuntimeInstallation,
        benchmark_contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
    ) -> Self {
        let mut installations = BTreeMap::new();
        installations.insert(
            baseline.installation_id().as_str().to_string(),
            VersionedRuntimeInstallation::new(baseline, 1),
        );
        Self {
            installations: Mutex::new(installations),
            benchmark_contract_sha256,
            target_contract_sha256,
            fail_acquisition: AtomicBool::new(false),
            ambiguous_success: AtomicBool::new(false),
            fail_remove: AtomicBool::new(false),
        }
    }
}

impl NodeModelRuntimePort for TestRuntime {
    // Rejects catalog selection because this fixture accepts only trusted exact candidates.
    fn select(
        &self,
        _model: &LogicalModelName,
        _explicit_candidate_id: Option<&RuntimeCandidateId>,
        _hardware: &HardwareObservation,
    ) -> Result<RuntimeCandidate, RuntimeError> {
        Err(RuntimeError::CatalogUnavailable)
    }

    // Rejects ordinary installation because candidate acquisition must use the exact entry point.
    fn install(
        &self,
        _node_id: NodeId,
        _model: &LogicalModelName,
        _candidate_id: &RuntimeCandidateId,
        _hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::CatalogUnavailable)
    }

    // Marks only one exact installation removed.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        if self.fail_remove.swap(false, Ordering::SeqCst) {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        let mut installations = self.installations.lock().expect("installations");
        let current = installations
            .get(installation_id.as_str())
            .cloned()
            .ok_or(RuntimeError::InstallationNotFound)?;
        let removed = installation(
            current.installation().installation_id().clone(),
            current.installation().runtime().clone(),
            RuntimeInstallationState::Removed,
        );
        let removed = VersionedRuntimeInstallation::new(removed, current.revision() + 1);
        installations.insert(installation_id.as_str().to_string(), removed.clone());
        Ok(removed)
    }

    // Returns one exact authoritative installation.
    fn installation(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .installations
            .lock()
            .expect("installations")
            .get(installation_id.as_str())
            .cloned())
    }

    // Returns every installation in stable identity order.
    fn installations(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .installations
            .lock()
            .expect("installations")
            .values()
            .cloned()
            .collect())
    }
}

impl NodeBenchmarkCandidateRuntimePort for TestRuntime {
    // Installs the exact supplied candidate or returns one deliberate provider fault.
    fn install_exact_candidate(
        &self,
        node_id: NodeId,
        installation_id: RuntimeInstallationId,
        candidate: RuntimeCandidate,
        _artifacts: RuntimeExactCandidateArtifacts,
        _hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, NodeBenchmarkCandidateHandoffError> {
        if self.fail_acquisition.load(Ordering::SeqCst) {
            return Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable);
        }
        let installation_id = if self.ambiguous_success.load(Ordering::SeqCst) {
            RuntimeInstallationId::parse(&identity('7')).expect("ambiguous installation")
        } else {
            installation_id
        };
        let installation = RuntimeInstallation::new(
            installation_id.clone(),
            node_id,
            candidate.logical_model().clone(),
            candidate.runtime().clone(),
            candidate.artifacts().to_vec(),
            candidate.evidence_label(),
            RuntimeInstallationState::Available,
            None,
            EntityTimestamps::new(UnixMilliseconds::new(2_000), UnixMilliseconds::new(2_001))
                .expect("timestamps"),
        )
        .expect("candidate installation");
        let versioned = VersionedRuntimeInstallation::new(installation, 1);
        self.installations
            .lock()
            .expect("installations")
            .insert(installation_id.as_str().to_string(), versioned.clone());
        Ok(versioned)
    }

    // Returns contract identities owned by the acquired candidate execution fixture.
    fn benchmark_subject(
        &self,
        core_installation_id: &InstallationId,
        candidate_installation_id: &RuntimeInstallationId,
        candidate_group_id: &PlacementGroupId,
        expected_execution_sha256: &Sha256Digest,
    ) -> Result<BenchmarkSubject, NodeBenchmarkCandidateHandoffError> {
        let installation = self
            .installation(candidate_installation_id)
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?
            .ok_or(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?;
        if installation
            .installation()
            .runtime()
            .execution_contract_digest()
            != expected_execution_sha256
        {
            return Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable);
        }
        Ok(BenchmarkSubject::new(
            core_installation_id.clone(),
            candidate_installation_id.clone(),
            installation.installation().logical_model().clone(),
            candidate_group_id.clone(),
            expected_execution_sha256.clone(),
            self.benchmark_contract_sha256.clone(),
            self.target_contract_sha256.clone(),
        ))
    }
}

// Stores placement aggregates and exposes one deterministic activation failure seam.
pub struct TestPlacement {
    records: Mutex<BTreeMap<String, (PlacementRequest, VersionedPlacementRecord)>>,
    pub fail_next_start: AtomicBool,
}

impl TestPlacement {
    // Creates one placement port containing the resident baseline group.
    fn new(request: PlacementRequest, state: PlacementGroupState) -> Self {
        let id = request.placement_group_id().clone();
        let record = VersionedPlacementRecord::new(placement_record(&request, state), 1);
        Self {
            records: Mutex::new(BTreeMap::from([(
                id.as_str().to_string(),
                (request, record),
            )])),
            fail_next_start: AtomicBool::new(false),
        }
    }

    // Replaces one exact aggregate state while retaining the immutable request.
    fn transition(
        &self,
        placement_group_id: &PlacementGroupId,
        state: PlacementGroupState,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        let mut records = self.records.lock().expect("records");
        let (request, current) = records
            .get(placement_group_id.as_str())
            .cloned()
            .ok_or(PlacementError::GroupNotFound)?;
        let next = VersionedPlacementRecord::new(
            placement_record(&request, state),
            current.revision() + 1,
        );
        records.insert(
            placement_group_id.as_str().to_string(),
            (request, next.clone()),
        );
        Ok(next)
    }
}

impl NodeModelPlacementPort for TestPlacement {
    // Creates or exactly replays one staged private or restoration group.
    fn stage(&self, request: PlacementRequest) -> Result<VersionedPlacementRecord, PlacementError> {
        let id = request.placement_group_id().clone();
        if let Some((stored_request, stored)) = self
            .records
            .lock()
            .expect("records")
            .get(id.as_str())
            .cloned()
        {
            return if stored_request == request {
                Ok(stored)
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        let staged = VersionedPlacementRecord::new(
            placement_record(&request, PlacementGroupState::Staged),
            1,
        );
        self.records
            .lock()
            .expect("records")
            .insert(id.as_str().to_string(), (request, staged.clone()));
        Ok(staged)
    }

    // Starts one complete group or returns one injected failure.
    fn start(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        if self.fail_next_start.swap(false, Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.transition(placement_group_id, PlacementGroupState::Running)
    }

    // Stops one complete group while retaining its assignment.
    fn stop(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.transition(placement_group_id, PlacementGroupState::Stopped)
    }

    // Recovers one complete group for the deterministic test boundary.
    fn recover(
        &self,
        placement_group_id: &PlacementGroupId,
        _acknowledge_protection_trips: bool,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.transition(placement_group_id, PlacementGroupState::Running)
    }

    // Removes one group while preserving its immutable audit aggregate.
    fn remove(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.transition(placement_group_id, PlacementGroupState::Removed)
    }

    // Returns one exact aggregate without mutation.
    fn record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError> {
        Ok(self
            .records
            .lock()
            .expect("records")
            .get(placement_group_id.as_str())
            .map(|(_, record)| record.clone()))
    }

    // Returns every authoritative aggregate in stable identity order.
    fn records(&self) -> Result<Vec<PlacementRecord>, PlacementError> {
        Ok(self
            .records
            .lock()
            .expect("records")
            .values()
            .map(|(_, record)| record.record().clone())
            .collect())
    }
}

// Reconstructs one exact single-node request and can deliberately drift its device identity.
pub struct TestPlacementRequests {
    pub drift: AtomicBool,
}

impl NodeModelPlacementRequestProvider for TestPlacementRequests {
    // Builds one model-neutral request from the exact installation receipt.
    fn request(
        &self,
        service_id: &ModelServiceId,
        _group_index: usize,
        placement_group_id: &PlacementGroupId,
        installations: &[RuntimeInstallation],
    ) -> Result<PlacementRequest, NodeModelError> {
        if installations.len() != 1 {
            return Err(NodeModelError::ProviderUnavailable);
        }
        placement_request(
            placement_group_id.clone(),
            service_id.clone(),
            &installations[0],
            if self.drift.load(Ordering::SeqCst) {
                "GPU-drift"
            } else {
                "GPU-fixture"
            },
        )
        .map_err(NodeModelError::from)
    }
}

// Returns one exact placement request for the resident or handoff-owned group.
pub fn placement_request(
    placement_group_id: PlacementGroupId,
    service_id: ModelServiceId,
    installation: &RuntimeInstallation,
    device_id: &str,
) -> Result<PlacementRequest, PlacementError> {
    let task = TaskId::parse("task-0").expect("task");
    PlacementRequest::new(
        placement_group_id,
        service_id,
        installation.runtime().clone(),
        PlacementGroupCapacity::new(
            8,
            4,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("capacity"),
        vec![PlacementTask::new(task.clone(), 1, 2)?],
        vec![PlacementNodeResources::new(
            installation.node_id().clone(),
            installation.installation_id().clone(),
            HardwareObservationId::parse(&identity('1')).expect("observation"),
            BootId::parse("boot-fixture").expect("boot"),
            UnixMilliseconds::new(1_000),
            NodeAddress::parse("spark.local").expect("address"),
            vec![DeviceId::parse(device_id).expect("device")],
            PortRange::new(18_000, 2).expect("ports"),
            None,
        )?],
        task.clone(),
        installation.node_id().clone(),
        vec![vec![task]],
        Vec::new(),
    )
}

// Builds one complete placement aggregate for an exact lifecycle state.
pub fn placement_record(request: &PlacementRequest, state: PlacementGroupState) -> PlacementRecord {
    let placement_id = PlacementId::parse(&identity('9')).expect("placement");
    let node = &request.nodes()[0];
    let resources = PlacementResources::new(
        PortRange::new(node.ports().base(), request.tasks()[0].port_count()).expect("ports"),
        node.device_ids().to_vec(),
        node.rdma_interface().cloned(),
    )
    .expect("resources");
    let placement_state = match state {
        PlacementGroupState::Staged => PlacementState::Staged,
        PlacementGroupState::Running => PlacementState::Running,
        PlacementGroupState::Stopped => PlacementState::Stopped,
        PlacementGroupState::Removed => PlacementState::Removed,
        _ => panic!("unsupported fixture state"),
    };
    let placement = Placement::new(
        placement_id.clone(),
        request.placement_group_id().clone(),
        PlacementAssignment::new(
            node.node_id().clone(),
            node.runtime_installation_id().clone(),
            node.hardware_observation_id().clone(),
            node.boot_id().clone(),
            node.observed_at(),
            request.tasks()[0].task_id().clone(),
            node.address().clone(),
            resources,
            EndpointOwnership::Owner,
        ),
        placement_state,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("placement");
    let endpoint = (state == PlacementGroupState::Running).then(|| {
        PlacementEndpoint::new(
            placement_id.clone(),
            node.node_id().clone(),
            EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("spark.local").expect("address"),
                18_000,
            )
            .expect("endpoint"),
            CredentialId::parse(&identity('a')).expect("credential"),
            None,
            None,
            4,
            262_144,
            EndpointHealth::new(true, false, Some(52_000), Vec::new()).expect("health"),
        )
        .expect("endpoint")
    });
    let desired_state = match state {
        PlacementGroupState::Stopped => ModelServiceDesiredState::Stopped,
        PlacementGroupState::Removed => ModelServiceDesiredState::Removed,
        PlacementGroupState::Staged | PlacementGroupState::Running => {
            ModelServiceDesiredState::Running
        }
        _ => unreachable!(),
    };
    let group = PlacementGroup::new(
        request.placement_group_id().clone(),
        request.service_id().clone(),
        request.runtime().clone(),
        vec![placement_id.clone()],
        placement_id.clone(),
        endpoint,
        request.capacity(),
        desired_state,
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("group");
    let lease_state = match state {
        PlacementGroupState::Running => ResourceLeaseState::Active,
        PlacementGroupState::Removed => ResourceLeaseState::Released,
        PlacementGroupState::Staged | PlacementGroupState::Stopped => ResourceLeaseState::Reserved,
        _ => unreachable!(),
    };
    let resources = [
        ResourceIdentity::Accelerator(DeviceId::parse("GPU-fixture").expect("device")),
        ResourceIdentity::Port(NetworkPort::new(18_000).expect("port")),
        ResourceIdentity::Port(NetworkPort::new(18_001).expect("port")),
    ];
    let leases = resources
        .into_iter()
        .enumerate()
        .map(|(index, resource)| {
            ResourceLease::new(
                ResourceLeaseId::parse(&format!("{:032x}", index + 10)).expect("lease"),
                placement_id.clone(),
                node.node_id().clone(),
                resource,
                lease_state,
                EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
                    .expect("timestamps"),
            )
        })
        .collect();
    PlacementRecord::new(
        group,
        vec![placement],
        leases,
        vec![vec![placement_id.clone()]],
        vec![(
            placement_id,
            Sha256Digest::parse(&"f".repeat(64)).expect("launch plan"),
        )],
    )
    .expect("record")
}

// Owns one complete handoff fixture and all restart-persistent providers.
pub struct BenchmarkCandidateHandoffFixture {
    _directory: TempDir,
    pub database: Arc<DatabaseManager>,
    pub node: Arc<NodeManager>,
    pub runtime: Arc<TestRuntime>,
    pub placement: Arc<TestPlacement>,
    pub requests: Arc<TestPlacementRequests>,
    pub hardware: Arc<TestHardware>,
    pub baseline_subject: BenchmarkSubject,
    pub baseline_group_id: PlacementGroupId,
}

impl BenchmarkCandidateHandoffFixture {
    // Creates one running or stopped resident service with exact persisted Node state.
    pub fn new(initial_state: PlacementGroupState) -> Self {
        Self::new_with_distinct_contracts(
            initial_state,
            Sha256Digest::parse(&"a".repeat(64)).expect("candidate benchmark contract"),
            Sha256Digest::parse(&"b".repeat(64)).expect("candidate target contract"),
            Sha256Digest::parse(&"7".repeat(64)).expect("baseline benchmark contract"),
            Sha256Digest::parse(&"8".repeat(64)).expect("baseline target contract"),
        )
    }

    // Creates one resident service whose candidate subject matches caller-owned contracts.
    pub fn new_with_contracts(
        initial_state: PlacementGroupState,
        benchmark_contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
    ) -> Self {
        Self::new_with_distinct_contracts(
            initial_state,
            benchmark_contract_sha256.clone(),
            target_contract_sha256.clone(),
            benchmark_contract_sha256,
            target_contract_sha256,
        )
    }

    // Creates one fixture with independently explicit candidate and baseline contracts.
    fn new_with_distinct_contracts(
        initial_state: PlacementGroupState,
        candidate_benchmark_contract_sha256: Sha256Digest,
        candidate_target_contract_sha256: Sha256Digest,
        baseline_benchmark_contract_sha256: Sha256Digest,
        baseline_target_contract_sha256: Sha256Digest,
    ) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = Arc::new(
            DatabaseManager::open(
                DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                    .with_busy_timeout(Duration::from_secs(1))
                    .with_clock(Arc::new(TestDatabaseClock(AtomicI64::new(10_000)))),
            )
            .expect("database"),
        );
        let initial_node = Node::new(
            NodeIdentity::new(
                node_id(),
                MachineId::parse(&identity('3')).expect("machine"),
                InstallationId::parse(&"6".repeat(64)).expect("Core installation"),
            ),
            DisplayName::parse("Home AI").expect("display name"),
            NodeRole::Main,
            NodeState::Active,
            NodeAddress::parse("spark.local").expect("address"),
            None,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
                .expect("timestamps"),
        );
        let (node, _) = NodeManager::open(database.clone(), initial_node, "initialize-node")
            .expect("node manager");
        let node = Arc::new(node);
        let baseline_installation_id =
            RuntimeInstallationId::parse(&identity('5')).expect("baseline installation");
        let baseline_installation = installation(
            baseline_installation_id.clone(),
            baseline_runtime(),
            RuntimeInstallationState::Available,
        );
        let baseline_group_id = PlacementGroupId::parse(&identity('6')).expect("baseline group");
        let request = placement_request(
            baseline_group_id.clone(),
            service_id(),
            &baseline_installation,
            "GPU-fixture",
        )
        .expect("baseline request");
        let placement = Arc::new(TestPlacement::new(request, initial_state));
        let runtime = Arc::new(TestRuntime::new(
            baseline_installation,
            candidate_benchmark_contract_sha256,
            candidate_target_contract_sha256,
        ));
        let service = ModelService::new(
            service_id(),
            model(),
            ModelServiceDesiredState::Stopped,
            Vec::new(),
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
                .expect("timestamps"),
        )
        .expect("service");
        let created = node
            .create_model_service("create-service", service)
            .expect("create service");
        let attached = node
            .attach_placement_group(
                "attach-baseline",
                &service_id(),
                baseline_group_id.clone(),
                created.revision(),
                UnixMilliseconds::new(1_001),
            )
            .expect("attach baseline");
        if initial_state == PlacementGroupState::Running {
            node.transition_model_service(
                "start-service",
                &service_id(),
                ModelServiceDesiredState::Running,
                attached.revision(),
                UnixMilliseconds::new(1_002),
            )
            .expect("start service");
        }
        let baseline_subject = BenchmarkSubject::new(
            InstallationId::parse(&"6".repeat(64)).expect("Core installation"),
            baseline_installation_id,
            model(),
            baseline_group_id.clone(),
            baseline_runtime().execution_contract_digest().clone(),
            baseline_benchmark_contract_sha256,
            baseline_target_contract_sha256,
        );
        Self {
            _directory: directory,
            database,
            node,
            runtime,
            placement,
            requests: Arc::new(TestPlacementRequests {
                drift: AtomicBool::new(false),
            }),
            hardware: Arc::new(TestHardware {
                drift: AtomicBool::new(false),
            }),
            baseline_subject,
            baseline_group_id,
        }
    }

    // Creates a fresh coordinator over the same durable and manager-owned providers.
    pub fn coordinator(&self) -> NodeBenchmarkCandidateHandoffCoordinator {
        NodeBenchmarkCandidateHandoffCoordinator::new(
            Arc::new(DatabaseNodeBenchmarkCandidateHandoffStore::new(
                self.database.clone(),
            )),
            self.runtime.clone(),
            self.placement.clone(),
            self.requests.clone(),
            self.hardware.clone(),
            self.node.clone(),
            Arc::new(TestNodeClock(AtomicU64::new(20_000))),
        )
    }

    // Returns one exact trusted private candidate handoff request.
    pub fn request(&self, transaction_character: char) -> NodeBenchmarkCandidateHandoffRequest {
        NodeBenchmarkCandidateHandoffRequest::new(
            OperationId::parse(&identity(transaction_character)).expect("transaction"),
            self.baseline_subject.clone(),
            candidate(),
            RuntimeExactCandidateArtifacts::new(
                "/private/tmp/runtime.letsinfer".into(),
                RuntimeExactEngineArtifact::Reuse,
                Sha256Digest::parse(&"9".repeat(64)).expect("closure"),
            )
            .expect("artifacts"),
            candidate_runtime().execution_contract_digest().clone(),
        )
        .expect("request")
    }

    // Returns the current persisted model service.
    pub fn service(&self) -> VersionedNodeModelService {
        li_node_manager::NodeModelStatePort::service(self.node.as_ref(), &service_id())
            .expect("service")
    }

    // Rewrites only the durable phase to model a crash after provider work but before phase commit.
    pub fn force_phase(
        &self,
        transaction_id: &OperationId,
        phase: NodeBenchmarkCandidateHandoffPhase,
    ) {
        let store = DatabaseNodeBenchmarkCandidateHandoffStore::new(self.database.clone());
        let current = store
            .read(transaction_id)
            .expect("read handoff")
            .expect("handoff");
        let record = current.record();
        let replacement = NodeBenchmarkCandidateHandoffRecord::restore(
            record.transaction_id().clone(),
            record.request_sha256().clone(),
            record.baseline().clone(),
            record.baseline_record_sha256().clone(),
            record.baseline_initial_state(),
            record.candidate_installation_id().clone(),
            record.candidate_group_id().clone(),
            record.restoration_group_id().clone(),
            record.runtime_execution_sha256().clone(),
            phase,
        )
        .expect("phase record");
        store
            .replace(replacement, current.revision())
            .expect("replace phase");
    }
}
