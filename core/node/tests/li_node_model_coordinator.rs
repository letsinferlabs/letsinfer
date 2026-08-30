// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::{panic, thread};

use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorVendor, ArtifactName, ArtifactRevision, ArtifactUri,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, CredentialId, DeviceId, DisplayName,
    EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme, EngineDistribution,
    EntityTimestamps, EvidenceLabel, FailureDescription, HardwareObservation,
    HardwareObservationId, InterconnectKind, InterconnectRequirement, LogicalModelName,
    MemoryTopology, ModelArtifact, ModelArtifactFormat, ModelService, ModelServiceDesiredState,
    ModelServiceId, NetworkPort, NodeAddress, NodeId, OperatingSystem, Operation, OperationId,
    OperationKind, OperationState, OperationTarget, Placement, PlacementAssignment,
    PlacementEndpoint, PlacementGroup, PlacementGroupCapacity, PlacementGroupId,
    PlacementGroupState, PlacementId, PlacementResources, PlacementState, PlatformIdentity,
    PortRange, ProcessorObservation, ResourceIdentity, ResourceLease, ResourceLeaseId,
    ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId, TaskId, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseCollection, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    DatabaseNodeModelJournalStore, NodeManagerError, NodeModelAction, NodeModelClock,
    NodeModelCommandIdentity, NodeModelCoordinator, NodeModelError, NodeModelHardwareProvider,
    NodeModelInstallGroup, NodeModelInstallRequest, NodeModelJournalState, NodeModelJournalStore,
    NodeModelPlacementPort, NodeModelPlacementRequestProvider, NodeModelRemovalRetention,
    NodeModelRemovalSelection, NodeModelRemoveRequest, NodeModelRuntimeLogRequest,
    NodeModelRuntimePort, NodeModelStatePort, NodeModelUpdateDisposition, NodeModelUpdateRequest,
    OperationCompletion, VersionedNodeModelOperation, VersionedNodeModelService,
};
use li_placement_manager::{
    PlacementError, PlacementLogBatch, PlacementLogCursor, PlacementLogReadRequest,
    PlacementNodeResources, PlacementRecord, PlacementRequest, PlacementTask,
    VersionedPlacementRecord,
};
use li_runtime_manager::{
    RuntimeAcceleratorVendor, RuntimeCandidate, RuntimeError, RuntimeTarget,
    VersionedRuntimeInstallation,
};
use rusqlite::{params, Connection};

// Returns one repeated canonical identity.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns the exact service identity used by coordinator fixtures.
fn service_id() -> ModelServiceId {
    ModelServiceId::parse(&identity('4')).expect("service")
}

// Returns the exact node identity used by coordinator fixtures.
fn node_id() -> NodeId {
    NodeId::parse(&identity('2')).expect("node")
}

// Returns one second authenticated node for partial placement-group tests.
fn other_node_id() -> NodeId {
    NodeId::parse(&identity('3')).expect("other node")
}

// Returns the user-facing logical model used by coordinator fixtures.
fn logical_model() -> LogicalModelName {
    LogicalModelName::parse("qwen3.8").expect("model")
}

// Returns one current fixture observation bound to an exact authenticated node.
fn hardware_for(node_id: NodeId) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&identity('1')).expect("observation"),
        node_id,
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

// Returns one exact unqualified candidate to prove evidence remains descriptive.
fn candidate() -> RuntimeCandidate {
    RuntimeCandidate::new(
        logical_model(),
        runtime_identity(),
        vec![ModelArtifact::new(
            ArtifactName::parse("model").expect("artifact"),
            ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("URI"),
            ArtifactRevision::parse(&"c".repeat(40)).expect("revision"),
            ModelArtifactFormat::HuggingFaceSnapshot,
        )],
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
        true,
        false,
    )
    .expect("candidate")
}

// Returns one exact sealed runtime identity.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "a".repeat(64)))
            .expect("source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                .expect("Engine source"),
            Sha256Digest::parse(&"c".repeat(64)).expect("Engine identity"),
            None,
            None,
        ),
        Sha256Digest::parse(&"a".repeat(64)).expect("runtime"),
        Sha256Digest::parse(&"d".repeat(64)).expect("manifest"),
        Sha256Digest::parse(&"e".repeat(64)).expect("execution"),
    )
    .expect("runtime")
}

// Returns a distinct signed runtime identity used only for update tests.
fn updated_runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.1.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "f".repeat(64)))
            .expect("source"),
        runtime_identity().engine_distribution().clone(),
        Sha256Digest::parse(&"f".repeat(64)).expect("runtime"),
        Sha256Digest::parse(&"9".repeat(64)).expect("manifest"),
        Sha256Digest::parse(&"8".repeat(64)).expect("execution"),
    )
    .expect("updated runtime")
}

// Returns the signed replacement candidate selected after the catalog advances.
fn updated_candidate() -> RuntimeCandidate {
    let current = candidate();
    RuntimeCandidate::new(
        logical_model(),
        updated_runtime_identity(),
        current.artifacts().to_vec(),
        current.target().clone(),
        EvidenceLabel::Unqualified,
        2,
        true,
        false,
    )
    .expect("updated candidate")
}

// Returns one available or removed runtime installation fixture.
fn installation(character: char, state: RuntimeInstallationState) -> RuntimeInstallation {
    installation_for_node(character, node_id(), state)
}

// Returns one available or removed fixture installation on an exact node.
fn installation_for_node(
    character: char,
    node_id: NodeId,
    state: RuntimeInstallationState,
) -> RuntimeInstallation {
    RuntimeInstallation::new(
        RuntimeInstallationId::parse(&identity(character)).expect("installation"),
        node_id,
        logical_model(),
        runtime_identity(),
        candidate().artifacts().to_vec(),
        EvidenceLabel::Unqualified,
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("installation")
}

// Returns one explicit command identity.
fn command(character: char, key: &str) -> NodeModelCommandIdentity {
    NodeModelCommandIdentity::new(
        OperationId::parse(&identity(character)).expect("operation"),
        TechnicalName::parse(key).expect("idempotency key"),
    )
}

// Returns one single-node install request.
fn install_request() -> NodeModelInstallRequest {
    NodeModelInstallRequest::new(
        command('7', "install_model"),
        service_id(),
        logical_model(),
        vec![NodeModelInstallGroup::new(vec![node_id()], None).expect("group")],
    )
    .expect("install request")
}

// Returns one deterministic model-update request with an explicit mutation choice.
fn update_request(character: char, key: &str, dry_run: bool) -> NodeModelUpdateRequest {
    NodeModelUpdateRequest::new(command(character, key), service_id(), None, dry_run)
}

// Supplies deterministic increasing coordinator time.
struct TestClock(AtomicU64);

impl NodeModelClock for TestClock {
    // Returns one unique deterministic lifecycle timestamp.
    fn now(&self) -> Result<UnixMilliseconds, NodeModelError> {
        Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Supplies one exact current hardware observation.
struct TestHardware;

impl NodeModelHardwareProvider for TestHardware {
    // Returns the fixture only for its exact node.
    fn observation(&self, requested: &NodeId) -> Result<HardwareObservation, NodeModelError> {
        if requested == &node_id() || requested == &other_node_id() {
            Ok(hardware_for(requested.clone()))
        } else {
            Err(NodeModelError::ProviderUnavailable)
        }
    }
}

// Stores NodeManager-owned service and operation state for ordering tests.
#[derive(Default)]
struct MockState {
    services: Mutex<BTreeMap<String, (ModelService, u64)>>,
    operations: Mutex<BTreeMap<String, (Operation, u64)>>,
    events: Mutex<Vec<String>>,
    fail_next_detach: AtomicBool,
    panic_after_service_create: AtomicBool,
    panic_after_service_running: AtomicBool,
}

impl MockState {
    // Returns the recorded cross-manager call order.
    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events").clone()
    }

    // Returns one stable missing-record failure.
    fn missing(collection: DatabaseCollection, identifier: &str) -> NodeManagerError {
        NodeManagerError::Database(DatabaseError::NotFound {
            collection,
            identifier: identifier.to_string(),
        })
    }
}

impl NodeModelStatePort for MockState {
    // Returns every service in stable identity order.
    fn services(&self) -> Result<Vec<ModelService>, NodeManagerError> {
        Ok(self
            .services
            .lock()
            .expect("services")
            .values()
            .map(|(service, _)| service.clone())
            .collect())
    }

    // Returns one exact service and revision.
    fn service(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.services
            .lock()
            .expect("services")
            .get(service_id.as_str())
            .map(|(service, revision)| VersionedNodeModelService::new(service.clone(), *revision))
            .ok_or_else(|| Self::missing(DatabaseCollection::Services, service_id.as_str()))
    }

    // Creates one empty stopped service exactly once.
    fn create_service(
        &self,
        _idempotency_key: &str,
        service: ModelService,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.events
            .lock()
            .expect("events")
            .push("state.service.create".to_string());
        let mut services = self.services.lock().expect("services");
        if let Some((existing, revision)) = services.get(service.service_id().as_str()) {
            return if existing == &service {
                Ok(VersionedNodeModelService::new(existing.clone(), *revision))
            } else {
                Err(NodeManagerError::InvalidModelService {
                    reason: "service identity conflict",
                })
            };
        }
        services.insert(
            service.service_id().as_str().to_string(),
            (service.clone(), 1),
        );
        drop(services);
        assert!(
            !self
                .panic_after_service_create
                .swap(false, Ordering::SeqCst),
            "simulated crash after service create"
        );
        Ok(VersionedNodeModelService::new(service, 1))
    }

    // Attaches one exact group under optimistic revision.
    fn attach_group(
        &self,
        _idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.events
            .lock()
            .expect("events")
            .push("state.group.attach".to_string());
        self.update_service(service_id, expected_revision, updated_at, |service| {
            let mut groups = service.placement_group_ids().to_vec();
            if !groups.contains(&placement_group_id) {
                groups.push(placement_group_id);
            }
            (service.desired_state(), groups)
        })
    }

    // Detaches one exact released group under optimistic revision.
    fn detach_group(
        &self,
        _idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: &PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.events
            .lock()
            .expect("events")
            .push("state.group.detach".to_string());
        if self.fail_next_detach.swap(false, Ordering::SeqCst) {
            return Err(NodeManagerError::Database(DatabaseError::Unavailable {
                reason: "simulated detach failure",
            }));
        }
        self.update_service(service_id, expected_revision, updated_at, |service| {
            (
                service.desired_state(),
                service
                    .placement_group_ids()
                    .iter()
                    .filter(|identity| *identity != placement_group_id)
                    .cloned()
                    .collect(),
            )
        })
    }

    // Applies one desired-state transition under optimistic revision.
    fn transition_service(
        &self,
        _idempotency_key: &str,
        service_id: &ModelServiceId,
        desired_state: ModelServiceDesiredState,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.events.lock().expect("events").push(format!(
            "state.service.{}",
            match desired_state {
                ModelServiceDesiredState::Running => "running",
                ModelServiceDesiredState::Stopped => "stopped",
                ModelServiceDesiredState::Removed => "removed",
            }
        ));
        let changed =
            self.update_service(service_id, expected_revision, updated_at, |service| {
                (desired_state, service.placement_group_ids().to_vec())
            })?;
        if desired_state == ModelServiceDesiredState::Running {
            assert!(
                !self
                    .panic_after_service_running
                    .swap(false, Ordering::SeqCst),
                "simulated crash after service running"
            );
        }
        Ok(changed)
    }

    // Returns one exact user-visible operation when present.
    fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<VersionedNodeModelOperation>, NodeManagerError> {
        Ok(self
            .operations
            .lock()
            .expect("operations")
            .get(operation_id.as_str())
            .map(|(operation, revision)| {
                VersionedNodeModelOperation::new(operation.clone(), *revision)
            }))
    }

    // Returns every operation in stable identity order.
    fn operations(&self) -> Result<Vec<Operation>, NodeManagerError> {
        Ok(self
            .operations
            .lock()
            .expect("operations")
            .values()
            .map(|(operation, _)| operation.clone())
            .collect())
    }

    // Begins one pending user-visible operation.
    fn begin_operation(
        &self,
        _idempotency_key: &str,
        operation_id: OperationId,
        kind: OperationKind,
        target: OperationTarget,
        created_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        self.events
            .lock()
            .expect("events")
            .push("state.operation.begin".to_string());
        let operation = Operation::new(
            operation_id.clone(),
            kind,
            target,
            OperationState::Pending,
            None,
            None,
            EntityTimestamps::new(created_at, created_at)?,
        )?;
        self.operations
            .lock()
            .expect("operations")
            .insert(operation_id.as_str().to_string(), (operation.clone(), 1));
        Ok(VersionedNodeModelOperation::new(operation, 1))
    }

    // Starts one exact pending user-visible operation.
    fn start_operation(
        &self,
        _idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        started_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        self.events
            .lock()
            .expect("events")
            .push("state.operation.start".to_string());
        self.update_operation(
            operation_id,
            expected_revision,
            OperationState::Running,
            None,
            None,
            started_at,
        )
    }

    // Completes one exact user-visible operation.
    fn complete_operation(
        &self,
        _idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        completion: OperationCompletion,
        completed_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        let (state, failure, name) = match completion {
            OperationCompletion::Succeeded => (OperationState::Succeeded, None, "succeed"),
            OperationCompletion::Failed(failure) => (OperationState::Failed, Some(failure), "fail"),
            OperationCompletion::Cancelled => (OperationState::Cancelled, None, "cancel"),
        };
        self.events
            .lock()
            .expect("events")
            .push(format!("state.operation.{name}"));
        self.update_operation(
            operation_id,
            expected_revision,
            state,
            failure,
            Some(completed_at),
            completed_at,
        )
    }
}

impl MockState {
    // Rebuilds one service under an exact optimistic revision.
    fn update_service<Update>(
        &self,
        service_id: &ModelServiceId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
        update: Update,
    ) -> Result<VersionedNodeModelService, NodeManagerError>
    where
        Update: FnOnce(&ModelService) -> (ModelServiceDesiredState, Vec<PlacementGroupId>),
    {
        let mut services = self.services.lock().expect("services");
        let (current, revision) = services
            .get(service_id.as_str())
            .cloned()
            .ok_or_else(|| Self::missing(DatabaseCollection::Services, service_id.as_str()))?;
        if revision != expected_revision {
            return Err(NodeManagerError::Database(DatabaseError::Conflict {
                collection: DatabaseCollection::Services,
                identifier: service_id.as_str().to_string(),
                expected: li_database::DatabaseRevision::Exact(expected_revision),
                observed: Some(revision),
            }));
        }
        let (state, groups) = update(&current);
        let service = ModelService::new(
            current.service_id().clone(),
            current.logical_model().clone(),
            state,
            groups,
            EntityTimestamps::new(current.timestamps().created_at(), updated_at)?,
        )?;
        let revision = revision + 1;
        services.insert(service_id.as_str().to_string(), (service.clone(), revision));
        Ok(VersionedNodeModelService::new(service, revision))
    }

    // Rebuilds one operation under an exact optimistic revision.
    fn update_operation(
        &self,
        operation_id: &OperationId,
        expected_revision: u64,
        state: OperationState,
        failure: Option<FailureDescription>,
        completed_at: Option<UnixMilliseconds>,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        let mut operations = self.operations.lock().expect("operations");
        let (current, revision) = operations
            .get(operation_id.as_str())
            .cloned()
            .ok_or_else(|| Self::missing(DatabaseCollection::Operations, operation_id.as_str()))?;
        if revision != expected_revision {
            return Err(NodeManagerError::InvalidOperationTransition {
                operation_id: operation_id.as_str().to_string(),
                current: "stale",
                action: "update",
            });
        }
        let operation = Operation::new(
            current.operation_id().clone(),
            current.kind(),
            current.target().clone(),
            state,
            failure,
            completed_at,
            EntityTimestamps::new(current.timestamps().created_at(), updated_at)?,
        )?;
        let revision = revision + 1;
        operations.insert(
            operation_id.as_str().to_string(),
            (operation.clone(), revision),
        );
        Ok(VersionedNodeModelOperation::new(operation, revision))
    }
}

// Stores exact RuntimeManager projections and deterministic provider failures.
struct MockRuntime {
    installations: Mutex<BTreeMap<String, VersionedRuntimeInstallation>>,
    events: Arc<Mutex<Vec<String>>>,
    fail_install_after_commit: AtomicBool,
    panic_install_after_commit: AtomicBool,
    fail_remove: AtomicBool,
    next_identity: AtomicUsize,
    install_gate: Mutex<Option<Arc<MockRuntimeInstallGate>>>,
    select_update: AtomicBool,
    fail_select: AtomicBool,
}

// Synchronizes one mock runtime acquisition without changing production timing.
struct MockRuntimeInstallGate {
    state: Mutex<MockRuntimeInstallGateState>,
    changed: Condvar,
}

// Records whether the first gated acquisition entered and may continue.
#[derive(Default)]
struct MockRuntimeInstallGateState {
    entered: bool,
    released: bool,
}

impl MockRuntimeInstallGate {
    // Creates one gate that blocks only the first runtime acquisition.
    fn new() -> Self {
        Self {
            state: Mutex::new(MockRuntimeInstallGateState::default()),
            changed: Condvar::new(),
        }
    }

    // Blocks the first acquisition until the owning test releases it.
    fn enter_once(&self) {
        let mut state = self.state.lock().expect("install gate");
        if state.entered {
            return;
        }
        state.entered = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).expect("install gate wait");
        }
    }

    // Waits until one acquisition holds the coordinator execution claim.
    fn wait_until_entered(&self) {
        let mut state = self.state.lock().expect("install gate");
        while !state.entered {
            state = self.changed.wait(state).expect("install gate wait");
        }
    }

    // Permits the blocked acquisition to finish its ordinary lifecycle.
    fn release(&self) {
        let mut state = self.state.lock().expect("install gate");
        state.released = true;
        self.changed.notify_all();
    }
}

impl MockRuntime {
    // Creates one empty runtime provider sharing the global call log.
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            installations: Mutex::new(BTreeMap::new()),
            events,
            fail_install_after_commit: AtomicBool::new(false),
            panic_install_after_commit: AtomicBool::new(false),
            fail_remove: AtomicBool::new(false),
            next_identity: AtomicUsize::new(5),
            install_gate: Mutex::new(None),
            select_update: AtomicBool::new(false),
            fail_select: AtomicBool::new(false),
        }
    }

    // Installs one deterministic synchronization gate for the next acquisition.
    fn block_next_install(&self) -> Arc<MockRuntimeInstallGate> {
        let gate = Arc::new(MockRuntimeInstallGate::new());
        *self.install_gate.lock().expect("install gate") = Some(Arc::clone(&gate));
        gate
    }

    // Inserts one authoritative installation before command execution.
    fn insert(&self, installation: RuntimeInstallation) {
        self.installations.lock().expect("installations").insert(
            installation.installation_id().as_str().to_string(),
            VersionedRuntimeInstallation::new(installation, 1),
        );
    }

    // Returns how often immutable runtime acquisition was invoked.
    fn install_calls(&self) -> usize {
        self.events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| event.as_str() == "runtime.install")
            .count()
    }
}

impl NodeModelRuntimePort for MockRuntime {
    // Returns the one compatible candidate without inspecting its evidence label.
    fn select(
        &self,
        model: &LogicalModelName,
        explicit_candidate_id: Option<&RuntimeCandidateId>,
        _hardware: &HardwareObservation,
    ) -> Result<RuntimeCandidate, RuntimeError> {
        if self.fail_select.load(Ordering::SeqCst) {
            return Err(RuntimeError::CandidateNotFound);
        }
        let candidate = if self.select_update.load(Ordering::SeqCst) {
            updated_candidate()
        } else {
            candidate()
        };
        if model != candidate.logical_model()
            || explicit_candidate_id
                .is_some_and(|identity| identity != candidate.runtime().candidate_id())
        {
            return Err(RuntimeError::CandidateNotFound);
        }
        Ok(candidate)
    }

    // Commits one available installation and optionally loses the provider response.
    fn install(
        &self,
        node_id: NodeId,
        _model: &LogicalModelName,
        _candidate_id: &RuntimeCandidateId,
        _hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        let install_gate = self.install_gate.lock().expect("install gate").clone();
        if let Some(install_gate) = install_gate {
            install_gate.enter_once();
        }
        self.events
            .lock()
            .expect("events")
            .push("runtime.install".to_string());
        let character = char::from_digit(
            u32::try_from(self.next_identity.fetch_add(1, Ordering::SeqCst)).expect("identity"),
            16,
        )
        .expect("identity digit");
        let mut installation =
            installation_for_node(character, node_id, RuntimeInstallationState::Available);
        if self.select_update.load(Ordering::SeqCst) {
            installation = RuntimeInstallation::new(
                installation.installation_id().clone(),
                installation.node_id().clone(),
                installation.logical_model().clone(),
                updated_runtime_identity(),
                installation.artifacts().to_vec(),
                installation.evidence_label(),
                RuntimeInstallationState::Available,
                None,
                installation.timestamps().clone(),
            )
            .expect("updated installation");
        }
        let versioned = VersionedRuntimeInstallation::new(installation.clone(), 1);
        self.installations.lock().expect("installations").insert(
            installation.installation_id().as_str().to_string(),
            versioned.clone(),
        );
        assert!(
            !self
                .panic_install_after_commit
                .swap(false, Ordering::SeqCst),
            "simulated crash after runtime install"
        );
        if self.fail_install_after_commit.load(Ordering::SeqCst) {
            Err(RuntimeError::DownloadUnavailable)
        } else {
            Ok(versioned)
        }
    }

    // Marks one exact installation removed unless cleanup is configured to fail.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.events
            .lock()
            .expect("events")
            .push("runtime.remove".to_string());
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        let mut installations = self.installations.lock().expect("installations");
        let current = installations
            .get(installation_id.as_str())
            .cloned()
            .ok_or(RuntimeError::InstallationNotFound)?;
        let removed = RuntimeInstallation::new(
            current.installation().installation_id().clone(),
            current.installation().node_id().clone(),
            current.installation().logical_model().clone(),
            current.installation().runtime().clone(),
            current.installation().artifacts().to_vec(),
            current.installation().evidence_label(),
            RuntimeInstallationState::Removed,
            None,
            EntityTimestamps::new(
                current.installation().timestamps().created_at(),
                UnixMilliseconds::new(9_000),
            )
            .expect("timestamps"),
        )
        .expect("removed installation");
        let removed = VersionedRuntimeInstallation::new(removed, current.revision() + 1);
        installations.insert(installation_id.as_str().to_string(), removed.clone());
        Ok(removed)
    }

    // Records selective model retention before applying the removed-state transition.
    fn remove_preserving_models(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.events
            .lock()
            .expect("events")
            .push("runtime.remove_preserving_models".to_string());
        self.remove(installation_id)
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

    // Returns every authoritative installation in stable identity order.
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

// Stores complete PlacementManager aggregates and deterministic provider failures.
struct MockPlacement {
    records: Mutex<BTreeMap<String, (PlacementRequest, VersionedPlacementRecord)>>,
    events: Arc<Mutex<Vec<String>>>,
    fail_stage_after_commit: AtomicBool,
    panic_stage_after_commit: AtomicBool,
    panic_start_after_commit: AtomicBool,
    fail_start: AtomicBool,
    fail_remove: AtomicBool,
    fail_logs: AtomicBool,
    log_requests: Mutex<Vec<PlacementLogReadRequest>>,
}

impl MockPlacement {
    // Creates one empty placement provider sharing the global call log.
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            events,
            fail_stage_after_commit: AtomicBool::new(false),
            panic_stage_after_commit: AtomicBool::new(false),
            panic_start_after_commit: AtomicBool::new(false),
            fail_start: AtomicBool::new(false),
            fail_remove: AtomicBool::new(false),
            fail_logs: AtomicBool::new(false),
            log_requests: Mutex::new(Vec::new()),
        }
    }

    // Returns the number of staged groups.
    fn stage_calls(&self) -> usize {
        self.events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| event.as_str() == "placement.stage")
            .count()
    }

    // Inserts one external authoritative group for reference-safety tests.
    fn insert(
        &self,
        request: PlacementRequest,
        placement_group_id: PlacementGroupId,
        state: PlacementGroupState,
    ) {
        let record = VersionedPlacementRecord::new(
            placement_record(&request, placement_group_id.clone(), state),
            1,
        );
        self.records
            .lock()
            .expect("records")
            .insert(placement_group_id.as_str().to_string(), (request, record));
    }

    // Replaces one exact aggregate state.
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
        let record = placement_record(&request, placement_group_id.clone(), state);
        let versioned = VersionedPlacementRecord::new(record, current.revision() + 1);
        records.insert(
            placement_group_id.as_str().to_string(),
            (request, versioned.clone()),
        );
        Ok(versioned)
    }
}

impl NodeModelPlacementPort for MockPlacement {
    // Commits one staged group and optionally loses the provider response.
    fn stage(&self, request: PlacementRequest) -> Result<VersionedPlacementRecord, PlacementError> {
        self.events
            .lock()
            .expect("events")
            .push("placement.stage".to_string());
        let placement_group_id = request.placement_group_id().clone();
        if let Some((stored_request, stored)) = self
            .records
            .lock()
            .expect("records")
            .get(placement_group_id.as_str())
            .cloned()
        {
            return if stored_request == request {
                Ok(stored)
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        let versioned = VersionedPlacementRecord::new(
            placement_record(
                &request,
                placement_group_id.clone(),
                PlacementGroupState::Staged,
            ),
            1,
        );
        self.records.lock().expect("records").insert(
            placement_group_id.as_str().to_string(),
            (request, versioned.clone()),
        );
        assert!(
            !self.panic_stage_after_commit.swap(false, Ordering::SeqCst),
            "simulated crash after placement stage"
        );
        if self.fail_stage_after_commit.load(Ordering::SeqCst) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(versioned)
        }
    }

    // Starts one exact group unless configured to fail before mutation.
    fn start(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.events
            .lock()
            .expect("events")
            .push("placement.start".to_string());
        if self.fail_start.swap(false, Ordering::SeqCst) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            let changed = self.transition(placement_group_id, PlacementGroupState::Running)?;
            assert!(
                !self.panic_start_after_commit.swap(false, Ordering::SeqCst),
                "simulated crash after placement start"
            );
            Ok(changed)
        }
    }

    // Stops one exact group while retaining its assignments.
    fn stop(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.events
            .lock()
            .expect("events")
            .push("placement.stop".to_string());
        self.transition(placement_group_id, PlacementGroupState::Stopped)
    }

    // Recovers one exact group while recording the acknowledgement decision.
    fn recover(
        &self,
        placement_group_id: &PlacementGroupId,
        acknowledge_protection_trips: bool,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.events
            .lock()
            .expect("events")
            .push(format!("placement.recover.{acknowledge_protection_trips}"));
        self.transition(placement_group_id, PlacementGroupState::Running)
    }

    // Removes one exact group unless cleanup is configured to fail.
    fn remove(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.events
            .lock()
            .expect("events")
            .push("placement.remove".to_string());
        if self.fail_remove.load(Ordering::SeqCst) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            self.transition(placement_group_id, PlacementGroupState::Removed)
        }
    }

    // Returns one exact authoritative aggregate.
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

    // Returns one deterministic opaque batch from the selected endpoint-owner placement.
    fn read_logs(
        &self,
        request: PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError> {
        if self.fail_logs.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let record = self
            .records
            .lock()
            .expect("records")
            .get(request.placement_group_id().as_str())
            .map(|(_, record)| record.clone())
            .ok_or(PlacementError::GroupNotFound)?;
        let placement = record
            .record()
            .placements()
            .iter()
            .find(|placement| {
                placement.assignment().endpoint_ownership() == EndpointOwnership::Owner
            })
            .ok_or(PlacementError::ExecutionUnavailable)?;
        self.log_requests
            .lock()
            .expect("log requests")
            .push(request.clone());
        PlacementLogBatch::new(
            request.placement_group_id().clone(),
            placement.placement_id().clone(),
            PlacementLogCursor::new(
                Sha256Digest::parse(&"9".repeat(64)).expect("source"),
                "fixture-position".to_string(),
            )?,
            b"opaque runtime output\n".to_vec(),
            false,
        )
    }
}

// Reconstructs fully typed placement requests from exact runtime receipts.
struct TestPlacementRequests;

impl NodeModelPlacementRequestProvider for TestPlacementRequests {
    // Builds one model-neutral single-node request for any bounded replica index.
    fn request(
        &self,
        service_id: &ModelServiceId,
        group_index: usize,
        placement_group_id: &PlacementGroupId,
        installations: &[RuntimeInstallation],
    ) -> Result<PlacementRequest, NodeModelError> {
        if group_index > 127 || installations.len() != 1 {
            return Err(NodeModelError::InvalidRequest {
                reason: "test placement receipt count is invalid",
            });
        }
        let installation = &installations[0];
        let task_id = TaskId::parse("task-0").expect("task");
        PlacementRequest::new(
            placement_group_id.clone(),
            service_id.clone(),
            installation.runtime().clone(),
            PlacementGroupCapacity::new(
                8,
                4,
                262_144,
                InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
            )
            .map_err(|_| NodeModelError::ProviderUnavailable)?,
            vec![PlacementTask::new(task_id.clone(), 1, 2)?],
            vec![PlacementNodeResources::new(
                installation.node_id().clone(),
                installation.installation_id().clone(),
                HardwareObservationId::parse(&identity('1')).expect("observation"),
                BootId::parse("boot-fixture").expect("boot"),
                UnixMilliseconds::new(1_000),
                NodeAddress::parse("spark.local").expect("address"),
                vec![DeviceId::parse("GPU-fixture").expect("device")],
                PortRange::new(18_000, 2).expect("ports"),
                None,
            )?],
            task_id.clone(),
            installation.node_id().clone(),
            vec![vec![task_id]],
            Vec::new(),
        )
        .map_err(NodeModelError::from)
    }
}

// Builds one complete aggregate from one request and lifecycle state.
fn placement_record(
    request: &PlacementRequest,
    placement_group_id: PlacementGroupId,
    state: PlacementGroupState,
) -> PlacementRecord {
    let placement_id = PlacementId::parse(&identity('9')).expect("placement");
    let node = &request.nodes()[0];
    let resources =
        PlacementResources::new(node.ports(), node.device_ids().to_vec(), None).expect("resources");
    let placement_state = match state {
        PlacementGroupState::Staged => PlacementState::Staged,
        PlacementGroupState::Running | PlacementGroupState::Degraded => PlacementState::Running,
        PlacementGroupState::Stopped => PlacementState::Stopped,
        PlacementGroupState::Removed => PlacementState::Removed,
        _ => panic!("unsupported fixture state"),
    };
    let placement = Placement::new(
        placement_id.clone(),
        placement_group_id.clone(),
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
    let endpoint = matches!(
        state,
        PlacementGroupState::Running | PlacementGroupState::Degraded
    )
    .then(|| {
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
        PlacementGroupState::Staged
        | PlacementGroupState::Running
        | PlacementGroupState::Degraded => ModelServiceDesiredState::Running,
        _ => unreachable!(),
    };
    let group = PlacementGroup::new(
        placement_group_id,
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
        PlacementGroupState::Running | PlacementGroupState::Degraded => ResourceLeaseState::Active,
        PlacementGroupState::Removed => ResourceLeaseState::Released,
        PlacementGroupState::Staged | PlacementGroupState::Stopped => ResourceLeaseState::Reserved,
        _ => unreachable!(),
    };
    let mut resources = vec![ResourceIdentity::Accelerator(
        DeviceId::parse("GPU-fixture").expect("device"),
    )];
    for port in 18_000..18_002 {
        resources.push(ResourceIdentity::Port(
            NetworkPort::new(port).expect("port"),
        ));
    }
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
            Sha256Digest::parse(&"f".repeat(64)).expect("plan"),
        )],
    )
    .expect("record")
}

// Owns one complete coordinator fixture and its shared provider call log.
struct Fixture {
    coordinator: NodeModelCoordinator,
    state: Arc<MockState>,
    runtime: Arc<MockRuntime>,
    placement: Arc<MockPlacement>,
    events: Arc<Mutex<Vec<String>>>,
    journals: Arc<DatabaseNodeModelJournalStore>,
}

// Panics after one durable journal commit to simulate immediate process death.
struct PanicJournalStore {
    inner: Arc<dyn NodeModelJournalStore>,
    panic_after_create: bool,
    panic_after_replace: Option<usize>,
    replace_count: AtomicUsize,
}

impl PanicJournalStore {
    // Creates one deterministic crash seam around an ordinary durable store.
    fn new(
        inner: Arc<dyn NodeModelJournalStore>,
        panic_after_create: bool,
        panic_after_replace: Option<usize>,
    ) -> Self {
        Self {
            inner,
            panic_after_create,
            panic_after_replace,
            replace_count: AtomicUsize::new(0),
        }
    }
}

impl NodeModelJournalStore for PanicJournalStore {
    // Commits one normalized command and optionally simulates process death.
    fn create(
        &self,
        journal: li_node_manager::NodeModelJournal,
    ) -> Result<li_node_manager::VersionedNodeModelJournal, NodeModelError> {
        let created = self.inner.create(journal)?;
        assert!(
            !self.panic_after_create,
            "simulated crash after journal create"
        );
        Ok(created)
    }

    // Delegates one exact journal read.
    fn read(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<li_node_manager::VersionedNodeModelJournal>, NodeModelError> {
        self.inner.read(operation_id)
    }

    // Delegates stable journal projection.
    fn all(&self) -> Result<Vec<li_node_manager::VersionedNodeModelJournal>, NodeModelError> {
        self.inner.all()
    }

    // Commits one phase receipt and optionally simulates immediate process death.
    fn replace(
        &self,
        journal: li_node_manager::NodeModelJournal,
        expected_revision: u64,
    ) -> Result<li_node_manager::VersionedNodeModelJournal, NodeModelError> {
        let replaced = self.inner.replace(journal, expected_revision)?;
        let count = self.replace_count.fetch_add(1, Ordering::SeqCst) + 1;
        assert_ne!(
            self.panic_after_replace,
            Some(count),
            "simulated crash after journal replace {count}"
        );
        Ok(replaced)
    }
}

// Fails the first durable mutation while permitting the coordinator's absence pre-read.
struct UnavailableJournalStore;

impl NodeModelJournalStore for UnavailableJournalStore {
    // Rejects command creation before any manager or provider mutation.
    fn create(
        &self,
        _journal: li_node_manager::NodeModelJournal,
    ) -> Result<li_node_manager::VersionedNodeModelJournal, NodeModelError> {
        Err(NodeModelError::JournalUnavailable)
    }

    // Reports that the command does not yet exist.
    fn read(
        &self,
        _operation_id: &OperationId,
    ) -> Result<Option<li_node_manager::VersionedNodeModelJournal>, NodeModelError> {
        Ok(None)
    }

    // Rejects durable recovery projection from an unavailable adapter.
    fn all(&self) -> Result<Vec<li_node_manager::VersionedNodeModelJournal>, NodeModelError> {
        Err(NodeModelError::JournalUnavailable)
    }

    // Rejects optimistic mutation from an unavailable adapter.
    fn replace(
        &self,
        _journal: li_node_manager::NodeModelJournal,
        _expected_revision: u64,
    ) -> Result<li_node_manager::VersionedNodeModelJournal, NodeModelError> {
        Err(NodeModelError::JournalUnavailable)
    }
}

// Composes one coordinator around shared manager ports and an explicit journal store.
fn coordinator(
    state: Arc<MockState>,
    runtime: Arc<MockRuntime>,
    placement: Arc<MockPlacement>,
    journals: Arc<dyn NodeModelJournalStore>,
    clock_start: u64,
) -> NodeModelCoordinator {
    NodeModelCoordinator::new(
        state,
        runtime,
        placement,
        Arc::new(TestPlacementRequests),
        Arc::new(TestHardware),
        journals,
        Arc::new(TestClock(AtomicU64::new(clock_start))),
    )
}

// Creates one coordinator over a real database journal and mock manager ports.
fn fixture(directory: &tempfile::TempDir) -> Fixture {
    let database_path = directory.path().join("core.sqlite3");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(database_path.clone())).expect("database"),
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(MockState::default());
    let runtime = Arc::new(MockRuntime::new(Arc::clone(&events)));
    let placement = Arc::new(MockPlacement::new(Arc::clone(&events)));
    let journals = Arc::new(DatabaseNodeModelJournalStore::new(database));
    let coordinator = coordinator(
        state.clone(),
        runtime.clone(),
        placement.clone(),
        journals.clone(),
        3_000,
    );
    Fixture {
        coordinator,
        state,
        runtime,
        placement,
        events,
        journals,
    }
}

// Installs in exact order, retains an unqualified label, and projects exact identities.
#[test]
fn install_orders_managers_and_projects_exact_unqualified_identity() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let result = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    assert_eq!(
        result.journal().journal().state(),
        NodeModelJournalState::Succeeded
    );
    assert_eq!(result.operation().state(), OperationState::Succeeded);
    assert_eq!(
        result.service().desired_state(),
        ModelServiceDesiredState::Running
    );
    assert_eq!(result.service().placement_group_ids().len(), 1);
    assert_eq!(fixture.runtime.install_calls(), 1);
    assert_eq!(fixture.placement.stage_calls(), 1);
    let provider_events = fixture.events.lock().expect("events").clone();
    assert_eq!(
        provider_events,
        vec!["runtime.install", "placement.stage", "placement.start"]
    );
    let state_events = fixture.state.events();
    assert_eq!(
        state_events,
        vec![
            "state.operation.begin",
            "state.operation.start",
            "state.service.create",
            "state.group.attach",
            "state.service.running",
            "state.operation.succeed",
        ]
    );
    let projection = fixture.coordinator.list().expect("list");
    assert_eq!(projection.len(), 1);
    assert_eq!(
        projection[0].evidence_labels(),
        [EvidenceLabel::Unqualified]
    );
    assert_eq!(projection[0].placement_groups().len(), 1);
    assert_eq!(projection[0].installations().len(), 1);
}

// Resolves one service group and forwards exact bounded runtime-log controls to PlacementManager.
#[test]
fn runtime_logs_require_service_owned_group_and_preserve_provider_bounds() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let placement_group_id = installed.service().placement_group_ids()[0].clone();
    let request = NodeModelRuntimeLogRequest::new(
        service_id(),
        None,
        None,
        200,
        64 * 1024,
        Duration::from_millis(750),
    )
    .expect("request");
    let batch = fixture
        .coordinator
        .runtime_logs(request)
        .expect("runtime logs");
    assert_eq!(batch.service_id(), &service_id());
    assert_eq!(batch.placement().placement_group_id(), &placement_group_id);
    assert_eq!(batch.placement().payload(), b"opaque runtime output\n");
    let forwarded = fixture.placement.log_requests.lock().expect("log requests");
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].maximum_lines(), 200);
    assert_eq!(forwarded[0].maximum_bytes(), 64 * 1024);
    assert_eq!(forwarded[0].wait(), Duration::from_millis(750));
    drop(forwarded);

    let foreign = NodeModelRuntimeLogRequest::new(
        service_id(),
        Some(PlacementGroupId::parse(&identity('e')).expect("foreign group")),
        None,
        200,
        64 * 1024,
        Duration::ZERO,
    )
    .expect("request");
    assert!(matches!(
        fixture.coordinator.runtime_logs(foreign),
        Err(NodeModelError::InvalidRequest { .. })
    ));
    fixture.placement.fail_logs.store(true, Ordering::SeqCst);
    let provider_failure = NodeModelRuntimeLogRequest::new(
        service_id(),
        Some(placement_group_id),
        None,
        200,
        64 * 1024,
        Duration::ZERO,
    )
    .expect("request");
    assert_eq!(
        fixture
            .coordinator
            .runtime_logs(provider_failure)
            .expect_err("provider failure"),
        NodeModelError::Placement(PlacementError::ExecutionUnavailable)
    );
}

// Requires an explicit placement group when one model service has independent replicas.
#[test]
fn runtime_logs_reject_ambiguous_replica_selection() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(
            NodeModelInstallRequest::new(
                command('c', "install_log_replicas"),
                service_id(),
                logical_model(),
                vec![
                    NodeModelInstallGroup::new(vec![node_id()], None).expect("first group"),
                    NodeModelInstallGroup::new(vec![other_node_id()], None).expect("second group"),
                ],
            )
            .expect("install request"),
        )
        .expect("install replicas");
    let request =
        NodeModelRuntimeLogRequest::new(service_id(), None, None, 200, 64 * 1024, Duration::ZERO)
            .expect("request");
    assert!(matches!(
        fixture.coordinator.runtime_logs(request),
        Err(NodeModelError::InvalidRequest { .. })
    ));
    assert!(fixture
        .placement
        .log_requests
        .lock()
        .expect("log requests")
        .is_empty());
}

// Distinguishes current and signed update availability without provider mutation.
#[test]
fn update_check_is_read_only_and_reports_exact_disposition() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let provider_count = fixture.events.lock().expect("events").len();
    let current = fixture
        .coordinator
        .update(update_request('8', "check_current", true))
        .expect("current check");
    assert_eq!(current.disposition(), NodeModelUpdateDisposition::Current);
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    let available = fixture
        .coordinator
        .update(update_request('9', "check_update", true))
        .expect("update check");
    assert_eq!(
        available.disposition(),
        NodeModelUpdateDisposition::UpdateAvailable
    );
    assert_eq!(available.placement_group_count(), 1);
    assert_eq!(fixture.events.lock().expect("events").len(), provider_count);
}

// Acquires one signed replacement, releases conflicting resources, then replays terminal state.
#[test]
fn update_replaces_group_and_terminal_replay_is_side_effect_free() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let previous_group = installed.service().placement_group_ids()[0].clone();
    let previous_installation = fixture.coordinator.list().expect("installed services")[0]
        .installations()[0]
        .installation_id()
        .clone();
    fixture.events.lock().expect("events").clear();
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    let request = update_request('8', "update_model", false);
    let updated = fixture.coordinator.update(request.clone()).expect("update");
    assert_eq!(updated.disposition(), NodeModelUpdateDisposition::Updated);
    assert_eq!(updated.placement_group_count(), 1);
    let services = fixture.coordinator.list().expect("services");
    assert_eq!(services[0].placement_groups().len(), 1);
    assert_ne!(
        services[0].placement_groups()[0]
            .group()
            .placement_group_id(),
        &previous_group
    );
    assert_eq!(
        services[0].installations()[0].runtime(),
        &updated_runtime_identity()
    );
    assert_eq!(
        fixture
            .runtime
            .installation(&previous_installation)
            .expect("previous runtime lookup")
            .expect("retained previous runtime")
            .installation()
            .state(),
        RuntimeInstallationState::Available
    );
    let events = fixture.events.lock().expect("events");
    let acquired = events
        .iter()
        .position(|event| event == "runtime.install")
        .expect("replacement acquisition");
    let released = events
        .iter()
        .position(|event| event == "placement.remove")
        .expect("old placement release");
    let staged = events
        .iter()
        .position(|event| event == "placement.stage")
        .expect("replacement placement stage");
    assert!(acquired < released && released < staged);
    drop(events);
    let provider_count = fixture.events.lock().expect("events").len();
    let replay = fixture.coordinator.update(request).expect("replay");
    assert_eq!(replay, updated);
    assert_eq!(fixture.events.lock().expect("events").len(), provider_count);
}

// Removes a failed pre-cutover replacement while retaining the original running group.
#[test]
fn update_failure_compensates_before_cutover_without_losing_service() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let previous_group = installed.service().placement_group_ids()[0].clone();
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    let request = update_request('8', "failed_update", false);
    assert!(matches!(
        fixture.coordinator.update(request.clone()),
        Err(NodeModelError::Placement(
            PlacementError::ExecutionUnavailable
        ))
    ));
    let failed = fixture
        .journals
        .read(request.identity().operation_id())
        .expect("failed journal")
        .expect("failed update journal");
    let restored_group = failed.journal().retained_groups()[0]
        .restoration_group_id()
        .clone();
    let service = fixture
        .state
        .service(&service_id())
        .expect("service after compensation");
    assert_eq!(service.service().placement_group_ids(), [restored_group]);
    assert_ne!(service.service().placement_group_ids(), [previous_group]);
    assert_eq!(
        fixture
            .placement
            .record(&service.service().placement_group_ids()[0])
            .expect("record")
            .expect("old group")
            .record()
            .group()
            .state(),
        PlacementGroupState::Running
    );
}

// Restores the retained current runtime after a post-removal update failure.
#[test]
fn update_post_cutover_failure_restores_current_without_forward_activation() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let previous_group = installed.service().placement_group_ids()[0].clone();
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture.state.fail_next_detach.store(true, Ordering::SeqCst);
    let request = update_request('8', "recover_update", false);
    assert_eq!(
        fixture.coordinator.update(request.clone()),
        Err(NodeModelError::StateUnavailable)
    );
    let failed = fixture
        .journals
        .read(request.identity().operation_id())
        .expect("read journal")
        .expect("failed journal");
    assert_eq!(failed.journal().state(), NodeModelJournalState::Failed);
    assert_eq!(
        fixture
            .state
            .operation(request.identity().operation_id())
            .expect("operation")
            .expect("failed operation")
            .operation()
            .state(),
        OperationState::Failed
    );
    assert_eq!(
        fixture
            .placement
            .record(&previous_group)
            .expect("record")
            .expect("old group")
            .record()
            .group()
            .state(),
        PlacementGroupState::Removed
    );

    let service = fixture
        .state
        .service(&service_id())
        .expect("restored service");
    assert_eq!(service.service().placement_group_ids().len(), 1);
    assert_ne!(service.service().placement_group_ids(), [previous_group]);
    let restored = fixture
        .placement
        .record(&service.service().placement_group_ids()[0])
        .expect("restored record")
        .expect("restored group");
    assert_eq!(restored.record().group().runtime(), &runtime_identity());
    assert_eq!(
        restored.record().group().state(),
        PlacementGroupState::Running
    );
    assert!(fixture
        .coordinator
        .recover_pending()
        .expect("no pending recovery")
        .is_empty());
}

// Previews and restores the latest retained runtime without consulting catalog selection.
#[test]
fn rollback_previews_and_restores_exact_retained_runtime_without_catalog_resolution() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    assert!(matches!(
        fixture.coordinator.preview_rollback(&service_id(), None),
        Err(NodeModelError::InvalidRequest { .. })
    ));
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .update(update_request('8', "update_before_rollback", false))
        .expect("update");
    let events_before_preview = fixture.events.lock().expect("events").len();
    let preview = fixture
        .coordinator
        .preview_rollback(
            &service_id(),
            Some(&TargetId::parse("dgx-spark").expect("target")),
        )
        .expect("rollback preview");
    assert_eq!(preview.groups().len(), 1);
    assert_eq!(preview.groups()[0].current().version().as_str(), "1.1.0");
    assert_eq!(preview.groups()[0].previous().version().as_str(), "1.0.0");
    assert_eq!(preview.groups()[0].node_ids(), [node_id()]);
    assert_eq!(
        fixture.events.lock().expect("events").len(),
        events_before_preview
    );

    fixture.runtime.fail_select.store(true, Ordering::SeqCst);
    let rolled_back = fixture
        .coordinator
        .rollback(command('9', "rollback_model"), service_id(), None)
        .expect("rollback");
    assert_eq!(
        rolled_back.journal().journal().action(),
        NodeModelAction::Rollback
    );
    assert_eq!(
        rolled_back.journal().journal().state(),
        NodeModelJournalState::Succeeded
    );
    let service = fixture.coordinator.list().expect("service");
    assert_eq!(service[0].placement_groups().len(), 1);
    assert_eq!(
        service[0].placement_groups()[0].group().runtime(),
        &runtime_identity()
    );
    assert_eq!(
        service[0].placement_groups()[0].group().state(),
        PlacementGroupState::Running
    );
    assert_eq!(service[0].installations().len(), 1);
    assert_eq!(service[0].installations()[0].runtime(), &runtime_identity());
}

// Preserves an explicitly stopped service while restoring its retained prior runtime.
#[test]
fn rollback_preserves_stopped_service_intent() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .update(update_request('8', "update_before_stopped_rollback", false))
        .expect("update");
    fixture
        .coordinator
        .pause(command('a', "pause_before_rollback"), service_id())
        .expect("pause");
    fixture.runtime.fail_select.store(true, Ordering::SeqCst);
    let result = fixture
        .coordinator
        .rollback(
            command('9', "rollback_stopped_model"),
            service_id(),
            Some(TargetId::parse("dgx-spark").expect("target")),
        )
        .expect("rollback stopped service");
    assert_eq!(
        result.service().desired_state(),
        ModelServiceDesiredState::Stopped
    );
    let service = fixture.coordinator.list().expect("service");
    assert_eq!(
        service[0].placement_groups()[0].group().runtime(),
        &runtime_identity()
    );
    assert_eq!(
        service[0].placement_groups()[0].group().state(),
        PlacementGroupState::Stopped
    );
}

// Restores the pre-rollback current runtime when retained activation fails after release.
#[test]
fn rollback_activation_failure_reconstructs_current_runtime_under_recovery_identity() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .update(update_request('8', "update_before_failed_rollback", false))
        .expect("update");
    let current_group = fixture
        .state
        .service(&service_id())
        .expect("current service")
        .service()
        .placement_group_ids()[0]
        .clone();
    fixture.runtime.fail_select.store(true, Ordering::SeqCst);
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    let identity = command('9', "failed_rollback");
    assert_eq!(
        fixture
            .coordinator
            .rollback(identity.clone(), service_id(), None),
        Err(NodeModelError::Placement(
            PlacementError::ExecutionUnavailable
        ))
    );
    let failed = fixture
        .journals
        .read(identity.operation_id())
        .expect("journal")
        .expect("failed rollback");
    assert_eq!(failed.journal().state(), NodeModelJournalState::Failed);
    let service = fixture
        .state
        .service(&service_id())
        .expect("restored service");
    assert_eq!(service.service().placement_group_ids().len(), 1);
    assert_ne!(service.service().placement_group_ids(), [current_group]);
    let restored = fixture
        .placement
        .record(&service.service().placement_group_ids()[0])
        .expect("restored record")
        .expect("restored group");
    assert_eq!(
        restored.record().group().runtime(),
        &updated_runtime_identity()
    );
    assert_eq!(
        restored.record().group().state(),
        PlacementGroupState::Running
    );
}

// Retries incomplete rollback compensation automatically and never exposes cleanup as rollback.
#[test]
fn rollback_cleanup_pending_is_recovered_automatically_to_current_runtime() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .update(update_request('8', "update_before_cleanup_retry", false))
        .expect("update");
    fixture.runtime.fail_select.store(true, Ordering::SeqCst);
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    fixture.placement.fail_remove.store(true, Ordering::SeqCst);
    let identity = command('9', "rollback_cleanup_retry");
    assert_eq!(
        fixture
            .coordinator
            .rollback(identity.clone(), service_id(), None),
        Err(NodeModelError::RecoveryRequired)
    );
    assert_eq!(
        fixture
            .journals
            .read(identity.operation_id())
            .expect("journal")
            .expect("pending rollback")
            .journal()
            .state(),
        NodeModelJournalState::CleanupPending
    );
    fixture.placement.fail_remove.store(false, Ordering::SeqCst);
    let recovered = fixture
        .coordinator
        .recover_pending()
        .expect("resident recovery");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].journal().journal().state(),
        NodeModelJournalState::RolledBack
    );
    assert_eq!(recovered[0].operation().state(), OperationState::Failed);
    assert_eq!(
        fixture.coordinator.list().expect("service")[0].placement_groups()[0]
            .group()
            .runtime(),
        &updated_runtime_identity()
    );
}

// Resumes a crash after retained rollback activation from the same durable journal and receipts.
#[test]
fn rollback_restart_replays_exact_retained_plan_to_terminal_success() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    fixture.runtime.select_update.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .update(update_request('8', "update_before_restart_rollback", false))
        .expect("update");
    fixture.runtime.fail_select.store(true, Ordering::SeqCst);
    fixture
        .placement
        .panic_start_after_commit
        .store(true, Ordering::SeqCst);
    let crashed = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = fixture
            .coordinator
            .rollback(command('9', "restart_rollback"), service_id(), None);
    }));
    assert!(crashed.is_err());
    let restarted = coordinator(
        fixture.state.clone(),
        fixture.runtime.clone(),
        fixture.placement.clone(),
        fixture.journals.clone(),
        20_000,
    );
    let recovered = restarted.recover_pending().expect("rollback recovery");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].journal().journal().action(),
        NodeModelAction::Rollback
    );
    assert_eq!(
        recovered[0].journal().journal().state(),
        NodeModelJournalState::Succeeded
    );
    assert_eq!(recovered[0].operation().state(), OperationState::Succeeded);
    assert_eq!(
        restarted.list().expect("service")[0].placement_groups()[0]
            .group()
            .runtime(),
        &runtime_identity()
    );
}

// Replays one terminal command without repeating any manager or provider mutation.
#[test]
fn install_terminal_replay_is_side_effect_free() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let first = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let provider_count = fixture.events.lock().expect("events").len();
    let state_count = fixture.state.events().len();
    let replay = fixture
        .coordinator
        .install(install_request())
        .expect("replay");
    assert_eq!(replay.journal(), first.journal());
    assert_eq!(fixture.events.lock().expect("events").len(), provider_count);
    assert_eq!(fixture.state.events().len(), state_count);
}

// Fails closed before manager mutation when the durable journal adapter is unavailable.
#[test]
fn install_journal_failure_precedes_every_manager_and_provider_mutation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(MockState::default());
    let runtime = Arc::new(MockRuntime::new(Arc::clone(&events)));
    let placement = Arc::new(MockPlacement::new(Arc::clone(&events)));
    let coordinator = coordinator(
        Arc::clone(&state),
        Arc::clone(&runtime),
        Arc::clone(&placement),
        Arc::new(UnavailableJournalStore),
        3_000,
    );
    assert_eq!(
        coordinator.install(install_request()),
        Err(NodeModelError::JournalUnavailable)
    );
    assert!(state.events().is_empty());
    assert!(state.services.lock().expect("services").is_empty());
    assert!(state.operations.lock().expect("operations").is_empty());
    assert!(runtime.installations().expect("installations").is_empty());
    assert!(placement.records().expect("placements").is_empty());
    assert!(events.lock().expect("events").is_empty());
}

// Resumes from every durable install journal boundary after simulated process death.
#[test]
fn install_restarts_after_every_durable_journal_boundary() {
    let cases = [
        (true, None, "command"),
        (false, Some(1), "executing"),
        (false, Some(2), "runtime pending"),
        (false, Some(3), "runtime created"),
        (false, Some(4), "group staged"),
        (false, Some(5), "journal succeeded"),
    ];
    for (panic_after_create, panic_after_replace, name) in cases {
        let directory = tempfile::tempdir().expect("directory");
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(
                directory.path().join("core.sqlite3"),
            ))
            .expect("database"),
        );
        let base_store = Arc::new(DatabaseNodeModelJournalStore::new(database));
        let events = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(MockState::default());
        let runtime = Arc::new(MockRuntime::new(Arc::clone(&events)));
        let placement = Arc::new(MockPlacement::new(events));
        let crashing = coordinator(
            Arc::clone(&state),
            Arc::clone(&runtime),
            Arc::clone(&placement),
            Arc::new(PanicJournalStore::new(
                base_store.clone(),
                panic_after_create,
                panic_after_replace,
            )),
            3_000,
        );
        let crashed = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = crashing.install(install_request());
        }));
        assert!(crashed.is_err(), "{name} boundary did not crash");
        let restarted = coordinator(state, runtime, placement, base_store, 10_000);
        let recovered = restarted.recover_pending().expect("recover pending");
        assert_eq!(recovered.len(), 1, "{name} recovery count");
        assert_eq!(
            recovered[0].journal().journal().state(),
            NodeModelJournalState::Succeeded,
            "{name} journal"
        );
        assert_eq!(
            recovered[0].operation().state(),
            OperationState::Succeeded,
            "{name} operation"
        );
        assert_eq!(
            recovered[0].service().desired_state(),
            ModelServiceDesiredState::Running,
            "{name} service"
        );
    }
}

// Recovers from process death immediately after each cross-manager mutation commits.
#[test]
fn install_restarts_after_every_manager_mutation_boundary() {
    enum CrashBoundary {
        ServiceCreate,
        RuntimeInstall,
        PlacementStage,
        PlacementStart,
        ServiceRunning,
    }

    let cases = [
        (CrashBoundary::ServiceCreate, "service create"),
        (CrashBoundary::RuntimeInstall, "runtime install"),
        (CrashBoundary::PlacementStage, "placement stage"),
        (CrashBoundary::PlacementStart, "placement start"),
        (CrashBoundary::ServiceRunning, "service running"),
    ];
    for (boundary, name) in cases {
        let directory = tempfile::tempdir().expect("directory");
        let fixture = fixture(&directory);
        match boundary {
            CrashBoundary::ServiceCreate => fixture
                .state
                .panic_after_service_create
                .store(true, Ordering::SeqCst),
            CrashBoundary::RuntimeInstall => fixture
                .runtime
                .panic_install_after_commit
                .store(true, Ordering::SeqCst),
            CrashBoundary::PlacementStage => fixture
                .placement
                .panic_stage_after_commit
                .store(true, Ordering::SeqCst),
            CrashBoundary::PlacementStart => fixture
                .placement
                .panic_start_after_commit
                .store(true, Ordering::SeqCst),
            CrashBoundary::ServiceRunning => fixture
                .state
                .panic_after_service_running
                .store(true, Ordering::SeqCst),
        }
        let crashed = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = fixture.coordinator.install(install_request());
        }));
        assert!(crashed.is_err(), "{name} boundary did not crash");
        let recovered = fixture
            .coordinator
            .recover_pending()
            .expect("recover pending");
        assert_eq!(recovered.len(), 1, "{name} recovery count");
        assert_eq!(
            recovered[0].journal().journal().state(),
            NodeModelJournalState::Succeeded,
            "{name} journal"
        );
        assert_eq!(
            recovered[0].service().desired_state(),
            ModelServiceDesiredState::Running,
            "{name} service"
        );
        assert_eq!(
            fixture
                .runtime
                .installations()
                .expect("installations")
                .len(),
            1,
            "{name} runtime count"
        );
        assert_eq!(
            fixture.placement.records().expect("placements").len(),
            1,
            "{name} placement count"
        );
    }
}

// Gives one concurrent caller the in-process execution claim and permits exact terminal replay.
#[test]
fn concurrent_same_command_has_one_winner_and_replays_after_completion() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let install_gate = fixture.runtime.block_next_install();
    let coordinator = Arc::new(fixture.coordinator);
    let executing = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || coordinator.install(install_request()))
    };
    install_gate.wait_until_entered();
    let duplicate = coordinator.install(install_request());
    install_gate.release();
    let completed = executing.join().expect("worker");
    assert_eq!(duplicate, Err(NodeModelError::JournalConflict));
    assert!(completed.is_ok());
    assert_eq!(fixture.runtime.install_calls(), 1);
    let replay = coordinator
        .install(install_request())
        .expect("terminal replay");
    assert_eq!(replay.operation().state(), OperationState::Succeeded);
}

// Accepts one provider response loss only after one authoritative installation reread.
#[test]
fn install_recovers_ambiguous_runtime_success_by_authoritative_reread() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .runtime
        .fail_install_after_commit
        .store(true, Ordering::SeqCst);
    let result = fixture
        .coordinator
        .install(install_request())
        .expect("install after lost response");
    assert_eq!(
        result.journal().journal().state(),
        NodeModelJournalState::Succeeded
    );
    assert_eq!(
        result.journal().journal().runtime_receipts()[0].disposition(),
        li_node_manager::NodeModelRuntimeDisposition::OwnershipUnknown
    );
    assert_eq!(fixture.runtime.install_calls(), 1);
}

// Never claims or deletes exact bytes whose concurrent acquisition ownership is ambiguous.
#[test]
fn ambiguous_runtime_acquisition_is_never_compensated_as_command_owned() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .runtime
        .fail_install_after_commit
        .store(true, Ordering::SeqCst);
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .install(install_request())
        .expect_err("start failure after ambiguous acquisition");
    let installations = fixture.runtime.installations().expect("installations");
    assert_eq!(installations.len(), 1);
    assert_eq!(
        installations[0].installation().state(),
        RuntimeInstallationState::Available
    );
    assert!(!fixture
        .events
        .lock()
        .expect("events")
        .contains(&"runtime.remove".to_string()));
}

// Accepts one PlacementManager stage response loss only after exact aggregate reread.
#[test]
fn install_recovers_ambiguous_stage_success_by_authoritative_reread() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .placement
        .fail_stage_after_commit
        .store(true, Ordering::SeqCst);
    let result = fixture
        .coordinator
        .install(install_request())
        .expect("install after lost stage response");
    assert_eq!(result.service().placement_group_ids().len(), 1);
    assert_eq!(fixture.placement.stage_calls(), 1);
}

// Reverses staged ownership and command-created bytes after start failure.
#[test]
fn install_failure_compensates_group_service_and_created_runtime() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .coordinator
            .install(install_request())
            .expect_err("start failure"),
        NodeModelError::Placement(PlacementError::ExecutionUnavailable)
    );
    let service = fixture
        .state
        .service(&service_id())
        .expect("service after compensation");
    assert_eq!(
        service.service().desired_state(),
        ModelServiceDesiredState::Removed
    );
    assert!(service.service().placement_group_ids().is_empty());
    let installations = fixture.runtime.installations().expect("installations");
    assert_eq!(installations.len(), 1);
    assert_eq!(
        installations[0].installation().state(),
        RuntimeInstallationState::Removed
    );
    assert!(fixture
        .events
        .lock()
        .expect("events")
        .contains(&"placement.remove".to_string()));
}

// Reuses existing immutable bytes and never removes them during compensation.
#[test]
fn install_compensation_never_removes_reused_runtime() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let reused = installation('5', RuntimeInstallationState::Available);
    fixture.runtime.insert(reused.clone());
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    fixture
        .coordinator
        .install(install_request())
        .expect_err("start failure");
    assert_eq!(fixture.runtime.install_calls(), 0);
    assert_eq!(
        fixture
            .runtime
            .installation(reused.installation_id())
            .expect("runtime")
            .expect("reused")
            .installation()
            .state(),
        RuntimeInstallationState::Available
    );
    assert!(!fixture
        .events
        .lock()
        .expect("events")
        .contains(&"runtime.remove".to_string()));
}

// Persists incomplete cleanup and retries it automatically during resident recovery.
#[test]
fn cleanup_pending_survives_failure_and_daemon_recovery_completes_it() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture.placement.fail_start.store(true, Ordering::SeqCst);
    fixture.placement.fail_remove.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .coordinator
            .install(install_request())
            .expect_err("cleanup pending"),
        NodeModelError::RecoveryRequired
    );
    let pending = fixture
        .journals
        .read(command('7', "install_model").operation_id())
        .expect("read")
        .expect("pending");
    assert_eq!(
        pending.journal().state(),
        NodeModelJournalState::CleanupPending
    );
    fixture.placement.fail_remove.store(false, Ordering::SeqCst);
    fixture.placement.fail_start.store(false, Ordering::SeqCst);
    let recovered = fixture
        .coordinator
        .recover_pending()
        .expect("resident recovery");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].journal().journal().state(),
        NodeModelJournalState::RolledBack
    );
    let source = fixture
        .journals
        .read(pending.journal().operation_id())
        .expect("read")
        .expect("source");
    assert_eq!(source.journal().state(), NodeModelJournalState::RolledBack);
    assert_eq!(recovered[0].operation().state(), OperationState::Failed);
    assert_eq!(fixture.journals.all().expect("journals").len(), 1);
}

// Keeps command-created bytes while any other non-removed group still references them.
#[test]
fn remove_never_deletes_runtime_referenced_by_another_group() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let installation = fixture.runtime.installations().expect("installations")[0]
        .installation()
        .clone();
    let other_service = ModelServiceId::parse(&identity('e')).expect("other service");
    let other_group = PlacementGroupId::parse(&identity('f')).expect("external group");
    let request = TestPlacementRequests
        .request(&other_service, 0, &other_group, &[installation.clone()])
        .expect("external request");
    fixture
        .placement
        .insert(request, other_group, PlacementGroupState::Running);
    fixture
        .coordinator
        .remove(NodeModelRemoveRequest::new(
            command('a', "remove_model"),
            service_id(),
            NodeModelRemovalSelection::All,
            NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
        ))
        .expect("remove service");
    assert_eq!(
        fixture
            .runtime
            .installation(installation.installation_id())
            .expect("runtime")
            .expect("installation")
            .installation()
            .state(),
        RuntimeInstallationState::Available
    );
}

// Removes every placement and runtime record while retaining models through RuntimeManager.
#[test]
fn remove_preserves_runtime_installations_and_binds_retention_into_replay() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let installation_id = fixture.runtime.installations().expect("installations")[0]
        .installation()
        .installation_id()
        .clone();
    fixture.events.lock().expect("events").clear();
    let request = NodeModelRemoveRequest::new(
        command('a', "remove_model_preserving_runtime"),
        service_id(),
        NodeModelRemovalSelection::All,
        NodeModelRemovalRetention::PreserveModels,
    );

    let removed = fixture
        .coordinator
        .remove(request.clone())
        .expect("remove while preserving runtime");

    assert_eq!(
        removed.journal().journal().removal_runtime_retention(),
        NodeModelRemovalRetention::PreserveModels
    );
    assert_eq!(
        fixture
            .runtime
            .installation(&installation_id)
            .expect("runtime")
            .expect("installation")
            .installation()
            .state(),
        RuntimeInstallationState::Removed
    );
    assert!(fixture
        .events
        .lock()
        .expect("events")
        .contains(&"runtime.remove_preserving_models".to_string()));
    let event_count = fixture.events.lock().expect("events").len();
    fixture
        .coordinator
        .remove(request.clone())
        .expect("exact terminal replay");
    assert_eq!(fixture.events.lock().expect("events").len(), event_count);
    assert_eq!(
        fixture
            .coordinator
            .remove(NodeModelRemoveRequest::new(
                request.identity().clone(),
                service_id(),
                NodeModelRemovalSelection::All,
                NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            ))
            .expect_err("retention drift"),
        NodeModelError::JournalConflict
    );
}

// Pauses, resumes, and removes one exact service through stable manager order.
#[test]
fn existing_service_lifecycle_orders_pause_resume_and_remove() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let installation_id = fixture.runtime.installations().expect("installations")[0]
        .installation()
        .installation_id()
        .clone();
    fixture.events.lock().expect("events").clear();
    fixture
        .coordinator
        .pause(command('8', "pause_model"), service_id())
        .expect("pause");
    assert_eq!(
        fixture
            .state
            .service(&service_id())
            .expect("service")
            .service()
            .desired_state(),
        ModelServiceDesiredState::Stopped
    );
    fixture
        .coordinator
        .resume(command('9', "resume_model"), service_id())
        .expect("resume");
    fixture
        .coordinator
        .remove(NodeModelRemoveRequest::new(
            command('a', "remove_model"),
            service_id(),
            NodeModelRemovalSelection::All,
            NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
        ))
        .expect("remove");
    assert_eq!(
        fixture
            .state
            .service(&service_id())
            .expect("service")
            .service()
            .desired_state(),
        ModelServiceDesiredState::Removed
    );
    assert!(fixture
        .events
        .lock()
        .expect("events")
        .windows(4)
        .any(|events| events
            == [
                "placement.stop",
                "placement.start",
                "placement.stop",
                "placement.remove"
            ]));
    assert_eq!(
        installed.service().service_id(),
        fixture
            .state
            .service(&service_id())
            .expect("service")
            .service()
            .service_id()
    );
    assert_eq!(
        fixture
            .runtime
            .installation(&installation_id)
            .expect("runtime")
            .expect("installation")
            .installation()
            .state(),
        RuntimeInstallationState::Removed
    );
}

// Removes only groups intersecting selected nodes and binds replay to that exact selection.
#[test]
fn partial_remove_preserves_other_groups_and_rejects_identity_drift() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture
        .coordinator
        .install(
            NodeModelInstallRequest::new(
                command('c', "install_replicas"),
                service_id(),
                logical_model(),
                vec![
                    NodeModelInstallGroup::new(vec![node_id()], None).expect("first group"),
                    NodeModelInstallGroup::new(vec![other_node_id()], None).expect("second group"),
                ],
            )
            .expect("install request"),
        )
        .expect("install replicas");
    let before = fixture.state.service(&service_id()).expect("service");
    assert_eq!(before.service().placement_group_ids().len(), 2);
    let retained = before.service().placement_group_ids()[1].clone();
    let request = NodeModelRemoveRequest::new(
        command('d', "remove_first_node"),
        service_id(),
        NodeModelRemovalSelection::nodes(vec![node_id()]).expect("selection"),
        NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
    );
    let removed = fixture
        .coordinator
        .remove(request.clone())
        .expect("partial remove");
    assert_eq!(
        removed.service().desired_state(),
        ModelServiceDesiredState::Running
    );
    assert_eq!(removed.service().placement_group_ids(), &[retained]);
    assert_eq!(removed.journal().journal().removal_node_ids(), &[node_id()]);
    let event_count = fixture.events.lock().expect("events").len();
    fixture
        .coordinator
        .remove(request)
        .expect("terminal replay");
    assert_eq!(fixture.events.lock().expect("events").len(), event_count);
    assert_eq!(
        fixture
            .coordinator
            .remove(NodeModelRemoveRequest::new(
                command('d', "remove_first_node"),
                service_id(),
                NodeModelRemovalSelection::nodes(vec![other_node_id()]).expect("selection"),
                NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            ))
            .expect_err("selection drift"),
        NodeModelError::JournalConflict
    );
}

// Restarts through an exact stop/start pair and recovers degraded state with acknowledgement.
#[test]
fn restart_and_recover_use_exact_group_lifecycle_contracts() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let placement_group_id = installed.service().placement_group_ids()[0].clone();
    fixture.events.lock().expect("events").clear();
    fixture
        .coordinator
        .restart(command('c', "restart_model"), service_id())
        .expect("restart");
    assert_eq!(
        fixture.events.lock().expect("events").as_slice(),
        ["placement.stop", "placement.start"]
    );
    fixture
        .placement
        .transition(&placement_group_id, PlacementGroupState::Degraded)
        .expect("degrade");
    fixture.events.lock().expect("events").clear();
    fixture
        .coordinator
        .recover(command('d', "recover_model"), service_id())
        .expect("recover");
    assert_eq!(
        fixture.events.lock().expect("events").as_slice(),
        ["placement.recover.true"]
    );
}

// Fails closed when an exact placement projection loses its runtime installation.
#[test]
fn list_fails_closed_on_dangling_runtime_reference() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let installed = fixture
        .coordinator
        .install(install_request())
        .expect("install");
    let installation_id = fixture.coordinator.list().expect("list")[0].installations()[0]
        .installation_id()
        .clone();
    fixture
        .runtime
        .installations
        .lock()
        .expect("installations")
        .remove(installation_id.as_str());
    assert_eq!(
        fixture.coordinator.list(),
        Err(NodeModelError::RecoveryRequired)
    );
    assert_eq!(installed.service().placement_group_ids().len(), 1);
}

// Reopens a terminal journal and preserves its exact command and receipts.
#[test]
fn database_journal_reopens_exact_terminal_command() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let expected = fixture
        .coordinator
        .install(install_request())
        .expect("install")
        .journal()
        .clone();
    drop(fixture);
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("reopen database"),
    );
    let store = DatabaseNodeModelJournalStore::new(database);
    let observed = store
        .read(expected.journal().operation_id())
        .expect("read")
        .expect("journal");
    assert_eq!(observed, expected);
    assert_eq!(observed.journal().runtime_receipts().len(), 1);
    assert_eq!(observed.journal().placement_group_ids().len(), 1);
}

// Accepts an exact database replay only while its authoritative revision remains current.
#[test]
fn database_journal_replace_replay_requires_exact_current_commit() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let terminal = fixture
        .coordinator
        .install(install_request())
        .expect("install")
        .journal()
        .clone();
    let first = fixture
        .journals
        .replace(terminal.journal().clone(), terminal.revision())
        .expect("first replacement");
    let replay = fixture
        .journals
        .replace(terminal.journal().clone(), terminal.revision())
        .expect("exact replay");
    assert_eq!(replay, first);
    let advanced = fixture
        .journals
        .replace(first.journal().clone(), first.revision())
        .expect("later replacement");
    assert_eq!(advanced.revision(), first.revision() + 1);
    assert_eq!(
        fixture
            .journals
            .replace(terminal.journal().clone(), terminal.revision()),
        Err(NodeModelError::JournalConflict)
    );
}

// Rejects a semantically corrupt private journal instead of projecting partial state.
#[test]
fn database_journal_fails_closed_on_corrupt_runtime_disposition() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let operation_id = fixture
        .coordinator
        .install(install_request())
        .expect("install")
        .journal()
        .journal()
        .operation_id()
        .clone();
    drop(fixture);
    let connection = Connection::open(directory.path().join("core.sqlite3")).expect("SQLite");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
            params!["model_lifecycles", operation_id.as_str()],
            |row| row.get(0),
        )
        .expect("payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    value["runtime_receipts"][0]["disposition"] = serde_json::json!("unknown");
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&value).expect("encoded"),
                "model_lifecycles",
                operation_id.as_str()
            ],
        )
        .expect("corrupt payload");
    drop(connection);
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("reopen database"),
    );
    assert_eq!(
        DatabaseNodeModelJournalStore::new(database).read(&operation_id),
        Err(NodeModelError::JournalCorrupt)
    );
}

// Rejects production-relevant journal mutations across every closed identity and phase invariant.
#[test]
fn database_journal_mutation_matrix_fails_closed() {
    type Mutation = fn(&mut serde_json::Value);
    let cases: [(&str, Mutation); 22] = [
        ("unknown field", |value| {
            value["extra"] = serde_json::json!(true)
        }),
        ("unknown action", |value| {
            value["action"] = serde_json::json!("unknown")
        }),
        ("unknown state", |value| {
            value["state"] = serde_json::json!("unknown")
        }),
        ("unknown runtime retention", |value| {
            value["removal_runtime_retention"] = serde_json::json!("unknown")
        }),
        ("action owns wrong fields", |value| {
            value["action"] = serde_json::json!("pause")
        }),
        ("zero created time", |value| {
            value["created_at_unix_milliseconds"] = serde_json::json!(0)
        }),
        ("backwards time", |value| {
            value["updated_at_unix_milliseconds"] = serde_json::json!(1)
        }),
        ("missing install groups", |value| {
            value["install_groups"] = serde_json::json!([])
        }),
        ("too many install groups", |value| {
            let group = value["install_groups"][0].clone();
            value["install_groups"] = serde_json::Value::Array(vec![group; 129]);
        }),
        ("duplicate group node", |value| {
            let node = value["install_groups"][0]["node_ids"][0].clone();
            value["install_groups"][0]["node_ids"] = serde_json::json!([node.clone(), node]);
        }),
        ("receipt missing installation", |value| {
            value["runtime_receipts"][0]["installation_id"] = serde_json::Value::Null
        }),
        ("pending receipt has installation", |value| {
            value["runtime_receipts"][0]["disposition"] = serde_json::json!("install_pending")
        }),
        ("receipt group outside plan", |value| {
            value["runtime_receipts"][0]["group_index"] = serde_json::json!(1)
        }),
        ("duplicate receipt", |value| {
            let receipt = value["runtime_receipts"][0].clone();
            value["runtime_receipts"] = serde_json::json!([receipt.clone(), receipt]);
        }),
        ("duplicate placement group", |value| {
            let group = value["placement_group_ids"][0].clone();
            value["placement_group_ids"] = serde_json::json!([group.clone(), group]);
        }),
        ("missing planned placement group", |value| {
            value["planned_group_ids"] = serde_json::json!([])
        }),
        ("substituted planned placement group", |value| {
            value["planned_group_ids"][0] = serde_json::json!(identity('e'))
        }),
        ("committed group differs from plan", |value| {
            value["placement_group_ids"][0] = serde_json::json!(identity('e'))
        }),
        ("invalid placement identity", |value| {
            value["placement_group_ids"][0] = serde_json::json!("invalid")
        }),
        ("install rollback target", |value| {
            value["rollback_target_id"] = serde_json::json!("dgx-spark")
        }),
        ("terminal failure code", |value| {
            value["failure_code"] = serde_json::json!("unexpected_failure")
        }),
        ("cleanup lacks failure", |value| {
            value["state"] = serde_json::json!("cleanup_pending")
        }),
    ];
    for (name, mutate) in cases {
        let directory = tempfile::tempdir().expect("directory");
        let fixture = fixture(&directory);
        let operation_id = fixture
            .coordinator
            .install(install_request())
            .expect("install")
            .journal()
            .journal()
            .operation_id()
            .clone();
        drop(fixture);
        let path = directory.path().join("core.sqlite3");
        let connection = Connection::open(&path).expect("SQLite");
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["model_lifecycles", operation_id.as_str()],
                |row| row.get(0),
            )
            .expect("payload");
        let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
        mutate(&mut value);
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
                params![
                    serde_json::to_vec(&value).expect("encoded"),
                    "model_lifecycles",
                    operation_id.as_str()
                ],
            )
            .expect("mutate payload");
        drop(connection);
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(path)).expect("reopen database"),
        );
        assert_eq!(
            DatabaseNodeModelJournalStore::new(database).read(&operation_id),
            Err(NodeModelError::JournalCorrupt),
            "{name}"
        );
    }
}

// Rejects every retained-runtime restoration identity and topology mutation on database reopen.
#[test]
fn database_retained_update_journal_mutation_matrix_fails_closed() {
    type Mutation = fn(&mut serde_json::Value);
    let cases: [(&str, Mutation); 7] = [
        ("missing retained group", |value| {
            value["retained_groups"] = serde_json::json!([])
        }),
        ("invalid restoration identity", |value| {
            value["retained_groups"][0]["restoration_group_id"] = serde_json::json!("invalid")
        }),
        ("substituted restoration identity", |value| {
            value["retained_groups"][0]["restoration_group_id"] = serde_json::json!(identity('e'))
        }),
        ("source equals restoration", |value| {
            value["retained_groups"][0]["source_group_id"] =
                value["retained_groups"][0]["restoration_group_id"].clone()
        }),
        ("substituted retained node", |value| {
            value["retained_groups"][0]["nodes"][0]["node_id"] = serde_json::json!(identity('a'))
        }),
        ("mismatched retained state", |value| {
            value["retained_groups"][0]["initial_state"] = serde_json::json!("stopped")
        }),
        ("invalid retained installation", |value| {
            value["retained_groups"][0]["nodes"][0]["installation_id"] =
                serde_json::json!("invalid")
        }),
    ];
    for (name, mutate) in cases {
        let directory = tempfile::tempdir().expect("directory");
        let fixture = fixture(&directory);
        fixture
            .coordinator
            .install(install_request())
            .expect("install");
        fixture.runtime.select_update.store(true, Ordering::SeqCst);
        let request = update_request('8', "retained_update", false);
        fixture.coordinator.update(request.clone()).expect("update");
        let operation_id = request.identity().operation_id().clone();
        drop(fixture);
        let path = directory.path().join("core.sqlite3");
        let connection = Connection::open(&path).expect("SQLite");
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["model_lifecycles", operation_id.as_str()],
                |row| row.get(0),
            )
            .expect("payload");
        let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
        mutate(&mut value);
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
                params![
                    serde_json::to_vec(&value).expect("encoded"),
                    "model_lifecycles",
                    operation_id.as_str()
                ],
            )
            .expect("mutate payload");
        drop(connection);
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(path)).expect("reopen database"),
        );
        assert_eq!(
            DatabaseNodeModelJournalStore::new(database).read(&operation_id),
            Err(NodeModelError::JournalCorrupt),
            "{name}"
        );
    }
}

// Rejects a future private journal record version before decoding its payload.
#[test]
fn database_journal_rejects_future_record_version() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let operation_id = fixture
        .coordinator
        .install(install_request())
        .expect("install")
        .journal()
        .journal()
        .operation_id()
        .clone();
    drop(fixture);
    let path = directory.path().join("core.sqlite3");
    let connection = Connection::open(&path).expect("SQLite");
    connection
        .execute(
            "UPDATE li_database_records SET record_version = 2 WHERE collection = ?1 AND identifier = ?2",
            params!["model_lifecycles", operation_id.as_str()],
        )
        .expect("future version");
    drop(connection);
    let database =
        Arc::new(DatabaseManager::open(DatabaseConfiguration::new(path)).expect("reopen database"));
    assert_eq!(
        DatabaseNodeModelJournalStore::new(database).read(&operation_id),
        Err(NodeModelError::JournalCorrupt)
    );
}
