// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_benchmark_manager::BenchmarkSubject;
use li_core_interface::{
    HardwareObservation, InstallationId, InterconnectKind, InterconnectRequirement,
    LogicalModelName, ModelService, ModelServiceDesiredState, ModelServiceId, NodeId, Operation,
    OperationId, OperationKind, OperationTarget, PlacementGroupCapacity, PlacementGroupId,
    PortRange, RuntimeCandidateId, RuntimeInstallation, RuntimeInstallationId, Sha256Digest,
    UnixMilliseconds,
};
use li_database::DatabaseError;
use li_placement_manager::{
    PlacementError, PlacementLogBatch, PlacementLogReadRequest, PlacementManager,
    PlacementNodeResources, PlacementRecord, PlacementRequest, PlacementStore, PlacementTask,
    VersionedPlacementRecord,
};
use li_runtime_manager::{
    RuntimeCandidate, RuntimeError, RuntimeExactCandidateArtifacts,
    RuntimeExecutionManifestProvider, RuntimeInstallationStore, RuntimeManager,
    VersionedRuntimeInstallation,
};

use crate::li_node_model_contract::{
    NodeModelClock, NodeModelError, NodeModelHardwareProvider, NodeModelPlacementPort,
    NodeModelPlacementRecordProvider, NodeModelPlacementRequestProvider, NodeModelRuntimePort,
    NodeModelStatePort, VersionedNodeModelOperation, VersionedNodeModelService,
};
use crate::{
    NodeBenchmarkCandidateHandoffError, NodeBenchmarkCandidateRuntimePort, NodeManager,
    NodeManagerError, OperationCompletion,
};

// Supplies wall-clock time only through the model lifecycle clock capability.
#[derive(Default)]
pub struct SystemNodeModelClock;

impl NodeModelClock for SystemNodeModelClock {
    // Returns current Unix milliseconds without truncating or wrapping native time.
    fn now(&self) -> Result<UnixMilliseconds, NodeModelError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NodeModelError::ProviderUnavailable)?;
        let milliseconds =
            u64::try_from(elapsed.as_millis()).map_err(|_| NodeModelError::ProviderUnavailable)?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Converts verified runtime task contracts and authenticated Node state into placement requests.
pub struct NativeNodeModelPlacementRequestProvider {
    nodes: Arc<NodeManager>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
    first_port: u16,
    port_count: u16,
}

impl NativeNodeModelPlacementRequestProvider {
    // Creates one explicit local resource envelope without discovering or reserving hidden ports.
    pub fn new(
        nodes: Arc<NodeManager>,
        executions: Arc<dyn RuntimeExecutionManifestProvider>,
        first_port: u16,
        port_count: u16,
    ) -> Result<Self, NodeModelError> {
        PortRange::new(first_port, port_count).map_err(|_| NodeModelError::ProviderUnavailable)?;
        Ok(Self {
            nodes,
            executions,
            first_port,
            port_count,
        })
    }
}

impl NodeModelPlacementRequestProvider for NativeNodeModelPlacementRequestProvider {
    // Builds one single-node request from an exact installed runtime and current hardware snapshot.
    fn request(
        &self,
        service_id: &ModelServiceId,
        group_index: usize,
        placement_group_id: &PlacementGroupId,
        installations: &[RuntimeInstallation],
    ) -> Result<PlacementRequest, NodeModelError> {
        if installations.len() != 1 {
            return Err(NodeModelError::InvalidRequest {
                reason: "native placement groups require exactly one runtime installation",
            });
        }
        let installation = &installations[0];
        let manifest = self.executions.manifest(installation.installation_id())?;
        if manifest.installation_id() != installation.installation_id()
            || manifest.logical_model() != installation.logical_model()
            || manifest.tasks().len() != 1
            || group_index > u16::MAX as usize
        {
            return Err(NodeModelError::ProviderUnavailable);
        }
        let task = &manifest.tasks()[0];
        if task.port_count() > self.port_count {
            return Err(NodeModelError::InvalidRequest {
                reason: "runtime task exceeds the configured placement port envelope",
            });
        }
        let node = self.nodes.node(installation.node_id())?;
        let observation = self.nodes.observation(installation.node_id())?;
        let device_ids = observation
            .accelerators()
            .iter()
            .take(usize::from(task.device_count()))
            .map(|accelerator| accelerator.device_id().clone())
            .collect::<Vec<_>>();
        if device_ids.len() != usize::from(task.device_count()) {
            return Err(NodeModelError::InvalidRequest {
                reason: "runtime task exceeds the observed accelerator envelope",
            });
        }
        let capacity = PlacementGroupCapacity::new(
            manifest.serving().max_connections(),
            manifest.serving().max_active_requests(),
            manifest.serving().max_context_tokens(),
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .map_err(|_| NodeModelError::ProviderUnavailable)?;
        let resources = PlacementNodeResources::new(
            installation.node_id().clone(),
            installation.installation_id().clone(),
            observation.observation_id().clone(),
            observation.boot_id().clone(),
            observation.observed_at(),
            node.value().control_address().clone(),
            device_ids,
            PortRange::new(self.first_port, self.port_count)
                .map_err(|_| NodeModelError::ProviderUnavailable)?,
            None,
        )?;
        PlacementRequest::new(
            placement_group_id.clone(),
            service_id.clone(),
            installation.runtime().clone(),
            capacity,
            vec![PlacementTask::new(
                task.task_id().clone(),
                task.device_count(),
                task.port_count(),
            )?],
            vec![resources],
            task.task_id().clone(),
            installation.node_id().clone(),
            manifest.startup_order().to_vec(),
            Vec::new(),
        )
        .map_err(NodeModelError::from)
    }
}

impl NodeModelHardwareProvider for NodeManager {
    // Returns the current durable observation for the exact authenticated node identity.
    fn observation(&self, node_id: &NodeId) -> Result<HardwareObservation, NodeModelError> {
        self.hardware_observation(node_id)?
            .ok_or(NodeModelError::ProviderUnavailable)
    }
}

// Composes ordinary PlacementManager calls with its authoritative projection store.
pub struct ManagedNodeModelPlacementPort {
    manager: Arc<PlacementManager>,
    store: Arc<dyn PlacementStore>,
    records: Arc<dyn NodeModelPlacementRecordProvider>,
}

impl ManagedNodeModelPlacementPort {
    // Creates one manager port without transferring manager or store ownership.
    pub const fn new(
        manager: Arc<PlacementManager>,
        store: Arc<dyn PlacementStore>,
        records: Arc<dyn NodeModelPlacementRecordProvider>,
    ) -> Self {
        Self {
            manager,
            store,
            records,
        }
    }
}

impl NodeModelPlacementPort for ManagedNodeModelPlacementPort {
    // Stages through ordinary PlacementManager lifecycle code.
    fn stage(&self, request: PlacementRequest) -> Result<VersionedPlacementRecord, PlacementError> {
        self.manager
            .stage(request)
            .map(|change| change.record().clone())
    }

    // Starts through ordinary PlacementManager lifecycle code.
    fn start(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.manager
            .start(placement_group_id)
            .map(|change| change.record().clone())
    }

    // Stops through ordinary PlacementManager lifecycle code.
    fn stop(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.manager
            .stop(placement_group_id)
            .map(|change| change.record().clone())
    }

    // Recovers through ordinary PlacementManager lifecycle code.
    fn recover(
        &self,
        placement_group_id: &PlacementGroupId,
        acknowledge_protection_trips: bool,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.manager
            .recover(placement_group_id, acknowledge_protection_trips)
            .map(|change| change.record().clone())
    }

    // Removes through ordinary PlacementManager lifecycle code.
    fn remove(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.manager
            .remove(placement_group_id)
            .map(|change| change.record().clone())
    }

    // Reads one aggregate directly from the manager's authoritative store.
    fn record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError> {
        self.store.read(placement_group_id)
    }

    // Reads every aggregate through the concrete projection provider.
    fn records(&self) -> Result<Vec<PlacementRecord>, PlacementError> {
        self.records.records()
    }

    // Reads one bounded opaque runtime-log batch through PlacementManager ownership.
    fn read_logs(
        &self,
        request: PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError> {
        self.manager.read_logs(request)
    }
}

// Composes ordinary RuntimeManager calls with its authoritative installation store.
pub struct ManagedNodeModelRuntimePort {
    manager: Arc<RuntimeManager>,
    store: Arc<dyn RuntimeInstallationStore>,
}

impl ManagedNodeModelRuntimePort {
    // Creates one manager port without transferring manager or store ownership.
    pub const fn new(
        manager: Arc<RuntimeManager>,
        store: Arc<dyn RuntimeInstallationStore>,
    ) -> Self {
        Self { manager, store }
    }
}

impl NodeModelRuntimePort for ManagedNodeModelRuntimePort {
    // Selects through ordinary RuntimeManager compatibility code.
    fn select(
        &self,
        model: &LogicalModelName,
        explicit_candidate_id: Option<&RuntimeCandidateId>,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeCandidate, RuntimeError> {
        self.manager.select(model, explicit_candidate_id, hardware)
    }

    // Installs one candidate pinned by its exact selected identity.
    fn install(
        &self,
        node_id: NodeId,
        model: &LogicalModelName,
        candidate_id: &RuntimeCandidateId,
        hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.manager
            .install(node_id, model, Some(candidate_id), hardware)
            .map(|change| change.installation().clone())
    }

    // Removes through ordinary RuntimeManager lifecycle code.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.manager
            .remove(installation_id)
            .map(|change| change.installation().clone())
    }

    // Retains verified model bytes through RuntimeManager's selective removal lifecycle.
    fn remove_preserving_models(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        self.manager
            .remove_preserving_models(installation_id)
            .map(|change| change.installation().clone())
    }

    // Reads one exact authoritative installation.
    fn installation(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        self.store.read(installation_id)
    }

    // Reads every authoritative installation.
    fn installations(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        self.store.all()
    }
}

impl NodeBenchmarkCandidateRuntimePort for ManagedNodeModelRuntimePort {
    // Installs one preparation-trusted closure without invoking catalog selection.
    fn install_exact_candidate(
        &self,
        node_id: NodeId,
        installation_id: RuntimeInstallationId,
        candidate: RuntimeCandidate,
        artifacts: RuntimeExactCandidateArtifacts,
        hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, NodeBenchmarkCandidateHandoffError> {
        self.manager
            .install_exact_candidate(node_id, installation_id, candidate, artifacts, hardware)
            .map(|change| change.installation().clone())
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)
    }

    // Resolves benchmark and target contract identities from the exact verified execution manifest.
    fn benchmark_subject(
        &self,
        core_installation_id: &InstallationId,
        candidate_installation_id: &RuntimeInstallationId,
        candidate_group_id: &PlacementGroupId,
        expected_execution_sha256: &Sha256Digest,
    ) -> Result<BenchmarkSubject, NodeBenchmarkCandidateHandoffError> {
        let installation = self
            .store
            .read(candidate_installation_id)
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?
            .filter(|versioned| {
                versioned.installation().state()
                    == li_core_interface::RuntimeInstallationState::Available
            })
            .ok_or(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?;
        if installation
            .installation()
            .runtime()
            .execution_contract_digest()
            != expected_execution_sha256
        {
            return Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable);
        }
        let manifest = self
            .manager
            .execution_manifest(candidate_installation_id)
            .map_err(|_| NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?;
        let benchmark = manifest
            .benchmark()
            .ok_or(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)?;
        if manifest.installation_id() != candidate_installation_id
            || manifest.logical_model() != installation.installation().logical_model()
        {
            return Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable);
        }
        Ok(BenchmarkSubject::new(
            core_installation_id.clone(),
            candidate_installation_id.clone(),
            manifest.logical_model().clone(),
            candidate_group_id.clone(),
            expected_execution_sha256.clone(),
            benchmark.contract_sha256().clone(),
            benchmark.target_contract_sha256().clone(),
        ))
    }
}

impl NodeModelStatePort for NodeManager {
    // Returns durable services through ordinary NodeManager state code.
    fn services(&self) -> Result<Vec<ModelService>, NodeManagerError> {
        self.model_services()
    }

    // Returns one exact service and its optimistic revision.
    fn service(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.model_service(service_id)
            .map(|change| VersionedNodeModelService::new(change.value().clone(), change.revision()))
    }

    // Creates one service through ordinary NodeManager state code.
    fn create_service(
        &self,
        idempotency_key: &str,
        service: ModelService,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.create_model_service(idempotency_key, service)
            .map(|change| VersionedNodeModelService::new(change.value().clone(), change.revision()))
    }

    // Attaches one group through ordinary NodeManager state code.
    fn attach_group(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.attach_placement_group(
            idempotency_key,
            service_id,
            placement_group_id,
            expected_revision,
            updated_at,
        )
        .map(|change| VersionedNodeModelService::new(change.value().clone(), change.revision()))
    }

    // Detaches one group through ordinary NodeManager state code.
    fn detach_group(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: &PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.detach_placement_group(
            idempotency_key,
            service_id,
            placement_group_id,
            expected_revision,
            updated_at,
        )
        .map(|change| VersionedNodeModelService::new(change.value().clone(), change.revision()))
    }

    // Applies one service transition through ordinary NodeManager state code.
    fn transition_service(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        desired_state: ModelServiceDesiredState,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError> {
        self.transition_model_service(
            idempotency_key,
            service_id,
            desired_state,
            expected_revision,
            updated_at,
        )
        .map(|change| VersionedNodeModelService::new(change.value().clone(), change.revision()))
    }

    // Returns one exact operation with its optimistic revision.
    fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<VersionedNodeModelOperation>, NodeManagerError> {
        match self.operation_change(operation_id) {
            Ok(change) => Ok(Some(VersionedNodeModelOperation::new(
                change.value().clone(),
                change.revision(),
            ))),
            Err(NodeManagerError::Database(DatabaseError::NotFound { .. })) => Ok(None),
            Err(error) => Err(error),
        }
    }

    // Returns every operation through ordinary NodeManager state code.
    fn operations(&self) -> Result<Vec<Operation>, NodeManagerError> {
        NodeManager::operations(self)
    }

    // Begins one operation through ordinary NodeManager state code.
    fn begin_operation(
        &self,
        idempotency_key: &str,
        operation_id: OperationId,
        kind: OperationKind,
        target: OperationTarget,
        created_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        NodeManager::begin_operation(
            self,
            idempotency_key,
            operation_id,
            kind,
            target,
            created_at,
        )
        .map(|change| VersionedNodeModelOperation::new(change.value().clone(), change.revision()))
    }

    // Starts one operation through ordinary NodeManager state code.
    fn start_operation(
        &self,
        idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        started_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        NodeManager::start_operation(
            self,
            idempotency_key,
            operation_id,
            expected_revision,
            started_at,
        )
        .map(|change| VersionedNodeModelOperation::new(change.value().clone(), change.revision()))
    }

    // Completes one operation through ordinary NodeManager state code.
    fn complete_operation(
        &self,
        idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        completion: OperationCompletion,
        completed_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError> {
        NodeManager::complete_operation(
            self,
            idempotency_key,
            operation_id,
            expected_revision,
            completion,
            completed_at,
        )
        .map(|change| VersionedNodeModelOperation::new(change.value().clone(), change.revision()))
    }
}

impl NodeModelPlacementRecordProvider for crate::DatabasePlacementStore {
    // Returns every validated placement aggregate through its database adapter.
    fn records(&self) -> Result<Vec<PlacementRecord>, PlacementError> {
        crate::DatabasePlacementStore::records(self)
    }
}
