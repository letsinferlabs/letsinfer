// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::li_node_model_contract::{
    planned_placement_group_id, planned_restoration_group_id, NodeModelAction, NodeModelApiPort,
    NodeModelClock, NodeModelCommandIdentity, NodeModelCommandResult, NodeModelCommandSummary,
    NodeModelError, NodeModelHardwareProvider, NodeModelInstallGroup, NodeModelInstallRequest,
    NodeModelJournal, NodeModelJournalState, NodeModelJournalStore, NodeModelLogProjection,
    NodeModelLogSummary, NodeModelPlacementPort, NodeModelPlacementRequestProvider,
    NodeModelRemovalRetention, NodeModelRemovalSelection, NodeModelRemoveRequest,
    NodeModelRetainedGroup, NodeModelRetainedNode, NodeModelRollbackGroupPreview,
    NodeModelRollbackPreview, NodeModelRollbackRuntime, NodeModelRuntimeDisposition,
    NodeModelRuntimeLogBatch, NodeModelRuntimeLogRequest, NodeModelRuntimePort,
    NodeModelRuntimeReceipt, NodeModelServiceProjection, NodeModelServiceSummary,
    NodeModelStatePort, NodeModelUpdateDisposition, NodeModelUpdateRequest, NodeModelUpdateSummary,
    VersionedNodeModelJournal, VersionedNodeModelOperation,
};
use crate::OperationCompletion;
use li_core_interface::{
    EntityTimestamps, FailureDescription, HardwareObservation, ModelService,
    ModelServiceDesiredState, ModelServiceId, NodeId, OperationId, OperationState, OperationTarget,
    PlacementGroupId, PlacementGroupState, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, TargetId, TechnicalName,
};
use li_placement_manager::{PlacementLogReadRequest, PlacementRecord, PlacementRequest};
use li_runtime_manager::{RuntimeCandidate, RuntimeError};

// Owns explicit cross-manager model-service ordering without merging manager responsibilities.
pub struct NodeModelCoordinator {
    state: Arc<dyn NodeModelStatePort>,
    runtime: Arc<dyn NodeModelRuntimePort>,
    placement: Arc<dyn NodeModelPlacementPort>,
    placement_requests: Arc<dyn NodeModelPlacementRequestProvider>,
    hardware: Arc<dyn NodeModelHardwareProvider>,
    journals: Arc<dyn NodeModelJournalStore>,
    clock: Arc<dyn NodeModelClock>,
    execution_claims: Arc<NodeModelExecutionClaims>,
}

// Carries one current group and its latest successful retained predecessor.
struct NodeModelRollbackPair {
    current: PlacementRecord,
    previous: PlacementRecord,
}

// Carries one complete atomic rollback selection before any journal or provider mutation.
struct NodeModelRollbackPlan {
    service: ModelService,
    target_id: Option<TargetId>,
    pairs: Vec<NodeModelRollbackPair>,
}

// Owns the bounded in-process claim for each executing durable operation.
struct NodeModelExecutionClaims {
    operation_ids: Mutex<HashSet<String>>,
}

impl NodeModelExecutionClaims {
    // Creates one empty claim set for a single resident Node composition.
    fn new() -> Self {
        Self {
            operation_ids: Mutex::new(HashSet::new()),
        }
    }

    // Claims one operation until its coordinator execution scope completes or unwinds.
    fn acquire(
        self: &Arc<Self>,
        operation_id: &OperationId,
    ) -> Result<NodeModelExecutionClaim, NodeModelError> {
        let mut operation_ids = self
            .operation_ids
            .lock()
            .map_err(|_| NodeModelError::StateUnavailable)?;
        let operation_id = operation_id.as_str().to_string();
        if !operation_ids.insert(operation_id.clone()) {
            return Err(NodeModelError::JournalConflict);
        }
        Ok(NodeModelExecutionClaim {
            claims: Arc::clone(self),
            operation_id,
        })
    }

    // Releases one exact operation claim without retaining a failed execution owner.
    fn release(&self, operation_id: &str) {
        let mut operation_ids = match self.operation_ids.lock() {
            Ok(operation_ids) => operation_ids,
            Err(poisoned) => poisoned.into_inner(),
        };
        operation_ids.remove(operation_id);
    }
}

// Releases one operation claim on success, failure, or panic unwinding.
struct NodeModelExecutionClaim {
    claims: Arc<NodeModelExecutionClaims>,
    operation_id: String,
}

impl Drop for NodeModelExecutionClaim {
    // Returns the operation identity to the resident coordinator claim set.
    fn drop(&mut self) {
        self.claims.release(&self.operation_id);
    }
}

impl NodeModelCoordinator {
    // Creates one coordinator from independent typed manager and provider ports.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: Arc<dyn NodeModelStatePort>,
        runtime: Arc<dyn NodeModelRuntimePort>,
        placement: Arc<dyn NodeModelPlacementPort>,
        placement_requests: Arc<dyn NodeModelPlacementRequestProvider>,
        hardware: Arc<dyn NodeModelHardwareProvider>,
        journals: Arc<dyn NodeModelJournalStore>,
        clock: Arc<dyn NodeModelClock>,
    ) -> Self {
        Self {
            state,
            runtime,
            placement,
            placement_requests,
            hardware,
            journals,
            clock,
            execution_claims: Arc::new(NodeModelExecutionClaims::new()),
        }
    }

    // Lists every durable model service with exact group and installation bindings.
    pub fn list(&self) -> Result<Vec<NodeModelServiceProjection>, NodeModelError> {
        let mut projections = Vec::new();
        for service in self.state.services()? {
            let mut placement_groups = Vec::new();
            let mut installation_ids = HashSet::new();
            for placement_group_id in service.placement_group_ids() {
                let record = self
                    .placement
                    .record(placement_group_id)?
                    .ok_or(NodeModelError::RecoveryRequired)?;
                if record.record().group().service_id() != service.service_id() {
                    return Err(NodeModelError::RecoveryRequired);
                }
                for placement in record.record().placements() {
                    installation_ids
                        .insert(placement.assignment().runtime_installation_id().clone());
                }
                placement_groups.push(record.record().clone());
            }
            let mut installation_ids: Vec<_> = installation_ids.into_iter().collect();
            installation_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            let mut installations = Vec::new();
            for installation_id in installation_ids {
                let installation = self
                    .runtime
                    .installation(&installation_id)?
                    .ok_or(NodeModelError::RecoveryRequired)?;
                if installation.installation().logical_model() != service.logical_model() {
                    return Err(NodeModelError::RecoveryRequired);
                }
                installations.push(installation.installation().clone());
            }
            projections.push(NodeModelServiceProjection {
                service,
                placement_groups,
                installations,
            });
        }
        Ok(projections)
    }

    // Projects every operation and journal owned by one exact model service.
    pub fn logs(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<NodeModelLogProjection, NodeModelError> {
        let operations = self
            .state
            .operations()?
            .into_iter()
            .filter(|operation| {
                operation.target() == &OperationTarget::ModelService(service_id.clone())
            })
            .collect();
        let journals = self
            .journals
            .all()?
            .into_iter()
            .filter(|journal| journal.journal().service_id() == service_id)
            .collect();
        Ok(NodeModelLogProjection {
            operations,
            journals,
        })
    }

    // Resolves one exact service group before delegating opaque runtime bytes to PlacementManager.
    pub fn runtime_logs(
        &self,
        request: NodeModelRuntimeLogRequest,
    ) -> Result<NodeModelRuntimeLogBatch, NodeModelError> {
        let service = self.state.service(request.service_id())?;
        let placement_group_id = match request.placement_group_id() {
            Some(placement_group_id)
                if service
                    .service()
                    .placement_group_ids()
                    .contains(placement_group_id) =>
            {
                placement_group_id.clone()
            }
            Some(_) => {
                return Err(NodeModelError::InvalidRequest {
                    reason: "placement group does not belong to the selected model service",
                })
            }
            None if service.service().placement_group_ids().len() == 1 => {
                service.service().placement_group_ids()[0].clone()
            }
            None => {
                return Err(NodeModelError::InvalidRequest {
                    reason: "model runtime logs require one unambiguous placement group",
                })
            }
        };
        let record = self
            .placement
            .record(&placement_group_id)?
            .ok_or(NodeModelError::RecoveryRequired)?;
        if record.record().group().service_id() != request.service_id() {
            return Err(NodeModelError::RecoveryRequired);
        }
        let placement_request = PlacementLogReadRequest::new(
            placement_group_id,
            request.cursor().cloned(),
            request.maximum_lines(),
            request.maximum_bytes(),
            request.wait(),
        )?;
        let batch = self.placement.read_logs(placement_request)?;
        Ok(NodeModelRuntimeLogBatch::new(
            request.service_id().clone(),
            batch,
        ))
    }

    // Installs runtimes, stages groups, and activates one logical service in explicit order.
    pub fn install(
        &self,
        request: NodeModelInstallRequest,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        let journal = self.prepare_install(request)?;
        self.resume_journal(journal, true)
    }

    // Checks or applies signed runtime replacements through this coordinator's journal.
    pub fn update(
        &self,
        request: NodeModelUpdateRequest,
    ) -> Result<NodeModelUpdateSummary, NodeModelError> {
        if let Some(existing) = self.journals.read(request.identity().operation_id())? {
            if !update_request_matches(existing.journal(), &request) || request.is_dry_run() {
                return Err(NodeModelError::JournalConflict);
            }
            let placement_group_count = existing.journal().install_groups.len();
            let result = self.resume_journal(existing, true)?;
            return Ok(NodeModelUpdateSummary::new(
                result.service().service_id().clone(),
                result.service().logical_model().clone(),
                NodeModelUpdateDisposition::Updated,
                placement_group_count,
                Some(command_summary(result)),
            ));
        }
        let (service, groups, initial_group_states) =
            self.update_plan(request.service_id(), request.explicit_candidate_id())?;
        let placement_group_count = groups.len();
        if placement_group_count == 0 || request.is_dry_run() {
            return Ok(NodeModelUpdateSummary::new(
                service.service_id().clone(),
                service.logical_model().clone(),
                if placement_group_count == 0 {
                    NodeModelUpdateDisposition::Current
                } else {
                    NodeModelUpdateDisposition::UpdateAvailable
                },
                placement_group_count,
                None,
            ));
        }
        let journal = self.prepare_update(request, &service, groups, initial_group_states)?;
        let result = self.resume_journal(journal, true)?;
        Ok(NodeModelUpdateSummary::new(
            service.service_id().clone(),
            service.logical_model().clone(),
            NodeModelUpdateDisposition::Updated,
            placement_group_count,
            Some(command_summary(result)),
        ))
    }

    // Stops every service group while retaining its exact assignments.
    pub fn pause(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        self.begin_existing(identity, service_id, NodeModelAction::Pause)
    }

    // Starts every stopped service group without changing runtime installations.
    pub fn resume(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        self.begin_existing(identity, service_id, NodeModelAction::Resume)
    }

    // Restarts every exact group through stop and start ordering.
    pub fn restart(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        self.begin_existing(identity, service_id, NodeModelAction::Restart)
    }

    // Recovers every failed or degraded group with explicit protection acknowledgement.
    pub fn recover(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        self.begin_existing(identity, service_id, NodeModelAction::Recover)
    }

    // Removes every group before deleting only command-created unreferenced runtimes.
    pub fn remove(
        &self,
        request: NodeModelRemoveRequest,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        let journal = self.prepare_remove(request)?;
        self.resume_journal(journal, true)
    }

    // Restores the latest retained prior runtime for one service and optional target.
    pub fn rollback(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        target_id: Option<TargetId>,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        if let Some(existing) = self.journals.read(identity.operation_id())? {
            if rollback_request_matches(
                existing.journal(),
                &identity,
                &service_id,
                target_id.as_ref(),
            ) {
                return self.resume_journal(existing, true);
            }
            return Err(NodeModelError::JournalConflict);
        }
        let plan = self.rollback_plan(&service_id, target_id.as_ref())?;
        let journal = self.prepare_rollback(identity, plan)?;
        self.resume_journal(journal, true)
    }

    // Projects one retained-runtime rollback plan without creating state or calling providers.
    pub fn preview_rollback(
        &self,
        service_id: &ModelServiceId,
        target_id: Option<&TargetId>,
    ) -> Result<NodeModelRollbackPreview, NodeModelError> {
        let plan = self.rollback_plan(service_id, target_id)?;
        Ok(NodeModelRollbackPreview::new(
            plan.service.service_id().clone(),
            plan.service.logical_model().clone(),
            plan.target_id,
            plan.pairs
                .iter()
                .map(|pair| {
                    NodeModelRollbackGroupPreview::new(
                        pair.current.group().placement_group_id().clone(),
                        pair.previous.group().placement_group_id().clone(),
                        placement_node_ids(&pair.current),
                        rollback_runtime(pair.current.group().runtime()),
                        rollback_runtime(pair.previous.group().runtime()),
                    )
                })
                .collect(),
        ))
    }

    // Selects one complete latest retained predecessor for every current matching group.
    fn rollback_plan(
        &self,
        service_id: &ModelServiceId,
        target_id: Option<&TargetId>,
    ) -> Result<NodeModelRollbackPlan, NodeModelError> {
        let service = self.state.service(service_id)?.service().clone();
        if service.desired_state() == ModelServiceDesiredState::Removed {
            return Err(NodeModelError::InvalidRequest {
                reason: "removed model service has no rollback target",
            });
        }
        let mut current = service
            .placement_group_ids()
            .iter()
            .map(|group_id| {
                self.placement
                    .record(group_id)?
                    .map(|record| record.record().clone())
                    .ok_or(NodeModelError::RecoveryRequired)
            })
            .collect::<Result<Vec<_>, _>>()?;
        current.retain(|record| {
            target_id.is_none_or(|target_id| record.group().runtime().target_id() == target_id)
        });
        if current.is_empty() {
            return Err(NodeModelError::InvalidRequest {
                reason: "model service has no current placement group for rollback",
            });
        }
        let mut journals = self.journals.all()?;
        journals.retain(|journal| {
            journal.journal().service_id() == service_id
                && journal.journal().state() == NodeModelJournalState::Succeeded
                && matches!(
                    journal.journal().action(),
                    NodeModelAction::Update | NodeModelAction::Rollback
                )
        });
        journals.sort_by(|left, right| {
            right
                .journal()
                .updated_at()
                .cmp(&left.journal().updated_at())
                .then_with(|| {
                    right
                        .journal()
                        .operation_id()
                        .as_str()
                        .cmp(left.journal().operation_id().as_str())
                })
        });
        let mut pairs = Vec::new();
        for current_group in current {
            let pair = journals.iter().find_map(|journal| {
                let index = journal
                    .journal()
                    .placement_group_ids()
                    .iter()
                    .position(|group_id| group_id == current_group.group().placement_group_id())?;
                let retained = journal.journal().retained_groups().get(index)?;
                let previous = self.placement.record(retained.source_group_id()).ok()??;
                rollback_pair_is_valid(&current_group, previous.record()).then(|| {
                    NodeModelRollbackPair {
                        current: current_group.clone(),
                        previous: previous.record().clone(),
                    }
                })
            });
            let pair = pair.ok_or(NodeModelError::InvalidRequest {
                reason: "model service has no retained prior runtime",
            })?;
            self.validate_rollback_previous(&pair.previous)?;
            pairs.push(pair);
        }
        Ok(NodeModelRollbackPlan {
            service,
            target_id: target_id.cloned(),
            pairs,
        })
    }

    // Persists exact previous installation identities before rollback releases current resources.
    fn prepare_rollback(
        &self,
        identity: NodeModelCommandIdentity,
        plan: NodeModelRollbackPlan,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let mut install_groups = Vec::new();
        let mut runtime_receipts = Vec::new();
        let mut initial_group_states = Vec::new();
        for (group_index, pair) in plan.pairs.iter().enumerate() {
            let node_ids = placement_node_ids(&pair.previous);
            install_groups.push(NodeModelInstallGroup::new(
                node_ids,
                Some(pair.previous.group().runtime().candidate_id().clone()),
            )?);
            for placement in pair.previous.placements() {
                runtime_receipts.push(NodeModelRuntimeReceipt {
                    group_index,
                    node_id: placement.assignment().node_id().clone(),
                    candidate_id: pair.previous.group().runtime().candidate_id().clone(),
                    installation_id: Some(placement.assignment().runtime_installation_id().clone()),
                    disposition: NodeModelRuntimeDisposition::Reused,
                });
            }
            initial_group_states.push((
                pair.current.group().placement_group_id().clone(),
                rollback_initial_state(pair.current.group().state())?,
            ));
        }
        runtime_receipts.sort_by(|left, right| {
            (left.group_index, left.node_id.as_str())
                .cmp(&(right.group_index, right.node_id.as_str()))
        });
        let planned_group_ids = (0..install_groups.len())
            .map(|index| planned_placement_group_id(identity.operation_id(), index))
            .collect::<Result<Vec<_>, _>>()?;
        let retained_groups =
            self.retained_groups(identity.operation_id(), &initial_group_states)?;
        let now = self.clock.now()?;
        self.journals.create(NodeModelJournal {
            operation_id: identity.operation_id,
            idempotency_key: identity.idempotency_key,
            action: NodeModelAction::Rollback,
            service_id: plan.service.service_id().clone(),
            logical_model: plan.service.logical_model().clone(),
            install_groups,
            rollback_target_id: plan.target_id,
            retained_groups,
            runtime_receipts,
            planned_group_ids,
            placement_group_ids: Vec::new(),
            initial_group_states,
            removal_node_ids: Vec::new(),
            removal_runtime_retention: NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            state: NodeModelJournalState::Prepared,
            failure_code: None,
            created_at: now,
            updated_at: now,
        })
    }

    // Resumes every non-terminal journal without caller-supplied hidden lifecycle state.
    pub fn recover_pending(&self) -> Result<Vec<NodeModelCommandResult>, NodeModelError> {
        let mut results = Vec::new();
        for journal in self.journals.all()? {
            if journal.journal().state() == NodeModelJournalState::CleanupPending {
                results.push(self.retry_compensation(journal)?);
                continue;
            }
            let incomplete_success = journal.journal().state() == NodeModelJournalState::Succeeded
                && self
                    .state
                    .operation(journal.journal().operation_id())?
                    .is_none_or(|operation| {
                        operation.operation().state() != OperationState::Succeeded
                    });
            if !journal.journal().state().is_terminal() || incomplete_success {
                results.push(self.resume_journal(journal, false)?);
            }
        }
        Ok(results)
    }

    // Retries one persisted compensation plan during resident recovery without a user command.
    fn retry_compensation(
        &self,
        journal: VersionedNodeModelJournal,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        let _execution_claim = self
            .execution_claims
            .acquire(journal.journal().operation_id())?;
        let current = self
            .journals
            .read(journal.journal().operation_id())?
            .ok_or(NodeModelError::JournalCorrupt)?;
        if current.journal().state() != NodeModelJournalState::CleanupPending {
            return self.result(current);
        }
        self.compensate(&current)?;
        let recovered = self.advance(current, NodeModelJournalState::RolledBack, None)?;
        self.fail_operation(recovered.journal())?;
        self.result(recovered)
    }

    // Creates and starts one existing-service lifecycle journal.
    fn begin_existing(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        action: NodeModelAction,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        let journal = self.prepare_existing(identity, service_id, action)?;
        self.resume_journal(journal, true)
    }

    // Commits the complete normalized install command before other mutation.
    fn prepare_install(
        &self,
        request: NodeModelInstallRequest,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        if let Some(existing) = self.journals.read(request.identity.operation_id())? {
            if install_request_matches(existing.journal(), &request) {
                return Ok(existing);
            }
            return Err(NodeModelError::JournalConflict);
        }
        let planned_group_ids = (0..request.groups.len())
            .map(|group_index| {
                planned_placement_group_id(request.identity.operation_id(), group_index)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let now = self.clock.now()?;
        self.journals.create(NodeModelJournal {
            operation_id: request.identity().operation_id().clone(),
            idempotency_key: request.identity().idempotency_key().clone(),
            action: NodeModelAction::Install,
            service_id: request.service_id().clone(),
            logical_model: request.logical_model,
            install_groups: request.groups,
            rollback_target_id: None,
            retained_groups: Vec::new(),
            runtime_receipts: Vec::new(),
            planned_group_ids,
            placement_group_ids: Vec::new(),
            initial_group_states: Vec::new(),
            removal_node_ids: Vec::new(),
            removal_runtime_retention: NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            state: NodeModelJournalState::Prepared,
            failure_code: None,
            created_at: now,
            updated_at: now,
        })
    }

    // Resolves only changed placement groups without applying provider mutation.
    fn update_plan(
        &self,
        service_id: &ModelServiceId,
        explicit_candidate_id: Option<&li_core_interface::RuntimeCandidateId>,
    ) -> Result<
        (
            ModelService,
            Vec<crate::NodeModelInstallGroup>,
            Vec<(PlacementGroupId, PlacementGroupState)>,
        ),
        NodeModelError,
    > {
        let service = self.state.service(service_id)?.service().clone();
        if service.desired_state() == ModelServiceDesiredState::Removed {
            return Err(NodeModelError::InvalidRequest {
                reason: "removed model service cannot be updated",
            });
        }
        let mut groups = Vec::new();
        let mut initial_group_states = Vec::new();
        for placement_group_id in service.placement_group_ids() {
            let record = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if record.record().group().service_id() != service_id
                || record.record().group().state() == PlacementGroupState::Removed
            {
                return Err(NodeModelError::RecoveryRequired);
            }
            let mut node_ids = Vec::new();
            let mut changed = false;
            for placement in record.record().placements() {
                let node_id = placement.assignment().node_id().clone();
                let installation = self
                    .runtime
                    .installation(placement.assignment().runtime_installation_id())?
                    .ok_or(NodeModelError::RecoveryRequired)?;
                let hardware = self.hardware.observation(&node_id)?;
                let candidate = self.runtime.select(
                    service.logical_model(),
                    explicit_candidate_id,
                    &hardware,
                )?;
                changed |= !candidate_matches_installation(&candidate, installation.installation());
                node_ids.push(node_id);
            }
            if changed {
                groups.push(crate::NodeModelInstallGroup::new(
                    node_ids,
                    explicit_candidate_id.cloned(),
                )?);
                initial_group_states
                    .push((placement_group_id.clone(), record.record().group().state()));
            }
        }
        Ok((service, groups, initial_group_states))
    }

    // Persists one replacement plan before acquiring runtimes or changing placements.
    fn prepare_update(
        &self,
        request: NodeModelUpdateRequest,
        service: &ModelService,
        install_groups: Vec<crate::NodeModelInstallGroup>,
        initial_group_states: Vec<(PlacementGroupId, PlacementGroupState)>,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        if let Some(existing) = self.journals.read(request.identity().operation_id())? {
            if update_request_matches(existing.journal(), &request) {
                return Ok(existing);
            }
            return Err(NodeModelError::JournalConflict);
        }
        let planned_group_ids = (0..install_groups.len())
            .map(|index| planned_placement_group_id(request.identity().operation_id(), index))
            .collect::<Result<Vec<_>, _>>()?;
        let retained_groups =
            self.retained_groups(request.identity.operation_id(), &initial_group_states)?;
        let now = self.clock.now()?;
        self.journals.create(NodeModelJournal {
            operation_id: request.identity.operation_id,
            idempotency_key: request.identity.idempotency_key,
            action: NodeModelAction::Update,
            service_id: service.service_id().clone(),
            logical_model: service.logical_model().clone(),
            install_groups,
            rollback_target_id: None,
            retained_groups,
            runtime_receipts: Vec::new(),
            planned_group_ids,
            placement_group_ids: Vec::new(),
            initial_group_states,
            removal_node_ids: Vec::new(),
            removal_runtime_retention: NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            state: NodeModelJournalState::Prepared,
            failure_code: None,
            created_at: now,
            updated_at: now,
        })
    }

    // Captures exact current assignments before update or rollback can release their resources.
    fn retained_groups(
        &self,
        operation_id: &OperationId,
        initial_group_states: &[(PlacementGroupId, PlacementGroupState)],
    ) -> Result<Vec<NodeModelRetainedGroup>, NodeModelError> {
        initial_group_states
            .iter()
            .enumerate()
            .map(|(group_index, (placement_group_id, initial_state))| {
                let record = self
                    .placement
                    .record(placement_group_id)?
                    .ok_or(NodeModelError::RecoveryRequired)?;
                if record.record().group().state() == PlacementGroupState::Removed {
                    return Err(NodeModelError::RecoveryRequired);
                }
                NodeModelRetainedGroup::new(
                    placement_group_id.clone(),
                    planned_restoration_group_id(operation_id, group_index)?,
                    *initial_state,
                    record
                        .record()
                        .placements()
                        .iter()
                        .map(|placement| {
                            NodeModelRetainedNode::new(
                                placement.assignment().node_id().clone(),
                                placement.assignment().runtime_installation_id().clone(),
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    // Commits one exact complete or node-scoped removal plan before provider mutation.
    fn prepare_remove(
        &self,
        request: NodeModelRemoveRequest,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let removal_node_ids = request
            .selection()
            .node_ids()
            .map_or_else(Vec::new, <[NodeId]>::to_vec);
        let runtime_retention = request.runtime_retention();
        if let Some(existing) = self.journals.read(request.identity().operation_id())? {
            if existing.journal().service_id == *request.service_id()
                && existing.journal().action == NodeModelAction::Remove
                && existing.journal().idempotency_key == *request.identity().idempotency_key()
                && existing.journal().removal_node_ids == removal_node_ids
                && existing.journal().removal_runtime_retention == runtime_retention
            {
                return Ok(existing);
            }
            return Err(NodeModelError::JournalConflict);
        }
        let service = self.state.service(request.service_id())?;
        let mut placement_group_ids = Vec::new();
        let mut initial_group_states = Vec::new();
        let mut matched_node_ids = HashSet::new();
        for placement_group_id in service.service().placement_group_ids() {
            let record = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if record.record().group().service_id() != request.service_id() {
                return Err(NodeModelError::RecoveryRequired);
            }
            let selected = match request.selection() {
                NodeModelRemovalSelection::All => true,
                NodeModelRemovalSelection::Nodes(node_ids) => {
                    let matching = record
                        .record()
                        .placements()
                        .iter()
                        .filter_map(|placement| {
                            let node_id = placement.assignment().node_id();
                            node_ids.contains(node_id).then(|| node_id.clone())
                        })
                        .collect::<Vec<_>>();
                    matched_node_ids.extend(matching.iter().cloned());
                    !matching.is_empty()
                }
            };
            if selected {
                placement_group_ids.push(placement_group_id.clone());
                initial_group_states
                    .push((placement_group_id.clone(), record.record().group().state()));
            }
        }
        if placement_group_ids.is_empty()
            || removal_node_ids
                .iter()
                .any(|node_id| !matched_node_ids.contains(node_id))
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "model removal selection does not match an installed placement group",
            });
        }
        let now = self.clock.now()?;
        self.journals.create(NodeModelJournal {
            operation_id: request.identity().operation_id().clone(),
            idempotency_key: request.identity().idempotency_key().clone(),
            action: NodeModelAction::Remove,
            service_id: request.service_id().clone(),
            logical_model: service.service().logical_model().clone(),
            install_groups: Vec::new(),
            rollback_target_id: None,
            retained_groups: Vec::new(),
            runtime_receipts: Vec::new(),
            planned_group_ids: Vec::new(),
            placement_group_ids,
            initial_group_states,
            removal_node_ids,
            removal_runtime_retention: runtime_retention,
            state: NodeModelJournalState::Prepared,
            failure_code: None,
            created_at: now,
            updated_at: now,
        })
    }

    // Commits one exact existing-service command and its pre-command group states.
    fn prepare_existing(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        action: NodeModelAction,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        if let Some(existing) = self.journals.read(identity.operation_id())? {
            if existing.journal().service_id == service_id
                && existing.journal().action == action
                && existing.journal().idempotency_key == identity.idempotency_key
            {
                return Ok(existing);
            }
            return Err(NodeModelError::JournalConflict);
        }
        let service = self.state.service(&service_id)?;
        if service.service().desired_state() == ModelServiceDesiredState::Removed
            && action != NodeModelAction::Remove
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "removed model service cannot change lifecycle",
            });
        }
        let mut initial_group_states = Vec::new();
        for placement_group_id in service.service().placement_group_ids() {
            let record = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if record.record().group().service_id() != &service_id {
                return Err(NodeModelError::RecoveryRequired);
            }
            initial_group_states
                .push((placement_group_id.clone(), record.record().group().state()));
        }
        let now = self.clock.now()?;
        self.journals.create(NodeModelJournal {
            operation_id: identity.operation_id,
            idempotency_key: identity.idempotency_key,
            action,
            service_id,
            logical_model: service.service().logical_model().clone(),
            install_groups: Vec::new(),
            rollback_target_id: None,
            retained_groups: Vec::new(),
            runtime_receipts: Vec::new(),
            planned_group_ids: Vec::new(),
            placement_group_ids: service.service().placement_group_ids().to_vec(),
            initial_group_states,
            removal_node_ids: Vec::new(),
            removal_runtime_retention: NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            state: NodeModelJournalState::Prepared,
            failure_code: None,
            created_at: now,
            updated_at: now,
        })
    }

    // Dispatches one durable journal through its ordinary lifecycle or compensation path.
    fn resume_journal(
        &self,
        journal: VersionedNodeModelJournal,
        compensate_on_failure: bool,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        if journal.journal().state() == NodeModelJournalState::Succeeded {
            let operation = self.state.operation(journal.journal().operation_id())?;
            if operation
                .is_some_and(|operation| operation.operation().state() == OperationState::Succeeded)
            {
                return self.result(journal);
            }
        }
        if journal.journal().state() == NodeModelJournalState::CleanupPending {
            return Err(NodeModelError::RecoveryRequired);
        }
        let _execution_claim = self
            .execution_claims
            .acquire(journal.journal().operation_id())?;
        let journal = self
            .journals
            .read(journal.journal().operation_id())?
            .ok_or(NodeModelError::JournalCorrupt)?;
        if journal.journal().state() == NodeModelJournalState::Succeeded {
            return self.succeed(journal);
        }
        let operation = self.ensure_operation(journal.journal())?;
        if operation.operation().state() == OperationState::Succeeded {
            return self.result(journal);
        }
        let journal = self.advance(journal, NodeModelJournalState::Executing, None)?;
        let executed = match journal.journal().action {
            NodeModelAction::Install => self.execute_install(journal.clone()),
            NodeModelAction::Update => self.execute_update(journal.clone()),
            NodeModelAction::Pause
            | NodeModelAction::Resume
            | NodeModelAction::Restart
            | NodeModelAction::Recover
            | NodeModelAction::Remove => self.execute_existing(journal.clone()),
            NodeModelAction::Rollback => self.execute_rollback(journal.clone()),
        };
        match executed {
            Ok(journal) => self.succeed(journal),
            Err(error) if compensate_on_failure => {
                let latest = self
                    .journals
                    .read(journal.journal().operation_id())?
                    .ok_or(NodeModelError::JournalCorrupt)?;
                let compensated = self.compensate(&latest);
                let state = if compensated.is_ok() {
                    NodeModelJournalState::Failed
                } else {
                    NodeModelJournalState::CleanupPending
                };
                let failed = self.advance(latest, state, Some(failure_code(&error)?))?;
                if compensated.is_err() {
                    self.fail_operation(failed.journal())?;
                    Err(NodeModelError::RecoveryRequired)
                } else {
                    self.fail_operation(failed.journal())?;
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    // Creates or resumes the user-visible operation without using it as the phase journal.
    fn ensure_operation(
        &self,
        journal: &NodeModelJournal,
    ) -> Result<VersionedNodeModelOperation, NodeModelError> {
        let operation = match self.state.operation(&journal.operation_id)? {
            Some(operation) => {
                if operation.operation().kind() != journal.action.operation_kind()
                    || operation.operation().target()
                        != &OperationTarget::ModelService(journal.service_id.clone())
                {
                    return Err(NodeModelError::JournalConflict);
                }
                operation
            }
            None => self.state.begin_operation(
                &phase_key(journal, "operation.begin"),
                journal.operation_id.clone(),
                journal.action.operation_kind(),
                OperationTarget::ModelService(journal.service_id.clone()),
                journal.created_at,
            )?,
        };
        match operation.operation().state() {
            OperationState::Pending => Ok(self.state.start_operation(
                &phase_key(journal, "operation.start"),
                &journal.operation_id,
                operation.revision(),
                self.clock.now()?,
            )?),
            OperationState::Running | OperationState::Succeeded => Ok(operation),
            OperationState::Failed | OperationState::Cancelled => {
                Err(NodeModelError::RecoveryRequired)
            }
        }
    }

    // Executes every restart-safe install phase and records each exact receipt.
    fn execute_install(
        &self,
        mut journal: VersionedNodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let service = match self.state.service(&journal.journal().service_id) {
            Ok(service) => service,
            Err(_) => {
                let now = self.clock.now()?;
                let service = ModelService::new(
                    journal.journal().service_id.clone(),
                    journal.journal().logical_model.clone(),
                    ModelServiceDesiredState::Stopped,
                    Vec::new(),
                    EntityTimestamps::new(now, now)
                        .map_err(|_| NodeModelError::StateUnavailable)?,
                )
                .map_err(|_| NodeModelError::StateUnavailable)?;
                self.state
                    .create_service(&phase_key(journal.journal(), "service.create"), service)?
            }
        };
        if service.service().logical_model() != &journal.journal().logical_model {
            return Err(NodeModelError::JournalConflict);
        }
        for group_index in 0..journal.journal().install_groups.len() {
            let installations = if journal.journal().action == NodeModelAction::Rollback {
                self.rollback_group_installations(journal.journal(), group_index)?
            } else {
                self.resolve_group_installations(&mut journal, group_index)?
            };
            require_group_runtime_identity(&installations)?;
            let planned_group_id = journal
                .journal()
                .planned_group_ids
                .get(group_index)
                .cloned()
                .ok_or(NodeModelError::JournalCorrupt)?;
            let request = self.placement_requests.request(
                &journal.journal().service_id,
                group_index,
                &planned_group_id,
                &installations,
            )?;
            validate_placement_request(
                &request,
                &planned_group_id,
                &journal.journal().service_id,
                &installations,
            )?;
            let placement_group_id =
                self.resolve_group(&mut journal, group_index, &planned_group_id, request)?;
            let current = self.state.service(&journal.journal().service_id)?;
            if !current
                .service()
                .placement_group_ids()
                .contains(&placement_group_id)
            {
                self.state.attach_group(
                    &phase_key(journal.journal(), &format!("group.{group_index}.attach")),
                    &journal.journal().service_id,
                    placement_group_id.clone(),
                    current.revision(),
                    self.clock.now()?,
                )?;
            }
            self.ensure_group_running(&placement_group_id)?;
        }
        let current = self.state.service(&journal.journal().service_id)?;
        if current.service().desired_state() != ModelServiceDesiredState::Running {
            self.state.transition_service(
                &phase_key(journal.journal(), "service.running"),
                &journal.journal().service_id,
                ModelServiceDesiredState::Running,
                current.revision(),
                self.clock.now()?,
            )?;
        }
        Ok(journal)
    }

    // Reads exact retained rollback installations without consulting mutable catalog selection.
    fn rollback_group_installations(
        &self,
        journal: &NodeModelJournal,
        group_index: usize,
    ) -> Result<Vec<RuntimeInstallation>, NodeModelError> {
        let group = journal
            .install_groups
            .get(group_index)
            .ok_or(NodeModelError::JournalCorrupt)?;
        let mut installations = Vec::new();
        for node_id in &group.node_ids {
            let receipt = journal
                .runtime_receipts
                .iter()
                .find(|receipt| receipt.group_index == group_index && &receipt.node_id == node_id)
                .ok_or(NodeModelError::JournalCorrupt)?;
            if receipt.disposition != NodeModelRuntimeDisposition::Reused
                || group
                    .explicit_candidate_id
                    .as_ref()
                    .is_some_and(|candidate_id| candidate_id != &receipt.candidate_id)
            {
                return Err(NodeModelError::JournalCorrupt);
            }
            let installation_id = receipt
                .installation_id
                .as_ref()
                .ok_or(NodeModelError::JournalCorrupt)?;
            let installation = self
                .runtime
                .installation(installation_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if installation.installation().node_id() != node_id
                || installation.installation().state() != RuntimeInstallationState::Available
                || installation.installation().runtime().candidate_id() != &receipt.candidate_id
            {
                return Err(NodeModelError::RecoveryRequired);
            }
            installations.push(installation.installation().clone());
        }
        require_group_runtime_identity(&installations)?;
        Ok(installations)
    }

    // Acquires immutable replacements before releasing old resources and preserves service intent.
    fn execute_update(
        &self,
        mut journal: VersionedNodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        for group_index in 0..journal.journal().install_groups.len() {
            let installations = self.resolve_group_installations(&mut journal, group_index)?;
            require_group_runtime_identity(&installations)?;
        }
        self.execute_replacement(journal)
    }

    // Releases retained current groups, activates replacements, and preserves stopped intent.
    fn execute_replacement(
        &self,
        journal: VersionedNodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let desired_state = self
            .state
            .service(&journal.journal().service_id)?
            .service()
            .desired_state();
        for retained in &journal.journal().retained_groups {
            let placement_group_id = retained.source_group_id();
            let record = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if record.record().group().state() != PlacementGroupState::Removed {
                self.ensure_group_stopped(placement_group_id)?;
                self.placement.remove(placement_group_id)?;
            }
            let current = self.state.service(&journal.journal().service_id)?;
            if current
                .service()
                .placement_group_ids()
                .contains(placement_group_id)
            {
                self.state.detach_group(
                    &phase_key(
                        journal.journal(),
                        &format!("group.{}.replace", placement_group_id.as_str()),
                    ),
                    &journal.journal().service_id,
                    placement_group_id,
                    current.revision(),
                    self.clock.now()?,
                )?;
            }
        }
        let journal = self.execute_install(journal)?;
        if desired_state == ModelServiceDesiredState::Stopped {
            for placement_group_id in journal.journal().placement_group_ids.iter().rev() {
                self.ensure_group_stopped(placement_group_id)?;
            }
            self.ensure_service_state(journal.journal(), ModelServiceDesiredState::Stopped)?;
        }
        Ok(journal)
    }

    // Resolves every exact group installation, recovering ambiguous provider returns by reread.
    fn resolve_group_installations(
        &self,
        journal: &mut VersionedNodeModelJournal,
        group_index: usize,
    ) -> Result<Vec<RuntimeInstallation>, NodeModelError> {
        let group = journal
            .journal()
            .install_groups
            .get(group_index)
            .cloned()
            .ok_or(NodeModelError::JournalCorrupt)?;
        let mut installations = Vec::new();
        for node_id in group.node_ids {
            let receipt = journal
                .journal()
                .runtime_receipts
                .iter()
                .find(|receipt| receipt.group_index == group_index && receipt.node_id == node_id)
                .cloned();
            let candidate_id = match &receipt {
                Some(receipt) => receipt.candidate_id.clone(),
                None => {
                    let hardware = self.hardware.observation(&node_id)?;
                    self.runtime
                        .select(
                            &journal.journal().logical_model,
                            group.explicit_candidate_id.as_ref(),
                            &hardware,
                        )?
                        .runtime()
                        .candidate_id()
                        .clone()
                }
            };
            let hardware = self.hardware.observation(&node_id)?;
            let candidate = self.runtime.select(
                &journal.journal().logical_model,
                Some(&candidate_id),
                &hardware,
            )?;
            let matching = self.matching_installations(&node_id, &candidate)?;
            let receipt = match receipt {
                Some(receipt)
                    if receipt.disposition != NodeModelRuntimeDisposition::InstallPending =>
                {
                    receipt
                }
                Some(mut pending) => {
                    if matching.len() > 1 {
                        return Err(NodeModelError::RecoveryRequired);
                    }
                    let (installation, disposition) =
                        if let Some(existing) = matching.into_iter().next() {
                            (existing, NodeModelRuntimeDisposition::OwnershipUnknown)
                        } else {
                            self.install_with_authoritative_reread(
                                &node_id, &candidate, &hardware, true,
                            )?
                        };
                    pending.installation_id = Some(installation.installation_id().clone());
                    pending.disposition = disposition;
                    *journal = self.save_runtime_receipt(journal.clone(), pending.clone())?;
                    pending
                }
                None if !matching.is_empty() => {
                    let installation = matching[0].clone();
                    let receipt = NodeModelRuntimeReceipt {
                        group_index,
                        node_id: node_id.clone(),
                        candidate_id,
                        installation_id: Some(installation.installation_id().clone()),
                        disposition: NodeModelRuntimeDisposition::Reused,
                    };
                    *journal = self.save_runtime_receipt(journal.clone(), receipt.clone())?;
                    receipt
                }
                None => {
                    let pending = NodeModelRuntimeReceipt {
                        group_index,
                        node_id: node_id.clone(),
                        candidate_id,
                        installation_id: None,
                        disposition: NodeModelRuntimeDisposition::InstallPending,
                    };
                    *journal = self.save_runtime_receipt(journal.clone(), pending.clone())?;
                    let (installation, disposition) = self
                        .install_with_authoritative_reread(&node_id, &candidate, &hardware, true)?;
                    let receipt = NodeModelRuntimeReceipt {
                        installation_id: Some(installation.installation_id().clone()),
                        disposition,
                        ..pending
                    };
                    *journal = self.save_runtime_receipt(journal.clone(), receipt.clone())?;
                    receipt
                }
            };
            let installation_id = receipt
                .installation_id
                .ok_or(NodeModelError::JournalCorrupt)?;
            let installation = self
                .runtime
                .installation(&installation_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if !candidate_matches_installation(&candidate, installation.installation())
                || installation.installation().node_id() != &node_id
                || installation.installation().state() != RuntimeInstallationState::Available
            {
                return Err(NodeModelError::RecoveryRequired);
            }
            installations.push(installation.installation().clone());
        }
        Ok(installations)
    }

    // Returns exact compatible available installations in stable identity order.
    fn matching_installations(
        &self,
        node_id: &NodeId,
        candidate: &RuntimeCandidate,
    ) -> Result<Vec<RuntimeInstallation>, NodeModelError> {
        let mut matching: Vec<_> = self
            .runtime
            .installations()?
            .into_iter()
            .map(|installation| installation.installation().clone())
            .filter(|installation| {
                installation.node_id() == node_id
                    && installation.state() == RuntimeInstallationState::Available
                    && candidate_matches_installation(candidate, installation)
            })
            .collect();
        matching.sort_by(|left, right| {
            left.installation_id()
                .as_str()
                .cmp(right.installation_id().as_str())
        });
        Ok(matching)
    }

    // Installs one pinned candidate and resolves an ambiguous success by authoritative reread.
    fn install_with_authoritative_reread(
        &self,
        node_id: &NodeId,
        candidate: &RuntimeCandidate,
        hardware: &HardwareObservation,
        fail_on_multiple: bool,
    ) -> Result<(RuntimeInstallation, NodeModelRuntimeDisposition), NodeModelError> {
        let result = self.runtime.install(
            node_id.clone(),
            candidate.logical_model(),
            candidate.runtime().candidate_id(),
            hardware,
        );
        let provider_error = match result {
            Ok(change) => {
                let installation = change.installation();
                if installation.state() == RuntimeInstallationState::Available
                    && candidate_matches_installation(candidate, installation)
                {
                    return Ok((installation.clone(), NodeModelRuntimeDisposition::Created));
                }
                return Err(NodeModelError::Runtime(
                    RuntimeError::InstallationUnavailable,
                ));
            }
            Err(error) => error,
        };
        let matching = self.matching_installations(node_id, candidate)?;
        if matching.len() == 1 || (!fail_on_multiple && !matching.is_empty()) {
            return Ok((
                matching[0].clone(),
                NodeModelRuntimeDisposition::OwnershipUnknown,
            ));
        }
        Err(provider_error.into())
    }

    // Records one selected, pending, created, or reused runtime binding optimistically.
    fn save_runtime_receipt(
        &self,
        journal: VersionedNodeModelJournal,
        receipt: NodeModelRuntimeReceipt,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let mut updated = journal.journal().clone();
        updated.runtime_receipts.retain(|existing| {
            existing.group_index != receipt.group_index || existing.node_id != receipt.node_id
        });
        updated.runtime_receipts.push(receipt);
        updated.runtime_receipts.sort_by(|left, right| {
            (left.group_index, left.node_id.as_str())
                .cmp(&(right.group_index, right.node_id.as_str()))
        });
        updated.updated_at = self.clock.now()?;
        self.journals.replace(updated, journal.revision())
    }

    // Resolves one staged group, including provider success followed by transport failure.
    fn resolve_group(
        &self,
        journal: &mut VersionedNodeModelJournal,
        group_index: usize,
        planned_group_id: &PlacementGroupId,
        request: PlacementRequest,
    ) -> Result<PlacementGroupId, NodeModelError> {
        if let Some(placement_group_id) = journal.journal().placement_group_ids.get(group_index) {
            if placement_group_id != planned_group_id {
                return Err(NodeModelError::JournalCorrupt);
            }
            let record = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if !placement_record_matches(record.record(), &request) {
                return Err(NodeModelError::RecoveryRequired);
            }
            return Ok(placement_group_id.clone());
        }
        let result = self.placement.stage(request.clone());
        let placement_group_id = match result {
            Ok(change) if change.record().group().placement_group_id() == planned_group_id => {
                planned_group_id.clone()
            }
            Ok(_) => return Err(NodeModelError::RecoveryRequired),
            Err(error) => {
                let observed = self
                    .placement
                    .record(planned_group_id)?
                    .filter(|record| placement_record_matches(record.record(), &request));
                if observed.is_none() {
                    return Err(NodeModelError::Placement(error));
                }
                planned_group_id.clone()
            }
        };
        let mut updated = journal.journal().clone();
        if updated.placement_group_ids.len() != group_index {
            return Err(NodeModelError::JournalCorrupt);
        }
        updated.placement_group_ids.push(placement_group_id.clone());
        updated.updated_at = self.clock.now()?;
        *journal = self.journals.replace(updated, journal.revision())?;
        Ok(placement_group_id)
    }

    // Starts one group or accepts an authoritative running reread after ambiguous failure.
    fn ensure_group_running(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<(), NodeModelError> {
        let record = self
            .placement
            .record(placement_group_id)?
            .ok_or(NodeModelError::RecoveryRequired)?;
        if record.record().group().state() == PlacementGroupState::Running {
            return Ok(());
        }
        if let Err(error) = self.placement.start(placement_group_id) {
            let observed = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::Placement(error.clone()))?;
            if observed.record().group().state() != PlacementGroupState::Running {
                return Err(NodeModelError::Placement(error));
            }
        }
        Ok(())
    }

    // Executes a complete existing-service action in stable group identity order.
    fn execute_existing(
        &self,
        journal: VersionedNodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let mut placement_group_ids = journal.journal().placement_group_ids.clone();
        placement_group_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        match journal.journal().action {
            NodeModelAction::Pause => {
                for placement_group_id in &placement_group_ids {
                    self.ensure_group_stopped(placement_group_id)?;
                }
                self.ensure_service_state(journal.journal(), ModelServiceDesiredState::Stopped)?;
            }
            NodeModelAction::Resume => {
                for placement_group_id in &placement_group_ids {
                    self.ensure_group_running_or_recovered(placement_group_id, false)?;
                }
                self.ensure_service_state(journal.journal(), ModelServiceDesiredState::Running)?;
            }
            NodeModelAction::Restart => {
                for placement_group_id in placement_group_ids.iter().rev() {
                    self.ensure_group_stopped(placement_group_id)?;
                }
                for placement_group_id in &placement_group_ids {
                    self.ensure_group_running_or_recovered(placement_group_id, false)?;
                }
                self.ensure_service_state(journal.journal(), ModelServiceDesiredState::Running)?;
            }
            NodeModelAction::Recover => {
                for placement_group_id in &placement_group_ids {
                    self.ensure_group_running_or_recovered(placement_group_id, true)?;
                }
                self.ensure_service_state(journal.journal(), ModelServiceDesiredState::Running)?;
            }
            NodeModelAction::Remove => self.remove_service(journal.journal())?,
            NodeModelAction::Install | NodeModelAction::Update | NodeModelAction::Rollback => {
                return Err(NodeModelError::JournalCorrupt);
            }
        }
        Ok(journal)
    }

    // Stops one group or accepts an authoritative stopped reread after ambiguous failure.
    fn ensure_group_stopped(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<(), NodeModelError> {
        let record = self
            .placement
            .record(placement_group_id)?
            .ok_or(NodeModelError::RecoveryRequired)?;
        if matches!(
            record.record().group().state(),
            PlacementGroupState::Stopped | PlacementGroupState::Removed
        ) {
            return Ok(());
        }
        if let Err(error) = self.placement.stop(placement_group_id) {
            let observed = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::Placement(error.clone()))?;
            if observed.record().group().state() != PlacementGroupState::Stopped {
                return Err(NodeModelError::Placement(error));
            }
        }
        Ok(())
    }

    // Starts or recovers one group according to its authoritative current state.
    fn ensure_group_running_or_recovered(
        &self,
        placement_group_id: &PlacementGroupId,
        acknowledge_protection_trips: bool,
    ) -> Result<(), NodeModelError> {
        let record = self
            .placement
            .record(placement_group_id)?
            .ok_or(NodeModelError::RecoveryRequired)?;
        if record.record().group().state() == PlacementGroupState::Running {
            return Ok(());
        }
        let result = if matches!(
            record.record().group().state(),
            PlacementGroupState::Staged | PlacementGroupState::Stopped
        ) {
            self.placement.start(placement_group_id)
        } else {
            self.placement
                .recover(placement_group_id, acknowledge_protection_trips)
        };
        if let Err(error) = result {
            let observed = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::Placement(error.clone()))?;
            if observed.record().group().state() != PlacementGroupState::Running {
                return Err(NodeModelError::Placement(error));
            }
        }
        Ok(())
    }

    // Applies one service state only after every group lifecycle has completed.
    fn ensure_service_state(
        &self,
        journal: &NodeModelJournal,
        desired_state: ModelServiceDesiredState,
    ) -> Result<(), NodeModelError> {
        let service = self.state.service(&journal.service_id)?;
        if service.service().desired_state() != desired_state {
            self.state.transition_service(
                &phase_key(journal, "service.transition"),
                &journal.service_id,
                desired_state,
                service.revision(),
                self.clock.now()?,
            )?;
        }
        Ok(())
    }

    // Removes exact selected groups and marks the service removed only when none remain.
    fn remove_service(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        let mut placement_group_ids = journal.placement_group_ids.clone();
        placement_group_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        for placement_group_id in &placement_group_ids {
            let record = self
                .placement
                .record(placement_group_id)?
                .ok_or(NodeModelError::RecoveryRequired)?;
            if record.record().group().state() != PlacementGroupState::Removed {
                if !matches!(
                    record.record().group().state(),
                    PlacementGroupState::Staged | PlacementGroupState::Stopped
                ) {
                    self.ensure_group_stopped(placement_group_id)?;
                }
                self.placement.remove(placement_group_id)?;
            }
            let service = self.state.service(&journal.service_id)?;
            if service
                .service()
                .placement_group_ids()
                .contains(placement_group_id)
            {
                self.state.detach_group(
                    &phase_key(
                        journal,
                        &format!("group.{}.detach", placement_group_id.as_str()),
                    ),
                    &journal.service_id,
                    placement_group_id,
                    service.revision(),
                    self.clock.now()?,
                )?;
            }
        }
        if self
            .state
            .service(&journal.service_id)?
            .service()
            .placement_group_ids()
            .is_empty()
        {
            self.ensure_service_state(journal, ModelServiceDesiredState::Removed)?;
        }
        self.remove_owned_runtimes(&journal.service_id, journal.removal_runtime_retention)?;
        Ok(())
    }

    // Removes only installations created by this service and no longer referenced by any group.
    fn remove_owned_runtimes(
        &self,
        service_id: &ModelServiceId,
        retention: NodeModelRemovalRetention,
    ) -> Result<(), NodeModelError> {
        let mut created = HashSet::new();
        for journal in self.journals.all()? {
            if journal.journal().service_id() == service_id
                && matches!(
                    journal.journal().action(),
                    NodeModelAction::Install | NodeModelAction::Update
                )
            {
                for receipt in journal.journal().runtime_receipts() {
                    if receipt.disposition() == NodeModelRuntimeDisposition::Created {
                        if let Some(installation_id) = receipt.installation_id() {
                            created.insert(installation_id.clone());
                        }
                    }
                }
            }
        }
        for installation_id in created {
            if self.runtime_is_referenced(&installation_id)? {
                continue;
            }
            let Some(installation) = self.runtime.installation(&installation_id)? else {
                continue;
            };
            if installation.installation().state() == RuntimeInstallationState::Removed {
                continue;
            }
            let change = match retention {
                NodeModelRemovalRetention::RemoveUnreferencedRuntimes => {
                    self.runtime.remove(&installation_id)?
                }
                NodeModelRemovalRetention::PreserveModels => {
                    self.runtime.remove_preserving_models(&installation_id)?
                }
            };
            if change.installation().state() != RuntimeInstallationState::Removed {
                return Err(NodeModelError::RecoveryRequired);
            }
        }
        Ok(())
    }

    // Returns whether any non-removed group still binds one exact runtime installation.
    fn runtime_is_referenced(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<bool, NodeModelError> {
        Ok(self.placement.records()?.iter().any(|record| {
            record.group().state() != PlacementGroupState::Removed
                && record.placements().iter().any(|placement| {
                    placement.assignment().runtime_installation_id() == installation_id
                })
        }))
    }

    // Activates exact retained prior installations without catalog re-resolution.
    fn execute_rollback(
        &self,
        journal: VersionedNodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        for group_index in 0..journal.journal().install_groups.len() {
            self.rollback_group_installations(journal.journal(), group_index)?;
        }
        self.execute_replacement(journal)
    }

    // Restores initial state or reverses install receipts in exact reverse ownership order.
    fn compensate(&self, journal: &VersionedNodeModelJournal) -> Result<(), NodeModelError> {
        match journal.journal().action {
            NodeModelAction::Install => self.compensate_install(journal.journal()),
            NodeModelAction::Update | NodeModelAction::Rollback => {
                self.compensate_replacement(journal.journal())
            }
            NodeModelAction::Pause
            | NodeModelAction::Resume
            | NodeModelAction::Restart
            | NodeModelAction::Recover => self.restore_initial_groups(journal.journal()),
            NodeModelAction::Remove => Err(NodeModelError::RecoveryRequired),
        }
    }

    // Removes failed replacements and reconstructs every retained current group exactly.
    fn compensate_replacement(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        self.remove_replacement_groups(journal)?;
        self.restore_retained_groups(journal)?;
        self.remove_created_runtimes(journal)
    }

    // Removes and detaches only groups created by the failed replacement operation.
    fn remove_replacement_groups(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        for placement_group_id in journal.placement_group_ids.iter().rev() {
            if let Some(record) = self.placement.record(placement_group_id)? {
                if record.record().group().state() != PlacementGroupState::Removed {
                    if !matches!(
                        record.record().group().state(),
                        PlacementGroupState::Staged | PlacementGroupState::Stopped
                    ) {
                        self.ensure_group_stopped(placement_group_id)?;
                    }
                    self.placement.remove(placement_group_id)?;
                }
            }
            let service = self.state.service(&journal.service_id)?;
            if service
                .service()
                .placement_group_ids()
                .contains(placement_group_id)
            {
                self.state.detach_group(
                    &phase_key(
                        journal,
                        &format!("replacement.{}.detach", placement_group_id.as_str()),
                    ),
                    &journal.service_id,
                    placement_group_id,
                    service.revision(),
                    self.clock.now()?,
                )?;
            }
        }
        Ok(())
    }

    // Restores every retained group in place or under its deterministic recovery identity.
    fn restore_retained_groups(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        for (group_index, retained) in journal.retained_groups.iter().enumerate() {
            let source = self
                .placement
                .record(retained.source_group_id())?
                .ok_or(NodeModelError::RecoveryRequired)?;
            let group_id = if source.record().group().state() != PlacementGroupState::Removed {
                self.validate_retained_record(retained, source.record())?;
                retained.source_group_id().clone()
            } else {
                let installations = self.retained_installations(retained)?;
                if source.record().group().runtime()
                    != require_group_runtime_identity(&installations)?
                {
                    return Err(NodeModelError::RecoveryRequired);
                }
                let request = self.placement_requests.request(
                    &journal.service_id,
                    group_index,
                    retained.restoration_group_id(),
                    &installations,
                )?;
                validate_placement_request(
                    &request,
                    retained.restoration_group_id(),
                    &journal.service_id,
                    &installations,
                )?;
                self.resolve_restoration_group(retained.restoration_group_id(), request)?
            };
            let service = self.state.service(&journal.service_id)?;
            if service
                .service()
                .placement_group_ids()
                .contains(retained.source_group_id())
                && retained.source_group_id() != &group_id
            {
                self.state.detach_group(
                    &phase_key(
                        journal,
                        &format!("retained.{}.detach", retained.source_group_id().as_str()),
                    ),
                    &journal.service_id,
                    retained.source_group_id(),
                    service.revision(),
                    self.clock.now()?,
                )?;
            }
            let service = self.state.service(&journal.service_id)?;
            if !service.service().placement_group_ids().contains(&group_id) {
                self.state.attach_group(
                    &phase_key(journal, &format!("retained.{}.attach", group_id.as_str())),
                    &journal.service_id,
                    group_id.clone(),
                    service.revision(),
                    self.clock.now()?,
                )?;
            }
            match retained.initial_state() {
                PlacementGroupState::Running => self.ensure_group_running(&group_id)?,
                PlacementGroupState::Staged | PlacementGroupState::Stopped => {
                    self.ensure_group_stopped(&group_id)?
                }
                _ => return Err(NodeModelError::JournalCorrupt),
            }
        }
        let desired_state = if journal
            .retained_groups
            .iter()
            .any(|group| group.initial_state() == PlacementGroupState::Running)
        {
            ModelServiceDesiredState::Running
        } else {
            ModelServiceDesiredState::Stopped
        };
        self.ensure_service_state(journal, desired_state)
    }

    // Resolves one deterministic restoration stage including ambiguous provider success.
    fn resolve_restoration_group(
        &self,
        restoration_group_id: &PlacementGroupId,
        request: PlacementRequest,
    ) -> Result<PlacementGroupId, NodeModelError> {
        if let Some(record) = self.placement.record(restoration_group_id)? {
            if placement_record_matches(record.record(), &request) {
                return Ok(restoration_group_id.clone());
            }
            return Err(NodeModelError::RecoveryRequired);
        }
        match self.placement.stage(request.clone()) {
            Ok(change) if change.record().group().placement_group_id() == restoration_group_id => {
                Ok(restoration_group_id.clone())
            }
            Ok(_) => Err(NodeModelError::RecoveryRequired),
            Err(error) => self
                .placement
                .record(restoration_group_id)?
                .filter(|record| placement_record_matches(record.record(), &request))
                .map(|_| restoration_group_id.clone())
                .ok_or(NodeModelError::Placement(error)),
        }
    }

    // Reads every retained installation and verifies its exact node and available state.
    fn retained_installations(
        &self,
        retained: &NodeModelRetainedGroup,
    ) -> Result<Vec<RuntimeInstallation>, NodeModelError> {
        let installations = retained
            .nodes()
            .iter()
            .map(|node| {
                let installation = self
                    .runtime
                    .installation(node.installation_id())?
                    .ok_or(NodeModelError::RecoveryRequired)?;
                if installation.installation().node_id() != node.node_id()
                    || installation.installation().state() != RuntimeInstallationState::Available
                {
                    return Err(NodeModelError::RecoveryRequired);
                }
                Ok(installation.installation().clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        require_group_runtime_identity(&installations)?;
        Ok(installations)
    }

    // Requires every retained prior placement to reference exact available matching bytes.
    fn validate_rollback_previous(&self, previous: &PlacementRecord) -> Result<(), NodeModelError> {
        let installations = previous
            .placements()
            .iter()
            .map(|placement| {
                let installation = self
                    .runtime
                    .installation(placement.assignment().runtime_installation_id())?
                    .ok_or(NodeModelError::RecoveryRequired)?;
                if installation.installation().state() != RuntimeInstallationState::Available
                    || installation.installation().node_id() != placement.assignment().node_id()
                    || installation.installation().runtime() != previous.group().runtime()
                {
                    return Err(NodeModelError::RecoveryRequired);
                }
                Ok(installation.installation().clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        require_group_runtime_identity(&installations).map(|_| ())
    }

    // Requires one retained source record to keep the exact persisted assignments.
    fn validate_retained_record(
        &self,
        retained: &NodeModelRetainedGroup,
        record: &PlacementRecord,
    ) -> Result<(), NodeModelError> {
        let assignments = record
            .placements()
            .iter()
            .map(|placement| {
                (
                    placement.assignment().node_id(),
                    placement.assignment().runtime_installation_id(),
                )
            })
            .collect::<HashSet<_>>();
        let expected = retained
            .nodes()
            .iter()
            .map(|node| (node.node_id(), node.installation_id()))
            .collect::<HashSet<_>>();
        if record.group().placement_group_id() != retained.source_group_id()
            || assignments != expected
        {
            return Err(NodeModelError::RecoveryRequired);
        }
        self.retained_installations(retained).map(|_| ())
    }

    // Removes only replacement-created runtimes after every retained group is authoritative.
    fn remove_created_runtimes(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        for receipt in journal.runtime_receipts.iter().rev() {
            if receipt.disposition != NodeModelRuntimeDisposition::Created {
                continue;
            }
            let Some(installation_id) = receipt.installation_id.as_ref() else {
                continue;
            };
            if self.runtime_is_referenced(installation_id)? {
                continue;
            }
            if let Some(installation) = self.runtime.installation(installation_id)? {
                if installation.installation().state() != RuntimeInstallationState::Removed {
                    let change = self.runtime.remove(installation_id)?;
                    if change.installation().state() != RuntimeInstallationState::Removed {
                        return Err(NodeModelError::RecoveryRequired);
                    }
                }
            }
        }
        Ok(())
    }

    // Removes command-created groups and installations while preserving reused bytes.
    fn compensate_install(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        for placement_group_id in journal.placement_group_ids.iter().rev() {
            if let Some(record) = self.placement.record(placement_group_id)? {
                if record.record().group().state() != PlacementGroupState::Removed {
                    if !matches!(
                        record.record().group().state(),
                        PlacementGroupState::Staged | PlacementGroupState::Stopped
                    ) {
                        self.ensure_group_stopped(placement_group_id)?;
                    }
                    self.placement.remove(placement_group_id)?;
                }
            }
            if let Ok(service) = self.state.service(&journal.service_id) {
                if service
                    .service()
                    .placement_group_ids()
                    .contains(placement_group_id)
                {
                    self.state.detach_group(
                        &phase_key(journal, "compensation.detach"),
                        &journal.service_id,
                        placement_group_id,
                        service.revision(),
                        self.clock.now()?,
                    )?;
                }
            }
        }
        if let Ok(service) = self.state.service(&journal.service_id) {
            if service.service().placement_group_ids().is_empty()
                && service.service().desired_state() != ModelServiceDesiredState::Removed
            {
                self.state.transition_service(
                    &phase_key(journal, "compensation.remove_service"),
                    &journal.service_id,
                    ModelServiceDesiredState::Removed,
                    service.revision(),
                    self.clock.now()?,
                )?;
            }
        }
        for receipt in journal.runtime_receipts.iter().rev() {
            if receipt.disposition != NodeModelRuntimeDisposition::Created {
                continue;
            }
            let Some(installation_id) = receipt.installation_id.as_ref() else {
                continue;
            };
            if self.runtime_is_referenced(installation_id)? {
                continue;
            }
            if let Some(installation) = self.runtime.installation(installation_id)? {
                if installation.installation().state() != RuntimeInstallationState::Removed {
                    let change = self.runtime.remove(installation_id)?;
                    if change.installation().state() != RuntimeInstallationState::Removed {
                        return Err(NodeModelError::RecoveryRequired);
                    }
                }
            }
        }
        Ok(())
    }

    // Converges every targeted group back to its exact pre-command running or stopped state.
    fn restore_initial_groups(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        for (placement_group_id, initial_state) in &journal.initial_group_states {
            match initial_state {
                PlacementGroupState::Running => {
                    self.ensure_group_running_or_recovered(placement_group_id, false)?;
                }
                PlacementGroupState::Staged | PlacementGroupState::Stopped => {
                    self.ensure_group_stopped(placement_group_id)?;
                }
                _ => return Err(NodeModelError::RecoveryRequired),
            }
        }
        let desired_state = if journal
            .initial_group_states
            .iter()
            .any(|(_, state)| *state == PlacementGroupState::Running)
        {
            ModelServiceDesiredState::Running
        } else {
            ModelServiceDesiredState::Stopped
        };
        self.ensure_service_state(journal, desired_state)
    }

    // Commits terminal success to the journal before its user-visible operation projection.
    fn succeed(
        &self,
        journal: VersionedNodeModelJournal,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        let journal = self.advance(journal, NodeModelJournalState::Succeeded, None)?;
        let operation = self
            .state
            .operation(journal.journal().operation_id())?
            .ok_or(NodeModelError::StateUnavailable)?;
        let operation = if operation.operation().state() == OperationState::Succeeded {
            operation
        } else {
            self.state.complete_operation(
                &phase_key(journal.journal(), "operation.succeed"),
                journal.journal().operation_id(),
                operation.revision(),
                OperationCompletion::Succeeded,
                self.clock.now()?,
            )?
        };
        let service = self.state.service(journal.journal().service_id())?;
        Ok(NodeModelCommandResult {
            journal,
            service: service.service().clone(),
            operation: operation.operation().clone(),
        })
    }

    // Records one stable failed user-visible operation without leaking provider details.
    fn fail_operation(&self, journal: &NodeModelJournal) -> Result<(), NodeModelError> {
        let Some(operation) = self.state.operation(&journal.operation_id)? else {
            return Ok(());
        };
        if matches!(
            operation.operation().state(),
            OperationState::Failed | OperationState::Cancelled | OperationState::Succeeded
        ) {
            return Ok(());
        }
        let failure = FailureDescription::new(
            journal.failure_code.clone().unwrap_or(
                TechnicalName::parse("model_lifecycle_failed")
                    .map_err(|_| NodeModelError::StateUnavailable)?,
            ),
            "Model lifecycle failed",
        )
        .map_err(|_| NodeModelError::StateUnavailable)?;
        self.state.complete_operation(
            &phase_key(journal, "operation.fail"),
            &journal.operation_id,
            operation.revision(),
            OperationCompletion::Failed(failure),
            self.clock.now()?,
        )?;
        Ok(())
    }

    // Returns one terminal replay result from durable state only.
    fn result(
        &self,
        journal: VersionedNodeModelJournal,
    ) -> Result<NodeModelCommandResult, NodeModelError> {
        let service = self.state.service(journal.journal().service_id())?;
        let operation = self
            .state
            .operation(journal.journal().operation_id())?
            .ok_or(NodeModelError::StateUnavailable)?;
        Ok(NodeModelCommandResult {
            journal,
            service: service.service().clone(),
            operation: operation.operation().clone(),
        })
    }

    // Advances one journal state with optimistic persistence and explicit time.
    fn advance(
        &self,
        journal: VersionedNodeModelJournal,
        state: NodeModelJournalState,
        failure_code: Option<TechnicalName>,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        if journal.journal().state == state && journal.journal().failure_code == failure_code {
            return Ok(journal);
        }
        let mut updated = journal.journal().clone();
        updated.state = state;
        updated.failure_code = failure_code;
        updated.updated_at = self.clock.now()?;
        self.journals.replace(updated, journal.revision())
    }
}

impl NodeModelApiPort for NodeModelCoordinator {
    // Lists the coordinator's exact installed-service projection through the private summary.
    fn list(&self) -> Result<Vec<NodeModelServiceSummary>, NodeModelError> {
        NodeModelCoordinator::list(self).map(|services| {
            services
                .into_iter()
                .map(service_summary)
                .collect::<Vec<_>>()
        })
    }

    // Installs one exact normalized request through the coordinator's durable lifecycle.
    fn install(
        &self,
        request: NodeModelInstallRequest,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::install(self, request).map(command_summary)
    }

    // Checks or applies one signed runtime replacement through ModelCoordinator.
    fn update(
        &self,
        request: NodeModelUpdateRequest,
    ) -> Result<NodeModelUpdateSummary, NodeModelError> {
        NodeModelCoordinator::update(self, request)
    }

    // Pauses one service through the coordinator's durable lifecycle.
    fn pause(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::pause(self, identity, service_id).map(command_summary)
    }

    // Resumes one service through the coordinator's durable lifecycle.
    fn resume(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::resume(self, identity, service_id).map(command_summary)
    }

    // Restarts one service through the coordinator's durable lifecycle.
    fn restart(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::restart(self, identity, service_id).map(command_summary)
    }

    // Recovers one service through the coordinator's explicit protection-aware lifecycle.
    fn recover(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::recover(self, identity, service_id).map(command_summary)
    }

    // Removes one complete or node-scoped selection through the ordered cleanup lifecycle.
    fn remove(
        &self,
        request: NodeModelRemoveRequest,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::remove(self, request).map(command_summary)
    }

    // Restores one service's latest retained prior runtime through the coordinator journal.
    fn rollback(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        target_id: Option<TargetId>,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        NodeModelCoordinator::rollback(self, identity, service_id, target_id).map(command_summary)
    }

    // Previews one exact retained-runtime transition without advancing manager state.
    fn preview_rollback(
        &self,
        service_id: &ModelServiceId,
        target_id: Option<&TargetId>,
    ) -> Result<NodeModelRollbackPreview, NodeModelError> {
        NodeModelCoordinator::preview_rollback(self, service_id, target_id)
    }

    // Reads bounded operation and recovery identities through the coordinator's log projection.
    fn logs(&self, service_id: &ModelServiceId) -> Result<NodeModelLogSummary, NodeModelError> {
        NodeModelCoordinator::logs(self, service_id).map(|logs| log_summary(service_id, logs))
    }

    // Reads one bounded opaque runtime batch through PlacementManager ownership.
    fn runtime_logs(
        &self,
        request: NodeModelRuntimeLogRequest,
    ) -> Result<NodeModelRuntimeLogBatch, NodeModelError> {
        NodeModelCoordinator::runtime_logs(self, request)
    }
}

// Converts one complete coordinator projection into the closed private service summary.
fn service_summary(projection: NodeModelServiceProjection) -> NodeModelServiceSummary {
    NodeModelServiceSummary::new(
        projection.service().service_id().clone(),
        projection.service().logical_model().clone(),
        projection.service().desired_state(),
        projection.service().placement_group_ids().to_vec(),
        projection
            .installations()
            .iter()
            .map(|installation| installation.installation_id().clone())
            .collect(),
        projection.evidence_labels(),
    )
}

// Converts one complete coordinator result into the closed private command summary.
fn command_summary(result: NodeModelCommandResult) -> NodeModelCommandSummary {
    NodeModelCommandSummary::new(
        result.operation().operation_id().clone(),
        result.service().service_id().clone(),
        result.service().logical_model().clone(),
        result.service().desired_state(),
        result.journal().journal().action(),
        result.journal().journal().state(),
        result.journal().journal().failure_code().cloned(),
    )
}

// Converts one complete coordinator log projection into bounded redacted identities.
fn log_summary(service_id: &ModelServiceId, logs: NodeModelLogProjection) -> NodeModelLogSummary {
    NodeModelLogSummary::new(
        service_id.clone(),
        logs.operations()
            .iter()
            .map(|operation| operation.operation_id().clone())
            .collect(),
        logs.journals()
            .iter()
            .map(|journal| journal.journal().operation_id().clone())
            .collect(),
        logs.journals()
            .iter()
            .filter_map(|journal| journal.journal().failure_code().cloned())
            .collect(),
    )
}

// Returns whether one install retry exactly matches its normalized durable command.
fn install_request_matches(journal: &NodeModelJournal, request: &NodeModelInstallRequest) -> bool {
    journal.action == NodeModelAction::Install
        && journal.operation_id == request.identity.operation_id
        && journal.idempotency_key == request.identity.idempotency_key
        && journal.service_id == request.service_id
        && journal.logical_model == request.logical_model
        && journal.install_groups == request.groups
}

// Returns whether one update replay uses the exact same normalized service command.
fn update_request_matches(journal: &NodeModelJournal, request: &NodeModelUpdateRequest) -> bool {
    journal.action == NodeModelAction::Update
        && journal.operation_id == request.identity.operation_id
        && journal.idempotency_key == request.identity.idempotency_key
        && journal.service_id == request.service_id
        && journal
            .install_groups
            .iter()
            .all(|group| group.explicit_candidate_id == request.explicit_candidate_id)
}

// Returns whether one rollback replay matches the exact persisted service and target selection.
fn rollback_request_matches(
    journal: &NodeModelJournal,
    identity: &NodeModelCommandIdentity,
    service_id: &ModelServiceId,
    target_id: Option<&TargetId>,
) -> bool {
    journal.action == NodeModelAction::Rollback
        && journal.operation_id == *identity.operation_id()
        && journal.idempotency_key == *identity.idempotency_key()
        && journal.service_id == *service_id
        && journal.rollback_target_id() == target_id
}

// Returns one placement record's exact node set in stable identity order.
fn placement_node_ids(record: &PlacementRecord) -> Vec<NodeId> {
    let mut node_ids = record
        .placements()
        .iter()
        .map(|placement| placement.assignment().node_id().clone())
        .collect::<Vec<_>>();
    node_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    node_ids
}

// Projects one exact runtime identity into the redacted rollback preview shape.
fn rollback_runtime(runtime: &RuntimeIdentity) -> NodeModelRollbackRuntime {
    NodeModelRollbackRuntime::new(
        runtime.candidate_id().clone(),
        runtime.version().clone(),
        runtime.target_id().clone(),
        runtime.source().clone(),
    )
}

// Requires one retained predecessor to preserve topology and change immutable runtime bytes.
fn rollback_pair_is_valid(current: &PlacementRecord, previous: &PlacementRecord) -> bool {
    let current_runtime = current.group().runtime();
    let previous_runtime = previous.group().runtime();
    current.group().service_id() == previous.group().service_id()
        && current.group().state() != PlacementGroupState::Removed
        && previous.group().state() == PlacementGroupState::Removed
        && current_runtime.candidate_id() == previous_runtime.candidate_id()
        && current_runtime.target_id() == previous_runtime.target_id()
        && current_runtime.version() != previous_runtime.version()
        && current_runtime.source() != previous_runtime.source()
        && placement_node_ids(current) == placement_node_ids(previous)
}

// Normalizes one current group state to the exact intent restored after rollback failure.
fn rollback_initial_state(
    state: PlacementGroupState,
) -> Result<PlacementGroupState, NodeModelError> {
    match state {
        PlacementGroupState::Running => Ok(PlacementGroupState::Running),
        PlacementGroupState::Staged | PlacementGroupState::Stopped => {
            Ok(PlacementGroupState::Stopped)
        }
        _ => Err(NodeModelError::RecoveryRequired),
    }
}

// Requires every installation in one group to expose the same sealed runtime identity.
fn require_group_runtime_identity(
    installations: &[RuntimeInstallation],
) -> Result<&RuntimeIdentity, NodeModelError> {
    let first = installations
        .first()
        .ok_or(NodeModelError::InvalidRequest {
            reason: "placement group has no runtime installation",
        })?;
    if installations
        .iter()
        .any(|installation| installation.runtime() != first.runtime())
    {
        return Err(NodeModelError::InvalidRequest {
            reason: "placement group installations have different runtime identities",
        });
    }
    Ok(first.runtime())
}

// Requires one provider request to bind the exact service, runtime, nodes, and installations.
fn validate_placement_request(
    request: &PlacementRequest,
    placement_group_id: &PlacementGroupId,
    service_id: &ModelServiceId,
    installations: &[RuntimeInstallation],
) -> Result<(), NodeModelError> {
    let runtime = require_group_runtime_identity(installations)?;
    if request.placement_group_id() != placement_group_id
        || request.service_id() != service_id
        || request.runtime() != runtime
    {
        return Err(NodeModelError::InvalidRequest {
            reason: "placement request differs from its service or runtime receipts",
        });
    }
    let expected: HashMap<&NodeId, &RuntimeInstallationId> = installations
        .iter()
        .map(|installation| (installation.node_id(), installation.installation_id()))
        .collect();
    if request.nodes().len() != expected.len()
        || request.nodes().iter().any(|node| {
            expected.get(node.node_id()).copied() != Some(node.runtime_installation_id())
        })
    {
        return Err(NodeModelError::InvalidRequest {
            reason: "placement request node bindings differ from runtime receipts",
        });
    }
    Ok(())
}

// Returns whether one authoritative aggregate exactly represents one placement request.
fn placement_record_matches(record: &PlacementRecord, request: &PlacementRequest) -> bool {
    if record.group().service_id() != request.service_id()
        || record.group().runtime() != request.runtime()
        || record.placements().len() != request.nodes().len()
    {
        return false;
    }
    let expected: HashMap<&NodeId, &RuntimeInstallationId> = request
        .nodes()
        .iter()
        .map(|node| (node.node_id(), node.runtime_installation_id()))
        .collect();
    record.placements().iter().all(|placement| {
        expected.get(placement.assignment().node_id()).copied()
            == Some(placement.assignment().runtime_installation_id())
    })
}

// Returns whether one installation is the exact selected immutable candidate.
fn candidate_matches_installation(
    candidate: &RuntimeCandidate,
    installation: &RuntimeInstallation,
) -> bool {
    installation.logical_model() == candidate.logical_model()
        && installation.runtime() == candidate.runtime()
        && installation.artifacts() == candidate.artifacts()
}

// Returns one bounded database idempotency identity for a command phase.
fn phase_key(journal: &NodeModelJournal, phase: &str) -> String {
    format!("{}.{}", journal.idempotency_key.as_str(), phase)
}

// Maps one redacted failure surface to a stable non-secret operation code.
fn failure_code(error: &NodeModelError) -> Result<TechnicalName, NodeModelError> {
    let value = match error {
        NodeModelError::InvalidRequest { .. } => "model_request_invalid",
        NodeModelError::StateUnavailable => "model_state_unavailable",
        NodeModelError::Runtime(_) => "model_runtime_failed",
        NodeModelError::Placement(_) => "model_placement_failed",
        NodeModelError::JournalUnavailable
        | NodeModelError::JournalConflict
        | NodeModelError::JournalCorrupt => "model_journal_failed",
        NodeModelError::ProviderUnavailable => "model_provider_failed",
        NodeModelError::RecoveryRequired => "model_recovery_required",
    };
    TechnicalName::parse(value).map_err(|_| NodeModelError::StateUnavailable)
}
