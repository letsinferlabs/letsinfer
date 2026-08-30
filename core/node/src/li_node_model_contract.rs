// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use li_core_interface::{
    EvidenceLabel, HardwareObservation, LogicalModelName, ModelService, ModelServiceDesiredState,
    ModelServiceId, NodeId, Operation, OperationId, OperationKind, OperationTarget,
    PlacementGroupId, PlacementGroupState, RuntimeCandidateId, RuntimeInstallation,
    RuntimeInstallationId, RuntimeSource, RuntimeVersion, TargetId, TechnicalName,
    UnixMilliseconds,
};
use li_placement_manager::{
    PlacementError, PlacementLogBatch, PlacementLogCursor, PlacementLogReadRequest,
    PlacementRecord, PlacementRequest, VersionedPlacementRecord,
};
use li_runtime_manager::{RuntimeCandidate, RuntimeError, VersionedRuntimeInstallation};
use sha2::{Digest, Sha256};

use crate::{NodeManagerError, OperationCompletion};

pub(crate) const MAX_INSTALL_GROUPS: usize = 128;
const MAX_NODES_PER_GROUP: usize = 64;
const MAXIMUM_RUNTIME_LOG_LINES: u32 = 10_000;
const MAXIMUM_RUNTIME_LOG_BYTES: usize = 512 * 1024;
const MAXIMUM_RUNTIME_LOG_WAIT: Duration = Duration::from_secs(1);

// Derives one opaque stable placement-group identity from its durable command position.
pub(crate) fn planned_placement_group_id(
    operation_id: &OperationId,
    group_index: usize,
) -> Result<PlacementGroupId, NodeModelError> {
    let mut hasher = Sha256::new();
    hasher.update(b"li_node_model_placement_group_v1\0");
    hasher.update(operation_id.as_str().as_bytes());
    hasher.update(
        u64::try_from(group_index)
            .map_err(|_| NodeModelError::InvalidRequest {
                reason: "placement group index is too large",
            })?
            .to_be_bytes(),
    );
    let digest = hasher.finalize();
    let identity = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    PlacementGroupId::parse(&identity).map_err(|_| NodeModelError::StateUnavailable)
}

// Derives one deterministic restoration identity distinct from the command's target group.
pub(crate) fn planned_restoration_group_id(
    operation_id: &OperationId,
    group_index: usize,
) -> Result<PlacementGroupId, NodeModelError> {
    let mut hasher = Sha256::new();
    hasher.update(b"li_node_model_restoration_group_v1\0");
    hasher.update(operation_id.as_str().as_bytes());
    hasher.update(
        u64::try_from(group_index)
            .map_err(|_| NodeModelError::InvalidRequest {
                reason: "restoration group index is too large",
            })?
            .to_be_bytes(),
    );
    let digest = hasher.finalize();
    let identity = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    PlacementGroupId::parse(&identity).map_err(|_| NodeModelError::StateUnavailable)
}

// Identifies the exact model-service lifecycle owned by one durable command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeModelAction {
    Install,
    Update,
    Pause,
    Resume,
    Restart,
    Recover,
    Remove,
    Rollback,
}

impl NodeModelAction {
    // Returns the stable private wire name for this lifecycle action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Restart => "restart",
            Self::Recover => "recover",
            Self::Remove => "remove",
            Self::Rollback => "rollback",
        }
    }

    // Returns the user-visible operation kind for this model lifecycle.
    pub(crate) const fn operation_kind(self) -> OperationKind {
        match self {
            Self::Install => OperationKind::Install,
            Self::Update => OperationKind::Update,
            Self::Pause => OperationKind::Stop,
            Self::Resume => OperationKind::Start,
            Self::Restart => OperationKind::Restart,
            Self::Recover | Self::Rollback => OperationKind::Recover,
            Self::Remove => OperationKind::Remove,
        }
    }
}

// Describes whether one signed runtime update would change an installed service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeModelUpdateDisposition {
    Current,
    UpdateAvailable,
    Updated,
}

impl NodeModelUpdateDisposition {
    // Returns the stable private wire name for this update disposition.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::UpdateAvailable => "update_available",
            Self::Updated => "updated",
        }
    }
}

// Carries one normalized model-update command after CLI selector resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelUpdateRequest {
    pub(crate) identity: NodeModelCommandIdentity,
    pub(crate) service_id: ModelServiceId,
    pub(crate) explicit_candidate_id: Option<RuntimeCandidateId>,
    pub(crate) dry_run: bool,
}

impl NodeModelUpdateRequest {
    // Creates one exact signed-catalog update request for an installed service.
    pub const fn new(
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        explicit_candidate_id: Option<RuntimeCandidateId>,
        dry_run: bool,
    ) -> Self {
        Self {
            identity,
            service_id,
            explicit_candidate_id,
            dry_run,
        }
    }

    // Returns the durable command and replay identities.
    pub const fn identity(&self) -> &NodeModelCommandIdentity {
        &self.identity
    }

    // Returns the exact installed logical service.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns an explicitly pinned signed runtime candidate when supplied.
    pub const fn explicit_candidate_id(&self) -> Option<&RuntimeCandidateId> {
        self.explicit_candidate_id.as_ref()
    }

    // Returns whether provider mutation is forbidden for this request.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

// Projects one signed runtime update decision without exposing catalog internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelUpdateSummary {
    service_id: ModelServiceId,
    logical_model: LogicalModelName,
    disposition: NodeModelUpdateDisposition,
    placement_group_count: usize,
    command: Option<NodeModelCommandSummary>,
}

impl NodeModelUpdateSummary {
    // Creates one bounded update projection from a coordinator decision.
    pub const fn new(
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        disposition: NodeModelUpdateDisposition,
        placement_group_count: usize,
        command: Option<NodeModelCommandSummary>,
    ) -> Self {
        Self {
            service_id,
            logical_model,
            disposition,
            placement_group_count,
            command,
        }
    }

    // Returns the exact logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns whether the service is current, has an update, or was updated.
    pub const fn disposition(&self) -> NodeModelUpdateDisposition {
        self.disposition
    }

    // Returns the number of independently replaced placement groups.
    pub const fn placement_group_count(&self) -> usize {
        self.placement_group_count
    }

    // Returns the durable mutation projection only when an update executed.
    pub const fn command(&self) -> Option<&NodeModelCommandSummary> {
        self.command.as_ref()
    }
}

// Carries the explicit operation and idempotency identities for one command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelCommandIdentity {
    pub(crate) operation_id: OperationId,
    pub(crate) idempotency_key: TechnicalName,
}

// Selects every placement group or only groups intersecting exact authenticated nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeModelRemovalSelection {
    All,
    Nodes(Vec<NodeId>),
}

impl NodeModelRemovalSelection {
    // Creates one bounded unique node selection for partial placement-group removal.
    pub fn nodes(mut node_ids: Vec<NodeId>) -> Result<Self, NodeModelError> {
        let unique: HashSet<&NodeId> = node_ids.iter().collect();
        if node_ids.is_empty()
            || node_ids.len() > MAX_NODES_PER_GROUP
            || unique.len() != node_ids.len()
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "model removal node identities must be unique and bounded",
            });
        }
        node_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(Self::Nodes(node_ids))
    }

    // Returns exact selected nodes or none when every placement group is selected.
    pub fn node_ids(&self) -> Option<&[NodeId]> {
        match self {
            Self::All => None,
            Self::Nodes(node_ids) => Some(node_ids),
        }
    }
}

// Selects whether service removal also retires its unreferenced runtime installations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeModelRemovalRetention {
    RemoveUnreferencedRuntimes,
    PreserveModels,
}

// Carries one durable complete or partial model-service removal command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRemoveRequest {
    identity: NodeModelCommandIdentity,
    service_id: ModelServiceId,
    selection: NodeModelRemovalSelection,
    runtime_retention: NodeModelRemovalRetention,
}

impl NodeModelRemoveRequest {
    // Creates one already-validated removal request from explicit placement and runtime policies.
    pub const fn new(
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        selection: NodeModelRemovalSelection,
        runtime_retention: NodeModelRemovalRetention,
    ) -> Self {
        Self {
            identity,
            service_id,
            selection,
            runtime_retention,
        }
    }

    // Returns the durable command identity.
    pub const fn identity(&self) -> &NodeModelCommandIdentity {
        &self.identity
    }

    // Returns the exact logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the complete or node-scoped placement selection.
    pub const fn selection(&self) -> &NodeModelRemovalSelection {
        &self.selection
    }

    // Returns whether unreferenced runtime installations are removed or preserved.
    pub const fn runtime_retention(&self) -> NodeModelRemovalRetention {
        self.runtime_retention
    }
}

impl NodeModelCommandIdentity {
    // Creates one bounded command identity supplied by the caller.
    pub const fn new(operation_id: OperationId, idempotency_key: TechnicalName) -> Self {
        Self {
            operation_id,
            idempotency_key,
        }
    }

    // Returns the durable operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    // Returns the canonical command idempotency identity.
    pub const fn idempotency_key(&self) -> &TechnicalName {
        &self.idempotency_key
    }
}

// Describes one target-specific placement group without encoding engine topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelInstallGroup {
    pub(crate) node_ids: Vec<NodeId>,
    pub(crate) explicit_candidate_id: Option<RuntimeCandidateId>,
}

impl NodeModelInstallGroup {
    // Creates one bounded unique node set for one independent placement group.
    pub fn new(
        node_ids: Vec<NodeId>,
        explicit_candidate_id: Option<RuntimeCandidateId>,
    ) -> Result<Self, NodeModelError> {
        let unique: HashSet<&NodeId> = node_ids.iter().collect();
        if node_ids.is_empty()
            || node_ids.len() > MAX_NODES_PER_GROUP
            || unique.len() != node_ids.len()
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "model install group node identities must be unique and bounded",
            });
        }
        Ok(Self {
            node_ids,
            explicit_candidate_id,
        })
    }

    // Returns the exact authenticated nodes assigned to this group.
    pub fn node_ids(&self) -> &[NodeId] {
        &self.node_ids
    }

    // Returns the explicit runtime candidate when selection is pinned by the caller.
    pub const fn explicit_candidate_id(&self) -> Option<&RuntimeCandidateId> {
        self.explicit_candidate_id.as_ref()
    }
}

// Binds one retained node assignment to its exact still-available runtime installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRetainedNode {
    pub(crate) node_id: NodeId,
    pub(crate) installation_id: RuntimeInstallationId,
}

impl NodeModelRetainedNode {
    // Creates one exact retained assignment without consulting a catalog.
    pub const fn new(node_id: NodeId, installation_id: RuntimeInstallationId) -> Self {
        Self {
            node_id,
            installation_id,
        }
    }

    // Returns the authenticated node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact retained runtime installation identity.
    pub const fn installation_id(&self) -> &RuntimeInstallationId {
        &self.installation_id
    }
}

// Stores one removed group and the deterministic identity used to restore it after failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRetainedGroup {
    pub(crate) source_group_id: PlacementGroupId,
    pub(crate) restoration_group_id: PlacementGroupId,
    pub(crate) initial_state: PlacementGroupState,
    pub(crate) nodes: Vec<NodeModelRetainedNode>,
}

impl NodeModelRetainedGroup {
    // Creates one bounded exact restoration plan with unique nodes and installations.
    pub fn new(
        source_group_id: PlacementGroupId,
        restoration_group_id: PlacementGroupId,
        initial_state: PlacementGroupState,
        nodes: Vec<NodeModelRetainedNode>,
    ) -> Result<Self, NodeModelError> {
        let node_ids = nodes
            .iter()
            .map(NodeModelRetainedNode::node_id)
            .collect::<HashSet<_>>();
        let installation_ids = nodes
            .iter()
            .map(NodeModelRetainedNode::installation_id)
            .collect::<HashSet<_>>();
        if nodes.is_empty()
            || nodes.len() > MAX_NODES_PER_GROUP
            || node_ids.len() != nodes.len()
            || installation_ids.len() != nodes.len()
            || !matches!(
                initial_state,
                PlacementGroupState::Running
                    | PlacementGroupState::Staged
                    | PlacementGroupState::Stopped
            )
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "retained placement group is invalid",
            });
        }
        Ok(Self {
            source_group_id,
            restoration_group_id,
            initial_state,
            nodes,
        })
    }

    // Returns the removed source group whose assignments were retained.
    pub const fn source_group_id(&self) -> &PlacementGroupId {
        &self.source_group_id
    }

    // Returns the deterministic group identity used only for failure restoration.
    pub const fn restoration_group_id(&self) -> &PlacementGroupId {
        &self.restoration_group_id
    }

    // Returns the exact pre-command running or stopped lifecycle state.
    pub const fn initial_state(&self) -> PlacementGroupState {
        self.initial_state
    }

    // Returns every exact node and retained runtime assignment in group order.
    pub fn nodes(&self) -> &[NodeModelRetainedNode] {
        &self.nodes
    }
}

// Describes one complete durable model installation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelInstallRequest {
    pub(crate) identity: NodeModelCommandIdentity,
    pub(crate) service_id: ModelServiceId,
    pub(crate) logical_model: LogicalModelName,
    pub(crate) groups: Vec<NodeModelInstallGroup>,
}

impl NodeModelInstallRequest {
    // Creates one bounded model service and its independent target-specific groups.
    pub fn new(
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        groups: Vec<NodeModelInstallGroup>,
    ) -> Result<Self, NodeModelError> {
        if groups.is_empty() || groups.len() > MAX_INSTALL_GROUPS {
            return Err(NodeModelError::InvalidRequest {
                reason: "model install requires a bounded non-empty placement-group plan",
            });
        }
        Ok(Self {
            identity,
            service_id,
            logical_model,
            groups,
        })
    }

    // Returns the explicit command identity.
    pub const fn identity(&self) -> &NodeModelCommandIdentity {
        &self.identity
    }

    // Returns the planned logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns every independent placement-group plan in caller order.
    pub fn groups(&self) -> &[NodeModelInstallGroup] {
        &self.groups
    }
}

// Identifies a pending, created, reused, or ambiguously owned installation acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeModelRuntimeDisposition {
    InstallPending,
    Created,
    Reused,
    OwnershipUnknown,
}

// Binds one planned group node to its exact selected candidate and installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRuntimeReceipt {
    pub(crate) group_index: usize,
    pub(crate) node_id: NodeId,
    pub(crate) candidate_id: RuntimeCandidateId,
    pub(crate) installation_id: Option<RuntimeInstallationId>,
    pub(crate) disposition: NodeModelRuntimeDisposition,
}

impl NodeModelRuntimeReceipt {
    // Returns the planned placement-group index.
    pub const fn group_index(&self) -> usize {
        self.group_index
    }

    // Returns the exact installation node.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the selected candidate identity fixed before acquisition.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns the exact installation after acquisition or reuse resolves.
    pub const fn installation_id(&self) -> Option<&RuntimeInstallationId> {
        self.installation_id.as_ref()
    }

    // Returns the exact durable acquisition disposition.
    pub const fn disposition(&self) -> NodeModelRuntimeDisposition {
        self.disposition
    }
}

// Identifies the durable cross-manager lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeModelJournalState {
    Prepared,
    Executing,
    Compensating,
    CleanupPending,
    Succeeded,
    RolledBack,
    Failed,
}

impl NodeModelJournalState {
    // Returns the stable private wire name for this durable lifecycle state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Executing => "executing",
            Self::Compensating => "compensating",
            Self::CleanupPending => "cleanup_pending",
            Self::Succeeded => "succeeded",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
        }
    }

    // Returns whether no further automatic lifecycle progress is required.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::RolledBack | Self::Failed)
    }
}

// Stores one restart-safe normalized command and every committed provider receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelJournal {
    pub(crate) operation_id: OperationId,
    pub(crate) idempotency_key: TechnicalName,
    pub(crate) action: NodeModelAction,
    pub(crate) service_id: ModelServiceId,
    pub(crate) logical_model: LogicalModelName,
    pub(crate) install_groups: Vec<NodeModelInstallGroup>,
    pub(crate) rollback_target_id: Option<TargetId>,
    pub(crate) retained_groups: Vec<NodeModelRetainedGroup>,
    pub(crate) runtime_receipts: Vec<NodeModelRuntimeReceipt>,
    pub(crate) planned_group_ids: Vec<PlacementGroupId>,
    pub(crate) placement_group_ids: Vec<PlacementGroupId>,
    pub(crate) initial_group_states: Vec<(PlacementGroupId, PlacementGroupState)>,
    pub(crate) removal_node_ids: Vec<NodeId>,
    pub(crate) removal_runtime_retention: NodeModelRemovalRetention,
    pub(crate) state: NodeModelJournalState,
    pub(crate) failure_code: Option<TechnicalName>,
    pub(crate) created_at: UnixMilliseconds,
    pub(crate) updated_at: UnixMilliseconds,
}

impl NodeModelJournal {
    // Returns the exact command operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    // Returns the normalized model action.
    pub const fn action(&self) -> NodeModelAction {
        self.action
    }

    // Returns the exact service identity owned by this command.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the logical model identity captured before mutation.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns every fixed runtime acquisition receipt.
    pub fn runtime_receipts(&self) -> &[NodeModelRuntimeReceipt] {
        &self.runtime_receipts
    }

    // Returns the optional runtime target selected by a user-facing rollback.
    pub const fn rollback_target_id(&self) -> Option<&TargetId> {
        self.rollback_target_id.as_ref()
    }

    // Returns every exact source group retained for rollback or failure restoration.
    pub fn retained_groups(&self) -> &[NodeModelRetainedGroup] {
        &self.retained_groups
    }

    // Returns every exact placement-group identity fixed before manager mutation.
    pub fn planned_group_ids(&self) -> &[PlacementGroupId] {
        &self.planned_group_ids
    }

    // Returns every exact placement group created or targeted by the command.
    pub fn placement_group_ids(&self) -> &[PlacementGroupId] {
        &self.placement_group_ids
    }

    // Returns exact node selectors for a partial removal or none for complete removal.
    pub fn removal_node_ids(&self) -> &[NodeId] {
        &self.removal_node_ids
    }

    // Returns the exact runtime-retention decision committed before model removal began.
    pub const fn removal_runtime_retention(&self) -> NodeModelRemovalRetention {
        self.removal_runtime_retention
    }

    // Returns the durable execution or compensation state.
    pub const fn state(&self) -> NodeModelJournalState {
        self.state
    }

    // Returns the stable redacted failure code when execution failed.
    pub const fn failure_code(&self) -> Option<&TechnicalName> {
        self.failure_code.as_ref()
    }

    // Returns when the journal was first committed.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns when the journal most recently advanced.
    pub const fn updated_at(&self) -> UnixMilliseconds {
        self.updated_at
    }
}

// Returns one journal with its optimistic persistence revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeModelJournal {
    journal: NodeModelJournal,
    revision: u64,
}

impl VersionedNodeModelJournal {
    // Creates one validated versioned journal for stores and deterministic tests.
    pub const fn new(journal: NodeModelJournal, revision: u64) -> Self {
        Self { journal, revision }
    }

    // Returns the immutable journal snapshot.
    pub const fn journal(&self) -> &NodeModelJournal {
        &self.journal
    }

    // Returns the optimistic revision required by the next advance.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines the sole durable cross-manager command journal.
pub trait NodeModelJournalStore: Send + Sync {
    // Creates one normalized command before any manager or provider mutation.
    fn create(
        &self,
        journal: NodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError>;

    // Returns one exact command journal when it exists.
    fn read(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<VersionedNodeModelJournal>, NodeModelError>;

    // Returns every journal in stable operation identity order.
    fn all(&self) -> Result<Vec<VersionedNodeModelJournal>, NodeModelError>;

    // Replaces one exact journal revision.
    fn replace(
        &self,
        journal: NodeModelJournal,
        expected_revision: u64,
    ) -> Result<VersionedNodeModelJournal, NodeModelError>;
}

// Returns one model service with the revision required by its next transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeModelService {
    service: ModelService,
    revision: u64,
}

impl VersionedNodeModelService {
    // Creates one versioned service projection for manager ports and tests.
    pub const fn new(service: ModelService, revision: u64) -> Self {
        Self { service, revision }
    }

    // Returns the service snapshot.
    pub const fn service(&self) -> &ModelService {
        &self.service
    }

    // Returns the optimistic service revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Returns one operation with the revision required by its next transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeModelOperation {
    operation: Operation,
    revision: u64,
}

impl VersionedNodeModelOperation {
    // Creates one versioned operation projection for manager ports and tests.
    pub const fn new(operation: Operation, revision: u64) -> Self {
        Self {
            operation,
            revision,
        }
    }

    // Returns the operation snapshot.
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    // Returns the optimistic operation revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines the exact NodeManager state capability consumed by model orchestration.
pub trait NodeModelStatePort: Send + Sync {
    // Returns every durable logical model service.
    fn services(&self) -> Result<Vec<ModelService>, NodeManagerError>;

    // Returns one exact service and its optimistic revision.
    fn service(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<VersionedNodeModelService, NodeManagerError>;

    // Creates one empty stopped service before provider mutation.
    fn create_service(
        &self,
        idempotency_key: &str,
        service: ModelService,
    ) -> Result<VersionedNodeModelService, NodeManagerError>;

    // Attaches one exact group after PlacementManager stages it.
    fn attach_group(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError>;

    // Detaches one exact group only after PlacementManager releases it.
    fn detach_group(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: &PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError>;

    // Applies one complete model-service desired-state transition.
    fn transition_service(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        desired_state: ModelServiceDesiredState,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelService, NodeManagerError>;

    // Returns one exact user-visible operation when it exists.
    fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<VersionedNodeModelOperation>, NodeManagerError>;

    // Returns every user-visible operation.
    fn operations(&self) -> Result<Vec<Operation>, NodeManagerError>;

    // Creates one pending user-visible operation.
    fn begin_operation(
        &self,
        idempotency_key: &str,
        operation_id: OperationId,
        kind: OperationKind,
        target: OperationTarget,
        created_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError>;

    // Advances one pending user-visible operation.
    fn start_operation(
        &self,
        idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        started_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError>;

    // Completes one pending or running user-visible operation.
    fn complete_operation(
        &self,
        idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        completion: OperationCompletion,
        completed_at: UnixMilliseconds,
    ) -> Result<VersionedNodeModelOperation, NodeManagerError>;
}

// Defines RuntimeManager selection, acquisition, projection, and cleanup for Node.
pub trait NodeModelRuntimePort: Send + Sync {
    // Selects one exact compatible candidate without applying evidence policy.
    fn select(
        &self,
        model: &LogicalModelName,
        explicit_candidate_id: Option<&RuntimeCandidateId>,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeCandidate, RuntimeError>;

    // Installs one exact selected candidate on an authenticated node.
    fn install(
        &self,
        node_id: NodeId,
        model: &LogicalModelName,
        candidate_id: &RuntimeCandidateId,
        hardware: &HardwareObservation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError>;

    // Removes one exact installation.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError>;

    // Removes one exact installation while retaining its model artifacts for exact reuse.
    fn remove_preserving_models(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Returns one exact installation when it exists.
    fn installation(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError>;

    // Returns every exact installation in stable identity order.
    fn installations(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError>;
}

// Defines PlacementManager lifecycle and authoritative aggregate projection for Node.
pub trait NodeModelPlacementPort: Send + Sync {
    // Allocates and stages one complete group.
    fn stage(&self, request: PlacementRequest) -> Result<VersionedPlacementRecord, PlacementError>;

    // Starts one exact complete group.
    fn start(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError>;

    // Stops one exact complete group while retaining assignments.
    fn stop(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError>;

    // Recovers one exact complete group.
    fn recover(
        &self,
        placement_group_id: &PlacementGroupId,
        acknowledge_protection_trips: bool,
    ) -> Result<VersionedPlacementRecord, PlacementError>;

    // Removes one exact complete group and releases assignments.
    fn remove(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError>;

    // Returns one exact authoritative group aggregate when it exists.
    fn record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError>;

    // Returns every authoritative group aggregate in stable identity order.
    fn records(&self) -> Result<Vec<PlacementRecord>, PlacementError>;

    // Reads one bounded opaque runtime-log batch from an exact placement group.
    fn read_logs(
        &self,
        request: PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError> {
        let _ = request;
        Err(PlacementError::ExecutionUnavailable)
    }
}

// Reconstructs one fully typed PlacementManager request from durable installation receipts.
pub trait NodeModelPlacementRequestProvider: Send + Sync {
    // Returns one exact model-neutral placement request for a planned group.
    fn request(
        &self,
        service_id: &ModelServiceId,
        group_index: usize,
        placement_group_id: &PlacementGroupId,
        installations: &[RuntimeInstallation],
    ) -> Result<PlacementRequest, NodeModelError>;
}

// Supplies current HardwareManager observations for exact authenticated nodes.
pub trait NodeModelHardwareProvider: Send + Sync {
    // Returns one current boot-scoped observation for the exact node.
    fn observation(&self, node_id: &NodeId) -> Result<HardwareObservation, NodeModelError>;
}

// Supplies model lifecycle time explicitly.
pub trait NodeModelClock: Send + Sync {
    // Returns current Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, NodeModelError>;
}

// Supplies aggregate records for a concrete PlacementManager composition.
pub trait NodeModelPlacementRecordProvider: Send + Sync {
    // Returns every fully validated aggregate.
    fn records(&self) -> Result<Vec<PlacementRecord>, PlacementError>;
}

// Identifies one stable cross-manager model lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeModelError {
    InvalidRequest { reason: &'static str },
    StateUnavailable,
    Runtime(RuntimeError),
    Placement(PlacementError),
    JournalUnavailable,
    JournalConflict,
    JournalCorrupt,
    ProviderUnavailable,
    RecoveryRequired,
}

impl fmt::Display for NodeModelError {
    // Presents stable redacted orchestration language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { reason } => {
                write!(formatter, "model command is invalid: {reason}")
            }
            Self::StateUnavailable => formatter.write_str("model service state is unavailable"),
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::Placement(error) => write!(formatter, "{error}"),
            Self::JournalUnavailable => {
                formatter.write_str("model lifecycle journal is unavailable")
            }
            Self::JournalConflict => formatter.write_str("model lifecycle changed concurrently"),
            Self::JournalCorrupt => formatter.write_str("model lifecycle journal is corrupt"),
            Self::ProviderUnavailable => {
                formatter.write_str("model lifecycle provider is unavailable")
            }
            Self::RecoveryRequired => formatter.write_str("model lifecycle requires recovery"),
        }
    }
}

impl Error for NodeModelError {}

impl From<RuntimeError> for NodeModelError {
    // Preserves RuntimeManager's stable failure surface.
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<PlacementError> for NodeModelError {
    // Preserves PlacementManager's stable failure surface.
    fn from(error: PlacementError) -> Self {
        Self::Placement(error)
    }
}

impl From<NodeManagerError> for NodeModelError {
    // Redacts NodeManager storage and state details at the coordinator boundary.
    fn from(_: NodeManagerError) -> Self {
        Self::StateUnavailable
    }
}

// Projects one logical service with its exact group and installation identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelServiceProjection {
    pub(crate) service: ModelService,
    pub(crate) placement_groups: Vec<PlacementRecord>,
    pub(crate) installations: Vec<RuntimeInstallation>,
}

impl NodeModelServiceProjection {
    // Returns the durable logical service snapshot.
    pub const fn service(&self) -> &ModelService {
        &self.service
    }

    // Returns every exact placement-group aggregate in service order.
    pub fn placement_groups(&self) -> &[PlacementRecord] {
        &self.placement_groups
    }

    // Returns every exact referenced installation in stable identity order.
    pub fn installations(&self) -> &[RuntimeInstallation] {
        &self.installations
    }

    // Returns every descriptive evidence label without interpreting it as admission.
    pub fn evidence_labels(&self) -> Vec<EvidenceLabel> {
        self.installations
            .iter()
            .map(RuntimeInstallation::evidence_label)
            .collect()
    }
}

// Projects bounded user-visible operation logs and internal recovery state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelLogProjection {
    pub(crate) operations: Vec<Operation>,
    pub(crate) journals: Vec<VersionedNodeModelJournal>,
}

impl NodeModelLogProjection {
    // Returns every user-visible operation for the service.
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    // Returns every redacted lifecycle journal for the service.
    pub fn journals(&self) -> &[VersionedNodeModelJournal] {
        &self.journals
    }
}

// Returns one completed or replayed model-service command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelCommandResult {
    pub(crate) journal: VersionedNodeModelJournal,
    pub(crate) service: ModelService,
    pub(crate) operation: Operation,
}

// Projects one installed model service without exposing manager-private aggregate documents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelServiceSummary {
    service_id: ModelServiceId,
    logical_model: LogicalModelName,
    desired_state: ModelServiceDesiredState,
    placement_group_ids: Vec<PlacementGroupId>,
    runtime_installation_ids: Vec<RuntimeInstallationId>,
    evidence_labels: Vec<EvidenceLabel>,
}

impl NodeModelServiceSummary {
    // Creates one already-validated private projection for transport and deterministic mocks.
    pub const fn new(
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        desired_state: ModelServiceDesiredState,
        placement_group_ids: Vec<PlacementGroupId>,
        runtime_installation_ids: Vec<RuntimeInstallationId>,
        evidence_labels: Vec<EvidenceLabel>,
    ) -> Self {
        Self {
            service_id,
            logical_model,
            desired_state,
            placement_group_ids,
            runtime_installation_ids,
            evidence_labels,
        }
    }

    // Returns the stable logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the durable desired state.
    pub const fn desired_state(&self) -> ModelServiceDesiredState {
        self.desired_state
    }

    // Returns every exact placement-group identity in service order.
    pub fn placement_group_ids(&self) -> &[PlacementGroupId] {
        &self.placement_group_ids
    }

    // Returns every referenced runtime installation in stable order.
    pub fn runtime_installation_ids(&self) -> &[RuntimeInstallationId] {
        &self.runtime_installation_ids
    }

    // Returns descriptive evidence labels without turning them into an admission gate.
    pub fn evidence_labels(&self) -> &[EvidenceLabel] {
        &self.evidence_labels
    }
}

// Projects one terminal or replayed model command without exposing its private journal document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelCommandSummary {
    operation_id: OperationId,
    service_id: ModelServiceId,
    logical_model: LogicalModelName,
    desired_state: ModelServiceDesiredState,
    action: NodeModelAction,
    journal_state: NodeModelJournalState,
    failure_code: Option<TechnicalName>,
}

impl NodeModelCommandSummary {
    // Creates one typed command projection for transport and deterministic mocks.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        operation_id: OperationId,
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        desired_state: ModelServiceDesiredState,
        action: NodeModelAction,
        journal_state: NodeModelJournalState,
        failure_code: Option<TechnicalName>,
    ) -> Self {
        Self {
            operation_id,
            service_id,
            logical_model,
            desired_state,
            action,
            journal_state,
            failure_code,
        }
    }

    // Returns the durable operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    // Returns the logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the latest service desired state.
    pub const fn desired_state(&self) -> ModelServiceDesiredState {
        self.desired_state
    }

    // Returns the exact model lifecycle action.
    pub const fn action(&self) -> NodeModelAction {
        self.action
    }

    // Returns the durable cross-manager journal state.
    pub const fn journal_state(&self) -> NodeModelJournalState {
        self.journal_state
    }

    // Returns only the stable redacted failure code.
    pub const fn failure_code(&self) -> Option<&TechnicalName> {
        self.failure_code.as_ref()
    }
}

// Projects bounded model lifecycle history without exposing private journal bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelLogSummary {
    service_id: ModelServiceId,
    operation_ids: Vec<OperationId>,
    journal_operation_ids: Vec<OperationId>,
    failure_codes: Vec<TechnicalName>,
}

// Selects and bounds one opaque runtime log read under an exact model service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRuntimeLogRequest {
    service_id: ModelServiceId,
    placement_group_id: Option<PlacementGroupId>,
    cursor: Option<PlacementLogCursor>,
    maximum_lines: u32,
    maximum_bytes: usize,
    wait: Duration,
}

impl NodeModelRuntimeLogRequest {
    // Creates one bounded immediate read or cancellable long-poll request.
    pub fn new(
        service_id: ModelServiceId,
        placement_group_id: Option<PlacementGroupId>,
        cursor: Option<PlacementLogCursor>,
        maximum_lines: u32,
        maximum_bytes: usize,
        wait: Duration,
    ) -> Result<Self, NodeModelError> {
        if maximum_lines == 0
            || maximum_lines > MAXIMUM_RUNTIME_LOG_LINES
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_RUNTIME_LOG_BYTES
            || wait > MAXIMUM_RUNTIME_LOG_WAIT
            || Duration::from_millis(wait.as_millis() as u64) != wait
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "model runtime log read bounds are invalid",
            });
        }
        Ok(Self {
            service_id,
            placement_group_id,
            cursor,
            maximum_lines,
            maximum_bytes,
            wait,
        })
    }

    // Returns the exact logical service selected by the caller.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns an exact placement group or none for unambiguous service resolution.
    pub const fn placement_group_id(&self) -> Option<&PlacementGroupId> {
        self.placement_group_id.as_ref()
    }

    // Returns the prior provider cursor when continuation was requested.
    pub const fn cursor(&self) -> Option<&PlacementLogCursor> {
        self.cursor.as_ref()
    }

    // Returns the maximum logical lines accepted from PlacementManager.
    pub const fn maximum_lines(&self) -> u32 {
        self.maximum_lines
    }

    // Returns the maximum opaque byte count accepted in one response.
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }

    // Returns the bounded provider wait used by a following client.
    pub const fn wait(&self) -> Duration {
        self.wait
    }
}

// Projects one Placement-owned opaque batch through the Node service boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRuntimeLogBatch {
    service_id: ModelServiceId,
    placement: PlacementLogBatch,
}

impl NodeModelRuntimeLogBatch {
    // Creates one service-bound projection from an already validated Placement batch.
    pub const fn new(service_id: ModelServiceId, placement: PlacementLogBatch) -> Self {
        Self {
            service_id,
            placement,
        }
    }

    // Returns the exact logical service selected by the caller.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the exact Placement-owned batch without interpreting runtime bytes.
    pub const fn placement(&self) -> &PlacementLogBatch {
        &self.placement
    }
}

// Identifies one exact immutable runtime in a non-mutating rollback preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRollbackRuntime {
    candidate_id: RuntimeCandidateId,
    version: RuntimeVersion,
    target_id: TargetId,
    source: RuntimeSource,
}

impl NodeModelRollbackRuntime {
    // Creates one exact runtime identity without exposing Engine or model artifact detail.
    pub const fn new(
        candidate_id: RuntimeCandidateId,
        version: RuntimeVersion,
        target_id: TargetId,
        source: RuntimeSource,
    ) -> Self {
        Self {
            candidate_id,
            version,
            target_id,
            source,
        }
    }

    // Returns the stable runtime candidate identity.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns the exact runtime version.
    pub const fn version(&self) -> &RuntimeVersion {
        &self.version
    }

    // Returns the exact target identity.
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    // Returns the exact immutable distribution source.
    pub const fn source(&self) -> &RuntimeSource {
        &self.source
    }
}

// Describes one exact current-to-retained placement-group transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRollbackGroupPreview {
    current_group_id: PlacementGroupId,
    previous_group_id: PlacementGroupId,
    node_ids: Vec<NodeId>,
    current: NodeModelRollbackRuntime,
    previous: NodeModelRollbackRuntime,
}

impl NodeModelRollbackGroupPreview {
    // Creates one already validated same-topology immutable runtime transition.
    pub const fn new(
        current_group_id: PlacementGroupId,
        previous_group_id: PlacementGroupId,
        node_ids: Vec<NodeId>,
        current: NodeModelRollbackRuntime,
        previous: NodeModelRollbackRuntime,
    ) -> Self {
        Self {
            current_group_id,
            previous_group_id,
            node_ids,
            current,
            previous,
        }
    }

    // Restores one private-wire transition while rechecking topology and runtime invariants.
    pub fn restore(
        current_group_id: PlacementGroupId,
        previous_group_id: PlacementGroupId,
        node_ids: Vec<NodeId>,
        current: NodeModelRollbackRuntime,
        previous: NodeModelRollbackRuntime,
    ) -> Result<Self, NodeModelError> {
        let unique = node_ids.iter().collect::<HashSet<_>>();
        if current_group_id == previous_group_id
            || node_ids.is_empty()
            || node_ids.len() > MAX_NODES_PER_GROUP
            || unique.len() != node_ids.len()
            || current.candidate_id() != previous.candidate_id()
            || current.target_id() != previous.target_id()
            || current.version() == previous.version()
            || current.source() == previous.source()
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "rollback group preview is invalid",
            });
        }
        Ok(Self::new(
            current_group_id,
            previous_group_id,
            node_ids,
            current,
            previous,
        ))
    }

    // Returns the currently active placement-group identity.
    pub const fn current_group_id(&self) -> &PlacementGroupId {
        &self.current_group_id
    }

    // Returns the retained prior placement-group identity.
    pub const fn previous_group_id(&self) -> &PlacementGroupId {
        &self.previous_group_id
    }

    // Returns the exact unchanged node topology.
    pub fn node_ids(&self) -> &[NodeId] {
        &self.node_ids
    }

    // Returns the current immutable runtime identity.
    pub const fn current(&self) -> &NodeModelRollbackRuntime {
        &self.current
    }

    // Returns the retained previous immutable runtime identity.
    pub const fn previous(&self) -> &NodeModelRollbackRuntime {
        &self.previous
    }
}

// Describes the exact non-mutating current-to-retained rollback plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelRollbackPreview {
    service_id: ModelServiceId,
    logical_model: LogicalModelName,
    target_id: Option<TargetId>,
    groups: Vec<NodeModelRollbackGroupPreview>,
}

impl NodeModelRollbackPreview {
    // Creates one typed preview only after the coordinator validates every retained group.
    pub const fn new(
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        target_id: Option<TargetId>,
        groups: Vec<NodeModelRollbackGroupPreview>,
    ) -> Self {
        Self {
            service_id,
            logical_model,
            target_id,
            groups,
        }
    }

    // Restores one private-wire preview while rechecking bounds, identity, and target scope.
    pub fn restore(
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        target_id: Option<TargetId>,
        groups: Vec<NodeModelRollbackGroupPreview>,
    ) -> Result<Self, NodeModelError> {
        let current_ids = groups
            .iter()
            .map(NodeModelRollbackGroupPreview::current_group_id)
            .collect::<HashSet<_>>();
        let previous_ids = groups
            .iter()
            .map(NodeModelRollbackGroupPreview::previous_group_id)
            .collect::<HashSet<_>>();
        if groups.is_empty()
            || groups.len() > MAX_INSTALL_GROUPS
            || current_ids.len() != groups.len()
            || previous_ids.len() != groups.len()
            || target_id.as_ref().is_some_and(|target_id| {
                groups
                    .iter()
                    .any(|group| group.current().target_id() != target_id)
            })
        {
            return Err(NodeModelError::InvalidRequest {
                reason: "rollback preview is invalid",
            });
        }
        Ok(Self::new(service_id, logical_model, target_id, groups))
    }

    // Returns the exact logical service selected for rollback.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the optional exact runtime target filter.
    pub const fn target_id(&self) -> Option<&TargetId> {
        self.target_id.as_ref()
    }

    // Returns every exact current-to-retained group transition.
    pub fn groups(&self) -> &[NodeModelRollbackGroupPreview] {
        &self.groups
    }
}

impl NodeModelLogSummary {
    // Creates one typed redacted log projection for transport and deterministic mocks.
    pub const fn new(
        service_id: ModelServiceId,
        operation_ids: Vec<OperationId>,
        journal_operation_ids: Vec<OperationId>,
        failure_codes: Vec<TechnicalName>,
    ) -> Self {
        Self {
            service_id,
            operation_ids,
            journal_operation_ids,
            failure_codes,
        }
    }

    // Returns the exact logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns every user-visible operation identity in coordinator order.
    pub fn operation_ids(&self) -> &[OperationId] {
        &self.operation_ids
    }

    // Returns every recovery-journal operation identity in coordinator order.
    pub fn journal_operation_ids(&self) -> &[OperationId] {
        &self.journal_operation_ids
    }

    // Returns only stable redacted failure identities.
    pub fn failure_codes(&self) -> &[TechnicalName] {
        &self.failure_codes
    }
}

// Defines the exact ModelCoordinator surface consumed by Node private dispatch.
pub trait NodeModelApiPort: Send + Sync {
    // Lists every installed logical model service.
    fn list(&self) -> Result<Vec<NodeModelServiceSummary>, NodeModelError>;

    // Installs one fully normalized placement-group plan.
    fn install(
        &self,
        request: NodeModelInstallRequest,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Checks or applies the latest signed runtime candidate for one installed service.
    fn update(
        &self,
        request: NodeModelUpdateRequest,
    ) -> Result<NodeModelUpdateSummary, NodeModelError>;

    // Pauses one exact logical service.
    fn pause(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Resumes one exact logical service.
    fn resume(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Restarts one exact logical service.
    fn restart(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Recovers one exact failed or degraded logical service.
    fn recover(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Removes every placement group owned by one logical service.
    fn remove(
        &self,
        request: NodeModelRemoveRequest,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Restores the latest retained prior runtime for one service and optional target.
    fn rollback(
        &self,
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        target_id: Option<TargetId>,
    ) -> Result<NodeModelCommandSummary, NodeModelError>;

    // Previews one retained-runtime rollback without creating state or mutating providers.
    fn preview_rollback(
        &self,
        service_id: &ModelServiceId,
        target_id: Option<&TargetId>,
    ) -> Result<NodeModelRollbackPreview, NodeModelError>;

    // Reads bounded operation and recovery-journal identities for one logical service.
    fn logs(&self, service_id: &ModelServiceId) -> Result<NodeModelLogSummary, NodeModelError>;

    // Reads one bounded opaque runtime-log batch through PlacementManager ownership.
    fn runtime_logs(
        &self,
        request: NodeModelRuntimeLogRequest,
    ) -> Result<NodeModelRuntimeLogBatch, NodeModelError> {
        let _ = request;
        Err(NodeModelError::ProviderUnavailable)
    }
}

impl NodeModelCommandResult {
    // Returns the durable cross-manager command journal.
    pub const fn journal(&self) -> &VersionedNodeModelJournal {
        &self.journal
    }

    // Returns the latest logical service snapshot.
    pub const fn service(&self) -> &ModelService {
        &self.service
    }

    // Returns the user-visible operation projection.
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }
}
