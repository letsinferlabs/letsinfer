// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use li_audit_manager::{AuditError, AuditEvent, AuditEventId};
use li_authentication_manager::{
    ApiKey, ApiKeyPolicy, AuthenticationError, ControllerError, ControllerRole,
};
use li_benchmark_manager::BenchmarkError;
use li_core_interface::{
    ControllerId, CredentialId, DisplayName, HardwareObservation, ModelServiceDesiredState,
    ModelServiceId, Node, NodeId, NodeRole, NodeState, OperationId, PairingInviteId,
    PlacementGroupId, RuntimeCandidateId, RuntimeInstallationId, Sha256Digest, TargetId,
    UnixMilliseconds,
};
use li_core_update_manager::CoreVersion;
use li_gateway_manager::{GatewayExposureError, GatewayExposureStatus};

use crate::li_node_catalog_api::{bounded_catalog_source, bounded_catalog_targets};
use crate::{
    NodeApiKeyPolicyUpdate, NodeAuditApiPort, NodeAuditExport, NodeAuditVerification,
    NodeAuthenticationApiPort, NodeBenchmarkApiPort, NodeBenchmarkPlan, NodeBenchmarkSelection,
    NodeBenchmarkSnapshot, NodeCatalogApiError, NodeCatalogApiPort, NodeCatalogListRequest,
    NodeCatalogListing, NodeCatalogTarget, NodeCommandAuditApiPort,
    NodeCommandAuditCompletionReceipt, NodeCommandAuditCompletionRequest, NodeCommandAuditError,
    NodeCommandAuditOpenReceipt, NodeCommandAuditOpenRequest, NodeControllerEnrollmentCandidate,
    NodeControllerEnrollmentReceipt, NodeControllerSummary, NodeCoreUpdateApiPort,
    NodeCoreUpdateCheck, NodeCoreUpdateSummary, NodeExposureApiPort, NodeGatewayApi,
    NodeGatewayApiError, NodeGatewayRequest, NodeGatewayResponse, NodeHostInventory,
    NodeHostProjectionPorts, NodeHostProjectionValue, NodeHostReadError, NodeHostSnapshot,
    NodeIssuedApiKey, NodeManager, NodeManagerChange, NodeManagerError, NodeModelApiPort,
    NodeModelCommandIdentity, NodeModelCommandSummary, NodeModelError, NodeModelInstallRequest,
    NodeModelLogSummary, NodeModelRemovalRetention, NodeModelRemovalSelection,
    NodeModelRemoveRequest, NodeModelRollbackPreview, NodeModelRuntimeLogBatch,
    NodeModelRuntimeLogRequest, NodeModelServiceSummary, NodeModelUpdateRequest,
    NodeModelUpdateSummary, NodePairedChildActivationRequest, NodePairedMainRestorationRequest,
    NodePairingActivationAuthorityError, NodePairingActivationAuthorityPort, NodePairingApiError,
    NodePairingApiPort, NodePairingApproveRequest, NodePairingAuthorityReceipt,
    NodePairingEnrollRequest, NodePairingEnrollment, NodePairingInvitation, NodePairingOpenRequest,
    NodePairingStatus, NodeRuntimeMaintenanceApiPort, NodeRuntimeMaintenanceError,
    NodeRuntimeModelRetention, NodeRuntimeRemovalDisposition, NodeStorageApiPort,
    NodeStorageCleanReceipt, NodeStorageCleanRequest, NodeStorageError, NodeStorageSnapshot,
    NodeTransition, NodeUpdateError, VersionedNodeOutboxEvent,
};

// Identifies one private API capability without coupling NodeManager to key storage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NodePrivateAction {
    ReadLocalNode,
    ReadNodes,
    ReadNode,
    ReadHardware,
    ReadHostProjection,
    ReadHostInventory,
    ReadStorage,
    CleanStorage,
    ReadCatalog,
    ReadCompatibleTargets,
    EnrollChild,
    TransitionChild,
    ReadOutbox,
    AcknowledgeOutbox,
    OpenPairing,
    EnrollPairing,
    ApprovePairing,
    ReadPairingStatus,
    PreviewBenchmark,
    StartBenchmark,
    ReadActiveBenchmark,
    ReadBenchmark,
    StopBenchmark,
    AddController,
    ReadControllers,
    RevokeController,
    CreateApiKey,
    ReadApiKeys,
    ReadApiKey,
    UpdateApiKeyPolicy,
    RotateApiKey,
    RevokeApiKey,
    OpenCommandAudit,
    CompleteCommandAudit,
    ReadAuditEvents,
    ReadAuditEvent,
    VerifyAudit,
    ExportAudit,
    ListModels,
    InstallModel,
    PauseModel,
    ResumeModel,
    RestartModel,
    RecoverModel,
    RemoveModel,
    RollbackModel,
    PreviewRollbackModel,
    ReadModelLogs,
    ReadModelRuntimeLogs,
    CheckCoreUpdate,
    UpdateCore,
    UpdateModel,
    ReadExposure,
    EnableExposure,
    DisableExposure,
    ReadRuntimeInstallationIds,
    RemoveRuntimeInstallation,
    Uninstall,
    ActivatePairedChild,
    RestorePairedMain,
    Gateway,
}

// Defines the narrow AuthenticationManager capability consumed by the private API.
pub trait NodePrivateAuthorizationProvider: Send + Sync {
    // Authorizes one authenticated principal for one exact private action.
    fn authorize(
        &self,
        principal_id: &CredentialId,
        action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError>;

    // Authorizes one exact active controller certificate without treating it as a paired node.
    fn authorize_controller(
        &self,
        _controller_id: &ControllerId,
        _certificate_sha256: &Sha256Digest,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        Err(NodePrivateApiError::AuthorizationDenied)
    }

    // Authorizes a child lifecycle mutation only for the authenticated child's own identity.
    fn authorize_child_transition(
        &self,
        principal_id: &CredentialId,
        _node_id: &NodeId,
    ) -> Result<(), NodePrivateApiError> {
        self.authorize(principal_id, NodePrivateAction::TransitionChild)
    }

    // Authorizes one child record read only for the authenticated child's own identity.
    fn authorize_child_read(
        &self,
        principal_id: &CredentialId,
        _node_id: &NodeId,
    ) -> Result<(), NodePrivateApiError> {
        self.authorize(principal_id, NodePrivateAction::ReadNode)
    }
}

// Describes one typed private control request before transport serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateRequest {
    ReadLocalNode,
    ReadNodes,
    ReadNode {
        node_id: NodeId,
    },
    ReadHardware {
        node_id: NodeId,
    },
    ReadHostProjection {
        node_id: NodeId,
    },
    ReadHostInventory,
    ReadStorage,
    CleanStorage(NodeStorageCleanRequest),
    ReadCatalog(NodeCatalogListRequest),
    ReadCompatibleTargets {
        node_id: NodeId,
        catalog_source: String,
    },
    EnrollChild {
        idempotency_key: String,
        child: Node,
    },
    TransitionChild {
        idempotency_key: String,
        node_id: NodeId,
        expected_revision: u64,
        transition: NodeTransition,
        updated_at: UnixMilliseconds,
    },
    ReadPendingOutbox,
    AcknowledgeOutbox {
        idempotency_key: String,
        event_id: Sha256Digest,
        expected_revision: u64,
        acknowledged_at: UnixMilliseconds,
    },
    OpenPairing(NodePairingOpenRequest),
    EnrollPairing(NodePairingEnrollRequest),
    ApprovePairing(NodePairingApproveRequest),
    ReadPairingStatus {
        invite_id: PairingInviteId,
    },
    PreviewBenchmark {
        selection: NodeBenchmarkSelection,
    },
    StartBenchmark {
        idempotency_key: String,
        selection: NodeBenchmarkSelection,
    },
    StartBenchmarkVerification {
        idempotency_key: String,
        pull_request_url: String,
        candidate: Option<RuntimeCandidateId>,
    },
    ReadActiveBenchmark,
    ReadBenchmark {
        job_id: li_core_interface::OperationId,
    },
    StopBenchmark {
        job_id: li_core_interface::OperationId,
    },
    AddController {
        candidate: NodeControllerEnrollmentCandidate,
        role: ControllerRole,
    },
    ReadControllers,
    RevokeController {
        selector: String,
    },
    CreateApiKey {
        name: DisplayName,
        policy: ApiKeyPolicy,
    },
    ReadApiKeys,
    ReadApiKey {
        selector: String,
    },
    UpdateApiKeyPolicy {
        selector: String,
        update: NodeApiKeyPolicyUpdate,
    },
    RotateApiKey {
        selector: String,
    },
    RevokeApiKey {
        selector: String,
    },
    OpenCommandAudit(NodeCommandAuditOpenRequest),
    CompleteCommandAudit(NodeCommandAuditCompletionRequest),
    ReadAuditEvents {
        limit: usize,
    },
    ReadAuditEvent {
        event_id: AuditEventId,
    },
    VerifyAudit,
    ExportAudit,
    ListModels,
    InstallModel(NodeModelInstallRequest),
    PauseModel {
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    },
    ResumeModel {
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    },
    RestartModel {
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    },
    RecoverModel {
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
    },
    RemoveModel(NodeModelRemoveRequest),
    RollbackModel {
        identity: NodeModelCommandIdentity,
        service_id: ModelServiceId,
        target_id: Option<TargetId>,
    },
    PreviewRollbackModel {
        service_id: ModelServiceId,
        target_id: Option<TargetId>,
    },
    ReadModelLogs {
        service_id: ModelServiceId,
    },
    ReadModelRuntimeLogs(NodeModelRuntimeLogRequest),
    CheckCoreUpdate {
        requested_version: Option<CoreVersion>,
    },
    UpdateCore {
        idempotency_key: String,
        requested_version: Option<CoreVersion>,
    },
    UpdateModel(NodeModelUpdateRequest),
    ReadExposure,
    EnableExposure,
    DisableExposure,
    ReadRuntimeInstallationIds,
    RemoveRuntimeInstallation {
        installation_id: RuntimeInstallationId,
        model_retention: NodeRuntimeModelRetention,
    },
    Uninstall(NodeUninstallRequest),
    ActivatePairedChild(NodePairedChildActivationRequest),
    RestorePairedMain(NodePairedMainRestorationRequest),
    Gateway(NodeGatewayRequest),
}

impl NodePrivateRequest {
    // Returns the exact authorization capability required by this request.
    const fn action(&self) -> NodePrivateAction {
        match self {
            Self::ReadLocalNode => NodePrivateAction::ReadLocalNode,
            Self::ReadNodes => NodePrivateAction::ReadNodes,
            Self::ReadNode { .. } => NodePrivateAction::ReadNode,
            Self::ReadHardware { .. } => NodePrivateAction::ReadHardware,
            Self::ReadHostProjection { .. } => NodePrivateAction::ReadHostProjection,
            Self::ReadHostInventory => NodePrivateAction::ReadHostInventory,
            Self::ReadStorage => NodePrivateAction::ReadStorage,
            Self::CleanStorage(_) => NodePrivateAction::CleanStorage,
            Self::ReadCatalog(_) => NodePrivateAction::ReadCatalog,
            Self::ReadCompatibleTargets { .. } => NodePrivateAction::ReadCompatibleTargets,
            Self::EnrollChild { .. } => NodePrivateAction::EnrollChild,
            Self::TransitionChild { .. } => NodePrivateAction::TransitionChild,
            Self::ReadPendingOutbox => NodePrivateAction::ReadOutbox,
            Self::AcknowledgeOutbox { .. } => NodePrivateAction::AcknowledgeOutbox,
            Self::OpenPairing(_) => NodePrivateAction::OpenPairing,
            Self::EnrollPairing(_) => NodePrivateAction::EnrollPairing,
            Self::ApprovePairing(_) => NodePrivateAction::ApprovePairing,
            Self::ReadPairingStatus { .. } => NodePrivateAction::ReadPairingStatus,
            Self::PreviewBenchmark { .. } => NodePrivateAction::PreviewBenchmark,
            Self::StartBenchmark { .. } | Self::StartBenchmarkVerification { .. } => {
                NodePrivateAction::StartBenchmark
            }
            Self::ReadActiveBenchmark => NodePrivateAction::ReadActiveBenchmark,
            Self::ReadBenchmark { .. } => NodePrivateAction::ReadBenchmark,
            Self::StopBenchmark { .. } => NodePrivateAction::StopBenchmark,
            Self::AddController { .. } => NodePrivateAction::AddController,
            Self::ReadControllers => NodePrivateAction::ReadControllers,
            Self::RevokeController { .. } => NodePrivateAction::RevokeController,
            Self::CreateApiKey { .. } => NodePrivateAction::CreateApiKey,
            Self::ReadApiKeys => NodePrivateAction::ReadApiKeys,
            Self::ReadApiKey { .. } => NodePrivateAction::ReadApiKey,
            Self::UpdateApiKeyPolicy { .. } => NodePrivateAction::UpdateApiKeyPolicy,
            Self::RotateApiKey { .. } => NodePrivateAction::RotateApiKey,
            Self::RevokeApiKey { .. } => NodePrivateAction::RevokeApiKey,
            Self::OpenCommandAudit(_) => NodePrivateAction::OpenCommandAudit,
            Self::CompleteCommandAudit(_) => NodePrivateAction::CompleteCommandAudit,
            Self::ReadAuditEvents { .. } => NodePrivateAction::ReadAuditEvents,
            Self::ReadAuditEvent { .. } => NodePrivateAction::ReadAuditEvent,
            Self::VerifyAudit => NodePrivateAction::VerifyAudit,
            Self::ExportAudit => NodePrivateAction::ExportAudit,
            Self::ListModels => NodePrivateAction::ListModels,
            Self::InstallModel(_) => NodePrivateAction::InstallModel,
            Self::PauseModel { .. } => NodePrivateAction::PauseModel,
            Self::ResumeModel { .. } => NodePrivateAction::ResumeModel,
            Self::RestartModel { .. } => NodePrivateAction::RestartModel,
            Self::RecoverModel { .. } => NodePrivateAction::RecoverModel,
            Self::RemoveModel(_) => NodePrivateAction::RemoveModel,
            Self::RollbackModel { .. } => NodePrivateAction::RollbackModel,
            Self::PreviewRollbackModel { .. } => NodePrivateAction::PreviewRollbackModel,
            Self::ReadModelLogs { .. } => NodePrivateAction::ReadModelLogs,
            Self::ReadModelRuntimeLogs(_) => NodePrivateAction::ReadModelRuntimeLogs,
            Self::CheckCoreUpdate { .. } => NodePrivateAction::CheckCoreUpdate,
            Self::UpdateCore { .. } => NodePrivateAction::UpdateCore,
            Self::UpdateModel(_) => NodePrivateAction::UpdateModel,
            Self::ReadExposure => NodePrivateAction::ReadExposure,
            Self::EnableExposure => NodePrivateAction::EnableExposure,
            Self::DisableExposure => NodePrivateAction::DisableExposure,
            Self::ReadRuntimeInstallationIds => NodePrivateAction::ReadRuntimeInstallationIds,
            Self::RemoveRuntimeInstallation { .. } => NodePrivateAction::RemoveRuntimeInstallation,
            Self::Uninstall(_) => NodePrivateAction::Uninstall,
            Self::ActivatePairedChild(_) => NodePrivateAction::ActivatePairedChild,
            Self::RestorePairedMain(_) => NodePrivateAction::RestorePairedMain,
            Self::Gateway(_) => NodePrivateAction::Gateway,
        }
    }

    // Returns whether this action may cross only the owner-authenticated local listener.
    const fn is_local_only(&self) -> bool {
        matches!(
            self,
            Self::ReadHostInventory
                | Self::ReadStorage
                | Self::CleanStorage(_)
                | Self::AddController { .. }
                | Self::ReadControllers
                | Self::RevokeController { .. }
                | Self::OpenCommandAudit(_)
                | Self::CompleteCommandAudit(_)
                | Self::ReadAuditEvents { .. }
                | Self::ReadAuditEvent { .. }
                | Self::VerifyAudit
                | Self::ExportAudit
                | Self::CheckCoreUpdate { .. }
                | Self::UpdateCore { .. }
                | Self::UpdateModel(_)
                | Self::ReadExposure
                | Self::EnableExposure
                | Self::DisableExposure
                | Self::ReadRuntimeInstallationIds
                | Self::RemoveRuntimeInstallation { .. }
                | Self::Uninstall(_)
                | Self::ActivatePairedChild(_)
                | Self::RestorePairedMain(_)
                | Self::Gateway(_)
        )
    }

    // Returns whether dispatch can create or change an uninstall teardown target.
    const fn conflicts_with_uninstall(&self) -> bool {
        matches!(
            self,
            Self::CleanStorage(_)
                | Self::EnrollChild { .. }
                | Self::TransitionChild { .. }
                | Self::OpenPairing(_)
                | Self::EnrollPairing(_)
                | Self::ApprovePairing(_)
                | Self::StartBenchmark { .. }
                | Self::StartBenchmarkVerification { .. }
                | Self::StopBenchmark { .. }
                | Self::InstallModel(_)
                | Self::PauseModel { .. }
                | Self::ResumeModel { .. }
                | Self::RestartModel { .. }
                | Self::RecoverModel { .. }
                | Self::RemoveModel(_)
                | Self::RollbackModel { .. }
                | Self::UpdateCore { .. }
                | Self::UpdateModel(_)
                | Self::EnableExposure
                | Self::DisableExposure
                | Self::RemoveRuntimeInstallation { .. }
                | Self::ActivatePairedChild(_)
                | Self::RestorePairedMain(_)
                | Self::Gateway(
                    NodeGatewayRequest::AuthorizeInference { .. }
                        | NodeGatewayRequest::AuthorizeInboundRelay { .. }
                )
        )
    }
}

// Carries only local uninstall operations that must present the exact active lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeUninstallRequest {
    Begin {
        session_id: Sha256Digest,
        model_retention: NodeRuntimeModelRetention,
    },
    StopBenchmark {
        session_id: Sha256Digest,
        job_id: OperationId,
    },
    DisableExposure {
        session_id: Sha256Digest,
    },
    RemoveModel {
        session_id: Sha256Digest,
        request: NodeModelRemoveRequest,
    },
    RemoveRuntimeInstallation {
        session_id: Sha256Digest,
        installation_id: RuntimeInstallationId,
        model_retention: NodeRuntimeModelRetention,
    },
    FinalizeRuntimeArtifacts {
        session_id: Sha256Digest,
        model_retention: NodeRuntimeModelRetention,
    },
    Cancel {
        session_id: Sha256Digest,
    },
}

impl NodeUninstallRequest {
    // Returns the exact lease identity required by every uninstall operation.
    pub const fn session_id(&self) -> &Sha256Digest {
        match self {
            Self::Begin { session_id, .. }
            | Self::StopBenchmark { session_id, .. }
            | Self::DisableExposure { session_id }
            | Self::RemoveModel { session_id, .. }
            | Self::RemoveRuntimeInstallation { session_id, .. }
            | Self::FinalizeRuntimeArtifacts { session_id, .. }
            | Self::Cancel { session_id } => session_id,
        }
    }
}

// Describes whether one exact BeginUninstall call applied or replayed its lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeUninstallSessionDisposition {
    Applied,
    Replayed,
}

pub const MAXIMUM_UNINSTALL_TEARDOWN_TARGETS: usize = 4096;

// Identifies one exact nonremoved model service and every placement group it owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUninstallModelTarget {
    service_id: ModelServiceId,
    placement_group_ids: Vec<PlacementGroupId>,
}

impl NodeUninstallModelTarget {
    // Creates one compact model teardown target from manager-validated identities.
    pub const fn new(
        service_id: ModelServiceId,
        placement_group_ids: Vec<PlacementGroupId>,
    ) -> Self {
        Self {
            service_id,
            placement_group_ids,
        }
    }

    // Returns the exact nonremoved model-service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns every exact placement group owned by the service in canonical order.
    pub fn placement_group_ids(&self) -> &[PlacementGroupId] {
        &self.placement_group_ids
    }
}

// Returns the exact retention-bound target inventory atomically captured by BeginUninstall.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUninstallInventory {
    local_role: NodeRole,
    active_benchmark_id: Option<OperationId>,
    exposure_configuration_sha256: Option<Sha256Digest>,
    model_targets: Vec<NodeUninstallModelTarget>,
    runtime_installation_ids: Vec<RuntimeInstallationId>,
}

impl NodeUninstallInventory {
    // Creates one canonical inventory only when its aggregate teardown target count is bounded.
    pub fn new(
        local_role: NodeRole,
        active_benchmark_id: Option<OperationId>,
        exposure_configuration_sha256: Option<Sha256Digest>,
        model_targets: Vec<NodeUninstallModelTarget>,
        runtime_installation_ids: Vec<RuntimeInstallationId>,
    ) -> Result<Self, NodePrivateApiError> {
        let inventory = Self {
            local_role,
            active_benchmark_id,
            exposure_configuration_sha256,
            model_targets,
            runtime_installation_ids,
        };
        inventory.validate()?;
        Ok(inventory)
    }

    // Returns the exact local role observed at admission.
    pub const fn local_role(&self) -> NodeRole {
        self.local_role
    }

    // Returns the sole active benchmark when one existed at admission.
    pub const fn active_benchmark_id(&self) -> Option<&OperationId> {
        self.active_benchmark_id.as_ref()
    }

    // Returns the exact enabled exposure configuration identity observed at admission.
    pub const fn exposure_configuration_sha256(&self) -> Option<&Sha256Digest> {
        self.exposure_configuration_sha256.as_ref()
    }

    // Returns every nonremoved model service and its exact placement-group identities.
    pub fn model_targets(&self) -> &[NodeUninstallModelTarget] {
        &self.model_targets
    }

    // Returns every runtime identity observed at admission in stable order.
    pub fn runtime_installation_ids(&self) -> &[RuntimeInstallationId] {
        &self.runtime_installation_ids
    }

    // Revalidates canonical identity ordering and the one aggregate teardown-target bound.
    fn validate(&self) -> Result<(), NodePrivateApiError> {
        if self.local_role == NodeRole::Child
            && (self.active_benchmark_id.is_some()
                || self.exposure_configuration_sha256.is_some()
                || !self.model_targets.is_empty())
        {
            return Err(NodePrivateApiError::UninstallBarrierUnavailable);
        }
        if self
            .model_targets
            .windows(2)
            .any(|pair| pair[0].service_id().as_str() >= pair[1].service_id().as_str())
            || self.model_targets.iter().any(|target| {
                target
                    .placement_group_ids()
                    .windows(2)
                    .any(|pair| pair[0].as_str() >= pair[1].as_str())
            })
            || self
                .runtime_installation_ids
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(NodePrivateApiError::UninstallBarrierUnavailable);
        }
        let target_count = self
            .model_targets
            .iter()
            .try_fold(
                usize::from(self.active_benchmark_id.is_some())
                    + usize::from(self.exposure_configuration_sha256.is_some())
                    + self.runtime_installation_ids.len(),
                |count, target| {
                    count
                        .checked_add(1)
                        .and_then(|count| count.checked_add(target.placement_group_ids().len()))
                },
            )
            .ok_or(NodePrivateApiError::UninstallBarrierUnavailable)?;
        if target_count > MAXIMUM_UNINSTALL_TEARDOWN_TARGETS {
            return Err(NodePrivateApiError::UninstallBarrierUnavailable);
        }
        Ok(())
    }
}

// Confirms one retention-bound uninstall lease and its atomic target inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUninstallBeginReceipt {
    session_id: Sha256Digest,
    disposition: NodeUninstallSessionDisposition,
    model_retention: NodeRuntimeModelRetention,
    inventory: NodeUninstallInventory,
}

impl NodeUninstallBeginReceipt {
    // Creates one exact applied or replayed lease receipt.
    pub const fn new(
        session_id: Sha256Digest,
        disposition: NodeUninstallSessionDisposition,
        model_retention: NodeRuntimeModelRetention,
        inventory: NodeUninstallInventory,
    ) -> Self {
        Self {
            session_id,
            disposition,
            model_retention,
            inventory,
        }
    }

    // Returns the exact caller-generated uninstall session identity.
    pub const fn session_id(&self) -> &Sha256Digest {
        &self.session_id
    }

    // Returns whether BeginUninstall applied or replayed the lease.
    pub const fn disposition(&self) -> NodeUninstallSessionDisposition {
        self.disposition
    }

    // Returns the immutable model retention bound to this lease.
    pub const fn model_retention(&self) -> NodeRuntimeModelRetention {
        self.model_retention
    }

    // Returns the target inventory captured by the applied lease.
    pub const fn inventory(&self) -> &NodeUninstallInventory {
        &self.inventory
    }
}

// Confirms cancellation of one exact local uninstall lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUninstallCancelReceipt {
    session_id: Sha256Digest,
}

// Confirms complete policy-bound RuntimeManager artifact-root validation and finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRuntimeArtifactsFinalizationReceipt {
    model_retention: NodeRuntimeModelRetention,
}

impl NodeRuntimeArtifactsFinalizationReceipt {
    // Creates one receipt only after RuntimeManager accepts complete root finalization.
    pub const fn new(model_retention: NodeRuntimeModelRetention) -> Self {
        Self { model_retention }
    }

    // Returns the exact model-retention policy applied to the finalized root.
    pub const fn model_retention(&self) -> NodeRuntimeModelRetention {
        self.model_retention
    }
}

impl NodeUninstallCancelReceipt {
    // Creates one matching canceled-lease receipt.
    pub const fn new(session_id: Sha256Digest) -> Self {
        Self { session_id }
    }

    // Returns the exact canceled lease identity.
    pub const fn session_id(&self) -> &Sha256Digest {
        &self.session_id
    }
}

// Returns one typed private control result without a second entity projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateResponse {
    LocalNode(Node),
    Nodes(Vec<Node>),
    NodeChanged(NodeManagerChange<Node>),
    HardwareObservation(Option<HardwareObservation>),
    HostProjection(NodeHostSnapshot),
    HostInventory(NodeHostInventory),
    StorageSnapshot(NodeStorageSnapshot),
    StorageCleaned(NodeStorageCleanReceipt),
    Catalog(NodeCatalogListing),
    CompatibleTargets(Vec<NodeCatalogTarget>),
    PendingOutbox(Vec<VersionedNodeOutboxEvent>),
    OutboxAcknowledged(VersionedNodeOutboxEvent),
    PairingInvitation(NodePairingInvitation),
    PairingEnrollment(NodePairingEnrollment),
    PairingStatus(NodePairingStatus),
    BenchmarkPlan(NodeBenchmarkPlan),
    BenchmarkChanged(NodeBenchmarkSnapshot),
    BenchmarkRecord(Option<NodeBenchmarkSnapshot>),
    ControllerEnrollment(NodeControllerEnrollmentReceipt),
    Controller(NodeControllerSummary),
    Controllers(Vec<NodeControllerSummary>),
    ApiKeyIssued(NodeIssuedApiKey),
    ApiKeys(Vec<ApiKey>),
    ApiKey(ApiKey),
    CommandAuditOpened(NodeCommandAuditOpenReceipt),
    CommandAuditCompleted(NodeCommandAuditCompletionReceipt),
    AuditEvents(Vec<AuditEvent>),
    AuditEvent(AuditEvent),
    AuditVerification(NodeAuditVerification),
    AuditExport(NodeAuditExport),
    ModelServices(Vec<NodeModelServiceSummary>),
    ModelChanged(NodeModelCommandSummary),
    ModelRollbackPreview(NodeModelRollbackPreview),
    ModelLogs(NodeModelLogSummary),
    ModelRuntimeLogs(NodeModelRuntimeLogBatch),
    CoreUpdateCheck(NodeCoreUpdateCheck),
    CoreUpdated(NodeCoreUpdateSummary),
    ModelUpdated(NodeModelUpdateSummary),
    Exposure(GatewayExposureStatus),
    RuntimeInstallationIds(Vec<RuntimeInstallationId>),
    RuntimeInstallationRemoved(NodeRuntimeRemovalDisposition),
    RuntimeArtifactsFinalized(NodeRuntimeArtifactsFinalizationReceipt),
    UninstallBegan(NodeUninstallBeginReceipt),
    UninstallCanceled(NodeUninstallCancelReceipt),
    PairingAuthorityChanged(NodePairingAuthorityReceipt),
    Gateway(NodeGatewayResponse),
}

// Describes one stable private API boundary failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateApiError {
    AuthorizationDenied,
    ActiveMainRequired,
    Manager(NodeManagerError),
    Catalog(NodeCatalogApiError),
    Pairing(NodePairingApiError),
    Benchmark(BenchmarkError),
    Controller(ControllerError),
    Authentication(AuthenticationError),
    CommandAudit(NodeCommandAuditError),
    Audit(AuditError),
    Model(NodeModelError),
    Update(NodeUpdateError),
    Exposure(GatewayExposureError),
    Storage(NodeStorageError),
    RuntimeMaintenance(NodeRuntimeMaintenanceError),
    PairingActivation(NodePairingActivationAuthorityError),
    Gateway(NodeGatewayApiError),
    HostProjectionUnavailable,
    UninstallInProgress,
    UninstallBusy,
    UninstallSessionConflict,
    UninstallBarrierUnavailable,
}

impl fmt::Display for NodePrivateApiError {
    // Presents stable private API language without leaking authorization details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorizationDenied => formatter.write_str("private node action is denied"),
            Self::ActiveMainRequired => {
                formatter.write_str("private node action requires an active main")
            }
            Self::Manager(error) => write!(formatter, "{error}"),
            Self::Catalog(error) => write!(formatter, "{error}"),
            Self::Pairing(error) => write!(formatter, "{error}"),
            Self::Benchmark(error) => write!(formatter, "{error}"),
            Self::Controller(error) => write!(formatter, "{error}"),
            Self::Authentication(error) => write!(formatter, "{error}"),
            Self::CommandAudit(error) => write!(formatter, "{error}"),
            Self::Audit(error) => write!(formatter, "{error}"),
            Self::Model(error) => write!(formatter, "{error}"),
            Self::Update(error) => write!(formatter, "{error}"),
            Self::Exposure(error) => write!(formatter, "{error}"),
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::RuntimeMaintenance(error) => write!(formatter, "{error}"),
            Self::PairingActivation(error) => write!(formatter, "{error}"),
            Self::Gateway(error) => write!(formatter, "{error}"),
            Self::HostProjectionUnavailable => {
                formatter.write_str("current host projection is unavailable")
            }
            Self::UninstallInProgress => formatter.write_str("node uninstall is in progress"),
            Self::UninstallBusy => formatter.write_str("node mutation is already in progress"),
            Self::UninstallSessionConflict => {
                formatter.write_str("node uninstall session conflicts with active state")
            }
            Self::UninstallBarrierUnavailable => {
                formatter.write_str("node uninstall mutation barrier is unavailable")
            }
        }
    }
}

impl Error for NodePrivateApiError {}

impl From<NodeManagerError> for NodePrivateApiError {
    // Preserves one stable manager failure at the private API boundary.
    fn from(error: NodeManagerError) -> Self {
        Self::Manager(error)
    }
}

impl From<NodeCatalogApiError> for NodePrivateApiError {
    // Preserves one stable Node catalog-projection failure at the private API boundary.
    fn from(error: NodeCatalogApiError) -> Self {
        Self::Catalog(error)
    }
}

impl From<NodePairingApiError> for NodePrivateApiError {
    // Preserves one stable injected pairing-port failure at the private API boundary.
    fn from(error: NodePairingApiError) -> Self {
        Self::Pairing(error)
    }
}

impl From<BenchmarkError> for NodePrivateApiError {
    // Preserves one stable benchmark failure at the private API boundary.
    fn from(error: BenchmarkError) -> Self {
        Self::Benchmark(error)
    }
}

impl From<AuthenticationError> for NodePrivateApiError {
    // Preserves one stable AuthenticationManager failure without exposing credential material.
    fn from(error: AuthenticationError) -> Self {
        Self::Authentication(error)
    }
}

impl From<ControllerError> for NodePrivateApiError {
    // Preserves one stable controller lifecycle failure without certificate material.
    fn from(error: ControllerError) -> Self {
        Self::Controller(error)
    }
}

impl From<NodeCommandAuditError> for NodePrivateApiError {
    // Preserves one stable Node-owned command-audit failure at the private API boundary.
    fn from(error: NodeCommandAuditError) -> Self {
        Self::CommandAudit(error)
    }
}

impl From<AuditError> for NodePrivateApiError {
    // Preserves one stable AuditManager failure at the private API boundary.
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

impl From<NodeModelError> for NodePrivateApiError {
    // Preserves one stable ModelCoordinator failure without provider diagnostics.
    fn from(error: NodeModelError) -> Self {
        Self::Model(error)
    }
}

impl From<NodeUpdateError> for NodePrivateApiError {
    // Preserves one stable manager-backed update failure at the private API boundary.
    fn from(error: NodeUpdateError) -> Self {
        Self::Update(error)
    }
}

impl From<GatewayExposureError> for NodePrivateApiError {
    // Preserves one stable Gateway exposure failure without native provider detail.
    fn from(error: GatewayExposureError) -> Self {
        Self::Exposure(error)
    }
}

impl From<NodeStorageError> for NodePrivateApiError {
    // Preserves one stable Node storage failure without native path diagnostics.
    fn from(error: NodeStorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<NodeRuntimeMaintenanceError> for NodePrivateApiError {
    // Preserves one stable runtime-maintenance failure without store or artifact detail.
    fn from(error: NodeRuntimeMaintenanceError) -> Self {
        Self::RuntimeMaintenance(error)
    }
}

impl From<NodePairingActivationAuthorityError> for NodePrivateApiError {
    // Preserves one stable local pairing-authority failure without database detail.
    fn from(error: NodePairingActivationAuthorityError) -> Self {
        Self::PairingActivation(error)
    }
}

impl From<NodeGatewayApiError> for NodePrivateApiError {
    // Preserves one stable local Gateway capability failure without provider detail.
    fn from(error: NodeGatewayApiError) -> Self {
        Self::Gateway(error)
    }
}

// Owns authorization ordering and typed dispatch into one NodeManager.
pub struct NodePrivateApi {
    manager: Arc<NodeManager>,
    authorization: Arc<dyn NodePrivateAuthorizationProvider>,
    pairing: Arc<dyn NodePairingApiPort>,
    catalog: Option<Arc<dyn NodeCatalogApiPort>>,
    benchmark: Option<Arc<dyn NodeBenchmarkApiPort>>,
    authentication: Option<Arc<dyn NodeAuthenticationApiPort>>,
    command_audit: Option<Arc<dyn NodeCommandAuditApiPort>>,
    audit: Option<Arc<dyn NodeAuditApiPort>>,
    model: Option<Arc<dyn NodeModelApiPort>>,
    core_update: Option<Arc<dyn NodeCoreUpdateApiPort>>,
    exposure: Option<Arc<dyn NodeExposureApiPort>>,
    storage: Option<Arc<dyn NodeStorageApiPort>>,
    runtime_maintenance: Option<Arc<dyn NodeRuntimeMaintenanceApiPort>>,
    pairing_activation: Option<Arc<dyn NodePairingActivationAuthorityPort>>,
    host_projection: Option<Arc<NodeHostProjectionPorts>>,
    gateway: Option<Arc<NodeGatewayApi>>,
    uninstall_session: Mutex<Option<ActiveNodeUninstallSession>>,
}

// Retains one active lease's immutable policy and applied target inventory for exact replay.
#[derive(Clone)]
struct ActiveNodeUninstallSession {
    session_id: Sha256Digest,
    model_retention: NodeRuntimeModelRetention,
    inventory: NodeUninstallInventory,
}

impl NodePrivateApi {
    // Creates one private dispatcher without taking manager or authorization lifecycle ownership.
    pub const fn new(
        manager: Arc<NodeManager>,
        authorization: Arc<dyn NodePrivateAuthorizationProvider>,
        pairing: Arc<dyn NodePairingApiPort>,
    ) -> Self {
        Self {
            manager,
            authorization,
            pairing,
            catalog: None,
            benchmark: None,
            authentication: None,
            command_audit: None,
            audit: None,
            model: None,
            core_update: None,
            exposure: None,
            storage: None,
            runtime_maintenance: None,
            pairing_activation: None,
            host_projection: None,
            gateway: None,
            uninstall_session: Mutex::new(None),
        }
    }

    // Adds the Node-owned benchmark command surface without changing ordinary Node ownership.
    pub fn with_benchmark(mut self, benchmark: Arc<dyn NodeBenchmarkApiPort>) -> Self {
        self.benchmark = Some(benchmark);
        self
    }

    // Adds signed catalog compatibility projection without transferring RuntimeManager ownership.
    pub fn with_catalog(mut self, catalog: Arc<dyn NodeCatalogApiPort>) -> Self {
        self.catalog = Some(catalog);
        self
    }

    // Adds the Node-owned authentication command surface without changing Gateway enforcement.
    pub fn with_authentication(
        mut self,
        authentication: Arc<dyn NodeAuthenticationApiPort>,
    ) -> Self {
        self.authentication = Some(authentication);
        self
    }

    // Adds the Node-owned local command-audit lifecycle without exposing it remotely.
    pub fn with_command_audit(mut self, command_audit: Arc<dyn NodeCommandAuditApiPort>) -> Self {
        self.command_audit = Some(command_audit);
        self
    }

    // Adds the Node-owned AuditManager query surface without exposing persistence to clients.
    pub fn with_audit(mut self, audit: Arc<dyn NodeAuditApiPort>) -> Self {
        self.audit = Some(audit);
        self
    }

    // Adds the existing ModelCoordinator private surface without changing manager ownership.
    pub fn with_model(mut self, model: Arc<dyn NodeModelApiPort>) -> Self {
        self.model = Some(model);
        self
    }

    // Adds the existing CoreUpdateManager projection without changing its lifecycle ownership.
    pub fn with_core_update(mut self, core_update: Arc<dyn NodeCoreUpdateApiPort>) -> Self {
        self.core_update = Some(core_update);
        self
    }

    // Adds the Gateway-owned exposure lifecycle through a local main-only Node projection.
    pub fn with_exposure(mut self, exposure: Arc<dyn NodeExposureApiPort>) -> Self {
        self.exposure = Some(exposure);
        self
    }

    // Adds local storage observation and cleanup without exposing it to paired nodes.
    pub fn with_storage(mut self, storage: Arc<dyn NodeStorageApiPort>) -> Self {
        self.storage = Some(storage);
        self
    }

    // Adds local runtime inventory and exact removal through the existing RuntimeManager owner.
    pub fn with_runtime_maintenance(
        mut self,
        runtime_maintenance: Arc<dyn NodeRuntimeMaintenanceApiPort>,
    ) -> Self {
        self.runtime_maintenance = Some(runtime_maintenance);
        self
    }

    // Adds atomic paired-role authority through the shared Node database owner.
    pub fn with_pairing_activation(
        mut self,
        pairing_activation: Arc<dyn NodePairingActivationAuthorityPort>,
    ) -> Self {
        self.pairing_activation = Some(pairing_activation);
        self
    }

    // Adds the exact read-only manager and platform ports used by every host view.
    pub fn with_host_projection(mut self, ports: Arc<NodeHostProjectionPorts>) -> Self {
        self.host_projection = Some(ports);
        self
    }

    // Adds the local-only Gateway capability surface without transferring manager ownership.
    pub fn with_gateway(mut self, gateway: Arc<NodeGatewayApi>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    // Authorizes first, then dispatches one exact typed request through ordinary manager code.
    pub fn dispatch(
        &self,
        principal_id: &CredentialId,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, NodePrivateApiError> {
        if request.is_local_only() {
            return Err(NodePrivateApiError::AuthorizationDenied);
        }
        match &request {
            NodePrivateRequest::ReadNode { node_id } => self
                .authorization
                .authorize_child_read(principal_id, node_id)?,
            NodePrivateRequest::ReadHostProjection { node_id } => self
                .authorization
                .authorize_child_read(principal_id, node_id)?,
            NodePrivateRequest::TransitionChild { node_id, .. } => self
                .authorization
                .authorize_child_transition(principal_id, node_id)?,
            _ => self
                .authorization
                .authorize(principal_id, request.action())?,
        }
        self.dispatch_authorized(request)
    }

    // Revalidates one controller certificate and dispatches only the non-local remote surface.
    pub fn dispatch_controller(
        &self,
        controller_id: &ControllerId,
        certificate_sha256: &Sha256Digest,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, NodePrivateApiError> {
        if request.is_local_only() {
            return Err(NodePrivateApiError::AuthorizationDenied);
        }
        self.authorization.authorize_controller(
            controller_id,
            certificate_sha256,
            request.action(),
        )?;
        self.dispatch_authorized(request)
    }

    // Dispatches one owner-UID-authenticated local request for this exact Node identity.
    pub fn dispatch_local(
        &self,
        local_node_id: &NodeId,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, NodePrivateApiError> {
        if local_node_id != self.manager.local_node_id() {
            return Err(NodePrivateApiError::AuthorizationDenied);
        }
        self.dispatch_authorized(request)
    }

    // Dispatches one request only after its remote or local authorization boundary succeeds.
    fn dispatch_authorized(
        &self,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, NodePrivateApiError> {
        if let NodePrivateRequest::Uninstall(NodeUninstallRequest::Begin {
            session_id,
            model_retention,
        }) = &request
        {
            return self.begin_uninstall(session_id, *model_retention);
        }
        let mut uninstall_session = (request.conflicts_with_uninstall()
            || matches!(request, NodePrivateRequest::Uninstall(_)))
        .then(|| self.lock_uninstall_session())
        .transpose()?;
        if let Some(active) = uninstall_session.as_mut() {
            match &request {
                NodePrivateRequest::Uninstall(request) => {
                    return self.dispatch_uninstall(active, request.clone());
                }
                _ if active.is_some() => return Err(NodePrivateApiError::UninstallInProgress),
                _ => {}
            }
        }
        match request {
            NodePrivateRequest::ReadLocalNode => self
                .manager
                .local_node()
                .map(NodePrivateResponse::LocalNode)
                .map_err(Into::into),
            NodePrivateRequest::ReadNodes => self
                .manager
                .nodes()
                .map(NodePrivateResponse::Nodes)
                .map_err(Into::into),
            NodePrivateRequest::ReadNode { node_id } => self
                .manager
                .node(&node_id)
                .map(NodePrivateResponse::NodeChanged)
                .map_err(Into::into),
            NodePrivateRequest::ReadHardware { node_id } => self
                .manager
                .hardware_observation(&node_id)
                .map(NodePrivateResponse::HardwareObservation)
                .map_err(Into::into),
            NodePrivateRequest::ReadHostProjection { node_id } => self
                .host_snapshot(&node_id)
                .map(NodePrivateResponse::HostProjection),
            NodePrivateRequest::ReadHostInventory => self
                .host_inventory()
                .map(NodePrivateResponse::HostInventory),
            NodePrivateRequest::ReadStorage => self
                .storage()?
                .snapshot()
                .map(NodePrivateResponse::StorageSnapshot)
                .map_err(Into::into),
            NodePrivateRequest::CleanStorage(request) => self
                .storage()?
                .clean(&request)
                .map(NodePrivateResponse::StorageCleaned)
                .map_err(Into::into),
            NodePrivateRequest::ReadCatalog(request) => self
                .catalog()?
                .list(&request)
                .map(NodePrivateResponse::Catalog)
                .map_err(Into::into),
            NodePrivateRequest::ReadCompatibleTargets {
                node_id,
                catalog_source,
            } => self
                .catalog()?
                .compatible_targets(&node_id, &bounded_catalog_source(catalog_source)?)
                .and_then(bounded_catalog_targets)
                .map(NodePrivateResponse::CompatibleTargets)
                .map_err(Into::into),
            NodePrivateRequest::EnrollChild {
                idempotency_key,
                child,
            } => self
                .manager
                .enroll_child(&idempotency_key, child)
                .map(NodePrivateResponse::NodeChanged)
                .map_err(Into::into),
            NodePrivateRequest::TransitionChild {
                idempotency_key,
                node_id,
                expected_revision,
                transition,
                updated_at,
            } => self
                .manager
                .transition_child(
                    &idempotency_key,
                    &node_id,
                    expected_revision,
                    transition,
                    updated_at,
                )
                .map(NodePrivateResponse::NodeChanged)
                .map_err(Into::into),
            NodePrivateRequest::ReadPendingOutbox => self
                .manager
                .pending_outbox_events()
                .map(NodePrivateResponse::PendingOutbox)
                .map_err(Into::into),
            NodePrivateRequest::AcknowledgeOutbox {
                idempotency_key,
                event_id,
                expected_revision,
                acknowledged_at,
            } => self
                .manager
                .acknowledge_outbox_event(
                    &idempotency_key,
                    &event_id,
                    expected_revision,
                    acknowledged_at,
                )
                .map(NodePrivateResponse::OutboxAcknowledged)
                .map_err(Into::into),
            NodePrivateRequest::OpenPairing(request) => {
                self.require_active_main()?;
                self.pairing
                    .open(&request)
                    .map(NodePrivateResponse::PairingInvitation)
                    .map_err(Into::into)
            }
            NodePrivateRequest::EnrollPairing(request) => {
                self.require_active_main()?;
                self.pairing
                    .enroll(&request)
                    .map(NodePrivateResponse::PairingEnrollment)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ApprovePairing(request) => {
                self.require_active_main()?;
                self.pairing
                    .approve(&request)
                    .map(NodePrivateResponse::PairingStatus)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadPairingStatus { invite_id } => {
                self.require_active_main()?;
                self.pairing
                    .status(&invite_id)
                    .map(NodePrivateResponse::PairingStatus)
                    .map_err(Into::into)
            }
            NodePrivateRequest::PreviewBenchmark { selection } => {
                self.require_active_main()?;
                self.benchmark()?
                    .preview(selection)
                    .map(NodePrivateResponse::BenchmarkPlan)
                    .map_err(Into::into)
            }
            NodePrivateRequest::StartBenchmark {
                idempotency_key,
                selection,
            } => {
                self.require_active_main()?;
                self.benchmark()?
                    .start(&idempotency_key, selection)
                    .map(NodePrivateResponse::BenchmarkChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::StartBenchmarkVerification {
                idempotency_key,
                pull_request_url,
                candidate,
            } => {
                self.require_active_main()?;
                self.benchmark()?
                    .start_verification(&idempotency_key, &pull_request_url, candidate.as_ref())
                    .map(NodePrivateResponse::BenchmarkChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadActiveBenchmark => {
                self.require_active_main()?;
                self.benchmark()?
                    .active()
                    .map(NodePrivateResponse::BenchmarkRecord)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadBenchmark { job_id } => {
                self.require_active_main()?;
                self.benchmark()?
                    .record(&job_id)
                    .map(NodePrivateResponse::BenchmarkRecord)
                    .map_err(Into::into)
            }
            NodePrivateRequest::StopBenchmark { job_id } => {
                self.require_active_main()?;
                self.benchmark()?
                    .stop(&job_id)
                    .map(NodePrivateResponse::BenchmarkChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::AddController { candidate, role } => {
                self.require_active_main()?;
                self.authentication()?
                    .add_controller(candidate, role)
                    .map(NodePrivateResponse::ControllerEnrollment)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadControllers => {
                self.require_active_main()?;
                self.authentication()?
                    .controllers()
                    .map(NodePrivateResponse::Controllers)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RevokeController { selector } => {
                self.require_active_main()?;
                self.authentication()?
                    .revoke_controller(&selector)
                    .map(NodePrivateResponse::Controller)
                    .map_err(Into::into)
            }
            NodePrivateRequest::CreateApiKey { name, policy } => {
                self.require_active_main()?;
                self.authentication()?
                    .create(name, policy)
                    .map(NodePrivateResponse::ApiKeyIssued)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadApiKeys => {
                self.require_active_main()?;
                self.authentication()?
                    .keys()
                    .map(NodePrivateResponse::ApiKeys)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadApiKey { selector } => {
                self.require_active_main()?;
                self.authentication()?
                    .key(&selector)
                    .map(NodePrivateResponse::ApiKey)
                    .map_err(Into::into)
            }
            NodePrivateRequest::UpdateApiKeyPolicy { selector, update } => {
                self.require_active_main()?;
                self.authentication()?
                    .update(&selector, update)
                    .map(NodePrivateResponse::ApiKey)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RotateApiKey { selector } => {
                self.require_active_main()?;
                self.authentication()?
                    .rotate(&selector)
                    .map(NodePrivateResponse::ApiKeyIssued)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RevokeApiKey { selector } => {
                self.require_active_main()?;
                self.authentication()?
                    .revoke(&selector)
                    .map(NodePrivateResponse::ApiKey)
                    .map_err(Into::into)
            }
            NodePrivateRequest::OpenCommandAudit(request) => {
                let local = self.manager.local_node()?;
                if local.state() != NodeState::Active
                    || local.role() != request.intent().local_role()
                {
                    return Err(NodePrivateApiError::AuthorizationDenied);
                }
                self.command_audit()?
                    .open(request)
                    .map(NodePrivateResponse::CommandAuditOpened)
                    .map_err(Into::into)
            }
            NodePrivateRequest::CompleteCommandAudit(request) => self
                .command_audit()?
                .complete(request)
                .map(NodePrivateResponse::CommandAuditCompleted)
                .map_err(Into::into),
            NodePrivateRequest::ReadAuditEvents { limit } => {
                self.require_active_main()?;
                self.audit()?
                    .list(limit)
                    .map(NodePrivateResponse::AuditEvents)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadAuditEvent { event_id } => {
                self.require_active_main()?;
                self.audit()?
                    .show(&event_id)
                    .map(NodePrivateResponse::AuditEvent)
                    .map_err(Into::into)
            }
            NodePrivateRequest::VerifyAudit => {
                self.require_active_main()?;
                self.audit()?
                    .verify()
                    .map(NodePrivateResponse::AuditVerification)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ExportAudit => {
                self.require_active_main()?;
                self.audit()?
                    .export()
                    .map(NodePrivateResponse::AuditExport)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ListModels => self
                .model()?
                .list()
                .map(NodePrivateResponse::ModelServices)
                .map_err(Into::into),
            NodePrivateRequest::InstallModel(request) => {
                self.require_active_main()?;
                self.model()?
                    .install(request)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::PauseModel {
                identity,
                service_id,
            } => {
                self.require_active_main()?;
                self.model()?
                    .pause(identity, service_id)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ResumeModel {
                identity,
                service_id,
            } => {
                self.require_active_main()?;
                self.model()?
                    .resume(identity, service_id)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RestartModel {
                identity,
                service_id,
            } => {
                self.require_active_main()?;
                self.model()?
                    .restart(identity, service_id)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RecoverModel {
                identity,
                service_id,
            } => {
                self.require_active_main()?;
                self.model()?
                    .recover(identity, service_id)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RemoveModel(request) => {
                self.require_active_main()?;
                self.model()?
                    .remove(request)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::RollbackModel {
                identity,
                service_id,
                target_id,
            } => {
                self.require_active_main()?;
                self.model()?
                    .rollback(identity, service_id, target_id)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodePrivateRequest::PreviewRollbackModel {
                service_id,
                target_id,
            } => self
                .model()?
                .preview_rollback(&service_id, target_id.as_ref())
                .map(NodePrivateResponse::ModelRollbackPreview)
                .map_err(Into::into),
            NodePrivateRequest::ReadModelLogs { service_id } => self
                .model()?
                .logs(&service_id)
                .map(NodePrivateResponse::ModelLogs)
                .map_err(Into::into),
            NodePrivateRequest::ReadModelRuntimeLogs(request) => self
                .model()?
                .runtime_logs(request)
                .map(NodePrivateResponse::ModelRuntimeLogs)
                .map_err(Into::into),
            NodePrivateRequest::CheckCoreUpdate { requested_version } => self
                .core_update()?
                .check(requested_version)
                .map(NodePrivateResponse::CoreUpdateCheck)
                .map_err(Into::into),
            NodePrivateRequest::UpdateCore {
                idempotency_key,
                requested_version,
            } => self
                .core_update()?
                .update(&idempotency_key, requested_version)
                .map(NodePrivateResponse::CoreUpdated)
                .map_err(Into::into),
            NodePrivateRequest::UpdateModel(request) => {
                self.require_active_main()?;
                self.model()?
                    .update(request)
                    .map(NodePrivateResponse::ModelUpdated)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadExposure => {
                self.require_active_main()?;
                self.exposure()?
                    .status()
                    .map(NodePrivateResponse::Exposure)
                    .map_err(Into::into)
            }
            NodePrivateRequest::EnableExposure => {
                self.require_active_main()?;
                self.exposure()?
                    .enable()
                    .map(NodePrivateResponse::Exposure)
                    .map_err(Into::into)
            }
            NodePrivateRequest::DisableExposure => {
                self.require_active_main()?;
                self.exposure()?
                    .disable()
                    .map(NodePrivateResponse::Exposure)
                    .map_err(Into::into)
            }
            NodePrivateRequest::ReadRuntimeInstallationIds => self
                .runtime_maintenance()?
                .installation_ids()
                .map(NodePrivateResponse::RuntimeInstallationIds)
                .map_err(Into::into),
            NodePrivateRequest::RemoveRuntimeInstallation {
                installation_id,
                model_retention,
            } => self
                .runtime_maintenance()?
                .remove(&installation_id, model_retention)
                .map(NodePrivateResponse::RuntimeInstallationRemoved)
                .map_err(Into::into),
            NodePrivateRequest::Uninstall(_) => {
                Err(NodePrivateApiError::UninstallBarrierUnavailable)
            }
            NodePrivateRequest::ActivatePairedChild(request) => self
                .pairing_activation()?
                .activate_paired_child(&request)
                .map(NodePrivateResponse::PairingAuthorityChanged)
                .map_err(Into::into),
            NodePrivateRequest::RestorePairedMain(request) => self
                .pairing_activation()?
                .restore_paired_main(&request)
                .map(NodePrivateResponse::PairingAuthorityChanged)
                .map_err(Into::into),
            NodePrivateRequest::Gateway(request) => {
                let role = self.manager.local_node()?.role();
                self.gateway()?
                    .dispatch(role, request)
                    .map(NodePrivateResponse::Gateway)
                    .map_err(Into::into)
            }
        }
    }

    // Locks the sole process-local mutation barrier or reports poisoned state explicitly.
    fn lock_uninstall_session(
        &self,
    ) -> Result<MutexGuard<'_, Option<ActiveNodeUninstallSession>>, NodePrivateApiError> {
        self.uninstall_session
            .lock()
            .map_err(|_| NodePrivateApiError::UninstallBarrierUnavailable)
    }

    // Nonblockingly activates or exactly replays one retention-bound uninstall lease.
    fn begin_uninstall(
        &self,
        session_id: &Sha256Digest,
        model_retention: NodeRuntimeModelRetention,
    ) -> Result<NodePrivateResponse, NodePrivateApiError> {
        let mut active = match self.uninstall_session.try_lock() {
            Ok(active) => active,
            Err(TryLockError::WouldBlock) => return Err(NodePrivateApiError::UninstallBusy),
            Err(TryLockError::Poisoned(_)) => {
                return Err(NodePrivateApiError::UninstallBarrierUnavailable);
            }
        };
        if let Some(current) = active.as_ref() {
            if &current.session_id != session_id || current.model_retention != model_retention {
                return Err(NodePrivateApiError::UninstallSessionConflict);
            }
            return Ok(NodePrivateResponse::UninstallBegan(
                NodeUninstallBeginReceipt::new(
                    session_id.clone(),
                    NodeUninstallSessionDisposition::Replayed,
                    model_retention,
                    current.inventory.clone(),
                ),
            ));
        }
        let inventory = self.uninstall_inventory()?;
        *active = Some(ActiveNodeUninstallSession {
            session_id: session_id.clone(),
            model_retention,
            inventory: inventory.clone(),
        });
        Ok(NodePrivateResponse::UninstallBegan(
            NodeUninstallBeginReceipt::new(
                session_id.clone(),
                NodeUninstallSessionDisposition::Applied,
                model_retention,
                inventory,
            ),
        ))
    }

    // Applies one exact leased cleanup or matching cancellation under the mutation lock.
    fn dispatch_uninstall(
        &self,
        active: &mut Option<ActiveNodeUninstallSession>,
        request: NodeUninstallRequest,
    ) -> Result<NodePrivateResponse, NodePrivateApiError> {
        let session_id = request.session_id().clone();
        let Some(session) = active.as_ref() else {
            return Err(NodePrivateApiError::UninstallSessionConflict);
        };
        if session.session_id != session_id {
            return Err(NodePrivateApiError::UninstallSessionConflict);
        }
        match request {
            NodeUninstallRequest::Begin { .. } => Err(NodePrivateApiError::UninstallBusy),
            NodeUninstallRequest::StopBenchmark { job_id, .. } => {
                self.require_active_main()?;
                if session.inventory.active_benchmark_id() != Some(&job_id) {
                    return Err(NodePrivateApiError::UninstallSessionConflict);
                }
                self.benchmark()?
                    .stop(&job_id)
                    .map(NodePrivateResponse::BenchmarkChanged)
                    .map_err(Into::into)
            }
            NodeUninstallRequest::DisableExposure { .. } => {
                self.require_active_main()?;
                let Some(expected_configuration_sha256) =
                    session.inventory.exposure_configuration_sha256()
                else {
                    return GatewayExposureStatus::new(None, true)
                        .map(NodePrivateResponse::Exposure)
                        .map_err(|_| NodePrivateApiError::UninstallBarrierUnavailable);
                };
                self.exposure()?
                    .disable_matching(expected_configuration_sha256)
                    .map(NodePrivateResponse::Exposure)
                    .map_err(Into::into)
            }
            NodeUninstallRequest::RemoveModel { request, .. } => {
                self.require_active_main()?;
                let is_snapshotted_service = session
                    .inventory
                    .model_targets()
                    .iter()
                    .any(|service| service.service_id() == request.service_id());
                if !is_snapshotted_service
                    || request.selection() != &NodeModelRemovalSelection::All
                    || runtime_model_retention(request.runtime_retention())
                        != session.model_retention
                {
                    return Err(NodePrivateApiError::UninstallSessionConflict);
                }
                self.model()?
                    .remove(request)
                    .map(NodePrivateResponse::ModelChanged)
                    .map_err(Into::into)
            }
            NodeUninstallRequest::RemoveRuntimeInstallation {
                installation_id,
                model_retention,
                ..
            } => {
                if model_retention != session.model_retention
                    || !session
                        .inventory
                        .runtime_installation_ids()
                        .contains(&installation_id)
                {
                    return Err(NodePrivateApiError::UninstallSessionConflict);
                }
                self.runtime_maintenance()?
                    .remove(&installation_id, model_retention)
                    .map(NodePrivateResponse::RuntimeInstallationRemoved)
                    .map_err(Into::into)
            }
            NodeUninstallRequest::FinalizeRuntimeArtifacts {
                model_retention, ..
            } => {
                if model_retention != session.model_retention {
                    return Err(NodePrivateApiError::UninstallSessionConflict);
                }
                self.runtime_maintenance()?
                    .finalize_cleanup(model_retention)
                    .map(|()| {
                        NodePrivateResponse::RuntimeArtifactsFinalized(
                            NodeRuntimeArtifactsFinalizationReceipt::new(model_retention),
                        )
                    })
                    .map_err(Into::into)
            }
            NodeUninstallRequest::Cancel { .. } => {
                *active = None;
                Ok(NodePrivateResponse::UninstallCanceled(
                    NodeUninstallCancelReceipt::new(session_id),
                ))
            }
        }
    }

    // Captures every preexisting teardown target before publishing the active lease.
    fn uninstall_inventory(&self) -> Result<NodeUninstallInventory, NodePrivateApiError> {
        let local_role = self.manager.local_node()?.role();
        let (active_benchmark_id, exposure_configuration_sha256, model_targets) = match local_role {
            NodeRole::Main => (
                self.benchmark()?
                    .active()?
                    .map(|benchmark| benchmark.job_id().clone()),
                self.exposure()?
                    .status()?
                    .exposure()
                    .map(|exposure| exposure.configuration_sha256().clone()),
                self.model()?
                    .list()?
                    .into_iter()
                    .filter(|service| service.desired_state() != ModelServiceDesiredState::Removed)
                    .map(|service| {
                        NodeUninstallModelTarget::new(
                            service.service_id().clone(),
                            service.placement_group_ids().to_vec(),
                        )
                    })
                    .collect(),
            ),
            NodeRole::Child => (None, None, Vec::new()),
        };
        let runtime_installation_ids = self.runtime_maintenance()?.installation_ids()?;
        NodeUninstallInventory::new(
            local_role,
            active_benchmark_id,
            exposure_configuration_sha256,
            model_targets,
            runtime_installation_ids,
        )
    }

    // Builds one exact redacted host snapshot through the sole manager-owned projection path.
    fn host_snapshot(&self, node_id: &NodeId) -> Result<NodeHostSnapshot, NodePrivateApiError> {
        let projection = self
            .manager
            .host_projection(node_id, self.host_projection_ports()?)?;
        NodeHostSnapshot::from_projection(&projection).map_err(host_projection_error)
    }

    // Builds one canonical local inventory without requiring the CLI to join manager reads.
    fn host_inventory(&self) -> Result<NodeHostInventory, NodePrivateApiError> {
        let hosts = self
            .manager
            .nodes()?
            .iter()
            .map(|node| self.host_snapshot(node.identity().node_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let model_services = match &self.model {
            Some(model) => model.list().map_or(
                NodeHostProjectionValue::Unavailable,
                NodeHostProjectionValue::Available,
            ),
            None => NodeHostProjectionValue::Unavailable,
        };
        NodeHostInventory::new(self.manager.local_node_id().clone(), hosts, model_services)
            .map_err(host_projection_error)
    }

    // Returns the exact composed host ports or one stable unavailable error.
    fn host_projection_ports(&self) -> Result<&NodeHostProjectionPorts, NodePrivateApiError> {
        self.host_projection
            .as_deref()
            .ok_or(NodePrivateApiError::HostProjectionUnavailable)
    }

    // Requires pairing control to execute only for this exact active local main authority.
    fn require_active_main(&self) -> Result<(), NodePrivateApiError> {
        let local = self.manager.local_node()?;
        if local.role() != NodeRole::Main || local.state() != NodeState::Active {
            return Err(NodePrivateApiError::ActiveMainRequired);
        }
        Ok(())
    }

    // Returns the composed Node benchmark role or one stable unavailable error.
    fn benchmark(&self) -> Result<&Arc<dyn NodeBenchmarkApiPort>, NodePrivateApiError> {
        self.benchmark.as_ref().ok_or_else(|| {
            BenchmarkError::provider("node API", "benchmark service is unavailable").into()
        })
    }

    // Returns the composed signed-catalog projection or one stable unavailable error.
    fn catalog(&self) -> Result<&Arc<dyn NodeCatalogApiPort>, NodePrivateApiError> {
        self.catalog
            .as_ref()
            .ok_or(NodeCatalogApiError::Unavailable.into())
    }

    // Returns the composed Node authentication role or one stable unavailable error.
    fn authentication(&self) -> Result<&Arc<dyn NodeAuthenticationApiPort>, NodePrivateApiError> {
        self.authentication.as_ref().ok_or_else(|| {
            AuthenticationError::Store(
                li_authentication_manager::AuthenticationStoreError::Unavailable,
            )
            .into()
        })
    }

    // Returns the composed Node command-audit owner or one stable unavailable error.
    fn command_audit(&self) -> Result<&Arc<dyn NodeCommandAuditApiPort>, NodePrivateApiError> {
        self.command_audit
            .as_ref()
            .ok_or(NodeCommandAuditError::Unavailable.into())
    }

    // Returns the composed Node audit-query owner or one stable unavailable error.
    fn audit(&self) -> Result<&Arc<dyn NodeAuditApiPort>, NodePrivateApiError> {
        self.audit
            .as_ref()
            .ok_or_else(|| AuditError::provider("node API", "audit service is unavailable").into())
    }

    // Returns the composed ModelCoordinator role or one stable unavailable error.
    fn model(&self) -> Result<&Arc<dyn NodeModelApiPort>, NodePrivateApiError> {
        self.model
            .as_ref()
            .ok_or(NodeModelError::ProviderUnavailable.into())
    }

    // Returns the composed CoreUpdateManager projection or one stable unavailable error.
    fn core_update(&self) -> Result<&Arc<dyn NodeCoreUpdateApiPort>, NodePrivateApiError> {
        self.core_update
            .as_ref()
            .ok_or(NodeUpdateError::ProjectionUnavailable.into())
    }

    // Returns the composed main-only Gateway exposure projection or one stable failure.
    fn exposure(&self) -> Result<&Arc<dyn NodeExposureApiPort>, NodePrivateApiError> {
        self.exposure
            .as_ref()
            .ok_or(GatewayExposureError::InvalidConfiguration.into())
    }

    // Returns the composed local storage owner or one stable unavailable error.
    fn storage(&self) -> Result<&Arc<dyn NodeStorageApiPort>, NodePrivateApiError> {
        self.storage
            .as_ref()
            .ok_or(NodeStorageError::ProviderUnavailable.into())
    }

    // Returns the composed local runtime-maintenance owner or one stable unavailable error.
    fn runtime_maintenance(
        &self,
    ) -> Result<&Arc<dyn NodeRuntimeMaintenanceApiPort>, NodePrivateApiError> {
        self.runtime_maintenance
            .as_ref()
            .ok_or(NodeRuntimeMaintenanceError::ProviderUnavailable.into())
    }

    // Returns the atomic pairing authority or one stable unavailable failure.
    fn pairing_activation(
        &self,
    ) -> Result<&Arc<dyn NodePairingActivationAuthorityPort>, NodePrivateApiError> {
        self.pairing_activation
            .as_ref()
            .ok_or(NodePairingActivationAuthorityError::Unavailable.into())
    }

    // Returns the composed local Gateway capability surface or one stable unavailable error.
    fn gateway(&self) -> Result<&Arc<NodeGatewayApi>, NodePrivateApiError> {
        self.gateway
            .as_ref()
            .ok_or(NodeGatewayApiError::Unavailable.into())
    }

    // Returns the shared manager for daemon composition without exposing mutable internals.
    pub fn manager(&self) -> &Arc<NodeManager> {
        &self.manager
    }
}

// Converts the model-service policy into the exact RuntimeManager retention contract.
const fn runtime_model_retention(
    retention: NodeModelRemovalRetention,
) -> NodeRuntimeModelRetention {
    match retention {
        NodeModelRemovalRetention::RemoveUnreferencedRuntimes => NodeRuntimeModelRetention::Remove,
        NodeModelRemovalRetention::PreserveModels => NodeRuntimeModelRetention::Preserve,
    }
}

// Collapses one redacted host projection validation failure into its stable API boundary.
fn host_projection_error(_error: NodeHostReadError) -> NodePrivateApiError {
    NodePrivateApiError::HostProjectionUnavailable
}
