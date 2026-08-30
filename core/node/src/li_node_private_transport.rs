// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditCorrelationId, AuditEvent,
    AuditEventId, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditReason, AuditTarget,
    AuditUnixNanoseconds,
};
use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, ControllerPublicKey, ControllerRole,
    ControllerState,
};
use li_benchmark_manager::{
    BenchmarkDisposition, BenchmarkError, BenchmarkFailureCategory, BenchmarkGitRevision,
    BenchmarkJobPhase, BenchmarkKind, BenchmarkRequest, BenchmarkScope, BenchmarkSubject,
    BenchmarkVerificationPhase,
};
use li_core_interface::{
    ApiKeyId, BootId, ControllerId, CredentialId, DeviceId, DisplayName, EndpointAddress,
    EndpointOwnership, EndpointScheme, EntityTimestamps, EvidenceLabel, FailureDescription,
    HardwareObservation, HardwareObservationId, InstallationId, InterconnectKind, LogicalModelName,
    MachineId, ModelServiceDesiredState, ModelServiceId, NetworkInterfaceName, Node, NodeAddress,
    NodeId, NodeIdentity, NodeRole, NodeState, OperationId, PairingInviteId, Placement,
    PlacementAssignment, PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeCandidateId, RuntimeInstallationId, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TaskId, TechnicalName, TokenCountContract,
    TokenCountProtocol, UnixMilliseconds,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateDisposition, CoreUpdateError, CoreUpdatePhase, CoreVersion,
};
use li_gateway_manager::{
    GatewayExposure, GatewayExposureStatus, GatewayNativeTarget, GatewayPrincipal, GatewayRoute,
    GatewayRouteTarget, GatewayUsageRecord, LETSINFER_PUBLIC_INFERENCE_TARGET,
};
use li_hardware_manager::{decode_hardware_observation, encode_hardware_observation};
use li_placement_manager::{PlacementLink, PlacementLogBatch, PlacementLogCursor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::li_node_catalog_api::{bounded_catalog_source, bounded_catalog_targets};
use crate::{
    NodeApiKeyPolicyUpdate, NodeAuditExport, NodeAuditVerification,
    NodeBenchmarkCandidateHandoffPhase, NodeBenchmarkContext, NodeBenchmarkPlan,
    NodeBenchmarkSelection, NodeBenchmarkSnapshot, NodeBenchmarkSnapshotProgress,
    NodeBenchmarkTerminalFailure, NodeBenchmarkVerificationProjection, NodeCatalogAuthor,
    NodeCatalogAuthorKind, NodeCatalogEntry, NodeCatalogListRequest, NodeCatalogListing,
    NodeCatalogRefreshPolicy, NodeCatalogSnapshot, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection, NodeCommandAuditCompletionDisposition,
    NodeCommandAuditCompletionReceipt, NodeCommandAuditCompletionRequest, NodeCommandAuditIntent,
    NodeCommandAuditMarker, NodeCommandAuditMutation, NodeCommandAuditOpenDisposition,
    NodeCommandAuditOpenReceipt, NodeCommandAuditOpenRequest, NodeCommandAuditOutcome,
    NodeCommandAuditPolicy, NodeCommandAuditResult, NodeCommandAuditTarget,
    NodeCommandAuditTargetKind, NodeControllerEnrollmentCandidate, NodeControllerEnrollmentReceipt,
    NodeControllerSummary, NodeCoreUpdateCheck, NodeCoreUpdateSummary, NodeGatewayApiError,
    NodeGatewayBearer, NodeGatewayMacOsPlacement, NodeGatewayMacOsSafetyInput, NodeGatewayRequest,
    NodeGatewayResponse, NodeGatewayUsageDisposition, NodeHostEndpointSnapshot,
    NodeHostGatewaySummary, NodeHostGatewayTelemetrySummary, NodeHostInventory,
    NodeHostPlacementGroupSnapshot, NodeHostPlacementSnapshot, NodeHostProjectionValue,
    NodeHostProtectionState, NodeHostProtectionSummary, NodeHostServiceState, NodeHostSnapshot,
    NodeHostWatchdogSummary, NodeHostWatchdogTelemetrySummary, NodeIssuedApiKey, NodeManagerChange,
    NodeManagerEvent, NodeModelAction, NodeModelCommandIdentity, NodeModelCommandSummary,
    NodeModelInstallGroup, NodeModelInstallRequest, NodeModelJournalState, NodeModelLogSummary,
    NodeModelRemovalRetention, NodeModelRemovalSelection, NodeModelRemoveRequest,
    NodeModelRollbackGroupPreview, NodeModelRollbackPreview, NodeModelRollbackRuntime,
    NodeModelRuntimeLogBatch, NodeModelRuntimeLogRequest, NodeModelServiceSummary,
    NodeModelUpdateDisposition, NodeModelUpdateRequest, NodeModelUpdateSummary, NodeOutboxEvent,
    NodeOutboxState, NodePairedChildActivationRequest, NodePairedMainRestorationRequest,
    NodePairingActivationAuthorityError, NodePairingApiError, NodePairingApproveRequest,
    NodePairingAuthorityDisposition, NodePairingAuthorityReceipt, NodePairingCredentials,
    NodePairingEnrollRequest, NodePairingEnrollment, NodePairingInvitation, NodePairingMode,
    NodePairingOpenRequest, NodePairingState, NodePairingStatus, NodePrivateApi,
    NodePrivateApiError, NodePrivateRequest, NodePrivateResponse,
    NodeRuntimeArtifactsFinalizationReceipt, NodeRuntimeMaintenanceError,
    NodeRuntimeModelRetention, NodeRuntimeRemovalDisposition, NodeStorageCandidate,
    NodeStorageCategory, NodeStorageCleanReceipt, NodeStorageCleanRequest, NodeStorageError,
    NodeStorageSnapshot, NodeStorageUsage, NodeTransition, NodeUninstallBeginReceipt,
    NodeUninstallCancelReceipt, NodeUninstallInventory, NodeUninstallModelTarget,
    NodeUninstallRequest, NodeUninstallSessionDisposition, NodeUpdateError,
    VersionedNodeOutboxEvent, MAXIMUM_RUNTIME_INSTALLATIONS,
};

const SCHEMA_NAME: &str = "li_node_private_api";
const SCHEMA_VERSION: u32 = 2;
pub const NODE_PRIVATE_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
const MAX_REMOTE_ERROR_BYTES: usize = 512;
const MAX_MODEL_RUNTIME_LOG_BYTES: usize = 512 * 1024;

// Carries one decoded private request and its transport correlation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateTransportRequest {
    request_id: Sha256Digest,
    request: NodePrivateRequest,
}

impl NodePrivateTransportRequest {
    // Creates one outbound request from a typed API request.
    pub const fn new(request_id: Sha256Digest, request: NodePrivateRequest) -> Self {
        Self {
            request_id,
            request,
        }
    }

    // Returns the exact correlation identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the typed request consumed by NodePrivateApi.
    pub const fn request(&self) -> &NodePrivateRequest {
        &self.request
    }

    // Transfers typed request ownership to the dispatcher.
    pub fn into_request(self) -> NodePrivateRequest {
        self.request
    }
}

// Describes one stable authenticated remote failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateRemoteError {
    code: TechnicalName,
    message: String,
}

impl NodePrivateRemoteError {
    // Creates one bounded remote failure without accepting terminal controls.
    pub fn new(code: TechnicalName, message: &str) -> Result<Self, NodePrivateTransportError> {
        if message.is_empty()
            || message.len() > MAX_REMOTE_ERROR_BYTES
            || message
                .chars()
                .any(|character| character.is_control() && character != '\t')
        {
            return Err(NodePrivateTransportError::InvalidDocument {
                reason: "remote error message is empty, oversized, or unsafe",
            });
        }
        Ok(Self {
            code,
            message: message.to_string(),
        })
    }

    // Returns the stable machine-readable failure code.
    pub const fn code(&self) -> &TechnicalName {
        &self.code
    }

    // Returns the bounded human-readable failure message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

// Distinguishes one successful typed response from a stable remote failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateTransportOutcome {
    Success(NodePrivateResponse),
    Failure(NodePrivateRemoteError),
}

// Carries one decoded private response and its exact request identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateTransportResponse {
    request_id: Sha256Digest,
    outcome: NodePrivateTransportOutcome,
}

impl NodePrivateTransportResponse {
    // Creates one outbound typed response.
    pub const fn new(request_id: Sha256Digest, outcome: NodePrivateTransportOutcome) -> Self {
        Self {
            request_id,
            outcome,
        }
    }

    // Returns the correlation identity copied from the request.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the typed success or remote failure.
    pub const fn outcome(&self) -> &NodePrivateTransportOutcome {
        &self.outcome
    }

    // Transfers the typed outcome without cloning one-time response material.
    pub fn into_outcome(self) -> NodePrivateTransportOutcome {
        self.outcome
    }
}

// Describes one stable private wire-boundary failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateTransportError {
    DocumentTooLarge,
    InvalidDocument { reason: &'static str },
    UnsupportedSchema,
}

impl fmt::Display for NodePrivateTransportError {
    // Presents stable transport language without echoing untrusted document values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge => {
                formatter.write_str("private node document exceeds its bound")
            }
            Self::InvalidDocument { reason } => {
                write!(formatter, "private node document is invalid: {reason}")
            }
            Self::UnsupportedSchema => formatter.write_str("private node schema is unsupported"),
        }
    }
}

impl Error for NodePrivateTransportError {}

// Owns the closed JSON serialization boundary for the typed private node API.
pub struct NodePrivateTransport;

impl NodePrivateTransport {
    // Encodes one typed request into canonical compact JSON bytes.
    pub fn encode_request(
        request: &NodePrivateTransportRequest,
    ) -> Result<Vec<u8>, NodePrivateTransportError> {
        validate_command_audit_identity(request.request_id(), request.request())?;
        encode_document(&WireRequest::from_request(request))
    }

    // Decodes, bounds, and validates one private request document.
    pub fn decode_request(
        document: &[u8],
    ) -> Result<NodePrivateTransportRequest, NodePrivateTransportError> {
        let wire: WireRequest = decode_document(document)?;
        wire.into_request()
    }

    // Encodes one dispatch result without exposing authorization implementation details.
    pub fn encode_dispatch_result(
        request_id: Sha256Digest,
        result: Result<NodePrivateResponse, NodePrivateApiError>,
    ) -> Result<Vec<u8>, NodePrivateTransportError> {
        let outcome = match result {
            Ok(response) => NodePrivateTransportOutcome::Success(response),
            Err(NodePrivateApiError::AuthorizationDenied) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("authorization_denied").map_err(interface_error)?,
                    "private node action is denied",
                )?)
            }
            Err(NodePrivateApiError::ActiveMainRequired) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("active_main_required").map_err(interface_error)?,
                    "private node action requires an active main",
                )?)
            }
            Err(NodePrivateApiError::Manager(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("manager_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Catalog(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("catalog_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Pairing(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("pairing_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Benchmark(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("benchmark_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Controller(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("controller_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Authentication(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("authentication_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::CommandAudit(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("command_audit_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Audit(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("audit_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Model(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("model_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Update(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse(update_error_code(&error)).map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Exposure(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("exposure_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Storage(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("storage_error").map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::RuntimeMaintenance(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse(runtime_maintenance_error_code(error))
                        .map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::PairingActivation(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse(pairing_activation_error_code(error))
                        .map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::Gateway(error)) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse(gateway_api_error_code(error)).map_err(interface_error)?,
                    &error.to_string(),
                )?)
            }
            Err(NodePrivateApiError::HostProjectionUnavailable) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("host_projection_unavailable").map_err(interface_error)?,
                    "current host projection is unavailable",
                )?)
            }
            Err(NodePrivateApiError::UninstallInProgress) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("uninstall_in_progress").map_err(interface_error)?,
                    "an uninstall session is active",
                )?)
            }
            Err(NodePrivateApiError::UninstallBusy) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("uninstall_busy").map_err(interface_error)?,
                    "uninstall admission is busy",
                )?)
            }
            Err(NodePrivateApiError::UninstallSessionConflict) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("uninstall_session_conflict").map_err(interface_error)?,
                    "uninstall session does not match",
                )?)
            }
            Err(NodePrivateApiError::UninstallBarrierUnavailable) => {
                NodePrivateTransportOutcome::Failure(NodePrivateRemoteError::new(
                    TechnicalName::parse("uninstall_barrier_unavailable")
                        .map_err(interface_error)?,
                    "uninstall admission is unavailable",
                )?)
            }
        };
        Self::encode_response(&NodePrivateTransportResponse::new(request_id, outcome))
    }

    // Encodes one typed success or remote failure response.
    pub fn encode_response(
        response: &NodePrivateTransportResponse,
    ) -> Result<Vec<u8>, NodePrivateTransportError> {
        encode_document(&WireResponse::from_response(response)?)
    }

    // Decodes, bounds, and validates one private response document.
    pub fn decode_response(
        document: &[u8],
    ) -> Result<NodePrivateTransportResponse, NodePrivateTransportError> {
        let wire: WireResponse = decode_document(document)?;
        wire.into_response()
    }
}

// Owns decode, authorization dispatch, and response encoding for one private listener.
pub struct NodePrivateEndpoint {
    api: Arc<NodePrivateApi>,
}

impl NodePrivateEndpoint {
    // Creates one endpoint without owning the listener or TLS implementation.
    pub const fn new(api: Arc<NodePrivateApi>) -> Self {
        Self { api }
    }

    // Handles one authenticated document through the exact typed API path.
    pub fn handle(
        &self,
        principal_id: &CredentialId,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateTransportError> {
        let request = NodePrivateTransport::decode_request(document)?;
        let request_id = request.request_id().clone();
        let result = self.api.dispatch(principal_id, request.into_request());
        NodePrivateTransport::encode_dispatch_result(request_id, result)
    }

    // Handles one controller-authenticated document without converting it into a peer credential.
    pub fn handle_controller(
        &self,
        controller_id: &ControllerId,
        certificate_sha256: &Sha256Digest,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateTransportError> {
        let request = NodePrivateTransport::decode_request(document)?;
        let request_id = request.request_id().clone();
        let result =
            self.api
                .dispatch_controller(controller_id, certificate_sha256, request.into_request());
        NodePrivateTransport::encode_dispatch_result(request_id, result)
    }

    // Returns the typed API owner for daemon lifecycle composition.
    pub const fn api(&self) -> &Arc<NodePrivateApi> {
        &self.api
    }
}

// Owns decode and exact local-Node dispatch after Unix peer authorization succeeds.
pub struct NodePrivateLocalEndpoint {
    api: Arc<NodePrivateApi>,
}

impl NodePrivateLocalEndpoint {
    // Creates one local endpoint without weakening the separate remote authorization path.
    pub const fn new(api: Arc<NodePrivateApi>) -> Self {
        Self { api }
    }

    // Handles one owner-UID-authenticated document for the exact mapped local Node identity.
    pub fn handle(
        &self,
        local_node_id: &NodeId,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateTransportError> {
        let request = NodePrivateTransport::decode_request(document)?;
        let request_id = request.request_id().clone();
        let result = self
            .api
            .dispatch_local(local_node_id, request.into_request());
        NodePrivateTransport::encode_dispatch_result(request_id, result)
    }

    // Returns the typed API owner for local listener lifecycle composition.
    pub const fn api(&self) -> &Arc<NodePrivateApi> {
        &self.api
    }
}

// Stores the required nested Let's Infer schema identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSchema {
    name: String,
    version: u32,
}

impl WireSchema {
    // Returns the only schema identity accepted by this codec.
    fn current() -> Self {
        Self {
            name: SCHEMA_NAME.to_string(),
            version: SCHEMA_VERSION,
        }
    }

    // Rejects every unknown schema name or version before payload conversion.
    fn validate(&self) -> Result<(), NodePrivateTransportError> {
        if self.name != SCHEMA_NAME || self.version != SCHEMA_VERSION {
            return Err(NodePrivateTransportError::UnsupportedSchema);
        }
        Ok(())
    }
}

// Stores one closed request envelope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    schema: WireSchema,
    request_id: String,
    request: WireRequestBody,
}

impl WireRequest {
    // Projects one typed request into its closed wire shape.
    fn from_request(request: &NodePrivateTransportRequest) -> Self {
        Self {
            schema: WireSchema::current(),
            request_id: request.request_id().as_str().to_string(),
            request: WireRequestBody::from_request(request.request()),
        }
    }

    // Reconstructs one typed request after validating schema and correlation identity.
    fn into_request(self) -> Result<NodePrivateTransportRequest, NodePrivateTransportError> {
        self.schema.validate()?;
        let request_id = parse_digest(&self.request_id)?;
        let request = self.request.into_request()?;
        validate_command_audit_identity(&request_id, &request)?;
        Ok(NodePrivateTransportRequest::new(request_id, request))
    }
}

// Stores one closed action and its exact arguments.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "action",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireRequestBody {
    ReadLocalNode,
    ReadNodes,
    ReadNode {
        node_id: String,
    },
    ReadHardware {
        node_id: String,
    },
    ReadHostProjection {
        node_id: String,
    },
    ReadHostInventory,
    ReadStorage,
    CleanStorage(WireStorageCleanRequest),
    ReadCatalog(WireCatalogListRequest),
    ReadCompatibleTargets {
        node_id: String,
        catalog_source: String,
    },
    EnrollChild {
        idempotency_key: String,
        child: WireNode,
    },
    TransitionChild {
        idempotency_key: String,
        node_id: String,
        expected_revision: u64,
        transition: String,
        updated_at_unix_milliseconds: u64,
    },
    ReadPendingOutbox,
    AcknowledgeOutbox {
        idempotency_key: String,
        event_id: String,
        expected_revision: u64,
        acknowledged_at_unix_milliseconds: u64,
    },
    OpenPairing {
        idempotency_key: String,
        mode: WirePairingMode,
        lifetime_seconds: u16,
    },
    EnrollPairing {
        idempotency_key: String,
        invite_id: String,
        candidate_node_id: String,
        candidate_machine_id: String,
        candidate_installation_id: String,
        candidate_name: String,
        candidate_address: String,
        candidate_public_key_base64: String,
        installation_created_at_unix_milliseconds: u64,
        proof_signature_base64: String,
        setup_code: Option<String>,
        observed_peer_address: String,
    },
    ApprovePairing {
        idempotency_key: String,
        invite_id: String,
    },
    ReadPairingStatus {
        invite_id: String,
    },
    PreviewBenchmark {
        selection: WireBenchmarkSelection,
    },
    StartBenchmark {
        idempotency_key: String,
        selection: WireBenchmarkSelection,
    },
    StartBenchmarkVerification {
        idempotency_key: String,
        pull_request_url: String,
        candidate: Option<String>,
    },
    ReadActiveBenchmark,
    ReadBenchmark {
        job_id: String,
    },
    StopBenchmark {
        job_id: String,
    },
    AddController {
        controller_id: String,
        name: String,
        public_key_base64: String,
        role: String,
    },
    ReadControllers,
    RevokeController {
        selector: String,
    },
    CreateApiKey {
        name: String,
        policy: WireApiKeyPolicy,
    },
    ReadApiKeys,
    ReadApiKey {
        selector: String,
    },
    UpdateApiKeyPolicy {
        selector: String,
        update: WireApiKeyPolicyUpdate,
    },
    RotateApiKey {
        selector: String,
    },
    RevokeApiKey {
        selector: String,
    },
    OpenCommandAudit {
        command_id: String,
        intent: WireCommandAuditIntent,
    },
    CompleteCommandAudit {
        marker: String,
        result: WireCommandAuditResult,
    },
    ReadAuditEvents {
        limit: usize,
    },
    ReadAuditEvent {
        event_id: String,
    },
    VerifyAudit,
    ExportAudit,
    ListModels,
    InstallModel(WireModelInstallRequest),
    PauseModel {
        identity: WireModelCommandIdentity,
        service_id: String,
    },
    ResumeModel {
        identity: WireModelCommandIdentity,
        service_id: String,
    },
    RestartModel {
        identity: WireModelCommandIdentity,
        service_id: String,
    },
    RecoverModel {
        identity: WireModelCommandIdentity,
        service_id: String,
    },
    RemoveModel {
        identity: WireModelCommandIdentity,
        service_id: String,
        node_ids: Option<Vec<String>>,
        runtime_retention: String,
    },
    RollbackModel {
        identity: WireModelCommandIdentity,
        service_id: String,
        target_id: Option<String>,
    },
    PreviewRollbackModel {
        service_id: String,
        target_id: Option<String>,
    },
    ReadModelLogs {
        service_id: String,
    },
    ReadModelRuntimeLogs(WireModelRuntimeLogRequest),
    CheckCoreUpdate {
        requested_version: Option<String>,
    },
    UpdateCore {
        idempotency_key: String,
        requested_version: Option<String>,
    },
    UpdateModel {
        identity: WireModelCommandIdentity,
        service_id: String,
        explicit_candidate_id: Option<String>,
        dry_run: bool,
    },
    ReadExposure,
    EnableExposure,
    DisableExposure,
    ReadRuntimeInstallationIds,
    RemoveRuntimeInstallation {
        installation_id: String,
        model_retention: String,
    },
    Uninstall(WireUninstallRequest),
    ActivatePairedChild(WirePairingAuthorityRequest),
    RestorePairedMain(WirePairingAuthorityRequest),
    Gateway(WireGatewayRequest),
}

impl WireRequestBody {
    // Projects one typed API request into its exact wire action.
    fn from_request(request: &NodePrivateRequest) -> Self {
        match request {
            NodePrivateRequest::ReadLocalNode => Self::ReadLocalNode,
            NodePrivateRequest::ReadNodes => Self::ReadNodes,
            NodePrivateRequest::ReadNode { node_id } => Self::ReadNode {
                node_id: node_id.as_str().to_string(),
            },
            NodePrivateRequest::ReadHardware { node_id } => Self::ReadHardware {
                node_id: node_id.as_str().to_string(),
            },
            NodePrivateRequest::ReadHostProjection { node_id } => Self::ReadHostProjection {
                node_id: node_id.as_str().to_string(),
            },
            NodePrivateRequest::ReadHostInventory => Self::ReadHostInventory,
            NodePrivateRequest::ReadStorage => Self::ReadStorage,
            NodePrivateRequest::CleanStorage(request) => {
                Self::CleanStorage(WireStorageCleanRequest::from_request(request))
            }
            NodePrivateRequest::ReadCatalog(request) => {
                Self::ReadCatalog(WireCatalogListRequest::from_request(request))
            }
            NodePrivateRequest::ReadCompatibleTargets {
                node_id,
                catalog_source,
            } => Self::ReadCompatibleTargets {
                node_id: node_id.as_str().to_string(),
                catalog_source: catalog_source.clone(),
            },
            NodePrivateRequest::EnrollChild {
                idempotency_key,
                child,
            } => Self::EnrollChild {
                idempotency_key: idempotency_key.clone(),
                child: WireNode::from_node(child),
            },
            NodePrivateRequest::TransitionChild {
                idempotency_key,
                node_id,
                expected_revision,
                transition,
                updated_at,
            } => Self::TransitionChild {
                idempotency_key: idempotency_key.clone(),
                node_id: node_id.as_str().to_string(),
                expected_revision: *expected_revision,
                transition: node_transition_name(*transition).to_string(),
                updated_at_unix_milliseconds: updated_at.value(),
            },
            NodePrivateRequest::ReadPendingOutbox => Self::ReadPendingOutbox,
            NodePrivateRequest::AcknowledgeOutbox {
                idempotency_key,
                event_id,
                expected_revision,
                acknowledged_at,
            } => Self::AcknowledgeOutbox {
                idempotency_key: idempotency_key.clone(),
                event_id: event_id.as_str().to_string(),
                expected_revision: *expected_revision,
                acknowledged_at_unix_milliseconds: acknowledged_at.value(),
            },
            NodePrivateRequest::OpenPairing(request) => Self::OpenPairing {
                idempotency_key: request.idempotency_key().to_string(),
                mode: WirePairingMode::from_mode(request.mode()),
                lifetime_seconds: request.lifetime_seconds(),
            },
            NodePrivateRequest::EnrollPairing(request) => Self::EnrollPairing {
                idempotency_key: request.idempotency_key().to_string(),
                invite_id: request.invite_id().as_str().to_string(),
                candidate_node_id: request.candidate_identity().node_id().as_str().to_string(),
                candidate_machine_id: request
                    .candidate_identity()
                    .machine_id()
                    .as_str()
                    .to_string(),
                candidate_installation_id: request
                    .candidate_identity()
                    .installation_id()
                    .as_str()
                    .to_string(),
                candidate_name: request.candidate_name().as_str().to_string(),
                candidate_address: request.candidate_address().as_str().to_string(),
                candidate_public_key_base64: BASE64.encode(request.candidate_public_key()),
                installation_created_at_unix_milliseconds: request
                    .installation_created_at()
                    .value(),
                proof_signature_base64: BASE64.encode(request.proof_signature()),
                setup_code: request.setup_code().map(str::to_string),
                observed_peer_address: request.observed_peer_address().as_str().to_string(),
            },
            NodePrivateRequest::ApprovePairing(request) => Self::ApprovePairing {
                idempotency_key: request.idempotency_key().to_string(),
                invite_id: request.invite_id().as_str().to_string(),
            },
            NodePrivateRequest::ReadPairingStatus { invite_id } => Self::ReadPairingStatus {
                invite_id: invite_id.as_str().to_string(),
            },
            NodePrivateRequest::PreviewBenchmark { selection } => Self::PreviewBenchmark {
                selection: WireBenchmarkSelection::from_selection(selection),
            },
            NodePrivateRequest::StartBenchmark {
                idempotency_key,
                selection,
            } => Self::StartBenchmark {
                idempotency_key: idempotency_key.clone(),
                selection: WireBenchmarkSelection::from_selection(selection),
            },
            NodePrivateRequest::StartBenchmarkVerification {
                idempotency_key,
                pull_request_url,
                candidate,
            } => Self::StartBenchmarkVerification {
                idempotency_key: idempotency_key.clone(),
                pull_request_url: pull_request_url.clone(),
                candidate: candidate
                    .as_ref()
                    .map(|candidate| candidate.as_str().to_string()),
            },
            NodePrivateRequest::ReadActiveBenchmark => Self::ReadActiveBenchmark,
            NodePrivateRequest::ReadBenchmark { job_id } => Self::ReadBenchmark {
                job_id: job_id.as_str().to_string(),
            },
            NodePrivateRequest::StopBenchmark { job_id } => Self::StopBenchmark {
                job_id: job_id.as_str().to_string(),
            },
            NodePrivateRequest::AddController { candidate, role } => Self::AddController {
                controller_id: candidate.controller_id().as_str().to_string(),
                name: candidate.name().as_str().to_string(),
                public_key_base64: BASE64.encode(candidate.public_key().bytes()),
                role: role.as_str().to_string(),
            },
            NodePrivateRequest::ReadControllers => Self::ReadControllers,
            NodePrivateRequest::RevokeController { selector } => Self::RevokeController {
                selector: selector.clone(),
            },
            NodePrivateRequest::CreateApiKey { name, policy } => Self::CreateApiKey {
                name: name.as_str().to_string(),
                policy: WireApiKeyPolicy::from_policy(policy),
            },
            NodePrivateRequest::ReadApiKeys => Self::ReadApiKeys,
            NodePrivateRequest::ReadApiKey { selector } => Self::ReadApiKey {
                selector: selector.clone(),
            },
            NodePrivateRequest::UpdateApiKeyPolicy { selector, update } => {
                Self::UpdateApiKeyPolicy {
                    selector: selector.clone(),
                    update: WireApiKeyPolicyUpdate::from_update(update),
                }
            }
            NodePrivateRequest::RotateApiKey { selector } => Self::RotateApiKey {
                selector: selector.clone(),
            },
            NodePrivateRequest::RevokeApiKey { selector } => Self::RevokeApiKey {
                selector: selector.clone(),
            },
            NodePrivateRequest::OpenCommandAudit(request) => Self::OpenCommandAudit {
                command_id: request.command_id().as_str().to_string(),
                intent: WireCommandAuditIntent::from_intent(request.intent()),
            },
            NodePrivateRequest::CompleteCommandAudit(request) => Self::CompleteCommandAudit {
                marker: request.marker().as_str().to_string(),
                result: WireCommandAuditResult::from_result(request.result()),
            },
            NodePrivateRequest::ReadAuditEvents { limit } => {
                Self::ReadAuditEvents { limit: *limit }
            }
            NodePrivateRequest::ReadAuditEvent { event_id } => Self::ReadAuditEvent {
                event_id: event_id.as_str().to_string(),
            },
            NodePrivateRequest::VerifyAudit => Self::VerifyAudit,
            NodePrivateRequest::ExportAudit => Self::ExportAudit,
            NodePrivateRequest::ListModels => Self::ListModels,
            NodePrivateRequest::InstallModel(request) => {
                Self::InstallModel(WireModelInstallRequest::from_request(request))
            }
            NodePrivateRequest::PauseModel {
                identity,
                service_id,
            } => Self::PauseModel {
                identity: WireModelCommandIdentity::from_identity(identity),
                service_id: service_id.as_str().to_string(),
            },
            NodePrivateRequest::ResumeModel {
                identity,
                service_id,
            } => Self::ResumeModel {
                identity: WireModelCommandIdentity::from_identity(identity),
                service_id: service_id.as_str().to_string(),
            },
            NodePrivateRequest::RestartModel {
                identity,
                service_id,
            } => Self::RestartModel {
                identity: WireModelCommandIdentity::from_identity(identity),
                service_id: service_id.as_str().to_string(),
            },
            NodePrivateRequest::RecoverModel {
                identity,
                service_id,
            } => Self::RecoverModel {
                identity: WireModelCommandIdentity::from_identity(identity),
                service_id: service_id.as_str().to_string(),
            },
            NodePrivateRequest::RemoveModel(request) => Self::RemoveModel {
                identity: WireModelCommandIdentity::from_identity(request.identity()),
                service_id: request.service_id().as_str().to_string(),
                node_ids: request.selection().node_ids().map(|node_ids| {
                    node_ids
                        .iter()
                        .map(|node_id| node_id.as_str().to_string())
                        .collect()
                }),
                runtime_retention: match request.runtime_retention() {
                    NodeModelRemovalRetention::RemoveUnreferencedRuntimes => {
                        "remove_unreferenced_runtimes"
                    }
                    NodeModelRemovalRetention::PreserveModels => "preserve_models",
                }
                .to_string(),
            },
            NodePrivateRequest::RollbackModel {
                identity,
                service_id,
                target_id,
            } => Self::RollbackModel {
                identity: WireModelCommandIdentity::from_identity(identity),
                service_id: service_id.as_str().to_string(),
                target_id: target_id.as_ref().map(|value| value.as_str().to_string()),
            },
            NodePrivateRequest::PreviewRollbackModel {
                service_id,
                target_id,
            } => Self::PreviewRollbackModel {
                service_id: service_id.as_str().to_string(),
                target_id: target_id.as_ref().map(|value| value.as_str().to_string()),
            },
            NodePrivateRequest::ReadModelLogs { service_id } => Self::ReadModelLogs {
                service_id: service_id.as_str().to_string(),
            },
            NodePrivateRequest::ReadModelRuntimeLogs(request) => {
                Self::ReadModelRuntimeLogs(WireModelRuntimeLogRequest::from_request(request))
            }
            NodePrivateRequest::CheckCoreUpdate { requested_version } => Self::CheckCoreUpdate {
                requested_version: requested_version
                    .as_ref()
                    .map(|version| version.as_str().to_string()),
            },
            NodePrivateRequest::UpdateCore {
                idempotency_key,
                requested_version,
            } => Self::UpdateCore {
                idempotency_key: idempotency_key.clone(),
                requested_version: requested_version
                    .as_ref()
                    .map(|version| version.as_str().to_string()),
            },
            NodePrivateRequest::UpdateModel(request) => Self::UpdateModel {
                identity: WireModelCommandIdentity::from_identity(request.identity()),
                service_id: request.service_id().as_str().to_string(),
                explicit_candidate_id: request
                    .explicit_candidate_id()
                    .map(|candidate| candidate.as_str().to_string()),
                dry_run: request.is_dry_run(),
            },
            NodePrivateRequest::ReadExposure => Self::ReadExposure,
            NodePrivateRequest::EnableExposure => Self::EnableExposure,
            NodePrivateRequest::DisableExposure => Self::DisableExposure,
            NodePrivateRequest::ReadRuntimeInstallationIds => Self::ReadRuntimeInstallationIds,
            NodePrivateRequest::RemoveRuntimeInstallation {
                installation_id,
                model_retention,
            } => Self::RemoveRuntimeInstallation {
                installation_id: installation_id.as_str().to_string(),
                model_retention: match model_retention {
                    NodeRuntimeModelRetention::Remove => "remove",
                    NodeRuntimeModelRetention::Preserve => "preserve",
                }
                .to_string(),
            },
            NodePrivateRequest::Uninstall(request) => {
                Self::Uninstall(WireUninstallRequest::from_request(request))
            }
            NodePrivateRequest::ActivatePairedChild(request) => {
                Self::ActivatePairedChild(WirePairingAuthorityRequest::from_activation(request))
            }
            NodePrivateRequest::RestorePairedMain(request) => {
                Self::RestorePairedMain(WirePairingAuthorityRequest::from_restoration(request))
            }
            NodePrivateRequest::Gateway(request) => {
                Self::Gateway(WireGatewayRequest::from_request(request))
            }
        }
    }

    // Reconstructs one typed API request from its closed wire action.
    fn into_request(self) -> Result<NodePrivateRequest, NodePrivateTransportError> {
        match self {
            Self::ReadLocalNode => Ok(NodePrivateRequest::ReadLocalNode),
            Self::ReadNodes => Ok(NodePrivateRequest::ReadNodes),
            Self::ReadNode { node_id } => Ok(NodePrivateRequest::ReadNode {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            }),
            Self::ReadHardware { node_id } => Ok(NodePrivateRequest::ReadHardware {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            }),
            Self::ReadHostProjection { node_id } => Ok(NodePrivateRequest::ReadHostProjection {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            }),
            Self::ReadHostInventory => Ok(NodePrivateRequest::ReadHostInventory),
            Self::ReadStorage => Ok(NodePrivateRequest::ReadStorage),
            Self::CleanStorage(request) => {
                Ok(NodePrivateRequest::CleanStorage(request.into_request()?))
            }
            Self::ReadCatalog(request) => {
                Ok(NodePrivateRequest::ReadCatalog(request.into_request()?))
            }
            Self::ReadCompatibleTargets {
                node_id,
                catalog_source,
            } => Ok(NodePrivateRequest::ReadCompatibleTargets {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
                catalog_source: bounded_catalog_source(catalog_source)
                    .map_err(|_| invalid("catalog source is invalid"))?,
            }),
            Self::EnrollChild {
                idempotency_key,
                child,
            } => Ok(NodePrivateRequest::EnrollChild {
                idempotency_key: bounded_idempotency_key(idempotency_key)?,
                child: child.into_node()?,
            }),
            Self::TransitionChild {
                idempotency_key,
                node_id,
                expected_revision,
                transition,
                updated_at_unix_milliseconds,
            } => Ok(NodePrivateRequest::TransitionChild {
                idempotency_key: bounded_idempotency_key(idempotency_key)?,
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
                expected_revision,
                transition: node_transition(&transition)?,
                updated_at: UnixMilliseconds::new(updated_at_unix_milliseconds),
            }),
            Self::ReadPendingOutbox => Ok(NodePrivateRequest::ReadPendingOutbox),
            Self::AcknowledgeOutbox {
                idempotency_key,
                event_id,
                expected_revision,
                acknowledged_at_unix_milliseconds,
            } => Ok(NodePrivateRequest::AcknowledgeOutbox {
                idempotency_key: bounded_idempotency_key(idempotency_key)?,
                event_id: parse_digest(&event_id)?,
                expected_revision,
                acknowledged_at: UnixMilliseconds::new(acknowledged_at_unix_milliseconds),
            }),
            Self::OpenPairing {
                idempotency_key,
                mode,
                lifetime_seconds,
            } => Ok(NodePrivateRequest::OpenPairing(
                NodePairingOpenRequest::new(
                    bounded_idempotency_key(idempotency_key)?,
                    mode.into_mode()?,
                    lifetime_seconds,
                )
                .map_err(pairing_value_error)?,
            )),
            Self::EnrollPairing {
                idempotency_key,
                invite_id,
                candidate_node_id,
                candidate_machine_id,
                candidate_installation_id,
                candidate_name,
                candidate_address,
                candidate_public_key_base64,
                installation_created_at_unix_milliseconds,
                proof_signature_base64,
                setup_code,
                observed_peer_address,
            } => Ok(NodePrivateRequest::EnrollPairing(
                NodePairingEnrollRequest::new(
                    bounded_idempotency_key(idempotency_key)?,
                    PairingInviteId::parse(&invite_id).map_err(interface_error)?,
                    NodeIdentity::new(
                        NodeId::parse(&candidate_node_id).map_err(interface_error)?,
                        MachineId::parse(&candidate_machine_id).map_err(interface_error)?,
                        InstallationId::parse(&candidate_installation_id)
                            .map_err(interface_error)?,
                    ),
                    DisplayName::parse(&candidate_name).map_err(interface_error)?,
                    NodeAddress::parse(&candidate_address).map_err(interface_error)?,
                    decode_base64(&candidate_public_key_base64)?,
                    UnixMilliseconds::new(installation_created_at_unix_milliseconds),
                    decode_base64(&proof_signature_base64)?,
                    setup_code,
                    NodeAddress::parse(&observed_peer_address).map_err(interface_error)?,
                )
                .map_err(pairing_value_error)?,
            )),
            Self::ApprovePairing {
                idempotency_key,
                invite_id,
            } => Ok(NodePrivateRequest::ApprovePairing(
                NodePairingApproveRequest::new(
                    bounded_idempotency_key(idempotency_key)?,
                    PairingInviteId::parse(&invite_id).map_err(interface_error)?,
                )
                .map_err(pairing_value_error)?,
            )),
            Self::ReadPairingStatus { invite_id } => Ok(NodePrivateRequest::ReadPairingStatus {
                invite_id: PairingInviteId::parse(&invite_id).map_err(interface_error)?,
            }),
            Self::PreviewBenchmark { selection } => Ok(NodePrivateRequest::PreviewBenchmark {
                selection: selection.into_selection()?,
            }),
            Self::StartBenchmark {
                idempotency_key,
                selection,
            } => Ok(NodePrivateRequest::StartBenchmark {
                idempotency_key: bounded_idempotency_key(idempotency_key)?,
                selection: selection.into_selection()?,
            }),
            Self::StartBenchmarkVerification {
                idempotency_key,
                pull_request_url,
                candidate,
            } => Ok(NodePrivateRequest::StartBenchmarkVerification {
                idempotency_key: bounded_idempotency_key(idempotency_key)?,
                pull_request_url: bounded_pull_request_url(pull_request_url)?,
                candidate: candidate
                    .map(|candidate| RuntimeCandidateId::parse(&candidate).map_err(interface_error))
                    .transpose()?,
            }),
            Self::ReadActiveBenchmark => Ok(NodePrivateRequest::ReadActiveBenchmark),
            Self::ReadBenchmark { job_id } => Ok(NodePrivateRequest::ReadBenchmark {
                job_id: OperationId::parse(&job_id).map_err(interface_error)?,
            }),
            Self::StopBenchmark { job_id } => Ok(NodePrivateRequest::StopBenchmark {
                job_id: OperationId::parse(&job_id).map_err(interface_error)?,
            }),
            Self::AddController {
                controller_id,
                name,
                public_key_base64,
                role,
            } => Ok(NodePrivateRequest::AddController {
                candidate: NodeControllerEnrollmentCandidate::new(
                    li_core_interface::ControllerId::parse(&controller_id)
                        .map_err(interface_error)?,
                    DisplayName::parse(&name).map_err(interface_error)?,
                    ControllerPublicKey::new(decode_base64(&public_key_base64)?)
                        .map_err(|_| invalid("controller public key is invalid"))?,
                ),
                role: ControllerRole::parse(&role).map_err(controller_value_error)?,
            }),
            Self::ReadControllers => Ok(NodePrivateRequest::ReadControllers),
            Self::RevokeController { selector } => Ok(NodePrivateRequest::RevokeController {
                selector: bounded_controller_selector(selector)?,
            }),
            Self::CreateApiKey { name, policy } => Ok(NodePrivateRequest::CreateApiKey {
                name: DisplayName::parse(&name).map_err(interface_error)?,
                policy: policy.into_policy()?,
            }),
            Self::ReadApiKeys => Ok(NodePrivateRequest::ReadApiKeys),
            Self::ReadApiKey { selector } => Ok(NodePrivateRequest::ReadApiKey {
                selector: bounded_key_selector(selector)?,
            }),
            Self::UpdateApiKeyPolicy { selector, update } => {
                Ok(NodePrivateRequest::UpdateApiKeyPolicy {
                    selector: bounded_key_selector(selector)?,
                    update: update.into_update()?,
                })
            }
            Self::RotateApiKey { selector } => Ok(NodePrivateRequest::RotateApiKey {
                selector: bounded_key_selector(selector)?,
            }),
            Self::RevokeApiKey { selector } => Ok(NodePrivateRequest::RevokeApiKey {
                selector: bounded_key_selector(selector)?,
            }),
            Self::OpenCommandAudit { command_id, intent } => Ok(
                NodePrivateRequest::OpenCommandAudit(NodeCommandAuditOpenRequest::new(
                    parse_digest(&command_id)?,
                    intent.into_intent()?,
                )),
            ),
            Self::CompleteCommandAudit { marker, result } => Ok(
                NodePrivateRequest::CompleteCommandAudit(NodeCommandAuditCompletionRequest::new(
                    NodeCommandAuditMarker::parse(&marker).map_err(command_audit_value_error)?,
                    result.into_result()?,
                )),
            ),
            Self::ReadAuditEvents { limit } => {
                if !(1..=10_000).contains(&limit) {
                    return Err(invalid("audit list limit is invalid"));
                }
                Ok(NodePrivateRequest::ReadAuditEvents { limit })
            }
            Self::ReadAuditEvent { event_id } => Ok(NodePrivateRequest::ReadAuditEvent {
                event_id: AuditEventId::parse(&event_id).map_err(audit_value_error)?,
            }),
            Self::VerifyAudit => Ok(NodePrivateRequest::VerifyAudit),
            Self::ExportAudit => Ok(NodePrivateRequest::ExportAudit),
            Self::ListModels => Ok(NodePrivateRequest::ListModels),
            Self::InstallModel(request) => {
                Ok(NodePrivateRequest::InstallModel(request.into_request()?))
            }
            Self::PauseModel {
                identity,
                service_id,
            } => Ok(NodePrivateRequest::PauseModel {
                identity: identity.into_identity()?,
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
            }),
            Self::ResumeModel {
                identity,
                service_id,
            } => Ok(NodePrivateRequest::ResumeModel {
                identity: identity.into_identity()?,
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
            }),
            Self::RestartModel {
                identity,
                service_id,
            } => Ok(NodePrivateRequest::RestartModel {
                identity: identity.into_identity()?,
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
            }),
            Self::RecoverModel {
                identity,
                service_id,
            } => Ok(NodePrivateRequest::RecoverModel {
                identity: identity.into_identity()?,
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
            }),
            Self::RemoveModel {
                identity,
                service_id,
                node_ids,
                runtime_retention,
            } => Ok(NodePrivateRequest::RemoveModel(
                NodeModelRemoveRequest::new(
                    identity.into_identity()?,
                    ModelServiceId::parse(&service_id).map_err(interface_error)?,
                    match node_ids {
                        Some(node_ids) => NodeModelRemovalSelection::nodes(
                            node_ids
                                .into_iter()
                                .map(|node_id| NodeId::parse(&node_id).map_err(interface_error))
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                        .map_err(model_value_error)?,
                        None => NodeModelRemovalSelection::All,
                    },
                    match runtime_retention.as_str() {
                        "remove_unreferenced_runtimes" => {
                            NodeModelRemovalRetention::RemoveUnreferencedRuntimes
                        }
                        "preserve_models" => NodeModelRemovalRetention::PreserveModels,
                        _ => return Err(invalid("model removal runtime retention is invalid")),
                    },
                ),
            )),
            Self::RollbackModel {
                identity,
                service_id,
                target_id,
            } => Ok(NodePrivateRequest::RollbackModel {
                identity: identity.into_identity()?,
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
                target_id: target_id
                    .map(|value| TargetId::parse(&value).map_err(interface_error))
                    .transpose()?,
            }),
            Self::PreviewRollbackModel {
                service_id,
                target_id,
            } => Ok(NodePrivateRequest::PreviewRollbackModel {
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
                target_id: target_id
                    .map(|value| TargetId::parse(&value).map_err(interface_error))
                    .transpose()?,
            }),
            Self::ReadModelLogs { service_id } => Ok(NodePrivateRequest::ReadModelLogs {
                service_id: ModelServiceId::parse(&service_id).map_err(interface_error)?,
            }),
            Self::ReadModelRuntimeLogs(request) => Ok(NodePrivateRequest::ReadModelRuntimeLogs(
                request.into_request()?,
            )),
            Self::CheckCoreUpdate { requested_version } => {
                Ok(NodePrivateRequest::CheckCoreUpdate {
                    requested_version: requested_version
                        .map(|version| CoreVersion::parse(&version).map_err(update_value_error))
                        .transpose()?,
                })
            }
            Self::UpdateCore {
                idempotency_key,
                requested_version,
            } => Ok(NodePrivateRequest::UpdateCore {
                idempotency_key: bounded_idempotency_key(idempotency_key)?,
                requested_version: requested_version
                    .map(|version| CoreVersion::parse(&version).map_err(update_value_error))
                    .transpose()?,
            }),
            Self::UpdateModel {
                identity,
                service_id,
                explicit_candidate_id,
                dry_run,
            } => Ok(NodePrivateRequest::UpdateModel(
                NodeModelUpdateRequest::new(
                    identity.into_identity()?,
                    ModelServiceId::parse(&service_id).map_err(interface_error)?,
                    explicit_candidate_id
                        .map(|candidate| {
                            RuntimeCandidateId::parse(&candidate).map_err(interface_error)
                        })
                        .transpose()?,
                    dry_run,
                ),
            )),
            Self::ReadExposure => Ok(NodePrivateRequest::ReadExposure),
            Self::EnableExposure => Ok(NodePrivateRequest::EnableExposure),
            Self::DisableExposure => Ok(NodePrivateRequest::DisableExposure),
            Self::ReadRuntimeInstallationIds => Ok(NodePrivateRequest::ReadRuntimeInstallationIds),
            Self::RemoveRuntimeInstallation {
                installation_id,
                model_retention,
            } => Ok(NodePrivateRequest::RemoveRuntimeInstallation {
                installation_id: RuntimeInstallationId::parse(&installation_id)
                    .map_err(interface_error)?,
                model_retention: match model_retention.as_str() {
                    "remove" => NodeRuntimeModelRetention::Remove,
                    "preserve" => NodeRuntimeModelRetention::Preserve,
                    _ => return Err(invalid("runtime model retention is invalid")),
                },
            }),
            Self::Uninstall(request) => Ok(NodePrivateRequest::Uninstall(request.into_request()?)),
            Self::ActivatePairedChild(request) => Ok(NodePrivateRequest::ActivatePairedChild(
                request.into_activation()?,
            )),
            Self::RestorePairedMain(request) => Ok(NodePrivateRequest::RestorePairedMain(
                request.into_restoration()?,
            )),
            Self::Gateway(request) => Ok(NodePrivateRequest::Gateway(request.into_request()?)),
        }
    }
}

// Stores one exact lease-bound local uninstall operation under a dedicated wire family.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireUninstallRequest {
    Begin {
        session_id: String,
        model_retention: String,
    },
    StopBenchmark {
        session_id: String,
        job_id: String,
    },
    DisableExposure {
        session_id: String,
    },
    RemoveModel {
        session_id: String,
        identity: WireModelCommandIdentity,
        service_id: String,
        node_ids: Option<Vec<String>>,
        runtime_retention: String,
    },
    RemoveRuntimeInstallation {
        session_id: String,
        installation_id: String,
        model_retention: String,
    },
    FinalizeRuntimeArtifacts {
        session_id: String,
        model_retention: String,
    },
    Cancel {
        session_id: String,
    },
}

impl WireUninstallRequest {
    // Projects one typed leased operation into its closed local-only wire shape.
    fn from_request(request: &NodeUninstallRequest) -> Self {
        match request {
            NodeUninstallRequest::Begin {
                session_id,
                model_retention,
            } => Self::Begin {
                session_id: session_id.as_str().to_string(),
                model_retention: runtime_model_retention_name(*model_retention).to_string(),
            },
            NodeUninstallRequest::StopBenchmark { session_id, job_id } => Self::StopBenchmark {
                session_id: session_id.as_str().to_string(),
                job_id: job_id.as_str().to_string(),
            },
            NodeUninstallRequest::DisableExposure { session_id } => Self::DisableExposure {
                session_id: session_id.as_str().to_string(),
            },
            NodeUninstallRequest::RemoveModel {
                session_id,
                request,
            } => Self::RemoveModel {
                session_id: session_id.as_str().to_string(),
                identity: WireModelCommandIdentity::from_identity(request.identity()),
                service_id: request.service_id().as_str().to_string(),
                node_ids: request.selection().node_ids().map(|node_ids| {
                    node_ids
                        .iter()
                        .map(|node_id| node_id.as_str().to_string())
                        .collect()
                }),
                runtime_retention: model_removal_retention_name(request.runtime_retention())
                    .to_string(),
            },
            NodeUninstallRequest::RemoveRuntimeInstallation {
                session_id,
                installation_id,
                model_retention,
            } => Self::RemoveRuntimeInstallation {
                session_id: session_id.as_str().to_string(),
                installation_id: installation_id.as_str().to_string(),
                model_retention: runtime_model_retention_name(*model_retention).to_string(),
            },
            NodeUninstallRequest::FinalizeRuntimeArtifacts {
                session_id,
                model_retention,
            } => Self::FinalizeRuntimeArtifacts {
                session_id: session_id.as_str().to_string(),
                model_retention: runtime_model_retention_name(*model_retention).to_string(),
            },
            NodeUninstallRequest::Cancel { session_id } => Self::Cancel {
                session_id: session_id.as_str().to_string(),
            },
        }
    }

    // Reconstructs one leased operation after validating every identity and closed policy.
    fn into_request(self) -> Result<NodeUninstallRequest, NodePrivateTransportError> {
        Ok(match self {
            Self::Begin {
                session_id,
                model_retention,
            } => NodeUninstallRequest::Begin {
                session_id: parse_digest(&session_id)?,
                model_retention: runtime_model_retention(&model_retention)?,
            },
            Self::StopBenchmark { session_id, job_id } => NodeUninstallRequest::StopBenchmark {
                session_id: parse_digest(&session_id)?,
                job_id: OperationId::parse(&job_id).map_err(interface_error)?,
            },
            Self::DisableExposure { session_id } => NodeUninstallRequest::DisableExposure {
                session_id: parse_digest(&session_id)?,
            },
            Self::RemoveModel {
                session_id,
                identity,
                service_id,
                node_ids,
                runtime_retention,
            } => NodeUninstallRequest::RemoveModel {
                session_id: parse_digest(&session_id)?,
                request: NodeModelRemoveRequest::new(
                    identity.into_identity()?,
                    ModelServiceId::parse(&service_id).map_err(interface_error)?,
                    match node_ids {
                        Some(node_ids) => NodeModelRemovalSelection::nodes(
                            node_ids
                                .into_iter()
                                .map(|node_id| NodeId::parse(&node_id).map_err(interface_error))
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                        .map_err(model_value_error)?,
                        None => NodeModelRemovalSelection::All,
                    },
                    model_removal_retention(&runtime_retention)?,
                ),
            },
            Self::RemoveRuntimeInstallation {
                session_id,
                installation_id,
                model_retention,
            } => NodeUninstallRequest::RemoveRuntimeInstallation {
                session_id: parse_digest(&session_id)?,
                installation_id: RuntimeInstallationId::parse(&installation_id)
                    .map_err(interface_error)?,
                model_retention: runtime_model_retention(&model_retention)?,
            },
            Self::FinalizeRuntimeArtifacts {
                session_id,
                model_retention,
            } => NodeUninstallRequest::FinalizeRuntimeArtifacts {
                session_id: parse_digest(&session_id)?,
                model_retention: runtime_model_retention(&model_retention)?,
            },
            Self::Cancel { session_id } => NodeUninstallRequest::Cancel {
                session_id: parse_digest(&session_id)?,
            },
        })
    }
}

// Stores one of the eight closed Gateway capabilities under one local-only Node action.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "capability",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireGatewayRequest {
    AuthorizeInference {
        bearer: String,
        model: String,
    },
    AuthorizeModelList {
        bearer: String,
    },
    ReadRoutes {
        model: String,
    },
    ResolveNativeTarget {
        route: WireGatewayRoute,
    },
    AuthorizeInboundRelay {
        bearer: String,
    },
    ReadRecentUsage {
        key_id: String,
        since_unix_milliseconds: u64,
    },
    RecordUsage {
        usage: WireGatewayUsageRecord,
    },
    ReadMacOsSafetyInput {
        placement_group_id: String,
    },
}

impl WireGatewayRequest {
    // Projects one typed Gateway request without logging its bearer material.
    fn from_request(request: &NodeGatewayRequest) -> Self {
        match request {
            NodeGatewayRequest::AuthorizeInference { bearer, model } => Self::AuthorizeInference {
                bearer: bearer.expose().to_string(),
                model: model.as_str().to_string(),
            },
            NodeGatewayRequest::AuthorizeModelList { bearer } => Self::AuthorizeModelList {
                bearer: bearer.expose().to_string(),
            },
            NodeGatewayRequest::ReadRoutes { model } => Self::ReadRoutes {
                model: model.as_str().to_string(),
            },
            NodeGatewayRequest::ResolveNativeTarget { route } => Self::ResolveNativeTarget {
                route: WireGatewayRoute::from_route(route),
            },
            NodeGatewayRequest::AuthorizeInboundRelay { bearer } => Self::AuthorizeInboundRelay {
                bearer: bearer.expose().to_string(),
            },
            NodeGatewayRequest::ReadRecentUsage { key_id, since } => Self::ReadRecentUsage {
                key_id: key_id.as_str().to_string(),
                since_unix_milliseconds: since.value(),
            },
            NodeGatewayRequest::RecordUsage { usage } => Self::RecordUsage {
                usage: WireGatewayUsageRecord::from_record(usage),
            },
            NodeGatewayRequest::ReadMacOsSafetyInput { placement_group_id } => {
                Self::ReadMacOsSafetyInput {
                    placement_group_id: placement_group_id.as_str().to_string(),
                }
            }
        }
    }

    // Reconstructs one exact typed Gateway request from its closed capability shape.
    fn into_request(self) -> Result<NodeGatewayRequest, NodePrivateTransportError> {
        Ok(match self {
            Self::AuthorizeInference { bearer, model } => NodeGatewayRequest::AuthorizeInference {
                bearer: gateway_bearer(&bearer)?,
                model: LogicalModelName::parse(&model).map_err(interface_error)?,
            },
            Self::AuthorizeModelList { bearer } => NodeGatewayRequest::AuthorizeModelList {
                bearer: gateway_bearer(&bearer)?,
            },
            Self::ReadRoutes { model } => NodeGatewayRequest::ReadRoutes {
                model: LogicalModelName::parse(&model).map_err(interface_error)?,
            },
            Self::ResolveNativeTarget { route } => NodeGatewayRequest::ResolveNativeTarget {
                route: route.into_route()?,
            },
            Self::AuthorizeInboundRelay { bearer } => NodeGatewayRequest::AuthorizeInboundRelay {
                bearer: gateway_bearer(&bearer)?,
            },
            Self::ReadRecentUsage {
                key_id,
                since_unix_milliseconds,
            } => NodeGatewayRequest::ReadRecentUsage {
                key_id: ApiKeyId::parse(&key_id).map_err(interface_error)?,
                since: UnixMilliseconds::new(since_unix_milliseconds),
            },
            Self::RecordUsage { usage } => NodeGatewayRequest::RecordUsage {
                usage: usage.into_record()?,
            },
            Self::ReadMacOsSafetyInput { placement_group_id } => {
                NodeGatewayRequest::ReadMacOsSafetyInput {
                    placement_group_id: PlacementGroupId::parse(&placement_group_id)
                        .map_err(interface_error)?,
                }
            }
        })
    }
}

// Stores one closed Gateway capability response behind the nested Node response.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireGatewayResponse {
    Principal(WireGatewayPrincipal),
    ModelScope(WireGatewayModelScope),
    Routes(Vec<WireGatewayRoute>),
    NativeTarget(WireGatewayNativeTarget),
    RelayPrincipal(String),
    UsageRecords(Vec<WireGatewayUsageRecord>),
    UsageRecorded(String),
    MacOsSafetyInput(WireGatewayMacOsSafetyInput),
}

impl WireGatewayResponse {
    // Projects one bounded typed Gateway result into its exact wire shape.
    fn from_response(response: &NodeGatewayResponse) -> Result<Self, NodePrivateTransportError> {
        Ok(match response {
            NodeGatewayResponse::Principal(principal) => {
                Self::Principal(WireGatewayPrincipal::from_principal(principal))
            }
            NodeGatewayResponse::ModelScope(scope) => {
                Self::ModelScope(WireGatewayModelScope::from_scope(scope))
            }
            NodeGatewayResponse::Routes(routes) => {
                if routes.len() > crate::NODE_GATEWAY_MAXIMUM_ROUTES {
                    return Err(invalid("Gateway route collection exceeds its bound"));
                }
                Self::Routes(routes.iter().map(WireGatewayRoute::from_route).collect())
            }
            NodeGatewayResponse::NativeTarget(target) => {
                Self::NativeTarget(WireGatewayNativeTarget::from_target(target)?)
            }
            NodeGatewayResponse::RelayPrincipal(node_id) => {
                Self::RelayPrincipal(node_id.as_str().to_string())
            }
            NodeGatewayResponse::UsageRecords(records) => {
                if records.len() > crate::NODE_GATEWAY_MAXIMUM_USAGE_RECORDS {
                    return Err(invalid("Gateway usage collection exceeds its bound"));
                }
                Self::UsageRecords(
                    records
                        .iter()
                        .map(WireGatewayUsageRecord::from_record)
                        .collect(),
                )
            }
            NodeGatewayResponse::UsageRecorded(disposition) => {
                Self::UsageRecorded(gateway_usage_disposition_name(*disposition).to_string())
            }
            NodeGatewayResponse::MacOsSafetyInput(input) => {
                Self::MacOsSafetyInput(WireGatewayMacOsSafetyInput::from_input(input))
            }
        })
    }

    // Reconstructs and revalidates one typed Gateway capability result.
    fn into_response(self) -> Result<NodeGatewayResponse, NodePrivateTransportError> {
        Ok(match self {
            Self::Principal(principal) => {
                NodeGatewayResponse::Principal(principal.into_principal()?)
            }
            Self::ModelScope(scope) => NodeGatewayResponse::ModelScope(scope.into_scope()?),
            Self::Routes(routes) => {
                if routes.len() > crate::NODE_GATEWAY_MAXIMUM_ROUTES {
                    return Err(invalid("Gateway route collection exceeds its bound"));
                }
                NodeGatewayResponse::Routes(
                    routes
                        .into_iter()
                        .map(WireGatewayRoute::into_route)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            Self::NativeTarget(target) => NodeGatewayResponse::NativeTarget(target.into_target()?),
            Self::RelayPrincipal(node_id) => NodeGatewayResponse::RelayPrincipal(
                NodeId::parse(&node_id).map_err(interface_error)?,
            ),
            Self::UsageRecords(records) => {
                if records.len() > crate::NODE_GATEWAY_MAXIMUM_USAGE_RECORDS {
                    return Err(invalid("Gateway usage collection exceeds its bound"));
                }
                NodeGatewayResponse::UsageRecords(
                    records
                        .into_iter()
                        .map(WireGatewayUsageRecord::into_record)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            Self::UsageRecorded(disposition) => {
                NodeGatewayResponse::UsageRecorded(gateway_usage_disposition(&disposition)?)
            }
            Self::MacOsSafetyInput(input) => {
                NodeGatewayResponse::MacOsSafetyInput(input.into_input()?)
            }
        })
    }
}

// Stores durable API-key limits without policy or credential material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayPrincipal {
    key_id: String,
    requests_per_minute: Option<u32>,
    tokens_per_minute: Option<u64>,
    concurrency: Option<u32>,
    context_tokens: Option<u64>,
}

impl WireGatewayPrincipal {
    // Projects one authenticated principal without retaining its bearer.
    fn from_principal(principal: &GatewayPrincipal) -> Self {
        let limits = principal.limits();
        Self {
            key_id: principal.key_id().as_str().to_string(),
            requests_per_minute: limits.requests_per_minute().map(NonZeroU32::get),
            tokens_per_minute: limits.tokens_per_minute().map(NonZeroU64::get),
            concurrency: limits.concurrency().map(NonZeroU32::get),
            context_tokens: limits.context_tokens().map(NonZeroU64::get),
        }
    }

    // Reconstructs one authenticated principal with exact positive limits.
    fn into_principal(self) -> Result<GatewayPrincipal, NodePrivateTransportError> {
        Ok(GatewayPrincipal::new(
            ApiKeyId::parse(&self.key_id).map_err(interface_error)?,
            ApiKeyLimits::new(
                positive_u32(self.requests_per_minute)?,
                positive_u64(self.tokens_per_minute)?,
                positive_u32(self.concurrency)?,
                positive_u64(self.context_tokens)?,
            ),
        ))
    }
}

// Stores one unrestricted or bounded selected API-key model scope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayModelScope {
    selected_models: Option<Vec<String>>,
}

impl WireGatewayModelScope {
    // Projects one exact durable model scope.
    fn from_scope(scope: &ApiKeyModelScope) -> Self {
        Self {
            selected_models: scope.selected_models().map(|models| {
                models
                    .iter()
                    .map(|model| model.as_str().to_string())
                    .collect()
            }),
        }
    }

    // Reconstructs one exact durable model scope and its uniqueness bound.
    fn into_scope(self) -> Result<ApiKeyModelScope, NodePrivateTransportError> {
        match self.selected_models {
            None => Ok(ApiKeyModelScope::all()),
            Some(models) => ApiKeyModelScope::selected(parse_models(models)?)
                .map_err(authentication_value_error),
        }
    }
}

// Stores one complete current Gateway route.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayRoute {
    placement_group_id: String,
    endpoint_node_id: String,
    model: String,
    target: WireGatewayRouteTarget,
    max_active_requests: u32,
    max_context_tokens: u64,
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<u32>,
    prefix_keys: Vec<String>,
}

impl WireGatewayRoute {
    // Projects one exact route without native credential material.
    fn from_route(route: &GatewayRoute) -> Self {
        Self {
            placement_group_id: route.placement_group_id().as_str().to_string(),
            endpoint_node_id: route.endpoint_node_id().as_str().to_string(),
            model: route.model().as_str().to_string(),
            target: WireGatewayRouteTarget::from_target(route.target()),
            max_active_requests: route.max_active_requests().get(),
            max_context_tokens: route.max_context_tokens().get(),
            healthy: route.is_healthy(),
            memory_pressure: route.has_memory_pressure(),
            temperature_millicelsius: route.temperature_millicelsius(),
            prefix_keys: route
                .prefix_keys()
                .iter()
                .map(|value| value.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one validated route and all exact capacity values.
    fn into_route(self) -> Result<GatewayRoute, NodePrivateTransportError> {
        GatewayRoute::new(
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            NodeId::parse(&self.endpoint_node_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.model).map_err(interface_error)?,
            self.target.into_target()?,
            NonZeroU32::new(self.max_active_requests)
                .ok_or_else(|| invalid("Gateway route capacity is invalid"))?,
            NonZeroU64::new(self.max_context_tokens)
                .ok_or_else(|| invalid("Gateway route context bound is invalid"))?,
            self.healthy,
            self.memory_pressure,
            self.temperature_millicelsius,
            self.prefix_keys
                .into_iter()
                .map(|value| parse_digest(&value))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| invalid("Gateway route is invalid"))
    }
}

// Stores the local Engine or child-relay address selected by one route.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireGatewayRouteTarget {
    LocalEngine {
        scheme: String,
        host: String,
        port: u16,
    },
    ChildRelay {
        address: String,
    },
}

impl WireGatewayRouteTarget {
    // Projects one exact route target.
    fn from_target(target: &GatewayRouteTarget) -> Self {
        match target {
            GatewayRouteTarget::LocalEngine { endpoint } => Self::LocalEngine {
                scheme: host_endpoint_scheme_name(endpoint.scheme()).to_string(),
                host: endpoint.host().as_str().to_string(),
                port: endpoint.port(),
            },
            GatewayRouteTarget::ChildRelay { address } => Self::ChildRelay {
                address: address.as_str().to_string(),
            },
        }
    }

    // Reconstructs one exact route target.
    fn into_target(self) -> Result<GatewayRouteTarget, NodePrivateTransportError> {
        Ok(match self {
            Self::LocalEngine { scheme, host, port } => GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    host_endpoint_scheme(&scheme)?,
                    NodeAddress::parse(&host).map_err(interface_error)?,
                    port,
                )
                .map_err(interface_error)?,
            },
            Self::ChildRelay { address } => GatewayRouteTarget::ChildRelay {
                address: NodeAddress::parse(&address).map_err(interface_error)?,
            },
        })
    }
}

// Stores one complete native target using only absolute owner-private file references.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayNativeTarget {
    kind: String,
    host: String,
    port: u16,
    owner_user_id: u32,
    bearer_file: String,
    ca_file: String,
    expected_server_leaf_sha256: Option<String>,
    client_certificate_file: Option<String>,
    client_private_key_file: Option<String>,
    token_count_path: Option<String>,
}

impl WireGatewayNativeTarget {
    // Projects one native target after requiring UTF-8 absolute path identities.
    fn from_target(target: &GatewayNativeTarget) -> Result<Self, NodePrivateTransportError> {
        Ok(Self {
            kind: if target.is_child_relay() {
                "child_relay"
            } else {
                "local_engine"
            }
            .to_string(),
            host: target.host().to_string(),
            port: target.port(),
            owner_user_id: target.owner_user_id(),
            bearer_file: gateway_path(target.bearer_file())?,
            ca_file: gateway_path(target.ca_file())?,
            expected_server_leaf_sha256: target
                .expected_server_leaf_sha256()
                .map(|value| value.as_str().to_string()),
            client_certificate_file: target
                .client_certificate_file()
                .map(gateway_path)
                .transpose()?,
            client_private_key_file: target
                .client_private_key_file()
                .map(gateway_path)
                .transpose()?,
            token_count_path: target.token_count().map(|value| value.path().to_string()),
        })
    }

    // Reconstructs one exact native target and rejects mixed local/relay identities.
    fn into_target(self) -> Result<GatewayNativeTarget, NodePrivateTransportError> {
        let token_count = self
            .token_count_path
            .map(|path| TokenCountContract::new(&path, TokenCountProtocol::LetsInferV1))
            .transpose()
            .map_err(interface_error)?;
        match self.kind.as_str() {
            "local_engine" => {
                if self.expected_server_leaf_sha256.is_some()
                    || self.client_certificate_file.is_some()
                    || self.client_private_key_file.is_some()
                {
                    return Err(invalid("Gateway local target contains relay identity"));
                }
                GatewayNativeTarget::local_engine(
                    &EndpointAddress::new(
                        EndpointScheme::Https,
                        NodeAddress::parse(&self.host).map_err(interface_error)?,
                        self.port,
                    )
                    .map_err(interface_error)?,
                    self.owner_user_id,
                    bounded_gateway_path(self.bearer_file)?,
                    bounded_gateway_path(self.ca_file)?,
                    token_count,
                )
            }
            "child_relay" => GatewayNativeTarget::child_relay(
                &self.host,
                self.port,
                self.owner_user_id,
                bounded_gateway_path(self.bearer_file)?,
                bounded_gateway_path(self.ca_file)?,
                parse_digest(
                    self.expected_server_leaf_sha256
                        .as_deref()
                        .ok_or_else(|| invalid("Gateway relay server identity is absent"))?,
                )?,
                bounded_gateway_path(
                    self.client_certificate_file
                        .ok_or_else(|| invalid("Gateway relay certificate is absent"))?,
                )?,
                bounded_gateway_path(
                    self.client_private_key_file
                        .ok_or_else(|| invalid("Gateway relay private key is absent"))?,
                )?,
                token_count,
            ),
            _ => return Err(invalid("Gateway native target kind is invalid")),
        }
        .map_err(|_| invalid("Gateway native target is invalid"))
    }
}

// Stores one complete secret-free usage record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayUsageRecord {
    request_id: String,
    key_id: String,
    received_at_unix_milliseconds: u64,
    completed_at_unix_milliseconds: u64,
    tokens: u64,
}

impl WireGatewayUsageRecord {
    // Projects one exact completed usage record.
    fn from_record(record: &GatewayUsageRecord) -> Self {
        Self {
            request_id: record.request_id().as_str().to_string(),
            key_id: record.key_id().as_str().to_string(),
            received_at_unix_milliseconds: record.received_at().value(),
            completed_at_unix_milliseconds: record.completed_at().value(),
            tokens: record.tokens(),
        }
    }

    // Reconstructs one exact completed usage record and its timestamp invariant.
    fn into_record(self) -> Result<GatewayUsageRecord, NodePrivateTransportError> {
        GatewayUsageRecord::new(
            parse_digest(&self.request_id)?,
            ApiKeyId::parse(&self.key_id).map_err(interface_error)?,
            UnixMilliseconds::new(self.received_at_unix_milliseconds),
            UnixMilliseconds::new(self.completed_at_unix_milliseconds),
            self.tokens,
        )
        .map_err(|_| invalid("Gateway usage record is invalid"))
    }
}

// Stores the exact placement and launch-plan inputs for one macOS group.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayMacOsSafetyInput {
    placement_group_id: String,
    placements: Vec<WireGatewayMacOsPlacement>,
}

impl WireGatewayMacOsSafetyInput {
    // Projects one complete bounded macOS safety input.
    fn from_input(input: &NodeGatewayMacOsSafetyInput) -> Self {
        Self {
            placement_group_id: input.placement_group_id().as_str().to_string(),
            placements: input
                .placements()
                .iter()
                .map(WireGatewayMacOsPlacement::from_placement)
                .collect(),
        }
    }

    // Reconstructs one bounded group and rechecks placement identity membership.
    fn into_input(self) -> Result<NodeGatewayMacOsSafetyInput, NodePrivateTransportError> {
        if self.placements.len() > crate::NODE_GATEWAY_MAXIMUM_MACOS_PLACEMENTS {
            return Err(invalid(
                "Gateway macOS placement collection exceeds its bound",
            ));
        }
        NodeGatewayMacOsSafetyInput::new(
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            self.placements
                .into_iter()
                .map(WireGatewayMacOsPlacement::into_placement)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| invalid("Gateway macOS safety input is invalid"))
    }
}

// Stores one complete placement and its committed launch-plan identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGatewayMacOsPlacement {
    placement_id: String,
    placement_group_id: String,
    node_id: String,
    runtime_installation_id: String,
    hardware_observation_id: String,
    hardware_boot_id: String,
    hardware_observed_at_unix_milliseconds: u64,
    task_id: String,
    address: String,
    port_base: u16,
    port_count: u16,
    device_ids: Vec<String>,
    rdma_interface: Option<String>,
    endpoint_ownership: String,
    state: String,
    active_operation_id: Option<String>,
    last_failure_code: Option<String>,
    last_failure_message: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
    launch_plan_identity: String,
}

impl WireGatewayMacOsPlacement {
    // Projects one exact placement and committed launch-plan identity.
    fn from_placement(value: &NodeGatewayMacOsPlacement) -> Self {
        let placement = value.placement();
        let assignment = placement.assignment();
        let resources = assignment.resources();
        Self {
            placement_id: placement.placement_id().as_str().to_string(),
            placement_group_id: placement.placement_group_id().as_str().to_string(),
            node_id: assignment.node_id().as_str().to_string(),
            runtime_installation_id: assignment.runtime_installation_id().as_str().to_string(),
            hardware_observation_id: assignment.hardware_observation_id().as_str().to_string(),
            hardware_boot_id: assignment.hardware_boot_id().as_str().to_string(),
            hardware_observed_at_unix_milliseconds: assignment.hardware_observed_at().value(),
            task_id: assignment.task_id().as_str().to_string(),
            address: assignment.address().as_str().to_string(),
            port_base: resources.ports().base(),
            port_count: resources.ports().count(),
            device_ids: resources
                .device_ids()
                .iter()
                .map(|value| value.as_str().to_string())
                .collect(),
            rdma_interface: resources
                .rdma_interface()
                .map(|value| value.as_str().to_string()),
            endpoint_ownership: host_endpoint_ownership_name(assignment.endpoint_ownership())
                .to_string(),
            state: host_placement_state_name(placement.state()).to_string(),
            active_operation_id: placement
                .active_operation_id()
                .map(|value| value.as_str().to_string()),
            last_failure_code: placement
                .last_failure()
                .map(|value| value.code().as_str().to_string()),
            last_failure_message: placement
                .last_failure()
                .map(|value| value.message().to_string()),
            created_at_unix_milliseconds: placement.timestamps().created_at().value(),
            updated_at_unix_milliseconds: placement.timestamps().updated_at().value(),
            launch_plan_identity: value.launch_plan_identity().as_str().to_string(),
        }
    }

    // Reconstructs one complete placement and its exact launch-plan identity.
    fn into_placement(self) -> Result<NodeGatewayMacOsPlacement, NodePrivateTransportError> {
        let failure = match (self.last_failure_code, self.last_failure_message) {
            (None, None) => None,
            (Some(code), Some(message)) => Some(
                FailureDescription::new(
                    TechnicalName::parse(&code).map_err(interface_error)?,
                    &message,
                )
                .map_err(interface_error)?,
            ),
            _ => return Err(invalid("Gateway placement failure is incomplete")),
        };
        let placement = Placement::new(
            PlacementId::parse(&self.placement_id).map_err(interface_error)?,
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            PlacementAssignment::new(
                NodeId::parse(&self.node_id).map_err(interface_error)?,
                RuntimeInstallationId::parse(&self.runtime_installation_id)
                    .map_err(interface_error)?,
                HardwareObservationId::parse(&self.hardware_observation_id)
                    .map_err(interface_error)?,
                BootId::parse(&self.hardware_boot_id).map_err(interface_error)?,
                UnixMilliseconds::new(self.hardware_observed_at_unix_milliseconds),
                TaskId::parse(&self.task_id).map_err(interface_error)?,
                NodeAddress::parse(&self.address).map_err(interface_error)?,
                PlacementResources::new(
                    PortRange::new(self.port_base, self.port_count).map_err(interface_error)?,
                    self.device_ids
                        .into_iter()
                        .map(|value| DeviceId::parse(&value).map_err(interface_error))
                        .collect::<Result<Vec<_>, _>>()?,
                    self.rdma_interface
                        .map(|value| NetworkInterfaceName::parse(&value).map_err(interface_error))
                        .transpose()?,
                )
                .map_err(interface_error)?,
                host_endpoint_ownership(&self.endpoint_ownership)?,
            ),
            host_placement_state(&self.state)?,
            self.active_operation_id
                .map(|value| OperationId::parse(&value).map_err(interface_error))
                .transpose()?,
            failure,
            EntityTimestamps::new(
                UnixMilliseconds::new(self.created_at_unix_milliseconds),
                UnixMilliseconds::new(self.updated_at_unix_milliseconds),
            )
            .map_err(interface_error)?,
        )
        .map_err(interface_error)?;
        Ok(NodeGatewayMacOsPlacement::new(
            placement,
            parse_digest(&self.launch_plan_identity)?,
        ))
    }
}

// Stores one exact operation and idempotency identity for a model lifecycle request.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelCommandIdentity {
    operation_id: String,
    idempotency_key: String,
}

impl WireModelCommandIdentity {
    // Projects one validated command identity into its stable private fields.
    fn from_identity(identity: &NodeModelCommandIdentity) -> Self {
        Self {
            operation_id: identity.operation_id().as_str().to_string(),
            idempotency_key: identity.idempotency_key().as_str().to_string(),
        }
    }

    // Reconstructs one typed command identity after validating both bounded values.
    fn into_identity(self) -> Result<NodeModelCommandIdentity, NodePrivateTransportError> {
        Ok(NodeModelCommandIdentity::new(
            OperationId::parse(&self.operation_id).map_err(interface_error)?,
            TechnicalName::parse(&self.idempotency_key).map_err(interface_error)?,
        ))
    }
}

// Stores one independent target-specific placement-group plan.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelInstallGroup {
    node_ids: Vec<String>,
    explicit_candidate_id: Option<String>,
}

impl WireModelInstallGroup {
    // Projects one typed group without introducing runtime topology semantics.
    fn from_group(group: &NodeModelInstallGroup) -> Self {
        Self {
            node_ids: group
                .node_ids()
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
            explicit_candidate_id: group
                .explicit_candidate_id()
                .map(|candidate_id| candidate_id.as_str().to_string()),
        }
    }

    // Reconstructs one bounded unique authenticated-node group.
    fn into_group(self) -> Result<NodeModelInstallGroup, NodePrivateTransportError> {
        NodeModelInstallGroup::new(
            self.node_ids
                .into_iter()
                .map(|node_id| NodeId::parse(&node_id).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.explicit_candidate_id
                .map(|candidate_id| {
                    RuntimeCandidateId::parse(&candidate_id).map_err(interface_error)
                })
                .transpose()?,
        )
        .map_err(model_value_error)
    }
}

// Stores one complete normalized model installation request.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelInstallRequest {
    identity: WireModelCommandIdentity,
    service_id: String,
    logical_model: String,
    groups: Vec<WireModelInstallGroup>,
}

impl WireModelInstallRequest {
    // Projects one exact typed installation plan into its closed private fields.
    fn from_request(request: &NodeModelInstallRequest) -> Self {
        Self {
            identity: WireModelCommandIdentity::from_identity(request.identity()),
            service_id: request.service_id().as_str().to_string(),
            logical_model: request.logical_model().as_str().to_string(),
            groups: request
                .groups()
                .iter()
                .map(WireModelInstallGroup::from_group)
                .collect(),
        }
    }

    // Reconstructs one complete request only through the coordinator contract constructor.
    fn into_request(self) -> Result<NodeModelInstallRequest, NodePrivateTransportError> {
        NodeModelInstallRequest::new(
            self.identity.into_identity()?,
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            self.groups
                .into_iter()
                .map(WireModelInstallGroup::into_group)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(model_value_error)
    }
}

// Stores one secret-free command intent in exact CLI registry terms.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCommandAuditIntent {
    action: String,
    target: Option<WireCommandAuditTarget>,
    policy: String,
    mutation: String,
    local_role: String,
}

impl WireCommandAuditIntent {
    // Projects one validated command intent without command arguments.
    fn from_intent(intent: &NodeCommandAuditIntent) -> Self {
        Self {
            action: intent.action().as_str().to_string(),
            target: intent.target().map(WireCommandAuditTarget::from_target),
            policy: intent.policy().as_str().to_string(),
            mutation: intent.mutation().as_str().to_string(),
            local_role: node_role_name(intent.local_role()).to_string(),
        }
    }

    // Reconstructs one closed command intent from exact stable names.
    fn into_intent(self) -> Result<NodeCommandAuditIntent, NodePrivateTransportError> {
        let intent = NodeCommandAuditIntent::new(
            TechnicalName::parse(&self.action).map_err(interface_error)?,
            command_audit_policy(&self.policy)?,
            command_audit_mutation(&self.mutation)?,
            node_role(&self.local_role)?,
        );
        match self.target {
            Some(target) => Ok(intent.with_target(target.into_target()?)),
            None => Ok(intent),
        }
    }
}

// Stores one closed target class and validated non-secret identifier.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCommandAuditTarget {
    kind: String,
    identifier: String,
}

impl WireCommandAuditTarget {
    // Projects one validated target into its independently mutable wire fields.
    fn from_target(target: &NodeCommandAuditTarget) -> Self {
        Self {
            kind: target.kind().as_str().to_string(),
            identifier: target.identifier().to_string(),
        }
    }

    // Reconstructs one closed target while rejecting unknown classes and unsafe identifiers.
    fn into_target(self) -> Result<NodeCommandAuditTarget, NodePrivateTransportError> {
        NodeCommandAuditTarget::new(command_audit_target_kind(&self.kind)?, &self.identifier)
            .map_err(command_audit_value_error)
    }
}

// Stores one terminal outcome and stable failure code without error messages or arguments.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCommandAuditResult {
    action: String,
    outcome: String,
    failure_code: Option<String>,
}

impl WireCommandAuditResult {
    // Projects one normalized terminal result into the private wire shape.
    fn from_result(result: &NodeCommandAuditResult) -> Self {
        Self {
            action: result.action().as_str().to_string(),
            outcome: result.outcome().as_str().to_string(),
            failure_code: result.failure_code().map(str::to_string),
        }
    }

    // Reconstructs one terminal result while preserving only a canonical failure code.
    fn into_result(self) -> Result<NodeCommandAuditResult, NodePrivateTransportError> {
        let result = NodeCommandAuditResult::new(
            TechnicalName::parse(&self.action).map_err(interface_error)?,
            command_audit_outcome(&self.outcome)?,
            self.failure_code.as_deref(),
        )
        .map_err(command_audit_value_error)?;
        if result.failure_code() != self.failure_code.as_deref() {
            return Err(invalid("command audit failure code is invalid"));
        }
        Ok(result)
    }
}

// Stores one complete durable API-key policy without plaintext credential material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireApiKeyPolicy {
    selected_models: Option<Vec<String>>,
    expires_at_unix_milliseconds: Option<u64>,
    requests_per_minute: Option<u32>,
    tokens_per_minute: Option<u64>,
    concurrency: Option<u32>,
    context_tokens: Option<u64>,
    tenant: Option<String>,
    application: Option<String>,
}

impl WireApiKeyPolicy {
    // Projects one complete policy into its closed JSON fields.
    fn from_policy(policy: &ApiKeyPolicy) -> Self {
        let limits = policy.limits();
        Self {
            selected_models: policy.model_scope().selected_models().map(|models| {
                models
                    .iter()
                    .map(|model| model.as_str().to_string())
                    .collect()
            }),
            expires_at_unix_milliseconds: policy.expires_at().map(UnixMilliseconds::value),
            requests_per_minute: limits.requests_per_minute().map(NonZeroU32::get),
            tokens_per_minute: limits.tokens_per_minute().map(NonZeroU64::get),
            concurrency: limits.concurrency().map(NonZeroU32::get),
            context_tokens: limits.context_tokens().map(NonZeroU64::get),
            tenant: policy.tenant().map(|value| value.as_str().to_string()),
            application: policy.application().map(|value| value.as_str().to_string()),
        }
    }

    // Reconstructs one validated complete policy from exact JSON values.
    fn into_policy(self) -> Result<ApiKeyPolicy, NodePrivateTransportError> {
        let model_scope = match self.selected_models {
            None => ApiKeyModelScope::all(),
            Some(models) => ApiKeyModelScope::selected(parse_models(models)?)
                .map_err(authentication_value_error)?,
        };
        Ok(ApiKeyPolicy::new(
            model_scope,
            self.expires_at_unix_milliseconds.map(UnixMilliseconds::new),
            ApiKeyLimits::new(
                positive_u32(self.requests_per_minute)?,
                positive_u64(self.tokens_per_minute)?,
                positive_u32(self.concurrency)?,
                positive_u64(self.context_tokens)?,
            ),
            self.tenant
                .map(|value| TechnicalName::parse(&value).map_err(interface_error))
                .transpose()?,
            self.application
                .map(|value| TechnicalName::parse(&value).map_err(interface_error))
                .transpose()?,
        ))
    }
}

// Stores only explicitly supplied policy-update fields.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireApiKeyPolicyUpdate {
    selected_models: Option<Vec<String>>,
    expires_at_unix_milliseconds: Option<u64>,
    requests_per_minute: Option<u32>,
    tokens_per_minute: Option<u64>,
    concurrency: Option<u32>,
    context_tokens: Option<u64>,
    tenant: Option<String>,
    application: Option<String>,
}

impl WireApiKeyPolicyUpdate {
    // Projects one partial update without filling absent values from local state.
    fn from_update(update: &NodeApiKeyPolicyUpdate) -> Self {
        Self {
            selected_models: update.selected_models().map(|models| {
                models
                    .iter()
                    .map(|model| model.as_str().to_string())
                    .collect()
            }),
            expires_at_unix_milliseconds: update.expires_at().map(UnixMilliseconds::value),
            requests_per_minute: update.requests_per_minute().map(NonZeroU32::get),
            tokens_per_minute: update.tokens_per_minute().map(NonZeroU64::get),
            concurrency: update.concurrency().map(NonZeroU32::get),
            context_tokens: update.context_tokens().map(NonZeroU64::get),
            tenant: update.tenant().map(|value| value.as_str().to_string()),
            application: update.application().map(|value| value.as_str().to_string()),
        }
    }

    // Reconstructs one validated partial update without inventing defaults.
    fn into_update(self) -> Result<NodeApiKeyPolicyUpdate, NodePrivateTransportError> {
        Ok(NodeApiKeyPolicyUpdate::new(
            self.selected_models.map(parse_models).transpose()?,
            self.expires_at_unix_milliseconds.map(UnixMilliseconds::new),
            positive_u32(self.requests_per_minute)?,
            positive_u64(self.tokens_per_minute)?,
            positive_u32(self.concurrency)?,
            positive_u64(self.context_tokens)?,
            self.tenant
                .map(|value| TechnicalName::parse(&value).map_err(interface_error))
                .transpose()?,
            self.application
                .map(|value| TechnicalName::parse(&value).map_err(interface_error))
                .transpose()?,
        ))
    }
}

// Stores public model and workload axes before exact benchmark resolution.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkSelection {
    logical_model: String,
    concurrencies: Vec<u16>,
    contexts: Vec<String>,
}

impl WireBenchmarkSelection {
    // Projects public workload axes without serializing resolved runtime identities.
    fn from_selection(selection: &NodeBenchmarkSelection) -> Self {
        Self {
            logical_model: selection.logical_model().as_str().to_string(),
            concurrencies: selection.concurrencies().to_vec(),
            contexts: selection
                .contexts()
                .iter()
                .map(|context| context.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one canonical selection and rejects unknown or reordered axes.
    fn into_selection(self) -> Result<NodeBenchmarkSelection, NodePrivateTransportError> {
        NodeBenchmarkSelection::new(
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            self.concurrencies,
            self.contexts
                .into_iter()
                .map(|context| match context.as_str() {
                    "32k" => Ok(NodeBenchmarkContext::Context32k),
                    "64k" => Ok(NodeBenchmarkContext::Context64k),
                    "128k" => Ok(NodeBenchmarkContext::Context128k),
                    "256k" => Ok(NodeBenchmarkContext::Context256k),
                    _ => Err(benchmark_value_error(BenchmarkError::InvalidContract {
                        reason: "benchmark context axis is unsupported",
                    })),
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(benchmark_value_error)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkPlan {
    request: WireBenchmarkRequest,
    declared_cells: Vec<String>,
    selected_cells: Vec<String>,
}

impl WireBenchmarkPlan {
    // Projects one exact resolved plan without execution or provider state.
    fn from_plan(plan: &NodeBenchmarkPlan) -> Self {
        Self {
            request: WireBenchmarkRequest::from_request(plan.request()),
            declared_cells: plan
                .declared_cells()
                .iter()
                .map(|cell| cell.as_str().to_string())
                .collect(),
            selected_cells: plan
                .selected_cells()
                .iter()
                .map(|cell| cell.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs and revalidates every exact request and cell-plan invariant.
    fn into_plan(self) -> Result<NodeBenchmarkPlan, NodePrivateTransportError> {
        let request = self.request.into_request()?;
        let selection =
            NodeBenchmarkSelection::new(request.subject().model().clone(), Vec::new(), Vec::new())
                .map_err(benchmark_value_error)?;
        NodeBenchmarkPlan::new(
            &selection,
            request,
            self.declared_cells
                .into_iter()
                .map(|cell| TechnicalName::parse(&cell).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.selected_cells
                .into_iter()
                .map(|cell| TechnicalName::parse(&cell).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(benchmark_value_error)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireBenchmarkKind {
    Local,
    Verification {
        pull_request: u64,
        proposal_head: String,
        candidate_id: String,
        transaction_id: String,
        verifier_bundle_sha256: String,
        candidate_subject_sha256: String,
        verifier_numeric_id: u64,
        device_id: String,
        baseline_execution_sha256: Option<String>,
    },
}

impl WireBenchmarkKind {
    // Projects one typed benchmark authority without repository credentials.
    fn from_kind(kind: &BenchmarkKind) -> Self {
        match kind {
            BenchmarkKind::Local => Self::Local,
            BenchmarkKind::Verification {
                pull_request,
                proposal_head,
                candidate,
                transaction_id,
                verifier_bundle_sha256,
                candidate_subject_sha256,
                verifier_numeric_id,
                device_id,
                baseline_execution_sha256,
            } => Self::Verification {
                pull_request: *pull_request,
                proposal_head: proposal_head.as_str().to_string(),
                candidate_id: candidate.as_str().to_string(),
                transaction_id: transaction_id.as_str().to_string(),
                verifier_bundle_sha256: verifier_bundle_sha256.as_str().to_string(),
                candidate_subject_sha256: candidate_subject_sha256.as_str().to_string(),
                verifier_numeric_id: *verifier_numeric_id,
                device_id: device_id.as_str().to_string(),
                baseline_execution_sha256: baseline_execution_sha256
                    .as_ref()
                    .map(|value| value.as_str().to_string()),
            },
        }
    }

    // Reconstructs one validated benchmark authority from exact public identities.
    fn into_kind(self) -> Result<BenchmarkKind, NodePrivateTransportError> {
        match self {
            Self::Local => Ok(BenchmarkKind::Local),
            Self::Verification {
                pull_request,
                proposal_head,
                candidate_id,
                transaction_id,
                verifier_bundle_sha256,
                candidate_subject_sha256,
                verifier_numeric_id,
                device_id,
                baseline_execution_sha256,
            } => BenchmarkKind::verification(
                pull_request,
                BenchmarkGitRevision::parse(&proposal_head).map_err(benchmark_value_error)?,
                RuntimeCandidateId::parse(&candidate_id).map_err(interface_error)?,
                OperationId::parse(&transaction_id).map_err(interface_error)?,
                parse_digest(&verifier_bundle_sha256)?,
                parse_digest(&candidate_subject_sha256)?,
                verifier_numeric_id,
                parse_digest(&device_id)?,
                baseline_execution_sha256
                    .map(|value| parse_digest(&value))
                    .transpose()?,
            )
            .map_err(benchmark_value_error),
        }
    }
}

// Stores the complete contract or one exact bounded diagnostic cell set.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "cells",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireBenchmarkScope {
    Complete,
    Selected(Vec<String>),
}

impl WireBenchmarkScope {
    // Projects one typed workload scope without runtime-specific execution semantics.
    fn from_scope(scope: &BenchmarkScope) -> Self {
        match scope {
            BenchmarkScope::Complete => Self::Complete,
            BenchmarkScope::Selected(cells) => {
                Self::Selected(cells.iter().map(|cell| cell.as_str().to_string()).collect())
            }
        }
    }

    // Reconstructs one validated complete or selected workload scope.
    fn into_scope(self) -> Result<BenchmarkScope, NodePrivateTransportError> {
        match self {
            Self::Complete => Ok(BenchmarkScope::Complete),
            Self::Selected(cells) => BenchmarkScope::selected(
                cells
                    .into_iter()
                    .map(|cell| TechnicalName::parse(&cell).map_err(interface_error))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(benchmark_value_error),
        }
    }
}

// Stores one exact model-neutral benchmark subject.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkSubject {
    core_installation_id: String,
    runtime_installation_id: String,
    logical_model: String,
    placement_group_id: String,
    execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
}

impl WireBenchmarkSubject {
    // Projects one exact subject without Engine options, ranks, or credentials.
    fn from_subject(subject: &BenchmarkSubject) -> Self {
        Self {
            core_installation_id: subject.installation_id().as_str().to_string(),
            runtime_installation_id: subject.runtime_installation_id().as_str().to_string(),
            logical_model: subject.model().as_str().to_string(),
            placement_group_id: subject.placement_group_id().as_str().to_string(),
            execution_sha256: subject.execution_sha256().as_str().to_string(),
            benchmark_contract_sha256: subject.benchmark_contract_sha256().as_str().to_string(),
            target_contract_sha256: subject.target_contract_sha256().as_str().to_string(),
        }
    }

    // Reconstructs one exact typed benchmark subject.
    fn into_subject(self) -> Result<BenchmarkSubject, NodePrivateTransportError> {
        Ok(BenchmarkSubject::new(
            InstallationId::parse(&self.core_installation_id).map_err(interface_error)?,
            RuntimeInstallationId::parse(&self.runtime_installation_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            parse_digest(&self.execution_sha256)?,
            parse_digest(&self.benchmark_contract_sha256)?,
            parse_digest(&self.target_contract_sha256)?,
        ))
    }
}

// Stores one complete private benchmark request without repository credentials.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkRequest {
    kind: WireBenchmarkKind,
    scope: WireBenchmarkScope,
    subject: WireBenchmarkSubject,
}

impl WireBenchmarkRequest {
    // Projects one exact typed benchmark request.
    fn from_request(request: &BenchmarkRequest) -> Self {
        Self {
            kind: WireBenchmarkKind::from_kind(request.kind()),
            scope: WireBenchmarkScope::from_scope(request.scope()),
            subject: WireBenchmarkSubject::from_subject(request.subject()),
        }
    }

    // Reconstructs one validated request and its verification-scope invariant.
    fn into_request(self) -> Result<BenchmarkRequest, NodePrivateTransportError> {
        BenchmarkRequest::new(
            self.kind.into_kind()?,
            self.scope.into_scope()?,
            self.subject.into_subject()?,
        )
        .map_err(benchmark_value_error)
    }
}

// Stores one reviewed cleanup request without accepting filesystem roots.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStorageCleanRequest {
    operation_id: String,
    plan_sha256: String,
    categories: Vec<String>,
}

impl WireStorageCleanRequest {
    // Projects one content-bound cleanup request into stable wire names.
    fn from_request(request: &NodeStorageCleanRequest) -> Self {
        Self {
            operation_id: request.operation_id().as_str().to_string(),
            plan_sha256: request.plan_digest().as_str().to_string(),
            categories: request
                .categories()
                .iter()
                .map(|category| category.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one cleanup request through the typed storage invariants.
    fn into_request(self) -> Result<NodeStorageCleanRequest, NodePrivateTransportError> {
        if !unique_strings(&self.categories) {
            return Err(invalid("storage categories are not unique"));
        }
        NodeStorageCleanRequest::new(
            OperationId::parse(&self.operation_id).map_err(interface_error)?,
            parse_digest(&self.plan_sha256)?,
            self.categories
                .into_iter()
                .map(|category| NodeStorageCategory::parse(&category).map_err(storage_value_error))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(storage_value_error)
    }
}

// Stores one measured category total without exposing its source path.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStorageUsage {
    category: String,
    allocated_bytes: u64,
    logical_bytes: u64,
    files: u64,
    reclaimable_bytes: u64,
}

impl WireStorageUsage {
    // Projects one validated category total into its closed wire shape.
    fn from_usage(usage: &NodeStorageUsage) -> Self {
        Self {
            category: usage.category().as_str().to_string(),
            allocated_bytes: usage.allocated_bytes(),
            logical_bytes: usage.logical_bytes(),
            files: usage.files(),
            reclaimable_bytes: usage.reclaimable_bytes(),
        }
    }

    // Reconstructs one category total through reclaimability invariants.
    fn into_usage(self) -> Result<NodeStorageUsage, NodePrivateTransportError> {
        NodeStorageUsage::new(
            NodeStorageCategory::parse(&self.category).map_err(storage_value_error)?,
            self.allocated_bytes,
            self.logical_bytes,
            self.files,
            self.reclaimable_bytes,
        )
        .map_err(storage_value_error)
    }
}

// Stores one exact reviewed cleanup target relative to the private home.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStorageCandidate {
    category: String,
    relative_path: String,
    allocated_bytes: u64,
    reason: String,
    models: Vec<String>,
}

impl WireStorageCandidate {
    // Projects one validated relative cleanup target without publishing its absolute root.
    fn from_candidate(candidate: &NodeStorageCandidate) -> Self {
        Self {
            category: candidate.category().as_str().to_string(),
            relative_path: candidate.relative_path().to_string(),
            allocated_bytes: candidate.allocated_bytes(),
            reason: candidate.reason().to_string(),
            models: candidate
                .models()
                .iter()
                .map(|model| model.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one target through relative-path and reclaimability invariants.
    fn into_candidate(self) -> Result<NodeStorageCandidate, NodePrivateTransportError> {
        if !unique_strings(&self.models) {
            return Err(invalid("storage candidate models are not unique"));
        }
        NodeStorageCandidate::new(
            NodeStorageCategory::parse(&self.category).map_err(storage_value_error)?,
            self.relative_path,
            self.allocated_bytes,
            self.reason,
            parse_models(self.models)?,
        )
        .map_err(storage_value_error)
    }
}

// Stores one complete reviewed storage projection and immutable plan identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStorageSnapshot {
    capacity_bytes: u64,
    available_bytes: u64,
    usage: Vec<WireStorageUsage>,
    candidates: Vec<WireStorageCandidate>,
    plan_sha256: String,
}

impl WireStorageSnapshot {
    // Projects one validated storage snapshot into stable ordered wire values.
    fn from_snapshot(snapshot: &NodeStorageSnapshot) -> Self {
        Self {
            capacity_bytes: snapshot.capacity_bytes(),
            available_bytes: snapshot.available_bytes(),
            usage: snapshot
                .usage()
                .iter()
                .map(WireStorageUsage::from_usage)
                .collect(),
            candidates: snapshot
                .candidates()
                .iter()
                .map(WireStorageCandidate::from_candidate)
                .collect(),
            plan_sha256: snapshot.plan_digest().as_str().to_string(),
        }
    }

    // Reconstructs one complete snapshot through ordering and sum invariants.
    fn into_snapshot(self) -> Result<NodeStorageSnapshot, NodePrivateTransportError> {
        NodeStorageSnapshot::new(
            self.capacity_bytes,
            self.available_bytes,
            self.usage
                .into_iter()
                .map(WireStorageUsage::into_usage)
                .collect::<Result<Vec<_>, _>>()?,
            self.candidates
                .into_iter()
                .map(WireStorageCandidate::into_candidate)
                .collect::<Result<Vec<_>, _>>()?,
            parse_digest(&self.plan_sha256)?,
        )
        .map_err(storage_value_error)
    }
}

// Stores one durable cleanup result without removed absolute paths.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStorageCleanReceipt {
    operation_id: String,
    plan_sha256: String,
    removed_targets: u64,
    reclaimed_bytes: u64,
    models_to_download: Vec<String>,
    replayed: bool,
}

impl WireStorageCleanReceipt {
    // Projects one exact cleanup receipt into its closed wire shape.
    fn from_receipt(receipt: &NodeStorageCleanReceipt) -> Self {
        Self {
            operation_id: receipt.operation_id().as_str().to_string(),
            plan_sha256: receipt.plan_digest().as_str().to_string(),
            removed_targets: receipt.removed_targets(),
            reclaimed_bytes: receipt.reclaimed_bytes(),
            models_to_download: receipt
                .models_to_download()
                .iter()
                .map(|model| model.as_str().to_string())
                .collect(),
            replayed: receipt.replayed(),
        }
    }

    // Reconstructs one receipt through exact projection invariants.
    fn into_receipt(self) -> Result<NodeStorageCleanReceipt, NodePrivateTransportError> {
        if !unique_strings(&self.models_to_download) {
            return Err(invalid("storage receipt models are not unique"));
        }
        NodeStorageCleanReceipt::new(
            OperationId::parse(&self.operation_id).map_err(interface_error)?,
            parse_digest(&self.plan_sha256)?,
            self.removed_targets,
            self.reclaimed_bytes,
            parse_models(self.models_to_download)?,
            self.replayed,
        )
        .map_err(storage_value_error)
    }
}

// Stores one closed response envelope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    schema: WireSchema,
    request_id: String,
    response: WireResponseBody,
}

impl WireResponse {
    // Projects one typed response into its closed wire shape.
    fn from_response(
        response: &NodePrivateTransportResponse,
    ) -> Result<Self, NodePrivateTransportError> {
        Ok(Self {
            schema: WireSchema::current(),
            request_id: response.request_id().as_str().to_string(),
            response: WireResponseBody::from_outcome(response.outcome())?,
        })
    }

    // Reconstructs one typed response after validating schema and correlation identity.
    fn into_response(self) -> Result<NodePrivateTransportResponse, NodePrivateTransportError> {
        self.schema.validate()?;
        Ok(NodePrivateTransportResponse::new(
            parse_digest(&self.request_id)?,
            self.response.into_outcome()?,
        ))
    }
}

// Stores one closed response value or stable remote failure.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireResponseBody {
    LocalNode(WireNode),
    Nodes(Vec<WireNode>),
    NodeChanged(WireNodeChange),
    HardwareObservation(Option<Value>),
    HostProjection(WireHostSnapshot),
    HostInventory(WireHostInventory),
    StorageSnapshot(WireStorageSnapshot),
    StorageCleaned(WireStorageCleanReceipt),
    Catalog(WireCatalogListing),
    CompatibleTargets(Vec<WireCatalogTarget>),
    PendingOutbox(Vec<WireVersionedOutboxEvent>),
    OutboxAcknowledged(WireVersionedOutboxEvent),
    PairingInvitation(WirePairingInvitation),
    PairingEnrollment(WirePairingEnrollment),
    PairingStatus(WirePairingStatus),
    BenchmarkPlan(WireBenchmarkPlan),
    BenchmarkChanged(WireBenchmarkSnapshot),
    BenchmarkRecord(Option<WireBenchmarkSnapshot>),
    ControllerEnrollment(WireControllerEnrollmentReceipt),
    Controller(WireControllerSummary),
    Controllers(Vec<WireControllerSummary>),
    ApiKeyIssued(WireIssuedApiKey),
    ApiKeys(Vec<WireApiKey>),
    ApiKey(WireApiKey),
    CommandAuditOpened(WireCommandAuditOpenReceipt),
    CommandAuditCompleted(WireCommandAuditCompletionReceipt),
    AuditEvents(Vec<WireAuditEvent>),
    AuditEvent(WireAuditEvent),
    AuditVerification(WireAuditVerification),
    AuditExport(WireAuditExport),
    ModelServices(Vec<WireModelServiceSummary>),
    ModelChanged(WireModelCommandSummary),
    ModelRollbackPreview(WireModelRollbackPreview),
    ModelLogs(WireModelLogSummary),
    ModelRuntimeLogs(WireModelRuntimeLogBatch),
    CoreUpdateCheck(WireCoreUpdateCheck),
    CoreUpdated(WireCoreUpdateSummary),
    ModelUpdated(WireModelUpdateSummary),
    Exposure(WireExposureStatus),
    RuntimeInstallationIds(Vec<String>),
    RuntimeInstallationRemoved(String),
    RuntimeArtifactsFinalized(String),
    UninstallBegan(WireUninstallBeginReceipt),
    UninstallCanceled(WireUninstallCancelReceipt),
    PairingAuthorityChanged(WirePairingAuthorityReceipt),
    Gateway(WireGatewayResponse),
    Error(WireRemoteError),
}

impl WireResponseBody {
    // Projects one typed response outcome into its exact closed variant.
    fn from_outcome(
        outcome: &NodePrivateTransportOutcome,
    ) -> Result<Self, NodePrivateTransportError> {
        Ok(match outcome {
            NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(node)) => {
                Self::LocalNode(WireNode::from_node(node))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Nodes(nodes)) => {
                Self::Nodes(nodes.iter().map(WireNode::from_node).collect())
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::NodeChanged(change)) => {
                Self::NodeChanged(WireNodeChange::from_change(change))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::HardwareObservation(
                observation,
            )) => Self::HardwareObservation(
                observation
                    .as_ref()
                    .map(wire_hardware_observation)
                    .transpose()?,
            ),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::HostProjection(snapshot)) => {
                Self::HostProjection(WireHostSnapshot::from_snapshot(snapshot)?)
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::HostInventory(inventory)) => {
                Self::HostInventory(WireHostInventory::from_inventory(inventory)?)
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::StorageSnapshot(
                snapshot,
            )) => Self::StorageSnapshot(WireStorageSnapshot::from_snapshot(snapshot)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::StorageCleaned(receipt)) => {
                Self::StorageCleaned(WireStorageCleanReceipt::from_receipt(receipt))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Catalog(listing)) => {
                Self::Catalog(WireCatalogListing::from_listing(listing))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::CompatibleTargets(
                targets,
            )) => Self::CompatibleTargets(
                targets.iter().map(WireCatalogTarget::from_target).collect(),
            ),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::PendingOutbox(events)) => {
                Self::PendingOutbox(
                    events
                        .iter()
                        .map(WireVersionedOutboxEvent::from_event)
                        .collect(),
                )
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::OutboxAcknowledged(
                event,
            )) => Self::OutboxAcknowledged(WireVersionedOutboxEvent::from_event(event)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::PairingInvitation(
                invitation,
            )) => Self::PairingInvitation(WirePairingInvitation::from_invitation(invitation)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::PairingEnrollment(
                enrollment,
            )) => Self::PairingEnrollment(WirePairingEnrollment::from_enrollment(enrollment)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::PairingStatus(status)) => {
                Self::PairingStatus(WirePairingStatus::from_status(status))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkPlan(plan)) => {
                Self::BenchmarkPlan(WireBenchmarkPlan::from_plan(plan))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkChanged(
                snapshot,
            )) => Self::BenchmarkChanged(WireBenchmarkSnapshot::from_snapshot(snapshot)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkRecord(
                snapshot,
            )) => {
                Self::BenchmarkRecord(snapshot.as_ref().map(WireBenchmarkSnapshot::from_snapshot))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ControllerEnrollment(
                receipt,
            )) => {
                Self::ControllerEnrollment(WireControllerEnrollmentReceipt::from_receipt(receipt))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Controller(controller)) => {
                Self::Controller(WireControllerSummary::from_summary(controller))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Controllers(controllers)) => {
                Self::Controllers(
                    controllers
                        .iter()
                        .map(WireControllerSummary::from_summary)
                        .collect(),
                )
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ApiKeyIssued(issued)) => {
                Self::ApiKeyIssued(WireIssuedApiKey::from_issued(issued)?)
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ApiKeys(keys)) => {
                Self::ApiKeys(keys.iter().map(WireApiKey::from_api_key).collect())
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ApiKey(key)) => {
                Self::ApiKey(WireApiKey::from_api_key(key))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::CommandAuditOpened(
                receipt,
            )) => Self::CommandAuditOpened(WireCommandAuditOpenReceipt::from_receipt(receipt)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::CommandAuditCompleted(
                receipt,
            )) => Self::CommandAuditCompleted(WireCommandAuditCompletionReceipt::from_receipt(
                receipt,
            )),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::AuditEvents(events)) => {
                Self::AuditEvents(events.iter().map(WireAuditEvent::from_event).collect())
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::AuditEvent(event)) => {
                Self::AuditEvent(WireAuditEvent::from_event(event))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::AuditVerification(
                verification,
            )) => Self::AuditVerification(WireAuditVerification::from_verification(verification)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::AuditExport(export)) => {
                Self::AuditExport(WireAuditExport::from_export(export))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelServices(services)) => {
                Self::ModelServices(
                    services
                        .iter()
                        .map(WireModelServiceSummary::from_summary)
                        .collect(),
                )
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelChanged(summary)) => {
                Self::ModelChanged(WireModelCommandSummary::from_summary(summary))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelRollbackPreview(
                preview,
            )) => Self::ModelRollbackPreview(WireModelRollbackPreview::from_preview(preview)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelLogs(summary)) => {
                Self::ModelLogs(WireModelLogSummary::from_summary(summary))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelRuntimeLogs(batch)) => {
                Self::ModelRuntimeLogs(WireModelRuntimeLogBatch::from_batch(batch))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::CoreUpdateCheck(check)) => {
                Self::CoreUpdateCheck(WireCoreUpdateCheck::from_check(check))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::CoreUpdated(summary)) => {
                Self::CoreUpdated(WireCoreUpdateSummary::from_summary(summary))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelUpdated(summary)) => {
                Self::ModelUpdated(WireModelUpdateSummary::from_summary(summary))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Exposure(status)) => {
                Self::Exposure(WireExposureStatus::from_status(status))
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::RuntimeInstallationIds(
                installation_ids,
            )) => Self::RuntimeInstallationIds(wire_runtime_installation_ids(installation_ids)?),
            NodePrivateTransportOutcome::Success(
                NodePrivateResponse::RuntimeInstallationRemoved(disposition),
            ) => Self::RuntimeInstallationRemoved(
                runtime_removal_disposition_name(*disposition).to_string(),
            ),
            NodePrivateTransportOutcome::Success(
                NodePrivateResponse::RuntimeArtifactsFinalized(receipt),
            ) => Self::RuntimeArtifactsFinalized(
                runtime_model_retention_name(receipt.model_retention()).to_string(),
            ),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::UninstallBegan(receipt)) => {
                Self::UninstallBegan(WireUninstallBeginReceipt::from_receipt(receipt)?)
            }
            NodePrivateTransportOutcome::Success(NodePrivateResponse::UninstallCanceled(
                receipt,
            )) => Self::UninstallCanceled(WireUninstallCancelReceipt::from_receipt(receipt)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::PairingAuthorityChanged(
                receipt,
            )) => Self::PairingAuthorityChanged(WirePairingAuthorityReceipt::from_receipt(receipt)),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Gateway(response)) => {
                Self::Gateway(WireGatewayResponse::from_response(response)?)
            }
            NodePrivateTransportOutcome::Failure(error) => {
                Self::Error(WireRemoteError::from_error(error))
            }
        })
    }

    // Reconstructs one typed response outcome from its closed wire variant.
    fn into_outcome(self) -> Result<NodePrivateTransportOutcome, NodePrivateTransportError> {
        let response = match self {
            Self::LocalNode(node) => NodePrivateResponse::LocalNode(node.into_node()?),
            Self::Nodes(nodes) => NodePrivateResponse::Nodes(
                nodes
                    .into_iter()
                    .map(WireNode::into_node)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::NodeChanged(change) => NodePrivateResponse::NodeChanged(change.into_change()?),
            Self::HardwareObservation(observation) => NodePrivateResponse::HardwareObservation(
                observation.map(hardware_observation).transpose()?,
            ),
            Self::HostProjection(snapshot) => {
                NodePrivateResponse::HostProjection(snapshot.into_snapshot()?)
            }
            Self::HostInventory(inventory) => {
                NodePrivateResponse::HostInventory(inventory.into_inventory()?)
            }
            Self::StorageSnapshot(snapshot) => {
                NodePrivateResponse::StorageSnapshot(snapshot.into_snapshot()?)
            }
            Self::StorageCleaned(receipt) => {
                NodePrivateResponse::StorageCleaned(receipt.into_receipt()?)
            }
            Self::Catalog(listing) => NodePrivateResponse::Catalog(listing.into_listing()?),
            Self::CompatibleTargets(targets) => NodePrivateResponse::CompatibleTargets(
                bounded_catalog_targets(
                    targets
                        .into_iter()
                        .map(WireCatalogTarget::into_target)
                        .collect::<Result<Vec<_>, _>>()?,
                )
                .map_err(|_| invalid("compatible target collection is invalid"))?,
            ),
            Self::PendingOutbox(events) => NodePrivateResponse::PendingOutbox(
                events
                    .into_iter()
                    .map(WireVersionedOutboxEvent::into_event)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::OutboxAcknowledged(event) => {
                NodePrivateResponse::OutboxAcknowledged(event.into_event()?)
            }
            Self::PairingInvitation(invitation) => {
                NodePrivateResponse::PairingInvitation(invitation.into_invitation()?)
            }
            Self::PairingEnrollment(enrollment) => {
                NodePrivateResponse::PairingEnrollment(enrollment.into_enrollment()?)
            }
            Self::PairingStatus(status) => {
                NodePrivateResponse::PairingStatus(status.into_status()?)
            }
            Self::BenchmarkPlan(plan) => NodePrivateResponse::BenchmarkPlan(plan.into_plan()?),
            Self::BenchmarkChanged(snapshot) => {
                NodePrivateResponse::BenchmarkChanged(snapshot.into_snapshot()?)
            }
            Self::BenchmarkRecord(snapshot) => NodePrivateResponse::BenchmarkRecord(
                snapshot
                    .map(WireBenchmarkSnapshot::into_snapshot)
                    .transpose()?,
            ),
            Self::ControllerEnrollment(receipt) => {
                NodePrivateResponse::ControllerEnrollment(receipt.into_receipt()?)
            }
            Self::Controller(controller) => {
                NodePrivateResponse::Controller(controller.into_summary()?)
            }
            Self::Controllers(controllers) => NodePrivateResponse::Controllers(
                controllers
                    .into_iter()
                    .map(WireControllerSummary::into_summary)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::ApiKeyIssued(issued) => NodePrivateResponse::ApiKeyIssued(issued.into_issued()?),
            Self::ApiKeys(keys) => NodePrivateResponse::ApiKeys(
                keys.into_iter()
                    .map(WireApiKey::into_api_key)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::ApiKey(key) => NodePrivateResponse::ApiKey(key.into_api_key()?),
            Self::CommandAuditOpened(receipt) => {
                NodePrivateResponse::CommandAuditOpened(receipt.into_receipt()?)
            }
            Self::CommandAuditCompleted(receipt) => {
                NodePrivateResponse::CommandAuditCompleted(receipt.into_receipt()?)
            }
            Self::AuditEvents(events) => NodePrivateResponse::AuditEvents(
                events
                    .into_iter()
                    .map(WireAuditEvent::into_event)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::AuditEvent(event) => NodePrivateResponse::AuditEvent(event.into_event()?),
            Self::AuditVerification(verification) => {
                NodePrivateResponse::AuditVerification(verification.into_verification()?)
            }
            Self::AuditExport(export) => NodePrivateResponse::AuditExport(export.into_export()?),
            Self::ModelServices(services) => NodePrivateResponse::ModelServices(
                services
                    .into_iter()
                    .map(WireModelServiceSummary::into_summary)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::ModelChanged(summary) => {
                NodePrivateResponse::ModelChanged(summary.into_summary()?)
            }
            Self::ModelRollbackPreview(preview) => {
                NodePrivateResponse::ModelRollbackPreview(preview.into_preview()?)
            }
            Self::ModelLogs(summary) => NodePrivateResponse::ModelLogs(summary.into_summary()?),
            Self::ModelRuntimeLogs(batch) => {
                NodePrivateResponse::ModelRuntimeLogs(batch.into_batch()?)
            }
            Self::CoreUpdateCheck(check) => {
                NodePrivateResponse::CoreUpdateCheck(check.into_check()?)
            }
            Self::CoreUpdated(summary) => NodePrivateResponse::CoreUpdated(summary.into_summary()?),
            Self::ModelUpdated(summary) => {
                NodePrivateResponse::ModelUpdated(summary.into_summary()?)
            }
            Self::Exposure(status) => NodePrivateResponse::Exposure(status.into_status()?),
            Self::RuntimeInstallationIds(installation_ids) => {
                NodePrivateResponse::RuntimeInstallationIds(runtime_installation_ids(
                    installation_ids,
                )?)
            }
            Self::RuntimeInstallationRemoved(disposition) => {
                NodePrivateResponse::RuntimeInstallationRemoved(runtime_removal_disposition(
                    &disposition,
                )?)
            }
            Self::RuntimeArtifactsFinalized(model_retention) => {
                NodePrivateResponse::RuntimeArtifactsFinalized(
                    NodeRuntimeArtifactsFinalizationReceipt::new(runtime_model_retention(
                        &model_retention,
                    )?),
                )
            }
            Self::UninstallBegan(receipt) => {
                NodePrivateResponse::UninstallBegan(receipt.into_receipt()?)
            }
            Self::UninstallCanceled(receipt) => {
                NodePrivateResponse::UninstallCanceled(receipt.into_receipt()?)
            }
            Self::PairingAuthorityChanged(receipt) => {
                NodePrivateResponse::PairingAuthorityChanged(receipt.into_receipt()?)
            }
            Self::Gateway(response) => NodePrivateResponse::Gateway(response.into_response()?),
            Self::Error(error) => {
                return Ok(NodePrivateTransportOutcome::Failure(error.into_error()?));
            }
        };
        Ok(NodePrivateTransportOutcome::Success(response))
    }
}

// Stores one retention-bound uninstall lease and the immutable admission inventory.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireUninstallBeginReceipt {
    session_id: String,
    disposition: String,
    model_retention: String,
    inventory: WireUninstallInventory,
}

impl WireUninstallBeginReceipt {
    // Projects one applied or replayed lease without joining inventory reads on the client.
    fn from_receipt(
        receipt: &NodeUninstallBeginReceipt,
    ) -> Result<Self, NodePrivateTransportError> {
        Ok(Self {
            session_id: receipt.session_id().as_str().to_string(),
            disposition: uninstall_disposition_name(receipt.disposition()).to_string(),
            model_retention: runtime_model_retention_name(receipt.model_retention()).to_string(),
            inventory: WireUninstallInventory::from_inventory(receipt.inventory())?,
        })
    }

    // Reconstructs one typed lease receipt after validating its policy and target inventory.
    fn into_receipt(self) -> Result<NodeUninstallBeginReceipt, NodePrivateTransportError> {
        Ok(NodeUninstallBeginReceipt::new(
            parse_digest(&self.session_id)?,
            uninstall_disposition(&self.disposition)?,
            runtime_model_retention(&self.model_retention)?,
            self.inventory.into_inventory()?,
        ))
    }
}

// Stores the exact teardown targets captured atomically when the lease was applied.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireUninstallInventory {
    local_role: String,
    active_benchmark_id: Option<String>,
    exposure_configuration_sha256: Option<String>,
    model_targets: Vec<WireUninstallModelTarget>,
    runtime_installation_ids: Vec<String>,
}

impl WireUninstallInventory {
    // Projects one already-bounded inventory into its closed transport representation.
    fn from_inventory(
        inventory: &NodeUninstallInventory,
    ) -> Result<Self, NodePrivateTransportError> {
        Ok(Self {
            local_role: node_role_name(inventory.local_role()).to_string(),
            active_benchmark_id: inventory
                .active_benchmark_id()
                .map(|job_id| job_id.as_str().to_string()),
            exposure_configuration_sha256: inventory
                .exposure_configuration_sha256()
                .map(|digest| digest.as_str().to_string()),
            model_targets: inventory
                .model_targets()
                .iter()
                .map(WireUninstallModelTarget::from_target)
                .collect(),
            runtime_installation_ids: wire_runtime_installation_ids(
                inventory.runtime_installation_ids(),
            )?,
        })
    }

    // Reconstructs one target inventory without accepting main-only targets on a child.
    fn into_inventory(self) -> Result<NodeUninstallInventory, NodePrivateTransportError> {
        let local_role = node_role(&self.local_role)?;
        let active_benchmark_id = self
            .active_benchmark_id
            .map(|job_id| OperationId::parse(&job_id).map_err(interface_error))
            .transpose()?;
        let exposure_configuration_sha256 = self
            .exposure_configuration_sha256
            .map(|digest| parse_digest(&digest))
            .transpose()?;
        let model_targets = self
            .model_targets
            .into_iter()
            .map(WireUninstallModelTarget::into_target)
            .collect::<Result<Vec<_>, _>>()?;
        NodeUninstallInventory::new(
            local_role,
            active_benchmark_id,
            exposure_configuration_sha256,
            model_targets,
            runtime_installation_ids(self.runtime_installation_ids)?,
        )
        .map_err(|_| invalid("uninstall inventory is invalid"))
    }
}

// Stores one compact model teardown identity and its exact placement-group closure.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireUninstallModelTarget {
    service_id: String,
    placement_group_ids: Vec<String>,
}

impl WireUninstallModelTarget {
    // Projects one compact model target without model metadata or runtime duplication.
    fn from_target(target: &NodeUninstallModelTarget) -> Self {
        Self {
            service_id: target.service_id().as_str().to_string(),
            placement_group_ids: target
                .placement_group_ids()
                .iter()
                .map(|group_id| group_id.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one compact model target after validating every exact identity.
    fn into_target(self) -> Result<NodeUninstallModelTarget, NodePrivateTransportError> {
        Ok(NodeUninstallModelTarget::new(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            self.placement_group_ids
                .into_iter()
                .map(|group_id| PlacementGroupId::parse(&group_id).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

// Stores one exact matching lease cancellation.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireUninstallCancelReceipt {
    session_id: String,
}

impl WireUninstallCancelReceipt {
    // Projects one canceled lease identity into its stable wire field.
    fn from_receipt(receipt: &NodeUninstallCancelReceipt) -> Self {
        Self {
            session_id: receipt.session_id().as_str().to_string(),
        }
    }

    // Reconstructs one cancellation receipt after digest validation.
    fn into_receipt(self) -> Result<NodeUninstallCancelReceipt, NodePrivateTransportError> {
        Ok(NodeUninstallCancelReceipt::new(parse_digest(
            &self.session_id,
        )?))
    }
}

// Stores one immutable Core installation identity without accepting provider metadata.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCoreInstallation {
    version: String,
    source_identity: String,
}

impl WireCoreInstallation {
    // Projects one verified immutable installation into exact wire fields.
    fn from_installation(installation: &CoreInstallation) -> Self {
        Self {
            version: installation.version().as_str().to_string(),
            source_identity: installation.source_identity().as_str().to_string(),
        }
    }

    // Reconstructs one validated immutable installation identity.
    fn into_installation(self) -> Result<CoreInstallation, NodePrivateTransportError> {
        Ok(CoreInstallation::new(
            CoreVersion::parse(&self.version).map_err(update_value_error)?,
            parse_digest(&self.source_identity)?,
        ))
    }
}

// Stores one signed read-only Core update decision.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCoreUpdateCheck {
    current: WireCoreInstallation,
    available: WireCoreInstallation,
    disposition: String,
}

impl WireCoreUpdateCheck {
    // Projects one manager-validated availability decision.
    fn from_check(check: &NodeCoreUpdateCheck) -> Self {
        Self {
            current: WireCoreInstallation::from_installation(check.current()),
            available: WireCoreInstallation::from_installation(check.available()),
            disposition: check.disposition().as_str().to_string(),
        }
    }

    // Reconstructs and requires the disposition implied by exact identities.
    fn into_check(self) -> Result<NodeCoreUpdateCheck, NodePrivateTransportError> {
        let check = NodeCoreUpdateCheck::new(
            self.current.into_installation()?,
            self.available.into_installation()?,
        );
        if check.disposition().as_str() != self.disposition {
            return Err(invalid("Core update check disposition is inconsistent"));
        }
        Ok(check)
    }
}

// Stores one terminal manager-backed Core update projection.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCoreUpdateSummary {
    installation: WireCoreInstallation,
    disposition: String,
    phase: String,
}

impl WireCoreUpdateSummary {
    // Projects one terminal update and its exact durable phase.
    fn from_summary(summary: &NodeCoreUpdateSummary) -> Self {
        Self {
            installation: WireCoreInstallation::from_installation(summary.installation()),
            disposition: crate::core_update_disposition_name(summary.disposition()).to_string(),
            phase: crate::core_update_phase_name(summary.phase()).to_string(),
        }
    }

    // Reconstructs one closed manager disposition and phase.
    fn into_summary(self) -> Result<NodeCoreUpdateSummary, NodePrivateTransportError> {
        Ok(NodeCoreUpdateSummary::new(
            self.installation.into_installation()?,
            core_update_disposition(&self.disposition)?,
            core_update_phase(&self.phase)?,
        ))
    }
}

// Stores one ModelCoordinator update decision and optional terminal command.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelUpdateSummary {
    service_id: String,
    logical_model: String,
    disposition: String,
    placement_group_count: usize,
    command: Option<WireModelCommandSummary>,
}

impl WireModelUpdateSummary {
    // Projects one closed ModelCoordinator update result.
    fn from_summary(summary: &NodeModelUpdateSummary) -> Self {
        Self {
            service_id: summary.service_id().as_str().to_string(),
            logical_model: summary.logical_model().as_str().to_string(),
            disposition: summary.disposition().as_str().to_string(),
            placement_group_count: summary.placement_group_count(),
            command: summary.command().map(WireModelCommandSummary::from_summary),
        }
    }

    // Reconstructs one coherent read-only or mutated update projection.
    fn into_summary(self) -> Result<NodeModelUpdateSummary, NodePrivateTransportError> {
        let disposition = model_update_disposition(&self.disposition)?;
        let command = self
            .command
            .map(WireModelCommandSummary::into_summary)
            .transpose()?;
        if (disposition == NodeModelUpdateDisposition::Updated) != command.is_some()
            || (disposition == NodeModelUpdateDisposition::Current
                && self.placement_group_count != 0)
        {
            return Err(invalid("model update projection is inconsistent"));
        }
        Ok(NodeModelUpdateSummary::new(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            disposition,
            self.placement_group_count,
            command,
        ))
    }
}

// Stores one closed public-exposure state and its current provider verification judgment.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireExposureStatus {
    state: String,
    provider: String,
    public_url: Option<String>,
    inference_target: String,
    configuration_sha256: Option<String>,
    provider_verified: bool,
}

impl WireExposureStatus {
    // Projects one manager-owned status without provider-private state.
    fn from_status(status: &GatewayExposureStatus) -> Self {
        Self {
            state: if status.exposure().is_some() {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            },
            provider: status
                .exposure()
                .map_or("tailscale-funnel", GatewayExposure::provider)
                .to_string(),
            public_url: status
                .exposure()
                .map(|exposure| exposure.public_url().to_string()),
            inference_target: LETSINFER_PUBLIC_INFERENCE_TARGET.to_string(),
            configuration_sha256: status
                .exposure()
                .map(|exposure| exposure.configuration_sha256().as_str().to_string()),
            provider_verified: status.provider_verified(),
        }
    }

    // Reconstructs one status only from the exact enabled or disabled wire shape.
    fn into_status(self) -> Result<GatewayExposureStatus, NodePrivateTransportError> {
        if self.provider != "tailscale-funnel"
            || self.inference_target != LETSINFER_PUBLIC_INFERENCE_TARGET
        {
            return Err(invalid("Gateway exposure provider identity is invalid"));
        }
        let exposure = match (
            self.state.as_str(),
            self.public_url,
            self.configuration_sha256,
        ) {
            ("disabled", None, None) => None,
            ("enabled", Some(public_url), Some(configuration_sha256)) => Some(
                GatewayExposure::new(public_url, parse_digest(&configuration_sha256)?)
                    .map_err(|_| invalid("Gateway exposure identity is invalid"))?,
            ),
            _ => return Err(invalid("Gateway exposure state is invalid")),
        };
        GatewayExposureStatus::new(exposure, self.provider_verified)
            .map_err(|_| invalid("Gateway exposure verification is invalid"))
    }
}

// Stores every non-secret field of one validated audit event.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAuditEvent {
    sequence: u64,
    event_id: String,
    correlation_id: String,
    timestamp_unix_nanoseconds: u64,
    node_id: String,
    actor_type: String,
    actor_id: String,
    origin_node_id: String,
    origin_interface: String,
    action: String,
    target: String,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
    outcome: String,
    reason: Option<String>,
    previous_sha256: String,
    event_sha256: String,
}

impl WireAuditEvent {
    // Projects one manager-validated event into its exact private wire fields.
    fn from_event(event: &AuditEvent) -> Self {
        Self {
            sequence: event.sequence(),
            event_id: event.event_id().as_str().to_string(),
            correlation_id: event.correlation_id().as_str().to_string(),
            timestamp_unix_nanoseconds: event.timestamp().value(),
            node_id: event.node_id().as_str().to_string(),
            actor_type: event.actor().kind().as_str().to_string(),
            actor_id: event.actor().identifier().as_str().to_string(),
            origin_node_id: event.origin().node_id().as_str().to_string(),
            origin_interface: event.origin().interface().as_str().to_string(),
            action: event.action().as_str().to_string(),
            target: event.target().as_str().to_string(),
            before_sha256: event
                .before_sha256()
                .map(|value| value.as_str().to_string()),
            after_sha256: event.after_sha256().map(|value| value.as_str().to_string()),
            outcome: event.outcome().as_str().to_string(),
            reason: event.reason().map(|value| value.as_str().to_string()),
            previous_sha256: event.previous_hash().as_str().to_string(),
            event_sha256: event.event_hash().as_str().to_string(),
        }
    }

    // Reconstructs one structurally valid event before any manager-level chain verification.
    fn into_event(self) -> Result<AuditEvent, NodePrivateTransportError> {
        AuditEvent::from_persisted(
            self.sequence,
            AuditEventId::parse(&self.event_id).map_err(audit_value_error)?,
            AuditCorrelationId::parse(&self.correlation_id).map_err(audit_value_error)?,
            AuditUnixNanoseconds::new(self.timestamp_unix_nanoseconds)
                .map_err(audit_value_error)?,
            NodeId::parse(&self.node_id).map_err(interface_error)?,
            AuditActor::new(
                audit_actor_type(&self.actor_type)?,
                AuditActorId::parse(&self.actor_id).map_err(audit_value_error)?,
            ),
            AuditOrigin::new(
                NodeId::parse(&self.origin_node_id).map_err(interface_error)?,
                audit_origin_interface(&self.origin_interface)?,
            ),
            AuditAction::parse(&self.action).map_err(audit_value_error)?,
            AuditTarget::parse(&self.target).map_err(audit_value_error)?,
            self.before_sha256
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.after_sha256
                .map(|value| parse_digest(&value))
                .transpose()?,
            audit_outcome(&self.outcome)?,
            self.reason
                .map(|value| AuditReason::parse(&value).map_err(audit_value_error))
                .transpose()?,
            parse_digest(&self.previous_sha256)?,
            parse_digest(&self.event_sha256)?,
        )
        .map_err(audit_value_error)
    }
}

// Stores one bounded AuditManager verification receipt.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAuditVerification {
    events: usize,
    checkpoints: usize,
    head_sha256: String,
}

impl WireAuditVerification {
    // Projects one verified receipt into stable private wire fields.
    fn from_verification(verification: &NodeAuditVerification) -> Self {
        Self {
            events: verification.events(),
            checkpoints: verification.checkpoints(),
            head_sha256: verification.head_sha256().as_str().to_string(),
        }
    }

    // Reconstructs one bounded receipt without re-running remote verification locally.
    fn into_verification(self) -> Result<NodeAuditVerification, NodePrivateTransportError> {
        NodeAuditVerification::new(
            self.events,
            self.checkpoints,
            parse_digest(&self.head_sha256)?,
        )
        .map_err(audit_value_error)
    }
}

// Carries one complete manager-produced export as canonical Base64 under the wire ceiling.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAuditExport {
    events: usize,
    document_base64: String,
}

impl WireAuditExport {
    // Encodes one bounded canonical JSON export without interpreting its contents.
    fn from_export(export: &NodeAuditExport) -> Self {
        Self {
            events: export.events(),
            document_base64: BASE64.encode(export.document()),
        }
    }

    // Reconstructs one bounded UTF-8 export after canonical Base64 validation.
    fn into_export(self) -> Result<NodeAuditExport, NodePrivateTransportError> {
        NodeAuditExport::new(decode_audit_export(&self.document_base64)?, self.events)
            .map_err(audit_value_error)
    }
}

// Stores one installed-service summary without manager-private aggregate documents.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelServiceSummary {
    service_id: String,
    logical_model: String,
    desired_state: String,
    placement_group_ids: Vec<String>,
    runtime_installation_ids: Vec<String>,
    evidence_labels: Vec<String>,
}

impl WireModelServiceSummary {
    // Projects one typed service summary into stable closed JSON fields.
    fn from_summary(summary: &NodeModelServiceSummary) -> Self {
        Self {
            service_id: summary.service_id().as_str().to_string(),
            logical_model: summary.logical_model().as_str().to_string(),
            desired_state: model_desired_state_name(summary.desired_state()).to_string(),
            placement_group_ids: summary
                .placement_group_ids()
                .iter()
                .map(|identity| identity.as_str().to_string())
                .collect(),
            runtime_installation_ids: summary
                .runtime_installation_ids()
                .iter()
                .map(|identity| identity.as_str().to_string())
                .collect(),
            evidence_labels: summary
                .evidence_labels()
                .iter()
                .map(|label| evidence_label_name(*label).to_string())
                .collect(),
        }
    }

    // Reconstructs one typed summary after validating every public identity and enum.
    fn into_summary(self) -> Result<NodeModelServiceSummary, NodePrivateTransportError> {
        Ok(NodeModelServiceSummary::new(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            model_desired_state(&self.desired_state)?,
            self.placement_group_ids
                .into_iter()
                .map(|value| PlacementGroupId::parse(&value).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.runtime_installation_ids
                .into_iter()
                .map(|value| RuntimeInstallationId::parse(&value).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.evidence_labels
                .into_iter()
                .map(|value| evidence_label(&value))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

// Stores one terminal or replayed model-command summary.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelCommandSummary {
    operation_id: String,
    service_id: String,
    logical_model: String,
    desired_state: String,
    action: String,
    journal_state: String,
    failure_code: Option<String>,
}

impl WireModelCommandSummary {
    // Projects one typed command summary without private journal or provider diagnostics.
    fn from_summary(summary: &NodeModelCommandSummary) -> Self {
        Self {
            operation_id: summary.operation_id().as_str().to_string(),
            service_id: summary.service_id().as_str().to_string(),
            logical_model: summary.logical_model().as_str().to_string(),
            desired_state: model_desired_state_name(summary.desired_state()).to_string(),
            action: summary.action().as_str().to_string(),
            journal_state: summary.journal_state().as_str().to_string(),
            failure_code: summary
                .failure_code()
                .map(|failure| failure.as_str().to_string()),
        }
    }

    // Reconstructs one typed command summary from stable bounded fields.
    fn into_summary(self) -> Result<NodeModelCommandSummary, NodePrivateTransportError> {
        Ok(NodeModelCommandSummary::new(
            OperationId::parse(&self.operation_id).map_err(interface_error)?,
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            model_desired_state(&self.desired_state)?,
            model_action(&self.action)?,
            model_journal_state(&self.journal_state)?,
            self.failure_code
                .map(|failure| TechnicalName::parse(&failure).map_err(interface_error))
                .transpose()?,
        ))
    }
}

// Stores one non-mutating retained-runtime rollback preview.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelRollbackPreview {
    service_id: String,
    logical_model: String,
    target_id: Option<String>,
    groups: Vec<WireModelRollbackGroupPreview>,
}

impl WireModelRollbackPreview {
    // Projects one coordinator-validated rollback preview into exact private fields.
    fn from_preview(preview: &NodeModelRollbackPreview) -> Self {
        Self {
            service_id: preview.service_id().as_str().to_string(),
            logical_model: preview.logical_model().as_str().to_string(),
            target_id: preview.target_id().map(|value| value.as_str().to_string()),
            groups: preview
                .groups()
                .iter()
                .map(WireModelRollbackGroupPreview::from_preview)
                .collect(),
        }
    }

    // Reconstructs one typed preview after validating every bounded identity.
    fn into_preview(self) -> Result<NodeModelRollbackPreview, NodePrivateTransportError> {
        NodeModelRollbackPreview::restore(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            self.target_id
                .map(|value| TargetId::parse(&value).map_err(interface_error))
                .transpose()?,
            self.groups
                .into_iter()
                .map(WireModelRollbackGroupPreview::into_preview)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(model_value_error)
    }
}

// Stores one exact current-to-retained placement-group transition.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelRollbackGroupPreview {
    current_group_id: String,
    previous_group_id: String,
    node_ids: Vec<String>,
    current: WireModelRollbackRuntime,
    previous: WireModelRollbackRuntime,
}

impl WireModelRollbackGroupPreview {
    // Projects one validated rollback group into stable private fields.
    fn from_preview(preview: &NodeModelRollbackGroupPreview) -> Self {
        Self {
            current_group_id: preview.current_group_id().as_str().to_string(),
            previous_group_id: preview.previous_group_id().as_str().to_string(),
            node_ids: preview
                .node_ids()
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
            current: WireModelRollbackRuntime::from_runtime(preview.current()),
            previous: WireModelRollbackRuntime::from_runtime(preview.previous()),
        }
    }

    // Reconstructs one typed rollback group after validating every identity.
    fn into_preview(self) -> Result<NodeModelRollbackGroupPreview, NodePrivateTransportError> {
        NodeModelRollbackGroupPreview::restore(
            PlacementGroupId::parse(&self.current_group_id).map_err(interface_error)?,
            PlacementGroupId::parse(&self.previous_group_id).map_err(interface_error)?,
            self.node_ids
                .into_iter()
                .map(|node_id| NodeId::parse(&node_id).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.current.into_runtime()?,
            self.previous.into_runtime()?,
        )
        .map_err(model_value_error)
    }
}

// Stores one redacted immutable runtime identity in a rollback transition.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelRollbackRuntime {
    candidate_id: String,
    version: String,
    target_id: String,
    source: String,
}

impl WireModelRollbackRuntime {
    // Projects one exact rollback runtime into stable private fields.
    fn from_runtime(runtime: &NodeModelRollbackRuntime) -> Self {
        Self {
            candidate_id: runtime.candidate_id().as_str().to_string(),
            version: runtime.version().as_str().to_string(),
            target_id: runtime.target_id().as_str().to_string(),
            source: runtime.source().as_str().to_string(),
        }
    }

    // Reconstructs one exact immutable rollback runtime identity.
    fn into_runtime(self) -> Result<NodeModelRollbackRuntime, NodePrivateTransportError> {
        Ok(NodeModelRollbackRuntime::new(
            RuntimeCandidateId::parse(&self.candidate_id).map_err(interface_error)?,
            RuntimeVersion::parse(&self.version).map_err(interface_error)?,
            TargetId::parse(&self.target_id).map_err(interface_error)?,
            RuntimeSource::parse(&self.source).map_err(interface_error)?,
        ))
    }
}

// Stores bounded operation and recovery-journal identities for one model service.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelLogSummary {
    service_id: String,
    operation_ids: Vec<String>,
    journal_operation_ids: Vec<String>,
    failure_codes: Vec<String>,
}

impl WireModelLogSummary {
    // Projects one redacted typed log summary into stable private fields.
    fn from_summary(summary: &NodeModelLogSummary) -> Self {
        Self {
            service_id: summary.service_id().as_str().to_string(),
            operation_ids: summary
                .operation_ids()
                .iter()
                .map(|identity| identity.as_str().to_string())
                .collect(),
            journal_operation_ids: summary
                .journal_operation_ids()
                .iter()
                .map(|identity| identity.as_str().to_string())
                .collect(),
            failure_codes: summary
                .failure_codes()
                .iter()
                .map(|failure| failure.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one typed redacted log summary after validating every identity.
    fn into_summary(self) -> Result<NodeModelLogSummary, NodePrivateTransportError> {
        Ok(NodeModelLogSummary::new(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            self.operation_ids
                .into_iter()
                .map(|value| OperationId::parse(&value).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.journal_operation_ids
                .into_iter()
                .map(|value| OperationId::parse(&value).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
            self.failure_codes
                .into_iter()
                .map(|value| TechnicalName::parse(&value).map_err(interface_error))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

// Stores one provider cursor without exposing platform-specific position semantics.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePlacementLogCursor {
    source_identity: String,
    position: String,
}

impl WirePlacementLogCursor {
    // Projects one validated Placement cursor into stable private fields.
    fn from_cursor(cursor: &PlacementLogCursor) -> Self {
        Self {
            source_identity: cursor.source_identity().as_str().to_string(),
            position: cursor.position().to_string(),
        }
    }

    // Reconstructs one bounded Placement cursor after exact identity validation.
    fn into_cursor(self) -> Result<PlacementLogCursor, NodePrivateTransportError> {
        PlacementLogCursor::new(
            Sha256Digest::parse(&self.source_identity).map_err(interface_error)?,
            self.position,
        )
        .map_err(|_| invalid("placement log cursor is invalid"))
    }
}

// Stores one bounded Node runtime-log read without lifecycle or platform fields.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelRuntimeLogRequest {
    service_id: String,
    placement_group_id: Option<String>,
    cursor: Option<WirePlacementLogCursor>,
    maximum_lines: u32,
    maximum_bytes: usize,
    wait_milliseconds: u64,
}

impl WireModelRuntimeLogRequest {
    // Projects one validated Node request into stable private fields.
    fn from_request(request: &NodeModelRuntimeLogRequest) -> Self {
        Self {
            service_id: request.service_id().as_str().to_string(),
            placement_group_id: request
                .placement_group_id()
                .map(|identity| identity.as_str().to_string()),
            cursor: request.cursor().map(WirePlacementLogCursor::from_cursor),
            maximum_lines: request.maximum_lines(),
            maximum_bytes: request.maximum_bytes(),
            wait_milliseconds: request.wait().as_millis() as u64,
        }
    }

    // Reconstructs one bounded Node request after every identity and limit is validated.
    fn into_request(self) -> Result<NodeModelRuntimeLogRequest, NodePrivateTransportError> {
        NodeModelRuntimeLogRequest::new(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            self.placement_group_id
                .map(|identity| PlacementGroupId::parse(&identity).map_err(interface_error))
                .transpose()?,
            self.cursor
                .map(WirePlacementLogCursor::into_cursor)
                .transpose()?,
            self.maximum_lines,
            self.maximum_bytes,
            Duration::from_millis(self.wait_milliseconds),
        )
        .map_err(model_value_error)
    }
}

// Stores one opaque Placement-owned log batch using canonical base64 for arbitrary bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModelRuntimeLogBatch {
    service_id: String,
    placement_group_id: String,
    placement_id: String,
    cursor: WirePlacementLogCursor,
    payload_base64: String,
    truncated: bool,
}

impl WireModelRuntimeLogBatch {
    // Projects one typed opaque batch without interpreting or normalizing runtime content.
    fn from_batch(batch: &NodeModelRuntimeLogBatch) -> Self {
        Self {
            service_id: batch.service_id().as_str().to_string(),
            placement_group_id: batch.placement().placement_group_id().as_str().to_string(),
            placement_id: batch.placement().placement_id().as_str().to_string(),
            cursor: WirePlacementLogCursor::from_cursor(batch.placement().cursor()),
            payload_base64: BASE64.encode(batch.placement().payload()),
            truncated: batch.placement().is_truncated(),
        }
    }

    // Reconstructs one bounded opaque batch after canonical binary and identity validation.
    fn into_batch(self) -> Result<NodeModelRuntimeLogBatch, NodePrivateTransportError> {
        let placement = PlacementLogBatch::new(
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            PlacementId::parse(&self.placement_id).map_err(interface_error)?,
            self.cursor.into_cursor()?,
            decode_runtime_log_payload(&self.payload_base64)?,
            self.truncated,
        )
        .map_err(|_| invalid("model runtime log batch is invalid"))?;
        Ok(NodeModelRuntimeLogBatch::new(
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            placement,
        ))
    }
}

// Stores one opened marker and whether it was newly created or exactly replayed.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCommandAuditOpenReceipt {
    marker: String,
    disposition: String,
}

impl WireCommandAuditOpenReceipt {
    // Projects one opened Node receipt into its exact closed wire fields.
    fn from_receipt(receipt: &NodeCommandAuditOpenReceipt) -> Self {
        Self {
            marker: receipt.marker().as_str().to_string(),
            disposition: match receipt.disposition() {
                NodeCommandAuditOpenDisposition::Opened => "opened",
                NodeCommandAuditOpenDisposition::Replayed => "replayed",
            }
            .to_string(),
        }
    }

    // Reconstructs one validated marker and exact open disposition.
    fn into_receipt(self) -> Result<NodeCommandAuditOpenReceipt, NodePrivateTransportError> {
        let disposition = match self.disposition.as_str() {
            "opened" => NodeCommandAuditOpenDisposition::Opened,
            "replayed" => NodeCommandAuditOpenDisposition::Replayed,
            _ => return Err(invalid("command audit disposition is invalid")),
        };
        Ok(NodeCommandAuditOpenReceipt::new(
            NodeCommandAuditMarker::parse(&self.marker).map_err(command_audit_value_error)?,
            disposition,
        ))
    }
}

// Stores one optional audit event identity and exact completion disposition.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCommandAuditCompletionReceipt {
    event_id: Option<String>,
    disposition: String,
}

impl WireCommandAuditCompletionReceipt {
    // Projects one terminal Node receipt without retaining event contents.
    fn from_receipt(receipt: &NodeCommandAuditCompletionReceipt) -> Self {
        Self {
            event_id: receipt.event_id().map(|value| value.as_str().to_string()),
            disposition: match receipt.disposition() {
                NodeCommandAuditCompletionDisposition::Completed => "completed",
                NodeCommandAuditCompletionDisposition::Replayed => "replayed",
            }
            .to_string(),
        }
    }

    // Reconstructs one terminal receipt from exact bounded identities.
    fn into_receipt(self) -> Result<NodeCommandAuditCompletionReceipt, NodePrivateTransportError> {
        let disposition = match self.disposition.as_str() {
            "completed" => NodeCommandAuditCompletionDisposition::Completed,
            "replayed" => NodeCommandAuditCompletionDisposition::Replayed,
            _ => return Err(invalid("command audit disposition is invalid")),
        };
        Ok(NodeCommandAuditCompletionReceipt::new(
            self.event_id
                .map(|value| AuditEventId::parse(&value))
                .transpose()
                .map_err(|_| invalid("command audit event identity is invalid"))?,
            disposition,
        ))
    }
}

// Stores one complete secret-free controller metadata projection.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireControllerSummary {
    controller_id: String,
    name: String,
    role: String,
    state: String,
    certificate_sha256: String,
    public_key_sha256: String,
    certificate_valid_from_unix_milliseconds: u64,
    certificate_expires_at_unix_milliseconds: u64,
    issued_at_unix_milliseconds: u64,
    activated_at_unix_milliseconds: Option<u64>,
    revoked_at_unix_milliseconds: Option<u64>,
}

impl WireControllerSummary {
    // Projects one secret-free controller snapshot onto strict transport fields.
    fn from_summary(summary: &NodeControllerSummary) -> Self {
        Self {
            controller_id: summary.controller_id().as_str().to_string(),
            name: summary.name().as_str().to_string(),
            role: summary.role().as_str().to_string(),
            state: summary.state().as_str().to_string(),
            certificate_sha256: summary.certificate_sha256().as_str().to_string(),
            public_key_sha256: summary.public_key_sha256().as_str().to_string(),
            certificate_valid_from_unix_milliseconds: summary.certificate_valid_from().value(),
            certificate_expires_at_unix_milliseconds: summary.certificate_expires_at().value(),
            issued_at_unix_milliseconds: summary.issued_at().value(),
            activated_at_unix_milliseconds: summary.activated_at().map(UnixMilliseconds::value),
            revoked_at_unix_milliseconds: summary.revoked_at().map(UnixMilliseconds::value),
        }
    }

    // Reconstructs one strict secret-free controller snapshot from typed wire fields.
    fn into_summary(self) -> Result<NodeControllerSummary, NodePrivateTransportError> {
        NodeControllerSummary::restore(
            li_core_interface::ControllerId::parse(&self.controller_id).map_err(interface_error)?,
            DisplayName::parse(&self.name).map_err(interface_error)?,
            ControllerRole::parse(&self.role).map_err(controller_value_error)?,
            ControllerState::parse(&self.state).map_err(controller_value_error)?,
            parse_digest(&self.certificate_sha256)?,
            parse_digest(&self.public_key_sha256)?,
            UnixMilliseconds::new(self.certificate_valid_from_unix_milliseconds),
            UnixMilliseconds::new(self.certificate_expires_at_unix_milliseconds),
            UnixMilliseconds::new(self.issued_at_unix_milliseconds),
            self.activated_at_unix_milliseconds
                .map(UnixMilliseconds::new),
            self.revoked_at_unix_milliseconds.map(UnixMilliseconds::new),
        )
        .map_err(controller_value_error)
    }
}

// Carries one committed controller plus only its public certificate back to the CLI enrollment owner.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireControllerEnrollmentReceipt {
    controller: WireControllerSummary,
    certificate_public_material_base64: String,
}

impl WireControllerEnrollmentReceipt {
    // Projects one manager commit receipt without private controller or CA material.
    fn from_receipt(receipt: &NodeControllerEnrollmentReceipt) -> Self {
        Self {
            controller: WireControllerSummary::from_summary(receipt.controller()),
            certificate_public_material_base64: BASE64
                .encode(receipt.certificate_public_material()),
        }
    }

    // Reconstructs one receipt only when public certificate bytes match the controller fingerprint.
    fn into_receipt(self) -> Result<NodeControllerEnrollmentReceipt, NodePrivateTransportError> {
        NodeControllerEnrollmentReceipt::restore(
            self.controller.into_summary()?,
            decode_base64(&self.certificate_public_material_base64)?,
        )
        .map_err(controller_value_error)
    }
}

// Stores one complete non-secret API-key metadata projection.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireApiKey {
    key_id: String,
    name: String,
    policy: WireApiKeyPolicy,
    created_at_unix_milliseconds: u64,
    revoked_at_unix_milliseconds: Option<u64>,
    rotated_from: Option<String>,
}

impl WireApiKey {
    // Projects one durable API-key snapshot without verifier or bearer material.
    fn from_api_key(api_key: &ApiKey) -> Self {
        Self {
            key_id: api_key.key_id().as_str().to_string(),
            name: api_key.name().as_str().to_string(),
            policy: WireApiKeyPolicy::from_policy(api_key.policy()),
            created_at_unix_milliseconds: api_key.created_at().value(),
            revoked_at_unix_milliseconds: api_key.revoked_at().map(UnixMilliseconds::value),
            rotated_from: api_key
                .rotated_from()
                .map(|value| value.as_str().to_string()),
        }
    }

    // Reconstructs one validated durable API-key snapshot.
    fn into_api_key(self) -> Result<ApiKey, NodePrivateTransportError> {
        ApiKey::new(
            ApiKeyId::parse(&self.key_id).map_err(interface_error)?,
            DisplayName::parse(&self.name).map_err(interface_error)?,
            self.policy.into_policy()?,
            UnixMilliseconds::new(self.created_at_unix_milliseconds),
            self.revoked_at_unix_milliseconds.map(UnixMilliseconds::new),
            self.rotated_from
                .map(|value| ApiKeyId::parse(&value).map_err(interface_error))
                .transpose()?,
        )
        .map_err(authentication_value_error)
    }
}

// Stores one immediate one-time token beside its non-secret metadata.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireIssuedApiKey {
    key: WireApiKey,
    token: String,
    token_shown_once: bool,
}

impl WireIssuedApiKey {
    // Projects one unconsumed token for the immediate response only.
    fn from_issued(issued: &NodeIssuedApiKey) -> Result<Self, NodePrivateTransportError> {
        let token =
            issued
                .take_token_for_wire()
                .ok_or(NodePrivateTransportError::InvalidDocument {
                    reason: "issued API-key token was already consumed",
                })?;
        Ok(Self {
            key: WireApiKey::from_api_key(issued.api_key()),
            token,
            token_shown_once: true,
        })
    }

    // Reconstructs one one-time response owner after strict token binding validation.
    fn into_issued(self) -> Result<NodeIssuedApiKey, NodePrivateTransportError> {
        let key = self.key.into_api_key()?;
        if !self.token_shown_once || !valid_api_token(&self.token, key.key_id()) {
            return Err(NodePrivateTransportError::InvalidDocument {
                reason: "issued API-key token is invalid",
            });
        }
        Ok(NodeIssuedApiKey::new(key, self.token))
    }
}

// Stores one bounded benchmark progress projection.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkProgress {
    phase: String,
    completed_cells: u32,
    total_cells: u32,
}

impl WireBenchmarkProgress {
    // Projects one bounded private benchmark progress value.
    fn from_progress(progress: &NodeBenchmarkSnapshotProgress) -> Self {
        Self {
            phase: progress.phase().as_str().to_string(),
            completed_cells: progress.completed_cells(),
            total_cells: progress.total_cells(),
        }
    }

    // Reconstructs one bounded private benchmark progress value.
    fn into_progress(self) -> Result<NodeBenchmarkSnapshotProgress, NodePrivateTransportError> {
        NodeBenchmarkSnapshotProgress::restore(
            TechnicalName::parse(&self.phase).map_err(interface_error)?,
            self.completed_cells,
            self.total_cells,
        )
        .map_err(benchmark_value_error)
    }
}

// Stores one secret-free durable benchmark snapshot for private status clients.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkSnapshot {
    job_id: String,
    revision: u64,
    kind: WireBenchmarkKind,
    phase: String,
    disposition: Option<String>,
    request_sha256: String,
    core_installation_id: String,
    runtime_installation_id: String,
    logical_model: String,
    placement_group_id: String,
    execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
    authorization_receipt_id: String,
    prepared_receipt_id: Option<String>,
    running_receipt_id: Option<String>,
    telemetry_receipt_id: Option<String>,
    telemetry_sample_count: Option<u64>,
    restoration_receipt_id: Option<String>,
    evidence_id: Option<String>,
    results_sha256: Option<String>,
    signature_key_id: Option<String>,
    progress: Option<WireBenchmarkProgress>,
    verification_phase: Option<String>,
    handoff_transaction_id: Option<String>,
    handoff_phase: Option<String>,
    recovery_required: Option<bool>,
    terminal_failure_category: Option<String>,
    terminal_failure_phase: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl WireBenchmarkSnapshot {
    // Projects one typed secret-free benchmark snapshot into exact wire fields.
    fn from_snapshot(snapshot: &NodeBenchmarkSnapshot) -> Self {
        Self {
            job_id: snapshot.job_id().as_str().to_string(),
            revision: snapshot.revision(),
            kind: WireBenchmarkKind::from_kind(snapshot.kind()),
            phase: benchmark_phase_name(snapshot.phase()).to_string(),
            disposition: snapshot
                .disposition()
                .map(benchmark_disposition_name)
                .map(str::to_string),
            request_sha256: snapshot.request_sha256().as_str().to_string(),
            core_installation_id: snapshot.core_installation_id().as_str().to_string(),
            runtime_installation_id: snapshot.runtime_installation_id().as_str().to_string(),
            logical_model: snapshot.logical_model().as_str().to_string(),
            placement_group_id: snapshot.placement_group_id().as_str().to_string(),
            execution_sha256: snapshot.execution_sha256().as_str().to_string(),
            benchmark_contract_sha256: snapshot.benchmark_contract_sha256().as_str().to_string(),
            target_contract_sha256: snapshot.target_contract_sha256().as_str().to_string(),
            authorization_receipt_id: snapshot.authorization_receipt_id().as_str().to_string(),
            prepared_receipt_id: snapshot
                .prepared_receipt_id()
                .map(|value| value.as_str().to_string()),
            running_receipt_id: snapshot
                .running_receipt_id()
                .map(|value| value.as_str().to_string()),
            telemetry_receipt_id: snapshot
                .telemetry_receipt_id()
                .map(|value| value.as_str().to_string()),
            telemetry_sample_count: snapshot.telemetry_sample_count(),
            restoration_receipt_id: snapshot
                .restoration_receipt_id()
                .map(|value| value.as_str().to_string()),
            evidence_id: snapshot
                .evidence_id()
                .map(|value| value.as_str().to_string()),
            results_sha256: snapshot
                .results_sha256()
                .map(|value| value.as_str().to_string()),
            signature_key_id: snapshot
                .signature_key_id()
                .map(|value| value.as_str().to_string()),
            progress: snapshot
                .progress()
                .map(WireBenchmarkProgress::from_progress),
            verification_phase: snapshot
                .verification()
                .map(|value| benchmark_verification_phase_name(value.phase()).to_string()),
            handoff_transaction_id: snapshot
                .verification()
                .map(|value| value.handoff_transaction_id().as_str().to_string()),
            handoff_phase: snapshot
                .verification()
                .map(|value| benchmark_handoff_phase_name(value.handoff_phase()).to_string()),
            recovery_required: snapshot
                .verification()
                .map(NodeBenchmarkVerificationProjection::recovery_required),
            terminal_failure_category: snapshot
                .terminal_failure()
                .map(|failure| failure.category().as_str().to_string()),
            terminal_failure_phase: snapshot
                .terminal_failure()
                .map(|failure| failure.phase().as_str().to_string()),
            created_at_unix_milliseconds: snapshot.created_at().value(),
            updated_at_unix_milliseconds: snapshot.updated_at().value(),
        }
    }

    // Reconstructs one validated typed snapshot without accepting secret-bearing fields.
    fn into_snapshot(self) -> Result<NodeBenchmarkSnapshot, NodePrivateTransportError> {
        let verification = match (
            self.verification_phase,
            self.handoff_transaction_id,
            self.handoff_phase,
            self.recovery_required,
        ) {
            (Some(phase), Some(transaction_id), Some(handoff_phase), Some(recovery_required)) => {
                Some(
                    NodeBenchmarkVerificationProjection::restore(
                        benchmark_verification_phase(&phase)?,
                        OperationId::parse(&transaction_id).map_err(interface_error)?,
                        benchmark_handoff_phase(&handoff_phase)?,
                        recovery_required,
                    )
                    .map_err(benchmark_value_error)?,
                )
            }
            (None, None, None, None) => None,
            _ => {
                return Err(NodePrivateTransportError::InvalidDocument {
                    reason: "benchmark verification projection is incomplete",
                });
            }
        };
        let terminal_failure = match (self.terminal_failure_category, self.terminal_failure_phase) {
            (Some(category), Some(phase)) => Some(NodeBenchmarkTerminalFailure::new(
                benchmark_failure_category(&category)?,
                TechnicalName::parse(&phase).map_err(interface_error)?,
            )),
            (None, None) => None,
            _ => {
                return Err(NodePrivateTransportError::InvalidDocument {
                    reason: "benchmark terminal failure projection is incomplete",
                });
            }
        };
        NodeBenchmarkSnapshot::restore(
            OperationId::parse(&self.job_id).map_err(interface_error)?,
            self.revision,
            self.kind.into_kind()?,
            benchmark_phase(&self.phase)?,
            self.disposition
                .map(|value| benchmark_disposition(&value))
                .transpose()?,
            parse_digest(&self.request_sha256)?,
            InstallationId::parse(&self.core_installation_id).map_err(interface_error)?,
            RuntimeInstallationId::parse(&self.runtime_installation_id).map_err(interface_error)?,
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            parse_digest(&self.execution_sha256)?,
            parse_digest(&self.benchmark_contract_sha256)?,
            parse_digest(&self.target_contract_sha256)?,
            parse_digest(&self.authorization_receipt_id)?,
            self.prepared_receipt_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.running_receipt_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.telemetry_receipt_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.telemetry_sample_count,
            self.restoration_receipt_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.evidence_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.results_sha256
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.signature_key_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.progress
                .map(WireBenchmarkProgress::into_progress)
                .transpose()?,
            verification,
            terminal_failure,
            UnixMilliseconds::new(self.created_at_unix_milliseconds),
            UnixMilliseconds::new(self.updated_at_unix_milliseconds),
        )
        .map_err(benchmark_value_error)
    }
}

// Stores one closed pairing mode without importing PairingManager wire shapes.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WirePairingMode {
    Lan,
    Remote,
    ConnectX {
        candidate_public_key_sha256: String,
        direct_interface: String,
    },
}

impl WirePairingMode {
    // Projects one typed Node pairing mode into its closed wire shape.
    fn from_mode(mode: &NodePairingMode) -> Self {
        match mode {
            NodePairingMode::Lan => Self::Lan,
            NodePairingMode::Remote => Self::Remote,
            NodePairingMode::ConnectX {
                candidate_public_key_sha256,
                direct_interface,
            } => Self::ConnectX {
                candidate_public_key_sha256: candidate_public_key_sha256.as_str().to_string(),
                direct_interface: direct_interface.as_str().to_string(),
            },
        }
    }

    // Reconstructs one validated Node pairing mode from its closed wire shape.
    fn into_mode(self) -> Result<NodePairingMode, NodePrivateTransportError> {
        Ok(match self {
            Self::Lan => NodePairingMode::Lan,
            Self::Remote => NodePairingMode::Remote,
            Self::ConnectX {
                candidate_public_key_sha256,
                direct_interface,
            } => NodePairingMode::ConnectX {
                candidate_public_key_sha256: parse_digest(&candidate_public_key_sha256)?,
                direct_interface: NetworkInterfaceName::parse(&direct_interface)
                    .map_err(interface_error)?,
            },
        })
    }
}

// Stores one opened pairing invitation and its one-time presentation material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingInvitation {
    invite_id: String,
    mode: WirePairingMode,
    nonce: String,
    expires_at_unix_milliseconds: u64,
    setup_code: Option<String>,
}

impl WirePairingInvitation {
    // Projects one typed invitation into exact private wire fields.
    fn from_invitation(invitation: &NodePairingInvitation) -> Self {
        Self {
            invite_id: invitation.invite_id().as_str().to_string(),
            mode: WirePairingMode::from_mode(invitation.mode()),
            nonce: invitation.nonce().as_str().to_string(),
            expires_at_unix_milliseconds: invitation.expires_at().value(),
            setup_code: invitation.setup_code().map(str::to_string),
        }
    }

    // Reconstructs one coherent invitation after every wire value is validated.
    fn into_invitation(self) -> Result<NodePairingInvitation, NodePrivateTransportError> {
        NodePairingInvitation::new(
            PairingInviteId::parse(&self.invite_id).map_err(interface_error)?,
            self.mode.into_mode()?,
            parse_digest(&self.nonce)?,
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
            self.setup_code,
        )
        .map_err(pairing_value_error)
    }
}

// Stores one durable pairing status and redacted-at-diagnostic approval material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingStatus {
    invite_id: String,
    mode: WirePairingMode,
    state: String,
    expires_at_unix_milliseconds: u64,
    attempts: u8,
    child_node_id: Option<String>,
    comparison_code: Option<String>,
}

impl WirePairingStatus {
    // Projects one typed pairing status into exact private wire fields.
    fn from_status(status: &NodePairingStatus) -> Self {
        Self {
            invite_id: status.invite_id().as_str().to_string(),
            mode: WirePairingMode::from_mode(status.mode()),
            state: pairing_state_name(status.state()).to_string(),
            expires_at_unix_milliseconds: status.expires_at().value(),
            attempts: status.attempts(),
            child_node_id: status
                .child_node_id()
                .map(|value| value.as_str().to_string()),
            comparison_code: status.comparison_code().map(str::to_string),
        }
    }

    // Reconstructs one coherent pairing status without persistence fields.
    fn into_status(self) -> Result<NodePairingStatus, NodePrivateTransportError> {
        NodePairingStatus::new(
            PairingInviteId::parse(&self.invite_id).map_err(interface_error)?,
            self.mode.into_mode()?,
            pairing_state(&self.state)?,
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
            self.attempts,
            self.child_node_id
                .map(|value| NodeId::parse(&value).map_err(interface_error))
                .transpose()?,
            self.comparison_code,
        )
        .map_err(pairing_value_error)
    }
}

// Stores one bounded public trust package using canonical base64 for binary values.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingCredentials {
    main_public_key_base64: String,
    main_ca_certificate_base64: String,
    child_certificate_base64: String,
    membership_signature_base64: String,
    child_leaf_sha256: String,
    valid_from_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

// Stores one exact atomic pairing-authority request without private credential material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingAuthorityRequest {
    idempotency_key: String,
    main: WireNode,
    main_certificate_sha256: String,
    credentials: WirePairingCredentials,
}

impl WirePairingAuthorityRequest {
    // Projects one paired-child request into the shared closed authority shape.
    fn from_activation(request: &NodePairedChildActivationRequest) -> Self {
        Self {
            idempotency_key: request.idempotency_key().to_string(),
            main: WireNode::from_node(request.main()),
            main_certificate_sha256: request.main_certificate_sha256().as_str().to_string(),
            credentials: WirePairingCredentials::from_credentials(request.credentials()),
        }
    }

    // Projects one paired-main restoration into the shared closed authority shape.
    fn from_restoration(request: &NodePairedMainRestorationRequest) -> Self {
        Self {
            idempotency_key: request.idempotency_key().to_string(),
            main: WireNode::from_node(request.main()),
            main_certificate_sha256: request.main_certificate_sha256().as_str().to_string(),
            credentials: WirePairingCredentials::from_credentials(request.credentials()),
        }
    }

    // Reconstructs one validated paired-child authority request.
    fn into_activation(
        self,
    ) -> Result<NodePairedChildActivationRequest, NodePrivateTransportError> {
        NodePairedChildActivationRequest::new(
            bounded_idempotency_key(self.idempotency_key)?,
            self.main.into_node()?,
            parse_digest(&self.main_certificate_sha256)?,
            self.credentials.into_credentials()?,
        )
        .map_err(pairing_activation_value_error)
    }

    // Reconstructs one validated paired-main restoration request.
    fn into_restoration(
        self,
    ) -> Result<NodePairedMainRestorationRequest, NodePrivateTransportError> {
        NodePairedMainRestorationRequest::new(
            bounded_idempotency_key(self.idempotency_key)?,
            self.main.into_node()?,
            parse_digest(&self.main_certificate_sha256)?,
            self.credentials.into_credentials()?,
        )
        .map_err(pairing_activation_value_error)
    }
}

// Stores one verified local role snapshot and its atomic transaction disposition.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingAuthorityReceipt {
    local: WireNode,
    disposition: String,
}

impl WirePairingAuthorityReceipt {
    // Projects one verified authority receipt without database revision detail.
    fn from_receipt(receipt: &NodePairingAuthorityReceipt) -> Self {
        Self {
            local: WireNode::from_node(receipt.local()),
            disposition: match receipt.disposition() {
                NodePairingAuthorityDisposition::Applied => "applied",
                NodePairingAuthorityDisposition::Replayed => "replayed",
            }
            .to_string(),
        }
    }

    // Reconstructs only one closed transaction disposition and valid Node snapshot.
    fn into_receipt(self) -> Result<NodePairingAuthorityReceipt, NodePrivateTransportError> {
        let disposition = match self.disposition.as_str() {
            "applied" => NodePairingAuthorityDisposition::Applied,
            "replayed" => NodePairingAuthorityDisposition::Replayed,
            _ => return Err(invalid("pairing authority disposition is invalid")),
        };
        let local = self.local.into_node()?;
        if local.state() != NodeState::Active {
            return Err(invalid("pairing authority local node is not active"));
        }
        Ok(NodePairingAuthorityReceipt::restore(local, disposition))
    }
}

impl WirePairingCredentials {
    // Projects one typed public trust package into canonical base64 wire values.
    fn from_credentials(credentials: &NodePairingCredentials) -> Self {
        Self {
            main_public_key_base64: BASE64.encode(credentials.main_public_key()),
            main_ca_certificate_base64: BASE64.encode(credentials.main_ca_certificate()),
            child_certificate_base64: BASE64.encode(credentials.child_certificate()),
            membership_signature_base64: BASE64.encode(credentials.membership_signature()),
            child_leaf_sha256: credentials.child_leaf_sha256().as_str().to_string(),
            valid_from_unix_milliseconds: credentials.valid_from().value(),
            expires_at_unix_milliseconds: credentials.expires_at().value(),
        }
    }

    // Reconstructs one bounded trust package only from canonical base64 and exact identities.
    fn into_credentials(self) -> Result<NodePairingCredentials, NodePrivateTransportError> {
        NodePairingCredentials::new(
            decode_base64(&self.main_public_key_base64)?,
            decode_base64(&self.main_ca_certificate_base64)?,
            decode_base64(&self.child_certificate_base64)?,
            decode_base64(&self.membership_signature_base64)?,
            parse_digest(&self.child_leaf_sha256)?,
            UnixMilliseconds::new(self.valid_from_unix_milliseconds),
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
        )
        .map_err(pairing_value_error)
    }
}

// Stores one completed enrollment as status plus the exact public trust package.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingEnrollment {
    status: WirePairingStatus,
    credentials: WirePairingCredentials,
}

impl WirePairingEnrollment {
    // Projects one typed completed enrollment into its two owned wire values.
    fn from_enrollment(enrollment: &NodePairingEnrollment) -> Self {
        Self {
            status: WirePairingStatus::from_status(enrollment.status()),
            credentials: WirePairingCredentials::from_credentials(enrollment.credentials()),
        }
    }

    // Reconstructs one coherent enrollment after validating status and trust together.
    fn into_enrollment(self) -> Result<NodePairingEnrollment, NodePrivateTransportError> {
        NodePairingEnrollment::new(
            self.status.into_status()?,
            self.credentials.into_credentials()?,
        )
        .map_err(pairing_value_error)
    }
}

// Stores one closed catalog query without accepting an alternate policy or unsigned source.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogListRequest {
    catalog_source: Option<String>,
    logical_model: Option<String>,
    versions: String,
    targets: String,
    refresh: String,
}

impl WireCatalogListRequest {
    // Projects one typed catalog query into exact closed wire names.
    fn from_request(request: &NodeCatalogListRequest) -> Self {
        Self {
            catalog_source: request.catalog_source().map(str::to_string),
            logical_model: request
                .logical_model()
                .map(|model| model.as_str().to_string()),
            versions: match request.versions() {
                NodeCatalogVersionSelection::Latest => "latest",
                NodeCatalogVersionSelection::All => "all",
            }
            .to_string(),
            targets: match request.targets() {
                NodeCatalogTargetSelection::Compatible => "compatible",
                NodeCatalogTargetSelection::All => "all",
            }
            .to_string(),
            refresh: match request.refresh() {
                NodeCatalogRefreshPolicy::Cached => "cached",
                NodeCatalogRefreshPolicy::Refresh => "refresh",
            }
            .to_string(),
        }
    }

    // Reconstructs one typed query after validating every identity and closed selector.
    fn into_request(self) -> Result<NodeCatalogListRequest, NodePrivateTransportError> {
        NodeCatalogListRequest::new(
            self.catalog_source,
            self.logical_model
                .map(|model| LogicalModelName::parse(&model).map_err(interface_error))
                .transpose()?,
            match self.versions.as_str() {
                "latest" => NodeCatalogVersionSelection::Latest,
                "all" => NodeCatalogVersionSelection::All,
                _ => return Err(invalid("catalog version selection is invalid")),
            },
            match self.targets.as_str() {
                "compatible" => NodeCatalogTargetSelection::Compatible,
                "all" => NodeCatalogTargetSelection::All,
                _ => return Err(invalid("catalog target selection is invalid")),
            },
            match self.refresh.as_str() {
                "cached" => NodeCatalogRefreshPolicy::Cached,
                "refresh" => NodeCatalogRefreshPolicy::Refresh,
                _ => return Err(invalid("catalog refresh policy is invalid")),
            },
        )
        .map_err(|_| invalid("catalog request is invalid"))
    }
}

// Stores the exact signed snapshot identity behind one catalog listing.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogSnapshot {
    source: String,
    catalog_sha256: String,
    revocations_sha256: String,
    revocation_sequence: u64,
    verified_at_unix: u64,
    stale: bool,
}

impl WireCatalogSnapshot {
    // Projects one verified snapshot into its exact bounded wire fields.
    fn from_snapshot(snapshot: &NodeCatalogSnapshot) -> Self {
        Self {
            source: snapshot.source().to_string(),
            catalog_sha256: snapshot.catalog_sha256().as_str().to_string(),
            revocations_sha256: snapshot.revocations_sha256().as_str().to_string(),
            revocation_sequence: snapshot.revocation_sequence(),
            verified_at_unix: snapshot.verified_at_unix(),
            stale: snapshot.is_stale(),
        }
    }

    // Reconstructs one verified snapshot identity without trusting unbounded wire text.
    fn into_snapshot(self) -> Result<NodeCatalogSnapshot, NodePrivateTransportError> {
        NodeCatalogSnapshot::new(
            self.source,
            parse_digest(&self.catalog_sha256)?,
            parse_digest(&self.revocations_sha256)?,
            self.revocation_sequence,
            self.verified_at_unix,
            self.stale,
        )
        .map_err(|_| invalid("catalog snapshot is invalid"))
    }
}

// Stores one structured signed catalog author.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogAuthor {
    login: String,
    numeric_id: u64,
    kind: String,
}

impl WireCatalogAuthor {
    // Projects one validated author without flattening its account kind.
    fn from_author(author: &NodeCatalogAuthor) -> Self {
        Self {
            login: author.login().to_string(),
            numeric_id: author.numeric_id(),
            kind: match author.kind() {
                NodeCatalogAuthorKind::User => "user",
                NodeCatalogAuthorKind::Organization => "organization",
            }
            .to_string(),
        }
    }

    // Reconstructs one bounded structured author.
    fn into_author(self) -> Result<NodeCatalogAuthor, NodePrivateTransportError> {
        NodeCatalogAuthor::new(
            self.login,
            self.numeric_id,
            match self.kind.as_str() {
                "user" => NodeCatalogAuthorKind::User,
                "organization" => NodeCatalogAuthorKind::Organization,
                _ => return Err(invalid("catalog author kind is invalid")),
            },
        )
        .map_err(|_| invalid("catalog author is invalid"))
    }
}

// Stores one user-relevant active signed catalog release.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogEntry {
    logical_model: String,
    target_id: String,
    candidate_id: String,
    version: String,
    runtime_source: String,
    engine: String,
    model_uri: String,
    authors: Vec<WireCatalogAuthor>,
    license: String,
    evidence_label: String,
    verification_method: String,
    benchmark_score: Option<f64>,
    recommended: bool,
}

impl WireCatalogEntry {
    // Projects one validated signed release into exact private fields.
    fn from_entry(entry: &NodeCatalogEntry) -> Self {
        Self {
            logical_model: entry.logical_model().as_str().to_string(),
            target_id: entry.target_id().as_str().to_string(),
            candidate_id: entry.candidate_id().as_str().to_string(),
            version: entry.version().to_string(),
            runtime_source: entry.runtime_source().to_string(),
            engine: entry.engine().as_str().to_string(),
            model_uri: entry.model_uri().to_string(),
            authors: entry
                .authors()
                .iter()
                .map(WireCatalogAuthor::from_author)
                .collect(),
            license: entry.license().to_string(),
            evidence_label: evidence_label_name(entry.evidence_label()).to_string(),
            verification_method: entry.verification_method().to_string(),
            benchmark_score: entry.benchmark_score(),
            recommended: entry.is_recommended(),
        }
    }

    // Reconstructs one bounded signed release projection and all nested authors.
    fn into_entry(self) -> Result<NodeCatalogEntry, NodePrivateTransportError> {
        NodeCatalogEntry::new(
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            TargetId::parse(&self.target_id).map_err(interface_error)?,
            RuntimeCandidateId::parse(&self.candidate_id).map_err(interface_error)?,
            self.version,
            self.runtime_source,
            TechnicalName::parse(&self.engine).map_err(interface_error)?,
            self.model_uri,
            self.authors
                .into_iter()
                .map(WireCatalogAuthor::into_author)
                .collect::<Result<Vec<_>, _>>()?,
            self.license,
            evidence_label(&self.evidence_label)?,
            self.verification_method,
            self.benchmark_score,
            self.recommended,
        )
        .map_err(|_| invalid("catalog entry is invalid"))
    }
}

// Stores one complete verified catalog result through a single private response variant.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogListing {
    snapshot: WireCatalogSnapshot,
    entries: Vec<WireCatalogEntry>,
}

impl WireCatalogListing {
    // Projects one validated listing into exact snapshot and ordered entry fields.
    fn from_listing(listing: &NodeCatalogListing) -> Self {
        Self {
            snapshot: WireCatalogSnapshot::from_snapshot(listing.snapshot()),
            entries: listing
                .entries()
                .iter()
                .map(WireCatalogEntry::from_entry)
                .collect(),
        }
    }

    // Reconstructs one bounded listing and rejects duplicate exact release identities.
    fn into_listing(self) -> Result<NodeCatalogListing, NodePrivateTransportError> {
        NodeCatalogListing::new(
            self.snapshot.into_snapshot()?,
            self.entries
                .into_iter()
                .map(WireCatalogEntry::into_entry)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| invalid("catalog listing is invalid"))
    }
}

// Stores one compatible signed target without copying a complete catalog release document.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogTarget {
    logical_model: String,
    target_id: String,
    candidate_id: String,
    recommended: bool,
}

impl WireCatalogTarget {
    // Projects one manager-validated compatible target into its exact wire fields.
    fn from_target(target: &NodeCatalogTarget) -> Self {
        Self {
            logical_model: target.logical_model().as_str().to_string(),
            target_id: target.target_id().as_str().to_string(),
            candidate_id: target.candidate_id().as_str().to_string(),
            recommended: target.is_recommended(),
        }
    }

    // Reconstructs one typed compatible target without re-running catalog judgment.
    fn into_target(self) -> Result<NodeCatalogTarget, NodePrivateTransportError> {
        Ok(NodeCatalogTarget::new(
            LogicalModelName::parse(&self.logical_model).map_err(interface_error)?,
            TargetId::parse(&self.target_id).map_err(interface_error)?,
            RuntimeCandidateId::parse(&self.candidate_id).map_err(interface_error)?,
            self.recommended,
        ))
    }
}

// Stores one explicit section availability state without replacing absence with defaults.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireHostProjectionValue<Value> {
    Available(Value),
    Unavailable,
    NotApplicable,
}

// Stores every host and model summary required by one CLI read.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostInventory {
    local_node_id: String,
    hosts: Vec<WireHostSnapshot>,
    model_services: WireHostProjectionValue<Vec<WireModelServiceSummary>>,
}

impl WireHostInventory {
    // Projects one validated inventory into its closed private wire shape.
    fn from_inventory(inventory: &NodeHostInventory) -> Result<Self, NodePrivateTransportError> {
        Ok(Self {
            local_node_id: inventory.local_node_id().as_str().to_string(),
            hosts: inventory
                .hosts()
                .iter()
                .map(WireHostSnapshot::from_snapshot)
                .collect::<Result<Vec<_>, _>>()?,
            model_services: wire_host_projection_value(inventory.model_services(), |services| {
                Ok(services
                    .iter()
                    .map(WireModelServiceSummary::from_summary)
                    .collect())
            })?,
        })
    }

    // Reconstructs one bounded inventory through its typed cross-section validator.
    fn into_inventory(self) -> Result<NodeHostInventory, NodePrivateTransportError> {
        NodeHostInventory::new(
            NodeId::parse(&self.local_node_id).map_err(interface_error)?,
            self.hosts
                .into_iter()
                .map(WireHostSnapshot::into_snapshot)
                .collect::<Result<Vec<_>, _>>()?,
            host_projection_value(self.model_services, |services| {
                services
                    .into_iter()
                    .map(WireModelServiceSummary::into_summary)
                    .collect::<Result<Vec<_>, _>>()
            })?,
        )
        .map_err(host_value_error)
    }
}

// Stores one wire-safe host read with explicit availability for every independent section.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostSnapshot {
    node: WireNode,
    hardware: WireHostProjectionValue<Value>,
    placement_groups: WireHostProjectionValue<Vec<WireHostPlacementGroup>>,
    verified_links: WireHostProjectionValue<Vec<WireHostLink>>,
    protection: WireHostProjectionValue<WireHostProtection>,
    gateway: WireHostProjectionValue<WireHostGateway>,
    watchdog: WireHostProjectionValue<WireHostWatchdog>,
}

impl WireHostSnapshot {
    // Projects one redacted host read without exposing endpoint credential references.
    fn from_snapshot(snapshot: &NodeHostSnapshot) -> Result<Self, NodePrivateTransportError> {
        Ok(Self {
            node: WireNode::from_node(snapshot.node()),
            hardware: wire_host_projection_value(snapshot.hardware(), wire_hardware_observation)?,
            placement_groups: wire_host_projection_value(snapshot.placement_groups(), |groups| {
                Ok(groups
                    .iter()
                    .map(WireHostPlacementGroup::from_group)
                    .collect())
            })?,
            verified_links: wire_host_projection_value(snapshot.verified_links(), |links| {
                Ok(links.iter().map(WireHostLink::from_link).collect())
            })?,
            protection: wire_host_projection_value(snapshot.protection(), |summary| {
                Ok(WireHostProtection::from_summary(summary))
            })?,
            gateway: wire_host_projection_value(snapshot.gateway(), |summary| {
                Ok(WireHostGateway::from_summary(summary))
            })?,
            watchdog: wire_host_projection_value(snapshot.watchdog(), |summary| {
                Ok(WireHostWatchdog::from_summary(summary))
            })?,
        })
    }

    // Reconstructs one host read while rechecking node, placement, hardware, and link scope.
    fn into_snapshot(self) -> Result<NodeHostSnapshot, NodePrivateTransportError> {
        NodeHostSnapshot::restore(
            self.node.into_node()?,
            host_projection_value(self.hardware, hardware_observation)?,
            host_projection_value(self.placement_groups, |groups| {
                groups
                    .into_iter()
                    .map(WireHostPlacementGroup::into_group)
                    .collect::<Result<Vec<_>, _>>()
            })?,
            host_projection_value(self.verified_links, |links| {
                links
                    .into_iter()
                    .map(WireHostLink::into_link)
                    .collect::<Result<Vec<_>, _>>()
            })?,
            host_projection_value(self.protection, WireHostProtection::into_summary)?,
            host_projection_value(self.gateway, WireHostGateway::into_summary)?,
            host_projection_value(self.watchdog, WireHostWatchdog::into_summary)?,
        )
        .map_err(host_value_error)
    }
}

// Stores one redacted placement group and every required opaque placement.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostPlacementGroup {
    placement_group_id: String,
    service_id: String,
    runtime_candidate_id: String,
    runtime_version: String,
    target_id: String,
    desired_state: String,
    state: String,
    endpoint: Option<WireHostEndpoint>,
    placements: Vec<WireHostPlacement>,
}

impl WireHostPlacementGroup {
    // Projects one validated redacted placement group into stable wire fields.
    fn from_group(group: &NodeHostPlacementGroupSnapshot) -> Self {
        Self {
            placement_group_id: group.placement_group_id().as_str().to_string(),
            service_id: group.service_id().as_str().to_string(),
            runtime_candidate_id: group.runtime_candidate_id().as_str().to_string(),
            runtime_version: group.runtime_version().as_str().to_string(),
            target_id: group.target_id().as_str().to_string(),
            desired_state: model_desired_state_name(group.desired_state()).to_string(),
            state: host_group_state_name(group.state()).to_string(),
            endpoint: group.endpoint().map(WireHostEndpoint::from_endpoint),
            placements: group
                .placements()
                .iter()
                .map(WireHostPlacement::from_placement)
                .collect(),
        }
    }

    // Reconstructs one redacted placement group and rechecks endpoint membership.
    fn into_group(self) -> Result<NodeHostPlacementGroupSnapshot, NodePrivateTransportError> {
        NodeHostPlacementGroupSnapshot::restore(
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            ModelServiceId::parse(&self.service_id).map_err(interface_error)?,
            RuntimeCandidateId::parse(&self.runtime_candidate_id).map_err(interface_error)?,
            RuntimeVersion::parse(&self.runtime_version).map_err(interface_error)?,
            TargetId::parse(&self.target_id).map_err(interface_error)?,
            model_desired_state(&self.desired_state)?,
            host_group_state(&self.state)?,
            self.endpoint
                .map(WireHostEndpoint::into_endpoint)
                .transpose()?,
            self.placements
                .into_iter()
                .map(WireHostPlacement::into_placement)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(host_value_error)
    }
}

// Stores one redacted endpoint without credential or token-count references.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostEndpoint {
    placement_id: String,
    node_id: String,
    scheme: String,
    host: String,
    port: u16,
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<i32>,
}

impl WireHostEndpoint {
    // Projects one redacted endpoint into its exact private wire fields.
    fn from_endpoint(endpoint: &NodeHostEndpointSnapshot) -> Self {
        Self {
            placement_id: endpoint.placement_id().as_str().to_string(),
            node_id: endpoint.node_id().as_str().to_string(),
            scheme: host_endpoint_scheme_name(endpoint.address().scheme()).to_string(),
            host: endpoint.address().host().as_str().to_string(),
            port: endpoint.address().port(),
            healthy: endpoint.is_healthy(),
            memory_pressure: endpoint.has_memory_pressure(),
            temperature_millicelsius: endpoint.temperature_millicelsius(),
        }
    }

    // Reconstructs one validated redacted endpoint without credential material.
    fn into_endpoint(self) -> Result<NodeHostEndpointSnapshot, NodePrivateTransportError> {
        NodeHostEndpointSnapshot::restore(
            PlacementId::parse(&self.placement_id).map_err(interface_error)?,
            NodeId::parse(&self.node_id).map_err(interface_error)?,
            EndpointAddress::new(
                host_endpoint_scheme(&self.scheme)?,
                NodeAddress::parse(&self.host).map_err(interface_error)?,
                self.port,
            )
            .map_err(interface_error)?,
            self.healthy,
            self.memory_pressure,
            self.temperature_millicelsius,
        )
        .map_err(host_value_error)
    }
}

// Stores one opaque placement and its exact Core-owned resource assignment.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostPlacement {
    placement_id: String,
    placement_group_id: String,
    node_id: String,
    runtime_installation_id: String,
    task_id: String,
    port_base: u16,
    port_count: u16,
    device_ids: Vec<String>,
    rdma_interface: Option<String>,
    endpoint_ownership: String,
    state: String,
}

impl WireHostPlacement {
    // Projects one redacted placement into stable resource and lifecycle fields.
    fn from_placement(placement: &NodeHostPlacementSnapshot) -> Self {
        Self {
            placement_id: placement.placement_id().as_str().to_string(),
            placement_group_id: placement.placement_group_id().as_str().to_string(),
            node_id: placement.node_id().as_str().to_string(),
            runtime_installation_id: placement.runtime_installation_id().as_str().to_string(),
            task_id: placement.task_id().as_str().to_string(),
            port_base: placement.resources().ports().base(),
            port_count: placement.resources().ports().count(),
            device_ids: placement
                .resources()
                .device_ids()
                .iter()
                .map(|identity| identity.as_str().to_string())
                .collect(),
            rdma_interface: placement
                .resources()
                .rdma_interface()
                .map(|value| value.as_str().to_string()),
            endpoint_ownership: host_endpoint_ownership_name(placement.endpoint_ownership())
                .to_string(),
            state: host_placement_state_name(placement.state()).to_string(),
        }
    }

    // Reconstructs one typed placement after validating every identity and resource.
    fn into_placement(self) -> Result<NodeHostPlacementSnapshot, NodePrivateTransportError> {
        Ok(NodeHostPlacementSnapshot::restore(
            PlacementId::parse(&self.placement_id).map_err(interface_error)?,
            PlacementGroupId::parse(&self.placement_group_id).map_err(interface_error)?,
            NodeId::parse(&self.node_id).map_err(interface_error)?,
            RuntimeInstallationId::parse(&self.runtime_installation_id).map_err(interface_error)?,
            TaskId::parse(&self.task_id).map_err(interface_error)?,
            PlacementResources::new(
                PortRange::new(self.port_base, self.port_count).map_err(interface_error)?,
                self.device_ids
                    .into_iter()
                    .map(|value| DeviceId::parse(&value).map_err(interface_error))
                    .collect::<Result<Vec<_>, _>>()?,
                self.rdma_interface
                    .map(|value| NetworkInterfaceName::parse(&value).map_err(interface_error))
                    .transpose()?,
            )
            .map_err(interface_error)?,
            host_endpoint_ownership(&self.endpoint_ownership)?,
            host_placement_state(&self.state)?,
        ))
    }
}

// Stores one current verified model-neutral link.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostLink {
    left_node_id: String,
    right_node_id: String,
    kind: String,
    rdma: bool,
    speed_mbps: u64,
    mtu: u32,
}

impl WireHostLink {
    // Projects one validated current link into stable wire fields.
    fn from_link(link: &PlacementLink) -> Self {
        Self {
            left_node_id: link.left_node_id().as_str().to_string(),
            right_node_id: link.right_node_id().as_str().to_string(),
            kind: host_interconnect_kind_name(link.kind()).to_string(),
            rdma: link.rdma(),
            speed_mbps: link.speed_mbps(),
            mtu: link.mtu(),
        }
    }

    // Reconstructs one current link through PlacementManager's semantic validator.
    fn into_link(self) -> Result<PlacementLink, NodePrivateTransportError> {
        PlacementLink::new(
            NodeId::parse(&self.left_node_id).map_err(interface_error)?,
            NodeId::parse(&self.right_node_id).map_err(interface_error)?,
            host_interconnect_kind(&self.kind)?,
            self.rdma,
            self.speed_mbps,
            self.mtu,
        )
        .map_err(|_| invalid("verified host link is invalid"))
    }
}

// Stores one current placement-protection result.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostProtection {
    state: String,
    observed_at_unix_milliseconds: u64,
}

impl WireHostProtection {
    // Projects one typed protection result into stable wire fields.
    fn from_summary(summary: &NodeHostProtectionSummary) -> Self {
        Self {
            state: host_protection_state_name(summary.state()).to_string(),
            observed_at_unix_milliseconds: summary.observed_at().value(),
        }
    }

    // Reconstructs one typed protection result without inventing native detail.
    fn into_summary(self) -> Result<NodeHostProtectionSummary, NodePrivateTransportError> {
        Ok(NodeHostProtectionSummary::new(
            host_protection_state(&self.state)?,
            UnixMilliseconds::new(self.observed_at_unix_milliseconds),
        ))
    }
}

// Stores one Gateway readiness result and optional bounded counters.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostGateway {
    state: String,
    telemetry: Option<WireHostGatewayTelemetry>,
}

impl WireHostGateway {
    // Projects one Gateway result without route or credential identities.
    fn from_summary(summary: &NodeHostGatewaySummary) -> Self {
        Self {
            state: host_service_state_name(summary.state()).to_string(),
            telemetry: summary
                .telemetry()
                .map(WireHostGatewayTelemetry::from_summary),
        }
    }

    // Reconstructs one Gateway result from already bounded primitive counters.
    fn into_summary(self) -> Result<NodeHostGatewaySummary, NodePrivateTransportError> {
        Ok(NodeHostGatewaySummary::new(
            host_service_state(&self.state)?,
            self.telemetry.map(WireHostGatewayTelemetry::into_summary),
        ))
    }
}

// Stores the bounded Gateway counters used by status and diagnosis.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostGatewayTelemetry {
    observed_at_unix_milliseconds: u64,
    active_requests: u64,
    queued_requests: u64,
    requests_completed: u64,
    requests_failed: u64,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
}

impl WireHostGatewayTelemetry {
    // Projects one typed Gateway counter snapshot into exact wire fields.
    fn from_summary(summary: &NodeHostGatewayTelemetrySummary) -> Self {
        Self {
            observed_at_unix_milliseconds: summary.observed_at().value(),
            active_requests: summary.active_requests(),
            queued_requests: summary.queued_requests(),
            requests_completed: summary.requests_completed(),
            requests_failed: summary.requests_failed(),
            input_tokens: summary.input_tokens(),
            output_tokens: summary.output_tokens(),
            cached_tokens: summary.cached_tokens(),
        }
    }

    // Reconstructs one typed Gateway counter snapshot without applying policy.
    fn into_summary(self) -> NodeHostGatewayTelemetrySummary {
        NodeHostGatewayTelemetrySummary::new(
            UnixMilliseconds::new(self.observed_at_unix_milliseconds),
            self.active_requests,
            self.queued_requests,
            self.requests_completed,
            self.requests_failed,
            self.input_tokens,
            self.output_tokens,
            self.cached_tokens,
        )
    }
}

// Stores one Watchdog readiness result and optional bounded host telemetry.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostWatchdog {
    state: String,
    telemetry: Option<WireHostWatchdogTelemetry>,
}

impl WireHostWatchdog {
    // Projects one Watchdog result without native lease or process identity.
    fn from_summary(summary: &NodeHostWatchdogSummary) -> Self {
        Self {
            state: host_service_state_name(summary.state()).to_string(),
            telemetry: summary
                .telemetry()
                .map(WireHostWatchdogTelemetry::from_summary),
        }
    }

    // Reconstructs one Watchdog result while validating optional utilization bounds.
    fn into_summary(self) -> Result<NodeHostWatchdogSummary, NodePrivateTransportError> {
        Ok(NodeHostWatchdogSummary::new(
            host_service_state(&self.state)?,
            self.telemetry
                .map(WireHostWatchdogTelemetry::into_summary)
                .transpose()?,
        ))
    }
}

// Stores the bounded Watchdog host metrics used by status and diagnosis.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHostWatchdogTelemetry {
    observed_at_unix_milliseconds: u64,
    cpu_percent: Option<u8>,
    gpu_percent: Option<u8>,
    memory_percent: Option<u8>,
    disk_percent: Option<u8>,
    gpu_memory_percent: Option<u8>,
    active_requests: u32,
    queued_requests: u32,
}

impl WireHostWatchdogTelemetry {
    // Projects one typed Watchdog telemetry snapshot into exact wire fields.
    fn from_summary(summary: &NodeHostWatchdogTelemetrySummary) -> Self {
        Self {
            observed_at_unix_milliseconds: summary.observed_at().value(),
            cpu_percent: summary.cpu_percent(),
            gpu_percent: summary.gpu_percent(),
            memory_percent: summary.memory_percent(),
            disk_percent: summary.disk_percent(),
            gpu_memory_percent: summary.gpu_memory_percent(),
            active_requests: summary.active_requests(),
            queued_requests: summary.queued_requests(),
        }
    }

    // Reconstructs one typed Watchdog telemetry snapshot through its bound validator.
    fn into_summary(self) -> Result<NodeHostWatchdogTelemetrySummary, NodePrivateTransportError> {
        NodeHostWatchdogTelemetrySummary::new(
            UnixMilliseconds::new(self.observed_at_unix_milliseconds),
            self.cpu_percent,
            self.gpu_percent,
            self.memory_percent,
            self.disk_percent,
            self.gpu_memory_percent,
            self.active_requests,
            self.queued_requests,
        )
        .map_err(host_value_error)
    }
}

// Projects one generic typed availability section into its wire representation.
fn wire_host_projection_value<Value, WireValue>(
    value: &NodeHostProjectionValue<Value>,
    project: impl FnOnce(&Value) -> Result<WireValue, NodePrivateTransportError>,
) -> Result<WireHostProjectionValue<WireValue>, NodePrivateTransportError> {
    match value {
        NodeHostProjectionValue::Available(value) => {
            project(value).map(WireHostProjectionValue::Available)
        }
        NodeHostProjectionValue::Unavailable => Ok(WireHostProjectionValue::Unavailable),
        NodeHostProjectionValue::NotApplicable => Ok(WireHostProjectionValue::NotApplicable),
    }
}

// Reconstructs one generic typed availability section from its closed wire representation.
fn host_projection_value<WireValue, Value>(
    value: WireHostProjectionValue<WireValue>,
    restore: impl FnOnce(WireValue) -> Result<Value, NodePrivateTransportError>,
) -> Result<NodeHostProjectionValue<Value>, NodePrivateTransportError> {
    match value {
        WireHostProjectionValue::Available(value) => {
            restore(value).map(NodeHostProjectionValue::Available)
        }
        WireHostProjectionValue::Unavailable => Ok(NodeHostProjectionValue::Unavailable),
        WireHostProjectionValue::NotApplicable => Ok(NodeHostProjectionValue::NotApplicable),
    }
}

// Stores one complete node snapshot without leaking persistence fields.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireNode {
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    state: String,
    control_address: String,
    latest_hardware_observation_id: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl WireNode {
    // Projects one immutable node snapshot into exact wire fields.
    fn from_node(node: &Node) -> Self {
        Self {
            node_id: node.identity().node_id().as_str().to_string(),
            machine_id: node.identity().machine_id().as_str().to_string(),
            installation_id: node.identity().installation_id().as_str().to_string(),
            display_name: node.display_name().as_str().to_string(),
            role: node_role_name(node.role()).to_string(),
            state: node_state_name(node.state()).to_string(),
            control_address: node.control_address().as_str().to_string(),
            latest_hardware_observation_id: node
                .latest_hardware_observation_id()
                .map(|identity| identity.as_str().to_string()),
            created_at_unix_milliseconds: node.timestamps().created_at().value(),
            updated_at_unix_milliseconds: node.timestamps().updated_at().value(),
        }
    }

    // Reconstructs one validated immutable node snapshot.
    fn into_node(self) -> Result<Node, NodePrivateTransportError> {
        Ok(Node::new(
            NodeIdentity::new(
                NodeId::parse(&self.node_id).map_err(interface_error)?,
                MachineId::parse(&self.machine_id).map_err(interface_error)?,
                InstallationId::parse(&self.installation_id).map_err(interface_error)?,
            ),
            DisplayName::parse(&self.display_name).map_err(interface_error)?,
            node_role(&self.role)?,
            node_state(&self.state)?,
            NodeAddress::parse(&self.control_address).map_err(interface_error)?,
            self.latest_hardware_observation_id
                .map(|value| HardwareObservationId::parse(&value).map_err(interface_error))
                .transpose()?,
            EntityTimestamps::new(
                UnixMilliseconds::new(self.created_at_unix_milliseconds),
                UnixMilliseconds::new(self.updated_at_unix_milliseconds),
            )
            .map_err(interface_error)?,
        ))
    }
}

// Stores one node mutation with its optimistic revision and optional event.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireNodeChange {
    node: WireNode,
    revision: u64,
    event: Option<WireNodeEvent>,
}

impl WireNodeChange {
    // Projects one manager change into exact response fields.
    fn from_change(change: &NodeManagerChange<Node>) -> Self {
        Self {
            node: WireNode::from_node(change.value()),
            revision: change.revision(),
            event: change.event().map(WireNodeEvent::from_event),
        }
    }

    // Reconstructs one manager change without replaying its mutation.
    fn into_change(self) -> Result<NodeManagerChange<Node>, NodePrivateTransportError> {
        Ok(NodeManagerChange::committed(
            self.node.into_node()?,
            self.revision,
            self.event.map(WireNodeEvent::into_event).transpose()?,
        ))
    }
}

// Stores every closed NodeManager event variant.
#[derive(Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum WireNodeEvent {
    NodeInitialized { node_id: String },
    NodeEnrolled { node_id: String },
    NodeActivated { node_id: String },
    NodePaused { node_id: String },
    NodeMarkedOffline { node_id: String },
    NodeRemoved { node_id: String },
    LocalRoleChanged { node_id: String, role: String },
    HardwareRecorded { observation_id: String },
    ModelServiceCreated { service_id: String },
    ModelServiceUpdated { service_id: String },
    ModelServiceRemoved { service_id: String },
    OperationBegan { operation_id: String },
    OperationStarted { operation_id: String },
    OperationSucceeded { operation_id: String },
    OperationFailed { operation_id: String },
    OperationCancelled { operation_id: String },
}

impl WireNodeEvent {
    // Projects one completed manager event into its closed wire variant.
    fn from_event(event: &NodeManagerEvent) -> Self {
        match event {
            NodeManagerEvent::NodeInitialized { node_id } => Self::NodeInitialized {
                node_id: node_id.as_str().to_string(),
            },
            NodeManagerEvent::NodeEnrolled { node_id } => Self::NodeEnrolled {
                node_id: node_id.as_str().to_string(),
            },
            NodeManagerEvent::NodeActivated { node_id } => Self::NodeActivated {
                node_id: node_id.as_str().to_string(),
            },
            NodeManagerEvent::NodePaused { node_id } => Self::NodePaused {
                node_id: node_id.as_str().to_string(),
            },
            NodeManagerEvent::NodeMarkedOffline { node_id } => Self::NodeMarkedOffline {
                node_id: node_id.as_str().to_string(),
            },
            NodeManagerEvent::NodeRemoved { node_id } => Self::NodeRemoved {
                node_id: node_id.as_str().to_string(),
            },
            NodeManagerEvent::LocalRoleChanged { node_id, role } => Self::LocalRoleChanged {
                node_id: node_id.as_str().to_string(),
                role: node_role_name(*role).to_string(),
            },
            NodeManagerEvent::HardwareRecorded { observation_id } => Self::HardwareRecorded {
                observation_id: observation_id.as_str().to_string(),
            },
            NodeManagerEvent::ModelServiceCreated { service_id } => Self::ModelServiceCreated {
                service_id: service_id.as_str().to_string(),
            },
            NodeManagerEvent::ModelServiceUpdated { service_id } => Self::ModelServiceUpdated {
                service_id: service_id.as_str().to_string(),
            },
            NodeManagerEvent::ModelServiceRemoved { service_id } => Self::ModelServiceRemoved {
                service_id: service_id.as_str().to_string(),
            },
            NodeManagerEvent::OperationBegan { operation_id } => Self::OperationBegan {
                operation_id: operation_id.as_str().to_string(),
            },
            NodeManagerEvent::OperationStarted { operation_id } => Self::OperationStarted {
                operation_id: operation_id.as_str().to_string(),
            },
            NodeManagerEvent::OperationSucceeded { operation_id } => Self::OperationSucceeded {
                operation_id: operation_id.as_str().to_string(),
            },
            NodeManagerEvent::OperationFailed { operation_id } => Self::OperationFailed {
                operation_id: operation_id.as_str().to_string(),
            },
            NodeManagerEvent::OperationCancelled { operation_id } => Self::OperationCancelled {
                operation_id: operation_id.as_str().to_string(),
            },
        }
    }

    // Reconstructs one completed manager event from its closed wire variant.
    fn into_event(self) -> Result<NodeManagerEvent, NodePrivateTransportError> {
        Ok(match self {
            Self::NodeInitialized { node_id } => NodeManagerEvent::NodeInitialized {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            },
            Self::NodeEnrolled { node_id } => NodeManagerEvent::NodeEnrolled {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            },
            Self::NodeActivated { node_id } => NodeManagerEvent::NodeActivated {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            },
            Self::NodePaused { node_id } => NodeManagerEvent::NodePaused {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            },
            Self::NodeMarkedOffline { node_id } => NodeManagerEvent::NodeMarkedOffline {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            },
            Self::NodeRemoved { node_id } => NodeManagerEvent::NodeRemoved {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
            },
            Self::LocalRoleChanged { node_id, role } => NodeManagerEvent::LocalRoleChanged {
                node_id: NodeId::parse(&node_id).map_err(interface_error)?,
                role: node_role(&role)?,
            },
            Self::HardwareRecorded { observation_id } => NodeManagerEvent::HardwareRecorded {
                observation_id: HardwareObservationId::parse(&observation_id)
                    .map_err(interface_error)?,
            },
            Self::ModelServiceCreated { service_id } => NodeManagerEvent::ModelServiceCreated {
                service_id: li_core_interface::ModelServiceId::parse(&service_id)
                    .map_err(interface_error)?,
            },
            Self::ModelServiceUpdated { service_id } => NodeManagerEvent::ModelServiceUpdated {
                service_id: li_core_interface::ModelServiceId::parse(&service_id)
                    .map_err(interface_error)?,
            },
            Self::ModelServiceRemoved { service_id } => NodeManagerEvent::ModelServiceRemoved {
                service_id: li_core_interface::ModelServiceId::parse(&service_id)
                    .map_err(interface_error)?,
            },
            Self::OperationBegan { operation_id } => NodeManagerEvent::OperationBegan {
                operation_id: OperationId::parse(&operation_id).map_err(interface_error)?,
            },
            Self::OperationStarted { operation_id } => NodeManagerEvent::OperationStarted {
                operation_id: OperationId::parse(&operation_id).map_err(interface_error)?,
            },
            Self::OperationSucceeded { operation_id } => NodeManagerEvent::OperationSucceeded {
                operation_id: OperationId::parse(&operation_id).map_err(interface_error)?,
            },
            Self::OperationFailed { operation_id } => NodeManagerEvent::OperationFailed {
                operation_id: OperationId::parse(&operation_id).map_err(interface_error)?,
            },
            Self::OperationCancelled { operation_id } => NodeManagerEvent::OperationCancelled {
                operation_id: OperationId::parse(&operation_id).map_err(interface_error)?,
            },
        })
    }
}

// Stores one durable outbox event and its optimistic revision.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireVersionedOutboxEvent {
    event_id: String,
    kind: String,
    entity_id: String,
    occurred_at_unix_milliseconds: u64,
    state: String,
    acknowledged_at_unix_milliseconds: Option<u64>,
    revision: u64,
}

impl WireVersionedOutboxEvent {
    // Projects one versioned outbox snapshot into exact wire fields.
    fn from_event(event: &VersionedNodeOutboxEvent) -> Self {
        Self {
            event_id: event.event().event_id().as_str().to_string(),
            kind: event.event().kind().as_str().to_string(),
            entity_id: event.event().entity_id().to_string(),
            occurred_at_unix_milliseconds: event.event().occurred_at().value(),
            state: outbox_state_name(event.event().state()).to_string(),
            acknowledged_at_unix_milliseconds: event
                .event()
                .acknowledged_at()
                .map(UnixMilliseconds::value),
            revision: event.revision(),
        }
    }

    // Reconstructs one validated versioned outbox snapshot.
    fn into_event(self) -> Result<VersionedNodeOutboxEvent, NodePrivateTransportError> {
        Ok(VersionedNodeOutboxEvent::new(
            NodeOutboxEvent::new(
                parse_digest(&self.event_id)?,
                TechnicalName::parse(&self.kind).map_err(interface_error)?,
                self.entity_id,
                UnixMilliseconds::new(self.occurred_at_unix_milliseconds),
                outbox_state(&self.state)?,
                self.acknowledged_at_unix_milliseconds
                    .map(UnixMilliseconds::new),
            )
            .map_err(manager_state_error)?,
            self.revision,
        ))
    }
}

// Stores one bounded stable remote failure.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRemoteError {
    code: String,
    message: String,
}

impl WireRemoteError {
    // Projects one stable remote failure into exact wire fields.
    fn from_error(error: &NodePrivateRemoteError) -> Self {
        Self {
            code: error.code().as_str().to_string(),
            message: error.message().to_string(),
        }
    }

    // Reconstructs one bounded stable remote failure.
    fn into_error(self) -> Result<NodePrivateRemoteError, NodePrivateTransportError> {
        NodePrivateRemoteError::new(
            TechnicalName::parse(&self.code).map_err(interface_error)?,
            &self.message,
        )
    }
}

// Projects one HardwareManager document without duplicating its closed wire vocabulary.
fn wire_hardware_observation(
    observation: &HardwareObservation,
) -> Result<Value, NodePrivateTransportError> {
    let document = encode_hardware_observation(observation)
        .map_err(|_| invalid("hardware observation could not be encoded"))?;
    serde_json::from_slice(&document)
        .map_err(|_| invalid("hardware observation encoding is invalid"))
}

// Reconstructs one HardwareManager value only through its authoritative semantic decoder.
fn hardware_observation(value: Value) -> Result<HardwareObservation, NodePrivateTransportError> {
    let document = serde_json::to_vec(&value)
        .map_err(|_| invalid("hardware observation could not be encoded"))?;
    decode_hardware_observation(&document).map_err(|_| invalid("hardware observation is invalid"))
}

// Encodes one bounded canonical JSON document.
fn encode_document<Value: Serialize>(value: &Value) -> Result<Vec<u8>, NodePrivateTransportError> {
    let document =
        serde_json::to_vec(value).map_err(|_| NodePrivateTransportError::InvalidDocument {
            reason: "typed value could not be encoded",
        })?;
    if document.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateTransportError::DocumentTooLarge);
    }
    Ok(document)
}

// Decodes one bounded closed JSON document.
fn decode_document<Value: for<'de> Deserialize<'de>>(
    document: &[u8],
) -> Result<Value, NodePrivateTransportError> {
    if document.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateTransportError::DocumentTooLarge);
    }
    serde_json::from_slice(document).map_err(|_| NodePrivateTransportError::InvalidDocument {
        reason: "JSON shape or value is invalid",
    })
}

// Requires one caller replay key to remain nonempty and bounded.
fn bounded_idempotency_key(value: String) -> Result<String, NodePrivateTransportError> {
    if value.is_empty() || value.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(NodePrivateTransportError::InvalidDocument {
            reason: "idempotency key is empty or oversized",
        });
    }
    Ok(value)
}

// Reconstructs one bounded bearer without retaining rejected secret material.
fn gateway_bearer(value: &str) -> Result<NodeGatewayBearer, NodePrivateTransportError> {
    NodeGatewayBearer::parse(value).map_err(|_| invalid("Gateway bearer is invalid"))
}

// Requires one native Gateway file reference to have a stable UTF-8 wire identity.
fn gateway_path(path: &std::path::Path) -> Result<String, NodePrivateTransportError> {
    let value = path
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| invalid("Gateway native path is invalid"))?;
    if value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(invalid(
            "Gateway native path is invalid or exceeds its bound",
        ));
    }
    Ok(value)
}

// Reconstructs one bounded absolute native Gateway file reference.
fn bounded_gateway_path(value: String) -> Result<PathBuf, NodePrivateTransportError> {
    let path = PathBuf::from(value);
    if !path.is_absolute() || gateway_path(&path).is_err() {
        return Err(invalid("Gateway native path is invalid"));
    }
    Ok(path)
}

// Returns one stable usage-write disposition name.
const fn gateway_usage_disposition_name(disposition: NodeGatewayUsageDisposition) -> &'static str {
    match disposition {
        NodeGatewayUsageDisposition::Applied => "applied",
        NodeGatewayUsageDisposition::Replayed => "replayed",
    }
}

// Parses one closed usage-write disposition.
fn gateway_usage_disposition(
    value: &str,
) -> Result<NodeGatewayUsageDisposition, NodePrivateTransportError> {
    match value {
        "applied" => Ok(NodeGatewayUsageDisposition::Applied),
        "replayed" => Ok(NodeGatewayUsageDisposition::Replayed),
        _ => Err(invalid("Gateway usage disposition is invalid")),
    }
}

// Requires only the canonical public runtimes pull-request URL and one positive number.
fn bounded_pull_request_url(value: String) -> Result<String, NodePrivateTransportError> {
    let prefix = "https://github.com/letsinferlabs/runtimes/pull/";
    let valid = value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 20
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
            && suffix.parse::<u64>().ok().is_some_and(|number| number > 0)
    });
    if value.len() > 512 || !valid {
        return Err(NodePrivateTransportError::InvalidDocument {
            reason: "benchmark verification pull-request URL is invalid",
        });
    }
    Ok(value)
}

// Requires one API-key identity or display-name selector to remain canonical and bounded.
fn bounded_key_selector(value: String) -> Result<String, NodePrivateTransportError> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        return Err(NodePrivateTransportError::InvalidDocument {
            reason: "API-key selector is empty, oversized, or unsafe",
        });
    }
    Ok(value)
}

// Requires one controller identity or display-name selector to remain canonical and bounded.
fn bounded_controller_selector(value: String) -> Result<String, NodePrivateTransportError> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        return Err(invalid(
            "controller selector is empty, oversized, or unsafe",
        ));
    }
    Ok(value)
}

// Reconstructs one bounded unique selected-model list.
fn parse_models(values: Vec<String>) -> Result<Vec<LogicalModelName>, NodePrivateTransportError> {
    values
        .into_iter()
        .map(|value| LogicalModelName::parse(&value).map_err(interface_error))
        .collect()
}

// Returns whether one wire list contains no alternate duplicate representation.
fn unique_strings(values: &[String]) -> bool {
    let mut canonical = values.to_vec();
    canonical.sort();
    canonical.dedup();
    canonical.len() == values.len()
}

// Converts one optional positive 32-bit wire limit.
fn positive_u32(value: Option<u32>) -> Result<Option<NonZeroU32>, NodePrivateTransportError> {
    value
        .map(|value| {
            NonZeroU32::new(value).ok_or(NodePrivateTransportError::InvalidDocument {
                reason: "API-key policy limit must be positive",
            })
        })
        .transpose()
}

// Converts one optional positive 64-bit wire limit.
fn positive_u64(value: Option<u64>) -> Result<Option<NonZeroU64>, NodePrivateTransportError> {
    value
        .map(|value| {
            NonZeroU64::new(value).ok_or(NodePrivateTransportError::InvalidDocument {
                reason: "API-key policy limit must be positive",
            })
        })
        .transpose()
}

// Verifies one exact bearer-token shape and public identity binding without decoding its secret.
fn valid_api_token(token: &str, key_id: &ApiKeyId) -> bool {
    let Some(secret) = token.strip_prefix(&format!("li_{}_", key_id.as_str())) else {
        return false;
    };
    secret.len() == 64
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Parses one exact lowercase SHA-256 identity.
fn parse_digest(value: &str) -> Result<Sha256Digest, NodePrivateTransportError> {
    Sha256Digest::parse(value).map_err(interface_error)
}

// Requires the opened command identity to be the authenticated transport request identity.
fn validate_command_audit_identity(
    request_id: &Sha256Digest,
    request: &NodePrivateRequest,
) -> Result<(), NodePrivateTransportError> {
    if let NodePrivateRequest::OpenCommandAudit(request) = request {
        if request.command_id() != request_id {
            return Err(invalid("command audit identity does not match its request"));
        }
    }
    Ok(())
}

// Creates one stable invalid-document result without retaining rejected bytes.
const fn invalid(reason: &'static str) -> NodePrivateTransportError {
    NodePrivateTransportError::InvalidDocument { reason }
}

// Decodes one canonical base64 value without accepting alternate textual identities.
fn decode_base64(value: &str) -> Result<Vec<u8>, NodePrivateTransportError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| NodePrivateTransportError::InvalidDocument {
            reason: "binary pairing value is invalid",
        })?;
    if BASE64.encode(&decoded) != value {
        return Err(NodePrivateTransportError::InvalidDocument {
            reason: "binary pairing value is not canonical",
        });
    }
    Ok(decoded)
}

// Decodes one canonical bounded opaque runtime payload with log-specific diagnostics.
fn decode_runtime_log_payload(value: &str) -> Result<Vec<u8>, NodePrivateTransportError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| invalid("model runtime log payload encoding is invalid"))?;
    if decoded.len() > MAX_MODEL_RUNTIME_LOG_BYTES || BASE64.encode(&decoded) != value {
        return Err(invalid("model runtime log payload is invalid or unbounded"));
    }
    Ok(decoded)
}

// Decodes one canonical bounded audit export without using pairing-specific diagnostics.
fn decode_audit_export(value: &str) -> Result<Vec<u8>, NodePrivateTransportError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| invalid("audit export encoding is invalid"))?;
    if BASE64.encode(&decoded) != value {
        return Err(invalid("audit export encoding is not canonical"));
    }
    Ok(decoded)
}

// Maps one validated-interface failure without exposing the rejected value.
fn interface_error(_error: li_core_interface::InterfaceError) -> NodePrivateTransportError {
    NodePrivateTransportError::InvalidDocument {
        reason: "typed interface value is invalid",
    }
}

// Maps one reconstructed manager-state failure without exposing persisted values.
fn manager_state_error(_error: crate::NodeManagerError) -> NodePrivateTransportError {
    NodePrivateTransportError::InvalidDocument {
        reason: "manager state value is invalid",
    }
}

// Maps one invalid Node-owned pairing value without exposing candidate or credential bytes.
fn pairing_value_error(_error: NodePairingApiError) -> NodePrivateTransportError {
    NodePrivateTransportError::InvalidDocument {
        reason: "pairing value is invalid",
    }
}

// Maps one invalid atomic pairing-authority value without exposing credential material.
fn pairing_activation_value_error(
    _error: NodePairingActivationAuthorityError,
) -> NodePrivateTransportError {
    invalid("pairing authority value is invalid")
}

// Maps one invalid benchmark contract or projection without exposing rejected identities.
fn benchmark_value_error(
    _error: li_benchmark_manager::BenchmarkError,
) -> NodePrivateTransportError {
    NodePrivateTransportError::InvalidDocument {
        reason: "benchmark value is invalid",
    }
}

// Maps one invalid storage request or projection without exposing private paths.
fn storage_value_error(_error: NodeStorageError) -> NodePrivateTransportError {
    invalid("storage value is invalid")
}

// Projects one already-bounded canonical runtime identity list into wire strings.
fn wire_runtime_installation_ids(
    installation_ids: &[RuntimeInstallationId],
) -> Result<Vec<String>, NodePrivateTransportError> {
    if installation_ids.len() > MAXIMUM_RUNTIME_INSTALLATIONS
        || installation_ids
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(invalid("runtime installation identities are invalid"));
    }
    Ok(installation_ids
        .iter()
        .map(|installation_id| installation_id.as_str().to_string())
        .collect())
}

// Reconstructs one bounded canonical runtime identity list from wire strings.
fn runtime_installation_ids(
    installation_ids: Vec<String>,
) -> Result<Vec<RuntimeInstallationId>, NodePrivateTransportError> {
    if installation_ids.len() > MAXIMUM_RUNTIME_INSTALLATIONS
        || installation_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("runtime installation identities are invalid"));
    }
    installation_ids
        .into_iter()
        .map(|installation_id| {
            RuntimeInstallationId::parse(&installation_id).map_err(interface_error)
        })
        .collect()
}

// Returns one closed wire name for an exact runtime removal result.
const fn runtime_removal_disposition_name(
    disposition: NodeRuntimeRemovalDisposition,
) -> &'static str {
    match disposition {
        NodeRuntimeRemovalDisposition::Applied => "applied",
        NodeRuntimeRemovalDisposition::Replayed => "replayed",
    }
}

// Reconstructs one exact runtime removal result from its closed wire name.
fn runtime_removal_disposition(
    value: &str,
) -> Result<NodeRuntimeRemovalDisposition, NodePrivateTransportError> {
    match value {
        "applied" => Ok(NodeRuntimeRemovalDisposition::Applied),
        "replayed" => Ok(NodeRuntimeRemovalDisposition::Replayed),
        _ => Err(invalid("runtime removal disposition is invalid")),
    }
}

// Returns the stable wire name for one RuntimeManager model-retention policy.
const fn runtime_model_retention_name(retention: NodeRuntimeModelRetention) -> &'static str {
    match retention {
        NodeRuntimeModelRetention::Remove => "remove",
        NodeRuntimeModelRetention::Preserve => "preserve",
    }
}

// Parses one closed RuntimeManager model-retention policy.
fn runtime_model_retention(
    value: &str,
) -> Result<NodeRuntimeModelRetention, NodePrivateTransportError> {
    match value {
        "remove" => Ok(NodeRuntimeModelRetention::Remove),
        "preserve" => Ok(NodeRuntimeModelRetention::Preserve),
        _ => Err(invalid("runtime model retention is invalid")),
    }
}

// Returns the stable wire name for one model-service runtime-retention policy.
const fn model_removal_retention_name(retention: NodeModelRemovalRetention) -> &'static str {
    match retention {
        NodeModelRemovalRetention::RemoveUnreferencedRuntimes => "remove_unreferenced_runtimes",
        NodeModelRemovalRetention::PreserveModels => "preserve_models",
    }
}

// Parses one closed model-service runtime-retention policy.
fn model_removal_retention(
    value: &str,
) -> Result<NodeModelRemovalRetention, NodePrivateTransportError> {
    match value {
        "remove_unreferenced_runtimes" => Ok(NodeModelRemovalRetention::RemoveUnreferencedRuntimes),
        "preserve_models" => Ok(NodeModelRemovalRetention::PreserveModels),
        _ => Err(invalid("model removal runtime retention is invalid")),
    }
}

// Returns whether one Begin request applied or exactly replayed an active lease.
const fn uninstall_disposition_name(disposition: NodeUninstallSessionDisposition) -> &'static str {
    match disposition {
        NodeUninstallSessionDisposition::Applied => "applied",
        NodeUninstallSessionDisposition::Replayed => "replayed",
    }
}

// Parses one closed Begin lease disposition.
fn uninstall_disposition(
    value: &str,
) -> Result<NodeUninstallSessionDisposition, NodePrivateTransportError> {
    match value {
        "applied" => Ok(NodeUninstallSessionDisposition::Applied),
        "replayed" => Ok(NodeUninstallSessionDisposition::Replayed),
        _ => Err(invalid("uninstall session disposition is invalid")),
    }
}

// Selects one stable remote code from the closed runtime-maintenance failure contract.
const fn runtime_maintenance_error_code(error: NodeRuntimeMaintenanceError) -> &'static str {
    match error {
        NodeRuntimeMaintenanceError::InvalidProjection => "runtime_maintenance_invalid",
        NodeRuntimeMaintenanceError::Conflict => "runtime_maintenance_conflict",
        NodeRuntimeMaintenanceError::ProviderUnavailable => "runtime_maintenance_unavailable",
    }
}

// Selects one stable remote code from the closed pairing-authority failure contract.
const fn pairing_activation_error_code(error: NodePairingActivationAuthorityError) -> &'static str {
    match error {
        NodePairingActivationAuthorityError::InvalidRequest => "pairing_authority_invalid",
        NodePairingActivationAuthorityError::AuthorityConflict => "pairing_authority_conflict",
        NodePairingActivationAuthorityError::Unavailable => "pairing_authority_unavailable",
        NodePairingActivationAuthorityError::RecoveryRequired => {
            "pairing_authority_recovery_required"
        }
    }
}

// Maps one invalid authentication value without exposing policy or credential bytes.
fn authentication_value_error(
    _error: li_authentication_manager::AuthenticationError,
) -> NodePrivateTransportError {
    NodePrivateTransportError::InvalidDocument {
        reason: "authentication value is invalid",
    }
}

// Maps one invalid controller projection without exposing certificate or identity bytes.
fn controller_value_error(
    _error: li_authentication_manager::ControllerError,
) -> NodePrivateTransportError {
    invalid("controller value is invalid")
}

// Maps one invalid command-audit value without exposing its opaque marker.
fn command_audit_value_error(_error: crate::NodeCommandAuditError) -> NodePrivateTransportError {
    invalid("command audit value is invalid")
}

// Maps one invalid audit projection without exposing event or export contents.
fn audit_value_error(_error: li_audit_manager::AuditError) -> NodePrivateTransportError {
    invalid("audit value is invalid")
}

// Maps one invalid Core update value without retaining release text.
fn update_value_error(
    _error: li_core_update_manager::CoreUpdateError,
) -> NodePrivateTransportError {
    invalid("Core update value is invalid")
}

// Selects one stable recovery-aware remote code from the closed update failure contract.
fn update_error_code(error: &NodeUpdateError) -> &'static str {
    match error {
        NodeUpdateError::Core(CoreUpdateError::Busy) => "update_busy",
        NodeUpdateError::Core(CoreUpdateError::IdempotencyConflict) => "update_conflict",
        NodeUpdateError::Core(CoreUpdateError::RolledBack { .. }) => "update_rolled_back",
        NodeUpdateError::Core(CoreUpdateError::RecoveryRequired { .. }) => {
            "update_recovery_required"
        }
        NodeUpdateError::Core(CoreUpdateError::Provider { .. }) => "update_provider_error",
        NodeUpdateError::Core(
            CoreUpdateError::InvalidContract { .. } | CoreUpdateError::Store(_),
        )
        | NodeUpdateError::ProjectionUnavailable => "update_error",
    }
}

// Selects one stable remote code from the closed local Gateway capability failure contract.
const fn gateway_api_error_code(error: NodeGatewayApiError) -> &'static str {
    match error {
        NodeGatewayApiError::AuthorizationDenied => "gateway_authorization_denied",
        NodeGatewayApiError::RoleDenied => "gateway_role_denied",
        NodeGatewayApiError::InvalidContract => "gateway_contract_invalid",
        NodeGatewayApiError::ReplayConflict => "gateway_replay_conflict",
        NodeGatewayApiError::CorruptState => "gateway_state_corrupt",
        NodeGatewayApiError::Unavailable => "gateway_unavailable",
    }
}

// Parses one closed Core update disposition.
fn core_update_disposition(
    value: &str,
) -> Result<CoreUpdateDisposition, NodePrivateTransportError> {
    match value {
        "current" => Ok(CoreUpdateDisposition::Current),
        "updated" => Ok(CoreUpdateDisposition::Updated),
        "cleanup_pending" => Ok(CoreUpdateDisposition::CleanupPending),
        _ => Err(invalid("Core update disposition is invalid")),
    }
}

// Parses one closed durable Core update phase.
fn core_update_phase(value: &str) -> Result<CoreUpdatePhase, NodePrivateTransportError> {
    match value {
        "requested" => Ok(CoreUpdatePhase::Requested),
        "prepared" => Ok(CoreUpdatePhase::Prepared),
        "services_snapshotted" => Ok(CoreUpdatePhase::ServicesSnapshotted),
        "activated" => Ok(CoreUpdatePhase::Activated),
        "services_rebound" => Ok(CoreUpdatePhase::ServicesRebound),
        "verified" => Ok(CoreUpdatePhase::Verified),
        "committed" => Ok(CoreUpdatePhase::Committed),
        "rolling_back" => Ok(CoreUpdatePhase::RollingBack),
        "current" => Ok(CoreUpdatePhase::Current),
        "cleanup_pending" => Ok(CoreUpdatePhase::CleanupPending),
        "succeeded" => Ok(CoreUpdatePhase::Succeeded),
        "rolled_back" => Ok(CoreUpdatePhase::RolledBack),
        "recovery_required" => Ok(CoreUpdatePhase::RecoveryRequired),
        _ => Err(invalid("Core update phase is invalid")),
    }
}

// Parses one closed ModelCoordinator update disposition.
fn model_update_disposition(
    value: &str,
) -> Result<NodeModelUpdateDisposition, NodePrivateTransportError> {
    match value {
        "current" => Ok(NodeModelUpdateDisposition::Current),
        "update_available" => Ok(NodeModelUpdateDisposition::UpdateAvailable),
        "updated" => Ok(NodeModelUpdateDisposition::Updated),
        _ => Err(invalid("model update disposition is invalid")),
    }
}

// Parses one closed audit actor type.
fn audit_actor_type(value: &str) -> Result<AuditActorType, NodePrivateTransportError> {
    match value {
        "local-user" => Ok(AuditActorType::LocalUser),
        "controller" => Ok(AuditActorType::Controller),
        "node-candidate" => Ok(AuditActorType::NodeCandidate),
        "node" => Ok(AuditActorType::Node),
        "system" => Ok(AuditActorType::System),
        _ => Err(invalid("audit actor type is invalid")),
    }
}

// Parses one closed audit origin interface.
fn audit_origin_interface(value: &str) -> Result<AuditOriginInterface, NodePrivateTransportError> {
    match value {
        "cli" => Ok(AuditOriginInterface::Cli),
        "controller" => Ok(AuditOriginInterface::Controller),
        "pairing" => Ok(AuditOriginInterface::Pairing),
        "gateway" => Ok(AuditOriginInterface::Gateway),
        "node" => Ok(AuditOriginInterface::Node),
        "system" => Ok(AuditOriginInterface::System),
        _ => Err(invalid("audit origin interface is invalid")),
    }
}

// Parses one closed audit outcome.
fn audit_outcome(value: &str) -> Result<AuditOutcome, NodePrivateTransportError> {
    match value {
        "success" => Ok(AuditOutcome::Success),
        "denied" => Ok(AuditOutcome::Denied),
        "failed" => Ok(AuditOutcome::Failed),
        _ => Err(invalid("audit outcome is invalid")),
    }
}

// Maps one invalid model contract without exposing provider or request values.
fn model_value_error(_error: crate::NodeModelError) -> NodePrivateTransportError {
    invalid("model value is invalid")
}

// Maps one invalid host read without exposing native observation or placement detail.
fn host_value_error(_error: crate::NodeHostReadError) -> NodePrivateTransportError {
    invalid("host projection value is invalid")
}

// Returns the stable wire name for one placement-group lifecycle state.
const fn host_group_state_name(state: PlacementGroupState) -> &'static str {
    match state {
        PlacementGroupState::Staging => "staging",
        PlacementGroupState::Staged => "staged",
        PlacementGroupState::Starting => "starting",
        PlacementGroupState::Running => "running",
        PlacementGroupState::Degraded => "degraded",
        PlacementGroupState::Stopping => "stopping",
        PlacementGroupState::Stopped => "stopped",
        PlacementGroupState::Recovering => "recovering",
        PlacementGroupState::Removing => "removing",
        PlacementGroupState::Removed => "removed",
        PlacementGroupState::Failed => "failed",
    }
}

// Parses one closed placement-group lifecycle state.
fn host_group_state(value: &str) -> Result<PlacementGroupState, NodePrivateTransportError> {
    match value {
        "staging" => Ok(PlacementGroupState::Staging),
        "staged" => Ok(PlacementGroupState::Staged),
        "starting" => Ok(PlacementGroupState::Starting),
        "running" => Ok(PlacementGroupState::Running),
        "degraded" => Ok(PlacementGroupState::Degraded),
        "stopping" => Ok(PlacementGroupState::Stopping),
        "stopped" => Ok(PlacementGroupState::Stopped),
        "recovering" => Ok(PlacementGroupState::Recovering),
        "removing" => Ok(PlacementGroupState::Removing),
        "removed" => Ok(PlacementGroupState::Removed),
        "failed" => Ok(PlacementGroupState::Failed),
        _ => Err(invalid("host placement-group state is invalid")),
    }
}

// Returns the stable wire name for one opaque placement lifecycle state.
const fn host_placement_state_name(state: PlacementState) -> &'static str {
    match state {
        PlacementState::Pending => "pending",
        PlacementState::Staging => "staging",
        PlacementState::Staged => "staged",
        PlacementState::Starting => "starting",
        PlacementState::Running => "running",
        PlacementState::Stopping => "stopping",
        PlacementState::Stopped => "stopped",
        PlacementState::Removing => "removing",
        PlacementState::Removed => "removed",
        PlacementState::Failed => "failed",
        PlacementState::Unreachable => "unreachable",
    }
}

// Parses one closed opaque placement lifecycle state.
fn host_placement_state(value: &str) -> Result<PlacementState, NodePrivateTransportError> {
    match value {
        "pending" => Ok(PlacementState::Pending),
        "staging" => Ok(PlacementState::Staging),
        "staged" => Ok(PlacementState::Staged),
        "starting" => Ok(PlacementState::Starting),
        "running" => Ok(PlacementState::Running),
        "stopping" => Ok(PlacementState::Stopping),
        "stopped" => Ok(PlacementState::Stopped),
        "removing" => Ok(PlacementState::Removing),
        "removed" => Ok(PlacementState::Removed),
        "failed" => Ok(PlacementState::Failed),
        "unreachable" => Ok(PlacementState::Unreachable),
        _ => Err(invalid("host placement state is invalid")),
    }
}

// Returns the stable wire name for endpoint ownership.
const fn host_endpoint_ownership_name(value: EndpointOwnership) -> &'static str {
    match value {
        EndpointOwnership::Owner => "owner",
        EndpointOwnership::Participant => "participant",
    }
}

// Parses one closed endpoint-ownership value.
fn host_endpoint_ownership(value: &str) -> Result<EndpointOwnership, NodePrivateTransportError> {
    match value {
        "owner" => Ok(EndpointOwnership::Owner),
        "participant" => Ok(EndpointOwnership::Participant),
        _ => Err(invalid("host endpoint ownership is invalid")),
    }
}

// Returns the stable wire name for one endpoint transport.
const fn host_endpoint_scheme_name(value: EndpointScheme) -> &'static str {
    match value {
        EndpointScheme::Http => "http",
        EndpointScheme::Https => "https",
    }
}

// Parses one closed endpoint transport.
fn host_endpoint_scheme(value: &str) -> Result<EndpointScheme, NodePrivateTransportError> {
    match value {
        "http" => Ok(EndpointScheme::Http),
        "https" => Ok(EndpointScheme::Https),
        _ => Err(invalid("host endpoint scheme is invalid")),
    }
}

// Returns the stable wire name for one model-neutral interconnect kind.
const fn host_interconnect_kind_name(value: InterconnectKind) -> &'static str {
    match value {
        InterconnectKind::Any => "any",
        InterconnectKind::Connectx => "connectx",
        InterconnectKind::Ethernet => "ethernet",
        InterconnectKind::Wifi => "wifi",
        InterconnectKind::Other => "other",
    }
}

// Parses one closed model-neutral interconnect kind.
fn host_interconnect_kind(value: &str) -> Result<InterconnectKind, NodePrivateTransportError> {
    match value {
        "any" => Ok(InterconnectKind::Any),
        "connectx" => Ok(InterconnectKind::Connectx),
        "ethernet" => Ok(InterconnectKind::Ethernet),
        "wifi" => Ok(InterconnectKind::Wifi),
        "other" => Ok(InterconnectKind::Other),
        _ => Err(invalid("host interconnect kind is invalid")),
    }
}

// Returns the stable wire name for one protection-readiness state.
const fn host_protection_state_name(value: NodeHostProtectionState) -> &'static str {
    match value {
        NodeHostProtectionState::Ready => "ready",
        NodeHostProtectionState::NotReady => "not_ready",
    }
}

// Parses one closed protection-readiness state.
fn host_protection_state(
    value: &str,
) -> Result<NodeHostProtectionState, NodePrivateTransportError> {
    match value {
        "ready" => Ok(NodeHostProtectionState::Ready),
        "not_ready" => Ok(NodeHostProtectionState::NotReady),
        _ => Err(invalid("host protection state is invalid")),
    }
}

// Returns the stable wire name for one resident service state.
const fn host_service_state_name(value: NodeHostServiceState) -> &'static str {
    match value {
        NodeHostServiceState::Ready => "ready",
        NodeHostServiceState::NotReady => "not_ready",
    }
}

// Parses one closed resident service state.
fn host_service_state(value: &str) -> Result<NodeHostServiceState, NodePrivateTransportError> {
    match value {
        "ready" => Ok(NodeHostServiceState::Ready),
        "not_ready" => Ok(NodeHostServiceState::NotReady),
        _ => Err(invalid("host service state is invalid")),
    }
}

// Returns one stable model-service desired-state wire name.
const fn model_desired_state_name(state: ModelServiceDesiredState) -> &'static str {
    match state {
        ModelServiceDesiredState::Running => "running",
        ModelServiceDesiredState::Stopped => "stopped",
        ModelServiceDesiredState::Removed => "removed",
    }
}

// Parses one closed model-service desired state.
fn model_desired_state(value: &str) -> Result<ModelServiceDesiredState, NodePrivateTransportError> {
    match value {
        "running" => Ok(ModelServiceDesiredState::Running),
        "stopped" => Ok(ModelServiceDesiredState::Stopped),
        "removed" => Ok(ModelServiceDesiredState::Removed),
        _ => Err(invalid("model desired state is invalid")),
    }
}

// Parses one closed model lifecycle action.
fn model_action(value: &str) -> Result<NodeModelAction, NodePrivateTransportError> {
    match value {
        "install" => Ok(NodeModelAction::Install),
        "update" => Ok(NodeModelAction::Update),
        "pause" => Ok(NodeModelAction::Pause),
        "resume" => Ok(NodeModelAction::Resume),
        "restart" => Ok(NodeModelAction::Restart),
        "recover" => Ok(NodeModelAction::Recover),
        "remove" => Ok(NodeModelAction::Remove),
        "rollback" => Ok(NodeModelAction::Rollback),
        _ => Err(invalid("model action is invalid")),
    }
}

// Parses one closed durable model journal state.
fn model_journal_state(value: &str) -> Result<NodeModelJournalState, NodePrivateTransportError> {
    match value {
        "prepared" => Ok(NodeModelJournalState::Prepared),
        "executing" => Ok(NodeModelJournalState::Executing),
        "compensating" => Ok(NodeModelJournalState::Compensating),
        "cleanup_pending" => Ok(NodeModelJournalState::CleanupPending),
        "succeeded" => Ok(NodeModelJournalState::Succeeded),
        "rolled_back" => Ok(NodeModelJournalState::RolledBack),
        "failed" => Ok(NodeModelJournalState::Failed),
        _ => Err(invalid("model journal state is invalid")),
    }
}

// Returns the descriptive evidence-label wire name without interpreting admission.
const fn evidence_label_name(label: EvidenceLabel) -> &'static str {
    match label {
        EvidenceLabel::Qualified => "qualified",
        EvidenceLabel::Unqualified => "unqualified",
        EvidenceLabel::Unknown => "unknown",
    }
}

// Parses one closed descriptive evidence label.
fn evidence_label(value: &str) -> Result<EvidenceLabel, NodePrivateTransportError> {
    match value {
        "qualified" => Ok(EvidenceLabel::Qualified),
        "unqualified" => Ok(EvidenceLabel::Unqualified),
        "unknown" => Ok(EvidenceLabel::Unknown),
        _ => Err(invalid("model evidence label is invalid")),
    }
}

// Parses one exact command-audit policy name.
fn command_audit_policy(value: &str) -> Result<NodeCommandAuditPolicy, NodePrivateTransportError> {
    match value {
        "success" => Ok(NodeCommandAuditPolicy::Success),
        "always" => Ok(NodeCommandAuditPolicy::Always),
        "sensitive_read" => Ok(NodeCommandAuditPolicy::SensitiveRead),
        _ => Err(invalid("command audit policy is invalid")),
    }
}

// Parses one exact command-audit mutation name.
fn command_audit_mutation(
    value: &str,
) -> Result<NodeCommandAuditMutation, NodePrivateTransportError> {
    match value {
        "read" => Ok(NodeCommandAuditMutation::Read),
        "local" => Ok(NodeCommandAuditMutation::Local),
        "node" => Ok(NodeCommandAuditMutation::Node),
        "internal" => Ok(NodeCommandAuditMutation::Internal),
        _ => Err(invalid("command audit mutation is invalid")),
    }
}

// Parses one exact command-audit outcome name.
fn command_audit_outcome(
    value: &str,
) -> Result<NodeCommandAuditOutcome, NodePrivateTransportError> {
    match value {
        "succeeded" => Ok(NodeCommandAuditOutcome::Succeeded),
        "failed" => Ok(NodeCommandAuditOutcome::Failed),
        "denied" => Ok(NodeCommandAuditOutcome::Denied),
        "cancelled" => Ok(NodeCommandAuditOutcome::Cancelled),
        _ => Err(invalid("command audit outcome is invalid")),
    }
}

// Parses one exact command-audit target class.
fn command_audit_target_kind(
    value: &str,
) -> Result<NodeCommandAuditTargetKind, NodePrivateTransportError> {
    match value {
        "node" => Ok(NodeCommandAuditTargetKind::Node),
        "model" => Ok(NodeCommandAuditTargetKind::Model),
        "api_key" => Ok(NodeCommandAuditTargetKind::ApiKey),
        "benchmark" => Ok(NodeCommandAuditTargetKind::Benchmark),
        "audit_event" => Ok(NodeCommandAuditTargetKind::AuditEvent),
        "core" => Ok(NodeCommandAuditTargetKind::Core),
        "service" => Ok(NodeCommandAuditTargetKind::Service),
        _ => Err(invalid("command audit target kind is invalid")),
    }
}

// Returns the stable durable benchmark-phase wire name.
fn benchmark_phase_name(phase: BenchmarkJobPhase) -> &'static str {
    match phase {
        BenchmarkJobPhase::Requested => "requested",
        BenchmarkJobPhase::Prepared => "prepared",
        BenchmarkJobPhase::Running => "running",
        BenchmarkJobPhase::Stopping => "stopping",
        BenchmarkJobPhase::Restoring => "restoring",
        BenchmarkJobPhase::Finalizing => "finalizing",
        BenchmarkJobPhase::Completed => "completed",
        BenchmarkJobPhase::Failed => "failed",
        BenchmarkJobPhase::Cancelled => "cancelled",
    }
}

// Parses one closed durable benchmark-phase wire value.
fn benchmark_phase(value: &str) -> Result<BenchmarkJobPhase, NodePrivateTransportError> {
    match value {
        "requested" => Ok(BenchmarkJobPhase::Requested),
        "prepared" => Ok(BenchmarkJobPhase::Prepared),
        "running" => Ok(BenchmarkJobPhase::Running),
        "stopping" => Ok(BenchmarkJobPhase::Stopping),
        "restoring" => Ok(BenchmarkJobPhase::Restoring),
        "finalizing" => Ok(BenchmarkJobPhase::Finalizing),
        "completed" => Ok(BenchmarkJobPhase::Completed),
        "failed" => Ok(BenchmarkJobPhase::Failed),
        "cancelled" => Ok(BenchmarkJobPhase::Cancelled),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "benchmark phase is invalid",
        }),
    }
}

// Returns the stable durable paired-verification phase wire name.
fn benchmark_verification_phase_name(phase: BenchmarkVerificationPhase) -> &'static str {
    match phase {
        BenchmarkVerificationPhase::Prepared => "prepared",
        BenchmarkVerificationPhase::BaselineRunning => "baseline_running",
        BenchmarkVerificationPhase::BaselineComplete => "baseline_complete",
        BenchmarkVerificationPhase::CandidateRunning => "candidate_running",
        BenchmarkVerificationPhase::CandidateComplete => "candidate_complete",
        BenchmarkVerificationPhase::Restoring => "restoring",
        BenchmarkVerificationPhase::Restored => "restored",
        BenchmarkVerificationPhase::RestorationFailed => "restoration_failed",
    }
}

// Parses one closed durable paired-verification phase wire value.
fn benchmark_verification_phase(
    value: &str,
) -> Result<BenchmarkVerificationPhase, NodePrivateTransportError> {
    match value {
        "prepared" => Ok(BenchmarkVerificationPhase::Prepared),
        "baseline_running" => Ok(BenchmarkVerificationPhase::BaselineRunning),
        "baseline_complete" => Ok(BenchmarkVerificationPhase::BaselineComplete),
        "candidate_running" => Ok(BenchmarkVerificationPhase::CandidateRunning),
        "candidate_complete" => Ok(BenchmarkVerificationPhase::CandidateComplete),
        "restoring" => Ok(BenchmarkVerificationPhase::Restoring),
        "restored" => Ok(BenchmarkVerificationPhase::Restored),
        "restoration_failed" => Ok(BenchmarkVerificationPhase::RestorationFailed),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "benchmark verification phase is invalid",
        }),
    }
}

// Returns the stable Node-owned candidate handoff phase wire name.
fn benchmark_handoff_phase_name(phase: NodeBenchmarkCandidateHandoffPhase) -> &'static str {
    match phase {
        NodeBenchmarkCandidateHandoffPhase::Prepared => "prepared",
        NodeBenchmarkCandidateHandoffPhase::CandidateAcquired => "candidate_acquired",
        NodeBenchmarkCandidateHandoffPhase::BaselineActivated => "baseline_activated",
        NodeBenchmarkCandidateHandoffPhase::BaselineReleasing => "baseline_releasing",
        NodeBenchmarkCandidateHandoffPhase::BaselineReleased => "baseline_released",
        NodeBenchmarkCandidateHandoffPhase::CandidateStaged => "candidate_staged",
        NodeBenchmarkCandidateHandoffPhase::CandidateRunning => "candidate_running",
        NodeBenchmarkCandidateHandoffPhase::Restoring => "restoring",
        NodeBenchmarkCandidateHandoffPhase::BaselineRestored => "baseline_restored",
        NodeBenchmarkCandidateHandoffPhase::Completed => "completed",
    }
}

// Parses one closed Node-owned candidate handoff phase wire value.
fn benchmark_handoff_phase(
    value: &str,
) -> Result<NodeBenchmarkCandidateHandoffPhase, NodePrivateTransportError> {
    match value {
        "prepared" => Ok(NodeBenchmarkCandidateHandoffPhase::Prepared),
        "candidate_acquired" => Ok(NodeBenchmarkCandidateHandoffPhase::CandidateAcquired),
        "baseline_activated" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineActivated),
        "baseline_releasing" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineReleasing),
        "baseline_released" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineReleased),
        "candidate_staged" => Ok(NodeBenchmarkCandidateHandoffPhase::CandidateStaged),
        "candidate_running" => Ok(NodeBenchmarkCandidateHandoffPhase::CandidateRunning),
        "restoring" => Ok(NodeBenchmarkCandidateHandoffPhase::Restoring),
        "baseline_restored" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineRestored),
        "completed" => Ok(NodeBenchmarkCandidateHandoffPhase::Completed),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "benchmark candidate handoff phase is invalid",
        }),
    }
}

// Parses one stable terminal benchmark failure category without provider diagnostics.
fn benchmark_failure_category(
    value: &str,
) -> Result<BenchmarkFailureCategory, NodePrivateTransportError> {
    match value {
        "crash" => Ok(BenchmarkFailureCategory::Crash),
        "out_of_memory" => Ok(BenchmarkFailureCategory::OutOfMemory),
        "protection_trip" => Ok(BenchmarkFailureCategory::ProtectionTrip),
        "output_validation" => Ok(BenchmarkFailureCategory::OutputValidation),
        "incomplete_workload" => Ok(BenchmarkFailureCategory::IncompleteWorkload),
        "restoration" => Ok(BenchmarkFailureCategory::Restoration),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "benchmark terminal failure category is invalid",
        }),
    }
}

// Returns the stable benchmark-disposition wire name.
fn benchmark_disposition_name(disposition: BenchmarkDisposition) -> &'static str {
    match disposition {
        BenchmarkDisposition::Started => "started",
        BenchmarkDisposition::Running => "running",
        BenchmarkDisposition::Stopping => "stopping",
        BenchmarkDisposition::Completed => "completed",
        BenchmarkDisposition::Failed => "failed",
        BenchmarkDisposition::Cancelled => "cancelled",
        BenchmarkDisposition::Replayed => "replayed",
    }
}

// Parses one closed benchmark-disposition wire value.
fn benchmark_disposition(value: &str) -> Result<BenchmarkDisposition, NodePrivateTransportError> {
    match value {
        "started" => Ok(BenchmarkDisposition::Started),
        "running" => Ok(BenchmarkDisposition::Running),
        "stopping" => Ok(BenchmarkDisposition::Stopping),
        "completed" => Ok(BenchmarkDisposition::Completed),
        "failed" => Ok(BenchmarkDisposition::Failed),
        "cancelled" => Ok(BenchmarkDisposition::Cancelled),
        "replayed" => Ok(BenchmarkDisposition::Replayed),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "benchmark disposition is invalid",
        }),
    }
}

// Returns the stable durable pairing-state wire name.
fn pairing_state_name(state: NodePairingState) -> &'static str {
    match state {
        NodePairingState::Open => "open",
        NodePairingState::PendingApproval => "pending_approval",
        NodePairingState::Active => "active",
    }
}

// Parses one closed durable pairing-state wire value.
fn pairing_state(value: &str) -> Result<NodePairingState, NodePrivateTransportError> {
    match value {
        "open" => Ok(NodePairingState::Open),
        "pending_approval" => Ok(NodePairingState::PendingApproval),
        "active" => Ok(NodePairingState::Active),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "pairing state is invalid",
        }),
    }
}

// Returns the stable node-role wire name.
fn node_role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "main",
        NodeRole::Child => "child",
    }
}

// Parses one closed node-role wire value.
fn node_role(value: &str) -> Result<NodeRole, NodePrivateTransportError> {
    match value {
        "main" => Ok(NodeRole::Main),
        "child" => Ok(NodeRole::Child),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "node role is invalid",
        }),
    }
}

// Returns the stable node-state wire name.
fn node_state_name(state: NodeState) -> &'static str {
    match state {
        NodeState::Pending => "pending",
        NodeState::Active => "active",
        NodeState::Draining => "draining",
        NodeState::Offline => "offline",
        NodeState::Removed => "removed",
    }
}

// Parses one closed node-state wire value.
fn node_state(value: &str) -> Result<NodeState, NodePrivateTransportError> {
    match value {
        "pending" => Ok(NodeState::Pending),
        "active" => Ok(NodeState::Active),
        "draining" => Ok(NodeState::Draining),
        "offline" => Ok(NodeState::Offline),
        "removed" => Ok(NodeState::Removed),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "node state is invalid",
        }),
    }
}

// Returns the stable child-transition wire name.
fn node_transition_name(transition: NodeTransition) -> &'static str {
    match transition {
        NodeTransition::Activate => "activate",
        NodeTransition::Pause => "pause",
        NodeTransition::Resume => "resume",
        NodeTransition::MarkOffline => "mark_offline",
        NodeTransition::Remove => "remove",
    }
}

// Parses one closed child-transition wire value.
fn node_transition(value: &str) -> Result<NodeTransition, NodePrivateTransportError> {
    match value {
        "activate" => Ok(NodeTransition::Activate),
        "pause" => Ok(NodeTransition::Pause),
        "resume" => Ok(NodeTransition::Resume),
        "mark_offline" => Ok(NodeTransition::MarkOffline),
        "remove" => Ok(NodeTransition::Remove),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "node transition is invalid",
        }),
    }
}

// Returns the stable outbox-state wire name.
fn outbox_state_name(state: NodeOutboxState) -> &'static str {
    match state {
        NodeOutboxState::Pending => "pending",
        NodeOutboxState::Acknowledged => "acknowledged",
    }
}

// Parses one closed outbox-state wire value.
fn outbox_state(value: &str) -> Result<NodeOutboxState, NodePrivateTransportError> {
    match value {
        "pending" => Ok(NodeOutboxState::Pending),
        "acknowledged" => Ok(NodeOutboxState::Acknowledged),
        _ => Err(NodePrivateTransportError::InvalidDocument {
            reason: "outbox state is invalid",
        }),
    }
}
