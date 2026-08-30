// SPDX-License-Identifier: AGPL-3.0-only

mod li_audit_composition;
mod li_audit_cryptography;
mod li_audit_database;
mod li_authentication;
mod li_authentication_database;
mod li_benchmark;
mod li_benchmark_candidate_handoff;
mod li_benchmark_candidate_handoff_database;
mod li_command_audit;
mod li_controller_database;
mod li_core_update_database;
mod li_core_update_service_snapshot_database;
mod li_gateway_database;
mod li_gateway_exposure_database;
mod li_gateway_native_target;
mod li_gateway_public_inventory;
mod li_gateway_relay_trust;
mod li_gateway_usage_database;
mod li_model_service_database;
mod li_node_catalog_api;
mod li_node_configuration;
mod li_node_daemon;
mod li_node_event;
mod li_node_exposure;
mod li_node_gateway_api;
mod li_node_gateway_capability;
mod li_node_hardware;
mod li_node_health;
mod li_node_host_projection;
mod li_node_manager_error;
mod li_node_model_contract;
mod li_node_model_coordinator;
mod li_node_model_journal;
mod li_node_model_ports;
mod li_node_outbox;
mod li_node_owner_path;
mod li_node_pairing_activation_authority;
mod li_node_pairing_api;
mod li_node_pairing_enrollment;
mod li_node_pairing_tls;
mod li_node_pairing_transport;
mod li_node_peer_credential_database;
mod li_node_private_api;
mod li_node_private_local_listener;
mod li_node_private_remote_client;
mod li_node_private_remote_listener;
mod li_node_private_remote_tls;
mod li_node_private_transport;
mod li_node_protection_api;
mod li_node_protection_connection;
mod li_node_protection_lease;
mod li_node_protection_local_ipc;
mod li_node_protection_peer_role;
mod li_node_protection_session_database;
mod li_node_protection_transport;
mod li_node_record;
mod li_node_resident;
mod li_node_role;
mod li_node_runtime_maintenance;
mod li_node_setup_identity;
mod li_node_signal;
mod li_node_storage;
mod li_node_update;
mod li_node_watchdog_protocol_identity;
mod li_node_watchdog_session;
mod li_placement_database;
mod li_runtime_database;

pub use li_audit_composition::{
    NodeAuditCommitModel, NodeAuditComposition, NodeAuditCompositionError,
};
pub use li_audit_cryptography::{
    NodeAuditCheckpointKeyReferences, NodeAuditCryptographyError, NodeAuditOpenSslRunner,
    OpenSslNodeAuditCheckpointCryptography, SystemNodeAuditOpenSslRunner,
};
pub use li_audit_database::DatabaseAuditStore;
pub use li_authentication::{
    NodeApiKeyPolicyUpdate, NodeAuthenticationApiPort, NodeAuthenticationCoordinator,
    NodeControllerAuthorization, NodeControllerAuthorizationProjectionPort,
    NodeControllerEnrollmentCandidate, NodeControllerEnrollmentReceipt, NodeControllerSummary,
    NodeIssuedApiKey,
};
pub use li_authentication_database::DatabaseAuthenticationStore;
pub use li_benchmark::{
    compose_node_benchmark_coordinator, compose_node_benchmark_coordinator_with_store,
    DatabaseNodeBenchmarkVerificationProjectionProvider, NodeBenchmarkApiPort,
    NodeBenchmarkContext, NodeBenchmarkCoordinator, NodeBenchmarkPlan, NodeBenchmarkPollingPort,
    NodeBenchmarkRequestProvider, NodeBenchmarkSelection, NodeBenchmarkSnapshot,
    NodeBenchmarkSnapshotProgress, NodeBenchmarkTerminalFailure,
    NodeBenchmarkVerificationProjection, NodeBenchmarkVerificationProjectionPort,
};
pub use li_benchmark_candidate_handoff::{
    NodeBenchmarkCandidateHandoffCoordinator, NodeBenchmarkCandidateHandoffError,
    NodeBenchmarkCandidateHandoffPhase, NodeBenchmarkCandidateHandoffReceipt,
    NodeBenchmarkCandidateHandoffRecord, NodeBenchmarkCandidateHandoffRequest,
    NodeBenchmarkCandidateHandoffStore, NodeBenchmarkCandidateRuntimePort,
    VersionedNodeBenchmarkCandidateHandoff,
};
pub use li_benchmark_candidate_handoff_database::DatabaseNodeBenchmarkCandidateHandoffStore;
pub use li_command_audit::{
    DatabaseNodeCommandAuditSessionStore, NodeAuditApiPort, NodeAuditExport, NodeAuditVerification,
    NodeCommandAuditApiPort, NodeCommandAuditCompletionDisposition,
    NodeCommandAuditCompletionReceipt, NodeCommandAuditCompletionRequest,
    NodeCommandAuditCoordinator, NodeCommandAuditError, NodeCommandAuditIntent,
    NodeCommandAuditMarker, NodeCommandAuditMutation, NodeCommandAuditOpenDisposition,
    NodeCommandAuditOpenReceipt, NodeCommandAuditOpenRequest, NodeCommandAuditOutcome,
    NodeCommandAuditPolicy, NodeCommandAuditResult, NodeCommandAuditSession,
    NodeCommandAuditSessionStore, NodeCommandAuditTarget, NodeCommandAuditTargetKind,
    VersionedNodeCommandAuditSession, NODE_AUDIT_EXPORT_MAXIMUM_BYTES,
    NODE_AUDIT_EXPORT_MAXIMUM_EVENTS,
};
pub use li_controller_database::DatabaseControllerStore;
pub use li_core_update_database::DatabaseCoreUpdateStore;
pub use li_core_update_service_snapshot_database::DatabaseCoreUpdateServiceSnapshotStore;
pub use li_gateway_database::NodeGatewayRouteProvider;
pub use li_gateway_exposure_database::DatabaseGatewayExposureStore;
pub use li_gateway_native_target::{
    GatewayPlacementRecordProvider, NodeGatewayNativeTargetProvider, NodeGatewayRelayTargetProvider,
};
pub use li_gateway_public_inventory::{
    NodeGatewayInventoryClock, NodeGatewayModelInventoryProvider, NodeGatewayModelProvider,
    SystemNodeGatewayInventoryClock,
};
pub use li_gateway_relay_trust::{
    DatabaseNodeGatewayRelayTrustStore, NodeGatewayRelayClock,
    NodeGatewayRelayCredentialReferences, NodeGatewayRelayNodeProvider, NodeGatewayRelayTarget,
    NodeGatewayRelayTrust, NodeGatewayRelayTrustError, NodeGatewayRelayTrustState,
    NodeGatewayRelayTrustStore, PersistedNodeGatewayRelayAuthorizationProvider,
    PersistedNodeGatewayRelayTargetProvider, SystemNodeGatewayRelayClock,
    VersionedNodeGatewayRelayTrust, LETSINFER_PRIVATE_GATEWAY_PORT,
};
pub use li_gateway_usage_database::DatabaseGatewayUsageStore;
pub use li_node_catalog_api::{
    NodeCatalogApiError, NodeCatalogApiPort, NodeCatalogAuthor, NodeCatalogAuthorKind,
    NodeCatalogEntry, NodeCatalogListRequest, NodeCatalogListing, NodeCatalogRefreshPolicy,
    NodeCatalogSnapshot, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection,
};
pub use li_node_configuration::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference, NodeHardwareConfiguration,
    NodeLinuxProtectionConfiguration, NodeModelConfiguration, NodePairingConfiguration,
    NodePairingPlatform, NodePlacementSafetyConfiguration, SystemNodeConfigurationFileProvider,
    NODE_CONFIGURATION_MAX_DOCUMENT_BYTES,
};
pub use li_node_daemon::{
    NodeDaemon, NodeDaemonClock, NodeDaemonError, NodeDaemonTick, NodeOutboxDeliveryProvider,
    SystemNodeDaemonClock,
};
pub use li_node_event::{NodeManagerChange, NodeManagerEvent};
pub use li_node_exposure::{ManagedNodeExposureApi, NodeExposureApiPort};
pub use li_node_gateway_api::{
    NodeGatewayApi, NodeGatewayApiError, NodeGatewayBearer, NodeGatewayCapabilityPort,
    NodeGatewayMacOsPlacement, NodeGatewayMacOsSafetyInput, NodeGatewayRequest,
    NodeGatewayResponse, NodeGatewayUsageDisposition, NODE_GATEWAY_MAXIMUM_BEARER_BYTES,
    NODE_GATEWAY_MAXIMUM_MACOS_PLACEMENTS, NODE_GATEWAY_MAXIMUM_ROUTES,
    NODE_GATEWAY_MAXIMUM_USAGE_RECORDS,
};
pub use li_node_gateway_capability::ManagedNodeGatewayCapabilityPort;
pub use li_node_hardware::{NodeHardwareChange, NodeHardwareObservationProvider};
pub use li_node_health::{
    NodeHealthError, NodeHealthExchange, NodeHealthProbe, SystemNodeHealthExchange,
};
pub use li_node_host_projection::{
    NodeHostEndpointSnapshot, NodeHostGatewaySummary, NodeHostGatewayTelemetrySummary,
    NodeHostInventory, NodeHostPlacementGroup, NodeHostPlacementGroupSnapshot,
    NodeHostPlacementReadPort, NodeHostPlacementSnapshot, NodeHostProjection,
    NodeHostProjectionPorts, NodeHostProjectionValue, NodeHostProtectionReadPort,
    NodeHostProtectionState, NodeHostProtectionSummary, NodeHostReadError, NodeHostServiceReadPort,
    NodeHostServiceState, NodeHostSnapshot, NodeHostTopologyReadPort, NodeHostWatchdogSummary,
    NodeHostWatchdogTelemetrySummary,
};
pub use li_node_manager_error::NodeManagerError;
pub use li_node_model_contract::{
    NodeModelAction, NodeModelApiPort, NodeModelClock, NodeModelCommandIdentity,
    NodeModelCommandResult, NodeModelCommandSummary, NodeModelError, NodeModelHardwareProvider,
    NodeModelInstallGroup, NodeModelInstallRequest, NodeModelJournal, NodeModelJournalState,
    NodeModelJournalStore, NodeModelLogProjection, NodeModelLogSummary, NodeModelPlacementPort,
    NodeModelPlacementRecordProvider, NodeModelPlacementRequestProvider, NodeModelRemovalRetention,
    NodeModelRemovalSelection, NodeModelRemoveRequest, NodeModelRetainedGroup,
    NodeModelRetainedNode, NodeModelRollbackGroupPreview, NodeModelRollbackPreview,
    NodeModelRollbackRuntime, NodeModelRuntimeDisposition, NodeModelRuntimeLogBatch,
    NodeModelRuntimeLogRequest, NodeModelRuntimePort, NodeModelRuntimeReceipt,
    NodeModelServiceProjection, NodeModelServiceSummary, NodeModelStatePort,
    NodeModelUpdateDisposition, NodeModelUpdateRequest, NodeModelUpdateSummary,
    VersionedNodeModelJournal, VersionedNodeModelOperation, VersionedNodeModelService,
};
pub use li_node_model_coordinator::NodeModelCoordinator;
pub use li_node_model_journal::DatabaseNodeModelJournalStore;
pub use li_node_model_ports::{
    ManagedNodeModelPlacementPort, ManagedNodeModelRuntimePort,
    NativeNodeModelPlacementRequestProvider, SystemNodeModelClock,
};
pub use li_node_outbox::{NodeOutboxEvent, NodeOutboxState, VersionedNodeOutboxEvent};
pub use li_node_owner_path::{NodePrivateUnixPathError, NodePrivateUnixPathGuard};
pub use li_node_pairing_activation_authority::{
    NodePairedChildActivationRequest, NodePairedMainRestorationRequest,
    NodePairingActivationAuthority, NodePairingActivationAuthorityError,
    NodePairingActivationAuthorityPort, NodePairingAuthorityDisposition,
    NodePairingAuthorityReceipt,
};
pub use li_node_pairing_api::{
    NodePairingApiError, NodePairingApiPort, NodePairingApproveRequest, NodePairingChallenge,
    NodePairingCredentials, NodePairingEnrollRequest, NodePairingEnrollment, NodePairingInvitation,
    NodePairingMode, NodePairingOpenRequest, NodePairingState, NodePairingStatus,
};
pub use li_node_pairing_tls::{
    NodePairingCancellation, NodePairingCancellationPort, NodePairingClientPort,
    NodePairingTlsConnectionService, NodePairingTlsError, NodePairingTlsFileSet,
    NodePairingTlsServerConfiguration, SystemNodePairingClient,
};
pub use li_node_pairing_transport::{
    decode_node_pairing_request, decode_node_pairing_response, encode_node_pairing_request,
    encode_node_pairing_response, node_pairing_candidate_offer_identity,
    node_pairing_candidate_offer_transcript, NodePairingCandidateEnrollment,
    NodePairingCandidateOffer, NodePairingCandidateOfferPort, NodePairingDocumentEndpoint,
    NodePairingLocalNodePort, NodePairingTransportError, NodePairingTransportRequest,
    NodePairingTransportResponse, NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES,
    NODE_PAIRING_TRANSPORT_SCHEMA_NAME, NODE_PAIRING_TRANSPORT_SCHEMA_VERSION,
};
pub use li_node_peer_credential_database::{
    CoreNodePrincipalResolver, DatabasePeerCredentialChange, DatabasePeerCredentialStore,
};
pub use li_node_private_api::{
    NodePrivateAction, NodePrivateApi, NodePrivateApiError, NodePrivateAuthorizationProvider,
    NodePrivateRequest, NodePrivateResponse, NodeRuntimeArtifactsFinalizationReceipt,
    NodeUninstallBeginReceipt, NodeUninstallCancelReceipt, NodeUninstallInventory,
    NodeUninstallModelTarget, NodeUninstallRequest, NodeUninstallSessionDisposition,
    MAXIMUM_UNINSTALL_TEARDOWN_TARGETS,
};
pub use li_node_private_local_listener::{
    read_node_private_local_frame, write_node_private_local_frame,
    ExactNodePrivateLocalPeerIdentity, NodePrivateLocalConnectionError,
    NodePrivateLocalConnectionHandler, NodePrivateLocalDocumentEndpoint,
    NodePrivateLocalDocumentError, NodePrivateLocalFrameError, NodePrivateLocalIoError,
    NodePrivateLocalListener, NodePrivateLocalPeerError, NodePrivateLocalPeerIdentityProvider,
    NodePrivateLocalServer, NodePrivateLocalServerConfiguration,
    NodePrivateLocalServerConfigurationError, NodePrivateLocalServerError,
    NodePrivateLocalServerHandle, NodePrivateLocalSocketProvider, NodePrivateLocalStream,
    SystemNodePrivateLocalSocketProvider, NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES,
};
pub use li_node_private_remote_client::{
    NodePrivateRemoteClientError, NodePrivateRemoteClientFileSet, NodePrivateRemoteClientPort,
    SystemNodePrivateRemoteClient,
};
pub use li_node_private_remote_listener::{
    NodePrivateRemoteConnectionService, NodePrivateRemoteListener, NodePrivateRemoteNetworkError,
    NodePrivateRemoteNetworkStream, NodePrivateRemoteServer, NodePrivateRemoteServerConfiguration,
    NodePrivateRemoteServerConfigurationError, NodePrivateRemoteServerError,
    NodePrivateRemoteServerHandle, NodePrivateRemoteSocketProvider,
    SystemNodePrivateRemoteSocketProvider,
};
pub use li_node_private_remote_tls::{
    NodePrivateAuthenticatedConnectionHandler, NodePrivatePrincipalResolver,
    NodePrivateRemoteDocumentEndpoint, NodePrivateRemotePrincipal, NodePrivateRemoteSecureStream,
    NodePrivateRemoteTlsConfiguration, NodePrivateRemoteTlsConnectionService,
    NodePrivateRemoteTlsError, NodePrivateRemoteTlsFile, NodePrivateRemoteTlsFileProvider,
    NodePrivateRemoteTlsFileSet, SystemNodePrivateRemoteTlsFileProvider,
};
pub use li_node_private_transport::{
    NodePrivateEndpoint, NodePrivateLocalEndpoint, NodePrivateRemoteError, NodePrivateTransport,
    NodePrivateTransportError, NodePrivateTransportOutcome, NodePrivateTransportRequest,
    NodePrivateTransportResponse, NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};
pub use li_node_protection_api::{
    NodeProtectionAction, NodeProtectionApi, NodeProtectionApiError,
    NodeProtectionAuthorizationProvider, NodeProtectionBeginRequest, NodeProtectionClock,
    NodeProtectionCommitRequest, NodeProtectionControllerBindingProvider, NodeProtectionEndRequest,
    NodeProtectionReadSiteStatusRequest, NodeProtectionRequest,
    NodeProtectionResolveControllerBindingRequest, NodeProtectionResponse,
    NodeProtectionSiteStatusProvider, NodeProtectionSnapshotProvider,
    NodeProtectionSnapshotRequest, SystemNodeProtectionClock,
};
pub use li_node_protection_connection::{NodeProtectionConnection, NodeProtectionConnectionRole};
pub use li_node_protection_lease::{
    NodeGatewayProtectionLeaseProvider, NodeProtectionBindingProvider, NodeProtectionLeaseBinding,
    NodeProtectionLeaseError, NodeProtectionLeaseStore, NodeProtectionNodeStatus,
    NodeProtectionTargetProvider, PersistedNodeProtectionBindingProvider,
};
pub use li_node_protection_local_ipc::{
    NodeProtectionLocalClient, NodeProtectionLocalClientConfiguration,
    NodeProtectionLocalConfiguration, NodeProtectionLocalError, NodeProtectionLocalServer,
};
pub use li_node_protection_peer_role::{
    ExpectedNodeProtectionExecutable, NodeProtectionPeerAuthorization, NodeProtectionPeerRoleError,
    NodeProtectionPeerRoleProvider, NodeProtectionProcessIdentity,
    NodeProtectionProcessIdentityProvider, SystemNodeProtectionPeerRoleProvider,
    SystemNodeProtectionProcessIdentityProvider,
};
pub use li_node_protection_session_database::{
    DatabaseNodeProtectionSessionGenerationStore, NodeProtectionSessionGenerationError,
    NODE_PROTECTION_SESSION_GENERATION_SCHEMA_NAME,
    NODE_PROTECTION_SESSION_GENERATION_SCHEMA_VERSION,
};
pub use li_node_protection_transport::{
    NodeProtectionEndpoint, NodeProtectionRemoteError, NodeProtectionTransport,
    NodeProtectionTransportError, NodeProtectionTransportOutcome, NodeProtectionTransportRequest,
    NodeProtectionTransportResponse, NODE_PROTECTION_MAX_DOCUMENT_BYTES,
};
pub use li_node_resident::{
    NodeResident, NodeResidentError, NodeResidentHandle, NodeResidentListenerHandle,
    NodeResidentLocalListenerProvider, NodeResidentRemoteListenerProvider, NodeResidentRunControl,
    NodeResidentRunDecision, NodeResidentRunSignal, NodeResidentThreadHandle,
    NodeResidentThreadProvider, SystemNodeResidentThreadProvider,
};
pub use li_node_role::{
    LocalNodeRoleReadinessProvider, LocalNodeRoleTransition, LocalNodeRoleTransitionProof,
};
pub use li_node_runtime_maintenance::{
    NodeRuntimeMaintenanceApiPort, NodeRuntimeMaintenanceCoordinator, NodeRuntimeMaintenanceError,
    NodeRuntimeModelRetention, NodeRuntimeRemovalDisposition, NodeRuntimeRemovalProvider,
    MAXIMUM_RUNTIME_INSTALLATIONS,
};
pub use li_node_setup_identity::{
    DatabaseNodeSetupIdentityStore, NodeSetupIdentity, NodeSetupIdentityError,
    NodeSetupIdentityInput, NODE_SETUP_IDENTITY_SCHEMA_NAME, NODE_SETUP_IDENTITY_SCHEMA_VERSION,
};
pub use li_node_signal::SystemNodeResidentRunControl;
pub use li_node_storage::{
    NodeStorageApiPort, NodeStorageCandidate, NodeStorageCategory, NodeStorageCleanReceipt,
    NodeStorageCleanRequest, NodeStorageCleanupPort, NodeStorageCoordinator, NodeStorageError,
    NodeStorageObservationProvider, NodeStorageSnapshot, NodeStorageUsage,
};
pub use li_node_update::{
    core_update_disposition_name, core_update_phase_name,
    ArtifactNodeCoreUpdateAvailabilityProvider, NodeCoreUpdateApiPort,
    NodeCoreUpdateAvailabilityProvider, NodeCoreUpdateCheck, NodeCoreUpdateCheckDisposition,
    NodeCoreUpdateCoordinator, NodeCoreUpdateSummary, NodeUpdateError,
};
pub use li_node_watchdog_protocol_identity::{
    NodeWatchdogProtocolIdentityProvider, NodeWatchdogRuntimeProvider, NodeWatchdogRuntimeStatus,
    NodeWatchdogSiteStatusProvider,
};
pub use li_node_watchdog_session::{
    LinuxNodeWatchdogProcessProvider, NodeWatchdogControllerId, NodeWatchdogProcessProvider,
    NodeWatchdogProtocolTarget, NodeWatchdogSession, NodeWatchdogSessionAuthority,
    NodeWatchdogSessionError, NodeWatchdogSessionState, NodeWatchdogTargetError,
    NodeWatchdogTargetKey, NodeWatchdogTargetProvider, PersistedNodeWatchdogTargetProvider,
    VersionedNodeWatchdogSession,
};
pub use li_placement_database::DatabasePlacementStore;
pub use li_runtime_database::DatabaseRuntimeInstallationStore;

use std::sync::Arc;

use li_core_interface::{
    EntityTimestamps, FailureDescription, HardwareObservation, ModelService,
    ModelServiceDesiredState, ModelServiceId, Node, NodeId, NodeRole, NodeState, Operation,
    OperationId, OperationKind, OperationState, OperationTarget, PlacementGroupId, Sha256Digest,
    UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};

use li_node_outbox::{
    outbox_from_record, outbox_record, pending_outbox_event, NodeOutboxDatabaseRecord,
};

use li_node_hardware::{
    hardware_observation_from_record, hardware_observation_record,
    HardwareObservationDatabaseRecord,
};

use li_node_record::{
    local_node_from_record, local_node_record, local_node_record_id, node_from_record, node_record,
    operation_from_record, operation_record, LocalNodeDatabaseRecord, NodeDatabaseRecord,
    OperationDatabaseRecord,
};

use li_model_service_database::{
    model_service_from_record, model_service_record, ModelServiceDatabaseRecord,
};

// Describes one terminal outcome requested for a running operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationCompletion {
    Succeeded,
    Failed(FailureDescription),
    Cancelled,
}

// Selects one main-owned child-node lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeTransition {
    Activate,
    Pause,
    Resume,
    MarkOffline,
    Remove,
}

// Owns local node identity, operations, orchestration, and durable state access.
pub struct NodeManager {
    database: Arc<DatabaseManager>,
    local_node_id: NodeId,
}

impl NodeManager {
    // Opens one read/write node owner from an already-initialized local identity.
    pub fn load(database: Arc<DatabaseManager>) -> Result<Self, NodeManagerError> {
        drop(database.take_event_receiver()?);
        let local = database.read(DatabaseQuery::<LocalNodeDatabaseRecord>::record(
            local_node_record_id(),
        ))?;
        let DatabaseResult::Record(local) = local else {
            return Err(NodeManagerError::CorruptState {
                reason: "local node query returned a collection",
            });
        };
        let identity = local_node_from_record(local.value)?;
        let node = database.read(DatabaseQuery::<NodeDatabaseRecord>::record(
            identity.node_id().as_str(),
        ))?;
        let DatabaseResult::Record(node) = node else {
            return Err(NodeManagerError::CorruptState {
                reason: "local node query returned a collection",
            });
        };
        let node = node_from_record(node.value)?;
        if node.identity() != &identity {
            return Err(NodeManagerError::IdentityMismatch);
        }
        Ok(Self {
            database,
            local_node_id: identity.node_id().clone(),
        })
    }

    // Opens one node owner and creates its local record exactly once.
    pub fn open(
        database: Arc<DatabaseManager>,
        initial_node: Node,
        idempotency_key: &str,
    ) -> Result<(Self, NodeManagerChange<Node>), NodeManagerError> {
        let local_node_id = initial_node.identity().node_id().clone();
        drop(database.take_event_receiver()?);
        ensure_local_identity(&database, initial_node.identity(), idempotency_key)?;
        let existing = database.read(DatabaseQuery::<NodeDatabaseRecord>::record(
            local_node_id.as_str(),
        ));
        let change = match existing {
            Ok(DatabaseResult::Record(stored)) => {
                let node = node_from_record(stored.value)?;
                if node.identity() != initial_node.identity() {
                    return Err(NodeManagerError::IdentityMismatch);
                }
                NodeManagerChange::observed(node, stored.revision)
            }
            Ok(DatabaseResult::Records(_)) => {
                return Err(NodeManagerError::CorruptState {
                    reason: "single-node query returned a collection",
                });
            }
            Err(DatabaseError::NotFound { .. }) => {
                let event = NodeManagerEvent::NodeInitialized {
                    node_id: local_node_id.clone(),
                };
                let (revision, disposition) = write_node_transaction(
                    &database,
                    idempotency_key,
                    &initial_node,
                    DatabaseRevision::Missing,
                    &event,
                )?;
                NodeManagerChange::committed(
                    initial_node,
                    revision,
                    event_if_applied(disposition, event),
                )
            }
            Err(error) => return Err(error.into()),
        };
        Ok((
            Self {
                database,
                local_node_id,
            },
            change,
        ))
    }

    // Returns the exact local node identity owned by this manager.
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    // Returns whether a composition owner supplied this exact shared DatabaseManager authority.
    pub fn uses_database(&self, database: &Arc<DatabaseManager>) -> bool {
        Arc::ptr_eq(&self.database, database)
    }

    // Returns the current committed local node snapshot.
    pub fn local_node(&self) -> Result<Node, NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<NodeDatabaseRecord>::record(
                self.local_node_id.as_str(),
            ))?;
        match result {
            DatabaseResult::Record(stored) => node_from_record(stored.value),
            DatabaseResult::Records(_) => Err(NodeManagerError::CorruptState {
                reason: "single-node query returned a collection",
            }),
        }
    }

    // Returns every committed node snapshot in canonical identity order.
    pub fn nodes(&self) -> Result<Vec<Node>, NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<NodeDatabaseRecord>::all())?;
        match result {
            DatabaseResult::Records(records) => records
                .into_iter()
                .map(|stored| node_from_record(stored.value))
                .collect(),
            DatabaseResult::Record(_) => Err(NodeManagerError::CorruptState {
                reason: "node collection query returned one record",
            }),
        }
    }

    // Returns one committed node snapshot and its optimistic revision.
    pub fn node(&self, node_id: &NodeId) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        let (node, revision) = self.node_with_revision(node_id)?;
        Ok(NodeManagerChange::observed(node, revision))
    }

    // Returns the one active main authority and its optimistic revision.
    pub fn main_node(&self) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        let (node, revision) = self.active_main_with_revision()?;
        Ok(NodeManagerChange::observed(node, revision))
    }

    // Returns the latest durable hardware observation for one node when available.
    pub fn hardware_observation(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<HardwareObservation>, NodeManagerError> {
        match self
            .database
            .read(DatabaseQuery::<HardwareObservationDatabaseRecord>::record(
                node_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                let observation = hardware_observation_from_record(stored.value)?;
                if observation.node_id() != node_id {
                    return Err(NodeManagerError::CorruptState {
                        reason: "hardware record identity differs from its database key",
                    });
                }
                Ok(Some(observation))
            }
            Ok(DatabaseResult::Records(_)) => Err(NodeManagerError::CorruptState {
                reason: "hardware observation query returned a collection",
            }),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    // Atomically records one local observation and advances the node's latest pointer.
    pub fn record_local_hardware_observation(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        observation: HardwareObservation,
    ) -> Result<NodeHardwareChange, NodeManagerError> {
        let (local, local_revision) = self.node_with_revision(&self.local_node_id)?;
        if observation.node_id() != &self.local_node_id {
            return Err(NodeManagerError::InvalidHardwareObservation {
                reason: "hardware observation belongs to a different node",
            });
        }
        if local.latest_hardware_observation_id() == Some(observation.observation_id()) {
            let stored = self.hardware_observation(&self.local_node_id)?.ok_or(
                NodeManagerError::CorruptState {
                    reason: "node references a missing hardware observation",
                },
            )?;
            if stored != observation {
                return Err(NodeManagerError::CorruptState {
                    reason: "node hardware observation identity changed content",
                });
            }
            return Ok(NodeHardwareChange::observed(observation, local_revision));
        }
        if local_revision != expected_local_revision {
            return Err(DatabaseError::Conflict {
                collection: DatabaseCollection::Nodes,
                identifier: self.local_node_id.as_str().to_string(),
                expected: DatabaseRevision::Exact(expected_local_revision),
                observed: Some(local_revision),
            }
            .into());
        }
        if observation.observed_at().value() < local.timestamps().updated_at().value() {
            return Err(NodeManagerError::InvalidHardwareObservation {
                reason: "hardware observation precedes committed node state",
            });
        }
        let (hardware_revision, previous) = self.hardware_observation_with_revision()?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous.observed_at() > observation.observed_at())
        {
            return Err(NodeManagerError::InvalidHardwareObservation {
                reason: "hardware observation time moved backwards",
            });
        }
        let node = Node::new(
            local.identity().clone(),
            local.display_name().clone(),
            local.role(),
            local.state(),
            local.control_address().clone(),
            Some(observation.observation_id().clone()),
            EntityTimestamps::new(local.timestamps().created_at(), observation.observed_at())?,
        );
        let event = NodeManagerEvent::HardwareRecorded {
            observation_id: observation.observation_id().clone(),
        };
        let (node_revision, disposition) = write_hardware_transaction(
            &self.database,
            idempotency_key,
            &observation,
            hardware_revision,
            &node,
            DatabaseRevision::Exact(expected_local_revision),
            &event,
        )?;
        Ok(NodeHardwareChange::committed(
            observation,
            node_revision,
            event_if_applied(disposition, event),
        ))
    }

    // Orchestrates one HardwareManager observation into the atomic local state boundary.
    pub fn refresh_local_hardware(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        hardware: &dyn NodeHardwareObservationProvider,
    ) -> Result<NodeHardwareChange, NodeManagerError> {
        let observation = hardware.observe()?;
        self.record_local_hardware_observation(
            idempotency_key,
            expected_local_revision,
            observation,
        )
    }

    // Returns every durable logical model service in stable identity order.
    pub fn model_services(&self) -> Result<Vec<ModelService>, NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<ModelServiceDatabaseRecord>::all())?;
        match result {
            DatabaseResult::Records(records) => records
                .into_iter()
                .map(|stored| model_service_from_record(stored.value))
                .collect(),
            DatabaseResult::Record(_) => Err(NodeManagerError::CorruptState {
                reason: "model service collection query returned one record",
            }),
        }
    }

    // Returns one durable logical model service and its optimistic revision.
    pub fn model_service(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<NodeManagerChange<ModelService>, NodeManagerError> {
        let (service, revision) = self.model_service_with_revision(service_id)?;
        Ok(NodeManagerChange::observed(service, revision))
    }

    // Creates one empty stopped logical model service under active main authority.
    pub fn create_model_service(
        &self,
        idempotency_key: &str,
        service: ModelService,
    ) -> Result<NodeManagerChange<ModelService>, NodeManagerError> {
        self.require_active_main()?;
        if service.desired_state() != ModelServiceDesiredState::Stopped
            || !service.placement_group_ids().is_empty()
        {
            return Err(NodeManagerError::InvalidModelService {
                reason: "new model service must be stopped with no placement groups",
            });
        }
        if let Some((existing, revision)) = self.model_service_if_available(service.service_id())? {
            if existing != service {
                return Err(NodeManagerError::InvalidModelService {
                    reason: "model service identity already has different content",
                });
            }
            return Ok(NodeManagerChange::observed(existing, revision));
        }
        if self.model_services()?.iter().any(|existing| {
            existing.desired_state() != ModelServiceDesiredState::Removed
                && existing.logical_model() == service.logical_model()
        }) {
            return Err(NodeManagerError::InvalidModelService {
                reason: "logical model already has an active service",
            });
        }
        let service_id = service.service_id().clone();
        self.save_model_service(
            idempotency_key,
            service,
            DatabaseRevision::Missing,
            NodeManagerEvent::ModelServiceCreated { service_id },
        )
    }

    // Attaches one placement group to its owning logical service exactly once.
    pub fn attach_placement_group(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<ModelService>, NodeManagerError> {
        self.require_active_main()?;
        let (current, revision) = self.model_service_with_revision(service_id)?;
        if current.placement_group_ids().contains(&placement_group_id) {
            return Ok(NodeManagerChange::observed(current, revision));
        }
        require_model_service_revision(service_id, revision, expected_revision)?;
        if current.desired_state() == ModelServiceDesiredState::Removed {
            return Err(NodeManagerError::InvalidModelService {
                reason: "removed model service cannot accept placement groups",
            });
        }
        let mut placement_group_ids = current.placement_group_ids().to_vec();
        placement_group_ids.push(placement_group_id);
        let service = model_service_with_state(
            &current,
            current.desired_state(),
            placement_group_ids,
            updated_at,
        )?;
        self.save_model_service(
            idempotency_key,
            service,
            DatabaseRevision::Exact(expected_revision),
            NodeManagerEvent::ModelServiceUpdated {
                service_id: service_id.clone(),
            },
        )
    }

    // Detaches one placement group after its PlacementManager lifecycle releases it.
    pub fn detach_placement_group(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        placement_group_id: &PlacementGroupId,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<ModelService>, NodeManagerError> {
        self.require_active_main()?;
        let (current, revision) = self.model_service_with_revision(service_id)?;
        if !current.placement_group_ids().contains(placement_group_id) {
            return Ok(NodeManagerChange::observed(current, revision));
        }
        require_model_service_revision(service_id, revision, expected_revision)?;
        let placement_group_ids = current
            .placement_group_ids()
            .iter()
            .filter(|identity| *identity != placement_group_id)
            .cloned()
            .collect();
        let service = model_service_with_state(
            &current,
            current.desired_state(),
            placement_group_ids,
            updated_at,
        )?;
        self.save_model_service(
            idempotency_key,
            service,
            DatabaseRevision::Exact(expected_revision),
            NodeManagerEvent::ModelServiceUpdated {
                service_id: service_id.clone(),
            },
        )
    }

    // Applies one explicit running, stopped, or removed service intention.
    pub fn transition_model_service(
        &self,
        idempotency_key: &str,
        service_id: &ModelServiceId,
        desired_state: ModelServiceDesiredState,
        expected_revision: u64,
        updated_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<ModelService>, NodeManagerError> {
        self.require_active_main()?;
        let (current, revision) = self.model_service_with_revision(service_id)?;
        if current.desired_state() == desired_state {
            return Ok(NodeManagerChange::observed(current, revision));
        }
        require_model_service_revision(service_id, revision, expected_revision)?;
        if current.desired_state() == ModelServiceDesiredState::Removed
            || (desired_state == ModelServiceDesiredState::Running
                && current.placement_group_ids().is_empty())
            || (desired_state == ModelServiceDesiredState::Removed
                && !current.placement_group_ids().is_empty())
        {
            return Err(NodeManagerError::InvalidModelService {
                reason: "model service desired-state transition is invalid",
            });
        }
        let service = model_service_with_state(
            &current,
            desired_state,
            current.placement_group_ids().to_vec(),
            updated_at,
        )?;
        let event = if desired_state == ModelServiceDesiredState::Removed {
            NodeManagerEvent::ModelServiceRemoved {
                service_id: service_id.clone(),
            }
        } else {
            NodeManagerEvent::ModelServiceUpdated {
                service_id: service_id.clone(),
            }
        };
        self.save_model_service(
            idempotency_key,
            service,
            DatabaseRevision::Exact(expected_revision),
            event,
        )
    }

    // Reconfigures local main or child authority after exact external readiness proof.
    pub fn transition_local_role(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        transition: LocalNodeRoleTransition,
        changed_at: UnixMilliseconds,
        readiness: &dyn LocalNodeRoleReadinessProvider,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        let (local, local_revision) = self.node_with_revision(&self.local_node_id)?;
        if let Some(observed) =
            self.observed_local_role_transition(&local, local_revision, &transition)?
        {
            return Ok(observed);
        }
        if local.state() != NodeState::Active {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "local role changes require an active node",
            });
        }
        match &transition {
            LocalNodeRoleTransition::BecomeChild { main } => self.become_child(
                idempotency_key,
                expected_local_revision,
                local,
                main,
                &transition,
                changed_at,
                readiness,
            ),
            LocalNodeRoleTransition::BecomeMain => self.become_main(
                idempotency_key,
                expected_local_revision,
                local,
                &transition,
                changed_at,
                readiness,
            ),
        }
    }

    // Enrolls one distinct pending child under the active local main authority.
    pub fn enroll_child(
        &self,
        idempotency_key: &str,
        child: Node,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        let transaction = DatabaseTransaction::new(idempotency_key)?;
        self.enroll_child_with_transaction(idempotency_key, child, transaction)
    }

    // Applies one exact optimistic child-node lifecycle transition under main authority.
    pub fn transition_child(
        &self,
        idempotency_key: &str,
        node_id: &NodeId,
        expected_revision: u64,
        transition: NodeTransition,
        updated_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        self.require_active_main()?;
        if node_id == &self.local_node_id {
            return Err(NodeManagerError::InvalidNodeEnrollment {
                reason: "child transition cannot target the local main",
            });
        }
        let (current, observed_revision) = self.node_with_revision(node_id)?;
        if observed_revision != expected_revision
            && current.state() != transition_node_state(transition)
        {
            return Err(DatabaseError::Conflict {
                collection: DatabaseCollection::Nodes,
                identifier: node_id.as_str().to_string(),
                expected: DatabaseRevision::Exact(expected_revision),
                observed: Some(observed_revision),
            }
            .into());
        }
        if current.role() != li_core_interface::NodeRole::Child {
            return Err(NodeManagerError::InvalidNodeEnrollment {
                reason: "child transition requires a child node",
            });
        }
        let desired = desired_node_state(node_id, current.state(), transition)?;
        let node = Node::new(
            current.identity().clone(),
            current.display_name().clone(),
            current.role(),
            desired,
            current.control_address().clone(),
            current.latest_hardware_observation_id().cloned(),
            EntityTimestamps::new(current.timestamps().created_at(), updated_at)?,
        );
        self.save_node(
            idempotency_key,
            node,
            DatabaseRevision::Exact(expected_revision),
            node_transition_event(node_id.clone(), transition),
        )
    }

    // Creates one pending operation through an idempotent database command.
    pub fn begin_operation(
        &self,
        idempotency_key: &str,
        operation_id: OperationId,
        kind: OperationKind,
        target: OperationTarget,
        created_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<Operation>, NodeManagerError> {
        let operation = Operation::new(
            operation_id.clone(),
            kind,
            target,
            OperationState::Pending,
            None,
            None,
            EntityTimestamps::new(created_at, created_at)?,
        )?;
        self.save_operation(
            idempotency_key,
            operation,
            DatabaseRevision::Missing,
            NodeManagerEvent::OperationBegan { operation_id },
        )
    }

    // Moves one pending operation into its running state.
    pub fn start_operation(
        &self,
        idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        started_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<Operation>, NodeManagerError> {
        let current = self.operation_with_revision(operation_id)?;
        let operation = if current.0.state() == OperationState::Running {
            current.0
        } else {
            require_operation_state(
                operation_id,
                current.0.state(),
                &[OperationState::Pending],
                "start",
            )?;
            Operation::new(
                operation_id.clone(),
                current.0.kind(),
                current.0.target().clone(),
                OperationState::Running,
                None,
                None,
                EntityTimestamps::new(current.0.timestamps().created_at(), started_at)?,
            )?
        };
        self.save_operation(
            idempotency_key,
            operation,
            DatabaseRevision::Exact(expected_revision),
            NodeManagerEvent::OperationStarted {
                operation_id: operation_id.clone(),
            },
        )
    }

    // Completes one pending or running operation with an explicit terminal result.
    pub fn complete_operation(
        &self,
        idempotency_key: &str,
        operation_id: &OperationId,
        expected_revision: u64,
        completion: OperationCompletion,
        completed_at: UnixMilliseconds,
    ) -> Result<NodeManagerChange<Operation>, NodeManagerError> {
        let current = self.operation_with_revision(operation_id)?;
        let desired_state = completion_state(&completion);
        let operation = if current.0.state() == desired_state {
            current.0
        } else {
            let allowed = match completion {
                OperationCompletion::Succeeded => [OperationState::Running].as_slice(),
                OperationCompletion::Failed(_) | OperationCompletion::Cancelled => {
                    [OperationState::Pending, OperationState::Running].as_slice()
                }
            };
            require_operation_state(operation_id, current.0.state(), allowed, "complete")?;
            let failure = match &completion {
                OperationCompletion::Failed(failure) => Some(failure.clone()),
                OperationCompletion::Succeeded | OperationCompletion::Cancelled => None,
            };
            Operation::new(
                operation_id.clone(),
                current.0.kind(),
                current.0.target().clone(),
                desired_state,
                failure,
                Some(completed_at),
                EntityTimestamps::new(current.0.timestamps().created_at(), completed_at)?,
            )?
        };
        let event = completion_event(operation_id.clone(), desired_state);
        self.save_operation(
            idempotency_key,
            operation,
            DatabaseRevision::Exact(expected_revision),
            event,
        )
    }

    // Returns one committed operation snapshot.
    pub fn operation(&self, operation_id: &OperationId) -> Result<Operation, NodeManagerError> {
        self.operation_with_revision(operation_id)
            .map(|(operation, _)| operation)
    }

    // Returns one committed operation together with its optimistic revision.
    pub fn operation_change(
        &self,
        operation_id: &OperationId,
    ) -> Result<NodeManagerChange<Operation>, NodeManagerError> {
        let (operation, revision) = self.operation_with_revision(operation_id)?;
        Ok(NodeManagerChange::observed(operation, revision))
    }

    // Returns every committed operation snapshot in canonical identity order.
    pub fn operations(&self) -> Result<Vec<Operation>, NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<OperationDatabaseRecord>::all())?;
        match result {
            DatabaseResult::Records(records) => records
                .into_iter()
                .map(|stored| operation_from_record(stored.value))
                .collect(),
            DatabaseResult::Record(_) => Err(NodeManagerError::CorruptState {
                reason: "operation collection query returned one record",
            }),
        }
    }

    // Returns every durable outbox event in deterministic identity order.
    pub fn outbox_events(&self) -> Result<Vec<VersionedNodeOutboxEvent>, NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<NodeOutboxDatabaseRecord>::all())?;
        match result {
            DatabaseResult::Records(records) => records
                .into_iter()
                .map(|stored| {
                    Ok(VersionedNodeOutboxEvent::new(
                        outbox_from_record(stored.value)?,
                        stored.revision,
                    ))
                })
                .collect(),
            DatabaseResult::Record(_) => Err(NodeManagerError::CorruptState {
                reason: "outbox collection query returned one record",
            }),
        }
    }

    // Returns only events that still require delivery acknowledgement.
    pub fn pending_outbox_events(&self) -> Result<Vec<VersionedNodeOutboxEvent>, NodeManagerError> {
        Ok(self
            .outbox_events()?
            .into_iter()
            .filter(|event| event.event().state() == NodeOutboxState::Pending)
            .collect())
    }

    // Returns one exact durable outbox event.
    pub fn outbox_event(
        &self,
        event_id: &Sha256Digest,
    ) -> Result<VersionedNodeOutboxEvent, NodeManagerError> {
        self.outbox_event_with_revision(event_id)
    }

    // Acknowledges one delivered event without generating another outbox event.
    pub fn acknowledge_outbox_event(
        &self,
        idempotency_key: &str,
        event_id: &Sha256Digest,
        expected_revision: u64,
        acknowledged_at: UnixMilliseconds,
    ) -> Result<VersionedNodeOutboxEvent, NodeManagerError> {
        let current = self.outbox_event_with_revision(event_id)?;
        if current.event().state() == NodeOutboxState::Acknowledged {
            return Ok(current);
        }
        let acknowledged = current.event().acknowledged(acknowledged_at)?;
        let result = self.database.write(DatabaseCommand::save(
            idempotency_key,
            outbox_record(&acknowledged),
            DatabaseRevision::Exact(expected_revision),
        ))?;
        Ok(VersionedNodeOutboxEvent::new(
            acknowledged,
            result.commit().revision,
        ))
    }

    // Stops the owned database lifecycle after accepted writes complete.
    pub fn close(self) -> Result<(), NodeManagerError> {
        match Arc::try_unwrap(self.database) {
            Ok(database) => database.close().map_err(Into::into),
            Err(_) => Err(NodeManagerError::DatabaseInUse),
        }
    }

    // Returns one operation with the revision required for its next transition.
    fn operation_with_revision(
        &self,
        operation_id: &OperationId,
    ) -> Result<(Operation, u64), NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<OperationDatabaseRecord>::record(
                operation_id.as_str(),
            ))?;
        match result {
            DatabaseResult::Record(stored) => {
                Ok((operation_from_record(stored.value)?, stored.revision))
            }
            DatabaseResult::Records(_) => Err(NodeManagerError::CorruptState {
                reason: "single-operation query returned a collection",
            }),
        }
    }

    // Returns one outbox event with the revision required by acknowledgment.
    fn outbox_event_with_revision(
        &self,
        event_id: &Sha256Digest,
    ) -> Result<VersionedNodeOutboxEvent, NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<NodeOutboxDatabaseRecord>::record(
                event_id.as_str(),
            ))?;
        match result {
            DatabaseResult::Record(stored) => Ok(VersionedNodeOutboxEvent::new(
                outbox_from_record(stored.value)?,
                stored.revision,
            )),
            DatabaseResult::Records(_) => Err(NodeManagerError::CorruptState {
                reason: "single-outbox query returned a collection",
            }),
        }
    }

    // Returns one node with the revision required by its next transition.
    fn node_with_revision(&self, node_id: &NodeId) -> Result<(Node, u64), NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<NodeDatabaseRecord>::record(
                node_id.as_str(),
            ))?;
        match result {
            DatabaseResult::Record(stored) => {
                Ok((node_from_record(stored.value)?, stored.revision))
            }
            DatabaseResult::Records(_) => Err(NodeManagerError::CorruptState {
                reason: "single-node query returned a collection",
            }),
        }
    }

    // Returns one model service with the revision required by its next mutation.
    fn model_service_with_revision(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<(ModelService, u64), NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<ModelServiceDatabaseRecord>::record(
                service_id.as_str(),
            ))?;
        match result {
            DatabaseResult::Record(stored) => {
                Ok((model_service_from_record(stored.value)?, stored.revision))
            }
            DatabaseResult::Records(_) => Err(NodeManagerError::CorruptState {
                reason: "model service query returned a collection",
            }),
        }
    }

    // Returns one model service when present while preserving non-not-found failures.
    fn model_service_if_available(
        &self,
        service_id: &ModelServiceId,
    ) -> Result<Option<(ModelService, u64)>, NodeManagerError> {
        match self
            .database
            .read(DatabaseQuery::<ModelServiceDatabaseRecord>::record(
                service_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some((
                model_service_from_record(stored.value)?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(NodeManagerError::CorruptState {
                reason: "model service query returned a collection",
            }),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    // Returns one node when present while preserving every non-not-found database failure.
    fn node_if_available(&self, node_id: &NodeId) -> Result<Option<(Node, u64)>, NodeManagerError> {
        match self
            .database
            .read(DatabaseQuery::<NodeDatabaseRecord>::record(
                node_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                Ok(Some((node_from_record(stored.value)?, stored.revision)))
            }
            Ok(DatabaseResult::Records(_)) => Err(NodeManagerError::CorruptState {
                reason: "single-node query returned a collection",
            }),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    // Returns the latest hardware record and revision condition for atomic replacement.
    fn hardware_observation_with_revision(
        &self,
    ) -> Result<(DatabaseRevision, Option<HardwareObservation>), NodeManagerError> {
        match self
            .database
            .read(DatabaseQuery::<HardwareObservationDatabaseRecord>::record(
                self.local_node_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                let observation = hardware_observation_from_record(stored.value)?;
                if observation.node_id() != &self.local_node_id {
                    return Err(NodeManagerError::CorruptState {
                        reason: "hardware record identity differs from its database key",
                    });
                }
                Ok((DatabaseRevision::Exact(stored.revision), Some(observation)))
            }
            Ok(DatabaseResult::Records(_)) => Err(NodeManagerError::CorruptState {
                reason: "hardware observation query returned a collection",
            }),
            Err(DatabaseError::NotFound { .. }) => Ok((DatabaseRevision::Missing, None)),
            Err(error) => Err(error.into()),
        }
    }

    // Returns the one active main and rejects missing or split authority.
    fn active_main_with_revision(&self) -> Result<(Node, u64), NodeManagerError> {
        let result = self
            .database
            .read(DatabaseQuery::<NodeDatabaseRecord>::all())?;
        let DatabaseResult::Records(records) = result else {
            return Err(NodeManagerError::CorruptState {
                reason: "node collection query returned one record",
            });
        };
        let mut active_mains = records
            .into_iter()
            .map(|stored| Ok((node_from_record(stored.value)?, stored.revision)))
            .collect::<Result<Vec<_>, NodeManagerError>>()?
            .into_iter()
            .filter(|(node, _)| node.role() == NodeRole::Main && node.state() == NodeState::Active);
        let main = active_mains
            .next()
            .ok_or(NodeManagerError::InvalidLocalRoleTransition {
                reason: "topology must contain exactly one active main",
            })?;
        if active_mains.next().is_some() {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "topology must contain exactly one active main",
            });
        }
        Ok(main)
    }

    // Returns an existing target-role snapshot without repeating external mutation.
    fn observed_local_role_transition(
        &self,
        local: &Node,
        local_revision: u64,
        transition: &LocalNodeRoleTransition,
    ) -> Result<Option<NodeManagerChange<Node>>, NodeManagerError> {
        if local.role() != transition.target_role() {
            return Ok(None);
        }
        if local.state() != NodeState::Active {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "the existing target role is not active",
            });
        }
        let main = self.active_main_with_revision()?.0;
        match transition {
            LocalNodeRoleTransition::BecomeMain
                if main.identity().node_id() == local.identity().node_id() => {}
            LocalNodeRoleTransition::BecomeChild { main: requested }
                if same_node_authority(&main, requested) => {}
            LocalNodeRoleTransition::BecomeMain | LocalNodeRoleTransition::BecomeChild { .. } => {
                return Err(NodeManagerError::InvalidLocalRoleTransition {
                    reason: "the existing authority does not match the requested role",
                });
            }
        }
        Ok(Some(NodeManagerChange::observed(
            local.clone(),
            local_revision,
        )))
    }

    // Moves the local active main beneath one exact active destination main.
    #[allow(clippy::too_many_arguments)]
    fn become_child(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        local: Node,
        requested_main: &Node,
        transition: &LocalNodeRoleTransition,
        changed_at: UnixMilliseconds,
        readiness: &dyn LocalNodeRoleReadinessProvider,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        if local.role() != NodeRole::Main
            || requested_main.role() != NodeRole::Main
            || requested_main.state() != NodeState::Active
            || requested_main.identity().node_id() == local.identity().node_id()
        {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "becoming a child requires a distinct active destination main",
            });
        }
        let current_main = self.active_main_with_revision()?.0;
        if current_main.identity().node_id() != local.identity().node_id() {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "the local node does not own current main authority",
            });
        }
        let (authority, authority_revision) = self.authority_record(requested_main)?;
        let proof = readiness.proof(&local, transition, changed_at)?;
        proof.validate(
            local.identity().node_id(),
            NodeRole::Main,
            NodeRole::Child,
            authority.identity().node_id(),
            changed_at,
        )?;
        let updated_local = node_with_role(&local, NodeRole::Child, NodeState::Active, changed_at)?;
        let event = NodeManagerEvent::LocalRoleChanged {
            node_id: self.local_node_id.clone(),
            role: NodeRole::Child,
        };
        let (revision, disposition) = write_local_role_transaction(
            &self.database,
            idempotency_key,
            &updated_local,
            DatabaseRevision::Exact(expected_local_revision),
            &authority,
            authority_revision,
            &event,
            changed_at,
        )?;
        Ok(NodeManagerChange::committed(
            updated_local,
            revision,
            event_if_applied(disposition, event),
        ))
    }

    // Promotes the local active child and retires its previous main atomically.
    #[allow(clippy::too_many_arguments)]
    fn become_main(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        local: Node,
        transition: &LocalNodeRoleTransition,
        changed_at: UnixMilliseconds,
        readiness: &dyn LocalNodeRoleReadinessProvider,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        if local.role() != NodeRole::Child {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "becoming main requires an active local child",
            });
        }
        let (authority, authority_revision) = self.active_main_with_revision()?;
        if authority.identity().node_id() == local.identity().node_id() {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "becoming main requires a distinct current authority",
            });
        }
        let proof = readiness.proof(&local, transition, changed_at)?;
        proof.validate(
            local.identity().node_id(),
            NodeRole::Child,
            NodeRole::Main,
            authority.identity().node_id(),
            changed_at,
        )?;
        let updated_local = node_with_role(&local, NodeRole::Main, NodeState::Active, changed_at)?;
        let retired_authority =
            node_with_role(&authority, NodeRole::Main, NodeState::Removed, changed_at)?;
        let event = NodeManagerEvent::LocalRoleChanged {
            node_id: self.local_node_id.clone(),
            role: NodeRole::Main,
        };
        let (revision, disposition) = write_local_role_transaction(
            &self.database,
            idempotency_key,
            &updated_local,
            DatabaseRevision::Exact(expected_local_revision),
            &retired_authority,
            DatabaseRevision::Exact(authority_revision),
            &event,
            changed_at,
        )?;
        Ok(NodeManagerChange::committed(
            updated_local,
            revision,
            event_if_applied(disposition, event),
        ))
    }

    // Resolves and validates the destination authority's optimistic revision.
    fn authority_record(
        &self,
        candidate: &Node,
    ) -> Result<(Node, DatabaseRevision), NodeManagerError> {
        match self.node_if_available(candidate.identity().node_id())? {
            Some((existing, revision)) => {
                if !same_node_authority(&existing, candidate) {
                    return Err(NodeManagerError::NodeIdentityConflict {
                        reason: "destination main conflicts with committed authority",
                    });
                }
                self.require_unique_node_identity_except(
                    candidate,
                    candidate.identity().node_id(),
                )?;
                Ok((existing, DatabaseRevision::Exact(revision)))
            }
            None => {
                self.require_unique_node_identity(candidate)?;
                Ok((candidate.clone(), DatabaseRevision::Missing))
            }
        }
    }

    // Requires the local node to be the active main before topology mutation.
    fn require_active_main(&self) -> Result<Node, NodeManagerError> {
        let local = self.local_node()?;
        if local.role() != li_core_interface::NodeRole::Main
            || local.state() != li_core_interface::NodeState::Active
        {
            return Err(NodeManagerError::NotMain);
        }
        Ok(local)
    }

    // Requires node, machine, installation, and control address to remain globally unique.
    fn require_unique_node_identity(&self, candidate: &Node) -> Result<(), NodeManagerError> {
        self.require_unique_node_identity_except(candidate, candidate.identity().node_id())
    }

    // Requires candidate identity fields to be unique outside one optional existing record.
    fn require_unique_node_identity_except(
        &self,
        candidate: &Node,
        excluded_node_id: &NodeId,
    ) -> Result<(), NodeManagerError> {
        for node in self.nodes()? {
            if node.identity().node_id() == excluded_node_id {
                continue;
            }
            if node.identity().node_id() == candidate.identity().node_id() {
                return Err(NodeManagerError::NodeIdentityConflict {
                    reason: "node identity is already enrolled",
                });
            }
            if node.identity().machine_id() == candidate.identity().machine_id() {
                return Err(NodeManagerError::NodeIdentityConflict {
                    reason: "machine identity is already enrolled",
                });
            }
            if node.identity().installation_id() == candidate.identity().installation_id() {
                return Err(NodeManagerError::NodeIdentityConflict {
                    reason: "Core installation identity is already enrolled",
                });
            }
            if node.control_address() == candidate.control_address() {
                return Err(NodeManagerError::NodeIdentityConflict {
                    reason: "control address is already enrolled",
                });
            }
        }
        Ok(())
    }

    // Saves one node and emits its domain event only for a new durable commit.
    fn save_node(
        &self,
        idempotency_key: &str,
        node: Node,
        expected_revision: DatabaseRevision,
        event: NodeManagerEvent,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        let (revision, disposition) = write_node_transaction(
            &self.database,
            idempotency_key,
            &node,
            expected_revision,
            &event,
        )?;
        let event = event_if_applied(disposition, event);
        Ok(NodeManagerChange::committed(node, revision, event))
    }

    // Saves one operation and returns its domain event only for a new commit.
    fn save_operation(
        &self,
        idempotency_key: &str,
        operation: Operation,
        expected_revision: DatabaseRevision,
        event: NodeManagerEvent,
    ) -> Result<NodeManagerChange<Operation>, NodeManagerError> {
        let (revision, disposition) = write_operation_transaction(
            &self.database,
            idempotency_key,
            &operation,
            expected_revision,
            &event,
        )?;
        let event = event_if_applied(disposition, event);
        Ok(NodeManagerChange::committed(operation, revision, event))
    }

    // Saves one model service and emits its event only for a new durable commit.
    fn save_model_service(
        &self,
        idempotency_key: &str,
        service: ModelService,
        expected_revision: DatabaseRevision,
        event: NodeManagerEvent,
    ) -> Result<NodeManagerChange<ModelService>, NodeManagerError> {
        let (revision, disposition) = write_model_service_transaction(
            &self.database,
            idempotency_key,
            &service,
            expected_revision,
            &event,
        )?;
        Ok(NodeManagerChange::committed(
            service,
            revision,
            event_if_applied(disposition, event),
        ))
    }
}

// Atomically commits local authority, its counterpart, and one durable outbox event.
#[allow(clippy::too_many_arguments)]
fn write_local_role_transaction(
    database: &DatabaseManager,
    idempotency_key: &str,
    local: &Node,
    local_expected_revision: DatabaseRevision,
    authority: &Node,
    authority_expected_revision: DatabaseRevision,
    event: &NodeManagerEvent,
    occurred_at: UnixMilliseconds,
) -> Result<(u64, DatabaseCommitDisposition), NodeManagerError> {
    let outbox = pending_outbox_event(idempotency_key, event, occurred_at)?;
    let transaction = DatabaseTransaction::new(idempotency_key)?
        .save(node_record(local), local_expected_revision)?
        .save(node_record(authority), authority_expected_revision)?
        .save(outbox_record(&outbox), DatabaseRevision::Missing)?;
    let result = database.write_transaction(transaction)?;
    let revision = local_role_transaction_revision(
        result.commit().commits(),
        local.identity().node_id(),
        authority.identity().node_id(),
    )?;
    Ok((revision, result.disposition()))
}

// Returns the local revision from one exact local/authority/outbox transaction.
fn local_role_transaction_revision(
    commits: &[li_database::DatabaseCommit],
    local_node_id: &NodeId,
    authority_node_id: &NodeId,
) -> Result<u64, NodeManagerError> {
    if commits.len() != 3
        || commits[0].collection != DatabaseCollection::Nodes
        || commits[0].identifier != local_node_id.as_str()
        || commits[1].collection != DatabaseCollection::Nodes
        || commits[1].identifier != authority_node_id.as_str()
        || commits[2].collection != DatabaseCollection::Outbox
    {
        return Err(NodeManagerError::CorruptState {
            reason: "local role transaction commit is inconsistent",
        });
    }
    Ok(commits[0].revision)
}

// Returns one node snapshot with only role, state, and update time changed.
fn node_with_role(
    node: &Node,
    role: NodeRole,
    state: NodeState,
    updated_at: UnixMilliseconds,
) -> Result<Node, NodeManagerError> {
    if updated_at.value() < node.timestamps().updated_at().value() {
        return Err(NodeManagerError::InvalidLocalRoleTransition {
            reason: "role transition time precedes committed node state",
        });
    }
    Ok(Node::new(
        node.identity().clone(),
        node.display_name().clone(),
        role,
        state,
        node.control_address().clone(),
        node.latest_hardware_observation_id().cloned(),
        EntityTimestamps::new(node.timestamps().created_at(), updated_at)?,
    ))
}

// Returns whether two snapshots identify the same active control authority.
fn same_node_authority(first: &Node, second: &Node) -> bool {
    first.identity() == second.identity()
        && first.role() == NodeRole::Main
        && second.role() == NodeRole::Main
        && first.state() == NodeState::Active
        && second.state() == NodeState::Active
        && first.control_address() == second.control_address()
}

// Atomically commits latest hardware, its node pointer, and one durable outbox event.
#[allow(clippy::too_many_arguments)]
fn write_hardware_transaction(
    database: &DatabaseManager,
    idempotency_key: &str,
    observation: &HardwareObservation,
    hardware_expected_revision: DatabaseRevision,
    node: &Node,
    node_expected_revision: DatabaseRevision,
    event: &NodeManagerEvent,
) -> Result<(u64, DatabaseCommitDisposition), NodeManagerError> {
    let outbox = pending_outbox_event(idempotency_key, event, observation.observed_at())?;
    let transaction = DatabaseTransaction::new(idempotency_key)?
        .save(
            hardware_observation_record(observation)?,
            hardware_expected_revision,
        )?
        .save(node_record(node), node_expected_revision)?
        .save(outbox_record(&outbox), DatabaseRevision::Missing)?;
    let result = database.write_transaction(transaction)?;
    let revision =
        hardware_transaction_node_revision(result.commit().commits(), observation.node_id())?;
    Ok((revision, result.disposition()))
}

// Returns the node revision from one exact hardware/node/outbox transaction.
fn hardware_transaction_node_revision(
    commits: &[li_database::DatabaseCommit],
    node_id: &NodeId,
) -> Result<u64, NodeManagerError> {
    if commits.len() != 3
        || commits[0].collection != DatabaseCollection::HardwareObservations
        || commits[0].identifier != node_id.as_str()
        || commits[1].collection != DatabaseCollection::Nodes
        || commits[1].identifier != node_id.as_str()
        || commits[2].collection != DatabaseCollection::Outbox
    {
        return Err(NodeManagerError::CorruptState {
            reason: "hardware transaction commit is inconsistent",
        });
    }
    Ok(commits[1].revision)
}

// Atomically commits one model service together with its durable outbox event.
fn write_model_service_transaction(
    database: &DatabaseManager,
    idempotency_key: &str,
    service: &ModelService,
    expected_revision: DatabaseRevision,
    event: &NodeManagerEvent,
) -> Result<(u64, DatabaseCommitDisposition), NodeManagerError> {
    let outbox = pending_outbox_event(idempotency_key, event, service.timestamps().updated_at())?;
    let transaction = DatabaseTransaction::new(idempotency_key)?
        .save(model_service_record(service), expected_revision)?
        .save(outbox_record(&outbox), DatabaseRevision::Missing)?;
    let result = database.write_transaction(transaction)?;
    let revision = transaction_entity_revision(
        result.commit().commits(),
        DatabaseCollection::Services,
        service.service_id().as_str(),
    )?;
    Ok((revision, result.disposition()))
}

// Returns one service snapshot with explicit desired state, groups, and update time.
fn model_service_with_state(
    current: &ModelService,
    desired_state: ModelServiceDesiredState,
    placement_group_ids: Vec<PlacementGroupId>,
    updated_at: UnixMilliseconds,
) -> Result<ModelService, NodeManagerError> {
    if updated_at < current.timestamps().updated_at() {
        return Err(NodeManagerError::InvalidModelService {
            reason: "model service update time moved backwards",
        });
    }
    ModelService::new(
        current.service_id().clone(),
        current.logical_model().clone(),
        desired_state,
        placement_group_ids,
        EntityTimestamps::new(current.timestamps().created_at(), updated_at)?,
    )
    .map_err(Into::into)
}

// Requires one caller revision to match current model-service state.
fn require_model_service_revision(
    service_id: &ModelServiceId,
    observed_revision: u64,
    expected_revision: u64,
) -> Result<(), NodeManagerError> {
    if observed_revision == expected_revision {
        return Ok(());
    }
    Err(DatabaseError::Conflict {
        collection: DatabaseCollection::Services,
        identifier: service_id.as_str().to_string(),
        expected: DatabaseRevision::Exact(expected_revision),
        observed: Some(observed_revision),
    }
    .into())
}

// Atomically commits one node snapshot together with its durable outbox event.
fn write_node_transaction(
    database: &DatabaseManager,
    idempotency_key: &str,
    node: &Node,
    expected_revision: DatabaseRevision,
    event: &NodeManagerEvent,
) -> Result<(u64, DatabaseCommitDisposition), NodeManagerError> {
    let outbox = pending_outbox_event(idempotency_key, event, node.timestamps().updated_at())?;
    let transaction = DatabaseTransaction::new(idempotency_key)?
        .save(node_record(node), expected_revision)?
        .save(outbox_record(&outbox), DatabaseRevision::Missing)?;
    let result = database.write_transaction(transaction)?;
    let revision = transaction_entity_revision(
        result.commit().commits(),
        DatabaseCollection::Nodes,
        node.identity().node_id().as_str(),
    )?;
    Ok((revision, result.disposition()))
}

// Atomically commits one operation snapshot together with its durable outbox event.
fn write_operation_transaction(
    database: &DatabaseManager,
    idempotency_key: &str,
    operation: &Operation,
    expected_revision: DatabaseRevision,
    event: &NodeManagerEvent,
) -> Result<(u64, DatabaseCommitDisposition), NodeManagerError> {
    let outbox = pending_outbox_event(idempotency_key, event, operation.timestamps().updated_at())?;
    let transaction = DatabaseTransaction::new(idempotency_key)?
        .save(operation_record(operation), expected_revision)?
        .save(outbox_record(&outbox), DatabaseRevision::Missing)?;
    let result = database.write_transaction(transaction)?;
    let revision = transaction_entity_revision(
        result.commit().commits(),
        DatabaseCollection::Operations,
        operation.operation_id().as_str(),
    )?;
    Ok((revision, result.disposition()))
}

// Returns one exact entity revision from a two-record entity/outbox transaction.
fn transaction_entity_revision(
    commits: &[li_database::DatabaseCommit],
    collection: DatabaseCollection,
    identifier: &str,
) -> Result<u64, NodeManagerError> {
    if commits.len() != 2
        || commits[0].collection != collection
        || commits[0].identifier != identifier
        || commits[1].collection != DatabaseCollection::Outbox
    {
        return Err(NodeManagerError::CorruptState {
            reason: "entity/outbox transaction commit is inconsistent",
        });
    }
    Ok(commits[0].revision)
}

// Creates or verifies the singleton local node identity before node registration.
fn ensure_local_identity(
    database: &DatabaseManager,
    identity: &li_core_interface::NodeIdentity,
    idempotency_key: &str,
) -> Result<(), NodeManagerError> {
    match database.read(DatabaseQuery::<LocalNodeDatabaseRecord>::record(
        local_node_record_id(),
    )) {
        Ok(DatabaseResult::Record(stored)) => {
            if local_node_from_record(stored.value)? != *identity {
                return Err(NodeManagerError::IdentityMismatch);
            }
            Ok(())
        }
        Ok(DatabaseResult::Records(_)) => Err(NodeManagerError::CorruptState {
            reason: "local identity query returned a collection",
        }),
        Err(DatabaseError::NotFound { .. }) => {
            database.write(DatabaseCommand::save(
                scoped_idempotency_key(idempotency_key, "identity")?,
                local_node_record(identity),
                DatabaseRevision::Missing,
            ))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

// Returns one bounded manager-owned idempotency identity.
fn scoped_idempotency_key(
    idempotency_key: &str,
    scope: &'static str,
) -> Result<String, NodeManagerError> {
    let value = format!("{idempotency_key}:{scope}");
    if value.len() > 255 {
        return Err(NodeManagerError::CorruptState {
            reason: "scoped idempotency key exceeds the database bound",
        });
    }
    Ok(value)
}

// Requires one operation to be in an allowed state before mutation.
fn require_operation_state(
    operation_id: &OperationId,
    current: OperationState,
    allowed: &[OperationState],
    action: &'static str,
) -> Result<(), NodeManagerError> {
    if allowed.contains(&current) {
        return Ok(());
    }
    Err(NodeManagerError::InvalidOperationTransition {
        operation_id: operation_id.as_str().to_string(),
        current: operation_state_name(current),
        action,
    })
}

// Returns the terminal state represented by one completion request.
fn completion_state(completion: &OperationCompletion) -> OperationState {
    match completion {
        OperationCompletion::Succeeded => OperationState::Succeeded,
        OperationCompletion::Failed(_) => OperationState::Failed,
        OperationCompletion::Cancelled => OperationState::Cancelled,
    }
}

// Returns the past-tense event corresponding to one terminal operation state.
fn completion_event(operation_id: OperationId, state: OperationState) -> NodeManagerEvent {
    match state {
        OperationState::Succeeded => NodeManagerEvent::OperationSucceeded { operation_id },
        OperationState::Failed => NodeManagerEvent::OperationFailed { operation_id },
        OperationState::Cancelled => NodeManagerEvent::OperationCancelled { operation_id },
        OperationState::Pending | OperationState::Running => {
            unreachable!("completion state is always terminal")
        }
    }
}

// Returns the exact target state allowed by one child lifecycle action.
fn desired_node_state(
    node_id: &NodeId,
    current: li_core_interface::NodeState,
    transition: NodeTransition,
) -> Result<li_core_interface::NodeState, NodeManagerError> {
    use li_core_interface::NodeState;

    let desired = match (current, transition) {
        (NodeState::Pending, NodeTransition::Activate)
        | (NodeState::Draining, NodeTransition::Resume)
        | (NodeState::Offline, NodeTransition::Resume) => NodeState::Active,
        (NodeState::Active, NodeTransition::Pause) => NodeState::Draining,
        (NodeState::Active | NodeState::Draining, NodeTransition::MarkOffline) => {
            NodeState::Offline
        }
        (NodeState::Pending | NodeState::Draining | NodeState::Offline, NodeTransition::Remove) => {
            NodeState::Removed
        }
        (state, transition) if state == transition_node_state(transition) => state,
        _ => {
            return Err(NodeManagerError::InvalidNodeTransition {
                node_id: node_id.as_str().to_string(),
                current: node_state_name(current),
                action: node_transition_name(transition),
            })
        }
    };
    Ok(desired)
}

// Returns the stable state produced by one idempotent node transition.
fn transition_node_state(transition: NodeTransition) -> li_core_interface::NodeState {
    use li_core_interface::NodeState;

    match transition {
        NodeTransition::Activate | NodeTransition::Resume => NodeState::Active,
        NodeTransition::Pause => NodeState::Draining,
        NodeTransition::MarkOffline => NodeState::Offline,
        NodeTransition::Remove => NodeState::Removed,
    }
}

// Returns the stable action name for one node transition.
fn node_transition_name(transition: NodeTransition) -> &'static str {
    match transition {
        NodeTransition::Activate => "activate",
        NodeTransition::Pause => "pause",
        NodeTransition::Resume => "resume",
        NodeTransition::MarkOffline => "mark offline",
        NodeTransition::Remove => "remove",
    }
}

// Returns the stable public state name for one node snapshot.
fn node_state_name(state: li_core_interface::NodeState) -> &'static str {
    match state {
        li_core_interface::NodeState::Pending => "pending",
        li_core_interface::NodeState::Active => "active",
        li_core_interface::NodeState::Draining => "draining",
        li_core_interface::NodeState::Offline => "offline",
        li_core_interface::NodeState::Removed => "removed",
    }
}

// Returns the committed event corresponding to one child lifecycle action.
fn node_transition_event(node_id: NodeId, transition: NodeTransition) -> NodeManagerEvent {
    match transition {
        NodeTransition::Activate | NodeTransition::Resume => {
            NodeManagerEvent::NodeActivated { node_id }
        }
        NodeTransition::Pause => NodeManagerEvent::NodePaused { node_id },
        NodeTransition::MarkOffline => NodeManagerEvent::NodeMarkedOffline { node_id },
        NodeTransition::Remove => NodeManagerEvent::NodeRemoved { node_id },
    }
}

// Returns one domain event only when this command created the durable commit.
fn event_if_applied(
    disposition: DatabaseCommitDisposition,
    event: NodeManagerEvent,
) -> Option<NodeManagerEvent> {
    match disposition {
        DatabaseCommitDisposition::Applied => Some(event),
        DatabaseCommitDisposition::Replayed => None,
    }
}

// Returns the stable interface name for one operation state.
fn operation_state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Pending => "pending",
        OperationState::Running => "running",
        OperationState::Succeeded => "succeeded",
        OperationState::Failed => "failed",
        OperationState::Cancelled => "cancelled",
    }
}
