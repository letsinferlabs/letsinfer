// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use li_audit_manager::{
    AuditActor, AuditActorId, AuditActorType, AuditOrigin, AuditOriginInterface,
};
use li_authentication_manager::{
    AuthenticationManager, ControllerCertificateProvider, ControllerRole, PeerCredentialDirection,
    SystemApiKeyMaterialProvider, SystemAuthenticationClock,
};
use li_benchmark_worker::{
    NativeBenchmarkTelemetrySource, NativeBenchmarkWatchdogInput,
    SystemNativeBenchmarkWatchdogTransport, WatchdogBenchmarkTelemetrySource,
};
use li_core_interface::{
    ControllerId, CredentialId, ModelServiceDesiredState, Node, NodeId, NodeRole, NodeState,
    OperationState, UnixMilliseconds,
};
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateReleasePlatform, CoreUpdateServiceContext,
    CoreUpdateServicePlatform,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_gateway_manager::{
    AuthenticationManagerGatewayProvider, GatewayConfiguration, GatewayConfigurationFile,
    GatewayExposureCoordinator, GatewayExposureStore, GatewayHealthError, GatewayHealthObservation,
    GatewayHealthProbe, SystemGatewayExposureProvider, SystemGatewayHealthExchange,
    SystemGatewayNativeFileIo,
};
use li_hardware_manager::{
    HardwareManager, LinuxHardwareConfiguration, LinuxHardwareProvider, MacOsHardwareConfiguration,
    MacOsHardwareProvider, SystemHardwareClock, SystemHardwareIdentityProvider,
    SystemHardwareNativeIo,
};
use li_node_manager::{
    DatabaseAuthenticationStore, DatabaseControllerStore, DatabaseGatewayExposureStore,
    DatabaseGatewayUsageStore, DatabaseNodeBenchmarkCandidateHandoffStore,
    DatabaseNodeBenchmarkVerificationProjectionProvider, DatabaseNodeCommandAuditSessionStore,
    DatabaseNodeGatewayRelayTrustStore, DatabaseNodeModelJournalStore, DatabasePlacementStore,
    DatabaseRuntimeInstallationStore, LocalNodeRoleReadinessProvider, LocalNodeRoleTransition,
    LocalNodeRoleTransitionProof, ManagedNodeExposureApi, ManagedNodeGatewayCapabilityPort,
    ManagedNodeModelPlacementPort, ManagedNodeModelRuntimePort,
    NativeNodeModelPlacementRequestProvider, NodeAuditCheckpointKeyReferences,
    NodeAuthenticationCoordinator, NodeBenchmarkCandidateHandoffCoordinator,
    NodeCommandAuditCoordinator, NodeConfiguration, NodeConfigurationFileReference, NodeDaemon,
    NodeGatewayApi, NodeGatewayNativeTargetProvider, NodeGatewayRouteProvider,
    NodeHardwareConfiguration, NodeHealthError, NodeHealthProbe, NodeHostGatewaySummary,
    NodeHostGatewayTelemetrySummary, NodeHostPlacementGroup, NodeHostProjectionPorts,
    NodeHostProtectionReadPort, NodeHostProtectionSummary, NodeHostReadError,
    NodeHostServiceReadPort, NodeHostServiceState, NodeHostTopologyReadPort,
    NodeHostWatchdogSummary, NodeHostWatchdogTelemetrySummary, NodeManager, NodeManagerError,
    NodePairingActivationAuthority, NodePairingDocumentEndpoint, NodePairingTlsConnectionService,
    NodePairingTlsFileSet, NodePairingTlsServerConfiguration, NodePrivateAction, NodePrivateApi,
    NodePrivateAuthorizationProvider, NodePrivateEndpoint, NodePrivateLocalEndpoint,
    NodePrivateLocalServer, NodePrivateRemoteServer, NodePrivateRemoteTlsConfiguration,
    NodePrivateRemoteTlsConnectionService, NodeResident, NodeResidentError, NodeResidentHandle,
    NodeRuntimeMaintenanceCoordinator, NodeStorageCategory, NodeStorageCoordinator,
    OpenSslNodeAuditCheckpointCryptography, PersistedNodeGatewayRelayAuthorizationProvider,
    PersistedNodeGatewayRelayTargetProvider, SystemNodeAuditOpenSslRunner,
    SystemNodeConfigurationFileProvider, SystemNodeDaemonClock, SystemNodeGatewayRelayClock,
    SystemNodeHealthExchange, SystemNodeModelClock, SystemNodePrivateLocalSocketProvider,
    SystemNodePrivateRemoteSocketProvider, SystemNodePrivateRemoteTlsFileProvider,
    SystemNodeResidentRunControl, SystemNodeResidentThreadProvider,
};

#[cfg(target_os = "linux")]
use li_core_interface::{
    Placement, PlacementState, RuntimeInstallationId, RuntimeInstallationState,
};
#[cfg(target_os = "linux")]
use li_node_manager::{
    DatabaseNodeProtectionSessionGenerationStore, NodeGatewayProtectionLeaseProvider,
    NodeHostProtectionState, NodeProtectionAction, NodeProtectionApi, NodeProtectionApiError,
    NodeProtectionAuthorizationProvider, NodeProtectionBindingProvider, NodeProtectionLeaseError,
    NodeProtectionLeaseStore, NodeProtectionLocalServer, NodeProtectionPeerRoleProvider,
    NodeProtectionSnapshotProvider, NodeProtectionTargetProvider, NodeWatchdogRuntimeProvider,
    NodeWatchdogRuntimeStatus, NodeWatchdogSessionAuthority, NodeWatchdogSiteStatusProvider,
    PersistedNodeProtectionBindingProvider, PersistedNodeWatchdogTargetProvider,
    SystemNodeProtectionClock, SystemNodeProtectionPeerRoleProvider,
};
use li_pairing_manager::{
    NativePairingCandidateDiscoveryProvider, OpenSslPairingCandidateTrustProvider,
    PairingCandidateAdvertisement, PairingCandidateIdentityFiles, PairingDiscoveryPlatform,
    PairingNativeCommandRunner, PairingTrustWorkspaceIo, SystemPairingClock,
    SystemPairingMaterialProvider, SystemPairingNativeCommandRunner, SystemPairingTrustWorkspaceIo,
    PAIRING_DISCOVERY_PORT,
};
#[cfg(target_os = "linux")]
use li_placement_manager::{
    FilesystemLinuxPlacementProtectionProvider, LinuxPlacementProtectedTargetProvider,
    PlacementProtectedTarget, SystemLinuxProtectionIo, SystemProtectionGenerationProvider,
};
use li_placement_manager::{PlacementCredentialReader, PlacementLink, PlacementManager};
use li_runtime_manager::{
    RuntimeExecutionManifestProvider, RuntimeInstallationStore, RuntimeManager,
    SignedRuntimeCatalogProvider,
};
#[cfg(target_os = "linux")]
use li_runtime_manager::{RuntimeInstallationProvider, StoredRuntimeInstallationProvider};
use li_watchdog_manager::{
    SystemWatchdogGatewayTelemetryFileProvider, WatchdogGatewayTelemetryProvider,
    WatchdogLinuxCapability, WatchdogSampleTelemetry,
};
#[cfg(target_os = "linux")]
use li_watchdog_manager::{
    SystemWatchdogLinuxHostFileProvider, SystemWatchdogLinuxPidFdProvider,
    SystemWatchdogLinuxProcessProvider, WatchdogLinuxProcessLayout, WatchdogLinuxProcessProvider,
    WatchdogProtocolDataError,
};

#[cfg(target_os = "linux")]
const PLACEMENT_ACKNOWLEDGEMENT_ATTEMPTS: u16 = 100;
#[cfg(target_os = "linux")]
const PLACEMENT_ACKNOWLEDGEMENT_INTERVAL: Duration = Duration::from_millis(10);

use crate::{
    compose_core_model_placement, compose_core_model_runtime, compose_core_node_pairing_api,
    compose_system_core_benchmark_with_verification,
    compose_system_core_controller_authorization_projection, compose_system_core_update,
    ApplicationCoreBenchmarkConfiguration, ApplicationCoreBenchmarkManagers,
    ApplicationCoreBenchmarkPorts, ApplicationCoreBenchmarkVerificationApi,
    ApplicationCoreBenchmarkVerificationComposition, ApplicationCoreBenchmarkVerificationHandoff,
    ApplicationSystemCoreUpdateConfiguration, CoreBenchmarkVerificationPreparation,
    CoreControllerAuthorizationProjectionConfiguration, CoreControllerCertificateAuthorityFiles,
    CoreModelPlacementCompositionInput, CoreModelPlacementPlatformInput,
    CoreModelRuntimeCompositionInput, CoreNodeCatalogApi, CoreNodePrincipalResolver,
    CoreNodeStorageRoot, CorePairingCandidate, CoreResidentProcess, CoreServiceSetupError,
    CoreServiceSetupNodeIdentity, CoreServiceSetupObservation, CoreServiceSetupResidentHealth,
    DatabasePeerCredentialStore, FilesystemCoreBenchmarkCommunityAuthority,
    FilesystemCoreNodeStorageObservationProvider, ManagerCoreBenchmarkVerificationSubjectResolver,
    RcgenCoreControllerCertificateProvider, ReadOnlyCoreNodeStorageCleanupPort,
    ReadOnlyCoreNodeStorageEntryProvider, SetupEd25519CoreBenchmarkVerificationSnapshotSigner,
    SystemCoreBenchmarkVerificationCommandRunner,
    SystemCoreBenchmarkVerificationGitHubCommandRunner, SystemCoreBenchmarkVerificationOracle,
    SystemCoreBenchmarkVerificationPublicationFactory,
    SystemCoreBenchmarkVerificationSnapshotPublisher, SystemCoreBenchmarkVerificationWallClock,
    SystemCoreGatewayExposureReadiness, SystemCoreNodeStorageFilesystem,
    UnavailableCoreControllerCertificateProvider, WatchdogCoreBenchmarkTelemetryObservationPort,
};

// Names stable process-boundary failures without exposing paths, credentials, or provider detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreNodeProcessError {
    InvalidArguments,
    ConfigurationUnavailable,
    CompositionUnavailable,
    RuntimeUnavailable,
}

impl fmt::Display for CoreNodeProcessError {
    // Presents one fixed resident-process failure suitable for native service logs.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str("li_node arguments are invalid"),
            Self::ConfigurationUnavailable => {
                formatter.write_str("li_node configuration is unavailable")
            }
            Self::CompositionUnavailable => {
                formatter.write_str("li_node composition is unavailable")
            }
            Self::RuntimeUnavailable => formatter.write_str("li_node runtime failed"),
        }
    }
}

// Proves a local paired-role transition only after every Node-owned activity surface is clear.
struct CoreNodePairingRoleReadiness {
    nodes: Arc<NodeManager>,
    exposure: DatabaseGatewayExposureStore,
}

impl LocalNodeRoleReadinessProvider for CoreNodePairingRoleReadiness {
    // Binds one short-lived role proof to the exact current and destination authorities.
    fn proof(
        &self,
        local: &Node,
        transition: &LocalNodeRoleTransition,
        now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
        let authority_node_id = match transition {
            LocalNodeRoleTransition::BecomeChild { main } => {
                let nodes = self.nodes.nodes()?;
                let services = self.nodes.model_services()?;
                let operations = self.nodes.operations()?;
                let exposure = self
                    .exposure
                    .exposure()
                    .map_err(|_| pairing_readiness_error())?;
                if local.role() != NodeRole::Main
                    || nodes.len() != 1
                    || nodes[0].identity() != local.identity()
                    || services.iter().any(|service| {
                        service.desired_state() != ModelServiceDesiredState::Removed
                            || !service.placement_group_ids().is_empty()
                    })
                    || operations.iter().any(|operation| {
                        matches!(
                            operation.state(),
                            OperationState::Pending | OperationState::Running
                        )
                    })
                    || exposure.is_some()
                {
                    return Err(pairing_readiness_error());
                }
                main.identity().node_id().clone()
            }
            LocalNodeRoleTransition::BecomeMain => paired_main_authority(local, &self.nodes)?,
        };
        LocalNodeRoleTransitionProof::new(
            local.identity().node_id().clone(),
            local.role(),
            transition.target_role(),
            authority_node_id,
            now,
            UnixMilliseconds::new(now.value().saturating_add(60_000)),
        )
    }
}

// Selects the sole distinct active main required by a child-to-main restoration proof.
fn paired_main_authority(local: &Node, nodes: &NodeManager) -> Result<NodeId, NodeManagerError> {
    let matching = nodes
        .nodes()?
        .into_iter()
        .filter(|node| {
            node.role() == NodeRole::Main
                && node.state() == NodeState::Active
                && node.identity().node_id() != local.identity().node_id()
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(pairing_readiness_error());
    }
    Ok(matching[0].identity().node_id().clone())
}

// Creates one stable NodeManager denial for an unsafe paired-role transition.
const fn pairing_readiness_error() -> NodeManagerError {
    NodeManagerError::InvalidLocalRoleTransition {
        reason: "pairing role transition is not safe",
    }
}

// Selects the minimum durable controller role for every private Node action.
const fn controller_role_for_action(action: NodePrivateAction) -> ControllerRole {
    match action {
        NodePrivateAction::ReadLocalNode
        | NodePrivateAction::ReadNodes
        | NodePrivateAction::ReadNode
        | NodePrivateAction::ReadHardware
        | NodePrivateAction::ReadHostProjection
        | NodePrivateAction::ReadCatalog
        | NodePrivateAction::ReadCompatibleTargets
        | NodePrivateAction::ReadOutbox
        | NodePrivateAction::ReadPairingStatus
        | NodePrivateAction::PreviewBenchmark
        | NodePrivateAction::ReadActiveBenchmark
        | NodePrivateAction::ReadBenchmark
        | NodePrivateAction::ListModels
        | NodePrivateAction::PreviewRollbackModel
        | NodePrivateAction::ReadModelLogs
        | NodePrivateAction::ReadModelRuntimeLogs => ControllerRole::Viewer,
        NodePrivateAction::StartBenchmark
        | NodePrivateAction::StopBenchmark
        | NodePrivateAction::PauseModel
        | NodePrivateAction::ResumeModel
        | NodePrivateAction::RestartModel
        | NodePrivateAction::RecoverModel => ControllerRole::Operator,
        NodePrivateAction::ReadHostInventory
        | NodePrivateAction::ReadStorage
        | NodePrivateAction::CleanStorage
        | NodePrivateAction::EnrollChild
        | NodePrivateAction::TransitionChild
        | NodePrivateAction::AcknowledgeOutbox
        | NodePrivateAction::OpenPairing
        | NodePrivateAction::EnrollPairing
        | NodePrivateAction::ApprovePairing
        | NodePrivateAction::AddController
        | NodePrivateAction::ReadControllers
        | NodePrivateAction::RevokeController
        | NodePrivateAction::CreateApiKey
        | NodePrivateAction::ReadApiKeys
        | NodePrivateAction::ReadApiKey
        | NodePrivateAction::UpdateApiKeyPolicy
        | NodePrivateAction::RotateApiKey
        | NodePrivateAction::RevokeApiKey
        | NodePrivateAction::OpenCommandAudit
        | NodePrivateAction::CompleteCommandAudit
        | NodePrivateAction::ReadAuditEvents
        | NodePrivateAction::ReadAuditEvent
        | NodePrivateAction::VerifyAudit
        | NodePrivateAction::ExportAudit
        | NodePrivateAction::InstallModel
        | NodePrivateAction::RemoveModel
        | NodePrivateAction::RollbackModel
        | NodePrivateAction::CheckCoreUpdate
        | NodePrivateAction::UpdateCore
        | NodePrivateAction::UpdateModel
        | NodePrivateAction::ReadExposure
        | NodePrivateAction::EnableExposure
        | NodePrivateAction::DisableExposure
        | NodePrivateAction::ReadRuntimeInstallationIds
        | NodePrivateAction::RemoveRuntimeInstallation
        | NodePrivateAction::Uninstall
        | NodePrivateAction::ActivatePairedChild
        | NodePrivateAction::RestorePairedMain
        | NodePrivateAction::Gateway => ControllerRole::Administrator,
    }
}

impl Error for CoreNodeProcessError {}

// Owns the exact persisted identity and local private-API probe used by service setup.
pub struct CoreNodeServiceHealth {
    configuration: NodeConfiguration,
    probe: NodeHealthProbe,
}

impl CoreNodeServiceHealth {
    // Loads owner-bound configuration without opening the Node-owned writable database.
    pub fn load(
        configuration_file: PathBuf,
        owner_user_id: u32,
    ) -> Result<Self, CoreServiceSetupError> {
        let reference = NodeConfigurationFileReference::new(configuration_file, owner_user_id)
            .map_err(|_| node_health_provider_error("Node health configuration is invalid"))?;
        let configuration =
            NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider)
                .map_err(|_| node_health_provider_error("Node health configuration is invalid"))?;
        Ok(Self {
            configuration,
            probe: NodeHealthProbe::new(Box::new(SystemNodeHealthExchange)),
        })
    }

    // Observes one role or exact setup identity through the owner-UID local Node API.
    fn observe_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: std::time::Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        let expected_role = node_role(context.role());
        if process != CoreResidentProcess::Node
            || identity
                .map(|identity| identity.role() != expected_role)
                .unwrap_or(false)
        {
            return Err(node_health_provider_error(
                "Node health request does not match its service role",
            ));
        }
        match self.probe.observe_expected(
            &self.configuration,
            identity.map(CoreServiceSetupNodeIdentity::node_id),
            expected_role,
            timeout,
        ) {
            Ok(()) => Ok(CoreServiceSetupObservation::Ready),
            Err(NodeHealthError::EndpointUnavailable | NodeHealthError::NotReady) => {
                Ok(CoreServiceSetupObservation::NotReady)
            }
            Err(NodeHealthError::InvalidContract | NodeHealthError::InvalidResponse) => Err(
                node_health_provider_error("Node health response is invalid"),
            ),
        }
    }
}

impl CoreServiceSetupResidentHealth for CoreNodeServiceHealth {
    // Requires role-exact active persisted identity through the live owner-authenticated endpoint.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: std::time::Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.observe_identity(context, process, None, timeout)
    }

    // Requires setup readiness to match the exact prepared Node identity and role.
    fn observe_with_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: std::time::Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.observe_identity(context, process, identity, timeout)
    }
}

// Holds the one strict command-line input emitted by CoreProcessLayout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreNodeProcessArguments {
    configuration: PathBuf,
}

impl CoreNodeProcessArguments {
    // Parses exactly `--configuration ABSOLUTE_PATH` without accepting aliases or extra fields.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, CoreNodeProcessError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments.len() != 2 || arguments[0] != OsStr::new("--configuration") {
            return Err(CoreNodeProcessError::InvalidArguments);
        }
        let configuration = PathBuf::from(&arguments[1]);
        if !configuration.is_absolute() {
            return Err(CoreNodeProcessError::InvalidArguments);
        }
        Ok(Self { configuration })
    }

    // Returns the exact absolute configuration selected by CoreProcessLayout.
    pub fn configuration(&self) -> &std::path::Path {
        &self.configuration
    }
}

// Revalidates one exact active peer credential before every private action dispatch.
struct CoreNodePrivateAuthorizationProvider {
    authentication: Arc<AuthenticationManager>,
    local_node_id: NodeId,
    local_role: li_core_interface::NodeRole,
}

impl CoreNodePrivateAuthorizationProvider {
    // Creates one authorization adapter for the exact persisted local Node role.
    const fn new_for_role(
        authentication: Arc<AuthenticationManager>,
        local_node_id: NodeId,
        local_role: li_core_interface::NodeRole,
    ) -> Self {
        Self {
            authentication,
            local_node_id,
            local_role,
        }
    }
}

impl NodePrivateAuthorizationProvider for CoreNodePrivateAuthorizationProvider {
    // Revalidates the full child-to-main relationship and denies unassigned remote capabilities.
    fn authorize(
        &self,
        principal_id: &CredentialId,
        action: NodePrivateAction,
    ) -> Result<(), li_node_manager::NodePrivateApiError> {
        let principal = self
            .authentication
            .authorize_peer_credential(principal_id)
            .map_err(|_| li_node_manager::NodePrivateApiError::AuthorizationDenied)?;
        let direction = match self.local_role {
            li_core_interface::NodeRole::Main => PeerCredentialDirection::ChildToMain,
            li_core_interface::NodeRole::Child => PeerCredentialDirection::MainToChild,
        };
        if principal.local_node_id() != &self.local_node_id
            || principal.peer_node_id() == &self.local_node_id
            || principal.direction() != direction
        {
            return Err(li_node_manager::NodePrivateApiError::AuthorizationDenied);
        }
        if self.local_role == li_core_interface::NodeRole::Child {
            return match action {
                NodePrivateAction::ReadLocalNode | NodePrivateAction::ReadHardware => Ok(()),
                _ => Err(li_node_manager::NodePrivateApiError::AuthorizationDenied),
            };
        }
        match action {
            NodePrivateAction::ReadLocalNode
            | NodePrivateAction::ReadNodes
            | NodePrivateAction::ReadNode
            | NodePrivateAction::ReadHardware
            | NodePrivateAction::ReadHostProjection
            | NodePrivateAction::ReadHostInventory
            | NodePrivateAction::ReadStorage
            | NodePrivateAction::CleanStorage
            | NodePrivateAction::ReadCatalog
            | NodePrivateAction::ReadCompatibleTargets
            | NodePrivateAction::EnrollChild
            | NodePrivateAction::TransitionChild
            | NodePrivateAction::ReadOutbox
            | NodePrivateAction::AcknowledgeOutbox
            | NodePrivateAction::OpenPairing
            | NodePrivateAction::EnrollPairing
            | NodePrivateAction::ApprovePairing
            | NodePrivateAction::ReadPairingStatus
            | NodePrivateAction::PreviewBenchmark
            | NodePrivateAction::StartBenchmark
            | NodePrivateAction::ReadActiveBenchmark
            | NodePrivateAction::ReadBenchmark
            | NodePrivateAction::StopBenchmark
            | NodePrivateAction::AddController
            | NodePrivateAction::ReadControllers
            | NodePrivateAction::RevokeController
            | NodePrivateAction::CreateApiKey
            | NodePrivateAction::ReadApiKeys
            | NodePrivateAction::ReadApiKey
            | NodePrivateAction::UpdateApiKeyPolicy
            | NodePrivateAction::RotateApiKey
            | NodePrivateAction::RevokeApiKey
            | NodePrivateAction::OpenCommandAudit
            | NodePrivateAction::CompleteCommandAudit
            | NodePrivateAction::ReadAuditEvents
            | NodePrivateAction::ReadAuditEvent
            | NodePrivateAction::VerifyAudit
            | NodePrivateAction::ExportAudit
            | NodePrivateAction::ListModels
            | NodePrivateAction::InstallModel
            | NodePrivateAction::PauseModel
            | NodePrivateAction::ResumeModel
            | NodePrivateAction::RestartModel
            | NodePrivateAction::RecoverModel
            | NodePrivateAction::RemoveModel
            | NodePrivateAction::RollbackModel
            | NodePrivateAction::PreviewRollbackModel
            | NodePrivateAction::ReadModelLogs
            | NodePrivateAction::ReadModelRuntimeLogs => {
                Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
            }
            NodePrivateAction::CheckCoreUpdate
            | NodePrivateAction::UpdateCore
            | NodePrivateAction::UpdateModel
            | NodePrivateAction::ReadExposure
            | NodePrivateAction::EnableExposure
            | NodePrivateAction::DisableExposure
            | NodePrivateAction::ReadRuntimeInstallationIds
            | NodePrivateAction::RemoveRuntimeInstallation
            | NodePrivateAction::Uninstall
            | NodePrivateAction::ActivatePairedChild
            | NodePrivateAction::RestorePairedMain
            | NodePrivateAction::Gateway => {
                Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
            }
        }
    }

    // Revalidates exact controller identity, DER fingerprint, lifetime, state, and role per action.
    fn authorize_controller(
        &self,
        controller_id: &ControllerId,
        certificate_sha256: &li_core_interface::Sha256Digest,
        action: NodePrivateAction,
    ) -> Result<(), li_node_manager::NodePrivateApiError> {
        if self.local_role != li_core_interface::NodeRole::Main {
            return Err(li_node_manager::NodePrivateApiError::AuthorizationDenied);
        }
        self.authentication
            .authorize_controller(
                controller_id,
                certificate_sha256,
                controller_role_for_action(action),
            )
            .map(|_| ())
            .map_err(|_| li_node_manager::NodePrivateApiError::AuthorizationDenied)
    }

    // Allows one paired child to mutate only its own main-owned lifecycle record.
    fn authorize_child_transition(
        &self,
        principal_id: &CredentialId,
        node_id: &NodeId,
    ) -> Result<(), li_node_manager::NodePrivateApiError> {
        let principal = self
            .authentication
            .authorize_peer_credential(principal_id)
            .map_err(|_| li_node_manager::NodePrivateApiError::AuthorizationDenied)?;
        if self.local_role != li_core_interface::NodeRole::Main
            || principal.local_node_id() != &self.local_node_id
            || principal.peer_node_id() != node_id
            || principal.peer_node_id() == &self.local_node_id
            || principal.direction() != PeerCredentialDirection::ChildToMain
        {
            return Err(li_node_manager::NodePrivateApiError::AuthorizationDenied);
        }
        Ok(())
    }

    // Allows one paired peer to read only the host projection assigned to that relationship.
    fn authorize_child_read(
        &self,
        principal_id: &CredentialId,
        node_id: &NodeId,
    ) -> Result<(), li_node_manager::NodePrivateApiError> {
        let principal = self
            .authentication
            .authorize_peer_credential(principal_id)
            .map_err(|_| li_node_manager::NodePrivateApiError::AuthorizationDenied)?;
        let allowed = match self.local_role {
            li_core_interface::NodeRole::Main => {
                principal.local_node_id() == &self.local_node_id
                    && principal.peer_node_id() == node_id
                    && principal.peer_node_id() != &self.local_node_id
                    && principal.direction() == PeerCredentialDirection::ChildToMain
            }
            li_core_interface::NodeRole::Child => {
                principal.local_node_id() == &self.local_node_id
                    && node_id == &self.local_node_id
                    && principal.peer_node_id() != &self.local_node_id
                    && principal.direction() == PeerCredentialDirection::MainToChild
            }
        };
        if !allowed {
            return Err(li_node_manager::NodePrivateApiError::AuthorizationDenied);
        }
        Ok(())
    }
}

// Preserves explicit topology unavailability until mutual link proofs have a durable read port.
struct CoreNodeHostTopologyProvider;

impl NodeHostTopologyReadPort for CoreNodeHostTopologyProvider {
    // Refuses to infer verified inter-node links from one-sided hardware observations.
    fn verified_links(&self) -> Result<Vec<PlacementLink>, NodeHostReadError> {
        Err(NodeHostReadError::Unavailable)
    }
}

// Reads Linux protection descriptors or reports that separate protection is not applicable.
struct CoreNodeHostProtectionProvider {
    #[cfg(target_os = "linux")]
    linux: Arc<dyn LinuxPlacementProtectedTargetProvider>,
}

impl CoreNodeHostProtectionProvider {
    // Creates one Linux provider over the exact descriptor reader shared with placement execution.
    #[cfg(target_os = "linux")]
    const fn linux(linux: Arc<dyn LinuxPlacementProtectedTargetProvider>) -> Self {
        Self { linux }
    }

    // Creates one macOS provider because launchd safety has no separate resident protection path.
    #[cfg(not(target_os = "linux"))]
    const fn macos() -> Self {
        Self {}
    }
}

impl NodeHostProtectionReadPort for CoreNodeHostProtectionProvider {
    // Requires every active local Linux placement to have an acknowledged untripped descriptor.
    fn protection(
        &self,
        node: &li_core_interface::Node,
        placement_groups: &[NodeHostPlacementGroup],
    ) -> Result<Option<NodeHostProtectionSummary>, NodeHostReadError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (node, placement_groups);
            Ok(None)
        }
        #[cfg(target_os = "linux")]
        {
            let placements = placement_groups
                .iter()
                .flat_map(NodeHostPlacementGroup::placements)
                .filter(|placement| placement.assignment().node_id() == node.identity().node_id())
                .filter(|placement| {
                    matches!(
                        placement.state(),
                        PlacementState::Starting | PlacementState::Running
                    )
                })
                .collect::<Vec<_>>();
            if placements.is_empty() {
                return Ok(None);
            }
            let ready = placements.iter().try_fold(true, |ready, placement| {
                self.linux
                    .active_target(placement)
                    .map(|target| ready && target.is_some())
                    .map_err(|_| NodeHostReadError::Unavailable)
            })?;
            Ok(Some(NodeHostProtectionSummary::new(
                if ready {
                    NodeHostProtectionState::Ready
                } else {
                    NodeHostProtectionState::NotReady
                },
                li_core_interface::UnixMilliseconds::new(host_unix_milliseconds()?),
            )))
        }
    }
}

// Reads the local Gateway health/counters and optional Linux Watchdog telemetry.
struct CoreNodeHostServiceProvider {
    local_node_id: NodeId,
    gateway_configuration: GatewayConfiguration,
    gateway_health: GatewayHealthProbe,
    gateway_telemetry: WatchdogGatewayTelemetryProvider,
    watchdog: Option<Arc<dyn NativeBenchmarkTelemetrySource>>,
}

impl NodeHostServiceReadPort for CoreNodeHostServiceProvider {
    // Reads only the exact local Gateway and preserves remote service state as unavailable.
    fn gateway(
        &self,
        node: &li_core_interface::Node,
    ) -> Result<Option<NodeHostGatewaySummary>, NodeHostReadError> {
        if node.identity().node_id() != &self.local_node_id {
            return Err(NodeHostReadError::Unavailable);
        }
        let state = match self
            .gateway_health
            .observe(&self.gateway_configuration, Duration::from_secs(2))
        {
            Ok(GatewayHealthObservation::Ready) => NodeHostServiceState::Ready,
            Ok(GatewayHealthObservation::NotReady)
            | Err(
                GatewayHealthError::EndpointUnavailable
                | GatewayHealthError::DeadlineExceeded
                | GatewayHealthError::ResidentUnavailable,
            ) => NodeHostServiceState::NotReady,
            Err(
                GatewayHealthError::InvalidContract
                | GatewayHealthError::AuthenticationUnavailable
                | GatewayHealthError::InvalidResponse,
            ) => return Err(NodeHostReadError::Unavailable),
        };
        let observed_at = host_unix_milliseconds()?;
        let telemetry = match self.gateway_telemetry.sample(observed_at) {
            Ok(WatchdogLinuxCapability::Available(telemetry)) => {
                let mut counters = WatchdogSampleTelemetry::default();
                telemetry.apply(&mut counters);
                Some(NodeHostGatewayTelemetrySummary::new(
                    li_core_interface::UnixMilliseconds::new(observed_at),
                    u64::from(counters.active_requests),
                    u64::from(counters.queued_requests),
                    counters.requests_completed,
                    counters.requests_failed,
                    counters.input_tokens,
                    counters.output_tokens,
                    counters.cached_tokens,
                ))
            }
            Ok(WatchdogLinuxCapability::Unsupported) | Err(_) => None,
        };
        Ok(Some(NodeHostGatewaySummary::new(state, telemetry)))
    }

    // Reads the latest authenticated Linux Watchdog sample or returns macOS not-applicable.
    fn watchdog(
        &self,
        node: &li_core_interface::Node,
    ) -> Result<Option<NodeHostWatchdogSummary>, NodeHostReadError> {
        if node.identity().node_id() != &self.local_node_id {
            return Err(NodeHostReadError::Unavailable);
        }
        let Some(watchdog) = &self.watchdog else {
            return Ok(None);
        };
        let observed_at = host_unix_milliseconds()?;
        let start = observed_at
            .checked_sub(2_000)
            .filter(|value| *value > 0)
            .ok_or(NodeHostReadError::Unavailable)?;
        match watchdog.query_range(start, observed_at) {
            Ok(samples) => Ok(Some(NodeHostWatchdogSummary::new(
                NodeHostServiceState::Ready,
                samples
                    .last()
                    .map(NodeHostWatchdogTelemetrySummary::from_sample),
            ))),
            Err(_) => Ok(Some(NodeHostWatchdogSummary::new(
                NodeHostServiceState::NotReady,
                None,
            ))),
        }
    }
}

// Reads current Unix time for one live host projection without accepting a zero timestamp.
fn host_unix_milliseconds() -> Result<u64, NodeHostReadError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NodeHostReadError::Unavailable)?;
    let milliseconds =
        u64::try_from(elapsed.as_millis()).map_err(|_| NodeHostReadError::Unavailable)?;
    if milliseconds == 0 {
        return Err(NodeHostReadError::Unavailable);
    }
    Ok(milliseconds)
}

// Authorizes only the exact role-fixed principals assigned by the Linux peer verifier.
#[cfg(target_os = "linux")]
struct CoreNodeProtectionAuthorizationProvider {
    gateway_principal: CredentialId,
    watchdog_principal: CredentialId,
}

#[cfg(target_os = "linux")]
impl NodeProtectionAuthorizationProvider for CoreNodeProtectionAuthorizationProvider {
    // Requires Gateway only for reads and Watchdog only for session mutation.
    fn authorize(
        &self,
        principal_id: &CredentialId,
        action: NodeProtectionAction,
        _node_id: &NodeId,
    ) -> Result<(), NodeProtectionApiError> {
        let accepted = match action {
            NodeProtectionAction::ReadGatewaySnapshot => principal_id == &self.gateway_principal,
            NodeProtectionAction::BeginWatchdogSession
            | NodeProtectionAction::CommitWatchdogCycle
            | NodeProtectionAction::EndWatchdogSession
            | NodeProtectionAction::ResolveControllerBinding
            | NodeProtectionAction::ReadSiteStatus => principal_id == &self.watchdog_principal,
        };
        if accepted {
            Ok(())
        } else {
            Err(NodeProtectionApiError::AuthorizationDenied)
        }
    }
}

// Adapts the shared Linux descriptor provider to Node's read-only current-target boundary.
#[cfg(target_os = "linux")]
struct CoreNodeProtectionTargetProvider {
    targets: Arc<dyn LinuxPlacementProtectedTargetProvider>,
}

#[cfg(target_os = "linux")]
impl NodeProtectionTargetProvider for CoreNodeProtectionTargetProvider {
    // Returns one exact acknowledged process target without granting mutation authority.
    fn current_target(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementProtectedTarget>, NodeProtectionLeaseError> {
        self.targets
            .active_target(placement)
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)
    }
}

// Retains every already-composed dependency needed to bind the Node protection listener.
#[cfg(target_os = "linux")]
struct CoreNodeProtectionResidentConfiguration {
    local: li_node_manager::NodeProtectionLocalConfiguration,
    api: Arc<NodeProtectionApi>,
    peer_roles: Arc<dyn NodeProtectionPeerRoleProvider>,
}

#[cfg(target_os = "linux")]
impl CoreNodeProtectionResidentConfiguration {
    // Binds the dedicated channel only after ordinary Node resident startup succeeds.
    fn start(&self) -> Result<NodeProtectionLocalServer, NodeResidentError> {
        NodeProtectionLocalServer::start(
            self.local.clone(),
            self.api.clone(),
            self.peer_roles.clone(),
        )
        .map_err(|_| NodeResidentError::LocalListenerStartFailed)
    }
}

// Couples only in-process Node-owned resources while preserving independent service processes.
struct CoreComposedNodeResident {
    resident: NodeResident,
    pairing_enabled: bool,
    pairing_server: Arc<NodePrivateRemoteServer>,
    pairing_discovery: Arc<NativePairingCandidateDiscoveryProvider>,
    pairing_advertisement: PairingCandidateAdvertisement,
    #[cfg(target_os = "linux")]
    protection: CoreNodeProtectionResidentConfiguration,
}

// Starts one already-composed Node resident without exposing its concrete listeners.
trait CoreNodeResidentLifecycle {
    // Starts all owned resources and returns their one cleanup owner.
    fn start_resident(&self) -> Result<Box<dyn CoreNodeResidentHandle>, NodeResidentError>;
}

impl CoreNodeResidentLifecycle for NodeResident {
    // Delegates to the ordinary NodeResident start and retains its exact handle.
    fn start_resident(&self) -> Result<Box<dyn CoreNodeResidentHandle>, NodeResidentError> {
        self.start()
            .map(|handle| Box::new(handle) as Box<dyn CoreNodeResidentHandle>)
    }
}

impl CoreNodeResidentLifecycle for CoreComposedNodeResident {
    // Starts ordinary, pairing, discovery, and protection owners with symmetric rollback.
    fn start_resident(&self) -> Result<Box<dyn CoreNodeResidentHandle>, NodeResidentError> {
        let mut resident = self.resident.start()?;
        let mut pairing = None;
        if self.pairing_enabled {
            let started = match self.pairing_server.start() {
                Ok(pairing) => pairing,
                Err(_) => {
                    let _ = resident.stop();
                    return Err(NodeResidentError::RemoteListenerStartFailed);
                }
            };
            pairing = Some(started);
            if self
                .pairing_discovery
                .publish(&self.pairing_advertisement)
                .is_err()
            {
                if let Some(mut started) = pairing.take() {
                    let _ = started.shutdown();
                }
                let _ = resident.stop();
                return Err(NodeResidentError::RemoteListenerStartFailed);
            }
        }
        #[cfg(target_os = "linux")]
        {
            let protection = match self.protection.start() {
                Ok(protection) => protection,
                Err(error) => {
                    let _ = self.pairing_discovery.close();
                    if let Some(mut pairing) = pairing.take() {
                        let _ = pairing.shutdown();
                    }
                    let _ = resident.stop();
                    return Err(error);
                }
            };
            return Ok(Box::new(CoreComposedNodeResidentHandle {
                resident,
                pairing,
                pairing_discovery: self.pairing_discovery.clone(),
                protection: Some(protection),
            }));
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Box::new(CoreComposedNodeResidentHandle {
                resident,
                pairing,
                pairing_discovery: self.pairing_discovery.clone(),
            }))
        }
    }
}

// Owns symmetric Node, pairing, discovery, and platform protection shutdown.
struct CoreComposedNodeResidentHandle {
    resident: NodeResidentHandle,
    pairing: Option<li_node_manager::NodePrivateRemoteServerHandle>,
    pairing_discovery: Arc<NativePairingCandidateDiscoveryProvider>,
    #[cfg(target_os = "linux")]
    protection: Option<NodeProtectionLocalServer>,
}

impl CoreComposedNodeResidentHandle {
    // Stops discovery and the exact pairing listener before ordinary Node release.
    fn stop_pairing(&mut self) -> Result<(), NodeResidentError> {
        let discovery = self
            .pairing_discovery
            .close()
            .map_err(|_| NodeResidentError::RemoteListenerStopFailed);
        let pairing = self.pairing.take().map_or(Ok(()), |mut pairing| {
            pairing
                .shutdown()
                .map_err(|_| NodeResidentError::RemoteListenerStopFailed)
        });
        discovery.and(pairing)
    }

    // Stops and joins the exact protection listener without hiding either cleanup result.
    #[cfg(target_os = "linux")]
    fn stop_protection(&mut self) -> Result<(), NodeResidentError> {
        let Some(mut protection) = self.protection.take() else {
            return Ok(());
        };
        protection.stop();
        protection
            .join()
            .map_err(|_| NodeResidentError::LocalListenerStopFailed)
    }
}

impl CoreNodeResidentHandle for CoreComposedNodeResidentHandle {
    // Requires ordinary, pairing, and platform protection owners to remain live.
    fn is_running(&self) -> bool {
        let common = self.resident.is_running()
            && self.pairing.as_ref().is_none_or(|value| value.is_running());
        #[cfg(target_os = "linux")]
        {
            return common
                && self
                    .protection
                    .as_ref()
                    .is_some_and(NodeProtectionLocalServer::is_running);
        }
        #[cfg(not(target_os = "linux"))]
        {
            common
        }
    }

    // Waits for Node termination and then always completes every pairing and protection cleanup.
    fn wait(&mut self) -> Result<(), NodeResidentError> {
        let resident = self.resident.wait();
        let pairing = self.stop_pairing();
        #[cfg(target_os = "linux")]
        let protection = self.stop_protection();
        #[cfg(target_os = "linux")]
        return resident.and(pairing).and(protection);
        #[cfg(not(target_os = "linux"))]
        resident.and(pairing)
    }

    // Stops every owner without leaving discovery, listeners, or sockets detached.
    fn stop(&mut self) -> Result<(), NodeResidentError> {
        let resident = self.resident.stop();
        let pairing = self.stop_pairing();
        #[cfg(target_os = "linux")]
        let protection = self.stop_protection();
        #[cfg(target_os = "linux")]
        return resident.and(pairing).and(protection);
        #[cfg(not(target_os = "linux"))]
        resident.and(pairing)
    }
}

// Owns health, wait, and explicit stop for one started resident resource set.
trait CoreNodeResidentHandle {
    // Reports whether both listeners and the daemon thread are currently live.
    fn is_running(&self) -> bool;

    // Waits for termination and completes every listener and daemon cleanup action.
    fn wait(&mut self) -> Result<(), NodeResidentError>;

    // Forces symmetric cleanup when readiness fails immediately after start.
    fn stop(&mut self) -> Result<(), NodeResidentError>;
}

impl CoreNodeResidentHandle for NodeResidentHandle {
    // Delegates the process readiness observation to its complete lifecycle owner.
    fn is_running(&self) -> bool {
        NodeResidentHandle::is_running(self)
    }

    // Delegates termination and complete joined cleanup to the concrete owner.
    fn wait(&mut self) -> Result<(), NodeResidentError> {
        NodeResidentHandle::wait(self)
    }

    // Delegates forced cleanup to the same idempotent concrete release path.
    fn stop(&mut self) -> Result<(), NodeResidentError> {
        NodeResidentHandle::stop(self)
    }
}

// Loads exact process state, installs native signal ownership, and owns clean shutdown.
pub fn run_core_node_process(
    arguments: CoreNodeProcessArguments,
) -> Result<(), CoreNodeProcessError> {
    let owner_user_id = effective_user_id();
    let reference =
        NodeConfigurationFileReference::new(arguments.configuration().to_path_buf(), owner_user_id)
            .map_err(|_| CoreNodeProcessError::ConfigurationUnavailable)?;
    let configuration = NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider)
        .map_err(|_| CoreNodeProcessError::ConfigurationUnavailable)?;
    let run_control = Arc::new(
        SystemNodeResidentRunControl::install()
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let gateway_configuration = arguments
        .configuration()
        .parent()
        .ok_or(CoreNodeProcessError::ConfigurationUnavailable)?
        .join(CoreResidentProcess::Gateway.configuration_name());
    let result = compose_node(
        &configuration,
        gateway_configuration,
        owner_user_id,
        run_control.clone(),
    )
    .and_then(|resident| run_resident(&resident));
    let signal_result = run_control
        .join()
        .map_err(|_| CoreNodeProcessError::RuntimeUnavailable);
    result.and(signal_result)
}

// Composes every concrete manager, transport, and listener before starting the resident.
fn compose_node(
    configuration: &NodeConfiguration,
    gateway_configuration: PathBuf,
    owner_user_id: u32,
    run_control: Arc<SystemNodeResidentRunControl>,
) -> Result<CoreComposedNodeResident, CoreNodeProcessError> {
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(configuration.database_file()))
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let manager = Arc::new(
        li_node_manager::NodeManager::load(database.clone())
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let local = manager
        .local_node()
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    if local.state() != NodeState::Active {
        return Err(CoreNodeProcessError::CompositionUnavailable);
    }
    let installation_id = local.identity().installation_id().clone();
    let hardware = Arc::new(hardware_manager(
        configuration,
        manager.local_node_id().clone(),
    )?);
    let pairing = compose_core_node_pairing_api(
        configuration,
        owner_user_id,
        database.clone(),
        manager.clone(),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let pairing_runner: Arc<dyn PairingNativeCommandRunner> =
        Arc::new(SystemPairingNativeCommandRunner);
    let pairing_workspace: Arc<dyn PairingTrustWorkspaceIo> =
        Arc::new(SystemPairingTrustWorkspaceIo);
    let pairing_material = Arc::new(SystemPairingMaterialProvider);
    let candidate_trust = Arc::new(
        OpenSslPairingCandidateTrustProvider::new(
            configuration.pairing().openssl_command().to_path_buf(),
            PairingCandidateIdentityFiles::new(
                configuration
                    .pairing()
                    .site_private_key_file()
                    .to_path_buf(),
                configuration.pairing().site_public_key_file().to_path_buf(),
            )
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            configuration
                .pairing()
                .trust_workspace()
                .parent()
                .ok_or(CoreNodeProcessError::CompositionUnavailable)?
                .join("pairing_candidate_staging"),
            owner_user_id,
            pairing_runner.clone(),
            pairing_workspace,
            pairing_material,
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let pairing_clock = Arc::new(SystemPairingClock);
    let pairing_activation = Arc::new(
        NodePairingActivationAuthority::new(
            manager.clone(),
            database.clone(),
            pairing_clock.clone(),
            Arc::new(CoreNodePairingRoleReadiness {
                nodes: manager.clone(),
                exposure: DatabaseGatewayExposureStore::new(database.clone()),
            }),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let candidate = Arc::new(CorePairingCandidate::new(
        manager.clone(),
        candidate_trust,
        configuration.pairing().certificate_sha256().clone(),
        pairing_clock.clone(),
    ));
    let pairing_endpoint = Arc::new(NodePairingDocumentEndpoint::new(
        pairing.clone(),
        candidate,
        manager.clone(),
    ));
    let pairing_tls = NodePairingTlsServerConfiguration::load(
        &NodePairingTlsFileSet::new(
            owner_user_id,
            configuration
                .pairing()
                .local_control_certificate_file()
                .to_path_buf(),
            configuration
                .pairing()
                .site_private_key_file()
                .to_path_buf(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
        &SystemNodePrivateRemoteTlsFileProvider,
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let pairing_service = Arc::new(
        NodePairingTlsConnectionService::new(
            pairing_tls,
            pairing_endpoint,
            configuration.remote_handshake_timeout(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let pairing_address = std::net::SocketAddr::new(
        configuration.remote_server().bind_address().ip(),
        PAIRING_DISCOVERY_PORT,
    );
    let pairing_server = Arc::new(NodePrivateRemoteServer::new(
        li_node_manager::NodePrivateRemoteServerConfiguration::new(
            pairing_address,
            configuration.remote_server().maximum_workers(),
            configuration.remote_server().accept_poll_interval(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
        pairing_service,
        Arc::new(SystemNodePrivateRemoteSocketProvider),
    ));
    let discovery_platform = match configuration.pairing().platform() {
        li_node_manager::NodePairingPlatform::Linux { .. } => PairingDiscoveryPlatform::LinuxAvahi,
        li_node_manager::NodePairingPlatform::Macos => PairingDiscoveryPlatform::MacosBonjour,
    };
    let pairing_discovery = Arc::new(
        NativePairingCandidateDiscoveryProvider::new(
            discovery_platform,
            configuration.pairing().discovery_command().to_path_buf(),
            pairing_runner,
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let pairing_advertisement = PairingCandidateAdvertisement::new(
        local.identity().node_id().clone(),
        local.display_name().clone(),
        local.control_address().clone(),
        configuration.pairing().public_key_sha256().clone(),
        configuration.pairing().certificate_sha256().clone(),
        li_core_interface::UnixMilliseconds::new(u64::MAX),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let peer_credentials = Arc::new(DatabasePeerCredentialStore::new(database.clone()));
    let controller_certificates: Arc<dyn ControllerCertificateProvider> =
        match configuration.benchmark() {
            Some(benchmark) => Arc::new(
                RcgenCoreControllerCertificateProvider::load(
                    &CoreControllerCertificateAuthorityFiles::new(
                        owner_user_id,
                        benchmark.watchdog().ca_file().to_path_buf(),
                        benchmark
                            .watchdog()
                            .controller_authority_private_key_file()
                            .to_path_buf(),
                    )
                    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
                )
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            ),
            None => Arc::new(UnavailableCoreControllerCertificateProvider),
        };
    let authentication = Arc::new(AuthenticationManager::new_with_controller_store(
        Arc::new(DatabaseAuthenticationStore::new(database.clone())),
        peer_credentials,
        Arc::new(DatabaseControllerStore::new(database.clone())),
        controller_certificates,
        Arc::new(SystemApiKeyMaterialProvider),
        Arc::new(SystemAuthenticationClock),
    ));
    let command_audit = compose_command_audit(
        configuration,
        owner_user_id,
        database.clone(),
        manager.clone(),
    )?;
    let model = compose_model(
        configuration,
        owner_user_id,
        database.clone(),
        manager.clone(),
    )?;
    #[cfg(target_os = "linux")]
    let protection = compose_linux_node_protection(
        configuration,
        owner_user_id,
        database.clone(),
        manager.clone(),
        installation_id.clone(),
        &model,
    )?;
    let host_projection = compose_host_projection(
        configuration,
        gateway_configuration.clone(),
        owner_user_id,
        manager.local_node_id().clone(),
        model.placement_store.clone(),
    )?;
    model
        .coordinator
        .recover_pending()
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let benchmark = compose_benchmark(
        configuration,
        owner_user_id,
        database.clone(),
        manager.clone(),
        &model,
    )?;
    let update = configuration.core_update();
    let core_update = Arc::new(
        compose_system_core_update(
            ApplicationSystemCoreUpdateConfiguration::new(
                update.release_platform(),
                CoreUpdateServiceContext::new(
                    release_service_platform(update.release_platform()),
                    update_node_role(local.role()),
                ),
                update.letsinfer_home().to_path_buf(),
                update.home_directory().to_path_buf(),
                update.setup_state_directory().to_path_buf(),
                update.configuration_root().to_path_buf(),
                owner_user_id,
                update.curl_command().to_path_buf(),
                update.ssh_keygen_command().to_path_buf(),
                update.allowed_signers_file().to_path_buf(),
                update.supervisor_command().to_path_buf(),
                update.readiness(),
            )
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            database.clone(),
            manager.clone(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let exposure = Arc::new(ManagedNodeExposureApi::new(Arc::new(
        GatewayExposureCoordinator::new(
            Arc::new(DatabaseGatewayExposureStore::new(database.clone())),
            Arc::new(
                SystemCoreGatewayExposureReadiness::new(gateway_configuration, owner_user_id)
                    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            ),
            Arc::new(SystemGatewayExposureProvider::new()),
        ),
    )));
    let storage = compose_storage(configuration, owner_user_id)?;
    let authentication_api = match configuration.benchmark() {
        Some(benchmark) => Arc::new(
            NodeAuthenticationCoordinator::new_with_controller_projection(
                authentication.clone(),
                compose_system_core_controller_authorization_projection(
                    CoreControllerAuthorizationProjectionConfiguration::new(
                        local.identity().installation_id().clone(),
                        ControllerId::parse(local.identity().node_id().as_str())
                            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
                        benchmark
                            .watchdog()
                            .controller_certificate_file()
                            .to_path_buf(),
                        benchmark
                            .watchdog()
                            .controller_allowlist_file()
                            .to_path_buf(),
                        benchmark
                            .watchdog()
                            .controller_reload_receipt_file()
                            .to_path_buf(),
                        owner_user_id,
                        configuration
                            .core_update()
                            .supervisor_command()
                            .to_path_buf(),
                    )
                    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
                )
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            ),
        ),
        None => Arc::new(NodeAuthenticationCoordinator::new(authentication.clone())),
    };
    let gateway_api = compose_node_gateway_api(
        owner_user_id,
        database.clone(),
        manager.clone(),
        authentication.clone(),
        &model,
    );
    let runtime_maintenance = Arc::new(NodeRuntimeMaintenanceCoordinator::new(
        model.runtime.clone(),
        model.runtime_store.clone(),
    ));
    let mut api = NodePrivateApi::new(
        manager.clone(),
        Arc::new(CoreNodePrivateAuthorizationProvider::new_for_role(
            authentication.clone(),
            manager.local_node_id().clone(),
            local.role(),
        )),
        pairing,
    )
    .with_authentication(authentication_api)
    .with_audit(command_audit.clone())
    .with_command_audit(command_audit)
    .with_catalog(Arc::new(CoreNodeCatalogApi::new(
        manager.clone(),
        model.catalog.clone(),
    )))
    .with_model(model.coordinator.clone())
    .with_host_projection(host_projection)
    .with_core_update(core_update)
    .with_exposure(exposure)
    .with_storage(storage)
    .with_runtime_maintenance(runtime_maintenance)
    .with_pairing_activation(pairing_activation)
    .with_gateway(gateway_api);
    if let Some(benchmark) = &benchmark {
        api = api.with_benchmark(benchmark.api.clone());
    }
    let api = Arc::new(api);
    let local_endpoint = Arc::new(NodePrivateLocalEndpoint::new(api.clone()));
    let local_server = Arc::new(NodePrivateLocalServer::new(
        configuration.local_server().clone(),
        local_endpoint,
        Arc::new(li_node_manager::ExactNodePrivateLocalPeerIdentity::new(
            owner_user_id,
            manager.local_node_id().clone(),
        )),
        Arc::new(SystemNodePrivateLocalSocketProvider),
    ));
    let remote_endpoint = Arc::new(NodePrivateEndpoint::new(api));
    let tls = NodePrivateRemoteTlsConfiguration::load(
        configuration.remote_tls_files(),
        &SystemNodePrivateRemoteTlsFileProvider,
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let handler = Arc::new(
        li_node_manager::NodePrivateAuthenticatedConnectionHandler::new(
            remote_endpoint,
            Arc::new(CoreNodePrincipalResolver::new_for_direction(
                authentication,
                manager.local_node_id().clone(),
                match local.role() {
                    li_core_interface::NodeRole::Main => PeerCredentialDirection::ChildToMain,
                    li_core_interface::NodeRole::Child => PeerCredentialDirection::MainToChild,
                },
            )),
            configuration.remote_read_timeout(),
            configuration.remote_write_timeout(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let remote_service = Arc::new(
        NodePrivateRemoteTlsConnectionService::new(
            tls,
            handler,
            configuration.remote_handshake_timeout(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let remote_server = Arc::new(NodePrivateRemoteServer::new(
        configuration.remote_server().clone(),
        remote_service,
        Arc::new(SystemNodePrivateRemoteSocketProvider),
    ));
    let daemon = NodeDaemon::new_with_private_outbox(
        manager.clone(),
        hardware,
        Arc::new(SystemNodeDaemonClock),
    );
    let daemon = match benchmark {
        Some(benchmark) => daemon.with_benchmark(benchmark.coordinator),
        None => daemon,
    };
    let daemon = Arc::new(daemon);
    let resident = NodeResident::new(
        configuration,
        daemon,
        local_server,
        remote_server,
        run_control,
        Arc::new(SystemNodeResidentThreadProvider),
    );
    #[cfg(target_os = "linux")]
    {
        return Ok(CoreComposedNodeResident {
            resident,
            pairing_enabled: local.role() == li_core_interface::NodeRole::Main,
            pairing_server,
            pairing_discovery,
            pairing_advertisement,
            protection,
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (database, manager, installation_id);
        Ok(CoreComposedNodeResident {
            resident,
            pairing_enabled: local.role() == li_core_interface::NodeRole::Main,
            pairing_server,
            pairing_discovery,
            pairing_advertisement,
        })
    }
}

// Composes every database-backed Gateway capability beneath the one Node-owned database lifecycle.
fn compose_node_gateway_api(
    owner_user_id: u32,
    database: Arc<DatabaseManager>,
    manager: Arc<li_node_manager::NodeManager>,
    authentication: Arc<AuthenticationManager>,
    model: &CoreComposedModel,
) -> Arc<NodeGatewayApi> {
    let placements = model.placement_store.clone();
    let routes = Arc::new(NodeGatewayRouteProvider::new(
        manager.clone(),
        placements.clone(),
    ));
    let trust = Arc::new(DatabaseNodeGatewayRelayTrustStore::new(database.clone()));
    let relay_clock = Arc::new(SystemNodeGatewayRelayClock);
    let relay_targets = Arc::new(PersistedNodeGatewayRelayTargetProvider::new(
        owner_user_id,
        manager.clone(),
        trust.clone(),
        relay_clock.clone(),
    ));
    let targets = Arc::new(NodeGatewayNativeTargetProvider::new(
        manager.local_node_id().clone(),
        owner_user_id,
        placements.clone(),
        model.credentials.clone(),
        relay_targets,
    ));
    let relay_authorization = Arc::new(PersistedNodeGatewayRelayAuthorizationProvider::new(
        owner_user_id,
        manager,
        trust,
        relay_clock,
        Arc::new(SystemGatewayNativeFileIo),
    ));
    let usage = Arc::new(DatabaseGatewayUsageStore::new(database));
    let gateway_authentication = Arc::new(AuthenticationManagerGatewayProvider::new(
        authentication.clone(),
    ));
    Arc::new(NodeGatewayApi::new(Arc::new(
        ManagedNodeGatewayCapabilityPort::new(
            authentication,
            gateway_authentication,
            routes,
            targets,
            relay_authorization,
            usage,
            placements,
        ),
    )))
}

// Composes truthful local observation without exposing unsupported cleanup candidates.
fn compose_storage(
    configuration: &NodeConfiguration,
    owner_user_id: u32,
) -> Result<Arc<NodeStorageCoordinator>, CoreNodeProcessError> {
    let home = configuration.core_update().letsinfer_home().to_path_buf();
    let model = configuration.model();
    let observation = FilesystemCoreNodeStorageObservationProvider::new(
        home.clone(),
        owner_user_id,
        vec![
            CoreNodeStorageRoot::new(
                NodeStorageCategory::Runtimes,
                model.installation_root().to_path_buf(),
            ),
            CoreNodeStorageRoot::new(
                NodeStorageCategory::Caches,
                model.runtime_cache_root().to_path_buf(),
            ),
            CoreNodeStorageRoot::new(
                NodeStorageCategory::Benchmarks,
                home.join("benchmark_evidence"),
            ),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
        Arc::new(ReadOnlyCoreNodeStorageEntryProvider),
        Arc::new(SystemCoreNodeStorageFilesystem),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    Ok(Arc::new(NodeStorageCoordinator::new(
        Arc::new(observation),
        Arc::new(ReadOnlyCoreNodeStorageCleanupPort),
    )))
}

// Composes one Linux benchmark owner from the same Runtime and Placement graph as model commands.
fn compose_benchmark(
    configuration: &NodeConfiguration,
    owner_user_id: u32,
    database: Arc<DatabaseManager>,
    manager: Arc<li_node_manager::NodeManager>,
    model: &CoreComposedModel,
) -> Result<Option<CoreComposedBenchmark>, CoreNodeProcessError> {
    let Some(input) = configuration.benchmark() else {
        return Ok(None);
    };
    let watchdog_input = input.watchdog();
    let watchdog = NativeBenchmarkWatchdogInput::new(
        watchdog_input.host().to_owned(),
        watchdog_input.port(),
        watchdog_input.server_name().to_owned(),
        watchdog_input.ca_file().to_path_buf(),
        watchdog_input.controller_certificate_file().to_path_buf(),
        watchdog_input.controller_private_key_file().to_path_buf(),
        watchdog_input.timeout(),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let transport = Arc::new(
        SystemNativeBenchmarkWatchdogTransport::load(&watchdog, owner_user_id)
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let telemetry_source: Arc<dyn NativeBenchmarkTelemetrySource> = Arc::new(
        WatchdogBenchmarkTelemetrySource::new(watchdog.clone(), transport)
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let telemetry = Arc::new(WatchdogCoreBenchmarkTelemetryObservationPort::new(
        telemetry_source,
    ));
    let community = Arc::new(
        FilesystemCoreBenchmarkCommunityAuthority::load(
            input.task_root().join("community_authority"),
            input.signing_public_key_file().to_path_buf(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let maximum_runtime_milliseconds = u64::try_from(input.maximum_runtime().as_millis())
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let stop_grace_milliseconds = u64::try_from(input.stop_grace().as_millis())
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let handoff = Arc::new(ApplicationCoreBenchmarkVerificationHandoff::new(
        model.candidate_handoff.clone(),
    ));
    let signer = Arc::new(
        SetupEd25519CoreBenchmarkVerificationSnapshotSigner::new(
            input.signing_private_key_file().to_path_buf(),
            owner_user_id,
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let publication = Arc::new(
        SystemCoreBenchmarkVerificationPublicationFactory::new(
            input.github_cli_command().to_path_buf(),
            input.task_root().join("verifier_artifacts"),
            input.evidence_root().to_path_buf(),
            owner_user_id,
            signer.clone(),
            Arc::new(SystemCoreBenchmarkVerificationGitHubCommandRunner),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let benchmark = compose_system_core_benchmark_with_verification(
        ApplicationCoreBenchmarkConfiguration::new(
            input.worker_executable().to_path_buf(),
            input.task_root().to_path_buf(),
            input.telemetry_root().to_path_buf(),
            input.evidence_root().to_path_buf(),
            input.signing_workspace_root().to_path_buf(),
            configuration.pairing().openssl_command().to_path_buf(),
            input.signing_private_key_file().to_path_buf(),
            input.signing_public_key_file().to_path_buf(),
            watchdog,
            owner_user_id,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
        ApplicationCoreBenchmarkManagers::new(
            database.clone(),
            manager.clone(),
            model.runtime.clone(),
            model.runtime_store.clone(),
            model.executions.clone(),
            model.placement.clone(),
            model.placement_store.clone(),
            model.credentials.clone(),
        ),
        ApplicationCoreBenchmarkPorts::new(community, telemetry),
        ApplicationCoreBenchmarkVerificationComposition::new(handoff.clone(), publication),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let benchmark = Arc::new(benchmark.with_verification_projection(Arc::new(
        DatabaseNodeBenchmarkVerificationProjectionProvider::new(database),
    )));
    let device_id = signer
        .public_key_sha256()
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let oracle = Arc::new(
        SystemCoreBenchmarkVerificationOracle::new(
            input.github_cli_command().to_path_buf(),
            input.task_root().join("verifier_artifacts"),
            owner_user_id,
            device_id,
            Arc::new(SystemCoreBenchmarkVerificationCommandRunner),
            model.http.clone(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let subject = Arc::new(ManagerCoreBenchmarkVerificationSubjectResolver::new(
        manager,
        model.runtime.clone(),
        model.runtime_store.clone(),
        model.placement_store.clone(),
    ));
    let publisher = Arc::new(
        SystemCoreBenchmarkVerificationSnapshotPublisher::new(
            input.task_root().join("community_authority"),
            owner_user_id,
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let preparation = Arc::new(CoreBenchmarkVerificationPreparation::new(
        oracle,
        subject.clone(),
        signer,
        publisher,
    ));
    let api = Arc::new(ApplicationCoreBenchmarkVerificationApi::new(
        benchmark.clone(),
        preparation,
        subject,
        handoff,
        benchmark.clone(),
        Arc::new(SystemCoreBenchmarkVerificationWallClock),
    ));
    Ok(Some(CoreComposedBenchmark {
        coordinator: benchmark,
        api,
    }))
}

// Retains the ordinary polling coordinator and resident-authority private API projection.
struct CoreComposedBenchmark {
    coordinator: Arc<li_node_manager::NodeBenchmarkCoordinator>,
    api: Arc<ApplicationCoreBenchmarkVerificationApi>,
}

// Retains one production model graph so benchmark and Node APIs share identical manager owners.
struct CoreComposedModel {
    coordinator: Arc<li_node_manager::NodeModelCoordinator>,
    candidate_handoff: Arc<NodeBenchmarkCandidateHandoffCoordinator>,
    catalog: Arc<SignedRuntimeCatalogProvider>,
    runtime: Arc<RuntimeManager>,
    runtime_store: Arc<dyn RuntimeInstallationStore>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
    placement: Arc<PlacementManager>,
    placement_store: Arc<DatabasePlacementStore>,
    credentials: Arc<dyn PlacementCredentialReader>,
    http: Arc<dyn li_runtime_manager::RuntimeHttpClient>,
}

// Adapts verified RuntimeManager records to the Node-owned Watchdog status projection.
#[cfg(target_os = "linux")]
struct CoreNodeWatchdogRuntimeProvider {
    installations: Arc<dyn RuntimeInstallationProvider>,
    manifests: Arc<dyn RuntimeExecutionManifestProvider>,
}

#[cfg(target_os = "linux")]
impl NodeWatchdogRuntimeProvider for CoreNodeWatchdogRuntimeProvider {
    // Returns exact Engine, cache, model, and runtime identity after all records agree.
    fn status(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<NodeWatchdogRuntimeStatus, WatchdogProtocolDataError> {
        let installation = self
            .installations
            .installation(installation_id)
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?
            .ok_or(WatchdogProtocolDataError::Unavailable)?;
        if installation.installation_id() != installation_id
            || installation.state() != RuntimeInstallationState::Available
        {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        let manifest = self
            .manifests
            .manifest(installation_id)
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?;
        if manifest.installation_id() != installation_id
            || manifest.logical_model() != installation.logical_model()
        {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        NodeWatchdogRuntimeStatus::new(
            installation.logical_model().clone(),
            installation.runtime().clone(),
            manifest.engine_id().clone(),
            manifest.cache_provider(),
            manifest.has_persistent_cache(),
        )
    }
}

// Composes signed runtime acquisition, native placement, and restart-safe model orchestration.
fn compose_model(
    configuration: &NodeConfiguration,
    owner_user_id: u32,
    database: Arc<DatabaseManager>,
    manager: Arc<li_node_manager::NodeManager>,
) -> Result<CoreComposedModel, CoreNodeProcessError> {
    let input = configuration.model();
    let runtime_store = Arc::new(DatabaseRuntimeInstallationStore::new(database.clone()));
    let runtime = compose_core_model_runtime(
        CoreModelRuntimeCompositionInput {
            catalog_source: input.catalog_source().to_string(),
            catalog_cache_root: input.catalog_cache_root().to_path_buf(),
            catalog_hydration_root: input.catalog_hydration_root().to_path_buf(),
            http_workspace_root: input.http_workspace_root().to_path_buf(),
            installation_root: input.installation_root().to_path_buf(),
            runtime_cache_root: input.runtime_cache_root().to_path_buf(),
            curl_command: input.curl_command().to_path_buf(),
            docker_command: input.docker_command().to_path_buf(),
            command_working_directory: input.command_working_directory().to_path_buf(),
        },
        runtime_store.clone(),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let placement_store = Arc::new(DatabasePlacementStore::new(database.clone()));
    let platform = match configuration.placement_safety() {
        li_node_manager::NodePlacementSafetyConfiguration::Linux(protection) => {
            CoreModelPlacementPlatformInput::Linux {
                docker_command: input.docker_command().to_path_buf(),
                protection_root: protection.protection_root().to_path_buf(),
                user_id: owner_user_id,
                group_id: input.group_id(),
            }
        }
        li_node_manager::NodePlacementSafetyConfiguration::MacosLaunchd => {
            CoreModelPlacementPlatformInput::Macos {
                launch_agents_root: input
                    .launch_agents_root()
                    .ok_or(CoreNodeProcessError::CompositionUnavailable)?
                    .to_path_buf(),
                launchctl_command: input
                    .launchctl_command()
                    .ok_or(CoreNodeProcessError::CompositionUnavailable)?
                    .to_path_buf(),
            }
        }
    };
    let placement = compose_core_model_placement(
        CoreModelPlacementCompositionInput {
            owner_user_id,
            material_root: input.placement_material_root().to_path_buf(),
            runtime_cache_root: input.runtime_cache_root().to_path_buf(),
            secret_root: input.placement_secret_root().to_path_buf(),
            tls_workspace_root: input.placement_tls_workspace_root().to_path_buf(),
            openssl_command: configuration.pairing().openssl_command().to_path_buf(),
            command_working_directory: input.command_working_directory().to_path_buf(),
            endpoint_timeout: input.endpoint_timeout(),
            maximum_hardware_age: input.maximum_hardware_age(),
            platform,
        },
        placement_store.clone(),
        runtime.executions(),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let catalog = runtime.catalog();
    let runtime_manager = runtime.manager();
    let executions = runtime.executions();
    let http = runtime.http();
    let placement_manager = placement.manager();
    let credentials = placement.credentials();
    let runtime_port = Arc::new(ManagedNodeModelRuntimePort::new(
        runtime_manager.clone(),
        runtime_store.clone(),
    ));
    let placement_port = Arc::new(ManagedNodeModelPlacementPort::new(
        placement_manager.clone(),
        placement_store.clone(),
        placement_store.clone(),
    ));
    let placement_requests = Arc::new(
        NativeNodeModelPlacementRequestProvider::new(
            manager.clone(),
            executions.clone(),
            input.first_port(),
            input.port_count(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let model_clock = Arc::new(SystemNodeModelClock);
    let model = Arc::new(li_node_manager::NodeModelCoordinator::new(
        manager.clone(),
        runtime_port.clone(),
        placement_port.clone(),
        placement_requests.clone(),
        manager.clone(),
        Arc::new(DatabaseNodeModelJournalStore::new(database.clone())),
        model_clock.clone(),
    ));
    let candidate_handoff = Arc::new(NodeBenchmarkCandidateHandoffCoordinator::new(
        Arc::new(DatabaseNodeBenchmarkCandidateHandoffStore::new(database)),
        runtime_port,
        placement_port,
        placement_requests,
        manager.clone(),
        manager,
        model_clock,
    ));
    Ok(CoreComposedModel {
        coordinator: model,
        candidate_handoff,
        catalog,
        runtime: runtime_manager,
        runtime_store,
        executions,
        placement: placement_manager,
        placement_store,
        credentials,
        http,
    })
}

// Composes one truthful host read from existing database, health, telemetry, and safety sources.
fn compose_host_projection(
    configuration: &NodeConfiguration,
    gateway_configuration_file: PathBuf,
    owner_user_id: u32,
    local_node_id: NodeId,
    placements: Arc<DatabasePlacementStore>,
) -> Result<Arc<NodeHostProjectionPorts>, CoreNodeProcessError> {
    let gateway_reference =
        GatewayConfigurationFile::new(owner_user_id, gateway_configuration_file)
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let gateway_configuration =
        GatewayConfiguration::load(&gateway_reference, &SystemGatewayNativeFileIo)
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let gateway_telemetry = WatchdogGatewayTelemetryProvider::new(
        gateway_configuration.telemetry_file().to_path_buf(),
        owner_user_id,
        Box::new(SystemWatchdogGatewayTelemetryFileProvider),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    let watchdog = configuration
        .benchmark()
        .map(|benchmark| {
            let input = benchmark.watchdog();
            let watchdog = NativeBenchmarkWatchdogInput::new(
                input.host().to_owned(),
                input.port(),
                input.server_name().to_owned(),
                input.ca_file().to_path_buf(),
                input.controller_certificate_file().to_path_buf(),
                input.controller_private_key_file().to_path_buf(),
                input.timeout(),
            )
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
            let transport = Arc::new(
                SystemNativeBenchmarkWatchdogTransport::load(&watchdog, owner_user_id)
                    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            );
            WatchdogBenchmarkTelemetrySource::new(watchdog, transport)
                .map(|source| Arc::new(source) as Arc<dyn NativeBenchmarkTelemetrySource>)
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)
        })
        .transpose()?;
    let services = Arc::new(CoreNodeHostServiceProvider {
        local_node_id,
        gateway_configuration,
        gateway_health: GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange)),
        gateway_telemetry,
        watchdog,
    });
    #[cfg(target_os = "linux")]
    let protection: Arc<dyn NodeHostProtectionReadPort> = {
        let li_node_manager::NodePlacementSafetyConfiguration::Linux(input) =
            configuration.placement_safety()
        else {
            return Err(CoreNodeProcessError::CompositionUnavailable);
        };
        let reader = FilesystemLinuxPlacementProtectionProvider::new(
            input.protection_root().to_path_buf(),
            owner_user_id,
            PLACEMENT_ACKNOWLEDGEMENT_ATTEMPTS,
            PLACEMENT_ACKNOWLEDGEMENT_INTERVAL,
            Arc::new(SystemLinuxProtectionIo::default()),
            Arc::new(SystemProtectionGenerationProvider),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
        Arc::new(CoreNodeHostProtectionProvider::linux(Arc::new(reader)))
    };
    #[cfg(not(target_os = "linux"))]
    let protection: Arc<dyn NodeHostProtectionReadPort> =
        Arc::new(CoreNodeHostProtectionProvider::macos());
    Ok(Arc::new(NodeHostProjectionPorts::new(
        placements,
        Arc::new(CoreNodeHostTopologyProvider),
        protection,
        services,
    )))
}

// Composes the Linux Node-owned durable generation, lease projection, and role-fixed listener.
#[cfg(target_os = "linux")]
fn compose_linux_node_protection(
    configuration: &NodeConfiguration,
    owner_user_id: u32,
    database: Arc<DatabaseManager>,
    manager: Arc<li_node_manager::NodeManager>,
    installation_id: li_core_interface::InstallationId,
    model: &CoreComposedModel,
) -> Result<CoreNodeProtectionResidentConfiguration, CoreNodeProcessError> {
    let li_node_manager::NodePlacementSafetyConfiguration::Linux(protection) =
        configuration.placement_safety()
    else {
        return Err(CoreNodeProcessError::CompositionUnavailable);
    };
    let placement_protection = Arc::new(
        FilesystemLinuxPlacementProtectionProvider::new(
            protection.protection_root().to_path_buf(),
            owner_user_id,
            PLACEMENT_ACKNOWLEDGEMENT_ATTEMPTS,
            PLACEMENT_ACKNOWLEDGEMENT_INTERVAL,
            Arc::new(SystemLinuxProtectionIo::default()),
            Arc::new(SystemProtectionGenerationProvider),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let targets: Arc<dyn NodeProtectionTargetProvider> =
        Arc::new(CoreNodeProtectionTargetProvider {
            targets: placement_protection.clone(),
        });
    let placements = Arc::new(DatabasePlacementStore::new(database.clone()));
    let host = Arc::new(SystemWatchdogLinuxHostFileProvider);
    let processes: Arc<dyn WatchdogLinuxProcessProvider> =
        Arc::new(SystemWatchdogLinuxProcessProvider::new(
            WatchdogLinuxProcessLayout::system(),
            host,
            Arc::new(SystemWatchdogLinuxPidFdProvider),
        ));
    let watchdog_targets = Arc::new(PersistedNodeWatchdogTargetProvider::new(
        manager.local_node_id().clone(),
        placements.clone(),
        placement_protection.clone(),
        Arc::new(li_node_manager::LinuxNodeWatchdogProcessProvider::new(
            processes,
        )),
    ));
    let watchdog_sessions = Arc::new(NodeWatchdogSessionAuthority::new(
        database.clone(),
        watchdog_targets,
    ));
    let installations: Arc<dyn RuntimeInstallationProvider> = Arc::new(
        StoredRuntimeInstallationProvider::new(model.runtime_store.clone()),
    );
    let runtimes: Arc<dyn NodeWatchdogRuntimeProvider> =
        Arc::new(CoreNodeWatchdogRuntimeProvider {
            installations,
            manifests: model.executions.clone(),
        });
    let watchdog_status = Arc::new(
        NodeWatchdogSiteStatusProvider::new(
            env!("CARGO_PKG_VERSION").to_string(),
            installation_id.as_str().to_string(),
            watchdog_sessions.clone(),
            placements.clone(),
            runtimes,
            placement_protection,
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let leases = Arc::new(NodeProtectionLeaseStore::new());
    let bindings: Arc<dyn NodeProtectionBindingProvider> = Arc::new(
        PersistedNodeProtectionBindingProvider::new(placements.clone(), targets.clone()),
    );
    let snapshots: Arc<dyn NodeProtectionSnapshotProvider> =
        Arc::new(NodeGatewayProtectionLeaseProvider::new(
            manager.clone(),
            placements,
            leases.clone(),
            targets,
        ));
    let authorization = Arc::new(CoreNodeProtectionAuthorizationProvider {
        gateway_principal: protection.gateway().principal_id().clone(),
        watchdog_principal: protection.watchdog().principal_id().clone(),
    });
    let api = Arc::new(
        NodeProtectionApi::new(
            manager.local_node_id().clone(),
            installation_id,
            protection.watchdog_source_identity().clone(),
            authorization,
            Arc::new(SystemNodeProtectionClock),
            Arc::new(DatabaseNodeProtectionSessionGenerationStore::new(database)),
            leases,
            bindings,
            snapshots.clone(),
            protection.lease_milliseconds(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?
        .with_watchdog_protocol(watchdog_sessions, watchdog_status),
    );
    let peer_roles = Arc::new(
        SystemNodeProtectionPeerRoleProvider::new_system(
            owner_user_id,
            protection.gateway().clone(),
            protection.watchdog().clone(),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    Ok(CoreNodeProtectionResidentConfiguration {
        local: protection.local_server().clone(),
        api,
        peer_roles,
    })
}

// Composes the Node-owned durable command-audit lifecycle before either listener can start.
fn compose_command_audit(
    configuration: &NodeConfiguration,
    owner_user_id: u32,
    database: Arc<DatabaseManager>,
    manager: Arc<li_node_manager::NodeManager>,
) -> Result<Arc<NodeCommandAuditCoordinator>, CoreNodeProcessError> {
    let audit_cryptography = Arc::new(
        OpenSslNodeAuditCheckpointCryptography::new(
            configuration.pairing().openssl_command().to_path_buf(),
            NodeAuditCheckpointKeyReferences::new(
                configuration
                    .pairing()
                    .site_private_key_file()
                    .to_path_buf(),
                configuration.pairing().site_public_key_file().to_path_buf(),
            )
            .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            Arc::new(
                SystemNodeAuditOpenSslRunner::new(
                    configuration.pairing().trust_workspace().to_path_buf(),
                    owner_user_id,
                    Duration::from_secs(10),
                )
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
            ),
        )
        .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
    );
    let audit_manager = Arc::new(manager.audit_manager(audit_cryptography));
    let command_audit = NodeCommandAuditCoordinator::new(
        audit_manager,
        Arc::new(DatabaseNodeCommandAuditSessionStore::new(database)),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse(&format!("local-user-{owner_user_id}"))
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
        ),
        AuditOrigin::new(manager.local_node_id().clone(), AuditOriginInterface::Cli),
    )
    .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?;
    Ok(Arc::new(command_audit))
}

// Starts, verifies, and completes one resident without leaving partial resources detached.
fn run_resident(resident: &dyn CoreNodeResidentLifecycle) -> Result<(), CoreNodeProcessError> {
    let mut handle = resident
        .start_resident()
        .map_err(|_| CoreNodeProcessError::RuntimeUnavailable)?;
    if !handle.is_running() {
        let _ = handle.stop();
        return Err(CoreNodeProcessError::RuntimeUnavailable);
    }
    handle
        .wait()
        .map_err(|_| CoreNodeProcessError::RuntimeUnavailable)
}

// Builds the exact platform provider selected by closed configuration and compile target.
fn hardware_manager(
    configuration: &NodeConfiguration,
    node_id: li_core_interface::NodeId,
) -> Result<HardwareManager, CoreNodeProcessError> {
    let io = Arc::new(SystemHardwareNativeIo::default());
    let provider: Arc<dyn li_hardware_manager::HardwareProvider> = match configuration.hardware() {
        NodeHardwareConfiguration::Linux {
            architecture,
            boot_id_file,
            cpu_information_file,
            memory_information_file,
            nvidia_smi_command,
            rdma_command,
        } if cfg!(target_os = "linux") && architecture_matches_target(*architecture) => {
            Arc::new(LinuxHardwareProvider::new(
                LinuxHardwareConfiguration::new(
                    *architecture,
                    boot_id_file.clone(),
                    cpu_information_file.clone(),
                    memory_information_file.clone(),
                    nvidia_smi_command.clone(),
                    rdma_command.clone(),
                )
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
                io,
            ))
        }
        NodeHardwareConfiguration::MacosArm64 {
            sysctl_command,
            metal_probe_command,
        } if cfg!(all(target_os = "macos", target_arch = "aarch64")) => {
            Arc::new(MacOsHardwareProvider::new(
                MacOsHardwareConfiguration::new(
                    sysctl_command.clone(),
                    metal_probe_command.clone(),
                )
                .map_err(|_| CoreNodeProcessError::CompositionUnavailable)?,
                io,
            ))
        }
        _ => return Err(CoreNodeProcessError::CompositionUnavailable),
    };
    Ok(HardwareManager::new(
        node_id,
        provider,
        Arc::new(SystemHardwareIdentityProvider),
        Arc::new(SystemHardwareClock),
    ))
}

// Returns whether one configured Linux architecture matches this exact native binary.
fn architecture_matches_target(architecture: li_core_interface::CpuArchitecture) -> bool {
    match architecture {
        li_core_interface::CpuArchitecture::Arm64 => cfg!(target_arch = "aarch64"),
        li_core_interface::CpuArchitecture::X86_64 => cfg!(target_arch = "x86_64"),
    }
}

// Converts the service-update role into the shared Node role vocabulary.
fn node_role(role: CoreUpdateNodeRole) -> li_core_interface::NodeRole {
    match role {
        CoreUpdateNodeRole::Main => li_core_interface::NodeRole::Main,
        CoreUpdateNodeRole::Child => li_core_interface::NodeRole::Child,
    }
}

// Converts the persisted Node role into the update service policy role.
const fn update_node_role(role: li_core_interface::NodeRole) -> CoreUpdateNodeRole {
    match role {
        li_core_interface::NodeRole::Main => CoreUpdateNodeRole::Main,
        li_core_interface::NodeRole::Child => CoreUpdateNodeRole::Child,
    }
}

// Maps one release archive family to the exact resident service platform.
const fn release_service_platform(
    platform: CoreUpdateReleasePlatform,
) -> CoreUpdateServicePlatform {
    match platform {
        CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
            CoreUpdateServicePlatform::Linux
        }
        CoreUpdateReleasePlatform::MacosArm64 => CoreUpdateServicePlatform::Macos,
    }
}

// Creates one redacted setup failure for an unavailable or invalid Node health boundary.
fn node_health_provider_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::provider("Node health", reason)
}

// Returns the effective account identity trusted by owner-only native file contracts.
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process credential identity.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use li_authentication_manager::PeerCredential;
    use li_core_interface::{
        DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
        NodeIdentity, NodeRole, Sha256Digest, TechnicalName, UnixMilliseconds,
    };
    use li_core_update_manager::CoreUpdateServicePlatform;
    use li_node_manager::{
        NodeCommandAuditApiPort, NodeConfigurationError, NodeConfigurationFile,
        NodeConfigurationFileProvider,
    };

    use super::*;

    // Records one deterministic process-handle lifecycle without creating native threads.
    #[derive(Default)]
    struct LifecycleState {
        starts: usize,
        waits: usize,
        stops: usize,
        cleaned: bool,
    }

    // Selects one construction and resident completion outcome.
    struct LifecycleMock {
        start_error: bool,
        running: bool,
        wait_error: bool,
        state: Arc<Mutex<LifecycleState>>,
    }

    impl CoreNodeResidentLifecycle for LifecycleMock {
        // Returns one configured lifecycle handle or one injected start failure.
        fn start_resident(&self) -> Result<Box<dyn CoreNodeResidentHandle>, NodeResidentError> {
            self.state.lock().expect("state").starts += 1;
            if self.start_error {
                return Err(NodeResidentError::LocalListenerStartFailed);
            }
            Ok(Box::new(HandleMock {
                running: self.running,
                wait_error: self.wait_error,
                state: self.state.clone(),
            }))
        }
    }

    // Simulates the same cleanup-on-wait contract implemented by NodeResidentHandle.
    struct HandleMock {
        running: bool,
        wait_error: bool,
        state: Arc<Mutex<LifecycleState>>,
    }

    impl CoreNodeResidentHandle for HandleMock {
        // Returns the configured complete-resource readiness state.
        fn is_running(&self) -> bool {
            self.running
        }

        // Completes cleanup before returning the configured loop outcome.
        fn wait(&mut self) -> Result<(), NodeResidentError> {
            let mut state = self.state.lock().expect("state");
            state.waits += 1;
            state.cleaned = true;
            if self.wait_error {
                Err(NodeResidentError::DaemonTickFailed)
            } else {
                Ok(())
            }
        }

        // Completes cleanup immediately for a failed readiness observation.
        fn stop(&mut self) -> Result<(), NodeResidentError> {
            let mut state = self.state.lock().expect("state");
            state.stops += 1;
            state.cleaned = true;
            Ok(())
        }
    }

    // Supplies one exact closed configuration document under the current test owner.
    struct ConfigurationProvider {
        owner_user_id: u32,
        document: Vec<u8>,
    }

    impl NodeConfigurationFileProvider for ConfigurationProvider {
        // Returns the configured safe file observation without touching host state.
        fn read_no_follow(
            &self,
            _path: &std::path::Path,
            _maximum_bytes: usize,
        ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
            Ok(NodeConfigurationFile::new(
                self.owner_user_id,
                0o600,
                1,
                true,
                self.document.clone(),
            ))
        }
    }

    // Returns one platform-exact closed document with selectable database and hardware identity.
    fn configuration_document(
        database_file: &std::path::Path,
        mismatched_platform: bool,
    ) -> Vec<u8> {
        let hardware = if mismatched_platform {
            if cfg!(target_os = "linux") {
                serde_json::json!({
                    "operating_system": "macos",
                    "architecture": "arm64",
                    "sysctl_command": "/usr/sbin/sysctl",
                    "metal_probe_command": "/usr/local/libexec/li_metal_probe"
                })
            } else {
                serde_json::json!({
                    "operating_system": "linux",
                    "architecture": "arm64",
                    "boot_id_file": "/proc/sys/kernel/random/boot_id",
                    "cpu_information_file": "/proc/cpuinfo",
                    "memory_information_file": "/proc/meminfo",
                    "nvidia_smi_command": null,
                    "rdma_command": null
                })
            }
        } else if cfg!(target_os = "linux") {
            serde_json::json!({
                "operating_system": "linux",
                "architecture": if cfg!(target_arch = "aarch64") { "arm64" } else { "x86_64" },
                "boot_id_file": "/proc/sys/kernel/random/boot_id",
                "cpu_information_file": "/proc/cpuinfo",
                "memory_information_file": "/proc/meminfo",
                "nvidia_smi_command": null,
                "rdma_command": null
            })
        } else {
            serde_json::json!({
                "operating_system": "macos",
                "architecture": "arm64",
                "sysctl_command": "/usr/sbin/sysctl",
                "metal_probe_command": "/usr/local/libexec/li_metal_probe"
            })
        };
        let pairing = if hardware["operating_system"] == "linux" {
            serde_json::json!({
                "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key", "operating_system": "linux",
                "discovery_command": "/usr/bin/avahi-publish-service", "openssl_command": "/usr/bin/openssl",
                "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
                "site_private_key_file": "/var/lib/letsinfer/trust/site.key", "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
                "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt", "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
                "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32),
                "direct_link_sys_class": "/sys/class", "direct_link_ip_command": "/usr/sbin/ip"
            })
        } else {
            serde_json::json!({
                "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key", "operating_system": "macos",
                "discovery_command": "/usr/bin/dns-sd", "openssl_command": "/usr/bin/openssl",
                "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
                "site_private_key_file": "/var/lib/letsinfer/trust/site.key", "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
                "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt", "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
                "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32)
            })
        };
        let placement_safety = if hardware["operating_system"] == "linux" {
            serde_json::json!({
                "operating_system": "linux",
                "socket_path": "/tmp/li_node_protection_test.sock",
                "maximum_workers": 4,
                "read_timeout_milliseconds": 1000,
                "write_timeout_milliseconds": 1000,
                "accept_poll_interval_milliseconds": 10,
                "protection_root": "/tmp/li_node_protected_placements",
                "watchdog_source_identity": "33".repeat(32),
                "gateway": {"path": "/usr/local/bin/li_gateway", "executable_sha256": "44".repeat(32), "principal_id": "5".repeat(32)},
                "watchdog": {"path": "/usr/local/bin/li_watchdog", "executable_sha256": "66".repeat(32), "principal_id": "7".repeat(32)},
                "lease_milliseconds": 3000
            })
        } else {
            serde_json::json!({"operating_system": "macos"})
        };
        let macos = hardware["operating_system"] == "macos";
        let core_update = serde_json::json!({
            "release_platform": if macos { "macos_arm64" } else { "linux_arm64" },
            "letsinfer_home": "/tmp/letsinfer", "home_directory": if macos { "/Users/test" } else { "/home/test" },
            "setup_state_directory": "/tmp/letsinfer/setup", "configuration_root": "/tmp",
            "curl_command": "/usr/bin/curl", "ssh_keygen_command": "/usr/bin/ssh-keygen",
            "allowed_signers_file": "/tmp/letsinfer/trust/release-allowed-signers",
            "supervisor_command": if macos { "/bin/launchctl" } else { "/usr/bin/systemctl" },
            "readiness_timeout_milliseconds": 30000, "readiness_poll_milliseconds": 100,
            "stable_readiness_observations": 2
        });
        let model = serde_json::json!({
            "catalog_source": "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json",
            "catalog_cache_root": "/tmp/li_node_catalog_cache",
            "catalog_hydration_root": "/tmp/li_node_catalog_hydration",
            "http_workspace_root": "/tmp/li_node_http_workspace",
            "installation_root": "/tmp/li_node_runtime_installations",
            "runtime_cache_root": "/tmp/li_node_runtime_cache",
            "curl_command": "/usr/bin/curl",
            "docker_command": "/usr/bin/docker",
            "command_working_directory": "/tmp/li_node_command_workspace",
            "placement_material_root": "/tmp/placement_material",
            "placement_secret_root": "/tmp/placement_secrets",
            "placement_tls_workspace_root": "/tmp/placement_tls_staging",
            "first_port": 18000,
            "port_count": 32,
            "endpoint_timeout_milliseconds": 1000,
            "maximum_hardware_age_milliseconds": 60000,
            "group_id": 20,
            "launch_agents_root": macos.then_some("/tmp/LaunchAgents"),
            "launchctl_command": macos.then_some("/bin/launchctl")
        });
        let benchmark = (!macos).then(|| {
            serde_json::json!({
                "worker_executable": "/usr/local/libexec/letsinfer/li_benchmark_worker",
                "github_cli_command": "/usr/bin/gh",
                "task_root": "/tmp/li_node_benchmark_tasks",
                "telemetry_root": "/tmp/li_node_benchmark_telemetry",
                "evidence_root": "/tmp/li_node_benchmark_evidence",
                "signing_workspace_root": "/tmp/li_node_benchmark_signing",
                "signing_private_key_file": "/tmp/li_node_benchmark_signing.key",
                "signing_public_key_file": "/tmp/li_node_benchmark_signing.pub",
                "maximum_runtime_milliseconds": 60_000,
                "stop_grace_milliseconds": 5_000,
                "watchdog": {
                    "host": "127.0.0.1",
                    "port": 9_445,
                    "server_name": "node.local",
                    "ca_file": "/tmp/li_node_watchdog_ca.pem",
                    "controller_authority_private_key_file": "/tmp/li_node_watchdog_ca.key",
                    "controller_allowlist_file": "/tmp/li_node_watchdog_controllers.allow",
                    "controller_reload_receipt_file": "/tmp/li_node_watchdog_controller_snapshot.json",
                    "enrollment_server_certificate_file": "/tmp/li_node_watchdog_server.pem",
                    "enrollment_server_private_key_file": "/tmp/li_node_watchdog_server.key",
                    "controller_certificate_file": "/tmp/li_node_watchdog_controller.pem",
                    "controller_private_key_file": "/tmp/li_node_watchdog_controller.key",
                    "timeout_milliseconds": 5_000
                }
            })
        });
        serde_json::to_vec(&serde_json::json!({
            "schema": {"name": "li_node_configuration", "version": 4},
            "runtime": {"database_file": database_file.display().to_string()},
            "core_update": core_update,
            "model": model,
            "benchmark": benchmark,
            "pairing": pairing,
            "hardware": hardware,
            "placement_safety": placement_safety,
            "daemon": {"cadence_milliseconds": 1000},
            "private_api": {
                "local": {
                    "socket_path": "/tmp/li_node_process_test.sock",
                    "maximum_workers": 4,
                    "read_timeout_milliseconds": 1000,
                    "write_timeout_milliseconds": 1000,
                    "accept_poll_interval_milliseconds": 10
                },
                "remote": {
                    "bind_address": "127.0.0.1:39770",
                    "maximum_workers": 4,
                    "accept_poll_interval_milliseconds": 10,
                    "handshake_timeout_milliseconds": 1000,
                    "read_timeout_milliseconds": 1000,
                    "write_timeout_milliseconds": 1000,
                    "server_certificate_file": "/tmp/li_node_missing.crt",
                    "server_private_key_file": "/tmp/li_node_missing.key",
                    "client_ca_file": "/tmp/li_node_missing_ca.crt"
                }
            }
        }))
        .expect("configuration")
    }

    // Loads one platform-exact configuration through the same strict production parser.
    fn configuration(
        database_file: &std::path::Path,
        mismatched_platform: bool,
    ) -> NodeConfiguration {
        let owner_user_id = effective_user_id();
        NodeConfiguration::load(
            &NodeConfigurationFileReference::new("/tmp/li_node.json".into(), owner_user_id)
                .expect("reference"),
            &ConfigurationProvider {
                owner_user_id,
                document: configuration_document(database_file, mismatched_platform),
            },
        )
        .expect("configuration")
    }

    // Returns one exact active local identity for composition failure tests.
    fn local_node() -> Node {
        Node::new(
            NodeIdentity::new(
                NodeId::parse(&"1".repeat(32)).expect("node"),
                MachineId::parse(&"2".repeat(32)).expect("machine"),
                InstallationId::parse(&"3".repeat(64)).expect("installation"),
            ),
            DisplayName::parse("Home AI").expect("name"),
            NodeRole::Main,
            NodeState::Active,
            NodeAddress::parse("homeai.local").expect("address"),
            None,
            EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
                .expect("timestamps"),
        )
    }

    // Initializes only the exact durable local identity required before native composition.
    fn initialize_identity(database_file: &std::path::Path) {
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(database_file)).expect("database"),
        );
        li_node_manager::NodeManager::open(database, local_node(), "initialize-node")
            .expect("identity");
    }

    // Proves a child gets only its own main-owned lifecycle record and no other capability.
    #[test]
    fn remote_authorization_denies_every_unassigned_child_to_main_action() {
        let temporary = tempfile::tempdir().expect("temporary");
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(
                temporary.path().join("core.sqlite3"),
            ))
            .expect("database"),
        );
        let local_node_id = local_node().identity().node_id().clone();
        let peer_credentials = Arc::new(DatabasePeerCredentialStore::new(database.clone()));
        let principal = CredentialId::parse(&"c".repeat(32)).expect("principal");
        peer_credentials
            .create(
                PeerCredential::new(
                    principal.clone(),
                    Sha256Digest::parse(&"d".repeat(64)).expect("peer leaf"),
                    local_node_id.clone(),
                    NodeId::parse(&"4".repeat(32)).expect("peer Node"),
                    PeerCredentialDirection::ChildToMain,
                    UnixMilliseconds::new(0),
                    UnixMilliseconds::new(u64::MAX),
                    None,
                    None,
                )
                .expect("peer credential"),
                "peer:create:application-authorization",
            )
            .expect("persist peer credential");
        let authentication = Arc::new(AuthenticationManager::new_with_peer_credential_store(
            Arc::new(DatabaseAuthenticationStore::new(database)),
            peer_credentials,
            Arc::new(SystemApiKeyMaterialProvider),
            Arc::new(SystemAuthenticationClock),
        ));
        let authorization = CoreNodePrivateAuthorizationProvider::new_for_role(
            authentication,
            local_node_id,
            li_core_interface::NodeRole::Main,
        );

        for action in [
            NodePrivateAction::ReadLocalNode,
            NodePrivateAction::ReadNodes,
            NodePrivateAction::ReadNode,
            NodePrivateAction::ReadHardware,
            NodePrivateAction::ReadHostProjection,
            NodePrivateAction::ReadHostInventory,
            NodePrivateAction::ReadStorage,
            NodePrivateAction::CleanStorage,
            NodePrivateAction::ReadCatalog,
            NodePrivateAction::ReadCompatibleTargets,
            NodePrivateAction::EnrollChild,
            NodePrivateAction::TransitionChild,
            NodePrivateAction::ReadOutbox,
            NodePrivateAction::AcknowledgeOutbox,
            NodePrivateAction::OpenPairing,
            NodePrivateAction::EnrollPairing,
            NodePrivateAction::ApprovePairing,
            NodePrivateAction::ReadPairingStatus,
            NodePrivateAction::PreviewBenchmark,
            NodePrivateAction::StartBenchmark,
            NodePrivateAction::ReadActiveBenchmark,
            NodePrivateAction::ReadBenchmark,
            NodePrivateAction::StopBenchmark,
            NodePrivateAction::CreateApiKey,
            NodePrivateAction::ReadApiKeys,
            NodePrivateAction::ReadApiKey,
            NodePrivateAction::UpdateApiKeyPolicy,
            NodePrivateAction::RotateApiKey,
            NodePrivateAction::RevokeApiKey,
            NodePrivateAction::OpenCommandAudit,
            NodePrivateAction::CompleteCommandAudit,
            NodePrivateAction::ReadAuditEvents,
            NodePrivateAction::ReadAuditEvent,
            NodePrivateAction::VerifyAudit,
            NodePrivateAction::ExportAudit,
            NodePrivateAction::ListModels,
            NodePrivateAction::InstallModel,
            NodePrivateAction::PauseModel,
            NodePrivateAction::ResumeModel,
            NodePrivateAction::RestartModel,
            NodePrivateAction::RecoverModel,
            NodePrivateAction::RemoveModel,
            NodePrivateAction::RollbackModel,
            NodePrivateAction::ReadModelLogs,
            NodePrivateAction::Gateway,
        ] {
            assert_eq!(
                authorization.authorize(&principal, action),
                Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
            );
        }
        let peer_node_id = NodeId::parse(&"4".repeat(32)).expect("peer Node");
        assert_eq!(
            authorization.authorize_child_read(&principal, &peer_node_id),
            Ok(())
        );
        assert_eq!(
            authorization.authorize_child_transition(&principal, &peer_node_id),
            Ok(())
        );
        let sibling_node_id = NodeId::parse(&"5".repeat(32)).expect("sibling Node");
        assert_eq!(
            authorization.authorize_child_read(&principal, &sibling_node_id),
            Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
        );
        assert_eq!(
            authorization.authorize_child_transition(&principal, &sibling_node_id),
            Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
        );
    }

    // Allows a paired main to observe only its child's identity and hardware projection.
    #[test]
    fn remote_authorization_limits_main_to_child_actions() {
        let temporary = tempfile::tempdir().expect("temporary");
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(
                temporary.path().join("core.sqlite3"),
            ))
            .expect("database"),
        );
        let local_node_id = local_node().identity().node_id().clone();
        let peer_credentials = Arc::new(DatabasePeerCredentialStore::new(database.clone()));
        let principal = CredentialId::parse(&"c".repeat(32)).expect("principal");
        let wrong_direction_principal =
            CredentialId::parse(&"e".repeat(32)).expect("wrong-direction principal");
        let main_node_id = NodeId::parse(&"4".repeat(32)).expect("main Node");
        peer_credentials
            .create(
                PeerCredential::new(
                    principal.clone(),
                    Sha256Digest::parse(&"d".repeat(64)).expect("peer leaf"),
                    local_node_id.clone(),
                    main_node_id,
                    PeerCredentialDirection::MainToChild,
                    UnixMilliseconds::new(0),
                    UnixMilliseconds::new(u64::MAX),
                    None,
                    None,
                )
                .expect("peer credential"),
                "peer:create:application-child-authorization",
            )
            .expect("persist peer credential");
        peer_credentials
            .create(
                PeerCredential::new(
                    wrong_direction_principal.clone(),
                    Sha256Digest::parse(&"f".repeat(64)).expect("wrong-direction peer leaf"),
                    local_node_id.clone(),
                    NodeId::parse(&"5".repeat(32)).expect("child peer Node"),
                    PeerCredentialDirection::ChildToMain,
                    UnixMilliseconds::new(0),
                    UnixMilliseconds::new(u64::MAX),
                    None,
                    None,
                )
                .expect("wrong-direction peer credential"),
                "peer:create:application-child-wrong-direction",
            )
            .expect("persist wrong-direction peer credential");
        let authentication = Arc::new(AuthenticationManager::new_with_peer_credential_store(
            Arc::new(DatabaseAuthenticationStore::new(database)),
            peer_credentials,
            Arc::new(SystemApiKeyMaterialProvider),
            Arc::new(SystemAuthenticationClock),
        ));
        let authorization = CoreNodePrivateAuthorizationProvider::new_for_role(
            authentication,
            local_node_id.clone(),
            li_core_interface::NodeRole::Child,
        );

        for action in [
            NodePrivateAction::ReadLocalNode,
            NodePrivateAction::ReadHardware,
        ] {
            assert_eq!(authorization.authorize(&principal, action), Ok(()));
        }
        assert_eq!(
            authorization.authorize(&wrong_direction_principal, NodePrivateAction::ReadLocalNode),
            Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
        );
        for action in [
            NodePrivateAction::ReadNodes,
            NodePrivateAction::ReadNode,
            NodePrivateAction::ReadHostProjection,
            NodePrivateAction::ReadHostInventory,
            NodePrivateAction::ReadStorage,
            NodePrivateAction::CleanStorage,
            NodePrivateAction::ReadCatalog,
            NodePrivateAction::ReadCompatibleTargets,
            NodePrivateAction::EnrollChild,
            NodePrivateAction::TransitionChild,
            NodePrivateAction::ReadOutbox,
            NodePrivateAction::AcknowledgeOutbox,
            NodePrivateAction::OpenPairing,
            NodePrivateAction::EnrollPairing,
            NodePrivateAction::ApprovePairing,
            NodePrivateAction::ReadPairingStatus,
            NodePrivateAction::PreviewBenchmark,
            NodePrivateAction::StartBenchmark,
            NodePrivateAction::ReadActiveBenchmark,
            NodePrivateAction::ReadBenchmark,
            NodePrivateAction::StopBenchmark,
            NodePrivateAction::AddController,
            NodePrivateAction::ReadControllers,
            NodePrivateAction::RevokeController,
            NodePrivateAction::CreateApiKey,
            NodePrivateAction::ReadApiKeys,
            NodePrivateAction::ReadApiKey,
            NodePrivateAction::UpdateApiKeyPolicy,
            NodePrivateAction::RotateApiKey,
            NodePrivateAction::RevokeApiKey,
            NodePrivateAction::OpenCommandAudit,
            NodePrivateAction::CompleteCommandAudit,
            NodePrivateAction::ReadAuditEvents,
            NodePrivateAction::ReadAuditEvent,
            NodePrivateAction::VerifyAudit,
            NodePrivateAction::ExportAudit,
            NodePrivateAction::ListModels,
            NodePrivateAction::InstallModel,
            NodePrivateAction::PauseModel,
            NodePrivateAction::ResumeModel,
            NodePrivateAction::RestartModel,
            NodePrivateAction::RecoverModel,
            NodePrivateAction::RemoveModel,
            NodePrivateAction::RollbackModel,
            NodePrivateAction::PreviewRollbackModel,
            NodePrivateAction::ReadModelLogs,
            NodePrivateAction::ReadModelRuntimeLogs,
            NodePrivateAction::CheckCoreUpdate,
            NodePrivateAction::UpdateCore,
            NodePrivateAction::UpdateModel,
            NodePrivateAction::ReadExposure,
            NodePrivateAction::EnableExposure,
            NodePrivateAction::DisableExposure,
            NodePrivateAction::Gateway,
        ] {
            assert_eq!(
                authorization.authorize(&principal, action),
                Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
            );
        }
        assert_eq!(
            authorization.authorize_child_read(&principal, &local_node_id),
            Ok(())
        );
        assert_eq!(
            authorization.authorize_child_read(
                &principal,
                &NodeId::parse(&"5".repeat(32)).expect("foreign child Node"),
            ),
            Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
        );
        assert_eq!(
            authorization.authorize_child_transition(&principal, &local_node_id),
            Err(li_node_manager::NodePrivateApiError::AuthorizationDenied)
        );
    }

    // Keeps controller reads, workload mutation, and authority mutation in distinct role tiers.
    #[test]
    fn controller_authorization_policy_uses_exact_minimum_roles() {
        assert_eq!(
            controller_role_for_action(NodePrivateAction::ReadLocalNode),
            ControllerRole::Viewer
        );
        assert_eq!(
            controller_role_for_action(NodePrivateAction::RestartModel),
            ControllerRole::Operator
        );
        assert_eq!(
            controller_role_for_action(NodePrivateAction::InstallModel),
            ControllerRole::Administrator
        );
        assert_eq!(
            controller_role_for_action(NodePrivateAction::UpdateCore),
            ControllerRole::Administrator
        );
    }

    // Proves production composition durably closes and replays one failed command across restart.
    #[test]
    fn production_command_audit_persists_terminal_failure_across_restart() {
        let temporary = tempfile::tempdir().expect("temporary");
        let database_file = temporary.path().join("core.sqlite3");
        let owner_user_id = effective_user_id();
        initialize_identity(&database_file);
        let configuration = configuration(&database_file, false);
        let command_id = Sha256Digest::parse(&"a".repeat(64)).expect("command id");
        let intent = li_node_manager::NodeCommandAuditIntent::new(
            TechnicalName::parse("service.stop").expect("action"),
            li_node_manager::NodeCommandAuditPolicy::Always,
            li_node_manager::NodeCommandAuditMutation::Local,
            NodeRole::Main,
        )
        .with_target(
            li_node_manager::NodeCommandAuditTarget::new(
                li_node_manager::NodeCommandAuditTargetKind::Service,
                "resident-services",
            )
            .expect("target"),
        );
        let open = li_node_manager::NodeCommandAuditOpenRequest::new(command_id, intent);
        let result = li_node_manager::NodeCommandAuditResult::new(
            TechnicalName::parse("service.stop").expect("action"),
            li_node_manager::NodeCommandAuditOutcome::Failed,
            Some("cli.node_action_unavailable"),
        )
        .expect("result");

        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(&database_file)).expect("database"),
        );
        let manager =
            Arc::new(li_node_manager::NodeManager::load(database.clone()).expect("manager"));
        let coordinator = compose_command_audit(
            &configuration,
            owner_user_id,
            database.clone(),
            manager.clone(),
        )
        .expect("command audit");
        let opened = coordinator.open(open.clone()).expect("open");
        let completed = coordinator
            .complete(li_node_manager::NodeCommandAuditCompletionRequest::new(
                opened.marker().clone(),
                result.clone(),
            ))
            .expect("complete");
        assert_eq!(
            completed.disposition(),
            li_node_manager::NodeCommandAuditCompletionDisposition::Completed
        );
        assert!(completed.event_id().is_some());
        let marker = opened.marker().clone();
        let event_id = completed.event_id().cloned();
        drop(coordinator);
        drop(manager);
        drop(database);

        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(&database_file)).expect("database"),
        );
        let manager =
            Arc::new(li_node_manager::NodeManager::load(database.clone()).expect("manager"));
        let coordinator = compose_command_audit(&configuration, owner_user_id, database, manager)
            .expect("command audit");
        let completion = coordinator
            .complete(li_node_manager::NodeCommandAuditCompletionRequest::new(
                marker, result,
            ))
            .expect("recomplete");
        assert_eq!(
            completion.disposition(),
            li_node_manager::NodeCommandAuditCompletionDisposition::Replayed
        );
        assert_eq!(completion.event_id(), event_id.as_ref());
    }

    // Proves strict argument parsing matches only the native service contract.
    #[test]
    fn process_arguments_are_closed_and_absolute() {
        let parsed = CoreNodeProcessArguments::parse([
            OsString::from("--configuration"),
            OsString::from("/var/lib/letsinfer/configuration/li_node.json"),
        ])
        .expect("arguments");
        assert_eq!(
            parsed.configuration(),
            std::path::Path::new("/var/lib/letsinfer/configuration/li_node.json")
        );
        for arguments in [
            vec![],
            vec![OsString::from("--configuration")],
            vec![
                OsString::from("--configuration"),
                OsString::from("relative.json"),
            ],
            vec![
                OsString::from("--config"),
                OsString::from("/tmp/li_node.json"),
            ],
            vec![
                OsString::from("--configuration"),
                OsString::from("/tmp/li_node.json"),
                OsString::from("extra"),
            ],
        ] {
            assert_eq!(
                CoreNodeProcessArguments::parse(arguments),
                Err(CoreNodeProcessError::InvalidArguments)
            );
        }
    }

    // Proves every start, readiness, normal wait, and failed wait exit completes owned cleanup.
    #[test]
    fn process_lifecycle_matrix_never_detaches_started_resources() {
        for (start_error, running, wait_error, expected, expected_waits, expected_stops) in [
            (
                true,
                false,
                false,
                Err(CoreNodeProcessError::RuntimeUnavailable),
                0,
                0,
            ),
            (
                false,
                false,
                false,
                Err(CoreNodeProcessError::RuntimeUnavailable),
                0,
                1,
            ),
            (false, true, false, Ok(()), 1, 0),
            (
                false,
                true,
                true,
                Err(CoreNodeProcessError::RuntimeUnavailable),
                1,
                0,
            ),
        ] {
            let state = Arc::new(Mutex::new(LifecycleState::default()));
            let result = run_resident(&LifecycleMock {
                start_error,
                running,
                wait_error,
                state: state.clone(),
            });
            assert_eq!(result, expected);
            let state = state.lock().expect("state");
            assert_eq!(state.starts, 1);
            assert_eq!(state.waits, expected_waits);
            assert_eq!(state.stops, expected_stops);
            assert_eq!(state.cleaned, !start_error);
        }
    }

    // Proves startup composes truthful read-only storage into the local Node API boundary.
    #[test]
    fn storage_startup_composition_observes_without_cleanup_candidates() {
        let temporary = tempfile::tempdir().expect("temporary");
        let home = temporary.path().join("letsinfer");
        let installations = home.join("runtime_installations");
        let caches = home.join("runtime_cache");
        let benchmarks = home.join("benchmark_evidence");
        for path in [&home, &installations, &caches, &benchmarks] {
            std::fs::create_dir(path).expect("storage root");
        }
        std::fs::write(installations.join("runtime.bin"), b"runtime").expect("runtime bytes");
        std::fs::write(caches.join("cache.bin"), b"cache").expect("cache bytes");
        std::fs::write(benchmarks.join("evidence.json"), b"evidence").expect("benchmark bytes");

        let database_file = temporary.path().join("core.sqlite3");
        let mut document: serde_json::Value =
            serde_json::from_slice(&configuration_document(&database_file, false))
                .expect("configuration document");
        document["core_update"]["letsinfer_home"] = serde_json::json!(home.display().to_string());
        document["core_update"]["setup_state_directory"] =
            serde_json::json!(home.join("setup").display().to_string());
        document["core_update"]["allowed_signers_file"] = serde_json::json!(home
            .join("trust/release-allowed-signers")
            .display()
            .to_string());
        document["model"]["installation_root"] =
            serde_json::json!(installations.display().to_string());
        document["model"]["runtime_cache_root"] = serde_json::json!(caches.display().to_string());
        let owner_user_id = effective_user_id();
        let configuration = NodeConfiguration::load(
            &NodeConfigurationFileReference::new("/tmp/li_node.json".into(), owner_user_id)
                .expect("configuration reference"),
            &ConfigurationProvider {
                owner_user_id,
                document: serde_json::to_vec(&document).expect("configuration bytes"),
            },
        )
        .expect("configuration");
        let storage = compose_storage(&configuration, owner_user_id).expect("storage composition");
        let snapshot = storage.snapshot().expect("storage snapshot");
        assert!(snapshot.candidates().is_empty());
        assert!(snapshot
            .usage()
            .iter()
            .all(|usage| usage.reclaimable_bytes() == 0));
        assert_eq!(
            snapshot
                .usage()
                .iter()
                .map(|usage| usage.category())
                .collect::<Vec<_>>(),
            vec![
                NodeStorageCategory::Runtimes,
                NodeStorageCategory::Caches,
                NodeStorageCategory::Benchmarks,
            ]
        );
    }

    // Fails before listeners for database, missing identity, platform, and TLS trust boundaries.
    #[test]
    fn composition_failure_matrix_is_ordered_and_fail_closed() {
        let temporary = tempfile::tempdir().expect("temporary");
        let owner_user_id = effective_user_id();
        let cases = [
            (temporary.path().to_path_buf(), false, false),
            (
                temporary.path().join("missing-identity.sqlite3"),
                false,
                false,
            ),
            (temporary.path().join("platform.sqlite3"), true, true),
            (temporary.path().join("missing-tls.sqlite3"), true, false),
        ];
        for (database_file, initialize, mismatched_platform) in cases {
            if initialize {
                initialize_identity(&database_file);
            }
            let run_control = Arc::new(SystemNodeResidentRunControl::install().expect("control"));
            assert_eq!(
                compose_node(
                    &configuration(&database_file, mismatched_platform),
                    temporary.path().join("li_gateway.json"),
                    owner_user_id,
                    run_control.clone(),
                )
                .map(|_| ()),
                Err(CoreNodeProcessError::CompositionUnavailable)
            );
            run_control.join().expect("join");
        }
    }

    // Proves service health never opens SQLite and binds setup identity through the private API.
    #[test]
    fn service_health_uses_only_the_expected_identity_and_live_local_endpoint() {
        let temporary = tempfile::tempdir().expect("temporary");
        let database_file = temporary.path().join("core.sqlite3");
        let mut document: serde_json::Value =
            serde_json::from_slice(&configuration_document(&database_file, false))
                .expect("document");
        document["core_update"]["configuration_root"] =
            serde_json::json!(temporary.path().display().to_string());
        document["private_api"]["local"]["socket_path"] =
            serde_json::json!(temporary.path().join("node.sock").display().to_string());
        let configuration_file = temporary.path().join("li_node.json");
        std::fs::write(
            &configuration_file,
            serde_json::to_vec(&document).expect("document"),
        )
        .expect("write configuration");
        std::fs::set_permissions(&configuration_file, std::fs::Permissions::from_mode(0o600))
            .expect("configuration mode");
        let health =
            CoreNodeServiceHealth::load(configuration_file, effective_user_id()).expect("health");
        assert!(!database_file.exists());
        let platform = if cfg!(target_os = "linux") {
            CoreUpdateServicePlatform::Linux
        } else {
            CoreUpdateServicePlatform::Macos
        };
        let identity = CoreServiceSetupNodeIdentity::new(
            local_node().identity().node_id().clone(),
            NodeRole::Main,
        );
        assert_eq!(
            health.observe_with_identity(
                CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
                CoreResidentProcess::Node,
                Some(&identity),
                std::time::Duration::from_secs(1),
            ),
            Ok(CoreServiceSetupObservation::NotReady)
        );
        assert!(health
            .observe_with_identity(
                CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Child),
                CoreResidentProcess::Node,
                Some(&identity),
                std::time::Duration::from_secs(1),
            )
            .is_err());
        assert!(health
            .observe(
                CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
                CoreResidentProcess::Gateway,
                std::time::Duration::from_secs(1),
            )
            .is_err());
        assert!(!database_file.exists());
    }
}
