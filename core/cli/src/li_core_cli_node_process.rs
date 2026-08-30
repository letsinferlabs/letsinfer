// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use li_audit_manager::{AuditEvent, AuditEventId, AuditOutcome};
use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, ControllerRole, ControllerState,
};
use li_core_interface::{
    AcceleratorVendor, ComputeCapability, CpuArchitecture, DisplayName, EndpointOwnership,
    EvidenceLabel, HardwareObservation, InterconnectKind, InterconnectObservationKind,
    LogicalModelName, MemoryTopology, ModelServiceDesiredState, ModelServiceId,
    NetworkInterfaceName, Node, NodeAddress, NodeId, NodeRole, NodeState, OperatingSystem,
    OperationId, PairingInviteId, PlacementGroupId, PlacementGroupState, PlacementState,
    RuntimeCandidateId, Sha256Digest, TargetId, TechnicalName, UnixMilliseconds,
};
use li_core_update_manager::{CoreUpdateDisposition, CoreVersion};
use li_gateway_manager::GatewayExposureStatus;
use li_node_manager::{
    NodeApiKeyPolicyUpdate, NodeAuditVerification, NodeBenchmarkContext, NodeBenchmarkPlan,
    NodeBenchmarkSelection, NodeBenchmarkSnapshot, NodeCatalogEntry, NodeCatalogListRequest,
    NodeCatalogListing, NodeCatalogRefreshPolicy, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection, NodeCommandAuditCompletionRequest, NodeCommandAuditIntent,
    NodeCommandAuditMarker, NodeCommandAuditMutation, NodeCommandAuditOpenRequest,
    NodeCommandAuditOutcome, NodeCommandAuditPolicy, NodeCommandAuditResult,
    NodeCommandAuditTarget, NodeCommandAuditTargetKind, NodeControllerEnrollmentCandidate,
    NodeControllerEnrollmentReceipt, NodeControllerSummary, NodeCoreUpdateCheck,
    NodeCoreUpdateSummary, NodeHostGatewaySummary, NodeHostGatewayTelemetrySummary,
    NodeHostInventory, NodeHostPlacementGroupSnapshot, NodeHostPlacementSnapshot,
    NodeHostProjectionValue, NodeHostProtectionState, NodeHostProtectionSummary,
    NodeHostServiceState, NodeHostSnapshot, NodeHostWatchdogSummary,
    NodeHostWatchdogTelemetrySummary, NodeModelAction, NodeModelCommandIdentity,
    NodeModelCommandSummary, NodeModelInstallGroup, NodeModelInstallRequest,
    NodeModelRemovalRetention, NodeModelRemovalSelection, NodeModelRemoveRequest,
    NodeModelRollbackPreview, NodeModelRuntimeLogBatch, NodeModelRuntimeLogRequest,
    NodeModelServiceSummary, NodeModelUpdateDisposition, NodeModelUpdateRequest,
    NodeModelUpdateSummary, NodePairingApproveRequest, NodePairingInvitation, NodePairingMode,
    NodePairingOpenRequest, NodePairingState, NodePairingStatus, NodePrivateRequest,
    NodePrivateResponse, NodeStorageCategory, NodeStorageCleanReceipt, NodeStorageCleanRequest,
    NodeStorageSnapshot, NodeTransition,
};
use li_placement_manager::PlacementLink;
use sha2::{Digest, Sha256};

use crate::{
    run_native_cli, ArgumentId, AuditCommand, AuditPolicy, AuthenticationCommand, BenchmarkCommand,
    CliExitCode, CommandAuditError, CommandAuditIntent, CommandAuditMarker, CommandAuditOutcome,
    CommandAuditPort, CommandAuditResult, CommandAuditTargetKind as CliCommandAuditTargetKind,
    CommandContext, CommandContextError, CommandContextPort, CommandFailure, CommandFailureKind,
    CommandInvocation, CommandOutput, CommandPresentation, CommandProgressEvent,
    CommandProgressPort, CoreCommandCapabilities, DisplayBlock, DisplayRecord, DisplaySemantic,
    DisplayTable, ExposureCommand, HostCommand, LocalRole, MachineNumber, MachineValue,
    ModelCommand, MutationClass, NodeCommand, NodePrivateClient, NodePrivateClientConfiguration,
    NodePrivateClientError, NodePrivateDocumentExchangePort, NodeRequestIdentitySource,
    OneTimeSecret, SystemNodePrivateDocumentExchange, SystemNodeRequestIdentitySource,
    UpdateCommand,
};

type SharedNodeClient<Exchange, Identity> = Rc<RefCell<NodePrivateClient<Exchange, Identity>>>;

const NATIVE_NODE_PAIRING_PORT: u16 = 9_769;

// Carries one exact public pairing endpoint without credentials or local identity material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeNodePairingEndpoint {
    address: NodeAddress,
    port: u16,
    certificate_sha256: Sha256Digest,
}

impl NativeNodePairingEndpoint {
    // Creates one explicit nonzero candidate-facing endpoint.
    pub fn new(
        address: NodeAddress,
        port: u16,
        certificate_sha256: Sha256Digest,
    ) -> Result<Self, CommandFailure> {
        if port == 0 {
            return Err(invalid_node_argument("The pairing endpoint is invalid."));
        }
        Ok(Self {
            address,
            port,
            certificate_sha256,
        })
    }

    // Returns the exact pairing listener address.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the exact dedicated pairing listener port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the exact TLS leaf identity candidates must pin.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }
}

// Selects one candidate-side invitation source without accepting machine proof material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeNodePairingJoinSource {
    Discovery,
    Remote {
        invite_id: PairingInviteId,
        endpoint: NativeNodePairingEndpoint,
    },
}

// Selects one user-visible pairing authorization mode without embedded proof identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeNodePairingMode {
    Lan,
    Remote,
    ConnectX,
}

// Carries one bounded child activation request whose identity and proof remain Core-derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeNodePairingJoinRequest {
    mode: NativeNodePairingMode,
    source: NativeNodePairingJoinSource,
    timeout: Duration,
}

impl NativeNodePairingJoinRequest {
    // Creates one join request from a closed mode, invitation source, and complete deadline.
    pub fn new(
        mode: NativeNodePairingMode,
        source: NativeNodePairingJoinSource,
        timeout: Duration,
    ) -> Result<Self, CommandFailure> {
        if timeout < Duration::from_secs(30) || timeout > Duration::from_secs(600) {
            return Err(invalid_node_argument(
                "Pairing timeout must be between 30 and 600 seconds.",
            ));
        }
        if matches!(mode, NativeNodePairingMode::Remote)
            != matches!(source, NativeNodePairingJoinSource::Remote { .. })
        {
            return Err(invalid_node_argument(
                "Remote pairing requires one exact invitation endpoint.",
            ));
        }
        Ok(Self {
            mode,
            source,
            timeout,
        })
    }

    // Returns the exact authorization mode requested by the candidate.
    pub const fn mode(&self) -> NativeNodePairingMode {
        self.mode
    }

    // Returns the discovered or explicitly pinned invitation source.
    pub const fn source(&self) -> &NativeNodePairingJoinSource {
        &self.source
    }

    // Returns the complete discovery, enrollment, approval, and activation deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

// Owns candidate discovery, setup-code prompting, ConnectX preflight, and child activation.
pub trait NativeNodePairingPort: Send + Sync {
    // Returns the exact local pairing endpoint presented with an opened invitation.
    fn local_endpoint(&self) -> Result<NativeNodePairingEndpoint, CommandFailure>;

    // Discovers and proof-validates one candidate before a ConnectX invitation is opened.
    fn connectx_mode(
        &self,
        direct_interface: &NetworkInterfaceName,
        timeout: Duration,
    ) -> Result<NodePairingMode, CommandFailure>;

    // Discovers or connects to one invitation and completes atomic child activation.
    fn join(
        &self,
        request: &NativeNodePairingJoinRequest,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Node, CommandFailure>;
}

// Rejects pairing until Application composition supplies exact native trust and activation.
struct UnavailableNativeNodePairing;

impl NativeNodePairingPort for UnavailableNativeNodePairing {
    // Rejects endpoint projection without reading another configuration source.
    fn local_endpoint(&self) -> Result<NativeNodePairingEndpoint, CommandFailure> {
        Err(unavailable_action_failure("node pairing"))
    }

    // Rejects ConnectX preflight before discovery or local invitation mutation.
    fn connectx_mode(
        &self,
        _direct_interface: &NetworkInterfaceName,
        _timeout: Duration,
    ) -> Result<NodePairingMode, CommandFailure> {
        Err(unavailable_action_failure("ConnectX node pairing"))
    }

    // Rejects child activation before discovery, prompting, or remote transport.
    fn join(
        &self,
        _request: &NativeNodePairingJoinRequest,
        _progress: &mut dyn CommandProgressPort,
    ) -> Result<Node, CommandFailure> {
        Err(unavailable_action_failure("child node pairing"))
    }
}

// Applies one child-local lifecycle request through its exact paired main authority.
pub trait NativeChildLifecyclePort: Send + Sync {
    // Returns the main-owned child projection after one optimistic self-transition.
    fn transition(
        &self,
        local: &Node,
        transition: NodeTransition,
        observed_at: UnixMilliseconds,
    ) -> Result<Node, CommandFailure>;
}

// Selects whether native uninstall preserves the exact preflight-verified model roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeUninstallModelDisposition {
    KeepModels,
    RemoveModels,
}

// Carries the stable terminal identity and user-visible counts from native teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeUninstallReceipt {
    receipt_id: Sha256Digest,
    removed_targets: u64,
    removed_containers: u64,
    removed_images: u64,
    models_preserved: bool,
    replayed: bool,
}

impl NativeUninstallReceipt {
    // Creates one truthful terminal projection from an Application-owned uninstall receipt.
    pub const fn new(
        receipt_id: Sha256Digest,
        removed_targets: u64,
        removed_containers: u64,
        removed_images: u64,
        models_preserved: bool,
        replayed: bool,
    ) -> Self {
        Self {
            receipt_id,
            removed_targets,
            removed_containers,
            removed_images,
            models_preserved,
            replayed,
        }
    }

    // Returns the stable terminal receipt identity.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the complete number of exact preflight targets retired.
    pub const fn removed_targets(&self) -> u64 {
        self.removed_targets
    }

    // Returns the number of owned managed containers retired.
    pub const fn removed_containers(&self) -> u64 {
        self.removed_containers
    }

    // Returns the number of owned managed images retired.
    pub const fn removed_images(&self) -> u64 {
        self.removed_images
    }

    // Returns whether downloaded model roots survived owner-data cleanup.
    pub const fn models_preserved(&self) -> bool {
        self.models_preserved
    }

    // Returns whether this invocation observed the exact completed receipt.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

// Executes one complete Application-owned native uninstall after explicit CLI confirmation.
pub trait NativeUninstallPort: Send + Sync {
    // Retires every verified target or returns the first exact destructive boundary failure.
    fn uninstall(
        &self,
        disposition: NativeUninstallModelDisposition,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<NativeUninstallReceipt, CommandFailure>;
}

// Rejects uninstall until Application composition supplies the complete native coordinator.
struct UnavailableNativeUninstall;

impl NativeUninstallPort for UnavailableNativeUninstall {
    // Fails before discovering or mutating any managed target.
    fn uninstall(
        &self,
        _disposition: NativeUninstallModelDisposition,
        _progress: &mut dyn CommandProgressPort,
    ) -> Result<NativeUninstallReceipt, CommandFailure> {
        Err(unavailable_action_failure("uninstall"))
    }
}

// Rejects child-local lifecycle commands until paired remote composition is present.
struct UnavailableNativeChildLifecycle;

impl NativeChildLifecyclePort for UnavailableNativeChildLifecycle {
    // Fails without attempting a local mutation or a public-listener fallback.
    fn transition(
        &self,
        _local: &Node,
        _transition: NodeTransition,
        _observed_at: UnixMilliseconds,
    ) -> Result<Node, CommandFailure> {
        Err(unavailable_action_failure(
            "child node transition through the paired main",
        ))
    }
}

// Owns one private paired-main client independently from the owner-local CLI client.
pub struct PairedMainChildLifecycle<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    client: Mutex<NodePrivateClient<Exchange, Identity>>,
}

impl<Exchange, Identity> PairedMainChildLifecycle<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Creates one exact remote lifecycle projection without discovering another endpoint.
    pub const fn new(client: NodePrivateClient<Exchange, Identity>) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }
}

impl<Exchange, Identity> NativeChildLifecyclePort for PairedMainChildLifecycle<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Reads the main-owned revision, then mutates only the authenticated child's own record.
    fn transition(
        &self,
        local: &Node,
        transition: NodeTransition,
        observed_at: UnixMilliseconds,
    ) -> Result<Node, CommandFailure> {
        if local.role() != NodeRole::Child {
            return Err(invalid_node_argument(
                "A paired-main lifecycle request requires the local child Node.",
            ));
        }
        let node_id = local.identity().node_id().clone();
        let mut client = self.client.lock().map_err(|_| client_busy_failure())?;
        let NodePrivateResponse::NodeChanged(current) = client
            .execute(NodePrivateRequest::ReadNode {
                node_id: node_id.clone(),
            })
            .map_err(client_failure)?
        else {
            return Err(invalid_response_failure());
        };
        if current.value().identity().node_id() != &node_id
            || current.value().role() != NodeRole::Child
        {
            return Err(invalid_response_failure());
        }
        let updated_at = node_transition_time(current.value(), observed_at)?;
        let idempotency_key = node_transition_identity(transition, &node_id, current.revision());
        let NodePrivateResponse::NodeChanged(changed) = client
            .execute(NodePrivateRequest::TransitionChild {
                idempotency_key,
                node_id: node_id.clone(),
                expected_revision: current.revision(),
                transition,
                updated_at,
            })
            .map_err(client_failure)?
        else {
            return Err(invalid_response_failure());
        };
        if changed.value().identity().node_id() != &node_id
            || changed.value().role() != NodeRole::Child
        {
            return Err(invalid_response_failure());
        }
        Ok(changed.value().clone())
    }
}

// Commits one already proof-validated and human-confirmed candidate through the local Node.
pub trait NativeControllerEnrollmentCommitPort {
    // Returns the durable manager receipt containing only public controller material.
    fn commit(
        &mut self,
        candidate: NodeControllerEnrollmentCandidate,
        role: ControllerRole,
    ) -> Result<NodeControllerEnrollmentReceipt, CommandFailure>;
}

// Owns the interactive transient controller enrollment lifecycle in the native CLI process.
pub trait NativeControllerEnrollmentPort: Send + Sync {
    // Opens one bounded session, confirms its comparison code, and commits exactly once.
    fn enroll(
        &self,
        timeout: Duration,
        role: ControllerRole,
        progress: &mut dyn CommandProgressPort,
        commit: &mut dyn NativeControllerEnrollmentCommitPort,
    ) -> Result<NodeControllerSummary, CommandFailure>;
}

// Rejects enrollment until Application composition supplies its TLS provider.
struct UnavailableNativeControllerEnrollment;

impl NativeControllerEnrollmentPort for UnavailableNativeControllerEnrollment {
    // Fails before opening a listener or changing Node state.
    fn enroll(
        &self,
        _timeout: Duration,
        _role: ControllerRole,
        _progress: &mut dyn CommandProgressPort,
        _commit: &mut dyn NativeControllerEnrollmentCommitPort,
    ) -> Result<NodeControllerSummary, CommandFailure> {
        Err(failure(
            "auth.controller.enrollment_unavailable",
            "Controller enrollment is unavailable in this Core composition.",
        ))
    }
}

// Supplies wall-clock time without coupling deterministic CLI tests to the native clock.
pub trait NativeNodeCommandClock: Send + Sync {
    // Returns the current Unix time for one node lifecycle mutation.
    fn now(&self) -> Result<UnixMilliseconds, NativeNodeCommandClockError>;
}

// Describes one unavailable native command clock without retaining platform diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeNodeCommandClockError;

impl fmt::Display for NativeNodeCommandClockError {
    // Presents fixed clock failure language without a platform value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the native command clock is unavailable")
    }
}

impl Error for NativeNodeCommandClockError {}

// Reads wall-clock time from the current native host.
pub struct SystemNativeNodeCommandClock;

impl NativeNodeCommandClock for SystemNativeNodeCommandClock {
    // Returns current Unix milliseconds or fails when the system clock cannot represent them.
    fn now(&self) -> Result<UnixMilliseconds, NativeNodeCommandClockError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NativeNodeCommandClockError)?;
        let milliseconds =
            u64::try_from(elapsed.as_millis()).map_err(|_| NativeNodeCommandClockError)?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Writes one bounded audit export without granting the AuditManager filesystem ownership.
pub trait NativeAuditExportFilePort: Send + Sync {
    // Atomically replaces one explicit output file with the complete private document.
    fn write(&self, path: &Path, document: &[u8]) -> Result<(), NativeAuditExportFileError>;
}

// Describes one redacted audit-export file failure without retaining a user path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAuditExportFileError;

impl fmt::Display for NativeAuditExportFileError {
    // Presents fixed provider language without copying a machine-specific path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the audit export file is unavailable")
    }
}

impl Error for NativeAuditExportFileError {}

// Writes owner-only audit exports through one same-directory atomic replacement.
pub struct SystemNativeAuditExportFile;

impl NativeAuditExportFilePort for SystemNativeAuditExportFile {
    // Writes, synchronizes, renames, and directory-synchronizes one complete document.
    fn write(&self, path: &Path, document: &[u8]) -> Result<(), NativeAuditExportFileError> {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if path.file_name().is_none() || document.is_empty() {
            return Err(NativeAuditExportFileError);
        }
        let mut temporary = None;
        for attempt in 0_u16..128 {
            let candidate = parent.join(format!(
                ".li-audit-export-{}-{attempt}.tmp",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&candidate)
            {
                Ok(file) => {
                    temporary = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(NativeAuditExportFileError),
            }
        }
        let (temporary_path, mut file) = temporary.ok_or(NativeAuditExportFileError)?;
        let result = (|| {
            file.write_all(document)
                .map_err(|_| NativeAuditExportFileError)?;
            file.sync_all().map_err(|_| NativeAuditExportFileError)?;
            drop(file);
            std::fs::rename(&temporary_path, path).map_err(|_| NativeAuditExportFileError)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| NativeAuditExportFileError)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        result
    }
}

// Identifies the production process composition over one explicit Unix socket and entropy source.
pub type SystemNativeNodeCliProcess =
    NativeNodeCliProcess<SystemNodePrivateDocumentExchange, SystemNodeRequestIdentitySource>;

// Describes one production process composition failure without retaining machine paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeNodeCliCompositionError {
    InvalidSocketPath,
    IdentityUnavailable,
}

impl fmt::Display for NativeNodeCliCompositionError {
    // Presents stable composition language without copying a socket or entropy path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSocketPath => {
                formatter.write_str("the private Node socket configuration is invalid")
            }
            Self::IdentityUnavailable => {
                formatter.write_str("the private Node request identity source is unavailable")
            }
        }
    }
}

impl Error for NativeNodeCliCompositionError {}

// Composes the ordinary native process from explicit system-owned endpoint and entropy paths.
pub fn compose_system_native_node_cli(
    socket_path: PathBuf,
    entropy_path: &Path,
    configuration: NodePrivateClientConfiguration,
) -> Result<SystemNativeNodeCliProcess, NativeNodeCliCompositionError> {
    let exchange = SystemNodePrivateDocumentExchange::open(socket_path)
        .map_err(|_| NativeNodeCliCompositionError::InvalidSocketPath)?;
    let identity = SystemNodeRequestIdentitySource::open(entropy_path)
        .map_err(|_| NativeNodeCliCompositionError::IdentityUnavailable)?;
    Ok(NativeNodeCliProcess::new(NodePrivateClient::new(
        exchange,
        identity,
        configuration,
    )))
}

// Owns one process-local client shared only between context resolution and command dispatch.
pub struct NativeNodeCliProcess<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    client: SharedNodeClient<Exchange, Identity>,
    clock: Arc<dyn NativeNodeCommandClock>,
    audit_export_file: Arc<dyn NativeAuditExportFilePort>,
    controller_enrollment: Arc<dyn NativeControllerEnrollmentPort>,
    child_lifecycle: Arc<dyn NativeChildLifecyclePort>,
    node_pairing: Arc<dyn NativeNodePairingPort>,
    uninstall: Arc<dyn NativeUninstallPort>,
}

impl<Exchange, Identity> NativeNodeCliProcess<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Creates one process composition without opening persistence or discovering native paths.
    pub fn new(client: NodePrivateClient<Exchange, Identity>) -> Self {
        Self::new_with_providers(
            client,
            Arc::new(SystemNativeNodeCommandClock),
            Arc::new(SystemNativeAuditExportFile),
        )
    }

    // Creates one process composition with an explicit command clock.
    pub fn new_with_clock(
        client: NodePrivateClient<Exchange, Identity>,
        clock: Arc<dyn NativeNodeCommandClock>,
    ) -> Self {
        Self::new_with_providers(client, clock, Arc::new(SystemNativeAuditExportFile))
    }

    // Creates one process composition with explicit command time and audit-export providers.
    pub fn new_with_providers(
        client: NodePrivateClient<Exchange, Identity>,
        clock: Arc<dyn NativeNodeCommandClock>,
        audit_export_file: Arc<dyn NativeAuditExportFilePort>,
    ) -> Self {
        Self {
            client: Rc::new(RefCell::new(client)),
            clock,
            audit_export_file,
            controller_enrollment: Arc::new(UnavailableNativeControllerEnrollment),
            child_lifecycle: Arc::new(UnavailableNativeChildLifecycle),
            node_pairing: Arc::new(UnavailableNativeNodePairing),
            uninstall: Arc::new(UnavailableNativeUninstall),
        }
    }

    // Injects the Application-owned interactive TLS enrollment capability.
    pub fn with_controller_enrollment(
        mut self,
        controller_enrollment: Arc<dyn NativeControllerEnrollmentPort>,
    ) -> Self {
        self.controller_enrollment = controller_enrollment;
        self
    }

    // Injects the paired private-main lifecycle authority used only on a local child.
    pub fn with_child_lifecycle(
        mut self,
        child_lifecycle: Arc<dyn NativeChildLifecyclePort>,
    ) -> Self {
        self.child_lifecycle = child_lifecycle;
        self
    }

    // Injects the Application-owned discovery, trust, and activation pairing workflow.
    pub fn with_node_pairing(mut self, node_pairing: Arc<dyn NativeNodePairingPort>) -> Self {
        self.node_pairing = node_pairing;
        self
    }

    // Injects the Application-owned complete native teardown capability.
    pub fn with_uninstall(mut self, uninstall: Arc<dyn NativeUninstallPort>) -> Self {
        self.uninstall = uninstall;
        self
    }

    // Runs the existing CLI lifecycle with Node context and the currently provable wire actions.
    pub fn run<I, S, Audit, StandardOutput, StandardError>(
        &mut self,
        arguments: I,
        audit: &mut Audit,
        standard_output: &mut StandardOutput,
        standard_error: &mut StandardError,
    ) -> CliExitCode
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        Audit: CommandAuditPort,
        StandardOutput: Write,
        StandardError: Write,
    {
        let mut context = NativeNodeCommandContext::new(Rc::clone(&self.client));
        let mut capabilities = NativeNodeCliCapabilities::from_shared(
            Rc::clone(&self.client),
            Arc::clone(&self.clock),
            Arc::clone(&self.audit_export_file),
            Arc::clone(&self.controller_enrollment),
            Arc::clone(&self.child_lifecycle),
            Arc::clone(&self.node_pairing),
            Arc::clone(&self.uninstall),
        );
        run_native_cli(
            arguments,
            &mut context,
            &mut capabilities,
            audit,
            standard_output,
            standard_error,
        )
    }

    // Runs the production CLI lifecycle with the same Node client owning audit and dispatch IPC.
    pub fn run_with_node_audit<I, S, StandardOutput, StandardError>(
        &mut self,
        arguments: I,
        standard_output: &mut StandardOutput,
        standard_error: &mut StandardError,
    ) -> CliExitCode
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        StandardOutput: Write,
        StandardError: Write,
    {
        let mut audit = NativeNodeCommandAuditPort::new(Rc::clone(&self.client));
        let mut context = NativeNodeCommandContext::new(Rc::clone(&self.client));
        let mut capabilities = NativeNodeCliCapabilities::from_shared(
            Rc::clone(&self.client),
            Arc::clone(&self.clock),
            Arc::clone(&self.audit_export_file),
            Arc::clone(&self.controller_enrollment),
            Arc::clone(&self.child_lifecycle),
            Arc::clone(&self.node_pairing),
            Arc::clone(&self.uninstall),
        );
        run_native_cli(
            arguments,
            &mut context,
            &mut capabilities,
            &mut audit,
            standard_output,
            standard_error,
        )
    }
}

// Bridges mandatory CLI audit hooks to the Node-owned durable lifecycle over local IPC.
pub struct NativeNodeCommandAuditPort<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    client: SharedNodeClient<Exchange, Identity>,
}

impl<Exchange, Identity> NativeNodeCommandAuditPort<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Creates one audit adapter sharing the exact process-local private client.
    const fn new(client: SharedNodeClient<Exchange, Identity>) -> Self {
        Self { client }
    }
}

impl<Exchange, Identity> CommandAuditPort for NativeNodeCommandAuditPort<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Opens one Node-owned audit session before capability dispatch can mutate state.
    fn will_execute(
        &mut self,
        intent: CommandAuditIntent,
    ) -> Result<Option<CommandAuditMarker>, CommandAuditError> {
        if intent.policy() == AuditPolicy::None {
            return Ok(None);
        }
        let local_role = intent
            .context()
            .local_role()
            .ok_or_else(audit_unavailable)?;
        let node_intent = node_audit_intent(&intent, local_role)?;
        let response = self
            .client
            .try_borrow_mut()
            .map_err(|_| audit_unavailable())?
            .execute_correlated(|request_id| {
                NodePrivateRequest::OpenCommandAudit(NodeCommandAuditOpenRequest::new(
                    request_id.clone(),
                    node_intent,
                ))
            })
            .map_err(|_| audit_unavailable())?;
        let NodePrivateResponse::CommandAuditOpened(receipt) = response else {
            return Err(audit_invalid_response());
        };
        CommandAuditMarker::new(receipt.marker().as_str()).map(Some)
    }

    // Completes one matching Node-owned audit session with only a stable terminal result.
    fn did_execute(
        &mut self,
        marker: &CommandAuditMarker,
        result: CommandAuditResult,
    ) -> Result<(), CommandAuditError> {
        let marker =
            NodeCommandAuditMarker::parse(marker.as_str()).map_err(|_| audit_invalid_response())?;
        let result = NodeCommandAuditResult::new(
            TechnicalName::parse(result.action().as_str()).map_err(|_| audit_invalid_response())?,
            node_audit_outcome(result.outcome()),
            result.failure_code(),
        )
        .map_err(|_| audit_invalid_response())?;
        match self
            .client
            .try_borrow_mut()
            .map_err(|_| audit_unavailable())?
            .execute(NodePrivateRequest::CompleteCommandAudit(
                NodeCommandAuditCompletionRequest::new(marker, result),
            ))
            .map_err(|_| audit_unavailable())?
        {
            NodePrivateResponse::CommandAuditCompleted(_) => Ok(()),
            _ => Err(audit_invalid_response()),
        }
    }
}

// Converts one secret-free CLI intent into the equivalent Node-owned closed contract.
fn node_audit_intent(
    intent: &CommandAuditIntent,
    local_role: LocalRole,
) -> Result<NodeCommandAuditIntent, CommandAuditError> {
    let node_intent = NodeCommandAuditIntent::new(
        TechnicalName::parse(intent.action().as_str()).map_err(|_| audit_invalid_response())?,
        match intent.policy() {
            AuditPolicy::None => return Err(audit_invalid_response()),
            AuditPolicy::Success => NodeCommandAuditPolicy::Success,
            AuditPolicy::Always => NodeCommandAuditPolicy::Always,
            AuditPolicy::SensitiveRead => NodeCommandAuditPolicy::SensitiveRead,
        },
        match intent.mutation() {
            MutationClass::Read => NodeCommandAuditMutation::Read,
            MutationClass::Local => NodeCommandAuditMutation::Local,
            MutationClass::Node => NodeCommandAuditMutation::Node,
        },
        match local_role {
            LocalRole::Main => NodeRole::Main,
            LocalRole::Child => NodeRole::Child,
        },
    );
    match intent.target() {
        Some(target) => Ok(node_intent.with_target(
            NodeCommandAuditTarget::new(
                match target.kind() {
                    CliCommandAuditTargetKind::Node => NodeCommandAuditTargetKind::Node,
                    CliCommandAuditTargetKind::Model => NodeCommandAuditTargetKind::Model,
                    CliCommandAuditTargetKind::ApiKey => NodeCommandAuditTargetKind::ApiKey,
                    CliCommandAuditTargetKind::Benchmark => NodeCommandAuditTargetKind::Benchmark,
                    CliCommandAuditTargetKind::AuditEvent => NodeCommandAuditTargetKind::AuditEvent,
                    CliCommandAuditTargetKind::Core => NodeCommandAuditTargetKind::Core,
                    CliCommandAuditTargetKind::Service => NodeCommandAuditTargetKind::Service,
                },
                target.identifier(),
            )
            .map_err(|_| audit_invalid_response())?,
        )),
        None => Ok(node_intent),
    }
}

// Converts one CLI terminal outcome into the exact Node lifecycle name.
const fn node_audit_outcome(outcome: CommandAuditOutcome) -> NodeCommandAuditOutcome {
    match outcome {
        CommandAuditOutcome::Succeeded => NodeCommandAuditOutcome::Succeeded,
        CommandAuditOutcome::Failed => NodeCommandAuditOutcome::Failed,
        CommandAuditOutcome::Denied => NodeCommandAuditOutcome::Denied,
        CommandAuditOutcome::Cancelled => NodeCommandAuditOutcome::Cancelled,
    }
}

// Returns one fixed provider failure without copying IPC, marker, or response diagnostics.
fn audit_unavailable() -> CommandAuditError {
    CommandAuditError::new(
        "cli.audit_unavailable",
        "The local Node command-audit service is unavailable.",
    )
}

// Returns one fixed contract failure without retaining a malformed response or secret value.
fn audit_invalid_response() -> CommandAuditError {
    CommandAuditError::new(
        "cli.audit_response_invalid",
        "The local Node command-audit response is invalid.",
    )
}

// Runs one native process from an already-composed Node client and audit owner.
pub fn run_native_node_cli<I, S, Exchange, Identity, Audit, StandardOutput, StandardError>(
    arguments: I,
    client: NodePrivateClient<Exchange, Identity>,
    audit: &mut Audit,
    standard_output: &mut StandardOutput,
    standard_error: &mut StandardError,
) -> CliExitCode
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
    Audit: CommandAuditPort,
    StandardOutput: Write,
    StandardError: Write,
{
    NativeNodeCliProcess::new(client).run(arguments, audit, standard_output, standard_error)
}

// Resolves the local authorization role through the same private Node client as dispatch.
struct NativeNodeCommandContext<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    client: SharedNodeClient<Exchange, Identity>,
}

impl<Exchange, Identity> NativeNodeCommandContext<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Creates one context adapter without caching mutable node state across commands.
    const fn new(client: SharedNodeClient<Exchange, Identity>) -> Self {
        Self { client }
    }
}

impl<Exchange, Identity> CommandContextPort for NativeNodeCommandContext<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Reads the exact local Node role and treats only explicit absence as unconfigured state.
    fn command_context(&mut self) -> Result<CommandContext, CommandContextError> {
        let mut client = self.client.try_borrow_mut().map_err(|_| {
            CommandContextError::new(
                "cli.node_client_busy",
                "the private Node client is already in use",
            )
        })?;
        match client.execute(NodePrivateRequest::ReadLocalNode) {
            Ok(NodePrivateResponse::LocalNode(node)) => {
                Ok(CommandContext::configured(match node.role() {
                    NodeRole::Main => LocalRole::Main,
                    NodeRole::Child => LocalRole::Child,
                }))
            }
            Ok(_) => Err(CommandContextError::new(
                "cli.node_response_invalid",
                "the private Node endpoint returned an unexpected context response",
            )),
            Err(NodePrivateClientError::NotConfigured) => Ok(CommandContext::unconfigured()),
            Err(error) => Err(CommandContextError::new(
                context_error_code(&error),
                error.to_string(),
            )),
        }
    }
}

// Adapts the existing Node private API reads into CLI output without fabricating other managers.
pub struct NativeNodeCliCapabilities<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    client: SharedNodeClient<Exchange, Identity>,
    clock: Arc<dyn NativeNodeCommandClock>,
    audit_export_file: Arc<dyn NativeAuditExportFilePort>,
    controller_enrollment: Arc<dyn NativeControllerEnrollmentPort>,
    child_lifecycle: Arc<dyn NativeChildLifecyclePort>,
    node_pairing: Arc<dyn NativeNodePairingPort>,
    uninstall: Arc<dyn NativeUninstallPort>,
}

// Adapts the held CLI Node client into the sole confirmed-candidate commit boundary.
struct NativeControllerEnrollmentCommit<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    client: SharedNodeClient<Exchange, Identity>,
}

impl<Exchange, Identity> NativeControllerEnrollmentCommitPort
    for NativeControllerEnrollmentCommit<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Sends only public candidate material after the enrollment provider confirms the human code.
    fn commit(
        &mut self,
        candidate: NodeControllerEnrollmentCandidate,
        role: ControllerRole,
    ) -> Result<NodeControllerEnrollmentReceipt, CommandFailure> {
        match self
            .client
            .try_borrow_mut()
            .map_err(|_| client_busy_failure())?
            .execute(NodePrivateRequest::AddController { candidate, role })
            .map_err(client_failure)?
        {
            NodePrivateResponse::ControllerEnrollment(receipt) => Ok(receipt),
            _ => Err(invalid_response_failure()),
        }
    }
}

impl<Exchange, Identity> NativeNodeCliCapabilities<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    // Creates a directly usable capability adapter around one owned private Node client.
    pub fn new(client: NodePrivateClient<Exchange, Identity>) -> Self {
        Self::new_with_providers(
            client,
            Arc::new(SystemNativeNodeCommandClock),
            Arc::new(SystemNativeAuditExportFile),
        )
    }

    // Creates one directly usable capability adapter with an explicit command clock.
    pub fn new_with_clock(
        client: NodePrivateClient<Exchange, Identity>,
        clock: Arc<dyn NativeNodeCommandClock>,
    ) -> Self {
        Self::new_with_providers(client, clock, Arc::new(SystemNativeAuditExportFile))
    }

    // Creates one capability adapter with explicit command time and audit-export providers.
    pub fn new_with_providers(
        client: NodePrivateClient<Exchange, Identity>,
        clock: Arc<dyn NativeNodeCommandClock>,
        audit_export_file: Arc<dyn NativeAuditExportFilePort>,
    ) -> Self {
        Self {
            client: Rc::new(RefCell::new(client)),
            clock,
            audit_export_file,
            controller_enrollment: Arc::new(UnavailableNativeControllerEnrollment),
            child_lifecycle: Arc::new(UnavailableNativeChildLifecycle),
            node_pairing: Arc::new(UnavailableNativeNodePairing),
            uninstall: Arc::new(UnavailableNativeUninstall),
        }
    }

    // Injects one Application-owned interactive enrollment provider.
    pub fn with_controller_enrollment(
        mut self,
        controller_enrollment: Arc<dyn NativeControllerEnrollmentPort>,
    ) -> Self {
        self.controller_enrollment = controller_enrollment;
        self
    }

    // Injects the paired private-main lifecycle authority used only on a local child.
    pub fn with_child_lifecycle(
        mut self,
        child_lifecycle: Arc<dyn NativeChildLifecyclePort>,
    ) -> Self {
        self.child_lifecycle = child_lifecycle;
        self
    }

    // Injects one Application-owned pairing workflow for direct capability tests.
    pub fn with_node_pairing(mut self, node_pairing: Arc<dyn NativeNodePairingPort>) -> Self {
        self.node_pairing = node_pairing;
        self
    }

    // Injects one Application-owned native uninstall capability for direct process tests.
    pub fn with_uninstall(mut self, uninstall: Arc<dyn NativeUninstallPort>) -> Self {
        self.uninstall = uninstall;
        self
    }

    // Creates the dispatch half of one process-shared client composition.
    fn from_shared(
        client: SharedNodeClient<Exchange, Identity>,
        clock: Arc<dyn NativeNodeCommandClock>,
        audit_export_file: Arc<dyn NativeAuditExportFilePort>,
        controller_enrollment: Arc<dyn NativeControllerEnrollmentPort>,
        child_lifecycle: Arc<dyn NativeChildLifecyclePort>,
        node_pairing: Arc<dyn NativeNodePairingPort>,
        uninstall: Arc<dyn NativeUninstallPort>,
    ) -> Self {
        Self {
            client,
            clock,
            audit_export_file,
            controller_enrollment,
            child_lifecycle,
            node_pairing,
            uninstall,
        }
    }

    // Reads one complete host inventory without joining independent manager calls in the CLI.
    fn host_inventory(&mut self) -> Result<NodeHostInventory, CommandFailure> {
        match self.execute_request(NodePrivateRequest::ReadHostInventory)? {
            NodePrivateResponse::HostInventory(inventory) => Ok(inventory),
            _ => Err(invalid_response_failure()),
        }
    }

    // Executes read-only host views and leaves unrepresented service mutations unavailable.
    fn execute_host_command(
        &mut self,
        command: HostCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        match command {
            HostCommand::Status(_) => host_status_output(self.host_inventory()?),
            HostCommand::Topology(_) => host_topology_output(self.host_inventory()?),
            HostCommand::Doctor(invocation) => host_doctor_output(
                self.host_inventory()?,
                invocation
                    .boolean(ArgumentId::RequireStable)
                    .unwrap_or(false),
            ),
            HostCommand::Uninstall(invocation) => {
                if !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
                    return Err(uninstall_confirmation_failure());
                }
                let disposition = if invocation.boolean(ArgumentId::KeepModels).unwrap_or(false) {
                    NativeUninstallModelDisposition::KeepModels
                } else {
                    NativeUninstallModelDisposition::RemoveModels
                };
                self.uninstall
                    .uninstall(disposition, progress)
                    .map(|receipt| uninstall_output(&receipt))
            }
        }
    }

    // Executes one currently representable Node read through the closed v1 wire contract.
    fn execute_node_command(
        &mut self,
        command: NodeCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        match command {
            NodeCommand::Info(invocation) => {
                let selector = invocation.text(ArgumentId::Node);
                let inventory = self.host_inventory()?;
                let host = selected_host(&inventory, selector)?;
                let Some(catalog_source) = invocation.text(ArgumentId::Catalog) else {
                    return Ok(node_host_output(host));
                };
                match self.execute_request(NodePrivateRequest::ReadCompatibleTargets {
                    node_id: host.node().identity().node_id().clone(),
                    catalog_source: catalog_source.to_string(),
                })? {
                    NodePrivateResponse::CompatibleTargets(targets) => {
                        node_host_catalog_output(host, targets)
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            NodeCommand::List(_) => nodes_output(self.host_inventory()?),
            NodeCommand::Usage(invocation) => self.execute_node_usage(invocation),
            NodeCommand::Add(invocation) => self.execute_node_add(invocation, progress),
            NodeCommand::Pause(invocation) => {
                self.execute_node_transition(invocation, NodeTransition::Pause)
            }
            NodeCommand::Resume(invocation) => {
                self.execute_node_transition(invocation, NodeTransition::Resume)
            }
            NodeCommand::Remove(invocation) => {
                self.execute_node_transition(invocation, NodeTransition::Remove)
            }
        }
    }

    // Opens, approves, or joins one pairing workflow without caller-supplied identity proof.
    fn execute_node_add(
        &mut self,
        invocation: &CommandInvocation,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        let timeout = pairing_timeout(invocation)?;
        if let Some(invite_id) = invocation.text(ArgumentId::Approve) {
            return self.execute_pairing_approval(invocation, invite_id);
        }
        let mode = pairing_mode_selection(invocation)?;
        if invocation.boolean(ArgumentId::Join).unwrap_or(false) {
            let local = self.local_node()?;
            let NodePrivateResponse::Nodes(nodes) =
                self.execute_request(NodePrivateRequest::ReadNodes)?
            else {
                return Err(invalid_response_failure());
            };
            if local.role() != NodeRole::Main
                || local.state() != NodeState::Active
                || nodes.len() != 1
                || nodes[0].identity() != local.identity()
            {
                return Err(invalid_node_argument(
                    "Only a standalone active Node can join another main.",
                ));
            }
            let source = pairing_join_source(invocation, mode)?;
            let request = NativeNodePairingJoinRequest::new(mode, source, timeout)?;
            return self
                .node_pairing
                .join(&request, progress)
                .map(|node| node_output(&node));
        }
        if invocation.text(ArgumentId::Invitation).is_some()
            || invocation.text(ArgumentId::Address).is_some()
            || invocation.text(ArgumentId::CertificateSha256).is_some()
            || invocation.boolean(ArgumentId::Yes).unwrap_or(false)
        {
            return Err(invalid_node_argument(
                "Invitation endpoint options require --join or --approve.",
            ));
        }
        let local = self.local_node()?;
        if local.role() != NodeRole::Main || local.state() != NodeState::Active {
            return Err(invalid_node_argument(
                "Only an active main Node can open a pairing invitation.",
            ));
        }
        let node_mode = match mode {
            NativeNodePairingMode::Lan => {
                require_absent_pairing_interface(invocation)?;
                NodePairingMode::Lan
            }
            NativeNodePairingMode::Remote => {
                require_absent_pairing_interface(invocation)?;
                NodePairingMode::Remote
            }
            NativeNodePairingMode::ConnectX => {
                let interface = NetworkInterfaceName::parse(
                    invocation.text(ArgumentId::Interface).ok_or_else(|| {
                        invalid_node_argument("ConnectX pairing requires --interface.")
                    })?,
                )
                .map_err(|_| invalid_node_argument("The ConnectX interface is invalid."))?;
                self.node_pairing.connectx_mode(&interface, timeout)?
            }
        };
        let now = self
            .clock
            .now()
            .map_err(|_| node_clock_unavailable_failure())?;
        let request = NodePairingOpenRequest::new(
            pairing_command_identity("open", mode, now),
            node_mode,
            u16::try_from(timeout.as_secs())
                .map_err(|_| invalid_node_argument("The pairing timeout is invalid."))?,
        )
        .map_err(|_| invalid_node_argument("The pairing invitation is invalid."))?;
        let NodePrivateResponse::PairingInvitation(mut invitation) =
            self.execute_request(NodePrivateRequest::OpenPairing(request))?
        else {
            return Err(invalid_response_failure());
        };
        pairing_invitation_output(&mut invitation, &self.node_pairing.local_endpoint()?)
    }

    // Reads or explicitly approves one remote invitation through PairingManager authority.
    fn execute_pairing_approval(
        &mut self,
        invocation: &CommandInvocation,
        invite_id: &str,
    ) -> Result<CommandOutput, CommandFailure> {
        if invocation.boolean(ArgumentId::Join).unwrap_or(false)
            || invocation.text(ArgumentId::Invitation).is_some()
            || invocation.text(ArgumentId::Address).is_some()
            || invocation.text(ArgumentId::CertificateSha256).is_some()
            || invocation.text(ArgumentId::Interface).is_some()
        {
            return Err(invalid_node_argument(
                "Remote approval does not accept join or endpoint options.",
            ));
        }
        let invite_id = PairingInviteId::parse(invite_id)
            .map_err(|_| invalid_node_argument("The pairing invitation identity is invalid."))?;
        if !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
            let NodePrivateResponse::PairingStatus(status) =
                self.execute_request(NodePrivateRequest::ReadPairingStatus { invite_id })?
            else {
                return Err(invalid_response_failure());
            };
            return pairing_status_output(&status);
        }
        let now = self
            .clock
            .now()
            .map_err(|_| node_clock_unavailable_failure())?;
        let request = NodePairingApproveRequest::new(
            pairing_command_identity("approve", NativeNodePairingMode::Remote, now),
            invite_id,
        )
        .map_err(|_| invalid_node_argument("The pairing approval is invalid."))?;
        let NodePrivateResponse::PairingStatus(status) =
            self.execute_request(NodePrivateRequest::ApprovePairing(request))?
        else {
            return Err(invalid_response_failure());
        };
        pairing_status_output(&status)
    }

    // Reports reviewed local storage or applies one exact explicitly confirmed cleanup plan.
    fn execute_node_usage(
        &mut self,
        invocation: &CommandInvocation,
    ) -> Result<CommandOutput, CommandFailure> {
        let clean = invocation.boolean(ArgumentId::Clean).unwrap_or(false);
        let confirmed = invocation.boolean(ArgumentId::Yes).unwrap_or(false);
        let selected_values = invocation.text_list(ArgumentId::Category);
        if !clean && (confirmed || selected_values.is_some()) {
            return Err(invalid_node_argument(
                "Storage cleanup options require --clean.",
            ));
        }
        if clean && !confirmed {
            return Err(storage_confirmation_required_failure());
        }
        let NodePrivateResponse::StorageSnapshot(snapshot) =
            self.execute_request(NodePrivateRequest::ReadStorage)?
        else {
            return Err(invalid_response_failure());
        };
        if !clean {
            return node_storage_output(&snapshot);
        }

        let explicit_selection = selected_values.is_some();
        let categories = match selected_values {
            Some(values) => storage_categories(values)?,
            None => snapshot
                .candidates()
                .iter()
                .map(|candidate| candidate.category())
                .collect::<BTreeSet<_>>(),
        };
        if categories.is_empty() {
            return node_storage_output(&snapshot);
        }
        if explicit_selection
            && categories.iter().any(|category| {
                !snapshot
                    .candidates()
                    .iter()
                    .any(|candidate| candidate.category() == *category)
            })
        {
            return Err(invalid_node_argument(
                "The selected storage category has no reviewed inactive data.",
            ));
        }
        let operation_id = storage_cleanup_operation_id(&snapshot, &categories)?;
        let plan_digest = snapshot.plan_digest().clone();
        let request =
            NodeStorageCleanRequest::new(operation_id.clone(), plan_digest.clone(), categories)
                .map_err(|_| invalid_node_argument("The storage cleanup selection is invalid."))?;
        match self.execute_request(NodePrivateRequest::CleanStorage(request))? {
            NodePrivateResponse::StorageCleaned(receipt)
                if receipt.operation_id() == &operation_id
                    && receipt.plan_digest() == &plan_digest =>
            {
                storage_clean_output(&receipt)
            }
            _ => Err(invalid_response_failure()),
        }
    }

    // Applies one explicit main-owned child transition with its exact optimistic revision.
    fn execute_node_transition(
        &mut self,
        invocation: &CommandInvocation,
        transition: NodeTransition,
    ) -> Result<CommandOutput, CommandFailure> {
        if !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
            return Err(confirmation_required_failure());
        }
        let local = self.local_node()?;
        if local.role() == NodeRole::Child {
            if invocation.text(ArgumentId::Member).is_some() {
                return Err(invalid_node_argument(
                    "A child lifecycle command targets this child and does not accept a Node selector.",
                ));
            }
            let observed_at = self
                .clock
                .now()
                .map_err(|_| node_clock_unavailable_failure())?;
            return self
                .child_lifecycle
                .transition(&local, transition, observed_at)
                .map(|node| node_output(&node));
        }
        let selector = invocation
            .text(ArgumentId::Member)
            .ok_or_else(node_selection_required_failure)?;
        let NodePrivateResponse::Nodes(nodes) =
            self.execute_request(NodePrivateRequest::ReadNodes)?
        else {
            return Err(invalid_response_failure());
        };
        let selected = selected_node(nodes, selector)?;
        if selected.role() != NodeRole::Child
            || selected.identity().node_id() == local.identity().node_id()
        {
            return Err(invalid_node_argument(
                "Node lifecycle target must be one enrolled child.",
            ));
        }
        let node_id = selected.identity().node_id().clone();
        let NodePrivateResponse::NodeChanged(current) =
            self.execute_request(NodePrivateRequest::ReadNode {
                node_id: node_id.clone(),
            })?
        else {
            return Err(invalid_response_failure());
        };
        if current.value().identity().node_id() != &node_id {
            return Err(invalid_response_failure());
        }
        let now = self
            .clock
            .now()
            .map_err(|_| node_clock_unavailable_failure())?;
        let updated_at = node_transition_time(current.value(), now)?;
        let idempotency_key = node_transition_identity(transition, &node_id, current.revision());
        match self.execute_request(NodePrivateRequest::TransitionChild {
            idempotency_key,
            node_id,
            expected_revision: current.revision(),
            transition,
            updated_at,
        })? {
            NodePrivateResponse::NodeChanged(change) => Ok(node_output(change.value())),
            _ => Err(invalid_response_failure()),
        }
    }

    // Sends one request while converting all redacted client failures into CLI failures.
    fn execute_request(
        &mut self,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, CommandFailure> {
        self.client
            .try_borrow_mut()
            .map_err(|_| client_busy_failure())?
            .execute(request)
            .map_err(client_failure)
    }

    // Executes one public authentication leaf through the Node-owned private projection.
    fn execute_authentication_command(
        &mut self,
        command: AuthenticationCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        match command {
            AuthenticationCommand::ControllerAdd(invocation) => {
                let timeout_seconds = invocation
                    .integer(ArgumentId::Timeout)
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|value| (30..=180).contains(value))
                    .ok_or_else(|| {
                        invalid_authentication_argument(
                            "Controller enrollment timeout must be between 30 and 180 seconds.",
                        )
                    })?;
                let role = invocation
                    .text(ArgumentId::Role)
                    .ok_or_else(|| invalid_authentication_argument("Controller role is required."))
                    .and_then(|value| {
                        ControllerRole::parse(value).map_err(|_| {
                            invalid_authentication_argument("Controller role is invalid.")
                        })
                    })?;
                let mut commit = NativeControllerEnrollmentCommit {
                    client: Rc::clone(&self.client),
                };
                let controller = self.controller_enrollment.enroll(
                    Duration::from_secs(u64::from(timeout_seconds)),
                    role,
                    progress,
                    &mut commit,
                )?;
                Ok(controller_output(&controller).without_completion())
            }
            AuthenticationCommand::ControllerList(_) => {
                match self.execute_request(NodePrivateRequest::ReadControllers)? {
                    NodePrivateResponse::Controllers(controllers) => {
                        controllers_output(controllers)
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::ControllerRevoke(invocation) => {
                let selector = invocation
                    .text(ArgumentId::Controller)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        invalid_authentication_argument("Controller identity or name is required.")
                    })?
                    .to_string();
                match self.execute_request(NodePrivateRequest::RevokeController { selector })? {
                    NodePrivateResponse::Controller(controller) => {
                        Ok(controller_output(&controller))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::KeyCreate(invocation) => {
                let name = DisplayName::parse(required_text(invocation, ArgumentId::Name)?)
                    .map_err(|_| invalid_authentication_argument("API-key name is invalid"))?;
                let policy = create_policy(invocation)?;
                match self.execute_request(NodePrivateRequest::CreateApiKey { name, policy })? {
                    NodePrivateResponse::ApiKeyIssued(mut issued) => issued_key_output(&mut issued),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::KeyList(_) => {
                match self.execute_request(NodePrivateRequest::ReadApiKeys)? {
                    NodePrivateResponse::ApiKeys(keys) => api_keys_output(keys),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::KeyShow(invocation) => {
                let selector = required_text(invocation, ArgumentId::Key)?.to_string();
                match self.execute_request(NodePrivateRequest::ReadApiKey { selector })? {
                    NodePrivateResponse::ApiKey(key) => Ok(api_key_output(&key)),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::KeyUpdate(invocation) => {
                let selector = required_text(invocation, ArgumentId::Key)?.to_string();
                let update = policy_update(invocation)?;
                match self
                    .execute_request(NodePrivateRequest::UpdateApiKeyPolicy { selector, update })?
                {
                    NodePrivateResponse::ApiKey(key) => Ok(api_key_output(&key)),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::KeyRotate(invocation) => {
                let selector = required_text(invocation, ArgumentId::Key)?.to_string();
                match self.execute_request(NodePrivateRequest::RotateApiKey { selector })? {
                    NodePrivateResponse::ApiKeyIssued(mut issued) => issued_key_output(&mut issued),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuthenticationCommand::KeyRevoke(invocation) => {
                let selector = required_text(invocation, ArgumentId::Key)?.to_string();
                match self.execute_request(NodePrivateRequest::RevokeApiKey { selector })? {
                    NodePrivateResponse::ApiKey(key) => Ok(api_key_output(&key)),
                    _ => Err(invalid_response_failure()),
                }
            }
        }
    }

    // Executes every registry-owned model leaf represented by the existing ModelCoordinator.
    fn execute_model_command(
        &mut self,
        command: ModelCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        match command {
            ModelCommand::List(invocation) => {
                if invocation.boolean(ArgumentId::Installed).unwrap_or(false) {
                    if invocation.boolean(ArgumentId::Refresh).unwrap_or(false)
                        || invocation.boolean(ArgumentId::Versions).unwrap_or(false)
                        || invocation.boolean(ArgumentId::AllTargets).unwrap_or(false)
                        || invocation.argument(ArgumentId::Catalog).is_some()
                    {
                        return Err(invalid_model_argument(
                            "Installed-only listing cannot select catalog options.",
                        ));
                    }
                    let response = self.execute_request(NodePrivateRequest::ListModels)?;
                    let NodePrivateResponse::ModelServices(mut services) = response else {
                        return Err(invalid_response_failure());
                    };
                    if let Some(model) = invocation.text(ArgumentId::Model) {
                        services.retain(|service| service.logical_model().as_str() == model);
                    }
                    return model_services_output(services);
                }
                let logical_model = invocation
                    .text(ArgumentId::Model)
                    .map(LogicalModelName::parse)
                    .transpose()
                    .map_err(|_| invalid_model_argument("Model name is invalid."))?;
                let request = NodeCatalogListRequest::new(
                    invocation.text(ArgumentId::Catalog).map(str::to_string),
                    logical_model,
                    if invocation.boolean(ArgumentId::Versions).unwrap_or(false) {
                        NodeCatalogVersionSelection::All
                    } else {
                        NodeCatalogVersionSelection::Latest
                    },
                    if invocation.boolean(ArgumentId::AllTargets).unwrap_or(false) {
                        NodeCatalogTargetSelection::All
                    } else {
                        NodeCatalogTargetSelection::Compatible
                    },
                    if invocation.boolean(ArgumentId::Refresh).unwrap_or(false) {
                        NodeCatalogRefreshPolicy::Refresh
                    } else {
                        NodeCatalogRefreshPolicy::Cached
                    },
                )
                .map_err(|_| invalid_model_argument("Catalog query is invalid."))?;
                let response = self.execute_request(NodePrivateRequest::ReadCatalog(request))?;
                let NodePrivateResponse::Catalog(listing) = response else {
                    return Err(invalid_response_failure());
                };
                catalog_listing_output(&listing)
            }
            ModelCommand::Install(invocation) => {
                let logical_model = required_model(invocation)?;
                self.assert_install_catalog(invocation, &logical_model)?;
                let local = self.local_node()?;
                let selected = self.install_nodes(invocation, &local)?;
                let explicit_candidate = invocation
                    .text(ArgumentId::Runtime)
                    .map(RuntimeCandidateId::parse)
                    .transpose()
                    .map_err(|_| invalid_model_argument("Runtime candidate is invalid."))?;
                let service_id = model_service_id(local.identity().node_id(), &logical_model)?;
                let groups = selected
                    .iter()
                    .map(|node_id| {
                        NodeModelInstallGroup::new(
                            vec![node_id.clone()],
                            explicit_candidate.clone(),
                        )
                        .map_err(|_| invalid_model_argument("Model placement plan is invalid."))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let identity = model_command_identity(
                    "install",
                    &format!(
                        "{}:{}:{}:{}",
                        service_id.as_str(),
                        selected
                            .iter()
                            .map(NodeId::as_str)
                            .collect::<Vec<_>>()
                            .join(","),
                        explicit_candidate
                            .as_ref()
                            .map_or("automatic", RuntimeCandidateId::as_str),
                        invocation.text(ArgumentId::Catalog).unwrap_or("configured")
                    ),
                )?;
                match self.execute_request(NodePrivateRequest::InstallModel(
                    NodeModelInstallRequest::new(identity, service_id, logical_model, groups)
                        .map_err(|_| invalid_model_argument("Model installation is invalid."))?,
                ))? {
                    NodePrivateResponse::ModelChanged(summary) => {
                        Ok(model_command_output(&summary))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            ModelCommand::Remove(invocation) => {
                let logical_model = required_model(invocation)?;
                let local = self.local_node()?;
                let service_id = model_service_id(local.identity().node_id(), &logical_model)?;
                let selection = self.removal_selection(invocation)?;
                let selection_identity = selection.node_ids().map_or_else(
                    || "all".to_string(),
                    |node_ids| {
                        node_ids
                            .iter()
                            .map(NodeId::as_str)
                            .collect::<Vec<_>>()
                            .join(",")
                    },
                );
                let identity = model_command_identity(
                    "remove",
                    &format!("{}:{selection_identity}", service_id.as_str()),
                )?;
                match self.execute_request(NodePrivateRequest::RemoveModel(
                    NodeModelRemoveRequest::new(
                        identity,
                        service_id,
                        selection,
                        NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
                    ),
                ))? {
                    NodePrivateResponse::ModelChanged(summary) => {
                        Ok(model_command_output(&summary))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            ModelCommand::Pause(invocation) => {
                self.execute_model_service_mutation(invocation, NodeModelAction::Pause)
            }
            ModelCommand::Resume(invocation) => {
                self.execute_model_service_mutation(invocation, NodeModelAction::Resume)
            }
            ModelCommand::Restart(invocation) => {
                self.execute_model_service_mutation(invocation, NodeModelAction::Restart)
            }
            ModelCommand::Recover(invocation) => {
                self.execute_model_service_mutation(invocation, NodeModelAction::Recover)
            }
            ModelCommand::Rollback(invocation) => {
                let logical_model = required_model(invocation)?;
                let local = self.local_node()?;
                let service_id = model_service_id(local.identity().node_id(), &logical_model)?;
                let target_id = invocation
                    .text(ArgumentId::Target)
                    .map(TargetId::parse)
                    .transpose()
                    .map_err(|_| invalid_model_argument("Rollback target is invalid."))?;
                if invocation.boolean(ArgumentId::DryRun).unwrap_or(false) {
                    return match self.execute_request(NodePrivateRequest::PreviewRollbackModel {
                        service_id,
                        target_id,
                    })? {
                        NodePrivateResponse::ModelRollbackPreview(preview) => {
                            model_rollback_preview_output(&preview)
                        }
                        _ => Err(invalid_response_failure()),
                    };
                }
                if !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
                    return Err(confirmation_required_failure());
                }
                let identity = model_command_identity(
                    "rollback",
                    &format!(
                        "{}:{}",
                        service_id.as_str(),
                        target_id.as_ref().map_or("all", TargetId::as_str)
                    ),
                )?;
                match self.execute_request(NodePrivateRequest::RollbackModel {
                    identity,
                    service_id,
                    target_id,
                })? {
                    NodePrivateResponse::ModelChanged(summary) => {
                        Ok(model_command_output(&summary))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            ModelCommand::Logs(invocation) => self.execute_model_runtime_logs(invocation, progress),
        }
    }

    // Streams one bounded Placement-owned runtime log through the private Node boundary.
    fn execute_model_runtime_logs(
        &mut self,
        invocation: &CommandInvocation,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        let logical_model = required_model(invocation)?;
        let local = self.local_node()?;
        let service_id = model_service_id(local.identity().node_id(), &logical_model)?;
        let placement_group_id = invocation
            .text(ArgumentId::PlacementGroup)
            .map(PlacementGroupId::parse)
            .transpose()
            .map_err(|_| invalid_model_argument("Placement-group identity is invalid."))?;
        let maximum_lines = invocation
            .integer(ArgumentId::Tail)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1..=10_000).contains(value))
            .ok_or_else(|| {
                invalid_model_argument("Model log tail must be between 1 and 10000 lines.")
            })?;
        let follow = invocation.boolean(ArgumentId::Follow).unwrap_or(false);
        let wait = if follow {
            Duration::from_secs(1)
        } else {
            Duration::ZERO
        };
        let mut cursor = None;
        loop {
            if progress.is_cancelled() {
                return Err(model_logs_cancelled_failure());
            }
            let request = NodeModelRuntimeLogRequest::new(
                service_id.clone(),
                placement_group_id.clone(),
                cursor,
                maximum_lines,
                64 * 1024,
                wait,
            )
            .map_err(|_| invalid_model_argument("Model log request is invalid."))?;
            let NodePrivateResponse::ModelRuntimeLogs(batch) =
                self.execute_request(NodePrivateRequest::ReadModelRuntimeLogs(request))?
            else {
                return Err(invalid_response_failure());
            };
            if batch.service_id() != &service_id
                || placement_group_id
                    .as_ref()
                    .is_some_and(|identity| batch.placement().placement_group_id() != identity)
            {
                return Err(invalid_response_failure());
            }
            if !follow {
                return Ok(model_runtime_logs_output(&batch));
            }
            cursor = Some(batch.placement().cursor().clone());
            if !batch.placement().payload().is_empty() {
                progress.report(CommandProgressEvent::Output(
                    batch.placement().payload().to_vec(),
                ));
            }
        }
    }

    // Requires an explicit catalog assertion to match the configured signed provider and model.
    fn assert_install_catalog(
        &mut self,
        invocation: &CommandInvocation,
        logical_model: &LogicalModelName,
    ) -> Result<(), CommandFailure> {
        let Some(source) = invocation.text(ArgumentId::Catalog) else {
            return Ok(());
        };
        let request = NodeCatalogListRequest::new(
            Some(source.to_string()),
            Some(logical_model.clone()),
            NodeCatalogVersionSelection::Latest,
            NodeCatalogTargetSelection::Compatible,
            NodeCatalogRefreshPolicy::Cached,
        )
        .map_err(|_| invalid_model_argument("Catalog assertion is invalid."))?;
        let NodePrivateResponse::Catalog(listing) =
            self.execute_request(NodePrivateRequest::ReadCatalog(request))?
        else {
            return Err(invalid_response_failure());
        };
        if listing
            .entries()
            .iter()
            .all(|entry| entry.logical_model() != logical_model)
        {
            return Err(invalid_model_argument(
                "The signed catalog does not contain a compatible release for this model.",
            ));
        }
        Ok(())
    }

    // Requires an optional update source assertion to pass through the signed catalog owner.
    fn assert_update_catalog(
        &mut self,
        invocation: &CommandInvocation,
    ) -> Result<(), CommandFailure> {
        let Some(source) = invocation.text(ArgumentId::Catalog) else {
            return Ok(());
        };
        let request = NodeCatalogListRequest::new(
            Some(source.to_string()),
            None,
            NodeCatalogVersionSelection::Latest,
            NodeCatalogTargetSelection::Compatible,
            NodeCatalogRefreshPolicy::Cached,
        )
        .map_err(|_| invalid_update_argument("Catalog assertion is invalid."))?;
        match self.execute_request(NodePrivateRequest::ReadCatalog(request))? {
            NodePrivateResponse::Catalog(_) => Ok(()),
            _ => Err(invalid_response_failure()),
        }
    }

    // Resolves one exact installed service from an optional logical-model selector.
    fn update_model_service(
        &mut self,
        invocation: &CommandInvocation,
    ) -> Result<NodeModelServiceSummary, CommandFailure> {
        let requested = invocation
            .text(ArgumentId::Model)
            .map(LogicalModelName::parse)
            .transpose()
            .map_err(|_| invalid_update_argument("Model name is invalid."))?;
        let NodePrivateResponse::ModelServices(mut services) =
            self.execute_request(NodePrivateRequest::ListModels)?
        else {
            return Err(invalid_response_failure());
        };
        services.retain(|service| {
            service.desired_state() != ModelServiceDesiredState::Removed
                && requested
                    .as_ref()
                    .is_none_or(|model| service.logical_model() == model)
        });
        if services.len() != 1 {
            return Err(invalid_update_argument(
                "Model selector must match exactly one installed service.",
            ));
        }
        Ok(services.remove(0))
    }

    // Resolves an optional target through the configured signed catalog identity.
    fn update_model_candidate(
        &mut self,
        invocation: &CommandInvocation,
        service: &NodeModelServiceSummary,
    ) -> Result<Option<RuntimeCandidateId>, CommandFailure> {
        let target = invocation
            .text(ArgumentId::Target)
            .map(TargetId::parse)
            .transpose()
            .map_err(|_| invalid_update_argument("Runtime target is invalid."))?;
        if target.is_none() && invocation.text(ArgumentId::Catalog).is_none() {
            return Ok(None);
        }
        let request = NodeCatalogListRequest::new(
            invocation.text(ArgumentId::Catalog).map(str::to_string),
            Some(service.logical_model().clone()),
            NodeCatalogVersionSelection::Latest,
            if target.is_some() {
                NodeCatalogTargetSelection::All
            } else {
                NodeCatalogTargetSelection::Compatible
            },
            NodeCatalogRefreshPolicy::Cached,
        )
        .map_err(|_| invalid_update_argument("Catalog query is invalid."))?;
        let NodePrivateResponse::Catalog(listing) =
            self.execute_request(NodePrivateRequest::ReadCatalog(request))?
        else {
            return Err(invalid_response_failure());
        };
        let mut candidates: Vec<_> = listing
            .entries()
            .iter()
            .filter(|entry| {
                target
                    .as_ref()
                    .is_none_or(|value| entry.target_id() == value)
            })
            .map(|entry| entry.candidate_id().clone())
            .collect();
        candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        candidates.dedup();
        if target.is_some() && candidates.len() != 1 {
            return Err(invalid_update_argument(
                "Runtime target must resolve to one signed candidate.",
            ));
        }
        Ok((candidates.len() == 1).then(|| candidates.remove(0)))
    }

    // Reads one exact local Node snapshot for stable model-service identity derivation.
    fn local_node(&mut self) -> Result<Node, CommandFailure> {
        match self.execute_request(NodePrivateRequest::ReadLocalNode)? {
            NodePrivateResponse::LocalNode(node) => Ok(node),
            _ => Err(invalid_response_failure()),
        }
    }

    // Resolves explicit identities or unique active display names for one install plan.
    fn install_nodes(
        &mut self,
        invocation: &CommandInvocation,
        local: &Node,
    ) -> Result<Vec<NodeId>, CommandFailure> {
        let requested = invocation.text_list(ArgumentId::Node).unwrap_or_default();
        let all_nodes = invocation.boolean(ArgumentId::AllNodes).unwrap_or(false);
        if all_nodes && !requested.is_empty() {
            return Err(invalid_model_argument(
                "--node and --all-nodes cannot be combined.",
            ));
        }
        if !all_nodes && requested.is_empty() {
            return Ok(vec![local.identity().node_id().clone()]);
        }
        let NodePrivateResponse::Nodes(nodes) =
            self.execute_request(NodePrivateRequest::ReadNodes)?
        else {
            return Err(invalid_response_failure());
        };
        let active: Vec<_> = nodes
            .into_iter()
            .filter(|node| node.state() == NodeState::Active)
            .collect();
        if all_nodes {
            let mut identities: Vec<_> = active
                .iter()
                .map(|node| node.identity().node_id().clone())
                .collect();
            identities.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            if identities.is_empty() {
                return Err(invalid_model_argument("No active nodes are available."));
            }
            return Ok(identities);
        }
        let mut selected = Vec::new();
        for selector in requested {
            let matches: Vec<_> = active
                .iter()
                .filter(|node| {
                    node.identity().node_id().as_str() == selector
                        || node.display_name().as_str() == selector
                })
                .collect();
            if matches.len() != 1 {
                return Err(invalid_model_argument(
                    "Node selector must match one active identity or unique name.",
                ));
            }
            let identity = matches[0].identity().node_id().clone();
            if !selected.contains(&identity) {
                selected.push(identity);
            }
        }
        Ok(selected)
    }

    // Resolves complete removal or exact node identities without requiring nodes to be online.
    fn removal_selection(
        &mut self,
        invocation: &CommandInvocation,
    ) -> Result<NodeModelRemovalSelection, CommandFailure> {
        let requested = invocation.text_list(ArgumentId::Node).unwrap_or_default();
        let all_nodes = invocation.boolean(ArgumentId::AllNodes).unwrap_or(false);
        if all_nodes && !requested.is_empty() {
            return Err(invalid_model_argument(
                "--node and --all-nodes cannot be combined.",
            ));
        }
        if all_nodes || requested.is_empty() {
            return Ok(NodeModelRemovalSelection::All);
        }
        let NodePrivateResponse::Nodes(nodes) =
            self.execute_request(NodePrivateRequest::ReadNodes)?
        else {
            return Err(invalid_response_failure());
        };
        let mut selected = Vec::new();
        for selector in requested {
            let node = selected_node(nodes.clone(), selector)?;
            if !selected.contains(node.identity().node_id()) {
                selected.push(node.identity().node_id().clone());
            }
        }
        NodeModelRemovalSelection::nodes(selected)
            .map_err(|_| invalid_model_argument("Model removal node selection is invalid."))
    }

    // Executes one exact service lifecycle using a deterministic replay identity.
    fn execute_model_service_mutation(
        &mut self,
        invocation: &CommandInvocation,
        action: NodeModelAction,
    ) -> Result<CommandOutput, CommandFailure> {
        let logical_model = required_model(invocation)?;
        let local = self.local_node()?;
        let service_id = model_service_id(local.identity().node_id(), &logical_model)?;
        let identity = model_command_identity(action.as_str(), service_id.as_str())?;
        let request = match action {
            NodeModelAction::Pause => NodePrivateRequest::PauseModel {
                identity,
                service_id,
            },
            NodeModelAction::Resume => NodePrivateRequest::ResumeModel {
                identity,
                service_id,
            },
            NodeModelAction::Restart => NodePrivateRequest::RestartModel {
                identity,
                service_id,
            },
            NodeModelAction::Recover => NodePrivateRequest::RecoverModel {
                identity,
                service_id,
            },
            NodeModelAction::Install
            | NodeModelAction::Update
            | NodeModelAction::Remove
            | NodeModelAction::Rollback => {
                return Err(invalid_model_argument("Model lifecycle action is invalid."));
            }
        };
        match self.execute_request(request)? {
            NodePrivateResponse::ModelChanged(summary) => Ok(model_command_output(&summary)),
            _ => Err(invalid_response_failure()),
        }
    }

    // Executes only benchmark leaves represented completely by the current private contract.
    fn execute_benchmark_command(
        &mut self,
        command: BenchmarkCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        match command {
            BenchmarkCommand::List(invocation) => {
                let selection = benchmark_selection(invocation)?;
                match self.execute_request(NodePrivateRequest::PreviewBenchmark { selection })? {
                    NodePrivateResponse::BenchmarkPlan(plan) => benchmark_plan_output(&plan),
                    _ => Err(invalid_response_failure()),
                }
            }
            BenchmarkCommand::Run(invocation) => {
                let selection = benchmark_selection(invocation)?;
                let started_at = self
                    .clock
                    .now()
                    .map_err(|_| node_clock_unavailable_failure())?;
                let idempotency_key = benchmark_start_identity(&selection, started_at);
                match self.execute_request(NodePrivateRequest::StartBenchmark {
                    idempotency_key,
                    selection,
                })? {
                    NodePrivateResponse::BenchmarkChanged(snapshot)
                        if !snapshot.is_verification() =>
                    {
                        Ok(benchmark_snapshot_output(&snapshot))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            BenchmarkCommand::Status(_) => {
                match self.execute_request(NodePrivateRequest::ReadActiveBenchmark)? {
                    NodePrivateResponse::BenchmarkRecord(Some(snapshot))
                        if snapshot.is_verification() =>
                    {
                        Ok(benchmark_status_output(None))
                    }
                    NodePrivateResponse::BenchmarkRecord(snapshot) => {
                        Ok(benchmark_status_output(snapshot.as_ref()))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            BenchmarkCommand::Stop(_) => {
                let active = match self.execute_request(NodePrivateRequest::ReadActiveBenchmark)? {
                    NodePrivateResponse::BenchmarkRecord(Some(snapshot))
                        if !snapshot.is_verification() =>
                    {
                        snapshot
                    }
                    NodePrivateResponse::BenchmarkRecord(None) => {
                        return Err(no_active_benchmark_failure());
                    }
                    NodePrivateResponse::BenchmarkRecord(Some(_)) => {
                        return Err(no_active_benchmark_failure());
                    }
                    _ => return Err(invalid_response_failure()),
                };
                match self.execute_request(NodePrivateRequest::StopBenchmark {
                    job_id: active.job_id().clone(),
                })? {
                    NodePrivateResponse::BenchmarkChanged(snapshot)
                        if !snapshot.is_verification() =>
                    {
                        Ok(benchmark_snapshot_output(&snapshot))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            BenchmarkCommand::VerificationStatus(_) => {
                match self.execute_request(NodePrivateRequest::ReadActiveBenchmark)? {
                    NodePrivateResponse::BenchmarkRecord(Some(snapshot))
                        if snapshot.is_verification() =>
                    {
                        Ok(benchmark_snapshot_output(&snapshot))
                    }
                    NodePrivateResponse::BenchmarkRecord(_) => {
                        Ok(verification_benchmark_inactive_output())
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            BenchmarkCommand::VerificationStop(_) => {
                let active = match self.execute_request(NodePrivateRequest::ReadActiveBenchmark)? {
                    NodePrivateResponse::BenchmarkRecord(Some(snapshot))
                        if snapshot.is_verification() =>
                    {
                        snapshot
                    }
                    NodePrivateResponse::BenchmarkRecord(_) => {
                        return Err(no_active_verification_benchmark_failure());
                    }
                    _ => return Err(invalid_response_failure()),
                };
                match self.execute_request(NodePrivateRequest::StopBenchmark {
                    job_id: active.job_id().clone(),
                })? {
                    NodePrivateResponse::BenchmarkChanged(snapshot)
                        if snapshot.is_verification() =>
                    {
                        Ok(benchmark_snapshot_output(&snapshot))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            BenchmarkCommand::Clean(invocation) => self.execute_benchmark_clean(invocation),
            BenchmarkCommand::VerificationRun(invocation) => {
                let pull_request_url = invocation
                    .text(ArgumentId::PullRequest)
                    .ok_or_else(|| invalid_benchmark_argument("Pull-request URL is required."))?;
                let candidate = invocation
                    .text(ArgumentId::Candidate)
                    .map(RuntimeCandidateId::parse)
                    .transpose()
                    .map_err(|_| invalid_benchmark_argument("Runtime candidate is invalid."))?;
                progress.report(CommandProgressEvent::Step {
                    completed: 1,
                    total: 2,
                    message: "Resolving trusted verifier authority".to_string(),
                });
                let idempotency_key =
                    benchmark_verification_start_identity(pull_request_url, candidate.as_ref());
                let response =
                    self.execute_request(NodePrivateRequest::StartBenchmarkVerification {
                        idempotency_key,
                        pull_request_url: pull_request_url.to_string(),
                        candidate,
                    })?;
                let NodePrivateResponse::BenchmarkChanged(snapshot) = response else {
                    return Err(invalid_response_failure());
                };
                if !snapshot.is_verification() {
                    return Err(invalid_response_failure());
                }
                progress.report(CommandProgressEvent::Step {
                    completed: 2,
                    total: 2,
                    message: if invocation.boolean(ArgumentId::Detach).unwrap_or(false) {
                        "Verification job started in the background".to_string()
                    } else {
                        "Verification job started".to_string()
                    },
                });
                Ok(benchmark_snapshot_output(&snapshot))
            }
        }
    }

    // Removes only reviewed inactive benchmark evidence through the shared storage contract.
    fn execute_benchmark_clean(
        &mut self,
        invocation: &CommandInvocation,
    ) -> Result<CommandOutput, CommandFailure> {
        if !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
            return Err(benchmark_confirmation_required_failure());
        }
        let NodePrivateResponse::StorageSnapshot(snapshot) =
            self.execute_request(NodePrivateRequest::ReadStorage)?
        else {
            return Err(invalid_response_failure());
        };
        if !snapshot
            .candidates()
            .iter()
            .any(|candidate| candidate.category() == NodeStorageCategory::Benchmarks)
        {
            return Ok(benchmark_clean_inactive_output());
        }
        let categories = BTreeSet::from([NodeStorageCategory::Benchmarks]);
        let operation_id = storage_cleanup_operation_id(&snapshot, &categories)?;
        let plan_digest = snapshot.plan_digest().clone();
        let request =
            NodeStorageCleanRequest::new(operation_id.clone(), plan_digest.clone(), categories)
                .map_err(|_| {
                    invalid_benchmark_argument("The benchmark cleanup plan is invalid.")
                })?;
        match self.execute_request(NodePrivateRequest::CleanStorage(request))? {
            NodePrivateResponse::StorageCleaned(receipt)
                if receipt.operation_id() == &operation_id
                    && receipt.plan_digest() == &plan_digest =>
            {
                storage_clean_output(&receipt)
            }
            _ => Err(invalid_response_failure()),
        }
    }
}

// Returns one required normalized text argument from a declared command leaf.
fn required_text(
    invocation: &CommandInvocation,
    argument: ArgumentId,
) -> Result<&str, CommandFailure> {
    invocation
        .text(argument)
        .ok_or_else(|| invalid_authentication_argument("required API-key argument is absent"))
}

// Resolves one complete creation policy from explicit CLI values and documented defaults.
fn create_policy(invocation: &CommandInvocation) -> Result<ApiKeyPolicy, CommandFailure> {
    let models = invocation.text_list(ArgumentId::Model).unwrap_or_default();
    let model_scope = if models.is_empty() {
        ApiKeyModelScope::all()
    } else {
        ApiKeyModelScope::selected(parse_logical_models(models)?)
            .map_err(|_| invalid_authentication_argument("API-key model scope is invalid"))?
    };
    Ok(ApiKeyPolicy::new(
        model_scope,
        optional_timestamp(invocation, ArgumentId::ExpiresAt)?,
        ApiKeyLimits::new(
            optional_nonzero_u32(invocation, ArgumentId::RequestsPerMinute)?,
            optional_nonzero_u64(invocation, ArgumentId::TokensPerMinute)?,
            optional_nonzero_u32(invocation, ArgumentId::Concurrency)?,
            optional_nonzero_u64(invocation, ArgumentId::MaxContext)?,
        ),
        optional_technical_name(invocation, ArgumentId::Tenant)?,
        optional_technical_name(invocation, ArgumentId::Application)?,
    ))
}

// Resolves one partial update without resetting omitted policy fields.
fn policy_update(invocation: &CommandInvocation) -> Result<NodeApiKeyPolicyUpdate, CommandFailure> {
    Ok(NodeApiKeyPolicyUpdate::new(
        invocation
            .text_list(ArgumentId::Model)
            .map(parse_logical_models)
            .transpose()?,
        optional_timestamp(invocation, ArgumentId::ExpiresAt)?,
        optional_nonzero_u32(invocation, ArgumentId::RequestsPerMinute)?,
        optional_nonzero_u64(invocation, ArgumentId::TokensPerMinute)?,
        optional_nonzero_u32(invocation, ArgumentId::Concurrency)?,
        optional_nonzero_u64(invocation, ArgumentId::MaxContext)?,
        optional_technical_name(invocation, ArgumentId::Tenant)?,
        optional_technical_name(invocation, ArgumentId::Application)?,
    ))
}

// Parses one ordered logical-model list without accepting invalid public names.
fn parse_logical_models(values: &[String]) -> Result<Vec<LogicalModelName>, CommandFailure> {
    values
        .iter()
        .map(|value| {
            LogicalModelName::parse(value)
                .map_err(|_| invalid_authentication_argument("API-key model scope is invalid"))
        })
        .collect()
}

// Parses one optional positive u32 policy limit.
fn optional_nonzero_u32(
    invocation: &CommandInvocation,
    argument: ArgumentId,
) -> Result<Option<NonZeroU32>, CommandFailure> {
    invocation
        .integer(argument)
        .map(|value| {
            u32::try_from(value)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| invalid_authentication_argument("API-key limit must be positive"))
        })
        .transpose()
}

// Parses one optional positive u64 policy limit.
fn optional_nonzero_u64(
    invocation: &CommandInvocation,
    argument: ArgumentId,
) -> Result<Option<NonZeroU64>, CommandFailure> {
    invocation
        .integer(argument)
        .map(|value| {
            u64::try_from(value)
                .ok()
                .and_then(NonZeroU64::new)
                .ok_or_else(|| invalid_authentication_argument("API-key limit must be positive"))
        })
        .transpose()
}

// Parses one optional nonnegative policy timestamp.
fn optional_timestamp(
    invocation: &CommandInvocation,
    argument: ArgumentId,
) -> Result<Option<UnixMilliseconds>, CommandFailure> {
    invocation
        .integer(argument)
        .map(|value| {
            u64::try_from(value)
                .map(UnixMilliseconds::new)
                .map_err(|_| invalid_authentication_argument("API-key expiration is invalid"))
        })
        .transpose()
}

// Parses one optional canonical tenant or application label.
fn optional_technical_name(
    invocation: &CommandInvocation,
    argument: ArgumentId,
) -> Result<Option<TechnicalName>, CommandFailure> {
    invocation
        .text(argument)
        .map(|value| {
            TechnicalName::parse(value)
                .map_err(|_| invalid_authentication_argument("API-key policy label is invalid"))
        })
        .transpose()
}

// Creates one stable invalid-argument failure without echoing rejected values.
fn invalid_authentication_argument(message: &'static str) -> CommandFailure {
    failure("authentication.invalid_argument", message)
}

// Returns a mutation timestamp that cannot move the selected Node backwards.
fn node_transition_time(
    node: &Node,
    now: UnixMilliseconds,
) -> Result<UnixMilliseconds, CommandFailure> {
    let minimum = node
        .timestamps()
        .updated_at()
        .value()
        .checked_add(1)
        .ok_or_else(node_clock_unavailable_failure)?;
    Ok(UnixMilliseconds::new(now.value().max(minimum)))
}

// Derives one bounded replay identity from the complete optimistic transition binding.
fn node_transition_identity(
    transition: NodeTransition,
    node_id: &NodeId,
    expected_revision: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_node_transition_v1\0");
    hasher.update(node_transition_name(transition).as_bytes());
    hasher.update(b"\0");
    hasher.update(node_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(expected_revision.to_be_bytes());
    format!("li_cli_node_{}", digest_hex(&hasher.finalize()))
}

// Returns one complete pairing deadline bounded by PairingManager invitation policy.
fn pairing_timeout(invocation: &CommandInvocation) -> Result<Duration, CommandFailure> {
    let seconds = invocation
        .integer(ArgumentId::Timeout)
        .ok_or_else(|| invalid_node_argument("The pairing timeout is required."))?;
    if !(30..=600).contains(&seconds) {
        return Err(invalid_node_argument(
            "Pairing timeout must be between 30 and 600 seconds.",
        ));
    }
    Ok(Duration::from_secs(u64::try_from(seconds).map_err(
        |_| invalid_node_argument("The pairing timeout is invalid."),
    )?))
}

// Parses one closed user-facing pairing mode without accepting proof identities.
fn pairing_mode_selection(
    invocation: &CommandInvocation,
) -> Result<NativeNodePairingMode, CommandFailure> {
    match invocation.text(ArgumentId::Mode) {
        Some("lan") => Ok(NativeNodePairingMode::Lan),
        Some("remote") => Ok(NativeNodePairingMode::Remote),
        Some("connectx") => Ok(NativeNodePairingMode::ConnectX),
        _ => Err(invalid_node_argument("The pairing mode is invalid.")),
    }
}

// Resolves discovery or one exact remote invitation endpoint for child activation.
fn pairing_join_source(
    invocation: &CommandInvocation,
    mode: NativeNodePairingMode,
) -> Result<NativeNodePairingJoinSource, CommandFailure> {
    if invocation.text(ArgumentId::Interface).is_some() {
        return Err(invalid_node_argument(
            "A joining Node does not accept a main-side direct interface.",
        ));
    }
    match mode {
        NativeNodePairingMode::Remote => {
            let invite_id = PairingInviteId::parse(
                invocation.text(ArgumentId::Invitation).ok_or_else(|| {
                    invalid_node_argument("Remote pairing requires --invitation.")
                })?,
            )
            .map_err(|_| invalid_node_argument("The pairing invitation identity is invalid."))?;
            let address = NodeAddress::parse(
                invocation
                    .text(ArgumentId::Address)
                    .ok_or_else(|| invalid_node_argument("Remote pairing requires --address."))?,
            )
            .map_err(|_| invalid_node_argument("The pairing address is invalid."))?;
            let certificate_sha256 =
                Sha256Digest::parse(invocation.text(ArgumentId::CertificateSha256).ok_or_else(
                    || invalid_node_argument("Remote pairing requires --certificate-sha256."),
                )?)
                .map_err(|_| {
                    invalid_node_argument("The pairing certificate identity is invalid.")
                })?;
            Ok(NativeNodePairingJoinSource::Remote {
                invite_id,
                endpoint: NativeNodePairingEndpoint::new(
                    address,
                    NATIVE_NODE_PAIRING_PORT,
                    certificate_sha256,
                )?,
            })
        }
        NativeNodePairingMode::Lan | NativeNodePairingMode::ConnectX => {
            if invocation.text(ArgumentId::Invitation).is_some()
                || invocation.text(ArgumentId::Address).is_some()
                || invocation.text(ArgumentId::CertificateSha256).is_some()
            {
                return Err(invalid_node_argument(
                    "LAN and ConnectX joins derive the invitation endpoint from trusted discovery.",
                ));
            }
            Ok(NativeNodePairingJoinSource::Discovery)
        }
    }
}

// Rejects a direct-interface option outside ConnectX invitation creation.
fn require_absent_pairing_interface(invocation: &CommandInvocation) -> Result<(), CommandFailure> {
    if invocation.text(ArgumentId::Interface).is_some() {
        return Err(invalid_node_argument(
            "--interface is available only for ConnectX pairing.",
        ));
    }
    Ok(())
}

// Returns one deterministic replay identity without setup codes or certificate material.
fn pairing_command_identity(
    operation: &str,
    mode: NativeNodePairingMode,
    now: UnixMilliseconds,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"letsinfer-node-pairing-command-v1\0");
    digest.update(operation.as_bytes());
    digest.update([match mode {
        NativeNodePairingMode::Lan => 1,
        NativeNodePairingMode::Remote => 2,
        NativeNodePairingMode::ConnectX => 3,
    }]);
    digest.update(now.value().to_be_bytes());
    format!("pairing:{}", digest_hex(&digest.finalize()))
}

// Returns the stable action name used only inside one node transition replay identity.
const fn node_transition_name(transition: NodeTransition) -> &'static str {
    match transition {
        NodeTransition::Activate => "activate",
        NodeTransition::Pause => "pause",
        NodeTransition::Resume => "resume",
        NodeTransition::MarkOffline => "mark_offline",
        NodeTransition::Remove => "remove",
    }
}

// Creates one stable invalid-node-argument failure without copying a rejected selector.
fn invalid_node_argument(message: &'static str) -> CommandFailure {
    failure("node.invalid_argument", message)
}

// Requires non-interactive native mutations to receive an explicit confirmation flag.
fn confirmation_required_failure() -> CommandFailure {
    failure(
        "cli.confirmation_required",
        "Pass --yes to confirm this node lifecycle change.",
    )
}

// Requires explicit acknowledgement before the CLI applies a reviewed storage cleanup plan.
fn storage_confirmation_required_failure() -> CommandFailure {
    failure(
        "cli.confirmation_required",
        "Pass --yes to confirm storage cleanup.",
    )
}

// Requires an explicit Node selector until a native interactive selector is composed.
fn node_selection_required_failure() -> CommandFailure {
    failure(
        "node.selection_required",
        "An explicit child node identity or unique name is required.",
    )
}

// Returns one fixed wall-clock failure without exposing a platform value.
fn node_clock_unavailable_failure() -> CommandFailure {
    failure(
        "cli.clock_unavailable",
        "The native command clock is unavailable.",
    )
}

impl<Exchange, Identity> CoreCommandCapabilities for NativeNodeCliCapabilities<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort,
    Identity: NodeRequestIdentitySource,
{
    type Output = CommandOutput;

    // Routes truthful host reads and rejects service mutations without typed native authorities.
    fn execute_host(
        &mut self,
        command: HostCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.execute_host_command(command, progress)
    }

    // Routes the two provable Node reads and rejects every unrepresented lifecycle explicitly.
    fn execute_node(
        &mut self,
        command: NodeCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.execute_node_command(command, progress)
    }

    // Routes every ModelCoordinator-owned model action through the typed private contract.
    fn execute_model(
        &mut self,
        command: ModelCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.execute_model_command(command, progress)
    }

    // Routes the active benchmark status and stop leaves through the typed private contract.
    fn execute_benchmark(
        &mut self,
        command: BenchmarkCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.execute_benchmark_command(command, progress)
    }

    // Routes inference-key actions through AuthenticationManager's private Node projection.
    fn execute_authentication(
        &mut self,
        command: AuthenticationCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.execute_authentication_command(command, progress)
    }

    // Routes every public-exposure action through the Gateway-owned local Node projection.
    fn execute_exposure(
        &mut self,
        command: ExposureCommand<'_>,
        _progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        let request = match command {
            ExposureCommand::Status(_) => NodePrivateRequest::ReadExposure,
            ExposureCommand::Enable(_) => NodePrivateRequest::EnableExposure,
            ExposureCommand::Disable(_) => NodePrivateRequest::DisableExposure,
        };
        match self.execute_request(request)? {
            NodePrivateResponse::Exposure(status) => Ok(exposure_output(&status)),
            _ => Err(invalid_response_failure()),
        }
    }

    // Routes bounded audit reads and export through the Node-owned AuditManager projection.
    fn execute_audit(
        &mut self,
        command: AuditCommand<'_>,
        _progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        match command {
            AuditCommand::List(invocation) => {
                let limit = audit_list_limit(invocation)?;
                match self.execute_request(NodePrivateRequest::ReadAuditEvents { limit })? {
                    NodePrivateResponse::AuditEvents(events) => audit_events_output(events),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuditCommand::Show(invocation) => {
                let event_id =
                    AuditEventId::parse(required_text(invocation, ArgumentId::Event)?)
                        .map_err(|_| invalid_audit_argument("Audit event identity is invalid."))?;
                match self.execute_request(NodePrivateRequest::ReadAuditEvent { event_id })? {
                    NodePrivateResponse::AuditEvent(event) => Ok(audit_event_output(&event)),
                    _ => Err(invalid_response_failure()),
                }
            }
            AuditCommand::Verify(_) => {
                match self.execute_request(NodePrivateRequest::VerifyAudit)? {
                    NodePrivateResponse::AuditVerification(verification) => {
                        Ok(audit_verification_output(&verification))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            AuditCommand::Export(invocation) => {
                let NodePrivateResponse::AuditExport(export) =
                    self.execute_request(NodePrivateRequest::ExportAudit)?
                else {
                    return Err(invalid_response_failure());
                };
                let document = std::str::from_utf8(export.document())
                    .map_err(|_| invalid_response_failure())?;
                match invocation.path(ArgumentId::Output) {
                    Some(path) => {
                        self.audit_export_file
                            .write(path, export.document())
                            .map_err(|_| audit_export_file_failure())?;
                        Ok(audit_export_file_output(path, export.events()))
                    }
                    None => Ok(CommandOutput::new(
                        CommandPresentation::new(vec![DisplayBlock::Raw(document.to_string())]),
                        None,
                    )
                    .without_completion()),
                }
            }
        }
    }

    // Routes signed Core and model updates through their manager-backed private projections.
    fn execute_update(
        &mut self,
        command: UpdateCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        match command {
            UpdateCommand::Check(invocation) => {
                self.assert_update_catalog(invocation)?;
                match self.execute_request(NodePrivateRequest::CheckCoreUpdate {
                    requested_version: None,
                })? {
                    NodePrivateResponse::CoreUpdateCheck(check) => {
                        Ok(core_update_check_output(&check))
                    }
                    _ => Err(invalid_response_failure()),
                }
            }
            UpdateCommand::Core(invocation) => {
                if !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
                    return Err(update_confirmation_required_failure());
                }
                let requested_version = invocation
                    .text(ArgumentId::Version)
                    .map(CoreVersion::parse)
                    .transpose()
                    .map_err(|_| invalid_update_argument("Core version is invalid."))?;
                progress.report(CommandProgressEvent::Step {
                    completed: 1,
                    total: 3,
                    message: "Resolved signed Core release".to_string(),
                });
                let NodePrivateResponse::CoreUpdateCheck(check) =
                    self.execute_request(NodePrivateRequest::CheckCoreUpdate {
                        requested_version: requested_version.clone(),
                    })?
                else {
                    return Err(invalid_response_failure());
                };
                progress.report(CommandProgressEvent::Step {
                    completed: 2,
                    total: 3,
                    message: "Verified signed Core identity".to_string(),
                });
                let idempotency_key = format!(
                    "li_cli_core_update:{}:{}",
                    check.available().version().as_str(),
                    check.available().source_identity().as_str()
                );
                let NodePrivateResponse::CoreUpdated(summary) =
                    self.execute_request(NodePrivateRequest::UpdateCore {
                        idempotency_key,
                        requested_version,
                    })?
                else {
                    return Err(invalid_response_failure());
                };
                progress.report(CommandProgressEvent::Step {
                    completed: 3,
                    total: 3,
                    message: "Verified Core service cutover".to_string(),
                });
                Ok(core_update_output(&summary))
            }
            UpdateCommand::Model(invocation) => {
                let dry_run = invocation.boolean(ArgumentId::DryRun).unwrap_or(false);
                if !dry_run && !invocation.boolean(ArgumentId::Yes).unwrap_or(false) {
                    return Err(update_confirmation_required_failure());
                }
                let service = self.update_model_service(invocation)?;
                let explicit_candidate = self.update_model_candidate(invocation, &service)?;
                let identity = model_command_identity(
                    "update",
                    &format!(
                        "{}:{}",
                        service.service_id().as_str(),
                        explicit_candidate
                            .as_ref()
                            .map_or("automatic", RuntimeCandidateId::as_str)
                    ),
                )?;
                let request = NodeModelUpdateRequest::new(
                    identity,
                    service.service_id().clone(),
                    explicit_candidate,
                    dry_run,
                );
                match self.execute_request(NodePrivateRequest::UpdateModel(request))? {
                    NodePrivateResponse::ModelUpdated(summary) => Ok(model_update_output(&summary)),
                    _ => Err(invalid_response_failure()),
                }
            }
        }
    }
}

// Parses one explicit audit-list bound without narrowing or wrapping signed input.
fn audit_list_limit(invocation: &CommandInvocation) -> Result<usize, CommandFailure> {
    let limit = invocation
        .integer(ArgumentId::Limit)
        .ok_or_else(|| invalid_audit_argument("Audit list limit is required."))?;
    usize::try_from(limit)
        .ok()
        .filter(|value| (1..=10_000).contains(value))
        .ok_or_else(|| invalid_audit_argument("Audit list limit must be between 1 and 10000."))
}

// Presents the exact local host from the single typed inventory read.
fn host_status_output(inventory: NodeHostInventory) -> Result<CommandOutput, CommandFailure> {
    let local = inventory
        .local_host()
        .ok_or_else(invalid_response_failure)?;
    let local_hardware = local.hardware().available();
    let (processor, logical_cpus, memory, accelerators, observed_at) = local_hardware.map_or(
        (
            "Unavailable".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
        ),
        |observation| {
            (
                observation.processor().model().as_str().to_string(),
                observation.processor().logical_cpu_count().to_string(),
                observation.memory_bytes().value().to_string(),
                observation.accelerators().len().to_string(),
                observation.observed_at().value().to_string(),
            )
        },
    );
    let presentation = CommandPresentation::new(vec![DisplayBlock::Records(vec![
        DisplayRecord::new(
            "Node",
            local.node().display_name().as_str(),
            None,
            DisplaySemantic::Information,
        ),
        DisplayRecord::new(
            "Role",
            node_role_name(local.node().role()),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "State",
            node_state_name(local.node().state()),
            None,
            node_state_semantic(local.node().state()),
        ),
        DisplayRecord::new(
            "Processor",
            processor,
            Some(format!("{logical_cpus} logical CPUs")),
            if local_hardware.is_some() {
                DisplaySemantic::Information
            } else {
                DisplaySemantic::Warning
            },
        ),
        DisplayRecord::new(
            "Memory",
            memory,
            Some("bytes".to_string()),
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new("Accelerators", accelerators, None, DisplaySemantic::Muted),
        DisplayRecord::new(
            "Placement groups",
            projection_count(local.placement_groups()),
            None,
            projection_semantic(local.placement_groups()),
        ),
        DisplayRecord::new(
            "Models",
            projection_count(inventory.model_services()),
            None,
            projection_semantic(inventory.model_services()),
        ),
        DisplayRecord::new(
            "Gateway",
            service_projection_name(local.gateway()),
            None,
            service_projection_semantic(local.gateway()),
        ),
        DisplayRecord::new(
            "Watchdog",
            service_projection_name(local.watchdog()),
            None,
            service_projection_semantic(local.watchdog()),
        ),
        DisplayRecord::new(
            "Protection",
            protection_projection_name(local.protection()),
            None,
            protection_projection_semantic(local.protection()),
        ),
        DisplayRecord::new(
            "Observed",
            observed_at,
            Some("Unix milliseconds".to_string()),
            DisplaySemantic::Muted,
        ),
    ])]);
    Ok(CommandOutput::new(
        presentation,
        Some(host_inventory_machine_value(&inventory)),
    ))
}

// Presents one deterministic node topology from manager-filtered groups and verified links.
fn host_topology_output(inventory: NodeHostInventory) -> Result<CommandOutput, CommandFailure> {
    let rows = inventory
        .hosts()
        .iter()
        .map(|host| {
            let hardware = host.hardware().available();
            vec![
                host.node().display_name().as_str().to_string(),
                node_role_name(host.node().role()).to_string(),
                node_state_name(host.node().state()).to_string(),
                hardware
                    .map_or("—", |value| value.processor().model().as_str())
                    .to_string(),
                projection_count(host.placement_groups()),
                projection_count(host.verified_links()),
                service_projection_name(host.gateway()),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "NODE".to_string(),
            "ROLE".to_string(),
            "STATE".to_string(),
            "PROCESSOR".to_string(),
            "GROUPS".to_string(),
            "LINKS".to_string(),
            "GATEWAY".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(host_inventory_machine_value(&inventory)),
    ))
}

// Audits operational readiness through explicit section availability and service states.
fn host_doctor_output(
    inventory: NodeHostInventory,
    require_stable: bool,
) -> Result<CommandOutput, CommandFailure> {
    let local = inventory
        .local_host()
        .ok_or_else(invalid_response_failure)?;
    let node_active = local.node().state() == NodeState::Active;
    let hardware_observed = local.hardware().available().is_some();
    let placements_observed = local.placement_groups().available().is_some();
    let gateway_ready = local
        .gateway()
        .available()
        .is_some_and(|summary| summary.state() == NodeHostServiceState::Ready);
    let protection_ready = match local.protection() {
        NodeHostProjectionValue::Available(summary) => {
            summary.state() == NodeHostProtectionState::Ready
        }
        NodeHostProjectionValue::NotApplicable => true,
        NodeHostProjectionValue::Unavailable => false,
    };
    let watchdog_ready = match local.watchdog() {
        NodeHostProjectionValue::Available(summary) => {
            summary.state() == NodeHostServiceState::Ready
        }
        NodeHostProjectionValue::NotApplicable => true,
        NodeHostProjectionValue::Unavailable => false,
    };
    let publication_ready = inventory
        .model_services()
        .available()
        .is_some_and(|services| {
            !services.is_empty()
                && services.iter().all(|service| {
                    service.desired_state() != ModelServiceDesiredState::Removed
                        && !service.runtime_installation_ids().is_empty()
                        && service.runtime_installation_ids().len()
                            == service.evidence_labels().len()
                        && service
                            .evidence_labels()
                            .iter()
                            .all(|label| *label == EvidenceLabel::Qualified)
                })
        });
    let checks = vec![
        (
            "node_active",
            node_active,
            true,
            if node_active {
                "Local Node is active"
            } else {
                "Local Node is not active"
            },
        ),
        (
            "hardware_observed",
            hardware_observed,
            true,
            if hardware_observed {
                "Current hardware facts are available"
            } else {
                "Current hardware facts are unavailable"
            },
        ),
        (
            "placements_observed",
            placements_observed,
            true,
            if placements_observed {
                "Placement groups are available"
            } else {
                "Placement groups are unavailable"
            },
        ),
        (
            "gateway_ready",
            gateway_ready,
            true,
            if gateway_ready {
                "Gateway is ready"
            } else {
                "Gateway is unavailable or not ready"
            },
        ),
        (
            "protection_ready",
            protection_ready,
            true,
            if protection_ready {
                "Placement protection is ready or not applicable"
            } else {
                "Placement protection is unavailable or not ready"
            },
        ),
        (
            "watchdog_ready",
            watchdog_ready,
            true,
            if watchdog_ready {
                "Watchdog is ready or not applicable"
            } else {
                "Watchdog is unavailable or not ready"
            },
        ),
        (
            "stable_publication",
            publication_ready,
            require_stable,
            if publication_ready {
                "Every installed runtime carries qualified publication evidence"
            } else {
                "Installed runtime publication evidence is absent or not qualified"
            },
        ),
    ];
    let ready = checks
        .iter()
        .all(|(_, passed, required, _)| !*required || *passed);
    let rows = checks
        .iter()
        .map(|(name, passed, required, detail)| {
            vec![
                (*name).to_string(),
                if *passed {
                    "pass"
                } else if *required {
                    "fail"
                } else {
                    "info"
                }
                .to_string(),
                (*detail).to_string(),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "CHECK".to_string(),
            "RESULT".to_string(),
            "DETAIL".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::object([
            (
                "checks",
                MachineValue::Array(
                    checks
                        .iter()
                        .map(|(name, passed, required, detail)| {
                            MachineValue::object([
                                ("detail", MachineValue::from(*detail)),
                                ("id", MachineValue::from(*name)),
                                ("passed", MachineValue::from(*passed)),
                                ("required", MachineValue::from(*required)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("host", host_snapshot_machine_value(local)),
            ("publication_ready", MachineValue::from(publication_ready)),
            ("ready", MachineValue::from(ready)),
        ])),
    ))
}

// Projects one complete inventory into stable JSON with explicit section availability.
fn host_inventory_machine_value(inventory: &NodeHostInventory) -> MachineValue {
    MachineValue::object([
        (
            "hosts",
            MachineValue::Array(
                inventory
                    .hosts()
                    .iter()
                    .map(host_snapshot_machine_value)
                    .collect(),
            ),
        ),
        (
            "local_node_id",
            MachineValue::from(inventory.local_node_id().as_str()),
        ),
        (
            "model_services",
            projection_machine_value(inventory.model_services(), |services| {
                MachineValue::Array(services.iter().map(model_service_machine_value).collect())
            }),
        ),
    ])
}

// Projects one exact host read into stable JSON without credential references.
fn host_snapshot_machine_value(snapshot: &NodeHostSnapshot) -> MachineValue {
    MachineValue::object([
        (
            "gateway",
            projection_machine_value(snapshot.gateway(), gateway_machine_value),
        ),
        (
            "hardware",
            projection_machine_value(snapshot.hardware(), hardware_machine_value),
        ),
        ("node", node_machine_value(snapshot.node())),
        (
            "placement_groups",
            projection_machine_value(snapshot.placement_groups(), |groups| {
                MachineValue::Array(groups.iter().map(host_group_machine_value).collect())
            }),
        ),
        (
            "protection",
            projection_machine_value(snapshot.protection(), protection_machine_value),
        ),
        (
            "verified_links",
            projection_machine_value(snapshot.verified_links(), |links| {
                MachineValue::Array(links.iter().map(host_link_machine_value).collect())
            }),
        ),
        (
            "watchdog",
            projection_machine_value(snapshot.watchdog(), watchdog_machine_value),
        ),
    ])
}

// Wraps one available value or explicit absence in the stable typed JSON shape.
fn projection_machine_value<Value>(
    value: &NodeHostProjectionValue<Value>,
    project: impl FnOnce(&Value) -> MachineValue,
) -> MachineValue {
    match value {
        NodeHostProjectionValue::Available(value) => MachineValue::object([
            ("status", MachineValue::from("available")),
            ("value", project(value)),
        ]),
        NodeHostProjectionValue::Unavailable => {
            MachineValue::object([("status", MachineValue::from("unavailable"))])
        }
        NodeHostProjectionValue::NotApplicable => {
            MachineValue::object([("status", MachineValue::from("not_applicable"))])
        }
    }
}

// Returns one concise count or explicit absence for a bounded projected collection.
fn projection_count<Value>(value: &NodeHostProjectionValue<Vec<Value>>) -> String {
    match value {
        NodeHostProjectionValue::Available(values) => values.len().to_string(),
        NodeHostProjectionValue::Unavailable => "Unavailable".to_string(),
        NodeHostProjectionValue::NotApplicable => "Not applicable".to_string(),
    }
}

// Returns a consistent semantic for one projected collection's availability.
fn projection_semantic<Value>(value: &NodeHostProjectionValue<Vec<Value>>) -> DisplaySemantic {
    match value {
        NodeHostProjectionValue::Available(_) => DisplaySemantic::Information,
        NodeHostProjectionValue::Unavailable => DisplaySemantic::Warning,
        NodeHostProjectionValue::NotApplicable => DisplaySemantic::Muted,
    }
}

// Returns concise resident-service language while retaining absence distinctions.
fn service_projection_name<Value>(value: &NodeHostProjectionValue<Value>) -> String
where
    Value: HostServiceState,
{
    match value {
        NodeHostProjectionValue::Available(summary) => match summary.service_state() {
            NodeHostServiceState::Ready => "Ready".to_string(),
            NodeHostServiceState::NotReady => "Not ready".to_string(),
        },
        NodeHostProjectionValue::Unavailable => "Unavailable".to_string(),
        NodeHostProjectionValue::NotApplicable => "Not applicable".to_string(),
    }
}

// Returns a consistent semantic for one resident service availability and state.
fn service_projection_semantic<Value>(value: &NodeHostProjectionValue<Value>) -> DisplaySemantic
where
    Value: HostServiceState,
{
    match value {
        NodeHostProjectionValue::Available(summary)
            if summary.service_state() == NodeHostServiceState::Ready =>
        {
            DisplaySemantic::Success
        }
        NodeHostProjectionValue::Available(_) | NodeHostProjectionValue::Unavailable => {
            DisplaySemantic::Warning
        }
        NodeHostProjectionValue::NotApplicable => DisplaySemantic::Muted,
    }
}

// Exposes the common readiness field shared by Gateway and Watchdog summaries.
trait HostServiceState {
    // Returns the current service readiness without inspecting telemetry.
    fn service_state(&self) -> NodeHostServiceState;
}

impl HostServiceState for NodeHostGatewaySummary {
    // Returns the Gateway readiness state.
    fn service_state(&self) -> NodeHostServiceState {
        self.state()
    }
}

impl HostServiceState for NodeHostWatchdogSummary {
    // Returns the Watchdog readiness state.
    fn service_state(&self) -> NodeHostServiceState {
        self.state()
    }
}

// Returns concise placement-protection language while retaining absence distinctions.
fn protection_projection_name(
    value: &NodeHostProjectionValue<NodeHostProtectionSummary>,
) -> String {
    match value {
        NodeHostProjectionValue::Available(summary) => match summary.state() {
            NodeHostProtectionState::Ready => "Ready".to_string(),
            NodeHostProtectionState::NotReady => "Not ready".to_string(),
        },
        NodeHostProjectionValue::Unavailable => "Unavailable".to_string(),
        NodeHostProjectionValue::NotApplicable => "Not applicable".to_string(),
    }
}

// Returns a consistent semantic for placement-protection availability and readiness.
fn protection_projection_semantic(
    value: &NodeHostProjectionValue<NodeHostProtectionSummary>,
) -> DisplaySemantic {
    match value {
        NodeHostProjectionValue::Available(summary)
            if summary.state() == NodeHostProtectionState::Ready =>
        {
            DisplaySemantic::Success
        }
        NodeHostProjectionValue::Available(_) | NodeHostProjectionValue::Unavailable => {
            DisplaySemantic::Warning
        }
        NodeHostProjectionValue::NotApplicable => DisplaySemantic::Muted,
    }
}

// Projects one redacted placement group and its exact opaque assignments.
fn host_group_machine_value(group: &NodeHostPlacementGroupSnapshot) -> MachineValue {
    MachineValue::object([
        (
            "desired_state",
            MachineValue::from(model_desired_state_name(group.desired_state())),
        ),
        (
            "endpoint",
            group
                .endpoint()
                .map_or(MachineValue::Null, host_endpoint_machine_value),
        ),
        (
            "placement_group_id",
            MachineValue::from(group.placement_group_id().as_str()),
        ),
        (
            "placements",
            MachineValue::Array(
                group
                    .placements()
                    .iter()
                    .map(host_placement_machine_value)
                    .collect(),
            ),
        ),
        (
            "runtime",
            MachineValue::object([
                (
                    "candidate_id",
                    MachineValue::from(group.runtime_candidate_id().as_str()),
                ),
                ("target_id", MachineValue::from(group.target_id().as_str())),
                (
                    "version",
                    MachineValue::from(group.runtime_version().as_str()),
                ),
            ]),
        ),
        (
            "service_id",
            MachineValue::from(group.service_id().as_str()),
        ),
        (
            "state",
            MachineValue::from(placement_group_state_name(group.state())),
        ),
    ])
}

// Projects one redacted placement endpoint without credential identities.
fn host_endpoint_machine_value(
    endpoint: &li_node_manager::NodeHostEndpointSnapshot,
) -> MachineValue {
    MachineValue::object([
        ("healthy", MachineValue::from(endpoint.is_healthy())),
        (
            "host",
            MachineValue::from(endpoint.address().host().as_str()),
        ),
        (
            "memory_pressure",
            MachineValue::from(endpoint.has_memory_pressure()),
        ),
        ("node_id", MachineValue::from(endpoint.node_id().as_str())),
        (
            "placement_id",
            MachineValue::from(endpoint.placement_id().as_str()),
        ),
        (
            "port",
            MachineValue::from(u64::from(endpoint.address().port())),
        ),
        (
            "scheme",
            MachineValue::from(match endpoint.address().scheme() {
                li_core_interface::EndpointScheme::Http => "http",
                li_core_interface::EndpointScheme::Https => "https",
            }),
        ),
        (
            "temperature_millicelsius",
            endpoint
                .temperature_millicelsius()
                .map_or(MachineValue::Null, |value| {
                    MachineValue::from(i64::from(value))
                }),
        ),
    ])
}

// Projects one opaque placement and its exact resource assignment.
fn host_placement_machine_value(placement: &NodeHostPlacementSnapshot) -> MachineValue {
    MachineValue::object([
        (
            "device_ids",
            MachineValue::Array(
                placement
                    .resources()
                    .device_ids()
                    .iter()
                    .map(|identity| MachineValue::from(identity.as_str()))
                    .collect(),
            ),
        ),
        (
            "endpoint_ownership",
            MachineValue::from(match placement.endpoint_ownership() {
                EndpointOwnership::Owner => "owner",
                EndpointOwnership::Participant => "participant",
            }),
        ),
        ("node_id", MachineValue::from(placement.node_id().as_str())),
        (
            "placement_group_id",
            MachineValue::from(placement.placement_group_id().as_str()),
        ),
        (
            "placement_id",
            MachineValue::from(placement.placement_id().as_str()),
        ),
        (
            "ports",
            MachineValue::object([
                (
                    "base",
                    MachineValue::from(u64::from(placement.resources().ports().base())),
                ),
                (
                    "count",
                    MachineValue::from(u64::from(placement.resources().ports().count())),
                ),
            ]),
        ),
        (
            "rdma_interface",
            placement
                .resources()
                .rdma_interface()
                .map_or(MachineValue::Null, |value| {
                    MachineValue::from(value.as_str())
                }),
        ),
        (
            "runtime_installation_id",
            MachineValue::from(placement.runtime_installation_id().as_str()),
        ),
        (
            "state",
            MachineValue::from(placement_state_name(placement.state())),
        ),
        ("task_id", MachineValue::from(placement.task_id().as_str())),
    ])
}

// Projects one current verified model-neutral link.
fn host_link_machine_value(link: &PlacementLink) -> MachineValue {
    MachineValue::object([
        (
            "kind",
            MachineValue::from(placement_interconnect_kind_name(link.kind())),
        ),
        (
            "left_node_id",
            MachineValue::from(link.left_node_id().as_str()),
        ),
        ("mtu", MachineValue::from(u64::from(link.mtu()))),
        ("rdma", MachineValue::from(link.rdma())),
        (
            "right_node_id",
            MachineValue::from(link.right_node_id().as_str()),
        ),
        ("speed_mbps", MachineValue::from(link.speed_mbps())),
    ])
}

// Projects one current protection readiness observation.
fn protection_machine_value(summary: &NodeHostProtectionSummary) -> MachineValue {
    MachineValue::object([
        (
            "observed_at_unix_milliseconds",
            MachineValue::from(summary.observed_at().value()),
        ),
        (
            "state",
            MachineValue::from(match summary.state() {
                NodeHostProtectionState::Ready => "ready",
                NodeHostProtectionState::NotReady => "not_ready",
            }),
        ),
    ])
}

// Projects one Gateway readiness observation and optional counters.
fn gateway_machine_value(summary: &NodeHostGatewaySummary) -> MachineValue {
    MachineValue::object([
        (
            "state",
            MachineValue::from(service_state_name(summary.state())),
        ),
        (
            "telemetry",
            summary
                .telemetry()
                .map_or(MachineValue::Null, gateway_telemetry_machine_value),
        ),
    ])
}

// Projects one bounded Gateway counter snapshot.
fn gateway_telemetry_machine_value(summary: &NodeHostGatewayTelemetrySummary) -> MachineValue {
    MachineValue::object([
        (
            "active_requests",
            MachineValue::from(summary.active_requests()),
        ),
        ("cached_tokens", MachineValue::from(summary.cached_tokens())),
        ("input_tokens", MachineValue::from(summary.input_tokens())),
        (
            "observed_at_unix_milliseconds",
            MachineValue::from(summary.observed_at().value()),
        ),
        ("output_tokens", MachineValue::from(summary.output_tokens())),
        (
            "queued_requests",
            MachineValue::from(summary.queued_requests()),
        ),
        (
            "requests_completed",
            MachineValue::from(summary.requests_completed()),
        ),
        (
            "requests_failed",
            MachineValue::from(summary.requests_failed()),
        ),
    ])
}

// Projects one Watchdog readiness observation and optional host telemetry.
fn watchdog_machine_value(summary: &NodeHostWatchdogSummary) -> MachineValue {
    MachineValue::object([
        (
            "state",
            MachineValue::from(service_state_name(summary.state())),
        ),
        (
            "telemetry",
            summary
                .telemetry()
                .map_or(MachineValue::Null, watchdog_telemetry_machine_value),
        ),
    ])
}

// Projects one bounded Watchdog host telemetry snapshot.
fn watchdog_telemetry_machine_value(summary: &NodeHostWatchdogTelemetrySummary) -> MachineValue {
    MachineValue::object([
        (
            "active_requests",
            MachineValue::from(u64::from(summary.active_requests())),
        ),
        ("cpu_percent", optional_percent(summary.cpu_percent())),
        ("disk_percent", optional_percent(summary.disk_percent())),
        (
            "gpu_memory_percent",
            optional_percent(summary.gpu_memory_percent()),
        ),
        ("gpu_percent", optional_percent(summary.gpu_percent())),
        ("memory_percent", optional_percent(summary.memory_percent())),
        (
            "observed_at_unix_milliseconds",
            MachineValue::from(summary.observed_at().value()),
        ),
        (
            "queued_requests",
            MachineValue::from(u64::from(summary.queued_requests())),
        ),
    ])
}

// Projects one optional bounded percentage without turning absence into zero.
fn optional_percent(value: Option<u8>) -> MachineValue {
    value.map_or(MachineValue::Null, |value| {
        MachineValue::from(u64::from(value))
    })
}

// Returns one stable resident-service state name.
const fn service_state_name(value: NodeHostServiceState) -> &'static str {
    match value {
        NodeHostServiceState::Ready => "ready",
        NodeHostServiceState::NotReady => "not_ready",
    }
}

// Returns one stable placement-group lifecycle state name.
const fn placement_group_state_name(value: PlacementGroupState) -> &'static str {
    match value {
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

// Returns one stable opaque placement lifecycle state name.
const fn placement_state_name(value: PlacementState) -> &'static str {
    match value {
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

// Returns one stable model-neutral interconnect kind name.
const fn placement_interconnect_kind_name(value: InterconnectKind) -> &'static str {
    match value {
        InterconnectKind::Any => "any",
        InterconnectKind::Connectx => "connectx",
        InterconnectKind::Ethernet => "ethernet",
        InterconnectKind::Wifi => "wifi",
        InterconnectKind::Other => "other",
    }
}

// Projects one complete observed hardware snapshot into stable CLI JSON.
fn hardware_machine_value(observation: &HardwareObservation) -> MachineValue {
    MachineValue::object([
        (
            "accelerators",
            MachineValue::Array(
                observation
                    .accelerators()
                    .iter()
                    .map(accelerator_machine_value)
                    .collect(),
            ),
        ),
        (
            "architecture",
            MachineValue::from(architecture_name(observation.platform().architecture())),
        ),
        (
            "boot_id",
            MachineValue::from(observation.boot_id().as_str()),
        ),
        (
            "interconnects",
            MachineValue::Array(
                observation
                    .interconnects()
                    .iter()
                    .map(interconnect_machine_value)
                    .collect(),
            ),
        ),
        (
            "logical_cpu_count",
            MachineValue::from(u64::from(observation.processor().logical_cpu_count())),
        ),
        (
            "memory_bytes",
            MachineValue::from(observation.memory_bytes().value()),
        ),
        (
            "node_id",
            MachineValue::from(observation.node_id().as_str()),
        ),
        (
            "observation_id",
            MachineValue::from(observation.observation_id().as_str()),
        ),
        (
            "observed_at_unix_milliseconds",
            MachineValue::from(observation.observed_at().value()),
        ),
        (
            "operating_system",
            MachineValue::from(operating_system_name(
                observation.platform().operating_system(),
            )),
        ),
        (
            "processor",
            MachineValue::from(observation.processor().model().as_str()),
        ),
    ])
}

// Projects one accelerator without applying RuntimeManager compatibility policy.
fn accelerator_machine_value(accelerator: &li_core_interface::Accelerator) -> MachineValue {
    let compute = match accelerator.compute() {
        ComputeCapability::Cuda {
            architecture,
            maximum_version,
        } => MachineValue::object([
            ("api", MachineValue::from("cuda")),
            ("architecture", MachineValue::from(architecture.as_str())),
            (
                "maximum_version",
                maximum_version
                    .as_ref()
                    .map_or(MachineValue::Null, |value| {
                        MachineValue::from(value.as_str())
                    }),
            ),
        ]),
        ComputeCapability::Metal { family, version } => MachineValue::object([
            ("api", MachineValue::from("metal")),
            ("family", MachineValue::from(family.as_str())),
            ("version", MachineValue::from(version.as_str())),
        ]),
        ComputeCapability::Other { api, capability } => MachineValue::object([
            ("api", MachineValue::from(api.as_str())),
            (
                "capability",
                capability.as_ref().map_or(MachineValue::Null, |value| {
                    MachineValue::from(value.as_str())
                }),
            ),
        ]),
    };
    let driver = accelerator.driver().map_or(MachineValue::Null, |driver| {
        MachineValue::object([
            ("source", MachineValue::from(driver.source().as_str())),
            ("version", MachineValue::from(driver.version().as_str())),
        ])
    });
    let telemetry = accelerator
        .telemetry()
        .map_or(MachineValue::Null, |telemetry| {
            MachineValue::object([
                (
                    "framebuffer_used_bytes",
                    optional_unsigned(telemetry.framebuffer_used_bytes()),
                ),
                (
                    "graphics_clock_mhz",
                    optional_unsigned(telemetry.graphics_clock_mhz().map(u64::from)),
                ),
                (
                    "memory_clock_mhz",
                    optional_unsigned(telemetry.memory_clock_mhz().map(u64::from)),
                ),
                (
                    "power_milliwatts",
                    optional_unsigned(telemetry.power_milliwatts()),
                ),
                (
                    "temperature_millicelsius",
                    telemetry
                        .temperature_millicelsius()
                        .map_or(MachineValue::Null, |value| {
                            MachineValue::from(i64::from(value))
                        }),
                ),
                (
                    "utilization_per_mille",
                    optional_unsigned(telemetry.utilization_per_mille().map(u64::from)),
                ),
            ])
        });
    MachineValue::object([
        ("compute", compute),
        (
            "device_id",
            MachineValue::from(accelerator.device_id().as_str()),
        ),
        ("driver", driver),
        (
            "memory",
            MachineValue::object([
                (
                    "addressing_mode",
                    accelerator
                        .memory()
                        .addressing_mode()
                        .map_or(MachineValue::Null, |value| {
                            MachineValue::from(value.as_str())
                        }),
                ),
                (
                    "framebuffer_bytes",
                    accelerator
                        .memory()
                        .framebuffer_bytes()
                        .map_or(MachineValue::Null, |value| {
                            MachineValue::from(value.value())
                        }),
                ),
                (
                    "topology",
                    MachineValue::from(memory_topology_name(accelerator.memory().topology())),
                ),
            ]),
        ),
        ("name", MachineValue::from(accelerator.name().as_str())),
        ("telemetry", telemetry),
        (
            "vendor",
            MachineValue::from(accelerator_vendor_name(accelerator.vendor())),
        ),
    ])
}

// Projects one mutable observed interconnect without claiming permanent topology.
fn interconnect_machine_value(
    interconnect: &li_core_interface::InterconnectObservation,
) -> MachineValue {
    MachineValue::object([
        ("available", MachineValue::from(interconnect.is_available())),
        (
            "device_ids",
            MachineValue::Array(
                interconnect
                    .device_ids()
                    .iter()
                    .map(|identity| MachineValue::from(identity.as_str()))
                    .collect(),
            ),
        ),
        (
            "interface",
            interconnect
                .interface()
                .map_or(MachineValue::Null, |value| {
                    MachineValue::from(value.as_str())
                }),
        ),
        (
            "kind",
            MachineValue::from(interconnect_kind_name(interconnect.kind())),
        ),
        ("mtu", optional_unsigned(interconnect.mtu().map(u64::from))),
        ("speed_mbps", optional_unsigned(interconnect.speed_mbps())),
    ])
}

// Converts one optional unsigned measurement into deterministic machine JSON.
fn optional_unsigned(value: Option<u64>) -> MachineValue {
    value.map_or(MachineValue::Null, MachineValue::from)
}

// Returns the stable operating-system name used by hardware JSON.
const fn operating_system_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    }
}

// Returns the stable CPU architecture name used by hardware JSON.
const fn architecture_name(value: CpuArchitecture) -> &'static str {
    match value {
        CpuArchitecture::Arm64 => "arm64",
        CpuArchitecture::X86_64 => "x86_64",
    }
}

// Returns the stable accelerator-vendor name used by hardware JSON.
fn accelerator_vendor_name(value: &AcceleratorVendor) -> &str {
    match value {
        AcceleratorVendor::Nvidia => "nvidia",
        AcceleratorVendor::Apple => "apple",
        AcceleratorVendor::Other(name) => name.as_str(),
    }
}

// Returns the stable accelerator-memory topology name used by hardware JSON.
const fn memory_topology_name(value: MemoryTopology) -> &'static str {
    match value {
        MemoryTopology::Unified => "unified",
        MemoryTopology::Discrete => "discrete",
        MemoryTopology::Unknown => "unknown",
    }
}

// Returns the stable observed interconnect kind used by hardware JSON.
const fn interconnect_kind_name(value: InterconnectObservationKind) -> &'static str {
    match value {
        InterconnectObservationKind::Pcie => "pcie",
        InterconnectObservationKind::Nvlink => "nvlink",
        InterconnectObservationKind::Rdma => "rdma",
        InterconnectObservationKind::Ethernet => "ethernet",
        InterconnectObservationKind::Wifi => "wifi",
        InterconnectObservationKind::Other => "other",
    }
}

// Presents durable public exposure and its live provider verification without native detail.
fn exposure_output(status: &GatewayExposureStatus) -> CommandOutput {
    let state = if status.exposure().is_some() {
        "enabled"
    } else {
        "disabled"
    };
    let provider = status
        .exposure()
        .map_or("tailscale-funnel", |exposure| exposure.provider());
    let public_url = status
        .exposure()
        .map(|exposure| exposure.public_url().to_string());
    let configuration_sha256 = status
        .exposure()
        .map(|exposure| exposure.configuration_sha256().as_str().to_string());
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "State",
                state,
                None,
                if state == "enabled" && status.provider_verified() {
                    DisplaySemantic::Success
                } else {
                    DisplaySemantic::Warning
                },
            ),
            DisplayRecord::new("Provider", provider, None, DisplaySemantic::Muted),
            DisplayRecord::new(
                "URL",
                public_url.as_deref().unwrap_or("—"),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Verified",
                if status.provider_verified() {
                    "yes"
                } else {
                    "no"
                },
                None,
                if status.provider_verified() {
                    DisplaySemantic::Success
                } else {
                    DisplaySemantic::Error
                },
            ),
        ])]),
        Some(MachineValue::object([
            (
                "configuration_sha256",
                configuration_sha256.map_or(MachineValue::Null, MachineValue::from),
            ),
            (
                "inference_target",
                MachineValue::from("http://127.0.0.1:8000"),
            ),
            ("provider", MachineValue::from(provider)),
            (
                "provider_verified",
                MachineValue::from(status.provider_verified()),
            ),
            (
                "public_url",
                public_url.map_or(MachineValue::Null, MachineValue::from),
            ),
            ("state", MachineValue::from(state)),
        ])),
    )
}

// Presents one complete native teardown receipt without claiming reversible cleanup.
fn uninstall_output(receipt: &NativeUninstallReceipt) -> CommandOutput {
    let models = if receipt.models_preserved() {
        "preserved"
    } else {
        "removed"
    };
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new("Let's Infer", "Removed", None, DisplaySemantic::Success),
            DisplayRecord::new("Models", models, None, DisplaySemantic::Information),
            DisplayRecord::new(
                "Containers",
                receipt.removed_containers().to_string(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Images",
                receipt.removed_images().to_string(),
                None,
                DisplaySemantic::Muted,
            ),
        ])]),
        Some(MachineValue::object([
            ("models", MachineValue::from(models)),
            (
                "receipt_id",
                MachineValue::from(receipt.receipt_id().as_str()),
            ),
            ("removed_containers", receipt.removed_containers().into()),
            ("removed_images", receipt.removed_images().into()),
            ("removed_targets", receipt.removed_targets().into()),
            ("replayed", MachineValue::from(receipt.replayed())),
        ])),
    )
}

// Presents one bounded AuditManager event collection in stable sequence order.
fn audit_events_output(events: Vec<AuditEvent>) -> Result<CommandOutput, CommandFailure> {
    let rows = events
        .iter()
        .map(|event| {
            vec![
                event.sequence().to_string(),
                event.outcome().as_str().to_string(),
                event.action().as_str().to_string(),
                event.target().as_str().to_string(),
                event.timestamp().value().to_string(),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "SEQ".to_string(),
            "RESULT".to_string(),
            "ACTION".to_string(),
            "TARGET".to_string(),
            "UNIX NS".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::Array(
            events.iter().map(audit_event_machine_value).collect(),
        )),
    ))
}

// Presents every non-secret field of one exact audit event.
fn audit_event_output(event: &AuditEvent) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Sequence",
                event.sequence().to_string(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Event",
                event.event_id().as_str(),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Action",
                event.action().as_str(),
                Some(event.target().as_str().to_string()),
                audit_outcome_semantic(event.outcome()),
            ),
            DisplayRecord::new(
                "Outcome",
                event.outcome().as_str(),
                event.reason().map(|value| value.as_str().to_string()),
                audit_outcome_semantic(event.outcome()),
            ),
            DisplayRecord::new(
                "Event hash",
                format!("sha256:{}", event.event_hash().as_str()),
                None,
                DisplaySemantic::Muted,
            ),
        ])]),
        Some(audit_event_machine_value(event)),
    )
}

// Projects every stable AuditManager event field into deterministic CLI JSON.
fn audit_event_machine_value(event: &AuditEvent) -> MachineValue {
    MachineValue::object([
        ("action", MachineValue::from(event.action().as_str())),
        (
            "actor_id",
            MachineValue::from(event.actor().identifier().as_str()),
        ),
        (
            "actor_type",
            MachineValue::from(event.actor().kind().as_str()),
        ),
        (
            "after_sha256",
            event.after_sha256().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.as_str())
            }),
        ),
        (
            "before_sha256",
            event.before_sha256().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.as_str())
            }),
        ),
        (
            "correlation_id",
            MachineValue::from(event.correlation_id().as_str()),
        ),
        ("event_id", MachineValue::from(event.event_id().as_str())),
        (
            "event_sha256",
            MachineValue::from(event.event_hash().as_str()),
        ),
        ("node_id", MachineValue::from(event.node_id().as_str())),
        (
            "origin_interface",
            MachineValue::from(event.origin().interface().as_str()),
        ),
        (
            "origin_node_id",
            MachineValue::from(event.origin().node_id().as_str()),
        ),
        ("outcome", MachineValue::from(event.outcome().as_str())),
        (
            "previous_sha256",
            MachineValue::from(event.previous_hash().as_str()),
        ),
        (
            "reason",
            event.reason().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.as_str())
            }),
        ),
        ("sequence", MachineValue::from(event.sequence())),
        ("target", MachineValue::from(event.target().as_str())),
        (
            "timestamp_unix_nanoseconds",
            MachineValue::from(event.timestamp().value()),
        ),
    ])
}

// Presents one complete chain-verification receipt.
fn audit_verification_output(verification: &NodeAuditVerification) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new("Audit", "Verified", None, DisplaySemantic::Success),
            DisplayRecord::new(
                "Events",
                verification.events().to_string(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Checkpoints",
                verification.checkpoints().to_string(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Head",
                format!("sha256:{}", verification.head_sha256().as_str()),
                None,
                DisplaySemantic::Information,
            ),
        ])]),
        Some(MachineValue::object([
            (
                "checkpoints",
                MachineValue::from(verification.checkpoints() as u64),
            ),
            ("events", MachineValue::from(verification.events() as u64)),
            (
                "head_sha256",
                MachineValue::from(verification.head_sha256().as_str()),
            ),
            ("valid", MachineValue::from(true)),
        ])),
    )
}

// Presents one successfully persisted audit-export artifact.
fn audit_export_file_output(path: &Path, events: usize) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new("Audit export", "Complete", None, DisplaySemantic::Success),
            DisplayRecord::new("Events", events.to_string(), None, DisplaySemantic::Muted),
            DisplayRecord::new(
                "Artifact",
                path.display().to_string(),
                None,
                DisplaySemantic::Information,
            ),
        ])]),
        None,
    )
}

// Selects stable audit result emphasis without exposing free-form event content.
const fn audit_outcome_semantic(outcome: AuditOutcome) -> DisplaySemantic {
    match outcome {
        AuditOutcome::Success => DisplaySemantic::Success,
        AuditOutcome::Denied | AuditOutcome::Failed => DisplaySemantic::Error,
    }
}

// Parses the registry's logical-model positional without accepting interactive omission.
fn required_model(invocation: &CommandInvocation) -> Result<LogicalModelName, CommandFailure> {
    invocation
        .text(ArgumentId::Model)
        .ok_or_else(|| invalid_model_argument("A logical model name is required."))
        .and_then(|value| {
            LogicalModelName::parse(value)
                .map_err(|_| invalid_model_argument("Logical model name is invalid."))
        })
}

// Derives the stable main-owned logical service identity used by the legacy contract.
fn model_service_id(
    main_node_id: &NodeId,
    logical_model: &LogicalModelName,
) -> Result<ModelServiceId, CommandFailure> {
    let document = format!(
        "{{\"contract\":\"letsinfer-model-service-v1\",\"model\":\"{}\",\"node_id\":\"{}\"}}",
        logical_model.as_str(),
        main_node_id.as_str()
    );
    let digest = Sha256::digest(document.as_bytes());
    ModelServiceId::parse(&digest_hex(&digest)[..32])
        .map_err(|_| invalid_model_argument("Model service identity is invalid."))
}

// Derives one exact replay identity from the normalized action and complete target binding.
fn model_command_identity(
    action: &str,
    binding: &str,
) -> Result<NodeModelCommandIdentity, CommandFailure> {
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_model_command_v1\0");
    hasher.update(action.as_bytes());
    hasher.update(b"\0");
    hasher.update(binding.as_bytes());
    let digest = digest_hex(&hasher.finalize());
    Ok(NodeModelCommandIdentity::new(
        OperationId::parse(&digest[..32])
            .map_err(|_| invalid_model_argument("Model operation identity is invalid."))?,
        TechnicalName::parse(&format!("cli_{}", &digest[..32]))
            .map_err(|_| invalid_model_argument("Model idempotency identity is invalid."))?,
    ))
}

// Encodes one digest in canonical lowercase hexadecimal.
fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Creates one stable invalid-model-argument failure without copying rejected values.
fn invalid_model_argument(message: &'static str) -> CommandFailure {
    failure("model.invalid_argument", message)
}

// Creates one stable invalid-update failure without copying a rejected release value.
fn invalid_update_argument(message: &'static str) -> CommandFailure {
    failure("update.invalid_argument", message)
}

// Requires explicit acknowledgement before a native update can mutate Core or runtimes.
fn update_confirmation_required_failure() -> CommandFailure {
    failure(
        "update.confirmation_required",
        "Pass --yes to confirm this update.",
    )
}

// Presents one verified signed catalog listing with stable human and machine projections.
fn catalog_listing_output(listing: &NodeCatalogListing) -> Result<CommandOutput, CommandFailure> {
    let rows = listing
        .entries()
        .iter()
        .map(|entry| {
            vec![
                entry.logical_model().as_str().to_string(),
                entry
                    .authors()
                    .iter()
                    .map(|author| author.login())
                    .collect::<Vec<_>>()
                    .join(", "),
                entry.version().to_string(),
                entry.engine().as_str().to_string(),
                entry.target_id().as_str().to_string(),
                entry.verification_method().to_string(),
                if entry.is_recommended() {
                    "recommended".to_string()
                } else {
                    evidence_label_name(entry.evidence_label()).to_string()
                },
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "MODEL".to_string(),
            "AUTHOR".to_string(),
            "VERSION".to_string(),
            "ENGINE".to_string(),
            "TARGET".to_string(),
            "VERIFIED".to_string(),
            "STATUS".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    let snapshot = listing.snapshot();
    let models = listing
        .entries()
        .iter()
        .map(catalog_entry_machine_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::object([
            (
                "catalog",
                MachineValue::object([
                    (
                        "catalog_sha256",
                        MachineValue::from(snapshot.catalog_sha256().as_str()),
                    ),
                    (
                        "revocation_sequence",
                        MachineValue::from(snapshot.revocation_sequence()),
                    ),
                    (
                        "revocations_sha256",
                        MachineValue::from(snapshot.revocations_sha256().as_str()),
                    ),
                    ("source", MachineValue::from(snapshot.source())),
                    ("stale", MachineValue::from(snapshot.is_stale())),
                    (
                        "verified_at_unix",
                        MachineValue::from(snapshot.verified_at_unix()),
                    ),
                ]),
            ),
            ("models", MachineValue::Array(models)),
        ])),
    ))
}

// Projects one signed catalog release into deterministic CLI JSON.
fn catalog_entry_machine_value(entry: &NodeCatalogEntry) -> Result<MachineValue, CommandFailure> {
    let score = entry
        .benchmark_score()
        .map_or(Ok(MachineValue::Null), |score| {
            MachineNumber::from_f64(score)
                .map(MachineValue::Number)
                .map_err(|_| invalid_response_failure())
        })?;
    Ok(MachineValue::object([
        (
            "authors",
            MachineValue::Array(
                entry
                    .authors()
                    .iter()
                    .map(|author| {
                        MachineValue::object([
                            ("login", MachineValue::from(author.login())),
                            ("numeric_id", MachineValue::from(author.numeric_id())),
                            (
                                "type",
                                MachineValue::from(match author.kind() {
                                    li_node_manager::NodeCatalogAuthorKind::User => "user",
                                    li_node_manager::NodeCatalogAuthorKind::Organization => {
                                        "organization"
                                    }
                                }),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("benchmark_score", score),
        (
            "candidate_id",
            MachineValue::from(entry.candidate_id().as_str()),
        ),
        ("engine", MachineValue::from(entry.engine().as_str())),
        (
            "evidence_label",
            MachineValue::from(evidence_label_name(entry.evidence_label())),
        ),
        ("license", MachineValue::from(entry.license())),
        (
            "logical_model",
            MachineValue::from(entry.logical_model().as_str()),
        ),
        ("model_uri", MachineValue::from(entry.model_uri())),
        ("recommended", MachineValue::from(entry.is_recommended())),
        ("runtime_source", MachineValue::from(entry.runtime_source())),
        ("target_id", MachineValue::from(entry.target_id().as_str())),
        (
            "verification_method",
            MachineValue::from(entry.verification_method()),
        ),
        ("version", MachineValue::from(entry.version())),
    ]))
}

// Presents every installed logical service in stable model and identity order.
fn model_services_output(
    mut services: Vec<NodeModelServiceSummary>,
) -> Result<CommandOutput, CommandFailure> {
    services.sort_by(|left, right| {
        left.logical_model()
            .as_str()
            .cmp(right.logical_model().as_str())
            .then_with(|| left.service_id().as_str().cmp(right.service_id().as_str()))
    });
    let rows = services
        .iter()
        .map(|service| {
            vec![
                service.logical_model().as_str().to_string(),
                model_desired_state_name(service.desired_state()).to_string(),
                service.placement_group_ids().len().to_string(),
                service.runtime_installation_ids().len().to_string(),
                service
                    .evidence_labels()
                    .iter()
                    .map(|label| evidence_label_name(*label))
                    .collect::<Vec<_>>()
                    .join(","),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "MODEL".to_string(),
            "STATE".to_string(),
            "GROUPS".to_string(),
            "RUNTIMES".to_string(),
            "EVIDENCE".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::Array(
            services.iter().map(model_service_machine_value).collect(),
        )),
    ))
}

// Projects one installed service into deterministic CLI JSON.
fn model_service_machine_value(service: &NodeModelServiceSummary) -> MachineValue {
    MachineValue::object([
        (
            "desired_state",
            MachineValue::from(model_desired_state_name(service.desired_state())),
        ),
        (
            "evidence_labels",
            MachineValue::Array(
                service
                    .evidence_labels()
                    .iter()
                    .map(|label| MachineValue::from(evidence_label_name(*label)))
                    .collect(),
            ),
        ),
        (
            "logical_model",
            MachineValue::from(service.logical_model().as_str()),
        ),
        (
            "placement_group_ids",
            MachineValue::Array(
                service
                    .placement_group_ids()
                    .iter()
                    .map(|identity| MachineValue::from(identity.as_str()))
                    .collect(),
            ),
        ),
        (
            "runtime_installation_ids",
            MachineValue::Array(
                service
                    .runtime_installation_ids()
                    .iter()
                    .map(|identity| MachineValue::from(identity.as_str()))
                    .collect(),
            ),
        ),
        (
            "service_id",
            MachineValue::from(service.service_id().as_str()),
        ),
    ])
}

// Presents one terminal or replayed ModelCoordinator command result.
fn model_command_output(summary: &NodeModelCommandSummary) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Model",
                summary.logical_model().as_str(),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Action",
                summary.action().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "State",
                summary.journal_state().as_str(),
                summary
                    .failure_code()
                    .map(|failure| failure.as_str().to_string()),
                if summary.failure_code().is_some() {
                    DisplaySemantic::Error
                } else {
                    DisplaySemantic::Success
                },
            ),
        ])]),
        Some(MachineValue::object([
            ("action", MachineValue::from(summary.action().as_str())),
            (
                "desired_state",
                MachineValue::from(model_desired_state_name(summary.desired_state())),
            ),
            (
                "failure_code",
                summary
                    .failure_code()
                    .map_or(MachineValue::Null, |failure| {
                        MachineValue::from(failure.as_str())
                    }),
            ),
            (
                "journal_state",
                MachineValue::from(summary.journal_state().as_str()),
            ),
            (
                "logical_model",
                MachineValue::from(summary.logical_model().as_str()),
            ),
            (
                "operation_id",
                MachineValue::from(summary.operation_id().as_str()),
            ),
            (
                "service_id",
                MachineValue::from(summary.service_id().as_str()),
            ),
        ])),
    )
}

// Presents one signed read-only Core availability decision in text and JSON.
fn core_update_check_output(check: &NodeCoreUpdateCheck) -> CommandOutput {
    let disposition = check.disposition().as_str();
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Core",
                disposition,
                None,
                if disposition == "current" {
                    DisplaySemantic::Success
                } else {
                    DisplaySemantic::Warning
                },
            ),
            DisplayRecord::new(
                "Installed",
                check.current().version().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Available",
                check.available().version().as_str(),
                None,
                DisplaySemantic::Information,
            ),
        ])]),
        Some(MachineValue::object([
            (
                "available_source_identity",
                MachineValue::from(check.available().source_identity().as_str()),
            ),
            (
                "available_version",
                MachineValue::from(check.available().version().as_str()),
            ),
            ("disposition", MachineValue::from(disposition)),
            (
                "installed_source_identity",
                MachineValue::from(check.current().source_identity().as_str()),
            ),
            (
                "installed_version",
                MachineValue::from(check.current().version().as_str()),
            ),
        ])),
    )
}

// Presents one terminal CoreUpdateManager projection without inventing lifecycle state.
fn core_update_output(summary: &NodeCoreUpdateSummary) -> CommandOutput {
    let disposition = match summary.disposition() {
        CoreUpdateDisposition::Current => "current",
        CoreUpdateDisposition::Updated => "updated",
        CoreUpdateDisposition::CleanupPending => "cleanup_pending",
    };
    let phase = li_node_manager::core_update_phase_name(summary.phase());
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Core",
                summary.installation().version().as_str(),
                None,
                DisplaySemantic::Success,
            ),
            DisplayRecord::new(
                "Result",
                disposition,
                Some(phase.to_string()),
                if summary.disposition() == CoreUpdateDisposition::CleanupPending {
                    DisplaySemantic::Warning
                } else {
                    DisplaySemantic::Success
                },
            ),
        ])]),
        Some(MachineValue::object([
            ("disposition", MachineValue::from(disposition)),
            ("phase", MachineValue::from(phase)),
            (
                "source_identity",
                MachineValue::from(summary.installation().source_identity().as_str()),
            ),
            (
                "version",
                MachineValue::from(summary.installation().version().as_str()),
            ),
        ])),
    )
}

// Presents one read-only or applied ModelCoordinator update decision.
fn model_update_output(summary: &NodeModelUpdateSummary) -> CommandOutput {
    let disposition = summary.disposition().as_str();
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Model",
                summary.logical_model().as_str(),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Result",
                disposition,
                Some(format!(
                    "{} placement groups",
                    summary.placement_group_count()
                )),
                if summary.disposition() == NodeModelUpdateDisposition::Current {
                    DisplaySemantic::Success
                } else if summary.disposition() == NodeModelUpdateDisposition::UpdateAvailable {
                    DisplaySemantic::Warning
                } else {
                    DisplaySemantic::Success
                },
            ),
        ])]),
        Some(MachineValue::object([
            ("disposition", MachineValue::from(disposition)),
            (
                "logical_model",
                MachineValue::from(summary.logical_model().as_str()),
            ),
            (
                "operation_id",
                summary.command().map_or(MachineValue::Null, |command| {
                    MachineValue::from(command.operation_id().as_str())
                }),
            ),
            (
                "placement_group_count",
                MachineValue::from(
                    u64::try_from(summary.placement_group_count()).unwrap_or(u64::MAX),
                ),
            ),
            (
                "service_id",
                MachineValue::from(summary.service_id().as_str()),
            ),
        ])),
    )
}

// Presents one truthful non-mutating current-to-retained runtime transition.
fn model_rollback_preview_output(
    preview: &NodeModelRollbackPreview,
) -> Result<CommandOutput, CommandFailure> {
    let groups = preview.groups();
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Rollback",
                "Retained runtime preview",
                Some("No state or provider was changed.".to_string()),
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Model",
                preview.logical_model().as_str(),
                Some(format!("{} placement group(s)", groups.len())),
                DisplaySemantic::Muted,
            ),
        ])]),
        Some(MachineValue::object([
            ("dry_run", MachineValue::from(true)),
            (
                "groups",
                MachineValue::Array(
                    groups
                        .iter()
                        .map(|group| {
                            let runtime = |value: &li_node_manager::NodeModelRollbackRuntime| {
                                MachineValue::object([
                                    (
                                        "candidate_id",
                                        MachineValue::from(value.candidate_id().as_str()),
                                    ),
                                    ("source", MachineValue::from(value.source().as_str())),
                                    ("target_id", MachineValue::from(value.target_id().as_str())),
                                    ("version", MachineValue::from(value.version().as_str())),
                                ])
                            };
                            MachineValue::object([
                                (
                                    "current_group_id",
                                    MachineValue::from(group.current_group_id().as_str()),
                                ),
                                ("current", runtime(group.current())),
                                (
                                    "node_ids",
                                    MachineValue::Array(
                                        group
                                            .node_ids()
                                            .iter()
                                            .map(|node_id| MachineValue::from(node_id.as_str()))
                                            .collect(),
                                    ),
                                ),
                                ("previous", runtime(group.previous())),
                                (
                                    "previous_group_id",
                                    MachineValue::from(group.previous_group_id().as_str()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("kind", MachineValue::from("retained_runtime")),
            (
                "logical_model",
                MachineValue::from(preview.logical_model().as_str()),
            ),
            (
                "service_id",
                MachineValue::from(preview.service_id().as_str()),
            ),
            (
                "target_id",
                preview.target_id().map_or(MachineValue::Null, |target_id| {
                    MachineValue::from(target_id.as_str())
                }),
            ),
        ])),
    ))
}

// Presents one opaque Placement-owned batch without changing bytes or fabricating a newline.
fn model_runtime_logs_output(batch: &NodeModelRuntimeLogBatch) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::RawBytes(
            batch.placement().payload().to_vec(),
        )]),
        None,
    )
}

// Parses one canonical public benchmark selection without accepting manager-owned identities.
fn benchmark_selection(
    invocation: &CommandInvocation,
) -> Result<NodeBenchmarkSelection, CommandFailure> {
    let logical_model = invocation
        .text(ArgumentId::Model)
        .ok_or_else(|| invalid_benchmark_argument("A model name is required."))
        .and_then(|value| {
            LogicalModelName::parse(value)
                .map_err(|_| invalid_benchmark_argument("The benchmark model name is invalid."))
        })?;
    let concurrencies = [
        (ArgumentId::C1, 1_u16),
        (ArgumentId::C2, 2_u16),
        (ArgumentId::C4, 4_u16),
        (ArgumentId::C8, 8_u16),
        (ArgumentId::C16, 16_u16),
    ]
    .into_iter()
    .filter_map(|(argument, value)| {
        invocation
            .boolean(argument)
            .unwrap_or(false)
            .then_some(value)
    })
    .collect();
    let contexts = [
        (ArgumentId::Context32k, NodeBenchmarkContext::Context32k),
        (ArgumentId::Context64k, NodeBenchmarkContext::Context64k),
        (ArgumentId::Context128k, NodeBenchmarkContext::Context128k),
        (ArgumentId::Context256k, NodeBenchmarkContext::Context256k),
    ]
    .into_iter()
    .filter_map(|(argument, value)| {
        invocation
            .boolean(argument)
            .unwrap_or(false)
            .then_some(value)
    })
    .collect();
    NodeBenchmarkSelection::new(logical_model, concurrencies, contexts)
        .map_err(|_| invalid_benchmark_argument("The benchmark workload selection is invalid."))
}

// Derives one bounded replay identity from the exact public selection and invocation time.
fn benchmark_start_identity(
    selection: &NodeBenchmarkSelection,
    started_at: UnixMilliseconds,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_benchmark_start_v1\0");
    hasher.update(selection.logical_model().as_str().as_bytes());
    for concurrency in selection.concurrencies() {
        hasher.update(b"\0c");
        hasher.update(concurrency.to_be_bytes());
    }
    for context in selection.contexts() {
        hasher.update(b"\0x");
        hasher.update(context.as_str().as_bytes());
    }
    hasher.update(b"\0t");
    hasher.update(started_at.value().to_be_bytes());
    format!("li_cli_benchmark_{}", digest_hex(&hasher.finalize()))
}

// Derives one stable replay identity from only the public proposal URL and candidate selector.
fn benchmark_verification_start_identity(
    pull_request_url: &str,
    candidate: Option<&RuntimeCandidateId>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_benchmark_verification_v1\0");
    hasher.update(pull_request_url.as_bytes());
    hasher.update(b"\0candidate\0");
    hasher.update(candidate.map_or(b"".as_slice(), |value| value.as_str().as_bytes()));
    format!(
        "li_cli_benchmark_verification_{}",
        digest_hex(&hasher.finalize())
    )
}

// Presents one exact resolved benchmark plan without exposing mutable provider internals.
fn benchmark_plan_output(plan: &NodeBenchmarkPlan) -> Result<CommandOutput, CommandFailure> {
    let selected = plan
        .selected_cells()
        .iter()
        .map(TechnicalName::as_str)
        .collect::<BTreeSet<_>>();
    let rows = plan
        .declared_cells()
        .iter()
        .map(|cell| {
            vec![
                cell.as_str().to_string(),
                if selected.contains(cell.as_str()) {
                    "selected".to_string()
                } else {
                    "not selected".to_string()
                },
            ]
        })
        .collect();
    let table = DisplayTable::new(vec!["CELL".to_string(), "STATUS".to_string()], rows)
        .map_err(|_| invalid_response_failure())?;
    let subject = plan.request().subject();
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::object([
            (
                "benchmark_contract_sha256",
                MachineValue::from(subject.benchmark_contract_sha256().as_str()),
            ),
            (
                "core_installation_id",
                MachineValue::from(subject.installation_id().as_str()),
            ),
            (
                "declared_cells",
                MachineValue::Array(
                    plan.declared_cells()
                        .iter()
                        .map(|cell| MachineValue::from(cell.as_str()))
                        .collect(),
                ),
            ),
            (
                "execution_sha256",
                MachineValue::from(subject.execution_sha256().as_str()),
            ),
            (
                "logical_model",
                MachineValue::from(subject.model().as_str()),
            ),
            (
                "placement_group_id",
                MachineValue::from(subject.placement_group_id().as_str()),
            ),
            (
                "runtime_installation_id",
                MachineValue::from(subject.runtime_installation_id().as_str()),
            ),
            (
                "selected_cells",
                MachineValue::Array(
                    plan.selected_cells()
                        .iter()
                        .map(|cell| MachineValue::from(cell.as_str()))
                        .collect(),
                ),
            ),
            (
                "target_contract_sha256",
                MachineValue::from(subject.target_contract_sha256().as_str()),
            ),
        ])),
    ))
}

// Presents an idempotent cleanup when no inactive benchmark evidence was reviewed.
fn benchmark_clean_inactive_output() -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![DisplayRecord::new(
            "Benchmarks",
            "No inactive benchmark data",
            None,
            DisplaySemantic::Muted,
        )])]),
        Some(MachineValue::object([
            ("cleaned", MachineValue::from(false)),
            ("reason", MachineValue::from("no_inactive_benchmark_data")),
        ])),
    )
}

// Presents either the sole active benchmark or an explicit inactive state.
fn benchmark_status_output(snapshot: Option<&NodeBenchmarkSnapshot>) -> CommandOutput {
    match snapshot {
        Some(snapshot) => benchmark_snapshot_output(snapshot),
        None => CommandOutput::new(
            CommandPresentation::new(vec![DisplayBlock::Records(vec![DisplayRecord::new(
                "Benchmark",
                "No active benchmark",
                None,
                DisplaySemantic::Muted,
            )])]),
            Some(MachineValue::object([
                ("active", MachineValue::from(false)),
                ("benchmark", MachineValue::Null),
            ])),
        ),
    }
}

// Presents explicit inactive community-verification state without conflating a local run.
fn verification_benchmark_inactive_output() -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![DisplayRecord::new(
            "Runtime verification",
            "No active verification",
            None,
            DisplaySemantic::Muted,
        )])]),
        Some(MachineValue::object([
            ("active", MachineValue::from(false)),
            ("benchmark", MachineValue::Null),
            ("kind", MachineValue::from("verification")),
        ])),
    )
}

// Presents one complete secret-free benchmark snapshot returned by NodeManager.
fn benchmark_snapshot_output(snapshot: &NodeBenchmarkSnapshot) -> CommandOutput {
    let phase = format!("{:?}", snapshot.phase()).to_ascii_lowercase();
    let progress_detail = snapshot.progress().map(|progress| {
        format!(
            "{} of {} cells",
            progress.completed_cells(),
            progress.total_cells()
        )
    });
    let mut records = vec![
        DisplayRecord::new(
            "Benchmark",
            snapshot.job_id().as_str(),
            None,
            DisplaySemantic::Information,
        ),
        DisplayRecord::new(
            "Model",
            snapshot.logical_model().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Phase",
            &phase,
            progress_detail,
            benchmark_phase_semantic(&phase),
        ),
    ];
    match snapshot.verification() {
        Some(verification) => {
            records.push(DisplayRecord::new(
                "Verification phase",
                verification.phase_name(),
                Some(format!("Handoff: {}", verification.handoff_phase_name())),
                if verification.recovery_required() {
                    DisplaySemantic::Error
                } else {
                    DisplaySemantic::Information
                },
            ));
            records.push(DisplayRecord::new(
                "Recovery",
                if verification.recovery_required() {
                    "Required"
                } else {
                    "Not required"
                },
                None,
                if verification.recovery_required() {
                    DisplaySemantic::Error
                } else {
                    DisplaySemantic::Success
                },
            ));
        }
        None => records.push(DisplayRecord::new(
            "Verification",
            "Not applicable",
            None,
            DisplaySemantic::Muted,
        )),
    }
    if let Some(failure) = snapshot.terminal_failure() {
        records.push(DisplayRecord::new(
            "Failure",
            failure.category().as_str(),
            Some(format!("Phase: {}", failure.phase().as_str())),
            DisplaySemantic::Error,
        ));
    }
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(records)]),
        Some(benchmark_snapshot_machine_value(snapshot, &phase)),
    )
}

// Projects one benchmark snapshot into deterministic machine-readable fields.
fn benchmark_snapshot_machine_value(snapshot: &NodeBenchmarkSnapshot, phase: &str) -> MachineValue {
    let progress = snapshot.progress().map_or(MachineValue::Null, |progress| {
        MachineValue::object([
            (
                "completed_cells",
                MachineValue::from(u64::from(progress.completed_cells())),
            ),
            ("phase", MachineValue::from(progress.phase().as_str())),
            (
                "total_cells",
                MachineValue::from(u64::from(progress.total_cells())),
            ),
        ])
    });
    let verification_phase = snapshot.verification().map_or(MachineValue::Null, |value| {
        MachineValue::from(value.phase_name())
    });
    let handoff_transaction_id = snapshot.verification().map_or(MachineValue::Null, |value| {
        MachineValue::from(value.handoff_transaction_id().as_str())
    });
    let handoff_phase = snapshot.verification().map_or(MachineValue::Null, |value| {
        MachineValue::from(value.handoff_phase_name())
    });
    let recovery_required = snapshot.verification().map_or(MachineValue::Null, |value| {
        MachineValue::from(value.recovery_required())
    });
    let terminal_failure_category = snapshot
        .terminal_failure()
        .map_or(MachineValue::Null, |failure| {
            MachineValue::from(failure.category().as_str())
        });
    let terminal_failure_phase = snapshot
        .terminal_failure()
        .map_or(MachineValue::Null, |failure| {
            MachineValue::from(failure.phase().as_str())
        });
    MachineValue::object([
        (
            "active",
            MachineValue::from(!snapshot.phase().is_terminal()),
        ),
        (
            "authorization_receipt_id",
            MachineValue::from(snapshot.authorization_receipt_id().as_str()),
        ),
        (
            "benchmark_contract_sha256",
            MachineValue::from(snapshot.benchmark_contract_sha256().as_str()),
        ),
        (
            "core_installation_id",
            MachineValue::from(snapshot.core_installation_id().as_str()),
        ),
        (
            "created_at_unix_milliseconds",
            MachineValue::from(snapshot.created_at().value()),
        ),
        (
            "disposition",
            snapshot
                .disposition()
                .map_or(MachineValue::Null, |disposition| {
                    MachineValue::from(format!("{disposition:?}").to_ascii_lowercase())
                }),
        ),
        (
            "evidence_id",
            snapshot
                .evidence_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        (
            "execution_sha256",
            MachineValue::from(snapshot.execution_sha256().as_str()),
        ),
        ("failure_category", terminal_failure_category),
        ("failure_phase", terminal_failure_phase),
        ("handoff_phase", handoff_phase),
        ("handoff_transaction_id", handoff_transaction_id),
        ("job_id", MachineValue::from(snapshot.job_id().as_str())),
        (
            "logical_model",
            MachineValue::from(snapshot.logical_model().as_str()),
        ),
        (
            "kind",
            MachineValue::from(if snapshot.is_verification() {
                "verification"
            } else {
                "local"
            }),
        ),
        ("phase", MachineValue::from(phase)),
        (
            "placement_group_id",
            MachineValue::from(snapshot.placement_group_id().as_str()),
        ),
        (
            "prepared_receipt_id",
            snapshot
                .prepared_receipt_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        ("progress", progress),
        ("recovery_required", recovery_required),
        (
            "request_sha256",
            MachineValue::from(snapshot.request_sha256().as_str()),
        ),
        (
            "restoration_receipt_id",
            snapshot
                .restoration_receipt_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        ("revision", MachineValue::from(snapshot.revision())),
        (
            "results_sha256",
            snapshot
                .results_sha256()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        (
            "running_receipt_id",
            snapshot
                .running_receipt_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        (
            "runtime_installation_id",
            MachineValue::from(snapshot.runtime_installation_id().as_str()),
        ),
        (
            "signature_key_id",
            snapshot
                .signature_key_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        (
            "target_contract_sha256",
            MachineValue::from(snapshot.target_contract_sha256().as_str()),
        ),
        (
            "telemetry_receipt_id",
            snapshot
                .telemetry_receipt_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        (
            "telemetry_sample_count",
            snapshot
                .telemetry_sample_count()
                .map_or(MachineValue::Null, MachineValue::from),
        ),
        (
            "updated_at_unix_milliseconds",
            MachineValue::from(snapshot.updated_at().value()),
        ),
        ("verification_phase", verification_phase),
    ])
}

// Selects stable benchmark lifecycle semantics from the closed private phase name.
const fn benchmark_phase_semantic(phase: &str) -> DisplaySemantic {
    match phase.as_bytes() {
        b"completed" => DisplaySemantic::Success,
        b"failed" => DisplaySemantic::Error,
        b"cancelled" => DisplaySemantic::Warning,
        b"requested" | b"prepared" | b"running" | b"stopping" | b"restoring" | b"finalizing" => {
            DisplaySemantic::Working
        }
        _ => DisplaySemantic::Muted,
    }
}

// Returns a stable failure when a stop request has no active benchmark target.
fn no_active_benchmark_failure() -> CommandFailure {
    failure(
        "benchmark.not_active",
        "There is no active benchmark to stop.",
    )
}

// Returns a stable failure when a verification stop cannot own the active local job.
fn no_active_verification_benchmark_failure() -> CommandFailure {
    failure(
        "benchmark.verification_not_active",
        "There is no active runtime verification to stop.",
    )
}

// Creates one stable invalid-benchmark-argument failure without copying rejected values.
fn invalid_benchmark_argument(message: &'static str) -> CommandFailure {
    failure("benchmark.invalid_argument", message)
}

// Requires explicit acknowledgement before inactive benchmark evidence is removed.
fn benchmark_confirmation_required_failure() -> CommandFailure {
    failure(
        "benchmark.confirmation_required",
        "Pass --yes to confirm benchmark cleanup.",
    )
}

// Returns one stable model desired-state presentation name.
const fn model_desired_state_name(state: ModelServiceDesiredState) -> &'static str {
    match state {
        ModelServiceDesiredState::Running => "running",
        ModelServiceDesiredState::Stopped => "stopped",
        ModelServiceDesiredState::Removed => "removed",
    }
}

// Returns one descriptive evidence-label presentation name.
const fn evidence_label_name(label: EvidenceLabel) -> &'static str {
    match label {
        EvidenceLabel::Qualified => "qualified",
        EvidenceLabel::Unqualified => "unqualified",
        EvidenceLabel::Unknown => "unknown",
    }
}

// Presents one controller without certificate or private-key material.
fn controller_output(controller: &NodeControllerSummary) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Controller",
                controller.name().as_str(),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Identity",
                controller.controller_id().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Role",
                controller.role().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "State",
                controller.state().as_str(),
                None,
                controller_state_semantic(controller.state()),
            ),
            DisplayRecord::new(
                "Certificate",
                controller.certificate_sha256().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
        ])]),
        Some(controller_machine_value(controller)),
    )
}

// Presents every controller in stable manager order without certificate documents.
fn controllers_output(
    controllers: Vec<NodeControllerSummary>,
) -> Result<CommandOutput, CommandFailure> {
    let rows = controllers
        .iter()
        .map(|controller| {
            vec![
                controller.controller_id().as_str().to_string(),
                controller.name().as_str().to_string(),
                controller.role().as_str().to_string(),
                controller.state().as_str().to_string(),
                controller.certificate_sha256().as_str().to_string(),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "CONTROLLER ID".to_string(),
            "NAME".to_string(),
            "ROLE".to_string(),
            "STATE".to_string(),
            "CERTIFICATE SHA-256".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::Array(
            controllers.iter().map(controller_machine_value).collect(),
        )),
    ))
}

// Projects one controller into deterministic secret-free CLI JSON.
fn controller_machine_value(controller: &NodeControllerSummary) -> MachineValue {
    MachineValue::object([
        (
            "activated_at_unix_milliseconds",
            controller
                .activated_at()
                .map_or(MachineValue::Null, |value| {
                    MachineValue::from(value.value())
                }),
        ),
        (
            "certificate_expires_at_unix_milliseconds",
            MachineValue::from(controller.certificate_expires_at().value()),
        ),
        (
            "certificate_sha256",
            MachineValue::from(controller.certificate_sha256().as_str()),
        ),
        (
            "certificate_valid_from_unix_milliseconds",
            MachineValue::from(controller.certificate_valid_from().value()),
        ),
        (
            "controller_id",
            MachineValue::from(controller.controller_id().as_str()),
        ),
        (
            "issued_at_unix_milliseconds",
            MachineValue::from(controller.issued_at().value()),
        ),
        ("name", MachineValue::from(controller.name().as_str())),
        (
            "public_key_sha256",
            MachineValue::from(controller.public_key_sha256().as_str()),
        ),
        ("role", MachineValue::from(controller.role().as_str())),
        ("state", MachineValue::from(controller.state().as_str())),
        (
            "revoked_at_unix_milliseconds",
            controller.revoked_at().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.value())
            }),
        ),
    ])
}

// Selects one stable semantic for each closed controller lifecycle state.
const fn controller_state_semantic(state: ControllerState) -> DisplaySemantic {
    match state {
        ControllerState::Issued => DisplaySemantic::Warning,
        ControllerState::Active => DisplaySemantic::Success,
        ControllerState::Revoked => DisplaySemantic::Muted,
    }
}

// Presents one issued token exactly once beside its durable public metadata.
fn issued_key_output(
    issued: &mut li_node_manager::NodeIssuedApiKey,
) -> Result<CommandOutput, CommandFailure> {
    let token = issued.take_token().ok_or_else(|| {
        failure(
            "authentication.secret_unavailable",
            "The one-time API-key token is unavailable.",
        )
    })?;
    let key = issued.api_key();
    let secret = OneTimeSecret::new(token);
    let presentation = CommandPresentation::new(vec![
        DisplayBlock::Records(vec![
            DisplayRecord::new(
                "API Key",
                key.name().as_str(),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Identity",
                key.key_id().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
        ]),
        DisplayBlock::Result {
            title: "This token is shown once".to_string(),
            detail: Some("Store it securely now".to_string()),
            semantic: DisplaySemantic::Warning,
        },
        DisplayBlock::OneTimeSecret {
            label: Some("Token".to_string()),
            value: secret.clone(),
        },
    ]);
    Ok(CommandOutput::new(
        presentation,
        Some(MachineValue::object([
            ("key", api_key_machine_value(key)),
            ("token", MachineValue::OneTimeSecret(secret)),
            ("token_shown_once", MachineValue::from(true)),
        ])),
    )
    .without_completion())
}

// Presents one API-key detail without verifier or bearer material.
fn api_key_output(key: &ApiKey) -> CommandOutput {
    let state = api_key_state(key);
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Records(vec![
            DisplayRecord::new(
                "API Key",
                key.name().as_str(),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Identity",
                key.key_id().as_str(),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "State",
                state,
                None,
                if state == "active" {
                    DisplaySemantic::Success
                } else {
                    DisplaySemantic::Muted
                },
            ),
            DisplayRecord::new("Models", api_key_models(key), None, DisplaySemantic::Muted),
        ])]),
        Some(api_key_machine_value(key)),
    )
}

// Presents every API key in stable manager order.
fn api_keys_output(keys: Vec<ApiKey>) -> Result<CommandOutput, CommandFailure> {
    let rows = keys
        .iter()
        .map(|key| {
            vec![
                key.key_id().as_str().to_string(),
                key.name().as_str().to_string(),
                api_key_state(key).to_string(),
                api_key_models(key),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "KEY ID".to_string(),
            "NAME".to_string(),
            "STATE".to_string(),
            "MODELS".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(MachineValue::Array(
            keys.iter().map(api_key_machine_value).collect(),
        )),
    ))
}

// Projects one non-secret API-key snapshot into deterministic CLI JSON.
fn api_key_machine_value(key: &ApiKey) -> MachineValue {
    let policy = key.policy();
    let limits = policy.limits();
    MachineValue::object([
        ("application", optional_name(policy.application())),
        ("concurrency", optional_u32(limits.concurrency())),
        ("context_tokens", optional_u64(limits.context_tokens())),
        (
            "created_at_unix_milliseconds",
            MachineValue::from(key.created_at().value()),
        ),
        (
            "expires_at_unix_milliseconds",
            policy.expires_at().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.value())
            }),
        ),
        ("key_id", MachineValue::from(key.key_id().as_str())),
        (
            "models",
            policy.model_scope().selected_models().map_or_else(
                || MachineValue::Array(Vec::new()),
                |models| {
                    MachineValue::Array(
                        models
                            .iter()
                            .map(|model| MachineValue::from(model.as_str()))
                            .collect(),
                    )
                },
            ),
        ),
        ("name", MachineValue::from(key.name().as_str())),
        (
            "requests_per_minute",
            optional_u32(limits.requests_per_minute()),
        ),
        (
            "revoked_at_unix_milliseconds",
            key.revoked_at().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.value())
            }),
        ),
        (
            "rotated_from",
            key.rotated_from().map_or(MachineValue::Null, |value| {
                MachineValue::from(value.as_str())
            }),
        ),
        ("state", MachineValue::from(api_key_state(key))),
        ("tenant", optional_name(policy.tenant())),
        (
            "tokens_per_minute",
            optional_u64(limits.tokens_per_minute()),
        ),
    ])
}

// Returns one human-readable model-scope summary.
fn api_key_models(key: &ApiKey) -> String {
    key.policy()
        .model_scope()
        .selected_models()
        .map(|models| {
            models
                .iter()
                .map(LogicalModelName::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "all".to_string())
}

// Returns one stable lifecycle state without evaluating current expiry time.
const fn api_key_state(key: &ApiKey) -> &'static str {
    if key.revoked_at().is_some() {
        "revoked"
    } else {
        "active"
    }
}

// Projects one optional u32 policy limit into JSON.
fn optional_u32(value: Option<NonZeroU32>) -> MachineValue {
    value.map_or(MachineValue::Null, |value| {
        MachineValue::from(u64::from(value.get()))
    })
}

// Projects one optional u64 policy limit into JSON.
fn optional_u64(value: Option<NonZeroU64>) -> MachineValue {
    value.map_or(MachineValue::Null, |value| MachineValue::from(value.get()))
}

// Projects one optional technical label into JSON.
fn optional_name(value: Option<&TechnicalName>) -> MachineValue {
    value.map_or(MachineValue::Null, |value| {
        MachineValue::from(value.as_str())
    })
}

// Selects one exact identity or globally unambiguous display name from a bounded Node response.
fn selected_node(nodes: Vec<Node>, selector: &str) -> Result<Node, CommandFailure> {
    let mut matches = nodes.into_iter().filter(|node| {
        node.identity().node_id().as_str() == selector || node.display_name().as_str() == selector
    });
    let Some(node) = matches.next() else {
        return Err(failure(
            "node.not_found",
            "No node matches the requested identity or name.",
        ));
    };
    if matches.next().is_some() {
        return Err(failure(
            "node.ambiguous",
            "More than one node matches the requested name; use its exact identity.",
        ));
    }
    Ok(node)
}

// Parses one unique nonempty CLI selection from the closed reclaimable category vocabulary.
fn storage_categories(values: &[String]) -> Result<BTreeSet<NodeStorageCategory>, CommandFailure> {
    if values.is_empty() {
        return Err(invalid_node_argument(
            "At least one storage category is required.",
        ));
    }
    let mut categories = BTreeSet::new();
    for value in values {
        let category = NodeStorageCategory::parse(value)
            .map_err(|_| invalid_node_argument("The storage category is invalid."))?;
        if !category.is_reclaimable() || !categories.insert(category) {
            return Err(invalid_node_argument(
                "Storage categories must be unique and reclaimable.",
            ));
        }
    }
    Ok(categories)
}

// Derives one replay identity from the exact reviewed plan and ordered category selection.
fn storage_cleanup_operation_id(
    snapshot: &NodeStorageSnapshot,
    categories: &BTreeSet<NodeStorageCategory>,
) -> Result<OperationId, CommandFailure> {
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_storage_cleanup_v1\0");
    hasher.update(snapshot.plan_digest().as_str().as_bytes());
    for category in categories {
        hasher.update(b"\0");
        hasher.update(category.as_str().as_bytes());
    }
    let digest = digest_hex(&hasher.finalize());
    OperationId::parse(&digest[..32])
        .map_err(|_| invalid_node_argument("The storage cleanup identity is invalid."))
}

// Creates stable human and machine projections for one reviewed local storage snapshot.
fn node_storage_output(snapshot: &NodeStorageSnapshot) -> Result<CommandOutput, CommandFailure> {
    let allocated_bytes = snapshot
        .usage()
        .iter()
        .try_fold(0_u64, |total, usage| {
            total.checked_add(usage.allocated_bytes())
        })
        .ok_or_else(invalid_response_failure)?;
    let reclaimable_bytes = snapshot
        .usage()
        .iter()
        .try_fold(0_u64, |total, usage| {
            total.checked_add(usage.reclaimable_bytes())
        })
        .ok_or_else(invalid_response_failure)?;
    let usage_rows = snapshot
        .usage()
        .iter()
        .map(|usage| {
            vec![
                usage.category().as_str().to_string(),
                usage.allocated_bytes().to_string(),
                usage.logical_bytes().to_string(),
                usage.files().to_string(),
                usage.reclaimable_bytes().to_string(),
            ]
        })
        .collect();
    let usage_table = DisplayTable::new(
        vec![
            "CATEGORY".to_string(),
            "ALLOCATED BYTES".to_string(),
            "LOGICAL BYTES".to_string(),
            "FILES".to_string(),
            "RECLAIMABLE BYTES".to_string(),
        ],
        usage_rows,
    )
    .map_err(|_| invalid_response_failure())?;
    let mut blocks = vec![
        DisplayBlock::Records(vec![
            DisplayRecord::new(
                "Capacity",
                format!("{} bytes", snapshot.capacity_bytes()),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Available",
                format!("{} bytes", snapshot.available_bytes()),
                None,
                DisplaySemantic::Information,
            ),
            DisplayRecord::new(
                "Let's Infer",
                format!("{allocated_bytes} bytes"),
                None,
                DisplaySemantic::Muted,
            ),
            DisplayRecord::new(
                "Reclaimable",
                format!("{reclaimable_bytes} bytes"),
                None,
                if reclaimable_bytes == 0 {
                    DisplaySemantic::Muted
                } else {
                    DisplaySemantic::Information
                },
            ),
        ]),
        DisplayBlock::Table(usage_table),
    ];
    if !snapshot.candidates().is_empty() {
        let candidate_rows = snapshot
            .candidates()
            .iter()
            .map(|candidate| {
                vec![
                    candidate.category().as_str().to_string(),
                    candidate.relative_path().to_string(),
                    candidate.allocated_bytes().to_string(),
                    candidate.reason().to_string(),
                ]
            })
            .collect();
        blocks.push(DisplayBlock::Table(
            DisplayTable::new(
                vec![
                    "CATEGORY".to_string(),
                    "RELATIVE PATH".to_string(),
                    "BYTES".to_string(),
                    "REASON".to_string(),
                ],
                candidate_rows,
            )
            .map_err(|_| invalid_response_failure())?,
        ));
    }
    Ok(CommandOutput::new(
        CommandPresentation::new(blocks),
        Some(storage_snapshot_machine_value(snapshot)),
    ))
}

// Projects one storage snapshot into deterministic JSON without private absolute paths.
fn storage_snapshot_machine_value(snapshot: &NodeStorageSnapshot) -> MachineValue {
    MachineValue::object([
        (
            "available_bytes",
            MachineValue::from(snapshot.available_bytes()),
        ),
        (
            "candidates",
            MachineValue::Array(
                snapshot
                    .candidates()
                    .iter()
                    .map(|candidate| {
                        MachineValue::object([
                            (
                                "allocated_bytes",
                                MachineValue::from(candidate.allocated_bytes()),
                            ),
                            (
                                "category",
                                MachineValue::from(candidate.category().as_str()),
                            ),
                            (
                                "models",
                                MachineValue::Array(
                                    candidate
                                        .models()
                                        .iter()
                                        .map(|model| MachineValue::from(model.as_str()))
                                        .collect(),
                                ),
                            ),
                            ("reason", MachineValue::from(candidate.reason())),
                            (
                                "relative_path",
                                MachineValue::from(candidate.relative_path()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "capacity_bytes",
            MachineValue::from(snapshot.capacity_bytes()),
        ),
        (
            "plan_sha256",
            MachineValue::from(snapshot.plan_digest().as_str()),
        ),
        (
            "usage",
            MachineValue::Array(
                snapshot
                    .usage()
                    .iter()
                    .map(|usage| {
                        MachineValue::object([
                            (
                                "allocated_bytes",
                                MachineValue::from(usage.allocated_bytes()),
                            ),
                            ("category", MachineValue::from(usage.category().as_str())),
                            ("files", MachineValue::from(usage.files())),
                            ("logical_bytes", MachineValue::from(usage.logical_bytes())),
                            (
                                "reclaimable_bytes",
                                MachineValue::from(usage.reclaimable_bytes()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

// Creates stable human and machine projections for one durable cleanup receipt.
fn storage_clean_output(
    receipt: &NodeStorageCleanReceipt,
) -> Result<CommandOutput, CommandFailure> {
    let models = receipt
        .models_to_download()
        .iter()
        .map(|model| model.as_str().to_string())
        .collect::<Vec<_>>();
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Result {
            title: if receipt.replayed() {
                "Storage cleanup already applied".to_string()
            } else {
                "Storage cleaned".to_string()
            },
            detail: Some(format!(
                "Removed {} reviewed targets representing {} bytes",
                receipt.removed_targets(),
                receipt.reclaimed_bytes()
            )),
            semantic: DisplaySemantic::Success,
        }]),
        Some(MachineValue::object([
            (
                "models_to_download",
                MachineValue::Array(models.into_iter().map(MachineValue::from).collect()),
            ),
            (
                "operation_id",
                MachineValue::from(receipt.operation_id().as_str()),
            ),
            (
                "plan_sha256",
                MachineValue::from(receipt.plan_digest().as_str()),
            ),
            (
                "reclaimed_bytes",
                MachineValue::from(receipt.reclaimed_bytes()),
            ),
            (
                "removed_targets",
                MachineValue::from(receipt.removed_targets()),
            ),
            ("replayed", MachineValue::from(receipt.replayed())),
        ])),
    ))
}

// Creates the detail and deterministic machine projections for one immutable Node snapshot.
fn node_output(node: &Node) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![node_records(node)]),
        Some(node_machine_value(node)),
    )
}

// Creates the detailed host result from one exact manager-owned read model.
fn node_host_output(host: &NodeHostSnapshot) -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![node_host_records(host)]),
        Some(host_snapshot_machine_value(host)),
    )
}

// Presents one opened invitation and transfers its setup code exactly once.
fn pairing_invitation_output(
    invitation: &mut NodePairingInvitation,
    endpoint: &NativeNodePairingEndpoint,
) -> Result<CommandOutput, CommandFailure> {
    let mut blocks = vec![DisplayBlock::Records(vec![
        DisplayRecord::new(
            "Invitation",
            invitation.invite_id().as_str(),
            None,
            DisplaySemantic::Information,
        ),
        DisplayRecord::new(
            "Mode",
            pairing_mode_name(invitation.mode()),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Address",
            endpoint.address().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Port",
            endpoint.port().to_string(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Certificate SHA256",
            endpoint.certificate_sha256().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Expires",
            invitation.expires_at().value().to_string(),
            Some("Unix milliseconds".to_string()),
            DisplaySemantic::Muted,
        ),
    ])];
    let setup_code = invitation
        .setup_code()
        .map(|value| OneTimeSecret::new(value.to_string()));
    if let Some(secret) = setup_code.as_ref() {
        blocks.push(DisplayBlock::Result {
            title: "This setup code is shown once".to_string(),
            detail: Some("Share it through a separate trusted channel".to_string()),
            semantic: DisplaySemantic::Warning,
        });
        blocks.push(DisplayBlock::OneTimeSecret {
            label: Some("Setup code".to_string()),
            value: secret.clone(),
        });
    }
    Ok(CommandOutput::new(
        CommandPresentation::new(blocks),
        Some(MachineValue::object([
            ("address", MachineValue::from(endpoint.address().as_str())),
            (
                "certificate_sha256",
                MachineValue::from(endpoint.certificate_sha256().as_str()),
            ),
            (
                "expires_at_unix_milliseconds",
                MachineValue::from(invitation.expires_at().value()),
            ),
            (
                "invitation_id",
                MachineValue::from(invitation.invite_id().as_str()),
            ),
            (
                "mode",
                MachineValue::from(pairing_mode_name(invitation.mode())),
            ),
            ("port", MachineValue::from(u64::from(endpoint.port()))),
            (
                "setup_code",
                setup_code.map_or(MachineValue::Null, MachineValue::OneTimeSecret),
            ),
            (
                "setup_code_shown_once",
                MachineValue::from(invitation.setup_code().is_some()),
            ),
        ])),
    )
    .without_completion())
}

// Presents one main-owned pairing state and transfers a comparison code exactly once.
fn pairing_status_output(status: &NodePairingStatus) -> Result<CommandOutput, CommandFailure> {
    let mut blocks = vec![DisplayBlock::Records(vec![
        DisplayRecord::new(
            "Invitation",
            status.invite_id().as_str(),
            None,
            DisplaySemantic::Information,
        ),
        DisplayRecord::new(
            "State",
            pairing_state_name(status.state()),
            None,
            pairing_state_semantic(status.state()),
        ),
        DisplayRecord::new(
            "Mode",
            pairing_mode_name(status.mode()),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Child",
            status
                .child_node_id()
                .map_or("Not enrolled", NodeId::as_str),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Expires",
            status.expires_at().value().to_string(),
            Some("Unix milliseconds".to_string()),
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Rejected attempts",
            status.attempts().to_string(),
            None,
            DisplaySemantic::Muted,
        ),
    ])];
    let comparison_code = status
        .comparison_code()
        .map(|value| OneTimeSecret::new(value.to_string()));
    if let Some(secret) = comparison_code.as_ref() {
        blocks.push(DisplayBlock::Result {
            title: "Verify this code on the child before approving".to_string(),
            detail: None,
            semantic: DisplaySemantic::Warning,
        });
        blocks.push(DisplayBlock::OneTimeSecret {
            label: Some("Comparison code".to_string()),
            value: secret.clone(),
        });
    }
    Ok(CommandOutput::new(
        CommandPresentation::new(blocks),
        Some(MachineValue::object([
            ("attempts", MachineValue::from(u64::from(status.attempts()))),
            (
                "child_node_id",
                status.child_node_id().map_or(MachineValue::Null, |value| {
                    MachineValue::from(value.as_str())
                }),
            ),
            (
                "comparison_code",
                comparison_code.map_or(MachineValue::Null, MachineValue::OneTimeSecret),
            ),
            (
                "comparison_code_shown_once",
                MachineValue::from(status.comparison_code().is_some()),
            ),
            (
                "expires_at_unix_milliseconds",
                MachineValue::from(status.expires_at().value()),
            ),
            (
                "invitation_id",
                MachineValue::from(status.invite_id().as_str()),
            ),
            ("mode", MachineValue::from(pairing_mode_name(status.mode()))),
            (
                "state",
                MachineValue::from(pairing_state_name(status.state())),
            ),
        ])),
    )
    .without_completion())
}

// Returns the stable presentation name for one closed pairing authorization mode.
const fn pairing_mode_name(mode: &NodePairingMode) -> &'static str {
    match mode {
        NodePairingMode::Lan => "lan",
        NodePairingMode::Remote => "remote",
        NodePairingMode::ConnectX { .. } => "connectx",
    }
}

// Returns the stable presentation name for one durable pairing lifecycle state.
const fn pairing_state_name(state: NodePairingState) -> &'static str {
    match state {
        NodePairingState::Open => "open",
        NodePairingState::PendingApproval => "pending_approval",
        NodePairingState::Active => "active",
    }
}

// Selects one stable display semantic for each durable pairing lifecycle state.
const fn pairing_state_semantic(state: NodePairingState) -> DisplaySemantic {
    match state {
        NodePairingState::Open => DisplaySemantic::Information,
        NodePairingState::PendingApproval => DisplaySemantic::Warning,
        NodePairingState::Active => DisplaySemantic::Success,
    }
}

// Creates the stable human node record shared by mutation and pairing results.
fn node_records(node: &Node) -> DisplayBlock {
    DisplayBlock::Records(vec![
        DisplayRecord::new(
            "Node",
            node.display_name().as_str(),
            None,
            DisplaySemantic::Information,
        ),
        DisplayRecord::new(
            "Role",
            node_role_name(node.role()),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "State",
            node_state_name(node.state()),
            None,
            node_state_semantic(node.state()),
        ),
        DisplayRecord::new(
            "Address",
            node.control_address().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Identity",
            node.identity().node_id().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
    ])
}

// Creates one detailed host record while preserving unavailable and inapplicable sections.
fn node_host_records(host: &NodeHostSnapshot) -> DisplayBlock {
    let processor = host
        .hardware()
        .available()
        .map_or("Unavailable", |hardware| {
            hardware.processor().model().as_str()
        });
    DisplayBlock::Records(vec![
        DisplayRecord::new(
            "Node",
            host.node().display_name().as_str(),
            None,
            DisplaySemantic::Information,
        ),
        DisplayRecord::new(
            "Role",
            node_role_name(host.node().role()),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "State",
            node_state_name(host.node().state()),
            None,
            node_state_semantic(host.node().state()),
        ),
        DisplayRecord::new(
            "Address",
            host.node().control_address().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Identity",
            host.node().identity().node_id().as_str(),
            None,
            DisplaySemantic::Muted,
        ),
        DisplayRecord::new(
            "Processor",
            processor,
            None,
            if host.hardware().available().is_some() {
                DisplaySemantic::Information
            } else {
                DisplaySemantic::Warning
            },
        ),
        DisplayRecord::new(
            "Placement groups",
            projection_count(host.placement_groups()),
            None,
            projection_semantic(host.placement_groups()),
        ),
        DisplayRecord::new(
            "Verified links",
            projection_count(host.verified_links()),
            None,
            projection_semantic(host.verified_links()),
        ),
        DisplayRecord::new(
            "Gateway",
            service_projection_name(host.gateway()),
            None,
            service_projection_semantic(host.gateway()),
        ),
        DisplayRecord::new(
            "Watchdog",
            service_projection_name(host.watchdog()),
            None,
            service_projection_semantic(host.watchdog()),
        ),
    ])
}

// Selects the local host or one exact globally unambiguous identity or display name.
fn selected_host<'a>(
    inventory: &'a NodeHostInventory,
    selector: Option<&str>,
) -> Result<&'a NodeHostSnapshot, CommandFailure> {
    let Some(selector) = selector else {
        return inventory.local_host().ok_or_else(invalid_response_failure);
    };
    let mut matches = inventory.hosts().iter().filter(|host| {
        host.node().identity().node_id().as_str() == selector
            || host.node().display_name().as_str() == selector
    });
    let Some(host) = matches.next() else {
        return Err(failure(
            "node.not_found",
            "No node matches the requested identity or name.",
        ));
    };
    if matches.next().is_some() {
        return Err(failure(
            "node.ambiguous",
            "More than one node matches the requested name; use its exact identity.",
        ));
    }
    Ok(host)
}

// Creates one catalog-aware node result from RuntimeManager-judged compatible targets.
fn node_host_catalog_output(
    host: &NodeHostSnapshot,
    mut targets: Vec<NodeCatalogTarget>,
) -> Result<CommandOutput, CommandFailure> {
    targets.sort_by(|left, right| {
        (
            left.logical_model().as_str(),
            left.target_id().as_str(),
            left.candidate_id().as_str(),
        )
            .cmp(&(
                right.logical_model().as_str(),
                right.target_id().as_str(),
                right.candidate_id().as_str(),
            ))
    });
    let rows = targets
        .iter()
        .map(|target| {
            vec![
                target.logical_model().as_str().to_string(),
                target.target_id().as_str().to_string(),
                target.candidate_id().as_str().to_string(),
                if target.is_recommended() { "yes" } else { "no" }.to_string(),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "MODEL".to_string(),
            "TARGET".to_string(),
            "RUNTIME".to_string(),
            "RECOMMENDED".to_string(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    let compatible_targets = MachineValue::Array(
        targets
            .iter()
            .map(|target| {
                MachineValue::object([
                    (
                        "candidate_id",
                        MachineValue::from(target.candidate_id().as_str()),
                    ),
                    (
                        "logical_model",
                        MachineValue::from(target.logical_model().as_str()),
                    ),
                    ("recommended", MachineValue::from(target.is_recommended())),
                    ("target_id", MachineValue::from(target.target_id().as_str())),
                ])
            })
            .collect(),
    );
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![node_host_records(host), DisplayBlock::Table(table)]),
        Some(MachineValue::object([
            ("compatible_targets", compatible_targets),
            ("host", host_snapshot_machine_value(host)),
        ])),
    ))
}

// Creates stable table and typed machine projections for every returned host.
fn nodes_output(inventory: NodeHostInventory) -> Result<CommandOutput, CommandFailure> {
    let rows = inventory
        .hosts()
        .iter()
        .map(|host| {
            vec![
                host.node().display_name().as_str().to_owned(),
                node_role_name(host.node().role()).to_owned(),
                node_state_name(host.node().state()).to_owned(),
                host.node().control_address().as_str().to_owned(),
                projection_count(host.placement_groups()),
                service_projection_name(host.gateway()),
            ]
        })
        .collect();
    let table = DisplayTable::new(
        vec![
            "NODE".to_owned(),
            "ROLE".to_owned(),
            "STATE".to_owned(),
            "ADDRESS".to_owned(),
            "GROUPS".to_owned(),
            "GATEWAY".to_owned(),
        ],
        rows,
    )
    .map_err(|_| invalid_response_failure())?;
    let machine = MachineValue::Array(
        inventory
            .hosts()
            .iter()
            .map(host_snapshot_machine_value)
            .collect(),
    );
    Ok(CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Table(table)]),
        Some(machine),
    ))
}

// Projects one immutable Node into the stable JSON object owned by this CLI adapter.
fn node_machine_value(node: &Node) -> MachineValue {
    MachineValue::object([
        (
            "address",
            MachineValue::from(node.control_address().as_str()),
        ),
        (
            "display_name",
            MachineValue::from(node.display_name().as_str()),
        ),
        (
            "hardware_observation_id",
            node.latest_hardware_observation_id()
                .map_or(MachineValue::Null, |identity| {
                    MachineValue::from(identity.as_str())
                }),
        ),
        (
            "installation_id",
            MachineValue::from(node.identity().installation_id().as_str()),
        ),
        (
            "machine_id",
            MachineValue::from(node.identity().machine_id().as_str()),
        ),
        (
            "node_id",
            MachineValue::from(node.identity().node_id().as_str()),
        ),
        ("role", MachineValue::from(node_role_name(node.role()))),
        ("state", MachineValue::from(node_state_name(node.state()))),
        (
            "timestamps",
            MachineValue::object([
                (
                    "created_at_unix_milliseconds",
                    MachineValue::from(node.timestamps().created_at().value()),
                ),
                (
                    "updated_at_unix_milliseconds",
                    MachineValue::from(node.timestamps().updated_at().value()),
                ),
            ]),
        ),
    ])
}

// Returns the stable lowercase wire-compatible role name used in CLI JSON.
const fn node_role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "main",
        NodeRole::Child => "child",
    }
}

// Returns the stable lowercase wire-compatible state name used in CLI JSON.
const fn node_state_name(state: NodeState) -> &'static str {
    match state {
        NodeState::Pending => "pending",
        NodeState::Active => "active",
        NodeState::Draining => "draining",
        NodeState::Offline => "offline",
        NodeState::Removed => "removed",
    }
}

// Selects terminal semantics without changing the authoritative Node state.
const fn node_state_semantic(state: NodeState) -> DisplaySemantic {
    match state {
        NodeState::Active => DisplaySemantic::Success,
        NodeState::Pending | NodeState::Draining => DisplaySemantic::Working,
        NodeState::Offline => DisplaySemantic::Warning,
        NodeState::Removed => DisplaySemantic::Muted,
    }
}

// Returns the stable context error identity for one already-redacted client failure.
const fn context_error_code(error: &NodePrivateClientError) -> &'static str {
    match error {
        NodePrivateClientError::NotConfigured => "cli.node_not_configured",
        NodePrivateClientError::TimedOut => "cli.node_timeout",
        NodePrivateClientError::Unavailable => "cli.node_unavailable",
        NodePrivateClientError::RequestTooLarge => "cli.node_request_oversized",
        NodePrivateClientError::ResponseTooLarge => "cli.node_response_oversized",
        NodePrivateClientError::IdentityUnavailable => "cli.node_identity_unavailable",
        NodePrivateClientError::MalformedResponse => "cli.node_response_malformed",
        NodePrivateClientError::MismatchedResponse => "cli.node_response_mismatched",
        NodePrivateClientError::RemoteRejected { .. } => "cli.node_request_rejected",
    }
}

// Converts one already-redacted client failure into the stable CLI failure contract.
fn client_failure(error: NodePrivateClientError) -> CommandFailure {
    failure(context_error_code(&error), &error.to_string())
}

// Returns the fixed failure used when process-local shared client access is violated.
fn client_busy_failure() -> CommandFailure {
    failure(
        "cli.node_client_busy",
        "The private Node client is already in use.",
    )
}

// Returns the fixed failure used when the endpoint violates its typed response contract.
fn invalid_response_failure() -> CommandFailure {
    failure(
        "cli.node_response_invalid",
        "The private Node endpoint returned an unexpected response.",
    )
}

// Returns one explicit cancellation after a bounded live log reader is asked to stop.
fn model_logs_cancelled_failure() -> CommandFailure {
    CommandFailure::new(
        CommandFailureKind::Cancelled,
        "model.logs_cancelled",
        "Model log following was cancelled.",
    )
    .expect("source-owned model log cancellation satisfies the closed contract")
}

// Returns one stable audit argument failure without echoing a rejected selector.
fn invalid_audit_argument(message: &'static str) -> CommandFailure {
    failure("audit.invalid_argument", message)
}

// Returns one redacted native audit-export persistence failure.
fn audit_export_file_failure() -> CommandFailure {
    failure(
        "audit.export_file_unavailable",
        "The audit export could not be written to the selected file.",
    )
}

// Returns the explicit blocker for a command absent from the current private Node schema.
fn unavailable_action_failure(action: &str) -> CommandFailure {
    failure(
        "cli.node_action_unavailable",
        &format!(
            "{action} is not represented by li_node_private_api version 2; native Node composition is incomplete."
        ),
    )
}

// Requires an explicit non-interactive acknowledgement before target discovery begins.
fn uninstall_confirmation_failure() -> CommandFailure {
    CommandFailure::new(
        CommandFailureKind::Denied,
        "uninstall.confirmation_required",
        "Uninstall requires --yes because managed data will be removed.",
    )
    .expect("static uninstall confirmation failure")
}

// Creates one fixed validated CLI failure from source-owned safe text.
fn failure(code: &str, message: &str) -> CommandFailure {
    CommandFailure::new(CommandFailureKind::Failed, code, message)
        .expect("source-owned Node CLI failures satisfy the closed contract")
}
