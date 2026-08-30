// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditCorrelationId, AuditEvent,
    AuditEventId, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditTarget,
    AuditUnixNanoseconds,
};
use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, ControllerPublicKey, ControllerRole,
    ControllerState,
};
use li_benchmark_manager::{
    BenchmarkDisposition, BenchmarkFailureCategory, BenchmarkGitRevision, BenchmarkJobPhase,
    BenchmarkKind, BenchmarkRequest, BenchmarkScope, BenchmarkSubject, BenchmarkVerificationPhase,
};
use li_core_cli::{
    compose_system_native_node_cli, CliExitCode, CommandAuditError, CommandAuditIntent,
    CommandAuditMarker, CommandAuditPort, CommandAuditResult, CommandFailure, CommandFailureKind,
    CommandParser, CommandProgressEvent, CommandProgressPort, CoreCommandCapabilities,
    ModelCommand, NativeControllerEnrollmentCommitPort, NativeControllerEnrollmentPort,
    NativeNodeCliCapabilities, NativeNodeCliProcess, NativeNodeCommandClock,
    NativeNodeCommandClockError, NativeNodePairingEndpoint, NativeNodePairingJoinRequest,
    NativeNodePairingJoinSource, NativeNodePairingMode, NativeNodePairingPort,
    NativeUninstallModelDisposition, NativeUninstallPort, NativeUninstallReceipt,
    NodePrivateClient, NodePrivateClientConfiguration, NodePrivateDocumentExchangeError,
    NodePrivateDocumentExchangePort, NodeRequestIdentityError, NodeRequestIdentitySource,
};
use li_core_interface::{
    Accelerator, AcceleratorDriver, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor,
    ApiKeyId, BootId, ByteCount, ComputeCapability, ControllerId, CpuArchitecture, DeviceId,
    DisplayName, EndpointOwnership, EntityTimestamps, EvidenceLabel, HardwareObservation,
    HardwareObservationId, InstallationId, InterconnectKind, InterconnectObservation,
    InterconnectObservationKind, LogicalModelName, MachineId, MemoryTopology,
    ModelServiceDesiredState, ModelServiceId, NetworkInterfaceName, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, OperatingSystem, OperationId, PairingInviteId,
    PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources, PlacementState,
    PlatformIdentity, PortRange, ProcessorObservation, RuntimeCandidateId, RuntimeInstallationId,
    RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TaskId, TechnicalName, UnixMilliseconds,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateDisposition, CoreUpdatePhase, CoreVersion,
};
use li_gateway_manager::{GatewayExposure, GatewayExposureStatus};
use li_node_manager::{
    NodeAuditExport, NodeAuditVerification, NodeBenchmarkCandidateHandoffPhase,
    NodeBenchmarkContext, NodeBenchmarkPlan, NodeBenchmarkSelection, NodeBenchmarkSnapshot,
    NodeBenchmarkSnapshotProgress, NodeBenchmarkTerminalFailure,
    NodeBenchmarkVerificationProjection, NodeCatalogAuthor, NodeCatalogAuthorKind,
    NodeCatalogEntry, NodeCatalogListRequest, NodeCatalogListing, NodeCatalogRefreshPolicy,
    NodeCatalogSnapshot, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection, NodeCommandAuditCompletionDisposition,
    NodeCommandAuditCompletionReceipt, NodeCommandAuditMarker, NodeCommandAuditOpenDisposition,
    NodeCommandAuditOpenReceipt, NodeCommandAuditOutcome, NodeControllerEnrollmentCandidate,
    NodeControllerEnrollmentReceipt, NodeControllerSummary, NodeCoreUpdateCheck,
    NodeCoreUpdateSummary, NodeHostGatewaySummary, NodeHostGatewayTelemetrySummary,
    NodeHostInventory, NodeHostPlacementGroupSnapshot, NodeHostPlacementSnapshot,
    NodeHostProjectionValue, NodeHostProtectionState, NodeHostProtectionSummary,
    NodeHostServiceState, NodeHostSnapshot, NodeHostWatchdogSummary,
    NodeHostWatchdogTelemetrySummary, NodeIssuedApiKey, NodeModelAction, NodeModelCommandSummary,
    NodeModelJournalState, NodeModelRollbackGroupPreview, NodeModelRollbackPreview,
    NodeModelRollbackRuntime, NodeModelRuntimeLogBatch, NodeModelServiceSummary,
    NodeModelUpdateDisposition, NodeModelUpdateSummary, NodePairingInvitation, NodePairingMode,
    NodePairingState, NodePairingStatus, NodePrivateRemoteError, NodePrivateRequest,
    NodePrivateResponse, NodePrivateTransport, NodePrivateTransportOutcome,
    NodePrivateTransportResponse, NodeStorageCandidate, NodeStorageCategory,
    NodeStorageCleanReceipt, NodeStorageSnapshot, NodeStorageUsage, NodeTransition,
};
use li_placement_manager::{PlacementLink, PlacementLogBatch, PlacementLogCursor};
use sha2::{Digest, Sha256};

// Returns exact queued request identities for deterministic process tests.
struct IdentityMock {
    values: VecDeque<Sha256Digest>,
}

impl IdentityMock {
    // Creates enough stable identities for one bounded process invocation.
    fn new() -> Self {
        Self {
            values: ['a', 'b', 'c', 'd', 'e', 'f', '1', '2']
                .into_iter()
                .map(digest)
                .collect(),
        }
    }
}

// Returns one fixed wall-clock value for deterministic node mutation tests.
struct ClockMock;

impl NativeNodeCommandClock for ClockMock {
    // Returns the exact timestamp expected by transition request assertions.
    fn now(&self) -> Result<UnixMilliseconds, NativeNodeCommandClockError> {
        Ok(UnixMilliseconds::new(3_000))
    }
}

// Captures opaque live bytes and cancels after an exact number of nonempty batches.
struct CancellingProgress {
    outputs: Vec<Vec<u8>>,
    cancellation_after: usize,
}

impl CommandProgressPort for CancellingProgress {
    // Records only runtime byte events emitted by the model log command.
    fn report(&mut self, event: CommandProgressEvent) {
        if let CommandProgressEvent::Output(value) = event {
            self.outputs.push(value);
        }
    }

    // Stops the next bounded provider request after the selected output count.
    fn is_cancelled(&self) -> bool {
        self.outputs.len() >= self.cancellation_after
    }
}

impl NodeRequestIdentitySource for IdentityMock {
    // Returns the next deterministic request identity.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError> {
        self.values
            .pop_front()
            .ok_or(NodeRequestIdentityError::Unavailable)
    }
}

// Runs ordered typed responses through the real Node codec and records request routing.
struct LoopbackExchange {
    responses: VecDeque<NodePrivateResponse>,
    requests: Rc<RefCell<Vec<NodePrivateRequest>>>,
}

// Serves one complete versioned child transition through the real private codec.
struct NodeTransitionExchange {
    local: Node,
    before: Node,
    after: Node,
    requests: Rc<RefCell<Vec<NodePrivateRequest>>>,
}

impl NodePrivateDocumentExchangePort for NodeTransitionExchange {
    // Returns typed reads and exact wire-level versioned changes for one transition.
    fn exchange(
        &mut self,
        request: &[u8],
        _timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        let request = NodePrivateTransport::decode_request(request)
            .map_err(|_| NodePrivateDocumentExchangeError::MalformedResponse)?;
        self.requests.borrow_mut().push(request.request().clone());
        let response = match request.request() {
            NodePrivateRequest::ReadLocalNode => typed_response(
                request.request_id(),
                NodePrivateResponse::LocalNode(self.local.clone()),
            )?,
            NodePrivateRequest::ReadNodes => typed_response(
                request.request_id(),
                NodePrivateResponse::Nodes(vec![self.local.clone(), self.before.clone()]),
            )?,
            NodePrivateRequest::ReadNode { node_id }
                if node_id == self.before.identity().node_id() =>
            {
                node_change_response(request.request_id(), &self.before, 7)
            }
            NodePrivateRequest::TransitionChild { node_id, .. }
                if node_id == self.before.identity().node_id() =>
            {
                node_change_response(request.request_id(), &self.after, 8)
            }
            _ => return Err(NodePrivateDocumentExchangeError::Unavailable),
        };
        if response.len() > maximum_response_bytes {
            return Err(NodePrivateDocumentExchangeError::ResponseTooLarge);
        }
        Ok(response)
    }
}

// Encodes one ordinary typed response for the transition fixture.
fn typed_response(
    request_id: &Sha256Digest,
    response: NodePrivateResponse,
) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
    NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
        request_id.clone(),
        NodePrivateTransportOutcome::Success(response),
    ))
    .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)
}

// Encodes one versioned Node change without exposing a constructor reserved to NodeManager.
fn node_change_response(request_id: &Sha256Digest, node: &Node, revision: u64) -> Vec<u8> {
    format!(
        "{{\"schema\":{{\"name\":\"li_node_private_api\",\"version\":2}},\"request_id\":\"{}\",\"response\":{{\"kind\":\"node_changed\",\"value\":{{\"node\":{{\"node_id\":\"{}\",\"machine_id\":\"{}\",\"installation_id\":\"{}\",\"display_name\":\"{}\",\"role\":\"{}\",\"state\":\"{}\",\"control_address\":\"{}\",\"latest_hardware_observation_id\":null,\"created_at_unix_milliseconds\":{},\"updated_at_unix_milliseconds\":{}}},\"revision\":{},\"event\":null}}}}}}",
        request_id.as_str(),
        node.identity().node_id().as_str(),
        node.identity().machine_id().as_str(),
        node.identity().installation_id().as_str(),
        node.display_name().as_str(),
        match node.role() {
            NodeRole::Main => "main",
            NodeRole::Child => "child",
        },
        match node.state() {
            NodeState::Pending => "pending",
            NodeState::Active => "active",
            NodeState::Draining => "draining",
            NodeState::Offline => "offline",
            NodeState::Removed => "removed",
        },
        node.control_address().as_str(),
        node.timestamps().created_at().value(),
        node.timestamps().updated_at().value(),
        revision,
    )
    .into_bytes()
}

// Represents the exact absence of a configured local Node endpoint.
struct AbsentExchange;

// Allows context resolution, rejects audit open, and records if dispatch is attempted afterward.
struct AuditOpenFailureExchange {
    local_node: Node,
    requests: Rc<RefCell<Vec<NodePrivateRequest>>>,
}

impl NodePrivateDocumentExchangePort for AuditOpenFailureExchange {
    // Returns one local context, then one stable audit rejection, with no third response.
    fn exchange(
        &mut self,
        request: &[u8],
        _timeout: Duration,
        _maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        let request = NodePrivateTransport::decode_request(request)
            .map_err(|_| NodePrivateDocumentExchangeError::MalformedResponse)?;
        self.requests.borrow_mut().push(request.request().clone());
        let outcome = match request.request() {
            NodePrivateRequest::ReadLocalNode => NodePrivateTransportOutcome::Success(
                NodePrivateResponse::LocalNode(self.local_node.clone()),
            ),
            NodePrivateRequest::OpenCommandAudit(_) => NodePrivateTransportOutcome::Failure(
                NodePrivateRemoteError::new(
                    li_core_interface::TechnicalName::parse("command_audit_error")
                        .expect("remote code"),
                    "command audit is unavailable",
                )
                .expect("remote error"),
            ),
            _ => return Err(NodePrivateDocumentExchangeError::Unavailable),
        };
        NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
            request.request_id().clone(),
            outcome,
        ))
        .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)
    }
}

impl NodePrivateDocumentExchangePort for AbsentExchange {
    // Reports explicit absence without collapsing it into a transient transport failure.
    fn exchange(
        &mut self,
        _request: &[u8],
        _timeout: Duration,
        _maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        Err(NodePrivateDocumentExchangeError::NotConfigured)
    }
}

impl LoopbackExchange {
    // Creates one deterministic codec loopback with shared request observations.
    fn new(
        responses: impl IntoIterator<Item = NodePrivateResponse>,
    ) -> (Self, Rc<RefCell<Vec<NodePrivateRequest>>>) {
        let requests = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                responses: responses.into_iter().collect(),
                requests: Rc::clone(&requests),
            },
            requests,
        )
    }
}

impl NodePrivateDocumentExchangePort for LoopbackExchange {
    // Decodes the request and encodes one exactly correlated typed response.
    fn exchange(
        &mut self,
        request: &[u8],
        _timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        let request = NodePrivateTransport::decode_request(request)
            .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)?;
        self.requests.borrow_mut().push(request.request().clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(NodePrivateDocumentExchangeError::Unavailable)?;
        let response = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
            request.request_id().clone(),
            NodePrivateTransportOutcome::Success(response),
        ))
        .map_err(|_| NodePrivateDocumentExchangeError::Unavailable)?;
        if response.len() > maximum_response_bytes {
            return Err(NodePrivateDocumentExchangeError::ResponseTooLarge);
        }
        Ok(response)
    }
}

// Records mandatory mutation audit outcomes without retaining arguments.
#[derive(Default)]
struct AuditMock {
    intents: Vec<CommandAuditIntent>,
    results: Vec<CommandAuditResult>,
}

// Records exact uninstall policy and returns one injected terminal receipt or boundary failure.
struct UninstallMock {
    calls: Mutex<Vec<NativeUninstallModelDisposition>>,
    result: Result<NativeUninstallReceipt, CommandFailure>,
}

impl NativeUninstallPort for UninstallMock {
    // Returns the deterministic Application projection without touching native state.
    fn uninstall(
        &self,
        disposition: NativeUninstallModelDisposition,
        _progress: &mut dyn CommandProgressPort,
    ) -> Result<NativeUninstallReceipt, CommandFailure> {
        self.calls
            .lock()
            .expect("uninstall calls")
            .push(disposition);
        self.result.clone()
    }
}

impl CommandAuditPort for AuditMock {
    // Opens one deterministic marker for every requested audited lifecycle.
    fn will_execute(
        &mut self,
        intent: CommandAuditIntent,
    ) -> Result<Option<CommandAuditMarker>, CommandAuditError> {
        self.intents.push(intent);
        Ok(Some(CommandAuditMarker::new("audit-1")?))
    }

    // Records one terminal result after the capability returns.
    fn did_execute(
        &mut self,
        _marker: &CommandAuditMarker,
        result: CommandAuditResult,
    ) -> Result<(), CommandAuditError> {
        self.results.push(result);
        Ok(())
    }
}

// Creates one canonical repeated-character digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one coherent local storage plan with only inactive cache data reclaimable.
fn storage_snapshot() -> NodeStorageSnapshot {
    NodeStorageSnapshot::new(
        10_000,
        4_000,
        vec![
            NodeStorageUsage::new(NodeStorageCategory::Caches, 1_000, 900, 2, 1_000)
                .expect("cache usage"),
            NodeStorageUsage::new(NodeStorageCategory::State, 500, 400, 3, 0).expect("state usage"),
        ],
        vec![NodeStorageCandidate::new(
            NodeStorageCategory::Caches,
            "caches/inactive-group",
            1_000,
            "placement group is inactive",
            Vec::new(),
        )
        .expect("cache candidate")],
        digest('e'),
    )
    .expect("storage snapshot")
}

// Derives the exact cleanup operation identity produced for the storage fixture.
fn storage_cleanup_operation_id() -> OperationId {
    let snapshot = storage_snapshot();
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_storage_cleanup_v1\0");
    hasher.update(snapshot.plan_digest().as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(NodeStorageCategory::Caches.as_str().as_bytes());
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    OperationId::parse(&digest[..32]).expect("cleanup operation")
}

// Returns one durable cleanup receipt exactly bound to the CLI fixture request.
fn storage_clean_receipt() -> NodeStorageCleanReceipt {
    NodeStorageCleanReceipt::new(
        storage_cleanup_operation_id(),
        storage_snapshot().plan_digest().clone(),
        1,
        1_000,
        Vec::new(),
        false,
    )
    .expect("cleanup receipt")
}

// Returns one reviewed inactive benchmark-evidence cleanup plan.
fn benchmark_storage_snapshot() -> NodeStorageSnapshot {
    NodeStorageSnapshot::new(
        10_000,
        4_000,
        vec![
            NodeStorageUsage::new(NodeStorageCategory::Benchmarks, 2_000, 1_500, 2, 1_200)
                .expect("benchmark usage"),
        ],
        vec![NodeStorageCandidate::new(
            NodeStorageCategory::Benchmarks,
            "benchmarks/inactive-job",
            1_200,
            "benchmark job is terminal",
            Vec::new(),
        )
        .expect("benchmark candidate")],
        digest('f'),
    )
    .expect("benchmark storage snapshot")
}

// Derives the exact cleanup operation identity for the reviewed benchmark plan.
fn benchmark_cleanup_operation_id() -> OperationId {
    let snapshot = benchmark_storage_snapshot();
    let mut hasher = Sha256::new();
    hasher.update(b"li_cli_storage_cleanup_v1\0");
    hasher.update(snapshot.plan_digest().as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(NodeStorageCategory::Benchmarks.as_str().as_bytes());
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    OperationId::parse(&digest[..32]).expect("benchmark cleanup operation")
}

// Returns one exact benchmark cleanup receipt bound to the reviewed plan.
fn benchmark_clean_receipt() -> NodeStorageCleanReceipt {
    NodeStorageCleanReceipt::new(
        benchmark_cleanup_operation_id(),
        benchmark_storage_snapshot().plan_digest().clone(),
        1,
        1_200,
        Vec::new(),
        false,
    )
    .expect("benchmark cleanup receipt")
}

// Derives the exact model-service identity produced by the native CLI adapter.
fn model_service_identity(node_id: &NodeId, logical_model: &str) -> ModelServiceId {
    let document = format!(
        "{{\"contract\":\"letsinfer-model-service-v1\",\"model\":\"{logical_model}\",\"node_id\":\"{}\"}}",
        node_id.as_str()
    );
    let digest = Sha256::digest(document.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ModelServiceId::parse(&digest[..32]).expect("service")
}

// Returns one opaque runtime log batch with exact provider cursor and placement identities.
fn runtime_log_batch(
    service_id: ModelServiceId,
    placement_group_id: PlacementGroupId,
    placement_character: char,
    cursor_position: &str,
    payload: &[u8],
) -> NodeModelRuntimeLogBatch {
    NodeModelRuntimeLogBatch::new(
        service_id,
        PlacementLogBatch::new(
            placement_group_id,
            li_core_interface::PlacementId::parse(&placement_character.to_string().repeat(32))
                .expect("placement"),
            PlacementLogCursor::new(digest('9'), cursor_position.to_string()).expect("cursor"),
            payload.to_vec(),
            false,
        )
        .expect("runtime log batch"),
    )
}

// Returns one exact community-verification authority fixture.
fn verification_kind() -> BenchmarkKind {
    BenchmarkKind::verification(
        42,
        BenchmarkGitRevision::parse(&"a".repeat(40)).expect("proposal revision"),
        RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
        OperationId::parse(&"d".repeat(32)).expect("transaction"),
        digest('e'),
        digest('f'),
        7,
        digest('b'),
        Some(digest('c')),
    )
    .expect("verification kind")
}

// Returns one coherent running benchmark snapshot for local or verification status tests.
fn benchmark_snapshot(kind: BenchmarkKind) -> NodeBenchmarkSnapshot {
    let verification = kind.is_verification().then(|| {
        NodeBenchmarkVerificationProjection::new(
            BenchmarkVerificationPhase::BaselineRunning,
            OperationId::parse(&"d".repeat(32)).expect("handoff transaction"),
            NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
        )
    });
    benchmark_snapshot_with_state(
        kind,
        BenchmarkJobPhase::Running,
        Some(BenchmarkDisposition::Running),
        verification,
        None,
        true,
    )
}

// Returns one exact verification snapshot for a selected paired and handoff recovery state.
fn verification_snapshot(
    phase: BenchmarkVerificationPhase,
    handoff_phase: NodeBenchmarkCandidateHandoffPhase,
    job_phase: BenchmarkJobPhase,
    disposition: BenchmarkDisposition,
    failure: Option<(BenchmarkFailureCategory, &str)>,
) -> NodeBenchmarkSnapshot {
    benchmark_snapshot_with_state(
        verification_kind(),
        job_phase,
        Some(disposition),
        Some(NodeBenchmarkVerificationProjection::new(
            phase,
            OperationId::parse(&"d".repeat(32)).expect("handoff transaction"),
            handoff_phase,
        )),
        failure.map(|(category, phase)| {
            NodeBenchmarkTerminalFailure::new(
                category,
                TechnicalName::parse(phase).expect("failure phase"),
            )
        }),
        false,
    )
}

// Builds one coherent benchmark snapshot from explicit durable projection fields.
fn benchmark_snapshot_with_state(
    kind: BenchmarkKind,
    job_phase: BenchmarkJobPhase,
    disposition: Option<BenchmarkDisposition>,
    verification: Option<NodeBenchmarkVerificationProjection>,
    terminal_failure: Option<NodeBenchmarkTerminalFailure>,
    include_progress: bool,
) -> NodeBenchmarkSnapshot {
    NodeBenchmarkSnapshot::restore(
        OperationId::parse(&"d".repeat(32)).expect("benchmark job"),
        3,
        kind,
        job_phase,
        disposition,
        digest('e'),
        InstallationId::parse(&"3".repeat(64)).expect("Core installation"),
        RuntimeInstallationId::parse(&"4".repeat(32)).expect("runtime installation"),
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        PlacementGroupId::parse(&"5".repeat(32)).expect("placement group"),
        digest('6'),
        digest('7'),
        digest('8'),
        digest('9'),
        Some(digest('a')),
        Some(digest('b')),
        None,
        None,
        None,
        None,
        None,
        None,
        include_progress.then(|| {
            NodeBenchmarkSnapshotProgress::restore(
                TechnicalName::parse("measure").expect("progress phase"),
                1,
                4,
            )
            .expect("progress")
        }),
        verification,
        terminal_failure,
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(2_000),
    )
    .expect("benchmark snapshot")
}

// Returns one canonical CLI benchmark selection for exact request assertions.
fn benchmark_selection() -> NodeBenchmarkSelection {
    NodeBenchmarkSelection::new(
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        vec![1, 4],
        vec![
            NodeBenchmarkContext::Context32k,
            NodeBenchmarkContext::Context128k,
        ],
    )
    .expect("benchmark selection")
}

// Returns one exact resolved benchmark preview from manager-owned immutable identities.
fn benchmark_plan() -> NodeBenchmarkPlan {
    let declared = vec![
        TechnicalName::parse("32k_code_c1").expect("cell"),
        TechnicalName::parse("32k_code_c4").expect("cell"),
        TechnicalName::parse("128k_code_c1").expect("cell"),
        TechnicalName::parse("128k_code_c4").expect("cell"),
    ];
    let request = BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"3".repeat(64)).expect("Core installation"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("runtime installation"),
            LogicalModelName::parse("deepseek_r1").expect("logical model"),
            PlacementGroupId::parse(&"5".repeat(32)).expect("placement group"),
            digest('6'),
            digest('7'),
            digest('8'),
        ),
    )
    .expect("benchmark request");
    NodeBenchmarkPlan::new(&benchmark_selection(), request, declared.clone(), declared)
        .expect("benchmark plan")
}

// Returns one complete deterministic signed catalog projection for CLI rendering.
fn catalog_listing() -> NodeCatalogListing {
    NodeCatalogListing::new(
        NodeCatalogSnapshot::new(
            "https://letsinfer.ai/catalog.json".to_string(),
            digest('a'),
            digest('b'),
            7,
            1_000,
            false,
        )
        .expect("snapshot"),
        vec![NodeCatalogEntry::new(
            LogicalModelName::parse("deepseek_r1").expect("model"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            "2.0.0".to_string(),
            format!("ghcr.io/letsinfer/runtime@sha256:{}", "c".repeat(64)),
            TechnicalName::parse("sglang").expect("engine"),
            "hf://owner/model".to_string(),
            vec![
                NodeCatalogAuthor::new("owner".to_string(), 7, NodeCatalogAuthorKind::User)
                    .expect("author"),
            ],
            "Apache-2.0".to_string(),
            EvidenceLabel::Qualified,
            "consensus-v1".to_string(),
            Some(2.5),
            true,
        )
        .expect("entry")],
    )
    .expect("listing")
}

// Returns one immutable Core installation fixture with an exact signed source identity.
fn core_installation(version: &str, identity: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("Core version"),
        digest(identity),
    )
}

// Returns one installed model-service projection for update routing tests.
fn installed_model_service() -> NodeModelServiceSummary {
    NodeModelServiceSummary::new(
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        ModelServiceDesiredState::Running,
        vec![PlacementGroupId::parse(&"5".repeat(32)).expect("group")],
        vec![RuntimeInstallationId::parse(&"6".repeat(32)).expect("runtime")],
        vec![EvidenceLabel::Qualified],
    )
}

// Returns one read-only model-update projection without inventing an operation receipt.
fn model_update_available() -> NodeModelUpdateSummary {
    NodeModelUpdateSummary::new(
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        NodeModelUpdateDisposition::UpdateAvailable,
        1,
        None,
    )
}

// Creates one immutable Node fixture with distinct logical and physical identities.
fn node(character: char, name: &str, role: NodeRole, state: NodeState) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&character.to_string().repeat(32)).expect("node identity"),
            MachineId::parse(&character.to_string().repeat(32)).expect("machine identity"),
            InstallationId::parse(&character.to_string().repeat(64)).expect("installation"),
        ),
        DisplayName::parse(name).expect("display name"),
        role,
        state,
        NodeAddress::parse(&format!("{name}.local:9770")).expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
}

// Returns the exact invitation identity shared across CLI pairing fixtures.
fn pairing_invite_id() -> PairingInviteId {
    PairingInviteId::parse(&"7".repeat(32)).expect("pairing invitation")
}

// Returns one remote invitation with its one-time setup code still present.
fn pairing_invitation() -> NodePairingInvitation {
    NodePairingInvitation::new(
        pairing_invite_id(),
        NodePairingMode::Remote,
        digest('6'),
        UnixMilliseconds::new(180_000),
        Some("12345678".to_string()),
    )
    .expect("pairing invitation")
}

// Returns one remote approval state containing only its one-time comparison code.
fn pairing_pending_status() -> NodePairingStatus {
    NodePairingStatus::new(
        pairing_invite_id(),
        NodePairingMode::Remote,
        NodePairingState::PendingApproval,
        UnixMilliseconds::new(180_000),
        1,
        Some(NodeId::parse(&"2".repeat(32)).expect("child node")),
        Some("654321".to_string()),
    )
    .expect("pending pairing")
}

// Returns one complete NVIDIA observation for host-view rendering contracts.
fn hardware_observation(node_id: NodeId) -> HardwareObservation {
    let device_id = DeviceId::parse("GPU-00000000-0000-0000-0000-000000000001").expect("device");
    let accelerator = Accelerator::new(
        device_id.clone(),
        AcceleratorVendor::Nvidia,
        DisplayName::parse("NVIDIA GB10").expect("accelerator"),
        AcceleratorMemory::new(
            MemoryTopology::Discrete,
            Some(ByteCount::new(24 * 1024 * 1024 * 1024).expect("framebuffer")),
            Some(TechnicalName::parse("ats").expect("addressing")),
        )
        .expect("memory"),
        ComputeCapability::Cuda {
            architecture: TechnicalName::parse("sm121").expect("architecture"),
            maximum_version: Some(TechnicalName::parse("cuda13").expect("CUDA")),
        },
    )
    .with_driver(AcceleratorDriver::new(
        TechnicalName::parse("nvidia").expect("driver source"),
        TechnicalName::parse("580.95.05").expect("driver version"),
    ))
    .with_telemetry(
        AcceleratorTelemetry::new(
            Some(60_000),
            Some(1_800),
            Some(7_000),
            Some(750),
            Some(90_000),
            Some(8 * 1024 * 1024 * 1024),
        )
        .expect("telemetry"),
    );
    HardwareObservation::new(
        HardwareObservationId::parse(&"4".repeat(32)).expect("observation"),
        node_id,
        BootId::parse("boot-1").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA GB10").expect("processor"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("system memory"),
        vec![accelerator],
        vec![InterconnectObservation::new(
            InterconnectObservationKind::Rdma,
            Some(NetworkInterfaceName::parse("enp1s0f0").expect("interface")),
            vec![device_id],
            true,
            Some(200_000),
            Some(1_500),
        )
        .expect("interconnect")],
        UnixMilliseconds::new(2_000),
    )
    .expect("hardware observation")
}

// Returns one redacted stopped placement group for an exact host.
fn host_placement_group(node: &Node, identity_character: char) -> NodeHostPlacementGroupSnapshot {
    let placement_group_id = PlacementGroupId::parse(&identity_character.to_string().repeat(32))
        .expect("placement group");
    let placement = NodeHostPlacementSnapshot::restore(
        PlacementId::parse(&identity_character.to_string().repeat(32)).expect("placement"),
        placement_group_id.clone(),
        node.identity().node_id().clone(),
        RuntimeInstallationId::parse(&"6".repeat(32)).expect("runtime installation"),
        TaskId::parse("task-0").expect("task"),
        PlacementResources::new(
            PortRange::new(18_000, 1).expect("ports"),
            vec![DeviceId::parse("GPU-00000000-0000-0000-0000-000000000001").expect("device")],
            None,
        )
        .expect("resources"),
        EndpointOwnership::Owner,
        PlacementState::Stopped,
    );
    NodeHostPlacementGroupSnapshot::restore(
        placement_group_id,
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        ModelServiceDesiredState::Stopped,
        PlacementGroupState::Stopped,
        None,
        vec![placement],
    )
    .expect("host placement group")
}

// Returns one complete host read with deterministic service and telemetry observations.
fn complete_host(
    node: Node,
    identity_character: char,
    links: Vec<PlacementLink>,
) -> NodeHostSnapshot {
    NodeHostSnapshot::restore(
        node.clone(),
        NodeHostProjectionValue::Available(hardware_observation(node.identity().node_id().clone())),
        NodeHostProjectionValue::Available(vec![host_placement_group(&node, identity_character)]),
        NodeHostProjectionValue::Available(links),
        NodeHostProjectionValue::Available(NodeHostProtectionSummary::new(
            NodeHostProtectionState::Ready,
            UnixMilliseconds::new(2_010),
        )),
        NodeHostProjectionValue::Available(NodeHostGatewaySummary::new(
            NodeHostServiceState::Ready,
            Some(NodeHostGatewayTelemetrySummary::new(
                UnixMilliseconds::new(2_011),
                2,
                1,
                10,
                1,
                1_000,
                500,
                250,
            )),
        )),
        NodeHostProjectionValue::Available(NodeHostWatchdogSummary::new(
            NodeHostServiceState::Ready,
            Some(
                NodeHostWatchdogTelemetrySummary::new(
                    UnixMilliseconds::new(2_012),
                    Some(20),
                    Some(30),
                    Some(40),
                    Some(50),
                    None,
                    2,
                    1,
                )
                .expect("Watchdog telemetry"),
            ),
        )),
    )
    .expect("complete host")
}

// Returns one partial host read preserving unavailable and inapplicable sections.
fn partial_host(node: Node) -> NodeHostSnapshot {
    NodeHostSnapshot::restore(
        node,
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::NotApplicable,
    )
    .expect("partial host")
}

// Returns one canonical inventory from explicit host and model availability.
fn host_inventory(
    local_node_id: NodeId,
    hosts: Vec<NodeHostSnapshot>,
    model_services: NodeHostProjectionValue<Vec<NodeModelServiceSummary>>,
) -> NodeHostInventory {
    NodeHostInventory::new(local_node_id, hosts, model_services).expect("host inventory")
}

// Returns one verified current link shared by both endpoint host reads.
fn host_link(left: &Node, right: &Node) -> PlacementLink {
    PlacementLink::new(
        left.identity().node_id().clone(),
        right.identity().node_id().clone(),
        InterconnectKind::Connectx,
        true,
        200_000,
        1_500,
    )
    .expect("host link")
}

// Returns one complete non-secret audit event for native CLI projection tests.
fn audit_event() -> AuditEvent {
    AuditEvent::from_persisted(
        1,
        AuditEventId::parse(&"a".repeat(32)).expect("event"),
        AuditCorrelationId::parse(&"b".repeat(32)).expect("correlation"),
        AuditUnixNanoseconds::new(1_000).expect("timestamp"),
        NodeId::parse(&"1".repeat(32)).expect("node"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("local-user-501").expect("actor"),
        ),
        AuditOrigin::new(
            NodeId::parse(&"1".repeat(32)).expect("origin node"),
            AuditOriginInterface::Cli,
        ),
        AuditAction::parse("model.install").expect("action"),
        AuditTarget::parse("model-service").expect("target"),
        None,
        Some(digest('d')),
        AuditOutcome::Success,
        None,
        digest('0'),
        digest('f'),
    )
    .expect("audit event")
}

// Returns one fixed non-secret API-key metadata projection.
fn api_key() -> ApiKey {
    ApiKey::new(
        ApiKeyId::parse(&"a".repeat(32)).expect("key identity"),
        DisplayName::parse("application").expect("name"),
        ApiKeyPolicy::new(
            ApiKeyModelScope::all(),
            None,
            ApiKeyLimits::default(),
            None,
            None,
        ),
        UnixMilliseconds::new(1_000),
        None,
        None,
    )
    .expect("API key")
}

// Returns one fixed secret-free controller metadata projection.
fn controller() -> NodeControllerSummary {
    let certificate = b"public-controller-certificate";
    NodeControllerSummary::restore(
        ControllerId::parse(&"c".repeat(32)).expect("controller identity"),
        DisplayName::parse("Desk Mac").expect("controller name"),
        ControllerRole::Administrator,
        ControllerState::Active,
        Sha256Digest::parse(&format!("{:x}", Sha256::digest(certificate))).expect("certificate"),
        Sha256Digest::parse(&"e".repeat(64)).expect("public key"),
        UnixMilliseconds::new(0),
        UnixMilliseconds::new(10_000),
        UnixMilliseconds::new(1_000),
        Some(UnixMilliseconds::new(1_000)),
        None,
    )
    .expect("controller summary")
}

// Returns one proof-validated public controller candidate for CLI commit routing.
fn controller_candidate() -> NodeControllerEnrollmentCandidate {
    NodeControllerEnrollmentCandidate::new(
        ControllerId::parse(&"c".repeat(32)).expect("controller"),
        DisplayName::parse("Desk Mac").expect("controller name"),
        ControllerPublicKey::new(vec![7; 96]).expect("public key"),
    )
}

// Returns one public certificate receipt matching the controller fixture.
fn controller_receipt() -> NodeControllerEnrollmentReceipt {
    NodeControllerEnrollmentReceipt::restore(
        controller(),
        b"public-controller-certificate".to_vec(),
    )
    .expect("controller receipt")
}

// Exercises the provider-owned enrollment lifecycle and its sole candidate commit callback.
struct ControllerEnrollmentMock;

impl NativeControllerEnrollmentPort for ControllerEnrollmentMock {
    // Commits one exact candidate and returns the secret-free durable projection.
    fn enroll(
        &self,
        timeout: Duration,
        role: ControllerRole,
        progress: &mut dyn CommandProgressPort,
        commit: &mut dyn NativeControllerEnrollmentCommitPort,
    ) -> Result<NodeControllerSummary, li_core_cli::CommandFailure> {
        assert_eq!(timeout, Duration::from_secs(30));
        assert_eq!(role, ControllerRole::Administrator);
        progress.report(CommandProgressEvent::Detail("Verify 123-456".to_string()));
        commit
            .commit(controller_candidate(), role)
            .map(|receipt| receipt.controller().clone())
    }
}

// Captures exact user-safe pairing requests while returning deterministic trusted results.
struct NodePairingMock {
    endpoint: NativeNodePairingEndpoint,
    joined_node: Node,
    joins: Mutex<Vec<NativeNodePairingJoinRequest>>,
    connectx: Mutex<Vec<(NetworkInterfaceName, Duration)>>,
}

impl NodePairingMock {
    // Creates one stable pairing adapter whose observations remain available to assertions.
    fn new(joined_node: Node) -> Self {
        Self {
            endpoint: NativeNodePairingEndpoint::new(
                NodeAddress::parse("homeai.local:9769").expect("pairing address"),
                9_769,
                digest('9'),
            )
            .expect("pairing endpoint"),
            joined_node,
            joins: Mutex::new(Vec::new()),
            connectx: Mutex::new(Vec::new()),
        }
    }
}

impl NativeNodePairingPort for NodePairingMock {
    // Returns the exact public pairing endpoint without local identity material.
    fn local_endpoint(&self) -> Result<NativeNodePairingEndpoint, CommandFailure> {
        Ok(self.endpoint.clone())
    }

    // Records direct-link preflight and returns its exact proof-bound invitation mode.
    fn connectx_mode(
        &self,
        direct_interface: &NetworkInterfaceName,
        timeout: Duration,
    ) -> Result<NodePairingMode, CommandFailure> {
        self.connectx
            .lock()
            .expect("connectx calls")
            .push((direct_interface.clone(), timeout));
        Ok(NodePairingMode::ConnectX {
            candidate_public_key_sha256: digest('8'),
            direct_interface: direct_interface.clone(),
        })
    }

    // Records one closed join contract and returns the atomically activated child projection.
    fn join(
        &self,
        request: &NativeNodePairingJoinRequest,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Node, CommandFailure> {
        self.joins.lock().expect("join calls").push(request.clone());
        progress.report(CommandProgressEvent::Detail(
            "Pairing proof verified".to_string(),
        ));
        Ok(self.joined_node.clone())
    }
}

// Returns one fixed identity-bound one-time bearer token.
fn api_token() -> String {
    format!("li_{}_{}", "a".repeat(32), "b".repeat(64))
}

// Runs one complete process invocation against typed loopback responses.
fn run(
    arguments: &[&str],
    responses: impl IntoIterator<Item = NodePrivateResponse>,
) -> (
    CliExitCode,
    String,
    String,
    Rc<RefCell<Vec<NodePrivateRequest>>>,
    AuditMock,
) {
    let (exchange, requests) = LoopbackExchange::new(responses);
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new(client);
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        arguments.iter().copied(),
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    (
        exit,
        String::from_utf8(standard_output).expect("standard output"),
        String::from_utf8(standard_error).expect("standard error"),
        requests,
        audit,
    )
}

// Runs one process invocation with deterministic command time for replay-identity assertions.
fn run_with_clock(
    arguments: &[&str],
    responses: impl IntoIterator<Item = NodePrivateResponse>,
) -> (
    CliExitCode,
    String,
    String,
    Rc<RefCell<Vec<NodePrivateRequest>>>,
    AuditMock,
) {
    let (exchange, requests) = LoopbackExchange::new(responses);
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new_with_clock(client, Arc::new(ClockMock));
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        arguments.iter().copied(),
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    (
        exit,
        String::from_utf8(standard_output).expect("standard output"),
        String::from_utf8(standard_error).expect("standard error"),
        requests,
        audit,
    )
}

// Runs one process invocation with the Application-owned controller enrollment capability.
fn run_with_controller_enrollment(
    arguments: &[&str],
    responses: impl IntoIterator<Item = NodePrivateResponse>,
) -> (
    CliExitCode,
    String,
    String,
    Rc<RefCell<Vec<NodePrivateRequest>>>,
    AuditMock,
) {
    let (exchange, requests) = LoopbackExchange::new(responses);
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new(client)
        .with_controller_enrollment(Arc::new(ControllerEnrollmentMock));
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        arguments.iter().copied(),
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    (
        exit,
        String::from_utf8(standard_output).expect("standard output"),
        String::from_utf8(standard_error).expect("standard error"),
        requests,
        audit,
    )
}

// Runs one process invocation with the Application-owned Node pairing capability.
fn run_with_node_pairing(
    arguments: &[&str],
    responses: impl IntoIterator<Item = NodePrivateResponse>,
    pairing: Arc<NodePairingMock>,
) -> (
    CliExitCode,
    String,
    String,
    Rc<RefCell<Vec<NodePrivateRequest>>>,
    AuditMock,
) {
    let (exchange, requests) = LoopbackExchange::new(responses);
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new_with_clock(client, Arc::new(ClockMock))
        .with_node_pairing(pairing);
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        arguments.iter().copied(),
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    (
        exit,
        String::from_utf8(standard_output).expect("standard output"),
        String::from_utf8(standard_error).expect("standard error"),
        requests,
        audit,
    )
}

// Runs one node transition with deterministic time and versioned private responses.
fn run_node_transition(
    arguments: &[&str],
    before: Node,
    after: Node,
) -> (
    CliExitCode,
    String,
    String,
    Rc<RefCell<Vec<NodePrivateRequest>>>,
    AuditMock,
) {
    let requests = Rc::new(RefCell::new(Vec::new()));
    let exchange = NodeTransitionExchange {
        local: node('1', "homeai", NodeRole::Main, NodeState::Active),
        before,
        after,
        requests: Rc::clone(&requests),
    };
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new_with_clock(client, Arc::new(ClockMock));
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        arguments.iter().copied(),
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    (
        exit,
        String::from_utf8(standard_output).expect("standard output"),
        String::from_utf8(standard_error).expect("standard error"),
        requests,
        audit,
    )
}

// Runs one complete process with the production Node-owned audit adapter enabled.
fn run_with_node_audit(
    arguments: &[&str],
    responses: impl IntoIterator<Item = NodePrivateResponse>,
) -> (
    CliExitCode,
    String,
    String,
    Rc<RefCell<Vec<NodePrivateRequest>>>,
) {
    let (exchange, requests) = LoopbackExchange::new(responses);
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new(client);
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run_with_node_audit(
        arguments.iter().copied(),
        &mut standard_output,
        &mut standard_error,
    );
    (
        exit,
        String::from_utf8(standard_output).expect("standard output"),
        String::from_utf8(standard_error).expect("standard error"),
        requests,
    )
}

// Returns one exact opaque marker for the second deterministic process request identity.
fn audit_marker() -> NodeCommandAuditMarker {
    NodeCommandAuditMarker::parse(&format!(
        "li_cli_audit_{}_{}",
        digest('b').as_str(),
        digest('e').as_str()
    ))
    .expect("audit marker")
}

// Accepts one real Unix connection before one fixed test deadline.
fn accept_before(listener: &UnixListener, deadline: Instant) -> UnixStream {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "bounded accept");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
}

// Serves one role read and one host inventory through the real fixed-header contract.
fn serve_local_node(listener: UnixListener, local_node: Node) {
    let deadline = Instant::now() + Duration::from_secs(2);
    for _ in 0..2 {
        let mut stream = accept_before(&listener, deadline);
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("server read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("server write timeout");
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).expect("request header");
        let mut document = vec![0_u8; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut document).expect("request document");
        let request = NodePrivateTransport::decode_request(&document).expect("typed request");
        let response = match request.request() {
            NodePrivateRequest::ReadLocalNode => NodePrivateResponse::LocalNode(local_node.clone()),
            NodePrivateRequest::ReadHostInventory => {
                NodePrivateResponse::HostInventory(host_inventory(
                    local_node.identity().node_id().clone(),
                    vec![partial_host(local_node.clone())],
                    NodeHostProjectionValue::Unavailable,
                ))
            }
            _ => panic!("unexpected system-process request"),
        };
        let response = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
            request.request_id().clone(),
            NodePrivateTransportOutcome::Success(response),
        ))
        .expect("response document");
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .expect("response header");
        for fragment in response.chunks(3) {
            stream.write_all(fragment).expect("response fragment");
        }
    }
}

// Routes status and topology through exact Node, hardware, and model manager projections.
#[test]
fn process_routes_host_status_and_topology_without_fabricated_service_state() {
    for action in ["status", "topology"] {
        let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
        let model = installed_model_service();
        let inventory = host_inventory(
            main.identity().node_id().clone(),
            vec![complete_host(main.clone(), '5', Vec::new())],
            NodeHostProjectionValue::Available(vec![model.clone()]),
        );
        let (exit, output, error, requests, audit) = run(
            &[action, "--json"],
            [
                NodePrivateResponse::LocalNode(main.clone()),
                NodePrivateResponse::HostInventory(inventory),
            ],
        );

        assert_eq!(exit, CliExitCode::Success);
        assert!(error.is_empty(), "{error}");
        assert!(output.contains("\"node_id\":\"11111111111111111111111111111111\""));
        assert!(output.contains("\"processor\":\"NVIDIA GB10\""));
        assert!(output.contains("\"vendor\":\"nvidia\""));
        assert!(output.contains("\"kind\":\"rdma\""));
        assert!(output.contains(model.service_id().as_str()));
        assert!(output.contains("\"placement_groups\":{\"status\":\"available\""));
        assert!(output.contains("\"gateway\":{\"status\":\"available\""));
        assert_eq!(
            requests.borrow().as_slice(),
            &[
                NodePrivateRequest::ReadLocalNode,
                NodePrivateRequest::ReadHostInventory,
            ]
        );
        assert!(audit.intents.is_empty());
        assert!(audit.results.is_empty());
    }
}

// Requires explicit confirmation and dispatches keep/remove policy through the real process.
#[test]
fn process_dispatches_confirmed_native_uninstall_and_rejects_unconfirmed_requests() {
    for (arguments, expected_disposition, models) in [
        (
            vec!["uninstall", "--yes", "--keep-models", "--json"],
            NativeUninstallModelDisposition::KeepModels,
            "preserved",
        ),
        (
            vec!["uninstall", "--yes", "--json"],
            NativeUninstallModelDisposition::RemoveModels,
            "removed",
        ),
    ] {
        let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
        let (exchange, requests) = LoopbackExchange::new([NodePrivateResponse::LocalNode(main)]);
        let uninstall = Arc::new(UninstallMock {
            calls: Mutex::new(Vec::new()),
            result: Ok(NativeUninstallReceipt::new(
                digest('f'),
                11,
                2,
                3,
                expected_disposition == NativeUninstallModelDisposition::KeepModels,
                false,
            )),
        });
        let mut process = NativeNodeCliProcess::new(NodePrivateClient::new(
            exchange,
            IdentityMock::new(),
            NodePrivateClientConfiguration::default(),
        ))
        .with_uninstall(uninstall.clone());
        let mut audit = AuditMock::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = process.run(arguments, &mut audit, &mut stdout, &mut stderr);
        assert_eq!(
            exit,
            CliExitCode::Success,
            "{}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
        let output = String::from_utf8(stdout).expect("uninstall output");
        assert!(output.contains(&format!("\"models\":\"{models}\"")));
        assert!(output.contains("\"removed_targets\":11"));
        assert_eq!(
            uninstall.calls.lock().expect("uninstall calls").as_slice(),
            &[expected_disposition]
        );
        assert_eq!(
            requests.borrow().as_slice(),
            &[NodePrivateRequest::ReadLocalNode]
        );
        assert!(audit.intents.is_empty());
        assert!(audit.results.is_empty());
    }

    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exchange, _) = LoopbackExchange::new([NodePrivateResponse::LocalNode(main)]);
    let uninstall = Arc::new(UninstallMock {
        calls: Mutex::new(Vec::new()),
        result: Ok(NativeUninstallReceipt::new(
            digest('f'),
            1,
            0,
            0,
            false,
            false,
        )),
    });
    let mut process = NativeNodeCliProcess::new(NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    ))
    .with_uninstall(uninstall.clone());
    let mut audit = AuditMock::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = process.run(
        ["uninstall", "--json"],
        &mut audit,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(stdout.is_empty());
    assert!(String::from_utf8(stderr)
        .expect("confirmation failure")
        .contains("Uninstall requires --yes"));
    assert!(uninstall.calls.lock().expect("uninstall calls").is_empty());
}

// Reports doctor readiness only when both local Node state and hardware are healthy.
#[test]
fn process_routes_host_doctor_with_truthful_ready_and_degraded_results() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let complete = host_inventory(
        main.identity().node_id().clone(),
        vec![complete_host(main.clone(), '5', Vec::new())],
        NodeHostProjectionValue::Available(Vec::new()),
    );
    let (exit, output, error, requests, _) = run(
        &["doctor", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(complete),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"ready\":true"));
    assert!(output.contains("\"id\":\"node_active\",\"passed\":true"));
    assert!(output.contains("\"id\":\"hardware_observed\",\"passed\":true"));
    assert!(output.contains("\"id\":\"gateway_ready\",\"passed\":true"));
    assert!(output.contains("\"publication_ready\":false"));
    assert!(output.contains("\"id\":\"stable_publication\",\"passed\":false,\"required\":false"));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadHostInventory)
    );

    let offline = node('1', "homeai", NodeRole::Main, NodeState::Offline);
    let degraded = host_inventory(
        offline.identity().node_id().clone(),
        vec![partial_host(offline.clone())],
        NodeHostProjectionValue::Unavailable,
    );
    let (exit, output, error, _, _) = run(
        &["doctor", "--json"],
        [
            NodePrivateResponse::LocalNode(offline.clone()),
            NodePrivateResponse::HostInventory(degraded),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"ready\":false"));
    assert!(output.contains("\"id\":\"node_active\",\"passed\":false"));
    assert!(output.contains("\"id\":\"hardware_observed\",\"passed\":false"));

    let stable = host_inventory(
        main.identity().node_id().clone(),
        vec![complete_host(main.clone(), '5', Vec::new())],
        NodeHostProjectionValue::Available(vec![installed_model_service()]),
    );
    let (exit, output, error, requests, _) = run(
        &["doctor", "--require-stable", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(stable),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"publication_ready\":true"));
    assert!(output.contains("\"id\":\"stable_publication\",\"passed\":true,\"required\":true"));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadHostInventory)
    );

    let unqualified = NodeModelServiceSummary::new(
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        ModelServiceDesiredState::Running,
        vec![PlacementGroupId::parse(&"5".repeat(32)).expect("group")],
        vec![RuntimeInstallationId::parse(&"6".repeat(32)).expect("runtime")],
        vec![EvidenceLabel::Unqualified],
    );
    let (exit, output, error, _, _) = run(
        &["doctor", "--require-stable", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(host_inventory(
                main.identity().node_id().clone(),
                vec![complete_host(main.clone(), '5', Vec::new())],
                NodeHostProjectionValue::Available(vec![unqualified]),
            )),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"ready\":false"));
    assert!(output.contains("\"publication_ready\":false"));
    assert!(output.contains("\"id\":\"stable_publication\",\"passed\":false,\"required\":true"));
}

// Composes local context and node-info dispatch into one machine-clean process result.
#[test]
fn process_executes_local_node_info_through_the_native_client() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let inventory = host_inventory(
        main.identity().node_id().clone(),
        vec![complete_host(main.clone(), '5', Vec::new())],
        NodeHostProjectionValue::Available(Vec::new()),
    );
    let (exit, standard_output, standard_error, requests, audit) = run(
        &["node", "info", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(inventory),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(standard_error.is_empty());
    assert!(standard_output.contains("\"node_id\":\"11111111111111111111111111111111\""));
    assert!(standard_output.contains("\"hardware\":{\"status\":\"available\""));
    assert!(standard_output.contains("\"gateway\":{\"status\":\"available\""));
    assert_eq!(
        requests.borrow().as_slice(),
        &[
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadHostInventory,
        ]
    );
    assert!(audit.intents.is_empty());
    assert!(audit.results.is_empty());
}

// Selects targeted info and sorts list output without changing the Node wire projection.
#[test]
fn process_routes_targeted_info_and_stable_node_list_reads() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let child = node('2', "homeai-node-2", NodeRole::Child, NodeState::Offline);
    let link = host_link(&main, &child);
    let inventory = host_inventory(
        main.identity().node_id().clone(),
        vec![
            complete_host(child.clone(), '6', vec![link.clone()]),
            complete_host(main.clone(), '5', vec![link]),
        ],
        NodeHostProjectionValue::Available(Vec::new()),
    );
    let (exit, output, error, requests, _) = run(
        &["node", "info", "homeai-node-2", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(inventory.clone()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"display_name\":\"homeai-node-2\""));
    assert!(output.contains("\"state\":\"offline\""));
    assert_eq!(
        requests.borrow().as_slice(),
        &[
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadHostInventory,
        ]
    );

    let (exit, output, error, requests, _) = run(
        &["node", "list", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(inventory),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(
        output.find("\"homeai\"").expect("main") < output.find("\"homeai-node-2\"").expect("child")
    );
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadHostInventory)
    );
}

// Reports exact local storage totals and reviewed relative cleanup candidates.
#[test]
fn process_reports_node_storage_through_the_local_private_api() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let snapshot = storage_snapshot();
    let (exit, output, error, requests, audit) = run(
        &["node", "usage", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::StorageSnapshot(snapshot.clone()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(error.is_empty());
    assert!(output.contains("\"capacity_bytes\":10000"));
    assert!(output.contains("\"available_bytes\":4000"));
    assert!(output.contains("\"relative_path\":\"caches/inactive-group\""));
    assert!(output.contains(&format!(
        "\"plan_sha256\":\"{}\"",
        snapshot.plan_digest().as_str()
    )));
    assert_eq!(
        requests.borrow().as_slice(),
        &[
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadStorage,
        ]
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Applies only the selected reviewed category with exact plan and replay identities.
#[test]
fn process_cleans_one_confirmed_storage_plan_with_exact_request_binding() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let snapshot = storage_snapshot();
    let receipt = storage_clean_receipt();
    let (exit, output, error, requests, audit) = run(
        &[
            "node",
            "usage",
            "--clean",
            "--category",
            "caches",
            "--yes",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::StorageSnapshot(snapshot.clone()),
            NodePrivateResponse::StorageCleaned(receipt.clone()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(error.is_empty());
    assert!(output.contains("\"reclaimed_bytes\":1000"));
    assert!(output.contains("\"removed_targets\":1"));
    assert!(output.contains("\"replayed\":false"));
    let requests = requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1], NodePrivateRequest::ReadStorage);
    let NodePrivateRequest::CleanStorage(request) = &requests[2] else {
        panic!("storage cleanup request");
    };
    assert_eq!(request.operation_id(), receipt.operation_id());
    assert_eq!(request.plan_digest(), snapshot.plan_digest());
    assert_eq!(
        request.categories().iter().copied().collect::<Vec<_>>(),
        vec![NodeStorageCategory::Caches]
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Fails before observation or cleanup when mutation confirmation and option intent are invalid.
#[test]
fn process_rejects_unconfirmed_or_nonclean_storage_mutation_options_before_dispatch() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    for arguments in [
        vec!["node", "usage", "--clean", "--json"],
        vec!["node", "usage", "--category", "caches", "--json"],
    ] {
        let (exit, output, error, requests, audit) =
            run(&arguments, [NodePrivateResponse::LocalNode(main.clone())]);
        assert_eq!(exit, CliExitCode::Failure);
        assert!(output.is_empty());
        assert!(error.contains(if arguments.contains(&"--clean") {
            "Pass --yes"
        } else {
            "require --clean"
        }));
        assert_eq!(
            requests.borrow().as_slice(),
            &[NodePrivateRequest::ReadLocalNode]
        );
        assert_eq!(audit.intents.len(), 1);
        assert_eq!(audit.results.len(), 1);
    }
}

// Rejects absent selections and response receipts that do not bind the reviewed request.
#[test]
fn process_rejects_unreviewed_storage_selection_and_mismatched_receipt() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, _) = run(
        &[
            "node",
            "usage",
            "--clean",
            "--category",
            "models",
            "--yes",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::StorageSnapshot(storage_snapshot()),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("no reviewed inactive data"));
    assert_eq!(requests.borrow().len(), 2);

    let mismatched = NodeStorageCleanReceipt::new(
        OperationId::parse(&"a".repeat(32)).expect("other operation"),
        storage_snapshot().plan_digest().clone(),
        1,
        1_000,
        Vec::new(),
        false,
    )
    .expect("mismatched receipt");
    let (exit, output, error, requests, _) = run(
        &["node", "usage", "--clean", "--yes", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::StorageSnapshot(storage_snapshot()),
            NodePrivateResponse::StorageCleaned(mismatched),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("unexpected response"));
    assert_eq!(requests.borrow().len(), 3);
}

// Routes catalog-aware info through the typed RuntimeManager-compatible Node projection.
#[test]
fn process_routes_catalog_aware_node_information() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let target = NodeCatalogTarget::new(
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
        true,
    );
    let source = "https://letsinfer.ai/catalog.json";
    let (exit, output, error, requests, audit) = run(
        &["node", "info", "--catalog", source, "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::HostInventory(host_inventory(
                main.identity().node_id().clone(),
                vec![complete_host(main.clone(), '5', Vec::new())],
                NodeHostProjectionValue::Available(Vec::new()),
            )),
            NodePrivateResponse::CompatibleTargets(vec![target.clone()]),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"compatible_targets\""));
    assert!(output.contains(target.candidate_id().as_str()));
    assert!(output.contains("\"recommended\":true"));
    assert!(audit.intents.is_empty());
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadCompatibleTargets {
            node_id: main.identity().node_id().clone(),
            catalog_source: source.to_string(),
        })
    );
}

// Routes the complete catalog-list leaf and preserves representative human and JSON fields.
#[test]
fn process_routes_catalog_model_listing_with_exact_options_and_output() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let source = "https://letsinfer.ai/catalog.json";
    let (exit, output, error, requests, _) = run(
        &[
            "model",
            "list",
            "deepseek_r1",
            "--versions",
            "--all-targets",
            "--refresh",
            "--catalog",
            source,
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::Catalog(catalog_listing()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"logical_model\":\"deepseek_r1\""));
    assert!(output.contains("\"version\":\"2.0.0\""));
    assert!(output.contains("\"target_id\":\"dgx-spark\""));
    assert!(output.contains("\"catalog_sha256\""));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadCatalog(
            NodeCatalogListRequest::new(
                Some(source.to_string()),
                Some(LogicalModelName::parse("deepseek_r1").expect("model")),
                NodeCatalogVersionSelection::All,
                NodeCatalogTargetSelection::All,
                NodeCatalogRefreshPolicy::Refresh,
            )
            .expect("request"),
        ))
    );

    let (exit, output, error, requests, _) = run(
        &["model", "list", "deepseek_r1"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::Catalog(catalog_listing()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.contains("Models loaded"));
    assert!(output.contains("MODEL"));
    assert!(output.contains("deepseek_r1"));
    assert!(output.contains("2.0.0"));
    assert!(output.contains("dgx-spark"));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::ReadCatalog(_))
    ));
}

// Asserts an exact signed catalog source before install and renders cleanup retry dry-runs.
#[test]
fn process_routes_catalog_install_and_non_mutating_rollback_preview() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let source = "https://letsinfer.ai/catalog.json";
    let summary = NodeModelCommandSummary::new(
        OperationId::parse(&"7".repeat(32)).expect("operation"),
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        ModelServiceDesiredState::Running,
        NodeModelAction::Install,
        NodeModelJournalState::Succeeded,
        None,
    );
    let (exit, output, error, requests, _) = run(
        &[
            "model",
            "install",
            "deepseek_r1",
            "--catalog",
            source,
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::Catalog(catalog_listing()),
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::ModelChanged(summary),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"action\":\"install\""));
    let requests = requests.borrow();
    assert!(matches!(
        &requests[1],
        NodePrivateRequest::ReadCatalog(request)
            if request.catalog_source() == Some(source)
                && request.logical_model().is_some_and(|model| model.as_str() == "deepseek_r1")
    ));
    assert!(matches!(
        requests.last(),
        Some(NodePrivateRequest::InstallModel(_))
    ));

    let rollback_service = model_service_identity(main.identity().node_id(), "deepseek_r1");
    let rollback_target = TargetId::parse("dgx-spark").expect("target");
    let runtime = |version: &str, source: char| {
        NodeModelRollbackRuntime::new(
            RuntimeCandidateId::parse("sglang--owner--model--target").expect("candidate"),
            RuntimeVersion::parse(version).expect("version"),
            rollback_target.clone(),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinfer/runtime@sha256:{}",
                source.to_string().repeat(64)
            ))
            .expect("source"),
        )
    };
    let preview = NodeModelRollbackPreview::new(
        rollback_service.clone(),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        Some(rollback_target.clone()),
        vec![NodeModelRollbackGroupPreview::new(
            PlacementGroupId::parse(&"8".repeat(32)).expect("current group"),
            PlacementGroupId::parse(&"9".repeat(32)).expect("previous group"),
            vec![main.identity().node_id().clone()],
            runtime("1.1.0", 'a'),
            runtime("1.0.0", 'b'),
        )],
    );
    let (exit, output, error, requests, _) = run(
        &[
            "model",
            "rollback",
            "deepseek_r1",
            "--target",
            rollback_target.as_str(),
            "--dry-run",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::ModelRollbackPreview(preview),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"dry_run\":true"));
    assert!(output.contains("\"kind\":\"retained_runtime\""));
    assert!(output.contains("\"version\":\"1.0.0\""));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::PreviewRollbackModel {
            service_id: rollback_service,
            target_id: Some(rollback_target),
        })
    );

    let summary = NodeModelCommandSummary::new(
        OperationId::parse(&"7".repeat(32)).expect("operation"),
        model_service_identity(main.identity().node_id(), "deepseek_r1"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        ModelServiceDesiredState::Running,
        NodeModelAction::Rollback,
        NodeModelJournalState::Succeeded,
        None,
    );
    let (exit, output, error, requests, _) = run(
        &[
            "model",
            "rollback",
            "deepseek_r1",
            "--target",
            "dgx-spark",
            "--yes",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::ModelChanged(summary),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(output.contains("\"action\":\"rollback\""));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::RollbackModel {
            service_id,
            target_id: Some(target_id),
            ..
        }) if service_id == &model_service_identity(main.identity().node_id(), "deepseek_r1")
            && target_id.as_str() == "dgx-spark"
    ));
}

// Resolves offline node identities for partial removal and forwards the closed selection.
#[test]
fn process_routes_partial_model_removal() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let child = node('2', "homeai-node-2", NodeRole::Child, NodeState::Offline);
    let summary = NodeModelCommandSummary::new(
        OperationId::parse(&"7".repeat(32)).expect("operation"),
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        ModelServiceDesiredState::Running,
        NodeModelAction::Remove,
        NodeModelJournalState::Succeeded,
        None,
    );
    let (exit, output, error, requests, _) = run(
        &[
            "model",
            "remove",
            "deepseek_r1",
            "--node",
            "homeai-node-2",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::Nodes(vec![main, child.clone()]),
            NodePrivateResponse::ModelChanged(summary),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"action\":\"remove\""));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::RemoveModel(request))
            if request.selection().node_ids() == Some(&[child.identity().node_id().clone()])
    ));
}

// Routes every ordinary service-state leaf through its exact ModelCoordinator request.
#[test]
fn process_routes_every_model_service_state_leaf() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let service_id = model_service_identity(main.identity().node_id(), "deepseek_r1");
    let cases = [
        (
            "pause",
            NodeModelAction::Pause,
            ModelServiceDesiredState::Stopped,
        ),
        (
            "resume",
            NodeModelAction::Resume,
            ModelServiceDesiredState::Running,
        ),
        (
            "restart",
            NodeModelAction::Restart,
            ModelServiceDesiredState::Running,
        ),
        (
            "recover",
            NodeModelAction::Recover,
            ModelServiceDesiredState::Running,
        ),
    ];
    for (command, action, desired_state) in cases {
        let summary = NodeModelCommandSummary::new(
            OperationId::parse(&"7".repeat(32)).expect("operation"),
            service_id.clone(),
            LogicalModelName::parse("deepseek_r1").expect("model"),
            desired_state,
            action,
            NodeModelJournalState::Succeeded,
            None,
        );
        let (exit, output, error, requests, audit) = run(
            &["model", command, "deepseek_r1"],
            [
                NodePrivateResponse::LocalNode(main.clone()),
                NodePrivateResponse::LocalNode(main.clone()),
                NodePrivateResponse::ModelChanged(summary),
            ],
        );
        assert_eq!(exit, CliExitCode::Success, "{command}: {error}");
        assert!(!error.contains("FATAL"), "{command}: {error}");
        assert!(output.contains("deepseek_r1"));
        assert!(match requests.borrow().last() {
            Some(NodePrivateRequest::PauseModel {
                service_id: value, ..
            }) => action == NodeModelAction::Pause && value == &service_id,
            Some(NodePrivateRequest::ResumeModel {
                service_id: value, ..
            }) => action == NodeModelAction::Resume && value == &service_id,
            Some(NodePrivateRequest::RestartModel {
                service_id: value, ..
            }) => action == NodeModelAction::Restart && value == &service_id,
            Some(NodePrivateRequest::RecoverModel {
                service_id: value, ..
            }) => action == NodeModelAction::Recover && value == &service_id,
            _ => false,
        });
        assert_eq!(audit.intents.len(), 1);
        assert_eq!(audit.results.len(), 1);
    }
}

// Preserves one bounded runtime batch and forwards the exact group and tail selectors.
#[test]
fn process_routes_bounded_model_runtime_logs_without_changing_bytes() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let service_id = model_service_identity(main.identity().node_id(), "deepseek_r1");
    let placement_group_id = PlacementGroupId::parse(&"5".repeat(32)).expect("group");
    let batch = runtime_log_batch(
        service_id.clone(),
        placement_group_id.clone(),
        '6',
        "1700000000.000000000|1",
        b"engine line one\nengine line two",
    );
    let (exit, output, error, requests, _) = run(
        &[
            "model",
            "logs",
            "deepseek_r1",
            "--placement-group",
            placement_group_id.as_str(),
            "--tail",
            "25",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::ModelRuntimeLogs(batch),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert_eq!(output.as_bytes(), b"engine line one\nengine line two");
    assert!(error.contains("LET'S INFER · Model Logs"));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::ReadModelRuntimeLogs(request))
            if request.service_id() == &service_id
                && request.placement_group_id() == Some(&placement_group_id)
                && request.maximum_lines() == 25
                && request.maximum_bytes() == 64 * 1024
                && request.wait() == Duration::ZERO
                && request.cursor().is_none()
    ));

    let wrong_service = ModelServiceId::parse(&"4".repeat(32)).expect("wrong service");
    let (exit, output, error, _, _) = run(
        &["model", "logs", "deepseek_r1"],
        [
            NodePrivateResponse::LocalNode(node('1', "homeai", NodeRole::Main, NodeState::Active)),
            NodePrivateResponse::LocalNode(node('1', "homeai", NodeRole::Main, NodeState::Active)),
            NodePrivateResponse::ModelRuntimeLogs(runtime_log_batch(
                wrong_service,
                placement_group_id,
                '6',
                "1700000000.000000000|1",
                b"must not be shown",
            )),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("unexpected response"));
    assert!(!error.contains("must not be shown"));

    let (exit, output, error, requests, _) = run(
        &["model", "logs", "deepseek_r1", "--tail", "0"],
        [
            NodePrivateResponse::LocalNode(node('1', "homeai", NodeRole::Main, NodeState::Active)),
            NodePrivateResponse::LocalNode(node('1', "homeai", NodeRole::Main, NodeState::Active)),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("between 1 and 10000"));
    assert!(requests
        .borrow()
        .iter()
        .all(|request| !matches!(request, NodePrivateRequest::ReadModelRuntimeLogs(_))));
}

// Follows opaque batches with cursor replay, one-second deadlines, and explicit cancellation.
#[test]
fn capability_follows_model_runtime_logs_until_deterministic_cancellation() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let service_id = model_service_identity(main.identity().node_id(), "deepseek_r1");
    let placement_group_id = PlacementGroupId::parse(&"5".repeat(32)).expect("group");
    let first = runtime_log_batch(
        service_id.clone(),
        placement_group_id.clone(),
        '6',
        "1700000000.000000000|1",
        b"first\n",
    );
    let first_cursor = first.placement().cursor().clone();
    let second = runtime_log_batch(
        service_id,
        placement_group_id,
        '6',
        "1700000001.000000000|1",
        b"second\n",
    );
    let (exchange, requests) = LoopbackExchange::new([
        NodePrivateResponse::LocalNode(main),
        NodePrivateResponse::ModelRuntimeLogs(first),
        NodePrivateResponse::ModelRuntimeLogs(second),
    ]);
    let client = NodePrivateClient::new(
        exchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut capabilities = NativeNodeCliCapabilities::new(client);
    let invocation = CommandParser::new()
        .expect("parser")
        .parse(["model", "logs", "deepseek_r1", "--follow", "--tail", "2"])
        .expect("invocation");
    let mut progress = CancellingProgress {
        outputs: Vec::new(),
        cancellation_after: 2,
    };
    let failure = capabilities
        .execute_model(ModelCommand::Logs(&invocation), &mut progress)
        .expect_err("cancelled follow");
    assert_eq!(failure.kind(), CommandFailureKind::Cancelled);
    assert_eq!(
        progress.outputs,
        [b"first\n".to_vec(), b"second\n".to_vec()]
    );
    let requests = requests.borrow();
    let log_requests = requests
        .iter()
        .filter_map(|request| match request {
            NodePrivateRequest::ReadModelRuntimeLogs(request) => Some(request),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(log_requests.len(), 2);
    assert_eq!(log_requests[0].wait(), Duration::from_secs(1));
    assert_eq!(log_requests[0].maximum_lines(), 2);
    assert!(log_requests[0].cursor().is_none());
    assert_eq!(log_requests[1].cursor(), Some(&first_cursor));
}

// Routes exposure reads and mutations through one exact manager-backed projection.
#[test]
fn process_routes_exposure_status_and_mutations_through_gateway_projection() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let enabled = GatewayExposureStatus::new(
        Some(
            GatewayExposure::new("https://inference.example.ts.net".to_string(), digest('a'))
                .expect("exposure"),
        ),
        true,
    )
    .expect("enabled status");
    let disabled = GatewayExposureStatus::new(None, true).expect("disabled status");
    for (arguments, request, status, audited) in [
        (
            vec!["exposure", "status", "--json"],
            NodePrivateRequest::ReadExposure,
            enabled.clone(),
            false,
        ),
        (
            vec!["exposure", "enable", "--json"],
            NodePrivateRequest::EnableExposure,
            enabled.clone(),
            true,
        ),
        (
            vec!["exposure", "disable", "--json"],
            NodePrivateRequest::DisableExposure,
            disabled.clone(),
            true,
        ),
    ] {
        let (exit, output, error, requests, audit) = run(
            &arguments,
            [
                NodePrivateResponse::LocalNode(main.clone()),
                NodePrivateResponse::Exposure(status),
            ],
        );
        assert_eq!(exit, CliExitCode::Success);
        assert!(error.is_empty());
        assert!(output.contains("\"provider\":\"tailscale-funnel\""));
        assert!(output.contains("\"provider_verified\":true"));
        assert_eq!(requests.borrow().last(), Some(&request));
        assert_eq!(audit.intents.len(), usize::from(audited));
        assert_eq!(audit.results.len(), usize::from(audited));
    }
}

// Resolves public benchmark axes and starts only the exact local manager-owned selection.
#[test]
fn process_routes_benchmark_preview_and_run_without_internal_execution_arguments() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let plan = benchmark_plan();
    let (exit, output, error, requests, audit) = run(
        &[
            "benchmark",
            "list",
            "deepseek_r1",
            "--c1",
            "--c4",
            "--32k",
            "--128k",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::BenchmarkPlan(plan),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(error.is_empty());
    assert!(output.contains("\"logical_model\":\"deepseek_r1\""));
    assert!(output.contains("\"selected_cells\":[\"32k_code_c1\""));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::PreviewBenchmark {
            selection: benchmark_selection(),
        })
    );
    assert!(audit.intents.is_empty());

    let snapshot = benchmark_snapshot(BenchmarkKind::Local);
    let (exit, output, error, requests, audit) = run_with_clock(
        &[
            "benchmark",
            "run",
            "deepseek_r1",
            "--c1",
            "--c4",
            "--32k",
            "--128k",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkChanged(snapshot),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(error.is_empty());
    assert!(output.contains("\"kind\":\"local\""));
    let requests = requests.borrow();
    let NodePrivateRequest::StartBenchmark {
        idempotency_key,
        selection,
    } = requests.last().expect("benchmark request")
    else {
        panic!("start benchmark request");
    };
    assert_eq!(
        idempotency_key,
        "li_cli_benchmark_6422d2aa75617298f61725186392d7f43d98655e7529f57f31c4606e11d45fe3"
    );
    assert_eq!(selection, &benchmark_selection());
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Sends only the public PR selector to the resident Node and accepts detach as presentation policy.
#[test]
fn process_routes_verification_run_without_client_supplied_authority_identities() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let verification = benchmark_snapshot(verification_kind());
    let (exit, output, error, requests, audit) = run(
        &[
            "benchmark",
            "verification",
            "run",
            "https://github.com/letsinferlabs/runtimes/pull/41",
            "--candidate",
            "vllm--owner--model--spark",
            "--detach",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkChanged(verification),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"kind\":\"verification\""));
    let requests = requests.borrow();
    let NodePrivateRequest::StartBenchmarkVerification {
        idempotency_key,
        pull_request_url,
        candidate,
    } = requests.last().expect("verification request")
    else {
        panic!("verification request");
    };
    assert!(idempotency_key.starts_with("li_cli_benchmark_verification_"));
    assert_eq!(
        pull_request_url,
        "https://github.com/letsinferlabs/runtimes/pull/41"
    );
    assert_eq!(
        candidate.as_ref().map(RuntimeCandidateId::as_str),
        Some("vllm--owner--model--spark")
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Requires confirmation and removes only the reviewed inactive benchmark category.
#[test]
fn process_cleans_only_confirmed_inactive_benchmark_data() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "clean", "--json"],
        [NodePrivateResponse::LocalNode(main.clone())],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("Pass --yes to confirm benchmark cleanup."));
    assert_eq!(requests.borrow().len(), 1);
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);

    let snapshot = benchmark_storage_snapshot();
    let receipt = benchmark_clean_receipt();
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "clean", "--yes", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::StorageSnapshot(snapshot.clone()),
            NodePrivateResponse::StorageCleaned(receipt.clone()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(error.is_empty());
    assert!(output.contains("\"reclaimed_bytes\":1200"));
    let requests = requests.borrow();
    let NodePrivateRequest::CleanStorage(request) = requests.last().expect("cleanup request")
    else {
        panic!("clean storage request");
    };
    assert_eq!(request.operation_id(), receipt.operation_id());
    assert_eq!(request.plan_digest(), snapshot.plan_digest());
    assert_eq!(
        request.categories().iter().copied().collect::<Vec<_>>(),
        vec![NodeStorageCategory::Benchmarks]
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Routes active benchmark status through the exact local or verification authority.
#[test]
fn process_routes_benchmark_status_with_exact_kind() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let local = benchmark_snapshot(BenchmarkKind::Local);
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "status", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::BenchmarkRecord(Some(local)),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"kind\":\"local\""));
    assert!(output.contains("\"active\":true"));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadActiveBenchmark)
    );
    assert!(audit.intents.is_empty());

    let (exit, output, error, requests, _) = run(
        &["benchmark", "status"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::BenchmarkRecord(Some(benchmark_snapshot(BenchmarkKind::Local))),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("Benchmark"));
    assert!(output.contains("deepseek_r1"));
    assert!(output.contains("running"));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadActiveBenchmark)
    );

    let verification = benchmark_snapshot(verification_kind());
    let (exit, output, error, requests, _) = run(
        &["benchmark", "verification", "status", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkRecord(Some(verification)),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"kind\":\"verification\""));
    assert!(output.contains("\"active\":true"));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadActiveBenchmark)
    );
}

// Presents exact baseline, candidate, recovery-required, cleanup-pending, and restored states.
#[test]
fn verification_status_projects_durable_parent_handoff_and_failure_state() {
    let cases = [
        (
            "baseline_running",
            verification_snapshot(
                BenchmarkVerificationPhase::BaselineRunning,
                NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
                BenchmarkJobPhase::Running,
                BenchmarkDisposition::Running,
                None,
            ),
            "candidate_acquired",
            false,
            None,
        ),
        (
            "candidate_running",
            verification_snapshot(
                BenchmarkVerificationPhase::CandidateRunning,
                NodeBenchmarkCandidateHandoffPhase::CandidateRunning,
                BenchmarkJobPhase::Running,
                BenchmarkDisposition::Running,
                None,
            ),
            "candidate_running",
            false,
            None,
        ),
        (
            "restoration_failed",
            verification_snapshot(
                BenchmarkVerificationPhase::RestorationFailed,
                NodeBenchmarkCandidateHandoffPhase::Restoring,
                BenchmarkJobPhase::Failed,
                BenchmarkDisposition::Failed,
                Some((BenchmarkFailureCategory::Restoration, "restoration")),
            ),
            "restoring",
            true,
            Some("restoration"),
        ),
        (
            "restoration_failed",
            verification_snapshot(
                BenchmarkVerificationPhase::RestorationFailed,
                NodeBenchmarkCandidateHandoffPhase::BaselineRestored,
                BenchmarkJobPhase::Failed,
                BenchmarkDisposition::Failed,
                Some((BenchmarkFailureCategory::Restoration, "cleanup")),
            ),
            "baseline_restored",
            true,
            Some("cleanup"),
        ),
        (
            "restored",
            verification_snapshot(
                BenchmarkVerificationPhase::Restored,
                NodeBenchmarkCandidateHandoffPhase::Completed,
                BenchmarkJobPhase::Completed,
                BenchmarkDisposition::Completed,
                None,
            ),
            "completed",
            false,
            None,
        ),
    ];
    for (verification_phase, snapshot, handoff_phase, recovery_required, failure_phase) in cases {
        let (exit, output, error, _, _) = run(
            &["benchmark", "verification", "status", "--json"],
            [
                NodePrivateResponse::LocalNode(node(
                    '1',
                    "homeai",
                    NodeRole::Main,
                    NodeState::Active,
                )),
                NodePrivateResponse::BenchmarkRecord(Some(snapshot)),
            ],
        );
        assert_eq!(exit, CliExitCode::Success, "{verification_phase}:{error}");
        assert!(error.is_empty(), "{verification_phase}:{error}");
        assert!(output.contains(&format!("\"verification_phase\":\"{verification_phase}\"")));
        assert!(output.contains(&format!("\"handoff_phase\":\"{handoff_phase}\"")));
        assert!(output.contains(&format!("\"recovery_required\":{recovery_required}")));
        match failure_phase {
            Some(phase) => {
                assert!(output.contains("\"failure_category\":\"restoration\""));
                assert!(output.contains(&format!("\"failure_phase\":\"{phase}\"")));
            }
            None => {
                assert!(output.contains("\"failure_category\":null"));
                assert!(output.contains("\"failure_phase\":null"));
            }
        }
    }

    let recovery = verification_snapshot(
        BenchmarkVerificationPhase::RestorationFailed,
        NodeBenchmarkCandidateHandoffPhase::BaselineRestored,
        BenchmarkJobPhase::Failed,
        BenchmarkDisposition::Failed,
        Some((BenchmarkFailureCategory::Restoration, "cleanup")),
    );
    let (exit, output, error, _, _) = run(
        &["benchmark", "verification", "status"],
        [
            NodePrivateResponse::LocalNode(node('1', "homeai", NodeRole::Main, NodeState::Active)),
            NodePrivateResponse::BenchmarkRecord(Some(recovery)),
        ],
    );
    assert_eq!(exit, CliExitCode::Success, "{error}");
    assert!(output.contains("Recovery"));
    assert!(output.contains("Required"));
    assert!(output.contains("restoration"));
    assert!(output.contains("cleanup"));
}

// Stops only the exact active ordinary benchmark and preserves its non-verification identity.
#[test]
fn process_stops_the_active_ordinary_benchmark() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let active = benchmark_snapshot(BenchmarkKind::Local);
    let job_id = active.job_id().clone();
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "stop", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkRecord(Some(active.clone())),
            NodePrivateResponse::BenchmarkChanged(active),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"kind\":\"local\""));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::StopBenchmark { job_id })
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Reports verification as inactive when the sole active benchmark is an ordinary local run.
#[test]
fn process_does_not_present_a_local_benchmark_as_verification() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, _) = run(
        &["benchmark", "verification", "status", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkRecord(Some(benchmark_snapshot(BenchmarkKind::Local))),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert_eq!(
        output.trim(),
        "{\"active\":false,\"benchmark\":null,\"kind\":\"verification\"}"
    );
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadActiveBenchmark)
    );
}

// Keeps the ordinary benchmark surface from presenting or stopping a verification job.
#[test]
fn process_does_not_present_or_stop_verification_as_an_ordinary_benchmark() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let verification = benchmark_snapshot(verification_kind());
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "status", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::BenchmarkRecord(Some(verification.clone())),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert_eq!(output.trim(), "{\"active\":false,\"benchmark\":null}");
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadActiveBenchmark)
    );
    assert!(audit.intents.is_empty());

    let (exit, output, error, requests, audit) = run(
        &["benchmark", "stop", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkRecord(Some(verification)),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("There is no active benchmark to stop."));
    assert_eq!(
        requests.borrow().as_slice(),
        &[
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadActiveBenchmark,
        ]
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Stops only the active verification identity and refuses to stop an unrelated local job.
#[test]
fn process_verification_stop_is_authority_scoped() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let local = benchmark_snapshot(BenchmarkKind::Local);
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "verification", "stop", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::BenchmarkRecord(Some(local)),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("There is no active runtime verification to stop."));
    assert_eq!(
        requests.borrow().as_slice(),
        &[
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadActiveBenchmark,
        ]
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);

    let verification = benchmark_snapshot(verification_kind());
    let job_id = verification.job_id().clone();
    let (exit, output, error, requests, audit) = run(
        &["benchmark", "verification", "stop", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::BenchmarkRecord(Some(verification.clone())),
            NodePrivateResponse::BenchmarkChanged(verification),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"kind\":\"verification\""));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::StopBenchmark { job_id })
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Routes every audit leaf through the typed Node projection and preserves bounded export modes.
#[test]
fn process_routes_audit_queries_and_bounded_export() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let event = audit_event();
    let (exit, output, error, requests, audit) = run(
        &["audit", "list", "--limit", "1", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::AuditEvents(vec![event.clone()]),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"action\":\"model.install\""));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ReadAuditEvents { limit: 1 })
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);

    let (exit, output, error, requests, _) = run(
        &["audit", "show", event.event_id().as_str(), "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::AuditEvent(event.clone()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains(event.event_id().as_str()));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::ReadAuditEvent { .. })
    ));

    let verification =
        NodeAuditVerification::new(1, 0, event.event_hash().clone()).expect("verification");
    let (exit, output, error, requests, _) = run(
        &["audit", "verify", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::AuditVerification(verification),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"valid\":true"));
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::VerifyAudit)
    );

    let document = b"{\"events\":[],\"schema_version\":2}\n".to_vec();
    let (exit, output, error, requests, _) = run(
        &["audit", "export"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::AuditExport(
                NodeAuditExport::new(document.clone(), 0).expect("export"),
            ),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert_eq!(output.as_bytes(), document.as_slice());
    assert_eq!(
        requests.borrow().last(),
        Some(&NodePrivateRequest::ExportAudit)
    );

    let directory = tempfile::tempdir().expect("temporary directory");
    let output_path = directory.path().join("audit.json");
    let output_argument = output_path.to_str().expect("output path");
    let (exit, output, error, _, _) = run(
        &["audit", "export", "--output", output_argument],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::AuditExport(
                NodeAuditExport::new(document.clone(), 0).expect("export"),
            ),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.contains("Exporting the audit chain"));
    assert!(!error.contains("ERROR"));
    assert!(output.contains("Audit export"));
    assert_eq!(fs::read(output_path).expect("export file"), document);
}

// Opens one remote invitation through Node authority and presents its setup code once.
#[test]
fn process_opens_pairing_invitation_with_exact_mode_and_one_time_output() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let pairing = Arc::new(NodePairingMock::new(node(
        '2',
        "homeai-child",
        NodeRole::Child,
        NodeState::Active,
    )));
    let setup_code = "12345678";
    let (exit, output, error, requests, audit) = run_with_node_pairing(
        &["node", "add", "--mode", "remote", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::PairingInvitation(pairing_invitation()),
        ],
        pairing,
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert_eq!(output.matches(setup_code).count(), 1);
    assert!(output.contains("\"mode\":\"remote\""));
    assert!(output.contains("\"port\":9769"));
    assert!(output.contains("\"setup_code_shown_once\":true"));
    let requests = requests.borrow();
    let NodePrivateRequest::OpenPairing(request) = requests.last().expect("open request") else {
        panic!("open pairing request");
    };
    assert!(matches!(request.mode(), NodePairingMode::Remote));
    assert_eq!(request.lifetime_seconds(), 180);
    assert!(request.idempotency_key().starts_with("pairing:"));
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Presents remote comparison state once and sends no approval before explicit confirmation.
#[test]
fn process_reads_remote_pairing_approval_before_mutation() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let pairing = Arc::new(NodePairingMock::new(node(
        '2',
        "homeai-child",
        NodeRole::Child,
        NodeState::Active,
    )));
    let comparison_code = "654321";
    let invitation = pairing_invite_id().as_str().to_string();
    let (exit, output, error, requests, audit) = run_with_node_pairing(
        &["node", "add", "--approve", &invitation, "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::PairingStatus(pairing_pending_status()),
        ],
        pairing,
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert_eq!(output.matches(comparison_code).count(), 1);
    assert!(output.contains("\"state\":\"pending_approval\""));
    assert!(output.contains("\"comparison_code_shown_once\":true"));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::ReadPairingStatus { .. })
    ));
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Forwards one exact remote join endpoint while deriving all machine proof inside Core.
#[test]
fn process_forwards_remote_pairing_join_without_machine_identity_arguments() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let child = node('2', "homeai-child", NodeRole::Child, NodeState::Active);
    let pairing = Arc::new(NodePairingMock::new(child));
    let invitation = pairing_invite_id().as_str().to_string();
    let certificate = digest('5').as_str().to_string();
    let (exit, output, error, requests, audit) = run_with_node_pairing(
        &[
            "node",
            "add",
            "--join",
            "--mode",
            "remote",
            "--invitation",
            &invitation,
            "--address",
            "main.example:9769",
            "--certificate-sha256",
            &certificate,
            "--timeout",
            "90",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::Nodes(vec![main]),
        ],
        Arc::clone(&pairing),
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"role\":\"child\""));
    assert_eq!(requests.borrow().len(), 3);
    let joins = pairing.joins.lock().expect("join calls");
    assert_eq!(joins.len(), 1);
    assert_eq!(joins[0].mode(), NativeNodePairingMode::Remote);
    assert_eq!(joins[0].timeout(), Duration::from_secs(90));
    let NativeNodePairingJoinSource::Remote {
        invite_id,
        endpoint,
    } = joins[0].source()
    else {
        panic!("remote join source");
    };
    assert_eq!(invite_id.as_str(), invitation);
    assert_eq!(endpoint.address().as_str(), "main.example:9769");
    assert_eq!(endpoint.port(), 9_769);
    assert_eq!(endpoint.certificate_sha256().as_str(), certificate);
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Uses candidate-offer preflight before opening one proof-bound ConnectX invitation.
#[test]
fn process_opens_connectx_pairing_only_after_exact_interface_preflight() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let pairing = Arc::new(NodePairingMock::new(node(
        '2',
        "homeai-child",
        NodeRole::Child,
        NodeState::Active,
    )));
    let interface = NetworkInterfaceName::parse("mlx5_0").expect("interface");
    let invitation = NodePairingInvitation::new(
        pairing_invite_id(),
        NodePairingMode::ConnectX {
            candidate_public_key_sha256: digest('8'),
            direct_interface: interface.clone(),
        },
        digest('6'),
        UnixMilliseconds::new(180_000),
        None,
    )
    .expect("ConnectX invitation");
    let (exit, output, error, requests, audit) = run_with_node_pairing(
        &[
            "node",
            "add",
            "--mode",
            "connectx",
            "--interface",
            interface.as_str(),
            "--timeout",
            "60",
            "--json",
        ],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::PairingInvitation(invitation),
        ],
        Arc::clone(&pairing),
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"mode\":\"connectx\""));
    assert!(output.contains("\"setup_code\":null"));
    let connectx = pairing.connectx.lock().expect("connectx calls");
    assert_eq!(connectx.as_slice(), &[(interface, Duration::from_secs(60))]);
    let requests = requests.borrow();
    let NodePrivateRequest::OpenPairing(request) = requests.last().expect("open request") else {
        panic!("open pairing request");
    };
    assert!(matches!(request.mode(), NodePairingMode::ConnectX { .. }));
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Routes every explicit main-owned child transition with exact version and deterministic time.
#[test]
fn process_routes_explicit_node_lifecycle_transitions() {
    let cases = [
        (
            "pause",
            NodeState::Active,
            NodeState::Draining,
            NodeTransition::Pause,
        ),
        (
            "resume",
            NodeState::Draining,
            NodeState::Active,
            NodeTransition::Resume,
        ),
        (
            "remove",
            NodeState::Draining,
            NodeState::Removed,
            NodeTransition::Remove,
        ),
    ];
    for (action, before_state, after_state, expected_transition) in cases {
        let before = node('2', "homeai-node-2", NodeRole::Child, before_state);
        let after = node('2', "homeai-node-2", NodeRole::Child, after_state);
        let (exit, output, error, requests, audit) = run_node_transition(
            &["node", action, "homeai-node-2", "--yes", "--json"],
            before,
            after,
        );
        assert_eq!(exit, CliExitCode::Success, "{action}: {error}");
        assert!(error.is_empty(), "{error}");
        assert!(output.contains(&format!(
            "\"state\":\"{}\"",
            match after_state {
                NodeState::Active => "active",
                NodeState::Draining => "draining",
                NodeState::Removed => "removed",
                _ => unreachable!("fixture state"),
            }
        )));
        let requests = requests.borrow();
        assert_eq!(requests.len(), 5);
        assert!(matches!(requests[2], NodePrivateRequest::ReadNodes));
        assert!(matches!(requests[3], NodePrivateRequest::ReadNode { .. }));
        let NodePrivateRequest::TransitionChild {
            expected_revision,
            transition,
            updated_at,
            idempotency_key,
            ..
        } = &requests[4]
        else {
            panic!("transition request");
        };
        assert_eq!(*expected_revision, 7);
        assert_eq!(*transition, expected_transition);
        assert_eq!(*updated_at, UnixMilliseconds::new(3_000));
        assert!(idempotency_key.starts_with("li_cli_node_"));
        assert_eq!(audit.intents.len(), 1);
        assert_eq!(audit.results.len(), 1);
        assert!(audit.results[0].failure_code().is_none());
    }
}

// Rejects an unexpected context response before any capability or audit call can execute.
#[test]
fn process_rejects_wrong_context_response_shape() {
    let (exit, output, error, requests, audit) = run(
        &["node", "list", "--json"],
        [NodePrivateResponse::Nodes(Vec::new())],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("unexpected context response"));
    assert_eq!(
        requests.borrow().as_slice(),
        &[NodePrivateRequest::ReadLocalNode]
    );
    assert!(audit.intents.is_empty());
}

// Converts explicit endpoint absence into unconfigured authorization rather than a transport fatal.
#[test]
fn process_preserves_unconfigured_node_context() {
    let client = NodePrivateClient::new(
        AbsentExchange,
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new(client);
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        ["node", "list", "--json"],
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(standard_output.is_empty());
    assert!(String::from_utf8(standard_error)
        .expect("standard error")
        .contains("requires a configured node"));
    assert!(audit.intents.is_empty());
}

// Routes controller add, list, and revoke through secret-free typed Node projections.
#[test]
fn process_routes_every_controller_leaf_with_stable_machine_output() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let controller = controller();
    let certificate_sha256 = controller.certificate_sha256().as_str().to_string();
    let cases = [
        (
            vec![
                "auth",
                "controller",
                "add",
                "--timeout",
                "30",
                "--role",
                "administrator",
            ],
            NodePrivateResponse::ControllerEnrollment(controller_receipt()),
            "add_controller",
            true,
        ),
        (
            vec!["auth", "controller", "list", "--json"],
            NodePrivateResponse::Controllers(vec![controller.clone()]),
            "read_controllers",
            false,
        ),
        (
            vec!["auth", "controller", "revoke", "Desk Mac", "--json"],
            NodePrivateResponse::Controller(controller),
            "revoke_controller",
            false,
        ),
    ];
    for (arguments, response, expected_request, enrollment) in cases {
        let responses = [NodePrivateResponse::LocalNode(main.clone()), response];
        let (exit, output, error, requests, audit) = if enrollment {
            run_with_controller_enrollment(&arguments, responses)
        } else {
            run(&arguments, responses)
        };
        assert_eq!(exit, CliExitCode::Success);
        assert!(!error.contains("ERROR"), "{error}");
        assert!(output.contains("Desk Mac"));
        assert!(output.contains(&certificate_sha256));
        assert!(!output.contains("certificate_public_material"));
        assert!(!output.contains("private_key"));
        assert_eq!(
            match requests.borrow().last().expect("request") {
                NodePrivateRequest::AddController { .. } => "add_controller",
                NodePrivateRequest::ReadControllers => "read_controllers",
                NodePrivateRequest::RevokeController { .. } => "revoke_controller",
                _ => "unexpected",
            },
            expected_request
        );
        assert_eq!(audit.intents.len(), 1);
        assert_eq!(audit.results.len(), 1);
    }
}

// Rejects unsafe controller enrollment timeout before opening a private request.
#[test]
fn process_rejects_invalid_controller_timeout_before_dispatch() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, audit) = run(
        &["auth", "controller", "add", "--timeout", "29"],
        [NodePrivateResponse::LocalNode(main)],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("between 30 and 180 seconds"));
    assert_eq!(requests.borrow().len(), 1);
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Routes all six public API-key leaves through the typed private Node contract.
#[test]
fn process_routes_every_api_key_leaf_with_stable_machine_output() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let key = api_key();
    let cases = [
        (
            vec!["auth", "key", "list", "--json"],
            NodePrivateResponse::ApiKeys(vec![key.clone()]),
            "read_api_keys",
        ),
        (
            vec!["auth", "key", "show", "application", "--json"],
            NodePrivateResponse::ApiKey(key.clone()),
            "read_api_key",
        ),
        (
            vec![
                "auth",
                "key",
                "update",
                "application",
                "--concurrency",
                "4",
                "--json",
            ],
            NodePrivateResponse::ApiKey(key.clone()),
            "update_api_key_policy",
        ),
        (
            vec!["auth", "key", "revoke", "application", "--json"],
            NodePrivateResponse::ApiKey(key.clone()),
            "revoke_api_key",
        ),
    ];
    for (arguments, response, expected_request) in cases {
        let (exit, output, error, requests, audit) = run(
            &arguments,
            [NodePrivateResponse::LocalNode(main.clone()), response],
        );
        assert_eq!(exit, CliExitCode::Success);
        assert!(error.is_empty());
        assert!(output.contains("\"key_id\""));
        assert!(!output.contains("\"token\""));
        assert_eq!(
            match requests.borrow().last().expect("request") {
                NodePrivateRequest::ReadApiKeys => "read_api_keys",
                NodePrivateRequest::ReadApiKey { .. } => "read_api_key",
                NodePrivateRequest::UpdateApiKeyPolicy { .. } => "update_api_key_policy",
                NodePrivateRequest::RevokeApiKey { .. } => "revoke_api_key",
                _ => "unexpected",
            },
            expected_request
        );
        if expected_request == "read_api_keys" || expected_request == "read_api_key" {
            assert_eq!(audit.intents.len(), 1, "sensitive read audit");
        } else {
            assert_eq!(audit.intents.len(), 1, "mutation audit");
        }
        assert_eq!(audit.results.len(), 1);
        if let Some(target) = audit.intents[0].target() {
            assert!(target.identifier().starts_with("sha256-"));
            assert!(!format!("{:?}", audit.intents[0]).contains("application"));
        }
    }
}

// Proves the production audit adapter opens before dispatch and completes after command success.
#[test]
fn node_audit_adapter_wraps_success_with_correlated_local_requests() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests) = run_with_node_audit(
        &["auth", "key", "revoke", "application", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::CommandAuditOpened(NodeCommandAuditOpenReceipt::new(
                audit_marker(),
                NodeCommandAuditOpenDisposition::Opened,
            )),
            NodePrivateResponse::ApiKey(api_key()),
            NodePrivateResponse::CommandAuditCompleted(NodeCommandAuditCompletionReceipt::new(
                None,
                NodeCommandAuditCompletionDisposition::Completed,
            )),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"state\":\"active\""));
    let requests = requests.borrow();
    assert_eq!(requests.len(), 4);
    let NodePrivateRequest::OpenCommandAudit(open) = &requests[1] else {
        panic!("audit open");
    };
    assert_eq!(open.command_id(), &digest('b'));
    let target = open.intent().target().expect("target");
    assert_eq!(
        target.kind(),
        li_node_manager::NodeCommandAuditTargetKind::ApiKey
    );
    assert!(target.identifier().starts_with("sha256-"));
    assert!(!format!("{open:?}").contains("application"));
    assert!(matches!(
        requests[2],
        NodePrivateRequest::RevokeApiKey { .. }
    ));
    let NodePrivateRequest::CompleteCommandAudit(completion) = &requests[3] else {
        panic!("audit completion");
    };
    assert_eq!(
        completion.result().outcome(),
        NodeCommandAuditOutcome::Succeeded
    );
}

// Proves a capability failure still closes the opened durable audit without a mutation request.
#[test]
fn node_audit_adapter_completes_local_capability_failure() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests) = run_with_node_audit(
        &["node", "pause", "--yes", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::CommandAuditOpened(NodeCommandAuditOpenReceipt::new(
                audit_marker(),
                NodeCommandAuditOpenDisposition::Opened,
            )),
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::CommandAuditCompleted(NodeCommandAuditCompletionReceipt::new(
                None,
                NodeCommandAuditCompletionDisposition::Completed,
            )),
        ],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("explicit child node identity"));
    let requests = requests.borrow();
    assert_eq!(requests.len(), 4);
    assert!(matches!(
        requests[1],
        NodePrivateRequest::OpenCommandAudit(_)
    ));
    assert!(matches!(requests[2], NodePrivateRequest::ReadLocalNode));
    let NodePrivateRequest::CompleteCommandAudit(completion) = &requests[3] else {
        panic!("audit completion");
    };
    assert_eq!(
        completion.result().outcome(),
        NodeCommandAuditOutcome::Failed
    );
    assert_eq!(
        completion.result().failure_code(),
        Some("node.selection_required")
    );
}

// Proves an unavailable audit begin fails closed before the capability can send its mutation.
#[test]
fn node_audit_open_failure_precedes_private_command_dispatch() {
    let requests = Rc::new(RefCell::new(Vec::new()));
    let client = NodePrivateClient::new(
        AuditOpenFailureExchange {
            local_node: node('1', "homeai", NodeRole::Main, NodeState::Active),
            requests: Rc::clone(&requests),
        },
        IdentityMock::new(),
        NodePrivateClientConfiguration::default(),
    );
    let mut process = NativeNodeCliProcess::new(client);
    let mut output = Vec::new();
    let mut error = Vec::new();
    let exit = process.run_with_node_audit(
        ["auth", "key", "revoke", "application", "--json"],
        &mut output,
        &mut error,
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    let error = String::from_utf8(error).expect("error");
    assert!(error.contains("command-audit service is unavailable"));
    let requests = requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], NodePrivateRequest::ReadLocalNode);
    assert!(matches!(
        requests[1],
        NodePrivateRequest::OpenCommandAudit(_)
    ));
}

// Presents create and rotation tokens once in JSON without retaining them in audit or debug state.
#[test]
fn process_presents_create_and_rotation_tokens_once_with_redacted_state() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    for arguments in [
        vec!["auth", "key", "create", "application", "--json"],
        vec!["auth", "key", "rotate", "application", "--json"],
    ] {
        let secret = api_token();
        let response =
            NodePrivateResponse::ApiKeyIssued(NodeIssuedApiKey::new(api_key(), secret.clone()));
        assert!(!format!("{response:?}").contains(&secret));
        let (exit, output, error, requests, audit) = run(
            &arguments,
            [NodePrivateResponse::LocalNode(main.clone()), response],
        );
        assert_eq!(exit, CliExitCode::Success);
        assert!(error.is_empty());
        assert_eq!(output.matches(&secret).count(), 1);
        assert!(output.contains("\"token_shown_once\":true"));
        assert_eq!(audit.intents.len(), 1);
        assert_eq!(audit.results.len(), 1);
        assert!(!format!("{:?}{:?}", audit.intents, audit.results).contains(&secret));
        assert!(matches!(
            requests.borrow().last(),
            Some(NodePrivateRequest::CreateApiKey { .. })
                | Some(NodePrivateRequest::RotateApiKey { .. })
        ));
    }
}

// Presents the one-time token once through the human display path and nowhere in diagnostics.
#[test]
fn process_presents_one_human_token_without_debug_or_error_leakage() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let secret = api_token();
    let (exit, output, error, _, audit) = run(
        &["auth", "key", "create", "application"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::ApiKeyIssued(NodeIssuedApiKey::new(api_key(), secret.clone())),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert_eq!(output.matches(&secret).count(), 1);
    assert!(output.contains("This token is shown once"));
    assert!(!error.contains(&secret));
    assert!(!format!("{:?}{:?}", audit.intents, audit.results).contains(&secret));
}

// Rejects invalid policy values before sending a mutation to the private Node endpoint.
#[test]
fn process_rejects_invalid_policy_before_private_dispatch() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, audit) = run(
        &[
            "auth",
            "key",
            "create",
            "application",
            "--concurrency",
            "0",
            "--json",
        ],
        [NodePrivateResponse::LocalNode(main)],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("limit must be positive"));
    assert_eq!(
        requests.borrow().as_slice(),
        &[NodePrivateRequest::ReadLocalNode]
    );
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Routes a read-only Core check through the typed projection in human and JSON modes.
#[test]
fn process_presents_core_update_check_without_mutation() {
    for json in [false, true] {
        let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
        let check = NodeCoreUpdateCheck::new(
            core_installation("1.0.0", '1'),
            core_installation("1.1.0", '2'),
        );
        let arguments = if json {
            vec!["update", "check", "--json"]
        } else {
            vec!["update", "check"]
        };
        let (exit, output, error, requests, audit) = run(
            &arguments,
            [
                NodePrivateResponse::LocalNode(main),
                NodePrivateResponse::CoreUpdateCheck(check),
            ],
        );
        assert_eq!(exit, CliExitCode::Success);
        if json {
            assert!(error.is_empty());
        } else {
            assert!(error.contains("Update check complete"));
        }
        assert!(output.contains("1.0.0"));
        assert!(output.contains("1.1.0"));
        assert!(output.contains("update_available"));
        assert!(matches!(
            requests.borrow().last(),
            Some(NodePrivateRequest::CheckCoreUpdate {
                requested_version: None
            })
        ));
        assert!(audit.intents.is_empty());
    }
}

// Requires confirmation, preserves an exact requested version, and presents manager state.
#[test]
fn process_core_update_confirms_and_binds_exact_version() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, audit) = run(
        &["update", "core", "1.1.0", "--json"],
        [NodePrivateResponse::LocalNode(main.clone())],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("Pass --yes"));
    assert_eq!(
        requests.borrow().as_slice(),
        &[NodePrivateRequest::ReadLocalNode]
    );
    assert_eq!(audit.results.len(), 1);

    let available = core_installation("1.1.0", '2');
    let (exit, output, error, requests, audit) = run(
        &["update", "core", "1.1.0", "--yes", "--json"],
        [
            NodePrivateResponse::LocalNode(main),
            NodePrivateResponse::CoreUpdateCheck(NodeCoreUpdateCheck::new(
                core_installation("1.0.0", '1'),
                available.clone(),
            )),
            NodePrivateResponse::CoreUpdated(NodeCoreUpdateSummary::new(
                available,
                CoreUpdateDisposition::Updated,
                CoreUpdatePhase::Succeeded,
            )),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"disposition\":\"updated\""));
    assert!(output.contains("\"phase\":\"succeeded\""));
    let requests = requests.borrow();
    assert!(matches!(
        &requests[1],
        NodePrivateRequest::CheckCoreUpdate {
            requested_version: Some(version)
        } if version.as_str() == "1.1.0"
    ));
    assert!(matches!(
        &requests[2],
        NodePrivateRequest::UpdateCore {
            requested_version: Some(version),
            ..
        } if version.as_str() == "1.1.0"
    ));
    assert_eq!(audit.results.len(), 1);
}

// Allows read-only model checks without confirmation and blocks unconfirmed mutation.
#[test]
fn process_model_update_confirmation_distinguishes_dry_run() {
    let main = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let (exit, output, error, requests, _) = run(
        &["update", "model", "deepseek_r1", "--dry-run", "--json"],
        [
            NodePrivateResponse::LocalNode(main.clone()),
            NodePrivateResponse::ModelServices(vec![installed_model_service()]),
            NodePrivateResponse::ModelUpdated(model_update_available()),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty());
    assert!(output.contains("\"disposition\":\"update_available\""));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::UpdateModel(request)) if request.is_dry_run()
    ));

    let (exit, output, error, requests, _) = run(
        &["update", "model", "deepseek_r1", "--json"],
        [NodePrivateResponse::LocalNode(main)],
    );
    assert_eq!(exit, CliExitCode::Failure);
    assert!(output.is_empty());
    assert!(error.contains("Pass --yes"));
    assert_eq!(
        requests.borrow().as_slice(),
        &[NodePrivateRequest::ReadLocalNode]
    );

    let updated = NodeModelUpdateSummary::new(
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("deepseek_r1").expect("model"),
        NodeModelUpdateDisposition::Updated,
        1,
        Some(NodeModelCommandSummary::new(
            OperationId::parse(&"7".repeat(32)).expect("operation"),
            ModelServiceId::parse(&"4".repeat(32)).expect("service"),
            LogicalModelName::parse("deepseek_r1").expect("model"),
            ModelServiceDesiredState::Running,
            NodeModelAction::Update,
            NodeModelJournalState::Succeeded,
            None,
        )),
    );
    let (exit, output, error, requests, audit) = run(
        &["update", "model", "deepseek_r1", "--yes", "--json"],
        [
            NodePrivateResponse::LocalNode(node('1', "homeai", NodeRole::Main, NodeState::Active)),
            NodePrivateResponse::ModelServices(vec![installed_model_service()]),
            NodePrivateResponse::ModelUpdated(updated),
        ],
    );
    assert_eq!(exit, CliExitCode::Success);
    assert!(error.is_empty(), "{error}");
    assert!(output.contains("\"disposition\":\"updated\""));
    assert!(matches!(
        requests.borrow().last(),
        Some(NodePrivateRequest::UpdateModel(request)) if !request.is_dry_run()
    ));
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
}

// Runs ordinary native process composition through a real owner-only Unix socket.
#[test]
fn system_process_executes_real_unix_node_roundtrip() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let directory_path = fs::canonicalize(directory.path()).expect("canonical private directory");
    let socket_path = directory_path.join("node.sock");
    let listener = UnixListener::bind(&socket_path).expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("private socket");
    let local_node = node('1', "homeai", NodeRole::Main, NodeState::Active);
    let server_node = local_node.clone();
    let server = thread::spawn(move || serve_local_node(listener, server_node));

    let entropy_path = directory_path.join("entropy");
    fs::write(&entropy_path, vec![0x12; 64]).expect("entropy");
    let mut process = compose_system_native_node_cli(
        socket_path,
        &entropy_path,
        NodePrivateClientConfiguration::default(),
    )
    .expect("system process");
    let mut audit = AuditMock::default();
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(
        ["node", "info", "--json"],
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    server.join().expect("server");

    assert_eq!(exit, CliExitCode::Success);
    assert!(standard_error.is_empty());
    let output = String::from_utf8(standard_output).expect("standard output");
    assert!(output.contains(local_node.identity().node_id().as_str()));
    assert!(output.contains("\"role\":\"main\""));
    assert!(audit.intents.is_empty());
}
