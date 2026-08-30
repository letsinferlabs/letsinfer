// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditCorrelationId, AuditEvent,
    AuditEventId, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditTarget,
    AuditUnixNanoseconds,
};
use li_benchmark_manager::{
    BenchmarkDisposition, BenchmarkGitRevision, BenchmarkJobPhase, BenchmarkKind, BenchmarkRequest,
    BenchmarkScope, BenchmarkSubject, BenchmarkVerificationPhase,
};
use li_core_interface::{
    BootId, ByteCount, CpuArchitecture, CredentialId, DisplayName, EntityTimestamps, EvidenceLabel,
    HardwareObservation, HardwareObservationId, InstallationId, LogicalModelName, MachineId,
    ModelServiceId, Node, NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, OperatingSystem,
    OperationId, PairingInviteId, PlacementGroupId, PlatformIdentity, ProcessorObservation,
    RuntimeCandidateId, RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId, TechnicalName, UnixMilliseconds,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateDisposition, CoreUpdatePhase, CoreVersion,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_gateway_manager::{GatewayExposure, GatewayExposureStatus};
use li_node_manager::{
    NodeAuditExport, NodeAuditVerification, NodeBenchmarkCandidateHandoffPhase,
    NodeBenchmarkContext, NodeBenchmarkPlan, NodeBenchmarkSelection, NodeBenchmarkSnapshot,
    NodeBenchmarkSnapshotProgress, NodeBenchmarkVerificationProjection, NodeCatalogAuthor,
    NodeCatalogAuthorKind, NodeCatalogEntry, NodeCatalogListRequest, NodeCatalogListing,
    NodeCatalogRefreshPolicy, NodeCatalogSnapshot, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection, NodeCommandAuditCompletionDisposition,
    NodeCommandAuditCompletionReceipt, NodeCommandAuditCompletionRequest, NodeCommandAuditIntent,
    NodeCommandAuditMarker, NodeCommandAuditMutation, NodeCommandAuditOpenDisposition,
    NodeCommandAuditOpenReceipt, NodeCommandAuditOpenRequest, NodeCommandAuditOutcome,
    NodeCommandAuditPolicy, NodeCommandAuditResult, NodeCommandAuditTarget,
    NodeCommandAuditTargetKind, NodeCoreUpdateCheck, NodeCoreUpdateSummary, NodeHostGatewaySummary,
    NodeHostInventory, NodeHostProjectionValue, NodeHostServiceState, NodeHostSnapshot,
    NodeManager, NodeModelCommandIdentity, NodeModelRemovalRetention, NodeModelRemovalSelection,
    NodeModelRemoveRequest, NodeModelRollbackGroupPreview, NodeModelRollbackPreview,
    NodeModelRollbackRuntime, NodeModelRuntimeLogBatch, NodeModelRuntimeLogRequest,
    NodeModelUpdateDisposition, NodeModelUpdateRequest, NodeModelUpdateSummary,
    NodePairedChildActivationRequest, NodePairedMainRestorationRequest, NodePairingApiError,
    NodePairingApiPort, NodePairingApproveRequest, NodePairingAuthorityDisposition,
    NodePairingAuthorityReceipt, NodePairingCredentials, NodePairingEnrollRequest,
    NodePairingEnrollment, NodePairingInvitation, NodePairingMode, NodePairingOpenRequest,
    NodePairingState, NodePairingStatus, NodePrivateAction, NodePrivateApi, NodePrivateApiError,
    NodePrivateAuthorizationProvider, NodePrivateEndpoint, NodePrivateRemoteError,
    NodePrivateRequest, NodePrivateResponse, NodePrivateTransport, NodePrivateTransportError,
    NodePrivateTransportOutcome, NodePrivateTransportRequest, NodePrivateTransportResponse,
    NodeRuntimeModelRetention, NodeRuntimeRemovalDisposition, NodeStorageCandidate,
    NodeStorageCategory, NodeStorageCleanReceipt, NodeStorageCleanRequest, NodeStorageError,
    NodeStorageSnapshot, NodeStorageUsage, NodeTransition, NodeUninstallBeginReceipt,
    NodeUninstallCancelReceipt, NodeUninstallInventory, NodeUninstallModelTarget,
    NodeUninstallRequest, NodeUninstallSessionDisposition, NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};
use li_placement_manager::{PlacementLogBatch, PlacementLogCursor};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Authorizes every private action for deterministic transport tests.
struct AllowAuthorization;

impl NodePrivateAuthorizationProvider for AllowAuthorization {
    // Allows one exact action without consulting external credentials.
    fn authorize(
        &self,
        _principal_id: &CredentialId,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        Ok(())
    }
}

// Denies every private action before dispatch.
struct DenyAuthorization;

impl NodePrivateAuthorizationProvider for DenyAuthorization {
    // Returns the generic private authorization denial.
    fn authorize(
        &self,
        _principal_id: &CredentialId,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        Err(NodePrivateApiError::AuthorizationDenied)
    }
}

// Rejects pairing because the ordinary transport fixtures below use manager-owned actions.
struct UnavailablePairing;

impl NodePairingApiPort for UnavailablePairing {
    // Rejects an unexpected invitation open call.
    fn open(
        &self,
        _request: &NodePairingOpenRequest,
    ) -> Result<NodePairingInvitation, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }

    // Rejects an unexpected candidate enrollment call.
    fn enroll(
        &self,
        _request: &NodePairingEnrollRequest,
    ) -> Result<NodePairingEnrollment, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }

    // Rejects an unexpected pending approval call.
    fn approve(
        &self,
        _request: &NodePairingApproveRequest,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }

    // Rejects an unexpected pairing status call.
    fn status(
        &self,
        _invite_id: &PairingInviteId,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }
}

// Opens one isolated database manager with deterministic native time.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    )
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one coherent node fixture.
#[allow(clippy::too_many_arguments)]
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    name: &str,
    role: NodeRole,
    state: NodeState,
    address: &str,
    updated_at: u64,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character, 32)).expect("node"),
            MachineId::parse(&identity(machine_character, 32)).expect("machine"),
            InstallationId::parse(&identity(installation_character, 64)).expect("installation"),
        ),
        DisplayName::parse(name).expect("name"),
        role,
        state,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(
            UnixMilliseconds::new(1_000),
            UnixMilliseconds::new(updated_at),
        )
        .expect("timestamps"),
    )
}

// Returns the ordinary active local main fixture.
fn main_node() -> Node {
    node(
        '1',
        '2',
        '3',
        "Home AI",
        NodeRole::Main,
        NodeState::Active,
        "homeai.local",
        1_000,
    )
}

// Returns one valid processor-only hardware observation for the local node.
fn hardware_observation() -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&identity('4', 32)).expect("observation"),
        NodeId::parse(&identity('1', 32)).expect("node"),
        BootId::parse("boot-1").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA GB10").expect("processor"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        Vec::new(),
        Vec::new(),
        UnixMilliseconds::new(2_000),
    )
    .expect("hardware observation")
}

// Returns one complete wire-safe local host with explicit unsupported sections.
fn host_snapshot() -> NodeHostSnapshot {
    NodeHostSnapshot::restore(
        main_node(),
        NodeHostProjectionValue::Available(hardware_observation()),
        NodeHostProjectionValue::Available(Vec::new()),
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::NotApplicable,
        NodeHostProjectionValue::Available(NodeHostGatewaySummary::new(
            NodeHostServiceState::Ready,
            None,
        )),
        NodeHostProjectionValue::NotApplicable,
    )
    .expect("host snapshot")
}

// Returns one canonical local inventory with explicit unavailable model state.
fn host_inventory() -> NodeHostInventory {
    NodeHostInventory::new(
        main_node().identity().node_id().clone(),
        vec![host_snapshot()],
        NodeHostProjectionValue::Unavailable,
    )
    .expect("host inventory")
}

// Returns one ordinary pending child fixture.
fn child_node() -> Node {
    node(
        '4',
        '5',
        '6',
        "Node 2",
        NodeRole::Child,
        NodeState::Pending,
        "homeai-node-2.local",
        1_000,
    )
}

// Opens one shared manager and private API over deterministic storage.
fn api(
    directory: &tempfile::TempDir,
    authorization: Arc<dyn NodePrivateAuthorizationProvider>,
) -> NodePrivateApi {
    let manager = NodeManager::open(database(directory), main_node(), "initialize-node")
        .expect("manager")
        .0;
    NodePrivateApi::new(
        Arc::new(manager),
        authorization,
        Arc::new(UnavailablePairing),
    )
}

// Returns one exact request correlation identity.
fn request_id(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("request identity")
}

// Returns one coherent reviewed storage projection without absolute paths.
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
        request_id('e'),
    )
    .expect("storage snapshot")
}

// Returns one exact cleanup request bound to the storage fixture.
fn storage_clean_request() -> NodeStorageCleanRequest {
    NodeStorageCleanRequest::new(
        OperationId::parse(&identity('f', 32)).expect("operation"),
        storage_snapshot().plan_digest().clone(),
        [NodeStorageCategory::Caches],
    )
    .expect("storage clean request")
}

// Returns one durable cleanup result bound to the storage fixture.
fn storage_clean_receipt() -> NodeStorageCleanReceipt {
    let request = storage_clean_request();
    NodeStorageCleanReceipt::new(
        request.operation_id().clone(),
        request.plan_digest().clone(),
        1,
        1_000,
        Vec::new(),
        false,
    )
    .expect("storage clean receipt")
}

// Returns one complete deterministic signed catalog projection.
fn catalog_listing() -> NodeCatalogListing {
    NodeCatalogListing::new(
        NodeCatalogSnapshot::new(
            "https://letsinfer.ai/catalog.json".to_string(),
            request_id('a'),
            request_id('b'),
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

// Returns one exact private credential identity.
fn principal() -> CredentialId {
    CredentialId::parse(&identity('a', 32)).expect("principal")
}

// Returns one exact model-neutral local benchmark request.
fn benchmark_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::selected(vec![
            TechnicalName::parse("context_32768_c1").expect("benchmark cell")
        ])
        .expect("benchmark scope"),
        BenchmarkSubject::new(
            InstallationId::parse(&identity('3', 64)).expect("Core installation"),
            RuntimeInstallationId::parse(&identity('4', 32)).expect("runtime installation"),
            LogicalModelName::parse("deepseek_r1").expect("logical model"),
            PlacementGroupId::parse(&identity('5', 32)).expect("placement group"),
            request_id('6'),
            request_id('7'),
            request_id('8'),
        ),
    )
    .expect("benchmark request")
}

// Returns one canonical public benchmark selection without resolved runtime identities.
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

// Returns one resolved exact local benchmark plan for response-codec coverage.
fn benchmark_plan() -> NodeBenchmarkPlan {
    let cell = TechnicalName::parse("context_32768_c1").expect("benchmark cell");
    NodeBenchmarkPlan::new(
        &benchmark_selection(),
        benchmark_request(),
        vec![cell.clone()],
        vec![cell],
    )
    .expect("benchmark plan")
}

// Returns one exact complete community-verification benchmark request.
fn verification_benchmark_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            42,
            BenchmarkGitRevision::parse(&identity('a', 40)).expect("proposal revision"),
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            OperationId::parse(&identity('d', 32)).expect("transaction"),
            request_id('e'),
            request_id('f'),
            7,
            request_id('b'),
            Some(request_id('c')),
        )
        .expect("verification kind"),
        BenchmarkScope::Complete,
        benchmark_request().subject().clone(),
    )
    .expect("verification request")
}

// Returns one coherent running benchmark status without prompts, outputs, or credentials.
fn benchmark_snapshot() -> NodeBenchmarkSnapshot {
    benchmark_snapshot_with_kind(BenchmarkKind::Local)
}

// Returns one coherent running community-verification status projection.
fn verification_benchmark_snapshot() -> NodeBenchmarkSnapshot {
    benchmark_snapshot_with_kind(verification_benchmark_request().kind().clone())
}

// Returns one coherent running benchmark status for the exact supplied authority.
fn benchmark_snapshot_with_kind(kind: BenchmarkKind) -> NodeBenchmarkSnapshot {
    let verification = kind.is_verification().then(|| {
        NodeBenchmarkVerificationProjection::new(
            BenchmarkVerificationPhase::BaselineRunning,
            OperationId::parse(&identity('d', 32)).expect("handoff transaction"),
            NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
        )
    });
    NodeBenchmarkSnapshot::restore(
        OperationId::parse(&identity('d', 32)).expect("benchmark job"),
        3,
        kind,
        BenchmarkJobPhase::Running,
        Some(BenchmarkDisposition::Running),
        request_id('c'),
        InstallationId::parse(&identity('3', 64)).expect("Core installation"),
        RuntimeInstallationId::parse(&identity('4', 32)).expect("runtime installation"),
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        PlacementGroupId::parse(&identity('5', 32)).expect("placement group"),
        request_id('6'),
        request_id('7'),
        request_id('8'),
        request_id('9'),
        Some(request_id('a')),
        Some(request_id('b')),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(
            NodeBenchmarkSnapshotProgress::restore(
                TechnicalName::parse("measure").expect("progress phase"),
                1,
                4,
            )
            .expect("progress"),
        ),
        verification,
        None,
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(2_000),
    )
    .expect("benchmark snapshot")
}

// Returns one exact pairing invitation identity.
fn invite_id() -> PairingInviteId {
    PairingInviteId::parse(&identity('7', 32)).expect("invitation")
}

// Returns one complete candidate enrollment request with bounded secret-bearing fields.
fn pairing_enroll_request() -> NodePairingEnrollRequest {
    NodePairingEnrollRequest::new(
        "enroll-pairing".to_string(),
        invite_id(),
        child_node().identity().clone(),
        DisplayName::parse("Candidate").expect("candidate name"),
        NodeAddress::parse("candidate.local").expect("candidate address"),
        vec![1; 128],
        UnixMilliseconds::new(1_000),
        vec![2; 64],
        Some("12345678".to_string()),
        NodeAddress::parse("192.0.2.10").expect("observed address"),
    )
    .expect("enrollment request")
}

// Returns one coherent remote status for pairing response codec coverage.
fn pairing_status(state: NodePairingState) -> NodePairingStatus {
    let (child_node_id, comparison_code) = match state {
        NodePairingState::Open => (None, None),
        NodePairingState::PendingApproval => (
            Some(child_node().identity().node_id().clone()),
            Some("123456".to_string()),
        ),
        NodePairingState::Active => (Some(child_node().identity().node_id().clone()), None),
    };
    NodePairingStatus::new(
        invite_id(),
        NodePairingMode::Remote,
        state,
        UnixMilliseconds::new(5_000),
        1,
        child_node_id,
        comparison_code,
    )
    .expect("pairing status")
}

// Returns one bounded public pairing credential package.
fn pairing_credentials() -> NodePairingCredentials {
    NodePairingCredentials::new(
        vec![1],
        vec![2],
        vec![3],
        vec![4],
        request_id('8'),
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(10_000),
    )
    .expect("pairing credentials")
}

// Returns one exact paired-child authority request for codec and local-only tests.
fn pairing_activation_request() -> NodePairedChildActivationRequest {
    NodePairedChildActivationRequest::new(
        "pairing:activate".to_string(),
        main_node(),
        request_id('c'),
        pairing_credentials(),
    )
    .expect("pairing activation")
}

// Returns one exact paired-main restoration request over the same public authority package.
fn pairing_restoration_request() -> NodePairedMainRestorationRequest {
    NodePairedMainRestorationRequest::new(
        "pairing:restore".to_string(),
        main_node(),
        request_id('c'),
        pairing_credentials(),
    )
    .expect("pairing restoration")
}

// Returns one request-identity-bound audited API-key action with an explicit non-secret target.
fn command_audit_open_request() -> NodeCommandAuditOpenRequest {
    NodeCommandAuditOpenRequest::new(
        request_id('b'),
        NodeCommandAuditIntent::new(
            TechnicalName::parse("auth.key.rotate").expect("action"),
            NodeCommandAuditPolicy::Always,
            NodeCommandAuditMutation::Node,
            NodeRole::Main,
        )
        .with_target(
            NodeCommandAuditTarget::new(NodeCommandAuditTargetKind::ApiKey, "admin_key")
                .expect("target"),
        ),
    )
}

// Returns the exact opaque marker corresponding to the audit fixture identity.
fn command_audit_marker() -> NodeCommandAuditMarker {
    NodeCommandAuditMarker::parse(&format!(
        "li_cli_audit_{}_{}",
        request_id('b').as_str(),
        request_id('c').as_str()
    ))
    .expect("marker")
}

// Returns one complete structurally valid non-secret audit event for codec tests.
fn audit_event() -> AuditEvent {
    AuditEvent::from_persisted(
        1,
        AuditEventId::parse(&identity('a', 32)).expect("event"),
        AuditCorrelationId::parse(&identity('b', 32)).expect("correlation"),
        AuditUnixNanoseconds::new(1_000).expect("timestamp"),
        NodeId::parse(&identity('1', 32)).expect("node"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("local-user-501").expect("actor"),
        ),
        AuditOrigin::new(
            NodeId::parse(&identity('1', 32)).expect("origin node"),
            AuditOriginInterface::Cli,
        ),
        AuditAction::parse("model.install").expect("action"),
        AuditTarget::parse("model-service").expect("target"),
        None,
        Some(request_id('d')),
        AuditOutcome::Success,
        None,
        request_id('0'),
        request_id('f'),
    )
    .expect("audit event")
}

// Encodes and decodes one private request.
fn round_trip_request(request: NodePrivateRequest) -> NodePrivateRequest {
    let envelope = NodePrivateTransportRequest::new(request_id('b'), request);
    let bytes = NodePrivateTransport::encode_request(&envelope).expect("encode request");
    NodePrivateTransport::decode_request(&bytes)
        .expect("decode request")
        .into_request()
}

// Round-trips every private request variant through the same closed codec.
#[test]
fn request_variant_matrix_round_trips_exact_types() {
    let child = child_node();
    let requests = [
        NodePrivateRequest::ReadLocalNode,
        NodePrivateRequest::ReadNodes,
        NodePrivateRequest::ReadNode {
            node_id: NodeId::parse(&identity('4', 32)).expect("node"),
        },
        NodePrivateRequest::ReadHardware {
            node_id: NodeId::parse(&identity('1', 32)).expect("node"),
        },
        NodePrivateRequest::ReadStorage,
        NodePrivateRequest::CleanStorage(storage_clean_request()),
        NodePrivateRequest::ReadCatalog(
            NodeCatalogListRequest::new(
                Some("https://letsinfer.ai/catalog.json".to_string()),
                Some(LogicalModelName::parse("deepseek_r1").expect("model")),
                NodeCatalogVersionSelection::All,
                NodeCatalogTargetSelection::All,
                NodeCatalogRefreshPolicy::Refresh,
            )
            .expect("catalog request"),
        ),
        NodePrivateRequest::ReadCompatibleTargets {
            node_id: NodeId::parse(&identity('4', 32)).expect("node"),
            catalog_source: "https://letsinfer.ai/catalog.json".to_string(),
        },
        NodePrivateRequest::EnrollChild {
            idempotency_key: "enroll".to_string(),
            child: child.clone(),
        },
        NodePrivateRequest::TransitionChild {
            idempotency_key: "activate".to_string(),
            node_id: child.identity().node_id().clone(),
            expected_revision: 1,
            transition: NodeTransition::Activate,
            updated_at: UnixMilliseconds::new(2_000),
        },
        NodePrivateRequest::ReadPendingOutbox,
        NodePrivateRequest::AcknowledgeOutbox {
            idempotency_key: "acknowledge".to_string(),
            event_id: request_id('c'),
            expected_revision: 1,
            acknowledged_at: UnixMilliseconds::new(3_000),
        },
        NodePrivateRequest::OpenPairing(
            NodePairingOpenRequest::new(
                "open-pairing".to_string(),
                NodePairingMode::ConnectX {
                    candidate_public_key_sha256: request_id('9'),
                    direct_interface: li_core_interface::NetworkInterfaceName::parse("enp1s0")
                        .expect("interface"),
                },
                120,
            )
            .expect("open request"),
        ),
        NodePrivateRequest::EnrollPairing(pairing_enroll_request()),
        NodePrivateRequest::ApprovePairing(
            NodePairingApproveRequest::new("approve-pairing".to_string(), invite_id())
                .expect("approve request"),
        ),
        NodePrivateRequest::ReadPairingStatus {
            invite_id: invite_id(),
        },
        NodePrivateRequest::PreviewBenchmark {
            selection: benchmark_selection(),
        },
        NodePrivateRequest::StartBenchmark {
            idempotency_key: "benchmark-local".to_string(),
            selection: benchmark_selection(),
        },
        NodePrivateRequest::StartBenchmarkVerification {
            idempotency_key: "benchmark-verification".to_string(),
            pull_request_url: "https://github.com/letsinferlabs/runtimes/pull/41".to_string(),
            candidate: Some(
                RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
            ),
        },
        NodePrivateRequest::ReadActiveBenchmark,
        NodePrivateRequest::ReadBenchmark {
            job_id: benchmark_snapshot().job_id().clone(),
        },
        NodePrivateRequest::StopBenchmark {
            job_id: benchmark_snapshot().job_id().clone(),
        },
        NodePrivateRequest::OpenCommandAudit(command_audit_open_request()),
        NodePrivateRequest::CompleteCommandAudit(NodeCommandAuditCompletionRequest::new(
            command_audit_marker(),
            NodeCommandAuditResult::new(
                TechnicalName::parse("auth.key.rotate").expect("action"),
                NodeCommandAuditOutcome::Failed,
                Some("manager_unavailable"),
            )
            .expect("result"),
        )),
        NodePrivateRequest::ReadAuditEvents { limit: 100 },
        NodePrivateRequest::ReadAuditEvent {
            event_id: audit_event().event_id().clone(),
        },
        NodePrivateRequest::VerifyAudit,
        NodePrivateRequest::ExportAudit,
    ];
    for request in requests {
        assert_eq!(round_trip_request(request.clone()), request);
    }
}

// Keeps the ordinary request bytes stable and explicitly schema-identified.
#[test]
fn request_encoding_is_compact_stable_and_li_namespaced() {
    let envelope =
        NodePrivateTransportRequest::new(request_id('b'), NodePrivateRequest::ReadLocalNode);
    let encoded = NodePrivateTransport::encode_request(&envelope).expect("encode");
    assert_eq!(
        String::from_utf8(encoded).expect("UTF-8"),
        format!(
            "{{\"schema\":{{\"name\":\"li_node_private_api\",\"version\":2}},\"request_id\":\"{}\",\"request\":{{\"action\":\"read_local_node\"}}}}",
            identity('b', 64)
        )
    );
}

// Round-trips retained-runtime preview requests and responses while rejecting malformed identities.
#[test]
fn rollback_preview_private_contract_round_trips_and_fails_closed() {
    let service_id = ModelServiceId::parse(&identity('4', 32)).expect("service");
    let target_id = TargetId::parse("dgx-spark").expect("target");
    let request = NodePrivateRequest::PreviewRollbackModel {
        service_id: service_id.clone(),
        target_id: Some(target_id.clone()),
    };
    assert_eq!(round_trip_request(request.clone()), request);
    let request = NodePrivateRequest::RollbackModel {
        identity: NodeModelCommandIdentity::new(
            OperationId::parse(&identity('7', 32)).expect("operation"),
            TechnicalName::parse("rollback_model").expect("idempotency key"),
        ),
        service_id: service_id.clone(),
        target_id: Some(target_id.clone()),
    };
    assert_eq!(round_trip_request(request.clone()), request);

    let runtime = |version: &str, source: char| {
        NodeModelRollbackRuntime::new(
            RuntimeCandidateId::parse("sglang--owner--model--target").expect("candidate"),
            RuntimeVersion::parse(version).expect("version"),
            target_id.clone(),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinfer/runtime@sha256:{}",
                identity(source, 64)
            ))
            .expect("source"),
        )
    };
    let preview = NodeModelRollbackPreview::new(
        service_id,
        LogicalModelName::parse("qwen3.8").expect("model"),
        Some(target_id.clone()),
        vec![NodeModelRollbackGroupPreview::new(
            PlacementGroupId::parse(&identity('8', 32)).expect("current group"),
            PlacementGroupId::parse(&identity('9', 32)).expect("previous group"),
            vec![NodeId::parse(&identity('1', 32)).expect("node")],
            runtime("1.1.0", 'a'),
            runtime("1.0.0", 'b'),
        )],
    );
    let response = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelRollbackPreview(
            preview.clone(),
        )),
    );
    let bytes = NodePrivateTransport::encode_response(&response).expect("encode response");
    assert_eq!(
        NodePrivateTransport::decode_response(&bytes).expect("decode response"),
        response
    );

    let base: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    let mut malformed_source = base.clone();
    malformed_source["response"]["value"]["groups"][0]["previous"]["source"] =
        serde_json::json!("mutable:latest");
    let mut changed_candidate = base.clone();
    changed_candidate["response"]["value"]["groups"][0]["previous"]["candidate_id"] =
        serde_json::json!("different--candidate--target");
    let mut same_group = base.clone();
    same_group["response"]["value"]["groups"][0]["previous_group_id"] =
        same_group["response"]["value"]["groups"][0]["current_group_id"].clone();
    let mut duplicate_node = base;
    let node = duplicate_node["response"]["value"]["groups"][0]["node_ids"][0].clone();
    duplicate_node["response"]["value"]["groups"][0]["node_ids"] =
        serde_json::json!([node.clone(), node]);
    for mutation in [
        malformed_source,
        changed_candidate,
        same_group,
        duplicate_node,
    ] {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("malformed response")
        )
        .is_err());
    }
}

// Preserves placement and runtime-retention selections while rejecting malformed alternatives.
#[test]
fn partial_remove_private_contract_round_trips_and_fails_closed() {
    let request = NodePrivateRequest::RemoveModel(NodeModelRemoveRequest::new(
        NodeModelCommandIdentity::new(
            OperationId::parse(&identity('7', 32)).expect("operation"),
            TechnicalName::parse("remove_node").expect("key"),
        ),
        li_core_interface::ModelServiceId::parse(&identity('4', 32)).expect("service"),
        NodeModelRemovalSelection::nodes(vec![NodeId::parse(&identity('2', 32)).expect("node")])
            .expect("selection"),
        NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
    ));
    assert_eq!(round_trip_request(request.clone()), request);
    let envelope = NodePrivateTransportRequest::new(request_id('b'), request);
    let encoded = NodePrivateTransport::encode_request(&envelope).expect("encode request");
    let mut malformed: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON");
    malformed["request"]["arguments"]["node_ids"] = serde_json::json!([]);
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&malformed).expect("malformed request")
    )
    .is_err());

    let preserved = NodePrivateRequest::RemoveModel(NodeModelRemoveRequest::new(
        NodeModelCommandIdentity::new(
            OperationId::parse(&identity('8', 32)).expect("operation"),
            TechnicalName::parse("uninstall_model").expect("key"),
        ),
        ModelServiceId::parse(&identity('4', 32)).expect("service"),
        NodeModelRemovalSelection::All,
        NodeModelRemovalRetention::PreserveModels,
    ));
    assert_eq!(round_trip_request(preserved.clone()), preserved);
    let envelope = NodePrivateTransportRequest::new(request_id('c'), preserved);
    let encoded = NodePrivateTransport::encode_request(&envelope).expect("encode request");
    let mut malformed: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON");
    assert_eq!(
        malformed["request"]["arguments"]["runtime_retention"],
        "preserve_models"
    );
    malformed["request"]["arguments"]["runtime_retention"] = serde_json::json!("unknown");
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&malformed).expect("malformed request")
    )
    .is_err());
}

// Preserves opaque runtime bytes and bounded cursors while rejecting malformed continuations.
#[test]
fn model_runtime_log_private_contract_round_trips_and_fails_closed() {
    let service_id = ModelServiceId::parse(&identity('4', 32)).expect("service");
    let placement_group_id = PlacementGroupId::parse(&identity('8', 32)).expect("group");
    let cursor = PlacementLogCursor::new(request_id('9'), "1700000000.000000000|2".to_string())
        .expect("cursor");
    let request = NodePrivateRequest::ReadModelRuntimeLogs(
        NodeModelRuntimeLogRequest::new(
            service_id.clone(),
            Some(placement_group_id.clone()),
            Some(cursor.clone()),
            200,
            64 * 1024,
            Duration::from_millis(750),
        )
        .expect("runtime log request"),
    );
    assert_eq!(round_trip_request(request.clone()), request);

    let request_envelope = NodePrivateTransportRequest::new(request_id('b'), request);
    let request_document =
        NodePrivateTransport::encode_request(&request_envelope).expect("request document");
    let request_json: serde_json::Value =
        serde_json::from_slice(&request_document).expect("request JSON");
    let request_mutations = [
        {
            let mut value = request_json.clone();
            value["request"]["arguments"]["maximum_bytes"] = serde_json::json!(524_289);
            value
        },
        {
            let mut value = request_json.clone();
            value["request"]["arguments"]["wait_milliseconds"] = serde_json::json!(1_001);
            value
        },
        {
            let mut value = request_json.clone();
            value["request"]["arguments"]["cursor"]["position"] =
                serde_json::json!("unsafe\nposition");
            value
        },
        {
            let mut value = request_json.clone();
            value["request"]["arguments"]["unexpected"] = serde_json::json!(true);
            value
        },
    ];
    for mutation in request_mutations {
        assert!(NodePrivateTransport::decode_request(
            &serde_json::to_vec(&mutation).expect("request mutation")
        )
        .is_err());
    }

    let response = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::ModelRuntimeLogs(
            NodeModelRuntimeLogBatch::new(
                service_id,
                PlacementLogBatch::new(
                    placement_group_id,
                    li_core_interface::PlacementId::parse(&identity('6', 32)).expect("placement"),
                    cursor,
                    vec![0, 255, b'\n'],
                    true,
                )
                .expect("placement log batch"),
            ),
        )),
    );
    let response_document =
        NodePrivateTransport::encode_response(&response).expect("response document");
    assert_eq!(
        NodePrivateTransport::decode_response(&response_document).expect("decoded response"),
        response
    );

    let response_json: serde_json::Value =
        serde_json::from_slice(&response_document).expect("response JSON");
    let response_mutations = [
        {
            let mut value = response_json.clone();
            value["response"]["value"]["payload_base64"] = serde_json::json!("AA=");
            value
        },
        {
            let mut value = response_json.clone();
            value["response"]["value"]["payload_base64"] = serde_json::json!("A".repeat(699_052));
            value
        },
        {
            let mut value = response_json.clone();
            value["response"]["value"]["placement_id"] = serde_json::json!("invalid");
            value
        },
        {
            let mut value = response_json.clone();
            value["response"]["value"]["cursor"]["source_identity"] = serde_json::json!("invalid");
            value
        },
        {
            let mut value = response_json.clone();
            value["response"]["value"]["unexpected"] = serde_json::json!(true);
            value
        },
    ];
    for mutation in response_mutations {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("response mutation")
        )
        .is_err());
    }
}

// Round-trips exact verification recovery state and rejects every semantic projection mutation.
#[test]
fn benchmark_verification_observability_wire_is_typed_and_fail_closed() {
    let response = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkChanged(
            verification_benchmark_snapshot(),
        )),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("verification response");
    let decoded = NodePrivateTransport::decode_response(&document).expect("verification decode");
    assert_eq!(decoded.outcome(), response.outcome());
    let base: serde_json::Value = serde_json::from_slice(&document).expect("verification JSON");
    assert_eq!(
        base["response"]["value"]["verification_phase"],
        serde_json::json!("baseline_running")
    );
    assert_eq!(
        base["response"]["value"]["handoff_phase"],
        serde_json::json!("candidate_acquired")
    );
    assert_eq!(
        base["response"]["value"]["recovery_required"],
        serde_json::json!(false)
    );
    let mut mutations = Vec::new();
    let mut value = base.clone();
    value["response"]["value"]["verification_phase"] = serde_json::json!("publishing");
    mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["handoff_phase"] = serde_json::json!("unknown");
    mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["handoff_transaction_id"] = serde_json::json!("invalid");
    mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["recovery_required"] = serde_json::json!(true);
    mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]
        .as_object_mut()
        .expect("verification snapshot")
        .remove("handoff_phase");
    mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["terminal_failure_category"] = serde_json::json!("restoration");
    mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["terminal_failure_category"] = serde_json::json!("restoration");
    value["response"]["value"]["terminal_failure_phase"] = serde_json::json!("restoration");
    mutations.push(value);
    let mut value = base;
    value["response"]["value"]["terminal_failure_category"] = serde_json::json!("provider_secret");
    value["response"]["value"]["terminal_failure_phase"] = serde_json::json!("restoration");
    mutations.push(value);

    for mutation in mutations {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("verification mutation")
        )
        .is_err());
    }

    let ordinary = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkChanged(
            benchmark_snapshot(),
        )),
    );
    let document = NodePrivateTransport::encode_response(&ordinary).expect("ordinary response");
    let mut mutation: serde_json::Value = serde_json::from_slice(&document).expect("ordinary JSON");
    mutation["response"]["value"]["verification_phase"] = serde_json::json!("baseline_running");
    mutation["response"]["value"]["handoff_transaction_id"] = serde_json::json!(identity('d', 32));
    mutation["response"]["value"]["handoff_phase"] = serde_json::json!("candidate_acquired");
    mutation["response"]["value"]["recovery_required"] = serde_json::json!(false);
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("ordinary mutation")
    )
    .is_err());
}

// Round-trips every update request and response while rejecting identity drift and remote use.
#[test]
fn update_private_contract_round_trips_and_fails_closed() {
    let current = CoreInstallation::new(
        CoreVersion::parse("1.0.0").expect("version"),
        request_id('1'),
    );
    let available = CoreInstallation::new(
        CoreVersion::parse("1.1.0").expect("version"),
        request_id('2'),
    );
    let requests = [
        NodePrivateRequest::CheckCoreUpdate {
            requested_version: Some(CoreVersion::parse("1.1.0").expect("version")),
        },
        NodePrivateRequest::UpdateCore {
            idempotency_key: "core-update-1.1.0".to_string(),
            requested_version: Some(CoreVersion::parse("1.1.0").expect("version")),
        },
        NodePrivateRequest::UpdateModel(NodeModelUpdateRequest::new(
            NodeModelCommandIdentity::new(
                OperationId::parse(&identity('8', 32)).expect("operation"),
                TechnicalName::parse("update_model").expect("key"),
            ),
            ModelServiceId::parse(&identity('4', 32)).expect("service"),
            Some(RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate")),
            true,
        )),
    ];
    for request in requests {
        assert_eq!(round_trip_request(request.clone()), request);
    }

    let responses = [
        NodePrivateResponse::CoreUpdateCheck(NodeCoreUpdateCheck::new(
            current.clone(),
            available.clone(),
        )),
        NodePrivateResponse::CoreUpdated(NodeCoreUpdateSummary::new(
            available.clone(),
            CoreUpdateDisposition::Updated,
            CoreUpdatePhase::Succeeded,
        )),
        NodePrivateResponse::ModelUpdated(NodeModelUpdateSummary::new(
            ModelServiceId::parse(&identity('4', 32)).expect("service"),
            LogicalModelName::parse("deepseek_r1").expect("model"),
            NodeModelUpdateDisposition::UpdateAvailable,
            1,
            None,
        )),
    ];
    for response in responses {
        let envelope = NodePrivateTransportResponse::new(
            request_id('d'),
            NodePrivateTransportOutcome::Success(response),
        );
        let bytes = NodePrivateTransport::encode_response(&envelope).expect("response");
        assert_eq!(
            NodePrivateTransport::decode_response(&bytes).expect("decode response"),
            envelope
        );
    }

    let envelope = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::CoreUpdateCheck(
            NodeCoreUpdateCheck::new(current, available),
        )),
    );
    let bytes = NodePrivateTransport::encode_response(&envelope).expect("response");
    let mut malformed: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    malformed["response"]["value"]["disposition"] = serde_json::json!("current");
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&malformed).expect("malformed response")
    )
    .is_err());

    let directory = tempfile::tempdir().expect("directory");
    let api = api(&directory, Arc::new(AllowAuthorization));
    let remote_requests = [
        NodePrivateRequest::CheckCoreUpdate {
            requested_version: None,
        },
        NodePrivateRequest::UpdateCore {
            idempotency_key: "remote-core-update".to_string(),
            requested_version: None,
        },
        NodePrivateRequest::UpdateModel(NodeModelUpdateRequest::new(
            NodeModelCommandIdentity::new(
                OperationId::parse(&identity('9', 32)).expect("operation"),
                TechnicalName::parse("remote_update").expect("key"),
            ),
            ModelServiceId::parse(&identity('4', 32)).expect("service"),
            None,
            false,
        )),
    ];
    for request in remote_requests {
        assert_eq!(
            api.dispatch(&principal(), request),
            Err(NodePrivateApiError::AuthorizationDenied)
        );
    }
}

// Dispatches every private API flow through decode, authorization, manager, and encode.
#[test]
fn complete_private_transport_flow_uses_real_manager_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let api = api(&directory, Arc::new(AllowAuthorization));
    let principal = principal();
    let mut sequence = 0_u8;

    let dispatch = |request: NodePrivateRequest,
                    sequence: &mut u8|
     -> NodePrivateTransportOutcome {
        let identity_characters = ['b', 'c', 'd', 'e', 'f', '1', '2', '3'];
        let identity_character = identity_characters[usize::from(*sequence)];
        *sequence += 1;
        let request_id = request_id(identity_character);
        let request_document = NodePrivateTransport::encode_request(
            &NodePrivateTransportRequest::new(request_id.clone(), request),
        )
        .expect("request document");
        let decoded =
            NodePrivateTransport::decode_request(&request_document).expect("decoded request");
        let result = api.dispatch(&principal, decoded.into_request());
        let response_document =
            NodePrivateTransport::encode_dispatch_result(request_id.clone(), result)
                .expect("response document");
        let response = NodePrivateTransport::decode_response(&response_document).expect("response");
        assert_eq!(response.request_id(), &request_id);
        response.outcome().clone()
    };

    assert!(matches!(
        dispatch(NodePrivateRequest::ReadLocalNode, &mut sequence),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(_))
    ));
    assert!(matches!(
        dispatch(NodePrivateRequest::ReadNodes, &mut sequence),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Nodes(_))
    ));
    let child = child_node();
    let enrolled = dispatch(
        NodePrivateRequest::EnrollChild {
            idempotency_key: "enroll".to_string(),
            child: child.clone(),
        },
        &mut sequence,
    );
    let NodePrivateTransportOutcome::Success(NodePrivateResponse::NodeChanged(enrolled)) = enrolled
    else {
        panic!("enrollment response");
    };
    let versioned = dispatch(
        NodePrivateRequest::ReadNode {
            node_id: child.identity().node_id().clone(),
        },
        &mut sequence,
    );
    let NodePrivateTransportOutcome::Success(NodePrivateResponse::NodeChanged(versioned)) =
        versioned
    else {
        panic!("versioned node response");
    };
    assert_eq!(versioned.value(), &child);
    assert_eq!(versioned.revision(), enrolled.revision());
    let activated = dispatch(
        NodePrivateRequest::TransitionChild {
            idempotency_key: "activate".to_string(),
            node_id: child.identity().node_id().clone(),
            expected_revision: enrolled.revision(),
            transition: NodeTransition::Activate,
            updated_at: UnixMilliseconds::new(2_000),
        },
        &mut sequence,
    );
    assert!(matches!(
        activated,
        NodePrivateTransportOutcome::Success(NodePrivateResponse::NodeChanged(_))
    ));
    let pending = dispatch(NodePrivateRequest::ReadPendingOutbox, &mut sequence);
    let NodePrivateTransportOutcome::Success(NodePrivateResponse::PendingOutbox(pending)) = pending
    else {
        panic!("pending response");
    };
    let first = pending.first().expect("pending event");
    let acknowledged = dispatch(
        NodePrivateRequest::AcknowledgeOutbox {
            idempotency_key: "acknowledge".to_string(),
            event_id: first.event().event_id().clone(),
            expected_revision: first.revision(),
            acknowledged_at: UnixMilliseconds::new(3_000),
        },
        &mut sequence,
    );
    assert!(matches!(
        acknowledged,
        NodePrivateTransportOutcome::Success(NodePrivateResponse::OutboxAcknowledged(_))
    ));
}

// Centralizes listener handling at one decode-authorize-dispatch-encode endpoint.
#[test]
fn endpoint_handles_authenticated_documents_and_rejects_malformed_input() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let endpoint =
        NodePrivateEndpoint::new(Arc::new(api(&directory, Arc::new(AllowAuthorization))));
    let request =
        NodePrivateTransportRequest::new(request_id('b'), NodePrivateRequest::ReadLocalNode);
    let document = NodePrivateTransport::encode_request(&request).expect("request");
    let response = endpoint.handle(&principal(), &document).expect("handle");
    assert!(matches!(
        NodePrivateTransport::decode_response(&response)
            .expect("response")
            .outcome(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(_))
    ));
    assert!(matches!(
        endpoint.handle(&principal(), b"{}"),
        Err(NodePrivateTransportError::InvalidDocument { .. })
    ));
    assert_eq!(
        endpoint.api().manager().local_node().expect("local"),
        main_node()
    );
}

// Round-trips every response shape produced by real manager dispatch.
#[test]
fn response_variant_matrix_round_trips_exact_types() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let api = api(&directory, Arc::new(AllowAuthorization));
    let principal = principal();
    let child = child_node();
    let changed = api
        .dispatch(
            &principal,
            NodePrivateRequest::EnrollChild {
                idempotency_key: "enroll".to_string(),
                child,
            },
        )
        .expect("enroll");
    let responses = [
        NodePrivateResponse::LocalNode(api.manager().local_node().expect("local")),
        NodePrivateResponse::Nodes(api.manager().nodes().expect("nodes")),
        NodePrivateResponse::HardwareObservation(Some(hardware_observation())),
        NodePrivateResponse::HardwareObservation(None),
        NodePrivateResponse::StorageSnapshot(storage_snapshot()),
        NodePrivateResponse::StorageCleaned(storage_clean_receipt()),
        NodePrivateResponse::Catalog(catalog_listing()),
        NodePrivateResponse::CompatibleTargets(vec![NodeCatalogTarget::new(
            LogicalModelName::parse("deepseek_r1").expect("model"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            true,
        )]),
        changed,
        NodePrivateResponse::PendingOutbox(
            api.manager()
                .pending_outbox_events()
                .expect("pending outbox"),
        ),
        NodePrivateResponse::OutboxAcknowledged(
            api.manager()
                .pending_outbox_events()
                .expect("pending outbox")
                .remove(0),
        ),
        NodePrivateResponse::PairingInvitation(
            NodePairingInvitation::new(
                invite_id(),
                NodePairingMode::Lan,
                request_id('9'),
                UnixMilliseconds::new(5_000),
                Some("12345678".to_string()),
            )
            .expect("pairing invitation"),
        ),
        NodePrivateResponse::PairingEnrollment(
            NodePairingEnrollment::new(
                pairing_status(NodePairingState::PendingApproval),
                pairing_credentials(),
            )
            .expect("pairing enrollment"),
        ),
        NodePrivateResponse::PairingStatus(pairing_status(NodePairingState::Active)),
        NodePrivateResponse::BenchmarkPlan(benchmark_plan()),
        NodePrivateResponse::BenchmarkChanged(benchmark_snapshot()),
        NodePrivateResponse::BenchmarkChanged(verification_benchmark_snapshot()),
        NodePrivateResponse::BenchmarkRecord(Some(benchmark_snapshot())),
        NodePrivateResponse::BenchmarkRecord(None),
        NodePrivateResponse::CommandAuditOpened(NodeCommandAuditOpenReceipt::new(
            command_audit_marker(),
            NodeCommandAuditOpenDisposition::Opened,
        )),
        NodePrivateResponse::CommandAuditCompleted(NodeCommandAuditCompletionReceipt::new(
            None,
            NodeCommandAuditCompletionDisposition::Completed,
        )),
        NodePrivateResponse::AuditEvents(vec![audit_event()]),
        NodePrivateResponse::AuditEvent(audit_event()),
        NodePrivateResponse::AuditVerification(
            NodeAuditVerification::new(1, 0, request_id('f')).expect("verification"),
        ),
        NodePrivateResponse::AuditExport(
            NodeAuditExport::new(b"{\"events\":[]}\n".to_vec(), 0).expect("export"),
        ),
    ];
    for response in responses {
        let envelope = NodePrivateTransportResponse::new(
            request_id('d'),
            NodePrivateTransportOutcome::Success(response),
        );
        let bytes = NodePrivateTransport::encode_response(&envelope).expect("encode response");
        assert_eq!(
            NodePrivateTransport::decode_response(&bytes).expect("decode response"),
            envelope
        );
    }
}

// Rejects malformed nested hardware through HardwareManager's authoritative decoder.
#[test]
fn hardware_response_fails_closed_on_semantic_and_shape_mutations() {
    let response = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::HardwareObservation(Some(
            hardware_observation(),
        ))),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("JSON");

    let mut wrong_node = base.clone();
    wrong_node["response"]["value"]["node_id"] = serde_json::json!("invalid");
    let mut unknown_field = base;
    unknown_field["response"]["value"]["unexpected"] = serde_json::json!(true);

    for mutation in [wrong_node, unknown_field] {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("mutation")
        )
        .is_err());
    }
}

// Round-trips both host reads and rejects availability or scope mutations deterministically.
#[test]
fn host_projection_wire_is_typed_scoped_and_fail_closed() {
    for request in [
        NodePrivateRequest::ReadHostProjection {
            node_id: main_node().identity().node_id().clone(),
        },
        NodePrivateRequest::ReadHostInventory,
    ] {
        assert_eq!(round_trip_request(request.clone()), request);
    }

    for response in [
        NodePrivateResponse::HostProjection(host_snapshot()),
        NodePrivateResponse::HostInventory(host_inventory()),
    ] {
        let expected = response.clone();
        let response = NodePrivateTransportResponse::new(
            request_id('8'),
            NodePrivateTransportOutcome::Success(response),
        );
        let document = NodePrivateTransport::encode_response(&response).expect("host response");
        let decoded = NodePrivateTransport::decode_response(&document).expect("host decode");
        assert_eq!(
            decoded.outcome(),
            &NodePrivateTransportOutcome::Success(expected)
        );
    }

    let response = NodePrivateTransportResponse::new(
        request_id('9'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::HostProjection(host_snapshot())),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("host response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("host JSON");
    let mut unknown_status = base.clone();
    unknown_status["response"]["value"]["verified_links"]["status"] = serde_json::json!("unknown");
    let mut mismatched_hardware = base.clone();
    mismatched_hardware["response"]["value"]["hardware"]["value"]["node_id"] =
        serde_json::json!(identity('2', 32));
    let mut unexpected = base;
    unexpected["response"]["value"]["gateway"]["unexpected"] = serde_json::json!(true);
    for mutation in [unknown_status, mismatched_hardware, unexpected] {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("host mutation")
        )
        .is_err());
    }
}

// Rejects changed cleanup identities, unsafe paths, incoherent totals, and malformed receipts.
#[test]
fn storage_wire_contract_round_trips_and_fails_closed_on_semantic_mutations() {
    for request in [
        NodePrivateRequest::ReadStorage,
        NodePrivateRequest::CleanStorage(storage_clean_request()),
    ] {
        assert_eq!(round_trip_request(request.clone()), request);
    }

    let request = NodePrivateTransportRequest::new(
        request_id('a'),
        NodePrivateRequest::CleanStorage(storage_clean_request()),
    );
    let document = NodePrivateTransport::encode_request(&request).expect("clean request");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("request JSON");
    let mut request_mutations = Vec::new();

    let mut mutation = base.clone();
    mutation["request"]["arguments"]["categories"] = serde_json::json!(["state"]);
    request_mutations.push(mutation);
    let mut mutation = base.clone();
    mutation["request"]["arguments"]["categories"] = serde_json::json!(["caches", "caches"]);
    request_mutations.push(mutation);
    let mut mutation = base;
    mutation["request"]["arguments"]["plan_sha256"] = serde_json::json!("invalid");
    request_mutations.push(mutation);

    for mutation in request_mutations {
        assert!(NodePrivateTransport::decode_request(
            &serde_json::to_vec(&mutation).expect("request mutation")
        )
        .is_err());
    }

    let response = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::StorageSnapshot(
            storage_snapshot(),
        )),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("snapshot response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("response JSON");
    let mut response_mutations = Vec::new();

    let mut mutation = base.clone();
    mutation["response"]["value"]["candidates"][0]["relative_path"] =
        serde_json::json!("/private/cache");
    response_mutations.push(mutation);
    let mut mutation = base.clone();
    mutation["response"]["value"]["usage"][0]["reclaimable_bytes"] = serde_json::json!(999);
    response_mutations.push(mutation);
    let mut mutation = base;
    mutation["response"]["value"]["usage"]
        .as_array_mut()
        .expect("usage")
        .push(serde_json::json!({
            "category": "caches",
            "allocated_bytes": 1,
            "logical_bytes": 1,
            "files": 1,
            "reclaimable_bytes": 0
        }));
    response_mutations.push(mutation);

    for mutation in response_mutations {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("response mutation")
        )
        .is_err());
    }

    let receipt = NodePrivateTransportResponse::new(
        request_id('c'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::StorageCleaned(
            storage_clean_receipt(),
        )),
    );
    let document = NodePrivateTransport::encode_response(&receipt).expect("receipt response");
    let mut mutation: serde_json::Value = serde_json::from_slice(&document).expect("receipt JSON");
    mutation["response"]["value"]["removed_targets"] = serde_json::json!(0);
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("receipt mutation")
    )
    .is_err());

    let document = NodePrivateTransport::encode_dispatch_result(
        request_id('d'),
        Err(NodePrivateApiError::Storage(
            NodeStorageError::ProviderUnavailable,
        )),
    )
    .expect("storage failure");
    let response = NodePrivateTransport::decode_response(&document).expect("failure response");
    let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
        panic!("storage remote failure");
    };
    assert_eq!(error.code().as_str(), "storage_error");
    assert_eq!(error.message(), "storage provider is unavailable");
}

// Round-trips both runtime-maintenance actions and rejects identity, ordering, and result drift.
#[test]
fn runtime_maintenance_wire_contract_round_trips_and_fails_closed() {
    let first = RuntimeInstallationId::parse(&identity('1', 32)).expect("first runtime");
    let second = RuntimeInstallationId::parse(&identity('2', 32)).expect("second runtime");
    for request in [
        NodePrivateRequest::ReadRuntimeInstallationIds,
        NodePrivateRequest::RemoveRuntimeInstallation {
            installation_id: first.clone(),
            model_retention: NodeRuntimeModelRetention::Remove,
        },
    ] {
        assert_eq!(round_trip_request(request.clone()), request);
    }

    let request = NodePrivateTransportRequest::new(
        request_id('b'),
        NodePrivateRequest::RemoveRuntimeInstallation {
            installation_id: first.clone(),
            model_retention: NodeRuntimeModelRetention::Preserve,
        },
    );
    let document = NodePrivateTransport::encode_request(&request).expect("remove request");
    let mut invalid_request: serde_json::Value =
        serde_json::from_slice(&document).expect("remove JSON");
    invalid_request["request"]["arguments"]["installation_id"] = serde_json::json!("invalid");
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&invalid_request).expect("request mutation")
    )
    .is_err());

    for response in [
        NodePrivateResponse::RuntimeInstallationIds(vec![first.clone(), second.clone()]),
        NodePrivateResponse::RuntimeInstallationRemoved(NodeRuntimeRemovalDisposition::Applied),
        NodePrivateResponse::RuntimeInstallationRemoved(NodeRuntimeRemovalDisposition::Replayed),
    ] {
        let envelope = NodePrivateTransportResponse::new(
            request_id('d'),
            NodePrivateTransportOutcome::Success(response),
        );
        let document = NodePrivateTransport::encode_response(&envelope).expect("response");
        assert_eq!(
            NodePrivateTransport::decode_response(&document).expect("round trip"),
            envelope
        );
    }

    let identities = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::RuntimeInstallationIds(vec![
            first.clone(),
            second.clone(),
        ])),
    );
    let document = NodePrivateTransport::encode_response(&identities).expect("identity response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("identity JSON");
    for value in [
        serde_json::json!([first.as_str(), first.as_str()]),
        serde_json::json!([second.as_str(), first.as_str()]),
        serde_json::json!(["invalid"]),
    ] {
        let mut mutation = base.clone();
        mutation["response"]["value"] = value;
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("identity mutation")
        )
        .is_err());
    }

    let removal = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::RuntimeInstallationRemoved(
            NodeRuntimeRemovalDisposition::Applied,
        )),
    );
    let document = NodePrivateTransport::encode_response(&removal).expect("removal response");
    let mut mutation: serde_json::Value = serde_json::from_slice(&document).expect("removal JSON");
    mutation["response"]["value"] = serde_json::json!("unknown");
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("removal mutation")
    )
    .is_err());

    for (error, code) in [
        (
            li_node_manager::NodeRuntimeMaintenanceError::Conflict,
            "runtime_maintenance_conflict",
        ),
        (
            li_node_manager::NodeRuntimeMaintenanceError::ProviderUnavailable,
            "runtime_maintenance_unavailable",
        ),
    ] {
        let document = NodePrivateTransport::encode_dispatch_result(
            request_id('e'),
            Err(NodePrivateApiError::RuntimeMaintenance(error)),
        )
        .expect("runtime failure");
        let response = NodePrivateTransport::decode_response(&document).expect("remote failure");
        let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
            panic!("runtime maintenance failure");
        };
        assert_eq!(error.code().as_str(), code);
    }
}

// Round-trips the dedicated leased uninstall family, immutable inventory, and stable failures.
#[test]
fn uninstall_wire_contract_is_closed_typed_and_fail_closed() {
    let session_id = request_id('1');
    let installation_id = RuntimeInstallationId::parse(&identity('4', 32)).expect("runtime");
    let remove_model = NodeModelRemoveRequest::new(
        NodeModelCommandIdentity::new(
            OperationId::parse(&identity('7', 32)).expect("operation"),
            TechnicalName::parse("uninstall_model").expect("key"),
        ),
        ModelServiceId::parse(&identity('6', 32)).expect("service"),
        NodeModelRemovalSelection::All,
        NodeModelRemovalRetention::PreserveModels,
    );
    let requests = vec![
        NodeUninstallRequest::Begin {
            session_id: session_id.clone(),
            model_retention: NodeRuntimeModelRetention::Preserve,
        },
        NodeUninstallRequest::StopBenchmark {
            session_id: session_id.clone(),
            job_id: benchmark_snapshot().job_id().clone(),
        },
        NodeUninstallRequest::DisableExposure {
            session_id: session_id.clone(),
        },
        NodeUninstallRequest::RemoveModel {
            session_id: session_id.clone(),
            request: remove_model,
        },
        NodeUninstallRequest::RemoveRuntimeInstallation {
            session_id: session_id.clone(),
            installation_id: installation_id.clone(),
            model_retention: NodeRuntimeModelRetention::Preserve,
        },
        NodeUninstallRequest::FinalizeRuntimeArtifacts {
            session_id: session_id.clone(),
            model_retention: NodeRuntimeModelRetention::Preserve,
        },
        NodeUninstallRequest::Cancel {
            session_id: session_id.clone(),
        },
    ];
    for request in requests {
        let request = NodePrivateRequest::Uninstall(request);
        assert_eq!(round_trip_request(request.clone()), request);
    }
    let begin_request = NodePrivateTransportRequest::new(
        request_id('c'),
        NodePrivateRequest::Uninstall(NodeUninstallRequest::Begin {
            session_id: session_id.clone(),
            model_retention: NodeRuntimeModelRetention::Preserve,
        }),
    );
    let document = NodePrivateTransport::encode_request(&begin_request).expect("begin request");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("begin request JSON");
    let mut invalid_session = base.clone();
    invalid_session["request"]["arguments"]["arguments"]["session_id"] =
        serde_json::json!("invalid");
    let mut invalid_operation = base.clone();
    invalid_operation["request"]["arguments"]["operation"] = serde_json::json!("unknown");
    let mut unexpected = base;
    unexpected["request"]["arguments"]["arguments"]["unexpected"] = serde_json::json!(true);
    for mutation in [invalid_session, invalid_operation, unexpected] {
        assert!(NodePrivateTransport::decode_request(
            &serde_json::to_vec(&mutation).expect("begin request mutation")
        )
        .is_err());
    }

    let inventory = NodeUninstallInventory::new(
        NodeRole::Main,
        Some(benchmark_snapshot().job_id().clone()),
        Some(request_id('a')),
        Vec::new(),
        vec![installation_id],
    )
    .expect("inventory");
    let began = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::UninstallBegan(
            NodeUninstallBeginReceipt::new(
                session_id.clone(),
                NodeUninstallSessionDisposition::Applied,
                NodeRuntimeModelRetention::Preserve,
                inventory,
            ),
        )),
    );
    let document = NodePrivateTransport::encode_response(&began).expect("begin response");
    assert_eq!(
        NodePrivateTransport::decode_response(&document).expect("begin decode"),
        began
    );
    let base: serde_json::Value = serde_json::from_slice(&document).expect("begin JSON");
    assert!(base["response"]["value"]["inventory"]
        .get("active_benchmark")
        .is_none());
    assert!(base["response"]["value"]["inventory"]
        .get("model_services")
        .is_none());
    let mut child_with_main_targets = base.clone();
    child_with_main_targets["response"]["value"]["inventory"]["local_role"] =
        serde_json::json!("child");
    let mut changed_disposition = base.clone();
    changed_disposition["response"]["value"]["disposition"] = serde_json::json!("unknown");
    let mut changed_session = base;
    changed_session["response"]["value"]["session_id"] = serde_json::json!("invalid");
    for mutation in [
        child_with_main_targets,
        changed_disposition,
        changed_session,
    ] {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("begin mutation")
        )
        .is_err());
    }

    let placement_group_ids = (1..=4093)
        .map(|value| PlacementGroupId::parse(&format!("{value:032x}")).expect("placement group"))
        .collect();
    let maximum_inventory = NodeUninstallInventory::new(
        NodeRole::Main,
        Some(OperationId::parse(&identity('d', 32)).expect("benchmark")),
        Some(request_id('a')),
        vec![NodeUninstallModelTarget::new(
            ModelServiceId::parse(&identity('e', 32)).expect("service"),
            placement_group_ids,
        )],
        Vec::new(),
    )
    .expect("maximum inventory");
    let maximum_response = NodePrivateTransportResponse::new(
        request_id('f'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::UninstallBegan(
            NodeUninstallBeginReceipt::new(
                request_id('1'),
                NodeUninstallSessionDisposition::Applied,
                NodeRuntimeModelRetention::Preserve,
                maximum_inventory,
            ),
        )),
    );
    let maximum_document =
        NodePrivateTransport::encode_response(&maximum_response).expect("maximum response");
    assert!(maximum_document.len() < NODE_PRIVATE_MAX_DOCUMENT_BYTES);
    assert_eq!(
        NodePrivateTransport::decode_response(&maximum_document).expect("maximum decode"),
        maximum_response
    );
    let mut duplicate_group: serde_json::Value =
        serde_json::from_slice(&maximum_document).expect("maximum JSON");
    let first_group = duplicate_group["response"]["value"]["inventory"]["model_targets"][0]
        ["placement_group_ids"][0]
        .clone();
    duplicate_group["response"]["value"]["inventory"]["model_targets"][0]["placement_group_ids"]
        [1] = first_group;
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&duplicate_group).expect("duplicate group mutation")
    )
    .is_err());

    let canceled = NodePrivateTransportResponse::new(
        request_id('e'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::UninstallCanceled(
            NodeUninstallCancelReceipt::new(session_id.clone()),
        )),
    );
    let document = NodePrivateTransport::encode_response(&canceled).expect("cancel response");
    assert_eq!(
        NodePrivateTransport::decode_response(&document).expect("cancel decode"),
        canceled
    );
    let finalized = NodePrivateTransportResponse::new(
        request_id('e'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::RuntimeArtifactsFinalized(
            li_node_manager::NodeRuntimeArtifactsFinalizationReceipt::new(
                NodeRuntimeModelRetention::Preserve,
            ),
        )),
    );
    let document = NodePrivateTransport::encode_response(&finalized).expect("finalize response");
    assert_eq!(
        NodePrivateTransport::decode_response(&document).expect("finalize decode"),
        finalized
    );

    for (failure, code) in [
        (NodePrivateApiError::UninstallBusy, "uninstall_busy"),
        (
            NodePrivateApiError::UninstallInProgress,
            "uninstall_in_progress",
        ),
        (
            NodePrivateApiError::UninstallSessionConflict,
            "uninstall_session_conflict",
        ),
        (
            NodePrivateApiError::UninstallBarrierUnavailable,
            "uninstall_barrier_unavailable",
        ),
    ] {
        let document = NodePrivateTransport::encode_dispatch_result(request_id('f'), Err(failure))
            .expect("uninstall failure");
        let response = NodePrivateTransport::decode_response(&document).expect("failure decode");
        let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
            panic!("uninstall failure response");
        };
        assert_eq!(error.code().as_str(), code);
        assert!(!error.message().contains(session_id.as_str()));
    }
}

// Round-trips both pairing-authority actions and denies every remote transport before dispatch.
#[test]
fn pairing_authority_wire_is_closed_local_only_and_receipt_exact() {
    let requests = [
        NodePrivateRequest::ActivatePairedChild(pairing_activation_request()),
        NodePrivateRequest::RestorePairedMain(pairing_restoration_request()),
    ];
    for request in requests.clone() {
        assert_eq!(round_trip_request(request.clone()), request);
    }

    let receipt = NodePairingAuthorityReceipt::restore(
        node(
            '1',
            '2',
            '3',
            "Home AI",
            NodeRole::Child,
            NodeState::Active,
            "homeai.local",
            2_000,
        ),
        NodePairingAuthorityDisposition::Applied,
    );
    let response = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::PairingAuthorityChanged(receipt)),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("authority response");
    assert_eq!(
        NodePrivateTransport::decode_response(&document).expect("authority response decode"),
        response
    );
    let mut invalid_disposition: serde_json::Value =
        serde_json::from_slice(&document).expect("authority JSON");
    invalid_disposition["response"]["value"]["disposition"] = serde_json::json!("unknown");
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&invalid_disposition).expect("invalid response")
    )
    .is_err());
    let mut inactive_local: serde_json::Value =
        serde_json::from_slice(&document).expect("authority JSON");
    inactive_local["response"]["value"]["local"]["state"] = serde_json::json!("pending");
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&inactive_local).expect("inactive response")
    )
    .is_err());

    let directory = tempfile::tempdir().expect("temporary directory");
    let endpoint =
        NodePrivateEndpoint::new(Arc::new(api(&directory, Arc::new(AllowAuthorization))));
    for request in requests {
        let document = NodePrivateTransport::encode_request(&NodePrivateTransportRequest::new(
            request_id('e'),
            request,
        ))
        .expect("remote authority request");
        let response = endpoint
            .handle(&principal(), &document)
            .expect("remote authority response");
        let NodePrivateTransportOutcome::Failure(error) =
            NodePrivateTransport::decode_response(&response)
                .expect("remote authority decode")
                .into_outcome()
        else {
            panic!("pairing authority crossed the remote boundary");
        };
        assert_eq!(error.code().as_str(), "authorization_denied");
    }
}

// Maps authorization and manager failures into stable bounded remote errors.
#[test]
fn dispatch_error_matrix_is_stable_and_round_trippable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let denied = api(&directory, Arc::new(DenyAuthorization));
    let denied_result = denied.dispatch(&principal(), NodePrivateRequest::ReadLocalNode);
    let bytes = NodePrivateTransport::encode_dispatch_result(request_id('e'), denied_result)
        .expect("denied response");
    let response = NodePrivateTransport::decode_response(&bytes).expect("decode denial");
    let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
        panic!("remote denial");
    };
    assert_eq!(error.code().as_str(), "authorization_denied");

    let directory = tempfile::tempdir().expect("temporary directory");
    let allowed = api(&directory, Arc::new(AllowAuthorization));
    let manager_result = allowed.dispatch(
        &principal(),
        NodePrivateRequest::TransitionChild {
            idempotency_key: "missing".to_string(),
            node_id: NodeId::parse(&identity('f', 32)).expect("node"),
            expected_revision: 1,
            transition: NodeTransition::Activate,
            updated_at: UnixMilliseconds::new(2_000),
        },
    );
    let bytes = NodePrivateTransport::encode_dispatch_result(request_id('f'), manager_result)
        .expect("manager response");
    let response = NodePrivateTransport::decode_response(&bytes).expect("decode manager error");
    let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
        panic!("remote manager error");
    };
    assert_eq!(error.code().as_str(), "manager_error");
    assert!(!error.message().is_empty());

    let explicit = NodePrivateTransportResponse::new(
        request_id('1'),
        NodePrivateTransportOutcome::Failure(
            NodePrivateRemoteError::new(
                TechnicalName::parse("temporary_failure").expect("code"),
                "try again",
            )
            .expect("error"),
        ),
    );
    let bytes = NodePrivateTransport::encode_response(&explicit).expect("encode explicit");
    assert_eq!(
        NodePrivateTransport::decode_response(&bytes).expect("decode explicit"),
        explicit
    );
}

// Rejects unknown fields, identities, actions, transitions, and schema mutations.
#[test]
fn request_mutation_matrix_fails_closed() {
    let request = NodePrivateTransportRequest::new(
        request_id('b'),
        NodePrivateRequest::TransitionChild {
            idempotency_key: "transition".to_string(),
            node_id: NodeId::parse(&identity('4', 32)).expect("node"),
            expected_revision: 1,
            transition: NodeTransition::Activate,
            updated_at: UnixMilliseconds::new(2_000),
        },
    );
    let document = NodePrivateTransport::encode_request(&request).expect("request");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    let mut mutations = Vec::new();

    let mut value = base.clone();
    value["schema"]["name"] = serde_json::json!("other");
    mutations.push(value);
    let mut value = base.clone();
    value["schema"]["version"] = serde_json::json!(1);
    mutations.push(value);
    let mut value = base.clone();
    value["unexpected"] = serde_json::json!(true);
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["action"] = serde_json::json!("unknown");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["transition"] = serde_json::json!("restart");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["node_id"] = serde_json::json!("bad");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["idempotency_key"] = serde_json::json!("");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["unexpected"] = serde_json::json!(true);
    mutations.push(value);

    for mutation in mutations {
        assert!(NodePrivateTransport::decode_request(
            &serde_json::to_vec(&mutation).expect("mutation")
        )
        .is_err());
    }
    let duplicate = format!(
        "{{\"schema\":{{\"name\":\"li_node_private_api\",\"version\":2}},\"request_id\":\"{}\",\"request_id\":\"{}\",\"request\":{{\"action\":\"read_nodes\"}}}}",
        identity('1', 64),
        identity('2', 64)
    );
    assert!(NodePrivateTransport::decode_request(duplicate.as_bytes()).is_err());
    let mut trailing = document;
    trailing.extend_from_slice(b"{}");
    assert!(NodePrivateTransport::decode_request(&trailing).is_err());
}

// Rejects malformed selectors, bounded nested values, and duplicate catalog release identities.
#[test]
fn catalog_wire_contract_fails_closed_on_malformed_and_duplicate_values() {
    let request = NodePrivateTransportRequest::new(
        request_id('b'),
        NodePrivateRequest::ReadCatalog(
            NodeCatalogListRequest::new(
                None,
                Some(LogicalModelName::parse("deepseek_r1").expect("model")),
                NodeCatalogVersionSelection::All,
                NodeCatalogTargetSelection::All,
                NodeCatalogRefreshPolicy::Refresh,
            )
            .expect("catalog request"),
        ),
    );
    let document = NodePrivateTransport::encode_request(&request).expect("request");
    let mut malformed: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    malformed["request"]["arguments"]["refresh"] = serde_json::json!("unsigned");
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&malformed).expect("malformed request")
    )
    .is_err());

    let response = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Catalog(catalog_listing())),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("JSON");

    let mut duplicate = base.clone();
    let entry = duplicate["response"]["value"]["entries"][0].clone();
    duplicate["response"]["value"]["entries"] = serde_json::json!([entry.clone(), entry]);
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&duplicate).expect("duplicate response")
    )
    .is_err());

    let mut oversized = base.clone();
    let author = oversized["response"]["value"]["entries"][0]["authors"][0].clone();
    oversized["response"]["value"]["entries"][0]["authors"] =
        serde_json::Value::Array(vec![author; 65]);
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&oversized).expect("oversized response")
    )
    .is_err());

    let mut malformed = base;
    malformed["response"]["value"]["entries"][0]["version"] = serde_json::json!("");
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&malformed).expect("malformed response")
    )
    .is_err());
}

// Rejects malformed public selection axes, lifecycle state, and secret-bearing mutations.
#[test]
fn benchmark_wire_mutation_matrix_fails_closed() {
    let request = NodePrivateTransportRequest::new(
        request_id('b'),
        NodePrivateRequest::StartBenchmark {
            idempotency_key: "benchmark-local".to_string(),
            selection: benchmark_selection(),
        },
    );
    let document = NodePrivateTransport::encode_request(&request).expect("benchmark request");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("request JSON");
    let mut request_mutations = Vec::new();

    let mut value = base.clone();
    value["request"]["arguments"]["selection"]["logical_model"] = serde_json::json!("");
    request_mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["selection"]["concurrencies"] = serde_json::json!([4, 1]);
    request_mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["selection"]["concurrencies"] = serde_json::json!([1, 3]);
    request_mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["selection"]["contexts"] = serde_json::json!(["128k", "32k"]);
    request_mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["selection"]["contexts"] = serde_json::json!(["32k", "512k"]);
    request_mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["selection"]["runtime_installation_id"] =
        serde_json::json!(identity('4', 32));
    request_mutations.push(value);
    let mut value = base;
    value["request"]["arguments"]["secret"] = serde_json::json!("must-not-cross-wire");
    request_mutations.push(value);

    for mutation in request_mutations {
        let encoded = serde_json::to_vec(&mutation).expect("request mutation");
        assert!(NodePrivateTransport::decode_request(&encoded).is_err());
        assert!(!String::from_utf8_lossy(&encoded).contains("credential_value"));
    }

    let verification = NodePrivateTransportRequest::new(
        request_id('c'),
        NodePrivateRequest::StartBenchmarkVerification {
            idempotency_key: "benchmark-verification".to_string(),
            pull_request_url: "https://github.com/letsinferlabs/runtimes/pull/41".to_string(),
            candidate: Some(
                RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
            ),
        },
    );
    let document = NodePrivateTransport::encode_request(&verification).expect("verification");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    for (field, value) in [
        (
            "pull_request_url",
            serde_json::json!("https://github.com/other/repository/pull/41"),
        ),
        (
            "pull_request_url",
            serde_json::json!("http://github.com/letsinferlabs/runtimes/pull/41"),
        ),
        ("candidate", serde_json::json!("invalid")),
    ] {
        let mut mutation = base.clone();
        mutation["request"]["arguments"][field] = value;
        assert!(NodePrivateTransport::decode_request(
            &serde_json::to_vec(&mutation).expect("mutation")
        )
        .is_err());
    }

    let plan_response = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkPlan(benchmark_plan())),
    );
    let document =
        NodePrivateTransport::encode_response(&plan_response).expect("benchmark plan response");
    let mut mutation: serde_json::Value =
        serde_json::from_slice(&document).expect("benchmark plan JSON");
    mutation["response"]["value"]["selected_cells"] = serde_json::json!(["undeclared_cell"]);
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("benchmark plan mutation")
    )
    .is_err());

    let response = NodePrivateTransportResponse::new(
        request_id('d'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::BenchmarkChanged(
            benchmark_snapshot(),
        )),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("benchmark response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("response JSON");
    let mut response_mutations = Vec::new();

    let mut value = base.clone();
    value["response"]["value"]
        .as_object_mut()
        .expect("benchmark snapshot")
        .remove("kind");
    response_mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["kind"] = serde_json::json!({
        "kind": "verification",
        "pull_request": 0,
        "proposal_head": identity('a', 40),
        "candidate_id": "fixture--owner--model--target",
        "verifier_numeric_id": 7,
        "device_id": identity('b', 64),
        "baseline_execution_sha256": null
    });
    response_mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["phase"] = serde_json::json!("publishing");
    response_mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["disposition"] = serde_json::json!("qualified");
    response_mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["telemetry_receipt_id"] = serde_json::json!(identity('e', 64));
    response_mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["progress"]["completed_cells"] = serde_json::json!(5);
    response_mutations.push(value);
    let mut value = base.clone();
    value["response"]["value"]["request_sha256"] = serde_json::json!("invalid");
    response_mutations.push(value);
    let mut value = base;
    value["response"]["value"]["api_key"] = serde_json::json!("must-not-cross-wire");
    response_mutations.push(value);

    for mutation in response_mutations {
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("response mutation")
        )
        .is_err());
    }
}

// Rejects alternate binary encodings and invalid pairing presentation values without echoing them.
#[test]
fn pairing_wire_values_are_canonical_bounded_and_redacted_on_failure() {
    let request = NodePrivateTransportRequest::new(
        request_id('b'),
        NodePrivateRequest::EnrollPairing(pairing_enroll_request()),
    );
    let document = NodePrivateTransport::encode_request(&request).expect("request");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    let mut mutations = Vec::new();

    let mut value = base.clone();
    value["request"]["arguments"]["candidate_public_key_base64"] = serde_json::json!("AR==");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["proof_signature_base64"] = serde_json::json!("");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["setup_code"] = serde_json::json!("secret-code");
    mutations.push(value);
    let mut value = base;
    value["request"]["arguments"]["observed_peer_address"] = serde_json::json!("unsafe address");
    mutations.push(value);

    for mutation in mutations {
        let error =
            NodePrivateTransport::decode_request(&serde_json::to_vec(&mutation).expect("mutation"))
                .err()
                .expect("pairing mutation rejected");
        assert!(!error.to_string().contains("secret-code"));
    }
}

// Round-trips every local exposure action and both exact status shapes without provider state.
#[test]
fn exposure_wire_round_trips_exact_closed_contract() {
    for request in [
        NodePrivateRequest::ReadExposure,
        NodePrivateRequest::EnableExposure,
        NodePrivateRequest::DisableExposure,
    ] {
        assert_eq!(round_trip_request(request.clone()), request);
    }
    let enabled = GatewayExposureStatus::new(
        Some(
            GatewayExposure::new(
                "https://inference.example.ts.net".to_string(),
                request_id('a'),
            )
            .expect("exposure"),
        ),
        true,
    )
    .expect("enabled status");
    let disabled = GatewayExposureStatus::new(None, true).expect("disabled status");
    for status in [enabled, disabled] {
        let envelope = NodePrivateTransportResponse::new(
            request_id('b'),
            NodePrivateTransportOutcome::Success(NodePrivateResponse::Exposure(status)),
        );
        let document = NodePrivateTransport::encode_response(&envelope).expect("response");
        assert_eq!(
            NodePrivateTransport::decode_response(&document).expect("decode response"),
            envelope
        );
    }
}

// Rejects provider, target, identity, state-shape, and verification mutations independently.
#[test]
fn exposure_wire_mutation_matrix_fails_closed_and_redacted() {
    let status = GatewayExposureStatus::new(
        Some(
            GatewayExposure::new(
                "https://inference.example.ts.net".to_string(),
                request_id('a'),
            )
            .expect("exposure"),
        ),
        true,
    )
    .expect("status");
    let envelope = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Exposure(status)),
    );
    let document = NodePrivateTransport::encode_response(&envelope).expect("response");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    let secret = "private-provider-value";
    let mutations = [
        {
            let mut value = base.clone();
            value["response"]["value"]["provider"] = serde_json::json!(secret);
            value
        },
        {
            let mut value = base.clone();
            value["response"]["value"]["inference_target"] =
                serde_json::json!("http://127.0.0.1:9000");
            value
        },
        {
            let mut value = base.clone();
            value["response"]["value"]["public_url"] =
                serde_json::json!("https://inference.example.ts.net/private");
            value
        },
        {
            let mut value = base.clone();
            value["response"]["value"]["configuration_sha256"] = serde_json::json!("invalid");
            value
        },
        {
            let mut value = base.clone();
            value["response"]["value"]["state"] = serde_json::json!("disabled");
            value
        },
        {
            let mut value = base;
            value["response"]["value"]["extra"] = serde_json::json!(true);
            value
        },
    ];
    for mutation in mutations {
        let error = NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("mutation"),
        )
        .expect_err("mutation rejected")
        .to_string();
        assert!(!error.contains(secret));
    }

    let disabled = GatewayExposureStatus::new(None, true).expect("disabled status");
    let envelope = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Exposure(disabled)),
    );
    let document = NodePrivateTransport::encode_response(&envelope).expect("response");
    let mut mutation: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    mutation["response"]["value"]["provider_verified"] = serde_json::json!(false);
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("mutation")
    )
    .is_err());
}

// Rejects oversized request and response documents before JSON allocation.
#[test]
fn document_size_bound_applies_in_both_directions() {
    let oversized = vec![b' '; 1024 * 1024 + 1];
    assert_eq!(
        NodePrivateTransport::decode_request(&oversized),
        Err(NodePrivateTransportError::DocumentTooLarge)
    );
    assert_eq!(
        NodePrivateTransport::decode_response(&oversized),
        Err(NodePrivateTransportError::DocumentTooLarge)
    );
}

// Rejects every independent command-audit identity, target, result, and receipt mutation.
#[test]
fn command_audit_wire_mutation_matrix_fails_closed_and_redacted() {
    let envelope = NodePrivateTransportRequest::new(
        request_id('b'),
        NodePrivateRequest::OpenCommandAudit(command_audit_open_request()),
    );
    let document = NodePrivateTransport::encode_request(&envelope).expect("open request");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("request JSON");
    let secret = "bearer-private-value";
    let mut mutations = Vec::new();

    let mut value = base.clone();
    value["request"]["arguments"]["command_id"] = serde_json::json!(identity('d', 64));
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["intent"]["target"]["kind"] = serde_json::json!("runtime");
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["intent"]["target"]["identifier"] = serde_json::json!(secret);
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["intent"]["target"]["extra"] = serde_json::json!(true);
    mutations.push(value);
    let mut value = base.clone();
    value["request"]["arguments"]["intent"]["target"] = serde_json::json!({"kind": "api_key"});
    mutations.push(value);
    let mut value = base;
    value["request"]["arguments"]["intent"]["policy"] = serde_json::json!("sometimes");
    mutations.push(value);

    for mutation in mutations {
        let bytes = serde_json::to_vec(&mutation).expect("mutation");
        let error = NodePrivateTransport::decode_request(&bytes)
            .expect_err("mutation rejected")
            .to_string();
        assert!(!error.contains(secret));
    }

    let completion = NodePrivateTransportRequest::new(
        request_id('d'),
        NodePrivateRequest::CompleteCommandAudit(NodeCommandAuditCompletionRequest::new(
            command_audit_marker(),
            NodeCommandAuditResult::new(
                TechnicalName::parse("auth.key.rotate").expect("action"),
                NodeCommandAuditOutcome::Failed,
                Some("manager_unavailable"),
            )
            .expect("result"),
        )),
    );
    let document = NodePrivateTransport::encode_request(&completion).expect("completion");
    let base: serde_json::Value = serde_json::from_slice(&document).expect("completion JSON");
    for mutation in [
        {
            let mut value = base.clone();
            value["request"]["arguments"]["result"]["outcome"] = serde_json::json!("unknown");
            value
        },
        {
            let mut value = base.clone();
            value["request"]["arguments"]["result"]["failure_code"] = serde_json::json!(secret);
            value
        },
        {
            let mut value = base;
            value["request"]["arguments"]["marker"] = serde_json::json!("invalid");
            value
        },
    ] {
        let bytes = serde_json::to_vec(&mutation).expect("completion mutation");
        let error = NodePrivateTransport::decode_request(&bytes)
            .expect_err("completion mutation rejected")
            .to_string();
        assert!(!error.contains(secret));
    }

    let response = NodePrivateTransportResponse::new(
        request_id('b'),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::CommandAuditOpened(
            NodeCommandAuditOpenReceipt::new(
                command_audit_marker(),
                NodeCommandAuditOpenDisposition::Opened,
            ),
        )),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("response");
    let mut mutation: serde_json::Value = serde_json::from_slice(&document).expect("response JSON");
    mutation["response"]["value"]["disposition"] = serde_json::json!("unknown");
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("response mutation")
    )
    .is_err());
}

// Requires remote errors to remain bounded, nonempty, and control-free.
#[test]
fn remote_error_message_contract_is_bounded() {
    let code = TechnicalName::parse("remote_failure").expect("code");
    assert!(NodePrivateRemoteError::new(code.clone(), "").is_err());
    assert!(NodePrivateRemoteError::new(code.clone(), &"x".repeat(513)).is_err());
    assert!(NodePrivateRemoteError::new(code, "unsafe\nmessage").is_err());
}

// Requires the checked-in schema to declare the codec's exact li identity and unions.
#[test]
fn checked_in_schema_matches_the_active_codec_identity() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/node/li_node_private_api_v2.schema.json"
    ))
    .expect("schema JSON");
    assert_eq!(
        schema["$defs"]["schema_identity"]["properties"]["name"]["const"],
        "li_node_private_api"
    );
    assert_eq!(
        schema["$defs"]["schema_identity"]["properties"]["version"]["const"],
        2
    );
    assert_eq!(schema["oneOf"].as_array().expect("document union").len(), 2);
    assert_eq!(
        schema["$defs"]["request"]["oneOf"]
            .as_array()
            .expect("request union")
            .len(),
        58
    );
    assert_eq!(
        schema["$defs"]["response"]["oneOf"]
            .as_array()
            .expect("response union")
            .len(),
        47
    );
    let benchmark_required = schema["$defs"]["benchmark_snapshot"]["required"]
        .as_array()
        .expect("benchmark required fields");
    for field in [
        "verification_phase",
        "handoff_transaction_id",
        "handoff_phase",
        "recovery_required",
        "terminal_failure_category",
        "terminal_failure_phase",
    ] {
        assert!(
            benchmark_required.iter().any(|value| value == field),
            "{field}"
        );
    }
    let verification_kind = &schema["$defs"]["benchmark_kind"]["oneOf"][1];
    assert!(verification_kind["required"]
        .as_array()
        .expect("verification kind fields")
        .iter()
        .any(|value| value == "transaction_id"));
    assert!(verification_kind["required"]
        .as_array()
        .expect("verification kind fields")
        .iter()
        .any(|value| value == "verifier_bundle_sha256"));
    assert_eq!(
        schema["$defs"]["uninstall_inventory"]["required"],
        serde_json::json!([
            "local_role",
            "active_benchmark_id",
            "exposure_configuration_sha256",
            "model_targets",
            "runtime_installation_ids"
        ])
    );
    let request_actions = schema["$defs"]["request"]["oneOf"]
        .as_array()
        .expect("request union")
        .iter()
        .filter_map(|variant| variant["properties"]["action"]["const"].as_str())
        .collect::<Vec<_>>();
    assert!(request_actions.contains(&"read_storage"));
    assert!(request_actions.contains(&"read_host_projection"));
    assert!(request_actions.contains(&"read_host_inventory"));
    assert!(request_actions.contains(&"clean_storage"));
    assert!(request_actions.contains(&"preview_benchmark"));
    assert!(request_actions.contains(&"start_benchmark"));
    assert!(request_actions.contains(&"read_runtime_installation_ids"));
    assert!(request_actions.contains(&"remove_runtime_installation"));
    assert!(request_actions.contains(&"uninstall"));
    let uninstall_operations = schema["$defs"]["uninstall_request"]["oneOf"]
        .as_array()
        .expect("uninstall request union")
        .iter()
        .filter_map(|variant| variant["properties"]["operation"]["const"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        uninstall_operations,
        [
            "begin",
            "stop_benchmark",
            "disable_exposure",
            "remove_model",
            "remove_runtime_installation",
            "finalize_runtime_artifacts",
            "cancel",
        ]
    );
    assert!(request_actions.contains(&"activate_paired_child"));
    assert!(request_actions.contains(&"restore_paired_main"));
    let response_kinds = schema["$defs"]["response"]["oneOf"]
        .as_array()
        .expect("response union")
        .iter()
        .filter_map(|variant| variant["properties"]["kind"]["const"].as_str())
        .collect::<Vec<_>>();
    assert!(response_kinds.contains(&"storage_snapshot"));
    assert!(response_kinds.contains(&"storage_cleaned"));
    assert!(response_kinds.contains(&"benchmark_plan"));
    assert!(response_kinds.contains(&"controller_enrollment"));
    assert!(response_kinds.contains(&"runtime_installation_ids"));
    assert!(response_kinds.contains(&"runtime_installation_removed"));
    assert!(response_kinds.contains(&"runtime_artifacts_finalized"));
    assert!(response_kinds.contains(&"uninstall_began"));
    assert!(response_kinds.contains(&"uninstall_canceled"));
    assert!(response_kinds.contains(&"pairing_authority_changed"));
}
