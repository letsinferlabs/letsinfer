// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditCorrelationId, AuditError,
    AuditEvent, AuditEventId, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditTarget,
    AuditUnixNanoseconds,
};
use li_benchmark_manager::{
    BenchmarkDisposition, BenchmarkError, BenchmarkJobPhase, BenchmarkKind, BenchmarkRequest,
    BenchmarkScope, BenchmarkSubject,
};
use li_core_interface::{
    BootId, ByteCount, ControllerId, CpuArchitecture, CredentialId, DisplayName, EntityTimestamps,
    EvidenceLabel, HardwareObservation, HardwareObservationId, InstallationId, LogicalModelName,
    MachineId, ModelServiceDesiredState, ModelServiceId, Node, NodeAddress, NodeId, NodeIdentity,
    NodeRole, NodeState, OperatingSystem, OperationId, PairingInviteId, PlacementGroupId,
    PlatformIdentity, ProcessorObservation, RuntimeCandidateId, RuntimeInstallationId,
    Sha256Digest, TargetId, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_gateway_manager::{GatewayExposure, GatewayExposureError, GatewayExposureStatus};
use li_node_manager::{
    NodeAuditApiPort, NodeAuditExport, NodeAuditVerification, NodeBenchmarkApiPort,
    NodeBenchmarkPlan, NodeBenchmarkSelection, NodeBenchmarkSnapshot,
    NodeBenchmarkSnapshotProgress, NodeCatalogApiError, NodeCatalogApiPort, NodeCatalogAuthor,
    NodeCatalogAuthorKind, NodeCatalogEntry, NodeCatalogListRequest, NodeCatalogListing,
    NodeCatalogRefreshPolicy, NodeCatalogSnapshot, NodeCatalogTarget, NodeCatalogTargetSelection,
    NodeCatalogVersionSelection, NodeCommandAuditApiPort, NodeCommandAuditCompletionDisposition,
    NodeCommandAuditCompletionReceipt, NodeCommandAuditCompletionRequest, NodeCommandAuditError,
    NodeCommandAuditIntent, NodeCommandAuditMarker, NodeCommandAuditMutation,
    NodeCommandAuditOpenDisposition, NodeCommandAuditOpenReceipt, NodeCommandAuditOpenRequest,
    NodeCommandAuditOutcome, NodeCommandAuditPolicy, NodeCommandAuditResult, NodeExposureApiPort,
    NodeGatewayApiError, NodeGatewayBearer, NodeGatewayRequest, NodeHostGatewaySummary,
    NodeHostPlacementGroup, NodeHostPlacementReadPort, NodeHostProjectionPorts,
    NodeHostProtectionReadPort, NodeHostProtectionSummary, NodeHostReadError,
    NodeHostServiceReadPort, NodeHostServiceState, NodeHostTopologyReadPort,
    NodeHostWatchdogSummary, NodeManager, NodeModelApiPort, NodeModelCommandIdentity,
    NodeModelCommandSummary, NodeModelError, NodeModelInstallRequest, NodeModelLogSummary,
    NodeModelRemovalRetention, NodeModelRemovalSelection, NodeModelRemoveRequest,
    NodeModelRollbackPreview, NodeModelRuntimeLogBatch, NodeModelRuntimeLogRequest,
    NodeModelServiceSummary, NodeModelUpdateRequest, NodeModelUpdateSummary,
    NodePairedChildActivationRequest, NodePairedMainRestorationRequest,
    NodePairingActivationAuthorityError, NodePairingActivationAuthorityPort, NodePairingApiError,
    NodePairingApiPort, NodePairingApproveRequest, NodePairingAuthorityDisposition,
    NodePairingAuthorityReceipt, NodePairingCredentials, NodePairingEnrollRequest,
    NodePairingEnrollment, NodePairingInvitation, NodePairingOpenRequest, NodePairingStatus,
    NodePrivateAction, NodePrivateApi, NodePrivateApiError, NodePrivateAuthorizationProvider,
    NodePrivateRequest, NodePrivateResponse, NodeRuntimeMaintenanceApiPort,
    NodeRuntimeMaintenanceError, NodeRuntimeModelRetention, NodeRuntimeRemovalDisposition,
    NodeStorageApiPort, NodeStorageCandidate, NodeStorageCategory, NodeStorageCleanReceipt,
    NodeStorageCleanRequest, NodeStorageError, NodeStorageSnapshot, NodeStorageUsage,
    NodeTransition, NodeUninstallRequest, NodeUninstallSessionDisposition,
};
use li_placement_manager::{PlacementLink, PlacementRecord};

// Supplies one exact storage projection and records local cleanup requests.
struct StorageMock {
    clean_calls: Mutex<Vec<NodeStorageCleanRequest>>,
}

impl StorageMock {
    // Returns one stable snapshot containing one reclaimable model target.
    fn snapshot() -> NodeStorageSnapshot {
        NodeStorageSnapshot::new(
            10_000,
            4_000,
            vec![
                NodeStorageUsage::new(NodeStorageCategory::Models, 1_000, 900, 1, 1_000)
                    .expect("usage"),
            ],
            vec![NodeStorageCandidate::new(
                NodeStorageCategory::Models,
                "models/owner--model/revision",
                1_000,
                "inactive model artifacts",
                vec![LogicalModelName::parse("model").expect("model")],
            )
            .expect("candidate")],
            Sha256Digest::parse(&"e".repeat(64)).expect("plan"),
        )
        .expect("snapshot")
    }
}

impl NodeStorageApiPort for StorageMock {
    // Returns one deterministic local storage observation.
    fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError> {
        Ok(Self::snapshot())
    }

    // Records one exact content-bound cleanup and returns its matching receipt.
    fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        self.clean_calls
            .lock()
            .expect("storage clean calls")
            .push(request.clone());
        NodeStorageCleanReceipt::new(
            request.operation_id().clone(),
            request.plan_digest().clone(),
            1,
            1_000,
            vec![LogicalModelName::parse("model").expect("model")],
            false,
        )
    }
}

// Supplies deterministic runtime identities and records exact local removal requests.
struct RuntimeMaintenanceMock {
    installation_ids: Vec<RuntimeInstallationId>,
    remove_calls: Mutex<Vec<RuntimeInstallationId>>,
    finalize_calls: Mutex<Vec<NodeRuntimeModelRetention>>,
}

// Records exact local pairing-authority requests and returns deterministic role receipts.
struct PairingActivationMock {
    calls: Mutex<Vec<&'static str>>,
    local_child: Node,
    local_main: Node,
    failure: Option<NodePairingActivationAuthorityError>,
}

impl NodePairingActivationAuthorityPort for PairingActivationMock {
    // Records and returns one exact active child authority receipt.
    fn activate_paired_child(
        &self,
        _request: &NodePairedChildActivationRequest,
    ) -> Result<NodePairingAuthorityReceipt, NodePairingActivationAuthorityError> {
        self.calls.lock().expect("pairing calls").push("activate");
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(NodePairingAuthorityReceipt::restore(
            self.local_child.clone(),
            NodePairingAuthorityDisposition::Applied,
        ))
    }

    // Records and returns one exact active main authority receipt.
    fn restore_paired_main(
        &self,
        _request: &NodePairedMainRestorationRequest,
    ) -> Result<NodePairingAuthorityReceipt, NodePairingActivationAuthorityError> {
        self.calls.lock().expect("pairing calls").push("restore");
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(NodePairingAuthorityReceipt::restore(
            self.local_main.clone(),
            NodePairingAuthorityDisposition::Replayed,
        ))
    }
}

impl NodeRuntimeMaintenanceApiPort for RuntimeMaintenanceMock {
    // Returns one already-bounded stable runtime identity list.
    fn installation_ids(&self) -> Result<Vec<RuntimeInstallationId>, NodeRuntimeMaintenanceError> {
        Ok(self.installation_ids.clone())
    }

    // Records one exact local removal and returns an applied disposition.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
        _retention: NodeRuntimeModelRetention,
    ) -> Result<NodeRuntimeRemovalDisposition, NodeRuntimeMaintenanceError> {
        self.remove_calls
            .lock()
            .expect("runtime removal calls")
            .push(installation_id.clone());
        Ok(NodeRuntimeRemovalDisposition::Applied)
    }

    // Rejects premature finalization and records each policy-bound successful replay.
    fn finalize_cleanup(
        &self,
        retention: NodeRuntimeModelRetention,
    ) -> Result<(), NodeRuntimeMaintenanceError> {
        let removed = self.remove_calls.lock().expect("runtime removal calls");
        if self
            .installation_ids
            .iter()
            .any(|installation_id| !removed.contains(installation_id))
        {
            return Err(NodeRuntimeMaintenanceError::Conflict);
        }
        self.finalize_calls
            .lock()
            .expect("runtime finalization calls")
            .push(retention);
        Ok(())
    }
}

// Records each exact main-only exposure action after the local authorization boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ExposureCall {
    Status,
    Enable,
    Disable,
    DisableMatching(Sha256Digest),
}

// Supplies deterministic exposure state while retaining exact dispatch ordering.
struct ExposureMock {
    calls: Mutex<Vec<ExposureCall>>,
    failure: Option<GatewayExposureError>,
}

impl ExposureMock {
    // Returns one exact verified enabled exposure fixture.
    fn enabled_status() -> GatewayExposureStatus {
        GatewayExposureStatus::new(
            Some(
                GatewayExposure::new(
                    "https://inference.example.ts.net".to_string(),
                    Sha256Digest::parse(&"a".repeat(64)).expect("digest"),
                )
                .expect("exposure"),
            ),
            true,
        )
        .expect("status")
    }
}

impl NodeExposureApiPort for ExposureMock {
    // Records one read and returns the exact enabled fixture.
    fn status(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.calls
            .lock()
            .expect("exposure calls")
            .push(ExposureCall::Status);
        self.failure.map_or_else(|| Ok(Self::enabled_status()), Err)
    }

    // Records one enable and returns the exact enabled fixture.
    fn enable(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.calls
            .lock()
            .expect("exposure calls")
            .push(ExposureCall::Enable);
        self.failure.map_or_else(|| Ok(Self::enabled_status()), Err)
    }

    // Records one disable and returns the exact verified disabled fixture.
    fn disable(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.calls
            .lock()
            .expect("exposure calls")
            .push(ExposureCall::Disable);
        self.failure
            .map_or_else(|| GatewayExposureStatus::new(None, true), Err)
    }

    // Records one lease-bound identity and returns the exact verified disabled fixture.
    fn disable_matching(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.calls
            .lock()
            .expect("exposure calls")
            .push(ExposureCall::DisableMatching(
                expected_configuration_sha256.clone(),
            ));
        self.failure
            .map_or_else(|| GatewayExposureStatus::new(None, true), Err)
    }
}

// Records whether one local-only command-audit request crossed the API boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandAuditCall {
    Open(NodeCommandAuditOpenRequest),
    Complete(NodeCommandAuditCompletionRequest),
}

// Supplies deterministic receipts while retaining every exact call for ordering assertions.
struct CommandAuditMock {
    calls: Mutex<Vec<CommandAuditCall>>,
    failure: Option<NodeCommandAuditError>,
}

// Records every AuditManager-backed private query while returning deterministic projections.
struct AuditQueryMock {
    calls: Mutex<Vec<&'static str>>,
    event: AuditEvent,
}

impl NodeAuditApiPort for AuditQueryMock {
    // Records one bounded recent-event query.
    fn list(&self, _limit: usize) -> Result<Vec<AuditEvent>, AuditError> {
        self.calls.lock().expect("audit calls").push("list");
        Ok(vec![self.event.clone()])
    }

    // Records one exact event query.
    fn show(&self, event_id: &AuditEventId) -> Result<AuditEvent, AuditError> {
        self.calls.lock().expect("audit calls").push("show");
        if event_id != self.event.event_id() {
            return Err(AuditError::NotFound);
        }
        Ok(self.event.clone())
    }

    // Records one complete verification query.
    fn verify(&self) -> Result<NodeAuditVerification, AuditError> {
        self.calls.lock().expect("audit calls").push("verify");
        NodeAuditVerification::new(1, 0, self.event.event_hash().clone())
    }

    // Records one bounded complete export query.
    fn export(&self) -> Result<NodeAuditExport, AuditError> {
        self.calls.lock().expect("audit calls").push("export");
        NodeAuditExport::new(b"{\"events\":[]}\n".to_vec(), 0)
    }
}

impl NodeCommandAuditApiPort for CommandAuditMock {
    // Records one open only after the local identity and role boundary succeeds.
    fn open(
        &self,
        request: NodeCommandAuditOpenRequest,
    ) -> Result<NodeCommandAuditOpenReceipt, NodeCommandAuditError> {
        self.calls
            .lock()
            .expect("command audit calls")
            .push(CommandAuditCall::Open(request.clone()));
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(NodeCommandAuditOpenReceipt::new(
            marker(request.command_id()),
            NodeCommandAuditOpenDisposition::Opened,
        ))
    }

    // Records one completion and returns an event-free deterministic receipt.
    fn complete(
        &self,
        request: NodeCommandAuditCompletionRequest,
    ) -> Result<NodeCommandAuditCompletionReceipt, NodeCommandAuditError> {
        self.calls
            .lock()
            .expect("command audit calls")
            .push(CommandAuditCall::Complete(request));
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(NodeCommandAuditCompletionReceipt::new(
            None,
            NodeCommandAuditCompletionDisposition::Completed,
        ))
    }
}

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic empty placement/topology state and explicit platform service results.
struct HostReadMock;

impl NodeHostPlacementReadPort for HostReadMock {
    // Returns one successfully observed empty placement collection.
    fn placement_records(&self) -> Result<Vec<PlacementRecord>, NodeHostReadError> {
        Ok(Vec::new())
    }
}

impl NodeHostTopologyReadPort for HostReadMock {
    // Returns one successfully observed empty verified-link collection.
    fn verified_links(&self) -> Result<Vec<PlacementLink>, NodeHostReadError> {
        Ok(Vec::new())
    }
}

impl NodeHostProtectionReadPort for HostReadMock {
    // Reports separate protection as not applicable when no placement is active.
    fn protection(
        &self,
        _node: &Node,
        _placement_groups: &[NodeHostPlacementGroup],
    ) -> Result<Option<NodeHostProtectionSummary>, NodeHostReadError> {
        Ok(None)
    }
}

impl NodeHostServiceReadPort for HostReadMock {
    // Reports one ready Gateway without inventing unavailable counters.
    fn gateway(&self, _node: &Node) -> Result<Option<NodeHostGatewaySummary>, NodeHostReadError> {
        Ok(Some(NodeHostGatewaySummary::new(
            NodeHostServiceState::Ready,
            None,
        )))
    }

    // Reports a platform without a separate Watchdog resident.
    fn watchdog(&self, _node: &Node) -> Result<Option<NodeHostWatchdogSummary>, NodeHostReadError> {
        Ok(None)
    }
}

// Adapts one shared deterministic mock to all four host projection ports.
fn host_ports() -> Arc<NodeHostProjectionPorts> {
    let mock = Arc::new(HostReadMock);
    Arc::new(NodeHostProjectionPorts::new(
        mock.clone(),
        mock.clone(),
        mock.clone(),
        mock,
    ))
}

// Returns one repeated canonical identity.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one coherent main or child node fixture.
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    role: NodeRole,
    state: NodeState,
    address: &str,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character)).expect("node"),
            MachineId::parse(&identity(machine_character)).expect("machine"),
            InstallationId::parse(&installation_character.to_string().repeat(64))
                .expect("installation"),
        ),
        DisplayName::parse(if role == NodeRole::Main {
            "Home AI"
        } else {
            "Node 2"
        })
        .expect("name"),
        role,
        state,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Returns one complete non-secret event for private AuditManager projection tests.
fn audit_event() -> AuditEvent {
    AuditEvent::from_persisted(
        1,
        AuditEventId::parse(&identity('a')).expect("event"),
        AuditCorrelationId::parse(&identity('b')).expect("correlation"),
        AuditUnixNanoseconds::new(1_000).expect("timestamp"),
        NodeId::parse(&identity('1')).expect("node"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("local-user-501").expect("actor"),
        ),
        AuditOrigin::new(
            NodeId::parse(&identity('1')).expect("origin node"),
            AuditOriginInterface::Cli,
        ),
        AuditAction::parse("model.install").expect("action"),
        AuditTarget::parse("model-service").expect("target"),
        None,
        Some(Sha256Digest::parse(&"d".repeat(64)).expect("after")),
        AuditOutcome::Success,
        None,
        Sha256Digest::parse(&"0".repeat(64)).expect("previous"),
        Sha256Digest::parse(&"f".repeat(64)).expect("event hash"),
    )
    .expect("audit event")
}

// Opens one isolated manager for the supplied local role.
fn open_manager(directory: &tempfile::TempDir, role: NodeRole) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(
            database,
            node('1', '2', '3', role, NodeState::Active, "homeai.local"),
            "initialize-node",
        )
        .expect("manager")
        .0,
    )
}

// Returns one ordinary pending child fixture.
fn child() -> Node {
    node(
        '4',
        '5',
        '6',
        NodeRole::Child,
        NodeState::Pending,
        "homeai-node-2.local",
    )
}

// Mocks action-level authorization and records every attempted principal/action pair.
struct MockAuthorization {
    denied: Mutex<HashSet<NodePrivateAction>>,
    calls: Mutex<Vec<(CredentialId, NodePrivateAction)>>,
}

impl MockAuthorization {
    // Creates one allow-all authorization provider.
    fn new() -> Self {
        Self {
            denied: Mutex::new(HashSet::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl NodePrivateAuthorizationProvider for MockAuthorization {
    // Records and authorizes or denies one exact private action.
    fn authorize(
        &self,
        principal_id: &CredentialId,
        action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        self.calls
            .lock()
            .expect("calls")
            .push((principal_id.clone(), action));
        if self.denied.lock().expect("denied").contains(&action) {
            Err(NodePrivateApiError::AuthorizationDenied)
        } else {
            Ok(())
        }
    }
}

// Rejects every unused pairing call in the manager-only private API contracts.
struct UnavailablePairing;

// Returns one deterministic catalog target or one selected provider failure.
struct CatalogMock {
    calls: Mutex<Vec<(NodeId, String)>>,
    list_calls: Mutex<Vec<NodeCatalogListRequest>>,
    failure: Option<NodeCatalogApiError>,
}

impl NodeCatalogApiPort for CatalogMock {
    // Records and returns one exact closed catalog listing request.
    fn list(
        &self,
        request: &NodeCatalogListRequest,
    ) -> Result<NodeCatalogListing, NodeCatalogApiError> {
        self.list_calls
            .lock()
            .expect("catalog list calls")
            .push(request.clone());
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        catalog_listing()
    }

    // Records the exact node/source binding before returning one compatible target.
    fn compatible_targets(
        &self,
        node_id: &NodeId,
        catalog_source: &str,
    ) -> Result<Vec<NodeCatalogTarget>, NodeCatalogApiError> {
        self.calls
            .lock()
            .expect("catalog calls")
            .push((node_id.clone(), catalog_source.to_string()));
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        Ok(vec![NodeCatalogTarget::new(
            LogicalModelName::parse("deepseek_r1").expect("model"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            true,
        )])
    }
}

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

// Records every exact benchmark command received after private authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
enum BenchmarkCall {
    Preview(NodeBenchmarkSelection),
    Start(String, NodeBenchmarkSelection),
    Verification(String, String, Option<RuntimeCandidateId>),
    Record(OperationId),
    Active,
    Stop(OperationId),
}

// Supplies one deterministic secret-free benchmark status through the injected Node port.
struct BenchmarkMock {
    calls: Mutex<Vec<BenchmarkCall>>,
    failure: Option<BenchmarkError>,
}

impl NodeBenchmarkApiPort for BenchmarkMock {
    // Records and resolves one exact read-only benchmark plan.
    fn preview(
        &self,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        self.calls
            .lock()
            .expect("benchmark calls")
            .push(BenchmarkCall::Preview(selection.clone()));
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        benchmark_plan(&selection)
    }

    // Records and accepts one exact benchmark start selection.
    fn start(
        &self,
        idempotency_key: &str,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.calls
            .lock()
            .expect("benchmark calls")
            .push(BenchmarkCall::Start(idempotency_key.to_string(), selection));
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        Ok(benchmark_snapshot())
    }

    // Records and accepts one resident-resolved verification selector.
    fn start_verification(
        &self,
        idempotency_key: &str,
        pull_request_url: &str,
        candidate: Option<&RuntimeCandidateId>,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.calls
            .lock()
            .expect("benchmark calls")
            .push(BenchmarkCall::Verification(
                idempotency_key.to_string(),
                pull_request_url.to_string(),
                candidate.cloned(),
            ));
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        Ok(benchmark_snapshot())
    }

    // Records and returns one exact durable benchmark job.
    fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.calls
            .lock()
            .expect("benchmark calls")
            .push(BenchmarkCall::Record(job_id.clone()));
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        Ok(Some(benchmark_snapshot()))
    }

    // Records and returns the sole active benchmark job.
    fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.calls
            .lock()
            .expect("benchmark calls")
            .push(BenchmarkCall::Active);
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        Ok(Some(benchmark_snapshot()))
    }

    // Records and accepts cancellation of one exact benchmark job.
    fn stop(&self, job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.calls
            .lock()
            .expect("benchmark calls")
            .push(BenchmarkCall::Stop(job_id.clone()));
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        Ok(benchmark_snapshot())
    }
}

// Coordinates one in-flight benchmark mutation without timing-dependent sleeps.
struct MutationGate {
    entered: Barrier,
    released: Mutex<bool>,
    condition: Condvar,
}

impl MutationGate {
    // Creates one two-party admission rendezvous in its blocked state.
    fn new() -> Self {
        Self {
            entered: Barrier::new(2),
            released: Mutex::new(false),
            condition: Condvar::new(),
        }
    }

    // Waits until the provider has entered the mutation dispatch.
    fn wait_until_entered(&self) {
        self.entered.wait();
    }

    // Releases the exact blocked provider mutation.
    fn release(&self) {
        *self.released.lock().expect("mutation release") = true;
        self.condition.notify_all();
    }

    // Blocks the provider after announcing entry until the test releases it.
    fn enter_and_wait(&self) {
        self.entered.wait();
        let mut released = self.released.lock().expect("mutation release");
        while !*released {
            released = self.condition.wait(released).expect("mutation release");
        }
    }
}

// Wraps the ordinary benchmark fixture with one deterministic blocking start call.
struct BlockingBenchmarkMock {
    inner: BenchmarkMock,
    gate: Arc<MutationGate>,
}

impl NodeBenchmarkApiPort for BlockingBenchmarkMock {
    // Delegates read-only planning unchanged.
    fn preview(
        &self,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        self.inner.preview(selection)
    }

    // Holds one mutation inside dispatch until the test explicitly releases it.
    fn start(
        &self,
        idempotency_key: &str,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.gate.enter_and_wait();
        self.inner.start(idempotency_key, selection)
    }

    // Delegates verification start unchanged.
    fn start_verification(
        &self,
        idempotency_key: &str,
        pull_request_url: &str,
        candidate: Option<&RuntimeCandidateId>,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.inner
            .start_verification(idempotency_key, pull_request_url, candidate)
    }

    // Delegates exact record reads unchanged.
    fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.inner.record(job_id)
    }

    // Delegates active-job inventory unchanged.
    fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.inner.active()
    }

    // Delegates exact leased cancellation unchanged.
    fn stop(&self, job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.inner.stop(job_id)
    }
}

// Supplies the immutable service inventory and records exact leased removals.
struct UninstallModelMock {
    services: Vec<NodeModelServiceSummary>,
    remove_calls: Mutex<Vec<NodeModelRemoveRequest>>,
}

impl NodeModelApiPort for UninstallModelMock {
    // Returns the exact installed-service inventory fixture.
    fn list(&self) -> Result<Vec<NodeModelServiceSummary>, NodeModelError> {
        Ok(self.services.clone())
    }

    // Rejects unexpected installation through this narrow fixture.
    fn install(
        &self,
        _request: NodeModelInstallRequest,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected update through this narrow fixture.
    fn update(
        &self,
        _request: NodeModelUpdateRequest,
    ) -> Result<NodeModelUpdateSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected pause through this narrow fixture.
    fn pause(
        &self,
        _identity: NodeModelCommandIdentity,
        _service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected resume through this narrow fixture.
    fn resume(
        &self,
        _identity: NodeModelCommandIdentity,
        _service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected restart through this narrow fixture.
    fn restart(
        &self,
        _identity: NodeModelCommandIdentity,
        _service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected recovery through this narrow fixture.
    fn recover(
        &self,
        _identity: NodeModelCommandIdentity,
        _service_id: ModelServiceId,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Records the exact leased removal before returning a deterministic provider result.
    fn remove(
        &self,
        request: NodeModelRemoveRequest,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        self.remove_calls
            .lock()
            .expect("model removal calls")
            .push(request);
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected rollback through this narrow fixture.
    fn rollback(
        &self,
        _identity: NodeModelCommandIdentity,
        _service_id: ModelServiceId,
        _target_id: Option<TargetId>,
    ) -> Result<NodeModelCommandSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected rollback preview through this narrow fixture.
    fn preview_rollback(
        &self,
        _service_id: &ModelServiceId,
        _target_id: Option<&TargetId>,
    ) -> Result<NodeModelRollbackPreview, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected log reads through this narrow fixture.
    fn logs(&self, _service_id: &ModelServiceId) -> Result<NodeModelLogSummary, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }

    // Rejects unexpected runtime-log reads through this narrow fixture.
    fn runtime_logs(
        &self,
        _request: NodeModelRuntimeLogRequest,
    ) -> Result<NodeModelRuntimeLogBatch, NodeModelError> {
        Err(NodeModelError::ProviderUnavailable)
    }
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one complete deterministic signed catalog projection.
fn catalog_listing() -> Result<NodeCatalogListing, NodeCatalogApiError> {
    NodeCatalogListing::new(
        NodeCatalogSnapshot::new(
            "https://letsinfer.ai/catalog.json".to_string(),
            digest('a'),
            digest('b'),
            7,
            1_000,
            false,
        )?,
        vec![NodeCatalogEntry::new(
            LogicalModelName::parse("deepseek_r1").expect("model"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            "2.0.0".to_string(),
            format!("ghcr.io/letsinfer/runtime@sha256:{}", "c".repeat(64)),
            TechnicalName::parse("sglang").expect("engine"),
            "hf://owner/model".to_string(),
            vec![NodeCatalogAuthor::new(
                "owner".to_string(),
                7,
                NodeCatalogAuthorKind::User,
            )?],
            "Apache-2.0".to_string(),
            EvidenceLabel::Qualified,
            "consensus-v1".to_string(),
            Some(2.5),
            true,
        )?],
    )
}

// Returns one exact opaque marker bound to the supplied command identity.
fn marker(command_id: &Sha256Digest) -> NodeCommandAuditMarker {
    NodeCommandAuditMarker::parse(&format!(
        "li_cli_audit_{}_{}",
        command_id.as_str(),
        "f".repeat(64)
    ))
    .expect("marker")
}

// Returns one ordinary main-only command-audit open request.
fn command_audit_open(role: NodeRole) -> NodeCommandAuditOpenRequest {
    NodeCommandAuditOpenRequest::new(
        digest('e'),
        NodeCommandAuditIntent::new(
            TechnicalName::parse("auth.key.rotate").expect("action"),
            NodeCommandAuditPolicy::Always,
            NodeCommandAuditMutation::Node,
            role,
        ),
    )
}

// Returns one model-neutral local benchmark request.
fn benchmark_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"3".repeat(64)).expect("Core installation"),
            RuntimeInstallationId::parse(&identity('4')).expect("runtime installation"),
            LogicalModelName::parse("deepseek_r1").expect("logical model"),
            PlacementGroupId::parse(&identity('5')).expect("placement group"),
            digest('6'),
            digest('7'),
            digest('8'),
        ),
    )
    .expect("benchmark request")
}

// Returns the public selection accepted by the private benchmark boundary.
fn benchmark_selection() -> NodeBenchmarkSelection {
    NodeBenchmarkSelection::new(
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        vec![1],
        Vec::new(),
    )
    .expect("benchmark selection")
}

// Returns one exact inspectable plan for the deterministic benchmark mock.
fn benchmark_plan(selection: &NodeBenchmarkSelection) -> Result<NodeBenchmarkPlan, BenchmarkError> {
    let cell = TechnicalName::parse("32k-code-c1").expect("cell");
    NodeBenchmarkPlan::new(
        selection,
        benchmark_request(),
        vec![cell.clone()],
        vec![cell],
    )
}

// Returns one coherent running benchmark projection.
fn benchmark_snapshot() -> NodeBenchmarkSnapshot {
    NodeBenchmarkSnapshot::restore(
        OperationId::parse(&identity('d')).expect("benchmark job"),
        3,
        BenchmarkKind::Local,
        BenchmarkJobPhase::Running,
        Some(BenchmarkDisposition::Running),
        digest('c'),
        InstallationId::parse(&"3".repeat(64)).expect("Core installation"),
        RuntimeInstallationId::parse(&identity('4')).expect("runtime installation"),
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        PlacementGroupId::parse(&identity('5')).expect("placement group"),
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
        Some(
            NodeBenchmarkSnapshotProgress::restore(
                TechnicalName::parse("measure").expect("phase"),
                1,
                4,
            )
            .expect("progress"),
        ),
        None,
        None,
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(2_000),
    )
    .expect("benchmark snapshot")
}

// Returns one nonremoved model-service target for an uninstall inventory.
fn uninstall_model_service(
    service_id: ModelServiceId,
    desired_state: ModelServiceDesiredState,
) -> NodeModelServiceSummary {
    NodeModelServiceSummary::new(
        service_id,
        LogicalModelName::parse("deepseek_r1").expect("logical model"),
        desired_state,
        Vec::new(),
        vec![RuntimeInstallationId::parse(&identity('4')).expect("runtime")],
        vec![EvidenceLabel::Qualified],
    )
}

// Returns one complete all-placement model removal bound to the selected retention policy.
fn uninstall_model_remove(
    service_id: ModelServiceId,
    retention: NodeModelRemovalRetention,
) -> NodeModelRemoveRequest {
    NodeModelRemoveRequest::new(
        NodeModelCommandIdentity::new(
            OperationId::parse(&identity('7')).expect("operation"),
            TechnicalName::parse("uninstall-model").expect("idempotency key"),
        ),
        service_id,
        NodeModelRemovalSelection::All,
        retention,
    )
}

// Creates one private API with retained manager and authorization mock.
fn api(
    directory: &tempfile::TempDir,
    role: NodeRole,
) -> (NodePrivateApi, Arc<NodeManager>, Arc<MockAuthorization>) {
    let manager = open_manager(directory, role);
    let authorization = Arc::new(MockAuthorization::new());
    (
        NodePrivateApi::new(
            manager.clone(),
            authorization.clone(),
            Arc::new(UnavailablePairing),
        ),
        manager,
        authorization,
    )
}

// Returns one exact authenticated private principal fixture.
fn principal() -> CredentialId {
    CredentialId::parse(&identity('9')).expect("principal")
}

// Returns one valid processor-only hardware observation for the local node.
fn hardware_observation(node_id: NodeId) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&identity('4')).expect("observation"),
        node_id,
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

// Dispatches local and topology reads after exact action authorization.
#[test]
fn private_api_dispatches_read_contracts_without_second_projection() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (api, manager, authorization) = api(&directory, NodeRole::Main);
    let NodePrivateResponse::LocalNode(local) = api
        .dispatch(&principal(), NodePrivateRequest::ReadLocalNode)
        .expect("local")
    else {
        panic!("local response");
    };
    assert_eq!(&local, &manager.local_node().expect("manager local"));
    let NodePrivateResponse::Nodes(nodes) = api
        .dispatch(&principal(), NodePrivateRequest::ReadNodes)
        .expect("nodes")
    else {
        panic!("nodes response");
    };
    assert_eq!(nodes, manager.nodes().expect("manager nodes"));
    let NodePrivateResponse::NodeChanged(versioned) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::ReadNode {
                node_id: local.identity().node_id().clone(),
            },
        )
        .expect("versioned node")
    else {
        panic!("versioned node response");
    };
    assert_eq!(versioned.value(), &local);
    assert!(versioned.revision() > 0);
    let observation = hardware_observation(manager.local_node_id().clone());
    manager
        .record_local_hardware_observation("hardware", versioned.revision(), observation.clone())
        .expect("record hardware");
    let NodePrivateResponse::HardwareObservation(recorded) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::ReadHardware {
                node_id: manager.local_node_id().clone(),
            },
        )
        .expect("hardware")
    else {
        panic!("hardware response");
    };
    assert_eq!(recorded, Some(observation));
    assert_eq!(
        authorization
            .calls
            .lock()
            .expect("calls")
            .iter()
            .map(|(_, action)| *action)
            .collect::<Vec<_>>(),
        [
            NodePrivateAction::ReadLocalNode,
            NodePrivateAction::ReadNodes,
            NodePrivateAction::ReadNode,
            NodePrivateAction::ReadHardware,
        ]
    );
}

// Proves the nested Gateway capability never crosses the remote principal boundary.
#[test]
fn private_api_denies_gateway_capabilities_before_remote_authorization() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (api, _manager, authorization) = api(&directory, NodeRole::Main);
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::Gateway(NodeGatewayRequest::AuthorizeModelList {
                bearer: NodeGatewayBearer::parse("li_fixture_bearer").expect("bearer"),
            }),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::FinalizeRuntimeArtifacts {
                session_id: digest('1'),
                model_retention: NodeRuntimeModelRetention::Preserve,
            }),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert!(authorization.calls.lock().expect("calls").is_empty());
}

// Composes the host ports once and exposes one local inventory plus one exact child projection.
#[test]
fn private_api_exposes_single_host_read_model_with_local_and_child_scope() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let child = child();
    manager
        .enroll_child("enroll-child", child.clone())
        .expect("child");
    let api = base.with_host_projection(host_ports());

    let NodePrivateResponse::HostInventory(inventory) = api
        .dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::ReadHostInventory,
        )
        .expect("host inventory")
    else {
        panic!("host inventory response");
    };
    assert_eq!(inventory.local_node_id(), manager.local_node_id());
    assert_eq!(inventory.hosts().len(), 2);
    assert!(inventory.hosts().iter().all(|host| host
        .placement_groups()
        .available()
        .is_some_and(Vec::is_empty)));
    assert!(inventory.model_services().is_unavailable());

    let NodePrivateResponse::HostProjection(projected_child) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::ReadHostProjection {
                node_id: child.identity().node_id().clone(),
            },
        )
        .expect("child host projection")
    else {
        panic!("child host projection response");
    };
    assert_eq!(projected_child.node().identity(), child.identity());
    assert!(projected_child.hardware().is_unavailable());
    assert!(projected_child.watchdog().is_not_applicable());
    assert_eq!(
        authorization
            .calls
            .lock()
            .expect("authorization calls")
            .last(),
        Some(&(principal(), NodePrivateAction::ReadNode))
    );
    assert_eq!(
        api.dispatch(&principal(), NodePrivateRequest::ReadHostInventory),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
}

// Authorizes and routes catalog judgment through the injected Node-owned projection only.
#[test]
fn private_api_dispatches_catalog_projection_and_preserves_provider_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let catalog = Arc::new(CatalogMock {
        calls: Mutex::new(Vec::new()),
        list_calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let catalog_api = base.with_catalog(catalog.clone());
    let request = NodePrivateRequest::ReadCompatibleTargets {
        node_id: manager.local_node_id().clone(),
        catalog_source: "https://letsinfer.ai/catalog.json".to_string(),
    };
    let NodePrivateResponse::CompatibleTargets(targets) = catalog_api
        .dispatch(&principal(), request)
        .expect("catalog targets")
    else {
        panic!("catalog response");
    };
    assert_eq!(targets.len(), 1);
    assert!(targets[0].is_recommended());
    assert_eq!(catalog.calls.lock().expect("calls").len(), 1);
    assert_eq!(
        authorization
            .calls
            .lock()
            .expect("authorization calls")
            .last(),
        Some(&(principal(), NodePrivateAction::ReadCompatibleTargets))
    );

    let list_request = NodeCatalogListRequest::new(
        Some("https://letsinfer.ai/catalog.json".to_string()),
        Some(LogicalModelName::parse("deepseek_r1").expect("model")),
        NodeCatalogVersionSelection::All,
        NodeCatalogTargetSelection::All,
        NodeCatalogRefreshPolicy::Refresh,
    )
    .expect("catalog request");
    let NodePrivateResponse::Catalog(listing) = catalog_api
        .dispatch(
            &principal(),
            NodePrivateRequest::ReadCatalog(list_request.clone()),
        )
        .expect("catalog listing")
    else {
        panic!("catalog listing response");
    };
    assert_eq!(listing.entries()[0].version(), "2.0.0");
    assert_eq!(listing.entries()[0].target_id().as_str(), "dgx-spark");
    assert_eq!(
        catalog
            .list_calls
            .lock()
            .expect("catalog list calls")
            .as_slice(),
        &[list_request]
    );
    assert_eq!(
        authorization
            .calls
            .lock()
            .expect("authorization calls")
            .last(),
        Some(&(principal(), NodePrivateAction::ReadCatalog))
    );

    let failing_directory = tempfile::tempdir().expect("failing directory");
    let (base, manager, _) = api(&failing_directory, NodeRole::Main);
    let failing = base.with_catalog(Arc::new(CatalogMock {
        calls: Mutex::new(Vec::new()),
        list_calls: Mutex::new(Vec::new()),
        failure: Some(NodeCatalogApiError::Unavailable),
    }));
    assert_eq!(
        failing
            .dispatch(
                &principal(),
                NodePrivateRequest::ReadCompatibleTargets {
                    node_id: manager.local_node_id().clone(),
                    catalog_source: "https://letsinfer.ai/catalog.json".to_string(),
                },
            )
            .expect_err("catalog failure"),
        NodePrivateApiError::Catalog(NodeCatalogApiError::Unavailable)
    );
}

// Dispatches child enrollment and transition through ordinary NodeManager lifecycle code.
#[test]
fn private_api_dispatches_mutations_with_exact_revision_and_replay() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (api, _, _) = api(&directory, NodeRole::Main);
    let child = child();
    let NodePrivateResponse::NodeChanged(enrolled) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::EnrollChild {
                idempotency_key: "enroll".to_string(),
                child: child.clone(),
            },
        )
        .expect("enroll")
    else {
        panic!("enroll response");
    };
    let NodePrivateResponse::NodeChanged(activated) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::TransitionChild {
                idempotency_key: "activate".to_string(),
                node_id: child.identity().node_id().clone(),
                expected_revision: enrolled.revision(),
                transition: NodeTransition::Activate,
                updated_at: UnixMilliseconds::new(2_000),
            },
        )
        .expect("activate")
    else {
        panic!("activate response");
    };
    assert_eq!(activated.value().state(), NodeState::Active);
    let NodePrivateResponse::NodeChanged(replay) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::TransitionChild {
                idempotency_key: "activate".to_string(),
                node_id: child.identity().node_id().clone(),
                expected_revision: enrolled.revision(),
                transition: NodeTransition::Activate,
                updated_at: UnixMilliseconds::new(2_000),
            },
        )
        .expect("replay")
    else {
        panic!("replay response");
    };
    assert_eq!(replay.revision(), activated.revision());
    assert!(replay.event().is_none());
}

// Dispatches pending-outbox delivery and acknowledgment through typed responses.
#[test]
fn private_api_dispatches_outbox_read_and_acknowledgment() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (api, _, _) = api(&directory, NodeRole::Main);
    let NodePrivateResponse::PendingOutbox(events) = api
        .dispatch(&principal(), NodePrivateRequest::ReadPendingOutbox)
        .expect("pending")
    else {
        panic!("pending response");
    };
    let event = events[0].clone();
    let NodePrivateResponse::OutboxAcknowledged(acknowledged) = api
        .dispatch(
            &principal(),
            NodePrivateRequest::AcknowledgeOutbox {
                idempotency_key: "acknowledge".to_string(),
                event_id: event.event().event_id().clone(),
                expected_revision: event.revision(),
                acknowledged_at: UnixMilliseconds::new(2_000),
            },
        )
        .expect("acknowledge")
    else {
        panic!("acknowledgment response");
    };
    assert_eq!(
        acknowledged.event().state(),
        li_node_manager::NodeOutboxState::Acknowledged
    );
}

// Denies every action before manager reads or mutations can execute.
#[test]
fn authorization_denial_precedes_every_dispatch_path() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (api, manager, authorization) = api(&directory, NodeRole::Main);
    for action in [
        NodePrivateAction::ReadLocalNode,
        NodePrivateAction::ReadNodes,
        NodePrivateAction::ReadNode,
        NodePrivateAction::ReadHardware,
        NodePrivateAction::ReadCompatibleTargets,
        NodePrivateAction::EnrollChild,
        NodePrivateAction::TransitionChild,
        NodePrivateAction::ReadOutbox,
        NodePrivateAction::AcknowledgeOutbox,
    ] {
        authorization.denied.lock().expect("denied").insert(action);
    }
    let initial_nodes = manager.nodes().expect("nodes");
    let initial_events = manager.outbox_events().expect("events");
    let requests = [
        NodePrivateRequest::ReadLocalNode,
        NodePrivateRequest::ReadNodes,
        NodePrivateRequest::ReadNode {
            node_id: manager.local_node_id().clone(),
        },
        NodePrivateRequest::ReadHardware {
            node_id: manager.local_node_id().clone(),
        },
        NodePrivateRequest::ReadCompatibleTargets {
            node_id: manager.local_node_id().clone(),
            catalog_source: "https://letsinfer.ai/catalog.json".to_string(),
        },
        NodePrivateRequest::EnrollChild {
            idempotency_key: "enroll".to_string(),
            child: child(),
        },
        NodePrivateRequest::TransitionChild {
            idempotency_key: "transition".to_string(),
            node_id: NodeId::parse(&identity('4')).expect("node"),
            expected_revision: 1,
            transition: NodeTransition::Activate,
            updated_at: UnixMilliseconds::new(2_000),
        },
        NodePrivateRequest::ReadPendingOutbox,
        NodePrivateRequest::AcknowledgeOutbox {
            idempotency_key: "acknowledge".to_string(),
            event_id: initial_events[0].event().event_id().clone(),
            expected_revision: initial_events[0].revision(),
            acknowledged_at: UnixMilliseconds::new(2_000),
        },
    ];
    for request in requests {
        assert_eq!(
            api.dispatch(&principal(), request).expect_err("denied"),
            NodePrivateApiError::AuthorizationDenied
        );
    }
    assert_eq!(manager.nodes().expect("nodes"), initial_nodes);
    assert_eq!(manager.outbox_events().expect("events"), initial_events);
}

// Maps manager authority failure without weakening or replacing its typed cause.
#[test]
fn manager_failure_is_preserved_at_private_api_boundary() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (api, _, _) = api(&directory, NodeRole::Child);
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::EnrollChild {
                idempotency_key: "enroll".to_string(),
                child: child(),
            },
        )
        .expect_err("not main"),
        NodePrivateApiError::Manager(li_node_manager::NodeManagerError::NotMain)
    );
}

// Authorizes and projects every exact benchmark command through one injected Node port.
#[test]
fn private_api_dispatches_exact_benchmark_commands_after_active_main_check() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, _, authorization) = api(&directory, NodeRole::Main);
    let benchmark = Arc::new(BenchmarkMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let api = base.with_benchmark(benchmark.clone());
    let selection = benchmark_selection();
    let job_id = benchmark_snapshot().job_id().clone();

    assert!(matches!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::PreviewBenchmark {
                selection: selection.clone(),
            },
        )
        .expect("preview"),
        NodePrivateResponse::BenchmarkPlan(_)
    ));
    assert!(matches!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::StartBenchmark {
                idempotency_key: "benchmark-local".to_string(),
                selection: selection.clone(),
            },
        )
        .expect("start"),
        NodePrivateResponse::BenchmarkChanged(_)
    ));
    let candidate = RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate");
    assert!(matches!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::StartBenchmarkVerification {
                idempotency_key: "benchmark-verification".to_string(),
                pull_request_url: "https://github.com/letsinferlabs/runtimes/pull/41".to_string(),
                candidate: Some(candidate.clone()),
            },
        )
        .expect("verification start"),
        NodePrivateResponse::BenchmarkChanged(_)
    ));
    assert!(matches!(
        api.dispatch(&principal(), NodePrivateRequest::ReadActiveBenchmark)
            .expect("active"),
        NodePrivateResponse::BenchmarkRecord(Some(_))
    ));
    assert!(matches!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::ReadBenchmark {
                job_id: job_id.clone(),
            },
        )
        .expect("record"),
        NodePrivateResponse::BenchmarkRecord(Some(_))
    ));
    assert!(matches!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::StopBenchmark {
                job_id: job_id.clone(),
            },
        )
        .expect("stop"),
        NodePrivateResponse::BenchmarkChanged(_)
    ));

    assert_eq!(
        *benchmark.calls.lock().expect("benchmark calls"),
        [
            BenchmarkCall::Preview(selection.clone()),
            BenchmarkCall::Start("benchmark-local".to_string(), selection),
            BenchmarkCall::Verification(
                "benchmark-verification".to_string(),
                "https://github.com/letsinferlabs/runtimes/pull/41".to_string(),
                Some(candidate),
            ),
            BenchmarkCall::Active,
            BenchmarkCall::Record(job_id.clone()),
            BenchmarkCall::Stop(job_id),
        ]
    );
    assert_eq!(
        authorization
            .calls
            .lock()
            .expect("authorization calls")
            .iter()
            .rev()
            .take(6)
            .map(|(_, action)| *action)
            .collect::<Vec<_>>(),
        [
            NodePrivateAction::StopBenchmark,
            NodePrivateAction::ReadBenchmark,
            NodePrivateAction::ReadActiveBenchmark,
            NodePrivateAction::StartBenchmark,
            NodePrivateAction::StartBenchmark,
            NodePrivateAction::PreviewBenchmark,
        ]
    );
}

// Denies benchmark commands before the benchmark port can observe an identity or replay key.
#[test]
fn private_api_benchmark_authorization_denial_precedes_port_dispatch() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, _, authorization) = api(&directory, NodeRole::Main);
    authorization
        .denied
        .lock()
        .expect("denied")
        .insert(NodePrivateAction::StartBenchmark);
    let benchmark = Arc::new(BenchmarkMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let api = base.with_benchmark(benchmark.clone());

    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::StartBenchmarkVerification {
                idempotency_key: "sensitive-replay-key".to_string(),
                pull_request_url: "https://github.com/letsinferlabs/runtimes/pull/41".to_string(),
                candidate: None,
            },
        )
        .expect_err("denied"),
        NodePrivateApiError::AuthorizationDenied
    );
    assert!(benchmark.calls.lock().expect("benchmark calls").is_empty());
}

// Rejects child-node benchmark control before invoking the injected benchmark port.
#[test]
fn private_api_benchmark_control_is_active_main_only() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, _, _) = api(&directory, NodeRole::Child);
    let benchmark = Arc::new(BenchmarkMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let api = base.with_benchmark(benchmark.clone());

    assert_eq!(
        api.dispatch(&principal(), NodePrivateRequest::ReadActiveBenchmark)
            .expect_err("child denied"),
        NodePrivateApiError::ActiveMainRequired
    );
    assert!(benchmark.calls.lock().expect("benchmark calls").is_empty());
}

// Preserves one stable benchmark-port failure without leaking provider details.
#[test]
fn private_api_preserves_benchmark_failure_and_unavailable_boundary() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, _, _) = api(&directory, NodeRole::Main);
    assert_eq!(
        base.dispatch(&principal(), NodePrivateRequest::ReadActiveBenchmark)
            .expect_err("unavailable"),
        NodePrivateApiError::Benchmark(BenchmarkError::provider(
            "node API",
            "benchmark service is unavailable"
        ))
    );

    let benchmark = Arc::new(BenchmarkMock {
        calls: Mutex::new(Vec::new()),
        failure: Some(BenchmarkError::Busy),
    });
    let api = base.with_benchmark(benchmark);
    assert_eq!(
        api.dispatch(&principal(), NodePrivateRequest::ReadActiveBenchmark)
            .expect_err("busy"),
        NodePrivateApiError::Benchmark(BenchmarkError::Busy)
    );
}

// Proves the owner-authenticated local API alone can open and complete a command audit lifecycle.
#[test]
fn command_audit_projection_is_local_role_bound_and_exact() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let audit = Arc::new(CommandAuditMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let api = base.with_command_audit(audit.clone());
    let request = command_audit_open(NodeRole::Main);
    let NodePrivateResponse::CommandAuditOpened(opened) = api
        .dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::OpenCommandAudit(request.clone()),
        )
        .expect("open")
    else {
        panic!("open response");
    };
    let result = NodeCommandAuditResult::new(
        TechnicalName::parse("auth.key.rotate").expect("action"),
        NodeCommandAuditOutcome::Failed,
        Some("manager_unavailable"),
    )
    .expect("result");
    let completion = NodeCommandAuditCompletionRequest::new(opened.marker().clone(), result);
    assert!(matches!(
        api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::CompleteCommandAudit(completion.clone()),
        )
        .expect("complete"),
        NodePrivateResponse::CommandAuditCompleted(_)
    ));
    assert_eq!(
        *audit.calls.lock().expect("command audit calls"),
        [
            CommandAuditCall::Open(request),
            CommandAuditCall::Complete(completion)
        ]
    );
    assert!(authorization
        .calls
        .lock()
        .expect("authorization calls")
        .is_empty());
}

// Proves remote, foreign-owner, and role-mismatched requests fail before authorization or audit.
#[test]
fn command_audit_denial_precedes_every_observer_and_store_boundary() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let audit = Arc::new(CommandAuditMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let api = base.with_command_audit(audit.clone());
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::OpenCommandAudit(command_audit_open(NodeRole::Main)),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert_eq!(
        api.dispatch_local(
            &NodeId::parse(&identity('f')).expect("foreign node"),
            NodePrivateRequest::OpenCommandAudit(command_audit_open(NodeRole::Main)),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert_eq!(
        api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::OpenCommandAudit(command_audit_open(NodeRole::Child)),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert!(audit.calls.lock().expect("command audit calls").is_empty());
    assert!(authorization
        .calls
        .lock()
        .expect("authorization calls")
        .is_empty());
}

// Routes every sensitive audit read through the composed owner and denies the remote surface.
#[test]
fn audit_query_projection_is_local_active_main_only_and_exact() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let event = audit_event();
    let event_id = event.event_id().clone();
    let audit = Arc::new(AuditQueryMock {
        calls: Mutex::new(Vec::new()),
        event: event.clone(),
    });
    let api = base.with_audit(audit.clone());
    let requests = [
        NodePrivateRequest::ReadAuditEvents { limit: 100 },
        NodePrivateRequest::ReadAuditEvent {
            event_id: event_id.clone(),
        },
        NodePrivateRequest::VerifyAudit,
        NodePrivateRequest::ExportAudit,
    ];
    for request in requests {
        api.dispatch_local(manager.local_node_id(), request)
            .expect("local audit query");
    }
    assert_eq!(
        *audit.calls.lock().expect("audit calls"),
        ["list", "show", "verify", "export"]
    );
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::ReadAuditEvent { event_id }
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert!(authorization
        .calls
        .lock()
        .expect("authorization calls")
        .is_empty());
}

// Routes every exposure action only through the owner-local active-main projection.
#[test]
fn exposure_projection_is_local_active_main_only_and_exact() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let exposure = Arc::new(ExposureMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let api = base.with_exposure(exposure.clone());
    let requests = [
        NodePrivateRequest::ReadExposure,
        NodePrivateRequest::EnableExposure,
        NodePrivateRequest::DisableExposure,
    ];
    for request in requests.clone() {
        assert!(matches!(
            api.dispatch_local(manager.local_node_id(), request)
                .expect("local exposure action"),
            NodePrivateResponse::Exposure(_)
        ));
    }
    assert_eq!(
        *exposure.calls.lock().expect("exposure calls"),
        [
            ExposureCall::Status,
            ExposureCall::Enable,
            ExposureCall::Disable
        ]
    );
    for request in requests {
        assert_eq!(
            api.dispatch(&principal(), request),
            Err(NodePrivateApiError::AuthorizationDenied)
        );
    }
    assert!(authorization
        .calls
        .lock()
        .expect("authorization calls")
        .is_empty());
    assert_eq!(
        api.dispatch_local(
            &NodeId::parse(&identity('f')).expect("foreign node"),
            NodePrivateRequest::ReadExposure,
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert_eq!(exposure.calls.lock().expect("exposure calls").len(), 3);
}

// Denies children and preserves unavailable or provider failures before native exposure mutation.
#[test]
fn exposure_projection_preserves_role_and_provider_failure_boundaries() {
    let main_directory = tempfile::tempdir().expect("temporary directory");
    let (main, manager, _) = api(&main_directory, NodeRole::Main);
    assert_eq!(
        main.dispatch_local(manager.local_node_id(), NodePrivateRequest::ReadExposure),
        Err(NodePrivateApiError::Exposure(
            GatewayExposureError::InvalidConfiguration
        ))
    );

    let failed = Arc::new(ExposureMock {
        calls: Mutex::new(Vec::new()),
        failure: Some(GatewayExposureError::ProviderUnavailable),
    });
    let main = main.with_exposure(failed.clone());
    assert_eq!(
        main.dispatch_local(manager.local_node_id(), NodePrivateRequest::EnableExposure),
        Err(NodePrivateApiError::Exposure(
            GatewayExposureError::ProviderUnavailable
        ))
    );
    assert_eq!(
        *failed.calls.lock().expect("exposure calls"),
        [ExposureCall::Enable]
    );

    let child_directory = tempfile::tempdir().expect("temporary directory");
    let (child, manager, _) = api(&child_directory, NodeRole::Child);
    let exposure = Arc::new(ExposureMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let child = child.with_exposure(exposure.clone());
    for request in [
        NodePrivateRequest::ReadExposure,
        NodePrivateRequest::EnableExposure,
        NodePrivateRequest::DisableExposure,
    ] {
        assert_eq!(
            child.dispatch_local(manager.local_node_id(), request),
            Err(NodePrivateApiError::ActiveMainRequired)
        );
    }
    assert!(exposure.calls.lock().expect("exposure calls").is_empty());
}

// Routes storage review and cleanup only through the owner-local Node boundary on either role.
#[test]
fn storage_projection_is_local_only_and_preserves_the_reviewed_plan() {
    for role in [NodeRole::Main, NodeRole::Child] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (base, manager, authorization) = api(&directory, role);
        let storage = Arc::new(StorageMock {
            clean_calls: Mutex::new(Vec::new()),
        });
        let api = base.with_storage(storage.clone());
        let snapshot = match api
            .dispatch_local(manager.local_node_id(), NodePrivateRequest::ReadStorage)
            .expect("local storage snapshot")
        {
            NodePrivateResponse::StorageSnapshot(value) => value,
            _ => panic!("unexpected storage response"),
        };
        let request = NodeStorageCleanRequest::new(
            OperationId::parse(&identity('9')).expect("operation"),
            snapshot.plan_digest().clone(),
            [NodeStorageCategory::Models],
        )
        .expect("cleanup request");
        assert!(matches!(
            api.dispatch_local(
                manager.local_node_id(),
                NodePrivateRequest::CleanStorage(request.clone()),
            )
            .expect("local storage cleanup"),
            NodePrivateResponse::StorageCleaned(receipt)
                if receipt.operation_id() == request.operation_id()
                    && receipt.plan_digest() == request.plan_digest()
        ));
        assert_eq!(
            storage.clean_calls.lock().expect("clean calls").as_slice(),
            &[request]
        );
        assert_eq!(
            api.dispatch(&principal(), NodePrivateRequest::ReadStorage),
            Err(NodePrivateApiError::AuthorizationDenied)
        );
        assert!(authorization
            .calls
            .lock()
            .expect("authorization calls")
            .is_empty());
    }
}

// Routes runtime inventory and exact removal only through the owner-local Node boundary.
#[test]
fn runtime_maintenance_is_local_only_and_preserves_exact_identity() {
    for role in [NodeRole::Main, NodeRole::Child] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (base, manager, authorization) = api(&directory, role);
        let installation_id = RuntimeInstallationId::parse(&identity('4')).expect("runtime");
        let maintenance = Arc::new(RuntimeMaintenanceMock {
            installation_ids: vec![installation_id.clone()],
            remove_calls: Mutex::new(Vec::new()),
            finalize_calls: Mutex::new(Vec::new()),
        });
        let api = base.with_runtime_maintenance(maintenance.clone());
        assert_eq!(
            api.dispatch_local(
                manager.local_node_id(),
                NodePrivateRequest::ReadRuntimeInstallationIds,
            ),
            Ok(NodePrivateResponse::RuntimeInstallationIds(vec![
                installation_id.clone()
            ]))
        );
        assert_eq!(
            api.dispatch_local(
                manager.local_node_id(),
                NodePrivateRequest::RemoveRuntimeInstallation {
                    installation_id: installation_id.clone(),
                    model_retention: NodeRuntimeModelRetention::Remove,
                },
            ),
            Ok(NodePrivateResponse::RuntimeInstallationRemoved(
                NodeRuntimeRemovalDisposition::Applied
            ))
        );
        assert_eq!(
            *maintenance
                .remove_calls
                .lock()
                .expect("runtime removal calls"),
            vec![installation_id]
        );
        assert_eq!(
            api.dispatch(&principal(), NodePrivateRequest::ReadRuntimeInstallationIds,),
            Err(NodePrivateApiError::AuthorizationDenied)
        );
        assert!(authorization
            .calls
            .lock()
            .expect("authorization calls")
            .is_empty());
    }
}

// Routes paired-role mutation only through the owner-local authority and preserves failures.
#[test]
fn pairing_activation_authority_is_local_only_and_exact() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let local_main = manager.local_node().expect("local main");
    let local_child = node(
        '1',
        '2',
        '3',
        NodeRole::Child,
        NodeState::Active,
        "homeai.local",
    );
    let remote_main = node(
        '4',
        '5',
        '6',
        NodeRole::Main,
        NodeState::Active,
        "main.local",
    );
    let authority = Arc::new(PairingActivationMock {
        calls: Mutex::new(Vec::new()),
        local_child,
        local_main,
        failure: None,
    });
    let pairing_api = base.with_pairing_activation(authority.clone());
    let credentials = NodePairingCredentials::new(
        b"main-public-key".to_vec(),
        b"main-ca".to_vec(),
        b"child-certificate".to_vec(),
        b"membership-signature".to_vec(),
        Sha256Digest::parse(&"b".repeat(64)).expect("child leaf"),
        UnixMilliseconds::new(500),
        UnixMilliseconds::new(500_000),
    )
    .expect("credentials");
    let activation = NodePairedChildActivationRequest::new(
        "pairing:activate".to_string(),
        remote_main.clone(),
        Sha256Digest::parse(&"c".repeat(64)).expect("main leaf"),
        credentials.clone(),
    )
    .expect("activation");
    let restoration = NodePairedMainRestorationRequest::new(
        "pairing:restore".to_string(),
        remote_main,
        Sha256Digest::parse(&"c".repeat(64)).expect("main leaf"),
        credentials,
    )
    .expect("restoration");
    assert!(matches!(
        pairing_api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::ActivatePairedChild(activation.clone()),
        ),
        Ok(NodePrivateResponse::PairingAuthorityChanged(receipt))
            if receipt.local().role() == NodeRole::Child
                && receipt.disposition() == NodePairingAuthorityDisposition::Applied
    ));
    assert!(matches!(
        pairing_api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::RestorePairedMain(restoration.clone()),
        ),
        Ok(NodePrivateResponse::PairingAuthorityChanged(receipt))
            if receipt.local().role() == NodeRole::Main
                && receipt.disposition() == NodePairingAuthorityDisposition::Replayed
    ));
    assert_eq!(
        *authority.calls.lock().expect("pairing calls"),
        vec!["activate", "restore"]
    );
    for request in [
        NodePrivateRequest::ActivatePairedChild(activation),
        NodePrivateRequest::RestorePairedMain(restoration),
    ] {
        assert_eq!(
            pairing_api.dispatch(&principal(), request),
            Err(NodePrivateApiError::AuthorizationDenied)
        );
    }
    assert!(authorization
        .calls
        .lock()
        .expect("authorization calls")
        .is_empty());
    let failed_directory = tempfile::tempdir().expect("failed temporary directory");
    let (failed, failed_manager, _) = api(&failed_directory, NodeRole::Main);
    let failed = failed.with_pairing_activation(Arc::new(PairingActivationMock {
        calls: Mutex::new(Vec::new()),
        local_child: node(
            '1',
            '2',
            '3',
            NodeRole::Child,
            NodeState::Active,
            "homeai.local",
        ),
        local_main: failed_manager.local_node().expect("failed local main"),
        failure: Some(NodePairingActivationAuthorityError::AuthorityConflict),
    }));
    assert_eq!(
        failed.dispatch_local(
            failed_manager.local_node_id(),
            NodePrivateRequest::ActivatePairedChild(
                NodePairedChildActivationRequest::new(
                    "pairing:failed".to_string(),
                    node(
                        '4',
                        '5',
                        '6',
                        NodeRole::Main,
                        NodeState::Active,
                        "main.local",
                    ),
                    Sha256Digest::parse(&"c".repeat(64)).expect("failed main leaf"),
                    NodePairingCredentials::new(
                        b"main-public-key".to_vec(),
                        b"main-ca".to_vec(),
                        b"child-certificate".to_vec(),
                        b"membership-signature".to_vec(),
                        Sha256Digest::parse(&"b".repeat(64)).expect("failed child leaf"),
                        UnixMilliseconds::new(500),
                        UnixMilliseconds::new(500_000),
                    )
                    .expect("failed credentials"),
                )
                .expect("failed activation"),
            ),
        ),
        Err(NodePrivateApiError::PairingActivation(
            NodePairingActivationAuthorityError::AuthorityConflict
        ))
    );
}

// Proves nonblocking admission, immutable targets, leased cleanup, origin denial, and cancellation.
#[test]
fn uninstall_barrier_serializes_exact_local_targets_without_blocking_begin() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, authorization) = api(&directory, NodeRole::Main);
    let gate = Arc::new(MutationGate::new());
    let benchmark = Arc::new(BlockingBenchmarkMock {
        inner: BenchmarkMock {
            calls: Mutex::new(Vec::new()),
            failure: None,
        },
        gate: gate.clone(),
    });
    let exposure = Arc::new(ExposureMock {
        calls: Mutex::new(Vec::new()),
        failure: None,
    });
    let service_id = ModelServiceId::parse(&identity('6')).expect("service");
    let model = Arc::new(UninstallModelMock {
        services: vec![
            uninstall_model_service(service_id.clone(), ModelServiceDesiredState::Running),
            uninstall_model_service(
                ModelServiceId::parse(&identity('8')).expect("removed service"),
                ModelServiceDesiredState::Removed,
            ),
        ],
        remove_calls: Mutex::new(Vec::new()),
    });
    let installation_id = RuntimeInstallationId::parse(&identity('4')).expect("runtime");
    let maintenance = Arc::new(RuntimeMaintenanceMock {
        installation_ids: vec![installation_id.clone()],
        remove_calls: Mutex::new(Vec::new()),
        finalize_calls: Mutex::new(Vec::new()),
    });
    let api = Arc::new(
        base.with_benchmark(benchmark.clone())
            .with_exposure(exposure.clone())
            .with_model(model.clone())
            .with_runtime_maintenance(maintenance.clone()),
    );
    let local_node_id = manager.local_node_id().clone();
    let worker_api = api.clone();
    let worker_node_id = local_node_id.clone();
    let worker = thread::spawn(move || {
        worker_api.dispatch_local(
            &worker_node_id,
            NodePrivateRequest::StartBenchmark {
                idempotency_key: "before-uninstall".to_string(),
                selection: benchmark_selection(),
            },
        )
    });
    gate.wait_until_entered();
    let session_id = digest('1');
    let begin = NodePrivateRequest::Uninstall(NodeUninstallRequest::Begin {
        session_id: session_id.clone(),
        model_retention: NodeRuntimeModelRetention::Preserve,
    });
    assert_eq!(
        api.dispatch_local(&local_node_id, begin.clone()),
        Err(NodePrivateApiError::UninstallBusy)
    );
    gate.release();
    assert!(matches!(
        worker.join().expect("benchmark thread"),
        Ok(NodePrivateResponse::BenchmarkChanged(_))
    ));
    let NodePrivateResponse::UninstallBegan(applied) = api
        .dispatch_local(&local_node_id, begin.clone())
        .expect("begin uninstall")
    else {
        panic!("uninstall begin response");
    };
    assert_eq!(
        applied.disposition(),
        NodeUninstallSessionDisposition::Applied
    );
    assert_eq!(applied.inventory().local_role(), NodeRole::Main);
    assert_eq!(
        applied.inventory().active_benchmark_id(),
        Some(benchmark_snapshot().job_id())
    );
    assert!(applied
        .inventory()
        .exposure_configuration_sha256()
        .is_some());
    assert_eq!(applied.inventory().model_targets().len(), 1);
    assert_eq!(
        applied.inventory().runtime_installation_ids(),
        &[installation_id.clone()]
    );
    let NodePrivateResponse::UninstallBegan(replayed) = api
        .dispatch_local(&local_node_id, begin.clone())
        .expect("replay uninstall")
    else {
        panic!("uninstall replay response");
    };
    assert_eq!(
        replayed.disposition(),
        NodeUninstallSessionDisposition::Replayed
    );
    assert_eq!(replayed.inventory(), applied.inventory());
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Begin {
                session_id: session_id.clone(),
                model_retention: NodeRuntimeModelRetention::Remove,
            }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
    assert!(matches!(
        api.dispatch_local(&local_node_id, NodePrivateRequest::ReadLocalNode),
        Ok(NodePrivateResponse::LocalNode(_))
    ));
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::StopBenchmark {
                job_id: benchmark_snapshot().job_id().clone(),
            },
        ),
        Err(NodePrivateApiError::UninstallInProgress)
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Gateway(NodeGatewayRequest::AuthorizeInference {
                bearer: NodeGatewayBearer::parse("li_fixture_bearer").expect("bearer"),
                model: LogicalModelName::parse("deepseek_r1").expect("model"),
            }),
        ),
        Err(NodePrivateApiError::UninstallInProgress)
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Gateway(NodeGatewayRequest::AuthorizeModelList {
                bearer: NodeGatewayBearer::parse("li_fixture_bearer").expect("bearer"),
            }),
        ),
        Err(NodePrivateApiError::Gateway(
            NodeGatewayApiError::Unavailable
        ))
    );
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Cancel {
                session_id: session_id.clone(),
            }),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert_eq!(
        api.dispatch_controller(
            &ControllerId::parse(&identity('a')).expect("controller"),
            &digest('b'),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Cancel {
                session_id: session_id.clone(),
            }),
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
    assert!(authorization.calls.lock().expect("calls").is_empty());
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::StopBenchmark {
                session_id: session_id.clone(),
                job_id: OperationId::parse(&identity('f')).expect("wrong benchmark"),
            }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
    assert!(matches!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::StopBenchmark {
                session_id: session_id.clone(),
                job_id: benchmark_snapshot().job_id().clone(),
            }),
        ),
        Ok(NodePrivateResponse::BenchmarkChanged(_))
    ));
    assert!(matches!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::DisableExposure {
                session_id: session_id.clone(),
            }),
        ),
        Ok(NodePrivateResponse::Exposure(_))
    ));
    assert!(matches!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::DisableExposure {
                session_id: session_id.clone(),
            }),
        ),
        Ok(NodePrivateResponse::Exposure(_))
    ));
    assert_eq!(
        exposure.calls.lock().expect("exposure calls").as_slice(),
        [
            ExposureCall::Status,
            ExposureCall::DisableMatching(digest('a')),
            ExposureCall::DisableMatching(digest('a')),
        ]
    );
    let partial_remove = NodeModelRemoveRequest::new(
        NodeModelCommandIdentity::new(
            OperationId::parse(&identity('e')).expect("operation"),
            TechnicalName::parse("partial-remove").expect("idempotency key"),
        ),
        service_id.clone(),
        NodeModelRemovalSelection::nodes(vec![manager.local_node_id().clone()]).expect("selection"),
        NodeModelRemovalRetention::PreserveModels,
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::RemoveModel {
                session_id: session_id.clone(),
                request: partial_remove,
            }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
    let exact_remove = uninstall_model_remove(
        service_id.clone(),
        NodeModelRemovalRetention::PreserveModels,
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::RemoveModel {
                session_id: session_id.clone(),
                request: exact_remove.clone(),
            }),
        ),
        Err(NodePrivateApiError::Model(
            NodeModelError::ProviderUnavailable
        ))
    );
    assert_eq!(
        model.remove_calls.lock().expect("model calls").as_slice(),
        &[exact_remove]
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::RemoveRuntimeInstallation {
                session_id: session_id.clone(),
                installation_id: RuntimeInstallationId::parse(&identity('f'))
                    .expect("wrong runtime"),
                model_retention: NodeRuntimeModelRetention::Preserve,
            }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::FinalizeRuntimeArtifacts {
                session_id: session_id.clone(),
                model_retention: NodeRuntimeModelRetention::Remove,
            }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::FinalizeRuntimeArtifacts {
                session_id: session_id.clone(),
                model_retention: NodeRuntimeModelRetention::Preserve,
            }),
        ),
        Err(NodePrivateApiError::RuntimeMaintenance(
            NodeRuntimeMaintenanceError::Conflict
        ))
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::RemoveRuntimeInstallation {
                session_id: session_id.clone(),
                installation_id: installation_id.clone(),
                model_retention: NodeRuntimeModelRetention::Preserve,
            }),
        ),
        Ok(NodePrivateResponse::RuntimeInstallationRemoved(
            NodeRuntimeRemovalDisposition::Applied
        ))
    );
    for _ in 0..2 {
        assert!(matches!(
            api.dispatch_local(
                &local_node_id,
                NodePrivateRequest::Uninstall(NodeUninstallRequest::FinalizeRuntimeArtifacts {
                    session_id: session_id.clone(),
                    model_retention: NodeRuntimeModelRetention::Preserve,
                }),
            ),
            Ok(NodePrivateResponse::RuntimeArtifactsFinalized(receipt))
                if receipt.model_retention() == NodeRuntimeModelRetention::Preserve
        ));
    }
    assert_eq!(
        maintenance
            .finalize_calls
            .lock()
            .expect("runtime finalization calls")
            .as_slice(),
        [
            NodeRuntimeModelRetention::Preserve,
            NodeRuntimeModelRetention::Preserve
        ]
    );
    assert_eq!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Cancel {
                session_id: digest('2'),
            }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
    assert!(matches!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Cancel {
                session_id: session_id.clone(),
            }),
        ),
        Ok(NodePrivateResponse::UninstallCanceled(receipt)) if receipt.session_id() == &session_id
    ));
    assert!(matches!(
        api.dispatch_local(
            &local_node_id,
            NodePrivateRequest::StopBenchmark {
                job_id: benchmark_snapshot().job_id().clone(),
            },
        ),
        Ok(NodePrivateResponse::BenchmarkChanged(_))
    ));
}

// Proves one aggregate target beyond the bound rejects admission without publishing a lease.
#[test]
fn uninstall_barrier_rejects_aggregate_overflow_without_activation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, _) = api(&directory, NodeRole::Main);
    let placement_group_ids = (1..=4094)
        .map(|value| PlacementGroupId::parse(&format!("{value:032x}")).expect("placement group"))
        .collect();
    let model = Arc::new(UninstallModelMock {
        services: vec![NodeModelServiceSummary::new(
            ModelServiceId::parse(&identity('6')).expect("service"),
            LogicalModelName::parse("deepseek_r1").expect("logical model"),
            ModelServiceDesiredState::Running,
            placement_group_ids,
            Vec::new(),
            Vec::new(),
        )],
        remove_calls: Mutex::new(Vec::new()),
    });
    let api = base
        .with_benchmark(Arc::new(BenchmarkMock {
            calls: Mutex::new(Vec::new()),
            failure: None,
        }))
        .with_exposure(Arc::new(ExposureMock {
            calls: Mutex::new(Vec::new()),
            failure: None,
        }))
        .with_model(model)
        .with_runtime_maintenance(Arc::new(RuntimeMaintenanceMock {
            installation_ids: Vec::new(),
            remove_calls: Mutex::new(Vec::new()),
            finalize_calls: Mutex::new(Vec::new()),
        }));
    let session_id = digest('2');
    assert_eq!(
        api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Begin {
                session_id: session_id.clone(),
                model_retention: NodeRuntimeModelRetention::Preserve,
            }),
        ),
        Err(NodePrivateApiError::UninstallBarrierUnavailable)
    );
    assert_eq!(
        api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Cancel { session_id }),
        ),
        Err(NodePrivateApiError::UninstallSessionConflict)
    );
}

// Proves child admission snapshots only child-owned runtimes without main-only providers.
#[test]
fn child_uninstall_inventory_omits_main_only_targets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (base, manager, _) = api(&directory, NodeRole::Child);
    let installation_id = RuntimeInstallationId::parse(&identity('4')).expect("runtime");
    let maintenance = Arc::new(RuntimeMaintenanceMock {
        installation_ids: vec![installation_id.clone()],
        remove_calls: Mutex::new(Vec::new()),
        finalize_calls: Mutex::new(Vec::new()),
    });
    let api = base.with_runtime_maintenance(maintenance.clone());
    let session_id = digest('3');
    let NodePrivateResponse::UninstallBegan(receipt) = api
        .dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::Begin {
                session_id: session_id.clone(),
                model_retention: NodeRuntimeModelRetention::Remove,
            }),
        )
        .expect("child begin")
    else {
        panic!("child begin response");
    };
    assert_eq!(receipt.inventory().local_role(), NodeRole::Child);
    assert!(receipt.inventory().active_benchmark_id().is_none());
    assert!(receipt
        .inventory()
        .exposure_configuration_sha256()
        .is_none());
    assert!(receipt.inventory().model_targets().is_empty());
    assert_eq!(
        receipt.inventory().runtime_installation_ids(),
        &[installation_id.clone()]
    );
    assert!(matches!(
        api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::RemoveRuntimeInstallation {
                session_id: session_id.clone(),
                installation_id,
                model_retention: NodeRuntimeModelRetention::Remove,
            }),
        ),
        Ok(NodePrivateResponse::RuntimeInstallationRemoved(_))
    ));
    assert!(matches!(
        api.dispatch_local(
            manager.local_node_id(),
            NodePrivateRequest::Uninstall(NodeUninstallRequest::FinalizeRuntimeArtifacts {
                session_id,
                model_retention: NodeRuntimeModelRetention::Remove,
            }),
        ),
        Ok(NodePrivateResponse::RuntimeArtifactsFinalized(receipt))
            if receipt.model_retention() == NodeRuntimeModelRetention::Remove
    ));
}
