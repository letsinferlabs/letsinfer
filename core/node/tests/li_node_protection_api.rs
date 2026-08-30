// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use li_core_interface::{
    BootId, CredentialId, InstallationId, NodeId, PlacementGroupId, PlacementId, Sha256Digest,
    TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_gateway_manager::{GatewayError, GatewayPlacementProtectionSnapshot};
use li_node_manager::{
    DatabaseNodeProtectionSessionGenerationStore, NodeProtectionAction, NodeProtectionApi,
    NodeProtectionApiError, NodeProtectionAuthorizationProvider, NodeProtectionBeginRequest,
    NodeProtectionBindingProvider, NodeProtectionClock, NodeProtectionCommitRequest,
    NodeProtectionConnection, NodeProtectionConnectionRole,
    NodeProtectionControllerBindingProvider, NodeProtectionEndRequest, NodeProtectionLeaseBinding,
    NodeProtectionLeaseError, NodeProtectionLeaseStore, NodeProtectionLocalClient,
    NodeProtectionLocalClientConfiguration, NodeProtectionLocalConfiguration,
    NodeProtectionLocalError, NodeProtectionLocalServer, NodeProtectionPeerAuthorization,
    NodeProtectionPeerRoleError, NodeProtectionPeerRoleProvider,
    NodeProtectionReadSiteStatusRequest, NodeProtectionRequest,
    NodeProtectionResolveControllerBindingRequest, NodeProtectionResponse,
    NodeProtectionSiteStatusProvider, NodeProtectionSnapshotProvider,
    NodeProtectionSnapshotRequest, NodeProtectionTransport, NodeProtectionTransportRequest,
};
use li_placement_manager::{
    LinuxProtectedProcessIdentity, PlacementProtectedTarget, PlacementProtectionGeneration,
    PlacementProtectionPhase,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogProtectedEngine, WatchdogProtectionCycle,
    WatchdogProtocolSiteStatus,
};
use tempfile::TempDir;

// Supplies deterministic database commit time.
struct DatabaseClockMock;

impl DatabaseClock for DatabaseClockMock {
    // Returns one fixed valid commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(1_000)
    }
}

// Supplies deterministic Node connection time.
struct NodeClockMock;

impl NodeProtectionClock for NodeClockMock {
    // Returns a time immediately before the completed cycle fixture.
    fn now(&self) -> Result<UnixMilliseconds, NodeProtectionApiError> {
        Ok(UnixMilliseconds::new(900))
    }
}

// Assigns the first native test connection to Watchdog and the second to Gateway.
struct PeerRoleMock(AtomicU64);

impl NodeProtectionPeerRoleProvider for PeerRoleMock {
    // Assigns a role before the connection's first request is decoded.
    fn authorize(
        &self,
        _user_id: u32,
        _process_id: u32,
    ) -> Result<NodeProtectionPeerAuthorization, NodeProtectionPeerRoleError> {
        let role = match self.0.fetch_add(1, Ordering::AcqRel) {
            0 => NodeProtectionConnectionRole::Watchdog,
            1 => NodeProtectionConnectionRole::Gateway,
            _ => return Err(NodeProtectionPeerRoleError::AuthenticationFailed),
        };
        Ok(NodeProtectionPeerAuthorization::new(principal_id(), role))
    }
}

// Authorizes one exact fixture principal and records authorization ordering.
struct AuthorizationMock {
    principal_id: CredentialId,
    actions: Mutex<Vec<NodeProtectionAction>>,
}

impl NodeProtectionAuthorizationProvider for AuthorizationMock {
    // Records the action and rejects every foreign principal before dispatch.
    fn authorize(
        &self,
        principal_id: &CredentialId,
        action: NodeProtectionAction,
        _node_id: &NodeId,
    ) -> Result<(), NodeProtectionApiError> {
        self.actions.lock().expect("actions").push(action);
        if principal_id != &self.principal_id {
            return Err(NodeProtectionApiError::AuthorizationDenied);
        }
        Ok(())
    }
}

// Resolves one completed cycle to one exact current placement binding.
struct BindingMock;

impl NodeProtectionBindingProvider for BindingMock {
    // Returns the one exact process identity present in every complete cycle fixture.
    fn bindings_for_cycle(
        &self,
        node_id: &NodeId,
        _cycle: &WatchdogProtectionCycle,
    ) -> Result<Vec<NodeProtectionLeaseBinding>, NodeProtectionLeaseError> {
        Ok(vec![NodeProtectionLeaseBinding::new(
            node_id.clone(),
            group_id(),
            placement_id(),
            placement_target(),
        )])
    }
}

// Projects the shared ephemeral lease store for one exact placement group.
struct SnapshotMock {
    leases: Arc<NodeProtectionLeaseStore>,
}

impl NodeProtectionSnapshotProvider for SnapshotMock {
    // Returns the current exact snapshot without fabricating missing lease state.
    fn snapshot_for_group(
        &self,
        placement_group_id: &PlacementGroupId,
        _endpoint_node_id: &NodeId,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        self.leases
            .placement_group_snapshot(placement_group_id, &[(placement_id(), node_id())])
            .map_err(|_| GatewayError::StateUnavailable)
    }
}

// Resolves one exact controller binding or returns the configured stable API failure.
struct ControllerBindingMock {
    failed: AtomicBool,
    calls: AtomicU64,
}

impl NodeProtectionControllerBindingProvider for ControllerBindingMock {
    // Records each read and preserves a meaningful authorization failure without provider detail.
    fn resolve(
        &self,
        certificate_sha256: &Sha256Digest,
    ) -> Result<WatchdogControllerBinding, NodeProtectionApiError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            return Err(NodeProtectionApiError::AuthorizationDenied);
        }
        if certificate_sha256 != &digest('d') {
            return Err(NodeProtectionApiError::Conflict);
        }
        Ok(controller_binding())
    }
}

// Revalidates one exact binding or returns the configured stable API failure.
struct SiteStatusMock {
    failed: AtomicBool,
    calls: AtomicU64,
}

impl NodeProtectionSiteStatusProvider for SiteStatusMock {
    // Records each read and preserves provider availability without disclosing state.
    fn status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, NodeProtectionApiError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            return Err(NodeProtectionApiError::ProviderUnavailable);
        }
        if binding != &controller_binding() {
            return Err(NodeProtectionApiError::Conflict);
        }
        Ok(site_status())
    }
}

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical Node identity.
fn node_id() -> NodeId {
    NodeId::parse(&identity('1', 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn group_id() -> PlacementGroupId {
    PlacementGroupId::parse(&identity('2', 32)).expect("group")
}

// Returns one canonical placement identity.
fn placement_id() -> PlacementId {
    PlacementId::parse(&identity('3', 32)).expect("placement")
}

// Returns one canonical Core installation identity.
fn installation_id() -> InstallationId {
    InstallationId::parse(&identity('4', 64)).expect("installation")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one exact process-bound controller identity for Watchdog protocol reads.
fn controller_binding() -> WatchdogControllerBinding {
    WatchdogControllerBinding::new(
        &identity('c', 32),
        &identity('d', 64),
        7,
        WatchdogProtectedEngine::parse(&descriptor()).expect("protected engine"),
    )
    .expect("controller binding")
}

// Returns one complete public status projection without private placement state.
fn site_status() -> WatchdogProtocolSiteStatus {
    WatchdogProtocolSiteStatus::new(
        "0.11.0-rc.114".to_string(),
        "model".to_string(),
        "engine".to_string(),
        "runtime".to_string(),
        "1.0.0".to_string(),
        identity('e', 64),
        "persistent".to_string(),
        true,
        9_770,
        64,
        8,
        32_768,
        "running".to_string(),
        "running".to_string(),
        "armed".to_string(),
        true,
        false,
        "li_engine".to_string(),
        identity('f', 64),
    )
    .expect("site status")
}

// Returns the authorized fixture principal.
fn principal_id() -> CredentialId {
    CredentialId::parse(&identity('5', 32)).expect("principal")
}

// Returns one canonical armed Watchdog descriptor.
fn descriptor() -> String {
    format!(
        "version=1\ngeneration={}\nphase=armed\ncontainer_name=li_engine\ncontainer_id={}\npid=1234\nstart_ticks=5678\nboot_id=12345678-1234-1234-1234-123456789abc\ncgroup=/sys/fs/cgroup/user.slice/li_engine\n",
        identity('6', 32),
        identity('7', 64),
    )
}

// Returns one authenticated complete cycle report.
fn cycle(sequence: u64) -> WatchdogProtectionCycle {
    WatchdogProtectionCycle::from_authenticated_report(
        sequence,
        1_000 + sequence,
        sequence,
        vec![WatchdogProtectedEngine::parse(&descriptor()).expect("descriptor")],
    )
    .expect("cycle")
}

// Returns the Placement-owned target matching the Watchdog descriptor.
fn placement_target() -> PlacementProtectedTarget {
    PlacementProtectedTarget::new(
        PlacementProtectionGeneration::parse(&identity('6', 32)).expect("generation"),
        PlacementProtectionPhase::Armed,
        LinuxProtectedProcessIdentity::new(
            TechnicalName::parse("li_engine").expect("container"),
            digest('7'),
            1234,
            5678,
            BootId::parse("12345678-1234-1234-1234-123456789abc").expect("boot"),
            "/sys/fs/cgroup/user.slice/li_engine",
        )
        .expect("process"),
    )
    .expect("target")
}

// Opens one real shared DatabaseManager.
fn database(root: &TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(root.path().join("li_core.db"))
                .with_clock(Arc::new(DatabaseClockMock)),
        )
        .expect("database"),
    )
}

// Creates one complete Node protection API before optional Watchdog protocol composition.
fn unshared_api(
    database: Arc<DatabaseManager>,
) -> (
    NodeProtectionApi,
    Arc<NodeProtectionLeaseStore>,
    Arc<AuthorizationMock>,
) {
    let leases = Arc::new(NodeProtectionLeaseStore::new());
    let snapshots = Arc::new(SnapshotMock {
        leases: leases.clone(),
    });
    let authorization = Arc::new(AuthorizationMock {
        principal_id: principal_id(),
        actions: Mutex::new(Vec::new()),
    });
    let api = NodeProtectionApi::new(
        node_id(),
        installation_id(),
        digest('8'),
        authorization.clone(),
        Arc::new(NodeClockMock),
        Arc::new(DatabaseNodeProtectionSessionGenerationStore::new(database)),
        leases.clone(),
        Arc::new(BindingMock),
        snapshots,
        1_000,
    )
    .expect("API");
    (api, leases, authorization)
}

// Creates one complete Node protection API and returns its shared lease store.
fn api(database: Arc<DatabaseManager>) -> (Arc<NodeProtectionApi>, Arc<NodeProtectionLeaseStore>) {
    let (api, leases, _) = unshared_api(database);
    (Arc::new(api), leases)
}

// Adds only the narrow Watchdog protocol providers to one ordinary protection API.
fn api_with_watchdog_protocol(
    database: Arc<DatabaseManager>,
) -> (
    Arc<NodeProtectionApi>,
    Arc<ControllerBindingMock>,
    Arc<SiteStatusMock>,
    Arc<AuthorizationMock>,
) {
    let sessions = Arc::new(ControllerBindingMock {
        failed: AtomicBool::new(false),
        calls: AtomicU64::new(0),
    });
    let status = Arc::new(SiteStatusMock {
        failed: AtomicBool::new(false),
        calls: AtomicU64::new(0),
    });
    let (api, _, authorization) = unshared_api(database);
    (
        Arc::new(api.with_watchdog_protocol(sessions.clone(), status.clone())),
        sessions,
        status,
        authorization,
    )
}

// Returns one exact begin request.
fn begin_request(idempotency_key: &str, nonce: char) -> NodeProtectionRequest {
    NodeProtectionRequest::BeginWatchdogSession(
        NodeProtectionBeginRequest::new(
            idempotency_key,
            node_id(),
            installation_id(),
            digest('8'),
            digest(nonce),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("begin"),
    )
}

// Encodes one exact connection-bound protection request for state-machine tests.
fn connection_document(
    request_id: char,
    connection_id: &Sha256Digest,
    request: NodeProtectionRequest,
) -> Vec<u8> {
    NodeProtectionTransport::encode_request(&NodeProtectionTransportRequest::new(
        digest(request_id),
        connection_id.clone(),
        request,
    ))
    .expect("document")
}

// Proves authenticated begin, complete-cycle commit, snapshot, and disconnect close the loop.
#[test]
fn authenticated_lifecycle_opens_only_after_fresh_cycle_and_closes_on_end() {
    let root = TempDir::new().expect("temporary directory");
    let (api, _) = api(database(&root));
    let authority = match api
        .dispatch(&principal_id(), begin_request("begin", '9'))
        .expect("begin")
    {
        NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
        _ => panic!("unexpected begin response"),
    };
    let snapshot_request = NodeProtectionRequest::ReadGatewaySnapshot(
        NodeProtectionSnapshotRequest::new(node_id(), group_id(), node_id()),
    );
    assert!(matches!(
        api.dispatch(&principal_id(), snapshot_request.clone())
            .expect("snapshot"),
        NodeProtectionResponse::GatewaySnapshot(Some(snapshot)) if snapshot.leases().is_empty()
    ));

    let committed = api
        .dispatch(
            &principal_id(),
            NodeProtectionRequest::CommitWatchdogCycle(NodeProtectionCommitRequest::new(
                node_id(),
                authority.watchdog_session_id().clone(),
                authority.watchdog_session_generation(),
                cycle(1),
            )),
        )
        .expect("commit");
    assert_eq!(
        committed,
        NodeProtectionResponse::WatchdogCycleCommitted { lease_count: 1 }
    );
    assert!(matches!(
        api.dispatch(&principal_id(), snapshot_request.clone())
            .expect("snapshot"),
        NodeProtectionResponse::GatewaySnapshot(Some(snapshot)) if snapshot.leases().len() == 1
    ));

    api.dispatch(
        &principal_id(),
        NodeProtectionRequest::EndWatchdogSession(NodeProtectionEndRequest::new(
            node_id(),
            authority.watchdog_session_id().clone(),
            authority.watchdog_session_generation(),
        )),
    )
    .expect("end");
    assert!(matches!(
        api.dispatch(&principal_id(), snapshot_request)
            .expect("snapshot"),
        NodeProtectionResponse::GatewaySnapshot(None)
    ));
}

// Proves duplicate begin is idempotent while a foreign principal cannot allocate generation.
#[test]
fn begin_is_idempotent_and_authorization_precedes_persistence() {
    let root = TempDir::new().expect("temporary directory");
    let (api, _) = api(database(&root));
    assert_eq!(
        api.dispatch(
            &CredentialId::parse(&identity('a', 32)).expect("foreign"),
            begin_request("denied", '9')
        ),
        Err(NodeProtectionApiError::AuthorizationDenied)
    );
    let first = api
        .dispatch(&principal_id(), begin_request("begin", '9'))
        .expect("begin");
    let replay = api
        .dispatch(&principal_id(), begin_request("begin", '9'))
        .expect("replay");

    assert_eq!(first, replay);
    assert!(matches!(
        first,
        NodeProtectionResponse::WatchdogSessionBegan(authority)
            if authority.watchdog_session_generation().get() == 1
    ));
}

// Replays both Watchdog protocol reads and preserves authorization, conflict, and provider errors.
#[test]
fn watchdog_protocol_reads_are_exact_replayable_and_redacted() {
    let root = TempDir::new().expect("temporary directory");
    let (protocol_api, sessions, status, authorization) =
        api_with_watchdog_protocol(database(&root));
    let resolve = NodeProtectionRequest::ResolveControllerBinding(
        NodeProtectionResolveControllerBindingRequest::new(digest('d')),
    );
    let expected_binding = NodeProtectionResponse::ControllerBinding(controller_binding());
    assert_eq!(
        protocol_api
            .dispatch(&principal_id(), resolve.clone())
            .expect("resolve"),
        expected_binding
    );
    assert_eq!(
        protocol_api
            .dispatch(&principal_id(), resolve)
            .expect("replay resolve"),
        expected_binding
    );
    let read = NodeProtectionRequest::ReadSiteStatus(NodeProtectionReadSiteStatusRequest::new(
        controller_binding(),
    ));
    let expected_status = NodeProtectionResponse::SiteStatus(site_status());
    assert_eq!(
        protocol_api
            .dispatch(&principal_id(), read.clone())
            .expect("status"),
        expected_status
    );
    assert_eq!(
        protocol_api
            .dispatch(&principal_id(), read)
            .expect("replay status"),
        expected_status
    );
    assert_eq!(sessions.calls.load(Ordering::Acquire), 2);
    assert_eq!(status.calls.load(Ordering::Acquire), 2);
    assert_eq!(
        *authorization.actions.lock().expect("actions"),
        vec![
            NodeProtectionAction::ResolveControllerBinding,
            NodeProtectionAction::ResolveControllerBinding,
            NodeProtectionAction::ReadSiteStatus,
            NodeProtectionAction::ReadSiteStatus,
        ]
    );

    assert_eq!(
        protocol_api.dispatch(
            &principal_id(),
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('e')),
            ),
        ),
        Err(NodeProtectionApiError::Conflict)
    );
    sessions.failed.store(true, Ordering::Release);
    assert_eq!(
        protocol_api.dispatch(
            &principal_id(),
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('d')),
            ),
        ),
        Err(NodeProtectionApiError::AuthorizationDenied)
    );
    status.failed.store(true, Ordering::Release);
    assert_eq!(
        protocol_api.dispatch(
            &principal_id(),
            NodeProtectionRequest::ReadSiteStatus(NodeProtectionReadSiteStatusRequest::new(
                controller_binding(),
            )),
        ),
        Err(NodeProtectionApiError::ProviderUnavailable)
    );
    let session_calls = sessions.calls.load(Ordering::Acquire);
    assert_eq!(
        protocol_api.dispatch(
            &CredentialId::parse(&identity('a', 32)).expect("foreign principal"),
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('d')),
            ),
        ),
        Err(NodeProtectionApiError::AuthorizationDenied)
    );
    assert_eq!(sessions.calls.load(Ordering::Acquire), session_calls);

    let (uncomposed, _) = api(database(&root));
    assert_eq!(
        uncomposed.dispatch(
            &principal_id(),
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('d')),
            ),
        ),
        Err(NodeProtectionApiError::ProviderUnavailable)
    );
}

// Proves an ended connection cannot reopen from its static begin document or prior authority.
#[test]
fn disconnected_session_replay_stays_closed_until_a_fresh_begin() {
    let root = TempDir::new().expect("temporary directory");
    let (api, _) = api(database(&root));
    let first = match api
        .dispatch(&principal_id(), begin_request("begin-a", '9'))
        .expect("begin")
    {
        NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
        _ => panic!("unexpected begin response"),
    };
    api.dispatch(
        &principal_id(),
        NodeProtectionRequest::EndWatchdogSession(NodeProtectionEndRequest::new(
            node_id(),
            first.watchdog_session_id().clone(),
            first.watchdog_session_generation(),
        )),
    )
    .expect("end");

    assert_eq!(
        api.dispatch(&principal_id(), begin_request("begin-a", '9')),
        Err(NodeProtectionApiError::Conflict)
    );
    let fresh = match api
        .dispatch(&principal_id(), begin_request("begin-b", 'a'))
        .expect("fresh begin")
    {
        NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
        _ => panic!("unexpected begin response"),
    };
    assert_eq!(fresh.watchdog_session_generation().get(), 2);
    assert_ne!(fresh.watchdog_session_id(), first.watchdog_session_id());
}

// Proves native disconnect durably ends Watchdog authority while sibling Gateway reads stay typed.
#[test]
fn authenticated_connection_disconnect_retires_watchdog_and_confines_roles() {
    let root = TempDir::new().expect("temporary directory");
    let (api, sessions, status, _) = api_with_watchdog_protocol(database(&root));
    let connection_id = digest('b');
    let mut watchdog = NodeProtectionConnection::new(
        api.clone(),
        principal_id(),
        connection_id.clone(),
        NodeProtectionConnectionRole::Watchdog,
    );
    let began = watchdog
        .handle(&connection_document(
            'c',
            &connection_id,
            begin_request("begin-connection", '9'),
        ))
        .expect("begin");
    let authority = match NodeProtectionTransport::decode_response(&began)
        .expect("begin response")
        .outcome()
    {
        li_node_manager::NodeProtectionTransportOutcome::Success(
            NodeProtectionResponse::WatchdogSessionBegan(authority),
        ) => authority.clone(),
        _ => panic!("unexpected begin response"),
    };
    let binding = watchdog
        .handle(&connection_document(
            '9',
            &connection_id,
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('d')),
            ),
        ))
        .expect("controller binding");
    assert!(matches!(
        NodeProtectionTransport::decode_response(&binding)
            .expect("binding response")
            .outcome(),
        li_node_manager::NodeProtectionTransportOutcome::Success(
            NodeProtectionResponse::ControllerBinding(observed)
        ) if observed == &controller_binding()
    ));
    watchdog
        .handle(&connection_document(
            'd',
            &connection_id,
            NodeProtectionRequest::CommitWatchdogCycle(NodeProtectionCommitRequest::new(
                node_id(),
                authority.watchdog_session_id().clone(),
                authority.watchdog_session_generation(),
                cycle(1),
            )),
        ))
        .expect("commit");
    assert!(watchdog
        .handle(&connection_document(
            'e',
            &connection_id,
            NodeProtectionRequest::ReadGatewaySnapshot(NodeProtectionSnapshotRequest::new(
                node_id(),
                group_id(),
                node_id(),
            )),
        ))
        .is_err());
    watchdog.disconnect().expect("disconnect");
    assert_eq!(
        api.dispatch(&principal_id(), begin_request("begin-connection", '9')),
        Err(NodeProtectionApiError::Conflict)
    );

    let gateway_connection_id = digest('f');
    let mut gateway = NodeProtectionConnection::new(
        api,
        principal_id(),
        gateway_connection_id.clone(),
        NodeProtectionConnectionRole::Gateway,
    );
    gateway
        .handle(&connection_document(
            'a',
            &gateway_connection_id,
            NodeProtectionRequest::ReadGatewaySnapshot(NodeProtectionSnapshotRequest::new(
                node_id(),
                group_id(),
                node_id(),
            )),
        ))
        .expect("Gateway snapshot");
    assert!(gateway
        .handle(&connection_document(
            '9',
            &gateway_connection_id,
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('d')),
            ),
        ))
        .is_err());
    assert_eq!(sessions.calls.load(Ordering::Acquire), 1);
    assert_eq!(status.calls.load(Ordering::Acquire), 0);
    assert!(gateway
        .handle(&connection_document(
            '8',
            &gateway_connection_id,
            NodeProtectionRequest::ReadSiteStatus(NodeProtectionReadSiteStatusRequest::new(
                controller_binding(),
            )),
        ))
        .is_err());
    assert_eq!(sessions.calls.load(Ordering::Acquire), 1);
    assert_eq!(status.calls.load(Ordering::Acquire), 0);
    assert!(gateway
        .handle(&connection_document(
            'b',
            &gateway_connection_id,
            begin_request("cross-role", 'a'),
        ))
        .is_err());
}

// Classifies an absent local endpoint as unavailable without accepting an unsafe socket.
#[test]
fn native_local_client_classifies_missing_socket_as_unavailable() {
    let root = TempDir::new().expect("temporary directory");
    let configuration = NodeProtectionLocalClientConfiguration::new(
        root.path().join("missing-node-protection.sock"),
        unsafe { libc::geteuid() },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("client configuration");

    assert!(matches!(
        NodeProtectionLocalClient::connect(&configuration, digest('a')),
        Err(NodeProtectionLocalError::EndpointUnavailable)
    ));
}

// Proves real owner-authenticated IPC opens after one cycle and closes on stream loss.
#[test]
fn native_local_ipc_disconnect_invalidates_gateway_snapshot() {
    let root = TempDir::new().expect("temporary directory");
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("permissions");
    let (api, _) = api(database(&root));
    let configuration = NodeProtectionLocalConfiguration::new(
        root.path()
            .canonicalize()
            .expect("canonical temporary directory")
            .join("li_node_protection.sock"),
        unsafe { libc::geteuid() },
        4,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(5),
    )
    .expect("configuration");
    let mut server = NodeProtectionLocalServer::start(
        configuration.clone(),
        api,
        Arc::new(PeerRoleMock(AtomicU64::new(0))),
    )
    .expect("server");
    let watchdog =
        NodeProtectionLocalClient::connect(&configuration.client_configuration(), digest('b'))
            .expect("Watchdog client");
    let authority = match watchdog
        .exchange(begin_request("native-begin", '9'))
        .expect("begin")
    {
        NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
        _ => panic!("unexpected begin response"),
    };
    let commit = watchdog.exchange(NodeProtectionRequest::CommitWatchdogCycle(
        NodeProtectionCommitRequest::new(
            node_id(),
            authority.watchdog_session_id().clone(),
            authority.watchdog_session_generation(),
            cycle(1),
        ),
    ));
    if let Err(error) = commit {
        for _ in 0..20 {
            if server.connection_failure().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!(
            "commit failed: {error:?}; server failure: {:?}",
            server.connection_failure()
        );
    }
    let gateway =
        NodeProtectionLocalClient::connect(&configuration.client_configuration(), digest('c'))
            .expect("Gateway client");
    let snapshot_request = NodeProtectionRequest::ReadGatewaySnapshot(
        NodeProtectionSnapshotRequest::new(node_id(), group_id(), node_id()),
    );
    assert!(matches!(
        gateway.exchange(snapshot_request.clone()).expect("snapshot"),
        NodeProtectionResponse::GatewaySnapshot(Some(snapshot)) if snapshot.leases().len() == 1
    ));

    drop(watchdog);
    let mut closed = false;
    for _ in 0..20 {
        if matches!(
            gateway
                .exchange(snapshot_request.clone())
                .expect("snapshot"),
            NodeProtectionResponse::GatewaySnapshot(None)
        ) {
            closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        closed,
        "Watchdog disconnect must invalidate the Node snapshot"
    );
    drop(gateway);
    server.join().expect("server join");
}

// Proves concurrent distinct Watchdog residents have exactly one active begin winner.
#[test]
fn concurrent_distinct_begins_have_one_winner() {
    let root = TempDir::new().expect("temporary directory");
    let (api, _) = api(database(&root));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (idempotency_key, nonce) in [("begin-a", '9'), ("begin-b", 'a')] {
        let api = api.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            api.dispatch(&principal_id(), begin_request(idempotency_key, nonce))
        }));
    }
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(NodeProtectionApiError::Conflict))
            .count(),
        1
    );
}

// Proves Node restart uses durable generation but remains closed until a fresh completed cycle.
#[test]
fn node_restart_advances_generation_and_requires_fresh_cycle() {
    let root = TempDir::new().expect("temporary directory");
    let database = database(&root);
    let (first_api, _) = api(database.clone());
    let first = match first_api
        .dispatch(&principal_id(), begin_request("begin-a", '9'))
        .expect("first begin")
    {
        NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
        _ => panic!("unexpected response"),
    };
    drop(first_api);

    let (restarted_api, _) = api(database);
    let restarted = match restarted_api
        .dispatch(&principal_id(), begin_request("begin-b", 'a'))
        .expect("restart begin")
    {
        NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
        _ => panic!("unexpected response"),
    };
    assert_eq!(first.watchdog_session_generation().get(), 1);
    assert_eq!(restarted.watchdog_session_generation().get(), 2);
    assert_ne!(first.watchdog_session_id(), restarted.watchdog_session_id());
    assert!(matches!(
        restarted_api
            .dispatch(
                &principal_id(),
                NodeProtectionRequest::ReadGatewaySnapshot(
                    NodeProtectionSnapshotRequest::new(node_id(), group_id(), node_id())
                )
            )
            .expect("snapshot"),
        NodeProtectionResponse::GatewaySnapshot(Some(snapshot)) if snapshot.leases().is_empty()
    ));
}
