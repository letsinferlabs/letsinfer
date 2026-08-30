// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::{
    CredentialId, DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress,
    NodeId, NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    read_node_private_local_frame, write_node_private_local_frame,
    ExactNodePrivateLocalPeerIdentity, NodeManager, NodePairingApiError, NodePairingApiPort,
    NodePairingApproveRequest, NodePairingEnrollRequest, NodePairingEnrollment,
    NodePairingInvitation, NodePairingOpenRequest, NodePairingStatus, NodePrivateAction,
    NodePrivateApi, NodePrivateApiError, NodePrivateAuthorizationProvider,
    NodePrivateLocalConnectionError, NodePrivateLocalConnectionHandler,
    NodePrivateLocalDocumentEndpoint, NodePrivateLocalDocumentError, NodePrivateLocalEndpoint,
    NodePrivateLocalFrameError, NodePrivateLocalIoError, NodePrivateLocalListener,
    NodePrivateLocalServer, NodePrivateLocalServerConfiguration, NodePrivateLocalServerError,
    NodePrivateLocalSocketProvider, NodePrivateLocalStream, NodePrivateRequest,
    NodePrivateResponse, NodePrivateTransport, NodePrivateTransportError,
    NodePrivateTransportOutcome, NodePrivateTransportRequest, SystemNodePrivateLocalSocketProvider,
    NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Retains explicit stream fragments, failures, timeout settings, and close state.
struct MockStream {
    peer_uid: u32,
    peer_failure: bool,
    input: Vec<u8>,
    input_offset: usize,
    maximum_read: usize,
    read_failure: Option<NodePrivateLocalIoError>,
    always_interrupted_read: bool,
    output: Vec<u8>,
    maximum_write: usize,
    write_failure: Option<NodePrivateLocalIoError>,
    zero_write: bool,
    timeout_failure: bool,
    closed: Arc<AtomicBool>,
}

impl MockStream {
    // Creates one deterministic readable and writable local stream.
    fn new(peer_uid: u32, input: Vec<u8>) -> Self {
        Self {
            peer_uid,
            peer_failure: false,
            input,
            input_offset: 0,
            maximum_read: usize::MAX,
            read_failure: None,
            always_interrupted_read: false,
            output: Vec::new(),
            maximum_write: usize::MAX,
            write_failure: None,
            zero_write: false,
            timeout_failure: false,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl NodePrivateLocalStream for MockStream {
    // Returns the configured kernel-peer identity or its redacted failure.
    fn peer_uid(&self) -> Result<u32, NodePrivateLocalIoError> {
        if self.peer_failure {
            Err(NodePrivateLocalIoError::Unavailable)
        } else {
            Ok(self.peer_uid)
        }
    }

    // Accepts the requested read timeout unless configuration was rejected.
    fn set_read_timeout(&self, _timeout: Duration) -> Result<(), NodePrivateLocalIoError> {
        if self.timeout_failure {
            Err(NodePrivateLocalIoError::Unavailable)
        } else {
            Ok(())
        }
    }

    // Accepts the requested write timeout unless configuration was rejected.
    fn set_write_timeout(&self, _timeout: Duration) -> Result<(), NodePrivateLocalIoError> {
        if self.timeout_failure {
            Err(NodePrivateLocalIoError::Unavailable)
        } else {
            Ok(())
        }
    }

    // Returns at most the configured fragment from deterministic input.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateLocalIoError> {
        if self.always_interrupted_read {
            thread::yield_now();
            return Err(NodePrivateLocalIoError::Interrupted);
        }
        if let Some(error) = self.read_failure.take() {
            return Err(error);
        }
        let remaining = &self.input[self.input_offset..];
        let count = remaining.len().min(buffer.len()).min(self.maximum_read);
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.input_offset += count;
        Ok(count)
    }

    // Retains at most the configured write fragment or returns zero progress.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateLocalIoError> {
        if let Some(error) = self.write_failure.take() {
            return Err(error);
        }
        if self.zero_write {
            return Ok(0);
        }
        let count = buffer.len().min(self.maximum_write);
        self.output.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    // Records the exact connection close boundary.
    fn close(&mut self) -> Result<(), NodePrivateLocalIoError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// Supplies deterministic accepted streams to one injected listener.
struct QueueListener {
    streams: Mutex<VecDeque<Box<dyn NodePrivateLocalStream>>>,
}

impl NodePrivateLocalListener for QueueListener {
    // Returns the next deterministic stream or one empty nonblocking poll.
    fn accept(
        &self,
    ) -> Result<Option<Box<dyn NodePrivateLocalStream>>, NodePrivateLocalServerError> {
        Ok(self.streams.lock().expect("streams").pop_front())
    }
}

// Returns one injected listener without acquiring a native socket.
struct QueueSocketProvider {
    listener: Arc<QueueListener>,
}

impl NodePrivateLocalSocketProvider for QueueSocketProvider {
    // Returns the retained deterministic listener for one server lifecycle.
    fn bind(
        &self,
        _configuration: &NodePrivateLocalServerConfiguration,
    ) -> Result<Arc<dyn NodePrivateLocalListener>, NodePrivateLocalServerError> {
        Ok(self.listener.clone())
    }
}

// Holds the first worker until the test releases its deterministic endpoint call.
struct BlockingEndpoint {
    started: AtomicBool,
    released: AtomicBool,
    calls: AtomicUsize,
}

impl BlockingEndpoint {
    // Creates one initially blocked endpoint.
    fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            released: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
}

impl NodePrivateLocalDocumentEndpoint for BlockingEndpoint {
    // Blocks the first authorized call until explicitly released by the test.
    fn handle_document(
        &self,
        _local_node_id: &NodeId,
        _document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateLocalDocumentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.store(true, Ordering::SeqCst);
        while !self.released.load(Ordering::SeqCst) {
            thread::yield_now();
        }
        Ok(b"response".to_vec())
    }
}

// Records the exact local Node identity and document delivered by the handler.
struct MockEndpoint {
    calls: Mutex<Vec<(NodeId, Vec<u8>)>>,
    response: Result<Vec<u8>, NodePrivateLocalDocumentError>,
}

impl MockEndpoint {
    // Creates one endpoint with a fixed deterministic result.
    fn new(response: Result<Vec<u8>, NodePrivateLocalDocumentError>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response,
        }
    }
}

impl NodePrivateLocalDocumentEndpoint for MockEndpoint {
    // Records the authorized identity and returns the fixed endpoint result.
    fn handle_document(
        &self,
        local_node_id: &NodeId,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateLocalDocumentError> {
        self.calls
            .lock()
            .expect("endpoint calls")
            .push((local_node_id.clone(), document.to_vec()));
        self.response.clone()
    }
}

// Authorizes remote API construction while local dispatch uses its separate identity gate.
struct AllowAuthorization;

impl NodePrivateAuthorizationProvider for AllowAuthorization {
    // Allows one remote action when a test directly exercises that separate path.
    fn authorize(
        &self,
        _principal_id: &CredentialId,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        Ok(())
    }
}

// Rejects pairing because these listener contracts exercise existing non-pairing actions.
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

// Adapts one client-side Unix stream to the public frame helpers.
struct ClientUnixStream(UnixStream);

impl NodePrivateLocalStream for ClientUnixStream {
    // Returns the effective user identity for the unused client-side peer capability.
    fn peer_uid(&self) -> Result<u32, NodePrivateLocalIoError> {
        Ok(unsafe { libc::geteuid() })
    }

    // Applies the complete client-side response-read timeout.
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), NodePrivateLocalIoError> {
        self.0
            .set_read_timeout(Some(timeout))
            .map_err(|_| NodePrivateLocalIoError::Unavailable)
    }

    // Applies the complete client-side request-write timeout.
    fn set_write_timeout(&self, timeout: Duration) -> Result<(), NodePrivateLocalIoError> {
        self.0
            .set_write_timeout(Some(timeout))
            .map_err(|_| NodePrivateLocalIoError::Unavailable)
    }

    // Reads one client-side response fragment.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateLocalIoError> {
        self.0.read(buffer).map_err(|error| client_io_error(&error))
    }

    // Writes one client-side request fragment.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateLocalIoError> {
        self.0
            .write(buffer)
            .map_err(|error| client_io_error(&error))
    }

    // Closes both directions of the client-side connection.
    fn close(&mut self) -> Result<(), NodePrivateLocalIoError> {
        self.0
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| NodePrivateLocalIoError::Unavailable)
    }
}

// Maps client-side timeout observations into the same closed frame error domain.
fn client_io_error(error: &std::io::Error) -> NodePrivateLocalIoError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            NodePrivateLocalIoError::TimedOut
        }
        std::io::ErrorKind::Interrupted => NodePrivateLocalIoError::Interrupted,
        _ => NodePrivateLocalIoError::Unavailable,
    }
}

// Returns one fixed-header frame for the supplied document.
fn frame(document: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + document.len());
    frame.extend_from_slice(&(document.len() as u32).to_be_bytes());
    frame.extend_from_slice(document);
    frame
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns the ordinary active local main fixture.
fn main_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1', 32)).expect("node"),
            MachineId::parse(&identity('2', 32)).expect("machine"),
            InstallationId::parse(&identity('3', 64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Opens one isolated manager with deterministic native time.
fn manager(directory: &tempfile::TempDir) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(database, main_node(), "initialize-node")
            .expect("manager")
            .0,
    )
}

// Returns one exact private request correlation identity.
fn request_id() -> Sha256Digest {
    Sha256Digest::parse(&identity('b', 64)).expect("request identity")
}

// Encodes one ordinary local-node request through the existing wire codec.
fn request_document() -> Vec<u8> {
    NodePrivateTransport::encode_request(&NodePrivateTransportRequest::new(
        request_id(),
        NodePrivateRequest::ReadLocalNode,
    ))
    .expect("request document")
}

// Makes one temporary socket parent satisfy the owner-only native contract.
fn protect_socket_parent(directory: &tempfile::TempDir) {
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("protect socket parent");
}

// Builds one real local server over the existing private API and codec.
fn system_server(
    directory: &tempfile::TempDir,
    socket_path: &Path,
    maximum_workers: usize,
) -> NodePrivateLocalServer {
    let manager = manager(directory);
    let local_node_id = manager.local_node_id().clone();
    let api = Arc::new(NodePrivateApi::new(
        manager,
        Arc::new(AllowAuthorization),
        Arc::new(UnavailablePairing),
    ));
    let endpoint = Arc::new(NodePrivateLocalEndpoint::new(api));
    let peer_identity = Arc::new(ExactNodePrivateLocalPeerIdentity::new(
        unsafe { libc::geteuid() },
        local_node_id,
    ));
    let configuration = NodePrivateLocalServerConfiguration::new(
        socket_path.to_path_buf(),
        unsafe { libc::geteuid() },
        maximum_workers,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_millis(2),
    )
    .expect("configuration");
    NodePrivateLocalServer::new(
        configuration,
        endpoint,
        peer_identity,
        Arc::new(SystemNodePrivateLocalSocketProvider),
    )
}

// Exchanges one complete framed request over a real Unix stream.
fn exchange(socket_path: &Path, document: &[u8]) -> Result<Vec<u8>, NodePrivateLocalFrameError> {
    let stream = UnixStream::connect(socket_path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("write timeout");
    let mut stream = ClientUnixStream(stream);
    write_node_private_local_frame(&mut stream, document)?;
    read_node_private_local_frame(&mut stream)
}

// Waits for one bounded concurrent lifecycle observation.
fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    assert!(condition(), "bounded condition");
}

// Proves the fixed big-endian frame across fragmentation and closed failure boundaries.
#[test]
fn frame_contract_handles_fragmentation_and_closed_failures() {
    let document = br#"{"request":"ordinary"}"#;
    let mut reader = MockStream::new(7, frame(document));
    reader.maximum_read = 1;
    assert_eq!(
        read_node_private_local_frame(&mut reader).expect("fragmented read"),
        document
    );

    let mut writer = MockStream::new(7, Vec::new());
    writer.maximum_write = 2;
    write_node_private_local_frame(&mut writer, document).expect("fragmented write");
    assert_eq!(writer.output, frame(document));

    let failures = [
        (vec![0, 0, 0], NodePrivateLocalFrameError::Truncated),
        (
            vec![0, 0, 0, 2, b'{'],
            NodePrivateLocalFrameError::Truncated,
        ),
        (
            [0_u8; 4].to_vec(),
            NodePrivateLocalFrameError::EmptyDocument,
        ),
        (
            ((NODE_PRIVATE_MAX_DOCUMENT_BYTES + 1) as u32)
                .to_be_bytes()
                .to_vec(),
            NodePrivateLocalFrameError::OversizedDocument,
        ),
    ];
    for (input, expected) in failures {
        assert_eq!(
            read_node_private_local_frame(&mut MockStream::new(7, input)),
            Err(expected)
        );
    }

    let mut timed_out = MockStream::new(7, frame(document));
    timed_out.read_failure = Some(NodePrivateLocalIoError::TimedOut);
    assert_eq!(
        read_node_private_local_frame(&mut timed_out),
        Err(NodePrivateLocalFrameError::TimedOut)
    );
    let mut zero_progress = MockStream::new(7, Vec::new());
    zero_progress.zero_write = true;
    assert_eq!(
        write_node_private_local_frame(&mut zero_progress, document),
        Err(NodePrivateLocalFrameError::ZeroProgress)
    );
    let mut write_timeout = MockStream::new(7, Vec::new());
    write_timeout.write_failure = Some(NodePrivateLocalIoError::TimedOut);
    assert_eq!(
        write_node_private_local_frame(&mut write_timeout, document),
        Err(NodePrivateLocalFrameError::TimedOut)
    );
    assert_eq!(
        write_node_private_local_frame(
            &mut MockStream::new(7, Vec::new()),
            &vec![0; NODE_PRIVATE_MAX_DOCUMENT_BYTES + 1],
        ),
        Err(NodePrivateLocalFrameError::OversizedDocument)
    );
}

// Proves exact UID mapping, one-response routing, isolation, and close behavior.
#[test]
fn connection_handler_authorizes_routes_and_isolates_failures() {
    let local_node_id = NodeId::parse(&identity('1', 32)).expect("node");
    let endpoint = Arc::new(MockEndpoint::new(Ok(b"response".to_vec())));
    let handler = NodePrivateLocalConnectionHandler::new(
        endpoint.clone(),
        Arc::new(ExactNodePrivateLocalPeerIdentity::new(
            7,
            local_node_id.clone(),
        )),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let mut stream = MockStream::new(7, frame(b"request"));
    handler.handle(&mut stream).expect("ordinary exchange");
    assert!(stream.closed.load(Ordering::SeqCst));
    assert_eq!(stream.output, frame(b"response"));
    assert_eq!(
        endpoint.calls.lock().expect("calls").as_slice(),
        &[(local_node_id, b"request".to_vec())]
    );

    let mut foreign = MockStream::new(8, frame(b"private-secret"));
    assert_eq!(
        handler.handle(&mut foreign),
        Err(NodePrivateLocalConnectionError::ForeignUser)
    );
    assert!(foreign.closed.load(Ordering::SeqCst));
    assert_eq!(foreign.input_offset, 0);
    assert_eq!(endpoint.calls.lock().expect("calls").len(), 1);

    let rejecting = NodePrivateLocalConnectionHandler::new(
        Arc::new(MockEndpoint::new(Err(
            NodePrivateLocalDocumentError::Rejected,
        ))),
        Arc::new(ExactNodePrivateLocalPeerIdentity::new(
            7,
            NodeId::parse(&identity('1', 32)).expect("node"),
        )),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let mut rejected = MockStream::new(7, frame(b"private-secret"));
    let error = rejecting.handle(&mut rejected).expect_err("rejected");
    assert_eq!(error, NodePrivateLocalConnectionError::EndpointRejected);
    assert!(!error.to_string().contains("private-secret"));
    assert!(rejected.closed.load(Ordering::SeqCst));

    let deadline_handler = NodePrivateLocalConnectionHandler::new(
        endpoint,
        Arc::new(ExactNodePrivateLocalPeerIdentity::new(
            7,
            NodeId::parse(&identity('1', 32)).expect("node"),
        )),
        Duration::from_millis(1),
        Duration::from_secs(1),
    );
    let mut interrupted = MockStream::new(7, frame(b"request"));
    interrupted.always_interrupted_read = true;
    assert_eq!(
        deadline_handler.handle(&mut interrupted),
        Err(NodePrivateLocalConnectionError::Frame(
            NodePrivateLocalFrameError::TimedOut,
        ))
    );
    assert!(interrupted.closed.load(Ordering::SeqCst));
}

// Proves the local endpoint reuses the v1 codec and exact local Node identity gate.
#[test]
fn local_endpoint_uses_existing_codec_and_exact_node_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory);
    let local_node_id = manager.local_node_id().clone();
    let endpoint = NodePrivateLocalEndpoint::new(Arc::new(NodePrivateApi::new(
        manager,
        Arc::new(AllowAuthorization),
        Arc::new(UnavailablePairing),
    )));
    let response = endpoint
        .handle(&local_node_id, &request_document())
        .expect("local endpoint");
    let response = NodePrivateTransport::decode_response(&response).expect("decode response");
    assert_eq!(response.request_id(), &request_id());
    assert!(matches!(
        response.outcome(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(_))
    ));

    assert!(matches!(
        endpoint.handle(&local_node_id, br#"{"secret":"do-not-copy"}"#),
        Err(NodePrivateTransportError::InvalidDocument { .. })
    ));
    let foreign_node_id = NodeId::parse(&identity('9', 32)).expect("foreign node");
    let response = endpoint
        .handle(&foreign_node_id, &request_document())
        .expect("authorization response");
    let response = NodePrivateTransport::decode_response(&response).expect("decode response");
    let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
        panic!("authorization failure");
    };
    assert_eq!(error.code().as_str(), "authorization_denied");
}

// Proves stale replacement, one real exchange, exact cleanup, and same-path restart.
#[test]
fn system_socket_runs_real_exchange_cleans_and_restarts() {
    let directory = tempfile::tempdir().expect("temporary directory");
    protect_socket_parent(&directory);
    let socket_path = fs::canonicalize(directory.path())
        .expect("canonical socket parent")
        .join("node.sock");
    let stale = UnixListener::bind(&socket_path).expect("stale bind");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("stale mode");
    drop(stale);

    let server = system_server(&directory, &socket_path, 2);
    let mut handle = server.start().expect("start");
    let response = exchange(&socket_path, &request_document()).expect("exchange");
    let response = NodePrivateTransport::decode_response(&response).expect("response");
    assert!(matches!(
        response.outcome(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(_))
    ));
    handle.shutdown().expect("shutdown");
    assert!(!socket_path.exists());

    let mut restarted = server.start().expect("restart");
    assert!(restarted.is_running());
    restarted.shutdown().expect("restart shutdown");
    assert!(!socket_path.exists());
}

// Proves one configured worker can never admit a second concurrent exchange.
#[test]
fn bounded_server_enforces_worker_cap_with_injected_listener() {
    let local_node_id = NodeId::parse(&identity('1', 32)).expect("node");
    let first = MockStream::new(7, frame(b"first"));
    let second = MockStream::new(7, frame(b"second"));
    let second_closed = Arc::clone(&second.closed);
    let listener = Arc::new(QueueListener {
        streams: Mutex::new(VecDeque::from([
            Box::new(first) as Box<dyn NodePrivateLocalStream>,
            Box::new(second) as Box<dyn NodePrivateLocalStream>,
        ])),
    });
    let endpoint = Arc::new(BlockingEndpoint::new());
    let configuration = NodePrivateLocalServerConfiguration::new(
        Path::new("/private/tmp/li_node_injected.sock").to_path_buf(),
        7,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(1),
    )
    .expect("configuration");
    let server = NodePrivateLocalServer::new(
        configuration,
        endpoint.clone(),
        Arc::new(ExactNodePrivateLocalPeerIdentity::new(7, local_node_id)),
        Arc::new(QueueSocketProvider { listener }),
    );
    let mut handle = server.start().expect("start");
    wait_until(|| endpoint.started.load(Ordering::SeqCst));
    wait_until(|| handle.active_workers() == 1);
    wait_until(|| second_closed.load(Ordering::SeqCst));
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);
    endpoint.released.store(true, Ordering::SeqCst);
    wait_until(|| handle.active_workers() == 0);
    handle.shutdown().expect("shutdown");
}

// Proves malformed-request isolation and recovery on one real listener.
#[test]
fn system_listener_recovers_after_malformed_request() {
    let directory = tempfile::tempdir().expect("temporary directory");
    protect_socket_parent(&directory);
    let socket_path = fs::canonicalize(directory.path())
        .expect("canonical socket parent")
        .join("node.sock");
    let server = system_server(&directory, &socket_path, 1);
    let mut handle = server.start().expect("start");
    let malformed = exchange(&socket_path, b"{}").expect_err("malformed request");
    assert!(matches!(
        malformed,
        NodePrivateLocalFrameError::Truncated | NodePrivateLocalFrameError::Unavailable
    ));
    wait_until(|| handle.active_workers() == 0);
    let response = exchange(&socket_path, &request_document()).expect("recovery exchange");
    assert!(matches!(
        NodePrivateTransport::decode_response(&response)
            .expect("response")
            .outcome(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(_))
    ));
    handle.shutdown().expect("shutdown");
}

// Proves unsafe path types and active sockets are never replaced.
#[test]
fn system_socket_rejects_unsafe_and_active_paths() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let directory_path = fs::canonicalize(directory.path()).expect("canonical socket parent");
    let owner_uid = unsafe { libc::geteuid() };
    let configuration = |path: &Path| {
        NodePrivateLocalServerConfiguration::new(
            path.to_path_buf(),
            owner_uid,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(2),
        )
        .expect("configuration")
    };
    let provider = SystemNodePrivateLocalSocketProvider;

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
        .expect("open parent mode");
    let exposed_path = directory_path.join("exposed.sock");
    assert!(matches!(
        provider.bind(&configuration(&exposed_path)),
        Err(NodePrivateLocalServerError::UnsafeSocketParent)
    ));
    protect_socket_parent(&directory);

    let foreign_owner = NodePrivateLocalServerConfiguration::new(
        directory_path.join("foreign.sock"),
        owner_uid.wrapping_add(1),
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(2),
    )
    .expect("foreign owner configuration");
    assert!(matches!(
        provider.bind(&foreign_owner),
        Err(NodePrivateLocalServerError::UnsafeSocketParent)
    ));

    let unsafe_path = directory_path.join("ordinary-file");
    fs::write(&unsafe_path, b"preserve").expect("ordinary file");
    assert!(matches!(
        provider.bind(&configuration(&unsafe_path)),
        Err(NodePrivateLocalServerError::UnsafeSocketPath)
    ));
    assert_eq!(fs::read(&unsafe_path).expect("preserved"), b"preserve");

    let active_path = directory_path.join("active.sock");
    let active = UnixListener::bind(&active_path).expect("active bind");
    fs::set_permissions(&active_path, fs::Permissions::from_mode(0o600)).expect("active mode");
    assert!(matches!(
        provider.bind(&configuration(&active_path)),
        Err(NodePrivateLocalServerError::AlreadyRunning)
    ));
    assert!(active_path.exists());
    drop(active);
}

// Rejects a protected final parent reached through any symlinked intermediate component.
#[test]
fn system_socket_rejects_an_intermediate_parent_symlink() {
    let directory = tempfile::tempdir().expect("temporary directory");
    protect_socket_parent(&directory);
    let directory_path = fs::canonicalize(directory.path()).expect("canonical socket parent");
    let target = directory_path.join("target");
    let protected = target.join("protected");
    fs::create_dir_all(&protected).expect("protected hierarchy");
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
        .expect("protected permissions");
    let real_socket = protected.join("node.sock");
    let _listener = UnixListener::bind(&real_socket).expect("real socket");
    fs::set_permissions(&real_socket, fs::Permissions::from_mode(0o600))
        .expect("socket permissions");
    let alias = directory_path.join("alias");
    symlink(&target, &alias).expect("intermediate symlink");
    let socket_path = alias.join("protected/node.sock");
    let owner_user_id = unsafe { libc::geteuid() };
    let configuration = NodePrivateLocalServerConfiguration::new(
        socket_path,
        owner_user_id,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(2),
    )
    .expect("configuration");

    assert!(matches!(
        SystemNodePrivateLocalSocketProvider.bind(&configuration),
        Err(NodePrivateLocalServerError::UnsafeSocketParent)
    ));
    assert!(real_socket.exists());
}

// Proves listener and connection failure strings never retain paths or document secrets.
#[test]
fn local_listener_failures_are_stable_and_redacted() {
    let secret = "bearer-private-secret";
    let errors = [
        NodePrivateLocalConnectionError::PeerIdentityUnavailable.to_string(),
        NodePrivateLocalConnectionError::ForeignUser.to_string(),
        NodePrivateLocalConnectionError::EndpointRejected.to_string(),
        NodePrivateLocalConnectionError::Frame(NodePrivateLocalFrameError::Unavailable).to_string(),
        NodePrivateLocalServerError::UnsafeSocketPath.to_string(),
        NodePrivateLocalServerError::BindFailed.to_string(),
        NodePrivateLocalServerError::AcceptFailed.to_string(),
    ];
    for error in errors {
        assert!(!error.contains(secret));
        assert!(!error.contains("/private/secret.sock"));
    }
}
