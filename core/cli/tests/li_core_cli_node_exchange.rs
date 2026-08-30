// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use li_core_cli::{
    NodePrivateClient, NodePrivateClientConfiguration, NodePrivateClientError,
    NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort, NodePrivateUnixConnectError,
    NodePrivateUnixConnector, NodePrivateUnixIoError, NodePrivateUnixStream,
    NodeRequestIdentityError, NodeRequestIdentitySource, SystemNodePrivateUnixConnector,
    UnixNodePrivateDocumentExchange, UnixNodePrivateExchangeConfigurationError,
};
use li_core_interface::{Sha256Digest, TechnicalName};
use li_node_manager::{
    NodePrivateRemoteError, NodePrivateRequest, NodePrivateTransport, NodePrivateTransportOutcome,
    NodePrivateTransportResponse, NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

// Retains one deterministic nonblocking stream behavior and its observations.
struct StreamState {
    input: Vec<u8>,
    input_offset: usize,
    output: Vec<u8>,
    maximum_read: usize,
    maximum_write: usize,
    read_waits: VecDeque<Result<(), NodePrivateUnixIoError>>,
    write_waits: VecDeque<Result<(), NodePrivateUnixIoError>>,
    always_interrupted_read: bool,
    always_interrupted_write: bool,
    zero_write: bool,
    closes: usize,
}

impl StreamState {
    // Creates one ordinary fully readable and writable stream behavior.
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            input_offset: 0,
            output: Vec::new(),
            maximum_read: usize::MAX,
            maximum_write: usize::MAX,
            read_waits: VecDeque::new(),
            write_waits: VecDeque::new(),
            always_interrupted_read: false,
            always_interrupted_write: false,
            zero_write: false,
            closes: 0,
        }
    }
}

// Adapts deterministic shared state to the injected nonblocking stream capability.
struct StreamMock {
    state: Rc<RefCell<StreamState>>,
}

impl NodePrivateUnixStream for StreamMock {
    // Returns the next scripted writable observation under the absolute deadline.
    fn wait_writable(&self, deadline: Instant) -> Result<(), NodePrivateUnixIoError> {
        if Instant::now() >= deadline {
            return Err(NodePrivateUnixIoError::TimedOut);
        }
        self.state
            .borrow_mut()
            .write_waits
            .pop_front()
            .unwrap_or(Ok(()))
    }

    // Returns the next scripted readable observation under the absolute deadline.
    fn wait_readable(&self, deadline: Instant) -> Result<(), NodePrivateUnixIoError> {
        if Instant::now() >= deadline {
            return Err(NodePrivateUnixIoError::TimedOut);
        }
        self.state
            .borrow_mut()
            .read_waits
            .pop_front()
            .unwrap_or(Ok(()))
    }

    // Retains one configured output fragment or one retryable interruption.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateUnixIoError> {
        let mut state = self.state.borrow_mut();
        if state.always_interrupted_write {
            return Err(NodePrivateUnixIoError::Interrupted);
        }
        if state.zero_write {
            return Ok(0);
        }
        let count = buffer.len().min(state.maximum_write);
        state.output.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    // Returns one configured input fragment or one retryable interruption.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateUnixIoError> {
        let mut state = self.state.borrow_mut();
        if state.always_interrupted_read {
            return Err(NodePrivateUnixIoError::Interrupted);
        }
        let remaining = &state.input[state.input_offset..];
        let count = remaining.len().min(buffer.len()).min(state.maximum_read);
        buffer[..count].copy_from_slice(&remaining[..count]);
        state.input_offset += count;
        Ok(count)
    }

    // Records the one terminal close without retaining request or response bytes.
    fn close(&mut self) -> Result<(), NodePrivateUnixIoError> {
        self.state.borrow_mut().closes += 1;
        Ok(())
    }
}

// Returns exactly one scripted stream or connection failure and records attempts.
struct ConnectorMock {
    step: Option<Result<StreamMock, NodePrivateUnixConnectError>>,
    calls: Rc<RefCell<Vec<PathBuf>>>,
}

impl ConnectorMock {
    // Creates one successful connector with externally observable stream state.
    fn stream(state: Rc<RefCell<StreamState>>) -> (Self, Rc<RefCell<Vec<PathBuf>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                step: Some(Ok(StreamMock { state })),
                calls: Rc::clone(&calls),
            },
            calls,
        )
    }

    // Creates one failed connector with externally observable attempt count.
    fn error(error: NodePrivateUnixConnectError) -> (Self, Rc<RefCell<Vec<PathBuf>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                step: Some(Err(error)),
                calls: Rc::clone(&calls),
            },
            calls,
        )
    }
}

impl NodePrivateUnixConnector for ConnectorMock {
    // Returns the one scripted outcome without retrying or discovering another path.
    fn connect(
        &mut self,
        socket_path: &Path,
        _deadline: Instant,
    ) -> Result<Box<dyn NodePrivateUnixStream>, NodePrivateUnixConnectError> {
        self.calls.borrow_mut().push(socket_path.to_path_buf());
        self.step
            .take()
            .expect("single connection attempt")
            .map(|stream| Box::new(stream) as Box<dyn NodePrivateUnixStream>)
    }
}

// Returns one fixed request identity for a single typed client exchange.
struct IdentityMock(Sha256Digest);

impl NodeRequestIdentitySource for IdentityMock {
    // Returns the retained exact identity without entropy discovery.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError> {
        Ok(self.0.clone())
    }
}

// Returns one exact fixed-header frame.
fn frame(document: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + document.len());
    frame.extend_from_slice(&(document.len() as u32).to_be_bytes());
    frame.extend_from_slice(document);
    frame
}

// Returns the explicit absolute path used only by injected tests.
fn socket_path() -> PathBuf {
    PathBuf::from("/private/tmp/li_node_private_test.sock")
}

// Creates one injected exchange and its shared observations.
fn mock_exchange(
    state: StreamState,
) -> (
    UnixNodePrivateDocumentExchange<ConnectorMock>,
    Rc<RefCell<StreamState>>,
    Rc<RefCell<Vec<PathBuf>>>,
) {
    let state = Rc::new(RefCell::new(state));
    let (connector, calls) = ConnectorMock::stream(Rc::clone(&state));
    (
        UnixNodePrivateDocumentExchange::new(socket_path(), connector).expect("exchange"),
        state,
        calls,
    )
}

// Returns one repeated canonical request identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Exchanges the exact big-endian frame across read and write fragmentation exactly once.
#[test]
fn unix_exchange_routes_one_fragmented_request_and_response() {
    let response = br#"{"response":"ordinary"}"#;
    let mut behavior = StreamState::new(frame(response));
    behavior.maximum_read = 1;
    behavior.maximum_write = 2;
    let (mut exchange, state, calls) = mock_exchange(behavior);
    let request = br#"{"request":"ordinary"}"#;
    assert_eq!(
        exchange.exchange(request, Duration::from_secs(1), 4096),
        Ok(response.to_vec())
    );
    let state = state.borrow();
    assert_eq!(state.output, frame(request));
    assert_eq!(state.closes, 1);
    assert_eq!(calls.borrow().as_slice(), &[socket_path()]);
}

// Rejects every malformed or unbounded frame before allocation, retry, or replay.
#[test]
fn unix_exchange_failure_matrix_is_bounded_and_single_attempt() {
    let response_failures = [
        (
            vec![0, 0, 0],
            4096,
            NodePrivateDocumentExchangeError::MalformedResponse,
        ),
        (
            vec![0, 0, 0, 2, b'{'],
            4096,
            NodePrivateDocumentExchangeError::MalformedResponse,
        ),
        (
            [0_u8; 4].to_vec(),
            4096,
            NodePrivateDocumentExchangeError::MalformedResponse,
        ),
        (
            4097_u32.to_be_bytes().to_vec(),
            4096,
            NodePrivateDocumentExchangeError::ResponseTooLarge,
        ),
    ];
    for (input, bound, expected) in response_failures {
        let (mut exchange, state, calls) = mock_exchange(StreamState::new(input));
        assert_eq!(
            exchange.exchange(b"request", Duration::from_secs(1), bound),
            Err(expected)
        );
        assert_eq!(calls.borrow().len(), 1);
        assert_eq!(state.borrow().closes, 1);
    }

    let (connector, calls) = ConnectorMock::error(NodePrivateUnixConnectError::Unavailable);
    let mut exchange =
        UnixNodePrivateDocumentExchange::new(socket_path(), connector).expect("exchange");
    assert_eq!(
        exchange.exchange(
            &vec![0; NODE_PRIVATE_MAX_DOCUMENT_BYTES + 1],
            Duration::from_secs(1),
            4096,
        ),
        Err(NodePrivateDocumentExchangeError::RequestTooLarge)
    );
    assert!(calls.borrow().is_empty());
    let (connector, _) = ConnectorMock::error(NodePrivateUnixConnectError::Unavailable);
    assert!(matches!(
        UnixNodePrivateDocumentExchange::new(PathBuf::from("relative.sock"), connector),
        Err(UnixNodePrivateExchangeConfigurationError::InvalidSocketPath)
    ));
}

// Maps connect, read, and write deadlines without retaining paths or request bytes.
#[test]
fn unix_exchange_timeout_and_connect_matrix_is_redacted() {
    let connect_cases = [
        (
            NodePrivateUnixConnectError::NotConfigured,
            NodePrivateDocumentExchangeError::NotConfigured,
        ),
        (
            NodePrivateUnixConnectError::TimedOut,
            NodePrivateDocumentExchangeError::TimedOut,
        ),
        (
            NodePrivateUnixConnectError::Unavailable,
            NodePrivateDocumentExchangeError::Unavailable,
        ),
    ];
    for (connection, expected) in connect_cases {
        let (connector, calls) = ConnectorMock::error(connection);
        let mut exchange =
            UnixNodePrivateDocumentExchange::new(socket_path(), connector).expect("exchange");
        assert_eq!(
            exchange.exchange(b"private-secret", Duration::from_secs(1), 4096),
            Err(expected)
        );
        assert_eq!(calls.borrow().len(), 1);
        assert!(!format!("{expected:?}").contains("private-secret"));
        assert!(!format!("{expected:?}").contains("li_node_private_test"));
    }

    let (connector, calls) = ConnectorMock::error(NodePrivateUnixConnectError::Unavailable);
    let mut exchange =
        UnixNodePrivateDocumentExchange::new(socket_path(), connector).expect("exchange");
    assert_eq!(
        exchange.exchange(b"request", Duration::ZERO, 4096),
        Err(NodePrivateDocumentExchangeError::TimedOut)
    );
    assert!(calls.borrow().is_empty());

    let mut read_timeout = StreamState::new(frame(b"response"));
    read_timeout
        .read_waits
        .push_back(Err(NodePrivateUnixIoError::TimedOut));
    let (mut exchange, state, _) = mock_exchange(read_timeout);
    assert_eq!(
        exchange.exchange(b"request", Duration::from_secs(1), 4096),
        Err(NodePrivateDocumentExchangeError::TimedOut)
    );
    assert_eq!(state.borrow().closes, 1);

    let mut write_timeout = StreamState::new(frame(b"response"));
    write_timeout
        .write_waits
        .push_back(Err(NodePrivateUnixIoError::TimedOut));
    let (mut exchange, state, _) = mock_exchange(write_timeout);
    assert_eq!(
        exchange.exchange(b"request", Duration::from_secs(1), 4096),
        Err(NodePrivateDocumentExchangeError::TimedOut)
    );
    assert_eq!(state.borrow().closes, 1);
}

// Proves retryable stream interruptions cannot extend the complete request deadline.
#[test]
fn unix_exchange_uses_one_absolute_deadline() {
    let mut behavior = StreamState::new(frame(b"response"));
    behavior.always_interrupted_write = true;
    let (mut exchange, state, calls) = mock_exchange(behavior);
    assert_eq!(
        exchange.exchange(b"request", Duration::from_millis(1), 4096),
        Err(NodePrivateDocumentExchangeError::TimedOut)
    );
    assert_eq!(calls.borrow().len(), 1);
    assert_eq!(state.borrow().closes, 1);
}

// Passes one typed server denial through the native exchange while dropping its secret message.
#[test]
fn unix_exchange_preserves_server_code_and_redacts_server_message() {
    let request_id = digest('a');
    let secret = "Bearer private-server-secret";
    let response = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
        request_id.clone(),
        NodePrivateTransportOutcome::Failure(
            NodePrivateRemoteError::new(
                TechnicalName::parse("authorization_denied").expect("code"),
                secret,
            )
            .expect("remote error"),
        ),
    ))
    .expect("response");
    let (exchange, _, _) = mock_exchange(StreamState::new(frame(&response)));
    let mut client = NodePrivateClient::new(
        exchange,
        IdentityMock(request_id),
        NodePrivateClientConfiguration::default(),
    );
    let error = client
        .execute(NodePrivateRequest::ReadNodes)
        .expect_err("server denial");
    assert_eq!(
        error,
        NodePrivateClientError::RemoteRejected {
            code: "authorization_denied".to_owned(),
        }
    );
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));
}

// Rejects a private endpoint reached through a real symlinked intermediate directory.
#[test]
fn system_connector_rejects_an_intermediate_parent_symlink() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
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
    let mut connector = SystemNodePrivateUnixConnector;

    assert!(matches!(
        connector.connect(
            &alias.join("protected/node.sock"),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(NodePrivateUnixConnectError::Unavailable)
    ));
}
