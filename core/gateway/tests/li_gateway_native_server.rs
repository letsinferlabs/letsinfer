// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::{LogicalModelName, Sha256Digest};
use li_gateway_manager::{
    GatewayChatCompletionRequest, GatewayError, GatewayHttpError, GatewayHttpExecutionProvider,
    GatewayHttpHandler, GatewayHttpHealthProvider, GatewayHttpModelList,
    GatewayHttpModelListProvider, GatewayHttpModelProvider, GatewayHttpOutcome,
    GatewayHttpRequestIdProvider, GatewayHttpSurface, GatewayHttpTokenProvider,
    GatewayNativeConnectionServer, GatewayNativeRequestParser, GatewayNativeResponseWriter,
    GatewayResponseHead, GatewayResponseHeader, GatewayResponseWriter, SystemGatewayHttpServer,
};

const REQUEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Resolves every test alias to one canonical model.
struct MockModelProvider;

impl GatewayHttpModelProvider for MockModelProvider {
    // Returns the canonical test model.
    fn resolve(&self, _requested_model: &str) -> Result<LogicalModelName, GatewayHttpError> {
        Ok(LogicalModelName::parse("model-a").unwrap())
    }
}

// Reports deterministic healthy readiness for a production-shaped public handler.
struct MockHealthProvider;

impl GatewayHttpHealthProvider for MockHealthProvider {
    // Returns healthy without consulting a live telemetry publisher.
    fn health(&self) -> Result<bool, GatewayHttpError> {
        Ok(true)
    }
}

// Returns one deterministic empty authenticated discovery snapshot.
struct MockModelListProvider;

impl GatewayHttpModelListProvider for MockModelListProvider {
    // Returns an empty model list after the handler has extracted a bearer.
    fn models(&self, _bearer_token: &str) -> Result<GatewayHttpModelList, GatewayHttpError> {
        GatewayHttpModelList::new(1, Vec::new())
    }
}

// Returns one fixed exact prompt-token count.
struct MockTokenProvider;

impl GatewayHttpTokenProvider for MockTokenProvider {
    // Returns the deterministic exact count without contacting an Engine.
    fn count(
        &self,
        _bearer_token: &str,
        _model: &LogicalModelName,
        _normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        Ok(NonZeroU64::new(4).unwrap())
    }
}

// Returns one fixed request identity.
struct MockRequestIdProvider;

impl GatewayHttpRequestIdProvider for MockRequestIdProvider {
    // Returns the deterministic test request identity.
    fn next(&self) -> Result<Sha256Digest, GatewayHttpError> {
        Ok(Sha256Digest::parse(REQUEST_ID).unwrap())
    }
}

// Records one request and emits a successful JSON response.
struct MockExecutionProvider {
    credentials: Mutex<Vec<String>>,
}

impl MockExecutionProvider {
    // Creates one empty deterministic execution provider.
    fn new() -> Self {
        Self {
            credentials: Mutex::new(Vec::new()),
        }
    }

    // Records one credential and writes the fixed backend response.
    fn forward(
        &self,
        credential: &str,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.credentials
            .lock()
            .unwrap()
            .push(credential.to_string());
        let head = GatewayResponseHead::new(
            200,
            vec![GatewayResponseHeader::new("content-type", "application/json").unwrap()],
        )
        .unwrap();
        response
            .write_head(&head)
            .and_then(|_| response.write_body(br#"{"ok":true}"#))
            .map_err(|_| GatewayError::provider("client", "client response failed"))
    }
}

impl GatewayHttpExecutionProvider for MockExecutionProvider {
    // Forwards one public request through the fixed response plan.
    fn forward_public(
        &self,
        bearer_token: &str,
        _request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.forward(bearer_token, response)
    }

    // Rejects relay execution because this test provider serves the public listener only.
    fn forward_relay(
        &self,
        _relay_credential: &str,
        _request: GatewayChatCompletionRequest,
        _response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::PrivateRelayUnavailableOnMain)
    }
}

// Separates deterministic request bytes from captured response bytes.
struct MockDuplex {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl MockDuplex {
    // Creates one in-memory full-duplex connection.
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }
}

impl Read for MockDuplex {
    // Reads only from the configured inbound request.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for MockDuplex {
    // Captures every outbound response byte.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    // Flushes the in-memory response without side effects.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Fails every attempted client write.
struct FailingWriter;

impl Write for FailingWriter {
    // Rejects every response byte as a disconnected client.
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "closed",
        ))
    }

    // Rejects response flushing as a disconnected client.
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "closed",
        ))
    }
}

// Creates one production-shaped public handler with deterministic capabilities.
fn handler() -> (Arc<GatewayHttpHandler>, Arc<MockExecutionProvider>) {
    let execution = Arc::new(MockExecutionProvider::new());
    let handler = Arc::new(
        GatewayHttpHandler::new_with_public_reads(
            0,
            Arc::new(MockModelProvider),
            Arc::new(MockHealthProvider),
            Arc::new(MockModelListProvider),
            Arc::new(MockTokenProvider),
            Arc::new(MockRequestIdProvider),
            execution.clone(),
        )
        .unwrap(),
    );
    (handler, execution)
}

// Creates one exact raw HTTP chat-completions request.
fn raw_request() -> Vec<u8> {
    let body = br#"{"model":"model-a","messages":[],"max_tokens":2}"#;
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nhost: main.local:8000\r\nauthorization: Bearer private-value\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
    .into_bytes()
}

// Waits briefly for one deterministic resident-state predicate.
fn wait_until(label: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "resident state did not converge: {label}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

// Proves a raw request crosses parsing, handling, and chunked framing exactly once.
#[test]
fn connection_server_composes_one_complete_public_request() {
    let (handler, execution) = handler();
    let server = GatewayNativeConnectionServer::new(handler);
    let mut connection = MockDuplex::new(raw_request());

    let outcome = server.serve(&mut connection).unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::Forwarded);
    assert_eq!(
        execution.credentials.lock().unwrap().as_slice(),
        ["private-value"]
    );
    let response = String::from_utf8(connection.output).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("transfer-encoding: chunked\r\n"));
    assert!(response.ends_with("b\r\n{\"ok\":true}\r\n0\r\n\r\n"));
}

// Proves parser failures use the same redacted JSON response and never execute.
#[test]
fn parser_rejection_is_serialized_without_execution() {
    let (handler, execution) = handler();
    let server = GatewayNativeConnectionServer::new(handler);
    let mut connection = MockDuplex::new(
        b"POST /v1/chat/completions HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n".to_vec(),
    );

    let outcome = server.serve(&mut connection).unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::Rejected { status_code: 400 });
    assert!(execution.credentials.lock().unwrap().is_empty());
    let response = String::from_utf8(connection.output).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("unsupported_transfer_encoding"));
    assert!(!response.contains("chunked request bodies are unsupported\r\n"));
}

// Proves framing rejects each distinct ambiguity before allocating a request body.
#[test]
fn request_parser_failure_matrix_is_closed_and_bounded() {
    let oversized_length = (32 * 1024 * 1024usize + 1).to_string();
    let oversized_head = format!("GET / HTTP/1.1\r\nx-long: {}\r\n\r\n", "a".repeat(65_536));
    let cases = [
        (b"PATCH / HTTP/1.1\r\n\r\n".to_vec(), 405),
        (
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 2\r\nContent-Length: 2\r\n\r\n{}"
                .to_vec(),
            400,
        ),
        (
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 4\r\n\r\n{}"
                .to_vec(),
            400,
        ),
        (
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nhost: main.local\r\ncontent-length: {oversized_length}\r\n\r\n"
            )
            .into_bytes(),
            413,
        ),
        (oversized_head.into_bytes(), 431),
        (b"GET / HTTP/1.1\n\n".to_vec(), 400),
    ];
    for (bytes, expected_status) in cases {
        let error = GatewayNativeRequestParser
            .read(&mut Cursor::new(bytes))
            .unwrap_err();
        assert_eq!(error.status_code(), expected_status);
    }
}

// Proves response framing splits large output, terminates once, and rejects bad ordering.
#[test]
fn response_writer_enforces_ordered_chunked_framing() {
    let head = GatewayResponseHead::new(
        200,
        vec![GatewayResponseHeader::new("content-type", "application/json").unwrap()],
    )
    .unwrap();
    let mut bytes = Vec::new();
    {
        let mut response = GatewayNativeResponseWriter::new(&mut bytes);
        assert!(response.write_body(b"early").is_err());
        response.write_head(&head).unwrap();
        assert!(response.write_head(&head).is_err());
        response.write_body(&vec![b'a'; 65_537]).unwrap();
        response.finish().unwrap();
        response.finish().unwrap();
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("10000\r\n"));
    assert!(text.contains("1\r\na\r\n"));
    assert_eq!(text.matches("0\r\n\r\n").count(), 1);
}

// Proves a native client disconnect is surfaced without retrying response writes.
#[test]
fn response_writer_reports_client_disconnect() {
    let head = GatewayResponseHead::new(503, Vec::new()).unwrap();
    let mut output = FailingWriter;
    let mut response = GatewayNativeResponseWriter::new(&mut output);

    let failure = response.write_head(&head).unwrap_err();

    assert_eq!(failure.reason(), "client closed before response");
}

// Proves plaintext serving can bind only the public surface under its worker bound.
#[test]
fn system_listener_rejects_private_or_unbounded_configuration_before_binding() {
    let execution = Arc::new(MockExecutionProvider::new());
    let private = Arc::new(
        GatewayHttpHandler::new(
            GatewayHttpSurface::PrivateRelay,
            0,
            Arc::new(MockModelProvider),
            Arc::new(MockTokenProvider),
            Arc::new(MockRequestIdProvider),
            execution,
        )
        .unwrap(),
    );
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let private_result = SystemGatewayHttpServer::bind(address, 1, private);
    assert_eq!(
        private_result.err().unwrap().reason(),
        "public Gateway listener configuration is invalid"
    );

    let incomplete = Arc::new(
        GatewayHttpHandler::new(
            GatewayHttpSurface::Public,
            0,
            Arc::new(MockModelProvider),
            Arc::new(MockTokenProvider),
            Arc::new(MockRequestIdProvider),
            Arc::new(MockExecutionProvider::new()),
        )
        .unwrap(),
    );
    let incomplete_result = SystemGatewayHttpServer::bind(address, 1, incomplete);
    assert_eq!(
        incomplete_result.err().unwrap().reason(),
        "public Gateway listener configuration is invalid"
    );

    let (public, _) = handler();
    let unbounded = SystemGatewayHttpServer::bind(address, 257, public);
    assert_eq!(
        unbounded.err().unwrap().reason(),
        "public Gateway listener configuration is invalid"
    );
}

// Proves a real loopback request closes its worker and repeated stop/join is safe.
#[test]
fn resident_public_listener_serves_joins_and_restarts_cleanly() {
    let (handler, execution) = handler();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server = SystemGatewayHttpServer::bind(address, 2, handler).expect("bind listener");
    let bound = server.local_address().expect("bound address");
    let handle = server.start().expect("start listener");
    let mut client = TcpStream::connect(bound).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    client.write_all(&raw_request()).expect("write request");
    let mut response = Vec::new();
    client.read_to_end(&mut response).expect("read response");

    assert!(String::from_utf8(response)
        .expect("response text")
        .starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        execution
            .credentials
            .lock()
            .expect("credentials")
            .as_slice(),
        ["private-value"]
    );
    wait_until("ordinary worker cleanup", || {
        handle.active_connections() == 0
    });
    assert!(handle.stop().is_ok());
    assert!(handle.stop().is_ok());
    assert!(handle.join().is_ok());
    assert!(handle.join().is_ok());

    let restarted = SystemGatewayHttpServer::bind(bound, 1, self::handler().0)
        .expect("restart bind")
        .start()
        .expect("restart listener");
    assert!(restarted.join().is_ok());
}

// Proves saturation rejects excess sockets and shutdown interrupts a stalled read worker.
#[test]
fn resident_public_listener_rejects_saturation_and_interrupts_stalled_read() {
    let (handler, _) = handler();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server = SystemGatewayHttpServer::bind(address, 1, handler).expect("bind listener");
    let bound = server.local_address().expect("bound address");
    let handle = server.start().expect("start listener");
    let partial_request = b"POST /v1/chat/completions HTTP/1.1\r\nhost: main.local\r\nauthorization: Bearer private-value\r\ncontent-type: application/json\r\ncontent-length: 10\r\n\r\n{";
    let mut connections = Vec::new();
    for _ in 0..5 {
        let mut connection = TcpStream::connect(bound).expect("connect stalled client");
        connection
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("stalled timeout");
        connection
            .write_all(partial_request)
            .expect("partial request");
        connections.push(connection);
    }
    wait_until("active worker and saturation rejection", || {
        handle.active_connections() == 1 && handle.rejected_connections() >= 1
    });

    handle.stop().expect("stop listener");
    handle.join().expect("join listener");
    assert_eq!(handle.active_connections(), 0);
    for mut connection in connections {
        let mut shutdown_response = Vec::new();
        let result = connection.read_to_end(&mut shutdown_response);
        assert!(
            result.is_ok()
                || result.is_err_and(|error| matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ))
        );
    }
}
