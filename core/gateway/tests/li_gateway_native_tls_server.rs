// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::{LogicalModelName, Sha256Digest};
use li_gateway_manager::{
    GatewayChatCompletionRequest, GatewayConfiguration, GatewayConfigurationFile, GatewayError,
    GatewayHttpError, GatewayHttpExecutionProvider, GatewayHttpHandler, GatewayHttpModelProvider,
    GatewayHttpRequestIdProvider, GatewayHttpSurface, GatewayHttpTokenProvider, GatewayNativeFile,
    GatewayNativeFileIo, GatewayNativeIoError, GatewayNativeTlsFileSet,
    GatewayNativeTlsServerConfiguration, GatewayProcess, GatewayProcessHandlers,
    GatewayResponseHead, GatewayResponseHeader, GatewayResponseWriter, SystemGatewayTlsServer,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};

const CERTIFICATE_PATH: &str = "/private/li_gateway_child.crt";
const PRIVATE_KEY_PATH: &str = "/private/li_gateway_child.key";
const CLIENT_CA_PATH: &str = "/private/li_gateway_main_ca.crt";
const CLIENT_CERTIFICATE_PATH: &str = "/private/li_gateway_main.crt";
const CONFIGURATION_PATH: &str = "/private/li_gateway.json";
const REQUEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Owns one generated CA, server identity, and client identity for in-memory TLS tests.
struct TestTlsIdentity {
    ca_certificate: Vec<u8>,
    server_certificate: Vec<u8>,
    server_private_key: Vec<u8>,
    client_certificate: Vec<u8>,
    client_private_key: Vec<u8>,
    alternate_client_certificate: Vec<u8>,
    alternate_client_private_key: Vec<u8>,
}

// Supplies descriptor-shaped private files from an in-memory path map.
struct MockFileIo {
    files: Mutex<BTreeMap<PathBuf, GatewayNativeFile>>,
}

impl MockFileIo {
    // Creates one exact safe file map for the private listener.
    fn safe(identity: &TestTlsIdentity) -> Self {
        Self::new([
            (
                CERTIFICATE_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.server_certificate.clone()).unwrap(),
            ),
            (
                PRIVATE_KEY_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.server_private_key.clone()).unwrap(),
            ),
            (
                CLIENT_CA_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.ca_certificate.clone()).unwrap(),
            ),
            (
                CLIENT_CERTIFICATE_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.client_certificate.clone()).unwrap(),
            ),
        ])
    }

    // Creates one in-memory descriptor map from exact path observations.
    fn new<const N: usize>(files: [(&str, GatewayNativeFile); N]) -> Self {
        Self {
            files: Mutex::new(
                files
                    .into_iter()
                    .map(|(path, file)| (PathBuf::from(path), file))
                    .collect(),
            ),
        }
    }
}

impl GatewayNativeFileIo for MockFileIo {
    // Returns one bounded cloned descriptor observation without following a path.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        let file = self
            .files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| GatewayNativeIoError::terminal_before_head("missing"))?;
        if file.bytes().len() > maximum_bytes {
            return Err(GatewayNativeIoError::terminal_before_head("oversized"));
        }
        Ok(file)
    }
}

// Resolves one fixed model for listener-construction tests.
struct MockModelProvider;

impl GatewayHttpModelProvider for MockModelProvider {
    // Returns one canonical model identity.
    fn resolve(&self, _requested_model: &str) -> Result<LogicalModelName, GatewayHttpError> {
        Ok(LogicalModelName::parse("model-a").unwrap())
    }
}

// Supplies one exact token count for listener-construction tests.
struct MockTokenProvider;

impl GatewayHttpTokenProvider for MockTokenProvider {
    // Returns a positive deterministic count.
    fn count(
        &self,
        _bearer_token: &str,
        _model: &LogicalModelName,
        _normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        Ok(NonZeroU64::new(1).unwrap())
    }
}

// Supplies one exact request identity for listener-construction tests.
struct MockRequestIdProvider;

impl GatewayHttpRequestIdProvider for MockRequestIdProvider {
    // Returns one deterministic request identity.
    fn next(&self) -> Result<Sha256Digest, GatewayHttpError> {
        Ok(Sha256Digest::parse(REQUEST_ID).unwrap())
    }
}

// Rejects execution because listener-construction tests never forward a request.
struct MockExecutionProvider;

impl GatewayHttpExecutionProvider for MockExecutionProvider {
    // Rejects an unused public execution path.
    fn forward_public(
        &self,
        _bearer_token: &str,
        _request: GatewayChatCompletionRequest,
        _response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::NoRoute)
    }

    // Rejects an unused private execution path.
    fn forward_relay(
        &self,
        _relay_credential: &str,
        _request: GatewayChatCompletionRequest,
        _response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::NoRoute)
    }
}

// Records only authenticated private requests and emits one fixed response.
struct LiveExecutionProvider {
    relay_calls: AtomicUsize,
}

impl LiveExecutionProvider {
    // Creates one provider with no observed private request.
    fn new() -> Self {
        Self {
            relay_calls: AtomicUsize::new(0),
        }
    }
}

impl GatewayHttpExecutionProvider for LiveExecutionProvider {
    // Rejects the unreachable public path on a private listener.
    fn forward_public(
        &self,
        _bearer_token: &str,
        _request: GatewayChatCompletionRequest,
        _response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::PublicUnavailableOnChild)
    }

    // Records one authenticated relay call before returning a fixed JSON response.
    fn forward_relay(
        &self,
        _relay_credential: &str,
        _request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.relay_calls.fetch_add(1, Ordering::AcqRel);
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

// Generates one ephemeral certificate hierarchy entirely in test memory.
fn identity() -> TestTlsIdentity {
    let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_parameters.distinguished_name = distinguished_name("li-test-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();

    let mut server_parameters = CertificateParams::new(vec!["child.local".to_string()]).unwrap();
    server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_parameters.distinguished_name = distinguished_name("child.local");
    let server_key = KeyPair::generate().unwrap();
    let server_certificate = server_parameters
        .signed_by(&server_key, &ca_certificate, &ca_key)
        .unwrap();

    let mut client_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_parameters.distinguished_name = distinguished_name("li-test-main");
    let client_key = KeyPair::generate().unwrap();
    let client_certificate = client_parameters
        .signed_by(&client_key, &ca_certificate, &ca_key)
        .unwrap();

    let mut alternate_client_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    alternate_client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    alternate_client_parameters.distinguished_name = distinguished_name("li-test-other-node");
    let alternate_client_key = KeyPair::generate().unwrap();
    let alternate_client_certificate = alternate_client_parameters
        .signed_by(&alternate_client_key, &ca_certificate, &ca_key)
        .unwrap();

    TestTlsIdentity {
        ca_certificate: ca_certificate.pem().into_bytes(),
        server_certificate: server_certificate.pem().into_bytes(),
        server_private_key: server_key.serialize_pem().into_bytes(),
        client_certificate: client_certificate.pem().into_bytes(),
        client_private_key: client_key.serialize_pem().into_bytes(),
        alternate_client_certificate: alternate_client_certificate.pem().into_bytes(),
        alternate_client_private_key: alternate_client_key.serialize_pem().into_bytes(),
    }
}

// Creates one simple certificate subject without environment-derived identity.
fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

// Creates the exact private listener file contract used by every configuration test.
fn file_set() -> GatewayNativeTlsFileSet {
    GatewayNativeTlsFileSet::new(
        501,
        PathBuf::from(CERTIFICATE_PATH),
        PathBuf::from(PRIVATE_KEY_PATH),
        PathBuf::from(CLIENT_CA_PATH),
        PathBuf::from(CLIENT_CERTIFICATE_PATH),
    )
    .unwrap()
}

// Creates one public or private request handler without live manager state.
fn handler(surface: GatewayHttpSurface) -> Arc<GatewayHttpHandler> {
    Arc::new(
        GatewayHttpHandler::new(
            surface,
            0,
            Arc::new(MockModelProvider),
            Arc::new(MockTokenProvider),
            Arc::new(MockRequestIdProvider),
            Arc::new(MockExecutionProvider),
        )
        .unwrap(),
    )
}

// Creates one production-shaped private handler and its observable execution boundary.
fn live_handler() -> (Arc<GatewayHttpHandler>, Arc<LiveExecutionProvider>) {
    let execution = Arc::new(LiveExecutionProvider::new());
    let handler = Arc::new(
        GatewayHttpHandler::new(
            GatewayHttpSurface::PrivateRelay,
            0,
            Arc::new(MockModelProvider),
            Arc::new(MockTokenProvider),
            Arc::new(MockRequestIdProvider),
            execution.clone(),
        )
        .unwrap(),
    );
    (handler, execution)
}

// Creates one exact private chat-completions request for a live TLS stream.
fn raw_private_request() -> Vec<u8> {
    let body = br#"{"model":"model-a","messages":[],"max_tokens":2}"#;
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nhost: child.local\r\nauthorization: Bearer relay-value\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
    .into_bytes()
}

// Opens and completes one bounded TLS 1.3 client connection to the resident listener.
fn connect_tls(
    address: SocketAddr,
    configuration: Arc<ClientConfig>,
) -> StreamOwned<ClientConnection, TcpStream> {
    let socket = TcpStream::connect(address).expect("connect private listener");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("private read timeout");
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("private write timeout");
    let client = ClientConnection::new(
        configuration,
        ServerName::try_from("child.local").unwrap().to_owned(),
    )
    .expect("create private TLS client");
    let mut connection = StreamOwned::new(client, socket);
    connection
        .conn
        .complete_io(&mut connection.sock)
        .expect("complete private TLS handshake");
    connection
}

// Waits briefly for one deterministic resident-state predicate.
fn wait_until(label: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {label}");
}

// Requires one native socket to terminate without receiving an HTTP response.
fn assert_terminal_socket(connection: &mut TcpStream) {
    let mut bytes = Vec::new();
    let result = connection.read_to_end(&mut bytes);
    assert!(
        result.is_ok()
            || result.is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            ))
    );
    assert!(!bytes.starts_with(b"HTTP/"));
}

// Builds one authenticated client configuration from the generated hierarchy.
fn client_configuration(identity: &TestTlsIdentity, include_identity: bool) -> Arc<ClientConfig> {
    let ca_certificates = rustls_pemfile::certs(&mut Cursor::new(&identity.ca_certificate))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate).unwrap();
    }
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    let configuration = if include_identity {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(&identity.client_certificate))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let private_key =
            rustls_pemfile::private_key(&mut Cursor::new(&identity.client_private_key))
                .unwrap()
                .unwrap();
        builder
            .with_client_auth_cert(certificates, private_key)
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(configuration)
}

// Builds one authenticated client using an explicitly selected CA-signed identity.
fn client_configuration_with_identity(
    identity: &TestTlsIdentity,
    certificate: &[u8],
    private_key: &[u8],
) -> Arc<ClientConfig> {
    let ca_certificates = rustls_pemfile::certs(&mut Cursor::new(&identity.ca_certificate))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate).unwrap();
    }
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(private_key))
        .unwrap()
        .unwrap();
    Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)
            .unwrap(),
    )
}

// Exchanges handshake records until both peers finish or one rejects the transcript.
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), String> {
    for _ in 0..32 {
        if client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).map_err(|_| "client write")?;
            server
                .read_tls(&mut Cursor::new(bytes))
                .map_err(|_| "server read")?;
            server
                .process_new_packets()
                .map_err(|_| "server rejected")?;
        }
        if server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).map_err(|_| "server write")?;
            client
                .read_tls(&mut Cursor::new(bytes))
                .map_err(|_| "client read")?;
            client
                .process_new_packets()
                .map_err(|_| "client rejected")?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err("handshake bound exceeded".to_string())
}

// Proves the loaded server accepts only a CA-authenticated TLS 1.3 client.
#[test]
fn private_configuration_completes_mutual_tls() {
    let identity = identity();
    let io = MockFileIo::safe(&identity);
    let configuration = GatewayNativeTlsServerConfiguration::load(&file_set(), &io).unwrap();
    let mut server = ServerConnection::new(configuration.server_configuration()).unwrap();
    let mut client = ClientConnection::new(
        client_configuration(&identity, true),
        ServerName::try_from("child.local").unwrap().to_owned(),
    )
    .unwrap();

    handshake(&mut client, &mut server).unwrap();

    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(server.peer_certificates().unwrap().len(), 1);
}

// Proves a client without a certificate cannot complete the private handshake.
#[test]
fn private_configuration_rejects_anonymous_client() {
    let identity = identity();
    let io = MockFileIo::safe(&identity);
    let configuration = GatewayNativeTlsServerConfiguration::load(&file_set(), &io).unwrap();
    let mut server = ServerConnection::new(configuration.server_configuration()).unwrap();
    let mut client = ClientConnection::new(
        client_configuration(&identity, false),
        ServerName::try_from("child.local").unwrap().to_owned(),
    )
    .unwrap();

    assert!(handshake(&mut client, &mut server).is_err());
}

// Proves another valid CA-signed node certificate is not accepted as the configured main.
#[test]
fn private_configuration_rejects_a_different_ca_signed_node() {
    let identity = identity();
    let io = MockFileIo::safe(&identity);
    let configuration = GatewayNativeTlsServerConfiguration::load(&file_set(), &io).unwrap();
    let mut server = ServerConnection::new(configuration.server_configuration()).unwrap();
    let mut client = ClientConnection::new(
        client_configuration_with_identity(
            &identity,
            &identity.alternate_client_certificate,
            &identity.alternate_client_private_key,
        ),
        ServerName::try_from("child.local").unwrap().to_owned(),
    )
    .unwrap();

    handshake(&mut client, &mut server).unwrap();

    assert!(configuration
        .verify_peer_certificates(server.peer_certificates())
        .is_err());
}

// Proves exact mTLS authentication precedes one private request and resident cleanup.
#[test]
fn resident_private_listener_authenticates_before_http_and_joins_cleanly() {
    let identity = identity();
    let tls = GatewayNativeTlsServerConfiguration::load(&file_set(), &MockFileIo::safe(&identity))
        .expect("load private TLS configuration");
    let (handler, execution) = live_handler();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server =
        SystemGatewayTlsServer::bind(address, 2, handler, tls).expect("bind private listener");
    let bound = server.local_address().expect("private bound address");
    let handle = server.start().expect("start private listener");

    let mut authenticated = connect_tls(bound, client_configuration(&identity, true));
    authenticated
        .write_all(&raw_private_request())
        .expect("write authenticated request");
    let mut response = Vec::new();
    authenticated
        .read_to_end(&mut response)
        .expect("read authenticated response through TLS close");
    let response = String::from_utf8(response).expect("authenticated response text");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert_eq!(execution.relay_calls.load(Ordering::Acquire), 1);

    let alternate_configuration = client_configuration_with_identity(
        &identity,
        &identity.alternate_client_certificate,
        &identity.alternate_client_private_key,
    );
    let mut alternate = connect_tls(bound, alternate_configuration);
    let _ = alternate.write_all(&raw_private_request());
    let mut rejected_response = Vec::new();
    let _ = alternate.read_to_end(&mut rejected_response);
    assert!(rejected_response.is_empty());
    wait_until("private worker cleanup", || {
        handle.active_connections() == 0
    });
    assert_eq!(execution.relay_calls.load(Ordering::Acquire), 1);

    assert!(handle.stop().is_ok());
    assert!(handle.stop().is_ok());
    assert!(handle.join().is_ok());
    assert!(handle.join().is_ok());
}

// Proves private saturation is silent and shutdown interrupts a stalled TLS handshake.
#[test]
fn resident_private_listener_rejects_saturation_and_interrupts_handshake() {
    let identity = identity();
    let tls = GatewayNativeTlsServerConfiguration::load(&file_set(), &MockFileIo::safe(&identity))
        .expect("load private TLS configuration");
    let (handler, execution) = live_handler();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server =
        SystemGatewayTlsServer::bind(address, 1, handler, tls).expect("bind private listener");
    let bound = server.local_address().expect("private bound address");
    let handle = server.start().expect("start private listener");
    let mut connections = Vec::new();
    for _ in 0..5 {
        let connection = TcpStream::connect(bound).expect("connect stalled handshake");
        connection
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("stalled read timeout");
        connections.push(connection);
    }
    wait_until("private active worker and saturation rejection", || {
        handle.active_connections() == 1 && handle.rejected_connections() >= 1
    });

    handle.stop().expect("stop private listener");
    handle.join().expect("join private listener");
    assert_eq!(handle.active_connections(), 0);
    assert_eq!(execution.relay_calls.load(Ordering::Acquire), 0);
    for mut connection in connections {
        assert_terminal_socket(&mut connection);
    }
}

// Proves the system child process owns, saturates, joins, and restarts its private listener.
#[test]
fn system_child_process_restarts_after_saturated_handshake_shutdown() {
    let identity = identity();
    let configuration_bytes = serde_json::to_vec(&serde_json::json!({
        "schema":{"name":"li_gateway_configuration","version":5},
        "node_id":"11111111111111111111111111111111",
        "core_release":"1.2.3",
        "core_source_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "mode":"child",
        "health":{
            "socket_path":"/private/gateway_health.sock",
            "maximum_workers":4,
            "read_timeout_milliseconds":1000,
            "write_timeout_milliseconds":1000,
            "accept_poll_interval_milliseconds":10
        },
        "node_protection":{
            "socket_path":"/private/node_protection.sock",
            "read_timeout_milliseconds":1000,
            "write_timeout_milliseconds":1000,
            "maximum_cache_milliseconds":2000,
            "poll_interval_milliseconds":500
        },
        "runtime":{
            "node_socket_path":"/private/node.sock",
            "telemetry_file":"/private/gateway_telemetry_v2",
            "telemetry_cadence_milliseconds":1000,
            "maximum_queue_milliseconds":30000
        },
        "private_listener":{
            "address":"127.0.0.1:0",
            "maximum_connections":1,
            "tls":{
                "server_certificate_file":CERTIFICATE_PATH,
                "server_private_key_file":PRIVATE_KEY_PATH,
                "client_ca_file":CLIENT_CA_PATH,
                "client_certificate_file":CLIENT_CERTIFICATE_PATH
            }
        }
    }))
    .unwrap();
    let io = MockFileIo::new([
        (
            CONFIGURATION_PATH,
            GatewayNativeFile::new(501, 0o600, 1, configuration_bytes).unwrap(),
        ),
        (
            CERTIFICATE_PATH,
            GatewayNativeFile::new(501, 0o600, 1, identity.server_certificate.clone()).unwrap(),
        ),
        (
            PRIVATE_KEY_PATH,
            GatewayNativeFile::new(501, 0o600, 1, identity.server_private_key.clone()).unwrap(),
        ),
        (
            CLIENT_CA_PATH,
            GatewayNativeFile::new(501, 0o600, 1, identity.ca_certificate.clone()).unwrap(),
        ),
        (
            CLIENT_CERTIFICATE_PATH,
            GatewayNativeFile::new(501, 0o600, 1, identity.client_certificate.clone()).unwrap(),
        ),
    ]);
    let file = GatewayConfigurationFile::new(501, PathBuf::from(CONFIGURATION_PATH)).unwrap();
    let configuration = GatewayConfiguration::load(&file, &io).unwrap();
    let process = GatewayProcess::start(
        &configuration,
        GatewayProcessHandlers::child(live_handler().0).unwrap(),
        &io,
    )
    .unwrap();
    assert!(process.public_address().is_none());
    let address = process.private_address().unwrap();
    let mut connections = Vec::new();
    for _ in 0..5 {
        let connection = TcpStream::connect(address).expect("connect process handshake");
        connection
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("process read timeout");
        connections.push(connection);
    }
    wait_until("process saturation", || {
        process.active_connections(GatewayHttpSurface::PrivateRelay) == 1
            && process.rejected_connections(GatewayHttpSurface::PrivateRelay) >= 1
    });

    process.stop().unwrap();
    process.join().unwrap();
    for mut connection in connections {
        assert_terminal_socket(&mut connection);
    }

    let restarted = GatewayProcess::start(
        &configuration,
        GatewayProcessHandlers::child(live_handler().0).unwrap(),
        &io,
    )
    .unwrap();
    assert!(restarted.private_address().is_some());
    restarted.join().unwrap();
}

// Proves owner, mode, and hard-link safety are all enforced before PEM parsing.
#[test]
fn private_file_metadata_matrix_fails_closed() {
    let identity = identity();
    let unsafe_files = [
        GatewayNativeFile::new(502, 0o600, 1, identity.server_private_key.clone()).unwrap(),
        GatewayNativeFile::new(501, 0o644, 1, identity.server_private_key.clone()).unwrap(),
        GatewayNativeFile::new(501, 0o600, 2, identity.server_private_key.clone()).unwrap(),
    ];
    for unsafe_key in unsafe_files {
        let io = MockFileIo::new([
            (
                CERTIFICATE_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.server_certificate.clone()).unwrap(),
            ),
            (PRIVATE_KEY_PATH, unsafe_key),
            (
                CLIENT_CA_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.ca_certificate.clone()).unwrap(),
            ),
            (
                CLIENT_CERTIFICATE_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.client_certificate.clone()).unwrap(),
            ),
        ]);

        let error = GatewayNativeTlsServerConfiguration::load(&file_set(), &io)
            .err()
            .unwrap();

        assert_eq!(
            error.reason(),
            "private Gateway TLS file metadata is unsafe"
        );
    }
}

// Proves malformed, unrelated, and mismatched identity material cannot build a server.
#[test]
fn tls_identity_mutation_matrix_is_rejected() {
    let identity = identity();
    let cases = [
        (
            b"not a certificate\n".to_vec(),
            identity.server_private_key.clone(),
            identity.ca_certificate.clone(),
        ),
        (
            identity.server_certificate.clone(),
            identity.client_private_key.clone(),
            identity.ca_certificate.clone(),
        ),
        (
            identity.server_certificate.clone(),
            identity.server_private_key.clone(),
            identity.server_private_key.clone(),
        ),
    ];
    for (certificate, key, ca) in cases {
        let io = MockFileIo::new([
            (
                CERTIFICATE_PATH,
                GatewayNativeFile::new(501, 0o600, 1, certificate).unwrap(),
            ),
            (
                PRIVATE_KEY_PATH,
                GatewayNativeFile::new(501, 0o600, 1, key).unwrap(),
            ),
            (
                CLIENT_CA_PATH,
                GatewayNativeFile::new(501, 0o600, 1, ca).unwrap(),
            ),
            (
                CLIENT_CERTIFICATE_PATH,
                GatewayNativeFile::new(501, 0o600, 1, identity.client_certificate.clone()).unwrap(),
            ),
        ]);

        assert!(GatewayNativeTlsServerConfiguration::load(&file_set(), &io).is_err());
    }
}

// Proves TLS file references are absolute, unique, and role-bound before serving.
#[test]
fn private_listener_configuration_rejects_ambiguous_role_or_bounds() {
    assert!(GatewayNativeTlsFileSet::new(
        501,
        PathBuf::from("relative.crt"),
        PathBuf::from(PRIVATE_KEY_PATH),
        PathBuf::from(CLIENT_CA_PATH),
        PathBuf::from(CLIENT_CERTIFICATE_PATH),
    )
    .is_err());
    assert!(GatewayNativeTlsFileSet::new(
        501,
        PathBuf::from(CERTIFICATE_PATH),
        PathBuf::from(CERTIFICATE_PATH),
        PathBuf::from(CLIENT_CA_PATH),
        PathBuf::from(CLIENT_CERTIFICATE_PATH),
    )
    .is_err());

    let identity = identity();
    let configuration =
        GatewayNativeTlsServerConfiguration::load(&file_set(), &MockFileIo::safe(&identity))
            .unwrap();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let public = SystemGatewayTlsServer::bind(
        address,
        1,
        handler(GatewayHttpSurface::Public),
        configuration,
    );
    assert_eq!(
        public.err().unwrap().reason(),
        "private Gateway listener configuration is invalid"
    );

    let configuration =
        GatewayNativeTlsServerConfiguration::load(&file_set(), &MockFileIo::safe(&identity))
            .unwrap();
    let unbounded = SystemGatewayTlsServer::bind(
        address,
        257,
        handler(GatewayHttpSurface::PrivateRelay),
        configuration,
    );
    assert_eq!(
        unbounded.err().unwrap().reason(),
        "private Gateway listener configuration is invalid"
    );
}
