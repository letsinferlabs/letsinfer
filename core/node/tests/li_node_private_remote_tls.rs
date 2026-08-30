// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::{CredentialId, NodeAddress, Sha256Digest};
use li_node_manager::{
    NodePairingCancellation, NodePrivateAuthenticatedConnectionHandler,
    NodePrivatePrincipalResolver, NodePrivateRemoteClientError, NodePrivateRemoteClientFileSet,
    NodePrivateRemoteClientPort, NodePrivateRemoteConnectionService,
    NodePrivateRemoteDocumentEndpoint, NodePrivateRemoteListener, NodePrivateRemoteNetworkError,
    NodePrivateRemoteNetworkStream, NodePrivateRemotePrincipal, NodePrivateRemoteSecureStream,
    NodePrivateRemoteServer, NodePrivateRemoteServerConfiguration, NodePrivateRemoteServerError,
    NodePrivateRemoteSocketProvider, NodePrivateRemoteTlsConfiguration,
    NodePrivateRemoteTlsConnectionService, NodePrivateRemoteTlsError, NodePrivateRemoteTlsFile,
    NodePrivateRemoteTlsFileProvider, NodePrivateRemoteTlsFileSet, SystemNodePrivateRemoteClient,
    SystemNodePrivateRemoteSocketProvider, SystemNodePrivateRemoteTlsFileProvider,
    NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};

const SERVER_CERTIFICATE_PATH: &str = "/private/li_node_server.crt";
const SERVER_PRIVATE_KEY_PATH: &str = "/private/li_node_server.key";
const CLIENT_CA_PATH: &str = "/private/li_node_client_ca.crt";
const CONTROLLER_CA_PATH: &str = "/private/li_controller_ca.crt";
const CLIENT_CERTIFICATE_PATH: &str = "/private/li_child_node.crt";
const CLIENT_PRIVATE_KEY_PATH: &str = "/private/li_child_node.key";

// Owns one generated CA, server identity, and two CA-signed client identities.
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
struct MockFileProvider {
    files: Mutex<BTreeMap<PathBuf, NodePrivateRemoteTlsFile>>,
}

impl MockFileProvider {
    // Creates one exact safe TLS input map.
    fn safe(identity: &TestTlsIdentity) -> Self {
        Self::new([
            (
                SERVER_CERTIFICATE_PATH,
                NodePrivateRemoteTlsFile::new(
                    501,
                    0o600,
                    1,
                    true,
                    identity.server_certificate.clone(),
                ),
            ),
            (
                SERVER_PRIVATE_KEY_PATH,
                NodePrivateRemoteTlsFile::new(
                    501,
                    0o600,
                    1,
                    true,
                    identity.server_private_key.clone(),
                ),
            ),
            (
                CLIENT_CA_PATH,
                NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, identity.ca_certificate.clone()),
            ),
        ])
    }

    // Creates one provider from exact path and metadata observations.
    fn new<const N: usize>(files: [(&str, NodePrivateRemoteTlsFile); N]) -> Self {
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

impl NodePrivateRemoteTlsFileProvider for MockFileProvider {
    // Returns one bounded cloned observation without discovering another path.
    fn read_no_follow(
        &self,
        path: &Path,
        _owner_uid: u32,
        maximum_bytes: usize,
    ) -> Result<NodePrivateRemoteTlsFile, NodePrivateRemoteTlsError> {
        let file = self
            .files
            .lock()
            .expect("files")
            .get(path)
            .cloned()
            .ok_or(NodePrivateRemoteTlsError::FileUnavailable)?;
        if file.bytes().len() > maximum_bytes {
            return Err(NodePrivateRemoteTlsError::UnsafeFile);
        }
        Ok(file)
    }
}

// Resolves only one exact peer leaf and records every attempted digest.
struct ResolverMock {
    allowed_digest: Sha256Digest,
    principal: NodePrivateRemotePrincipal,
    calls: Mutex<Vec<Sha256Digest>>,
}

impl ResolverMock {
    // Creates one exact paired leaf-to-credential mapping.
    fn new(allowed_digest: Sha256Digest) -> Self {
        Self {
            allowed_digest,
            principal: NodePrivateRemotePrincipal::Peer(
                CredentialId::parse(&"c".repeat(32)).expect("credential"),
            ),
            calls: Mutex::new(Vec::new()),
        }
    }

    // Creates one exact active controller leaf mapping without a peer credential identity.
    fn controller(allowed_digest: Sha256Digest) -> Self {
        Self {
            principal: NodePrivateRemotePrincipal::Controller {
                controller_id: li_core_interface::ControllerId::parse(&"d".repeat(32))
                    .expect("controller"),
                certificate_sha256: allowed_digest.clone(),
            },
            allowed_digest,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl NodePrivatePrincipalResolver for ResolverMock {
    // Returns the configured credential only for the exact paired leaf digest.
    fn principal_for_certificate(
        &self,
        peer_leaf_sha256: &Sha256Digest,
    ) -> Result<NodePrivateRemotePrincipal, NodePrivateRemoteTlsError> {
        self.calls
            .lock()
            .expect("resolver calls")
            .push(peer_leaf_sha256.clone());
        if peer_leaf_sha256 != &self.allowed_digest {
            return Err(NodePrivateRemoteTlsError::PrincipalRejected);
        }
        Ok(self.principal.clone())
    }
}

// Records the resolved credential and request document before returning one fixed response.
struct EndpointMock {
    calls: Mutex<Vec<(NodePrivateRemotePrincipal, Vec<u8>)>>,
    response: Result<Vec<u8>, NodePrivateRemoteTlsError>,
}

impl EndpointMock {
    // Creates one endpoint with one fixed deterministic response behavior.
    fn new(response: Result<Vec<u8>, NodePrivateRemoteTlsError>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response,
        }
    }
}

impl NodePrivateRemoteDocumentEndpoint for EndpointMock {
    // Records one authorized call and returns the fixed response without decoding it.
    fn handle_document(
        &self,
        principal: &NodePrivateRemotePrincipal,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateRemoteTlsError> {
        self.calls
            .lock()
            .expect("endpoint calls")
            .push((principal.clone(), document.to_vec()));
        self.response.clone()
    }
}

// Retains deterministic authenticated plaintext fragments and errors.
struct SecureStreamMock {
    input: Vec<u8>,
    input_offset: usize,
    output: Vec<u8>,
    maximum_read: usize,
    maximum_write: usize,
    read_error: Option<NodePrivateRemoteTlsError>,
    write_error: Option<NodePrivateRemoteTlsError>,
}

impl SecureStreamMock {
    // Creates one ordinary authenticated plaintext stream.
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            input_offset: 0,
            output: Vec::new(),
            maximum_read: usize::MAX,
            maximum_write: usize::MAX,
            read_error: None,
            write_error: None,
        }
    }
}

impl NodePrivateRemoteSecureStream for SecureStreamMock {
    // Returns one configured plaintext fragment or redacted failure before the deadline.
    fn read_bytes(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError> {
        if Instant::now() >= deadline {
            return Err(NodePrivateRemoteTlsError::TimedOut);
        }
        if let Some(error) = self.read_error.take() {
            return Err(error);
        }
        let remaining = &self.input[self.input_offset..];
        let count = remaining.len().min(buffer.len()).min(self.maximum_read);
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.input_offset += count;
        Ok(count)
    }

    // Retains one configured plaintext fragment or redacted failure before the deadline.
    fn write_bytes(
        &mut self,
        buffer: &[u8],
        deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError> {
        if Instant::now() >= deadline {
            return Err(NodePrivateRemoteTlsError::TimedOut);
        }
        if let Some(error) = self.write_error.take() {
            return Err(error);
        }
        let count = buffer.len().min(self.maximum_write);
        self.output.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
}

// Retains only whether one injected listener stream was closed.
struct ListenerStreamMock {
    closed: Arc<AtomicBool>,
}

impl NodePrivateRemoteNetworkStream for ListenerStreamMock {
    // Rejects an unused readable wait capability.
    fn wait_readable(&self, _deadline: Instant) -> Result<(), NodePrivateRemoteNetworkError> {
        Err(NodePrivateRemoteNetworkError::Unavailable)
    }

    // Rejects an unused writable wait capability.
    fn wait_writable(&self, _deadline: Instant) -> Result<(), NodePrivateRemoteNetworkError> {
        Err(NodePrivateRemoteNetworkError::Unavailable)
    }

    // Rejects an unused encrypted read capability.
    fn read_bytes(&mut self, _buffer: &mut [u8]) -> Result<usize, NodePrivateRemoteNetworkError> {
        Err(NodePrivateRemoteNetworkError::Unavailable)
    }

    // Rejects an unused encrypted write capability.
    fn write_bytes(&mut self, _buffer: &[u8]) -> Result<usize, NodePrivateRemoteNetworkError> {
        Err(NodePrivateRemoteNetworkError::Unavailable)
    }

    // Records deterministic listener rejection or worker completion.
    fn close(&mut self) -> Result<(), NodePrivateRemoteNetworkError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// Supplies deterministic streams to one injected nonblocking listener.
struct QueueListener {
    streams: Mutex<VecDeque<Box<dyn NodePrivateRemoteNetworkStream>>>,
    address: SocketAddr,
}

impl NodePrivateRemoteListener for QueueListener {
    // Returns the retained deterministic local address.
    fn local_address(&self) -> Result<SocketAddr, NodePrivateRemoteServerError> {
        Ok(self.address)
    }

    // Returns the next deterministic stream or one empty nonblocking poll.
    fn accept(
        &self,
    ) -> Result<Option<Box<dyn NodePrivateRemoteNetworkStream>>, NodePrivateRemoteServerError> {
        Ok(self.streams.lock().expect("streams").pop_front())
    }
}

// Returns one retained deterministic listener without acquiring a TCP socket.
struct QueueSocketProvider {
    listener: Arc<QueueListener>,
}

impl NodePrivateRemoteSocketProvider for QueueSocketProvider {
    // Returns the retained listener for one bounded server lifecycle.
    fn bind(
        &self,
        _configuration: &NodePrivateRemoteServerConfiguration,
    ) -> Result<Arc<dyn NodePrivateRemoteListener>, NodePrivateRemoteServerError> {
        Ok(self.listener.clone())
    }
}

// Blocks the first service call until the worker-bound test releases it.
struct BlockingService {
    started: AtomicBool,
    released: AtomicBool,
    calls: AtomicUsize,
}

impl BlockingService {
    // Creates one initially blocked deterministic connection service.
    fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            released: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
}

impl NodePrivateRemoteConnectionService for BlockingService {
    // Holds the first worker and closes its stream only after explicit release.
    fn serve(&self, mut stream: Box<dyn NodePrivateRemoteNetworkStream>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.store(true, Ordering::SeqCst);
        while !self.released.load(Ordering::SeqCst) {
            thread::yield_now();
        }
        let _ = stream.close();
    }
}

// Generates one ephemeral certificate hierarchy entirely in test memory.
fn identity() -> TestTlsIdentity {
    let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_parameters.distinguished_name = distinguished_name("li-test-ca");
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_certificate = ca_parameters.self_signed(&ca_key).expect("CA certificate");

    let mut server_parameters =
        CertificateParams::new(vec!["node.local".to_owned()]).expect("server parameters");
    server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_parameters.distinguished_name = distinguished_name("node.local");
    let server_key = KeyPair::generate().expect("server key");
    let server_certificate = server_parameters
        .signed_by(&server_key, &ca_certificate, &ca_key)
        .expect("server certificate");

    let mut client_parameters =
        CertificateParams::new(Vec::<String>::new()).expect("client parameters");
    client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_parameters.distinguished_name = distinguished_name("paired-node");
    let client_key = KeyPair::generate().expect("client key");
    let client_certificate = client_parameters
        .signed_by(&client_key, &ca_certificate, &ca_key)
        .expect("client certificate");

    let mut alternate_parameters =
        CertificateParams::new(Vec::<String>::new()).expect("alternate parameters");
    alternate_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    alternate_parameters.distinguished_name = distinguished_name("unpaired-node");
    let alternate_key = KeyPair::generate().expect("alternate key");
    let alternate_certificate = alternate_parameters
        .signed_by(&alternate_key, &ca_certificate, &ca_key)
        .expect("alternate certificate");

    TestTlsIdentity {
        ca_certificate: ca_certificate.pem().into_bytes(),
        server_certificate: server_certificate.pem().into_bytes(),
        server_private_key: server_key.serialize_pem().into_bytes(),
        client_certificate: client_certificate.pem().into_bytes(),
        client_private_key: client_key.serialize_pem().into_bytes(),
        alternate_client_certificate: alternate_certificate.pem().into_bytes(),
        alternate_client_private_key: alternate_key.serialize_pem().into_bytes(),
    }
}

// Creates one simple certificate subject without environment-derived identity.
fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

// Creates the exact three-file TLS input contract.
fn file_set() -> NodePrivateRemoteTlsFileSet {
    NodePrivateRemoteTlsFileSet::new(
        501,
        PathBuf::from(SERVER_CERTIFICATE_PATH),
        PathBuf::from(SERVER_PRIVATE_KEY_PATH),
        PathBuf::from(CLIENT_CA_PATH),
    )
    .expect("file set")
}

// Builds one TLS 1.3 client configuration with an optional exact identity.
fn client_configuration(
    identity: &TestTlsIdentity,
    certificate: Option<(&[u8], &[u8])>,
) -> Arc<ClientConfig> {
    let ca_certificates = rustls_pemfile::certs(&mut Cursor::new(&identity.ca_certificate))
        .collect::<Result<Vec<_>, _>>()
        .expect("CA certificates");
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate).expect("CA root");
    }
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    Arc::new(match certificate {
        Some((certificate, private_key)) => {
            let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate))
                .collect::<Result<Vec<_>, _>>()
                .expect("client certificate");
            let private_key = rustls_pemfile::private_key(&mut Cursor::new(private_key))
                .expect("private key parse")
                .expect("private key");
            builder
                .with_client_auth_cert(certificates, private_key)
                .expect("client identity")
        }
        None => builder.with_no_client_auth(),
    })
}

// Exchanges in-memory handshake records until both peers finish or one rejects them.
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), ()> {
    for _ in 0..32 {
        if client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).map_err(|_| ())?;
            server.read_tls(&mut Cursor::new(bytes)).map_err(|_| ())?;
            server.process_new_packets().map_err(|_| ())?;
        }
        if server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).map_err(|_| ())?;
            client.read_tls(&mut Cursor::new(bytes)).map_err(|_| ())?;
            client.process_new_packets().map_err(|_| ())?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(())
}

// Returns the SHA-256 identity of one PEM leaf certificate.
fn certificate_digest(certificate: &[u8]) -> Sha256Digest {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .next()
        .expect("certificate item")
        .expect("certificate");
    Sha256Digest::parse(&lower_hex(&Sha256::digest(certificate.as_ref()))).expect("digest")
}

// Encodes one byte slice as canonical lowercase hexadecimal text.
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

// Returns one exact fixed-header frame.
fn frame(document: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + document.len());
    frame.extend_from_slice(&(document.len() as u32).to_be_bytes());
    frame.extend_from_slice(document);
    frame
}

// Waits for one bounded concurrent lifecycle observation.
fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    assert!(condition(), "bounded condition");
}

// Proves real rustls permits only TLS 1.3 clients authenticated under the exact CA.
#[test]
fn tls_configuration_requires_mutual_tls_and_exact_protocol() {
    let identity = identity();
    let configuration =
        NodePrivateRemoteTlsConfiguration::load(&file_set(), &MockFileProvider::safe(&identity))
            .expect("configuration");
    let mut server =
        ServerConnection::new(configuration.server_configuration()).expect("server connection");
    let mut client = ClientConnection::new(
        client_configuration(
            &identity,
            Some((&identity.client_certificate, &identity.client_private_key)),
        ),
        ServerName::try_from("node.local")
            .expect("server name")
            .to_owned(),
    )
    .expect("client connection");
    handshake(&mut client, &mut server).expect("mTLS handshake");
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(server.peer_certificates().expect("peer").len(), 1);

    let mut anonymous_server =
        ServerConnection::new(configuration.server_configuration()).expect("anonymous server");
    let mut anonymous_client = ClientConnection::new(
        client_configuration(&identity, None),
        ServerName::try_from("node.local")
            .expect("server name")
            .to_owned(),
    )
    .expect("anonymous client");
    assert!(handshake(&mut anonymous_client, &mut anonymous_server).is_err());

    let mut alternate_server =
        ServerConnection::new(configuration.server_configuration()).expect("alternate server");
    let mut alternate_client = ClientConnection::new(
        client_configuration(
            &identity,
            Some((
                &identity.alternate_client_certificate,
                &identity.alternate_client_private_key,
            )),
        ),
        ServerName::try_from("node.local")
            .expect("server name")
            .to_owned(),
    )
    .expect("alternate client");
    handshake(&mut alternate_client, &mut alternate_server)
        .expect("CA-authenticated alternate handshake");
}

// Trusts a distinct controller CA without weakening or replacing the paired-node authority.
#[test]
fn tls_configuration_accepts_distinct_peer_and_controller_authorities() {
    let peer = identity();
    let controller = identity();
    let files = file_set()
        .with_additional_client_ca_file(PathBuf::from(CONTROLLER_CA_PATH))
        .expect("controller authority");
    let provider = MockFileProvider::new([
        (
            SERVER_CERTIFICATE_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, peer.server_certificate.clone()),
        ),
        (
            SERVER_PRIVATE_KEY_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, peer.server_private_key.clone()),
        ),
        (
            CLIENT_CA_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, peer.ca_certificate.clone()),
        ),
        (
            CONTROLLER_CA_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, controller.ca_certificate.clone()),
        ),
    ]);
    let configuration =
        NodePrivateRemoteTlsConfiguration::load(&files, &provider).expect("configuration");

    let mut peer_server =
        ServerConnection::new(configuration.server_configuration()).expect("peer server");
    let mut peer_client = ClientConnection::new(
        client_configuration(
            &peer,
            Some((&peer.client_certificate, &peer.client_private_key)),
        ),
        ServerName::try_from("node.local")
            .expect("server name")
            .to_owned(),
    )
    .expect("peer client");
    handshake(&mut peer_client, &mut peer_server).expect("peer handshake");

    let mut controller_server =
        ServerConnection::new(configuration.server_configuration()).expect("controller server");
    let mut controller_client = ClientConnection::new(
        client_configuration(
            &peer,
            Some((
                &controller.client_certificate,
                &controller.client_private_key,
            )),
        ),
        ServerName::try_from("node.local")
            .expect("server name")
            .to_owned(),
    )
    .expect("controller client");
    handshake(&mut controller_client, &mut controller_server).expect("controller handshake");

    assert!(file_set()
        .with_additional_client_ca_file(PathBuf::from(CLIENT_CA_PATH))
        .is_err());
}

// Proves unsafe metadata, malformed identity bytes, and ambiguous paths fail closed.
#[test]
fn tls_file_and_identity_matrix_fails_closed() {
    let identity = identity();
    let unsafe_files = [
        NodePrivateRemoteTlsFile::new(502, 0o600, 1, true, identity.server_private_key.clone()),
        NodePrivateRemoteTlsFile::new(501, 0o644, 1, true, identity.server_private_key.clone()),
        NodePrivateRemoteTlsFile::new(501, 0o600, 2, true, identity.server_private_key.clone()),
        NodePrivateRemoteTlsFile::new(501, 0o600, 1, false, identity.server_private_key.clone()),
    ];
    for unsafe_key in unsafe_files {
        let provider = MockFileProvider::new([
            (
                SERVER_CERTIFICATE_PATH,
                NodePrivateRemoteTlsFile::new(
                    501,
                    0o600,
                    1,
                    true,
                    identity.server_certificate.clone(),
                ),
            ),
            (SERVER_PRIVATE_KEY_PATH, unsafe_key),
            (
                CLIENT_CA_PATH,
                NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, identity.ca_certificate.clone()),
            ),
        ]);
        assert!(matches!(
            NodePrivateRemoteTlsConfiguration::load(&file_set(), &provider),
            Err(NodePrivateRemoteTlsError::UnsafeFile)
        ));
    }

    let malformed = MockFileProvider::new([
        (
            SERVER_CERTIFICATE_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, b"secret-invalid".to_vec()),
        ),
        (
            SERVER_PRIVATE_KEY_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, identity.server_private_key.clone()),
        ),
        (
            CLIENT_CA_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, identity.ca_certificate.clone()),
        ),
    ]);
    let error = NodePrivateRemoteTlsConfiguration::load(&file_set(), &malformed)
        .err()
        .expect("malformed certificate");
    assert_eq!(error, NodePrivateRemoteTlsError::MalformedCertificate);
    assert!(!error.to_string().contains("secret-invalid"));
    assert!(NodePrivateRemoteTlsFileSet::new(
        501,
        PathBuf::from("relative.crt"),
        PathBuf::from(SERVER_PRIVATE_KEY_PATH),
        PathBuf::from(CLIENT_CA_PATH),
    )
    .is_err());
    assert!(NodePrivateRemoteTlsFileSet::new(
        501,
        PathBuf::from(SERVER_CERTIFICATE_PATH),
        PathBuf::from(SERVER_CERTIFICATE_PATH),
        PathBuf::from(CLIENT_CA_PATH),
    )
    .is_err());
}

// Proves the system provider rejects symlinks and hard links before returning bytes.
#[test]
fn system_tls_file_provider_enforces_no_follow_and_single_link() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner_uid = unsafe { libc::geteuid() };
    let ordinary = directory.path().join("ordinary.pem");
    std::fs::write(&ordinary, b"private-bytes").expect("ordinary file");
    std::fs::set_permissions(&ordinary, std::fs::Permissions::from_mode(0o600))
        .expect("ordinary mode");
    let provider = SystemNodePrivateRemoteTlsFileProvider;
    let file = provider
        .read_no_follow(&ordinary, owner_uid, 1024)
        .expect("ordinary read");
    assert_eq!(file.bytes(), b"private-bytes");
    assert_eq!(file.link_count(), 1);

    let symbolic = directory.path().join("symbolic.pem");
    symlink(&ordinary, &symbolic).expect("symbolic link");
    assert!(matches!(
        provider.read_no_follow(&symbolic, owner_uid, 1024),
        Err(NodePrivateRemoteTlsError::FileUnavailable)
    ));

    let hard_link = directory.path().join("hard.pem");
    std::fs::hard_link(&ordinary, &hard_link).expect("hard link");
    assert!(matches!(
        provider.read_no_follow(&ordinary, owner_uid, 1024),
        Err(NodePrivateRemoteTlsError::UnsafeFile)
    ));
}

// Proves exact peer resolution precedes one fragmented request and endpoint dispatch.
#[test]
fn authenticated_handler_maps_exact_peer_and_routes_one_frame() {
    let digest = Sha256Digest::parse(&"a".repeat(64)).expect("digest");
    let resolver = Arc::new(ResolverMock::new(digest.clone()));
    let endpoint = Arc::new(EndpointMock::new(Ok(b"response".to_vec())));
    let handler = NodePrivateAuthenticatedConnectionHandler::new(
        endpoint.clone(),
        resolver.clone(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("handler");
    let mut stream = SecureStreamMock::new(frame(b"request"));
    stream.maximum_read = 1;
    stream.maximum_write = 2;
    handler.handle(&digest, &mut stream).expect("exchange");
    assert_eq!(stream.output, frame(b"response"));
    assert_eq!(
        resolver.calls.lock().expect("resolver calls").as_slice(),
        &[digest]
    );
    assert_eq!(endpoint.calls.lock().expect("endpoint calls").len(), 1);
    assert_eq!(
        endpoint.calls.lock().expect("endpoint calls")[0].1,
        b"request"
    );
}

// Preserves an exact controller principal through frame dispatch without peer conversion.
#[test]
fn authenticated_handler_routes_controller_principal_without_peer_fallback() {
    let digest = Sha256Digest::parse(&"a".repeat(64)).expect("digest");
    let resolver = Arc::new(ResolverMock::controller(digest.clone()));
    let endpoint = Arc::new(EndpointMock::new(Ok(b"response".to_vec())));
    let handler = NodePrivateAuthenticatedConnectionHandler::new(
        endpoint.clone(),
        resolver,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("handler");
    let mut stream = SecureStreamMock::new(frame(b"request"));
    handler.handle(&digest, &mut stream).expect("exchange");
    assert!(matches!(
        &endpoint.calls.lock().expect("endpoint calls")[0].0,
        NodePrivateRemotePrincipal::Controller {
            controller_id,
            certificate_sha256,
        } if controller_id.as_str() == "d".repeat(32)
            && certificate_sha256 == &digest
    ));
}

// Proves unpaired peers and malformed frames fail before unauthorized endpoint dispatch.
#[test]
fn authenticated_handler_failure_matrix_fails_before_fallback() {
    let paired = Sha256Digest::parse(&"a".repeat(64)).expect("paired digest");
    let foreign = Sha256Digest::parse(&"b".repeat(64)).expect("foreign digest");
    let resolver = Arc::new(ResolverMock::new(paired.clone()));
    let endpoint = Arc::new(EndpointMock::new(Ok(b"response".to_vec())));
    let handler = NodePrivateAuthenticatedConnectionHandler::new(
        endpoint.clone(),
        resolver,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("handler");
    let mut foreign_stream = SecureStreamMock::new(frame(b"private-secret"));
    assert_eq!(
        handler.handle(&foreign, &mut foreign_stream),
        Err(NodePrivateRemoteTlsError::PrincipalRejected)
    );
    assert_eq!(foreign_stream.input_offset, 0);
    assert!(endpoint.calls.lock().expect("endpoint calls").is_empty());

    let failures = [
        (vec![0, 0, 0], NodePrivateRemoteTlsError::FrameTruncated),
        (
            [0, 0, 0, 3, b'a'].to_vec(),
            NodePrivateRemoteTlsError::FrameTruncated,
        ),
        ([0_u8; 4].to_vec(), NodePrivateRemoteTlsError::EmptyDocument),
        (
            ((NODE_PRIVATE_MAX_DOCUMENT_BYTES + 1) as u32)
                .to_be_bytes()
                .to_vec(),
            NodePrivateRemoteTlsError::OversizedDocument,
        ),
    ];
    for (input, expected) in failures {
        let mut stream = SecureStreamMock::new(input);
        assert_eq!(handler.handle(&paired, &mut stream), Err(expected));
    }
    let mut timed_out = SecureStreamMock::new(frame(b"request"));
    timed_out.read_error = Some(NodePrivateRemoteTlsError::TimedOut);
    assert_eq!(
        handler.handle(&paired, &mut timed_out),
        Err(NodePrivateRemoteTlsError::TimedOut)
    );

    let rejected_endpoint = Arc::new(EndpointMock::new(Err(
        NodePrivateRemoteTlsError::EndpointRejected,
    )));
    let rejected_handler = NodePrivateAuthenticatedConnectionHandler::new(
        rejected_endpoint,
        Arc::new(ResolverMock::new(paired.clone())),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("rejected handler");
    let mut rejected_stream = SecureStreamMock::new(frame(b"request"));
    assert_eq!(
        rejected_handler.handle(&paired, &mut rejected_stream),
        Err(NodePrivateRemoteTlsError::EndpointRejected)
    );

    let write_endpoint = Arc::new(EndpointMock::new(Ok(b"response".to_vec())));
    let write_handler = NodePrivateAuthenticatedConnectionHandler::new(
        write_endpoint,
        Arc::new(ResolverMock::new(paired.clone())),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("write handler");
    let mut zero_progress = SecureStreamMock::new(frame(b"request"));
    zero_progress.maximum_write = 0;
    assert_eq!(
        write_handler.handle(&paired, &mut zero_progress),
        Err(NodePrivateRemoteTlsError::ZeroProgress)
    );

    let oversized_endpoint = Arc::new(EndpointMock::new(Ok(vec![
        0_u8;
        NODE_PRIVATE_MAX_DOCUMENT_BYTES
            + 1
    ])));
    let oversized_handler = NodePrivateAuthenticatedConnectionHandler::new(
        oversized_endpoint,
        Arc::new(ResolverMock::new(paired.clone())),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("oversized handler");
    let mut oversized_stream = SecureStreamMock::new(frame(b"request"));
    assert_eq!(
        oversized_handler.handle(&paired, &mut oversized_stream),
        Err(NodePrivateRemoteTlsError::OversizedDocument)
    );
    assert!(NodePrivateAuthenticatedConnectionHandler::new(
        endpoint,
        Arc::new(ResolverMock::new(paired)),
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .is_err());
}

// Proves the injected listener never exceeds its hard worker bound and shuts down cleanly.
#[test]
fn remote_listener_enforces_worker_bound_and_clean_shutdown() {
    let first_closed = Arc::new(AtomicBool::new(false));
    let second_closed = Arc::new(AtomicBool::new(false));
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9771);
    assert!(
        NodePrivateRemoteServerConfiguration::new(address, 0, Duration::from_millis(1)).is_err()
    );
    assert!(
        NodePrivateRemoteServerConfiguration::new(address, 65, Duration::from_millis(1)).is_err()
    );
    assert!(NodePrivateRemoteServerConfiguration::new(address, 1, Duration::ZERO).is_err());
    assert!(NodePrivateRemoteServerConfiguration::new(address, 1, Duration::from_secs(2)).is_err());
    let listener = Arc::new(QueueListener {
        streams: Mutex::new(VecDeque::from([
            Box::new(ListenerStreamMock {
                closed: Arc::clone(&first_closed),
            }) as Box<dyn NodePrivateRemoteNetworkStream>,
            Box::new(ListenerStreamMock {
                closed: Arc::clone(&second_closed),
            }) as Box<dyn NodePrivateRemoteNetworkStream>,
        ])),
        address,
    });
    let service = Arc::new(BlockingService::new());
    let configuration =
        NodePrivateRemoteServerConfiguration::new(address, 1, Duration::from_millis(1))
            .expect("configuration");
    let server = NodePrivateRemoteServer::new(
        configuration,
        service.clone(),
        Arc::new(QueueSocketProvider { listener }),
    );
    let mut handle = server.start().expect("start");
    assert_eq!(handle.local_address(), address);
    wait_until(|| service.started.load(Ordering::SeqCst));
    wait_until(|| handle.active_workers() == 1);
    wait_until(|| second_closed.load(Ordering::SeqCst));
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    service.released.store(true, Ordering::SeqCst);
    wait_until(|| handle.active_workers() == 0);
    handle.shutdown().expect("shutdown");
    assert!(first_closed.load(Ordering::SeqCst));
    assert!(!handle.is_running());
}

// Proves the production TCP, rustls, resolver, frame, endpoint, and close path together.
#[test]
fn production_remote_server_completes_one_real_mtls_exchange() {
    let identity = identity();
    let tls =
        NodePrivateRemoteTlsConfiguration::load(&file_set(), &MockFileProvider::safe(&identity))
            .expect("TLS configuration");
    let peer_digest = certificate_digest(&identity.client_certificate);
    let resolver = Arc::new(ResolverMock::new(peer_digest));
    let endpoint = Arc::new(EndpointMock::new(Ok(b"response".to_vec())));
    let handler = Arc::new(
        NodePrivateAuthenticatedConnectionHandler::new(
            endpoint.clone(),
            resolver,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("handler"),
    );
    let service = Arc::new(
        NodePrivateRemoteTlsConnectionService::new(tls, handler, Duration::from_secs(1))
            .expect("service"),
    );
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let configuration =
        NodePrivateRemoteServerConfiguration::new(address, 2, Duration::from_millis(1))
            .expect("server configuration");
    let server = NodePrivateRemoteServer::new(
        configuration,
        service,
        Arc::new(SystemNodePrivateRemoteSocketProvider),
    );
    let mut handle = server.start().expect("server start");

    let socket = TcpStream::connect(handle.local_address()).expect("client connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client read timeout");
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("client write timeout");
    let client = ClientConnection::new(
        client_configuration(
            &identity,
            Some((&identity.client_certificate, &identity.client_private_key)),
        ),
        ServerName::try_from("node.local")
            .expect("server name")
            .to_owned(),
    )
    .expect("client TLS");
    let mut client = StreamOwned::new(client, socket);
    client
        .write_all(&frame(b"request"))
        .expect("framed request");
    client.flush().expect("request flush");
    let mut header = [0_u8; 4];
    client.read_exact(&mut header).expect("response header");
    let mut response = vec![0_u8; u32::from_be_bytes(header) as usize];
    client.read_exact(&mut response).expect("response document");
    assert_eq!(response, b"response");
    drop(client);
    wait_until(|| handle.active_workers() == 0);

    let alternate_socket = TcpStream::connect(handle.local_address()).expect("alternate connect");
    alternate_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("alternate read timeout");
    alternate_socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("alternate write timeout");
    let alternate_client = ClientConnection::new(
        client_configuration(
            &identity,
            Some((
                &identity.alternate_client_certificate,
                &identity.alternate_client_private_key,
            )),
        ),
        ServerName::try_from("node.local")
            .expect("alternate server name")
            .to_owned(),
    )
    .expect("alternate client TLS");
    let mut alternate_client = StreamOwned::new(alternate_client, alternate_socket);
    let _ = alternate_client.write_all(&frame(b"private-secret"));
    let _ = alternate_client.flush();
    let mut unauthorized_header = [0_u8; 4];
    assert!(alternate_client
        .read_exact(&mut unauthorized_header)
        .is_err());
    drop(alternate_client);
    wait_until(|| handle.active_workers() == 0);
    handle.shutdown().expect("shutdown");
    assert_eq!(endpoint.calls.lock().expect("endpoint calls").len(), 1);
}

// Proves the paired client pins the main leaf, presents its child identity, and fails closed.
#[test]
fn production_remote_client_completes_only_exact_paired_mtls_exchange() {
    let identity = identity();
    let tls =
        NodePrivateRemoteTlsConfiguration::load(&file_set(), &MockFileProvider::safe(&identity))
            .expect("TLS configuration");
    let endpoint = Arc::new(EndpointMock::new(Ok(b"response".to_vec())));
    let handler = Arc::new(
        NodePrivateAuthenticatedConnectionHandler::new(
            endpoint.clone(),
            Arc::new(ResolverMock::new(certificate_digest(
                &identity.client_certificate,
            ))),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("handler"),
    );
    let service = Arc::new(
        NodePrivateRemoteTlsConnectionService::new(tls, handler, Duration::from_secs(1))
            .expect("service"),
    );
    let server = NodePrivateRemoteServer::new(
        NodePrivateRemoteServerConfiguration::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            2,
            Duration::from_millis(1),
        )
        .expect("server configuration"),
        service,
        Arc::new(SystemNodePrivateRemoteSocketProvider),
    );
    let mut handle = server.start().expect("server start");
    let files = NodePrivateRemoteClientFileSet::new(
        501,
        PathBuf::from(CLIENT_CERTIFICATE_PATH),
        PathBuf::from(CLIENT_PRIVATE_KEY_PATH),
    )
    .expect("client files");
    let provider = MockFileProvider::new([
        (
            CLIENT_CERTIFICATE_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, identity.client_certificate.clone()),
        ),
        (
            CLIENT_PRIVATE_KEY_PATH,
            NodePrivateRemoteTlsFile::new(501, 0o600, 1, true, identity.client_private_key.clone()),
        ),
    ]);
    let client = SystemNodePrivateRemoteClient::load(&files, &provider).expect("paired client");
    let cancellation = NodePairingCancellation::default();
    let address = NodeAddress::parse("127.0.0.1").expect("address");
    let server_digest = certificate_digest(&identity.server_certificate);
    assert_eq!(
        client.exchange(
            &address,
            handle.local_address().port(),
            &server_digest,
            b"request",
            Duration::from_secs(2),
            NODE_PRIVATE_MAX_DOCUMENT_BYTES,
            &cancellation,
        ),
        Ok(b"response".to_vec())
    );
    wait_until(|| handle.active_workers() == 0);

    assert_eq!(
        client.exchange(
            &address,
            handle.local_address().port(),
            &Sha256Digest::parse(&"f".repeat(64)).expect("foreign leaf"),
            b"private-secret",
            Duration::from_secs(2),
            NODE_PRIVATE_MAX_DOCUMENT_BYTES,
            &cancellation,
        ),
        Err(NodePrivateRemoteClientError::UntrustedPeer)
    );
    cancellation.cancel();
    assert_eq!(
        client.exchange(
            &address,
            handle.local_address().port(),
            &server_digest,
            b"private-secret",
            Duration::from_secs(2),
            NODE_PRIVATE_MAX_DOCUMENT_BYTES,
            &cancellation,
        ),
        Err(NodePrivateRemoteClientError::Cancelled)
    );
    handle.shutdown().expect("shutdown");
    assert_eq!(endpoint.calls.lock().expect("endpoint calls").len(), 1);
}
