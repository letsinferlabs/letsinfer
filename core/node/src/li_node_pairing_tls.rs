// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::{NodeAddress, Sha256Digest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
};
use sha2::{Digest, Sha256};

use crate::{
    decode_node_pairing_request, decode_node_pairing_response, encode_node_pairing_request,
    encode_node_pairing_response, NodePairingDocumentEndpoint, NodePairingTransportError,
    NodePairingTransportRequest, NodePairingTransportResponse, NodePrivateRemoteConnectionService,
    NodePrivateRemoteNetworkError, NodePrivateRemoteNetworkStream,
    NodePrivateRemoteTlsFileProvider, NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES,
};

const MAXIMUM_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAXIMUM_PRIVATE_KEY_BYTES: usize = 128 * 1024;
const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(60);
const MAXIMUM_RESOLVED_ADDRESSES: usize = 8;
const FRAME_HEADER_BYTES: usize = 4;

// Binds one dedicated pairing server identity to exact owner-only file references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingTlsFileSet {
    owner_user_id: u32,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}

impl NodePairingTlsFileSet {
    // Creates one unambiguous absolute pairing identity file set.
    pub fn new(
        owner_user_id: u32,
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    ) -> Result<Self, NodePairingTlsError> {
        if !certificate_file.is_absolute()
            || !private_key_file.is_absolute()
            || certificate_file == private_key_file
        {
            return Err(NodePairingTlsError::InvalidConfiguration);
        }
        Ok(Self {
            owner_user_id,
            certificate_file,
            private_key_file,
        })
    }
}

// Names stable dedicated pairing TLS failures without retaining peer or credential values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePairingTlsError {
    InvalidConfiguration,
    IdentityUnavailable,
    InvalidIdentity,
    AddressUnavailable,
    ConnectionUnavailable,
    UntrustedPeer,
    TimedOut,
    Cancelled,
    FrameUnavailable,
    RequestRejected,
}

impl fmt::Display for NodePairingTlsError {
    // Presents stable pairing transport language without paths, addresses, or TLS diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("pairing TLS configuration is invalid")
            }
            Self::IdentityUnavailable => formatter.write_str("pairing TLS identity is unavailable"),
            Self::InvalidIdentity => formatter.write_str("pairing TLS identity is invalid"),
            Self::AddressUnavailable => formatter.write_str("pairing peer address is unavailable"),
            Self::ConnectionUnavailable => {
                formatter.write_str("pairing TLS connection is unavailable")
            }
            Self::UntrustedPeer => formatter.write_str("pairing TLS peer identity is untrusted"),
            Self::TimedOut => formatter.write_str("pairing TLS operation timed out"),
            Self::Cancelled => formatter.write_str("pairing TLS operation was cancelled"),
            Self::FrameUnavailable => formatter.write_str("pairing TLS frame is unavailable"),
            Self::RequestRejected => formatter.write_str("pairing TLS request was rejected"),
        }
    }
}

impl Error for NodePairingTlsError {}

// Loads one TLS 1.3 server-authentication-only policy for initial pairing.
pub struct NodePairingTlsServerConfiguration {
    server: Arc<ServerConfig>,
}

impl NodePairingTlsServerConfiguration {
    // Loads owner-only identity files and explicitly omits client-certificate authentication.
    pub fn load(
        files: &NodePairingTlsFileSet,
        provider: &dyn NodePrivateRemoteTlsFileProvider,
    ) -> Result<Self, NodePairingTlsError> {
        let certificate = provider
            .read_no_follow(
                &files.certificate_file,
                files.owner_user_id,
                MAXIMUM_CERTIFICATE_BYTES,
            )
            .map_err(|_| NodePairingTlsError::IdentityUnavailable)?;
        let private_key_file = provider
            .read_no_follow(
                &files.private_key_file,
                files.owner_user_id,
                MAXIMUM_PRIVATE_KEY_BYTES,
            )
            .map_err(|_| NodePairingTlsError::IdentityUnavailable)?;
        let certificates = certificates(certificate.bytes())?;
        let private_key = private_key(private_key_file.bytes())?;
        let server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| NodePairingTlsError::InvalidIdentity)?;
        Ok(Self {
            server: Arc::new(server),
        })
    }
}

// Serves one candidate-facing request over the dedicated server-authenticated channel.
pub struct NodePairingTlsConnectionService {
    tls: Arc<ServerConfig>,
    endpoint: Arc<NodePairingDocumentEndpoint>,
    timeout: Duration,
}

impl NodePairingTlsConnectionService {
    // Creates one bounded connection service from an exact TLS policy and endpoint.
    pub fn new(
        tls: NodePairingTlsServerConfiguration,
        endpoint: Arc<NodePairingDocumentEndpoint>,
        timeout: Duration,
    ) -> Result<Self, NodePairingTlsError> {
        validate_timeout(timeout)?;
        Ok(Self {
            tls: tls.server,
            endpoint,
            timeout,
        })
    }

    // Completes TLS, one frame request, one frame response, and close under one deadline.
    pub fn handle_connection(
        &self,
        network: Box<dyn NodePrivateRemoteNetworkStream>,
    ) -> Result<(), NodePairingTlsError> {
        let peer_address = network
            .peer_address()
            .map_err(|_| NodePairingTlsError::AddressUnavailable)?;
        let observed_peer = NodeAddress::parse(&peer_address.ip().to_string())
            .map_err(|_| NodePairingTlsError::AddressUnavailable)?;
        let deadline = deadline(self.timeout)?;
        let connection = ServerConnection::new(Arc::clone(&self.tls))
            .map_err(|_| NodePairingTlsError::ConnectionUnavailable)?;
        let adapter = PairingNetworkAdapter::new(network, deadline);
        let mut stream = StreamOwned::new(connection, adapter);
        complete_server_handshake(&mut stream, deadline)?;
        let request = read_frame(&mut stream, deadline)?;
        let request = decode_node_pairing_request(&request)
            .map_err(|_| NodePairingTlsError::RequestRejected)?;
        let response = self
            .endpoint
            .handle(request, &observed_peer)
            .map_err(|_| NodePairingTlsError::RequestRejected)?;
        let response = encode_node_pairing_response(&response)
            .map_err(|_| NodePairingTlsError::RequestRejected)?;
        write_frame(&mut stream, &response, deadline)?;
        stream.conn.send_close_notify();
        let close_result = stream.flush().map_err(io_error);
        let network_close = stream.sock.network.close().map_err(network_error);
        close_result.and(network_close)
    }
}

impl NodePrivateRemoteConnectionService for NodePairingTlsConnectionService {
    // Contains every redacted candidate-facing failure inside the bounded listener worker.
    fn serve(&self, stream: Box<dyn NodePrivateRemoteNetworkStream>) {
        let _ = self.handle_connection(stream);
    }
}

// Allows callers to interrupt a bounded client operation between native I/O transitions.
pub trait NodePairingCancellationPort: Send + Sync {
    // Returns whether the caller has cancelled the current pairing workflow.
    fn is_cancelled(&self) -> bool;
}

// Supplies one shareable process-local cancellation flag.
#[derive(Default)]
pub struct NodePairingCancellation {
    cancelled: AtomicBool,
}

impl NodePairingCancellation {
    // Marks every current observer cancelled without blocking.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl NodePairingCancellationPort for NodePairingCancellation {
    // Reads the current cancellation state.
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

// Exchanges one typed document through a server-leaf-pinned TLS 1.3 connection.
pub trait NodePairingClientPort: Send + Sync {
    // Sends one request to one explicit endpoint under a complete deadline and cancellation token.
    fn exchange(
        &self,
        address: &NodeAddress,
        port: u16,
        expected_certificate_sha256: &Sha256Digest,
        request: &NodePairingTransportRequest,
        timeout: Duration,
        cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<NodePairingTransportResponse, NodePairingTransportError>;
}

// Performs production DNS resolution, TCP connection, pinned TLS, and one framed exchange.
#[derive(Default)]
pub struct SystemNodePairingClient;

impl NodePairingClientPort for SystemNodePairingClient {
    // Executes one candidate-facing exchange without consulting the authenticated private channel.
    fn exchange(
        &self,
        address: &NodeAddress,
        port: u16,
        expected_certificate_sha256: &Sha256Digest,
        request: &NodePairingTransportRequest,
        timeout: Duration,
        cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        validate_timeout(timeout).map_err(transport_tls_error)?;
        require_not_cancelled(cancellation)?;
        let deadline = deadline(timeout).map_err(transport_tls_error)?;
        let addresses = (address.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| NodePairingTransportError::Unavailable)?
            .take(MAXIMUM_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAXIMUM_RESOLVED_ADDRESSES {
            return Err(NodePairingTransportError::Unavailable);
        }
        let mut socket = None;
        for resolved in addresses {
            require_not_cancelled(cancellation)?;
            let remaining = remaining(deadline)?;
            if let Ok(stream) = TcpStream::connect_timeout(&resolved, remaining) {
                socket = Some(stream);
                break;
            }
        }
        let socket = socket.ok_or(NodePairingTransportError::Unavailable)?;
        let socket_timeout = remaining(deadline)?;
        socket
            .set_read_timeout(Some(socket_timeout))
            .and_then(|()| socket.set_write_timeout(Some(socket_timeout)))
            .and_then(|()| socket.set_nodelay(true))
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        let verifier = Arc::new(PinnedPairingServerVerifier::new(
            expected_certificate_sha256.clone(),
        ));
        let client = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let server_name = ServerName::try_from("pairing.letsinfer.invalid")
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        let connection = ClientConnection::new(Arc::new(client), server_name)
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        let mut stream = StreamOwned::new(connection, socket);
        complete_client_handshake(&mut stream, deadline)?;
        require_not_cancelled(cancellation)?;
        let document = encode_node_pairing_request(request)?;
        write_blocking_frame(&mut stream, &document, deadline)?;
        require_not_cancelled(cancellation)?;
        let response = read_blocking_frame(&mut stream, deadline)?;
        require_not_cancelled(cancellation)?;
        decode_node_pairing_response(&response)
    }
}

// Verifies the exact discovery-pinned server leaf while retaining TLS handshake proof validation.
#[derive(Debug)]
struct PinnedPairingServerVerifier {
    expected: Sha256Digest,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedPairingServerVerifier {
    // Creates one verifier from the exact public discovery fingerprint.
    fn new(expected: Sha256Digest) -> Self {
        Self {
            expected,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedPairingServerVerifier {
    // Accepts only the exact single leaf digest advertised before connection.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() || certificate_digest(end_entity.as_ref()) != self.expected {
            return Err(rustls::Error::General(
                "pairing peer identity is untrusted".to_string(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    // Rejects TLS 1.2 signature verification because the channel is TLS 1.3 only.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "pairing TLS version is unsupported".to_string(),
        ))
    }

    // Verifies the TLS 1.3 handshake signature under the pinned leaf public key.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    // Returns only provider-supported TLS 1.3 signature schemes.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// Adapts the existing nonblocking listener stream to deadline-bound std I/O for rustls.
struct PairingNetworkAdapter {
    network: Box<dyn NodePrivateRemoteNetworkStream>,
    deadline: Instant,
}

impl PairingNetworkAdapter {
    // Creates one adapter whose absolute deadline never extends during TLS or framing.
    const fn new(network: Box<dyn NodePrivateRemoteNetworkStream>, deadline: Instant) -> Self {
        Self { network, deadline }
    }
}

impl Read for PairingNetworkAdapter {
    // Waits and reads one encrypted fragment before the fixed deadline.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.network
                .wait_readable(self.deadline)
                .map_err(network_io_error)?;
            match self.network.read_bytes(buffer) {
                Ok(count) => return Ok(count),
                Err(
                    NodePrivateRemoteNetworkError::Interrupted
                    | NodePrivateRemoteNetworkError::WouldBlock,
                ) => {}
                Err(error) => return Err(network_io_error(error)),
            }
        }
    }
}

impl Write for PairingNetworkAdapter {
    // Waits and writes one encrypted fragment before the fixed deadline.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        loop {
            self.network
                .wait_writable(self.deadline)
                .map_err(network_io_error)?;
            match self.network.write_bytes(buffer) {
                Ok(count) => return Ok(count),
                Err(
                    NodePrivateRemoteNetworkError::Interrupted
                    | NodePrivateRemoteNetworkError::WouldBlock,
                ) => {}
                Err(error) => return Err(network_io_error(error)),
            }
        }
    }

    // Confirms the nonbuffering adapter has no pending native bytes.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Completes the server handshake without extending the complete connection deadline.
fn complete_server_handshake(
    stream: &mut StreamOwned<ServerConnection, PairingNetworkAdapter>,
    deadline: Instant,
) -> Result<(), NodePairingTlsError> {
    while stream.conn.is_handshaking() {
        ensure_deadline(deadline)?;
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(io_error)?;
    }
    Ok(())
}

// Completes the pinned client handshake without extending the complete request deadline.
fn complete_client_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<(), NodePairingTransportError> {
    while stream.conn.is_handshaking() {
        remaining(deadline)?;
        let socket_timeout = remaining(deadline)?;
        stream
            .sock
            .set_read_timeout(Some(socket_timeout))
            .and_then(|()| stream.sock.set_write_timeout(Some(socket_timeout)))
            .map_err(|_| NodePairingTransportError::Unavailable)?;
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                    NodePairingTransportError::TimedOut
                }
                std::io::ErrorKind::InvalidData => NodePairingTransportError::UntrustedPeer,
                _ => NodePairingTransportError::Unavailable,
            })?;
    }
    Ok(())
}

// Reads one bounded request or response frame through a deadline-aware server stream.
fn read_frame(stream: &mut impl Read, deadline: Instant) -> Result<Vec<u8>, NodePairingTlsError> {
    ensure_deadline(deadline)?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header).map_err(io_error)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES {
        return Err(NodePairingTlsError::FrameUnavailable);
    }
    let mut document = vec![0_u8; length];
    stream.read_exact(&mut document).map_err(io_error)?;
    ensure_deadline(deadline)?;
    Ok(document)
}

// Writes one bounded request or response frame through a deadline-aware server stream.
fn write_frame(
    stream: &mut impl Write,
    document: &[u8],
    deadline: Instant,
) -> Result<(), NodePairingTlsError> {
    ensure_deadline(deadline)?;
    let length = frame_length(document)?;
    stream.write_all(&length.to_be_bytes()).map_err(io_error)?;
    stream.write_all(document).map_err(io_error)?;
    stream.flush().map_err(io_error)?;
    ensure_deadline(deadline)
}

// Writes one bounded frame through a blocking client stream under its socket timeout.
fn write_blocking_frame(
    stream: &mut impl Write,
    document: &[u8],
    deadline: Instant,
) -> Result<(), NodePairingTransportError> {
    remaining(deadline)?;
    let length = frame_length(document).map_err(transport_tls_error)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(document))
        .and_then(|()| stream.flush())
        .map_err(blocking_io_error)?;
    remaining(deadline).map(|_| ())
}

// Reads one bounded frame through a blocking client stream under its socket timeout.
fn read_blocking_frame(
    stream: &mut impl Read,
    deadline: Instant,
) -> Result<Vec<u8>, NodePairingTransportError> {
    remaining(deadline)?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header).map_err(blocking_io_error)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES {
        return Err(NodePairingTransportError::InvalidDocument {
            reason: "frame size is invalid",
        });
    }
    let mut document = vec![0_u8; length];
    stream
        .read_exact(&mut document)
        .map_err(blocking_io_error)?;
    remaining(deadline)?;
    Ok(document)
}

// Returns one checked frame length for the shared four-byte prefix.
fn frame_length(document: &[u8]) -> Result<u32, NodePairingTlsError> {
    if document.is_empty() || document.len() > NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES {
        return Err(NodePairingTlsError::FrameUnavailable);
    }
    u32::try_from(document.len()).map_err(|_| NodePairingTlsError::FrameUnavailable)
}

// Parses one nonempty certificate chain from PEM.
fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, NodePairingTlsError> {
    let mut reader = Cursor::new(bytes);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NodePairingTlsError::InvalidIdentity)?;
    if certificates.is_empty() {
        return Err(NodePairingTlsError::InvalidIdentity);
    }
    Ok(certificates)
}

// Parses exactly one supported private key from PEM.
fn private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, NodePairingTlsError> {
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| NodePairingTlsError::InvalidIdentity)?
        .ok_or(NodePairingTlsError::InvalidIdentity)
}

// Returns the canonical SHA-256 digest of one certificate DER payload.
fn certificate_digest(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    let text = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&text).expect("SHA-256 hex digest")
}

// Returns one absolute operation deadline.
fn deadline(timeout: Duration) -> Result<Instant, NodePairingTlsError> {
    validate_timeout(timeout)?;
    Instant::now()
        .checked_add(timeout)
        .ok_or(NodePairingTlsError::TimedOut)
}

// Returns the remaining positive duration before one complete operation deadline.
fn remaining(deadline: Instant) -> Result<Duration, NodePairingTransportError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(NodePairingTransportError::TimedOut)
}

// Rejects an elapsed server deadline.
fn ensure_deadline(deadline: Instant) -> Result<(), NodePairingTlsError> {
    (Instant::now() < deadline)
        .then_some(())
        .ok_or(NodePairingTlsError::TimedOut)
}

// Requires one complete operation timeout to remain within the hard public bound.
fn validate_timeout(timeout: Duration) -> Result<(), NodePairingTlsError> {
    if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
        return Err(NodePairingTlsError::InvalidConfiguration);
    }
    Ok(())
}

// Rejects one explicitly cancelled client operation.
fn require_not_cancelled(
    cancellation: &dyn NodePairingCancellationPort,
) -> Result<(), NodePairingTransportError> {
    (!cancellation.is_cancelled())
        .then_some(())
        .ok_or(NodePairingTransportError::Cancelled)
}

// Maps nonblocking transport outcomes into stable server TLS failures.
fn network_error(error: NodePrivateRemoteNetworkError) -> NodePairingTlsError {
    match error {
        NodePrivateRemoteNetworkError::TimedOut => NodePairingTlsError::TimedOut,
        _ => NodePairingTlsError::ConnectionUnavailable,
    }
}

// Maps one nonblocking transport failure into the std I/O vocabulary rustls consumes.
fn network_io_error(error: NodePrivateRemoteNetworkError) -> std::io::Error {
    let kind = match error {
        NodePrivateRemoteNetworkError::TimedOut => std::io::ErrorKind::TimedOut,
        NodePrivateRemoteNetworkError::Interrupted => std::io::ErrorKind::Interrupted,
        NodePrivateRemoteNetworkError::WouldBlock => std::io::ErrorKind::WouldBlock,
        NodePrivateRemoteNetworkError::Unavailable => std::io::ErrorKind::Other,
    };
    std::io::Error::from(kind)
}

// Maps server std I/O without retaining TLS or native diagnostics.
fn io_error(error: std::io::Error) -> NodePairingTlsError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            NodePairingTlsError::TimedOut
        }
        std::io::ErrorKind::InvalidData => NodePairingTlsError::UntrustedPeer,
        _ => NodePairingTlsError::FrameUnavailable,
    }
}

// Maps blocking client std I/O without retaining peer or native diagnostics.
fn blocking_io_error(error: std::io::Error) -> NodePairingTransportError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            NodePairingTransportError::TimedOut
        }
        std::io::ErrorKind::InvalidData => NodePairingTransportError::UntrustedPeer,
        _ => NodePairingTransportError::Unavailable,
    }
}

// Maps dedicated TLS configuration failures into the public client transport domain.
fn transport_tls_error(error: NodePairingTlsError) -> NodePairingTransportError {
    match error {
        NodePairingTlsError::TimedOut => NodePairingTransportError::TimedOut,
        NodePairingTlsError::Cancelled => NodePairingTransportError::Cancelled,
        NodePairingTlsError::UntrustedPeer => NodePairingTransportError::UntrustedPeer,
        NodePairingTlsError::RequestRejected | NodePairingTlsError::FrameUnavailable => {
            NodePairingTransportError::RequestRejected
        }
        _ => NodePairingTransportError::Unavailable,
    }
}
