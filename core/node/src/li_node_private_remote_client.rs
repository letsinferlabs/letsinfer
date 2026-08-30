// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::{NodeAddress, Sha256Digest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, StreamOwned};
use sha2::{Digest, Sha256};

use crate::{
    NodePairingCancellationPort, NodePrivateRemoteTlsFileProvider,
    SystemNodePrivateRemoteTlsFileProvider, NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES,
    NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

const MAXIMUM_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAXIMUM_PRIVATE_KEY_BYTES: usize = 128 * 1024;
const MAXIMUM_RESOLVED_ADDRESSES: usize = 8;
const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(60);

// Names closed paired-client failures without retaining addresses, paths, or TLS diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateRemoteClientError {
    InvalidConfiguration,
    UnsafeFile,
    MalformedCertificate,
    MalformedPrivateKey,
    Unavailable,
    TimedOut,
    Cancelled,
    UntrustedPeer,
    RequestTooLarge,
    ResponseTooLarge,
    MalformedResponse,
}

impl fmt::Display for NodePrivateRemoteClientError {
    // Presents stable redacted language for the private paired-client boundary.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("paired private Node client configuration is invalid")
            }
            Self::UnsafeFile => formatter.write_str("paired private Node identity file is unsafe"),
            Self::MalformedCertificate => {
                formatter.write_str("paired private Node certificate is malformed")
            }
            Self::MalformedPrivateKey => {
                formatter.write_str("paired private Node key is malformed")
            }
            Self::Unavailable => formatter.write_str("paired private Node endpoint is unavailable"),
            Self::TimedOut => formatter.write_str("paired private Node request timed out"),
            Self::Cancelled => formatter.write_str("paired private Node request was cancelled"),
            Self::UntrustedPeer => formatter.write_str("paired private Node peer is untrusted"),
            Self::RequestTooLarge => {
                formatter.write_str("paired private Node request is oversized")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("paired private Node response is oversized")
            }
            Self::MalformedResponse => {
                formatter.write_str("paired private Node response is malformed")
            }
        }
    }
}

impl Error for NodePrivateRemoteClientError {}

// Binds one child certificate and its existing local identity key to exact owner-only files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateRemoteClientFileSet {
    owner_user_id: u32,
    client_certificate_file: PathBuf,
    client_private_key_file: PathBuf,
}

impl NodePrivateRemoteClientFileSet {
    // Creates one file set only from distinct absolute certificate and private-key paths.
    pub fn new(
        owner_user_id: u32,
        client_certificate_file: PathBuf,
        client_private_key_file: PathBuf,
    ) -> Result<Self, NodePrivateRemoteClientError> {
        if !client_certificate_file.is_absolute()
            || !client_private_key_file.is_absolute()
            || client_certificate_file == client_private_key_file
        {
            return Err(NodePrivateRemoteClientError::InvalidConfiguration);
        }
        Ok(Self {
            owner_user_id,
            client_certificate_file,
            client_private_key_file,
        })
    }
}

// Exchanges one complete private v1 document through the paired child identity.
pub trait NodePrivateRemoteClientPort: Send + Sync {
    // Applies one non-extendable deadline, cancellation source, and response allocation bound.
    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &self,
        address: &NodeAddress,
        port: u16,
        expected_server_certificate_sha256: &Sha256Digest,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
        cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<Vec<u8>, NodePrivateRemoteClientError>;
}

// Owns one strict TLS 1.3 client identity loaded before any remote connection begins.
pub struct SystemNodePrivateRemoteClient {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl SystemNodePrivateRemoteClient {
    // Loads exact owner-only identity files through the existing no-follow capability.
    pub fn load(
        files: &NodePrivateRemoteClientFileSet,
        provider: &dyn NodePrivateRemoteTlsFileProvider,
    ) -> Result<Self, NodePrivateRemoteClientError> {
        let certificate = private_file(
            provider,
            &files.client_certificate_file,
            files.owner_user_id,
            MAXIMUM_CERTIFICATE_BYTES,
        )?;
        let private_key = private_file(
            provider,
            &files.client_private_key_file,
            files.owner_user_id,
            MAXIMUM_PRIVATE_KEY_BYTES,
        )?;
        Ok(Self {
            certificate_chain: certificates(&certificate)?,
            private_key: private_key_value(&private_key)?,
        })
    }

    // Loads the production paired client from no-follow native file observations.
    pub fn open(
        files: &NodePrivateRemoteClientFileSet,
    ) -> Result<Self, NodePrivateRemoteClientError> {
        Self::load(files, &SystemNodePrivateRemoteTlsFileProvider)
    }
}

impl NodePrivateRemoteClientPort for SystemNodePrivateRemoteClient {
    // Performs one exact certificate-pinned mTLS request without discovery or fallback.
    fn exchange(
        &self,
        address: &NodeAddress,
        port: u16,
        expected_server_certificate_sha256: &Sha256Digest,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
        cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<Vec<u8>, NodePrivateRemoteClientError> {
        validate_exchange(port, request, timeout, maximum_response_bytes)?;
        require_active(cancellation)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(NodePrivateRemoteClientError::TimedOut)?;
        let addresses = (address.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| NodePrivateRemoteClientError::Unavailable)?
            .take(MAXIMUM_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAXIMUM_RESOLVED_ADDRESSES {
            return Err(NodePrivateRemoteClientError::Unavailable);
        }
        let mut socket = None;
        for resolved in addresses {
            require_active(cancellation)?;
            let remaining = remaining(deadline)?;
            if let Ok(candidate) = TcpStream::connect_timeout(&resolved, remaining) {
                socket = Some(candidate);
                break;
            }
        }
        let socket = socket.ok_or(NodePrivateRemoteClientError::Unavailable)?;
        let remaining = remaining(deadline)?;
        socket
            .set_read_timeout(Some(remaining))
            .and_then(|()| socket.set_write_timeout(Some(remaining)))
            .and_then(|()| socket.set_nodelay(true))
            .map_err(|_| NodePrivateRemoteClientError::Unavailable)?;
        let verifier = Arc::new(PinnedNodeServerVerifier::new(
            expected_server_certificate_sha256.clone(),
        ));
        let client = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(self.certificate_chain.clone(), self.private_key.clone_key())
            .map_err(|_| NodePrivateRemoteClientError::InvalidConfiguration)?;
        let server_name = ServerName::try_from("node.letsinfer.invalid")
            .map_err(|_| NodePrivateRemoteClientError::InvalidConfiguration)?;
        let connection = ClientConnection::new(Arc::new(client), server_name)
            .map_err(|_| NodePrivateRemoteClientError::Unavailable)?;
        let mut stream = StreamOwned::new(connection, socket);
        require_active(cancellation)?;
        write_frame(&mut stream, request, deadline)?;
        require_active(cancellation)?;
        let response = read_frame(&mut stream, maximum_response_bytes, deadline)?;
        require_active(cancellation)?;
        Ok(response)
    }
}

// Verifies only the exact pairing-bound server leaf while retaining TLS signature proof.
#[derive(Debug)]
struct PinnedNodeServerVerifier {
    expected: Sha256Digest,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedNodeServerVerifier {
    // Creates one verifier from the exact pairing membership fingerprint.
    fn new(expected: Sha256Digest) -> Self {
        Self {
            expected,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedNodeServerVerifier {
    // Requires one exact leaf and refuses alternate intermediate paths.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() || digest(end_entity.as_ref()) != self.expected {
            return Err(rustls::Error::General(
                "paired Node certificate mismatch".to_string(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    // Refuses TLS 1.2 because production configuration enables only TLS 1.3.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".to_string()))
    }

    // Uses rustls' provider algorithms to verify the exact pinned leaf's handshake signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    // Returns only the signature schemes backed by the selected rustls provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// Requires useful bounded exchange inputs before DNS or file-independent network work.
fn validate_exchange(
    port: u16,
    request: &[u8],
    timeout: Duration,
    maximum_response_bytes: usize,
) -> Result<(), NodePrivateRemoteClientError> {
    if port == 0 || timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
        return Err(NodePrivateRemoteClientError::InvalidConfiguration);
    }
    if request.is_empty() || request.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateRemoteClientError::RequestTooLarge);
    }
    if maximum_response_bytes == 0 || maximum_response_bytes > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateRemoteClientError::ResponseTooLarge);
    }
    Ok(())
}

// Reads one exact response frame under the caller's complete deadline and allocation bound.
fn read_frame(
    stream: &mut impl Read,
    maximum_response_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NodePrivateRemoteClientError> {
    ensure_deadline(deadline)?;
    let mut header = [0_u8; NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES];
    stream.read_exact(&mut header).map_err(classify_io_error)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(NodePrivateRemoteClientError::MalformedResponse);
    }
    if length > maximum_response_bytes || length > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateRemoteClientError::ResponseTooLarge);
    }
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .map_err(classify_io_error)?;
    ensure_deadline(deadline)?;
    Ok(response)
}

// Writes one exact request frame under the caller's complete deadline.
fn write_frame(
    stream: &mut impl Write,
    request: &[u8],
    deadline: Instant,
) -> Result<(), NodePrivateRemoteClientError> {
    ensure_deadline(deadline)?;
    let length =
        u32::try_from(request.len()).map_err(|_| NodePrivateRemoteClientError::RequestTooLarge)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(request))
        .and_then(|()| stream.flush())
        .map_err(classify_io_error)?;
    ensure_deadline(deadline)
}

// Reads one provider-validated private file and rechecks its retained metadata shape.
fn private_file(
    provider: &dyn NodePrivateRemoteTlsFileProvider,
    path: &std::path::Path,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<Vec<u8>, NodePrivateRemoteClientError> {
    let file = provider
        .read_no_follow(path, owner_user_id, maximum_bytes)
        .map_err(|_| NodePrivateRemoteClientError::UnsafeFile)?;
    if file.owner_uid() != owner_user_id
        || file.mode() != 0o600
        || file.link_count() != 1
        || !file.is_regular_file()
        || file.bytes().is_empty()
        || file.bytes().len() > maximum_bytes
    {
        return Err(NodePrivateRemoteClientError::UnsafeFile);
    }
    Ok(file.bytes().to_vec())
}

// Parses one certificate-only PEM chain containing at least one certificate.
fn certificates(
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, NodePrivateRemoteClientError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NodePrivateRemoteClientError::MalformedCertificate)?;
    let values = items
        .into_iter()
        .map(|item| match item {
            rustls_pemfile::Item::X509Certificate(certificate) => Ok(certificate),
            _ => Err(NodePrivateRemoteClientError::MalformedCertificate),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Err(NodePrivateRemoteClientError::MalformedCertificate);
    }
    Ok(values)
}

// Parses exactly one supported PEM private key.
fn private_key_value(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, NodePrivateRemoteClientError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NodePrivateRemoteClientError::MalformedPrivateKey)?;
    if items.len() != 1 {
        return Err(NodePrivateRemoteClientError::MalformedPrivateKey);
    }
    match items.into_iter().next() {
        Some(rustls_pemfile::Item::Pkcs1Key(key)) => Ok(key.into()),
        Some(rustls_pemfile::Item::Pkcs8Key(key)) => Ok(key.into()),
        Some(rustls_pemfile::Item::Sec1Key(key)) => Ok(key.into()),
        _ => Err(NodePrivateRemoteClientError::MalformedPrivateKey),
    }
}

// Returns the canonical SHA-256 identity of one certificate DER document.
fn digest(bytes: &[u8]) -> Sha256Digest {
    let value = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&value).expect("SHA-256 encoding is canonical")
}

// Rejects work immediately after an externally requested cancellation.
fn require_active(
    cancellation: &dyn NodePairingCancellationPort,
) -> Result<(), NodePrivateRemoteClientError> {
    if cancellation.is_cancelled() {
        Err(NodePrivateRemoteClientError::Cancelled)
    } else {
        Ok(())
    }
}

// Returns only positive time remaining under one non-extendable deadline.
fn remaining(deadline: Instant) -> Result<Duration, NodePrivateRemoteClientError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(NodePrivateRemoteClientError::TimedOut)
    } else {
        Ok(remaining)
    }
}

// Requires the complete exchange deadline to remain open after each blocking stage.
fn ensure_deadline(deadline: Instant) -> Result<(), NodePrivateRemoteClientError> {
    remaining(deadline).map(|_| ())
}

// Maps native I/O into a closed timeout-or-availability result.
fn classify_io_error(error: std::io::Error) -> NodePrivateRemoteClientError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        NodePrivateRemoteClientError::TimedOut
    } else if error.kind() == std::io::ErrorKind::InvalidData {
        NodePrivateRemoteClientError::UntrustedPeer
    } else {
        NodePrivateRemoteClientError::Unavailable
    }
}
