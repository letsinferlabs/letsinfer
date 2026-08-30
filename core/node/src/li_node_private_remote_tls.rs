// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::{ControllerId, CredentialId, Sha256Digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};

use crate::{
    NodePrivateEndpoint, NodePrivateRemoteConnectionService, NodePrivateRemoteNetworkError,
    NodePrivateRemoteNetworkStream, NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES,
    NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 128 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_HANDSHAKE_TRANSITIONS: usize = 256;

// Names stable TLS, peer, frame, and endpoint failures without retaining untrusted bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateRemoteTlsError {
    InvalidFileSet,
    FileUnavailable,
    UnsafeFile,
    MalformedCertificate,
    MalformedPrivateKey,
    InvalidClientAuthority,
    InvalidServerIdentity,
    InvalidTimeout,
    TlsUnavailable,
    HandshakeRejected,
    PeerCertificateMissing,
    PrincipalRejected,
    TimedOut,
    FrameUnavailable,
    FrameTruncated,
    EmptyDocument,
    OversizedDocument,
    ZeroProgress,
    EndpointRejected,
    CloseFailed,
}

impl fmt::Display for NodePrivateRemoteTlsError {
    // Presents fixed redacted language without paths, certificates, documents, or native text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFileSet => formatter.write_str("private Node TLS files are invalid"),
            Self::FileUnavailable => formatter.write_str("private Node TLS file is unavailable"),
            Self::UnsafeFile => formatter.write_str("private Node TLS file metadata is unsafe"),
            Self::MalformedCertificate => {
                formatter.write_str("private Node TLS certificate is malformed")
            }
            Self::MalformedPrivateKey => {
                formatter.write_str("private Node TLS private key is malformed")
            }
            Self::InvalidClientAuthority => {
                formatter.write_str("private Node client certificate authority is invalid")
            }
            Self::InvalidServerIdentity => {
                formatter.write_str("private Node TLS server identity is invalid")
            }
            Self::InvalidTimeout => formatter.write_str("private Node TLS timeout is invalid"),
            Self::TlsUnavailable => formatter.write_str("private Node TLS is unavailable"),
            Self::HandshakeRejected => {
                formatter.write_str("private Node TLS handshake was rejected")
            }
            Self::PeerCertificateMissing => {
                formatter.write_str("private Node peer certificate is missing")
            }
            Self::PrincipalRejected => {
                formatter.write_str("private Node remote principal is unauthorized")
            }
            Self::TimedOut => formatter.write_str("private Node remote connection timed out"),
            Self::FrameUnavailable => formatter.write_str("private Node remote frame I/O failed"),
            Self::FrameTruncated => formatter.write_str("private Node remote frame is truncated"),
            Self::EmptyDocument => formatter.write_str("private Node remote frame is empty"),
            Self::OversizedDocument => {
                formatter.write_str("private Node remote frame is oversized")
            }
            Self::ZeroProgress => formatter.write_str("private Node remote frame made no progress"),
            Self::EndpointRejected => {
                formatter.write_str("private Node endpoint rejected the request")
            }
            Self::CloseFailed => formatter.write_str("private Node remote connection close failed"),
        }
    }
}

impl Error for NodePrivateRemoteTlsError {}

// Binds one server identity and client authority to exact owner-only file references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateRemoteTlsFileSet {
    owner_uid: u32,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    client_ca_file: PathBuf,
    additional_client_ca_file: Option<PathBuf>,
}

impl NodePrivateRemoteTlsFileSet {
    // Creates one file set only from three distinct absolute references.
    pub fn new(
        owner_uid: u32,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        client_ca_file: PathBuf,
    ) -> Result<Self, NodePrivateRemoteTlsError> {
        let paths = [
            &server_certificate_file,
            &server_private_key_file,
            &client_ca_file,
        ];
        let unique = paths
            .iter()
            .enumerate()
            .all(|(index, path)| paths.iter().skip(index + 1).all(|other| path != other));
        if paths.iter().any(|path| !path.is_absolute()) || !unique {
            return Err(NodePrivateRemoteTlsError::InvalidFileSet);
        }
        Ok(Self {
            owner_uid,
            server_certificate_file,
            server_private_key_file,
            client_ca_file,
            additional_client_ca_file: None,
        })
    }

    // Adds one distinct controller authority without merging its identity with the peer CA.
    pub fn with_additional_client_ca_file(
        mut self,
        additional_client_ca_file: PathBuf,
    ) -> Result<Self, NodePrivateRemoteTlsError> {
        if !additional_client_ca_file.is_absolute()
            || [
                &self.server_certificate_file,
                &self.server_private_key_file,
                &self.client_ca_file,
            ]
            .contains(&&additional_client_ca_file)
        {
            return Err(NodePrivateRemoteTlsError::InvalidFileSet);
        }
        self.additional_client_ca_file = Some(additional_client_ca_file);
        Ok(self)
    }

    // Returns the exact owner identity required for every TLS input.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
}

// Carries one no-follow file observation without granting transport direct filesystem access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateRemoteTlsFile {
    owner_uid: u32,
    mode: u32,
    link_count: u64,
    regular_file: bool,
    bytes: Vec<u8>,
}

impl NodePrivateRemoteTlsFile {
    // Creates one exact descriptor-shaped file observation for an injected provider.
    pub fn new(
        owner_uid: u32,
        mode: u32,
        link_count: u64,
        regular_file: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_uid,
            mode,
            link_count,
            regular_file,
            bytes,
        }
    }

    // Returns the observed file owner identity.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    // Returns the observed permission bits without file-type bits.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    // Returns the observed hard-link count.
    pub const fn link_count(&self) -> u64 {
        self.link_count
    }

    // Reports whether the opened descriptor references a regular file.
    pub const fn is_regular_file(&self) -> bool {
        self.regular_file
    }

    // Returns the exact bounded bytes copied from the opened descriptor.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for NodePrivateRemoteTlsFile {
    // Clears every injected or system-read TLS input copy before releasing its allocation.
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

// Reads one exact bounded TLS input without following its final path component.
pub trait NodePrivateRemoteTlsFileProvider: Send + Sync {
    // Returns one descriptor-shaped observation only after the provider's no-follow open.
    fn read_no_follow(
        &self,
        path: &Path,
        owner_uid: u32,
        maximum_bytes: usize,
    ) -> Result<NodePrivateRemoteTlsFile, NodePrivateRemoteTlsError>;
}

// Supplies the production no-follow, close-on-exec TLS file reader.
#[derive(Default)]
pub struct SystemNodePrivateRemoteTlsFileProvider;

impl NodePrivateRemoteTlsFileProvider for SystemNodePrivateRemoteTlsFileProvider {
    // Opens, verifies, reads, and re-verifies one owner-only single-link regular file.
    fn read_no_follow(
        &self,
        path: &Path,
        owner_uid: u32,
        maximum_bytes: usize,
    ) -> Result<NodePrivateRemoteTlsFile, NodePrivateRemoteTlsError> {
        read_system_private_file(path, owner_uid, maximum_bytes)
    }
}

// Owns one TLS 1.3 server policy that requires a client certificate under the exact CA.
pub struct NodePrivateRemoteTlsConfiguration {
    server: Arc<ServerConfig>,
}

impl NodePrivateRemoteTlsConfiguration {
    // Loads strict private files and constructs one certificate-required TLS 1.3 policy.
    pub fn load(
        files: &NodePrivateRemoteTlsFileSet,
        provider: &dyn NodePrivateRemoteTlsFileProvider,
    ) -> Result<Self, NodePrivateRemoteTlsError> {
        let server_certificates = private_file(
            provider,
            &files.server_certificate_file,
            files.owner_uid,
            MAX_CERTIFICATE_BYTES,
        )?;
        let server_private_key = private_file(
            provider,
            &files.server_private_key_file,
            files.owner_uid,
            MAX_PRIVATE_KEY_BYTES,
        )?;
        let client_ca = private_file(
            provider,
            &files.client_ca_file,
            files.owner_uid,
            MAX_CERTIFICATE_BYTES,
        )?;
        let additional_client_ca = files
            .additional_client_ca_file
            .as_ref()
            .map(|path| private_file(provider, path, files.owner_uid, MAX_CERTIFICATE_BYTES))
            .transpose()?;
        let server_certificates = certificates(server_certificates.bytes())?;
        let server_private_key = private_key(server_private_key.bytes())?;
        let client_ca = certificates(client_ca.bytes())?;
        let mut roots = RootCertStore::empty();
        let (mut added, mut ignored) = roots.add_parsable_certificates(client_ca);
        if let Some(additional) = additional_client_ca {
            let (additional_added, additional_ignored) =
                roots.add_parsable_certificates(certificates(additional.bytes())?);
            added += additional_added;
            ignored += additional_ignored;
        }
        if added == 0 || ignored != 0 {
            return Err(NodePrivateRemoteTlsError::InvalidClientAuthority);
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| NodePrivateRemoteTlsError::InvalidClientAuthority)?;
        let server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certificates, server_private_key)
            .map_err(|_| NodePrivateRemoteTlsError::InvalidServerIdentity)?;
        Ok(Self {
            server: Arc::new(server),
        })
    }

    // Returns the immutable rustls policy for one server connection lifecycle.
    pub fn server_configuration(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.server)
    }
}

// Keeps paired-node and controller identities distinct after one authenticated TLS handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePrivateRemotePrincipal {
    Peer(CredentialId),
    Controller {
        controller_id: ControllerId,
        certificate_sha256: Sha256Digest,
    },
}

// Resolves one authenticated leaf digest to exactly one active remote principal.
pub trait NodePrivatePrincipalResolver: Send + Sync {
    // Returns one paired peer or controller identity without merging their durable stores.
    fn principal_for_certificate(
        &self,
        peer_leaf_sha256: &Sha256Digest,
    ) -> Result<NodePrivateRemotePrincipal, NodePrivateRemoteTlsError>;
}

// Handles one already-authenticated document through the existing remote Node endpoint.
pub trait NodePrivateRemoteDocumentEndpoint: Send + Sync {
    // Returns one existing v1 response document for the exact resolved credential.
    fn handle_document(
        &self,
        principal: &NodePrivateRemotePrincipal,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateRemoteTlsError>;
}

impl NodePrivateRemoteDocumentEndpoint for NodePrivateEndpoint {
    // Delegates decode, action authorization, manager dispatch, and response encoding unchanged.
    fn handle_document(
        &self,
        principal: &NodePrivateRemotePrincipal,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateRemoteTlsError> {
        match principal {
            NodePrivateRemotePrincipal::Peer(credential_id) => self.handle(credential_id, document),
            NodePrivateRemotePrincipal::Controller {
                controller_id,
                certificate_sha256,
            } => self.handle_controller(controller_id, certificate_sha256, document),
        }
        .map_err(|_| NodePrivateRemoteTlsError::EndpointRejected)
    }
}

// Supplies authenticated plaintext I/O without exposing the TLS engine to endpoint policy.
pub trait NodePrivateRemoteSecureStream {
    // Reads one available plaintext fragment before the absolute frame deadline.
    fn read_bytes(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError>;

    // Writes one available plaintext fragment before the absolute frame deadline.
    fn write_bytes(
        &mut self,
        buffer: &[u8],
        deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError>;
}

// Owns peer resolution, one framed request, endpoint dispatch, and one framed response.
pub struct NodePrivateAuthenticatedConnectionHandler {
    endpoint: Arc<dyn NodePrivateRemoteDocumentEndpoint>,
    resolver: Arc<dyn NodePrivatePrincipalResolver>,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl NodePrivateAuthenticatedConnectionHandler {
    // Creates one handler only from positive hard complete-frame deadlines.
    pub fn new(
        endpoint: Arc<dyn NodePrivateRemoteDocumentEndpoint>,
        resolver: Arc<dyn NodePrivatePrincipalResolver>,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, NodePrivateRemoteTlsError> {
        validate_timeout(read_timeout)?;
        validate_timeout(write_timeout)?;
        Ok(Self {
            endpoint,
            resolver,
            read_timeout,
            write_timeout,
        })
    }

    // Resolves the exact peer before reading or dispatching one request document.
    pub fn handle(
        &self,
        peer_leaf_sha256: &Sha256Digest,
        stream: &mut dyn NodePrivateRemoteSecureStream,
    ) -> Result<(), NodePrivateRemoteTlsError> {
        let principal = self
            .resolver
            .principal_for_certificate(peer_leaf_sha256)
            .map_err(|_| NodePrivateRemoteTlsError::PrincipalRejected)?;
        let read_deadline = deadline(self.read_timeout)?;
        let request = read_frame(stream, read_deadline)?;
        let response = self.endpoint.handle_document(&principal, &request)?;
        let write_deadline = deadline(self.write_timeout)?;
        write_frame(stream, &response, write_deadline)
    }

    // Returns the bounded response and close-notify deadline used by production TLS.
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
}

// Owns production rustls handshake and authenticated framed endpoint composition.
pub struct NodePrivateRemoteTlsConnectionService {
    tls: Arc<ServerConfig>,
    handler: Arc<NodePrivateAuthenticatedConnectionHandler>,
    handshake_timeout: Duration,
}

impl NodePrivateRemoteTlsConnectionService {
    // Creates one service only from one positive hard handshake deadline.
    pub fn new(
        tls: NodePrivateRemoteTlsConfiguration,
        handler: Arc<NodePrivateAuthenticatedConnectionHandler>,
        handshake_timeout: Duration,
    ) -> Result<Self, NodePrivateRemoteTlsError> {
        validate_timeout(handshake_timeout)?;
        Ok(Self {
            tls: tls.server_configuration(),
            handler,
            handshake_timeout,
        })
    }

    // Performs mTLS, exact peer resolution, one request/response, and one close.
    pub fn handle_connection(
        &self,
        mut network: Box<dyn NodePrivateRemoteNetworkStream>,
    ) -> Result<(), NodePrivateRemoteTlsError> {
        let result = self.handle_open(network.as_mut());
        let close = network
            .close()
            .map_err(|_| NodePrivateRemoteTlsError::CloseFailed);
        match result {
            Err(error) => Err(error),
            Ok(()) => close,
        }
    }

    // Completes the authenticated exchange before the outer symmetric close boundary.
    fn handle_open(
        &self,
        network: &mut dyn NodePrivateRemoteNetworkStream,
    ) -> Result<(), NodePrivateRemoteTlsError> {
        let mut connection = ServerConnection::new(Arc::clone(&self.tls))
            .map_err(|_| NodePrivateRemoteTlsError::TlsUnavailable)?;
        complete_handshake(&mut connection, network, deadline(self.handshake_timeout)?)?;
        let peer_leaf_sha256 = peer_leaf_digest(connection.peer_certificates())?;
        let mut secure = RustlsNodePrivateSecureStream {
            connection: &mut connection,
            network,
        };
        self.handler.handle(&peer_leaf_sha256, &mut secure)?;
        secure.close_notify(deadline(self.handler.write_timeout())?)
    }
}

impl NodePrivateRemoteConnectionService for NodePrivateRemoteTlsConnectionService {
    // Isolates every redacted connection failure inside its bounded listener worker.
    fn serve(&self, stream: Box<dyn NodePrivateRemoteNetworkStream>) {
        let _ = self.handle_connection(stream);
    }
}

// Adapts rustls plaintext reads and writes to one injected encrypted network stream.
struct RustlsNodePrivateSecureStream<'a> {
    connection: &'a mut ServerConnection,
    network: &'a mut dyn NodePrivateRemoteNetworkStream,
}

impl RustlsNodePrivateSecureStream<'_> {
    // Queues and flushes one TLS close-notify record before the absolute deadline.
    fn close_notify(&mut self, deadline: Instant) -> Result<(), NodePrivateRemoteTlsError> {
        self.connection.send_close_notify();
        flush_tls(self.connection, self.network, deadline)
    }
}

impl NodePrivateRemoteSecureStream for RustlsNodePrivateSecureStream<'_> {
    // Returns available plaintext or drives one bounded encrypted read until it exists.
    fn read_bytes(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError> {
        loop {
            ensure_deadline(deadline)?;
            match self.connection.reader().read(buffer) {
                Ok(count) if count > 0 => return Ok(count),
                Ok(0) => return Ok(0),
                Ok(_) => return Err(NodePrivateRemoteTlsError::FrameUnavailable),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    read_tls(self.connection, self.network, deadline)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(NodePrivateRemoteTlsError::FrameUnavailable),
            }
        }
    }

    // Queues one plaintext fragment and flushes its encrypted records before returning.
    fn write_bytes(
        &mut self,
        buffer: &[u8],
        deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError> {
        ensure_deadline(deadline)?;
        let count = self
            .connection
            .writer()
            .write(buffer)
            .map_err(|_| NodePrivateRemoteTlsError::FrameUnavailable)?;
        flush_tls(self.connection, self.network, deadline)?;
        Ok(count)
    }
}

// Reads one exact fixed-header response document before one absolute deadline.
fn read_frame(
    stream: &mut dyn NodePrivateRemoteSecureStream,
    deadline: Instant,
) -> Result<Vec<u8>, NodePrivateRemoteTlsError> {
    let mut header = [0_u8; NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(NodePrivateRemoteTlsError::EmptyDocument);
    }
    if length > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateRemoteTlsError::OversizedDocument);
    }
    let mut document = vec![0_u8; length];
    read_exact(stream, &mut document, deadline)?;
    Ok(document)
}

// Writes one exact fixed-header response document before one absolute deadline.
fn write_frame(
    stream: &mut dyn NodePrivateRemoteSecureStream,
    document: &[u8],
    deadline: Instant,
) -> Result<(), NodePrivateRemoteTlsError> {
    if document.is_empty() {
        return Err(NodePrivateRemoteTlsError::EmptyDocument);
    }
    if document.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateRemoteTlsError::OversizedDocument);
    }
    let length =
        u32::try_from(document.len()).map_err(|_| NodePrivateRemoteTlsError::OversizedDocument)?;
    write_all(stream, &length.to_be_bytes(), deadline)?;
    write_all(stream, document, deadline)
}

// Reads every frame byte across fragmentation without extending its deadline.
fn read_exact(
    stream: &mut dyn NodePrivateRemoteSecureStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), NodePrivateRemoteTlsError> {
    while !buffer.is_empty() {
        ensure_deadline(deadline)?;
        match stream.read_bytes(buffer, deadline) {
            Ok(0) => return Err(NodePrivateRemoteTlsError::FrameTruncated),
            Ok(count) if count <= buffer.len() => {
                let (_, remaining) = buffer.split_at_mut(count);
                buffer = remaining;
            }
            Ok(_) => return Err(NodePrivateRemoteTlsError::FrameUnavailable),
            Err(error) => return Err(error),
        }
    }
    ensure_deadline(deadline)
}

// Writes every frame byte across fragmentation and rejects zero progress.
fn write_all(
    stream: &mut dyn NodePrivateRemoteSecureStream,
    mut buffer: &[u8],
    deadline: Instant,
) -> Result<(), NodePrivateRemoteTlsError> {
    while !buffer.is_empty() {
        ensure_deadline(deadline)?;
        match stream.write_bytes(buffer, deadline) {
            Ok(0) => return Err(NodePrivateRemoteTlsError::ZeroProgress),
            Ok(count) if count <= buffer.len() => buffer = &buffer[count..],
            Ok(_) => return Err(NodePrivateRemoteTlsError::FrameUnavailable),
            Err(error) => return Err(error),
        }
    }
    ensure_deadline(deadline)
}

// Completes one real TLS 1.3 server handshake under transition and time bounds.
fn complete_handshake(
    connection: &mut ServerConnection,
    network: &mut dyn NodePrivateRemoteNetworkStream,
    deadline: Instant,
) -> Result<(), NodePrivateRemoteTlsError> {
    for _ in 0..MAX_HANDSHAKE_TRANSITIONS {
        ensure_deadline(deadline)?;
        if connection.wants_write() {
            flush_tls(connection, network, deadline)?;
        }
        if !connection.is_handshaking() {
            flush_tls(connection, network, deadline)?;
            return Ok(());
        }
        if connection.wants_read() {
            read_tls(connection, network, deadline)?;
        } else if !connection.wants_write() {
            return Err(NodePrivateRemoteTlsError::HandshakeRejected);
        }
    }
    Err(NodePrivateRemoteTlsError::HandshakeRejected)
}

// Reads and processes one encrypted TLS fragment before the absolute deadline.
fn read_tls(
    connection: &mut ServerConnection,
    network: &mut dyn NodePrivateRemoteNetworkStream,
    deadline: Instant,
) -> Result<(), NodePrivateRemoteTlsError> {
    loop {
        ensure_deadline(deadline)?;
        network.wait_readable(deadline).map_err(network_tls_error)?;
        let mut reader = NetworkReader(network);
        match connection.read_tls(&mut reader) {
            Ok(0) => return Err(NodePrivateRemoteTlsError::HandshakeRejected),
            Ok(_) => {
                connection
                    .process_new_packets()
                    .map_err(|_| NodePrivateRemoteTlsError::HandshakeRejected)?;
                return Ok(());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err(NodePrivateRemoteTlsError::FrameUnavailable),
        }
    }
}

// Flushes every queued encrypted TLS record before the absolute deadline.
fn flush_tls(
    connection: &mut ServerConnection,
    network: &mut dyn NodePrivateRemoteNetworkStream,
    deadline: Instant,
) -> Result<(), NodePrivateRemoteTlsError> {
    while connection.wants_write() {
        ensure_deadline(deadline)?;
        network.wait_writable(deadline).map_err(network_tls_error)?;
        let mut writer = NetworkWriter(network);
        match connection.write_tls(&mut writer) {
            Ok(0) => return Err(NodePrivateRemoteTlsError::ZeroProgress),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return Err(NodePrivateRemoteTlsError::FrameUnavailable),
        }
    }
    ensure_deadline(deadline)
}

// Adapts encrypted network reads to rustls without exposing native error text.
struct NetworkReader<'a>(&'a mut dyn NodePrivateRemoteNetworkStream);

impl Read for NetworkReader<'_> {
    // Reads one available encrypted fragment and retains only its closed error class.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read_bytes(buffer).map_err(network_standard_error)
    }
}

// Adapts encrypted network writes to rustls without exposing native error text.
struct NetworkWriter<'a>(&'a mut dyn NodePrivateRemoteNetworkStream);

impl Write for NetworkWriter<'_> {
    // Writes one available encrypted fragment and retains only its closed error class.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write_bytes(buffer).map_err(network_standard_error)
    }

    // Declares no additional buffering below the injected network capability.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Returns the exact SHA-256 identity of the authenticated peer leaf certificate.
fn peer_leaf_digest(
    certificates: Option<&[CertificateDer<'static>]>,
) -> Result<Sha256Digest, NodePrivateRemoteTlsError> {
    let certificate = certificates
        .and_then(|certificates| certificates.first())
        .ok_or(NodePrivateRemoteTlsError::PeerCertificateMissing)?;
    Sha256Digest::parse(&lower_hex(&Sha256::digest(certificate.as_ref())))
        .map_err(|_| NodePrivateRemoteTlsError::PeerCertificateMissing)
}

// Loads one provider-verified owner-only, single-link regular file into clearing storage.
fn private_file(
    provider: &dyn NodePrivateRemoteTlsFileProvider,
    path: &Path,
    owner_uid: u32,
    maximum_bytes: usize,
) -> Result<NodePrivateRemotePrivateBytes, NodePrivateRemoteTlsError> {
    let file = provider.read_no_follow(path, owner_uid, maximum_bytes)?;
    if file.owner_uid() != owner_uid
        || file.mode() != 0o600
        || file.link_count() != 1
        || !file.is_regular_file()
        || file.bytes().is_empty()
        || file.bytes().len() > maximum_bytes
    {
        return Err(NodePrivateRemoteTlsError::UnsafeFile);
    }
    Ok(NodePrivateRemotePrivateBytes(file.bytes().to_vec()))
}

// Owns one temporary TLS-file copy and clears it after configuration.
struct NodePrivateRemotePrivateBytes(Vec<u8>);

impl NodePrivateRemotePrivateBytes {
    // Returns temporary bytes only to strict PEM parsing.
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for NodePrivateRemotePrivateBytes {
    // Clears temporary file bytes before releasing their allocation.
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

// Parses one certificate-only PEM document with at least one certificate.
fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, NodePrivateRemoteTlsError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NodePrivateRemoteTlsError::MalformedCertificate)?;
    let certificates = items
        .into_iter()
        .map(|item| match item {
            rustls_pemfile::Item::X509Certificate(certificate) => Ok(certificate),
            _ => Err(NodePrivateRemoteTlsError::MalformedCertificate),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(NodePrivateRemoteTlsError::MalformedCertificate);
    }
    Ok(certificates)
}

// Parses one PEM document containing exactly one supported private-key item.
fn private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, NodePrivateRemoteTlsError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NodePrivateRemoteTlsError::MalformedPrivateKey)?;
    if items.len() != 1 {
        return Err(NodePrivateRemoteTlsError::MalformedPrivateKey);
    }
    match items.into_iter().next() {
        Some(rustls_pemfile::Item::Pkcs1Key(key)) => Ok(key.into()),
        Some(rustls_pemfile::Item::Pkcs8Key(key)) => Ok(key.into()),
        Some(rustls_pemfile::Item::Sec1Key(key)) => Ok(key.into()),
        _ => Err(NodePrivateRemoteTlsError::MalformedPrivateKey),
    }
}

// Opens and verifies one no-follow regular file before copying any bytes.
fn read_system_private_file(
    path: &Path,
    owner_uid: u32,
    maximum_bytes: usize,
) -> Result<NodePrivateRemoteTlsFile, NodePrivateRemoteTlsError> {
    if !path.is_absolute() || maximum_bytes == 0 {
        return Err(NodePrivateRemoteTlsError::FileUnavailable);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| NodePrivateRemoteTlsError::FileUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| NodePrivateRemoteTlsError::FileUnavailable)?;
    validate_system_metadata(&before, owner_uid, maximum_bytes)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| NodePrivateRemoteTlsError::FileUnavailable)?;
    if bytes.len() > maximum_bytes {
        bytes.fill(0);
        return Err(NodePrivateRemoteTlsError::UnsafeFile);
    }
    let after = file
        .metadata()
        .map_err(|_| NodePrivateRemoteTlsError::FileUnavailable)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bytes.fill(0);
        return Err(NodePrivateRemoteTlsError::UnsafeFile);
    }
    Ok(NodePrivateRemoteTlsFile::new(
        after.uid(),
        after.mode() & 0o777,
        after.nlink(),
        after.file_type().is_file(),
        bytes,
    ))
}

// Requires owner-only, single-link, bounded regular metadata before reading.
fn validate_system_metadata(
    metadata: &std::fs::Metadata,
    owner_uid: u32,
    maximum_bytes: usize,
) -> Result<(), NodePrivateRemoteTlsError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(NodePrivateRemoteTlsError::UnsafeFile);
    }
    Ok(())
}

// Converts one authenticated digest into canonical lowercase hexadecimal text.
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

// Validates one positive timeout against the fixed remote transport upper bound.
fn validate_timeout(timeout: Duration) -> Result<(), NodePrivateRemoteTlsError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        Err(NodePrivateRemoteTlsError::InvalidTimeout)
    } else {
        Ok(())
    }
}

// Creates one checked absolute deadline for a validated transport duration.
fn deadline(timeout: Duration) -> Result<Instant, NodePrivateRemoteTlsError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(NodePrivateRemoteTlsError::TimedOut)
}

// Requires one complete-operation deadline to remain open at this observation.
fn ensure_deadline(deadline: Instant) -> Result<(), NodePrivateRemoteTlsError> {
    if Instant::now() >= deadline {
        Err(NodePrivateRemoteTlsError::TimedOut)
    } else {
        Ok(())
    }
}

// Maps one closed network wait result into the redacted TLS error domain.
fn network_tls_error(error: NodePrivateRemoteNetworkError) -> NodePrivateRemoteTlsError {
    match error {
        NodePrivateRemoteNetworkError::TimedOut => NodePrivateRemoteTlsError::TimedOut,
        NodePrivateRemoteNetworkError::Interrupted
        | NodePrivateRemoteNetworkError::WouldBlock
        | NodePrivateRemoteNetworkError::Unavailable => NodePrivateRemoteTlsError::FrameUnavailable,
    }
}

// Maps one closed network result into a standard error kind consumed only by rustls.
fn network_standard_error(error: NodePrivateRemoteNetworkError) -> std::io::Error {
    let kind = match error {
        NodePrivateRemoteNetworkError::TimedOut => std::io::ErrorKind::TimedOut,
        NodePrivateRemoteNetworkError::Interrupted => std::io::ErrorKind::Interrupted,
        NodePrivateRemoteNetworkError::WouldBlock => std::io::ErrorKind::WouldBlock,
        NodePrivateRemoteNetworkError::Unavailable => std::io::ErrorKind::Other,
    };
    std::io::Error::from(kind)
}
