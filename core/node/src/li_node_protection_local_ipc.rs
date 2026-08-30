// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::{
    NodePrivateUnixPathGuard, NodeProtectionApi, NodeProtectionConnection,
    NodeProtectionPeerRoleProvider, NodeProtectionRequest, NodeProtectionResponse,
    NodeProtectionTransport, NodeProtectionTransportOutcome, NodeProtectionTransportRequest,
    NodeProtectionTransportResponse, NODE_PROTECTION_MAX_DOCUMENT_BYTES,
};

const FRAME_HEADER_BYTES: usize = 4;
const MAXIMUM_WORKERS: usize = 64;
const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(60);
const MAXIMUM_ACCEPT_POLL: Duration = Duration::from_secs(1);

// Names stable owner-authenticated protection channel failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionLocalError {
    InvalidConfiguration,
    UnsafeSocket,
    AlreadyRunning,
    EndpointUnavailable,
    AuthenticationFailed,
    FrameInvalid,
    RemoteRejected,
    WorkerUnavailable,
}

impl fmt::Display for NodeProtectionLocalError {
    // Presents fixed channel language without native paths or payloads.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("Node protection channel configuration is invalid")
            }
            Self::UnsafeSocket => formatter.write_str("Node protection socket is unsafe"),
            Self::AlreadyRunning => {
                formatter.write_str("Node protection server is already running")
            }
            Self::EndpointUnavailable => {
                formatter.write_str("Node protection endpoint is unavailable")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("Node protection peer authentication failed")
            }
            Self::FrameInvalid => formatter.write_str("Node protection frame is invalid"),
            Self::RemoteRejected => formatter.write_str("Node protection request was rejected"),
            Self::WorkerUnavailable => formatter.write_str("Node protection worker is unavailable"),
        }
    }
}

impl Error for NodeProtectionLocalError {}

// Holds every explicit native bound for the dedicated persistent protection channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionLocalConfiguration {
    socket_path: PathBuf,
    owner_user_id: u32,
    maximum_workers: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    accept_poll_interval: Duration,
}

// Holds only the explicit owner, path, and frame bounds required by a channel client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionLocalClientConfiguration {
    socket_path: PathBuf,
    owner_user_id: u32,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl NodeProtectionLocalClientConfiguration {
    // Creates one client configuration without inventing server worker or polling values.
    pub fn new(
        socket_path: PathBuf,
        owner_user_id: u32,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, NodeProtectionLocalError> {
        if !socket_path.is_absolute()
            || read_timeout.is_zero()
            || read_timeout > MAXIMUM_TIMEOUT
            || write_timeout.is_zero()
            || write_timeout > MAXIMUM_TIMEOUT
        {
            return Err(NodeProtectionLocalError::InvalidConfiguration);
        }
        Ok(Self {
            socket_path,
            owner_user_id,
            read_timeout,
            write_timeout,
        })
    }

    // Returns the exact owner-private Unix socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the kernel user identity required on the server peer.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns the exact complete-frame read timeout.
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // Returns the exact complete-frame write timeout.
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
}

impl NodeProtectionLocalConfiguration {
    // Creates one configuration only when path, worker, and timing bounds are closed.
    pub fn new(
        socket_path: PathBuf,
        owner_user_id: u32,
        maximum_workers: usize,
        read_timeout: Duration,
        write_timeout: Duration,
        accept_poll_interval: Duration,
    ) -> Result<Self, NodeProtectionLocalError> {
        if !socket_path.is_absolute()
            || maximum_workers == 0
            || maximum_workers > MAXIMUM_WORKERS
            || read_timeout.is_zero()
            || read_timeout > MAXIMUM_TIMEOUT
            || write_timeout.is_zero()
            || write_timeout > MAXIMUM_TIMEOUT
            || accept_poll_interval.is_zero()
            || accept_poll_interval > MAXIMUM_ACCEPT_POLL
        {
            return Err(NodeProtectionLocalError::InvalidConfiguration);
        }
        Ok(Self {
            socket_path,
            owner_user_id,
            maximum_workers,
            read_timeout,
            write_timeout,
            accept_poll_interval,
        })
    }

    // Returns the exact owner-private Unix socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the kernel user identity accepted on both ends.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns the exact complete-frame read timeout.
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // Returns the exact complete-frame write timeout.
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    // Projects the exact client-visible subset without hidden server defaults.
    pub fn client_configuration(&self) -> NodeProtectionLocalClientConfiguration {
        NodeProtectionLocalClientConfiguration {
            socket_path: self.socket_path.clone(),
            owner_user_id: self.owner_user_id,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
        }
    }
}

// Owns a bound listener, all accepted workers, and exact socket cleanup.
pub struct NodeProtectionLocalServer {
    stopping: Arc<AtomicBool>,
    listener: Option<JoinHandle<Result<(), NodeProtectionLocalError>>>,
    socket_path: PathBuf,
    owner_user_id: u32,
    device: u64,
    inode: u64,
    connection_failure: Arc<Mutex<Option<NodeProtectionLocalError>>>,
}

// Removes a newly bound socket if any later startup phase fails before ownership transfers.
struct PendingNodeProtectionSocketCleanup {
    socket_path: PathBuf,
    owner_user_id: u32,
    exact_identity: Option<(u64, u64)>,
    armed: bool,
}

impl PendingNodeProtectionSocketCleanup {
    // Arms safe owner/socket fallback cleanup immediately after bind returns.
    fn new(socket_path: PathBuf, owner_user_id: u32) -> Self {
        Self {
            socket_path,
            owner_user_id,
            exact_identity: None,
            armed: true,
        }
    }

    // Narrows cleanup to the exact device and inode observed for this bind.
    fn bind_exact(&mut self, device: u64, inode: u64) {
        self.exact_identity = Some((device, inode));
    }

    // Transfers cleanup ownership to the live server after the listener thread starts.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingNodeProtectionSocketCleanup {
    // Removes only the just-bound owner socket and never an arbitrary replacement path.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some((device, inode)) = self.exact_identity {
            remove_exact_socket(&self.socket_path, self.owner_user_id, device, inode);
            return;
        }
        let Ok(metadata) = fs::symlink_metadata(&self.socket_path) else {
            return;
        };
        if metadata.file_type().is_socket() && metadata.uid() == self.owner_user_id {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

impl NodeProtectionLocalServer {
    // Binds one owner-only listener before publishing its worker lifecycle.
    pub fn start(
        configuration: NodeProtectionLocalConfiguration,
        api: Arc<NodeProtectionApi>,
        peer_roles: Arc<dyn NodeProtectionPeerRoleProvider>,
    ) -> Result<Self, NodeProtectionLocalError> {
        let _parent = NodePrivateUnixPathGuard::acquire(
            configuration.socket_path(),
            configuration.owner_user_id(),
        )
        .map_err(|_| NodeProtectionLocalError::UnsafeSocket)?;
        prepare_socket(&configuration)?;
        let listener = UnixListener::bind(configuration.socket_path())
            .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
        let mut cleanup = PendingNodeProtectionSocketCleanup::new(
            configuration.socket_path().to_path_buf(),
            configuration.owner_user_id(),
        );
        let bound_metadata = fs::symlink_metadata(configuration.socket_path())
            .map_err(|_| NodeProtectionLocalError::UnsafeSocket)?;
        if !bound_metadata.file_type().is_socket()
            || bound_metadata.uid() != configuration.owner_user_id()
        {
            return Err(NodeProtectionLocalError::UnsafeSocket);
        }
        cleanup.bind_exact(bound_metadata.dev(), bound_metadata.ino());
        fs::set_permissions(
            configuration.socket_path(),
            fs::Permissions::from_mode(0o600),
        )
        .map_err(|_| NodeProtectionLocalError::UnsafeSocket)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
        let metadata = safe_socket_metadata(&configuration)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let connection_failure = Arc::new(Mutex::new(None));
        let worker_stopping = stopping.clone();
        let worker_connection_failure = connection_failure.clone();
        let worker_configuration = configuration.clone();
        let worker = thread::Builder::new()
            .name("li_node_protection_listener".to_string())
            .spawn(move || {
                serve_listener(
                    listener,
                    worker_configuration,
                    api,
                    peer_roles,
                    worker_stopping,
                    worker_connection_failure,
                )
            })
            .map_err(|_| NodeProtectionLocalError::WorkerUnavailable)?;
        cleanup.disarm();
        Ok(Self {
            stopping,
            listener: Some(worker),
            socket_path: configuration.socket_path,
            owner_user_id: configuration.owner_user_id,
            device: metadata.dev(),
            inode: metadata.ino(),
            connection_failure,
        })
    }

    // Requests bounded listener and connection-worker shutdown without coupling other services.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    // Returns the latest isolated connection failure observed by the listener.
    pub fn connection_failure(&self) -> Option<NodeProtectionLocalError> {
        self.connection_failure.lock().ok().and_then(|value| *value)
    }

    // Reports whether the listener worker remains live for process readiness judgment.
    pub fn is_running(&self) -> bool {
        self.listener
            .as_ref()
            .is_some_and(|listener| !listener.is_finished())
    }

    // Joins the listener and every accepted worker before exact socket removal.
    pub fn join(&mut self) -> Result<(), NodeProtectionLocalError> {
        self.stop();
        let result = self
            .listener
            .take()
            .ok_or(NodeProtectionLocalError::WorkerUnavailable)?
            .join()
            .map_err(|_| NodeProtectionLocalError::WorkerUnavailable)?;
        remove_exact_socket(
            &self.socket_path,
            self.owner_user_id,
            self.device,
            self.inode,
        );
        result
    }
}

impl Drop for NodeProtectionLocalServer {
    // Requests shutdown and removes only the exact socket owned by this server instance.
    fn drop(&mut self) {
        self.stop();
        remove_exact_socket(
            &self.socket_path,
            self.owner_user_id,
            self.device,
            self.inode,
        );
    }
}

// Owns one persistent authenticated connection and strict request/response sequencing.
pub struct NodeProtectionLocalClient {
    connection_id: Sha256Digest,
    state: Mutex<NodeProtectionLocalClientState>,
}

// Serializes one stream with its exact request and response sequence high-water marks.
struct NodeProtectionLocalClientState {
    stream: Option<UnixStream>,
    next_request_sequence: u64,
    next_response_sequence: u64,
}

impl NodeProtectionLocalClient {
    // Connects only to an exact owner-private socket under the configured time bounds.
    pub fn connect(
        configuration: &NodeProtectionLocalClientConfiguration,
        connection_id: Sha256Digest,
    ) -> Result<Self, NodeProtectionLocalError> {
        safe_socket_metadata(configuration)?;
        let stream = UnixStream::connect(configuration.socket_path())
            .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
        authenticate_server(&stream, configuration.owner_user_id())?;
        stream
            .set_read_timeout(Some(configuration.read_timeout()))
            .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
        stream
            .set_write_timeout(Some(configuration.write_timeout()))
            .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
        Ok(Self {
            connection_id,
            state: Mutex::new(NodeProtectionLocalClientState {
                stream: Some(stream),
                next_request_sequence: 1,
                next_response_sequence: 1,
            }),
        })
    }

    // Returns the immutable connection identity bound into every closed wire document.
    pub const fn connection_id(&self) -> &Sha256Digest {
        &self.connection_id
    }

    // Exchanges one typed operation while enforcing correlation, connection, and response order.
    pub fn exchange(
        &self,
        request: NodeProtectionRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionLocalError> {
        let response = self.exchange_transport(request)?;
        match response.outcome() {
            NodeProtectionTransportOutcome::Success(response) => Ok(response.clone()),
            NodeProtectionTransportOutcome::Failure(_) => {
                Err(NodeProtectionLocalError::RemoteRejected)
            }
        }
    }

    // Exchanges one request while retaining authenticated response identity for Gateway polling.
    pub fn exchange_transport(
        &self,
        request: NodeProtectionRequest,
    ) -> Result<NodeProtectionTransportResponse, NodeProtectionLocalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
        let result = exchange_open(&self.connection_id, &mut state, request);
        if result.is_err() {
            poison_client(&mut state);
        }
        result
    }
}

// Completes one request only while the caller holds the complete client-state lock.
fn exchange_open(
    connection_id: &Sha256Digest,
    state: &mut NodeProtectionLocalClientState,
    request: NodeProtectionRequest,
) -> Result<NodeProtectionTransportResponse, NodeProtectionLocalError> {
    let stream = state
        .stream
        .as_mut()
        .ok_or(NodeProtectionLocalError::EndpointUnavailable)?;
    let sequence = state.next_request_sequence;
    state.next_request_sequence = state
        .next_request_sequence
        .checked_add(1)
        .ok_or(NodeProtectionLocalError::FrameInvalid)?;
    let request_id = request_identity(connection_id, sequence)?;
    let document = NodeProtectionTransport::encode_request(&NodeProtectionTransportRequest::new(
        request_id.clone(),
        connection_id.clone(),
        request,
    ))
    .map_err(|_| NodeProtectionLocalError::FrameInvalid)?;
    write_frame(stream, &document)?;
    let response =
        read_frame(stream, false)?.ok_or(NodeProtectionLocalError::EndpointUnavailable)?;
    let response = NodeProtectionTransport::decode_response(&response)
        .map_err(|_| NodeProtectionLocalError::FrameInvalid)?;
    let expected_response = state.next_response_sequence;
    state.next_response_sequence = state
        .next_response_sequence
        .checked_add(1)
        .ok_or(NodeProtectionLocalError::FrameInvalid)?;
    if response.request_id() != &request_id
        || response.connection_id() != connection_id
        || response.sequence().get() != expected_response
    {
        return Err(NodeProtectionLocalError::FrameInvalid);
    }
    Ok(response)
}

// Permanently shuts down one ambiguous connection so no later request can reuse it.
fn poison_client(state: &mut NodeProtectionLocalClientState) {
    if let Some(stream) = state.stream.take() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

// Accepts owner-authenticated peers and keeps every connection failure isolated.
fn serve_listener(
    listener: UnixListener,
    configuration: NodeProtectionLocalConfiguration,
    api: Arc<NodeProtectionApi>,
    peer_roles: Arc<dyn NodeProtectionPeerRoleProvider>,
    stopping: Arc<AtomicBool>,
    connection_failure: Arc<Mutex<Option<NodeProtectionLocalError>>>,
) -> Result<(), NodeProtectionLocalError> {
    let mut workers = Vec::<JoinHandle<Result<(), NodeProtectionLocalError>>>::new();
    while !stopping.load(Ordering::Acquire) {
        reap_finished_workers(&mut workers, &connection_failure)?;
        match listener.accept() {
            Ok((stream, _)) if workers.len() < configuration.maximum_workers => {
                let api = api.clone();
                let peer_roles = peer_roles.clone();
                let configuration = configuration.clone();
                let stopping = stopping.clone();
                let worker = thread::Builder::new()
                    .name("li_node_protection_connection".to_string())
                    .spawn(move || {
                        serve_connection(stream, &configuration, api, peer_roles, stopping)
                    })
                    .map_err(|_| NodeProtectionLocalError::WorkerUnavailable)?;
                workers.push(worker);
            }
            Ok((stream, _)) => drop(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(configuration.accept_poll_interval);
            }
            Err(_) => return Err(NodeProtectionLocalError::EndpointUnavailable),
        }
    }
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => record_connection_failure(&connection_failure, error),
            Err(_) => return Err(NodeProtectionLocalError::WorkerUnavailable),
        }
    }
    Ok(())
}

// Joins every completed connection worker and escalates only an uncontained panic.
fn reap_finished_workers(
    workers: &mut Vec<JoinHandle<Result<(), NodeProtectionLocalError>>>,
    connection_failure: &Mutex<Option<NodeProtectionLocalError>>,
) -> Result<(), NodeProtectionLocalError> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => record_connection_failure(connection_failure, error),
                Err(_) => return Err(NodeProtectionLocalError::WorkerUnavailable),
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

// Records one redacted connection failure without terminating independent healthy peers.
fn record_connection_failure(
    connection_failure: &Mutex<Option<NodeProtectionLocalError>>,
    error: NodeProtectionLocalError,
) {
    if let Ok(mut current) = connection_failure.lock() {
        *current = Some(error);
    }
}

// Serves one persistent stream and always applies durable disconnect retirement.
fn serve_connection(
    mut stream: UnixStream,
    configuration: &NodeProtectionLocalConfiguration,
    api: Arc<NodeProtectionApi>,
    peer_roles: Arc<dyn NodeProtectionPeerRoleProvider>,
    stopping: Arc<AtomicBool>,
) -> Result<(), NodeProtectionLocalError> {
    stream
        .set_nonblocking(false)
        .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
    let user_id = peer_user_id(&stream).ok_or(NodeProtectionLocalError::AuthenticationFailed)?;
    if user_id != configuration.owner_user_id() {
        return Err(NodeProtectionLocalError::AuthenticationFailed);
    }
    let process_id =
        peer_process_id(&stream).ok_or(NodeProtectionLocalError::AuthenticationFailed)?;
    let authorization = peer_roles
        .authorize(user_id, process_id)
        .map_err(|_| NodeProtectionLocalError::AuthenticationFailed)?;
    stream
        .set_read_timeout(Some(configuration.read_timeout()))
        .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
    stream
        .set_write_timeout(Some(configuration.write_timeout()))
        .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
    let first = read_frame(&mut stream, true)?.ok_or(NodeProtectionLocalError::FrameInvalid)?;
    let first_request = NodeProtectionTransport::decode_request(&first)
        .map_err(|_| NodeProtectionLocalError::FrameInvalid)?;
    let mut connection = NodeProtectionConnection::new(
        api,
        authorization.principal_id().clone(),
        first_request.connection_id().clone(),
        authorization.role(),
    );
    let first_response = connection
        .handle(&first)
        .map_err(|_| NodeProtectionLocalError::RemoteRejected)?;
    write_frame(&mut stream, &first_response)?;
    let mut result = Ok(());
    while !stopping.load(Ordering::Acquire) {
        match read_frame(&mut stream, true) {
            Ok(Some(document)) => match connection.handle(&document) {
                Ok(response) => {
                    if let Err(error) = write_frame(&mut stream, &response) {
                        result = Err(error);
                        break;
                    }
                }
                Err(_) => {
                    result = Err(NodeProtectionLocalError::RemoteRejected);
                    break;
                }
            },
            Ok(None) => break,
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    let retirement = connection
        .disconnect()
        .map_err(|_| NodeProtectionLocalError::EndpointUnavailable);
    result.and(retirement)
}

// Writes one bounded big-endian length-prefixed document without partial success.
fn write_frame(stream: &mut UnixStream, document: &[u8]) -> Result<(), NodeProtectionLocalError> {
    if document.is_empty() || document.len() > NODE_PROTECTION_MAX_DOCUMENT_BYTES {
        return Err(NodeProtectionLocalError::FrameInvalid);
    }
    let length = u32::try_from(document.len())
        .map_err(|_| NodeProtectionLocalError::FrameInvalid)?
        .to_be_bytes();
    stream
        .write_all(&length)
        .and_then(|_| stream.write_all(document))
        .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)
}

// Reads one bounded frame and distinguishes clean between-request disconnect from truncation.
fn read_frame(
    stream: &mut UnixStream,
    clean_disconnect: bool,
) -> Result<Option<Vec<u8>>, NodeProtectionLocalError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let first = stream
        .read(&mut header[..1])
        .map_err(|_| NodeProtectionLocalError::EndpointUnavailable)?;
    if first == 0 {
        return if clean_disconnect {
            Ok(None)
        } else {
            Err(NodeProtectionLocalError::FrameInvalid)
        };
    }
    stream
        .read_exact(&mut header[1..])
        .map_err(|_| NodeProtectionLocalError::FrameInvalid)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > NODE_PROTECTION_MAX_DOCUMENT_BYTES {
        return Err(NodeProtectionLocalError::FrameInvalid);
    }
    let mut document = vec![0_u8; length];
    stream
        .read_exact(&mut document)
        .map_err(|_| NodeProtectionLocalError::FrameInvalid)?;
    Ok(Some(document))
}

// Derives one deterministic per-connection request identity from a strict local sequence.
fn request_identity(
    connection_id: &Sha256Digest,
    sequence: u64,
) -> Result<Sha256Digest, NodeProtectionLocalError> {
    if sequence == 0 {
        return Err(NodeProtectionLocalError::FrameInvalid);
    }
    let mut digest = Sha256::new();
    digest.update(b"li_node_protection_request_v1");
    digest.update(connection_id.as_str().as_bytes());
    digest.update(sequence.to_be_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeProtectionLocalError::FrameInvalid)
}

// Validates the bound socket's owner, type, and owner-only mode without following links.
fn safe_socket_metadata(
    configuration: &impl NodeProtectionSocketConfiguration,
) -> Result<fs::Metadata, NodeProtectionLocalError> {
    let metadata = fs::symlink_metadata(configuration.socket_path()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            NodeProtectionLocalError::EndpointUnavailable
        } else {
            NodeProtectionLocalError::UnsafeSocket
        }
    })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != configuration.owner_user_id()
        || metadata.mode() & 0o077 != 0
    {
        return Err(NodeProtectionLocalError::UnsafeSocket);
    }
    Ok(metadata)
}

// Supplies the shared path and owner fields needed by exact socket metadata checks.
trait NodeProtectionSocketConfiguration {
    // Returns the exact configured socket path.
    fn socket_path(&self) -> &Path;

    // Returns the exact configured owner user identity.
    fn owner_user_id(&self) -> u32;
}

impl NodeProtectionSocketConfiguration for NodeProtectionLocalConfiguration {
    // Returns the server socket path.
    fn socket_path(&self) -> &Path {
        self.socket_path()
    }

    // Returns the server owner identity.
    fn owner_user_id(&self) -> u32 {
        self.owner_user_id()
    }
}

impl NodeProtectionSocketConfiguration for NodeProtectionLocalClientConfiguration {
    // Returns the client socket path.
    fn socket_path(&self) -> &Path {
        self.socket_path()
    }

    // Returns the required server owner identity.
    fn owner_user_id(&self) -> u32 {
        self.owner_user_id()
    }
}

// Removes only an inactive owner-only stale socket inside an already validated directory.
fn prepare_socket(
    configuration: &NodeProtectionLocalConfiguration,
) -> Result<(), NodeProtectionLocalError> {
    let metadata = match fs::symlink_metadata(configuration.socket_path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(NodeProtectionLocalError::UnsafeSocket),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != configuration.owner_user_id()
        || metadata.mode() & 0o077 != 0
    {
        return Err(NodeProtectionLocalError::UnsafeSocket);
    }
    match UnixStream::connect(configuration.socket_path()) {
        Ok(_) => Err(NodeProtectionLocalError::AlreadyRunning),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(configuration.socket_path())
                .map_err(|_| NodeProtectionLocalError::UnsafeSocket)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NodeProtectionLocalError::UnsafeSocket),
    }
}

// Removes only the exact owner, device, and inode created by this server instance.
fn remove_exact_socket(path: &Path, owner_user_id: u32, device: u64, inode: u64) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket()
        && metadata.uid() == owner_user_id
        && metadata.dev() == device
        && metadata.ino() == inode
    {
        let _ = fs::remove_file(path);
    }
}

// Requires the accepted Unix peer to carry the exact configured kernel user identity.
fn authenticate_client(
    stream: &UnixStream,
    owner_user_id: u32,
) -> Result<(), NodeProtectionLocalError> {
    peer_user_id(stream)
        .filter(|user_id| *user_id == owner_user_id)
        .map(|_| ())
        .ok_or(NodeProtectionLocalError::AuthenticationFailed)
}

// Requires the connected Unix server to carry the exact configured kernel user identity.
fn authenticate_server(
    stream: &UnixStream,
    owner_user_id: u32,
) -> Result<(), NodeProtectionLocalError> {
    authenticate_client(stream, owner_user_id)
}

// Reads the kernel-authenticated peer user identity without trusting filesystem metadata alone.
#[cfg(target_os = "linux")]
fn peer_user_id(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::ucred>())
        .then_some(credentials.uid)
}

// Reads the kernel-authenticated peer user identity without trusting filesystem metadata alone.
#[cfg(target_os = "macos")]
fn peer_user_id(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut user_id: libc::uid_t = 0;
    let mut group_id: libc::gid_t = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut user_id, &mut group_id) };
    (result == 0).then_some(user_id)
}

// Rejects unsupported targets instead of fabricating a local peer identity.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_user_id(_stream: &UnixStream) -> Option<u32> {
    None
}

// Reads the kernel-authenticated Linux peer process identity from the accepted stream.
#[cfg(target_os = "linux")]
fn peer_process_id(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::ucred>())
        .then(|| u32::try_from(credentials.pid).ok())
        .flatten()
        .filter(|process_id| *process_id > 1)
}

// Reads the kernel-authenticated macOS peer process identity from the accepted stream.
#[cfg(target_os = "macos")]
fn peer_process_id(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut process_id: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(process_id).cast(),
            &mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::pid_t>())
        .then(|| u32::try_from(process_id).ok())
        .flatten()
        .filter(|process_id| *process_id > 1)
}

// Rejects unsupported targets instead of fabricating a local process identity.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_process_id(_stream: &UnixStream) -> Option<u32> {
    None
}
