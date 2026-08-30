// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use li_core_interface::NodeId;

use crate::{NodePrivateLocalEndpoint, NodePrivateUnixPathGuard, NODE_PRIVATE_MAX_DOCUMENT_BYTES};

pub const NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES: usize = 4;
const MAX_WORKERS: usize = 64;
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ACCEPT_POLL_INTERVAL: Duration = Duration::from_secs(1);

// Describes one invalid local listener configuration before native resources are acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalServerConfigurationError {
    RelativeSocketPath,
    InvalidWorkerBound,
    InvalidReadTimeout,
    InvalidWriteTimeout,
    InvalidAcceptPollInterval,
}

impl fmt::Display for NodePrivateLocalServerConfigurationError {
    // Presents the exact invalid configuration boundary without platform error text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeSocketPath => {
                formatter.write_str("the private Node socket path must be absolute")
            }
            Self::InvalidWorkerBound => {
                formatter.write_str("the private Node worker bound must be between 1 and 64")
            }
            Self::InvalidReadTimeout => formatter
                .write_str("the private Node read timeout must be positive and at most 60 seconds"),
            Self::InvalidWriteTimeout => formatter.write_str(
                "the private Node write timeout must be positive and at most 60 seconds",
            ),
            Self::InvalidAcceptPollInterval => formatter.write_str(
                "the private Node accept poll interval must be positive and at most one second",
            ),
        }
    }
}

impl Error for NodePrivateLocalServerConfigurationError {}

// Holds immutable owner, path, timeout, and concurrency bounds for one local listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePrivateLocalServerConfiguration {
    socket_path: PathBuf,
    owner_uid: u32,
    maximum_workers: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    accept_poll_interval: Duration,
}

impl NodePrivateLocalServerConfiguration {
    // Creates one server configuration only after every native bound is closed.
    pub fn new(
        socket_path: PathBuf,
        owner_uid: u32,
        maximum_workers: usize,
        read_timeout: Duration,
        write_timeout: Duration,
        accept_poll_interval: Duration,
    ) -> Result<Self, NodePrivateLocalServerConfigurationError> {
        if !socket_path.is_absolute() {
            return Err(NodePrivateLocalServerConfigurationError::RelativeSocketPath);
        }
        if maximum_workers == 0 || maximum_workers > MAX_WORKERS {
            return Err(NodePrivateLocalServerConfigurationError::InvalidWorkerBound);
        }
        validate_timeout(read_timeout)
            .map_err(|_| NodePrivateLocalServerConfigurationError::InvalidReadTimeout)?;
        validate_timeout(write_timeout)
            .map_err(|_| NodePrivateLocalServerConfigurationError::InvalidWriteTimeout)?;
        if accept_poll_interval.is_zero() || accept_poll_interval > MAX_ACCEPT_POLL_INTERVAL {
            return Err(NodePrivateLocalServerConfigurationError::InvalidAcceptPollInterval);
        }
        Ok(Self {
            socket_path,
            owner_uid,
            maximum_workers,
            read_timeout,
            write_timeout,
            accept_poll_interval,
        })
    }

    // Returns the exact absolute socket path owned by this server lifecycle.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the effective user identity permitted to own the socket.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    // Returns the maximum number of concurrently active connection workers.
    pub const fn maximum_workers(&self) -> usize {
        self.maximum_workers
    }

    // Returns the complete-frame read timeout applied to every accepted stream.
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // Returns the complete-frame write timeout applied to every accepted stream.
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    // Returns the bounded delay between nonblocking accept attempts.
    pub const fn accept_poll_interval(&self) -> Duration {
        self.accept_poll_interval
    }
}

// Names closed native stream failures without retaining operating-system messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalIoError {
    TimedOut,
    Interrupted,
    Unavailable,
}

// Supplies only the stream capabilities required by one local framed exchange.
pub trait NodePrivateLocalStream: Send {
    // Returns the authenticated operating-system user identity of the connected peer.
    fn peer_uid(&self) -> Result<u32, NodePrivateLocalIoError>;

    // Applies the exact bounded timeout before any request bytes are read.
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), NodePrivateLocalIoError>;

    // Applies the exact bounded timeout before any response bytes are written.
    fn set_write_timeout(&self, timeout: Duration) -> Result<(), NodePrivateLocalIoError>;

    // Reads available bytes without implying complete-frame progress.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateLocalIoError>;

    // Writes available bytes without implying complete-frame progress.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateLocalIoError>;

    // Closes both directions of this one-request connection.
    fn close(&mut self) -> Result<(), NodePrivateLocalIoError>;
}

// Describes one invalid or incomplete fixed-header local frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalFrameError {
    TimedOut,
    Unavailable,
    Truncated,
    EmptyDocument,
    OversizedDocument,
    ZeroProgress,
}

impl fmt::Display for NodePrivateLocalFrameError {
    // Presents stable frame failures without copying untrusted payload bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => formatter.write_str("the private Node frame timed out"),
            Self::Unavailable => formatter.write_str("the private Node frame I/O failed"),
            Self::Truncated => formatter.write_str("the private Node frame is truncated"),
            Self::EmptyDocument => formatter.write_str("the private Node frame is empty"),
            Self::OversizedDocument => formatter.write_str("the private Node frame is oversized"),
            Self::ZeroProgress => formatter.write_str("the private Node frame made no progress"),
        }
    }
}

impl Error for NodePrivateLocalFrameError {}

// Reads one four-byte big-endian length followed by exactly one bounded JSON document.
pub fn read_node_private_local_frame(
    stream: &mut dyn NodePrivateLocalStream,
) -> Result<Vec<u8>, NodePrivateLocalFrameError> {
    read_node_private_local_frame_before(stream, None)
}

// Writes one four-byte big-endian length followed by exactly one bounded JSON document.
pub fn write_node_private_local_frame(
    stream: &mut dyn NodePrivateLocalStream,
    document: &[u8],
) -> Result<(), NodePrivateLocalFrameError> {
    write_node_private_local_frame_before(stream, document, None)
}

// Describes failure to map one Unix peer into the exact local Node identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalPeerError {
    ForeignUser,
}

// Maps an authenticated Unix peer identity into the Node identity it may represent.
pub trait NodePrivateLocalPeerIdentityProvider: Send + Sync {
    // Returns the exact local Node identity only for an authorized peer user.
    fn node_id_for_peer(&self, peer_uid: u32) -> Result<NodeId, NodePrivateLocalPeerError>;
}

// Maps exactly one owner user into exactly one immutable local Node identity.
pub struct ExactNodePrivateLocalPeerIdentity {
    owner_uid: u32,
    local_node_id: NodeId,
}

impl ExactNodePrivateLocalPeerIdentity {
    // Creates one immutable owner-to-Node mapping without discovering either identity.
    pub const fn new(owner_uid: u32, local_node_id: NodeId) -> Self {
        Self {
            owner_uid,
            local_node_id,
        }
    }
}

impl NodePrivateLocalPeerIdentityProvider for ExactNodePrivateLocalPeerIdentity {
    // Rejects every foreign user and returns no substitute Node identity.
    fn node_id_for_peer(&self, peer_uid: u32) -> Result<NodeId, NodePrivateLocalPeerError> {
        if peer_uid != self.owner_uid {
            return Err(NodePrivateLocalPeerError::ForeignUser);
        }
        Ok(self.local_node_id.clone())
    }
}

// Describes one local endpoint rejection without retaining codec or manager details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalDocumentError {
    Rejected,
}

// Handles one already-framed document after exact peer identity authorization.
pub trait NodePrivateLocalDocumentEndpoint: Send + Sync {
    // Returns one bounded response document or one redacted rejection.
    fn handle_document(
        &self,
        local_node_id: &NodeId,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateLocalDocumentError>;
}

impl NodePrivateLocalDocumentEndpoint for NodePrivateLocalEndpoint {
    // Dispatches through the ordinary typed Node endpoint while redacting internal failures.
    fn handle_document(
        &self,
        local_node_id: &NodeId,
        document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateLocalDocumentError> {
        self.handle(local_node_id, document)
            .map_err(|_| NodePrivateLocalDocumentError::Rejected)
    }
}

// Describes one isolated connection failure without terminating the listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalConnectionError {
    TimeoutConfiguration,
    PeerIdentityUnavailable,
    ForeignUser,
    Frame(NodePrivateLocalFrameError),
    EndpointRejected,
    CloseFailed,
}

impl fmt::Display for NodePrivateLocalConnectionError {
    // Presents stable redacted language for one failed local connection.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeoutConfiguration => {
                formatter.write_str("private Node connection timeout configuration failed")
            }
            Self::PeerIdentityUnavailable => {
                formatter.write_str("private Node peer identity is unavailable")
            }
            Self::ForeignUser => formatter.write_str("private Node peer user is not authorized"),
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::EndpointRejected => {
                formatter.write_str("private Node endpoint rejected the request")
            }
            Self::CloseFailed => formatter.write_str("private Node connection close failed"),
        }
    }
}

impl Error for NodePrivateLocalConnectionError {}

// Owns peer authorization and one framed request/response lifecycle.
pub struct NodePrivateLocalConnectionHandler {
    endpoint: Arc<dyn NodePrivateLocalDocumentEndpoint>,
    peer_identity: Arc<dyn NodePrivateLocalPeerIdentityProvider>,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl NodePrivateLocalConnectionHandler {
    // Creates one handler from explicit endpoint, peer identity, and timeout dependencies.
    pub const fn new(
        endpoint: Arc<dyn NodePrivateLocalDocumentEndpoint>,
        peer_identity: Arc<dyn NodePrivateLocalPeerIdentityProvider>,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            endpoint,
            peer_identity,
            read_timeout,
            write_timeout,
        }
    }

    // Serves exactly one request and response, then closes the connection in every outcome.
    pub fn handle(
        &self,
        stream: &mut dyn NodePrivateLocalStream,
    ) -> Result<(), NodePrivateLocalConnectionError> {
        let result = self.handle_open(stream);
        let close = stream
            .close()
            .map_err(|_| NodePrivateLocalConnectionError::CloseFailed);
        match result {
            Err(error) => Err(error),
            Ok(()) => close,
        }
    }

    // Completes the authorized framed exchange before the symmetric close boundary.
    fn handle_open(
        &self,
        stream: &mut dyn NodePrivateLocalStream,
    ) -> Result<(), NodePrivateLocalConnectionError> {
        stream
            .set_read_timeout(self.read_timeout)
            .map_err(|_| NodePrivateLocalConnectionError::TimeoutConfiguration)?;
        stream
            .set_write_timeout(self.write_timeout)
            .map_err(|_| NodePrivateLocalConnectionError::TimeoutConfiguration)?;
        let peer_uid = stream
            .peer_uid()
            .map_err(|_| NodePrivateLocalConnectionError::PeerIdentityUnavailable)?;
        let local_node_id = self
            .peer_identity
            .node_id_for_peer(peer_uid)
            .map_err(|_| NodePrivateLocalConnectionError::ForeignUser)?;
        let request = read_node_private_local_frame_until(stream, self.read_timeout)
            .map_err(NodePrivateLocalConnectionError::Frame)?;
        let response = self
            .endpoint
            .handle_document(&local_node_id, &request)
            .map_err(|_| NodePrivateLocalConnectionError::EndpointRejected)?;
        write_node_private_local_frame_until(stream, &response, self.write_timeout)
            .map_err(NodePrivateLocalConnectionError::Frame)
    }
}

// Names fixed listener lifecycle failures without retaining paths or platform text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateLocalServerError {
    UnsafeSocketParent,
    UnsafeSocketPath,
    AlreadyRunning,
    BindFailed,
    PermissionFailed,
    ListenerConfigurationFailed,
    AcceptFailed,
    ListenerSpawnFailed,
    WorkerSpawnFailed,
    WorkerPanicked,
    ServerThreadPanicked,
}

impl fmt::Display for NodePrivateLocalServerError {
    // Presents stable listener failures without copying native error messages.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeSocketParent => {
                formatter.write_str("private Node socket parent is not owner-only")
            }
            Self::UnsafeSocketPath => {
                formatter.write_str("private Node socket path is not a safe owned socket")
            }
            Self::AlreadyRunning => {
                formatter.write_str("another private Node listener is already running")
            }
            Self::BindFailed => formatter.write_str("private Node socket bind failed"),
            Self::PermissionFailed => {
                formatter.write_str("private Node socket permission update failed")
            }
            Self::ListenerConfigurationFailed => {
                formatter.write_str("private Node listener configuration failed")
            }
            Self::AcceptFailed => formatter.write_str("private Node socket accept failed"),
            Self::ListenerSpawnFailed => {
                formatter.write_str("private Node listener could not start")
            }
            Self::WorkerSpawnFailed => {
                formatter.write_str("private Node connection worker could not start")
            }
            Self::WorkerPanicked => formatter.write_str("private Node connection worker failed"),
            Self::ServerThreadPanicked => {
                formatter.write_str("private Node listener thread failed")
            }
        }
    }
}

impl Error for NodePrivateLocalServerError {}

// Accepts nonblocking streams while retaining socket cleanup ownership in the provider.
pub trait NodePrivateLocalListener: Send + Sync {
    // Returns one accepted stream, no pending stream, or one terminal listener failure.
    fn accept(
        &self,
    ) -> Result<Option<Box<dyn NodePrivateLocalStream>>, NodePrivateLocalServerError>;
}

// Creates one owner-only listener after validating any stale socket path.
pub trait NodePrivateLocalSocketProvider: Send + Sync {
    // Binds the exact configured socket and returns its complete cleanup owner.
    fn bind(
        &self,
        configuration: &NodePrivateLocalServerConfiguration,
    ) -> Result<Arc<dyn NodePrivateLocalListener>, NodePrivateLocalServerError>;
}

// Owns local listener binding and bounded worker lifecycle composition.
pub struct NodePrivateLocalServer {
    configuration: NodePrivateLocalServerConfiguration,
    endpoint: Arc<dyn NodePrivateLocalDocumentEndpoint>,
    peer_identity: Arc<dyn NodePrivateLocalPeerIdentityProvider>,
    socket: Arc<dyn NodePrivateLocalSocketProvider>,
}

impl NodePrivateLocalServer {
    // Creates one inert server without binding or spawning native resources.
    pub const fn new(
        configuration: NodePrivateLocalServerConfiguration,
        endpoint: Arc<dyn NodePrivateLocalDocumentEndpoint>,
        peer_identity: Arc<dyn NodePrivateLocalPeerIdentityProvider>,
        socket: Arc<dyn NodePrivateLocalSocketProvider>,
    ) -> Self {
        Self {
            configuration,
            endpoint,
            peer_identity,
            socket,
        }
    }

    // Binds the socket and starts one bounded nonblocking accept lifecycle.
    pub fn start(&self) -> Result<NodePrivateLocalServerHandle, NodePrivateLocalServerError> {
        let listener = self.socket.bind(&self.configuration)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_workers = Arc::new(AtomicUsize::new(0));
        let terminal_error = Arc::new(Mutex::new(None));
        let handler = Arc::new(NodePrivateLocalConnectionHandler::new(
            Arc::clone(&self.endpoint),
            Arc::clone(&self.peer_identity),
            self.configuration.read_timeout(),
            self.configuration.write_timeout(),
        ));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_workers = Arc::clone(&active_workers);
        let thread_error = Arc::clone(&terminal_error);
        let maximum_workers = self.configuration.maximum_workers();
        let poll_interval = self.configuration.accept_poll_interval();
        let thread = thread::Builder::new()
            .name("li_node_private_listener".to_owned())
            .spawn(move || {
                let result = accept_loop(
                    listener,
                    handler,
                    thread_shutdown,
                    Arc::clone(&thread_workers),
                    maximum_workers,
                    poll_interval,
                );
                if let Err(error) = result {
                    if let Ok(mut terminal) = thread_error.lock() {
                        *terminal = Some(error);
                    }
                }
            })
            .map_err(|_| NodePrivateLocalServerError::ListenerSpawnFailed)?;
        Ok(NodePrivateLocalServerHandle {
            shutdown,
            active_workers,
            terminal_error,
            thread: Some(thread),
        })
    }
}

// Owns shutdown, join, and terminal readback for one running local listener.
pub struct NodePrivateLocalServerHandle {
    shutdown: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    terminal_error: Arc<Mutex<Option<NodePrivateLocalServerError>>>,
    thread: Option<JoinHandle<()>>,
}

impl NodePrivateLocalServerHandle {
    // Returns the current number of active workers for health and bounded tests.
    pub fn active_workers(&self) -> usize {
        self.active_workers.load(Ordering::Acquire)
    }

    // Reports whether the accept thread remains live at this observation.
    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    // Signals shutdown, waits for bounded workers, and returns any terminal listener failure.
    pub fn shutdown(&mut self) -> Result<(), NodePrivateLocalServerError> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| NodePrivateLocalServerError::ServerThreadPanicked)?;
        }
        self.terminal_error
            .lock()
            .map_err(|_| NodePrivateLocalServerError::ServerThreadPanicked)?
            .take()
            .map_or(Ok(()), Err)
    }
}

impl Drop for NodePrivateLocalServerHandle {
    // Completes the same bounded shutdown lifecycle when the owner leaves scope.
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// Provides the production owner-only Unix-domain socket implementation.
#[derive(Default)]
pub struct SystemNodePrivateLocalSocketProvider;

impl NodePrivateLocalSocketProvider for SystemNodePrivateLocalSocketProvider {
    // Validates the parent and stale path before binding one nonblocking 0600 socket.
    fn bind(
        &self,
        configuration: &NodePrivateLocalServerConfiguration,
    ) -> Result<Arc<dyn NodePrivateLocalListener>, NodePrivateLocalServerError> {
        bind_system_listener(configuration)
            .map(|listener| Arc::new(listener) as Arc<dyn NodePrivateLocalListener>)
    }
}

// Owns one bound system listener and its exact device/inode cleanup identity.
struct SystemNodePrivateLocalListener {
    listener: UnixListener,
    socket_path: PathBuf,
    owner_uid: u32,
    device: u64,
    inode: u64,
}

// Removes one newly bound socket unless its exact identity transfers to the listener.
struct PendingSystemSocketCleanup {
    socket_path: PathBuf,
    owner_uid: u32,
    device: u64,
    inode: u64,
    armed: bool,
}

impl PendingSystemSocketCleanup {
    // Records the exact newly bound socket identity before later configuration can fail.
    fn new(socket_path: PathBuf, owner_uid: u32, device: u64, inode: u64) -> Self {
        Self {
            socket_path,
            owner_uid,
            device,
            inode,
            armed: true,
        }
    }

    // Transfers cleanup ownership to the completed listener.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingSystemSocketCleanup {
    // Removes only the exact owned socket created during this incomplete bind.
    fn drop(&mut self) {
        if self.armed {
            remove_exact_socket(&self.socket_path, self.owner_uid, self.device, self.inode);
        }
    }
}

impl NodePrivateLocalListener for SystemNodePrivateLocalListener {
    // Accepts one nonblocking Unix stream while treating WouldBlock as no pending work.
    fn accept(
        &self,
    ) -> Result<Option<Box<dyn NodePrivateLocalStream>>, NodePrivateLocalServerError> {
        match self.listener.accept() {
            Ok((stream, _)) => Ok(Some(Box::new(SystemNodePrivateLocalStream { stream }))),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(None),
            Err(_) => Err(NodePrivateLocalServerError::AcceptFailed),
        }
    }
}

impl Drop for SystemNodePrivateLocalListener {
    // Removes only the exact owned socket inode created by this listener lifecycle.
    fn drop(&mut self) {
        remove_exact_socket(&self.socket_path, self.owner_uid, self.device, self.inode);
    }
}

// Adapts one accepted UnixStream into the narrow local stream contract.
struct SystemNodePrivateLocalStream {
    stream: UnixStream,
}

impl NodePrivateLocalStream for SystemNodePrivateLocalStream {
    // Resolves the kernel-authenticated peer user without trusting client bytes.
    fn peer_uid(&self) -> Result<u32, NodePrivateLocalIoError> {
        system_peer_uid(&self.stream)
    }

    // Applies the configured system read timeout.
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), NodePrivateLocalIoError> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(classify_io_error)
    }

    // Applies the configured system write timeout.
    fn set_write_timeout(&self, timeout: Duration) -> Result<(), NodePrivateLocalIoError> {
        self.stream
            .set_write_timeout(Some(timeout))
            .map_err(classify_io_error)
    }

    // Reads one available system-stream fragment.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateLocalIoError> {
        std::io::Read::read(&mut self.stream, buffer).map_err(classify_io_error)
    }

    // Writes one available system-stream fragment.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateLocalIoError> {
        std::io::Write::write(&mut self.stream, buffer).map_err(classify_io_error)
    }

    // Shuts down both directions while allowing an already-closed peer to remain closed.
    fn close(&mut self) -> Result<(), NodePrivateLocalIoError> {
        match self.stream.shutdown(std::net::Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(classify_io_error(error)),
        }
    }
}

// Runs nonblocking acceptance and joins every bounded worker before listener cleanup.
fn accept_loop(
    listener: Arc<dyn NodePrivateLocalListener>,
    handler: Arc<NodePrivateLocalConnectionHandler>,
    shutdown: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    maximum_workers: usize,
    poll_interval: Duration,
) -> Result<(), NodePrivateLocalServerError> {
    let mut workers = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        reap_workers(&mut workers)?;
        match listener.accept()? {
            Some(mut stream) if reserve_worker(&active_workers, maximum_workers) => {
                let worker_handler = Arc::clone(&handler);
                let worker_count = Arc::clone(&active_workers);
                let worker = thread::Builder::new()
                    .name("li_node_private_worker".to_owned())
                    .spawn(move || {
                        let _guard = ActiveWorkerGuard(worker_count);
                        let _ = worker_handler.handle(stream.as_mut());
                    })
                    .map_err(|_| {
                        active_workers.fetch_sub(1, Ordering::AcqRel);
                        NodePrivateLocalServerError::WorkerSpawnFailed
                    })?;
                workers.push(worker);
            }
            Some(mut stream) => {
                let _ = stream.close();
            }
            None => thread::sleep(poll_interval),
        }
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| NodePrivateLocalServerError::WorkerPanicked)?;
    }
    drop(listener);
    Ok(())
}

// Reaps completed workers so the retained join-handle set remains concurrency-bounded.
fn reap_workers(workers: &mut Vec<JoinHandle<()>>) -> Result<(), NodePrivateLocalServerError> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            worker
                .join()
                .map_err(|_| NodePrivateLocalServerError::WorkerPanicked)?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

// Reserves one active-worker slot without ever exceeding the configured maximum.
fn reserve_worker(active_workers: &AtomicUsize, maximum_workers: usize) -> bool {
    active_workers
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < maximum_workers).then_some(current + 1)
        })
        .is_ok()
}

// Releases exactly one worker reservation on every worker exit.
struct ActiveWorkerGuard(Arc<AtomicUsize>);

impl Drop for ActiveWorkerGuard {
    // Returns this worker's reserved slot to the listener.
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

// Reads exactly the requested byte count across fragmentation and retryable interruption.
fn read_exact(
    stream: &mut dyn NodePrivateLocalStream,
    mut buffer: &mut [u8],
    deadline: Option<Instant>,
) -> Result<(), NodePrivateLocalFrameError> {
    while !buffer.is_empty() {
        if let Some(deadline) = deadline {
            stream
                .set_read_timeout(remaining_duration(deadline)?)
                .map_err(|_| NodePrivateLocalFrameError::Unavailable)?;
        }
        match stream.read_bytes(buffer) {
            Ok(0) => return Err(NodePrivateLocalFrameError::Truncated),
            Ok(count) if count <= buffer.len() => {
                let (_, remaining) = buffer.split_at_mut(count);
                buffer = remaining;
            }
            Ok(_) => return Err(NodePrivateLocalFrameError::Unavailable),
            Err(NodePrivateLocalIoError::Interrupted) => {}
            Err(NodePrivateLocalIoError::TimedOut) => {
                return Err(NodePrivateLocalFrameError::TimedOut)
            }
            Err(NodePrivateLocalIoError::Unavailable) => {
                return Err(NodePrivateLocalFrameError::Unavailable)
            }
        }
    }
    Ok(())
}

// Reads one complete frame before one absolute request deadline can be extended by fragments.
fn read_node_private_local_frame_until(
    stream: &mut dyn NodePrivateLocalStream,
    timeout: Duration,
) -> Result<Vec<u8>, NodePrivateLocalFrameError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(NodePrivateLocalFrameError::TimedOut)?;
    read_node_private_local_frame_before(stream, Some(deadline))
}

// Reads one fixed-header frame with an optional complete-frame deadline.
fn read_node_private_local_frame_before(
    stream: &mut dyn NodePrivateLocalStream,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, NodePrivateLocalFrameError> {
    let mut header = [0_u8; NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(NodePrivateLocalFrameError::EmptyDocument);
    }
    if length > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateLocalFrameError::OversizedDocument);
    }
    let mut document = vec![0_u8; length];
    read_exact(stream, &mut document, deadline)?;
    Ok(document)
}

// Writes every byte across fragmentation and rejects a zero-progress writer.
fn write_all(
    stream: &mut dyn NodePrivateLocalStream,
    mut buffer: &[u8],
    deadline: Option<Instant>,
) -> Result<(), NodePrivateLocalFrameError> {
    while !buffer.is_empty() {
        if let Some(deadline) = deadline {
            stream
                .set_write_timeout(remaining_duration(deadline)?)
                .map_err(|_| NodePrivateLocalFrameError::Unavailable)?;
        }
        match stream.write_bytes(buffer) {
            Ok(0) => return Err(NodePrivateLocalFrameError::ZeroProgress),
            Ok(count) if count <= buffer.len() => buffer = &buffer[count..],
            Ok(_) => return Err(NodePrivateLocalFrameError::Unavailable),
            Err(NodePrivateLocalIoError::Interrupted) => {}
            Err(NodePrivateLocalIoError::TimedOut) => {
                return Err(NodePrivateLocalFrameError::TimedOut)
            }
            Err(NodePrivateLocalIoError::Unavailable) => {
                return Err(NodePrivateLocalFrameError::Unavailable)
            }
        }
    }
    Ok(())
}

// Writes one complete frame before one absolute response deadline can be extended by fragments.
fn write_node_private_local_frame_until(
    stream: &mut dyn NodePrivateLocalStream,
    document: &[u8],
    timeout: Duration,
) -> Result<(), NodePrivateLocalFrameError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(NodePrivateLocalFrameError::TimedOut)?;
    write_node_private_local_frame_before(stream, document, Some(deadline))
}

// Writes one fixed-header frame with an optional complete-frame deadline.
fn write_node_private_local_frame_before(
    stream: &mut dyn NodePrivateLocalStream,
    document: &[u8],
    deadline: Option<Instant>,
) -> Result<(), NodePrivateLocalFrameError> {
    if document.is_empty() {
        return Err(NodePrivateLocalFrameError::EmptyDocument);
    }
    if document.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
        return Err(NodePrivateLocalFrameError::OversizedDocument);
    }
    let length =
        u32::try_from(document.len()).map_err(|_| NodePrivateLocalFrameError::OversizedDocument)?;
    write_all(stream, &length.to_be_bytes(), deadline)?;
    write_all(stream, document, deadline)
}

// Returns the positive duration remaining before one complete-frame deadline.
fn remaining_duration(deadline: Instant) -> Result<Duration, NodePrivateLocalFrameError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(NodePrivateLocalFrameError::TimedOut)
}

// Validates one positive timeout against the fixed native upper bound.
fn validate_timeout(timeout: Duration) -> Result<(), ()> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        Err(())
    } else {
        Ok(())
    }
}

// Binds one nonblocking 0600 Unix listener after strict parent and stale-path checks.
fn bind_system_listener(
    configuration: &NodePrivateLocalServerConfiguration,
) -> Result<SystemNodePrivateLocalListener, NodePrivateLocalServerError> {
    let effective_uid = unsafe { libc::geteuid() };
    if configuration.owner_uid() != effective_uid {
        return Err(NodePrivateLocalServerError::UnsafeSocketParent);
    }
    let _parent_guard = validate_socket_parent(configuration.socket_path(), effective_uid)?;
    prepare_socket_path(configuration.socket_path(), effective_uid)?;
    let listener = UnixListener::bind(configuration.socket_path())
        .map_err(|_| NodePrivateLocalServerError::BindFailed)?;
    let bound_metadata = fs::symlink_metadata(configuration.socket_path())
        .map_err(|_| NodePrivateLocalServerError::UnsafeSocketPath)?;
    if !bound_metadata.file_type().is_socket() || bound_metadata.uid() != effective_uid {
        return Err(NodePrivateLocalServerError::UnsafeSocketPath);
    }
    let mut cleanup = PendingSystemSocketCleanup::new(
        configuration.socket_path().to_path_buf(),
        effective_uid,
        bound_metadata.dev(),
        bound_metadata.ino(),
    );
    fs::set_permissions(
        configuration.socket_path(),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| NodePrivateLocalServerError::PermissionFailed)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| NodePrivateLocalServerError::ListenerConfigurationFailed)?;
    let metadata = fs::symlink_metadata(configuration.socket_path())
        .map_err(|_| NodePrivateLocalServerError::UnsafeSocketPath)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o077 != 0
        || metadata.dev() != bound_metadata.dev()
        || metadata.ino() != bound_metadata.ino()
    {
        return Err(NodePrivateLocalServerError::UnsafeSocketPath);
    }
    cleanup.disarm();
    Ok(SystemNodePrivateLocalListener {
        listener,
        socket_path: configuration.socket_path().to_path_buf(),
        owner_uid: effective_uid,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

// Removes a socket only when its owner and filesystem identity exactly match expectations.
fn remove_exact_socket(path: &Path, owner_uid: u32, device: u64, inode: u64) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket()
        && metadata.uid() == owner_uid
        && metadata.dev() == device
        && metadata.ino() == inode
    {
        let _ = fs::remove_file(path);
    }
}

// Requires one real owner-only directory without following a symbolic link.
fn validate_socket_parent(
    path: &Path,
    owner_uid: u32,
) -> Result<NodePrivateUnixPathGuard, NodePrivateLocalServerError> {
    NodePrivateUnixPathGuard::acquire(path, owner_uid)
        .map_err(|_| NodePrivateLocalServerError::UnsafeSocketParent)
}

// Removes only an inactive owner-only stale socket from an already protected directory.
fn prepare_socket_path(path: &Path, owner_uid: u32) -> Result<(), NodePrivateLocalServerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(NodePrivateLocalServerError::UnsafeSocketPath),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(NodePrivateLocalServerError::UnsafeSocketPath);
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(NodePrivateLocalServerError::AlreadyRunning),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path).map_err(|_| NodePrivateLocalServerError::UnsafeSocketPath)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NodePrivateLocalServerError::UnsafeSocketPath),
    }
}

// Maps one standard I/O failure into a closed redacted stream result.
fn classify_io_error(error: std::io::Error) -> NodePrivateLocalIoError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            NodePrivateLocalIoError::TimedOut
        }
        std::io::ErrorKind::Interrupted => NodePrivateLocalIoError::Interrupted,
        _ => NodePrivateLocalIoError::Unavailable,
    }
}

// Returns the kernel-authenticated peer UID for one connected Unix stream.
#[cfg(target_os = "linux")]
fn system_peer_uid(stream: &UnixStream) -> Result<u32, NodePrivateLocalIoError> {
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
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(NodePrivateLocalIoError::Unavailable);
    }
    Ok(credentials.uid)
}

// Returns the kernel-authenticated peer UID for one connected Unix stream.
#[cfg(target_os = "macos")]
fn system_peer_uid(stream: &UnixStream) -> Result<u32, NodePrivateLocalIoError> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(NodePrivateLocalIoError::Unavailable);
    }
    Ok(uid)
}

// Rejects unsupported Unix targets instead of fabricating peer identity.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn system_peer_uid(_stream: &UnixStream) -> Result<u32, NodePrivateLocalIoError> {
    Err(NodePrivateLocalIoError::Unavailable)
}
