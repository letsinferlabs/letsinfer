// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_WORKERS: usize = 64;
const MAX_ACCEPT_POLL_INTERVAL: Duration = Duration::from_secs(1);

// Names closed nonblocking network outcomes without retaining peer or platform text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateRemoteNetworkError {
    TimedOut,
    Interrupted,
    WouldBlock,
    Unavailable,
}

// Supplies only the nonblocking network capabilities required by TLS framing.
pub trait NodePrivateRemoteNetworkStream: Send {
    // Returns the exact peer address observed by the accepting socket when available.
    fn peer_address(&self) -> Result<SocketAddr, NodePrivateRemoteNetworkError> {
        Err(NodePrivateRemoteNetworkError::Unavailable)
    }

    // Waits for readable network state before one absolute deadline.
    fn wait_readable(&self, deadline: Instant) -> Result<(), NodePrivateRemoteNetworkError>;

    // Waits for writable network state before one absolute deadline.
    fn wait_writable(&self, deadline: Instant) -> Result<(), NodePrivateRemoteNetworkError>;

    // Reads one currently available encrypted fragment without blocking.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateRemoteNetworkError>;

    // Writes one currently available encrypted fragment without blocking.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateRemoteNetworkError>;

    // Closes both directions of this one-request network connection.
    fn close(&mut self) -> Result<(), NodePrivateRemoteNetworkError>;
}

// Owns one accepted connection without exposing its TLS or endpoint policy to the listener.
pub trait NodePrivateRemoteConnectionService: Send + Sync {
    // Serves and closes one accepted nonblocking connection in an isolated worker.
    fn serve(&self, stream: Box<dyn NodePrivateRemoteNetworkStream>);
}

// Describes one invalid bounded TCP listener configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateRemoteServerConfigurationError {
    InvalidWorkerBound,
    InvalidAcceptPollInterval,
}

impl fmt::Display for NodePrivateRemoteServerConfigurationError {
    // Presents stable configuration language without copying a bind address.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWorkerBound => {
                formatter.write_str("private Node remote worker bound must be between 1 and 64")
            }
            Self::InvalidAcceptPollInterval => formatter.write_str(
                "private Node remote accept poll interval must be positive and at most one second",
            ),
        }
    }
}

impl Error for NodePrivateRemoteServerConfigurationError {}

// Holds one exact bind address and hard listener concurrency bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodePrivateRemoteServerConfiguration {
    bind_address: SocketAddr,
    maximum_workers: usize,
    accept_poll_interval: Duration,
}

impl NodePrivateRemoteServerConfiguration {
    // Creates one listener configuration only after both hard bounds are closed.
    pub fn new(
        bind_address: SocketAddr,
        maximum_workers: usize,
        accept_poll_interval: Duration,
    ) -> Result<Self, NodePrivateRemoteServerConfigurationError> {
        if maximum_workers == 0 || maximum_workers > MAX_WORKERS {
            return Err(NodePrivateRemoteServerConfigurationError::InvalidWorkerBound);
        }
        if accept_poll_interval.is_zero() || accept_poll_interval > MAX_ACCEPT_POLL_INTERVAL {
            return Err(NodePrivateRemoteServerConfigurationError::InvalidAcceptPollInterval);
        }
        Ok(Self {
            bind_address,
            maximum_workers,
            accept_poll_interval,
        })
    }

    // Returns the exact address selected by daemon composition.
    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    // Returns the maximum number of concurrent TLS connection workers.
    pub const fn maximum_workers(&self) -> usize {
        self.maximum_workers
    }

    // Returns the bounded delay between nonblocking accept attempts.
    pub const fn accept_poll_interval(&self) -> Duration {
        self.accept_poll_interval
    }
}

// Names stable listener lifecycle failures without retaining addresses or native text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateRemoteServerError {
    BindFailed,
    ListenerConfigurationFailed,
    LocalAddressUnavailable,
    AcceptFailed,
    ListenerSpawnFailed,
    WorkerSpawnFailed,
    WorkerPanicked,
    ListenerPanicked,
}

impl fmt::Display for NodePrivateRemoteServerError {
    // Presents one redacted listener failure using source-owned fixed language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindFailed => formatter.write_str("private Node remote address cannot be bound"),
            Self::ListenerConfigurationFailed => {
                formatter.write_str("private Node remote listener configuration failed")
            }
            Self::LocalAddressUnavailable => {
                formatter.write_str("private Node remote address is unavailable")
            }
            Self::AcceptFailed => {
                formatter.write_str("private Node remote connection cannot be accepted")
            }
            Self::ListenerSpawnFailed => {
                formatter.write_str("private Node remote listener could not start")
            }
            Self::WorkerSpawnFailed => {
                formatter.write_str("private Node remote worker could not start")
            }
            Self::WorkerPanicked => formatter.write_str("private Node remote worker failed"),
            Self::ListenerPanicked => formatter.write_str("private Node remote listener failed"),
        }
    }
}

impl Error for NodePrivateRemoteServerError {}

// Accepts nonblocking remote connections without owning TLS or credential policy.
pub trait NodePrivateRemoteListener: Send + Sync {
    // Returns the exact bound address for daemon readiness reporting.
    fn local_address(&self) -> Result<SocketAddr, NodePrivateRemoteServerError>;

    // Returns one accepted stream, no pending stream, or one terminal accept failure.
    fn accept(
        &self,
    ) -> Result<Option<Box<dyn NodePrivateRemoteNetworkStream>>, NodePrivateRemoteServerError>;
}

// Creates one nonblocking TCP listener from the exact daemon-selected address.
pub trait NodePrivateRemoteSocketProvider: Send + Sync {
    // Binds one listener and returns its complete native lifecycle owner.
    fn bind(
        &self,
        configuration: &NodePrivateRemoteServerConfiguration,
    ) -> Result<Arc<dyn NodePrivateRemoteListener>, NodePrivateRemoteServerError>;
}

// Owns bounded TCP acceptance while delegating every connection to one TLS service.
pub struct NodePrivateRemoteServer {
    configuration: NodePrivateRemoteServerConfiguration,
    service: Arc<dyn NodePrivateRemoteConnectionService>,
    socket: Arc<dyn NodePrivateRemoteSocketProvider>,
}

impl NodePrivateRemoteServer {
    // Creates one inert server without binding or spawning native resources.
    pub const fn new(
        configuration: NodePrivateRemoteServerConfiguration,
        service: Arc<dyn NodePrivateRemoteConnectionService>,
        socket: Arc<dyn NodePrivateRemoteSocketProvider>,
    ) -> Self {
        Self {
            configuration,
            service,
            socket,
        }
    }

    // Binds and starts one nonblocking listener with a hard worker reservation bound.
    pub fn start(&self) -> Result<NodePrivateRemoteServerHandle, NodePrivateRemoteServerError> {
        let listener = self.socket.bind(&self.configuration)?;
        let local_address = listener.local_address()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_workers = Arc::new(AtomicUsize::new(0));
        let terminal_error = Arc::new(Mutex::new(None));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_workers = Arc::clone(&active_workers);
        let thread_error = Arc::clone(&terminal_error);
        let service = Arc::clone(&self.service);
        let maximum_workers = self.configuration.maximum_workers();
        let poll_interval = self.configuration.accept_poll_interval();
        let thread = thread::Builder::new()
            .name("li_node_private_remote_listener".to_owned())
            .spawn(move || {
                let result = accept_loop(
                    listener,
                    service,
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
            .map_err(|_| NodePrivateRemoteServerError::ListenerSpawnFailed)?;
        Ok(NodePrivateRemoteServerHandle {
            local_address,
            shutdown,
            active_workers,
            terminal_error,
            thread: Some(thread),
        })
    }
}

// Owns readiness, shutdown, and worker completion for one running remote listener.
pub struct NodePrivateRemoteServerHandle {
    local_address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    terminal_error: Arc<Mutex<Option<NodePrivateRemoteServerError>>>,
    thread: Option<JoinHandle<()>>,
}

impl NodePrivateRemoteServerHandle {
    // Returns the exact address bound by this running listener.
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    // Returns the current active worker count for bounded health reporting.
    pub fn active_workers(&self) -> usize {
        self.active_workers.load(Ordering::Acquire)
    }

    // Reports whether the accept thread remains live at this observation.
    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    // Signals shutdown, joins all bounded workers, and returns any terminal listener failure.
    pub fn shutdown(&mut self) -> Result<(), NodePrivateRemoteServerError> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| NodePrivateRemoteServerError::ListenerPanicked)?;
        }
        self.terminal_error
            .lock()
            .map_err(|_| NodePrivateRemoteServerError::ListenerPanicked)?
            .take()
            .map_or(Ok(()), Err)
    }
}

impl Drop for NodePrivateRemoteServerHandle {
    // Completes the same bounded shutdown lifecycle when the owner leaves scope.
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// Supplies the production nonblocking TCP listener implementation.
#[derive(Default)]
pub struct SystemNodePrivateRemoteSocketProvider;

impl NodePrivateRemoteSocketProvider for SystemNodePrivateRemoteSocketProvider {
    // Binds one nonblocking system listener without discovering another interface or port.
    fn bind(
        &self,
        configuration: &NodePrivateRemoteServerConfiguration,
    ) -> Result<Arc<dyn NodePrivateRemoteListener>, NodePrivateRemoteServerError> {
        let listener = TcpListener::bind(configuration.bind_address())
            .map_err(|_| NodePrivateRemoteServerError::BindFailed)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| NodePrivateRemoteServerError::ListenerConfigurationFailed)?;
        Ok(Arc::new(SystemNodePrivateRemoteListener { listener }))
    }
}

// Adapts one nonblocking system TCP listener to the injected listener contract.
struct SystemNodePrivateRemoteListener {
    listener: TcpListener,
}

impl NodePrivateRemoteListener for SystemNodePrivateRemoteListener {
    // Returns the exact bound system address without exposing native errors.
    fn local_address(&self) -> Result<SocketAddr, NodePrivateRemoteServerError> {
        self.listener
            .local_addr()
            .map_err(|_| NodePrivateRemoteServerError::LocalAddressUnavailable)
    }

    // Accepts one nonblocking stream and explicitly preserves its nonblocking contract.
    fn accept(
        &self,
    ) -> Result<Option<Box<dyn NodePrivateRemoteNetworkStream>>, NodePrivateRemoteServerError> {
        match self.listener.accept() {
            Ok((stream, peer_address)) => {
                stream
                    .set_nonblocking(true)
                    .and_then(|()| stream.set_nodelay(true))
                    .map_err(|_| NodePrivateRemoteServerError::ListenerConfigurationFailed)?;
                Ok(Some(Box::new(SystemNodePrivateRemoteNetworkStream {
                    stream,
                    peer_address,
                })))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(None),
            Err(_) => Err(NodePrivateRemoteServerError::AcceptFailed),
        }
    }
}

// Adapts one accepted nonblocking TCP stream to the narrow encrypted-I/O contract.
struct SystemNodePrivateRemoteNetworkStream {
    stream: TcpStream,
    peer_address: SocketAddr,
}

impl NodePrivateRemoteNetworkStream for SystemNodePrivateRemoteNetworkStream {
    // Returns the immutable address captured by the accepting socket.
    fn peer_address(&self) -> Result<SocketAddr, NodePrivateRemoteNetworkError> {
        Ok(self.peer_address)
    }

    // Waits for readable encrypted bytes before one absolute deadline.
    fn wait_readable(&self, deadline: Instant) -> Result<(), NodePrivateRemoteNetworkError> {
        poll_file_descriptor(self.stream.as_raw_fd(), libc::POLLIN, deadline)
    }

    // Waits for writable encrypted capacity before one absolute deadline.
    fn wait_writable(&self, deadline: Instant) -> Result<(), NodePrivateRemoteNetworkError> {
        poll_file_descriptor(self.stream.as_raw_fd(), libc::POLLOUT, deadline)
    }

    // Reads one available encrypted TCP fragment.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateRemoteNetworkError> {
        self.stream.read(buffer).map_err(classify_network_error)
    }

    // Writes one available encrypted TCP fragment.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateRemoteNetworkError> {
        self.stream.write(buffer).map_err(classify_network_error)
    }

    // Shuts down both directions while allowing an already-closed peer to remain closed.
    fn close(&mut self) -> Result<(), NodePrivateRemoteNetworkError> {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(classify_network_error(error)),
        }
    }
}

// Runs nonblocking acceptance and joins every bounded worker before listener release.
fn accept_loop(
    listener: Arc<dyn NodePrivateRemoteListener>,
    service: Arc<dyn NodePrivateRemoteConnectionService>,
    shutdown: Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    maximum_workers: usize,
    poll_interval: Duration,
) -> Result<(), NodePrivateRemoteServerError> {
    let mut workers = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        reap_workers(&mut workers)?;
        match listener.accept()? {
            Some(stream) if reserve_worker(&active_workers, maximum_workers) => {
                let worker_service = Arc::clone(&service);
                let worker_count = Arc::clone(&active_workers);
                let worker = thread::Builder::new()
                    .name("li_node_private_remote_worker".to_owned())
                    .spawn(move || {
                        let _guard = ActiveWorkerGuard(worker_count);
                        worker_service.serve(stream);
                    })
                    .map_err(|_| {
                        active_workers.fetch_sub(1, Ordering::AcqRel);
                        NodePrivateRemoteServerError::WorkerSpawnFailed
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
            .map_err(|_| NodePrivateRemoteServerError::WorkerPanicked)?;
    }
    drop(listener);
    Ok(())
}

// Reaps completed workers so the retained join set remains concurrency-bounded.
fn reap_workers(workers: &mut Vec<JoinHandle<()>>) -> Result<(), NodePrivateRemoteServerError> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            worker
                .join()
                .map_err(|_| NodePrivateRemoteServerError::WorkerPanicked)?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

// Reserves one worker slot without ever exceeding the configured maximum.
fn reserve_worker(active_workers: &AtomicUsize, maximum_workers: usize) -> bool {
    active_workers
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < maximum_workers).then_some(current + 1)
        })
        .is_ok()
}

// Releases exactly one remote worker reservation on every worker exit.
struct ActiveWorkerGuard(Arc<AtomicUsize>);

impl Drop for ActiveWorkerGuard {
    // Returns this worker's reserved slot to the listener.
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

// Waits for one descriptor event without extending its absolute deadline.
fn poll_file_descriptor(
    descriptor: std::os::fd::RawFd,
    events: libc::c_short,
    deadline: Instant,
) -> Result<(), NodePrivateRemoteNetworkError> {
    loop {
        let timeout = poll_timeout(deadline)?;
        let mut poll_descriptor = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll_descriptor, 1, timeout) };
        if result > 0 {
            if poll_descriptor.revents & libc::POLLNVAL != 0 {
                return Err(NodePrivateRemoteNetworkError::Unavailable);
            }
            return Ok(());
        }
        if result == 0 {
            return Err(NodePrivateRemoteNetworkError::TimedOut);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(NodePrivateRemoteNetworkError::Unavailable);
        }
    }
}

// Converts one remaining deadline into a positive ceiling-rounded poll timeout.
fn poll_timeout(deadline: Instant) -> Result<libc::c_int, NodePrivateRemoteNetworkError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(NodePrivateRemoteNetworkError::TimedOut)?;
    let milliseconds = remaining.as_nanos().saturating_add(999_999) / 1_000_000;
    Ok(milliseconds.min(libc::c_int::MAX as u128) as libc::c_int)
}

// Maps one native stream error into the closed nonblocking network domain.
fn classify_network_error(error: std::io::Error) -> NodePrivateRemoteNetworkError {
    match error.kind() {
        std::io::ErrorKind::TimedOut => NodePrivateRemoteNetworkError::TimedOut,
        std::io::ErrorKind::Interrupted => NodePrivateRemoteNetworkError::Interrupted,
        std::io::ErrorKind::WouldBlock => NodePrivateRemoteNetworkError::WouldBlock,
        _ => NodePrivateRemoteNetworkError::Unavailable,
    }
}
