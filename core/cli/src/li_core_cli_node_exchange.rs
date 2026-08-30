// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use li_node_manager::{
    NodePrivateUnixPathGuard, NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES,
    NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

use crate::{NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort};

// Describes an invalid native Unix endpoint path before any connection is attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixNodePrivateExchangeConfigurationError {
    InvalidSocketPath,
}

impl fmt::Display for UnixNodePrivateExchangeConfigurationError {
    // Presents stable configuration language without copying a machine path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private Node socket path is invalid")
    }
}

impl Error for UnixNodePrivateExchangeConfigurationError {}

// Names one closed native connection outcome without retaining platform diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateUnixConnectError {
    NotConfigured,
    TimedOut,
    Unavailable,
}

// Names one closed nonblocking stream outcome without retaining platform diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateUnixIoError {
    TimedOut,
    Interrupted,
    WouldBlock,
    Unavailable,
}

// Supplies only the nonblocking stream capabilities required by one framed exchange.
pub trait NodePrivateUnixStream {
    // Waits until the stream may accept request bytes before the absolute deadline.
    fn wait_writable(&self, deadline: Instant) -> Result<(), NodePrivateUnixIoError>;

    // Waits until the stream may return response bytes before the absolute deadline.
    fn wait_readable(&self, deadline: Instant) -> Result<(), NodePrivateUnixIoError>;

    // Writes one currently available request fragment without blocking.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateUnixIoError>;

    // Reads one currently available response fragment without blocking.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateUnixIoError>;

    // Closes both directions of the one-request connection.
    fn close(&mut self) -> Result<(), NodePrivateUnixIoError>;
}

// Opens exactly one nonblocking Unix stream under one absolute request deadline.
pub trait NodePrivateUnixConnector {
    // Connects to the explicit endpoint without discovery, fallback, retry, or replay.
    fn connect(
        &mut self,
        socket_path: &Path,
        deadline: Instant,
    ) -> Result<Box<dyn NodePrivateUnixStream>, NodePrivateUnixConnectError>;
}

// Owns one explicit Unix endpoint and its injected native connection capability.
pub struct UnixNodePrivateDocumentExchange<Connector>
where
    Connector: NodePrivateUnixConnector,
{
    socket_path: PathBuf,
    connector: Connector,
}

impl<Connector> UnixNodePrivateDocumentExchange<Connector>
where
    Connector: NodePrivateUnixConnector,
{
    // Creates one exchange only when the explicit path fits the native Unix address contract.
    pub fn new(
        socket_path: PathBuf,
        connector: Connector,
    ) -> Result<Self, UnixNodePrivateExchangeConfigurationError> {
        validate_socket_path(&socket_path)?;
        Ok(Self {
            socket_path,
            connector,
        })
    }

    // Returns the exact endpoint path selected by process composition.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the connector for deterministic composition-level observation.
    pub const fn connector(&self) -> &Connector {
        &self.connector
    }
}

impl UnixNodePrivateDocumentExchange<SystemNodePrivateUnixConnector> {
    // Creates one production exchange from an explicit native socket path.
    pub fn open(socket_path: PathBuf) -> Result<Self, UnixNodePrivateExchangeConfigurationError> {
        Self::new(socket_path, SystemNodePrivateUnixConnector)
    }
}

impl<Connector> NodePrivateDocumentExchangePort for UnixNodePrivateDocumentExchange<Connector>
where
    Connector: NodePrivateUnixConnector,
{
    // Completes one framed request and response under one non-extendable absolute deadline.
    fn exchange(
        &mut self,
        request: &[u8],
        timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        if request.is_empty() || request.len() > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
            return Err(NodePrivateDocumentExchangeError::RequestTooLarge);
        }
        if maximum_response_bytes == 0 || maximum_response_bytes > NODE_PRIVATE_MAX_DOCUMENT_BYTES {
            return Err(NodePrivateDocumentExchangeError::ResponseTooLarge);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(NodePrivateDocumentExchangeError::TimedOut)?;
        ensure_exchange_deadline(deadline)?;
        let mut stream = self
            .connector
            .connect(&self.socket_path, deadline)
            .map_err(exchange_connect_error)?;
        let result = exchange_connected(stream.as_mut(), request, maximum_response_bytes, deadline);
        let close = stream
            .close()
            .map_err(|_| NodePrivateDocumentExchangeError::Unavailable);
        match result {
            Err(error) => Err(error),
            Ok(response) => close.map(|()| response),
        }
    }
}

// Identifies the ordinary native implementation used by process composition.
pub type SystemNodePrivateDocumentExchange =
    UnixNodePrivateDocumentExchange<SystemNodePrivateUnixConnector>;

// Supplies the production nonblocking Unix connector.
#[derive(Default)]
pub struct SystemNodePrivateUnixConnector;

impl NodePrivateUnixConnector for SystemNodePrivateUnixConnector {
    // Validates the owner-only socket and opens one nonblocking stream before the deadline.
    fn connect(
        &mut self,
        socket_path: &Path,
        deadline: Instant,
    ) -> Result<Box<dyn NodePrivateUnixStream>, NodePrivateUnixConnectError> {
        let _path_guard =
            NodePrivateUnixPathGuard::acquire(socket_path, unsafe { libc::geteuid() })
                .map_err(|_| NodePrivateUnixConnectError::Unavailable)?;
        validate_system_socket(socket_path)?;
        connect_system_stream(socket_path, deadline)
            .map(|stream| Box::new(stream) as Box<dyn NodePrivateUnixStream>)
    }
}

// Adapts one nonblocking production Unix stream to the injected I/O contract.
struct SystemNodePrivateUnixStream {
    stream: UnixStream,
}

impl NodePrivateUnixStream for SystemNodePrivateUnixStream {
    // Waits for one writable observation without extending the absolute request deadline.
    fn wait_writable(&self, deadline: Instant) -> Result<(), NodePrivateUnixIoError> {
        poll_file_descriptor(self.stream.as_raw_fd(), libc::POLLOUT, deadline)
    }

    // Waits for one readable observation without extending the absolute request deadline.
    fn wait_readable(&self, deadline: Instant) -> Result<(), NodePrivateUnixIoError> {
        poll_file_descriptor(self.stream.as_raw_fd(), libc::POLLIN, deadline)
    }

    // Writes one available nonblocking stream fragment.
    fn write_bytes(&mut self, buffer: &[u8]) -> Result<usize, NodePrivateUnixIoError> {
        self.stream.write(buffer).map_err(classify_stream_error)
    }

    // Reads one available nonblocking stream fragment.
    fn read_bytes(&mut self, buffer: &mut [u8]) -> Result<usize, NodePrivateUnixIoError> {
        self.stream.read(buffer).map_err(classify_stream_error)
    }

    // Shuts down both directions while allowing an already-closed peer to remain closed.
    fn close(&mut self) -> Result<(), NodePrivateUnixIoError> {
        match self.stream.shutdown(std::net::Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(classify_stream_error(error)),
        }
    }
}

// Closes one raw descriptor unless its ownership transfers into UnixStream.
struct PendingFileDescriptor {
    descriptor: RawFd,
    armed: bool,
}

impl PendingFileDescriptor {
    // Starts one exact descriptor cleanup lifecycle.
    const fn new(descriptor: RawFd) -> Self {
        Self {
            descriptor,
            armed: true,
        }
    }

    // Transfers the descriptor into its final Rust owner.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingFileDescriptor {
    // Closes only the descriptor retained by this incomplete connection.
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::close(self.descriptor);
            }
        }
    }
}

// Writes one fixed header and request, then reads one bounded response frame.
fn exchange_connected(
    stream: &mut dyn NodePrivateUnixStream,
    request: &[u8],
    maximum_response_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
    let request_length = u32::try_from(request.len())
        .map_err(|_| NodePrivateDocumentExchangeError::RequestTooLarge)?;
    write_all(stream, &request_length.to_be_bytes(), deadline)?;
    write_all(stream, request, deadline)?;

    let mut header = [0_u8; NODE_PRIVATE_LOCAL_FRAME_HEADER_BYTES];
    read_exact(stream, &mut header, deadline)?;
    let response_length = u32::from_be_bytes(header) as usize;
    if response_length == 0 {
        return Err(NodePrivateDocumentExchangeError::MalformedResponse);
    }
    if response_length > maximum_response_bytes || response_length > NODE_PRIVATE_MAX_DOCUMENT_BYTES
    {
        return Err(NodePrivateDocumentExchangeError::ResponseTooLarge);
    }
    let mut response = vec![0_u8; response_length];
    read_exact(stream, &mut response, deadline)?;
    Ok(response)
}

// Writes every request byte across nonblocking fragmentation before one deadline.
fn write_all(
    stream: &mut dyn NodePrivateUnixStream,
    mut buffer: &[u8],
    deadline: Instant,
) -> Result<(), NodePrivateDocumentExchangeError> {
    while !buffer.is_empty() {
        ensure_exchange_deadline(deadline)?;
        stream.wait_writable(deadline).map_err(exchange_io_error)?;
        match stream.write_bytes(buffer) {
            Ok(0) => return Err(NodePrivateDocumentExchangeError::Unavailable),
            Ok(count) if count <= buffer.len() => buffer = &buffer[count..],
            Ok(_) => return Err(NodePrivateDocumentExchangeError::Unavailable),
            Err(NodePrivateUnixIoError::Interrupted | NodePrivateUnixIoError::WouldBlock) => {}
            Err(error) => return Err(exchange_io_error(error)),
        }
    }
    ensure_exchange_deadline(deadline)?;
    Ok(())
}

// Reads every response byte across nonblocking fragmentation before one deadline.
fn read_exact(
    stream: &mut dyn NodePrivateUnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), NodePrivateDocumentExchangeError> {
    while !buffer.is_empty() {
        ensure_exchange_deadline(deadline)?;
        stream.wait_readable(deadline).map_err(exchange_io_error)?;
        match stream.read_bytes(buffer) {
            Ok(0) => return Err(NodePrivateDocumentExchangeError::MalformedResponse),
            Ok(count) if count <= buffer.len() => {
                let (_, remaining) = buffer.split_at_mut(count);
                buffer = remaining;
            }
            Ok(_) => return Err(NodePrivateDocumentExchangeError::Unavailable),
            Err(NodePrivateUnixIoError::Interrupted | NodePrivateUnixIoError::WouldBlock) => {}
            Err(error) => return Err(exchange_io_error(error)),
        }
    }
    ensure_exchange_deadline(deadline)?;
    Ok(())
}

// Requires the complete request deadline to remain open at this observation.
fn ensure_exchange_deadline(deadline: Instant) -> Result<(), NodePrivateDocumentExchangeError> {
    if Instant::now() >= deadline {
        Err(NodePrivateDocumentExchangeError::TimedOut)
    } else {
        Ok(())
    }
}

// Requires one absolute, NUL-free path that fits one native sockaddr_un.
fn validate_socket_path(
    socket_path: &Path,
) -> Result<(), UnixNodePrivateExchangeConfigurationError> {
    if !socket_path.is_absolute() {
        return Err(UnixNodePrivateExchangeConfigurationError::InvalidSocketPath);
    }
    let bytes = socket_path.as_os_str().as_bytes();
    let address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(UnixNodePrivateExchangeConfigurationError::InvalidSocketPath);
    }
    Ok(())
}

// Requires one owner-controlled real socket before the system connector trusts its path.
fn validate_system_socket(socket_path: &Path) -> Result<(), NodePrivateUnixConnectError> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(NodePrivateUnixConnectError::NotConfigured)
        }
        Err(_) => return Err(NodePrivateUnixConnectError::Unavailable),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(NodePrivateUnixConnectError::Unavailable);
    }
    Ok(())
}

// Opens and completes one nonblocking AF_UNIX connection before the absolute deadline.
fn connect_system_stream(
    socket_path: &Path,
    deadline: Instant,
) -> Result<SystemNodePrivateUnixStream, NodePrivateUnixConnectError> {
    ensure_connect_deadline(deadline)?;
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if descriptor < 0 {
        return Err(NodePrivateUnixConnectError::Unavailable);
    }
    let mut pending = PendingFileDescriptor::new(descriptor);
    configure_descriptor(descriptor)?;
    let (address, length) = socket_address(socket_path)?;
    let result = unsafe { libc::connect(descriptor, std::ptr::addr_of!(address).cast(), length) };
    if result != 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if !connection_is_pending(code) {
            return Err(classify_connect_code(code));
        }
        poll_file_descriptor(descriptor, libc::POLLOUT, deadline).map_err(|error| match error {
            NodePrivateUnixIoError::TimedOut => NodePrivateUnixConnectError::TimedOut,
            _ => NodePrivateUnixConnectError::Unavailable,
        })?;
        complete_nonblocking_connect(descriptor)?;
    }
    ensure_connect_deadline(deadline)?;
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    pending.disarm();
    Ok(SystemNodePrivateUnixStream { stream })
}

// Applies close-on-exec and nonblocking flags without replacing existing descriptor state.
fn configure_descriptor(descriptor: RawFd) -> Result<(), NodePrivateUnixConnectError> {
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                descriptor,
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(NodePrivateUnixConnectError::Unavailable);
    }
    let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if status_flags < 0
        || unsafe { libc::fcntl(descriptor, libc::F_SETFL, status_flags | libc::O_NONBLOCK) } < 0
    {
        return Err(NodePrivateUnixConnectError::Unavailable);
    }
    Ok(())
}

// Builds one pathname sockaddr_un with the platform-specific family header.
fn socket_address(
    socket_path: &Path,
) -> Result<(libc::sockaddr_un, libc::socklen_t), NodePrivateUnixConnectError> {
    validate_socket_path(socket_path).map_err(|_| NodePrivateUnixConnectError::Unavailable)?;
    let bytes = socket_path.as_os_str().as_bytes();
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(target_os = "macos")]
    {
        address.sun_len =
            u8::try_from(length).map_err(|_| NodePrivateUnixConnectError::Unavailable)?;
    }
    Ok((address, length as libc::socklen_t))
}

// Waits for one descriptor event while preserving one non-extendable absolute deadline.
fn poll_file_descriptor(
    descriptor: RawFd,
    events: libc::c_short,
    deadline: Instant,
) -> Result<(), NodePrivateUnixIoError> {
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
                return Err(NodePrivateUnixIoError::Unavailable);
            }
            return Ok(());
        }
        if result == 0 {
            return Err(NodePrivateUnixIoError::TimedOut);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(NodePrivateUnixIoError::Unavailable);
        }
    }
}

// Converts the remaining deadline into one positive, ceiling-rounded poll timeout.
fn poll_timeout(deadline: Instant) -> Result<libc::c_int, NodePrivateUnixIoError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(NodePrivateUnixIoError::TimedOut)?;
    let milliseconds = remaining.as_nanos().saturating_add(999_999) / 1_000_000;
    Ok(milliseconds.min(libc::c_int::MAX as u128) as libc::c_int)
}

// Requires the absolute connect deadline to remain open at this observation.
fn ensure_connect_deadline(deadline: Instant) -> Result<(), NodePrivateUnixConnectError> {
    if Instant::now() >= deadline {
        Err(NodePrivateUnixConnectError::TimedOut)
    } else {
        Ok(())
    }
}

// Verifies the terminal SO_ERROR result after one writable nonblocking connect.
fn complete_nonblocking_connect(descriptor: RawFd) -> Result<(), NodePrivateUnixConnectError> {
    let mut code: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            std::ptr::addr_of_mut!(code).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::c_int>() {
        return Err(NodePrivateUnixConnectError::Unavailable);
    }
    if code == 0 {
        Ok(())
    } else {
        Err(classify_connect_code(code))
    }
}

// Returns whether one native connect result requires writable completion polling.
fn connection_is_pending(code: libc::c_int) -> bool {
    code == libc::EINPROGRESS
        || code == libc::EALREADY
        || code == libc::EAGAIN
        || code == libc::EWOULDBLOCK
}

// Maps one native connection code without retaining a machine diagnostic or socket path.
fn classify_connect_code(code: libc::c_int) -> NodePrivateUnixConnectError {
    if code == libc::ENOENT {
        NodePrivateUnixConnectError::NotConfigured
    } else if code == libc::ETIMEDOUT {
        NodePrivateUnixConnectError::TimedOut
    } else {
        NodePrivateUnixConnectError::Unavailable
    }
}

// Maps one native stream error into the closed nonblocking I/O domain.
fn classify_stream_error(error: std::io::Error) -> NodePrivateUnixIoError {
    match error.kind() {
        std::io::ErrorKind::TimedOut => NodePrivateUnixIoError::TimedOut,
        std::io::ErrorKind::Interrupted => NodePrivateUnixIoError::Interrupted,
        std::io::ErrorKind::WouldBlock => NodePrivateUnixIoError::WouldBlock,
        _ => NodePrivateUnixIoError::Unavailable,
    }
}

// Maps one injected I/O error into the stable document exchange domain.
fn exchange_io_error(error: NodePrivateUnixIoError) -> NodePrivateDocumentExchangeError {
    match error {
        NodePrivateUnixIoError::TimedOut => NodePrivateDocumentExchangeError::TimedOut,
        NodePrivateUnixIoError::Interrupted
        | NodePrivateUnixIoError::WouldBlock
        | NodePrivateUnixIoError::Unavailable => NodePrivateDocumentExchangeError::Unavailable,
    }
}

// Maps one injected connect error into the stable document exchange domain.
fn exchange_connect_error(error: NodePrivateUnixConnectError) -> NodePrivateDocumentExchangeError {
    match error {
        NodePrivateUnixConnectError::NotConfigured => {
            NodePrivateDocumentExchangeError::NotConfigured
        }
        NodePrivateUnixConnectError::TimedOut => NodePrivateDocumentExchangeError::TimedOut,
        NodePrivateUnixConnectError::Unavailable => NodePrivateDocumentExchangeError::Unavailable,
    }
}
