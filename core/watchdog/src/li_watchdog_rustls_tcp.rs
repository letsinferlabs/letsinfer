// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};

use crate::{
    SystemWatchdogLiveClock, SystemWatchdogLiveWake, WatchdogAuthenticatedStream, WatchdogError,
    WatchdogLiveFanout, WatchdogLiveRunControl, WatchdogLiveSink,
    WatchdogProtocolConnectionOutcome, WatchdogProtocolListener, WatchdogProtocolSubscription,
    WatchdogSample,
};

const WATCHDOG_TLS_MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const WATCHDOG_TLS_MAX_PRIVATE_KEY_BYTES: usize = 128 * 1024;
const WATCHDOG_TLS_MAX_WORKERS: usize = 16;
const WATCHDOG_TLS_MAX_HANDSHAKE_TIMEOUT_MILLISECONDS: u64 = 10_000;
const WATCHDOG_TLS_MAX_ACCEPT_POLL_MILLISECONDS: u64 = 100;
const WATCHDOG_TLS_HANDSHAKE_POLL_MILLISECONDS: u64 = 1;

// Binds the native listener to three distinct owner-protected TLS inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTlsFileSet {
    owner_user_id: u32,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    controller_ca_file: PathBuf,
}

impl WatchdogTlsFileSet {
    // Creates one closed file set from exact absolute role-specific references.
    pub fn new(
        owner_user_id: u32,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        controller_ca_file: PathBuf,
    ) -> Result<Self, WatchdogError> {
        let paths = [
            &server_certificate_file,
            &server_private_key_file,
            &controller_ca_file,
        ];
        let unique = paths
            .iter()
            .enumerate()
            .all(|(index, path)| paths.iter().skip(index + 1).all(|other| path != other));
        if paths.iter().any(|path| !path.is_absolute()) || !unique {
            return Err(tls_identity_error("TLS file references are invalid"));
        }
        Ok(Self {
            owner_user_id,
            server_certificate_file,
            server_private_key_file,
            controller_ca_file,
        })
    }
}

// Captures one descriptor-bound TLS file observation for production or mocks.
#[derive(Debug, Eq, PartialEq)]
pub struct WatchdogTlsFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    bytes: Vec<u8>,
}

impl WatchdogTlsFile {
    // Creates one raw observation whose safety is judged at the TLS composition boundary.
    pub fn new(
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        is_regular_file: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_user_id,
            mode,
            link_count,
            is_regular_file,
            bytes,
        }
    }
}

impl Drop for WatchdogTlsFile {
    // Clears the temporary identity copy before releasing its allocation.
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

// Reads one exact TLS input without following its final path component.
pub trait WatchdogTlsFileProvider: Send + Sync {
    // Returns a bounded descriptor observation or one redacted native failure.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogTlsFile, WatchdogError>;
}

// Reads strict TLS identity files directly from owner-protected descriptors.
pub struct SystemWatchdogTlsFileProvider;

#[cfg(unix)]
impl WatchdogTlsFileProvider for SystemWatchdogTlsFileProvider {
    // Opens one regular file with no-follow and copies exactly its bounded descriptor bytes.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogTlsFile, WatchdogError> {
        if maximum_bytes == 0 {
            return Err(tls_identity_error("TLS file size bound is invalid"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| tls_identity_error("TLS file is unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| tls_identity_error("TLS file metadata is unavailable"))?;
        let maximum_bytes_u64 = u64::try_from(maximum_bytes)
            .map_err(|_| tls_identity_error("TLS file size bound is invalid"))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes_u64 {
            return Err(tls_identity_error("TLS file metadata is unsafe"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum_bytes_u64.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| tls_identity_error("TLS file cannot be read"))?;
        let final_metadata = file
            .metadata()
            .map_err(|_| tls_identity_error("TLS file metadata is unavailable"))?;
        if bytes.len() as u64 != metadata.len()
            || bytes.len() > maximum_bytes
            || !same_file_observation(&metadata, &final_metadata)
        {
            bytes.fill(0);
            return Err(tls_identity_error("TLS file changed while being read"));
        }
        Ok(WatchdogTlsFile::new(
            metadata.uid(),
            metadata.mode() & 0o7777,
            metadata.nlink(),
            metadata.is_file(),
            bytes,
        ))
    }
}

#[cfg(unix)]
// Returns whether one descriptor retained its complete relevant identity during a bounded read.
fn same_file_observation(initial: &std::fs::Metadata, final_metadata: &std::fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
        && initial.ctime() == final_metadata.ctime()
        && initial.ctime_nsec() == final_metadata.ctime_nsec()
}

#[cfg(not(unix))]
impl WatchdogTlsFileProvider for SystemWatchdogTlsFileProvider {
    // Rejects platforms without the required Unix descriptor identity contract.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<WatchdogTlsFile, WatchdogError> {
        Err(tls_identity_error(
            "no-follow TLS files are unsupported on this platform",
        ))
    }
}

// Owns one immutable TLS 1.3 server policy requiring a trusted controller certificate.
#[derive(Clone)]
pub struct WatchdogRustlsServerConfiguration {
    server: Arc<ServerConfig>,
}

impl WatchdogRustlsServerConfiguration {
    // Loads strict private inputs and constructs one closed mutual-TLS policy.
    pub fn load(
        files: &WatchdogTlsFileSet,
        provider: &dyn WatchdogTlsFileProvider,
    ) -> Result<Self, WatchdogError> {
        let server_certificates = private_tls_file(
            provider,
            &files.server_certificate_file,
            files.owner_user_id,
            WATCHDOG_TLS_MAX_CERTIFICATE_BYTES,
        )?;
        let server_private_key = private_tls_file(
            provider,
            &files.server_private_key_file,
            files.owner_user_id,
            WATCHDOG_TLS_MAX_PRIVATE_KEY_BYTES,
        )?;
        let controller_ca = private_tls_file(
            provider,
            &files.controller_ca_file,
            files.owner_user_id,
            WATCHDOG_TLS_MAX_CERTIFICATE_BYTES,
        )?;
        let server_certificates = parse_certificates(&server_certificates.bytes)?;
        let server_private_key = parse_private_key(&server_private_key.bytes)?;
        let controller_ca = parse_certificates(&controller_ca.bytes)?;
        let mut controller_roots = RootCertStore::empty();
        let (added, ignored) = controller_roots.add_parsable_certificates(controller_ca);
        if added == 0 || ignored != 0 {
            return Err(tls_identity_error("controller CA is invalid"));
        }
        let controller_verifier = WebPkiClientVerifier::builder(Arc::new(controller_roots))
            .build()
            .map_err(|_| tls_identity_error("controller certificate verifier is invalid"))?;
        let server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(controller_verifier)
            .with_single_cert(server_certificates, server_private_key)
            .map_err(|_| tls_identity_error("server certificate identity is invalid"))?;
        Ok(Self {
            server: Arc::new(server),
        })
    }

    // Returns the immutable server policy for one accepted native connection.
    pub fn server_configuration(&self) -> Arc<ServerConfig> {
        self.server.clone()
    }
}

// Defines the worker, handshake, and accept-poll bounds for one native listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogRustlsTcpLimits {
    maximum_workers: usize,
    handshake_timeout_milliseconds: u64,
    accept_poll_milliseconds: u64,
}

impl WatchdogRustlsTcpLimits {
    // Creates one limit set inside the established native Watchdog bounds.
    pub fn new(
        maximum_workers: usize,
        handshake_timeout_milliseconds: u64,
        accept_poll_milliseconds: u64,
    ) -> Result<Self, WatchdogError> {
        if maximum_workers == 0
            || maximum_workers > WATCHDOG_TLS_MAX_WORKERS
            || handshake_timeout_milliseconds == 0
            || handshake_timeout_milliseconds > WATCHDOG_TLS_MAX_HANDSHAKE_TIMEOUT_MILLISECONDS
            || accept_poll_milliseconds == 0
            || accept_poll_milliseconds > WATCHDOG_TLS_MAX_ACCEPT_POLL_MILLISECONDS
        {
            return Err(tcp_listener_error("native listener limits are invalid"));
        }
        Ok(Self {
            maximum_workers,
            handshake_timeout_milliseconds,
            accept_poll_milliseconds,
        })
    }

    // Returns the unchanged production worker and deadline policy.
    pub fn production() -> Self {
        Self {
            maximum_workers: WATCHDOG_TLS_MAX_WORKERS,
            handshake_timeout_milliseconds: WATCHDOG_TLS_MAX_HANDSHAKE_TIMEOUT_MILLISECONDS,
            accept_poll_milliseconds: 25,
        }
    }
}

impl Default for WatchdogRustlsTcpLimits {
    // Supplies the explicit production policy without widening any native bound.
    fn default() -> Self {
        Self::production()
    }
}

// Owns one bounded TCP accept loop and every active mutual-TLS worker.
pub struct WatchdogRustlsTcpServer {
    listener: TcpListener,
    protocol_listener: Arc<WatchdogProtocolListener>,
    fanout: Arc<WatchdogLiveFanout>,
    tls: Arc<ServerConfig>,
    limits: WatchdogRustlsTcpLimits,
    state: Arc<WatchdogRustlsTcpState>,
}

impl WatchdogRustlsTcpServer {
    // Binds one nonblocking listener after all protocol and TLS policy is complete.
    pub fn bind(
        address: SocketAddr,
        protocol_listener: Arc<WatchdogProtocolListener>,
        fanout: Arc<WatchdogLiveFanout>,
        tls: WatchdogRustlsServerConfiguration,
        limits: WatchdogRustlsTcpLimits,
    ) -> Result<Self, WatchdogError> {
        if !protocol_listener.has_persistent_controller_registry() {
            return Err(tcp_listener_error(
                "controller registry is not restart-safe",
            ));
        }
        let listener = TcpListener::bind(address)
            .map_err(|_| tcp_listener_error("native listener address cannot be bound"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| tcp_listener_error("native listener cannot become nonblocking"))?;
        Ok(Self {
            listener,
            protocol_listener,
            fanout,
            tls: tls.server_configuration(),
            limits,
            state: Arc::new(WatchdogRustlsTcpState::new()),
        })
    }

    // Returns the exact bound address for process readiness checks.
    pub fn local_address(&self) -> Result<SocketAddr, WatchdogError> {
        self.listener
            .local_addr()
            .map_err(|_| tcp_listener_error("native listener address is unavailable"))
    }

    // Runs the bounded accept lifecycle until explicit shutdown or a terminal native error.
    pub fn serve(&self) -> Result<(), WatchdogError> {
        let _serve_guard = WatchdogRustlsServeGuard::acquire(self.state.clone())?;
        let mut workers = Vec::with_capacity(self.limits.maximum_workers);
        let result = self.serve_until_shutdown(&mut workers);
        if result.is_err() {
            self.state.shutdown.store(true, Ordering::Release);
        }
        let fanout_result = self.fanout.close();
        let shutdown_result = shutdown_worker_sockets(&self.state);
        let join_result = join_all_workers(&mut workers);
        result
            .and(fanout_result)
            .and(shutdown_result)
            .and(join_result)
    }

    // Requests terminal shutdown and interrupts every active handshake or protocol read.
    pub fn shutdown(&self) -> Result<(), WatchdogError> {
        self.state.shutdown.store(true, Ordering::Release);
        self.fanout.close()?;
        shutdown_worker_sockets(&self.state)
    }

    // Accepts and starts workers while keeping both active sockets and thread handles bounded.
    fn serve_until_shutdown(&self, workers: &mut Vec<JoinHandle<()>>) -> Result<(), WatchdogError> {
        while !self.state.shutdown.load(Ordering::Acquire) {
            reap_finished_workers(workers)?;
            match self.listener.accept() {
                Ok((connection, _)) => self.start_worker(connection, workers)?,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(self.limits.accept_poll_milliseconds));
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    return Err(tcp_listener_error(
                        "native listener connection cannot be accepted",
                    ))
                }
            }
        }
        Ok(())
    }

    // Registers and spawns one worker or rejects the connection at the hard worker bound.
    fn start_worker(
        &self,
        connection: TcpStream,
        workers: &mut Vec<JoinHandle<()>>,
    ) -> Result<(), WatchdogError> {
        let worker_id =
            match register_worker_socket(&self.state, &connection, self.limits.maximum_workers)? {
                Some(worker_id) => worker_id,
                None => {
                    let _ = connection.shutdown(Shutdown::Both);
                    return Ok(());
                }
            };
        let protocol_listener = self.protocol_listener.clone();
        let fanout = self.fanout.clone();
        let tls = self.tls.clone();
        let limits = self.limits;
        let state = self.state.clone();
        let release_state = self.state.clone();
        let worker = thread::Builder::new()
            .name("li_watchdog_tls_connection".to_string())
            .spawn(move || {
                let _worker_guard = WatchdogRustlsWorkerGuard::new(state.clone(), worker_id);
                let _ = serve_rustls_connection(
                    connection,
                    protocol_listener,
                    fanout,
                    tls,
                    limits,
                    state,
                );
            });
        match worker {
            Ok(worker) => {
                workers.push(worker);
                Ok(())
            }
            Err(_) => {
                remove_worker_socket(&release_state, worker_id);
                Err(tcp_listener_error(
                    "native listener worker cannot be created",
                ))
            }
        }
    }
}

// Stores only the listener-wide shutdown and bounded worker ownership state.
struct WatchdogRustlsTcpState {
    shutdown: AtomicBool,
    serving: AtomicBool,
    next_worker_id: AtomicU64,
    worker_sockets: Mutex<BTreeMap<u64, TcpStream>>,
}

impl WatchdogRustlsTcpState {
    // Creates an idle state with no active native resources.
    fn new() -> Self {
        Self {
            shutdown: AtomicBool::new(false),
            serving: AtomicBool::new(false),
            next_worker_id: AtomicU64::new(1),
            worker_sockets: Mutex::new(BTreeMap::new()),
        }
    }
}

// Releases the exclusive serve lifecycle marker on every terminal path.
struct WatchdogRustlsServeGuard {
    state: Arc<WatchdogRustlsTcpState>,
}

impl WatchdogRustlsServeGuard {
    // Acquires the one permitted accept loop for this listener instance.
    fn acquire(state: Arc<WatchdogRustlsTcpState>) -> Result<Self, WatchdogError> {
        state
            .serving
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| tcp_listener_error("native listener is already serving"))?;
        Ok(Self { state })
    }
}

impl Drop for WatchdogRustlsServeGuard {
    // Marks the accept lifecycle complete after all worker joins finish.
    fn drop(&mut self) {
        self.state.serving.store(false, Ordering::Release);
    }
}

// Removes one registered worker socket after its connection lifecycle exits.
struct WatchdogRustlsWorkerGuard {
    state: Arc<WatchdogRustlsTcpState>,
    worker_id: u64,
}

impl WatchdogRustlsWorkerGuard {
    // Creates one symmetric ownership guard for a registered worker socket.
    const fn new(state: Arc<WatchdogRustlsTcpState>, worker_id: u64) -> Self {
        Self { state, worker_id }
    }
}

impl Drop for WatchdogRustlsWorkerGuard {
    // Releases the worker registry slot without allowing a cleanup panic.
    fn drop(&mut self) {
        remove_worker_socket(&self.state, self.worker_id);
    }
}

// Adapts one verified Rustls connection to the existing accepted-stream contract.
struct WatchdogRustlsStream {
    connection: StreamOwned<ServerConnection, TcpStream>,
    certificate_sha256: String,
}

impl WatchdogRustlsStream {
    // Creates one authenticated stream from the exact accepted peer leaf identity.
    fn new(
        connection: StreamOwned<ServerConnection, TcpStream>,
        certificate_sha256: String,
    ) -> Self {
        Self {
            connection,
            certificate_sha256,
        }
    }

    // Terminates the underlying socket without exposing TLS or peer details.
    fn shutdown(&self) {
        let _ = self.connection.sock.shutdown(Shutdown::Both);
    }
}

impl Read for WatchdogRustlsStream {
    // Reads authenticated plaintext through the verified Rustls connection.
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.connection.read(bytes)
    }
}

impl Write for WatchdogRustlsStream {
    // Writes authenticated plaintext through the verified Rustls connection.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.connection.write(bytes)
    }

    // Flushes every pending authenticated plaintext byte to the peer.
    fn flush(&mut self) -> std::io::Result<()> {
        self.connection.flush()
    }
}

impl WatchdogAuthenticatedStream for WatchdogRustlsStream {
    // Returns the exact verified peer-leaf SHA-256 identity.
    fn authenticated_certificate_sha256(&self) -> Result<String, WatchdogError> {
        Ok(self.certificate_sha256.clone())
    }

    // Applies the protocol listener's hard read and write deadlines.
    fn configure_timeouts(
        &self,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(), WatchdogError> {
        self.connection
            .sock
            .set_read_timeout(Some(read_timeout))
            .and_then(|_| self.connection.sock.set_write_timeout(Some(write_timeout)))
            .map_err(|_| tcp_listener_error("protocol socket deadline cannot be applied"))
    }
}

// Performs one absolute-deadline mutual-TLS handshake before centralized dispatch.
fn serve_rustls_connection(
    connection: TcpStream,
    protocol_listener: Arc<WatchdogProtocolListener>,
    fanout: Arc<WatchdogLiveFanout>,
    tls: Arc<ServerConfig>,
    limits: WatchdogRustlsTcpLimits,
    state: Arc<WatchdogRustlsTcpState>,
) -> Result<(), WatchdogError> {
    connection
        .set_nonblocking(true)
        .map_err(|_| tcp_listener_error("handshake socket cannot become nonblocking"))?;
    let server = ServerConnection::new(tls)
        .map_err(|_| tcp_listener_error("TLS connection cannot be created"))?;
    let mut connection = StreamOwned::new(server, connection);
    complete_rustls_handshake(
        &mut connection,
        Duration::from_millis(limits.handshake_timeout_milliseconds),
        &state.shutdown,
    )?;
    let certificate_sha256 = peer_leaf_certificate_sha256(connection.conn.peer_certificates())?;
    connection
        .sock
        .set_nonblocking(false)
        .map_err(|_| tcp_listener_error("protocol socket cannot become blocking"))?;
    let mut stream = WatchdogRustlsStream::new(connection, certificate_sha256);
    let outcome = protocol_listener.serve_authenticated_stream(&mut stream)?;
    if let WatchdogProtocolConnectionOutcome::Subscribed(subscription) = outcome {
        let wake = Arc::new(SystemWatchdogLiveWake::new());
        let mut receiver = fanout.subscribe(wake)?;
        let clock = SystemWatchdogLiveClock::new();
        let control = WatchdogRustlsLiveControl { state: &state };
        let mut sink = WatchdogRustlsLiveSink {
            subscription: &subscription,
            stream: &mut stream,
        };
        receiver.serve(&mut sink, &clock, &control)?;
    }
    stream.shutdown();
    Ok(())
}

// Adapts one retained protocol subscription to the resident fanout sink contract.
struct WatchdogRustlsLiveSink<'a> {
    subscription: &'a WatchdogProtocolSubscription,
    stream: &'a mut WatchdogRustlsStream,
}

impl WatchdogLiveSink for WatchdogRustlsLiveSink<'_> {
    // Revalidates both the immutable TLS leaf and current registry generation.
    fn is_authorized(&self) -> Result<bool, WatchdogError> {
        self.subscription.is_authorized_for(self.stream)
    }

    // Sends one exact live sample through the existing typed protocol encoder.
    fn send_sample(&mut self, sample: WatchdogSample) -> Result<(), WatchdogError> {
        self.subscription.send_live_sample(self.stream, sample)
    }

    // Sends one explicit sequence gap through the existing typed protocol encoder.
    fn send_gap(
        &mut self,
        first_missing_sequence: u64,
        latest_sequence: u64,
    ) -> Result<(), WatchdogError> {
        self.subscription
            .send_gap(self.stream, first_missing_sequence, latest_sequence)
    }
}

// Observes the listener-wide shutdown flag for one subscriber worker.
struct WatchdogRustlsLiveControl<'a> {
    state: &'a WatchdogRustlsTcpState,
}

impl WatchdogLiveRunControl for WatchdogRustlsLiveControl<'_> {
    // Stops the subscriber as soon as the owning native listener begins shutdown.
    fn should_stop(&self) -> bool {
        self.state.shutdown.load(Ordering::Acquire)
    }
}

// Completes TLS 1.3 under one absolute deadline that progress cannot extend.
fn complete_rustls_handshake(
    connection: &mut StreamOwned<ServerConnection, TcpStream>,
    timeout: Duration,
    shutdown: &AtomicBool,
) -> Result<(), WatchdogError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| tcp_listener_error("TLS handshake deadline is invalid"))?;
    while connection.conn.is_handshaking() {
        if shutdown.load(Ordering::Acquire) {
            return Err(tcp_listener_error("TLS handshake was interrupted"));
        }
        if Instant::now() >= deadline {
            return Err(tcp_listener_error("TLS handshake timed out"));
        }
        match connection.conn.complete_io(&mut connection.sock) {
            Ok(_) => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(
                Duration::from_millis(WATCHDOG_TLS_HANDSHAKE_POLL_MILLISECONDS),
            ),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(tcp_listener_error("TLS handshake was rejected")),
        }
    }
    Ok(())
}

// Returns the lowercase SHA-256 identity of the accepted verified leaf certificate.
fn peer_leaf_certificate_sha256(
    certificates: Option<&[CertificateDer<'static>]>,
) -> Result<String, WatchdogError> {
    let certificate = certificates
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| tcp_listener_error("verified controller certificate is missing"))?;
    Ok(lower_hex(&Sha256::digest(certificate.as_ref())))
}

// Registers one cloned control socket without exceeding the worker bound.
fn register_worker_socket(
    state: &WatchdogRustlsTcpState,
    connection: &TcpStream,
    maximum_workers: usize,
) -> Result<Option<u64>, WatchdogError> {
    let mut sockets = state
        .worker_sockets
        .lock()
        .map_err(|_| WatchdogError::StateUnavailable)?;
    if state.shutdown.load(Ordering::Acquire) || sockets.len() >= maximum_workers {
        return Ok(None);
    }
    let worker_id = state
        .next_worker_id
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| tcp_listener_error("native listener worker identity is exhausted"))?;
    let control_socket = connection
        .try_clone()
        .map_err(|_| tcp_listener_error("native listener worker cannot be registered"))?;
    sockets.insert(worker_id, control_socket);
    Ok(Some(worker_id))
}

// Removes one control socket without allowing cleanup to poison a worker exit.
fn remove_worker_socket(state: &WatchdogRustlsTcpState, worker_id: u64) {
    if let Ok(mut sockets) = state.worker_sockets.lock() {
        sockets.remove(&worker_id);
    }
}

// Interrupts every registered worker socket while preserving the registry for its guard.
fn shutdown_worker_sockets(state: &WatchdogRustlsTcpState) -> Result<(), WatchdogError> {
    let sockets = state
        .worker_sockets
        .lock()
        .map_err(|_| WatchdogError::StateUnavailable)?;
    for socket in sockets.values() {
        let _ = socket.shutdown(Shutdown::Both);
    }
    Ok(())
}

// Joins completed workers eagerly so the accept loop cannot retain stale handles.
fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) -> Result<(), WatchdogError> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            worker
                .join()
                .map_err(|_| tcp_listener_error("native listener worker terminated"))?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

// Joins every worker after its control socket has been interrupted.
fn join_all_workers(workers: &mut Vec<JoinHandle<()>>) -> Result<(), WatchdogError> {
    let mut failed = false;
    while let Some(worker) = workers.pop() {
        failed |= worker.join().is_err();
    }
    if failed {
        Err(tcp_listener_error("native listener worker terminated"))
    } else {
        Ok(())
    }
}

// Requires exact owner, mode, link, type, presence, and size before parsing identity bytes.
fn private_tls_file(
    provider: &dyn WatchdogTlsFileProvider,
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<WatchdogTlsFile, WatchdogError> {
    let file = provider
        .read_no_follow(path, maximum_bytes)
        .map_err(|_| tls_identity_error("TLS file is unavailable"))?;
    if file.owner_user_id != owner_user_id
        || file.mode != 0o600
        || file.link_count != 1
        || !file.is_regular_file
        || file.bytes.is_empty()
        || file.bytes.len() > maximum_bytes
    {
        return Err(tls_identity_error("TLS file metadata is unsafe"));
    }
    Ok(file)
}

// Parses a PEM document containing certificates and no unrelated item kind.
fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, WatchdogError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| tls_identity_error("certificate is malformed"))?;
    let certificates = items
        .into_iter()
        .map(|item| match item {
            rustls_pemfile::Item::X509Certificate(certificate) => Ok(certificate),
            _ => Err(tls_identity_error(
                "certificate file contains an unrelated item",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(tls_identity_error("certificate chain is empty"));
    }
    Ok(certificates)
}

// Parses a PEM document containing exactly one supported private key.
fn parse_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, WatchdogError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| tls_identity_error("private key is malformed"))?;
    if items.len() != 1 {
        return Err(tls_identity_error(
            "private key file must contain exactly one item",
        ));
    }
    match items.into_iter().next() {
        Some(rustls_pemfile::Item::Pkcs1Key(key)) => Ok(key.into()),
        Some(rustls_pemfile::Item::Pkcs8Key(key)) => Ok(key.into()),
        Some(rustls_pemfile::Item::Sec1Key(key)) => Ok(key.into()),
        _ => Err(tls_identity_error("private key file contains no key")),
    }
}

// Encodes bytes as their canonical lowercase hexadecimal identity.
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

// Creates one stable redacted TLS identity failure.
const fn tls_identity_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("TLS identity", reason)
}

// Creates one stable redacted native listener failure.
const fn tcp_listener_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("rustls TCP", reason)
}
