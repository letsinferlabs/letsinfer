// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use li_core_interface::{NodeId, Sha256Digest};
use li_core_update_manager::CoreVersion;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    GatewayConfiguration, GatewayConfigurationMode, GatewayHealthConfiguration, GatewayManager,
};

pub const LI_GATEWAY_HEALTH_SCHEMA_NAME: &str = "li_gateway_health";
pub const LI_GATEWAY_HEALTH_SCHEMA_VERSION: u32 = 1;

const GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES: usize = 4 * 1024;
const GATEWAY_HEALTH_MAXIMUM_TIMEOUT: Duration = Duration::from_secs(10);
const GATEWAY_HEALTH_SOCKET_MODE: u32 = 0o600;
const GATEWAY_HEALTH_DIRECTORY_MODE: u32 = 0o700;

// Names stable local-health failures without retaining paths, identities, or native detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHealthError {
    InvalidContract,
    EndpointUnavailable,
    AuthenticationUnavailable,
    InvalidResponse,
    DeadlineExceeded,
    ResidentUnavailable,
}

impl fmt::Display for GatewayHealthError {
    // Presents fixed process-readiness language without leaking native or identity detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("Gateway health contract is invalid"),
            Self::EndpointUnavailable => {
                formatter.write_str("Gateway health endpoint is unavailable")
            }
            Self::AuthenticationUnavailable => {
                formatter.write_str("Gateway health authentication is unavailable")
            }
            Self::InvalidResponse => formatter.write_str("Gateway health response is invalid"),
            Self::DeadlineExceeded => formatter.write_str("Gateway health deadline expired"),
            Self::ResidentUnavailable => {
                formatter.write_str("Gateway health resident is unavailable")
            }
        }
    }
}

impl Error for GatewayHealthError {}

// Carries the exact immutable process identity returned by the local health endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResidentIdentity {
    node_id: NodeId,
    mode: GatewayConfigurationMode,
    core_version: CoreVersion,
    core_source_identity: Sha256Digest,
}

impl GatewayResidentIdentity {
    // Copies the exact process identity from one already validated configuration.
    pub fn from_configuration(configuration: &GatewayConfiguration) -> Self {
        Self {
            node_id: configuration.node_id().clone(),
            mode: configuration.mode(),
            core_version: configuration.core_version().clone(),
            core_source_identity: configuration.core_source_identity().clone(),
        }
    }

    // Returns the local Node identity served by this Gateway.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns whether this is a main or child Gateway.
    pub const fn mode(&self) -> GatewayConfigurationMode {
        self.mode
    }

    // Returns the exact Core release executing this resident.
    pub const fn core_version(&self) -> &CoreVersion {
        &self.core_version
    }

    // Returns the immutable Core source-manifest identity executing this resident.
    pub const fn core_source_identity(&self) -> &Sha256Digest {
        &self.core_source_identity
    }
}

// Selects whether the exact resident is currently ready to serve its configured surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHealthObservation {
    Ready,
    NotReady,
}

// Supplies the one live readiness judgment owned by GatewayManager telemetry state.
pub trait GatewayHealthReadinessProvider: Send + Sync {
    // Returns true only after a successful atomic telemetry publication remains fresh.
    fn is_ready(&self) -> Result<bool, GatewayHealthError>;
}

impl GatewayHealthReadinessProvider for GatewayManager {
    // Projects manager-owned telemetry freshness without exposing its native failure.
    fn is_ready(&self) -> Result<bool, GatewayHealthError> {
        self.telemetry_health()
            .map(|health| health.is_healthy())
            .map_err(|_| GatewayHealthError::ResidentUnavailable)
    }
}

// Exchanges one bounded request through an explicit owner-authenticated local boundary.
pub trait GatewayHealthExchange: Send + Sync {
    // Returns one complete response under the caller's single absolute operation deadline.
    fn exchange(
        &self,
        configuration: &GatewayHealthConfiguration,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, GatewayHealthError>;
}

// Supplies the production owner-checked Unix-domain health exchange.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGatewayHealthExchange;

impl GatewayHealthExchange for SystemGatewayHealthExchange {
    // Connects, authenticates, exchanges, and revalidates one socket under one deadline.
    fn exchange(
        &self,
        configuration: &GatewayHealthConfiguration,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, GatewayHealthError> {
        if timeout.is_zero()
            || timeout > GATEWAY_HEALTH_MAXIMUM_TIMEOUT
            || request.is_empty()
            || request.len() > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES
        {
            return Err(GatewayHealthError::InvalidContract);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(GatewayHealthError::InvalidContract)?;
        let directories =
            directory_chain_identity(configuration.socket_path(), configuration.owner_user_id())?;
        let before = socket_identity(configuration.socket_path(), configuration.owner_user_id())?;
        let mut stream = connect_unix_before(configuration.socket_path(), deadline)?;
        if peer_user_id(&stream).map_err(|_| GatewayHealthError::AuthenticationUnavailable)?
            != configuration.owner_user_id()
        {
            return Err(GatewayHealthError::AuthenticationUnavailable);
        }
        require_same_directory_chain(configuration, &directories)?;
        require_same_socket(configuration, before)?;
        write_frame_before(&mut stream, request, deadline)?;
        let response = read_frame_before(&mut stream, deadline)?;
        require_same_directory_chain(configuration, &directories)?;
        require_same_socket(configuration, before)?;
        Ok(response)
    }
}

// Owns the exact expected identity and local health exchange used by service setup.
pub struct GatewayHealthProbe {
    exchange: Arc<dyn GatewayHealthExchange>,
}

impl GatewayHealthProbe {
    // Creates one probe without discovering a socket, identity, or timeout.
    pub const fn new(exchange: Arc<dyn GatewayHealthExchange>) -> Self {
        Self { exchange }
    }

    // Verifies correlation, every immutable identity field, and live telemetry readiness.
    pub fn observe(
        &self,
        configuration: &GatewayConfiguration,
        timeout: Duration,
    ) -> Result<GatewayHealthObservation, GatewayHealthError> {
        if timeout.is_zero() || timeout > GATEWAY_HEALTH_MAXIMUM_TIMEOUT {
            return Err(GatewayHealthError::InvalidContract);
        }
        let identity = GatewayResidentIdentity::from_configuration(configuration);
        let request_id = health_request_id(&identity)?;
        let request = encode_request(&request_id)?;
        let response = self
            .exchange
            .exchange(configuration.health(), &request, timeout)?;
        let response = decode_response(&response)?;
        if response.request_id != request_id.as_str()
            || response.node_id != identity.node_id().as_str()
            || response.mode != mode_text(identity.mode())
            || response.core_release != identity.core_version().as_str()
            || response.core_source_identity != identity.core_source_identity().as_str()
        {
            return Err(GatewayHealthError::InvalidResponse);
        }
        match response.readiness.as_str() {
            "ready" => Ok(GatewayHealthObservation::Ready),
            "not_ready" => Ok(GatewayHealthObservation::NotReady),
            _ => Err(GatewayHealthError::InvalidResponse),
        }
    }
}

// Owns one live health socket, every accepted stream, and complete worker shutdown.
pub struct GatewayHealthServer {
    configuration: GatewayHealthConfiguration,
    socket_identity: SocketIdentity,
    _directory_guard: GatewayOwnerPathGuard,
    state: Arc<GatewayHealthServerState>,
}

impl GatewayHealthServer {
    // Starts one owner-only local resident without replacing an active or foreign endpoint.
    pub fn start(
        configuration: GatewayHealthConfiguration,
        identity: GatewayResidentIdentity,
        readiness: Arc<dyn GatewayHealthReadinessProvider>,
    ) -> Result<Self, GatewayHealthError> {
        validate_server_owner(&configuration)?;
        let directories =
            directory_chain_identity(configuration.socket_path(), configuration.owner_user_id())?;
        prepare_socket_path(&configuration)?;
        let cleanup_path = configuration.socket_path().to_path_buf();
        let cleanup_owner = configuration.owner_user_id();
        let listener = UnixListener::bind(configuration.socket_path())
            .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
        let startup = (|| {
            fs::set_permissions(
                configuration.socket_path(),
                fs::Permissions::from_mode(GATEWAY_HEALTH_SOCKET_MODE),
            )
            .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
            let socket_identity =
                socket_identity(configuration.socket_path(), configuration.owner_user_id())?;
            require_same_directory_chain(&configuration, &directories)?;
            listener
                .set_nonblocking(true)
                .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
            let state = Arc::new(GatewayHealthServerState::new());
            let endpoint = Arc::new(GatewayHealthEndpoint {
                identity,
                readiness,
            });
            let supervisor_state = state.clone();
            let supervisor_configuration = configuration.clone();
            let supervisor = thread::Builder::new()
                .name("li_gateway_health_listener".to_string())
                .spawn(move || {
                    serve_health_listener(
                        listener,
                        supervisor_configuration,
                        endpoint,
                        supervisor_state,
                    )
                })
                .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
            match state.completion.lock() {
                Ok(mut completion) => completion.supervisor = Some(supervisor),
                Err(_) => {
                    state.stopping.store(true, Ordering::Release);
                    let _ = supervisor.join();
                    return Err(GatewayHealthError::ResidentUnavailable);
                }
            }
            Ok(Self {
                configuration,
                socket_identity,
                _directory_guard: directories,
                state,
            })
        })();
        if startup.is_err() {
            let _ = remove_exact_socket(&cleanup_path, cleanup_owner, None);
        }
        startup
    }

    // Requests idempotent stop and interrupts every currently accepted connection.
    pub fn stop(&self) -> Result<(), GatewayHealthError> {
        self.state.stopping.store(true, Ordering::Release);
        let streams = self
            .state
            .streams
            .lock()
            .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
        for stream in streams.values() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }

    // Stops, joins the supervisor and workers, then removes only this exact socket identity.
    pub fn join(&self) -> Result<(), GatewayHealthError> {
        self.stop()?;
        let mut completion = self
            .state
            .completion
            .lock()
            .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
        if let Some(result) = completion.result {
            return result;
        }
        let supervisor = completion
            .supervisor
            .take()
            .ok_or(GatewayHealthError::ResidentUnavailable)?;
        let worker_result = supervisor
            .join()
            .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
        let socket_result = remove_exact_socket(
            self.configuration.socket_path(),
            self.configuration.owner_user_id(),
            Some(self.socket_identity),
        );
        let result = worker_result.and(socket_result);
        completion.result = Some(result);
        result
    }
}

impl Drop for GatewayHealthServer {
    // Prevents the health listener or any stalled connection from surviving its process owner.
    fn drop(&mut self) {
        let _ = self.join();
    }
}

// Handles one validated request without owning socket or worker lifecycle.
struct GatewayHealthEndpoint {
    identity: GatewayResidentIdentity,
    readiness: Arc<dyn GatewayHealthReadinessProvider>,
}

impl GatewayHealthEndpoint {
    // Returns one exact identity-bound response and treats provider failure as not ready.
    fn handle(&self, request: &[u8]) -> Result<Vec<u8>, GatewayHealthError> {
        let request = decode_request(request)?;
        let readiness = if self.readiness.is_ready().unwrap_or(false) {
            "ready"
        } else {
            "not_ready"
        };
        encode_response(&request.request_id, &self.identity, readiness)
    }
}

// Owns stop state, interruptible streams, and replayable supervisor completion.
struct GatewayHealthServerState {
    stopping: AtomicBool,
    active_workers: AtomicUsize,
    next_connection_id: AtomicU64,
    streams: Mutex<BTreeMap<u64, UnixStream>>,
    completion: Mutex<GatewayHealthServerCompletion>,
}

impl GatewayHealthServerState {
    // Creates one empty server state before any worker can observe it.
    fn new() -> Self {
        Self {
            stopping: AtomicBool::new(false),
            active_workers: AtomicUsize::new(0),
            next_connection_id: AtomicU64::new(1),
            streams: Mutex::new(BTreeMap::new()),
            completion: Mutex::new(GatewayHealthServerCompletion::default()),
        }
    }

    // Reserves one worker slot without ever exceeding the configured maximum.
    fn reserve_worker(&self, maximum_workers: usize) -> bool {
        let mut active = self.active_workers.load(Ordering::Acquire);
        loop {
            if active >= maximum_workers {
                return false;
            }
            match self.active_workers.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => active = observed,
            }
        }
    }
}

// Retains one completed supervisor outcome so repeated joins are idempotent.
#[derive(Default)]
struct GatewayHealthServerCompletion {
    supervisor: Option<JoinHandle<Result<(), GatewayHealthError>>>,
    result: Option<Result<(), GatewayHealthError>>,
}

// Releases one registered stream and its worker slot on every exit path.
struct GatewayHealthWorkerGuard {
    connection_id: u64,
    state: Arc<GatewayHealthServerState>,
}

impl Drop for GatewayHealthWorkerGuard {
    // Removes the connection interruption handle before releasing its exact slot.
    fn drop(&mut self) {
        match self.state.streams.lock() {
            Ok(mut streams) => {
                streams.remove(&self.connection_id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&self.connection_id);
            }
        }
        self.state.active_workers.fetch_sub(1, Ordering::AcqRel);
    }
}

// Accepts bounded connections and joins every spawned worker before completion.
fn serve_health_listener(
    listener: UnixListener,
    configuration: GatewayHealthConfiguration,
    endpoint: Arc<GatewayHealthEndpoint>,
    state: Arc<GatewayHealthServerState>,
) -> Result<(), GatewayHealthError> {
    let mut workers = Vec::new();
    let mut result = Ok(());
    while !state.stopping.load(Ordering::Acquire) {
        reap_health_workers(&mut workers, &mut result);
        match listener.accept() {
            Ok((mut stream, _)) => {
                if state.stopping.load(Ordering::Acquire) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    break;
                }
                if !state.reserve_worker(configuration.maximum_workers()) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let guard = match register_health_stream(&state, &stream) {
                    Ok(guard) => guard,
                    Err(error) => {
                        state.active_workers.fetch_sub(1, Ordering::AcqRel);
                        result = Err(error);
                        break;
                    }
                };
                let worker_endpoint = endpoint.clone();
                let worker_configuration = configuration.clone();
                match thread::Builder::new()
                    .name("li_gateway_health_connection".to_string())
                    .spawn(move || {
                        let _guard = guard;
                        serve_health_connection(
                            &mut stream,
                            &worker_configuration,
                            worker_endpoint.as_ref(),
                        )
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(_) => {
                        result = Err(GatewayHealthError::ResidentUnavailable);
                        break;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(configuration.accept_poll_interval());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                result = Err(GatewayHealthError::ResidentUnavailable);
                break;
            }
        }
    }
    state.stopping.store(true, Ordering::Release);
    if let Ok(streams) = state.streams.lock() {
        for stream in streams.values() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    } else if result.is_ok() {
        result = Err(GatewayHealthError::ResidentUnavailable);
    }
    for worker in workers {
        if worker.join().is_err() && result.is_ok() {
            result = Err(GatewayHealthError::ResidentUnavailable);
        }
    }
    result
}

// Registers one cloned interruption handle before its worker becomes visible.
fn register_health_stream(
    state: &Arc<GatewayHealthServerState>,
    stream: &UnixStream,
) -> Result<GatewayHealthWorkerGuard, GatewayHealthError> {
    let interrupt = stream
        .try_clone()
        .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
    let connection_id = state
        .next_connection_id
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
    state
        .streams
        .lock()
        .map_err(|_| GatewayHealthError::ResidentUnavailable)?
        .insert(connection_id, interrupt);
    Ok(GatewayHealthWorkerGuard {
        connection_id,
        state: state.clone(),
    })
}

// Reaps finished workers while preserving the first resident lifecycle failure.
fn reap_health_workers(
    workers: &mut Vec<JoinHandle<Result<(), GatewayHealthError>>>,
    result: &mut Result<(), GatewayHealthError>,
) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            if worker.join().is_err() && result.is_ok() {
                *result = Err(GatewayHealthError::ResidentUnavailable);
            }
        } else {
            index += 1;
        }
    }
}

// Authenticates one peer, exchanges one frame, and always closes the connection.
fn serve_health_connection(
    stream: &mut UnixStream,
    configuration: &GatewayHealthConfiguration,
    endpoint: &GatewayHealthEndpoint,
) -> Result<(), GatewayHealthError> {
    stream
        .set_read_timeout(Some(configuration.read_timeout()))
        .and_then(|()| stream.set_write_timeout(Some(configuration.write_timeout())))
        .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
    if peer_user_id(stream).map_err(|_| GatewayHealthError::AuthenticationUnavailable)?
        != configuration.owner_user_id()
    {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    let result = read_frame(stream)
        .and_then(|request| endpoint.handle(&request))
        .and_then(|response| write_frame(stream, &response));
    let _ = stream.shutdown(if result.is_ok() {
        std::net::Shutdown::Write
    } else {
        std::net::Shutdown::Both
    });
    result
}

// Validates the effective owner and one canonical private socket directory.
fn validate_server_owner(
    configuration: &GatewayHealthConfiguration,
) -> Result<(), GatewayHealthError> {
    if effective_user_id() != configuration.owner_user_id() {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    directory_chain_identity(configuration.socket_path(), configuration.owner_user_id()).map(|_| ())
}

// Rejects active or unsafe paths and removes only an unchanged stale owner socket.
fn prepare_socket_path(
    configuration: &GatewayHealthConfiguration,
) -> Result<(), GatewayHealthError> {
    directory_chain_identity(configuration.socket_path(), configuration.owner_user_id())?;
    let observed = match fs::symlink_metadata(configuration.socket_path()) {
        Ok(metadata) => socket_identity_from_metadata(&metadata, configuration.owner_user_id())?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(GatewayHealthError::EndpointUnavailable),
    };
    if UnixStream::connect(configuration.socket_path()).is_ok() {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    remove_exact_socket(
        configuration.socket_path(),
        configuration.owner_user_id(),
        Some(observed),
    )
}

// Records the metadata needed to detect replacement or permission mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    user_id: u32,
    mode: u32,
    link_count: u64,
}

// Records one directory component identity without retaining its path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

// Retains every no-follow directory descriptor across one native path operation.
struct GatewayOwnerPathGuard {
    _directories: Vec<File>,
    identities: Vec<DirectoryIdentity>,
}

// Opens every directory component without following links and validates mutation authority.
fn directory_chain_identity(
    socket_path: &Path,
    owner_user_id: u32,
) -> Result<GatewayOwnerPathGuard, GatewayHealthError> {
    let parent = socket_path
        .parent()
        .ok_or(GatewayHealthError::InvalidContract)?;
    if !parent.is_absolute() {
        return Err(GatewayHealthError::InvalidContract);
    }
    let component_count = parent
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    let mut directories = Vec::new();
    let mut identities = Vec::new();
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    let directory = options
        .open("/")
        .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
    let root = directory
        .metadata()
        .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
    if !root.is_dir() {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    identities.push(DirectoryIdentity {
        device: root.dev(),
        inode: root.ino(),
    });
    validate_directory_authority(&root, owner_user_id, component_count == 0)?;
    directories.push(directory);
    let mut component_index = 0;
    for component in parent.components() {
        let component = match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(component) => component,
            _ => return Err(GatewayHealthError::InvalidContract),
        };
        let name =
            CString::new(component.as_bytes()).map_err(|_| GatewayHealthError::InvalidContract)?;
        // SAFETY: directory is live and name contains one relative NUL-free component.
        let descriptor = unsafe {
            libc::openat(
                directories
                    .last()
                    .ok_or(GatewayHealthError::AuthenticationUnavailable)?
                    .as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if descriptor < 0 {
            return Err(directory_open_error(&io::Error::last_os_error()));
        }
        // SAFETY: descriptor is newly owned and transfers into exactly one File.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        let metadata = opened
            .metadata()
            .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
        if !metadata.is_dir() {
            return Err(GatewayHealthError::AuthenticationUnavailable);
        }
        component_index += 1;
        identities.push(DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        validate_directory_authority(&metadata, owner_user_id, component_index == component_count)?;
        directories.push(opened);
    }
    Ok(GatewayOwnerPathGuard {
        _directories: directories,
        identities,
    })
}

// Requires immutable ancestors and one exact owner-only final socket directory.
fn validate_directory_authority(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    is_final: bool,
) -> Result<(), GatewayHealthError> {
    if !metadata.is_dir() {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    let mode = metadata.mode() & 0o7777;
    if is_final {
        if metadata.uid() != owner_user_id || mode != GATEWAY_HEALTH_DIRECTORY_MODE {
            return Err(GatewayHealthError::AuthenticationUnavailable);
        }
        return Ok(());
    }
    if mode & 0o022 == 0 || metadata.uid() == 0 && mode & libc::S_ISVTX as u32 != 0 {
        return Ok(());
    }
    Err(GatewayHealthError::AuthenticationUnavailable)
}

// Classifies missing directories separately from symlink or non-directory traversal.
fn directory_open_error(error: &io::Error) -> GatewayHealthError {
    if error.kind() == io::ErrorKind::NotFound {
        GatewayHealthError::EndpointUnavailable
    } else {
        GatewayHealthError::AuthenticationUnavailable
    }
}

// Requires every directory component to retain its pre-connection identity.
fn require_same_directory_chain(
    configuration: &GatewayHealthConfiguration,
    expected: &GatewayOwnerPathGuard,
) -> Result<(), GatewayHealthError> {
    let observed =
        directory_chain_identity(configuration.socket_path(), configuration.owner_user_id())?;
    if observed.identities != expected.identities {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    Ok(())
}

// Observes one exact owner-only socket without following a symlink.
fn socket_identity(path: &Path, owner_user_id: u32) -> Result<SocketIdentity, GatewayHealthError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GatewayHealthError::EndpointUnavailable)?;
    socket_identity_from_metadata(&metadata, owner_user_id)
}

// Converts safe native metadata into one comparable socket identity.
fn socket_identity_from_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<SocketIdentity, GatewayHealthError> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != GATEWAY_HEALTH_SOCKET_MODE
        || metadata.nlink() != 1
    {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        user_id: metadata.uid(),
        mode: metadata.mode(),
        link_count: metadata.nlink(),
    })
}

// Requires the path to retain the exact socket observed before connection.
fn require_same_socket(
    configuration: &GatewayHealthConfiguration,
    expected: SocketIdentity,
) -> Result<(), GatewayHealthError> {
    if socket_identity(configuration.socket_path(), configuration.owner_user_id())? != expected {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    Ok(())
}

// Removes only an optional exact socket identity and never follows another file type.
fn remove_exact_socket(
    path: &Path,
    owner_user_id: u32,
    expected: Option<SocketIdentity>,
) -> Result<(), GatewayHealthError> {
    directory_chain_identity(path, owner_user_id)?;
    let observed = match fs::symlink_metadata(path) {
        Ok(metadata) => socket_identity_from_metadata(&metadata, owner_user_id)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(GatewayHealthError::EndpointUnavailable),
    };
    if expected.is_some_and(|expected| expected != observed) {
        return Err(GatewayHealthError::AuthenticationUnavailable);
    }
    fs::remove_file(path).map_err(|_| GatewayHealthError::EndpointUnavailable)
}

// Derives one stable request correlation identity from every expected resident field.
fn health_request_id(
    identity: &GatewayResidentIdentity,
) -> Result<Sha256Digest, GatewayHealthError> {
    let mut digest = Sha256::new();
    digest.update(b"li_gateway_health_v1\0");
    digest.update(identity.node_id().as_str().as_bytes());
    digest.update(b"\0");
    digest.update(mode_text(identity.mode()).as_bytes());
    digest.update(b"\0");
    digest.update(identity.core_version().as_str().as_bytes());
    digest.update(b"\0");
    digest.update(identity.core_source_identity().as_str().as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| GatewayHealthError::InvalidContract)
}

// Returns the one canonical wire value for a validated Gateway mode.
const fn mode_text(mode: GatewayConfigurationMode) -> &'static str {
    match mode {
        GatewayConfigurationMode::Main => "main",
        GatewayConfigurationMode::Child => "child",
    }
}

// Serializes one exact closed health request.
fn encode_request(request_id: &Sha256Digest) -> Result<Vec<u8>, GatewayHealthError> {
    serde_json::to_vec(&GatewayHealthRequestDocument {
        schema: GatewayHealthSchemaDocument {
            name: LI_GATEWAY_HEALTH_SCHEMA_NAME,
            version: LI_GATEWAY_HEALTH_SCHEMA_VERSION,
        },
        request_id: request_id.as_str(),
    })
    .map_err(|_| GatewayHealthError::InvalidContract)
}

// Decodes one exact closed request and validates its correlation identity.
fn decode_request(document: &[u8]) -> Result<GatewayHealthRequestOwned, GatewayHealthError> {
    if document.is_empty() || document.len() > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES {
        return Err(GatewayHealthError::InvalidContract);
    }
    let decoded = serde_json::from_slice::<GatewayHealthRequestOwned>(document)
        .map_err(|_| GatewayHealthError::InvalidContract)?;
    validate_schema(&decoded.schema).map_err(|_| GatewayHealthError::InvalidContract)?;
    Sha256Digest::parse(&decoded.request_id).map_err(|_| GatewayHealthError::InvalidContract)?;
    Ok(decoded)
}

// Serializes one exact identity-bound readiness response.
fn encode_response(
    request_id: &str,
    identity: &GatewayResidentIdentity,
    readiness: &'static str,
) -> Result<Vec<u8>, GatewayHealthError> {
    serde_json::to_vec(&GatewayHealthResponseDocument {
        schema: GatewayHealthSchemaDocument {
            name: LI_GATEWAY_HEALTH_SCHEMA_NAME,
            version: LI_GATEWAY_HEALTH_SCHEMA_VERSION,
        },
        request_id,
        node_id: identity.node_id().as_str(),
        mode: mode_text(identity.mode()),
        core_release: identity.core_version().as_str(),
        core_source_identity: identity.core_source_identity().as_str(),
        readiness,
    })
    .map_err(|_| GatewayHealthError::ResidentUnavailable)
}

// Decodes and structurally validates one exact closed response document.
fn decode_response(document: &[u8]) -> Result<GatewayHealthResponseOwned, GatewayHealthError> {
    if document.is_empty() || document.len() > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES {
        return Err(GatewayHealthError::InvalidResponse);
    }
    let decoded = serde_json::from_slice::<GatewayHealthResponseOwned>(document)
        .map_err(|_| GatewayHealthError::InvalidResponse)?;
    validate_schema(&decoded.schema)?;
    Sha256Digest::parse(&decoded.request_id).map_err(|_| GatewayHealthError::InvalidResponse)?;
    NodeId::parse(&decoded.node_id).map_err(|_| GatewayHealthError::InvalidResponse)?;
    CoreVersion::parse(&decoded.core_release).map_err(|_| GatewayHealthError::InvalidResponse)?;
    Sha256Digest::parse(&decoded.core_source_identity)
        .map_err(|_| GatewayHealthError::InvalidResponse)?;
    Ok(decoded)
}

// Requires the exact protocol name and version without accepting compatibility aliases.
fn validate_schema(schema: &GatewayHealthSchemaOwned) -> Result<(), GatewayHealthError> {
    if schema.name != LI_GATEWAY_HEALTH_SCHEMA_NAME
        || schema.version != LI_GATEWAY_HEALTH_SCHEMA_VERSION
    {
        return Err(GatewayHealthError::InvalidResponse);
    }
    Ok(())
}

// Projects the common nested schema identity into encoded documents.
#[derive(Serialize)]
struct GatewayHealthSchemaDocument<'a> {
    name: &'a str,
    version: u32,
}

// Projects one correlation-only health request.
#[derive(Serialize)]
struct GatewayHealthRequestDocument<'a> {
    schema: GatewayHealthSchemaDocument<'a>,
    request_id: &'a str,
}

// Projects one complete identity-bound health response.
#[derive(Serialize)]
struct GatewayHealthResponseDocument<'a> {
    schema: GatewayHealthSchemaDocument<'a>,
    request_id: &'a str,
    node_id: &'a str,
    mode: &'a str,
    core_release: &'a str,
    core_source_identity: &'a str,
    readiness: &'a str,
}

// Decodes the exact nested health schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayHealthSchemaOwned {
    name: String,
    version: u32,
}

// Decodes the exact health request field set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayHealthRequestOwned {
    schema: GatewayHealthSchemaOwned,
    request_id: String,
}

// Decodes the exact health response field set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayHealthResponseOwned {
    schema: GatewayHealthSchemaOwned,
    request_id: String,
    node_id: String,
    mode: String,
    core_release: String,
    core_source_identity: String,
    readiness: String,
}

// Writes one bounded frame with a fixed four-byte big-endian length.
fn write_frame(stream: &mut UnixStream, document: &[u8]) -> Result<(), GatewayHealthError> {
    if document.is_empty() || document.len() > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES {
        return Err(GatewayHealthError::InvalidContract);
    }
    let length = u32::try_from(document.len()).map_err(|_| GatewayHealthError::InvalidContract)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(document))
        .map_err(|_| GatewayHealthError::ResidentUnavailable)
}

// Reads one bounded complete frame without accepting trailing or empty payload semantics.
fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, GatewayHealthError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| GatewayHealthError::InvalidContract)?;
    if length == 0 || length > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES {
        return Err(GatewayHealthError::InvalidContract);
    }
    let mut document = vec![0_u8; length];
    stream
        .read_exact(&mut document)
        .map_err(|_| GatewayHealthError::ResidentUnavailable)?;
    Ok(document)
}

// Writes one complete frame while recomputing the remaining absolute deadline on progress.
fn write_frame_before(
    stream: &mut UnixStream,
    document: &[u8],
    deadline: Instant,
) -> Result<(), GatewayHealthError> {
    if document.is_empty() || document.len() > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES {
        return Err(GatewayHealthError::InvalidContract);
    }
    let length = u32::try_from(document.len()).map_err(|_| GatewayHealthError::InvalidContract)?;
    write_all_before(stream, &length.to_be_bytes(), deadline)?;
    write_all_before(stream, document, deadline)
}

// Reads one complete frame while keeping header and body under the same deadline.
fn read_frame_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, GatewayHealthError> {
    let mut header = [0_u8; 4];
    read_exact_before(stream, &mut header, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| GatewayHealthError::InvalidResponse)?;
    if length == 0 || length > GATEWAY_HEALTH_MAXIMUM_DOCUMENT_BYTES {
        return Err(GatewayHealthError::InvalidResponse);
    }
    let mut document = vec![0_u8; length];
    read_exact_before(stream, &mut document, deadline)?;
    Ok(document)
}

// Writes until complete while applying the remaining deadline before every native call.
fn write_all_before(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), GatewayHealthError> {
    while !bytes.is_empty() {
        wait_for_io(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(GatewayHealthError::EndpointUnavailable),
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(GatewayHealthError::DeadlineExceeded);
            }
            Err(_) => return Err(GatewayHealthError::EndpointUnavailable),
        }
    }
    Ok(())
}

// Reads until complete while applying the remaining deadline before every native call.
fn read_exact_before(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), GatewayHealthError> {
    while !bytes.is_empty() {
        wait_for_io(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(GatewayHealthError::InvalidResponse),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(GatewayHealthError::DeadlineExceeded);
            }
            Err(_) => return Err(GatewayHealthError::InvalidResponse),
        }
    }
    Ok(())
}

// Returns the positive duration left under one previously established deadline.
fn remaining(deadline: Instant) -> Result<Duration, GatewayHealthError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(GatewayHealthError::DeadlineExceeded)
    } else {
        Ok(remaining)
    }
}

// Waits for one descriptor direction while preserving the caller's absolute deadline.
fn wait_for_io(descriptor: i32, events: i16, deadline: Instant) -> Result<(), GatewayHealthError> {
    let timeout = poll_milliseconds(remaining(deadline)?)?;
    let mut descriptor_poll = libc::pollfd {
        fd: descriptor,
        events,
        revents: 0,
    };
    // SAFETY: descriptor_poll is valid for one element for the bounded poll duration.
    let result = unsafe { libc::poll(&mut descriptor_poll, 1, timeout) };
    if result == 0 {
        return Err(GatewayHealthError::DeadlineExceeded);
    }
    if result < 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    if descriptor_poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    Ok(())
}

// Connects a nonblocking Unix socket before the caller's absolute deadline.
fn connect_unix_before(path: &Path, deadline: Instant) -> Result<UnixStream, GatewayHealthError> {
    let path = unix_socket_path(path)?;
    // SAFETY: socket arguments are fixed valid constants and the returned descriptor is owned.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if descriptor < 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    // SAFETY: descriptor was just returned by socket and transfers exactly once into OwnedFd.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    configure_nonblocking_descriptor(descriptor.as_raw_fd())?;
    // SAFETY: zero is a valid initial representation before required fields are assigned.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = sockaddr_length(path.len())? as u8;
    }
    for (target, source) in address.sun_path.iter_mut().zip(path.iter().copied()) {
        *target = source as libc::c_char;
    }
    let address_length = sockaddr_length(path.len())?;
    // SAFETY: address is initialized for AF_UNIX and address_length covers its path bytes.
    let result = unsafe {
        libc::connect(
            descriptor.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            address_length,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        ) {
            return Err(GatewayHealthError::EndpointUnavailable);
        }
        wait_for_connection(descriptor.as_raw_fd(), deadline)?;
    }
    configure_blocking_descriptor(descriptor.as_raw_fd())?;
    // SAFETY: descriptor ownership transfers from OwnedFd into exactly one UnixStream.
    Ok(unsafe { UnixStream::from_raw_fd(descriptor.into_raw_fd()) })
}

// Converts one absolute non-NUL path into bounded sockaddr bytes.
fn unix_socket_path(path: &Path) -> Result<Vec<u8>, GatewayHealthError> {
    let bytes = OsStr::new(path).as_bytes();
    // SAFETY: a zeroed sockaddr_un is used only to observe its fixed path capacity.
    let capacity = unsafe { mem::zeroed::<libc::sockaddr_un>() }.sun_path.len();
    if !path.is_absolute() || bytes.is_empty() || bytes.contains(&0) || bytes.len() >= capacity {
        return Err(GatewayHealthError::InvalidContract);
    }
    Ok(bytes.to_vec())
}

// Returns the native sockaddr length for the exact path plus its terminator.
fn sockaddr_length(path_bytes: usize) -> Result<libc::socklen_t, GatewayHealthError> {
    let base = mem::size_of::<libc::sockaddr_un>()
        .checked_sub(unsafe { mem::zeroed::<libc::sockaddr_un>() }.sun_path.len())
        .ok_or(GatewayHealthError::InvalidContract)?;
    libc::socklen_t::try_from(base + path_bytes + 1)
        .map_err(|_| GatewayHealthError::InvalidContract)
}

// Enables close-on-exec and nonblocking connect on one newly owned descriptor.
fn configure_nonblocking_descriptor(descriptor: i32) -> Result<(), GatewayHealthError> {
    // SAFETY: fcntl receives one live descriptor and fixed commands with integer arguments.
    let descriptor_result = unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: the returned file-status flags are read without changing descriptor ownership.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    // SAFETY: the same live descriptor receives its prior flags plus O_NONBLOCK.
    let nonblocking = unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if descriptor_result != 0 || flags < 0 || nonblocking != 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    Ok(())
}

// Restores blocking stream semantics after the bounded connect completes.
fn configure_blocking_descriptor(descriptor: i32) -> Result<(), GatewayHealthError> {
    // SAFETY: fcntl only reads and writes status flags on one live owned descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    let result = unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if flags < 0 || result != 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    Ok(())
}

// Waits for nonblocking connect completion and verifies its terminal socket error.
fn wait_for_connection(descriptor: i32, deadline: Instant) -> Result<(), GatewayHealthError> {
    let timeout = poll_milliseconds(remaining(deadline)?)?;
    let mut descriptor_poll = libc::pollfd {
        fd: descriptor,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: descriptor_poll is valid for one element for the bounded poll duration.
    let result = unsafe { libc::poll(&mut descriptor_poll, 1, timeout) };
    if result == 0 {
        return Err(GatewayHealthError::DeadlineExceeded);
    }
    if result < 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    let mut socket_error = 0_i32;
    let mut length = libc::socklen_t::try_from(mem::size_of::<i32>())
        .map_err(|_| GatewayHealthError::EndpointUnavailable)?;
    // SAFETY: socket_error and length form a valid writable SO_ERROR result buffer.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut socket_error as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0 || socket_error != 0 {
        return Err(GatewayHealthError::EndpointUnavailable);
    }
    Ok(())
}

// Converts one positive duration to a bounded poll timeout rounded up to milliseconds.
fn poll_milliseconds(duration: Duration) -> Result<i32, GatewayHealthError> {
    let milliseconds = duration.as_millis().saturating_add(1);
    i32::try_from(milliseconds).map_err(|_| GatewayHealthError::InvalidContract)
}

// Returns the authenticated effective user on the peer end of one Unix stream.
#[cfg(target_os = "linux")]
fn peer_user_id(stream: &UnixStream) -> io::Result<u32> {
    // SAFETY: zero initializes the output credential before getsockopt fills every byte.
    let mut credential: libc::ucred = unsafe { mem::zeroed() };
    let mut length = libc::socklen_t::try_from(mem::size_of::<libc::ucred>())
        .map_err(|_| io::Error::other("credential size"))?;
    // SAFETY: credential and length are valid writable SO_PEERCRED result buffers.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(credential.uid).map_err(|_| io::Error::other("credential identity"))
}

// Returns the authenticated effective user on the peer end of one Unix stream.
#[cfg(target_os = "macos")]
fn peer_user_id(stream: &UnixStream) -> io::Result<u32> {
    let mut user_id: libc::uid_t = 0;
    let mut group_id: libc::gid_t = 0;
    // SAFETY: both identity pointers are valid writable outputs for one live descriptor.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut user_id, &mut group_id) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(user_id)
}

// Returns the effective process account expected by owner-only native contracts.
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process identity.
    unsafe { libc::geteuid() }
}
