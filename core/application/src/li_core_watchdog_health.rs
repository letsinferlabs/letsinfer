// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_core_update_manager::{CoreUpdateServiceContext, CoreUpdateServicePlatform};
use li_watchdog_manager::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_response,
    encode_watchdog_protocol_frame, encode_watchdog_protocol_request,
    SystemWatchdogConfigurationFileProvider, WatchdogConfiguration, WatchdogConfigurationLoader,
    WatchdogProtocolRequest, WatchdogProtocolRequestKind, WatchdogProtocolResidentLifecycle,
    WatchdogProtocolResponseKind, WATCHDOG_PROTOCOL_MAX_FRAME_BYTES,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};

use crate::{
    CoreResidentProcess, CoreServiceSetupError, CoreServiceSetupObservation,
    CoreServiceSetupResidentHealth,
};

const WATCHDOG_HEALTH_MAXIMUM_TIMEOUT: Duration = Duration::from_secs(10);
const WATCHDOG_HEALTH_MAXIMUM_CERTIFICATE_BYTES: usize = 128 * 1024;
const WATCHDOG_HEALTH_MAXIMUM_PRIVATE_KEY_BYTES: usize = 128 * 1024;

// Names one stable Watchdog health failure without exposing endpoints or credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreWatchdogHealthError {
    InvalidContract,
    AuthenticationUnavailable,
    TransportUnavailable,
    DeadlineExceeded,
    InvalidResponse,
}

impl fmt::Display for CoreWatchdogHealthError {
    // Presents fixed health language without native diagnostic detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("Watchdog health contract is invalid"),
            Self::AuthenticationUnavailable => {
                formatter.write_str("Watchdog health authentication is unavailable")
            }
            Self::TransportUnavailable => {
                formatter.write_str("Watchdog health transport is unavailable")
            }
            Self::DeadlineExceeded => formatter.write_str("Watchdog health deadline expired"),
            Self::InvalidResponse => formatter.write_str("Watchdog health response is invalid"),
        }
    }
}

impl Error for CoreWatchdogHealthError {}

// Binds one owner to the exact trust anchor and controller identity used by the health client.
#[derive(Clone, Eq, PartialEq)]
pub struct CoreWatchdogHealthTlsFiles {
    owner_user_id: u32,
    server_ca_certificate_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
}

impl CoreWatchdogHealthTlsFiles {
    // Creates one distinct absolute owner-only TLS input set.
    pub fn new(
        owner_user_id: u32,
        server_ca_certificate_file: PathBuf,
        controller_certificate_file: PathBuf,
        controller_private_key_file: PathBuf,
    ) -> Result<Self, CoreWatchdogHealthError> {
        let paths = [
            &server_ca_certificate_file,
            &controller_certificate_file,
            &controller_private_key_file,
        ];
        let distinct = paths
            .iter()
            .enumerate()
            .all(|(index, path)| paths.iter().skip(index + 1).all(|other| path != other));
        if paths.iter().any(|path| !path.is_absolute()) || !distinct {
            return Err(CoreWatchdogHealthError::InvalidContract);
        }
        Ok(Self {
            owner_user_id,
            server_ca_certificate_file,
            controller_certificate_file,
            controller_private_key_file,
        })
    }
}

// Exchanges one exact framed Watchdog request through an authenticated native boundary.
pub trait CoreWatchdogHealthExchange: Send + Sync {
    // Returns exactly one complete response frame under the caller's absolute operation bound.
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, CoreWatchdogHealthError>;
}

// Supplies the production TLS 1.3 mutual-authentication Watchdog exchange.
pub struct SystemCoreWatchdogHealthExchange {
    client: Arc<ClientConfig>,
}

impl SystemCoreWatchdogHealthExchange {
    // Loads strict owner-only trust and controller identity files before service mutation.
    pub fn load(files: &CoreWatchdogHealthTlsFiles) -> Result<Self, CoreWatchdogHealthError> {
        let server_ca = read_tls_file(
            &files.server_ca_certificate_file,
            files.owner_user_id,
            WATCHDOG_HEALTH_MAXIMUM_CERTIFICATE_BYTES,
        )?;
        let controller_certificate = read_tls_file(
            &files.controller_certificate_file,
            files.owner_user_id,
            WATCHDOG_HEALTH_MAXIMUM_CERTIFICATE_BYTES,
        )?;
        let mut controller_private_key = read_tls_file(
            &files.controller_private_key_file,
            files.owner_user_id,
            WATCHDOG_HEALTH_MAXIMUM_PRIVATE_KEY_BYTES,
        )?;
        let result =
            client_configuration(&server_ca, &controller_certificate, &controller_private_key);
        controller_private_key.fill(0);
        result.map(|client| Self {
            client: Arc::new(client),
        })
    }
}

impl CoreWatchdogHealthExchange for SystemCoreWatchdogHealthExchange {
    // Completes one TLS handshake and one length-framed request/response under one deadline.
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, CoreWatchdogHealthError> {
        if timeout.is_zero()
            || timeout > WATCHDOG_HEALTH_MAXIMUM_TIMEOUT
            || request.len() < 5
            || request.len() > WATCHDOG_PROTOCOL_MAX_FRAME_BYTES + 4
        {
            return Err(CoreWatchdogHealthError::InvalidContract);
        }
        decode_watchdog_protocol_frame(request)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(CoreWatchdogHealthError::InvalidContract)?;
        let socket = TcpStream::connect_timeout(&endpoint, remaining(deadline)?)
            .map_err(|error| connection_error(&error))?;
        configure_socket_timeout(&socket, deadline)?;
        let server_name = ServerName::IpAddress(endpoint.ip().into());
        let connection = ClientConnection::new(self.client.clone(), server_name)
            .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)?;
        let mut stream = StreamOwned::new(connection, socket);
        complete_handshake(&mut stream, deadline)?;
        write_all(&mut stream, request, deadline)?;
        let response = read_frame(&mut stream, deadline);
        let _ = stream.sock.shutdown(Shutdown::Both);
        response
    }
}

// Owns the expected resident identity and its exact Watchdog health exchange.
pub struct CoreWatchdogServiceHealth {
    configuration: WatchdogConfiguration,
    expected_installation_id: InstallationId,
    exchange: Arc<dyn CoreWatchdogHealthExchange>,
}

impl CoreWatchdogServiceHealth {
    // Loads owner-bound Watchdog configuration and the production controller identity.
    pub fn load(
        configuration_file: PathBuf,
        owner_user_id: u32,
        tls_files: CoreWatchdogHealthTlsFiles,
    ) -> Result<Self, CoreServiceSetupError> {
        if tls_files.owner_user_id != owner_user_id {
            return Err(watchdog_health_provider_error(
                "Watchdog health credential owner is invalid",
            ));
        }
        let configuration = WatchdogConfigurationLoader::new(
            configuration_file,
            owner_user_id,
            Box::new(SystemWatchdogConfigurationFileProvider),
        )
        .and_then(|loader| loader.load())
        .map_err(|_| watchdog_health_provider_error("Watchdog health configuration is invalid"))?;
        let exchange = SystemCoreWatchdogHealthExchange::load(&tls_files)
            .map_err(map_watchdog_health_error)?;
        Self::new(configuration, Arc::new(exchange)).map_err(map_watchdog_health_error)
    }

    // Creates one deterministic health adapter from validated configuration and exchange.
    pub fn new(
        configuration: WatchdogConfiguration,
        exchange: Arc<dyn CoreWatchdogHealthExchange>,
    ) -> Result<Self, CoreWatchdogHealthError> {
        let expected_installation_id = InstallationId::parse(configuration.installation_id())
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        Ok(Self {
            configuration,
            expected_installation_id,
            exchange,
        })
    }

    // Observes one semantic resident identity through the authenticated protocol endpoint.
    pub fn observe_watchdog(
        &self,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreWatchdogHealthError> {
        if timeout.is_zero() {
            return Ok(CoreServiceSetupObservation::NotReady);
        }
        let timeout = timeout.min(WATCHDOG_HEALTH_MAXIMUM_TIMEOUT);
        let request_id = health_request_id(
            self.configuration.node_id(),
            self.configuration.core_release(),
            self.configuration.core_source_identity(),
            &self.expected_installation_id,
        )?;
        let request = WatchdogProtocolRequest::new(
            request_id,
            WatchdogProtocolRequestKind::GetResidentStatus,
        )
        .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let payload = encode_watchdog_protocol_request(&request)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let frame = encode_watchdog_protocol_frame(&payload)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let response = self.exchange.exchange(
            SocketAddr::new(
                self.configuration.listen_address(),
                self.configuration.listen_port(),
            ),
            &frame,
            timeout,
        )?;
        let payload = decode_watchdog_protocol_frame(&response)
            .map_err(|_| CoreWatchdogHealthError::InvalidResponse)?;
        let response = decode_watchdog_protocol_response(payload)
            .map_err(|_| CoreWatchdogHealthError::InvalidResponse)?;
        if response.request_id() != request_id {
            return Err(CoreWatchdogHealthError::InvalidResponse);
        }
        match response.kind() {
            WatchdogProtocolResponseKind::ResidentStatus(status)
                if status.node_id() == self.configuration.node_id()
                    && status.core_release() == self.configuration.core_release()
                    && status.core_source_identity()
                        == self.configuration.core_source_identity()
                    && status.installation_id() == &self.expected_installation_id
                    && status.lifecycle() == WatchdogProtocolResidentLifecycle::Ready =>
            {
                Ok(CoreServiceSetupObservation::Ready)
            }
            WatchdogProtocolResponseKind::ResidentStatus(_)
            | WatchdogProtocolResponseKind::Error { .. } => {
                Ok(CoreServiceSetupObservation::NotReady)
            }
            _ => Err(CoreWatchdogHealthError::InvalidResponse),
        }
    }
}

impl CoreServiceSetupResidentHealth for CoreWatchdogServiceHealth {
    // Requires the Linux Watchdog role and delegates to the authenticated semantic probe.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if context.platform() != CoreUpdateServicePlatform::Linux
            || process != CoreResidentProcess::Watchdog
        {
            return Err(watchdog_health_provider_error(
                "Watchdog health request does not match its service role",
            ));
        }
        self.observe_watchdog(timeout)
            .map_err(map_watchdog_health_error)
    }
}

// Reads one owner-only, no-follow, single-link TLS input under an exact byte bound.
fn read_tls_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<Vec<u8>, CoreWatchdogHealthError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)?;
    if !before.is_file()
        || before.uid() != owner_user_id
        || before.nlink() != 1
        || before.permissions().mode() & 0o777 != 0o600
        || before.len() == 0
        || before.len() > maximum_bytes as u64
    {
        return Err(CoreWatchdogHealthError::AuthenticationUnavailable);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bytes.fill(0);
        return Err(CoreWatchdogHealthError::AuthenticationUnavailable);
    }
    Ok(bytes)
}

// Builds one TLS 1.3-only mutual-authentication client from exact input bytes.
fn client_configuration(
    server_ca: &[u8],
    controller_certificate: &[u8],
    controller_private_key: &[u8],
) -> Result<ClientConfig, CoreWatchdogHealthError> {
    let server_certificates = parse_certificates(server_ca)?;
    let controller_certificates = parse_certificates(controller_certificate)?;
    let controller_private_key =
        rustls_pemfile::private_key(&mut Cursor::new(controller_private_key))
            .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)?
            .ok_or(CoreWatchdogHealthError::AuthenticationUnavailable)?;
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(server_certificates);
    if added == 0 || ignored != 0 || controller_certificates.is_empty() {
        return Err(CoreWatchdogHealthError::AuthenticationUnavailable);
    }
    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(controller_certificates, controller_private_key)
        .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)
}

// Parses every PEM certificate without accepting malformed or partial input.
fn parse_certificates(
    source: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, CoreWatchdogHealthError> {
    rustls_pemfile::certs(&mut Cursor::new(source))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreWatchdogHealthError::AuthenticationUnavailable)
}

// Completes TLS authentication while reapplying the one absolute operation deadline.
fn complete_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<(), CoreWatchdogHealthError> {
    while stream.conn.is_handshaking() {
        configure_socket_timeout(&stream.sock, deadline)?;
        let progress = stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|error| handshake_error(&error))?;
        if progress == (0, 0) && stream.conn.is_handshaking() {
            return Err(CoreWatchdogHealthError::AuthenticationUnavailable);
        }
    }
    Ok(())
}

// Writes every request byte while enforcing the same absolute deadline before each attempt.
fn write_all(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    source: &[u8],
    deadline: Instant,
) -> Result<(), CoreWatchdogHealthError> {
    let mut offset = 0;
    while offset < source.len() {
        configure_socket_timeout(&stream.sock, deadline)?;
        match stream.write(&source[offset..]) {
            Ok(0) => return Err(CoreWatchdogHealthError::TransportUnavailable),
            Ok(count) if count <= source.len() - offset => offset += count,
            Ok(_) => return Err(CoreWatchdogHealthError::TransportUnavailable),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(stream_error(&error)),
        }
    }
    configure_socket_timeout(&stream.sock, deadline)?;
    stream.flush().map_err(|error| stream_error(&error))
}

// Reads one exact bounded response frame under the shared absolute deadline.
fn read_frame(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<Vec<u8>, CoreWatchdogHealthError> {
    let mut header = [0_u8; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > WATCHDOG_PROTOCOL_MAX_FRAME_BYTES {
        return Err(CoreWatchdogHealthError::InvalidResponse);
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&header);
    read_exact(stream, &mut frame[4..], deadline)?;
    Ok(frame)
}

// Reads every destination byte while enforcing the same absolute deadline before each attempt.
fn read_exact(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    destination: &mut [u8],
    deadline: Instant,
) -> Result<(), CoreWatchdogHealthError> {
    let mut offset = 0;
    while offset < destination.len() {
        configure_socket_timeout(&stream.sock, deadline)?;
        match stream.read(&mut destination[offset..]) {
            Ok(0) => return Err(CoreWatchdogHealthError::TransportUnavailable),
            Ok(count) if count <= destination.len() - offset => offset += count,
            Ok(_) => return Err(CoreWatchdogHealthError::TransportUnavailable),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(stream_error(&error)),
        }
    }
    Ok(())
}

// Applies the exact remaining absolute deadline to both socket directions.
fn configure_socket_timeout(
    socket: &TcpStream,
    deadline: Instant,
) -> Result<(), CoreWatchdogHealthError> {
    let remaining = remaining(deadline)?;
    socket
        .set_read_timeout(Some(remaining))
        .and_then(|()| socket.set_write_timeout(Some(remaining)))
        .map_err(|_| CoreWatchdogHealthError::TransportUnavailable)
}

// Returns the positive duration remaining before one absolute deadline.
fn remaining(deadline: Instant) -> Result<Duration, CoreWatchdogHealthError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(CoreWatchdogHealthError::DeadlineExceeded)
}

// Classifies one native connection failure without retaining endpoint diagnostics.
fn connection_error(error: &std::io::Error) -> CoreWatchdogHealthError {
    if is_timeout(error) {
        CoreWatchdogHealthError::DeadlineExceeded
    } else {
        CoreWatchdogHealthError::TransportUnavailable
    }
}

// Classifies one TLS handshake failure without exposing certificate detail.
fn handshake_error(error: &std::io::Error) -> CoreWatchdogHealthError {
    if is_timeout(error) {
        CoreWatchdogHealthError::DeadlineExceeded
    } else {
        CoreWatchdogHealthError::AuthenticationUnavailable
    }
}

// Classifies one authenticated stream failure without retaining peer diagnostics.
fn stream_error(error: &std::io::Error) -> CoreWatchdogHealthError {
    if is_timeout(error) {
        CoreWatchdogHealthError::DeadlineExceeded
    } else {
        CoreWatchdogHealthError::TransportUnavailable
    }
}

// Returns whether one native I/O failure represents the elapsed operation bound.
fn is_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

// Derives one deterministic nonzero request identity from the exact expected resident identity.
fn health_request_id(
    node_id: &NodeId,
    core_release: &str,
    core_source_identity: &Sha256Digest,
    installation_id: &InstallationId,
) -> Result<u64, CoreWatchdogHealthError> {
    let mut digest = Sha256::new();
    digest.update(b"li_watchdog_health_v1\0");
    digest.update(node_id.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(core_release.as_bytes());
    digest.update(b"\0");
    digest.update(core_source_identity.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(installation_id.as_str().as_bytes());
    let output = digest.finalize();
    let request_id = u64::from_be_bytes(
        output[..8]
            .try_into()
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?,
    );
    Ok(request_id.max(1))
}

// Converts one closed health failure into stable service-setup provider language.
fn map_watchdog_health_error(error: CoreWatchdogHealthError) -> CoreServiceSetupError {
    let reason = match error {
        CoreWatchdogHealthError::InvalidContract => "Watchdog health contract is invalid",
        CoreWatchdogHealthError::AuthenticationUnavailable => {
            "Watchdog health authentication is unavailable"
        }
        CoreWatchdogHealthError::TransportUnavailable => "Watchdog health transport is unavailable",
        CoreWatchdogHealthError::DeadlineExceeded => "Watchdog health deadline expired",
        CoreWatchdogHealthError::InvalidResponse => "Watchdog health response is invalid",
    };
    watchdog_health_provider_error(reason)
}

// Creates one stable Watchdog service-setup failure without native detail.
fn watchdog_health_provider_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::provider("Watchdog resident health", reason)
}
