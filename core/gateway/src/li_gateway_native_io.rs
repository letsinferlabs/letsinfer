// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};

use crate::GatewayExecutionFailure;

const MAX_FILE_BYTES: usize = 128 * 1024;
const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_HEADER_NAME_BYTES: usize = 128;
const MAX_RESPONSE_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_CHUNK_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT_SECONDS: u64 = 10;
const HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
const WRITE_TIMEOUT_SECONDS: u64 = 30;
const READ_TIMEOUT_SECONDS: u64 = 60 * 60;
const MAX_HANDSHAKE_IO_CYCLES: usize = 16;

// Identifies whether one native failure occurred before or after caller-visible output began.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayNativeIoFailurePhase {
    BeforeResponseHead,
    AfterResponseHead,
}

// Carries one stable redacted native network or filesystem failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayNativeIoError {
    phase: GatewayNativeIoFailurePhase,
    retryable: bool,
    reason: &'static str,
}

impl GatewayNativeIoError {
    // Creates one transient connection failure that is safe to retry before output.
    pub const fn retryable_before_head(reason: &'static str) -> Self {
        Self {
            phase: GatewayNativeIoFailurePhase::BeforeResponseHead,
            retryable: true,
            reason,
        }
    }

    // Creates one invalid native contract that cannot be corrected by a sibling retry.
    pub const fn terminal_before_head(reason: &'static str) -> Self {
        Self {
            phase: GatewayNativeIoFailurePhase::BeforeResponseHead,
            retryable: false,
            reason,
        }
    }

    // Creates one transport failure after output became visible to the caller.
    pub const fn after_head(reason: &'static str) -> Self {
        Self {
            phase: GatewayNativeIoFailurePhase::AfterResponseHead,
            retryable: false,
            reason,
        }
    }

    // Returns where the native boundary failed relative to committed output.
    pub const fn phase(&self) -> GatewayNativeIoFailurePhase {
        self.phase
    }

    // Returns whether another placement may receive the request before output begins.
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    // Returns a stable explanation without paths, request bodies, or credentials.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

// Distinguishes native transport failure from caller-output failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayNativeHttpFailure {
    Native(GatewayNativeIoError),
    Output(GatewayExecutionFailure),
}

// Carries one bounded file observation read through a no-follow descriptor.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayNativeFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    bytes: Vec<u8>,
}

impl fmt::Debug for GatewayNativeFile {
    // Presents descriptor metadata without printing credential or private-key bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeFile")
            .field("owner_user_id", &self.owner_user_id)
            .field("mode", &format_args!("{:04o}", self.mode))
            .field("link_count", &self.link_count)
            .field("bytes", &"[REDACTED]")
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

impl Drop for GatewayNativeFile {
    // Clears possibly private file bytes before releasing their allocation.
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl GatewayNativeFile {
    // Creates one deterministic file observation for production or injected tests.
    pub fn new(
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, GatewayNativeIoError> {
        if mode > 0o7777 || link_count == 0 || bytes.len() > MAX_FILE_BYTES {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native file metadata or size is invalid",
            ));
        }
        Ok(Self {
            owner_user_id,
            mode,
            link_count,
            bytes,
        })
    }

    // Returns the numeric owner observed from the opened descriptor.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns the permission bits observed from the opened descriptor.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    // Returns the hard-link count observed from the opened descriptor.
    pub const fn link_count(&self) -> u64 {
        self.link_count
    }

    // Returns the exact bounded file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Reads bounded native files without following symbolic links.
pub trait GatewayNativeFileIo: Send + Sync {
    // Opens one exact path without following links and returns descriptor-derived metadata.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError>;
}

// Reads production credential and TLS files through no-follow Unix descriptors.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGatewayNativeFileIo;

impl GatewayNativeFileIo for SystemGatewayNativeFileIo {
    // Opens one regular file with O_NOFOLLOW and bounds it before returning any bytes.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        if !path.is_absolute() || maximum_bytes == 0 || maximum_bytes > MAX_FILE_BYTES {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native file request is invalid",
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| {
                GatewayNativeIoError::terminal_before_head("native file is unavailable")
            })?;
        let metadata = file.metadata().map_err(|_| {
            GatewayNativeIoError::terminal_before_head("native file metadata is unavailable")
        })?;
        if !metadata.is_file() || metadata.len() > maximum_bytes as u64 {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native file is not regular or exceeds its bound",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::by_ref(&mut file)
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                GatewayNativeIoError::terminal_before_head("native file cannot be read")
            })?;
        if bytes.len() > maximum_bytes {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native file exceeds its bound",
            ));
        }
        GatewayNativeFile::new(
            metadata.uid(),
            metadata.permissions().mode() & 0o7777,
            metadata.nlink(),
            bytes,
        )
    }
}

// Carries one optional client certificate and private key for child-relay mTLS.
pub struct GatewayNativeClientIdentity {
    certificate_chain: Vec<u8>,
    private_key: Vec<u8>,
}

impl GatewayNativeClientIdentity {
    // Creates one bounded in-memory identity from already verified private files.
    pub fn new(
        certificate_chain: Vec<u8>,
        mut private_key: Vec<u8>,
    ) -> Result<Self, GatewayNativeIoError> {
        if certificate_chain.is_empty()
            || private_key.is_empty()
            || certificate_chain.len() > MAX_FILE_BYTES
            || private_key.len() > MAX_FILE_BYTES
        {
            private_key.fill(0);
            return Err(GatewayNativeIoError::terminal_before_head(
                "native client TLS identity is invalid",
            ));
        }
        Ok(Self {
            certificate_chain,
            private_key,
        })
    }

    // Returns the bounded PEM certificate chain for native TLS setup.
    pub fn certificate_chain(&self) -> &[u8] {
        &self.certificate_chain
    }

    // Returns the bounded private key only to the native TLS boundary.
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

impl fmt::Debug for GatewayNativeClientIdentity {
    // Redacts the private key while retaining useful configuration shape.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeClientIdentity")
            .field("certificate_chain_bytes", &self.certificate_chain.len())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for GatewayNativeClientIdentity {
    // Clears private key bytes before releasing their allocation.
    fn drop(&mut self) {
        self.private_key.fill(0);
    }
}

// Carries a pinned CA, exact server name, TLS 1.3 policy, and optional mTLS identity.
pub struct GatewayNativeTlsConfiguration {
    server_name: String,
    ca_certificate: Vec<u8>,
    expected_server_leaf_sha256: Option<Sha256Digest>,
    client_identity: Option<GatewayNativeClientIdentity>,
}

impl GatewayNativeTlsConfiguration {
    // Creates one server-authenticated TLS 1.3 configuration with a pinned CA.
    pub fn new(
        server_name: &str,
        ca_certificate: Vec<u8>,
        expected_server_leaf_sha256: Option<Sha256Digest>,
        client_identity: Option<GatewayNativeClientIdentity>,
    ) -> Result<Self, GatewayNativeIoError> {
        if !is_valid_server_name(server_name)
            || ca_certificate.is_empty()
            || ca_certificate.len() > MAX_FILE_BYTES
        {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native TLS server name or pinned CA is invalid",
            ));
        }
        Ok(Self {
            server_name: server_name.to_string(),
            ca_certificate,
            expected_server_leaf_sha256,
            client_identity,
        })
    }

    // Returns the exact hostname used for certificate verification and SNI.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    // Returns the exact pinned CA bytes used to build an isolated trust store.
    pub fn ca_certificate(&self) -> &[u8] {
        &self.ca_certificate
    }

    // Returns the exact expected server leaf DER digest when one is required.
    pub const fn expected_server_leaf_sha256(&self) -> Option<&Sha256Digest> {
        self.expected_server_leaf_sha256.as_ref()
    }

    // Verifies one peer leaf before any authenticated application bytes are sent.
    pub fn verify_server_leaf(&self, certificate_der: &[u8]) -> Result<(), GatewayNativeIoError> {
        let Some(expected) = self.expected_server_leaf_sha256() else {
            return Ok(());
        };
        let observed = Sha256Digest::parse(&format!("{:x}", Sha256::digest(certificate_der)))
            .map_err(|_| {
                GatewayNativeIoError::terminal_before_head("server leaf identity is unavailable")
            })?;
        if &observed != expected {
            return Err(GatewayNativeIoError::terminal_before_head(
                "server leaf identity differs from its enrolled pin",
            ));
        }
        Ok(())
    }

    // Returns the client identity required for child-relay mTLS when present.
    pub const fn client_identity(&self) -> Option<&GatewayNativeClientIdentity> {
        self.client_identity.as_ref()
    }
}

impl fmt::Debug for GatewayNativeTlsConfiguration {
    // Presents only non-secret TLS identity and material shape.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayNativeTlsConfiguration")
            .field("server_name", &self.server_name)
            .field("ca_certificate_bytes", &self.ca_certificate.len())
            .field(
                "expected_server_leaf_sha256",
                &self.expected_server_leaf_sha256,
            )
            .field("client_identity", &self.client_identity)
            .field("minimum_version", &"TLS1.3")
            .field("maximum_version", &"TLS1.3")
            .finish()
    }
}

// Carries one bounded HTTP response head parsed before caller-visible output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayNativeResponseHead {
    status_code: u16,
    headers: Vec<(String, String)>,
}

impl GatewayNativeResponseHead {
    // Creates one syntactically safe bounded HTTP response head.
    pub fn new(
        status_code: u16,
        headers: Vec<(String, String)>,
    ) -> Result<Self, GatewayNativeIoError> {
        let total = headers.iter().try_fold(0usize, |size, (name, value)| {
            size.checked_add(name.len())
                .and_then(|value_size| value_size.checked_add(value.len()))
                .and_then(|value_size| value_size.checked_add(4))
        });
        if !(100..=599).contains(&status_code)
            || headers.len() > MAX_RESPONSE_HEADERS
            || total.is_none_or(|size| size > MAX_RESPONSE_HEAD_BYTES)
            || headers.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > MAX_RESPONSE_HEADER_NAME_BYTES
                    || !name.bytes().all(is_header_name_byte)
                    || value.len() > MAX_RESPONSE_HEADER_VALUE_BYTES
                    || !value.bytes().all(is_header_value_byte)
            })
        {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native response head is malformed or exceeds its bound",
            ));
        }
        Ok(Self {
            status_code,
            headers,
        })
    }

    // Returns the exact backend HTTP status code.
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    // Returns the bounded raw headers for end-to-end filtering.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

// Carries one closed native POST request with an in-memory bearer and TLS configuration.
pub struct GatewayNativeHttpRequest {
    host: String,
    port: u16,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    tls: GatewayNativeTlsConfiguration,
}

impl GatewayNativeHttpRequest {
    // Creates one fixed chat-completions request without accepting another public path.
    pub fn chat_completions(
        host: &str,
        port: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        tls: GatewayNativeTlsConfiguration,
    ) -> Result<Self, GatewayNativeIoError> {
        Self::new(
            host,
            port,
            "/v1/chat/completions",
            false,
            headers,
            body,
            tls,
        )
    }

    // Creates one private token-count request using its endpoint-declared exact path.
    pub fn token_count(
        host: &str,
        port: u16,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        tls: GatewayNativeTlsConfiguration,
    ) -> Result<Self, GatewayNativeIoError> {
        Self::new(host, port, path, true, headers, body, tls)
    }

    // Creates one HTTPS request after validating its closed purpose, headers, and body bounds.
    #[allow(clippy::too_many_arguments)]
    fn new(
        host: &str,
        port: u16,
        path: &str,
        token_count: bool,
        mut headers: Vec<(String, String)>,
        mut body: Vec<u8>,
        tls: GatewayNativeTlsConfiguration,
    ) -> Result<Self, GatewayNativeIoError> {
        let path_is_valid = if token_count {
            is_safe_private_path(path)
        } else {
            path == "/v1/chat/completions"
        };
        if host != tls.server_name()
            || port == 0
            || !path_is_valid
            || body.is_empty()
            || body.len() > 32 * 1024 * 1024
            || !valid_request_headers(&headers, host, port, body.len())
        {
            clear_authorization(&mut headers);
            body.fill(0);
            return Err(GatewayNativeIoError::terminal_before_head(
                "native HTTP request is invalid or exceeds its bound",
            ));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            path: path.to_string(),
            headers,
            body,
            tls,
        })
    }

    // Returns the exact unresolved host used by TCP and TLS.
    pub fn host(&self) -> &str {
        &self.host
    }

    // Returns the exact backend port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the closed request path.
    pub fn path(&self) -> &str {
        &self.path
    }

    // Returns fixed request headers only to the injected HTTP boundary.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    // Returns the bounded request body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    // Returns the pinned TLS configuration.
    pub const fn tls(&self) -> &GatewayNativeTlsConfiguration {
        &self.tls
    }
}

impl fmt::Debug for GatewayNativeHttpRequest {
    // Redacts authorization and body bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("GatewayNativeHttpRequest")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("header_names", &header_names)
            .field("body_bytes", &self.body.len())
            .field("tls", &self.tls)
            .finish()
    }
}

impl Drop for GatewayNativeHttpRequest {
    // Clears authorization and request-body bytes before releasing native request storage.
    fn drop(&mut self) {
        if let Some((_, authorization)) = self
            .headers
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            zero_string(authorization);
        }
        self.body.fill(0);
    }
}

// Receives one ordered bounded native response without owning forwarding policy.
pub trait GatewayNativeHttpResponseObserver {
    // Observes one complete backend response head before body delivery.
    fn receive_head(
        &mut self,
        head: &GatewayNativeResponseHead,
    ) -> Result<(), GatewayExecutionFailure>;

    // Observes one ordered decoded response body fragment.
    fn receive_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure>;
}

// Sends one exact HTTPS request through an injected network and TLS boundary.
pub trait GatewayNativeHttpIo: Send + Sync {
    // Sends one request and delivers exactly one response head followed by bounded chunks.
    fn send(
        &self,
        request: &GatewayNativeHttpRequest,
        observer: &mut dyn GatewayNativeHttpResponseObserver,
    ) -> Result<(), GatewayNativeHttpFailure>;
}

// Sends production TLS 1.3 HTTP/1.1 requests over bounded blocking sockets.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGatewayNativeHttpIo;

impl GatewayNativeHttpIo for SystemGatewayNativeHttpIo {
    // Opens one pinned TLS 1.3 connection and streams one closed HTTP response.
    fn send(
        &self,
        request: &GatewayNativeHttpRequest,
        observer: &mut dyn GatewayNativeHttpResponseObserver,
    ) -> Result<(), GatewayNativeHttpFailure> {
        let address = (request.host(), request.port())
            .to_socket_addrs()
            .map_err(|_| native_before("native backend address cannot be resolved"))?
            .next()
            .ok_or_else(|| native_before("native backend address cannot be resolved"))?;
        let socket =
            TcpStream::connect_timeout(&address, Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
                .map_err(|_| native_before("native backend connection failed"))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS)))
            .map_err(|_| native_before("native backend read timeout cannot be configured"))?;
        socket
            .set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECONDS)))
            .map_err(|_| native_before("native backend write timeout cannot be configured"))?;

        let config = tls_client_config(request.tls()).map_err(GatewayNativeHttpFailure::Native)?;
        let server_name = ServerName::try_from(request.tls().server_name().to_string())
            .map_err(|_| native_before("native TLS server name is invalid"))?;
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|_| native_before("native TLS configuration failed"))?;
        let mut stream = StreamOwned::new(connection, socket);
        complete_tls_handshake(&mut stream, request.tls())?;
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECONDS)))
            .map_err(|_| native_before("native backend read timeout cannot be configured"))?;
        let outcome = send_http_request(&mut stream, request, observer);
        let _ = stream.sock.shutdown(Shutdown::Both);
        outcome
    }
}

// Completes bounded TLS 1.3 authentication and verifies the exact enrolled leaf pin.
fn complete_tls_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    configuration: &GatewayNativeTlsConfiguration,
) -> Result<(), GatewayNativeHttpFailure> {
    for _ in 0..MAX_HANDSHAKE_IO_CYCLES {
        if !stream.conn.is_handshaking() {
            break;
        }
        let progress = stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|_| native_before("native TLS handshake failed"))?;
        if progress == (0, 0) && stream.conn.is_handshaking() {
            return Err(native_terminal("native TLS handshake made no progress"));
        }
    }
    if stream.conn.is_handshaking() {
        return Err(native_terminal("native TLS handshake exceeded its bound"));
    }
    let leaf = stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| native_terminal("native TLS peer leaf is unavailable"))?;
    configuration
        .verify_server_leaf(leaf.as_ref())
        .map_err(GatewayNativeHttpFailure::Native)
}

// Writes one fixed request and parses exactly one HTTP/1.1 response.
fn send_http_request(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    request: &GatewayNativeHttpRequest,
    observer: &mut dyn GatewayNativeHttpResponseObserver,
) -> Result<(), GatewayNativeHttpFailure> {
    write!(stream, "POST {} HTTP/1.1\r\n", request.path())
        .map_err(|_| native_before("native backend request head could not be written"))?;
    for (name, value) in request.headers() {
        write!(stream, "{name}: {value}\r\n")
            .map_err(|_| native_before("native backend request head could not be written"))?;
    }
    stream
        .write_all(b"\r\n")
        .and_then(|()| stream.write_all(request.body()))
        .and_then(|()| stream.flush())
        .map_err(|_| native_before("native backend request body could not be written"))?;

    let mut reader = BufReader::with_capacity(MAX_RESPONSE_HEAD_BYTES, stream);
    let (head, framing) = read_response_head(&mut reader)?;
    observer
        .receive_head(&head)
        .map_err(GatewayNativeHttpFailure::Output)?;
    read_response_body(&mut reader, framing, observer)
}

// Describes the only body framing accepted from a connection-close backend.
enum ResponseFraming {
    Empty,
    Length(usize),
    Chunked,
    UntilClose,
}

// Reads and validates one bounded HTTP/1.1 response head.
fn read_response_head(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
) -> Result<(GatewayNativeResponseHead, ResponseFraming), GatewayNativeHttpFailure> {
    let status_line = read_head_line(reader)?;
    let status_code = parse_status_line(&status_line)?;
    let mut headers = Vec::new();
    let mut head_bytes = status_line.len();
    loop {
        let line = read_head_line(reader)?;
        head_bytes = head_bytes
            .checked_add(line.len())
            .ok_or_else(|| native_terminal("native response head size overflowed"))?;
        if head_bytes > MAX_RESPONSE_HEAD_BYTES {
            return Err(native_terminal("native response head exceeds 64 KiB"));
        }
        if line == b"\r\n" {
            break;
        }
        if headers.len() >= MAX_RESPONSE_HEADERS {
            return Err(native_terminal("native response has too many headers"));
        }
        headers.push(parse_header_line(&line)?);
    }
    let framing = response_framing(status_code, &headers)?;
    let head = GatewayNativeResponseHead::new(status_code, headers)
        .map_err(GatewayNativeHttpFailure::Native)?;
    Ok((head, framing))
}

// Reads one response-head line while preserving its CRLF terminator.
fn read_head_line(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
) -> Result<Vec<u8>, GatewayNativeHttpFailure> {
    let mut line = Vec::new();
    let bytes = reader
        .read_until(b'\n', &mut line)
        .map_err(|_| native_before("native response head could not be read"))?;
    if bytes == 0 || line.len() > MAX_RESPONSE_HEAD_BYTES || !line.ends_with(b"\r\n") {
        return Err(native_terminal(
            "native response head is incomplete or malformed",
        ));
    }
    Ok(line)
}

// Parses one exact HTTP/1.1 status line without accepting interim responses.
fn parse_status_line(line: &[u8]) -> Result<u16, GatewayNativeHttpFailure> {
    let line = std::str::from_utf8(line)
        .map_err(|_| native_terminal("native response status is not ASCII"))?;
    let mut fields = line.trim_end_matches("\r\n").splitn(3, ' ');
    if fields.next() != Some("HTTP/1.1") {
        return Err(native_terminal("native response is not HTTP/1.1"));
    }
    let status = fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (200..=599).contains(value))
        .ok_or_else(|| native_terminal("native response status is invalid"))?;
    Ok(status)
}

// Parses one bounded response header without obs-fold or control bytes.
fn parse_header_line(line: &[u8]) -> Result<(String, String), GatewayNativeHttpFailure> {
    let line = std::str::from_utf8(line)
        .map_err(|_| native_terminal("native response header is not ASCII"))?
        .trim_end_matches("\r\n");
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| native_terminal("native response header is malformed"))?;
    let value = value.trim_matches([' ', '\t']);
    if name.is_empty()
        || name.len() > MAX_RESPONSE_HEADER_NAME_BYTES
        || !name.bytes().all(is_header_name_byte)
        || value.len() > MAX_RESPONSE_HEADER_VALUE_BYTES
        || !value.bytes().all(is_header_value_byte)
    {
        return Err(native_terminal(
            "native response header is unsafe or oversized",
        ));
    }
    Ok((name.to_ascii_lowercase(), value.to_string()))
}

// Resolves one unambiguous bounded response-body framing contract.
fn response_framing(
    status_code: u16,
    headers: &[(String, String)],
) -> Result<ResponseFraming, GatewayNativeHttpFailure> {
    if matches!(status_code, 204 | 304) {
        return Ok(ResponseFraming::Empty);
    }
    let lengths = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    let transfer_encodings = headers
        .iter()
        .filter(|(name, _)| name == "transfer-encoding")
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    if lengths.len() > 1
        || transfer_encodings.len() > 1
        || (!lengths.is_empty() && !transfer_encodings.is_empty())
    {
        return Err(native_terminal("native response framing is ambiguous"));
    }
    if let Some(value) = transfer_encodings.first() {
        if !value.eq_ignore_ascii_case("chunked") {
            return Err(native_terminal(
                "native response transfer encoding is unsupported",
            ));
        }
        return Ok(ResponseFraming::Chunked);
    }
    if let Some(value) = lengths.first() {
        let length = value
            .parse::<usize>()
            .ok()
            .filter(|length| *length <= MAX_RESPONSE_BODY_BYTES)
            .ok_or_else(|| {
                native_terminal("native response content length is invalid or oversized")
            })?;
        return Ok(ResponseFraming::Length(length));
    }
    Ok(ResponseFraming::UntilClose)
}

// Streams one bounded response body according to its validated framing.
fn read_response_body(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
    framing: ResponseFraming,
    observer: &mut dyn GatewayNativeHttpResponseObserver,
) -> Result<(), GatewayNativeHttpFailure> {
    match framing {
        ResponseFraming::Empty => Ok(()),
        ResponseFraming::Length(length) => read_exact_body(reader, length, observer),
        ResponseFraming::Chunked => read_chunked_body(reader, observer),
        ResponseFraming::UntilClose => read_until_close(reader, observer),
    }
}

// Reads exactly one declared response length in bounded fragments.
fn read_exact_body(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
    mut remaining: usize,
    observer: &mut dyn GatewayNativeHttpResponseObserver,
) -> Result<(), GatewayNativeHttpFailure> {
    let mut buffer = vec![0u8; MAX_RESPONSE_CHUNK_BYTES];
    while remaining > 0 {
        let size = remaining.min(buffer.len());
        reader
            .read_exact(&mut buffer[..size])
            .map_err(|_| native_after("native response body ended before its content length"))?;
        observer
            .receive_body(&buffer[..size])
            .map_err(GatewayNativeHttpFailure::Output)?;
        remaining -= size;
    }
    Ok(())
}

// Reads one decoded chunked response with bounded chunk extensions and trailers.
fn read_chunked_body(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
    observer: &mut dyn GatewayNativeHttpResponseObserver,
) -> Result<(), GatewayNativeHttpFailure> {
    let mut total = 0usize;
    loop {
        let line = read_body_line(reader)?;
        let size_value = line
            .strip_suffix(b"\r\n")
            .and_then(|value| value.split(|byte| *byte == b';').next())
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or_else(|| native_after("native response chunk size is malformed"))?;
        if size_value == 0 {
            read_trailers(reader)?;
            return Ok(());
        }
        total = total
            .checked_add(size_value)
            .filter(|value| *value <= MAX_RESPONSE_BODY_BYTES)
            .ok_or_else(|| native_after("native response body exceeds 64 MiB"))?;
        let mut remaining = size_value;
        let mut buffer = vec![0u8; MAX_RESPONSE_CHUNK_BYTES];
        while remaining > 0 {
            let size = remaining.min(buffer.len());
            reader
                .read_exact(&mut buffer[..size])
                .map_err(|_| native_after("native response chunk is incomplete"))?;
            observer
                .receive_body(&buffer[..size])
                .map_err(GatewayNativeHttpFailure::Output)?;
            remaining -= size;
        }
        let mut terminator = [0u8; 2];
        reader
            .read_exact(&mut terminator)
            .map_err(|_| native_after("native response chunk terminator is incomplete"))?;
        if terminator != *b"\r\n" {
            return Err(native_after(
                "native response chunk terminator is malformed",
            ));
        }
    }
}

// Reads one short CRLF-terminated body-framing line.
fn read_body_line(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
) -> Result<Vec<u8>, GatewayNativeHttpFailure> {
    let mut line = Vec::new();
    let bytes = reader
        .read_until(b'\n', &mut line)
        .map_err(|_| native_after("native response framing could not be read"))?;
    if bytes == 0 || line.len() > 1024 || !line.ends_with(b"\r\n") {
        return Err(native_after(
            "native response framing is incomplete or oversized",
        ));
    }
    Ok(line)
}

// Consumes only bounded empty trailers after the final chunk.
fn read_trailers(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
) -> Result<(), GatewayNativeHttpFailure> {
    let mut total = 0usize;
    for _ in 0..=MAX_RESPONSE_HEADERS {
        let line = read_body_line(reader)?;
        total = total
            .checked_add(line.len())
            .filter(|value| *value <= MAX_RESPONSE_HEAD_BYTES)
            .ok_or_else(|| native_after("native response trailers exceed their bound"))?;
        if line == b"\r\n" {
            return Ok(());
        }
        parse_header_line(&line)
            .map_err(|_| native_after("native response trailer is malformed"))?;
    }
    Err(native_after("native response has too many trailers"))
}

// Reads a connection-close response while enforcing the aggregate body bound.
fn read_until_close(
    reader: &mut BufReader<&mut StreamOwned<ClientConnection, TcpStream>>,
    observer: &mut dyn GatewayNativeHttpResponseObserver,
) -> Result<(), GatewayNativeHttpFailure> {
    let mut total = 0usize;
    let mut buffer = vec![0u8; MAX_RESPONSE_CHUNK_BYTES];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| native_after("native response body could not be read"))?;
        if count == 0 {
            return Ok(());
        }
        total = total
            .checked_add(count)
            .filter(|value| *value <= MAX_RESPONSE_BODY_BYTES)
            .ok_or_else(|| native_after("native response body exceeds 64 MiB"))?;
        observer
            .receive_body(&buffer[..count])
            .map_err(GatewayNativeHttpFailure::Output)?;
    }
}

// Builds an isolated TLS 1.3 client configuration from exact in-memory trust material.
fn tls_client_config(
    configuration: &GatewayNativeTlsConfiguration,
) -> Result<ClientConfig, GatewayNativeIoError> {
    let mut roots = RootCertStore::empty();
    let certificates = pem_certificates(configuration.ca_certificate())?;
    if certificates.is_empty() {
        return Err(GatewayNativeIoError::terminal_before_head(
            "pinned CA contains no certificates",
        ));
    }
    for certificate in certificates {
        roots.add(certificate).map_err(|_| {
            GatewayNativeIoError::terminal_before_head("pinned CA certificate is invalid")
        })?;
    }
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    if let Some(identity) = configuration.client_identity() {
        let certificates = pem_certificates(identity.certificate_chain())?;
        let private_key = rustls_pemfile::private_key(&mut Cursor::new(identity.private_key()))
            .map_err(|_| {
                GatewayNativeIoError::terminal_before_head("client TLS private key is invalid")
            })?
            .ok_or_else(|| {
                GatewayNativeIoError::terminal_before_head("client TLS private key is missing")
            })?;
        if certificates.is_empty() {
            return Err(GatewayNativeIoError::terminal_before_head(
                "client TLS certificate chain is empty",
            ));
        }
        builder
            .with_client_auth_cert(certificates, private_key)
            .map_err(|_| {
                GatewayNativeIoError::terminal_before_head("client TLS identity is invalid")
            })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

// Parses every PEM certificate and rejects partial or malformed trust input.
fn pem_certificates(
    bytes: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, GatewayNativeIoError> {
    rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayNativeIoError::terminal_before_head("TLS certificate input is invalid"))
}

// Returns whether one canonical DNS or numeric host is safe for SNI and Host.
fn is_valid_server_name(value: &str) -> bool {
    let character_shape = !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'));
    character_shape && ServerName::try_from(value.to_string()).is_ok()
}

// Returns whether one endpoint-owned private path is absolute, bounded, and origin-local.
fn is_safe_private_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 255
        && !value.starts_with("//")
        && !value.contains("://")
        && !value.contains(['?', '#', '\0'])
        && !value.chars().any(char::is_whitespace)
}

// Validates the fixed unique request header set against its exact request identity.
fn valid_request_headers(
    headers: &[(String, String)],
    host: &str,
    port: u16,
    body_bytes: usize,
) -> bool {
    const REQUIRED: [&str; 7] = [
        "accept",
        "authorization",
        "connection",
        "content-length",
        "content-type",
        "host",
        "x-letsinfer-request-id",
    ];
    if headers.len() != REQUIRED.len() {
        return false;
    }
    let mut names = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    let value = |name: &str| {
        headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    };
    names == REQUIRED
        && headers.iter().all(|(name, value)| {
            name.bytes().all(is_header_name_byte)
                && !value.is_empty()
                && value.len() <= 8 * 1024
                && value.bytes().all(is_header_value_byte)
        })
        && value("accept") == Some("application/json, text/event-stream")
        && value("connection") == Some("close")
        && value("content-type") == Some("application/json")
        && value("content-length").and_then(|value| value.parse::<usize>().ok()) == Some(body_bytes)
        && value("host") == Some(host_header(host, port).as_str())
        && value("authorization").is_some_and(valid_authorization)
        && value("x-letsinfer-request-id").is_some_and(|identity| {
            matches!(identity.len(), 32 | 64)
                && identity
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

// Returns one exact Host field for a DNS, IPv4, or IPv6 target.
fn host_header(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// Validates one private bearer header without retaining its token.
fn valid_authorization(value: &str) -> bool {
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| token.len() >= 32 && !token.chars().any(char::is_whitespace))
}

// Returns whether one ASCII byte is legal in an HTTP field name.
fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

// Returns whether one header byte is visible ASCII or horizontal tab.
fn is_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte)
}

// Wraps one retryable pre-output transport error.
fn native_before(reason: &'static str) -> GatewayNativeHttpFailure {
    GatewayNativeHttpFailure::Native(GatewayNativeIoError::retryable_before_head(reason))
}

// Wraps one terminal pre-output protocol or configuration error.
fn native_terminal(reason: &'static str) -> GatewayNativeHttpFailure {
    GatewayNativeHttpFailure::Native(GatewayNativeIoError::terminal_before_head(reason))
}

// Wraps one terminal post-output transport or framing error.
fn native_after(reason: &'static str) -> GatewayNativeHttpFailure {
    GatewayNativeHttpFailure::Native(GatewayNativeIoError::after_head(reason))
}

// Clears a String's initialized bytes before its allocation is released.
fn zero_string(value: &mut String) {
    let length = value.len();
    value.clear();
    value.extend(std::iter::repeat_n('\0', length));
}

// Clears bearer material from an incomplete request before validation returns an error.
fn clear_authorization(headers: &mut [(String, String)]) {
    if let Some((_, authorization)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        zero_string(authorization);
    }
}
