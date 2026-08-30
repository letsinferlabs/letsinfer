// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use crate::li_gateway_native_resident::{
    start_gateway_native_server, GatewayNativeServerSurface, GatewayNativeSocketWorker,
};
use crate::{
    GatewayExecutionFailure, GatewayHttpError, GatewayHttpHandler, GatewayHttpMethod,
    GatewayHttpOutcome, GatewayHttpRequest, GatewayHttpSurface, GatewayNativeServerHandle,
    GatewayResponseHead, GatewayResponseWriter,
};

const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;
const MAX_REQUEST_HEADERS: usize = 64;
const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_WRITE_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 256;
const READ_TIMEOUT_SECONDS: u64 = 30;
const WRITE_TIMEOUT_SECONDS: u64 = 60;

// Reports whether an accepted socket can still receive one eventual response.
pub(crate) trait GatewayNativeDisconnectProbe {
    // Returns false only after the peer has closed its exact transport.
    fn is_connected(&self) -> Result<bool, GatewayExecutionFailure>;
}

// Treats deterministic in-memory streams as connected unless their writer rejects output.
struct ConnectedGatewayNativeProbe;

impl GatewayNativeDisconnectProbe for ConnectedGatewayNativeProbe {
    // Preserves the ordinary injected byte-stream contract without native socket discovery.
    fn is_connected(&self) -> Result<bool, GatewayExecutionFailure> {
        Ok(true)
    }
}

// Observes peer shutdown through one cloned accepted TCP descriptor.
pub(crate) struct GatewayTcpDisconnectProbe {
    connection: TcpStream,
}

impl GatewayTcpDisconnectProbe {
    // Clones one accepted descriptor so liveness checks never consume request bytes.
    pub(crate) fn new(connection: &TcpStream) -> Result<Self, GatewayNativeServerError> {
        connection
            .try_clone()
            .map(|connection| Self { connection })
            .map_err(|_| GatewayNativeServerError::new("Gateway connection cannot be observed"))
    }
}

impl GatewayNativeDisconnectProbe for GatewayTcpDisconnectProbe {
    // Peeks without blocking and distinguishes peer EOF from an idle live socket.
    fn is_connected(&self) -> Result<bool, GatewayExecutionFailure> {
        let mut byte = 0u8;
        // SAFETY: the cloned descriptor remains live and byte is writable for one-byte MSG_PEEK.
        let result = unsafe {
            libc::recv(
                self.connection.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if result > 0 {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Ok(true),
            _ => Err(GatewayExecutionFailure::client(
                "client connection cannot be observed",
            )),
        }
    }
}

// Carries one stable redacted public-listener failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayNativeServerError {
    reason: &'static str,
}

impl GatewayNativeServerError {
    // Creates one listener failure without addresses, headers, or request bytes.
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    // Returns the stable redacted failure reason.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for GatewayNativeServerError {
    // Presents one stable listener failure without native details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for GatewayNativeServerError {}

// Parses one closed HTTP/1.1 request from a connection without owning policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct GatewayNativeRequestParser;

impl GatewayNativeRequestParser {
    // Reads exactly one bounded request and rejects ambiguous framing.
    pub fn read(&self, connection: &mut dyn Read) -> Result<GatewayHttpRequest, GatewayHttpError> {
        let mut reader = BufReader::new(connection);
        let mut head_bytes = 0usize;
        let request_line = read_line(&mut reader, &mut head_bytes)?;
        let (method, path) = parse_request_line(&request_line)?;
        let mut headers = Vec::new();
        loop {
            let line = read_line(&mut reader, &mut head_bytes)?;
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_REQUEST_HEADERS || line.starts_with([' ', '\t']) {
                return Err(invalid_request("request headers are invalid"));
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid_request("request header is malformed"))?;
            let value = value.trim_matches([' ', '\t']);
            if headers
                .iter()
                .any(|(candidate, _): &(String, String)| candidate.eq_ignore_ascii_case(name))
            {
                return Err(invalid_request("duplicate request header is forbidden"));
            }
            headers.push((name.to_string(), value.to_string()));
        }
        if header(&headers, "transfer-encoding").is_some() {
            return Err(GatewayHttpError::new(
                400,
                "unsupported_transfer_encoding",
                "chunked request bodies are unsupported",
            ));
        }
        if header(&headers, "expect").is_some() || header(&headers, "host").is_none() {
            return Err(GatewayHttpError::new(
                400,
                "invalid_request",
                "request framing is unsupported or incomplete",
            ));
        }
        let body_length = match header(&headers, "content-length") {
            Some(value) => value
                .parse::<usize>()
                .ok()
                .filter(|length| *length <= MAX_REQUEST_BODY_BYTES)
                .ok_or_else(|| {
                    GatewayHttpError::new(413, "request_too_large", "request body exceeds 32 MiB")
                })?,
            None => 0,
        };
        let mut body = vec![0u8; body_length];
        reader.read_exact(&mut body).map_err(|_| {
            GatewayHttpError::new(400, "incomplete_request", "request body is incomplete")
        })?;
        GatewayHttpRequest::new(method, &path, headers, body)
    }
}

// Serializes one connection-closing chunked HTTP/1.1 response.
pub struct GatewayNativeResponseWriter<'a> {
    connection: &'a mut dyn Write,
    disconnect: &'a dyn GatewayNativeDisconnectProbe,
    started: bool,
    finished: bool,
}

impl<'a> GatewayNativeResponseWriter<'a> {
    // Creates one uncommitted native response writer.
    pub const fn new(connection: &'a mut dyn Write) -> Self {
        Self {
            connection,
            disconnect: &ConnectedGatewayNativeProbe,
            started: false,
            finished: false,
        }
    }

    // Creates one response writer that observes the accepted socket during queue waits.
    pub(crate) const fn with_disconnect_probe(
        connection: &'a mut dyn Write,
        disconnect: &'a dyn GatewayNativeDisconnectProbe,
    ) -> Self {
        Self {
            connection,
            disconnect,
            started: false,
            finished: false,
        }
    }

    // Terminates chunked framing exactly once after the handler completes.
    pub fn finish(&mut self) -> Result<(), GatewayExecutionFailure> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.started {
            self.connection
                .write_all(b"0\r\n\r\n")
                .map_err(|_| GatewayExecutionFailure::client("client closed during response"))?;
            self.connection
                .flush()
                .map_err(|_| GatewayExecutionFailure::client("client closed during response"))?;
        }
        Ok(())
    }
}

impl GatewayResponseWriter for GatewayNativeResponseWriter<'_> {
    // Checks the exact accepted transport without consuming any client bytes.
    fn client_is_connected(&mut self) -> Result<bool, GatewayExecutionFailure> {
        self.disconnect.is_connected()
    }

    // Writes one safe response head with server-owned connection framing.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        if self.started || self.finished {
            return Err(GatewayExecutionFailure::terminal_backend(
                "native response head was emitted more than once",
            ));
        }
        let mut bytes = format!(
            "HTTP/1.1 {} {}\r\nserver: letsinfer\r\nconnection: close\r\ntransfer-encoding: chunked\r\n",
            head.status_code(),
            reason_phrase(head.status_code())
        )
        .into_bytes();
        for header in head.headers() {
            bytes.extend_from_slice(header.name().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(header.value().as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        self.connection
            .write_all(&bytes)
            .map_err(|_| GatewayExecutionFailure::client("client closed before response"))?;
        self.started = true;
        Ok(())
    }

    // Writes one ordered body fragment as bounded HTTP chunks.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        if !self.started || self.finished {
            return Err(GatewayExecutionFailure::terminal_backend(
                "native response body has no active response head",
            ));
        }
        for chunk in body.chunks(MAX_WRITE_CHUNK_BYTES) {
            if chunk.is_empty() {
                continue;
            }
            write!(self.connection, "{:x}\r\n", chunk.len())
                .and_then(|_| self.connection.write_all(chunk))
                .and_then(|_| self.connection.write_all(b"\r\n"))
                .map_err(|_| GatewayExecutionFailure::client("client closed during response"))?;
        }
        Ok(())
    }
}

impl Drop for GatewayNativeResponseWriter<'_> {
    // Makes a best-effort framing close without hiding an earlier response error.
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

// Serves exactly one already-established plaintext or authenticated TLS stream.
pub struct GatewayNativeConnectionServer {
    handler: Arc<GatewayHttpHandler>,
}

impl GatewayNativeConnectionServer {
    // Creates one connection server without acquiring or authenticating a socket.
    pub const fn new(handler: Arc<GatewayHttpHandler>) -> Self {
        Self { handler }
    }

    // Parses, handles, frames, and closes one deterministic byte stream.
    pub fn serve(
        &self,
        connection: &mut (impl Read + Write),
    ) -> Result<GatewayHttpOutcome, GatewayNativeServerError> {
        self.serve_with_disconnect_probe(connection, &ConnectedGatewayNativeProbe)
    }

    // Serves one stream while exposing its exact transport liveness to queued execution.
    pub(crate) fn serve_with_disconnect_probe(
        &self,
        connection: &mut (impl Read + Write),
        disconnect: &dyn GatewayNativeDisconnectProbe,
    ) -> Result<GatewayHttpOutcome, GatewayNativeServerError> {
        let request = GatewayNativeRequestParser.read(connection);
        let mut response =
            GatewayNativeResponseWriter::with_disconnect_probe(connection, disconnect);
        let outcome = match request {
            Ok(request) => self.handler.handle(&request, &mut response),
            Err(error) => self.handler.reject(&error, &mut response),
        }
        .map_err(|_| GatewayNativeServerError::new("Gateway client response failed"))?;
        response
            .finish()
            .map_err(|_| GatewayNativeServerError::new("Gateway client response failed"))?;
        Ok(outcome)
    }
}

// Owns the production plaintext LAN listener for a main Gateway.
pub struct SystemGatewayHttpServer {
    listener: TcpListener,
    handler: Arc<GatewayHttpHandler>,
    maximum_connections: usize,
}

impl SystemGatewayHttpServer {
    // Binds one public HTTP listener after validating its role and connection bound.
    pub fn bind(
        address: SocketAddr,
        maximum_connections: usize,
        handler: Arc<GatewayHttpHandler>,
    ) -> Result<Self, GatewayNativeServerError> {
        if handler.surface() != GatewayHttpSurface::Public
            || !handler.has_public_reads()
            || maximum_connections == 0
            || maximum_connections > MAX_CONNECTIONS
        {
            return Err(GatewayNativeServerError::new(
                "public Gateway listener configuration is invalid",
            ));
        }
        let listener = TcpListener::bind(address)
            .map_err(|_| GatewayNativeServerError::new("public Gateway address cannot be bound"))?;
        Ok(Self {
            listener,
            handler,
            maximum_connections,
        })
    }

    // Returns the exact bound address for readiness checks.
    pub fn local_address(&self) -> Result<SocketAddr, GatewayNativeServerError> {
        self.listener
            .local_addr()
            .map_err(|_| GatewayNativeServerError::new("public Gateway address is unavailable"))
    }

    // Starts one nonblocking resident public listener with owned shutdown and joins.
    pub fn start(self) -> Result<GatewayNativeServerHandle, GatewayNativeServerError> {
        let worker = Arc::new(GatewayHttpSocketWorker {
            handler: self.handler,
        });
        start_gateway_native_server(
            self.listener,
            self.maximum_connections,
            GatewayNativeServerSurface::Public,
            worker,
        )
    }
}

// Serves one registered public socket under the shared resident lifecycle.
struct GatewayHttpSocketWorker {
    handler: Arc<GatewayHttpHandler>,
}

impl GatewayNativeSocketWorker for GatewayHttpSocketWorker {
    // Serves and closes exactly one plaintext request without surfacing client details.
    fn serve(&self, connection: TcpStream) {
        let _ = serve_tcp_connection(connection, self.handler.clone());
    }
}

// Configures and serves one production plaintext connection.
fn serve_tcp_connection(
    mut connection: TcpStream,
    handler: Arc<GatewayHttpHandler>,
) -> Result<GatewayHttpOutcome, GatewayNativeServerError> {
    connection
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECONDS)))
        .and_then(|_| {
            connection.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECONDS)))
        })
        .map_err(|_| GatewayNativeServerError::new("Gateway connection timeout is unavailable"))?;
    let disconnect = GatewayTcpDisconnectProbe::new(&connection)?;
    let result = GatewayNativeConnectionServer::new(handler)
        .serve_with_disconnect_probe(&mut connection, &disconnect);
    let _ = connection.shutdown(std::net::Shutdown::Both);
    result
}

// Reads one strict CRLF-terminated line under the aggregate head bound.
fn read_line(
    reader: &mut dyn BufRead,
    aggregate_bytes: &mut usize,
) -> Result<String, GatewayHttpError> {
    let mut bytes = Vec::new();
    let remaining = MAX_REQUEST_HEAD_BYTES.saturating_sub(*aggregate_bytes);
    let count = (&mut *reader)
        .take(remaining as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| {
            GatewayHttpError::new(400, "invalid_request", "request head cannot be read")
        })?;
    if count > remaining {
        return Err(GatewayHttpError::new(
            431,
            "request_header_fields_too_large",
            "request head exceeds 64 KiB",
        ));
    }
    *aggregate_bytes = aggregate_bytes
        .checked_add(count)
        .filter(|length| *length <= MAX_REQUEST_HEAD_BYTES)
        .ok_or_else(|| {
            GatewayHttpError::new(
                431,
                "request_header_fields_too_large",
                "request head exceeds 64 KiB",
            )
        })?;
    if count < 2 || !bytes.ends_with(b"\r\n") || bytes[..bytes.len() - 2].contains(&b'\0') {
        return Err(invalid_request("request head is malformed"));
    }
    bytes.truncate(bytes.len() - 2);
    if !bytes.is_ascii() {
        return Err(invalid_request("request head is not ASCII"));
    }
    String::from_utf8(bytes).map_err(|_| invalid_request("request head is not ASCII"))
}

// Parses one exact HTTP/1.1 origin-form request line.
fn parse_request_line(line: &str) -> Result<(GatewayHttpMethod, String), GatewayHttpError> {
    let values = line.split(' ').collect::<Vec<_>>();
    if values.len() != 3 || values[1].is_empty() || values[2] != "HTTP/1.1" {
        return Err(invalid_request("request line is invalid"));
    }
    let method = match values[0] {
        "GET" => GatewayHttpMethod::Get,
        "POST" => GatewayHttpMethod::Post,
        "OPTIONS" => GatewayHttpMethod::Options,
        _ => {
            return Err(GatewayHttpError::new(
                405,
                "method_not_allowed",
                "request method is unsupported",
            ))
        }
    };
    if !values[1].starts_with('/') || values[1].starts_with("//") {
        return Err(invalid_request("request target is invalid"));
    }
    Ok((method, values[1].to_string()))
}

// Finds one case-insensitive request-header value.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

// Returns one stable malformed-request failure.
fn invalid_request(message: &'static str) -> GatewayHttpError {
    GatewayHttpError::new(400, "invalid_request", message)
}

// Returns a stable reason phrase for every accepted response status class.
fn reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Response",
    }
}
