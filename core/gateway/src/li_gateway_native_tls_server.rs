// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};

use crate::li_gateway_native_resident::{
    start_gateway_native_server, GatewayNativeServerSurface, GatewayNativeSocketWorker,
};
use crate::li_gateway_native_server::GatewayTcpDisconnectProbe;
use crate::{
    GatewayHttpHandler, GatewayHttpOutcome, GatewayHttpSurface, GatewayNativeConnectionServer,
    GatewayNativeFileIo, GatewayNativeServerError, GatewayNativeServerHandle,
};

const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 128 * 1024;
const MAX_CONNECTIONS: usize = 256;
const MAX_TLS_HANDSHAKE_STEPS: usize = 32;
const READ_TIMEOUT_SECONDS: u64 = 30;
const WRITE_TIMEOUT_SECONDS: u64 = 60;

// Binds the private child listener to exact owner-protected TLS file references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayNativeTlsFileSet {
    owner_user_id: u32,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    client_ca_file: PathBuf,
    client_certificate_file: PathBuf,
}

impl GatewayNativeTlsFileSet {
    // Creates one closed file set with four distinct absolute references.
    pub fn new(
        owner_user_id: u32,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        client_ca_file: PathBuf,
        client_certificate_file: PathBuf,
    ) -> Result<Self, GatewayNativeServerError> {
        let paths = [
            &server_certificate_file,
            &server_private_key_file,
            &client_ca_file,
            &client_certificate_file,
        ];
        let unique = paths
            .iter()
            .enumerate()
            .all(|(index, path)| paths.iter().skip(index + 1).all(|other| path != other));
        if paths.iter().any(|path| !path.is_absolute()) || !unique {
            return Err(GatewayNativeServerError::new(
                "private Gateway TLS file references are invalid",
            ));
        }
        Ok(Self {
            owner_user_id,
            server_certificate_file,
            server_private_key_file,
            client_ca_file,
            client_certificate_file,
        })
    }
}

// Owns one TLS 1.3 server configuration that requires a pinned client certificate.
pub struct GatewayNativeTlsServerConfiguration {
    server: Arc<ServerConfig>,
    client_certificate_sha256: [u8; 32],
}

impl GatewayNativeTlsServerConfiguration {
    // Loads strict private files and constructs one TLS 1.3 mutual-authentication policy.
    pub fn load(
        files: &GatewayNativeTlsFileSet,
        io: &dyn GatewayNativeFileIo,
    ) -> Result<Self, GatewayNativeServerError> {
        let server_certificates = private_file(
            io,
            &files.server_certificate_file,
            files.owner_user_id,
            MAX_CERTIFICATE_BYTES,
        )?;
        let server_private_key = private_file(
            io,
            &files.server_private_key_file,
            files.owner_user_id,
            MAX_PRIVATE_KEY_BYTES,
        )?;
        let client_ca = private_file(
            io,
            &files.client_ca_file,
            files.owner_user_id,
            MAX_CERTIFICATE_BYTES,
        )?;
        let client_certificate = private_file(
            io,
            &files.client_certificate_file,
            files.owner_user_id,
            MAX_CERTIFICATE_BYTES,
        )?;
        let server_certificates = certificates(server_certificates.bytes())?;
        let server_private_key = private_key(server_private_key.bytes())?;
        let client_ca = certificates(client_ca.bytes())?;
        let client_certificates = certificates(client_certificate.bytes())?;
        if client_certificates.len() != 1 {
            return Err(GatewayNativeServerError::new(
                "private Gateway pinned client certificate is ambiguous",
            ));
        }
        let client_certificate_sha256 = Sha256::digest(client_certificates[0].as_ref()).into();
        let mut client_roots = RootCertStore::empty();
        let (added, ignored) = client_roots.add_parsable_certificates(client_ca);
        if added == 0 || ignored != 0 {
            return Err(GatewayNativeServerError::new(
                "private Gateway client CA is invalid",
            ));
        }
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| {
                GatewayNativeServerError::new("private Gateway client verifier is invalid")
            })?;
        let server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certificates, server_private_key)
            .map_err(|_| {
                GatewayNativeServerError::new("private Gateway server identity is invalid")
            })?;
        Ok(Self {
            server: Arc::new(server),
            client_certificate_sha256,
        })
    }

    // Returns the immutable server configuration for one native TLS connection.
    pub fn server_configuration(&self) -> Arc<ServerConfig> {
        self.server.clone()
    }

    // Requires the authenticated leaf to be the exact configured main-node certificate.
    pub fn verify_peer_certificates(
        &self,
        certificates: Option<&[CertificateDer<'static>]>,
    ) -> Result<(), GatewayNativeServerError> {
        verify_peer_certificates(certificates, &self.client_certificate_sha256)
    }
}

// Owns the production mTLS listener used only by a child Gateway relay surface.
pub struct SystemGatewayTlsServer {
    listener: TcpListener,
    handler: Arc<GatewayHttpHandler>,
    tls: Arc<ServerConfig>,
    client_certificate_sha256: [u8; 32],
    maximum_connections: usize,
}

impl SystemGatewayTlsServer {
    // Binds one private listener after proving its handler, TLS policy, and worker bound.
    pub fn bind(
        address: SocketAddr,
        maximum_connections: usize,
        handler: Arc<GatewayHttpHandler>,
        tls: GatewayNativeTlsServerConfiguration,
    ) -> Result<Self, GatewayNativeServerError> {
        if handler.surface() != GatewayHttpSurface::PrivateRelay
            || maximum_connections == 0
            || maximum_connections > MAX_CONNECTIONS
        {
            return Err(GatewayNativeServerError::new(
                "private Gateway listener configuration is invalid",
            ));
        }
        let listener = TcpListener::bind(address).map_err(|_| {
            GatewayNativeServerError::new("private Gateway address cannot be bound")
        })?;
        Ok(Self {
            listener,
            handler,
            tls: tls.server_configuration(),
            client_certificate_sha256: tls.client_certificate_sha256,
            maximum_connections,
        })
    }

    // Returns the exact bound address for readiness checks.
    pub fn local_address(&self) -> Result<SocketAddr, GatewayNativeServerError> {
        self.listener
            .local_addr()
            .map_err(|_| GatewayNativeServerError::new("private Gateway address is unavailable"))
    }

    // Starts one nonblocking resident private listener with owned shutdown and joins.
    pub fn start(self) -> Result<GatewayNativeServerHandle, GatewayNativeServerError> {
        let worker = Arc::new(GatewayTlsSocketWorker {
            handler: self.handler,
            tls: self.tls,
            client_certificate_sha256: self.client_certificate_sha256,
        });
        start_gateway_native_server(
            self.listener,
            self.maximum_connections,
            GatewayNativeServerSurface::Private,
            worker,
        )
    }
}

// Serves one registered private socket under the shared resident lifecycle.
struct GatewayTlsSocketWorker {
    handler: Arc<GatewayHttpHandler>,
    tls: Arc<ServerConfig>,
    client_certificate_sha256: [u8; 32],
}

impl GatewayNativeSocketWorker for GatewayTlsSocketWorker {
    // Authenticates, serves, and closes exactly one private relay connection.
    fn serve(&self, connection: TcpStream) {
        let _ = serve_tls_connection(
            connection,
            self.handler.clone(),
            self.tls.clone(),
            self.client_certificate_sha256,
        );
    }
}

// Performs mandatory mutual TLS before serving one private request.
fn serve_tls_connection(
    connection: TcpStream,
    handler: Arc<GatewayHttpHandler>,
    tls: Arc<ServerConfig>,
    client_certificate_sha256: [u8; 32],
) -> Result<GatewayHttpOutcome, GatewayNativeServerError> {
    connection
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECONDS)))
        .and_then(|_| {
            connection.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECONDS)))
        })
        .map_err(|_| {
            GatewayNativeServerError::new("private Gateway connection timeout is unavailable")
        })?;
    let server = ServerConnection::new(tls).map_err(|_| {
        GatewayNativeServerError::new("private Gateway TLS connection cannot be created")
    })?;
    let disconnect = GatewayTcpDisconnectProbe::new(&connection)?;
    let mut connection = StreamOwned::new(server, connection);
    complete_tls_handshake(&mut connection)?;
    verify_peer_certificates(
        connection.conn.peer_certificates(),
        &client_certificate_sha256,
    )?;
    let result = GatewayNativeConnectionServer::new(handler)
        .serve_with_disconnect_probe(&mut connection, &disconnect);
    connection.conn.send_close_notify();
    while connection.conn.wants_write() {
        match connection.conn.write_tls(&mut connection.sock) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = connection.sock.shutdown(Shutdown::Both);
    result
}

// Completes a bounded mutual TLS transcript before any HTTP byte is interpreted.
fn complete_tls_handshake(
    connection: &mut StreamOwned<ServerConnection, TcpStream>,
) -> Result<(), GatewayNativeServerError> {
    for _ in 0..MAX_TLS_HANDSHAKE_STEPS {
        if !connection.conn.is_handshaking() && connection.conn.peer_certificates().is_some() {
            return Ok(());
        }
        connection
            .conn
            .complete_io(&mut connection.sock)
            .map_err(|_| {
                GatewayNativeServerError::new("private Gateway TLS handshake was rejected")
            })?;
    }
    Err(GatewayNativeServerError::new(
        "private Gateway TLS handshake was rejected",
    ))
}

// Requires one exact leaf certificate rather than trusting every certificate under the CA.
fn verify_peer_certificates(
    certificates: Option<&[CertificateDer<'static>]>,
    expected_sha256: &[u8; 32],
) -> Result<(), GatewayNativeServerError> {
    let certificates = certificates.ok_or_else(|| {
        GatewayNativeServerError::new("private Gateway client certificate is missing")
    })?;
    if certificates.len() != 1 || &Sha256::digest(certificates[0].as_ref())[..] != expected_sha256 {
        return Err(GatewayNativeServerError::new(
            "private Gateway client certificate does not match the configured main",
        ));
    }
    Ok(())
}

// Reads one owner-only single-link file and copies only its bounded bytes.
fn private_file(
    io: &dyn GatewayNativeFileIo,
    path: &std::path::Path,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<GatewayNativePrivateBytes, GatewayNativeServerError> {
    let file = io
        .read_no_follow(path, maximum_bytes)
        .map_err(|_| GatewayNativeServerError::new("private Gateway TLS file is unavailable"))?;
    if file.owner_user_id() != owner_user_id
        || file.mode() != 0o600
        || file.link_count() != 1
        || file.bytes().is_empty()
    {
        return Err(GatewayNativeServerError::new(
            "private Gateway TLS file metadata is unsafe",
        ));
    }
    Ok(GatewayNativePrivateBytes(file.bytes().to_vec()))
}

// Owns one temporary private-file copy and clears it after TLS configuration.
struct GatewayNativePrivateBytes(Vec<u8>);

impl GatewayNativePrivateBytes {
    // Returns the temporary bytes only to strict PEM parsing.
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for GatewayNativePrivateBytes {
    // Clears temporary TLS file bytes before releasing their allocation.
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

// Parses a PEM document containing certificates and no unrelated item kinds.
fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, GatewayNativeServerError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayNativeServerError::new("private Gateway certificate is malformed"))?;
    let certificates = items
        .into_iter()
        .map(|item| match item {
            rustls_pemfile::Item::X509Certificate(certificate) => Ok(certificate),
            _ => Err(GatewayNativeServerError::new(
                "private Gateway certificate file contains an unrelated item",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(GatewayNativeServerError::new(
            "private Gateway certificate chain is empty",
        ));
    }
    Ok(certificates)
}

// Parses a PEM document containing exactly one private key and no unrelated item kinds.
fn private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, GatewayNativeServerError> {
    let items = rustls_pemfile::read_all(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayNativeServerError::new("private Gateway key is malformed"))?;
    if items.len() != 1 {
        return Err(GatewayNativeServerError::new(
            "private Gateway key file must contain exactly one item",
        ));
    }
    match items.into_iter().next().unwrap() {
        rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Sec1Key(key) => Ok(key.into()),
        _ => Err(GatewayNativeServerError::new(
            "private Gateway key file contains no private key",
        )),
    }
}
