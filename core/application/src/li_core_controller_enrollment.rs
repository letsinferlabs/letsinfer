// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use li_authentication_manager::{ControllerPublicKey, ControllerRole};
use li_core_cli::{
    CommandFailure, CommandFailureKind, CommandProgressEvent, CommandProgressPort,
    NativeControllerEnrollmentCommitPort, NativeControllerEnrollmentPort,
};
use li_core_interface::{ControllerId, DisplayName, InstallationId};
use li_node_manager::{NodeControllerEnrollmentCandidate, NodeControllerSummary};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CORE_CONTROLLER_ENROLLMENT_PROTOCOL: &str = "letsinfer-controller-pair-v1";
pub const CORE_CONTROLLER_ENROLLMENT_PORT: u16 = 9_769;

const MAXIMUM_REQUEST_BYTES: usize = 8 * 1024;
const MAXIMUM_TLS_FILE_BYTES: usize = 64 * 1024;
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

// Names one redacted transient-enrollment failure without retaining setup or proof material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreControllerEnrollmentError {
    Cancelled,
    TimedOut,
    ConfigurationUnavailable,
    ListenerUnavailable,
    TlsUnavailable,
    RequestInvalid,
    SetupCodeInvalid,
    ProofInvalid,
    ConfirmationDenied,
    ResponseUnavailable,
}

impl fmt::Display for CoreControllerEnrollmentError {
    // Presents stable product language without native or cryptographic diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "controller pairing was cancelled",
            Self::TimedOut => "controller pairing timed out",
            Self::ConfigurationUnavailable => "controller pairing configuration is unavailable",
            Self::ListenerUnavailable => "controller pairing listener is unavailable",
            Self::TlsUnavailable => "controller pairing TLS is unavailable",
            Self::RequestInvalid => "controller pairing request is invalid",
            Self::SetupCodeInvalid => "controller pairing code did not match",
            Self::ProofInvalid => "controller public-key proof is invalid",
            Self::ConfirmationDenied => "controller pairing was not approved",
            Self::ResponseUnavailable => "controller pairing response is unavailable",
        })
    }
}

impl Error for CoreControllerEnrollmentError {}

// Binds one short-lived listener to exact installation and public trust inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreControllerEnrollmentConfiguration {
    installation_id: InstallationId,
    listen_address: SocketAddr,
    watchdog_port: u16,
    control_port: u16,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    controller_ca_certificate_file: PathBuf,
}

impl CoreControllerEnrollmentConfiguration {
    // Creates one explicit configuration without discovering service or runtime state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: InstallationId,
        listen_address: SocketAddr,
        watchdog_port: u16,
        control_port: u16,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        controller_ca_certificate_file: PathBuf,
    ) -> Result<Self, CoreControllerEnrollmentError> {
        if listen_address.port() != CORE_CONTROLLER_ENROLLMENT_PORT
            || watchdog_port == 0
            || control_port == 0
            || [
                &server_certificate_file,
                &server_private_key_file,
                &controller_ca_certificate_file,
            ]
            .iter()
            .any(|path| !normal_absolute_path(path))
        {
            return Err(CoreControllerEnrollmentError::ConfigurationUnavailable);
        }
        Ok(Self {
            installation_id,
            listen_address,
            watchdog_port,
            control_port,
            server_certificate_file,
            server_private_key_file,
            controller_ca_certificate_file,
        })
    }
}

// Carries one untrusted enrollment claim until exact challenge proof succeeds.
#[derive(Clone, Eq, PartialEq)]
pub struct CoreControllerEnrollmentClaim {
    controller_id: ControllerId,
    name: DisplayName,
    public_key: ControllerPublicKey,
    proof: Vec<u8>,
}

impl CoreControllerEnrollmentClaim {
    // Creates one bounded claim without treating public-key possession as proven.
    pub fn new(
        controller_id: ControllerId,
        name: DisplayName,
        public_key: ControllerPublicKey,
        proof: Vec<u8>,
    ) -> Result<Self, CoreControllerEnrollmentError> {
        if !(64..=128).contains(&proof.len()) {
            return Err(CoreControllerEnrollmentError::ProofInvalid);
        }
        Ok(Self {
            controller_id,
            name,
            public_key,
            proof,
        })
    }
}

impl fmt::Debug for CoreControllerEnrollmentClaim {
    // Redacts proof and public-key bytes from generic diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreControllerEnrollmentClaim")
            .field("controller_id", &self.controller_id)
            .field("name", &self.name)
            .field("public_key", &self.public_key)
            .field("proof", &"<redacted>")
            .finish()
    }
}

// Receives one controller claim while retaining the TLS response until durable commit.
pub trait CoreControllerEnrollmentSession: Send {
    // Waits for one exact claim or a bounded cancellation/timeout boundary.
    fn receive(
        &mut self,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CoreControllerEnrollmentClaim, CoreControllerEnrollmentError>;

    // Returns the public certificate and installation CA only after durable Node commit.
    fn complete(
        &mut self,
        controller: &NodeControllerSummary,
        certificate_public_material: &[u8],
    ) -> Result<(), CoreControllerEnrollmentError>;

    // Closes the held response without accepting or persisting the candidate.
    fn reject(&mut self);
}

// Opens one single-worker TLS 1.3 session from exact transient values.
pub trait CoreControllerEnrollmentSessionProvider: Send + Sync {
    // Binds the listener before the setup code is presented to the user.
    fn open(
        &self,
        configuration: &CoreControllerEnrollmentConfiguration,
        setup_code: &str,
        session_id: &str,
        nonce: &str,
        timeout: Duration,
    ) -> Result<Box<dyn CoreControllerEnrollmentSession>, CoreControllerEnrollmentError>;
}

// Supplies cryptographic randomness without granting entropy ownership to orchestration.
pub trait CoreControllerEnrollmentEntropyPort: Send + Sync {
    // Fills one exact destination or fails before listener creation.
    fn fill(&self, destination: &mut [u8]) -> Result<(), CoreControllerEnrollmentError>;
}

// Owns the sole local human approval interaction.
pub trait CoreControllerEnrollmentConfirmationPort: Send + Sync {
    // Confirms that the comparison code shown by the controller matches this terminal.
    fn confirm(
        &self,
        controller_name: &DisplayName,
        comparison_code: &str,
    ) -> Result<bool, CoreControllerEnrollmentError>;
}

// Verifies proof of possession for the exact P-256 public-key transcript.
pub trait CoreControllerEnrollmentProofPort: Send + Sync {
    // Rejects malformed keys, signatures, and transcript divergence before confirmation.
    fn verify(
        &self,
        public_key: &ControllerPublicKey,
        challenge: &[u8],
        proof: &[u8],
    ) -> Result<(), CoreControllerEnrollmentError>;
}

// Owns one interactive CLI enrollment from listener creation through issued response.
pub struct CoreControllerEnrollmentProvider {
    configuration: CoreControllerEnrollmentConfiguration,
    sessions: Arc<dyn CoreControllerEnrollmentSessionProvider>,
    entropy: Arc<dyn CoreControllerEnrollmentEntropyPort>,
    confirmation: Arc<dyn CoreControllerEnrollmentConfirmationPort>,
    proof: Arc<dyn CoreControllerEnrollmentProofPort>,
}

impl CoreControllerEnrollmentProvider {
    // Creates one provider from explicit external mechanisms and immutable installation context.
    pub fn new(
        configuration: CoreControllerEnrollmentConfiguration,
        sessions: Arc<dyn CoreControllerEnrollmentSessionProvider>,
        entropy: Arc<dyn CoreControllerEnrollmentEntropyPort>,
        confirmation: Arc<dyn CoreControllerEnrollmentConfirmationPort>,
        proof: Arc<dyn CoreControllerEnrollmentProofPort>,
    ) -> Self {
        Self {
            configuration,
            sessions,
            entropy,
            confirmation,
            proof,
        }
    }
}

impl NativeControllerEnrollmentPort for CoreControllerEnrollmentProvider {
    // Performs proof and human confirmation before the sole durable candidate commit.
    fn enroll(
        &self,
        timeout: Duration,
        role: ControllerRole,
        progress: &mut dyn CommandProgressPort,
        commit: &mut dyn NativeControllerEnrollmentCommitPort,
    ) -> Result<NodeControllerSummary, CommandFailure> {
        if !(Duration::from_secs(30)..=Duration::from_secs(180)).contains(&timeout) {
            return Err(enrollment_failure(
                CoreControllerEnrollmentError::ConfigurationUnavailable,
            ));
        }
        let mut random = [0_u8; 52];
        self.entropy.fill(&mut random).map_err(enrollment_failure)?;
        let setup_code = format!(
            "{:08}",
            u32::from_be_bytes(random[..4].try_into().expect("fixed entropy")) % 100_000_000
        );
        let session_id = lowercase_hex(&random[4..20]);
        let nonce = lowercase_hex(&random[20..52]);
        let mut session = self
            .sessions
            .open(
                &self.configuration,
                &setup_code,
                &session_id,
                &nonce,
                timeout,
            )
            .map_err(enrollment_failure)?;
        progress.report(CommandProgressEvent::Detail(format!(
            "Pair code {}-{}-{} · port {}",
            &setup_code[..3],
            &setup_code[3..5],
            &setup_code[5..],
            CORE_CONTROLLER_ENROLLMENT_PORT
        )));
        let claim = match session.receive(progress) {
            Ok(claim) => claim,
            Err(error) => {
                session.reject();
                return Err(enrollment_failure(error));
            }
        };
        let challenge = enrollment_challenge(
            &self.configuration.installation_id,
            &session_id,
            &nonce,
            &claim,
        );
        if let Err(error) = self
            .proof
            .verify(&claim.public_key, &challenge, &claim.proof)
        {
            session.reject();
            return Err(enrollment_failure(error));
        }
        let comparison = comparison_code(
            &self.configuration.installation_id,
            &session_id,
            &nonce,
            &claim,
        );
        progress.report(CommandProgressEvent::Detail(format!(
            "Controller {} · verify {}-{}",
            claim.name.as_str(),
            &comparison[..3],
            &comparison[3..]
        )));
        if progress.is_cancelled() {
            session.reject();
            return Err(enrollment_failure(CoreControllerEnrollmentError::Cancelled));
        }
        let confirmed = match self.confirmation.confirm(&claim.name, &comparison) {
            Ok(confirmed) => confirmed,
            Err(error) => {
                session.reject();
                return Err(enrollment_failure(error));
            }
        };
        if !confirmed {
            session.reject();
            return Err(enrollment_failure(
                CoreControllerEnrollmentError::ConfirmationDenied,
            ));
        }
        let receipt = match commit.commit(
            NodeControllerEnrollmentCandidate::new(
                claim.controller_id,
                claim.name,
                claim.public_key,
            ),
            role,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                session.reject();
                return Err(error);
            }
        };
        session
            .complete(receipt.controller(), receipt.certificate_public_material())
            .map_err(enrollment_failure)?;
        Ok(receipt.controller().clone())
    }
}

// Fills enrollment entropy through the operating-system CSPRNG.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreControllerEnrollmentEntropy;

impl CoreControllerEnrollmentEntropyPort for SystemCoreControllerEnrollmentEntropy {
    // Fails closed without selecting a weaker source.
    fn fill(&self, destination: &mut [u8]) -> Result<(), CoreControllerEnrollmentError> {
        getrandom::fill(destination)
            .map_err(|_| CoreControllerEnrollmentError::ConfigurationUnavailable)
    }
}

// Verifies exact P-256 ECDSA proof through the process cryptography provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingCoreControllerEnrollmentProof;

impl CoreControllerEnrollmentProofPort for RingCoreControllerEnrollmentProof {
    // Accepts only the canonical P-256 SPKI prefix and ASN.1 SHA-256 signature.
    fn verify(
        &self,
        public_key: &ControllerPublicKey,
        challenge: &[u8],
        proof: &[u8],
    ) -> Result<(), CoreControllerEnrollmentError> {
        let point = public_key
            .bytes()
            .strip_prefix(P256_SPKI_PREFIX)
            .filter(|point| point.len() == 65 && point[0] == 0x04)
            .ok_or(CoreControllerEnrollmentError::ProofInvalid)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(challenge, proof)
            .map_err(|_| CoreControllerEnrollmentError::ProofInvalid)
    }
}

// Reads one explicit yes/no approval from the native CLI terminal.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreControllerEnrollmentConfirmation;

impl CoreControllerEnrollmentConfirmationPort for SystemCoreControllerEnrollmentConfirmation {
    // Accepts only an explicit yes response and treats interrupted input as cancellation.
    fn confirm(
        &self,
        _controller_name: &DisplayName,
        _comparison_code: &str,
    ) -> Result<bool, CoreControllerEnrollmentError> {
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::Interrupted {
                CoreControllerEnrollmentError::Cancelled
            } else {
                CoreControllerEnrollmentError::ConfigurationUnavailable
            }
        })?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
    }
}

// Opens one real TLS 1.3-only single-worker enrollment listener.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreControllerEnrollmentSessions;

impl CoreControllerEnrollmentSessionProvider for SystemCoreControllerEnrollmentSessions {
    // Loads exact TLS inputs and binds the one non-reusable transient socket before presentation.
    fn open(
        &self,
        configuration: &CoreControllerEnrollmentConfiguration,
        setup_code: &str,
        session_id: &str,
        nonce: &str,
        timeout: Duration,
    ) -> Result<Box<dyn CoreControllerEnrollmentSession>, CoreControllerEnrollmentError> {
        let tls = server_configuration(
            &configuration.server_certificate_file,
            &configuration.server_private_key_file,
        )?;
        let ca_certificate = read_bounded_file(&configuration.controller_ca_certificate_file)?;
        let listener = TcpListener::bind(configuration.listen_address)
            .map_err(|_| CoreControllerEnrollmentError::ListenerUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| CoreControllerEnrollmentError::ListenerUnavailable)?;
        Ok(Box::new(SystemCoreControllerEnrollmentSession {
            listener,
            tls: Arc::new(tls),
            installation_id: configuration.installation_id.clone(),
            setup_code: setup_code.to_string(),
            session_id: session_id.to_string(),
            nonce: nonce.to_string(),
            watchdog_port: configuration.watchdog_port,
            control_port: configuration.control_port,
            ca_certificate,
            deadline: Instant::now() + timeout,
            response: None,
            attempted: false,
        }))
    }
}

// Retains one accepted TLS response only until confirmation and durable commit complete.
struct SystemCoreControllerEnrollmentSession {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    installation_id: InstallationId,
    setup_code: String,
    session_id: String,
    nonce: String,
    watchdog_port: u16,
    control_port: u16,
    ca_certificate: Vec<u8>,
    deadline: Instant,
    response: Option<StreamOwned<ServerConnection, TcpStream>>,
    attempted: bool,
}

impl CoreControllerEnrollmentSession for SystemCoreControllerEnrollmentSession {
    // Serves one hello and accepts one bounded enrollment body under one absolute deadline.
    fn receive(
        &mut self,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CoreControllerEnrollmentClaim, CoreControllerEnrollmentError> {
        loop {
            if progress.is_cancelled() {
                return Err(CoreControllerEnrollmentError::Cancelled);
            }
            if Instant::now() >= self.deadline {
                return Err(CoreControllerEnrollmentError::TimedOut);
            }
            let (stream, _) = match self.listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => return Err(CoreControllerEnrollmentError::ListenerUnavailable),
            };
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            stream
                .set_read_timeout(Some(remaining.min(Duration::from_secs(15))))
                .map_err(|_| CoreControllerEnrollmentError::ListenerUnavailable)?;
            stream
                .set_write_timeout(Some(remaining.min(Duration::from_secs(15))))
                .map_err(|_| CoreControllerEnrollmentError::ListenerUnavailable)?;
            let connection = ServerConnection::new(Arc::clone(&self.tls))
                .map_err(|_| CoreControllerEnrollmentError::TlsUnavailable)?;
            let mut secure = StreamOwned::new(connection, stream);
            let request = read_http_request(&mut secure)?;
            if request.method == "GET" && request.path == "/pair/v1/hello" && !self.attempted {
                let body = serde_json::to_vec(&WireHello {
                    protocol: CORE_CONTROLLER_ENROLLMENT_PROTOCOL,
                    installation_id: self.installation_id.as_str(),
                    session_id: &self.session_id,
                    nonce: &self.nonce,
                    watchdog_port: self.watchdog_port,
                    control_port: self.control_port,
                })
                .map_err(|_| CoreControllerEnrollmentError::ResponseUnavailable)?;
                write_http_response(&mut secure, 200, &body)?;
                continue;
            }
            if request.method != "POST" || request.path != "/pair/v1/enroll" || self.attempted {
                let _ = write_http_response(&mut secure, 404, br#"{"error":"not found"}"#);
                continue;
            }
            self.attempted = true;
            let wire: WireEnrollment = serde_json::from_slice(&request.body)
                .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?;
            if wire.protocol != CORE_CONTROLLER_ENROLLMENT_PROTOCOL
                || !constant_time_equal(wire.setup_code.as_bytes(), self.setup_code.as_bytes())
            {
                return Err(CoreControllerEnrollmentError::SetupCodeInvalid);
            }
            let claim = CoreControllerEnrollmentClaim::new(
                ControllerId::parse(&wire.controller_id)
                    .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?,
                DisplayName::parse(&wire.name)
                    .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?,
                ControllerPublicKey::new(
                    BASE64
                        .decode(&wire.public_key_spki)
                        .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?,
                )
                .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?,
                BASE64
                    .decode(&wire.proof)
                    .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?,
            )?;
            self.response = Some(secure);
            return Ok(claim);
        }
    }

    // Returns public trust material only after the caller reports a durable active controller.
    fn complete(
        &mut self,
        controller: &NodeControllerSummary,
        certificate_public_material: &[u8],
    ) -> Result<(), CoreControllerEnrollmentError> {
        let certificate = certificate_pem(certificate_public_material)?;
        let ca = std::str::from_utf8(&self.ca_certificate)
            .map_err(|_| CoreControllerEnrollmentError::ResponseUnavailable)?;
        let body = serde_json::to_vec(&WireEnrollmentResponse {
            protocol: CORE_CONTROLLER_ENROLLMENT_PROTOCOL,
            status: "paired",
            installation_id: self.installation_id.as_str(),
            controller_id: controller.controller_id().as_str(),
            role: controller.role().as_str(),
            watchdog_port: self.watchdog_port,
            control_port: self.control_port,
            certificate_pem: &certificate,
            ca_pem: ca,
        })
        .map_err(|_| CoreControllerEnrollmentError::ResponseUnavailable)?;
        let mut response = self
            .response
            .take()
            .ok_or(CoreControllerEnrollmentError::ResponseUnavailable)?;
        write_http_response(&mut response, 200, &body)
    }

    // Sends one generic closed response without copying failure or candidate details.
    fn reject(&mut self) {
        if let Some(mut response) = self.response.take() {
            let _ = write_http_response(&mut response, 403, br#"{"error":"pairing failed"}"#);
        }
    }
}

// Encodes exact certificate DER as canonical PEM only at the controller response boundary.
fn certificate_pem(der: &[u8]) -> Result<String, CoreControllerEnrollmentError> {
    if der.is_empty() || der.len() > MAXIMUM_TLS_FILE_BYTES {
        return Err(CoreControllerEnrollmentError::ResponseUnavailable);
    }
    let encoded = BASE64.encode(der);
    let mut pem = String::with_capacity(encoded.len() + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(
            std::str::from_utf8(line)
                .map_err(|_| CoreControllerEnrollmentError::ResponseUnavailable)?,
        );
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem)
}

// Stores one strict HTTP request used only inside the transient TLS connection.
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

// Stores the exact public hello document expected by the existing Mac client.
#[derive(Serialize)]
struct WireHello<'a> {
    protocol: &'static str,
    installation_id: &'a str,
    session_id: &'a str,
    nonce: &'a str,
    watchdog_port: u16,
    control_port: u16,
}

// Stores one closed controller claim without accepting extra fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnrollment {
    protocol: String,
    setup_code: String,
    controller_id: String,
    name: String,
    public_key_spki: String,
    proof: String,
}

// Stores the exact public trust response consumed by the existing Mac client.
#[derive(Serialize)]
struct WireEnrollmentResponse<'a> {
    protocol: &'static str,
    status: &'static str,
    installation_id: &'a str,
    controller_id: &'a str,
    role: &'static str,
    watchdog_port: u16,
    control_port: u16,
    certificate_pem: &'a str,
    ca_pem: &'a str,
}

// Builds one production provider from real TLS, entropy, proof, and terminal mechanisms.
pub fn compose_system_core_controller_enrollment(
    configuration: CoreControllerEnrollmentConfiguration,
) -> Arc<dyn NativeControllerEnrollmentPort> {
    Arc::new(CoreControllerEnrollmentProvider::new(
        configuration,
        Arc::new(SystemCoreControllerEnrollmentSessions),
        Arc::new(SystemCoreControllerEnrollmentEntropy),
        Arc::new(SystemCoreControllerEnrollmentConfirmation),
        Arc::new(RingCoreControllerEnrollmentProof),
    ))
}

// Creates the exact proof transcript shared with the existing Mac client.
fn enrollment_challenge(
    installation_id: &InstallationId,
    session_id: &str,
    nonce: &str,
    claim: &CoreControllerEnrollmentClaim,
) -> Vec<u8> {
    format!(
        "{CORE_CONTROLLER_ENROLLMENT_PROTOCOL}\n{}\n{session_id}\n{nonce}\n{}\n{}\n{}\n",
        installation_id.as_str(),
        claim.controller_id.as_str(),
        claim.name.as_str(),
        claim.public_key.sha256().as_str(),
    )
    .into_bytes()
}

// Derives the six-digit human comparison code from exact session and key identity.
fn comparison_code(
    installation_id: &InstallationId,
    session_id: &str,
    nonce: &str,
    claim: &CoreControllerEnrollmentClaim,
) -> String {
    let transcript = format!(
        "{CORE_CONTROLLER_ENROLLMENT_PROTOCOL}:confirmation\n{}\n{session_id}\n{nonce}\n{}\n{}\n",
        installation_id.as_str(),
        claim.controller_id.as_str(),
        claim.public_key.sha256().as_str(),
    );
    let digest = Sha256::digest(transcript.as_bytes());
    let value = u32::from_be_bytes(digest[..4].try_into().expect("SHA-256 prefix")) % 1_000_000;
    format!("{value:06}")
}

// Maps one enrollment terminal state into stable CLI outcome and language.
fn enrollment_failure(error: CoreControllerEnrollmentError) -> CommandFailure {
    let kind = match error {
        CoreControllerEnrollmentError::Cancelled => CommandFailureKind::Cancelled,
        CoreControllerEnrollmentError::ConfirmationDenied => CommandFailureKind::Denied,
        _ => CommandFailureKind::Failed,
    };
    CommandFailure::new(kind, enrollment_failure_code(error), error.to_string())
        .expect("static enrollment failure contract")
}

// Selects one bounded stable code without exposing native or cryptographic detail.
const fn enrollment_failure_code(error: CoreControllerEnrollmentError) -> &'static str {
    match error {
        CoreControllerEnrollmentError::Cancelled => "auth.controller.cancelled",
        CoreControllerEnrollmentError::TimedOut => "auth.controller.timed_out",
        CoreControllerEnrollmentError::ConfigurationUnavailable => {
            "auth.controller.configuration_unavailable"
        }
        CoreControllerEnrollmentError::ListenerUnavailable => {
            "auth.controller.listener_unavailable"
        }
        CoreControllerEnrollmentError::TlsUnavailable => "auth.controller.tls_unavailable",
        CoreControllerEnrollmentError::RequestInvalid => "auth.controller.request_invalid",
        CoreControllerEnrollmentError::SetupCodeInvalid => "auth.controller.code_invalid",
        CoreControllerEnrollmentError::ProofInvalid => "auth.controller.proof_invalid",
        CoreControllerEnrollmentError::ConfirmationDenied => "auth.controller.denied",
        CoreControllerEnrollmentError::ResponseUnavailable => {
            "auth.controller.response_unavailable"
        }
    }
}

// Loads one bounded TLS input without copying bytes or paths into diagnostics.
fn read_bounded_file(path: &Path) -> Result<Vec<u8>, CoreControllerEnrollmentError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| CoreControllerEnrollmentError::ConfigurationUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| CoreControllerEnrollmentError::ConfigurationUnavailable)?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAXIMUM_TLS_FILE_BYTES as u64
    {
        return Err(CoreControllerEnrollmentError::ConfigurationUnavailable);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take((MAXIMUM_TLS_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CoreControllerEnrollmentError::ConfigurationUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| CoreControllerEnrollmentError::ConfigurationUnavailable)?;
    if bytes.len() > MAXIMUM_TLS_FILE_BYTES
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != before.uid()
        || after.mode() != before.mode()
        || after.nlink() != before.nlink()
        || after.len() != before.len()
        || after.len() != bytes.len() as u64
    {
        return Err(CoreControllerEnrollmentError::ConfigurationUnavailable);
    }
    Ok(bytes)
}

// Builds one TLS 1.3-only server configuration from exact PEM inputs.
fn server_configuration(
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<ServerConfig, CoreControllerEnrollmentError> {
    let certificate = read_bounded_file(certificate_file)?;
    let mut private_key = read_bounded_file(private_key_file)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| CoreControllerEnrollmentError::TlsUnavailable)?;
    let parsed_private_key = rustls_pemfile::private_key(&mut Cursor::new(&private_key));
    private_key.fill(0);
    let parsed_private_key = parsed_private_key
        .map_err(|_| CoreControllerEnrollmentError::TlsUnavailable)?
        .ok_or(CoreControllerEnrollmentError::TlsUnavailable)?;
    if certificates.is_empty() {
        return Err(CoreControllerEnrollmentError::TlsUnavailable);
    }
    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certificates, PrivateKeyDer::from(parsed_private_key))
        .map_err(|_| CoreControllerEnrollmentError::TlsUnavailable)
}

// Reads one strict request line, bounded headers, exact content length, and no chunked body.
fn read_http_request(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
) -> Result<HttpRequest, CoreControllerEnrollmentError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?;
    if line.len() > 256 || !line.ends_with("\r\n") {
        return Err(CoreControllerEnrollmentError::RequestInvalid);
    }
    let request = line.trim_end_matches("\r\n").split(' ').collect::<Vec<_>>();
    if request.len() != 3 || request[2] != "HTTP/1.1" {
        return Err(CoreControllerEnrollmentError::RequestInvalid);
    }
    let method = request[0].to_string();
    let path = request[1].to_string();
    let mut content_length = 0_usize;
    let mut content_type = None;
    let mut header_bytes = line.len();
    loop {
        line.clear();
        reader
            .read_line(&mut line)
            .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAXIMUM_REQUEST_BYTES {
            return Err(CoreControllerEnrollmentError::RequestInvalid);
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line
            .trim_end_matches("\r\n")
            .split_once(':')
            .ok_or(CoreControllerEnrollmentError::RequestInvalid)?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?;
            }
            "content-type" => content_type = Some(value.trim().to_ascii_lowercase()),
            "transfer-encoding" => return Err(CoreControllerEnrollmentError::RequestInvalid),
            _ => {}
        }
    }
    if content_length > MAXIMUM_REQUEST_BYTES.saturating_sub(header_bytes)
        || (method == "POST"
            && (content_length < 2 || content_type.as_deref() != Some("application/json")))
    {
        return Err(CoreControllerEnrollmentError::RequestInvalid);
    }
    let mut body = vec![0_u8; content_length];
    reader
        .read_exact(&mut body)
        .map_err(|_| CoreControllerEnrollmentError::RequestInvalid)?;
    Ok(HttpRequest { method, path, body })
}

// Compares one-use setup bytes without an early content-dependent exit.
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

// Writes one no-store JSON response and closes the transient connection.
fn write_http_response(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    status: u16,
    body: &[u8],
) -> Result<(), CoreControllerEnrollmentError> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => return Err(CoreControllerEnrollmentError::ResponseUnavailable),
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .and_then(|_| stream.flush())
    .map_err(|_| CoreControllerEnrollmentError::ResponseUnavailable)
}

// Returns canonical lowercase hexadecimal text for exact random session bytes.
fn lowercase_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

// Requires one explicit absolute path without root, dot, or empty components.
fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .skip(1)
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}
