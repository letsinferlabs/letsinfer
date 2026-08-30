// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use li_core_cli::{
    CommandFailure, CommandFailureKind, CommandProgressEvent, CommandProgressPort,
    NativeNodePairingEndpoint, NativeNodePairingJoinRequest, NativeNodePairingJoinSource,
    NativeNodePairingMode, NativeNodePairingPort,
};
use li_core_interface::{NetworkInterfaceName, Node, Sha256Digest};
use li_node_manager::{
    node_pairing_candidate_offer_transcript, NodePairingCancellation, NodePairingClientPort,
    NodePairingMode, NodePairingTransportRequest, NodePairingTransportResponse,
};
use li_pairing_manager::{
    NativePairingDiscoveryBrowser, PairingCandidateTrustProvider, PairingClock,
    PairingDiscoveredAdvertisement, PairingDiscoveredCandidate, PairingDiscoveryMode,
};

use crate::{
    CorePairingActivationConfirmationPort, CorePairingActivationCoordinator,
    CorePairingActivationError, CorePairingJoinRequest,
};

const MAXIMUM_DISCOVERY_SECONDS: u64 = 15;
const SETUP_CODE_BYTES: usize = 8;
const COMPARISON_CODE_BYTES: usize = 6;
const CONFIRMATION_BYTES: usize = 3;

// Browses only complete signed-pairing advertisements through one injected native boundary.
pub trait CoreCliPairingDiscoveryPort: Send + Sync {
    // Returns complete main invitation advertisements within the selected bound.
    fn invitations(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredAdvertisement>, CoreCliPairingError>;

    // Returns complete candidate-offer advertisements within the selected bound.
    fn candidates(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredCandidate>, CoreCliPairingError>;
}

impl CoreCliPairingDiscoveryPort for NativePairingDiscoveryBrowser {
    // Delegates invitation browsing without altering native DNS-SD validation.
    fn invitations(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredAdvertisement>, CoreCliPairingError> {
        self.browse(timeout_seconds)
            .map_err(|_| CoreCliPairingError::DiscoveryUnavailable)
    }

    // Delegates candidate browsing without altering native DNS-SD validation.
    fn candidates(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredCandidate>, CoreCliPairingError> {
        self.browse_candidates(timeout_seconds)
            .map_err(|_| CoreCliPairingError::DiscoveryUnavailable)
    }
}

// Supplies the human setup code outside argv, environment, persistence, and diagnostics.
pub trait CoreCliPairingSetupCodePort: Send + Sync {
    // Reads exactly one eight-digit code for the selected invitation.
    fn read_setup_code(&self) -> Result<String, CoreCliPairingError>;
}

// Supplies one unpredictable nonce without coupling pairing to CLI request identities.
pub trait CoreCliPairingEntropyPort: Send + Sync {
    // Returns one fresh 256-bit nonce for candidate-offer replay protection.
    fn nonce(&self) -> Result<Sha256Digest, CoreCliPairingError>;
}

// Isolates atomic Node/configuration/service activation from discovery and presentation.
pub trait CoreCliPairingActivationPort: Send + Sync {
    // Activates one child only after the exact endpoint and human authorization are resolved.
    fn activate(
        &self,
        request: &CorePairingJoinRequest,
        confirmation: &dyn CorePairingActivationConfirmationPort,
    ) -> Result<Node, CoreCliPairingError>;
}

impl CoreCliPairingActivationPort for CorePairingActivationCoordinator {
    // Delegates the complete durable activation transaction and returns the local child snapshot.
    fn activate(
        &self,
        request: &CorePairingJoinRequest,
        confirmation: &dyn CorePairingActivationConfirmationPort,
    ) -> Result<Node, CoreCliPairingError> {
        CorePairingActivationCoordinator::activate(self, request, confirmation)
            .map(|result| result.local().clone())
            .map_err(activation_error)
    }
}

// Reads one setup code directly from the controlling terminal with echo disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreCliPairingSetupCode;

impl CoreCliPairingSetupCodePort for SystemCoreCliPairingSetupCode {
    // Reads one bounded line and restores terminal echo on every return path.
    fn read_setup_code(&self) -> Result<String, CoreCliPairingError> {
        read_terminal_setup_code(Path::new("/dev/tty"))
    }
}

// Obtains native cryptographic randomness for one preflight challenge nonce.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreCliPairingEntropy;

impl CoreCliPairingEntropyPort for SystemCoreCliPairingEntropy {
    // Returns one canonical digest-shaped nonce without retaining the random buffer.
    fn nonce(&self) -> Result<Sha256Digest, CoreCliPairingError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CoreCliPairingError::EntropyUnavailable)?;
        let text = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        bytes.fill(0);
        Sha256Digest::parse(&text).map_err(|_| CoreCliPairingError::EntropyUnavailable)
    }
}

// Owns the child terminal presentation and explicit approval of one remote comparison code.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCorePairingActivationConfirmation;

impl CorePairingActivationConfirmationPort for SystemCorePairingActivationConfirmation {
    // Presents the code exactly once on the controlling terminal and accepts only "yes".
    fn confirm(&self, comparison_code: &str) -> Result<bool, CorePairingActivationError> {
        read_terminal_comparison_confirmation(Path::new("/dev/tty"), comparison_code)
    }
}

// Owns the complete user-safe pairing workflow over existing PairingManager/Node authorities.
pub struct ApplicationCoreCliPairing {
    endpoint: NativeNodePairingEndpoint,
    discovery: Arc<dyn CoreCliPairingDiscoveryPort>,
    client: Arc<dyn NodePairingClientPort>,
    trust: Arc<dyn PairingCandidateTrustProvider>,
    clock: Arc<dyn PairingClock>,
    cancellation: Arc<NodePairingCancellation>,
    setup_code: Arc<dyn CoreCliPairingSetupCodePort>,
    entropy: Arc<dyn CoreCliPairingEntropyPort>,
    confirmation: Arc<dyn CorePairingActivationConfirmationPort>,
    activation: Arc<dyn CoreCliPairingActivationPort>,
}

impl ApplicationCoreCliPairing {
    // Creates one closed workflow from exact discovery, trust, activation, and user-input ports.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: NativeNodePairingEndpoint,
        discovery: Arc<dyn CoreCliPairingDiscoveryPort>,
        client: Arc<dyn NodePairingClientPort>,
        trust: Arc<dyn PairingCandidateTrustProvider>,
        clock: Arc<dyn PairingClock>,
        cancellation: Arc<NodePairingCancellation>,
        setup_code: Arc<dyn CoreCliPairingSetupCodePort>,
        entropy: Arc<dyn CoreCliPairingEntropyPort>,
        confirmation: Arc<dyn CorePairingActivationConfirmationPort>,
        activation: Arc<dyn CoreCliPairingActivationPort>,
    ) -> Self {
        Self {
            endpoint,
            discovery,
            client,
            trust,
            clock,
            cancellation,
            setup_code,
            entropy,
            confirmation,
            activation,
        }
    }

    // Resolves exactly one unexpired main advertisement matching the requested authorization mode.
    fn discovered_invitation(
        &self,
        mode: NativeNodePairingMode,
        timeout: Duration,
    ) -> Result<PairingDiscoveredAdvertisement, CoreCliPairingError> {
        let expected = match mode {
            NativeNodePairingMode::Lan => PairingDiscoveryMode::Lan,
            NativeNodePairingMode::ConnectX => PairingDiscoveryMode::ConnectX,
            NativeNodePairingMode::Remote => return Err(CoreCliPairingError::InvalidRequest),
        };
        let now = self
            .clock
            .now()
            .map_err(|_| CoreCliPairingError::ClockUnavailable)?;
        let mut values = self
            .discovery
            .invitations(discovery_seconds(timeout))?
            .into_iter()
            .filter(|value| value.mode() == expected && value.expires_at() > now)
            .collect::<Vec<_>>();
        if values.len() != 1 {
            return Err(CoreCliPairingError::AmbiguousDiscovery);
        }
        values.pop().ok_or(CoreCliPairingError::AmbiguousDiscovery)
    }

    // Resolves and proof-validates exactly one candidate before ConnectX invitation mutation.
    fn connectx_candidate(
        &self,
        timeout: Duration,
    ) -> Result<PairingDiscoveredCandidate, CoreCliPairingError> {
        let now = self
            .clock
            .now()
            .map_err(|_| CoreCliPairingError::ClockUnavailable)?;
        let mut candidates = self
            .discovery
            .candidates(discovery_seconds(timeout))?
            .into_iter()
            .filter(|candidate| candidate.expires_at() > now)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(CoreCliPairingError::AmbiguousDiscovery);
        }
        candidates
            .pop()
            .ok_or(CoreCliPairingError::AmbiguousDiscovery)
    }

    // Verifies nonce, discovery identities, time, and candidate possession on one TLS-pinned offer.
    fn verify_candidate_offer(
        &self,
        advertisement: &PairingDiscoveredCandidate,
        nonce: &Sha256Digest,
        response: NodePairingTransportResponse,
    ) -> Result<Sha256Digest, CoreCliPairingError> {
        let NodePairingTransportResponse::CandidateOffer(offer) = response else {
            return Err(CoreCliPairingError::UntrustedPeer);
        };
        let now = self
            .clock
            .now()
            .map_err(|_| CoreCliPairingError::ClockUnavailable)?;
        if offer.request_nonce() != nonce
            || offer.candidate().identity().node_id() != advertisement.node_id()
            || offer.candidate().display_name() != advertisement.display_name()
            || offer.public_key_sha256() != advertisement.public_key_sha256()
            || offer.certificate_sha256() != advertisement.certificate_sha256()
            || offer.issued_at() > now
            || offer.expires_at() <= now
            || advertisement.expires_at() <= now
        {
            return Err(CoreCliPairingError::UntrustedPeer);
        }
        let transcript = node_pairing_candidate_offer_transcript(
            offer.candidate(),
            offer.public_key_sha256(),
            offer.certificate_sha256(),
            offer.request_nonce(),
            offer.issued_at(),
            offer.expires_at(),
        );
        let verified = self
            .trust
            .verify(offer.public_key(), &transcript, offer.signature())
            .map_err(|_| CoreCliPairingError::UntrustedPeer)?;
        if &verified != advertisement.public_key_sha256() {
            return Err(CoreCliPairingError::UntrustedPeer);
        }
        Ok(verified)
    }
}

impl NativeNodePairingPort for ApplicationCoreCliPairing {
    // Returns the exact locally configured public pairing endpoint.
    fn local_endpoint(&self) -> Result<NativeNodePairingEndpoint, CommandFailure> {
        Ok(self.endpoint.clone())
    }

    // Discovers and proof-validates one candidate before creating a direct-link invitation.
    fn connectx_mode(
        &self,
        direct_interface: &NetworkInterfaceName,
        timeout: Duration,
    ) -> Result<NodePairingMode, CommandFailure> {
        let candidate = self.connectx_candidate(timeout).map_err(command_failure)?;
        let nonce = self.entropy.nonce().map_err(command_failure)?;
        let response = self
            .client
            .exchange(
                candidate.address(),
                candidate.port(),
                candidate.certificate_sha256(),
                &NodePairingTransportRequest::CandidateOffer {
                    request_nonce: nonce.clone(),
                },
                timeout,
                self.cancellation.as_ref(),
            )
            .map_err(|_| command_failure(CoreCliPairingError::TransportUnavailable))?;
        let candidate_public_key_sha256 = self
            .verify_candidate_offer(&candidate, &nonce, response)
            .map_err(command_failure)?;
        Ok(NodePairingMode::ConnectX {
            candidate_public_key_sha256,
            direct_interface: direct_interface.clone(),
        })
    }

    // Resolves one invitation, prompts only for its human code, and runs atomic activation.
    fn join(
        &self,
        request: &NativeNodePairingJoinRequest,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Node, CommandFailure> {
        if progress.is_cancelled() {
            self.cancellation.cancel();
            return Err(command_failure(CoreCliPairingError::Cancelled));
        }
        progress.report(CommandProgressEvent::Detail(
            "Discovering the main Node".to_string(),
        ));
        let (invite_id, address, port, certificate_sha256) = match request.source() {
            NativeNodePairingJoinSource::Remote {
                invite_id,
                endpoint,
            } => (
                invite_id.clone(),
                endpoint.address().clone(),
                endpoint.port(),
                endpoint.certificate_sha256().clone(),
            ),
            NativeNodePairingJoinSource::Discovery => {
                let invitation = self
                    .discovered_invitation(request.mode(), request.timeout())
                    .map_err(command_failure)?;
                (
                    invitation.invite_id().clone(),
                    invitation.address().clone(),
                    invitation.port(),
                    invitation.certificate_fingerprint().clone(),
                )
            }
        };
        let setup_code = if request.mode() == NativeNodePairingMode::ConnectX {
            None
        } else {
            Some(self.setup_code.read_setup_code().map_err(command_failure)?)
        };
        let activation = CorePairingJoinRequest::new(
            invite_id,
            address,
            port,
            certificate_sha256,
            setup_code,
            request.timeout(),
        )
        .map_err(activation_error)
        .map_err(command_failure)?;
        progress.report(CommandProgressEvent::Detail(
            "Verifying pairing proof".to_string(),
        ));
        self.activation
            .activate(&activation, self.confirmation.as_ref())
            .map_err(command_failure)
    }
}

// Names stable, redacted pairing composition and execution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreCliPairingError {
    InvalidRequest,
    DiscoveryUnavailable,
    AmbiguousDiscovery,
    TransportUnavailable,
    UntrustedPeer,
    ClockUnavailable,
    EntropyUnavailable,
    SetupCodeUnavailable,
    ConfirmationUnavailable,
    ConfirmationDenied,
    ActivationUnavailable,
    Cancelled,
}

impl fmt::Display for CoreCliPairingError {
    // Presents fixed language without addresses, setup codes, keys, proofs, or native paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "node pairing request is invalid",
            Self::DiscoveryUnavailable => "node pairing discovery is unavailable",
            Self::AmbiguousDiscovery => "node pairing discovery did not find exactly one peer",
            Self::TransportUnavailable => "node pairing transport is unavailable",
            Self::UntrustedPeer => "node pairing peer identity is untrusted",
            Self::ClockUnavailable => "node pairing clock is unavailable",
            Self::EntropyUnavailable => "node pairing entropy is unavailable",
            Self::SetupCodeUnavailable => "node pairing setup code is unavailable",
            Self::ConfirmationUnavailable => "node pairing comparison confirmation is unavailable",
            Self::ConfirmationDenied => "node pairing comparison code was not approved",
            Self::ActivationUnavailable => "node pairing activation failed",
            Self::Cancelled => "node pairing was cancelled",
        })
    }
}

impl Error for CoreCliPairingError {}

// Restores the original terminal flags after one setup-code prompt.
struct TerminalEchoGuard {
    descriptor: i32,
    original: libc::termios,
}

impl Drop for TerminalEchoGuard {
    // Restores the exact observed terminal flags on success and every failure path.
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.descriptor, libc::TCSAFLUSH, &self.original);
        }
    }
}

// Reads one exact digit code from a real character terminal without echoing its bytes.
fn read_terminal_setup_code(path: &Path) -> Result<String, CoreCliPairingError> {
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CoreCliPairingError::SetupCodeUnavailable)?;
    if !terminal
        .metadata()
        .map_err(|_| CoreCliPairingError::SetupCodeUnavailable)?
        .file_type()
        .is_char_device()
    {
        return Err(CoreCliPairingError::SetupCodeUnavailable);
    }
    let descriptor = terminal.as_raw_fd();
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(descriptor, &mut original) } != 0 {
        return Err(CoreCliPairingError::SetupCodeUnavailable);
    }
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    if unsafe { libc::tcsetattr(descriptor, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(CoreCliPairingError::SetupCodeUnavailable);
    }
    let _guard = TerminalEchoGuard {
        descriptor,
        original,
    };
    terminal
        .write_all(b"Setup code: ")
        .and_then(|()| terminal.flush())
        .map_err(|_| CoreCliPairingError::SetupCodeUnavailable)?;
    let mut bytes = Vec::with_capacity(SETUP_CODE_BYTES);
    loop {
        let mut byte = [0_u8; 1];
        terminal
            .read_exact(&mut byte)
            .map_err(|_| CoreCliPairingError::SetupCodeUnavailable)?;
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        if bytes.len() == SETUP_CODE_BYTES {
            return Err(CoreCliPairingError::SetupCodeUnavailable);
        }
        bytes.push(byte[0]);
    }
    let _ = terminal.write_all(b"\n");
    if bytes.len() != SETUP_CODE_BYTES || !bytes.iter().all(u8::is_ascii_digit) {
        bytes.fill(0);
        return Err(CoreCliPairingError::SetupCodeUnavailable);
    }
    let code = String::from_utf8(bytes).map_err(|_| CoreCliPairingError::SetupCodeUnavailable)?;
    Ok(code)
}

// Presents one six-digit comparison code once and reads one bounded explicit decision.
fn read_terminal_comparison_confirmation(
    path: &Path,
    comparison_code: &str,
) -> Result<bool, CorePairingActivationError> {
    if comparison_code.len() != COMPARISON_CODE_BYTES
        || !comparison_code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CorePairingActivationError::UntrustedMain);
    }
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CorePairingActivationError::ConfirmationUnavailable)?;
    if !terminal
        .metadata()
        .map_err(|_| CorePairingActivationError::ConfirmationUnavailable)?
        .file_type()
        .is_char_device()
    {
        return Err(CorePairingActivationError::ConfirmationUnavailable);
    }
    write!(
        terminal,
        "Remote pairing comparison code: {}-{}\nType yes only after it matches the main Node: ",
        &comparison_code[..3],
        &comparison_code[3..]
    )
    .and_then(|()| terminal.flush())
    .map_err(|_| CorePairingActivationError::ConfirmationUnavailable)?;
    let mut bytes = Vec::with_capacity(CONFIRMATION_BYTES);
    loop {
        let mut byte = [0_u8; 1];
        terminal.read_exact(&mut byte).map_err(|error| {
            if error.kind() == std::io::ErrorKind::Interrupted {
                CorePairingActivationError::Cancelled
            } else {
                CorePairingActivationError::ConfirmationUnavailable
            }
        })?;
        if matches!(byte[0], b'\n' | b'\r') {
            break;
        }
        if bytes.len() == CONFIRMATION_BYTES {
            bytes.fill(0);
            return Ok(false);
        }
        bytes.push(byte[0]);
    }
    let confirmed = bytes == b"yes";
    bytes.fill(0);
    Ok(confirmed)
}

// Returns one native discovery bound no longer than the complete workflow deadline.
fn discovery_seconds(timeout: Duration) -> u8 {
    u8::try_from(timeout.as_secs().min(MAXIMUM_DISCOVERY_SECONDS).max(1)).unwrap_or(1)
}

// Maps durable activation failures into the single user-safe CLI pairing vocabulary.
const fn activation_error(error: CorePairingActivationError) -> CoreCliPairingError {
    match error {
        CorePairingActivationError::InvalidRequest => CoreCliPairingError::InvalidRequest,
        CorePairingActivationError::UntrustedMain => CoreCliPairingError::UntrustedPeer,
        CorePairingActivationError::TransportUnavailable => {
            CoreCliPairingError::TransportUnavailable
        }
        CorePairingActivationError::ApprovalTimedOut
        | CorePairingActivationError::StateConflict
        | CorePairingActivationError::ConfigurationUnavailable
        | CorePairingActivationError::RoleUnavailable
        | CorePairingActivationError::ServiceUnavailable
        | CorePairingActivationError::RolledBack
        | CorePairingActivationError::RecoveryRequired => {
            CoreCliPairingError::ActivationUnavailable
        }
        CorePairingActivationError::ConfirmationUnavailable => {
            CoreCliPairingError::ConfirmationUnavailable
        }
        CorePairingActivationError::ConfirmationDenied => CoreCliPairingError::ConfirmationDenied,
        CorePairingActivationError::Cancelled => CoreCliPairingError::Cancelled,
    }
}

// Creates one redacted native command failure from the closed pairing error contract.
fn command_failure(error: CoreCliPairingError) -> CommandFailure {
    let kind = if error == CoreCliPairingError::Cancelled {
        CommandFailureKind::Cancelled
    } else {
        CommandFailureKind::Failed
    };
    let code = match error {
        CoreCliPairingError::InvalidRequest => "node.pairing_invalid",
        CoreCliPairingError::DiscoveryUnavailable => "node.pairing_discovery_unavailable",
        CoreCliPairingError::AmbiguousDiscovery => "node.pairing_discovery_ambiguous",
        CoreCliPairingError::TransportUnavailable => "node.pairing_transport_unavailable",
        CoreCliPairingError::UntrustedPeer => "node.pairing_untrusted",
        CoreCliPairingError::ClockUnavailable => "node.pairing_clock_unavailable",
        CoreCliPairingError::EntropyUnavailable => "node.pairing_entropy_unavailable",
        CoreCliPairingError::SetupCodeUnavailable => "node.pairing_setup_code_unavailable",
        CoreCliPairingError::ConfirmationUnavailable => "node.pairing_confirmation_unavailable",
        CoreCliPairingError::ConfirmationDenied => "node.pairing_confirmation_denied",
        CoreCliPairingError::ActivationUnavailable => "node.pairing_activation_failed",
        CoreCliPairingError::Cancelled => "node.pairing_cancelled",
    };
    CommandFailure::new(kind, code, error.to_string()).expect("static pairing command failure")
}
