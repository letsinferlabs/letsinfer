// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    ApplicationCoreCliPairing, CoreCliPairingActivationPort, CoreCliPairingDiscoveryPort,
    CoreCliPairingEntropyPort, CoreCliPairingError, CoreCliPairingSetupCodePort,
    CorePairingActivationConfirmationPort, CorePairingActivationError, CorePairingJoinRequest,
};
use li_core_cli::{
    CommandProgressEvent, CommandProgressPort, NativeNodePairingEndpoint,
    NativeNodePairingJoinRequest, NativeNodePairingJoinSource, NativeNodePairingMode,
    NativeNodePairingPort,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, NetworkInterfaceName, Node,
    NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest,
    UnixMilliseconds,
};
use li_node_manager::{
    NodePairingCancellationPort, NodePairingCandidateOffer, NodePairingClientPort,
    NodePairingTransportError, NodePairingTransportRequest, NodePairingTransportResponse,
};
use li_pairing_manager::{
    PairingCandidateTrustProvider, PairingClock, PairingDiscoveredAdvertisement,
    PairingDiscoveredCandidate, PairingDiscoveryMode, PairingError, PAIRING_DISCOVERY_PORT,
};

// Returns fixed invitation and candidate records without granting discovery mutation authority.
struct DiscoveryMock {
    invitations: Vec<PairingDiscoveredAdvertisement>,
    candidates: Vec<PairingDiscoveredCandidate>,
}

impl CoreCliPairingDiscoveryPort for DiscoveryMock {
    // Returns exact invitation fixtures and verifies the provider preserves its native bound.
    fn invitations(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredAdvertisement>, CoreCliPairingError> {
        assert_eq!(timeout_seconds, 15);
        Ok(self.invitations.clone())
    }

    // Returns exact candidate fixtures and verifies the provider preserves its native bound.
    fn candidates(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredCandidate>, CoreCliPairingError> {
        assert_eq!(timeout_seconds, 15);
        Ok(self.candidates.clone())
    }
}

// Returns one fixed clock observation for advertisement and offer validity checks.
struct ClockMock;

impl PairingClock for ClockMock {
    // Returns the exact shared observation used by all pairing fixtures.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        Ok(UnixMilliseconds::new(2_000))
    }
}

// Returns one exact nonce and exposes no independent identity source.
struct EntropyMock;

impl CoreCliPairingEntropyPort for EntropyMock {
    // Returns the nonce bound into the candidate offer fixture.
    fn nonce(&self) -> Result<Sha256Digest, CoreCliPairingError> {
        Ok(digest('7'))
    }
}

// Returns one human setup code while keeping it outside command arguments and diagnostics.
struct SetupCodeMock;

impl CoreCliPairingSetupCodePort for SetupCodeMock {
    // Returns one exact valid eight-digit authorization code.
    fn read_setup_code(&self) -> Result<String, CoreCliPairingError> {
        Ok("12345678".to_string())
    }
}

// Records the closed activation request and returns one already-committed child snapshot.
struct ActivationMock {
    requests: Mutex<Vec<CorePairingJoinRequest>>,
    child: Node,
}

impl CoreCliPairingActivationPort for ActivationMock {
    // Captures the public endpoint/code request without reading manager persistence.
    fn activate(
        &self,
        request: &CorePairingJoinRequest,
        _confirmation: &dyn CorePairingActivationConfirmationPort,
    ) -> Result<Node, CoreCliPairingError> {
        self.requests
            .lock()
            .expect("activation requests")
            .push(request.clone());
        Ok(self.child.clone())
    }
}

// Accepts remote comparison codes only when an activation coordinator requests confirmation.
struct ConfirmationMock;

impl CorePairingActivationConfirmationPort for ConfirmationMock {
    // Accepts the deterministic test code without retaining it in diagnostics or state.
    fn confirm(&self, comparison_code: &str) -> Result<bool, CorePairingActivationError> {
        assert_eq!(comparison_code, "654321");
        Ok(true)
    }
}

// Returns one typed candidate response and records the exact pinned request boundary.
struct ClientMock {
    response: NodePairingTransportResponse,
    calls: Mutex<Vec<(NodeAddress, u16, Sha256Digest, NodePairingTransportRequest)>>,
}

impl NodePairingClientPort for ClientMock {
    // Records the endpoint and request while proving the supplied cancellation starts live.
    fn exchange(
        &self,
        address: &NodeAddress,
        port: u16,
        expected_certificate_sha256: &Sha256Digest,
        request: &NodePairingTransportRequest,
        timeout: Duration,
        cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        assert_eq!(timeout, Duration::from_secs(60));
        assert!(!cancellation.is_cancelled());
        self.calls.lock().expect("client calls").push((
            address.clone(),
            port,
            expected_certificate_sha256.clone(),
            request.clone(),
        ));
        Ok(self.response.clone())
    }
}

// Verifies candidate possession while returning the canonical public-key fingerprint.
struct TrustMock;

impl PairingCandidateTrustProvider for TrustMock {
    // Is unused because candidate-side activation owns local public-key loading.
    fn public_key(&self) -> Result<(Vec<u8>, Sha256Digest), PairingError> {
        Err(PairingError::TrustUnavailable)
    }

    // Is unused because candidate-side activation owns local proof signing.
    fn sign(&self, _transcript: &[u8]) -> Result<Vec<u8>, PairingError> {
        Err(PairingError::TrustUnavailable)
    }

    // Accepts only the exact fixture public key, canonical transcript, and signature.
    fn verify(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        assert_eq!(public_key, vec![b'p'; 128]);
        assert!(!transcript.is_empty());
        assert_eq!(signature, b"candidate-signature");
        Ok(digest('8'))
    }

    // Is unused because the activation coordinator owns issued-certificate validation.
    fn verify_membership_certificate(
        &self,
        _candidate_public_key: &[u8],
        _main_ca_certificate: &[u8],
        _child_certificate: &[u8],
        _expected_child_leaf_sha256: &Sha256Digest,
    ) -> Result<(), PairingError> {
        Err(PairingError::TrustUnavailable)
    }
}

// Captures pairing progress and exposes deterministic caller cancellation.
#[derive(Default)]
struct ProgressMock {
    events: Vec<CommandProgressEvent>,
    cancelled: bool,
}

impl CommandProgressPort for ProgressMock {
    // Retains only stable provider-authored progress strings.
    fn report(&mut self, event: CommandProgressEvent) {
        self.events.push(event);
    }

    // Returns the caller-selected cancellation state.
    fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

// Resolves one LAN invitation, prompts once, and forwards only its public activation contract.
#[test]
fn cli_pairing_resolves_one_lan_invitation_and_activates_atomically() {
    let activation = Arc::new(ActivationMock {
        requests: Mutex::new(Vec::new()),
        child: node('2', "child", NodeRole::Child),
    });
    let provider = provider(
        vec![invitation(PairingDiscoveryMode::Lan)],
        Vec::new(),
        candidate_offer('8'),
        activation.clone(),
    );
    let request = NativeNodePairingJoinRequest::new(
        NativeNodePairingMode::Lan,
        NativeNodePairingJoinSource::Discovery,
        Duration::from_secs(60),
    )
    .expect("join request");
    let mut progress = ProgressMock::default();
    let child = provider
        .join(&request, &mut progress)
        .expect("joined child");
    assert_eq!(child.role(), NodeRole::Child);
    let requests = activation.requests.lock().expect("activation requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].invite_id(), &invite_id());
    assert_eq!(requests[0].address().as_str(), "main.local");
    assert_eq!(requests[0].port(), PAIRING_DISCOVERY_PORT);
    assert_eq!(requests[0].certificate_sha256(), &digest('9'));
    assert_eq!(requests[0].setup_code(), Some("12345678"));
    assert_eq!(requests[0].timeout(), Duration::from_secs(60));
    assert_eq!(progress.events.len(), 2);
}

// Pins candidate TLS, validates signed offer identity, and preserves the exact direct interface.
#[test]
fn cli_pairing_proof_validates_connectx_candidate_before_returning_mode() {
    let activation = Arc::new(ActivationMock {
        requests: Mutex::new(Vec::new()),
        child: node('2', "child", NodeRole::Child),
    });
    let provider = provider(
        Vec::new(),
        vec![candidate()],
        candidate_offer('8'),
        activation,
    );
    let interface = NetworkInterfaceName::parse("mlx5_0").expect("interface");
    let mode = provider
        .connectx_mode(&interface, Duration::from_secs(60))
        .expect("ConnectX mode");
    assert_eq!(
        mode,
        li_node_manager::NodePairingMode::ConnectX {
            candidate_public_key_sha256: digest('8'),
            direct_interface: interface,
        }
    );
}

// Rejects discovery/offer identity drift before returning any ConnectX authorization material.
#[test]
fn cli_pairing_rejects_connectx_offer_drift_and_pre_cancelled_join() {
    let activation = Arc::new(ActivationMock {
        requests: Mutex::new(Vec::new()),
        child: node('2', "child", NodeRole::Child),
    });
    let provider = provider(
        Vec::new(),
        vec![candidate()],
        candidate_offer('6'),
        activation.clone(),
    );
    let failure = provider
        .connectx_mode(
            &NetworkInterfaceName::parse("mlx5_0").expect("interface"),
            Duration::from_secs(60),
        )
        .expect_err("offer drift");
    assert_eq!(failure.code(), "node.pairing_untrusted");
    assert!(!failure.message().contains("candidate-signature"));

    let request = NativeNodePairingJoinRequest::new(
        NativeNodePairingMode::Lan,
        NativeNodePairingJoinSource::Discovery,
        Duration::from_secs(60),
    )
    .expect("join request");
    let mut progress = ProgressMock {
        events: Vec::new(),
        cancelled: true,
    };
    let failure = provider
        .join(&request, &mut progress)
        .expect_err("cancelled join");
    assert_eq!(failure.code(), "node.pairing_cancelled");
    assert!(activation
        .requests
        .lock()
        .expect("activation requests")
        .is_empty());
}

// Composes one provider from exact deterministic discovery, trust, and activation ports.
fn provider(
    invitations: Vec<PairingDiscoveredAdvertisement>,
    candidates: Vec<PairingDiscoveredCandidate>,
    offer: NodePairingCandidateOffer,
    activation: Arc<ActivationMock>,
) -> ApplicationCoreCliPairing {
    ApplicationCoreCliPairing::new(
        NativeNodePairingEndpoint::new(
            NodeAddress::parse("main.local").expect("endpoint"),
            PAIRING_DISCOVERY_PORT,
            digest('9'),
        )
        .expect("endpoint"),
        Arc::new(DiscoveryMock {
            invitations,
            candidates,
        }),
        Arc::new(ClientMock {
            response: NodePairingTransportResponse::CandidateOffer(offer),
            calls: Mutex::new(Vec::new()),
        }),
        Arc::new(TrustMock),
        Arc::new(ClockMock),
        Arc::new(li_node_manager::NodePairingCancellation::default()),
        Arc::new(SetupCodeMock),
        Arc::new(EntropyMock),
        Arc::new(ConfirmationMock),
        activation,
    )
}

// Returns one complete invitation advertisement for the selected authorization mode.
fn invitation(mode: PairingDiscoveryMode) -> PairingDiscoveredAdvertisement {
    PairingDiscoveredAdvertisement::new(
        invite_id(),
        DisplayName::parse("Main").expect("display name"),
        NodeAddress::parse("main.local").expect("address"),
        PAIRING_DISCOVERY_PORT,
        digest('9'),
        UnixMilliseconds::new(10_000),
        mode,
    )
    .expect("invitation")
}

// Returns one complete candidate advertisement for ConnectX preflight.
fn candidate() -> PairingDiscoveredCandidate {
    PairingDiscoveredCandidate::new(
        NodeId::parse(&"3".repeat(32)).expect("candidate node"),
        DisplayName::parse("Candidate").expect("display name"),
        NodeAddress::parse("candidate.local").expect("address"),
        PAIRING_DISCOVERY_PORT,
        digest('8'),
        digest('9'),
        UnixMilliseconds::new(10_000),
    )
    .expect("candidate")
}

// Returns one signed offer whose fingerprint may intentionally drift from discovery.
fn candidate_offer(public_key_character: char) -> NodePairingCandidateOffer {
    NodePairingCandidateOffer::new(
        node('3', "Candidate", NodeRole::Main),
        vec![b'p'; 128],
        digest(public_key_character),
        digest('9'),
        digest('7'),
        UnixMilliseconds::new(1_500),
        UnixMilliseconds::new(5_000),
        b"candidate-signature".to_vec(),
    )
    .expect("candidate offer")
}

// Returns one stable invitation identity.
fn invite_id() -> PairingInviteId {
    PairingInviteId::parse(&"4".repeat(32)).expect("invitation")
}

// Returns one coherent active Node fixture.
fn node(character: char, name: &str, role: NodeRole) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&character.to_string().repeat(32)).expect("node"),
            MachineId::parse(&character.to_string().repeat(32)).expect("machine"),
            InstallationId::parse(&character.to_string().repeat(64)).expect("installation"),
        ),
        DisplayName::parse(name).expect("display name"),
        role,
        NodeState::Active,
        NodeAddress::parse(&format!("{name}.local:9770")).expect("control address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_500))
            .expect("timestamps"),
    )
}

// Returns one canonical repeated-character digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}
