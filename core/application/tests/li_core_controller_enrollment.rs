// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_authentication_manager::{ControllerPublicKey, ControllerRole, ControllerState};
use li_core_application::{
    CoreControllerEnrollmentClaim, CoreControllerEnrollmentConfiguration,
    CoreControllerEnrollmentConfirmationPort, CoreControllerEnrollmentEntropyPort,
    CoreControllerEnrollmentError, CoreControllerEnrollmentProofPort,
    CoreControllerEnrollmentProvider, CoreControllerEnrollmentSession,
    CoreControllerEnrollmentSessionProvider, RingCoreControllerEnrollmentProof,
    CORE_CONTROLLER_ENROLLMENT_PORT,
};
use li_core_cli::{
    CommandFailure, CommandFailureKind, CommandProgressEvent, CommandProgressPort,
    NativeControllerEnrollmentCommitPort, NativeControllerEnrollmentPort,
};
use li_core_interface::{
    ControllerId, DisplayName, InstallationId, Sha256Digest, UnixMilliseconds,
};
use li_node_manager::{
    NodeControllerEnrollmentCandidate, NodeControllerEnrollmentReceipt, NodeControllerSummary,
};
use sha2::{Digest, Sha256};

const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

// Retains observable session boundaries without copying setup, proof, or certificate bytes.
#[derive(Default)]
struct SessionState {
    rejected: usize,
    completed: usize,
    opened: usize,
}

// Supplies one deterministic claim or exact receive failure.
struct SessionProvider {
    state: Arc<Mutex<SessionState>>,
    result: Result<CoreControllerEnrollmentClaim, CoreControllerEnrollmentError>,
}

impl CoreControllerEnrollmentSessionProvider for SessionProvider {
    // Opens one mock session after checking the provider received bounded context.
    fn open(
        &self,
        _configuration: &CoreControllerEnrollmentConfiguration,
        setup_code: &str,
        session_id: &str,
        nonce: &str,
        timeout: Duration,
    ) -> Result<Box<dyn CoreControllerEnrollmentSession>, CoreControllerEnrollmentError> {
        assert_eq!(setup_code.len(), 8);
        assert_eq!(session_id.len(), 32);
        assert_eq!(nonce.len(), 64);
        assert_eq!(timeout, Duration::from_secs(30));
        self.state.lock().expect("session state").opened += 1;
        Ok(Box::new(Session {
            state: Arc::clone(&self.state),
            result: self.result.clone(),
        }))
    }
}

// Retains one mock response until commit or rejection.
struct Session {
    state: Arc<Mutex<SessionState>>,
    result: Result<CoreControllerEnrollmentClaim, CoreControllerEnrollmentError>,
}

impl CoreControllerEnrollmentSession for Session {
    // Returns the configured claim or terminal receive result without sleeping.
    fn receive(
        &mut self,
        _progress: &mut dyn CommandProgressPort,
    ) -> Result<CoreControllerEnrollmentClaim, CoreControllerEnrollmentError> {
        self.result.clone()
    }

    // Records one public-certificate response only for an active committed controller.
    fn complete(
        &mut self,
        controller: &NodeControllerSummary,
        certificate_public_material: &[u8],
    ) -> Result<(), CoreControllerEnrollmentError> {
        assert_eq!(controller.state(), ControllerState::Active);
        assert!(!certificate_public_material.is_empty());
        self.state.lock().expect("session state").completed += 1;
        Ok(())
    }

    // Records one closed response without changing controller storage.
    fn reject(&mut self) {
        self.state.lock().expect("session state").rejected += 1;
    }
}

// Fills one stable entropy block for setup, session, and nonce identities.
struct Entropy;

impl CoreControllerEnrollmentEntropyPort for Entropy {
    // Fills every byte deterministically without external state.
    fn fill(&self, destination: &mut [u8]) -> Result<(), CoreControllerEnrollmentError> {
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("bounded entropy");
        }
        Ok(())
    }
}

// Applies one explicit human confirmation decision.
struct Confirmation(bool);

impl CoreControllerEnrollmentConfirmationPort for Confirmation {
    // Returns the configured decision after checking the six-digit code shape.
    fn confirm(
        &self,
        controller_name: &DisplayName,
        comparison_code: &str,
    ) -> Result<bool, CoreControllerEnrollmentError> {
        assert_eq!(controller_name.as_str(), "Desk Mac");
        assert_eq!(comparison_code.len(), 6);
        assert!(comparison_code.bytes().all(|byte| byte.is_ascii_digit()));
        Ok(self.0)
    }
}

// Accepts or rejects the exact proof-verification boundary deterministically.
struct Proof(bool);

impl CoreControllerEnrollmentProofPort for Proof {
    // Proves that orchestration supplies a nonempty transcript and bounded signature.
    fn verify(
        &self,
        _public_key: &ControllerPublicKey,
        challenge: &[u8],
        proof: &[u8],
    ) -> Result<(), CoreControllerEnrollmentError> {
        assert!(!challenge.is_empty());
        assert_eq!(proof.len(), 64);
        if self.0 {
            Ok(())
        } else {
            Err(CoreControllerEnrollmentError::ProofInvalid)
        }
    }
}

// Records whether durable Node commit was reached and returns one fixed public receipt.
struct Commit {
    calls: usize,
    fail: bool,
}

impl NativeControllerEnrollmentCommitPort for Commit {
    // Returns one receipt only after checking exact candidate and assigned role.
    fn commit(
        &mut self,
        candidate: NodeControllerEnrollmentCandidate,
        role: ControllerRole,
    ) -> Result<NodeControllerEnrollmentReceipt, CommandFailure> {
        self.calls += 1;
        assert_eq!(candidate.controller_id(), &controller_id());
        assert_eq!(candidate.name().as_str(), "Desk Mac");
        assert_eq!(role, ControllerRole::Administrator);
        if self.fail {
            return Err(CommandFailure::new(
                CommandFailureKind::Failed,
                "auth.controller.commit_failed",
                "controller commit failed",
            )
            .expect("failure"));
        }
        receipt()
    }
}

// Records progress text and supplies deterministic cancellation.
#[derive(Default)]
struct Progress {
    details: Vec<String>,
    cancelled: bool,
}

impl CommandProgressPort for Progress {
    // Retains only detail events used by the interactive enrollment surface.
    fn report(&mut self, event: CommandProgressEvent) {
        if let CommandProgressEvent::Detail(detail) = event {
            self.details.push(detail);
        }
    }

    // Returns the configured cancellation state without timing dependence.
    fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

// Returns one exact installation-bound provider configuration for mock sessions.
fn configuration() -> CoreControllerEnrollmentConfiguration {
    CoreControllerEnrollmentConfiguration::new(
        InstallationId::parse(&"1".repeat(64)).expect("installation"),
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            CORE_CONTROLLER_ENROLLMENT_PORT,
        ),
        9_768,
        9_771,
        PathBuf::from("/tmp/server.crt"),
        PathBuf::from("/tmp/server.key"),
        PathBuf::from("/tmp/ca.crt"),
    )
    .expect("configuration")
}

// Returns one bounded controller identity.
fn controller_id() -> ControllerId {
    ControllerId::parse(&"c".repeat(32)).expect("controller")
}

// Returns one untrusted claim suitable for an injected proof decision.
fn claim() -> CoreControllerEnrollmentClaim {
    CoreControllerEnrollmentClaim::new(
        controller_id(),
        DisplayName::parse("Desk Mac").expect("name"),
        ControllerPublicKey::new(vec![7; 96]).expect("public key"),
        vec![8; 64],
    )
    .expect("claim")
}

// Returns one fingerprint-bound public certificate receipt.
fn receipt() -> Result<NodeControllerEnrollmentReceipt, CommandFailure> {
    let certificate = b"public-controller-certificate".to_vec();
    let fingerprint = Sha256Digest::parse(&format!("{:x}", Sha256::digest(&certificate)))
        .expect("certificate fingerprint");
    let summary = NodeControllerSummary::restore(
        controller_id(),
        DisplayName::parse("Desk Mac").expect("name"),
        ControllerRole::Administrator,
        ControllerState::Active,
        fingerprint,
        Sha256Digest::parse(&"e".repeat(64)).expect("public key fingerprint"),
        UnixMilliseconds::new(0),
        UnixMilliseconds::new(10_000),
        UnixMilliseconds::new(1_000),
        Some(UnixMilliseconds::new(1_000)),
        None,
    )
    .expect("summary");
    NodeControllerEnrollmentReceipt::restore(summary, certificate).map_err(|_| {
        CommandFailure::new(
            CommandFailureKind::Failed,
            "auth.controller.fixture_invalid",
            "controller fixture is invalid",
        )
        .expect("failure")
    })
}

// Composes one provider and returns its observable session state.
fn provider(
    result: Result<CoreControllerEnrollmentClaim, CoreControllerEnrollmentError>,
    confirmed: bool,
    proof: bool,
) -> (CoreControllerEnrollmentProvider, Arc<Mutex<SessionState>>) {
    let state = Arc::new(Mutex::new(SessionState::default()));
    (
        CoreControllerEnrollmentProvider::new(
            configuration(),
            Arc::new(SessionProvider {
                state: Arc::clone(&state),
                result,
            }),
            Arc::new(Entropy),
            Arc::new(Confirmation(confirmed)),
            Arc::new(Proof(proof)),
        ),
        state,
    )
}

// Completes one proof-confirm-commit-response lifecycle with stable progress and no secret output.
#[test]
fn controller_enrollment_commits_only_after_proof_and_confirmation() {
    let (provider, state) = provider(Ok(claim()), true, true);
    let mut progress = Progress::default();
    let mut commit = Commit {
        calls: 0,
        fail: false,
    };
    let controller = provider
        .enroll(
            Duration::from_secs(30),
            ControllerRole::Administrator,
            &mut progress,
            &mut commit,
        )
        .expect("enrollment");
    assert_eq!(controller.state(), ControllerState::Active);
    assert_eq!(commit.calls, 1);
    let state = state.lock().expect("session state");
    assert_eq!((state.opened, state.completed, state.rejected), (1, 1, 0));
    assert_eq!(progress.details.len(), 2);
    assert!(progress.details[0].contains("Pair code"));
    assert!(progress.details[1].contains("verify"));
    assert!(!format!("{controller:?}").contains("public-controller-certificate"));
}

// Rejects timeout, proof failure, denial, cancellation, and commit failure before completion.
#[test]
fn controller_enrollment_failure_boundaries_never_complete_partial_state() {
    let cases = [
        (
            Err(CoreControllerEnrollmentError::TimedOut),
            true,
            true,
            false,
            "auth.controller.timed_out",
        ),
        (
            Ok(claim()),
            true,
            false,
            false,
            "auth.controller.proof_invalid",
        ),
        (Ok(claim()), false, true, false, "auth.controller.denied"),
        (
            Ok(claim()),
            true,
            true,
            true,
            "auth.controller.commit_failed",
        ),
    ];
    for (result, confirmed, proof, commit_failure, code) in cases {
        let (provider, state) = provider(result, confirmed, proof);
        let mut progress = Progress::default();
        let mut commit = Commit {
            calls: 0,
            fail: commit_failure,
        };
        let failure = provider
            .enroll(
                Duration::from_secs(30),
                ControllerRole::Administrator,
                &mut progress,
                &mut commit,
            )
            .expect_err("enrollment failure");
        assert_eq!(failure.code(), code);
        let state = state.lock().expect("session state");
        assert_eq!(state.completed, 0);
        assert_eq!(state.rejected, 1);
        assert_eq!(commit.calls, usize::from(commit_failure));
    }

    let (provider, state) = provider(Ok(claim()), true, true);
    let mut progress = Progress {
        details: Vec::new(),
        cancelled: true,
    };
    let mut commit = Commit {
        calls: 0,
        fail: false,
    };
    let failure = provider
        .enroll(
            Duration::from_secs(30),
            ControllerRole::Administrator,
            &mut progress,
            &mut commit,
        )
        .expect_err("cancelled enrollment");
    assert_eq!(failure.kind(), CommandFailureKind::Cancelled);
    assert_eq!(commit.calls, 0);
    assert_eq!(state.lock().expect("session state").rejected, 1);
}

// Verifies the exact P-256 SPKI and ASN.1 signature shapes emitted by the existing Mac client.
#[test]
fn ring_proof_provider_accepts_only_the_exact_controller_transcript() {
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
        .expect("P-256 key document");
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .expect("P-256 key");
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key.public_key().as_ref());
    let public_key = ControllerPublicKey::new(spki).expect("controller public key");
    let challenge = b"exact-controller-enrollment-transcript";
    let signature = key.sign(&random, challenge).expect("proof");
    let provider = RingCoreControllerEnrollmentProof;
    provider
        .verify(&public_key, challenge, signature.as_ref())
        .expect("valid proof");
    assert_eq!(
        provider.verify(&public_key, b"different-transcript", signature.as_ref()),
        Err(CoreControllerEnrollmentError::ProofInvalid)
    );
}
