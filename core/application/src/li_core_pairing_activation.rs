// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use li_core_interface::{Node, NodeAddress, NodeRole, NodeState, PairingInviteId, Sha256Digest};
use li_node_manager::{
    NodePairedChildActivationRequest, NodePairedMainRestorationRequest,
    NodePairingCancellationPort, NodePairingCandidateEnrollment, NodePairingClientPort,
    NodePairingCredentials, NodePairingMode, NodePairingState, NodePairingTransportRequest,
    NodePairingTransportResponse,
};
use li_pairing_manager::{
    pairing_enrollment_transcript, pairing_membership_transcript, PairingCandidate,
    PairingCandidateTrustProvider, PairingContext, PairingMembershipState, PairingMode,
};

const MAXIMUM_APPROVAL_POLLS: usize = 600;

// Carries only the public discovery and human setup material needed to join one main.
#[derive(Clone, Eq, PartialEq)]
pub struct CorePairingJoinRequest {
    invite_id: PairingInviteId,
    address: NodeAddress,
    port: u16,
    certificate_sha256: Sha256Digest,
    setup_code: Option<String>,
    timeout: Duration,
}

impl CorePairingJoinRequest {
    // Creates one bounded join request without accepting local identity or proof fields.
    pub fn new(
        invite_id: PairingInviteId,
        address: NodeAddress,
        port: u16,
        certificate_sha256: Sha256Digest,
        setup_code: Option<String>,
        timeout: Duration,
    ) -> Result<Self, CorePairingActivationError> {
        if port == 0
            || timeout.is_zero()
            || timeout > Duration::from_secs(600)
            || setup_code.as_deref().is_some_and(|value| {
                value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(CorePairingActivationError::InvalidRequest);
        }
        Ok(Self {
            invite_id,
            address,
            port,
            certificate_sha256,
            setup_code,
            timeout,
        })
    }

    // Returns the exact invitation discovered or supplied by remote main authorization.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the exact main pairing endpoint address.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the fixed dedicated pairing endpoint port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the discovery-pinned main pairing TLS leaf fingerprint.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the one-time setup code for LAN and remote modes.
    pub fn setup_code(&self) -> Option<&str> {
        self.setup_code.as_deref()
    }

    // Returns the complete pairing and approval deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Debug for CorePairingJoinRequest {
    // Presents public endpoint identity while redacting the one-time setup code.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorePairingJoinRequest")
            .field("invite_id", &self.invite_id)
            .field("address", &self.address)
            .field("port", &self.port)
            .field("certificate_sha256", &self.certificate_sha256)
            .field("setup_code", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

// Names every durable crash-replay point in one child activation transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorePairingActivationPhase {
    Requested,
    CredentialsVerified,
    ConfigurationPrepared,
    RoleCommitted,
    ConfigurationCommitted,
    ServicesActivated,
    Completed,
    Compensating,
    RolledBack,
    RecoveryRequired,
}

// Retains only public identities and opaque receipts required for crash replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorePairingActivationRecord {
    request_identity: Sha256Digest,
    invite_id: PairingInviteId,
    main_node_id: Option<li_core_interface::NodeId>,
    configuration_receipt: Option<Sha256Digest>,
    phase: CorePairingActivationPhase,
}

impl CorePairingActivationRecord {
    // Creates one requested activation record before any external mutation.
    pub const fn requested(request_identity: Sha256Digest, invite_id: PairingInviteId) -> Self {
        Self {
            request_identity,
            invite_id,
            main_node_id: None,
            configuration_receipt: None,
            phase: CorePairingActivationPhase::Requested,
        }
    }

    // Returns the exact request identity used for replay conflict detection.
    pub const fn request_identity(&self) -> &Sha256Digest {
        &self.request_identity
    }

    // Returns the exact invitation bound into this activation transaction.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the durable activation phase.
    pub const fn phase(&self) -> CorePairingActivationPhase {
        self.phase
    }

    // Returns the destination main identity after trust verification.
    pub const fn main_node_id(&self) -> Option<&li_core_interface::NodeId> {
        self.main_node_id.as_ref()
    }

    // Returns the opaque configuration snapshot receipt after preparation.
    pub const fn configuration_receipt(&self) -> Option<&Sha256Digest> {
        self.configuration_receipt.as_ref()
    }

    // Reconstructs one persisted record after the store validates every closed field.
    pub(crate) const fn decoded(
        request_identity: Sha256Digest,
        invite_id: PairingInviteId,
        main_node_id: Option<li_core_interface::NodeId>,
        configuration_receipt: Option<Sha256Digest>,
        phase: CorePairingActivationPhase,
    ) -> Self {
        Self {
            request_identity,
            invite_id,
            main_node_id,
            configuration_receipt,
            phase,
        }
    }

    // Returns one exact legal successor without mutating the observed record.
    fn transitioned(
        &self,
        phase: CorePairingActivationPhase,
        main_node_id: Option<li_core_interface::NodeId>,
        configuration_receipt: Option<Sha256Digest>,
    ) -> Result<Self, CorePairingActivationError> {
        if !legal_transition(self.phase, phase) {
            return Err(CorePairingActivationError::StateConflict);
        }
        let mut next = self.clone();
        next.phase = phase;
        if let Some(main_node_id) = main_node_id {
            if next
                .main_node_id
                .as_ref()
                .is_some_and(|current| current != &main_node_id)
            {
                return Err(CorePairingActivationError::StateConflict);
            }
            next.main_node_id = Some(main_node_id);
        }
        if let Some(receipt) = configuration_receipt {
            if next
                .configuration_receipt
                .as_ref()
                .is_some_and(|current| current != &receipt)
            {
                return Err(CorePairingActivationError::StateConflict);
            }
            next.configuration_receipt = Some(receipt);
        }
        Ok(next)
    }
}

// Persists one optimistic activation journal independent of configuration snapshots.
pub trait CorePairingActivationStore: Send + Sync {
    // Reads the current activation record or absence before first mutation.
    fn load(&self) -> Result<Option<CorePairingActivationRecord>, CorePairingActivationError>;

    // Creates one exact initial record only when no activation is present.
    fn create(
        &self,
        record: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError>;

    // Replaces one exact observed phase with its legal successor.
    fn replace(
        &self,
        expected: CorePairingActivationPhase,
        replacement: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError>;
}

// Snapshots, stages, activates, verifies, and restores child-specific configuration files.
pub trait CorePairingActivationConfigurationPort: Send + Sync {
    // Durably snapshots current files and stages exact child credentials without activation.
    fn prepare(
        &self,
        request_identity: &Sha256Digest,
        main: &Node,
        main_private_port: u16,
        main_certificate_sha256: &Sha256Digest,
        credentials: &NodePairingCredentials,
    ) -> Result<Sha256Digest, CorePairingActivationError>;

    // Recovers exact verified public pairing material from one durable prepared owner.
    fn prepared(
        &self,
        receipt: &Sha256Digest,
    ) -> Result<CorePairingPreparedActivation, CorePairingActivationError>;

    // Atomically activates every staged child configuration under its exact receipt.
    fn commit(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError>;

    // Verifies exact owner-only child configuration and credential continuity.
    fn verify(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError>;

    // Restores the exact snapshotted main configuration idempotently.
    fn restore(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError>;

    // Removes the durable rollback owner only after the rollback journal is terminal.
    fn finish_rollback(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError>;
}

// Carries exact non-secret pairing material recovered from durable staged configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorePairingPreparedActivation {
    main: Node,
    main_private_port: u16,
    main_certificate_sha256: Sha256Digest,
    credentials: NodePairingCredentials,
}

impl CorePairingPreparedActivation {
    // Creates one prepared activation only for one active remote main authority.
    pub fn new(
        main: Node,
        main_private_port: u16,
        main_certificate_sha256: Sha256Digest,
        credentials: NodePairingCredentials,
    ) -> Result<Self, CorePairingActivationError> {
        if main.role() != NodeRole::Main
            || main.state() != NodeState::Active
            || main_private_port == 0
        {
            return Err(CorePairingActivationError::UntrustedMain);
        }
        Ok(Self {
            main,
            main_private_port,
            main_certificate_sha256,
            credentials,
        })
    }

    // Returns the exact destination main identity.
    pub const fn main(&self) -> &Node {
        &self.main
    }

    // Returns the exact authenticated private Node listener port.
    pub const fn main_private_port(&self) -> u16 {
        self.main_private_port
    }

    // Returns the exact main leaf identity accepted for private main-to-child traffic.
    pub const fn main_certificate_sha256(&self) -> &Sha256Digest {
        &self.main_certificate_sha256
    }

    // Returns the exact public trust package staged for child services.
    pub const fn credentials(&self) -> &NodePairingCredentials {
        &self.credentials
    }
}

// Applies and restores the existing platform service set around one local role cutover.
pub trait CorePairingActivationServicePort: Send + Sync {
    // Atomically rebinds the existing installation to the child service contract.
    fn activate_child(&self) -> Result<(), CorePairingActivationError>;

    // Verifies the exact child Node and private-only Gateway resident contract.
    fn verify_child(&self) -> Result<(), CorePairingActivationError>;

    // Restores the exact snapshotted main service contract idempotently.
    fn restore_main(&self) -> Result<(), CorePairingActivationError>;
}

// Isolates bounded remote-approval polling for deterministic tests.
pub trait CorePairingActivationWaiter: Send + Sync {
    // Waits one positive interval without extending the complete workflow deadline.
    fn wait(&self, interval: Duration) -> Result<(), CorePairingActivationError>;
}

// Owns the sole child-local human decision for one remote comparison code.
pub trait CorePairingActivationConfirmationPort: Send + Sync {
    // Presents the six-digit code once and returns only an explicit human approval.
    fn confirm(&self, comparison_code: &str) -> Result<bool, CorePairingActivationError>;
}

// Defines the owner-local Node authority required by the pairing compensation saga.
pub trait CorePairingActivationAuthorityPort: Send + Sync {
    // Reads the exact current local Node through the owner-authenticated Node endpoint.
    fn local_node(&self) -> Result<Node, CorePairingActivationError>;

    // Reads the bounded complete Node inventory through the same local endpoint.
    fn nodes(&self) -> Result<Vec<Node>, CorePairingActivationError>;

    // Atomically commits the verified main credential and local child authority.
    fn activate_paired_child(
        &self,
        request: NodePairedChildActivationRequest,
    ) -> Result<(), CorePairingActivationError>;

    // Atomically deletes activation-owned trust and restores local main authority.
    fn restore_paired_main(
        &self,
        request: NodePairedMainRestorationRequest,
    ) -> Result<(), CorePairingActivationError>;
}

// Uses the system sleep primitive only for the coordinator-selected bounded interval.
pub struct SystemCorePairingActivationWaiter;

impl CorePairingActivationWaiter for SystemCorePairingActivationWaiter {
    // Sleeps for one positive interval of at most one second.
    fn wait(&self, interval: Duration) -> Result<(), CorePairingActivationError> {
        if interval.is_zero() || interval > Duration::from_secs(1) {
            return Err(CorePairingActivationError::InvalidRequest);
        }
        std::thread::sleep(interval);
        Ok(())
    }
}

// Returns one successful activation identity without exposing credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorePairingActivationResult {
    main: Node,
    local: Node,
    replayed: bool,
}

impl CorePairingActivationResult {
    // Returns the exact enrolled main Node.
    pub const fn main(&self) -> &Node {
        &self.main
    }

    // Returns the exact local child Node after activation.
    pub const fn local(&self) -> &Node {
        &self.local
    }

    // Returns whether this call observed an already completed activation.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

// Names stable activation failures without retaining setup codes, proofs, certificates, or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorePairingActivationError {
    InvalidRequest,
    UntrustedMain,
    StateConflict,
    TransportUnavailable,
    ApprovalTimedOut,
    ConfirmationUnavailable,
    ConfirmationDenied,
    Cancelled,
    ConfigurationUnavailable,
    RoleUnavailable,
    ServiceUnavailable,
    RolledBack,
    RecoveryRequired,
}

impl fmt::Display for CorePairingActivationError {
    // Presents stable recovery-aware language without sensitive or machine-specific values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("child pairing request is invalid"),
            Self::UntrustedMain => formatter.write_str("child pairing main identity is untrusted"),
            Self::StateConflict => formatter.write_str("child pairing state changed concurrently"),
            Self::TransportUnavailable => {
                formatter.write_str("child pairing transport is unavailable")
            }
            Self::ApprovalTimedOut => formatter.write_str("child pairing approval timed out"),
            Self::ConfirmationUnavailable => {
                formatter.write_str("child pairing confirmation is unavailable")
            }
            Self::ConfirmationDenied => {
                formatter.write_str("child pairing comparison code was not approved")
            }
            Self::Cancelled => formatter.write_str("child pairing was cancelled"),
            Self::ConfigurationUnavailable => {
                formatter.write_str("child pairing configuration failed")
            }
            Self::RoleUnavailable => formatter.write_str("child pairing role transition failed"),
            Self::ServiceUnavailable => {
                formatter.write_str("child pairing service activation failed")
            }
            Self::RolledBack => formatter.write_str("child pairing activation rolled back"),
            Self::RecoveryRequired => {
                formatter.write_str("child pairing activation requires recovery")
            }
        }
    }
}

impl Error for CorePairingActivationError {}

// Coordinates secure enrollment, credential verification, role commit, configuration, and services.
pub struct CorePairingActivationCoordinator {
    authority: Arc<dyn CorePairingActivationAuthorityPort>,
    client: Arc<dyn NodePairingClientPort>,
    trust: Arc<dyn PairingCandidateTrustProvider>,
    cancellation: Arc<dyn NodePairingCancellationPort>,
    configurations: Arc<dyn CorePairingActivationConfigurationPort>,
    services: Arc<dyn CorePairingActivationServicePort>,
    store: Arc<dyn CorePairingActivationStore>,
    waiter: Arc<dyn CorePairingActivationWaiter>,
    operation_lock: Mutex<()>,
}

impl CorePairingActivationCoordinator {
    // Creates one coordinator from exact existing authorities without introducing another manager.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: Arc<dyn CorePairingActivationAuthorityPort>,
        client: Arc<dyn NodePairingClientPort>,
        trust: Arc<dyn PairingCandidateTrustProvider>,
        cancellation: Arc<dyn NodePairingCancellationPort>,
        configurations: Arc<dyn CorePairingActivationConfigurationPort>,
        services: Arc<dyn CorePairingActivationServicePort>,
        store: Arc<dyn CorePairingActivationStore>,
        waiter: Arc<dyn CorePairingActivationWaiter>,
    ) -> Self {
        Self {
            authority,
            client,
            trust,
            cancellation,
            configurations,
            services,
            store,
            waiter,
            operation_lock: Mutex::new(()),
        }
    }

    // Executes or exactly replays one complete child activation transaction.
    pub fn activate(
        &self,
        request: &CorePairingJoinRequest,
        confirmation: &dyn CorePairingActivationConfirmationPort,
    ) -> Result<CorePairingActivationResult, CorePairingActivationError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| CorePairingActivationError::StateConflict)?;
        let deadline = Instant::now()
            .checked_add(request.timeout())
            .ok_or(CorePairingActivationError::InvalidRequest)?;
        let request_identity = join_request_identity(request)?;
        let mut record = match self.store.load()? {
            Some(record) if record.request_identity() == &request_identity => record,
            Some(_) => return Err(CorePairingActivationError::StateConflict),
            None => {
                let record = CorePairingActivationRecord::requested(
                    request_identity.clone(),
                    request.invite_id().clone(),
                );
                self.store.create(&record)?;
                record
            }
        };
        if record.phase() == CorePairingActivationPhase::Completed {
            let local = self.authority.local_node()?;
            let main = active_main(self.authority.nodes()?)?;
            if local.role() != NodeRole::Child
                || main.identity().node_id() == local.identity().node_id()
            {
                return Err(CorePairingActivationError::RecoveryRequired);
            }
            return Ok(CorePairingActivationResult {
                main,
                local,
                replayed: true,
            });
        }
        if record.phase() == CorePairingActivationPhase::RecoveryRequired {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        if record.phase() == CorePairingActivationPhase::RolledBack {
            let receipt = record
                .configuration_receipt()
                .ok_or(CorePairingActivationError::RecoveryRequired)?;
            self.configurations.finish_rollback(receipt)?;
            return Err(CorePairingActivationError::RolledBack);
        }
        if record.phase() == CorePairingActivationPhase::Requested {
            let verified =
                self.enroll_and_verify(request, &request_identity, confirmation, deadline)?;
            let receipt = self.configurations.prepare(
                &request_identity,
                &verified.main,
                verified.main_private_port,
                &verified.main_certificate_sha256,
                &verified.credentials,
            )?;
            record = self.advance(
                &record,
                CorePairingActivationPhase::CredentialsVerified,
                Some(verified.main.identity().node_id().clone()),
                Some(receipt),
            )?;
        }
        let receipt = record
            .configuration_receipt()
            .cloned()
            .ok_or(CorePairingActivationError::RecoveryRequired)?;
        let prepared = self.configurations.prepared(&receipt)?;
        if record.main_node_id() != Some(prepared.main().identity().node_id()) {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        if record.phase() == CorePairingActivationPhase::Compensating {
            return self.compensate(&record, &receipt, &prepared);
        }
        if record.phase() == CorePairingActivationPhase::CredentialsVerified {
            record = self.advance(
                &record,
                CorePairingActivationPhase::ConfigurationPrepared,
                None,
                None,
            )?;
        }
        if record.phase() == CorePairingActivationPhase::ConfigurationPrepared {
            self.commit_child_authority(&request_identity, &prepared)?;
            record = self.advance(
                &record,
                CorePairingActivationPhase::RoleCommitted,
                None,
                None,
            )?;
        }
        let transaction = (|| {
            if record.phase() == CorePairingActivationPhase::RoleCommitted {
                self.configurations.commit(&receipt)?;
                record = self.advance(
                    &record,
                    CorePairingActivationPhase::ConfigurationCommitted,
                    None,
                    None,
                )?;
            }
            if record.phase() == CorePairingActivationPhase::ConfigurationCommitted {
                self.services.activate_child()?;
                record = self.advance(
                    &record,
                    CorePairingActivationPhase::ServicesActivated,
                    None,
                    None,
                )?;
            }
            self.configurations.verify(&receipt)?;
            self.services.verify_child()?;
            if record.phase() == CorePairingActivationPhase::ServicesActivated {
                record =
                    self.advance(&record, CorePairingActivationPhase::Completed, None, None)?;
            }
            Ok::<(), CorePairingActivationError>(())
        })();
        if transaction.is_err() {
            return self.compensate(&record, &receipt, &prepared);
        }
        let local = self.authority.local_node()?;
        Ok(CorePairingActivationResult {
            main: prepared.main().clone(),
            local,
            replayed: false,
        })
    }

    // Atomically commits the exact main credential, main Node, and local child authority.
    fn commit_child_authority(
        &self,
        request_identity: &Sha256Digest,
        prepared: &CorePairingPreparedActivation,
    ) -> Result<(), CorePairingActivationError> {
        let idempotency_key = format!("{}:child-authority", request_identity.as_str());
        let request = NodePairedChildActivationRequest::new(
            idempotency_key,
            prepared.main().clone(),
            prepared.main_certificate_sha256().clone(),
            prepared.credentials().clone(),
        )
        .map_err(|_| CorePairingActivationError::RoleUnavailable)?;
        self.authority.activate_paired_child(request)
    }

    // Enrolls through pinned TLS and verifies every returned identity before mutation.
    fn enroll_and_verify(
        &self,
        request: &CorePairingJoinRequest,
        request_identity: &Sha256Digest,
        confirmation: &dyn CorePairingActivationConfirmationPort,
        deadline: Instant,
    ) -> Result<VerifiedPairing, CorePairingActivationError> {
        let local = self.authority.local_node()?;
        if local.role() != NodeRole::Main || local.state() != NodeState::Active {
            return Err(CorePairingActivationError::InvalidRequest);
        }
        let response = self.exchange(
            request,
            &NodePairingTransportRequest::Challenge {
                invite_id: request.invite_id().clone(),
            },
            deadline,
        )?;
        let NodePairingTransportResponse::Challenge { challenge, main } = response else {
            return Err(CorePairingActivationError::UntrustedMain);
        };
        if challenge.invite_id() != request.invite_id()
            || challenge.main_certificate_sha256() != request.certificate_sha256()
            || challenge.main_node_id() != main.identity().node_id()
            || challenge.main_address() != main.control_address()
            || main.role() != NodeRole::Main
            || main.state() != NodeState::Active
            || main.identity().node_id() == local.identity().node_id()
        {
            return Err(CorePairingActivationError::UntrustedMain);
        }
        let (public_key, public_key_sha256) = self
            .trust
            .public_key()
            .map_err(|_| CorePairingActivationError::UntrustedMain)?;
        let mode = pairing_mode(challenge.mode());
        let transcript = pairing_enrollment_transcript(
            challenge.main_node_id(),
            challenge.main_private_port(),
            challenge.invite_id(),
            challenge.nonce(),
            challenge.created_at(),
            &mode,
            challenge.expires_at(),
            local.identity(),
            local.display_name(),
            local.control_address(),
            local.timestamps().created_at(),
        );
        let proof_signature = self
            .trust
            .sign(&transcript)
            .map_err(|_| CorePairingActivationError::UntrustedMain)?;
        let candidate = NodePairingCandidateEnrollment::new(
            format!("{}:enroll", request_identity.as_str()),
            request.invite_id().clone(),
            local.clone(),
            public_key.clone(),
            proof_signature.clone(),
            request.setup_code().map(str::to_string),
        )
        .map_err(|_| CorePairingActivationError::InvalidRequest)?;
        let response = self.exchange(
            request,
            &NodePairingTransportRequest::Enroll(candidate),
            deadline,
        )?;
        let NodePairingTransportResponse::Enrollment(enrollment) = response else {
            return Err(CorePairingActivationError::UntrustedMain);
        };
        if enrollment.status().invite_id() != request.invite_id()
            || enrollment.status().child_node_id() != Some(local.identity().node_id())
            || enrollment.status().mode() != challenge.mode()
            || enrollment.status().expires_at() != challenge.expires_at()
        {
            return Err(CorePairingActivationError::UntrustedMain);
        }
        let initial_state = enrollment.status().state();
        if matches!(challenge.mode(), NodePairingMode::Remote) {
            if initial_state != NodePairingState::PendingApproval {
                return Err(CorePairingActivationError::UntrustedMain);
            }
            let comparison_code = enrollment
                .status()
                .comparison_code()
                .ok_or(CorePairingActivationError::UntrustedMain)?;
            if !confirmation.confirm(comparison_code)? {
                return Err(CorePairingActivationError::ConfirmationDenied);
            }
            self.await_remote_approval(
                request,
                local.identity().node_id(),
                comparison_code,
                deadline,
            )?;
        } else if initial_state != NodePairingState::Active {
            return Err(CorePairingActivationError::UntrustedMain);
        }
        self.trust
            .verify_membership_certificate(
                &public_key,
                enrollment.credentials().main_ca_certificate(),
                enrollment.credentials().child_certificate(),
                enrollment.credentials().child_leaf_sha256(),
            )
            .map_err(|_| CorePairingActivationError::UntrustedMain)?;
        let context = PairingContext::new(
            main.identity().clone(),
            main.role(),
            main.display_name().clone(),
            main.control_address().clone(),
            challenge.main_private_port(),
            challenge.main_public_key_sha256().clone(),
            challenge.main_certificate_sha256().clone(),
        );
        let candidate = PairingCandidate::new(
            local.identity().clone(),
            local.display_name().clone(),
            local.control_address().clone(),
            public_key,
            local.timestamps().created_at(),
            proof_signature,
            request.setup_code().map(str::to_string),
            local.control_address().clone(),
        )
        .map_err(|_| CorePairingActivationError::UntrustedMain)?;
        let membership_state = match initial_state {
            NodePairingState::Active => PairingMembershipState::Active,
            NodePairingState::PendingApproval => PairingMembershipState::PendingApproval,
            NodePairingState::Open => return Err(CorePairingActivationError::UntrustedMain),
        };
        let membership = pairing_membership_transcript(
            &context,
            &candidate,
            &public_key_sha256,
            enrollment.credentials().child_leaf_sha256(),
            membership_state,
            (membership_state == PairingMembershipState::PendingApproval)
                .then_some(enrollment.status().expires_at()),
        );
        let main_fingerprint = self
            .trust
            .verify(
                enrollment.credentials().main_public_key(),
                &membership,
                enrollment.credentials().membership_signature(),
            )
            .map_err(|_| CorePairingActivationError::UntrustedMain)?;
        if &main_fingerprint != challenge.main_public_key_sha256() {
            return Err(CorePairingActivationError::UntrustedMain);
        }
        Ok(VerifiedPairing {
            main,
            main_private_port: challenge.main_private_port(),
            main_certificate_sha256: challenge.main_certificate_sha256().clone(),
            credentials: enrollment.credentials().clone(),
        })
    }

    // Polls only the exact invitation until explicit main approval, timeout, or cancellation.
    fn await_remote_approval(
        &self,
        request: &CorePairingJoinRequest,
        local_node_id: &li_core_interface::NodeId,
        comparison_code: &str,
        deadline: Instant,
    ) -> Result<(), CorePairingActivationError> {
        for _ in 0..MAXIMUM_APPROVAL_POLLS {
            if self.cancellation.is_cancelled() {
                return Err(CorePairingActivationError::Cancelled);
            }
            let response = self.exchange(
                request,
                &NodePairingTransportRequest::Status {
                    invite_id: request.invite_id().clone(),
                },
                deadline,
            )?;
            let NodePairingTransportResponse::Status(status) = response else {
                return Err(CorePairingActivationError::UntrustedMain);
            };
            if status.invite_id() != request.invite_id()
                || status.mode() != &NodePairingMode::Remote
                || status.child_node_id() != Some(local_node_id)
            {
                return Err(CorePairingActivationError::UntrustedMain);
            }
            match status.state() {
                NodePairingState::Active => return Ok(()),
                NodePairingState::PendingApproval => {
                    if status.comparison_code() != Some(comparison_code) {
                        return Err(CorePairingActivationError::UntrustedMain);
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(CorePairingActivationError::ApprovalTimedOut);
                    }
                    self.waiter.wait(remaining.min(Duration::from_secs(1)))?;
                }
                NodePairingState::Open => return Err(CorePairingActivationError::UntrustedMain),
            }
        }
        Err(CorePairingActivationError::ApprovalTimedOut)
    }

    // Executes one pinned exchange and maps only stable timeout, cancellation, and availability.
    fn exchange(
        &self,
        request: &CorePairingJoinRequest,
        message: &NodePairingTransportRequest,
        deadline: Instant,
    ) -> Result<NodePairingTransportResponse, CorePairingActivationError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CorePairingActivationError::ApprovalTimedOut);
        }
        self.client
            .exchange(
                request.address(),
                request.port(),
                request.certificate_sha256(),
                message,
                remaining,
                self.cancellation.as_ref(),
            )
            .map_err(|error| match error {
                li_node_manager::NodePairingTransportError::TimedOut => {
                    CorePairingActivationError::ApprovalTimedOut
                }
                li_node_manager::NodePairingTransportError::Cancelled => {
                    CorePairingActivationError::Cancelled
                }
                li_node_manager::NodePairingTransportError::UntrustedPeer => {
                    CorePairingActivationError::UntrustedMain
                }
                _ => CorePairingActivationError::TransportUnavailable,
            })
    }

    // Persists one legal optimistic phase transition.
    fn advance(
        &self,
        current: &CorePairingActivationRecord,
        phase: CorePairingActivationPhase,
        main_node_id: Option<li_core_interface::NodeId>,
        configuration_receipt: Option<Sha256Digest>,
    ) -> Result<CorePairingActivationRecord, CorePairingActivationError> {
        let replacement = current.transitioned(phase, main_node_id, configuration_receipt)?;
        self.store.replace(current.phase(), &replacement)?;
        Ok(replacement)
    }

    // Restores services, configuration, and Node authority after any post-role failure.
    fn compensate(
        &self,
        record: &CorePairingActivationRecord,
        receipt: &Sha256Digest,
        prepared: &CorePairingPreparedActivation,
    ) -> Result<CorePairingActivationResult, CorePairingActivationError> {
        let compensating = if record.phase() == CorePairingActivationPhase::Compensating {
            record.clone()
        } else {
            self.advance(record, CorePairingActivationPhase::Compensating, None, None)?
        };
        let service = self.services.restore_main();
        let authority = self.restore_child_authority(record.request_identity(), prepared);
        let configuration = self.configurations.restore(receipt);
        if service.is_err() || authority.is_err() || configuration.is_err() {
            let _ = self.advance(
                &compensating,
                CorePairingActivationPhase::RecoveryRequired,
                None,
                None,
            );
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        let rolled_back = self.advance(
            &compensating,
            CorePairingActivationPhase::RolledBack,
            None,
            None,
        )?;
        self.configurations.finish_rollback(
            rolled_back
                .configuration_receipt()
                .ok_or(CorePairingActivationError::RecoveryRequired)?,
        )?;
        Err(CorePairingActivationError::RolledBack)
    }

    // Atomically deletes activation-owned trust and main authority while restoring local main.
    fn restore_child_authority(
        &self,
        request_identity: &Sha256Digest,
        prepared: &CorePairingPreparedActivation,
    ) -> Result<(), CorePairingActivationError> {
        let idempotency_key = format!("{}:restore-main", request_identity.as_str());
        let request = NodePairedMainRestorationRequest::new(
            idempotency_key,
            prepared.main().clone(),
            prepared.main_certificate_sha256().clone(),
            prepared.credentials().clone(),
        )
        .map_err(|_| CorePairingActivationError::RoleUnavailable)?;
        self.authority.restore_paired_main(request)
    }
}

// Retains one verified public enrollment package only until configuration staging completes.
struct VerifiedPairing {
    main: Node,
    main_private_port: u16,
    main_certificate_sha256: Sha256Digest,
    credentials: NodePairingCredentials,
}

// Selects the sole active main from one bounded Node-owned snapshot without a fallback.
fn active_main(nodes: Vec<Node>) -> Result<Node, CorePairingActivationError> {
    let mut matching = nodes
        .into_iter()
        .filter(|node| node.role() == NodeRole::Main && node.state() == NodeState::Active);
    let main = matching
        .next()
        .ok_or(CorePairingActivationError::RecoveryRequired)?;
    if matching.next().is_some() {
        return Err(CorePairingActivationError::RecoveryRequired);
    }
    Ok(main)
}

// Converts one Node API mode into the shared canonical transcript mode.
fn pairing_mode(mode: &NodePairingMode) -> PairingMode {
    match mode {
        NodePairingMode::Lan => PairingMode::Lan,
        NodePairingMode::Remote => PairingMode::Remote,
        NodePairingMode::ConnectX {
            candidate_public_key_sha256,
            direct_interface,
        } => PairingMode::ConnectX {
            candidate_public_key: candidate_public_key_sha256.clone(),
            direct_interface: direct_interface.clone(),
        },
    }
}

// Returns one canonical request identity without including the setup code.
fn join_request_identity(
    request: &CorePairingJoinRequest,
) -> Result<Sha256Digest, CorePairingActivationError> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for field in [
        b"letsinfer-child-activation-v1\0".as_slice(),
        request.invite_id().as_str().as_bytes(),
        request.address().as_str().as_bytes(),
        request.port().to_string().as_bytes(),
        request.certificate_sha256().as_str().as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    let value = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&value).map_err(|_| CorePairingActivationError::InvalidRequest)
}

// Returns whether one journal transition preserves the exact activation state machine.
const fn legal_transition(
    current: CorePairingActivationPhase,
    next: CorePairingActivationPhase,
) -> bool {
    matches!(
        (current, next),
        (
            CorePairingActivationPhase::Requested,
            CorePairingActivationPhase::CredentialsVerified
        ) | (
            CorePairingActivationPhase::CredentialsVerified,
            CorePairingActivationPhase::ConfigurationPrepared
        ) | (
            CorePairingActivationPhase::ConfigurationPrepared,
            CorePairingActivationPhase::RoleCommitted
        ) | (
            CorePairingActivationPhase::RoleCommitted,
            CorePairingActivationPhase::ConfigurationCommitted
        ) | (
            CorePairingActivationPhase::ConfigurationCommitted,
            CorePairingActivationPhase::ServicesActivated
        ) | (
            CorePairingActivationPhase::ServicesActivated,
            CorePairingActivationPhase::Completed
        ) | (
            CorePairingActivationPhase::RoleCommitted,
            CorePairingActivationPhase::Compensating
        ) | (
            CorePairingActivationPhase::ConfigurationCommitted,
            CorePairingActivationPhase::Compensating
        ) | (
            CorePairingActivationPhase::ServicesActivated,
            CorePairingActivationPhase::Compensating
        ) | (
            CorePairingActivationPhase::Compensating,
            CorePairingActivationPhase::RolledBack
        ) | (
            CorePairingActivationPhase::Compensating,
            CorePairingActivationPhase::RecoveryRequired
        )
    )
}
