// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    NodePairingApiError, NodePairingApiPort, NodePairingChallenge, NodePairingCredentials,
    NodePairingEnrollRequest, NodePairingEnrollment, NodePairingMode, NodePairingState,
    NodePairingStatus,
};

pub const NODE_PAIRING_TRANSPORT_SCHEMA_NAME: &str = "li_node_pairing_transport";
pub const NODE_PAIRING_TRANSPORT_SCHEMA_VERSION: u32 = 2;
pub const NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES: usize = 256 * 1024;

const MAXIMUM_SIGNATURE_BYTES: usize = 2 * 1024;
const MAXIMUM_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const MINIMUM_PUBLIC_KEY_BYTES: usize = 128;

// Carries one signed candidate offer returned before ConnectX invitation creation.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairingCandidateOffer {
    candidate: Node,
    public_key: Vec<u8>,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
    request_nonce: Sha256Digest,
    issued_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    signature: Vec<u8>,
}

impl NodePairingCandidateOffer {
    // Creates one bounded candidate offer bound to the caller's exact nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate: Node,
        public_key: Vec<u8>,
        public_key_sha256: Sha256Digest,
        certificate_sha256: Sha256Digest,
        request_nonce: Sha256Digest,
        issued_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        signature: Vec<u8>,
    ) -> Result<Self, NodePairingTransportError> {
        if candidate.role() != NodeRole::Main
            || candidate.state() != NodeState::Active
            || !(MINIMUM_PUBLIC_KEY_BYTES..=MAXIMUM_PUBLIC_KEY_BYTES).contains(&public_key.len())
            || signature.is_empty()
            || signature.len() > MAXIMUM_SIGNATURE_BYTES
            || issued_at.value() == 0
            || expires_at <= issued_at
        {
            return Err(invalid("candidate offer is invalid"));
        }
        Ok(Self {
            candidate,
            public_key,
            public_key_sha256,
            certificate_sha256,
            request_nonce,
            issued_at,
            expires_at,
            signature,
        })
    }

    // Returns the exact local node volunteering for child enrollment.
    pub const fn candidate(&self) -> &Node {
        &self.candidate
    }

    // Returns the candidate public key used to verify its signed offer and enrollment proof.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    // Returns the canonical candidate public-key fingerprint.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the candidate TLS leaf fingerprint advertised before connection.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the exact main-supplied nonce bound into the offer signature.
    pub const fn request_nonce(&self) -> &Sha256Digest {
        &self.request_nonce
    }

    // Returns the inclusive offer creation time.
    pub const fn issued_at(&self) -> UnixMilliseconds {
        self.issued_at
    }

    // Returns the exclusive offer expiration time.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the candidate possession signature over the canonical offer transcript.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl fmt::Debug for NodePairingCandidateOffer {
    // Presents offer identity while redacting key and signature bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairingCandidateOffer")
            .field("candidate", &self.candidate)
            .field("public_key", &"<redacted>")
            .field("public_key_sha256", &self.public_key_sha256)
            .field("certificate_sha256", &self.certificate_sha256)
            .field("request_nonce", &self.request_nonce)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("signature", &"<redacted>")
            .finish()
    }
}

// Isolates local identity signing from the public candidate-facing endpoint.
pub trait NodePairingCandidateOfferPort: Send + Sync {
    // Returns one short-lived signed offer bound to the caller's exact nonce.
    fn candidate_offer(
        &self,
        request_nonce: &Sha256Digest,
    ) -> Result<NodePairingCandidateOffer, NodePairingTransportError>;
}

// Supplies the local Node snapshot without granting transport direct database access.
pub trait NodePairingLocalNodePort: Send + Sync {
    // Returns the exact current local Node snapshot.
    fn local_node(&self) -> Result<Node, NodePairingTransportError>;
}

// Carries candidate-controlled enrollment fields while transport owns observed peer identity.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairingCandidateEnrollment {
    idempotency_key: String,
    invite_id: PairingInviteId,
    candidate: Node,
    public_key: Vec<u8>,
    proof_signature: Vec<u8>,
    setup_code: Option<String>,
}

impl NodePairingCandidateEnrollment {
    // Creates one bounded candidate enrollment without accepting an observed peer address.
    pub fn new(
        idempotency_key: String,
        invite_id: PairingInviteId,
        candidate: Node,
        public_key: Vec<u8>,
        proof_signature: Vec<u8>,
        setup_code: Option<String>,
    ) -> Result<Self, NodePairingTransportError> {
        let candidate_created_at = candidate.timestamps().created_at();
        NodePairingEnrollRequest::new(
            idempotency_key.clone(),
            invite_id.clone(),
            candidate.identity().clone(),
            candidate.display_name().clone(),
            candidate.control_address().clone(),
            public_key.clone(),
            candidate_created_at,
            proof_signature.clone(),
            setup_code.clone(),
            candidate.control_address().clone(),
        )
        .map_err(pairing_error)?;
        if candidate.role() != NodeRole::Main || candidate.state() != NodeState::Active {
            return Err(invalid("candidate enrollment is invalid"));
        }
        Ok(Self {
            idempotency_key,
            invite_id,
            candidate,
            public_key,
            proof_signature,
            setup_code,
        })
    }

    // Returns the exact replay identity for the remote enrollment commit.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the exact invitation consumed by this candidate.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the exact local candidate Node snapshot bound into proof.
    pub const fn candidate(&self) -> &Node {
        &self.candidate
    }

    // Returns the candidate public key bound into proof.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    // Returns the candidate possession signature over the canonical enrollment transcript.
    pub fn proof_signature(&self) -> &[u8] {
        &self.proof_signature
    }

    // Returns the optional setup code required by LAN and remote invitations.
    pub fn setup_code(&self) -> Option<&str> {
        self.setup_code.as_deref()
    }

    // Creates the main-side request with only the trusted socket-observed peer address added.
    fn into_request(
        self,
        observed_peer_address: NodeAddress,
    ) -> Result<NodePairingEnrollRequest, NodePairingTransportError> {
        NodePairingEnrollRequest::new(
            self.idempotency_key,
            self.invite_id,
            self.candidate.identity().clone(),
            self.candidate.display_name().clone(),
            self.candidate.control_address().clone(),
            self.public_key,
            self.candidate.timestamps().created_at(),
            self.proof_signature,
            self.setup_code,
            observed_peer_address,
        )
        .map_err(pairing_error)
    }
}

impl fmt::Debug for NodePairingCandidateEnrollment {
    // Presents candidate identity while redacting proof, key, and setup material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairingCandidateEnrollment")
            .field("idempotency_key", &self.idempotency_key)
            .field("invite_id", &self.invite_id)
            .field("candidate", &self.candidate)
            .field("public_key", &"<redacted>")
            .field("proof_signature", &"<redacted>")
            .field("setup_code", &"<redacted>")
            .finish()
    }
}

impl NodePairingLocalNodePort for crate::NodeManager {
    // Delegates one local snapshot to NodeManager without exposing its database.
    fn local_node(&self) -> Result<Node, NodePairingTransportError> {
        crate::NodeManager::local_node(self).map_err(|_| NodePairingTransportError::Unavailable)
    }
}

// Returns canonical candidate-offer bytes shared by the signer and preflight verifier.
pub fn node_pairing_candidate_offer_transcript(
    candidate: &Node,
    public_key_sha256: &Sha256Digest,
    certificate_sha256: &Sha256Digest,
    request_nonce: &Sha256Digest,
    issued_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"letsinfer-candidate-offer-v1\0";
    let mut transcript = Vec::new();
    append_transcript_field(&mut transcript, DOMAIN);
    append_transcript_field(
        &mut transcript,
        candidate.identity().node_id().as_str().as_bytes(),
    );
    append_transcript_field(
        &mut transcript,
        candidate.identity().machine_id().as_str().as_bytes(),
    );
    append_transcript_field(
        &mut transcript,
        candidate.identity().installation_id().as_str().as_bytes(),
    );
    append_transcript_field(
        &mut transcript,
        candidate.display_name().as_str().as_bytes(),
    );
    append_transcript_field(
        &mut transcript,
        candidate.control_address().as_str().as_bytes(),
    );
    append_transcript_field(&mut transcript, public_key_sha256.as_str().as_bytes());
    append_transcript_field(&mut transcript, certificate_sha256.as_str().as_bytes());
    append_transcript_field(&mut transcript, request_nonce.as_str().as_bytes());
    append_transcript_field(&mut transcript, &issued_at.value().to_be_bytes());
    append_transcript_field(&mut transcript, &expires_at.value().to_be_bytes());
    transcript
}

// Returns the SHA-256 identity of one canonical candidate-offer transcript.
pub fn node_pairing_candidate_offer_identity(
    offer: &NodePairingCandidateOffer,
) -> Result<Sha256Digest, NodePairingTransportError> {
    let transcript = node_pairing_candidate_offer_transcript(
        offer.candidate(),
        offer.public_key_sha256(),
        offer.certificate_sha256(),
        offer.request_nonce(),
        offer.issued_at(),
        offer.expires_at(),
    );
    let digest = Sha256::digest(transcript);
    let text = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&text).map_err(interface_error)
}

// Names the only candidate-facing pairing protocol requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePairingTransportRequest {
    CandidateOffer { request_nonce: Sha256Digest },
    Challenge { invite_id: PairingInviteId },
    Enroll(NodePairingCandidateEnrollment),
    Status { invite_id: PairingInviteId },
}

// Names the only candidate-facing pairing protocol responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePairingTransportResponse {
    CandidateOffer(NodePairingCandidateOffer),
    Challenge {
        challenge: NodePairingChallenge,
        main: Node,
    },
    Enrollment(NodePairingEnrollment),
    Status(NodePairingStatus),
}

// Describes one stable redacted candidate-facing pairing transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePairingTransportError {
    InvalidDocument { reason: &'static str },
    RequestRejected,
    Unavailable,
    TimedOut,
    Cancelled,
    UntrustedPeer,
}

impl fmt::Display for NodePairingTransportError {
    // Presents stable transport language without identities, secrets, addresses, or native errors.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDocument { reason } => {
                write!(formatter, "pairing document is invalid: {reason}")
            }
            Self::RequestRejected => formatter.write_str("pairing request was rejected"),
            Self::Unavailable => formatter.write_str("pairing transport is unavailable"),
            Self::TimedOut => formatter.write_str("pairing transport timed out"),
            Self::Cancelled => formatter.write_str("pairing operation was cancelled"),
            Self::UntrustedPeer => formatter.write_str("pairing peer identity is untrusted"),
        }
    }
}

impl Error for NodePairingTransportError {}

// Dispatches one decoded request through PairingManager-backed Node authority.
pub struct NodePairingDocumentEndpoint {
    pairing: std::sync::Arc<dyn NodePairingApiPort>,
    candidate: std::sync::Arc<dyn NodePairingCandidateOfferPort>,
    local: std::sync::Arc<dyn NodePairingLocalNodePort>,
}

impl NodePairingDocumentEndpoint {
    // Creates one endpoint from exact pairing, candidate-signing, and local-node capabilities.
    pub const fn new(
        pairing: std::sync::Arc<dyn NodePairingApiPort>,
        candidate: std::sync::Arc<dyn NodePairingCandidateOfferPort>,
        local: std::sync::Arc<dyn NodePairingLocalNodePort>,
    ) -> Self {
        Self {
            pairing,
            candidate,
            local,
        }
    }

    // Handles one request after the TLS adapter supplies its observed network peer address.
    pub fn handle(
        &self,
        request: NodePairingTransportRequest,
        observed_peer_address: &NodeAddress,
    ) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        match request {
            NodePairingTransportRequest::CandidateOffer { request_nonce } => self
                .candidate
                .candidate_offer(&request_nonce)
                .map(NodePairingTransportResponse::CandidateOffer),
            NodePairingTransportRequest::Challenge { invite_id } => {
                let challenge = self
                    .pairing
                    .challenge(&invite_id, observed_peer_address)
                    .map_err(pairing_error)?;
                let main = self.local.local_node()?;
                if main.identity().node_id() != challenge.main_node_id()
                    || main.control_address() != challenge.main_address()
                    || main.role() != NodeRole::Main
                    || main.state() != NodeState::Active
                {
                    return Err(NodePairingTransportError::RequestRejected);
                }
                Ok(NodePairingTransportResponse::Challenge { challenge, main })
            }
            NodePairingTransportRequest::Enroll(request) => {
                let request = request.into_request(observed_peer_address.clone())?;
                self.pairing
                    .enroll(&request)
                    .map(NodePairingTransportResponse::Enrollment)
                    .map_err(pairing_error)
            }
            NodePairingTransportRequest::Status { invite_id } => self
                .pairing
                .status(&invite_id)
                .map(NodePairingTransportResponse::Status)
                .map_err(pairing_error),
        }
    }
}

// Encodes one request as a closed bounded v1 JSON document.
pub fn encode_node_pairing_request(
    request: &NodePairingTransportRequest,
) -> Result<Vec<u8>, NodePairingTransportError> {
    encode(&WireDocument::request(request))
}

// Decodes one closed bounded v1 JSON request document.
pub fn decode_node_pairing_request(
    document: &[u8],
) -> Result<NodePairingTransportRequest, NodePairingTransportError> {
    WireDocument::decode(document)?.into_request()
}

// Encodes one response as a closed bounded v1 JSON document.
pub fn encode_node_pairing_response(
    response: &NodePairingTransportResponse,
) -> Result<Vec<u8>, NodePairingTransportError> {
    encode(&WireDocument::response(response))
}

// Decodes one closed bounded v1 JSON response document.
pub fn decode_node_pairing_response(
    document: &[u8],
) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
    WireDocument::decode(document)?.into_response()
}

// Stores the required nested protocol identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSchema {
    name: String,
    version: u32,
}

// Stores exactly one request or response in the closed v1 union.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireDocument {
    schema: WireSchema,
    request: Option<WireRequest>,
    response: Option<WireResponse>,
}

impl WireDocument {
    // Projects one typed request into its only legal document envelope.
    fn request(request: &NodePairingTransportRequest) -> Self {
        Self {
            schema: schema(),
            request: Some(WireRequest::from_request(request)),
            response: None,
        }
    }

    // Projects one typed response into its only legal document envelope.
    fn response(response: &NodePairingTransportResponse) -> Self {
        Self {
            schema: schema(),
            request: None,
            response: Some(WireResponse::from_response(response)),
        }
    }

    // Parses one structurally closed document under the hard allocation bound.
    fn decode(document: &[u8]) -> Result<Self, NodePairingTransportError> {
        if document.is_empty() || document.len() > NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES {
            return Err(invalid("document size is invalid"));
        }
        let value: Self =
            serde_json::from_slice(document).map_err(|_| invalid("JSON is invalid"))?;
        if value.schema.name != NODE_PAIRING_TRANSPORT_SCHEMA_NAME
            || value.schema.version != NODE_PAIRING_TRANSPORT_SCHEMA_VERSION
            || value.request.is_some() == value.response.is_some()
        {
            return Err(invalid("document envelope is invalid"));
        }
        Ok(value)
    }

    // Reconstructs one request and rejects a response envelope.
    fn into_request(self) -> Result<NodePairingTransportRequest, NodePairingTransportError> {
        self.request
            .ok_or_else(|| invalid("request is missing"))?
            .into_request()
    }

    // Reconstructs one response and rejects a request envelope.
    fn into_response(self) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        self.response
            .ok_or_else(|| invalid("response is missing"))?
            .into_response()
    }
}

// Stores the closed request union without ambiguous optional fields.
#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum WireRequest {
    CandidateOffer { request_nonce: String },
    Challenge { invite_id: String },
    Enroll { enrollment: WireEnrollmentRequest },
    Status { invite_id: String },
}

impl WireRequest {
    // Projects one typed request into primitive wire fields.
    fn from_request(request: &NodePairingTransportRequest) -> Self {
        match request {
            NodePairingTransportRequest::CandidateOffer { request_nonce } => Self::CandidateOffer {
                request_nonce: request_nonce.as_str().to_string(),
            },
            NodePairingTransportRequest::Challenge { invite_id } => Self::Challenge {
                invite_id: invite_id.as_str().to_string(),
            },
            NodePairingTransportRequest::Enroll(request) => Self::Enroll {
                enrollment: WireEnrollmentRequest::from_request(request),
            },
            NodePairingTransportRequest::Status { invite_id } => Self::Status {
                invite_id: invite_id.as_str().to_string(),
            },
        }
    }

    // Reconstructs one typed request under every value-level invariant.
    fn into_request(self) -> Result<NodePairingTransportRequest, NodePairingTransportError> {
        match self {
            Self::CandidateOffer { request_nonce } => {
                Ok(NodePairingTransportRequest::CandidateOffer {
                    request_nonce: Sha256Digest::parse(&request_nonce).map_err(interface_error)?,
                })
            }
            Self::Challenge { invite_id } => Ok(NodePairingTransportRequest::Challenge {
                invite_id: PairingInviteId::parse(&invite_id).map_err(interface_error)?,
            }),
            Self::Enroll { enrollment } => enrollment
                .into_request()
                .map(NodePairingTransportRequest::Enroll),
            Self::Status { invite_id } => Ok(NodePairingTransportRequest::Status {
                invite_id: PairingInviteId::parse(&invite_id).map_err(interface_error)?,
            }),
        }
    }
}

// Stores the closed successful response union.
#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum WireResponse {
    CandidateOffer {
        offer: WireCandidateOffer,
    },
    Challenge {
        challenge: WireChallenge,
        main: WireNode,
    },
    Enrollment {
        enrollment: WireEnrollment,
    },
    Status {
        status: WireStatus,
    },
}

impl WireResponse {
    // Projects one typed response into primitive wire fields.
    fn from_response(response: &NodePairingTransportResponse) -> Self {
        match response {
            NodePairingTransportResponse::CandidateOffer(offer) => Self::CandidateOffer {
                offer: WireCandidateOffer::from_offer(offer),
            },
            NodePairingTransportResponse::Challenge { challenge, main } => Self::Challenge {
                challenge: WireChallenge::from_challenge(challenge),
                main: WireNode::from_node(main),
            },
            NodePairingTransportResponse::Enrollment(enrollment) => Self::Enrollment {
                enrollment: WireEnrollment::from_enrollment(enrollment),
            },
            NodePairingTransportResponse::Status(status) => Self::Status {
                status: WireStatus::from_status(status),
            },
        }
    }

    // Reconstructs one typed response under every value-level invariant.
    fn into_response(self) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        match self {
            Self::CandidateOffer { offer } => offer
                .into_offer()
                .map(NodePairingTransportResponse::CandidateOffer),
            Self::Challenge { challenge, main } => Ok(NodePairingTransportResponse::Challenge {
                challenge: challenge.into_challenge()?,
                main: main.into_node()?,
            }),
            Self::Enrollment { enrollment } => enrollment
                .into_enrollment()
                .map(NodePairingTransportResponse::Enrollment),
            Self::Status { status } => status
                .into_status()
                .map(NodePairingTransportResponse::Status),
        }
    }
}

// Stores one binary-bearing enrollment request with base64 payloads.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEnrollmentRequest {
    idempotency_key: String,
    invite_id: String,
    node: WireNode,
    public_key_base64: String,
    installation_created_at_unix_milliseconds: u64,
    proof_signature_base64: String,
    setup_code: Option<String>,
}

impl WireEnrollmentRequest {
    // Projects one candidate request without exposing binary values as diagnostic text.
    fn from_request(request: &NodePairingCandidateEnrollment) -> Self {
        Self {
            idempotency_key: request.idempotency_key().to_string(),
            invite_id: request.invite_id().as_str().to_string(),
            node: WireNode::from_node(request.candidate()),
            public_key_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                request.public_key(),
            ),
            installation_created_at_unix_milliseconds: request
                .candidate()
                .timestamps()
                .created_at()
                .value(),
            proof_signature_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                request.proof_signature(),
            ),
            setup_code: request.setup_code().map(str::to_string),
        }
    }

    // Reconstructs one enrollment request without accepting transport-supplied peer substitution.
    fn into_request(self) -> Result<NodePairingCandidateEnrollment, NodePairingTransportError> {
        let node = self.node.into_node()?;
        if node.timestamps().created_at().value() != self.installation_created_at_unix_milliseconds
        {
            return Err(invalid("candidate installation timestamp is divergent"));
        }
        NodePairingCandidateEnrollment::new(
            self.idempotency_key,
            PairingInviteId::parse(&self.invite_id).map_err(interface_error)?,
            node,
            decode_base64(&self.public_key_base64, MAXIMUM_PUBLIC_KEY_BYTES)?,
            decode_base64(&self.proof_signature_base64, MAXIMUM_SIGNATURE_BYTES)?,
            self.setup_code,
        )
    }
}

// Stores one signed candidate offer.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCandidateOffer {
    candidate: WireNode,
    public_key_base64: String,
    public_key_sha256: String,
    certificate_sha256: String,
    request_nonce: String,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    signature_base64: String,
}

impl WireCandidateOffer {
    // Projects one signed offer into its exact bounded wire fields.
    fn from_offer(offer: &NodePairingCandidateOffer) -> Self {
        Self {
            candidate: WireNode::from_node(offer.candidate()),
            public_key_base64: encode_base64(offer.public_key()),
            public_key_sha256: offer.public_key_sha256().as_str().to_string(),
            certificate_sha256: offer.certificate_sha256().as_str().to_string(),
            request_nonce: offer.request_nonce().as_str().to_string(),
            issued_at_unix_milliseconds: offer.issued_at().value(),
            expires_at_unix_milliseconds: offer.expires_at().value(),
            signature_base64: encode_base64(offer.signature()),
        }
    }

    // Reconstructs one signed offer and reapplies every bounded invariant.
    fn into_offer(self) -> Result<NodePairingCandidateOffer, NodePairingTransportError> {
        NodePairingCandidateOffer::new(
            self.candidate.into_node()?,
            decode_base64(&self.public_key_base64, MAXIMUM_PUBLIC_KEY_BYTES)?,
            Sha256Digest::parse(&self.public_key_sha256).map_err(interface_error)?,
            Sha256Digest::parse(&self.certificate_sha256).map_err(interface_error)?,
            Sha256Digest::parse(&self.request_nonce).map_err(interface_error)?,
            UnixMilliseconds::new(self.issued_at_unix_milliseconds),
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
            decode_base64(&self.signature_base64, MAXIMUM_SIGNATURE_BYTES)?,
        )
    }
}

// Stores one public PairingManager challenge.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireChallenge {
    invite_id: String,
    mode: WireMode,
    nonce: String,
    created_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    main_node_id: String,
    main_address: String,
    main_private_port: u16,
    main_public_key_sha256: String,
    main_certificate_sha256: String,
}

impl WireChallenge {
    // Projects one typed challenge without setup or proof material.
    fn from_challenge(challenge: &NodePairingChallenge) -> Self {
        Self {
            invite_id: challenge.invite_id().as_str().to_string(),
            mode: WireMode::from_mode(challenge.mode()),
            nonce: challenge.nonce().as_str().to_string(),
            created_at_unix_milliseconds: challenge.created_at().value(),
            expires_at_unix_milliseconds: challenge.expires_at().value(),
            main_node_id: challenge.main_node_id().as_str().to_string(),
            main_address: challenge.main_address().as_str().to_string(),
            main_private_port: challenge.main_private_port(),
            main_public_key_sha256: challenge.main_public_key_sha256().as_str().to_string(),
            main_certificate_sha256: challenge.main_certificate_sha256().as_str().to_string(),
        }
    }

    // Reconstructs one challenge under every typed value invariant.
    fn into_challenge(self) -> Result<NodePairingChallenge, NodePairingTransportError> {
        NodePairingChallenge::new(
            PairingInviteId::parse(&self.invite_id).map_err(interface_error)?,
            self.mode.into_mode()?,
            Sha256Digest::parse(&self.nonce).map_err(interface_error)?,
            UnixMilliseconds::new(self.created_at_unix_milliseconds),
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
            NodeId::parse(&self.main_node_id).map_err(interface_error)?,
            NodeAddress::parse(&self.main_address).map_err(interface_error)?,
            self.main_private_port,
            Sha256Digest::parse(&self.main_public_key_sha256).map_err(interface_error)?,
            Sha256Digest::parse(&self.main_certificate_sha256).map_err(interface_error)?,
        )
        .map_err(pairing_error)
    }
}

// Stores one closed pairing mode.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireMode {
    Lan,
    Remote,
    ConnectX {
        candidate_public_key_sha256: String,
        direct_interface: String,
    },
}

impl WireMode {
    // Projects one typed mode without optional-field ambiguity.
    fn from_mode(mode: &NodePairingMode) -> Self {
        match mode {
            NodePairingMode::Lan => Self::Lan,
            NodePairingMode::Remote => Self::Remote,
            NodePairingMode::ConnectX {
                candidate_public_key_sha256,
                direct_interface,
            } => Self::ConnectX {
                candidate_public_key_sha256: candidate_public_key_sha256.as_str().to_string(),
                direct_interface: direct_interface.as_str().to_string(),
            },
        }
    }

    // Reconstructs one typed mode without fallback.
    fn into_mode(self) -> Result<NodePairingMode, NodePairingTransportError> {
        match self {
            Self::Lan => Ok(NodePairingMode::Lan),
            Self::Remote => Ok(NodePairingMode::Remote),
            Self::ConnectX {
                candidate_public_key_sha256,
                direct_interface,
            } => Ok(NodePairingMode::ConnectX {
                candidate_public_key_sha256: Sha256Digest::parse(&candidate_public_key_sha256)
                    .map_err(interface_error)?,
                direct_interface: li_core_interface::NetworkInterfaceName::parse(&direct_interface)
                    .map_err(interface_error)?,
            }),
        }
    }
}

// Stores one status projection shared by enrollment and polling responses.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStatus {
    invite_id: String,
    mode: WireMode,
    state: String,
    expires_at_unix_milliseconds: u64,
    attempts: u8,
    child_node_id: Option<String>,
    comparison_code: Option<String>,
}

impl WireStatus {
    // Projects one typed status while retaining the optional approval code only in the payload.
    fn from_status(status: &NodePairingStatus) -> Self {
        Self {
            invite_id: status.invite_id().as_str().to_string(),
            mode: WireMode::from_mode(status.mode()),
            state: match status.state() {
                NodePairingState::Open => "open",
                NodePairingState::PendingApproval => "pending_approval",
                NodePairingState::Active => "active",
            }
            .to_string(),
            expires_at_unix_milliseconds: status.expires_at().value(),
            attempts: status.attempts(),
            child_node_id: status
                .child_node_id()
                .map(|value| value.as_str().to_string()),
            comparison_code: status.comparison_code().map(str::to_string),
        }
    }

    // Reconstructs one typed status without accepting unknown lifecycle values.
    fn into_status(self) -> Result<NodePairingStatus, NodePairingTransportError> {
        let state = match self.state.as_str() {
            "open" => NodePairingState::Open,
            "pending_approval" => NodePairingState::PendingApproval,
            "active" => NodePairingState::Active,
            _ => return Err(invalid("pairing status is invalid")),
        };
        NodePairingStatus::new(
            PairingInviteId::parse(&self.invite_id).map_err(interface_error)?,
            self.mode.into_mode()?,
            state,
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
            self.attempts,
            self.child_node_id
                .map(|value| NodeId::parse(&value).map_err(interface_error))
                .transpose()?,
            self.comparison_code,
        )
        .map_err(pairing_error)
    }
}

// Stores one public trust credential package.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCredentials {
    main_public_key_base64: String,
    main_ca_certificate_base64: String,
    child_certificate_base64: String,
    membership_signature_base64: String,
    child_leaf_sha256: String,
    valid_from_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

impl WireCredentials {
    // Projects one credential package as bounded base64 payloads.
    fn from_credentials(credentials: &NodePairingCredentials) -> Self {
        Self {
            main_public_key_base64: encode_base64(credentials.main_public_key()),
            main_ca_certificate_base64: encode_base64(credentials.main_ca_certificate()),
            child_certificate_base64: encode_base64(credentials.child_certificate()),
            membership_signature_base64: encode_base64(credentials.membership_signature()),
            child_leaf_sha256: credentials.child_leaf_sha256().as_str().to_string(),
            valid_from_unix_milliseconds: credentials.valid_from().value(),
            expires_at_unix_milliseconds: credentials.expires_at().value(),
        }
    }

    // Reconstructs one bounded credential package and reapplies time invariants.
    fn into_credentials(self) -> Result<NodePairingCredentials, NodePairingTransportError> {
        NodePairingCredentials::new(
            decode_base64(&self.main_public_key_base64, 64 * 1024)?,
            decode_base64(&self.main_ca_certificate_base64, 64 * 1024)?,
            decode_base64(&self.child_certificate_base64, 64 * 1024)?,
            decode_base64(&self.membership_signature_base64, MAXIMUM_SIGNATURE_BYTES)?,
            Sha256Digest::parse(&self.child_leaf_sha256).map_err(interface_error)?,
            UnixMilliseconds::new(self.valid_from_unix_milliseconds),
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
        )
        .map_err(pairing_error)
    }
}

// Stores one completed enrollment.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEnrollment {
    status: WireStatus,
    credentials: WireCredentials,
}

impl WireEnrollment {
    // Projects one completed enrollment into status and public credentials.
    fn from_enrollment(enrollment: &NodePairingEnrollment) -> Self {
        Self {
            status: WireStatus::from_status(enrollment.status()),
            credentials: WireCredentials::from_credentials(enrollment.credentials()),
        }
    }

    // Reconstructs one coherent enrollment response.
    fn into_enrollment(self) -> Result<NodePairingEnrollment, NodePairingTransportError> {
        NodePairingEnrollment::new(
            self.status.into_status()?,
            self.credentials.into_credentials()?,
        )
        .map_err(pairing_error)
    }
}

// Stores one complete Node snapshot without persistence-only fields.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireNode {
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    state: String,
    control_address: String,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl WireNode {
    // Projects one immutable Node snapshot into exact transport fields.
    fn from_node(node: &Node) -> Self {
        Self {
            node_id: node.identity().node_id().as_str().to_string(),
            machine_id: node.identity().machine_id().as_str().to_string(),
            installation_id: node.identity().installation_id().as_str().to_string(),
            display_name: node.display_name().as_str().to_string(),
            role: match node.role() {
                NodeRole::Main => "main",
                NodeRole::Child => "child",
            }
            .to_string(),
            state: match node.state() {
                NodeState::Pending => "pending",
                NodeState::Active => "active",
                NodeState::Draining => "draining",
                NodeState::Offline => "offline",
                NodeState::Removed => "removed",
            }
            .to_string(),
            control_address: node.control_address().as_str().to_string(),
            created_at_unix_milliseconds: node.timestamps().created_at().value(),
            updated_at_unix_milliseconds: node.timestamps().updated_at().value(),
        }
    }

    // Reconstructs one validated immutable Node snapshot.
    fn into_node(self) -> Result<Node, NodePairingTransportError> {
        let role = match self.role.as_str() {
            "main" => NodeRole::Main,
            "child" => NodeRole::Child,
            _ => return Err(invalid("node role is invalid")),
        };
        let state = match self.state.as_str() {
            "pending" => NodeState::Pending,
            "active" => NodeState::Active,
            "draining" => NodeState::Draining,
            "offline" => NodeState::Offline,
            "removed" => NodeState::Removed,
            _ => return Err(invalid("node state is invalid")),
        };
        Ok(Node::new(
            NodeIdentity::new(
                NodeId::parse(&self.node_id).map_err(interface_error)?,
                MachineId::parse(&self.machine_id).map_err(interface_error)?,
                InstallationId::parse(&self.installation_id).map_err(interface_error)?,
            ),
            DisplayName::parse(&self.display_name).map_err(interface_error)?,
            role,
            state,
            NodeAddress::parse(&self.control_address).map_err(interface_error)?,
            None,
            EntityTimestamps::new(
                UnixMilliseconds::new(self.created_at_unix_milliseconds),
                UnixMilliseconds::new(self.updated_at_unix_milliseconds),
            )
            .map_err(interface_error)?,
        ))
    }
}

// Returns the fixed protocol identity for every document.
fn schema() -> WireSchema {
    WireSchema {
        name: NODE_PAIRING_TRANSPORT_SCHEMA_NAME.to_string(),
        version: NODE_PAIRING_TRANSPORT_SCHEMA_VERSION,
    }
}

// Adds one length-delimited value to a canonical candidate-offer transcript.
fn append_transcript_field(transcript: &mut Vec<u8>, value: &[u8]) {
    transcript.extend_from_slice(&(value.len() as u64).to_be_bytes());
    transcript.extend_from_slice(value);
}

// Serializes one document and enforces the same hard bound used during decoding.
fn encode(document: &WireDocument) -> Result<Vec<u8>, NodePairingTransportError> {
    let bytes = serde_json::to_vec(document).map_err(|_| invalid("JSON could not be encoded"))?;
    if bytes.is_empty() || bytes.len() > NODE_PAIRING_TRANSPORT_MAXIMUM_DOCUMENT_BYTES {
        return Err(invalid("document size is invalid"));
    }
    Ok(bytes)
}

// Encodes one non-secret binary payload without changing its bytes.
fn encode_base64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

// Decodes one strict bounded base64 payload.
fn decode_base64(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, NodePairingTransportError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| invalid("binary payload is invalid"))?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(invalid("binary payload size is invalid"));
    }
    Ok(bytes)
}

// Maps one PairingManager-backed API failure to fixed candidate-facing language.
fn pairing_error(_error: NodePairingApiError) -> NodePairingTransportError {
    NodePairingTransportError::RequestRejected
}

// Maps one interface value failure without retaining the invalid source value.
fn interface_error(_error: li_core_interface::InterfaceError) -> NodePairingTransportError {
    invalid("typed value is invalid")
}

// Creates one stable invalid-document failure.
const fn invalid(reason: &'static str) -> NodePairingTransportError {
    NodePairingTransportError::InvalidDocument { reason }
}
