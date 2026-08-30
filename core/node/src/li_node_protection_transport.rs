// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use li_core_interface::{
    BootId, CredentialId, InstallationId, NodeId, PlacementGroupId, PlacementId, Sha256Digest,
    TechnicalName, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot,
    GatewayProtectionAuthority, GatewayProtectionPollResponse,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogProtectedEngine, WatchdogProtectionCycle,
    WatchdogProtectionPhase, WatchdogProtocolSiteStatus,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    NodeProtectionApi, NodeProtectionApiError, NodeProtectionBeginRequest,
    NodeProtectionCommitRequest, NodeProtectionEndRequest, NodeProtectionReadSiteStatusRequest,
    NodeProtectionRequest, NodeProtectionResolveControllerBindingRequest, NodeProtectionResponse,
    NodeProtectionSnapshotRequest,
};

const SCHEMA_NAME: &str = "li_node_protection_api";
const SCHEMA_VERSION: u32 = 2;
pub const NODE_PROTECTION_MAX_DOCUMENT_BYTES: usize = 256 * 1_024;
const MAXIMUM_CYCLE_TARGETS: usize = 64;
const MAXIMUM_SNAPSHOT_PLACEMENTS: usize = 1_024;

// Carries one decoded request with its exact correlation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionTransportRequest {
    request_id: Sha256Digest,
    connection_id: Sha256Digest,
    request: NodeProtectionRequest,
}

impl NodeProtectionTransportRequest {
    // Creates one outbound typed protection request.
    pub const fn new(
        request_id: Sha256Digest,
        connection_id: Sha256Digest,
        request: NodeProtectionRequest,
    ) -> Self {
        Self {
            request_id,
            connection_id,
            request,
        }
    }

    // Returns the exact correlation identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the caller-selected unique identity for this authenticated native connection.
    pub const fn connection_id(&self) -> &Sha256Digest {
        &self.connection_id
    }

    // Returns the typed request consumed by NodeProtectionApi.
    pub const fn request(&self) -> &NodeProtectionRequest {
        &self.request
    }

    // Transfers the typed request to the authenticated dispatcher.
    pub fn into_request(self) -> NodeProtectionRequest {
        self.request
    }
}

// Names stable authenticated protection failures on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionRemoteError {
    AuthorizationDenied,
    InvalidContract,
    Conflict,
    Corrupt,
    ProviderUnavailable,
}

// Distinguishes one successful response from one redacted remote failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeProtectionTransportOutcome {
    Success(NodeProtectionResponse),
    Failure(NodeProtectionRemoteError),
}

// Carries one response bound to its authenticated connection and strict sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionTransportResponse {
    request_id: Sha256Digest,
    connection_id: Sha256Digest,
    sequence: NonZeroU64,
    outcome: NodeProtectionTransportOutcome,
}

impl NodeProtectionTransportResponse {
    // Creates one outbound typed response.
    pub const fn new(
        request_id: Sha256Digest,
        connection_id: Sha256Digest,
        sequence: NonZeroU64,
        outcome: NodeProtectionTransportOutcome,
    ) -> Self {
        Self {
            request_id,
            connection_id,
            sequence,
            outcome,
        }
    }

    // Returns the exact request correlation identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the authenticated transport connection identity.
    pub const fn connection_id(&self) -> &Sha256Digest {
        &self.connection_id
    }

    // Returns the strict response sequence on this connection.
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    // Returns the typed response or stable remote failure.
    pub const fn outcome(&self) -> &NodeProtectionTransportOutcome {
        &self.outcome
    }

    // Transfers one successful snapshot response into Gateway's authenticated poll contract.
    pub fn into_gateway_poll_response(
        self,
    ) -> Result<GatewayProtectionPollResponse, NodeProtectionTransportError> {
        match self.outcome {
            NodeProtectionTransportOutcome::Success(NodeProtectionResponse::GatewaySnapshot(
                snapshot,
            )) => Ok(GatewayProtectionPollResponse::new(
                self.connection_id,
                self.sequence,
                snapshot,
            )),
            _ => Err(NodeProtectionTransportError::InvalidDocument),
        }
    }
}

// Names stable closed-codec failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionTransportError {
    DocumentTooLarge,
    InvalidDocument,
    UnsupportedSchema,
    SequenceExhausted,
}

impl fmt::Display for NodeProtectionTransportError {
    // Presents fixed transport language without echoing untrusted values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge => formatter.write_str("protection document exceeds its bound"),
            Self::InvalidDocument => formatter.write_str("protection document is invalid"),
            Self::UnsupportedSchema => formatter.write_str("protection schema is unsupported"),
            Self::SequenceExhausted => {
                formatter.write_str("protection response sequence exhausted")
            }
        }
    }
}

impl Error for NodeProtectionTransportError {}

// Owns closed JSON conversion for the dedicated Node protection channel.
pub struct NodeProtectionTransport;

impl NodeProtectionTransport {
    // Encodes one typed request into compact closed JSON.
    pub fn encode_request(
        request: &NodeProtectionTransportRequest,
    ) -> Result<Vec<u8>, NodeProtectionTransportError> {
        encode_document(&WireRequest::from_request(request))
    }

    // Decodes and validates one bounded request document.
    pub fn decode_request(
        document: &[u8],
    ) -> Result<NodeProtectionTransportRequest, NodeProtectionTransportError> {
        let wire: WireRequest = decode_document(document)?;
        wire.into_request()
    }

    // Encodes one typed response into compact closed JSON.
    pub fn encode_response(
        response: &NodeProtectionTransportResponse,
    ) -> Result<Vec<u8>, NodeProtectionTransportError> {
        encode_document(&WireResponse::from_response(response))
    }

    // Decodes and validates one bounded response document.
    pub fn decode_response(
        document: &[u8],
    ) -> Result<NodeProtectionTransportResponse, NodeProtectionTransportError> {
        let wire: WireResponse = decode_document(document)?;
        wire.into_response()
    }
}

// Owns authenticated decode, dispatch, and connection-bound response sequencing.
pub struct NodeProtectionEndpoint {
    api: Arc<NodeProtectionApi>,
    connection_id: Sha256Digest,
    next_sequence: AtomicU64,
}

impl NodeProtectionEndpoint {
    // Creates one endpoint for one already-authenticated connection.
    pub const fn new(api: Arc<NodeProtectionApi>, connection_id: Sha256Digest) -> Self {
        Self {
            api,
            connection_id,
            next_sequence: AtomicU64::new(1),
        }
    }

    // Handles one document only after the native listener supplies its authenticated principal.
    pub fn handle(
        &self,
        principal_id: &CredentialId,
        document: &[u8],
    ) -> Result<Vec<u8>, NodeProtectionTransportError> {
        let request = NodeProtectionTransport::decode_request(document)?;
        if request.connection_id() != &self.connection_id {
            return Err(NodeProtectionTransportError::InvalidDocument);
        }
        let request_id = request.request_id().clone();
        let result = self.api.dispatch(principal_id, request.into_request());
        let sequence = self.next_sequence.fetch_add(1, Ordering::AcqRel);
        let sequence =
            NonZeroU64::new(sequence).ok_or(NodeProtectionTransportError::SequenceExhausted)?;
        let outcome = match result {
            Ok(response) => NodeProtectionTransportOutcome::Success(response),
            Err(error) => NodeProtectionTransportOutcome::Failure(remote_error(error)),
        };
        NodeProtectionTransport::encode_response(&NodeProtectionTransportResponse::new(
            request_id,
            self.connection_id.clone(),
            sequence,
            outcome,
        ))
    }

    // Returns the exact authenticated connection identity used by Gateway invalidation.
    pub const fn connection_id(&self) -> &Sha256Digest {
        &self.connection_id
    }
}

// Stores the required nested schema identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSchema {
    name: String,
    version: u32,
}

impl WireSchema {
    // Returns the only supported protection schema identity.
    fn current() -> Self {
        Self {
            name: SCHEMA_NAME.to_string(),
            version: SCHEMA_VERSION,
        }
    }

    // Rejects every unknown schema name or version.
    fn validate(&self) -> Result<(), NodeProtectionTransportError> {
        if self.name != SCHEMA_NAME || self.version != SCHEMA_VERSION {
            return Err(NodeProtectionTransportError::UnsupportedSchema);
        }
        Ok(())
    }
}

// Stores one closed request envelope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    schema: WireSchema,
    request_id: String,
    connection_id: String,
    request: WireRequestBody,
}

impl WireRequest {
    // Projects one typed request into its exact wire shape.
    fn from_request(request: &NodeProtectionTransportRequest) -> Self {
        Self {
            schema: WireSchema::current(),
            request_id: request.request_id().as_str().to_string(),
            connection_id: request.connection_id().as_str().to_string(),
            request: WireRequestBody::from_request(request.request()),
        }
    }

    // Reconstructs one typed request after schema and identity validation.
    fn into_request(self) -> Result<NodeProtectionTransportRequest, NodeProtectionTransportError> {
        self.schema.validate()?;
        Ok(NodeProtectionTransportRequest::new(
            parse_digest(&self.request_id)?,
            parse_digest(&self.connection_id)?,
            self.request.into_request()?,
        ))
    }
}

// Stores the six closed protection operations.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "action",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireRequestBody {
    BeginWatchdogSession {
        idempotency_key: String,
        node_id: String,
        core_installation_id: String,
        watchdog_source_identity: String,
        watchdog_session_nonce: String,
        minimum_sample_sequence: u64,
    },
    CommitWatchdogCycle {
        node_id: String,
        watchdog_session_id: String,
        watchdog_session_generation: u64,
        cycle: WireProtectionCycle,
    },
    EndWatchdogSession {
        node_id: String,
        watchdog_session_id: String,
        watchdog_session_generation: u64,
    },
    ResolveControllerBinding {
        certificate_sha256: String,
    },
    ReadSiteStatus {
        binding: WireControllerBinding,
    },
    ReadGatewaySnapshot {
        node_id: String,
        placement_group_id: String,
        endpoint_node_id: String,
    },
}

impl WireRequestBody {
    // Projects one typed operation without changing its identity.
    fn from_request(request: &NodeProtectionRequest) -> Self {
        match request {
            NodeProtectionRequest::BeginWatchdogSession(request) => Self::BeginWatchdogSession {
                idempotency_key: request.idempotency_key().to_string(),
                node_id: request.node_id().as_str().to_string(),
                core_installation_id: request.core_installation_id().as_str().to_string(),
                watchdog_source_identity: request.watchdog_source_identity().as_str().to_string(),
                watchdog_session_nonce: request.watchdog_session_nonce().as_str().to_string(),
                minimum_sample_sequence: request.minimum_sample_sequence().get(),
            },
            NodeProtectionRequest::CommitWatchdogCycle(request) => Self::CommitWatchdogCycle {
                node_id: request.node_id().as_str().to_string(),
                watchdog_session_id: request.watchdog_session_id().as_str().to_string(),
                watchdog_session_generation: request.watchdog_session_generation().get(),
                cycle: WireProtectionCycle::from_cycle(request.cycle()),
            },
            NodeProtectionRequest::EndWatchdogSession(request) => Self::EndWatchdogSession {
                node_id: request.node_id().as_str().to_string(),
                watchdog_session_id: request.watchdog_session_id().as_str().to_string(),
                watchdog_session_generation: request.watchdog_session_generation().get(),
            },
            NodeProtectionRequest::ResolveControllerBinding(request) => {
                Self::ResolveControllerBinding {
                    certificate_sha256: request.certificate_sha256().as_str().to_string(),
                }
            }
            NodeProtectionRequest::ReadSiteStatus(request) => Self::ReadSiteStatus {
                binding: WireControllerBinding::from_binding(request.binding()),
            },
            NodeProtectionRequest::ReadGatewaySnapshot(request) => Self::ReadGatewaySnapshot {
                node_id: request.node_id().as_str().to_string(),
                placement_group_id: request.placement_group_id().as_str().to_string(),
                endpoint_node_id: request.endpoint_node_id().as_str().to_string(),
            },
        }
    }

    // Reconstructs one typed operation after every scalar is parsed and bounded.
    fn into_request(self) -> Result<NodeProtectionRequest, NodeProtectionTransportError> {
        match self {
            Self::BeginWatchdogSession {
                idempotency_key,
                node_id,
                core_installation_id,
                watchdog_source_identity,
                watchdog_session_nonce,
                minimum_sample_sequence,
            } => NodeProtectionBeginRequest::new(
                &idempotency_key,
                parse_node_id(&node_id)?,
                parse_installation_id(&core_installation_id)?,
                parse_digest(&watchdog_source_identity)?,
                parse_digest(&watchdog_session_nonce)?,
                nonzero(minimum_sample_sequence)?,
            )
            .map(NodeProtectionRequest::BeginWatchdogSession)
            .map_err(|_| NodeProtectionTransportError::InvalidDocument),
            Self::CommitWatchdogCycle {
                node_id,
                watchdog_session_id,
                watchdog_session_generation,
                cycle,
            } => Ok(NodeProtectionRequest::CommitWatchdogCycle(
                NodeProtectionCommitRequest::new(
                    parse_node_id(&node_id)?,
                    parse_digest(&watchdog_session_id)?,
                    nonzero(watchdog_session_generation)?,
                    cycle.into_cycle()?,
                ),
            )),
            Self::EndWatchdogSession {
                node_id,
                watchdog_session_id,
                watchdog_session_generation,
            } => Ok(NodeProtectionRequest::EndWatchdogSession(
                NodeProtectionEndRequest::new(
                    parse_node_id(&node_id)?,
                    parse_digest(&watchdog_session_id)?,
                    nonzero(watchdog_session_generation)?,
                ),
            )),
            Self::ResolveControllerBinding { certificate_sha256 } => {
                Ok(NodeProtectionRequest::ResolveControllerBinding(
                    NodeProtectionResolveControllerBindingRequest::new(parse_digest(
                        &certificate_sha256,
                    )?),
                ))
            }
            Self::ReadSiteStatus { binding } => Ok(NodeProtectionRequest::ReadSiteStatus(
                NodeProtectionReadSiteStatusRequest::new(binding.into_binding()?),
            )),
            Self::ReadGatewaySnapshot {
                node_id,
                placement_group_id,
                endpoint_node_id,
            } => Ok(NodeProtectionRequest::ReadGatewaySnapshot(
                NodeProtectionSnapshotRequest::new(
                    parse_node_id(&node_id)?,
                    parse_group_id(&placement_group_id)?,
                    parse_node_id(&endpoint_node_id)?,
                ),
            )),
        }
    }
}

// Stores one complete Watchdog cycle through canonical protected descriptors.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireProtectionCycle {
    sample_sequence: u64,
    observed_at_unix_milliseconds: u64,
    observed_at_monotonic_milliseconds: u64,
    protected_descriptors: Vec<String>,
}

impl WireProtectionCycle {
    // Projects one completed cycle into exact descriptor text.
    fn from_cycle(cycle: &WatchdogProtectionCycle) -> Self {
        Self {
            sample_sequence: cycle.sample_sequence(),
            observed_at_unix_milliseconds: cycle.observed_at_unix_milliseconds(),
            observed_at_monotonic_milliseconds: cycle.observed_at_monotonic_milliseconds(),
            protected_descriptors: cycle
                .targets()
                .iter()
                .map(|seed| protected_descriptor(seed.target()))
                .collect(),
        }
    }

    // Rehydrates one authenticated completed-cycle receipt with strict target bounds.
    fn into_cycle(self) -> Result<WatchdogProtectionCycle, NodeProtectionTransportError> {
        if self.protected_descriptors.len() > MAXIMUM_CYCLE_TARGETS {
            return Err(NodeProtectionTransportError::InvalidDocument);
        }
        let targets = self
            .protected_descriptors
            .iter()
            .map(|descriptor| {
                WatchdogProtectedEngine::parse(descriptor)
                    .map_err(|_| NodeProtectionTransportError::InvalidDocument)
            })
            .collect::<Result<Vec<_>, _>>()?;
        WatchdogProtectionCycle::from_authenticated_report(
            self.sample_sequence,
            self.observed_at_unix_milliseconds,
            self.observed_at_monotonic_milliseconds,
            targets,
        )
        .map_err(|_| NodeProtectionTransportError::InvalidDocument)
    }
}

// Stores one closed response envelope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    schema: WireSchema,
    request_id: String,
    connection_id: String,
    sequence: u64,
    outcome: WireOutcome,
}

impl WireResponse {
    // Projects one typed response into its exact closed wire shape.
    fn from_response(response: &NodeProtectionTransportResponse) -> Self {
        Self {
            schema: WireSchema::current(),
            request_id: response.request_id().as_str().to_string(),
            connection_id: response.connection_id().as_str().to_string(),
            sequence: response.sequence().get(),
            outcome: WireOutcome::from_outcome(response.outcome()),
        }
    }

    // Reconstructs one typed response after every envelope invariant passes.
    fn into_response(
        self,
    ) -> Result<NodeProtectionTransportResponse, NodeProtectionTransportError> {
        self.schema.validate()?;
        Ok(NodeProtectionTransportResponse::new(
            parse_digest(&self.request_id)?,
            parse_digest(&self.connection_id)?,
            nonzero(self.sequence)?,
            self.outcome.into_outcome()?,
        ))
    }
}

// Stores one closed success or failure response.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "status",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireOutcome {
    Success(WireResponseBody),
    Failure { code: String },
}

impl WireOutcome {
    // Projects one typed outcome into its exact wire branch.
    fn from_outcome(outcome: &NodeProtectionTransportOutcome) -> Self {
        match outcome {
            NodeProtectionTransportOutcome::Success(response) => {
                Self::Success(WireResponseBody::from_response(response))
            }
            NodeProtectionTransportOutcome::Failure(error) => Self::Failure {
                code: remote_error_name(*error).to_string(),
            },
        }
    }

    // Reconstructs one typed outcome without accepting arbitrary error codes.
    fn into_outcome(self) -> Result<NodeProtectionTransportOutcome, NodeProtectionTransportError> {
        match self {
            Self::Success(response) => response
                .into_response()
                .map(NodeProtectionTransportOutcome::Success),
            Self::Failure { code } => {
                remote_error_from_name(&code).map(NodeProtectionTransportOutcome::Failure)
            }
        }
    }
}

// Stores every closed success response.
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "result",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireResponseBody {
    WatchdogSessionBegan(WireAuthority),
    WatchdogCycleCommitted { lease_count: u16 },
    WatchdogSessionEnded,
    ControllerBinding(WireControllerBinding),
    SiteStatus(WireSiteStatus),
    GatewaySnapshot { snapshot: Option<WireSnapshot> },
}

impl WireResponseBody {
    // Projects one typed success response.
    fn from_response(response: &NodeProtectionResponse) -> Self {
        match response {
            NodeProtectionResponse::WatchdogSessionBegan(authority) => {
                Self::WatchdogSessionBegan(WireAuthority::from_authority(authority))
            }
            NodeProtectionResponse::WatchdogCycleCommitted { lease_count } => {
                Self::WatchdogCycleCommitted {
                    lease_count: u16::try_from(*lease_count).unwrap_or(u16::MAX),
                }
            }
            NodeProtectionResponse::WatchdogSessionEnded => Self::WatchdogSessionEnded,
            NodeProtectionResponse::ControllerBinding(binding) => {
                Self::ControllerBinding(WireControllerBinding::from_binding(binding))
            }
            NodeProtectionResponse::SiteStatus(status) => {
                Self::SiteStatus(WireSiteStatus::from_status(status))
            }
            NodeProtectionResponse::GatewaySnapshot(snapshot) => Self::GatewaySnapshot {
                snapshot: snapshot.as_ref().map(WireSnapshot::from_snapshot),
            },
        }
    }

    // Reconstructs one typed success response.
    fn into_response(self) -> Result<NodeProtectionResponse, NodeProtectionTransportError> {
        match self {
            Self::WatchdogSessionBegan(authority) => authority
                .into_authority()
                .map(NodeProtectionResponse::WatchdogSessionBegan),
            Self::WatchdogCycleCommitted { lease_count } => {
                if usize::from(lease_count) > MAXIMUM_SNAPSHOT_PLACEMENTS {
                    return Err(NodeProtectionTransportError::InvalidDocument);
                }
                Ok(NodeProtectionResponse::WatchdogCycleCommitted {
                    lease_count: usize::from(lease_count),
                })
            }
            Self::WatchdogSessionEnded => Ok(NodeProtectionResponse::WatchdogSessionEnded),
            Self::ControllerBinding(binding) => binding
                .into_binding()
                .map(NodeProtectionResponse::ControllerBinding),
            Self::SiteStatus(status) => {
                status.into_status().map(NodeProtectionResponse::SiteStatus)
            }
            Self::GatewaySnapshot { snapshot } => snapshot
                .map(WireSnapshot::into_snapshot)
                .transpose()
                .map(NodeProtectionResponse::GatewaySnapshot),
        }
    }
}

// Stores one exact authenticated controller and protected-process binding.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireControllerBinding {
    controller_id: String,
    certificate_sha256: String,
    session_generation: u64,
    protected_descriptor: String,
}

impl WireControllerBinding {
    // Projects one complete controller binding without weakening process identity.
    fn from_binding(binding: &WatchdogControllerBinding) -> Self {
        Self {
            controller_id: binding.controller_id().to_string(),
            certificate_sha256: binding.certificate_sha256().to_string(),
            session_generation: binding.session_generation(),
            protected_descriptor: protected_descriptor(binding.target()),
        }
    }

    // Reconstructs one binding only through Watchdog's complete typed contract.
    fn into_binding(self) -> Result<WatchdogControllerBinding, NodeProtectionTransportError> {
        WatchdogControllerBinding::new(
            &self.controller_id,
            &self.certificate_sha256,
            self.session_generation,
            WatchdogProtectedEngine::parse(&self.protected_descriptor)
                .map_err(|_| NodeProtectionTransportError::InvalidDocument)?,
        )
        .map_err(|_| NodeProtectionTransportError::InvalidDocument)
    }
}

// Stores the exact established public site-status field set.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSiteStatus {
    release: String,
    model: String,
    engine: String,
    runtime_name: String,
    runtime_version: String,
    manifest_sha256: String,
    cache_provider: String,
    cache_persistent: bool,
    inference_port: u32,
    maximum_connections: u32,
    maximum_active_requests: u32,
    maximum_context_tokens: u32,
    service_state: String,
    engine_state: String,
    protection_phase: String,
    protection_armed: bool,
    trip_latched: bool,
    container_name: String,
    installation_id: String,
}

impl WireSiteStatus {
    // Projects every validated status field without adding Node-owned semantics.
    fn from_status(status: &WatchdogProtocolSiteStatus) -> Self {
        Self {
            release: status.release().to_string(),
            model: status.model().to_string(),
            engine: status.engine().to_string(),
            runtime_name: status.runtime_name().to_string(),
            runtime_version: status.runtime_version().to_string(),
            manifest_sha256: status.manifest_sha256().to_string(),
            cache_provider: status.cache_provider().to_string(),
            cache_persistent: status.cache_persistent(),
            inference_port: status.inference_port(),
            maximum_connections: status.maximum_connections(),
            maximum_active_requests: status.maximum_active_requests(),
            maximum_context_tokens: status.maximum_context_tokens(),
            service_state: status.service_state().to_string(),
            engine_state: status.engine_state().to_string(),
            protection_phase: status.protection_phase().to_string(),
            protection_armed: status.protection_armed(),
            trip_latched: status.trip_latched(),
            container_name: status.container_name().to_string(),
            installation_id: status.installation_id().to_string(),
        }
    }

    // Reconstructs one status only through Watchdog's complete validation constructor.
    fn into_status(self) -> Result<WatchdogProtocolSiteStatus, NodeProtectionTransportError> {
        WatchdogProtocolSiteStatus::new(
            self.release,
            self.model,
            self.engine,
            self.runtime_name,
            self.runtime_version,
            self.manifest_sha256,
            self.cache_provider,
            self.cache_persistent,
            self.inference_port,
            self.maximum_connections,
            self.maximum_active_requests,
            self.maximum_context_tokens,
            self.service_state,
            self.engine_state,
            self.protection_phase,
            self.protection_armed,
            self.trip_latched,
            self.container_name,
            self.installation_id,
        )
        .map_err(|_| NodeProtectionTransportError::InvalidDocument)
    }
}

// Stores one protection authority.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAuthority {
    node_id: String,
    core_installation_id: String,
    watchdog_source_identity: String,
    watchdog_session_id: String,
    watchdog_session_generation: u64,
}

impl WireAuthority {
    // Projects one exact authority.
    fn from_authority(authority: &GatewayProtectionAuthority) -> Self {
        Self {
            node_id: authority.node_id().as_str().to_string(),
            core_installation_id: authority.core_installation_id().as_str().to_string(),
            watchdog_source_identity: authority.watchdog_source_identity().as_str().to_string(),
            watchdog_session_id: authority.watchdog_session_id().as_str().to_string(),
            watchdog_session_generation: authority.watchdog_session_generation().get(),
        }
    }

    // Reconstructs one exact authority.
    fn into_authority(self) -> Result<GatewayProtectionAuthority, NodeProtectionTransportError> {
        Ok(GatewayProtectionAuthority::new(
            parse_node_id(&self.node_id)?,
            parse_installation_id(&self.core_installation_id)?,
            parse_digest(&self.watchdog_source_identity)?,
            parse_digest(&self.watchdog_session_id)?,
            nonzero(self.watchdog_session_generation)?,
        ))
    }
}

// Stores one complete placement-group protection snapshot.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    placement_group_id: String,
    expected_placements: Vec<WireExpectedPlacement>,
    authorities: Vec<WireAuthority>,
    leases: Vec<WireLease>,
}

impl WireSnapshot {
    // Projects one exact Node-owned snapshot.
    fn from_snapshot(snapshot: &GatewayPlacementProtectionSnapshot) -> Self {
        Self {
            placement_group_id: snapshot.placement_group_id().as_str().to_string(),
            expected_placements: snapshot
                .expected_placements()
                .iter()
                .map(|(placement_id, node_id)| WireExpectedPlacement {
                    placement_id: placement_id.as_str().to_string(),
                    node_id: node_id.as_str().to_string(),
                })
                .collect(),
            authorities: snapshot
                .authorities()
                .iter()
                .map(WireAuthority::from_authority)
                .collect(),
            leases: snapshot
                .leases()
                .iter()
                .map(WireLease::from_lease)
                .collect(),
        }
    }

    // Reconstructs one bounded snapshot through Gateway's typed constructor.
    fn into_snapshot(
        self,
    ) -> Result<GatewayPlacementProtectionSnapshot, NodeProtectionTransportError> {
        if self.expected_placements.len() > MAXIMUM_SNAPSHOT_PLACEMENTS
            || self.authorities.len() > MAXIMUM_SNAPSHOT_PLACEMENTS
            || self.leases.len() > MAXIMUM_SNAPSHOT_PLACEMENTS
        {
            return Err(NodeProtectionTransportError::InvalidDocument);
        }
        GatewayPlacementProtectionSnapshot::new(
            parse_group_id(&self.placement_group_id)?,
            self.expected_placements
                .into_iter()
                .map(WireExpectedPlacement::into_pair)
                .collect::<Result<Vec<_>, _>>()?,
            self.authorities
                .into_iter()
                .map(WireAuthority::into_authority)
                .collect::<Result<Vec<_>, _>>()?,
            self.leases
                .into_iter()
                .map(WireLease::into_lease)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| NodeProtectionTransportError::InvalidDocument)
    }
}

// Stores one expected placement and owning Node pair.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireExpectedPlacement {
    placement_id: String,
    node_id: String,
}

impl WireExpectedPlacement {
    // Reconstructs one exact expected placement pair.
    fn into_pair(self) -> Result<(PlacementId, NodeId), NodeProtectionTransportError> {
        Ok((
            parse_placement_id(&self.placement_id)?,
            parse_node_id(&self.node_id)?,
        ))
    }
}

// Stores every field of one exact expiring Linux protection lease.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireLease {
    node_id: String,
    placement_group_id: String,
    placement_id: String,
    core_installation_id: String,
    watchdog_source_identity: String,
    watchdog_session_id: String,
    watchdog_session_generation: u64,
    protection_generation: String,
    container_name: String,
    container_id: String,
    process_id: u32,
    process_start_ticks: u64,
    boot_id: String,
    cgroup: String,
    sample_sequence: u64,
    observed_at_unix_milliseconds: u64,
    observed_at_monotonic_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    armed: bool,
    trip_latched: bool,
}

impl WireLease {
    // Projects one exact identity-bound lease.
    fn from_lease(lease: &GatewayPlacementProtectionLease) -> Self {
        Self {
            node_id: lease.node_id().as_str().to_string(),
            placement_group_id: lease.placement_group_id().as_str().to_string(),
            placement_id: lease.placement_id().as_str().to_string(),
            core_installation_id: lease.core_installation_id().as_str().to_string(),
            watchdog_source_identity: lease.watchdog_source_identity().as_str().to_string(),
            watchdog_session_id: lease.watchdog_session_id().as_str().to_string(),
            watchdog_session_generation: lease.watchdog_session_generation().get(),
            protection_generation: lease.protection_generation().to_string(),
            container_name: lease.container_name().as_str().to_string(),
            container_id: lease.container_id().as_str().to_string(),
            process_id: lease.process_id(),
            process_start_ticks: lease.process_start_ticks(),
            boot_id: lease.boot_id().as_str().to_string(),
            cgroup: lease.cgroup().to_string(),
            sample_sequence: lease.sample_sequence().get(),
            observed_at_unix_milliseconds: lease.observed_at().value(),
            observed_at_monotonic_milliseconds: lease.observed_at_monotonic_milliseconds(),
            expires_at_unix_milliseconds: lease.expires_at().value(),
            armed: lease.is_armed(),
            trip_latched: lease.trip_latched(),
        }
    }

    // Reconstructs one lease only through Gateway's complete contract constructor.
    fn into_lease(self) -> Result<GatewayPlacementProtectionLease, NodeProtectionTransportError> {
        GatewayPlacementProtectionLease::new(
            parse_node_id(&self.node_id)?,
            parse_group_id(&self.placement_group_id)?,
            parse_placement_id(&self.placement_id)?,
            parse_installation_id(&self.core_installation_id)?,
            parse_digest(&self.watchdog_source_identity)?,
            parse_digest(&self.watchdog_session_id)?,
            nonzero(self.watchdog_session_generation)?,
            &self.protection_generation,
            TechnicalName::parse(&self.container_name)
                .map_err(|_| NodeProtectionTransportError::InvalidDocument)?,
            parse_digest(&self.container_id)?,
            self.process_id,
            self.process_start_ticks,
            BootId::parse(&self.boot_id)
                .map_err(|_| NodeProtectionTransportError::InvalidDocument)?,
            &self.cgroup,
            nonzero(self.sample_sequence)?,
            UnixMilliseconds::new(self.observed_at_unix_milliseconds),
            self.observed_at_monotonic_milliseconds,
            UnixMilliseconds::new(self.expires_at_unix_milliseconds),
            self.armed,
            self.trip_latched,
        )
        .map_err(|_| NodeProtectionTransportError::InvalidDocument)
    }
}

// Encodes one document and enforces the same bound used for decoding.
fn encode_document<Value: Serialize>(
    value: &Value,
) -> Result<Vec<u8>, NodeProtectionTransportError> {
    let document =
        serde_json::to_vec(value).map_err(|_| NodeProtectionTransportError::InvalidDocument)?;
    if document.len() > NODE_PROTECTION_MAX_DOCUMENT_BYTES {
        return Err(NodeProtectionTransportError::DocumentTooLarge);
    }
    Ok(document)
}

// Decodes exactly one bounded JSON value without trailing data.
fn decode_document<Value: DeserializeOwned>(
    document: &[u8],
) -> Result<Value, NodeProtectionTransportError> {
    if document.len() > NODE_PROTECTION_MAX_DOCUMENT_BYTES {
        return Err(NodeProtectionTransportError::DocumentTooLarge);
    }
    serde_json::from_slice(document).map_err(|_| NodeProtectionTransportError::InvalidDocument)
}

// Returns the canonical Watchdog descriptor used by source and Node validation.
fn protected_descriptor(target: &WatchdogProtectedEngine) -> String {
    format!(
        "version=1\ngeneration={}\nphase={}\ncontainer_name={}\ncontainer_id={}\npid={}\nstart_ticks={}\nboot_id={}\ncgroup={}\n",
        target.generation(),
        protection_phase_name(target.phase()),
        target.container_name(),
        target.container_id().unwrap_or_default(),
        target.process_id().unwrap_or_default(),
        target.process_start_ticks().unwrap_or_default(),
        target.boot_id().unwrap_or_default(),
        target.cgroup().unwrap_or_default(),
    )
}

// Returns the exact process-bound phase accepted by controller bindings and completed cycles.
const fn protection_phase_name(phase: WatchdogProtectionPhase) -> &'static str {
    match phase {
        WatchdogProtectionPhase::Starting => "starting",
        WatchdogProtectionPhase::Armed => "armed",
        WatchdogProtectionPhase::Pending => "pending",
        WatchdogProtectionPhase::Disarmed => "disarmed",
    }
}

// Parses one canonical Node identity.
fn parse_node_id(value: &str) -> Result<NodeId, NodeProtectionTransportError> {
    NodeId::parse(value).map_err(|_| NodeProtectionTransportError::InvalidDocument)
}

// Parses one canonical placement-group identity.
fn parse_group_id(value: &str) -> Result<PlacementGroupId, NodeProtectionTransportError> {
    PlacementGroupId::parse(value).map_err(|_| NodeProtectionTransportError::InvalidDocument)
}

// Parses one canonical placement identity.
fn parse_placement_id(value: &str) -> Result<PlacementId, NodeProtectionTransportError> {
    PlacementId::parse(value).map_err(|_| NodeProtectionTransportError::InvalidDocument)
}

// Parses one canonical Core installation identity.
fn parse_installation_id(value: &str) -> Result<InstallationId, NodeProtectionTransportError> {
    InstallationId::parse(value).map_err(|_| NodeProtectionTransportError::InvalidDocument)
}

// Parses one canonical SHA-256 identity.
fn parse_digest(value: &str) -> Result<Sha256Digest, NodeProtectionTransportError> {
    Sha256Digest::parse(value).map_err(|_| NodeProtectionTransportError::InvalidDocument)
}

// Converts one required nonzero scalar.
fn nonzero(value: u64) -> Result<NonZeroU64, NodeProtectionTransportError> {
    NonZeroU64::new(value).ok_or(NodeProtectionTransportError::InvalidDocument)
}

// Maps one internal API failure to the closed redacted wire vocabulary.
fn remote_error(error: NodeProtectionApiError) -> NodeProtectionRemoteError {
    match error {
        NodeProtectionApiError::AuthorizationDenied => {
            NodeProtectionRemoteError::AuthorizationDenied
        }
        NodeProtectionApiError::InvalidContract => NodeProtectionRemoteError::InvalidContract,
        NodeProtectionApiError::Conflict => NodeProtectionRemoteError::Conflict,
        NodeProtectionApiError::Corrupt => NodeProtectionRemoteError::Corrupt,
        NodeProtectionApiError::ProviderUnavailable => {
            NodeProtectionRemoteError::ProviderUnavailable
        }
    }
}

// Returns the stable wire name for one redacted remote failure.
fn remote_error_name(error: NodeProtectionRemoteError) -> &'static str {
    match error {
        NodeProtectionRemoteError::AuthorizationDenied => "authorization_denied",
        NodeProtectionRemoteError::InvalidContract => "invalid_contract",
        NodeProtectionRemoteError::Conflict => "conflict",
        NodeProtectionRemoteError::Corrupt => "corrupt",
        NodeProtectionRemoteError::ProviderUnavailable => "provider_unavailable",
    }
}

// Reconstructs one redacted remote failure from its closed wire name.
fn remote_error_from_name(
    value: &str,
) -> Result<NodeProtectionRemoteError, NodeProtectionTransportError> {
    match value {
        "authorization_denied" => Ok(NodeProtectionRemoteError::AuthorizationDenied),
        "invalid_contract" => Ok(NodeProtectionRemoteError::InvalidContract),
        "conflict" => Ok(NodeProtectionRemoteError::Conflict),
        "corrupt" => Ok(NodeProtectionRemoteError::Corrupt),
        "provider_unavailable" => Ok(NodeProtectionRemoteError::ProviderUnavailable),
        _ => Err(NodeProtectionTransportError::InvalidDocument),
    }
}
