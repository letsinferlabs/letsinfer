// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{
    CredentialId, InstallationId, NodeId, PlacementGroupId, Sha256Digest, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayError, GatewayPlacementProtectionSnapshot, GatewayProtectionAuthority,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogProtectionCycle, WatchdogProtocolSiteStatus,
};

use crate::{
    DatabaseNodeProtectionSessionGenerationStore, NodeGatewayProtectionLeaseProvider,
    NodeProtectionBindingProvider, NodeProtectionLeaseError, NodeProtectionLeaseStore,
    NodeProtectionSessionGenerationError,
};

const MAXIMUM_LEASE_MILLISECONDS: u64 = 60_000;

// Identifies the six narrow capabilities on the authenticated protection channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionAction {
    BeginWatchdogSession,
    CommitWatchdogCycle,
    EndWatchdogSession,
    ResolveControllerBinding,
    ReadSiteStatus,
    ReadGatewaySnapshot,
}

// Authorizes one already-authenticated peer before any protection state is read or mutated.
pub trait NodeProtectionAuthorizationProvider: Send + Sync {
    // Requires the exact principal, action, and local Node identity.
    fn authorize(
        &self,
        principal_id: &CredentialId,
        action: NodeProtectionAction,
        node_id: &NodeId,
    ) -> Result<(), NodeProtectionApiError>;
}

// Supplies Node time explicitly for restart and stale-cycle tests.
pub trait NodeProtectionClock: Send + Sync {
    // Returns the current non-negative Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, NodeProtectionApiError>;
}

// Reads host Unix time for ordinary Node protection dispatch.
#[derive(Default)]
pub struct SystemNodeProtectionClock;

impl NodeProtectionClock for SystemNodeProtectionClock {
    // Returns current host time without accepting a pre-epoch clock.
    fn now(&self) -> Result<UnixMilliseconds, NodeProtectionApiError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        let milliseconds = u64::try_from(duration.as_millis())
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Supplies one Node-owned group snapshot without exposing Gateway to the database.
pub trait NodeProtectionSnapshotProvider: Send + Sync {
    // Returns the exact current snapshot or absence when any required protection is unavailable.
    fn snapshot_for_group(
        &self,
        placement_group_id: &PlacementGroupId,
        endpoint_node_id: &NodeId,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError>;
}

// Resolves an authenticated controller leaf without exposing session persistence to the IPC API.
pub trait NodeProtectionControllerBindingProvider: Send + Sync {
    // Returns one exact active process-bound controller or a stable redacted API failure.
    fn resolve(
        &self,
        certificate_sha256: &Sha256Digest,
    ) -> Result<WatchdogControllerBinding, NodeProtectionApiError>;
}

// Revalidates one controller binding and returns only the established public status projection.
pub trait NodeProtectionSiteStatusProvider: Send + Sync {
    // Returns current public site status or one stable redacted API failure.
    fn status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, NodeProtectionApiError>;
}

impl NodeProtectionSnapshotProvider for NodeGatewayProtectionLeaseProvider {
    // Uses the existing Node-owned placement, process, and session projection.
    fn snapshot_for_group(
        &self,
        placement_group_id: &PlacementGroupId,
        endpoint_node_id: &NodeId,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        self.snapshot_for_group(placement_group_id, endpoint_node_id)
    }
}

// Requests one durable restart-safe Watchdog protection session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionBeginRequest {
    idempotency_key: String,
    node_id: NodeId,
    core_installation_id: InstallationId,
    watchdog_source_identity: Sha256Digest,
    watchdog_session_nonce: Sha256Digest,
    minimum_sample_sequence: NonZeroU64,
}

impl NodeProtectionBeginRequest {
    // Creates one exact begin request after wire values are parsed and bounded.
    pub fn new(
        idempotency_key: &str,
        node_id: NodeId,
        core_installation_id: InstallationId,
        watchdog_source_identity: Sha256Digest,
        watchdog_session_nonce: Sha256Digest,
        minimum_sample_sequence: NonZeroU64,
    ) -> Result<Self, NodeProtectionApiError> {
        if !valid_idempotency_key(idempotency_key) {
            return Err(NodeProtectionApiError::InvalidContract);
        }
        Ok(Self {
            idempotency_key: idempotency_key.to_string(),
            node_id,
            core_installation_id,
            watchdog_source_identity,
            watchdog_session_nonce,
            minimum_sample_sequence,
        })
    }

    // Returns the caller-owned idempotency identity.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the exact local Node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact Core installation identity.
    pub const fn core_installation_id(&self) -> &InstallationId {
        &self.core_installation_id
    }

    // Returns the immutable Watchdog/Core source identity.
    pub const fn watchdog_source_identity(&self) -> &Sha256Digest {
        &self.watchdog_source_identity
    }

    // Returns the authenticated resident's fresh session nonce.
    pub const fn watchdog_session_nonce(&self) -> &Sha256Digest {
        &self.watchdog_session_nonce
    }

    // Returns the first durable sample sequence allowed for this resident session.
    pub const fn minimum_sample_sequence(&self) -> NonZeroU64 {
        self.minimum_sample_sequence
    }
}

// Submits one complete authenticated Watchdog cycle to the Node-owned lease store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionCommitRequest {
    node_id: NodeId,
    watchdog_session_id: Sha256Digest,
    watchdog_session_generation: NonZeroU64,
    cycle: WatchdogProtectionCycle,
}

impl NodeProtectionCommitRequest {
    // Creates one exact completed-cycle request.
    pub const fn new(
        node_id: NodeId,
        watchdog_session_id: Sha256Digest,
        watchdog_session_generation: NonZeroU64,
        cycle: WatchdogProtectionCycle,
    ) -> Self {
        Self {
            node_id,
            watchdog_session_id,
            watchdog_session_generation,
            cycle,
        }
    }

    // Returns the Node protected by this cycle.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact authenticated Watchdog session identity.
    pub const fn watchdog_session_id(&self) -> &Sha256Digest {
        &self.watchdog_session_id
    }

    // Returns the durable Node-owned session generation.
    pub const fn watchdog_session_generation(&self) -> NonZeroU64 {
        self.watchdog_session_generation
    }

    // Returns the receipt created only by one complete successful Watchdog cycle.
    pub const fn cycle(&self) -> &WatchdogProtectionCycle {
        &self.cycle
    }
}

// Ends one exact Watchdog session without affecting a replacement or sibling Node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionEndRequest {
    node_id: NodeId,
    watchdog_session_id: Sha256Digest,
    watchdog_session_generation: NonZeroU64,
}

impl NodeProtectionEndRequest {
    // Creates one exact terminal session request.
    pub const fn new(
        node_id: NodeId,
        watchdog_session_id: Sha256Digest,
        watchdog_session_generation: NonZeroU64,
    ) -> Self {
        Self {
            node_id,
            watchdog_session_id,
            watchdog_session_generation,
        }
    }

    // Returns the Node whose exact session ended.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact authenticated session identity.
    pub const fn watchdog_session_id(&self) -> &Sha256Digest {
        &self.watchdog_session_id
    }

    // Returns the exact durable session generation.
    pub const fn watchdog_session_generation(&self) -> NonZeroU64 {
        self.watchdog_session_generation
    }
}

// Selects one exact placement group for a Gateway safety poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionSnapshotRequest {
    node_id: NodeId,
    placement_group_id: PlacementGroupId,
    endpoint_node_id: NodeId,
}

impl NodeProtectionSnapshotRequest {
    // Creates one explicit snapshot request without inferring an active group.
    pub const fn new(
        node_id: NodeId,
        placement_group_id: PlacementGroupId,
        endpoint_node_id: NodeId,
    ) -> Self {
        Self {
            node_id,
            placement_group_id,
            endpoint_node_id,
        }
    }

    // Returns the Node API authority receiving this poll.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact atomic placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the Node that owns the selected group endpoint.
    pub const fn endpoint_node_id(&self) -> &NodeId {
        &self.endpoint_node_id
    }
}

// Selects one exact authenticated controller certificate for Watchdog session resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionResolveControllerBindingRequest {
    certificate_sha256: Sha256Digest,
}

impl NodeProtectionResolveControllerBindingRequest {
    // Creates one resolution request from an already validated certificate identity.
    pub const fn new(certificate_sha256: Sha256Digest) -> Self {
        Self { certificate_sha256 }
    }

    // Returns the exact authenticated controller certificate identity.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }
}

// Selects one exact process-bound controller session for current public site status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionReadSiteStatusRequest {
    binding: WatchdogControllerBinding,
}

impl NodeProtectionReadSiteStatusRequest {
    // Creates one status request from a fully validated controller binding.
    pub const fn new(binding: WatchdogControllerBinding) -> Self {
        Self { binding }
    }

    // Returns the exact controller and protected-process binding to revalidate.
    pub const fn binding(&self) -> &WatchdogControllerBinding {
        &self.binding
    }
}

// Describes one closed authenticated protection operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeProtectionRequest {
    BeginWatchdogSession(NodeProtectionBeginRequest),
    CommitWatchdogCycle(NodeProtectionCommitRequest),
    EndWatchdogSession(NodeProtectionEndRequest),
    ResolveControllerBinding(NodeProtectionResolveControllerBindingRequest),
    ReadSiteStatus(NodeProtectionReadSiteStatusRequest),
    ReadGatewaySnapshot(NodeProtectionSnapshotRequest),
}

impl NodeProtectionRequest {
    // Returns the exact authorization capability and local Node named by this request.
    fn authorization<'a>(
        &'a self,
        local_node_id: &'a NodeId,
    ) -> (NodeProtectionAction, &'a NodeId) {
        match self {
            Self::BeginWatchdogSession(request) => (
                NodeProtectionAction::BeginWatchdogSession,
                request.node_id(),
            ),
            Self::CommitWatchdogCycle(request) => {
                (NodeProtectionAction::CommitWatchdogCycle, request.node_id())
            }
            Self::EndWatchdogSession(request) => {
                (NodeProtectionAction::EndWatchdogSession, request.node_id())
            }
            Self::ResolveControllerBinding(_) => (
                NodeProtectionAction::ResolveControllerBinding,
                local_node_id,
            ),
            Self::ReadSiteStatus(_) => (NodeProtectionAction::ReadSiteStatus, local_node_id),
            Self::ReadGatewaySnapshot(request) => {
                (NodeProtectionAction::ReadGatewaySnapshot, request.node_id())
            }
        }
    }
}

// Returns one typed result without exposing DatabaseManager or placement internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeProtectionResponse {
    WatchdogSessionBegan(GatewayProtectionAuthority),
    WatchdogCycleCommitted { lease_count: usize },
    WatchdogSessionEnded,
    ControllerBinding(WatchdogControllerBinding),
    SiteStatus(WatchdogProtocolSiteStatus),
    GatewaySnapshot(Option<GatewayPlacementProtectionSnapshot>),
}

// Names stable authenticated protection API failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionApiError {
    AuthorizationDenied,
    InvalidContract,
    Conflict,
    Corrupt,
    ProviderUnavailable,
}

impl fmt::Display for NodeProtectionApiError {
    // Presents fixed redacted failure language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorizationDenied => formatter.write_str("protection action is denied"),
            Self::InvalidContract => formatter.write_str("protection request is invalid"),
            Self::Conflict => formatter.write_str("protection state changed concurrently"),
            Self::Corrupt => formatter.write_str("protection state is corrupt"),
            Self::ProviderUnavailable => formatter.write_str("protection provider is unavailable"),
        }
    }
}

impl Error for NodeProtectionApiError {}

// Owns authenticated Node dispatch while NodeManager retains persistence and lifecycle ownership.
pub struct NodeProtectionApi {
    local_node_id: NodeId,
    core_installation_id: InstallationId,
    watchdog_source_identity: Sha256Digest,
    authorization: Arc<dyn NodeProtectionAuthorizationProvider>,
    clock: Arc<dyn NodeProtectionClock>,
    generations: Arc<DatabaseNodeProtectionSessionGenerationStore>,
    leases: Arc<NodeProtectionLeaseStore>,
    bindings: Arc<dyn NodeProtectionBindingProvider>,
    snapshots: Arc<dyn NodeProtectionSnapshotProvider>,
    watchdog_sessions: Option<Arc<dyn NodeProtectionControllerBindingProvider>>,
    watchdog_identity: Option<Arc<dyn NodeProtectionSiteStatusProvider>>,
    lease_milliseconds: u64,
    lifecycle: Mutex<NodeProtectionLifecycleState>,
}

// Serializes begin and end so durable retirement cannot race an ephemeral reopen.
#[derive(Default)]
struct NodeProtectionLifecycleState {
    retirement_failed: bool,
}

impl NodeProtectionApi {
    // Creates one Node-owned protection dispatcher from explicit narrow capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_node_id: NodeId,
        core_installation_id: InstallationId,
        watchdog_source_identity: Sha256Digest,
        authorization: Arc<dyn NodeProtectionAuthorizationProvider>,
        clock: Arc<dyn NodeProtectionClock>,
        generations: Arc<DatabaseNodeProtectionSessionGenerationStore>,
        leases: Arc<NodeProtectionLeaseStore>,
        bindings: Arc<dyn NodeProtectionBindingProvider>,
        snapshots: Arc<dyn NodeProtectionSnapshotProvider>,
        lease_milliseconds: u64,
    ) -> Result<Self, NodeProtectionApiError> {
        if lease_milliseconds == 0 || lease_milliseconds > MAXIMUM_LEASE_MILLISECONDS {
            return Err(NodeProtectionApiError::InvalidContract);
        }
        generations
            .recover(&local_node_id)
            .map_err(generation_error)?;
        Ok(Self {
            local_node_id,
            core_installation_id,
            watchdog_source_identity,
            authorization,
            clock,
            generations,
            leases,
            bindings,
            snapshots,
            watchdog_sessions: None,
            watchdog_identity: None,
            lease_milliseconds,
            lifecycle: Mutex::new(NodeProtectionLifecycleState::default()),
        })
    }

    // Adds Watchdog protocol reads without transferring their persistence or identity ownership.
    pub fn with_watchdog_protocol(
        mut self,
        sessions: Arc<dyn NodeProtectionControllerBindingProvider>,
        identity: Arc<dyn NodeProtectionSiteStatusProvider>,
    ) -> Self {
        self.watchdog_sessions = Some(sessions);
        self.watchdog_identity = Some(identity);
        self
    }

    // Authorizes first and then dispatches one exact protection-channel operation.
    pub fn dispatch(
        &self,
        principal_id: &CredentialId,
        request: NodeProtectionRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        let (action, node_id) = request.authorization(&self.local_node_id);
        self.authorization
            .authorize(principal_id, action, node_id)?;
        if node_id != &self.local_node_id {
            return Err(NodeProtectionApiError::AuthorizationDenied);
        }
        match request {
            NodeProtectionRequest::BeginWatchdogSession(request) => self.begin(request),
            NodeProtectionRequest::CommitWatchdogCycle(request) => self.commit(request),
            NodeProtectionRequest::EndWatchdogSession(request) => self.end(request),
            NodeProtectionRequest::ResolveControllerBinding(request) => {
                self.resolve_controller_binding(request)
            }
            NodeProtectionRequest::ReadSiteStatus(request) => self.read_site_status(request),
            NodeProtectionRequest::ReadGatewaySnapshot(request) => self.snapshot(request),
        }
    }

    // Allocates one durable generation before opening the corresponding ephemeral session.
    fn begin(
        &self,
        request: NodeProtectionBeginRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        if lifecycle.retirement_failed {
            return Err(NodeProtectionApiError::ProviderUnavailable);
        }
        if request.core_installation_id() != &self.core_installation_id
            || request.watchdog_source_identity() != &self.watchdog_source_identity
        {
            return Err(NodeProtectionApiError::AuthorizationDenied);
        }
        let authority = self
            .generations
            .allocate(
                request.idempotency_key(),
                request.node_id(),
                request.core_installation_id(),
                request.watchdog_source_identity(),
                request.watchdog_session_nonce(),
            )
            .map_err(generation_error)?;
        self.leases
            .begin_watchdog_session(
                authority.clone(),
                self.clock.now()?,
                request.minimum_sample_sequence(),
            )
            .map_err(lease_error)?;
        Ok(NodeProtectionResponse::WatchdogSessionBegan(authority))
    }

    // Resolves current placement bindings and commits only one complete authenticated cycle.
    fn commit(
        &self,
        request: NodeProtectionCommitRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        let bindings = self
            .bindings
            .bindings_for_cycle(request.node_id(), request.cycle())
            .map_err(lease_error)?;
        let leases = self
            .leases
            .commit_protection_cycle(
                request.node_id(),
                request.watchdog_session_id(),
                request.watchdog_session_generation(),
                request.cycle(),
                &bindings,
                self.lease_milliseconds,
            )
            .map_err(lease_error)?;
        Ok(NodeProtectionResponse::WatchdogCycleCommitted {
            lease_count: leases.len(),
        })
    }

    // Invalidates one exact disconnected session immediately.
    fn end(
        &self,
        request: NodeProtectionEndRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        let lease_result = self.leases.end_watchdog_session(
            request.node_id(),
            request.watchdog_session_id(),
            request.watchdog_session_generation(),
        );
        let authority = GatewayProtectionAuthority::new(
            request.node_id().clone(),
            self.core_installation_id.clone(),
            self.watchdog_source_identity.clone(),
            request.watchdog_session_id().clone(),
            request.watchdog_session_generation(),
        );
        let retirement = self
            .generations
            .retire(&end_idempotency_key(&authority), &authority);
        if let Err(error) = retirement {
            lifecycle.retirement_failed = true;
            return Err(generation_error(error));
        }
        lifecycle.retirement_failed = false;
        if let Err(error) = lease_result {
            if error != NodeProtectionLeaseError::SessionUnavailable {
                return Err(lease_error(error));
            }
        }
        Ok(NodeProtectionResponse::WatchdogSessionEnded)
    }

    // Resolves one controller leaf only through the injected Watchdog session authority.
    fn resolve_controller_binding(
        &self,
        request: NodeProtectionResolveControllerBindingRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        self.watchdog_sessions
            .as_ref()
            .ok_or(NodeProtectionApiError::ProviderUnavailable)?
            .resolve(request.certificate_sha256())
            .map(NodeProtectionResponse::ControllerBinding)
    }

    // Reads public status only after the injected identity provider revalidates the full binding.
    fn read_site_status(
        &self,
        request: NodeProtectionReadSiteStatusRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        self.watchdog_identity
            .as_ref()
            .ok_or(NodeProtectionApiError::ProviderUnavailable)?
            .status(request.binding())
            .map(NodeProtectionResponse::SiteStatus)
    }

    // Returns the fail-closed Node-owned snapshot for one exact Gateway route identity.
    fn snapshot(
        &self,
        request: NodeProtectionSnapshotRequest,
    ) -> Result<NodeProtectionResponse, NodeProtectionApiError> {
        self.snapshots
            .snapshot_for_group(request.placement_group_id(), request.endpoint_node_id())
            .map(NodeProtectionResponse::GatewaySnapshot)
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)
    }
}

// Rejects empty, oversized, or control-bearing replay identities before persistence.
fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.chars().any(|character| character.is_control())
}

// Derives one stable redacted retirement key for exact disconnect retries.
fn end_idempotency_key(authority: &GatewayProtectionAuthority) -> String {
    format!(
        "li_node_protection_end_{}_{}",
        authority.node_id().as_str(),
        authority.watchdog_session_generation()
    )
}

// Maps durable-generation failures into the stable authenticated API vocabulary.
fn generation_error(error: NodeProtectionSessionGenerationError) -> NodeProtectionApiError {
    match error {
        NodeProtectionSessionGenerationError::Conflict => NodeProtectionApiError::Conflict,
        NodeProtectionSessionGenerationError::Corrupt => NodeProtectionApiError::Corrupt,
        NodeProtectionSessionGenerationError::StoreUnavailable => {
            NodeProtectionApiError::ProviderUnavailable
        }
    }
}

// Maps ephemeral lease failures without exposing process identities.
fn lease_error(error: NodeProtectionLeaseError) -> NodeProtectionApiError {
    match error {
        NodeProtectionLeaseError::InvalidContract => NodeProtectionApiError::InvalidContract,
        NodeProtectionLeaseError::SessionUnavailable => NodeProtectionApiError::AuthorizationDenied,
        NodeProtectionLeaseError::RegressedCycle => NodeProtectionApiError::Conflict,
        NodeProtectionLeaseError::StateUnavailable => NodeProtectionApiError::ProviderUnavailable,
    }
}
