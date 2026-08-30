// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};

use li_authentication_manager::ApiKeyLimits;
use li_core_interface::{
    ApiKeyId, EndpointAddress, LogicalModelName, NodeAddress, NodeId, PlacementGroupId,
    Sha256Digest, UnixMilliseconds,
};

use crate::GatewayError;

const MAX_PREFIX_KEYS: usize = 4096;
const MAX_QUEUE_MILLISECONDS: u64 = 5 * 60 * 1_000;

// Selects whether this gateway exposes public inference or a private child relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayMode {
    Main {
        local_node_id: NodeId,
    },
    Child {
        local_node_id: NodeId,
        main_node_id: NodeId,
    },
}

impl GatewayMode {
    // Returns the node on which this gateway runs.
    pub const fn local_node_id(&self) -> &NodeId {
        match self {
            Self::Main { local_node_id } | Self::Child { local_node_id, .. } => local_node_id,
        }
    }

    // Returns the only main authorized to relay into a child gateway.
    pub const fn main_node_id(&self) -> Option<&NodeId> {
        match self {
            Self::Main { .. } => None,
            Self::Child { main_node_id, .. } => Some(main_node_id),
        }
    }
}

// Describes whether one placement endpoint is local or reached through a child relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayRouteTarget {
    LocalEngine { endpoint: EndpointAddress },
    ChildRelay { address: NodeAddress },
}

// Describes one current routable placement-group endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRoute {
    placement_group_id: PlacementGroupId,
    endpoint_node_id: NodeId,
    model: LogicalModelName,
    target: GatewayRouteTarget,
    max_active_requests: NonZeroU32,
    max_context_tokens: NonZeroU64,
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<u32>,
    prefix_keys: Vec<Sha256Digest>,
}

impl GatewayRoute {
    // Creates one complete placement-group route without judging current capacity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placement_group_id: PlacementGroupId,
        endpoint_node_id: NodeId,
        model: LogicalModelName,
        target: GatewayRouteTarget,
        max_active_requests: NonZeroU32,
        max_context_tokens: NonZeroU64,
        healthy: bool,
        memory_pressure: bool,
        temperature_millicelsius: Option<u32>,
        mut prefix_keys: Vec<Sha256Digest>,
    ) -> Result<Self, GatewayError> {
        if prefix_keys.len() > MAX_PREFIX_KEYS
            || temperature_millicelsius.is_some_and(|temperature| temperature > 250_000)
        {
            return Err(GatewayError::InvalidContract {
                reason: "gateway route exceeds the prefix-key or temperature bound",
            });
        }
        prefix_keys.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        if prefix_keys.windows(2).any(|values| values[0] == values[1]) {
            return Err(GatewayError::InvalidContract {
                reason: "gateway route contains duplicate prefix keys",
            });
        }
        Ok(Self {
            placement_group_id,
            endpoint_node_id,
            model,
            target,
            max_active_requests,
            max_context_tokens,
            healthy,
            memory_pressure,
            temperature_millicelsius,
            prefix_keys,
        })
    }

    // Returns the atomic placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the node that owns the group endpoint.
    pub const fn endpoint_node_id(&self) -> &NodeId {
        &self.endpoint_node_id
    }

    // Returns the exact routed logical model.
    pub const fn model(&self) -> &LogicalModelName {
        &self.model
    }

    // Returns the local Engine or authenticated child-relay target.
    pub const fn target(&self) -> &GatewayRouteTarget {
        &self.target
    }

    // Returns the declared concurrent-request capacity.
    pub const fn max_active_requests(&self) -> NonZeroU32 {
        self.max_active_requests
    }

    // Returns the exact maximum context capacity.
    pub const fn max_context_tokens(&self) -> NonZeroU64 {
        self.max_context_tokens
    }

    // Returns whether current placement and topology health are routable.
    pub const fn is_healthy(&self) -> bool {
        self.healthy
    }

    // Returns whether current hardware pressure blocks new admission.
    pub const fn has_memory_pressure(&self) -> bool {
        self.memory_pressure
    }

    // Returns the latest bounded endpoint temperature when available.
    pub const fn temperature_millicelsius(&self) -> Option<u32> {
        self.temperature_millicelsius
    }

    // Returns exact prefix identities already local to this placement group.
    pub fn prefix_keys(&self) -> &[Sha256Digest] {
        &self.prefix_keys
    }
}

// Describes one fully token-counted inference request before admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequest {
    request_id: Sha256Digest,
    model: LogicalModelName,
    context_tokens: NonZeroU64,
    maximum_output_tokens: NonZeroU64,
    prefix_key: Option<Sha256Digest>,
    maximum_queue_milliseconds: u64,
}

impl GatewayRequest {
    // Creates one exact request after token counting and client-policy normalization.
    pub fn new(
        request_id: Sha256Digest,
        model: LogicalModelName,
        context_tokens: NonZeroU64,
        maximum_output_tokens: NonZeroU64,
        prefix_key: Option<Sha256Digest>,
        maximum_queue_milliseconds: u64,
    ) -> Result<Self, GatewayError> {
        if maximum_queue_milliseconds > MAX_QUEUE_MILLISECONDS
            || context_tokens
                .get()
                .checked_add(maximum_output_tokens.get())
                .is_none()
        {
            return Err(GatewayError::InvalidContract {
                reason: "gateway request queue or token demand exceeds its bound",
            });
        }
        Ok(Self {
            request_id,
            model,
            context_tokens,
            maximum_output_tokens,
            prefix_key,
            maximum_queue_milliseconds,
        })
    }

    // Returns the caller's immutable request identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the exact logical model selected before routing.
    pub const fn model(&self) -> &LogicalModelName {
        &self.model
    }

    // Returns exact rendered context tokens.
    pub const fn context_tokens(&self) -> NonZeroU64 {
        self.context_tokens
    }

    // Returns the maximum completion-token reservation.
    pub const fn maximum_output_tokens(&self) -> NonZeroU64 {
        self.maximum_output_tokens
    }

    // Returns the total worst-case token demand.
    pub fn token_demand(&self) -> u64 {
        self.context_tokens.get() + self.maximum_output_tokens.get()
    }

    // Returns an exact reusable-prefix identity when supplied.
    pub const fn prefix_key(&self) -> Option<&Sha256Digest> {
        self.prefix_key.as_ref()
    }

    // Returns the bounded time this request may remain queued.
    pub const fn maximum_queue_milliseconds(&self) -> u64 {
        self.maximum_queue_milliseconds
    }
}

// Carries verified durable API-key policy into live Gateway enforcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPrincipal {
    key_id: ApiKeyId,
    limits: ApiKeyLimits,
}

impl GatewayPrincipal {
    // Creates one verified principal projection without bearer material.
    pub const fn new(key_id: ApiKeyId, limits: ApiKeyLimits) -> Self {
        Self { key_id, limits }
    }

    // Returns the durable API-key identity.
    pub const fn key_id(&self) -> &ApiKeyId {
        &self.key_id
    }

    // Returns the configured limits enforced by live Gateway counters.
    pub const fn limits(&self) -> ApiKeyLimits {
        self.limits
    }
}

// Records one completed request for durable rolling-window reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayUsageRecord {
    request_id: Sha256Digest,
    key_id: ApiKeyId,
    received_at: UnixMilliseconds,
    completed_at: UnixMilliseconds,
    tokens: u64,
}

impl GatewayUsageRecord {
    // Creates one coherent completed usage record.
    pub fn new(
        request_id: Sha256Digest,
        key_id: ApiKeyId,
        received_at: UnixMilliseconds,
        completed_at: UnixMilliseconds,
        tokens: u64,
    ) -> Result<Self, GatewayError> {
        if completed_at.value() < received_at.value() {
            return Err(GatewayError::InvalidContract {
                reason: "gateway usage completion precedes receipt",
            });
        }
        Ok(Self {
            request_id,
            key_id,
            received_at,
            completed_at,
            tokens,
        })
    }

    // Returns the immutable request identity used for idempotent persistence.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the API-key identity that consumed capacity.
    pub const fn key_id(&self) -> &ApiKeyId {
        &self.key_id
    }

    // Returns when request admission began.
    pub const fn received_at(&self) -> UnixMilliseconds {
        self.received_at
    }

    // Returns when the request reached a terminal outcome.
    pub const fn completed_at(&self) -> UnixMilliseconds {
        self.completed_at
    }

    // Returns exact input plus output tokens recorded for the rolling window.
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }
}

// Authenticates public bearer material and returns current durable policy.
pub trait GatewayAuthenticationProvider: Send + Sync {
    // Verifies one bearer token for one exact logical model.
    fn authenticate(
        &self,
        bearer_token: &str,
        model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError>;
}

// Authenticates one main-node relay into a child gateway.
pub trait GatewayRelayAuthorizationProvider: Send + Sync {
    // Returns the exact main identity bound to one private relay credential.
    fn authorize(&self, relay_credential: &str) -> Result<NodeId, GatewayError>;
}

// Supplies current placement-group routes without deciding Gateway policy.
pub trait GatewayRouteProvider: Send + Sync {
    // Returns current candidate routes for one logical model.
    fn routes(&self, model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError>;
}

// Supplies time explicitly for quotas, queues, metrics, and deterministic tests.
pub trait GatewayClock: Send + Sync {
    // Returns current non-negative Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, GatewayError>;
}

// Persists bounded completed usage without owning live admission counters.
pub trait GatewayUsageStore: Send + Sync {
    // Returns completed records at or after the supplied rolling-window boundary.
    fn recent(
        &self,
        key_id: &ApiKeyId,
        since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError>;

    // Appends one completed secret-free request usage record.
    fn record(&self, usage: &GatewayUsageRecord) -> Result<(), GatewayError>;
}

// Proves ownership of one active placement-group and live quota reservation.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "gateway reservations must be completed or cancelled"]
pub struct GatewayReservation {
    pub(crate) request: GatewayRequest,
    pub(crate) route: GatewayRoute,
    pub(crate) principal: Option<GatewayPrincipal>,
    pub(crate) received_at: UnixMilliseconds,
    pub(crate) queued_milliseconds: u64,
    pub(crate) reserved_tokens: u64,
}

impl GatewayReservation {
    // Returns the exact admitted request.
    pub const fn request(&self) -> &GatewayRequest {
        &self.request
    }

    // Returns the selected atomic placement-group route.
    pub const fn route(&self) -> &GatewayRoute {
        &self.route
    }

    // Returns how long this request waited for capacity.
    pub const fn queued_milliseconds(&self) -> u64 {
        self.queued_milliseconds
    }
}

// Identifies one live FIFO queue entry without retaining bearer material.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "gateway queue tickets must be polled or cancelled"]
pub struct GatewayQueueTicket {
    request_id: Sha256Digest,
}

impl GatewayQueueTicket {
    // Creates one queue ticket from the immutable request identity.
    pub(crate) const fn new(request_id: Sha256Digest) -> Self {
        Self { request_id }
    }

    // Returns the queued request identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }
}

// Describes immediate admission or durable in-memory queue ownership.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "gateway admission owns live request capacity"]
pub enum GatewayAdmission {
    Admitted(GatewayReservation),
    Queued(GatewayQueueTicket),
}

// Describes one queue poll without blocking the caller thread.
#[derive(Debug, Eq, PartialEq)]
pub enum GatewayQueueStatus {
    Waiting,
    Admitted(GatewayReservation),
}
