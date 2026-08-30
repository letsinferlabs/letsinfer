// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_authentication_manager::ApiKeyModelScope;
use li_core_interface::{
    ApiKeyId, LogicalModelName, NodeId, NodeRole, Placement, PlacementGroupId, PlacementId,
    Sha256Digest, UnixMilliseconds,
};
use li_gateway_manager::{GatewayNativeTarget, GatewayPrincipal, GatewayRoute, GatewayUsageRecord};

pub const NODE_GATEWAY_MAXIMUM_BEARER_BYTES: usize = 512;
pub const NODE_GATEWAY_MAXIMUM_ROUTES: usize = 1_024;
pub const NODE_GATEWAY_MAXIMUM_USAGE_RECORDS: usize = 4_096;
pub const NODE_GATEWAY_MAXIMUM_MACOS_PLACEMENTS: usize = 1_024;

// Carries bounded bearer material without exposing it through ordinary debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeGatewayBearer(String);

impl NodeGatewayBearer {
    // Creates one bounded single-line bearer value at the local IPC boundary.
    pub fn parse(value: &str) -> Result<Self, NodeGatewayApiError> {
        if value.is_empty()
            || value.len() > NODE_GATEWAY_MAXIMUM_BEARER_BYTES
            || value.chars().any(char::is_whitespace)
            || value.chars().any(char::is_control)
        {
            return Err(NodeGatewayApiError::InvalidContract);
        }
        Ok(Self(value.to_string()))
    }

    // Returns bearer material only to the exact injected authorization capability.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NodeGatewayBearer {
    // Redacts bearer material from test, error, and process debug output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NodeGatewayBearer([REDACTED])")
    }
}

// Binds one macOS placement to the launch plan committed by PlacementManager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGatewayMacOsPlacement {
    placement: Placement,
    launch_plan_identity: Sha256Digest,
}

impl NodeGatewayMacOsPlacement {
    // Creates one exact placement and committed launch-plan binding.
    pub const fn new(placement: Placement, launch_plan_identity: Sha256Digest) -> Self {
        Self {
            placement,
            launch_plan_identity,
        }
    }

    // Returns the complete placement consumed by native launch-plan observation.
    pub const fn placement(&self) -> &Placement {
        &self.placement
    }

    // Returns the immutable launch-plan identity committed for this placement.
    pub const fn launch_plan_identity(&self) -> &Sha256Digest {
        &self.launch_plan_identity
    }
}

// Carries the complete bounded macOS input needed to observe one placement group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGatewayMacOsSafetyInput {
    placement_group_id: PlacementGroupId,
    placements: Vec<NodeGatewayMacOsPlacement>,
}

impl NodeGatewayMacOsSafetyInput {
    // Creates one nonempty exact group projection without a generic database snapshot.
    pub fn new(
        placement_group_id: PlacementGroupId,
        placements: Vec<NodeGatewayMacOsPlacement>,
    ) -> Result<Self, NodeGatewayApiError> {
        if placements.is_empty()
            || placements.len() > NODE_GATEWAY_MAXIMUM_MACOS_PLACEMENTS
            || placements
                .iter()
                .any(|value| value.placement().placement_group_id() != &placement_group_id)
            || has_duplicate_placement_identities(&placements)
        {
            return Err(NodeGatewayApiError::InvalidContract);
        }
        Ok(Self {
            placement_group_id,
            placements,
        })
    }

    // Returns the exact placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns every exact placement and committed launch-plan binding.
    pub fn placements(&self) -> &[NodeGatewayMacOsPlacement] {
        &self.placements
    }
}

// Describes whether one idempotent usage write was new or an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeGatewayUsageDisposition {
    Applied,
    Replayed,
}

// Describes one exact Gateway capability request nested under the local Node API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeGatewayRequest {
    AuthorizeInference {
        bearer: NodeGatewayBearer,
        model: LogicalModelName,
    },
    AuthorizeModelList {
        bearer: NodeGatewayBearer,
    },
    ReadRoutes {
        model: LogicalModelName,
    },
    ResolveNativeTarget {
        route: GatewayRoute,
    },
    AuthorizeInboundRelay {
        bearer: NodeGatewayBearer,
    },
    ReadRecentUsage {
        key_id: ApiKeyId,
        since: UnixMilliseconds,
    },
    RecordUsage {
        usage: GatewayUsageRecord,
    },
    ReadMacOsSafetyInput {
        placement_group_id: PlacementGroupId,
    },
}

// Returns one closed typed result for an exact Gateway capability request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeGatewayResponse {
    Principal(GatewayPrincipal),
    ModelScope(ApiKeyModelScope),
    Routes(Vec<GatewayRoute>),
    NativeTarget(GatewayNativeTarget),
    RelayPrincipal(NodeId),
    UsageRecords(Vec<GatewayUsageRecord>),
    UsageRecorded(NodeGatewayUsageDisposition),
    MacOsSafetyInput(NodeGatewayMacOsSafetyInput),
}

// Describes one stable local Gateway capability failure without provider detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeGatewayApiError {
    AuthorizationDenied,
    RoleDenied,
    InvalidContract,
    ReplayConflict,
    CorruptState,
    Unavailable,
}

impl fmt::Display for NodeGatewayApiError {
    // Presents stable redacted language for the local Node transport.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorizationDenied => "Gateway authorization is denied",
            Self::RoleDenied => "Gateway capability is unavailable for this node role",
            Self::InvalidContract => "Gateway capability contract is invalid",
            Self::ReplayConflict => "Gateway capability replay conflicts with committed state",
            Self::CorruptState => "Gateway capability state is corrupt",
            Self::Unavailable => "Gateway capability provider is unavailable",
        })
    }
}

impl Error for NodeGatewayApiError {}

// Defines the eight exact Node-owned capabilities consumed by the Gateway resident.
pub trait NodeGatewayCapabilityPort: Send + Sync {
    // Authenticates one public inference bearer for one exact logical model.
    fn authorize_inference(
        &self,
        bearer: &str,
        model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, NodeGatewayApiError>;

    // Authenticates one model-list bearer and returns its exact durable scope.
    fn authorize_model_list(&self, bearer: &str) -> Result<ApiKeyModelScope, NodeGatewayApiError>;

    // Returns current bounded placement-group routes for one logical model.
    fn routes(&self, model: &LogicalModelName) -> Result<Vec<GatewayRoute>, NodeGatewayApiError>;

    // Resolves one selected route to exact native transport and credential references.
    fn native_target(
        &self,
        route: &GatewayRoute,
    ) -> Result<GatewayNativeTarget, NodeGatewayApiError>;

    // Authenticates one inbound main-to-child relay credential.
    fn authorize_inbound_relay(&self, bearer: &str) -> Result<NodeId, NodeGatewayApiError>;

    // Returns bounded completed usage at or after one rolling-window boundary.
    fn recent_usage(
        &self,
        key_id: &ApiKeyId,
        since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, NodeGatewayApiError>;

    // Persists one immutable usage record or confirms its exact replay.
    fn record_usage(
        &self,
        usage: &GatewayUsageRecord,
    ) -> Result<NodeGatewayUsageDisposition, NodeGatewayApiError>;

    // Returns complete Node-owned macOS placement inputs for one exact group.
    fn macos_safety_input(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<NodeGatewayMacOsSafetyInput, NodeGatewayApiError>;
}

// Enforces the node-role matrix before invoking one injected Gateway capability port.
pub struct NodeGatewayApi {
    capabilities: Arc<dyn NodeGatewayCapabilityPort>,
}

impl NodeGatewayApi {
    // Creates one local Gateway API without taking capability lifecycle ownership.
    pub const fn new(capabilities: Arc<dyn NodeGatewayCapabilityPort>) -> Self {
        Self { capabilities }
    }

    // Dispatches one exact request after enforcing main and child ownership boundaries.
    pub fn dispatch(
        &self,
        local_role: NodeRole,
        request: NodeGatewayRequest,
    ) -> Result<NodeGatewayResponse, NodeGatewayApiError> {
        require_gateway_role(local_role, &request)?;
        match request {
            NodeGatewayRequest::AuthorizeInference { bearer, model } => self
                .capabilities
                .authorize_inference(bearer.expose(), &model)
                .map(NodeGatewayResponse::Principal),
            NodeGatewayRequest::AuthorizeModelList { bearer } => self
                .capabilities
                .authorize_model_list(bearer.expose())
                .map(NodeGatewayResponse::ModelScope),
            NodeGatewayRequest::ReadRoutes { model } => self
                .capabilities
                .routes(&model)
                .and_then(bounded_routes)
                .map(NodeGatewayResponse::Routes),
            NodeGatewayRequest::ResolveNativeTarget { route } => self
                .capabilities
                .native_target(&route)
                .map(NodeGatewayResponse::NativeTarget),
            NodeGatewayRequest::AuthorizeInboundRelay { bearer } => self
                .capabilities
                .authorize_inbound_relay(bearer.expose())
                .map(NodeGatewayResponse::RelayPrincipal),
            NodeGatewayRequest::ReadRecentUsage { key_id, since } => self
                .capabilities
                .recent_usage(&key_id, since)
                .and_then(bounded_usage_records)
                .map(NodeGatewayResponse::UsageRecords),
            NodeGatewayRequest::RecordUsage { usage } => self
                .capabilities
                .record_usage(&usage)
                .map(NodeGatewayResponse::UsageRecorded),
            NodeGatewayRequest::ReadMacOsSafetyInput { placement_group_id } => self
                .capabilities
                .macos_safety_input(&placement_group_id)
                .and_then(|input| {
                    if input.placement_group_id() != &placement_group_id {
                        return Err(NodeGatewayApiError::InvalidContract);
                    }
                    Ok(input)
                })
                .map(NodeGatewayResponse::MacOsSafetyInput),
        }
    }
}

// Rejects capabilities that do not belong to the local main or child Gateway role.
fn require_gateway_role(
    local_role: NodeRole,
    request: &NodeGatewayRequest,
) -> Result<(), NodeGatewayApiError> {
    let permitted = match request {
        NodeGatewayRequest::AuthorizeInboundRelay { .. } => local_role == NodeRole::Child,
        NodeGatewayRequest::ReadRoutes { .. }
        | NodeGatewayRequest::ResolveNativeTarget { .. }
        | NodeGatewayRequest::ReadMacOsSafetyInput { .. } => true,
        NodeGatewayRequest::AuthorizeInference { .. }
        | NodeGatewayRequest::AuthorizeModelList { .. }
        | NodeGatewayRequest::ReadRecentUsage { .. }
        | NodeGatewayRequest::RecordUsage { .. } => local_role == NodeRole::Main,
    };
    if permitted {
        Ok(())
    } else {
        Err(NodeGatewayApiError::RoleDenied)
    }
}

// Rejects provider output that could create an unbounded local IPC response.
fn bounded_routes(routes: Vec<GatewayRoute>) -> Result<Vec<GatewayRoute>, NodeGatewayApiError> {
    if routes.len() > NODE_GATEWAY_MAXIMUM_ROUTES {
        Err(NodeGatewayApiError::InvalidContract)
    } else {
        Ok(routes)
    }
}

// Rejects provider output that could create an unbounded local IPC response.
fn bounded_usage_records(
    records: Vec<GatewayUsageRecord>,
) -> Result<Vec<GatewayUsageRecord>, NodeGatewayApiError> {
    if records.len() > NODE_GATEWAY_MAXIMUM_USAGE_RECORDS {
        Err(NodeGatewayApiError::InvalidContract)
    } else {
        Ok(records)
    }
}

// Returns whether one macOS safety projection repeats a placement identity.
fn has_duplicate_placement_identities(placements: &[NodeGatewayMacOsPlacement]) -> bool {
    let mut identities = placements
        .iter()
        .map(|value| value.placement().placement_id())
        .collect::<Vec<&PlacementId>>();
    identities.sort();
    identities.windows(2).any(|values| values[0] == values[1])
}
