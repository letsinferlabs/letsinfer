// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::{
    CredentialId, EndpointAddress, EntityTimestamps, FailureDescription, InterfaceError,
    ModelServiceDesiredState, ModelServiceId, NodeId, PlacementGroupId, PlacementId,
    RuntimeIdentity, TechnicalName,
};

const MAX_PLACEMENTS_PER_GROUP: usize = 64;
const MAX_PREFIX_KEYS: usize = 128;
const MAX_TOKEN_COUNT_PATH_BYTES: usize = 255;

// Identifies one model-neutral interconnect contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterconnectKind {
    Any,
    Connectx,
    Ethernet,
    Wifi,
    Other,
}

// Describes the minimum interconnect required by one runtime target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterconnectRequirement {
    kind: InterconnectKind,
    rdma_required: bool,
    minimum_speed_mbps: u64,
    minimum_mtu: u32,
}

impl InterconnectRequirement {
    // Creates one explicit requirement without testing a live topology.
    pub const fn new(
        kind: InterconnectKind,
        rdma_required: bool,
        minimum_speed_mbps: u64,
        minimum_mtu: u32,
    ) -> Self {
        Self {
            kind,
            rdma_required,
            minimum_speed_mbps,
            minimum_mtu,
        }
    }

    // Returns the accepted interconnect kind.
    pub const fn kind(self) -> InterconnectKind {
        self.kind
    }

    // Returns whether the runtime requires RDMA.
    pub const fn rdma_required(self) -> bool {
        self.rdma_required
    }

    // Returns the minimum observed link speed.
    pub const fn minimum_speed_mbps(self) -> u64 {
        self.minimum_speed_mbps
    }

    // Returns the minimum observed MTU.
    pub const fn minimum_mtu(self) -> u32 {
        self.minimum_mtu
    }
}

// Describes the bounded serving capacity advertised by one placement group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementGroupCapacity {
    max_connections: u32,
    max_active_requests: u32,
    max_context_tokens: u64,
    interconnect: InterconnectRequirement,
}

impl PlacementGroupCapacity {
    // Creates one positive capacity contract without performing admission.
    pub fn new(
        max_connections: u32,
        max_active_requests: u32,
        max_context_tokens: u64,
        interconnect: InterconnectRequirement,
    ) -> Result<Self, InterfaceError> {
        if max_connections == 0 || max_active_requests == 0 || max_context_tokens == 0 {
            return Err(InterfaceError::new(
                "placement group capacity",
                "connection, request, and context limits must be positive",
            ));
        }
        Ok(Self {
            max_connections,
            max_active_requests,
            max_context_tokens,
            interconnect,
        })
    }

    // Returns the maximum concurrent gateway connections.
    pub const fn max_connections(self) -> u32 {
        self.max_connections
    }

    // Returns the maximum active inference requests.
    pub const fn max_active_requests(self) -> u32 {
        self.max_active_requests
    }

    // Returns the maximum supported context length.
    pub const fn max_context_tokens(self) -> u64 {
        self.max_context_tokens
    }

    // Returns the runtime's minimum interconnect requirement.
    pub const fn interconnect(self) -> InterconnectRequirement {
        self.interconnect
    }
}

// Identifies the one exact token-count protocol understood by Core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenCountProtocol {
    LetsInferV1,
}

// Describes the engine-owned exact token-count endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenCountContract {
    path: String,
    protocol: TokenCountProtocol,
}

impl TokenCountContract {
    // Creates one canonical absolute endpoint path for exact token counting.
    pub fn new(path: &str, protocol: TokenCountProtocol) -> Result<Self, InterfaceError> {
        if path.len() > MAX_TOKEN_COUNT_PATH_BYTES
            || !path.starts_with('/')
            || path.contains("://")
            || path.chars().any(char::is_control)
            || path.chars().any(char::is_whitespace)
        {
            return Err(InterfaceError::new(
                "token count contract",
                "path must be absolute, local, bounded, and contain no whitespace",
            ));
        }
        Ok(Self {
            path: path.to_string(),
            protocol,
        })
    }

    // Returns the engine-owned token-count path.
    pub fn path(&self) -> &str {
        &self.path
    }

    // Returns the exact token-count protocol.
    pub const fn protocol(&self) -> TokenCountProtocol {
        self.protocol
    }
}

// Describes one endpoint health snapshot without retaining telemetry history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointHealth {
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<i32>,
    prefix_keys: Vec<TechnicalName>,
}

impl EndpointHealth {
    // Creates one bounded current health snapshot.
    pub fn new(
        healthy: bool,
        memory_pressure: bool,
        temperature_millicelsius: Option<i32>,
        prefix_keys: Vec<TechnicalName>,
    ) -> Result<Self, InterfaceError> {
        if temperature_millicelsius.is_some_and(|value| !(-1_000..=250_000).contains(&value)) {
            return Err(InterfaceError::new(
                "endpoint health",
                "temperature must be between -1 and 250 degrees Celsius",
            ));
        }
        let unique: HashSet<&TechnicalName> = prefix_keys.iter().collect();
        if prefix_keys.len() > MAX_PREFIX_KEYS || unique.len() != prefix_keys.len() {
            return Err(InterfaceError::new(
                "endpoint health",
                "prefix identities must be unique and bounded",
            ));
        }
        Ok(Self {
            healthy,
            memory_pressure,
            temperature_millicelsius,
            prefix_keys,
        })
    }

    // Returns whether the endpoint passed its latest readiness observation.
    pub const fn healthy(&self) -> bool {
        self.healthy
    }

    // Returns whether the endpoint reported memory pressure.
    pub const fn memory_pressure(&self) -> bool {
        self.memory_pressure
    }

    // Returns current temperature in thousandths of a degree Celsius.
    pub const fn temperature_millicelsius(&self) -> Option<i32> {
        self.temperature_millicelsius
    }

    // Returns the bounded prefix-cache identities currently available.
    pub fn prefix_keys(&self) -> &[TechnicalName] {
        &self.prefix_keys
    }
}

// Describes the one routable endpoint exposed by a complete placement group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementEndpoint {
    placement_id: PlacementId,
    node_id: NodeId,
    address: EndpointAddress,
    credential_id: CredentialId,
    ca_credential_id: Option<CredentialId>,
    token_count: Option<TokenCountContract>,
    max_active_requests: u32,
    max_context_tokens: u64,
    health: EndpointHealth,
}

impl PlacementEndpoint {
    // Creates one bounded endpoint without resolving credentials or connecting to it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placement_id: PlacementId,
        node_id: NodeId,
        address: EndpointAddress,
        credential_id: CredentialId,
        ca_credential_id: Option<CredentialId>,
        token_count: Option<TokenCountContract>,
        max_active_requests: u32,
        max_context_tokens: u64,
        health: EndpointHealth,
    ) -> Result<Self, InterfaceError> {
        if max_active_requests == 0 || max_context_tokens == 0 {
            return Err(InterfaceError::new(
                "placement endpoint",
                "request and context limits must be positive",
            ));
        }
        Ok(Self {
            placement_id,
            node_id,
            address,
            credential_id,
            ca_credential_id,
            token_count,
            max_active_requests,
            max_context_tokens,
            health,
        })
    }

    // Returns the placement that owns this endpoint.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the node that owns this endpoint.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the structured endpoint address.
    pub const fn address(&self) -> &EndpointAddress {
        &self.address
    }

    // Returns the credential reference used for engine authentication.
    pub const fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    // Returns the optional certificate-authority credential reference.
    pub const fn ca_credential_id(&self) -> Option<&CredentialId> {
        self.ca_credential_id.as_ref()
    }

    // Returns the exact token-count contract when the runtime provides one.
    pub const fn token_count(&self) -> Option<&TokenCountContract> {
        self.token_count.as_ref()
    }

    // Returns the endpoint's maximum active requests.
    pub const fn max_active_requests(&self) -> u32 {
        self.max_active_requests
    }

    // Returns the endpoint's maximum context length.
    pub const fn max_context_tokens(&self) -> u64 {
        self.max_context_tokens
    }

    // Returns the latest bounded health snapshot.
    pub const fn health(&self) -> &EndpointHealth {
        &self.health
    }
}

// Describes the latest observed lifecycle state of one placement group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementGroupState {
    Staging,
    Staged,
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Recovering,
    Removing,
    Removed,
    Failed,
}

// Describes one atomic runtime execution and its single endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementGroup {
    placement_group_id: PlacementGroupId,
    service_id: ModelServiceId,
    runtime: RuntimeIdentity,
    placement_ids: Vec<PlacementId>,
    endpoint_placement_id: PlacementId,
    endpoint: Option<PlacementEndpoint>,
    capacity: PlacementGroupCapacity,
    desired_state: ModelServiceDesiredState,
    state: PlacementGroupState,
    last_failure: Option<FailureDescription>,
    timestamps: EntityTimestamps,
}

impl PlacementGroup {
    // Creates one coherent placement-group snapshot without changing its lifecycle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placement_group_id: PlacementGroupId,
        service_id: ModelServiceId,
        runtime: RuntimeIdentity,
        placement_ids: Vec<PlacementId>,
        endpoint_placement_id: PlacementId,
        endpoint: Option<PlacementEndpoint>,
        capacity: PlacementGroupCapacity,
        desired_state: ModelServiceDesiredState,
        state: PlacementGroupState,
        last_failure: Option<FailureDescription>,
        timestamps: EntityTimestamps,
    ) -> Result<Self, InterfaceError> {
        let unique: HashSet<&PlacementId> = placement_ids.iter().collect();
        if placement_ids.is_empty()
            || placement_ids.len() > MAX_PLACEMENTS_PER_GROUP
            || unique.len() != placement_ids.len()
        {
            return Err(InterfaceError::new(
                "placement group",
                "placement identities must be non-empty, unique, and bounded",
            ));
        }
        if !placement_ids.contains(&endpoint_placement_id) {
            return Err(InterfaceError::new(
                "placement group",
                "endpoint owner must belong to the placement group",
            ));
        }
        if endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.placement_id() != &endpoint_placement_id)
        {
            return Err(InterfaceError::new(
                "placement group",
                "endpoint identity differs from the endpoint owner",
            ));
        }
        if state == PlacementGroupState::Running && endpoint.is_none() {
            return Err(InterfaceError::new(
                "placement group",
                "running state requires one endpoint",
            ));
        }
        if state == PlacementGroupState::Failed && last_failure.is_none() {
            return Err(InterfaceError::new(
                "placement group",
                "failed state requires a failure description",
            ));
        }
        if endpoint.as_ref().is_some_and(|endpoint| {
            endpoint.max_active_requests() > capacity.max_active_requests()
                || endpoint.max_context_tokens() > capacity.max_context_tokens()
        }) {
            return Err(InterfaceError::new(
                "placement group",
                "endpoint limits exceed the group capacity",
            ));
        }
        Ok(Self {
            placement_group_id,
            service_id,
            runtime,
            placement_ids,
            endpoint_placement_id,
            endpoint,
            capacity,
            desired_state,
            state,
            last_failure,
            timestamps,
        })
    }

    // Returns the placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the owning model-service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the sealed runtime identity shared by every placement.
    pub const fn runtime(&self) -> &RuntimeIdentity {
        &self.runtime
    }

    // Returns every required placement identity.
    pub fn placement_ids(&self) -> &[PlacementId] {
        &self.placement_ids
    }

    // Returns the placement designated to own the endpoint.
    pub const fn endpoint_placement_id(&self) -> &PlacementId {
        &self.endpoint_placement_id
    }

    // Returns the routable endpoint when the group has completed startup.
    pub const fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }

    // Returns the runtime-qualified serving capacity.
    pub const fn capacity(&self) -> PlacementGroupCapacity {
        self.capacity
    }

    // Returns the operator's intended lifecycle state.
    pub const fn desired_state(&self) -> ModelServiceDesiredState {
        self.desired_state
    }

    // Returns the latest observed group state.
    pub const fn state(&self) -> PlacementGroupState {
        self.state
    }

    // Returns the most recent bounded group failure.
    pub const fn last_failure(&self) -> Option<&FailureDescription> {
        self.last_failure.as_ref()
    }

    // Returns the placement-group snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
