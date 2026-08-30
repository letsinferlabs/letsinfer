// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use li_authentication_manager::ApiKeyModelScope;
use li_core_cli::{
    NodePrivateClient, NodePrivateClientConfiguration, NodePrivateClientError,
    NodeRequestIdentityError, NodeRequestIdentitySource, SystemNodePrivateDocumentExchange,
};
use li_core_interface::{
    ApiKeyId, LogicalModelName, ModelServiceDesiredState, Node, NodeId, NodeRole, NodeState,
    Sha256Digest, UnixMilliseconds,
};
#[cfg(target_os = "macos")]
use li_core_interface::{Placement, PlacementGroupId};
use li_gateway_manager::{
    GatewayAuthenticationProvider, GatewayError, GatewayHttpError, GatewayHttpModelInventory,
    GatewayHttpModelInventoryEntry, GatewayHttpModelList, GatewayHttpModelListProvider,
    GatewayHttpModelProvider, GatewayNativeIoError, GatewayNativeTarget,
    GatewayNativeTargetProvider, GatewayPrincipal, GatewayRelayAuthorizationProvider, GatewayRoute,
    GatewayRouteProvider, GatewayUsageRecord, GatewayUsageRuntimeCounterProvider,
    GatewayUsageStore,
};
#[cfg(target_os = "macos")]
use li_node_manager::NodeGatewayMacOsSafetyInput;
use li_node_manager::{
    NodeGatewayBearer, NodeGatewayRequest, NodeGatewayResponse, NodeModelServiceSummary,
    NodePrivateRequest, NodePrivateResponse,
};

// Supplies request identities from the operating system without adding a configuration path.
struct CoreGatewayRequestIdentitySource;

impl NodeRequestIdentitySource for CoreGatewayRequestIdentitySource {
    // Returns one fresh correlation identity from 256 operating-system entropy bits.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| NodeRequestIdentityError::Unavailable)?;
        let value = bytes
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>();
        Sha256Digest::parse(&value).map_err(|_| NodeRequestIdentityError::Unavailable)
    }
}

// Owns the one serialized owner-UID local Node connection capability used by Gateway.
pub(crate) struct CoreGatewayNodeClient {
    client: Mutex<
        NodePrivateClient<SystemNodePrivateDocumentExchange, CoreGatewayRequestIdentitySource>,
    >,
    local_node: Node,
    nodes: Vec<Node>,
    usage_write_errors: AtomicU64,
}

impl CoreGatewayNodeClient {
    // Opens one owner-checked endpoint and proves Node readiness before Gateway binds listeners.
    pub(crate) fn open(socket_path: std::path::PathBuf) -> Result<Self, NodePrivateClientError> {
        let exchange = SystemNodePrivateDocumentExchange::open(socket_path)
            .map_err(|_| NodePrivateClientError::NotConfigured)?;
        let mut client = NodePrivateClient::new(
            exchange,
            CoreGatewayRequestIdentitySource,
            NodePrivateClientConfiguration::default(),
        );
        let local_node = match client.execute(NodePrivateRequest::ReadLocalNode)? {
            NodePrivateResponse::LocalNode(node) => node,
            _ => return Err(NodePrivateClientError::MismatchedResponse),
        };
        let nodes = match client.execute(NodePrivateRequest::ReadNodes)? {
            NodePrivateResponse::Nodes(nodes) => nodes,
            _ => return Err(NodePrivateClientError::MismatchedResponse),
        };
        Ok(Self {
            client: Mutex::new(client),
            local_node,
            nodes,
            usage_write_errors: AtomicU64::new(0),
        })
    }

    // Returns the exact active local Node observed before listener mutation.
    pub(crate) const fn local_node(&self) -> &Node {
        &self.local_node
    }

    // Returns the unique active main from the same startup snapshot.
    pub(crate) fn main_node(&self) -> Result<&Node, GatewayError> {
        let matching = self
            .nodes
            .iter()
            .filter(|node| node.role() == NodeRole::Main && node.state() == NodeState::Active)
            .collect::<Vec<_>>();
        if matching.len() == 1 {
            Ok(matching[0])
        } else {
            Err(node_gateway_error())
        }
    }

    // Returns current model-service summaries through the existing typed Node request.
    fn model_services(&self) -> Result<Vec<NodeModelServiceSummary>, NodePrivateClientError> {
        match self.execute(NodePrivateRequest::ListModels)? {
            NodePrivateResponse::ModelServices(services) => Ok(services),
            _ => Err(NodePrivateClientError::MismatchedResponse),
        }
    }

    // Returns the exact model-list scope without exposing bearer material in any result.
    fn model_scope(&self, bearer: &str) -> Result<ApiKeyModelScope, GatewayHttpError> {
        let request = NodeGatewayRequest::AuthorizeModelList {
            bearer: NodeGatewayBearer::parse(bearer).map_err(|_| authentication_http_error())?,
        };
        match self.gateway(request).map_err(gateway_http_error)? {
            NodeGatewayResponse::ModelScope(scope) => Ok(scope),
            _ => Err(gateway_http_unavailable()),
        }
    }

    // Returns one complete macOS placement safety projection through the typed Gateway union.
    #[cfg(target_os = "macos")]
    pub(crate) fn macos_safety_input(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<NodeGatewayMacOsSafetyInput, GatewayError> {
        match self
            .gateway(NodeGatewayRequest::ReadMacOsSafetyInput {
                placement_group_id: placement_group_id.clone(),
            })
            .map_err(gateway_provider_error)?
        {
            NodeGatewayResponse::MacOsSafetyInput(input) => Ok(input),
            _ => Err(node_gateway_error()),
        }
    }

    // Executes one nested Gateway capability over the single serialized local Node client.
    fn gateway(
        &self,
        request: NodeGatewayRequest,
    ) -> Result<NodeGatewayResponse, NodePrivateClientError> {
        match self.execute(NodePrivateRequest::Gateway(request))? {
            NodePrivateResponse::Gateway(response) => Ok(response),
            _ => Err(NodePrivateClientError::MismatchedResponse),
        }
    }

    // Executes one typed private request while preserving the client's correlation lifecycle.
    fn execute(
        &self,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, NodePrivateClientError> {
        self.client
            .lock()
            .map_err(|_| NodePrivateClientError::Unavailable)?
            .execute(request)
    }

    // Advances the process-local durable-write failure counter without wrapping.
    fn record_usage_write_error(&self) {
        let _ =
            self.usage_write_errors
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    Some(value.saturating_add(1))
                });
    }
}

impl GatewayAuthenticationProvider for CoreGatewayNodeClient {
    // Authenticates public inference through Node without retaining bearer material.
    fn authenticate(
        &self,
        bearer_token: &str,
        model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError> {
        let bearer = NodeGatewayBearer::parse(bearer_token)
            .map_err(|_| GatewayError::AuthenticationDenied)?;
        match self
            .gateway(NodeGatewayRequest::AuthorizeInference {
                bearer,
                model: model.clone(),
            })
            .map_err(gateway_provider_error)?
        {
            NodeGatewayResponse::Principal(principal) => Ok(principal),
            _ => Err(node_gateway_error()),
        }
    }
}

impl GatewayRelayAuthorizationProvider for CoreGatewayNodeClient {
    // Authenticates an inbound relay only through the child Node's persisted pairing trust.
    fn authorize(&self, relay_credential: &str) -> Result<NodeId, GatewayError> {
        let bearer =
            NodeGatewayBearer::parse(relay_credential).map_err(|_| GatewayError::RelayDenied)?;
        match self
            .gateway(NodeGatewayRequest::AuthorizeInboundRelay { bearer })
            .map_err(gateway_relay_error)?
        {
            NodeGatewayResponse::RelayPrincipal(node_id) => Ok(node_id),
            _ => Err(node_gateway_error()),
        }
    }
}

impl GatewayRouteProvider for CoreGatewayNodeClient {
    // Reads current bounded routes from Node-owned placement state.
    fn routes(&self, model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        match self
            .gateway(NodeGatewayRequest::ReadRoutes {
                model: model.clone(),
            })
            .map_err(gateway_provider_error)?
        {
            NodeGatewayResponse::Routes(routes) => Ok(routes),
            _ => Err(node_gateway_error()),
        }
    }
}

impl GatewayNativeTargetProvider for CoreGatewayNodeClient {
    // Resolves exact native file and relay references without opening database state.
    fn target(&self, route: &GatewayRoute) -> Result<GatewayNativeTarget, GatewayNativeIoError> {
        match self.gateway(NodeGatewayRequest::ResolveNativeTarget {
            route: route.clone(),
        }) {
            Ok(NodeGatewayResponse::NativeTarget(target)) => Ok(target),
            _ => Err(GatewayNativeIoError::terminal_before_head(
                "Node Gateway target is unavailable",
            )),
        }
    }
}

impl GatewayUsageStore for CoreGatewayNodeClient {
    // Reads current quota history through the Node-owned database lifecycle.
    fn recent(
        &self,
        key_id: &ApiKeyId,
        since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
        match self
            .gateway(NodeGatewayRequest::ReadRecentUsage {
                key_id: key_id.clone(),
                since,
            })
            .map_err(gateway_provider_error)?
        {
            NodeGatewayResponse::UsageRecords(records) => Ok(records),
            _ => Err(node_gateway_error()),
        }
    }

    // Persists one exact completion and accepts both first commit and exact replay.
    fn record(&self, usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
        let response = self.gateway(NodeGatewayRequest::RecordUsage {
            usage: usage.clone(),
        });
        match response {
            Ok(NodeGatewayResponse::UsageRecorded(_)) => Ok(()),
            _ => {
                self.record_usage_write_error();
                Err(node_gateway_error())
            }
        }
    }
}

impl GatewayUsageRuntimeCounterProvider for CoreGatewayNodeClient {
    // Reports no dropped records and every failed synchronous Node persistence exchange.
    fn usage_counters(&self) -> Result<(u64, u64), GatewayError> {
        Ok((0, self.usage_write_errors.load(Ordering::Acquire)))
    }
}

#[cfg(target_os = "macos")]
impl li_placement_manager::PlacementLaunchPlanIdentityProvider for CoreGatewayNodeClient {
    // Returns the Node-owned launch-plan identity paired with the exact placement projection.
    fn expected_identity(
        &self,
        placement: &Placement,
    ) -> Result<Option<Sha256Digest>, li_placement_manager::PlacementError> {
        let input = self
            .macos_safety_input(placement.placement_group_id())
            .map_err(|_| li_placement_manager::PlacementError::ExecutionUnavailable)?;
        let matching = input
            .placements()
            .iter()
            .filter(|value| value.placement().placement_id() == placement.placement_id())
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].placement() != placement {
            return Err(li_placement_manager::PlacementError::ExecutionUnavailable);
        }
        Ok(Some(matching[0].launch_plan_identity().clone()))
    }
}

impl GatewayHttpModelProvider for CoreGatewayNodeClient {
    // Resolves one running canonical model against current Node-owned model services.
    fn resolve(&self, requested_model: &str) -> Result<LogicalModelName, GatewayHttpError> {
        let requested = LogicalModelName::parse(requested_model).map_err(|_| model_not_found())?;
        let matching = self
            .model_services()
            .map_err(|_| gateway_http_unavailable())?
            .into_iter()
            .filter(|service| {
                service.logical_model() == &requested
                    && service.desired_state() == ModelServiceDesiredState::Running
            })
            .count();
        if matching == 1 {
            Ok(requested)
        } else {
            Err(model_not_found())
        }
    }
}

// Filters Node-owned model services through current Gateway availability and bearer scope.
pub(crate) struct CoreGatewayNodeModelListProvider {
    node: Arc<CoreGatewayNodeClient>,
    availability: Arc<dyn li_gateway_manager::GatewayHttpModelAvailabilityProvider>,
    clock: Arc<dyn li_node_manager::NodeGatewayInventoryClock>,
}

impl CoreGatewayNodeModelListProvider {
    // Creates one model-list projection without copying Authentication or Node state.
    pub(crate) const fn new(
        node: Arc<CoreGatewayNodeClient>,
        availability: Arc<dyn li_gateway_manager::GatewayHttpModelAvailabilityProvider>,
        clock: Arc<dyn li_node_manager::NodeGatewayInventoryClock>,
    ) -> Self {
        Self {
            node,
            availability,
            clock,
        }
    }

    // Projects unique configured models and immediate availability into one bounded inventory.
    fn inventory(&self) -> Result<GatewayHttpModelInventory, GatewayHttpError> {
        let services = self
            .node
            .model_services()
            .map_err(|_| gateway_http_unavailable())?;
        let mut configured = BTreeSet::new();
        for service in services
            .iter()
            .filter(|service| service.desired_state() != ModelServiceDesiredState::Removed)
        {
            if !configured.insert(service.logical_model().clone()) {
                return Err(gateway_http_unavailable());
            }
        }
        let mut entries = Vec::new();
        for service in services
            .into_iter()
            .filter(|service| service.desired_state() == ModelServiceDesiredState::Running)
        {
            if self
                .availability
                .model_is_available(service.logical_model())?
            {
                entries.push(GatewayHttpModelInventoryEntry::new(
                    service.logical_model().clone(),
                    Vec::new(),
                )?);
            }
        }
        let observed_at_unix = self.clock.now()?.value() / 1_000;
        GatewayHttpModelInventory::new(observed_at_unix, entries)
    }
}

impl GatewayHttpModelListProvider for CoreGatewayNodeModelListProvider {
    // Authenticates once through Node and applies the exact durable scope to live inventory.
    fn models(&self, bearer_token: &str) -> Result<GatewayHttpModelList, GatewayHttpError> {
        let scope = self.node.model_scope(bearer_token)?;
        let inventory = self.inventory()?;
        let names = inventory
            .entries()
            .iter()
            .filter(|entry| scope.permits(entry.model()))
            .map(|entry| entry.model().clone())
            .collect::<Vec<_>>();
        GatewayHttpModelList::new(inventory.observed_at_unix(), names)
    }
}

// Maps one local IPC failure into Gateway's stable provider boundary.
fn gateway_provider_error(error: NodePrivateClientError) -> GatewayError {
    match error {
        NodePrivateClientError::RemoteRejected { code }
            if code == "gateway_authorization_denied" =>
        {
            GatewayError::AuthenticationDenied
        }
        _ => node_gateway_error(),
    }
}

// Maps one relay IPC failure without confusing public and private authorization errors.
fn gateway_relay_error(error: NodePrivateClientError) -> GatewayError {
    match error {
        NodePrivateClientError::RemoteRejected { code }
            if code == "gateway_authorization_denied" =>
        {
            GatewayError::RelayDenied
        }
        _ => node_gateway_error(),
    }
}

// Maps one Node capability failure into a redacted public model-list result.
fn gateway_http_error(error: NodePrivateClientError) -> GatewayHttpError {
    match error {
        NodePrivateClientError::RemoteRejected { code }
            if code == "gateway_authorization_denied" =>
        {
            authentication_http_error()
        }
        _ => gateway_http_unavailable(),
    }
}

// Returns one stable private capability provider failure.
fn node_gateway_error() -> GatewayError {
    GatewayError::provider("node", "local Node capability is unavailable")
}

// Returns one indistinguishable public bearer failure.
fn authentication_http_error() -> GatewayHttpError {
    GatewayHttpError::new(401, "unauthorized", "credential is invalid or expired")
}

// Returns one stable public provider failure.
fn gateway_http_unavailable() -> GatewayHttpError {
    GatewayHttpError::new(
        503,
        "gateway_unavailable",
        "Gateway model inventory is unavailable",
    )
}

// Returns one stable public model-resolution failure.
fn model_not_found() -> GatewayHttpError {
    GatewayHttpError::new(404, "model_not_found", "requested model is unavailable")
}
