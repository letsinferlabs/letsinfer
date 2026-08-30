// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_authentication_manager::{AuthenticationError, AuthenticationManager};
use li_core_interface::{ApiKeyId, LogicalModelName, NodeId, PlacementGroupId, UnixMilliseconds};
use li_gateway_manager::{
    GatewayAuthenticationProvider, GatewayError, GatewayNativeTarget, GatewayNativeTargetProvider,
    GatewayPrincipal, GatewayRelayAuthorizationProvider, GatewayRoute, GatewayRouteProvider,
    GatewayUsageRecord, GatewayUsageStore,
};

use crate::{
    DatabaseGatewayUsageStore, DatabasePlacementStore, NodeGatewayApiError,
    NodeGatewayCapabilityPort, NodeGatewayMacOsSafetyInput, NodeGatewayUsageDisposition,
};

// Composes the eight Gateway capabilities beneath the Node-owned database lifecycle.
pub struct ManagedNodeGatewayCapabilityPort {
    authentication: Arc<AuthenticationManager>,
    gateway_authentication: Arc<dyn GatewayAuthenticationProvider>,
    routes: Arc<dyn GatewayRouteProvider>,
    targets: Arc<dyn GatewayNativeTargetProvider>,
    relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
    usage: Arc<DatabaseGatewayUsageStore>,
    placements: Arc<DatabasePlacementStore>,
}

impl ManagedNodeGatewayCapabilityPort {
    // Creates one narrow capability adapter without transferring manager lifecycle ownership.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authentication: Arc<AuthenticationManager>,
        gateway_authentication: Arc<dyn GatewayAuthenticationProvider>,
        routes: Arc<dyn GatewayRouteProvider>,
        targets: Arc<dyn GatewayNativeTargetProvider>,
        relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
        usage: Arc<DatabaseGatewayUsageStore>,
        placements: Arc<DatabasePlacementStore>,
    ) -> Self {
        Self {
            authentication,
            gateway_authentication,
            routes,
            targets,
            relay_authorization,
            usage,
            placements,
        }
    }
}

impl NodeGatewayCapabilityPort for ManagedNodeGatewayCapabilityPort {
    // Authenticates one public request through AuthenticationManager's existing Gateway adapter.
    fn authorize_inference(
        &self,
        bearer: &str,
        model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, NodeGatewayApiError> {
        self.gateway_authentication
            .authenticate(bearer, model)
            .map_err(gateway_authorization_error)
    }

    // Returns only the durable model scope after exact bearer identity authentication.
    fn authorize_model_list(
        &self,
        bearer: &str,
    ) -> Result<li_authentication_manager::ApiKeyModelScope, NodeGatewayApiError> {
        self.authentication
            .authenticate_identity(bearer)
            .map(|principal| principal.policy().model_scope().clone())
            .map_err(authentication_error)
    }

    // Delegates current route projection to the Node-owned placement adapter.
    fn routes(&self, model: &LogicalModelName) -> Result<Vec<GatewayRoute>, NodeGatewayApiError> {
        self.routes.routes(model).map_err(gateway_state_error)
    }

    // Resolves one selected route while credential files remain Node-owned references.
    fn native_target(
        &self,
        route: &GatewayRoute,
    ) -> Result<GatewayNativeTarget, NodeGatewayApiError> {
        self.targets
            .target(route)
            .map_err(|_| NodeGatewayApiError::Unavailable)
    }

    // Authenticates one inbound relay through the persisted Node pairing trust.
    fn authorize_inbound_relay(&self, bearer: &str) -> Result<NodeId, NodeGatewayApiError> {
        self.relay_authorization
            .authorize(bearer)
            .map_err(gateway_authorization_error)
    }

    // Reads the exact bounded usage window from Node-owned persistence.
    fn recent_usage(
        &self,
        key_id: &ApiKeyId,
        since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, NodeGatewayApiError> {
        self.usage
            .recent(key_id, since)
            .map_err(gateway_state_error)
    }

    // Preserves the database commit disposition across the local typed boundary.
    fn record_usage(
        &self,
        usage: &GatewayUsageRecord,
    ) -> Result<NodeGatewayUsageDisposition, NodeGatewayApiError> {
        self.usage.record_for_gateway_api(usage)
    }

    // Projects only one placement group's complete macOS safety inputs.
    fn macos_safety_input(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<NodeGatewayMacOsSafetyInput, NodeGatewayApiError> {
        self.placements
            .gateway_macos_safety_input(placement_group_id)
    }
}

// Maps bearer failures without disclosing whether identity, policy, or storage rejected it.
fn authentication_error(error: AuthenticationError) -> NodeGatewayApiError {
    match error {
        AuthenticationError::Unauthorized | AuthenticationError::NotFound => {
            NodeGatewayApiError::AuthorizationDenied
        }
        _ => NodeGatewayApiError::Unavailable,
    }
}

// Maps Gateway bearer failures while preserving only authorization versus provider availability.
fn gateway_authorization_error(error: GatewayError) -> NodeGatewayApiError {
    match error {
        GatewayError::AuthenticationDenied | GatewayError::RelayDenied => {
            NodeGatewayApiError::AuthorizationDenied
        }
        _ => gateway_state_error(error),
    }
}

// Maps provider contract failures into the closed local Node capability taxonomy.
fn gateway_state_error(error: GatewayError) -> NodeGatewayApiError {
    match error {
        GatewayError::InvalidContract { .. } => NodeGatewayApiError::CorruptState,
        GatewayError::AuthenticationDenied | GatewayError::RelayDenied => {
            NodeGatewayApiError::AuthorizationDenied
        }
        _ => NodeGatewayApiError::Unavailable,
    }
}
