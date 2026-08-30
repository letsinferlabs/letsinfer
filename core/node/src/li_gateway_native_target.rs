// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    ModelServiceDesiredState, NodeAddress, NodeId, PlacementEndpoint, PlacementGroupId,
    PlacementGroupState, TokenCountContract,
};
use li_gateway_manager::{
    GatewayNativeIoError, GatewayNativeTarget, GatewayNativeTargetProvider, GatewayRoute,
    GatewayRouteTarget,
};
use li_placement_manager::{PlacementCredentialReader, PlacementRecord};

use crate::{DatabasePlacementStore, NodeGatewayRelayTarget};

// Supplies one current placement aggregate without exposing database mechanics to Gateway.
pub trait GatewayPlacementRecordProvider: Send + Sync {
    // Returns one exact placement-group aggregate or explicit absence.
    fn record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<PlacementRecord>, GatewayNativeIoError>;
}

impl GatewayPlacementRecordProvider for DatabasePlacementStore {
    // Resolves one placement aggregate from the durable global store.
    fn record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<PlacementRecord>, GatewayNativeIoError> {
        let matching = self
            .records()
            .map_err(|_| native_target_error("placement state is unavailable"))?
            .into_iter()
            .filter(|record| record.group().placement_group_id() == placement_group_id)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(native_target_error("placement-group identity is ambiguous"));
        }
        Ok(matching.into_iter().next())
    }
}

// Resolves an authenticated child Gateway target from Node-owned trust references.
pub trait NodeGatewayRelayTargetProvider: Send + Sync {
    // Returns the exact private child relay and its enrolled server-leaf pin.
    fn target(
        &self,
        placement_group_id: &PlacementGroupId,
        child_node_id: &NodeId,
        address: &NodeAddress,
        engine_token_count: Option<TokenCountContract>,
    ) -> Result<NodeGatewayRelayTarget, GatewayNativeIoError>;
}

// Projects selected routes back to exact placement and credential references.
pub struct NodeGatewayNativeTargetProvider {
    local_node_id: NodeId,
    owner_user_id: u32,
    placements: Arc<dyn GatewayPlacementRecordProvider>,
    credentials: Arc<dyn PlacementCredentialReader>,
    relays: Arc<dyn NodeGatewayRelayTargetProvider>,
}

impl NodeGatewayNativeTargetProvider {
    // Creates one native target adapter from explicit placement, credential, and relay owners.
    pub const fn new(
        local_node_id: NodeId,
        owner_user_id: u32,
        placements: Arc<dyn GatewayPlacementRecordProvider>,
        credentials: Arc<dyn PlacementCredentialReader>,
        relays: Arc<dyn NodeGatewayRelayTargetProvider>,
    ) -> Self {
        Self {
            local_node_id,
            owner_user_id,
            placements,
            credentials,
            relays,
        }
    }

    // Reconstructs the exact running placement and endpoint selected by one route.
    fn placement(
        &self,
        route: &GatewayRoute,
    ) -> Result<(PlacementRecord, PlacementEndpoint), GatewayNativeIoError> {
        let record = self
            .placements
            .record(route.placement_group_id())?
            .ok_or_else(|| native_target_error("selected placement group is unavailable"))?;
        let group = record.group();
        if group.state() != PlacementGroupState::Running
            || group.desired_state() != ModelServiceDesiredState::Running
        {
            return Err(native_target_error(
                "selected placement group is not running",
            ));
        }
        let endpoint = group
            .endpoint()
            .cloned()
            .ok_or_else(|| native_target_error("selected placement endpoint is unavailable"))?;
        if endpoint.node_id() != route.endpoint_node_id()
            || group.endpoint_placement_id() != endpoint.placement_id()
        {
            return Err(native_target_error(
                "selected route differs from its placement endpoint",
            ));
        }
        Ok((record, endpoint))
    }

    // Resolves one local Engine from exact provisioned placement credential references.
    fn local_target(
        &self,
        route: &GatewayRoute,
        record: &PlacementRecord,
        endpoint: &PlacementEndpoint,
    ) -> Result<GatewayNativeTarget, GatewayNativeIoError> {
        let GatewayRouteTarget::LocalEngine {
            endpoint: route_endpoint,
        } = route.target()
        else {
            return Err(native_target_error("selected route target kind changed"));
        };
        if endpoint.node_id() != &self.local_node_id || endpoint.address() != route_endpoint {
            return Err(native_target_error(
                "selected local Engine identity changed",
            ));
        }
        let placement = record
            .placements()
            .iter()
            .find(|placement| placement.placement_id() == endpoint.placement_id())
            .ok_or_else(|| native_target_error("endpoint placement is unavailable"))?;
        let references = self
            .credentials
            .existing(placement)
            .map_err(|_| native_target_error("placement credentials are unavailable"))?
            .ok_or_else(|| native_target_error("placement credentials are unavailable"))?;
        if references.placement_id() != endpoint.placement_id()
            || references.credential_id() != endpoint.credential_id()
            || endpoint.ca_credential_id() != Some(references.ca_credential_id())
        {
            return Err(native_target_error(
                "placement credential identity differs from its endpoint",
            ));
        }
        GatewayNativeTarget::local_engine(
            endpoint.address(),
            self.owner_user_id,
            references.engine_credential_file().to_path_buf(),
            references.tls_certificate_file().to_path_buf(),
            endpoint.token_count().cloned(),
        )
    }
}

impl GatewayNativeTargetProvider for NodeGatewayNativeTargetProvider {
    // Resolves one selected route to exact local placement or child trust references.
    fn target(&self, route: &GatewayRoute) -> Result<GatewayNativeTarget, GatewayNativeIoError> {
        let (record, endpoint) = self.placement(route)?;
        match route.target() {
            GatewayRouteTarget::LocalEngine { .. } => self.local_target(route, &record, &endpoint),
            GatewayRouteTarget::ChildRelay { address } => {
                if endpoint.node_id() == &self.local_node_id {
                    return Err(native_target_error(
                        "local placement cannot use a child relay",
                    ));
                }
                self.relays
                    .target(
                        route.placement_group_id(),
                        endpoint.node_id(),
                        address,
                        endpoint.token_count().cloned(),
                    )
                    .map(NodeGatewayRelayTarget::into_native_target)
            }
        }
    }
}

// Returns one stable terminal native-target contract failure.
fn native_target_error(reason: &'static str) -> GatewayNativeIoError {
    GatewayNativeIoError::terminal_before_head(reason)
}
