// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use li_core_interface::{
    LogicalModelName, ModelServiceDesiredState, NodeRole, NodeState, PlacementGroupState,
    Sha256Digest,
};
use li_gateway_manager::{GatewayError, GatewayRoute, GatewayRouteProvider, GatewayRouteTarget};
use li_placement_manager::PlacementRecord;
use sha2::{Digest, Sha256};

use crate::{DatabasePlacementStore, NodeManager};

// Projects NodeManager services and PlacementManager aggregates into live Gateway routes.
pub struct NodeGatewayRouteProvider {
    manager: Arc<NodeManager>,
    placements: Arc<DatabasePlacementStore>,
}

impl NodeGatewayRouteProvider {
    // Creates one route adapter without copying manager or placement state.
    pub const fn new(manager: Arc<NodeManager>, placements: Arc<DatabasePlacementStore>) -> Self {
        Self {
            manager,
            placements,
        }
    }
}

impl GatewayRouteProvider for NodeGatewayRouteProvider {
    // Returns current running placement-group endpoints for one logical model.
    fn routes(&self, model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        let services = self
            .manager
            .model_services()
            .map_err(|_| route_state_error())?;
        let matching = services
            .into_iter()
            .filter(|service| {
                service.logical_model() == model
                    && service.desired_state() == ModelServiceDesiredState::Running
            })
            .collect::<Vec<_>>();
        let Some(service) = matching.first() else {
            return Ok(Vec::new());
        };
        if matching.len() != 1 {
            return Err(GatewayError::InvalidContract {
                reason: "logical model resolves to more than one running service",
            });
        }
        let records = self
            .placements
            .records()
            .map_err(|_| route_state_error())?
            .into_iter()
            .map(|record| (record.group().placement_group_id().clone(), record))
            .collect::<BTreeMap<_, _>>();
        let mut routes = Vec::new();
        for placement_group_id in service.placement_group_ids() {
            let record = records
                .get(placement_group_id)
                .ok_or(GatewayError::InvalidContract {
                    reason: "model service references a missing placement group",
                })?;
            if record.group().service_id() != service.service_id() {
                return Err(GatewayError::InvalidContract {
                    reason: "placement group belongs to a different model service",
                });
            }
            if record.group().desired_state() != ModelServiceDesiredState::Running
                || record.group().state() != PlacementGroupState::Running
            {
                continue;
            }
            routes.push(self.route(service.logical_model(), record)?);
        }
        routes.sort_by(|left, right| left.placement_group_id().cmp(right.placement_group_id()));
        Ok(routes)
    }
}

impl NodeGatewayRouteProvider {
    // Projects one running placement aggregate into its local or child-relay endpoint.
    fn route(
        &self,
        model: &LogicalModelName,
        record: &PlacementRecord,
    ) -> Result<GatewayRoute, GatewayError> {
        let endpoint = record
            .group()
            .endpoint()
            .ok_or(GatewayError::InvalidContract {
                reason: "running placement group has no endpoint",
            })?;
        let target = if endpoint.node_id() == self.manager.local_node_id() {
            GatewayRouteTarget::LocalEngine {
                endpoint: endpoint.address().clone(),
            }
        } else {
            let node = self
                .manager
                .node(endpoint.node_id())
                .map_err(|_| route_state_error())?;
            if node.value().role() != NodeRole::Child || node.value().state() != NodeState::Active {
                return Err(GatewayError::InvalidContract {
                    reason: "remote placement endpoint is not on an active child",
                });
            }
            GatewayRouteTarget::ChildRelay {
                address: node.value().control_address().clone(),
            }
        };
        let temperature_millicelsius = endpoint
            .health()
            .temperature_millicelsius()
            .and_then(|temperature| u32::try_from(temperature).ok());
        let prefix_keys = endpoint
            .health()
            .prefix_keys()
            .iter()
            .map(|prefix| prefix_identity(prefix.as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        GatewayRoute::new(
            record.group().placement_group_id().clone(),
            endpoint.node_id().clone(),
            model.clone(),
            target,
            NonZeroU32::new(endpoint.max_active_requests()).ok_or(
                GatewayError::InvalidContract {
                    reason: "placement endpoint active-request capacity is zero",
                },
            )?,
            NonZeroU64::new(endpoint.max_context_tokens()).ok_or(
                GatewayError::InvalidContract {
                    reason: "placement endpoint context capacity is zero",
                },
            )?,
            endpoint.health().healthy(),
            endpoint.health().memory_pressure(),
            temperature_millicelsius,
            prefix_keys,
        )
    }
}

// Derives the canonical Gateway affinity identity from one runtime prefix key.
fn prefix_identity(value: &str) -> Result<Sha256Digest, GatewayError> {
    let mut digest = Sha256::new();
    let domain = b"li_gateway_prefix_v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| route_state_error())
}

// Returns one redacted route-state provider failure.
fn route_state_error() -> GatewayError {
    GatewayError::provider("routes", "node placement state is unavailable")
}
