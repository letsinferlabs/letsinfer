// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{ModelServiceDesiredState, NodeRole, NodeState, UnixMilliseconds};
use li_gateway_manager::{
    GatewayHttpError, GatewayHttpModelAvailabilityProvider, GatewayHttpModelInventory,
    GatewayHttpModelInventoryEntry, GatewayHttpModelInventoryProvider, GatewayHttpModelProvider,
};

use crate::NodeManager;

// Supplies the public inventory observation time through one deterministic boundary.
pub trait NodeGatewayInventoryClock: Send + Sync {
    // Returns current non-negative Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, GatewayHttpError>;
}

// Reads public inventory observation time from the active host.
#[derive(Default)]
pub struct SystemNodeGatewayInventoryClock;

impl NodeGatewayInventoryClock for SystemNodeGatewayInventoryClock {
    // Returns current host time without accepting pre-epoch or overflowing clocks.
    fn now(&self) -> Result<UnixMilliseconds, GatewayHttpError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| inventory_error())?;
        let milliseconds = u64::try_from(duration.as_millis()).map_err(|_| inventory_error())?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Projects main-owned model services through the Gateway's exact live admission gates.
pub struct NodeGatewayModelInventoryProvider {
    manager: Arc<NodeManager>,
    availability: Arc<dyn GatewayHttpModelAvailabilityProvider>,
    clock: Arc<dyn NodeGatewayInventoryClock>,
}

// Resolves public request names against the one canonical Node-owned model-service identity.
pub struct NodeGatewayModelProvider {
    manager: Arc<NodeManager>,
}

impl NodeGatewayModelProvider {
    // Creates one read-only canonical model resolver.
    pub const fn new(manager: Arc<NodeManager>) -> Self {
        Self { manager }
    }
}

impl GatewayHttpModelProvider for NodeGatewayModelProvider {
    // Resolves one exact running canonical model and rejects absent or ambiguous state.
    fn resolve(
        &self,
        requested_model: &str,
    ) -> Result<li_core_interface::LogicalModelName, GatewayHttpError> {
        let requested = li_core_interface::LogicalModelName::parse(requested_model)
            .map_err(|_| model_resolution_error())?;
        let matching = self
            .manager
            .model_services()
            .map_err(|_| model_resolution_error())?
            .into_iter()
            .filter(|service| {
                service.logical_model() == &requested
                    && service.desired_state() == ModelServiceDesiredState::Running
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(model_resolution_error());
        }
        Ok(requested)
    }
}

impl NodeGatewayModelInventoryProvider {
    // Creates one read-only composition without duplicating Gateway admission policy.
    pub const fn new(
        manager: Arc<NodeManager>,
        availability: Arc<dyn GatewayHttpModelAvailabilityProvider>,
        clock: Arc<dyn NodeGatewayInventoryClock>,
    ) -> Self {
        Self {
            manager,
            availability,
            clock,
        }
    }
}

impl GatewayHttpModelInventoryProvider for NodeGatewayModelInventoryProvider {
    // Returns only running canonical models with immediate safe Gateway capacity.
    fn inventory(&self) -> Result<GatewayHttpModelInventory, GatewayHttpError> {
        let local = self.manager.local_node().map_err(|_| inventory_error())?;
        if local.role() != NodeRole::Main || local.state() != NodeState::Active {
            return Err(inventory_error());
        }
        let services = self
            .manager
            .model_services()
            .map_err(|_| inventory_error())?;
        let mut configured_models = BTreeSet::new();
        for service in services
            .iter()
            .filter(|service| service.desired_state() != ModelServiceDesiredState::Removed)
        {
            if !configured_models.insert(service.logical_model().clone()) {
                return Err(inventory_error());
            }
        }
        let mut entries = Vec::new();
        for service in services
            .into_iter()
            .filter(|service| service.desired_state() == ModelServiceDesiredState::Running)
        {
            if self
                .availability
                .model_is_available(service.logical_model())
                .map_err(|_| inventory_error())?
            {
                entries.push(
                    GatewayHttpModelInventoryEntry::new(
                        service.logical_model().clone(),
                        Vec::new(),
                    )
                    .map_err(|_| inventory_error())?,
                );
            }
        }
        let observed_at_unix = self.clock.now().map_err(|_| inventory_error())?.value() / 1_000;
        GatewayHttpModelInventory::new(observed_at_unix, entries).map_err(|_| inventory_error())
    }
}

// Returns one generic public failure for unavailable or inconsistent composition state.
fn inventory_error() -> GatewayHttpError {
    GatewayHttpError::new(
        503,
        "gateway_unavailable",
        "Gateway model inventory is unavailable",
    )
}

// Returns one indistinguishable public model-resolution failure.
fn model_resolution_error() -> GatewayHttpError {
    GatewayHttpError::new(404, "model_not_found", "requested model is unavailable")
}
