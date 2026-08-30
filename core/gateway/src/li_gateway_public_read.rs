// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::sync::Arc;

use li_authentication_manager::{AuthenticationError, AuthenticationManager};
use li_core_interface::LogicalModelName;

use crate::{
    GatewayHttpError, GatewayHttpHealthProvider, GatewayHttpModelList,
    GatewayHttpModelListProvider, GatewayManager,
};

const MAX_DISCOVERABLE_NAMES: usize = 4_096;

// Binds one discoverable canonical model to its currently routable aliases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpModelInventoryEntry {
    model: LogicalModelName,
    aliases: Vec<LogicalModelName>,
}

impl GatewayHttpModelInventoryEntry {
    // Creates one canonical model entry with sorted unique aliases.
    pub fn new(
        model: LogicalModelName,
        mut aliases: Vec<LogicalModelName>,
    ) -> Result<Self, GatewayHttpError> {
        aliases.sort();
        if aliases.iter().any(|alias| alias == &model)
            || aliases.windows(2).any(|values| values[0] == values[1])
        {
            return Err(inventory_error());
        }
        Ok(Self { model, aliases })
    }

    // Returns the canonical logical model represented by this entry.
    pub const fn model(&self) -> &LogicalModelName {
        &self.model
    }

    // Returns the stable aliases that currently resolve to the canonical model.
    pub fn aliases(&self) -> &[LogicalModelName] {
        &self.aliases
    }
}

// Carries one bounded snapshot containing only healthy, currently available models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpModelInventory {
    observed_at_unix: u64,
    entries: Vec<GatewayHttpModelInventoryEntry>,
}

impl GatewayHttpModelInventory {
    // Creates one globally unique inventory without inventing availability defaults.
    pub fn new(
        observed_at_unix: u64,
        mut entries: Vec<GatewayHttpModelInventoryEntry>,
    ) -> Result<Self, GatewayHttpError> {
        entries.sort_by(|left, right| left.model().cmp(right.model()));
        let name_count = entries.iter().try_fold(0usize, |count, entry| {
            count.checked_add(1 + entry.aliases().len())
        });
        if name_count.is_none_or(|count| count > MAX_DISCOVERABLE_NAMES) {
            return Err(inventory_error());
        }
        let mut names = BTreeSet::new();
        for entry in &entries {
            if !names.insert(entry.model().as_str())
                || entry
                    .aliases()
                    .iter()
                    .any(|alias| !names.insert(alias.as_str()))
            {
                return Err(inventory_error());
            }
        }
        Ok(Self {
            observed_at_unix,
            entries,
        })
    }

    // Returns the exact Unix-second observation shared by public model rows.
    pub const fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    // Returns the sorted discoverable canonical model entries.
    pub fn entries(&self) -> &[GatewayHttpModelInventoryEntry] {
        &self.entries
    }
}

// Supplies healthy and capacity-available model identities without authenticating clients.
pub trait GatewayHttpModelInventoryProvider: Send + Sync {
    // Returns one current closed inventory snapshot or a redacted provider failure.
    fn inventory(&self) -> Result<GatewayHttpModelInventory, GatewayHttpError>;
}

// Reports whether one canonical model currently has safe admission capacity.
pub trait GatewayHttpModelAvailabilityProvider: Send + Sync {
    // Returns false for an absent, unhealthy, pressured, cooled-down, or full route set.
    fn model_is_available(&self, model: &LogicalModelName) -> Result<bool, GatewayHttpError>;
}

// Authenticates one bearer and applies its durable model scope to current inventory.
pub struct AuthenticationManagerGatewayModelListProvider {
    authentication: Arc<AuthenticationManager>,
    inventory: Arc<dyn GatewayHttpModelInventoryProvider>,
}

impl AuthenticationManagerGatewayModelListProvider {
    // Creates one public model-list adapter from exact authority and inventory roles.
    pub const fn new(
        authentication: Arc<AuthenticationManager>,
        inventory: Arc<dyn GatewayHttpModelInventoryProvider>,
    ) -> Self {
        Self {
            authentication,
            inventory,
        }
    }
}

impl GatewayHttpModelListProvider for AuthenticationManagerGatewayModelListProvider {
    // Verifies the bearer once and filters canonical models and aliases by exact scope.
    fn models(&self, bearer_token: &str) -> Result<GatewayHttpModelList, GatewayHttpError> {
        let principal = self
            .authentication
            .authenticate_identity(bearer_token)
            .map_err(authentication_error)?;
        let scope = principal.policy().model_scope();
        let inventory = self.inventory.inventory()?;
        let mut names = Vec::new();
        for entry in inventory.entries() {
            let model_permitted = scope.permits(entry.model());
            if model_permitted {
                names.push(entry.model().clone());
            }
            for alias in entry.aliases() {
                if model_permitted || scope.permits(alias) {
                    names.push(alias.clone());
                }
            }
        }
        GatewayHttpModelList::new(inventory.observed_at_unix(), names)
    }
}

impl GatewayHttpHealthProvider for GatewayManager {
    // Projects telemetry publication freshness into one fail-closed readiness result.
    fn health(&self) -> Result<bool, GatewayHttpError> {
        self.telemetry_health()
            .map(|health| health.is_healthy())
            .map_err(|_| GatewayHttpError::new(503, "gateway_unavailable", "Gateway is degraded"))
    }
}

impl GatewayHttpModelAvailabilityProvider for GatewayManager {
    // Projects the live admission state without reserving capacity or mutating telemetry.
    fn model_is_available(&self, model: &LogicalModelName) -> Result<bool, GatewayHttpError> {
        self.public_model_is_available(model)
            .map_err(|_| inventory_error())
    }
}

// Maps bearer failures to generic public authentication or authority availability errors.
fn authentication_error(error: AuthenticationError) -> GatewayHttpError {
    match error {
        AuthenticationError::Unauthorized | AuthenticationError::NotFound => {
            GatewayHttpError::new(401, "unauthorized", "credential is invalid or expired")
        }
        _ => GatewayHttpError::new(
            503,
            "key_authority_unavailable",
            "API-key authority is temporarily unavailable",
        ),
    }
}

// Returns one stable fail-closed error for malformed or oversized inventory state.
fn inventory_error() -> GatewayHttpError {
    GatewayHttpError::new(
        503,
        "gateway_unavailable",
        "Gateway model inventory is unavailable",
    )
}
