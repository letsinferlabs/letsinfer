// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use li_core_interface::{PlacementGroupId, Sha256Digest};

use crate::{
    GatewayError, GatewayPlacementProtectionSnapshot, GatewayProtectionLeaseProvider, GatewayRoute,
};

const MAXIMUM_LOCAL_CACHE_MILLISECONDS: u64 = 60_000;

// Carries one validated process-local monotonic protection-cache bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayProtectionCachePolicy {
    maximum_cache_milliseconds: u64,
}

impl GatewayProtectionCachePolicy {
    // Creates one positive short cache bound without requiring a placeholder client.
    pub fn new(maximum_cache_milliseconds: u64) -> Result<Self, GatewayError> {
        if maximum_cache_milliseconds == 0
            || maximum_cache_milliseconds > MAXIMUM_LOCAL_CACHE_MILLISECONDS
        {
            return Err(poller_error());
        }
        Ok(Self {
            maximum_cache_milliseconds,
        })
    }

    // Returns the exact local monotonic age bound.
    pub const fn maximum_cache_milliseconds(self) -> u64 {
        self.maximum_cache_milliseconds
    }
}

// Supplies boot-scoped local Gateway time for transport freshness decisions.
pub trait GatewayProtectionMonotonicClock: Send + Sync {
    // Returns a non-regressing boot-scoped timestamp in milliseconds.
    fn now_milliseconds(&self) -> Result<u64, GatewayError>;
}

// Reads one process-local monotonic clock for ordinary Gateway operation.
pub struct SystemGatewayProtectionMonotonicClock {
    origin: Instant,
}

impl SystemGatewayProtectionMonotonicClock {
    // Creates one clock whose origin remains fixed for the poller lifetime.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemGatewayProtectionMonotonicClock {
    // Creates the ordinary process-local monotonic clock.
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayProtectionMonotonicClock for SystemGatewayProtectionMonotonicClock {
    // Returns elapsed process-local monotonic milliseconds.
    fn now_milliseconds(&self) -> Result<u64, GatewayError> {
        u64::try_from(self.origin.elapsed().as_millis()).map_err(|_| poller_error())
    }
}

// Returns one authenticated Node poll response bound to its exact connection and sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProtectionPollResponse {
    connection_id: Sha256Digest,
    sequence: NonZeroU64,
    snapshot: Option<GatewayPlacementProtectionSnapshot>,
}

impl GatewayProtectionPollResponse {
    // Creates one typed response after the Node transport validates its closed document.
    pub const fn new(
        connection_id: Sha256Digest,
        sequence: NonZeroU64,
        snapshot: Option<GatewayPlacementProtectionSnapshot>,
    ) -> Self {
        Self {
            connection_id,
            sequence,
            snapshot,
        }
    }

    // Returns the authenticated transport connection identity.
    pub const fn connection_id(&self) -> &Sha256Digest {
        &self.connection_id
    }

    // Returns the strictly increasing response sequence on this connection.
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    // Returns the current Node-owned snapshot or fail-closed absence.
    pub const fn snapshot(&self) -> Option<&GatewayPlacementProtectionSnapshot> {
        self.snapshot.as_ref()
    }
}

// Polls the authenticated local Node channel without owning socket or TLS lifecycle.
pub trait GatewayProtectionSnapshotClient: Send + Sync {
    // Reads one exact placement-group snapshot on the named authenticated connection.
    fn poll(
        &self,
        connection_id: &Sha256Digest,
        route: &GatewayRoute,
    ) -> Result<GatewayProtectionPollResponse, GatewayError>;
}

// Stores one response with its local monotonic receipt time.
struct CachedGatewayProtectionSnapshot {
    response_sequence: NonZeroU64,
    received_at_monotonic_milliseconds: u64,
    snapshot: Option<GatewayPlacementProtectionSnapshot>,
}

// Stores one authenticated connection and its bounded group snapshots.
#[derive(Default)]
struct GatewayProtectionPollerState {
    connection_id: Option<Sha256Digest>,
    snapshots: BTreeMap<PlacementGroupId, CachedGatewayProtectionSnapshot>,
}

// Owns fail-closed Gateway caching across the authenticated Node polling channel.
pub struct GatewayNodeProtectionPoller {
    client: Arc<dyn GatewayProtectionSnapshotClient>,
    clock: Arc<dyn GatewayProtectionMonotonicClock>,
    maximum_cache_milliseconds: u64,
    state: Mutex<GatewayProtectionPollerState>,
}

impl GatewayNodeProtectionPoller {
    // Creates one disconnected poller with a short local monotonic freshness bound.
    pub fn new(
        client: Arc<dyn GatewayProtectionSnapshotClient>,
        clock: Arc<dyn GatewayProtectionMonotonicClock>,
        cache_policy: GatewayProtectionCachePolicy,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            client,
            clock,
            maximum_cache_milliseconds: cache_policy.maximum_cache_milliseconds(),
            state: Mutex::new(GatewayProtectionPollerState::default()),
        })
    }

    // Opens one authenticated connection and invalidates every prior cached snapshot.
    pub fn connection_did_open(&self, connection_id: Sha256Digest) -> Result<(), GatewayError> {
        let mut state = self.state.lock().map_err(|_| poller_error())?;
        if state.connection_id.as_ref() != Some(&connection_id) {
            state.snapshots.clear();
            state.connection_id = Some(connection_id);
        }
        Ok(())
    }

    // Invalidates every snapshot immediately when the exact connection closes.
    pub fn connection_did_close(&self, connection_id: &Sha256Digest) -> Result<(), GatewayError> {
        let mut state = self.state.lock().map_err(|_| poller_error())?;
        if state.connection_id.as_ref() == Some(connection_id) {
            state.connection_id = None;
            state.snapshots.clear();
        }
        Ok(())
    }

    // Polls one route and refreshes local age only when Node protection state advances.
    pub fn poll(&self, route: &GatewayRoute) -> Result<(), GatewayError> {
        let connection_id = self
            .state
            .lock()
            .map_err(|_| poller_error())?
            .connection_id
            .clone()
            .ok_or_else(poller_error)?;
        let response = match self.client.poll(&connection_id, route) {
            Ok(response) => response,
            Err(error) => {
                self.invalidate_all()?;
                return Err(error);
            }
        };
        let observed_at = self.clock.now_milliseconds()?;
        let mut state = self.state.lock().map_err(|_| poller_error())?;
        if state.connection_id.as_ref() != Some(&connection_id)
            || response.connection_id() != &connection_id
            || response
                .snapshot()
                .is_some_and(|snapshot| snapshot.placement_group_id() != route.placement_group_id())
        {
            state.snapshots.clear();
            return Err(poller_error());
        }
        let previous = state.snapshots.get(route.placement_group_id());
        if previous.is_some_and(|cached| {
            response.sequence() <= cached.response_sequence
                || observed_at < cached.received_at_monotonic_milliseconds
        }) {
            state.snapshots.clear();
            return Err(poller_error());
        }
        let unchanged = previous.is_some_and(|cached| cached.snapshot == response.snapshot);
        let received_at_monotonic_milliseconds = if unchanged {
            previous
                .expect("unchanged response has a previous snapshot")
                .received_at_monotonic_milliseconds
        } else {
            observed_at
        };
        state.snapshots.insert(
            route.placement_group_id().clone(),
            CachedGatewayProtectionSnapshot {
                response_sequence: response.sequence(),
                received_at_monotonic_milliseconds,
                snapshot: response.snapshot,
            },
        );
        Ok(())
    }

    // Clears all cached state after any transport or observation failure.
    fn invalidate_all(&self) -> Result<(), GatewayError> {
        let mut state = self.state.lock().map_err(|_| poller_error())?;
        state.snapshots.clear();
        Ok(())
    }
}

impl GatewayProtectionLeaseProvider for GatewayNodeProtectionPoller {
    // Returns only state recently received on the current authenticated connection.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        let observed_at = self.clock.now_milliseconds()?;
        let state = self.state.lock().map_err(|_| poller_error())?;
        if state.connection_id.is_none() {
            return Ok(None);
        }
        let Some(cached) = state.snapshots.get(route.placement_group_id()) else {
            return Ok(None);
        };
        if observed_at < cached.received_at_monotonic_milliseconds
            || observed_at.saturating_sub(cached.received_at_monotonic_milliseconds)
                >= self.maximum_cache_milliseconds
        {
            return Ok(None);
        }
        Ok(cached.snapshot.clone())
    }
}

// Creates one stable redacted poller failure.
const fn poller_error() -> GatewayError {
    GatewayError::provider(
        "placement protection polling",
        "authenticated Node protection state is unavailable",
    )
}
