// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use li_core_interface::{NodeId, PlacementGroupId, Sha256Digest};
use li_gateway_manager::{
    GatewayError, GatewayNodeProtectionPoller, GatewayPlacementProtectionSnapshot,
    GatewayProtectionCachePolicy, GatewayProtectionLeaseProvider, GatewayProtectionMonotonicClock,
    GatewayProtectionPollResponse, GatewayProtectionSnapshotClient, GatewayRoute,
    SystemGatewayProtectionMonotonicClock,
};
use li_node_manager::{
    NodeProtectionLocalClient, NodeProtectionLocalClientConfiguration, NodeProtectionRequest,
    NodeProtectionSnapshotRequest,
};

const MAXIMUM_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAXIMUM_REGISTERED_ROUTES: usize = 1_024;

// Supplies a fresh non-secret identity for each authenticated Gateway connection attempt.
pub trait CoreGatewayProtectionConnectionIdentityProvider: Send + Sync {
    // Returns one new canonical connection identity or fails closed.
    fn next(&self) -> Result<Sha256Digest, GatewayError>;
}

// Reads system entropy so connection identities remain fresh across process restarts.
#[derive(Default)]
pub struct SystemCoreGatewayProtectionConnectionIdentityProvider;

impl CoreGatewayProtectionConnectionIdentityProvider
    for SystemCoreGatewayProtectionConnectionIdentityProvider
{
    // Returns one fresh identity derived only from bounded operating-system entropy.
    fn next(&self) -> Result<Sha256Digest, GatewayError> {
        let mut identity = [0_u8; 32];
        getrandom::fill(&mut identity).map_err(|_| protection_error())?;
        Sha256Digest::parse(&hexadecimal_identity(&identity)).map_err(|_| protection_error())
    }
}

// Represents one exact persistent Node connection used only by the polling resident.
pub trait CoreGatewayProtectionConnection: Send + Sync {
    // Returns the immutable connection identity bound into every response.
    fn connection_id(&self) -> &Sha256Digest;

    // Reads one Node-owned snapshot for the exact route.
    fn poll(
        &self,
        node_id: &NodeId,
        route: &GatewayRoute,
    ) -> Result<GatewayProtectionPollResponse, GatewayError>;
}

// Opens one authenticated connection without exposing native transport to the cache owner.
pub trait CoreGatewayProtectionConnectionProvider: Send + Sync {
    // Opens one new connection carrying the caller-supplied fresh identity.
    fn connect(
        &self,
        connection_id: Sha256Digest,
    ) -> Result<Arc<dyn CoreGatewayProtectionConnection>, GatewayError>;
}

// Opens owner-authenticated local Node protection sockets for ordinary Linux operation.
pub struct SystemCoreGatewayProtectionConnectionProvider {
    configuration: NodeProtectionLocalClientConfiguration,
}

impl SystemCoreGatewayProtectionConnectionProvider {
    // Creates one provider from an explicit dedicated protection-socket configuration.
    pub const fn new(configuration: NodeProtectionLocalClientConfiguration) -> Self {
        Self { configuration }
    }
}

impl CoreGatewayProtectionConnectionProvider for SystemCoreGatewayProtectionConnectionProvider {
    // Opens one persistent owner-authenticated local Node connection.
    fn connect(
        &self,
        connection_id: Sha256Digest,
    ) -> Result<Arc<dyn CoreGatewayProtectionConnection>, GatewayError> {
        let client = NodeProtectionLocalClient::connect(&self.configuration, connection_id)
            .map_err(|_| protection_error())?;
        Ok(Arc::new(LocalCoreGatewayProtectionConnection { client }))
    }
}

// Adapts the exact local Node client to the resident's narrow connection contract.
struct LocalCoreGatewayProtectionConnection {
    client: NodeProtectionLocalClient,
}

impl CoreGatewayProtectionConnection for LocalCoreGatewayProtectionConnection {
    // Returns the exact native transport connection identity.
    fn connection_id(&self) -> &Sha256Digest {
        self.client.connection_id()
    }

    // Requests one exact route snapshot and preserves Node response sequencing.
    fn poll(
        &self,
        node_id: &NodeId,
        route: &GatewayRoute,
    ) -> Result<GatewayProtectionPollResponse, GatewayError> {
        self.client
            .exchange_transport(NodeProtectionRequest::ReadGatewaySnapshot(
                NodeProtectionSnapshotRequest::new(
                    node_id.clone(),
                    route.placement_group_id().clone(),
                    route.endpoint_node_id().clone(),
                ),
            ))
            .map_err(|_| protection_error())?
            .into_gateway_poll_response()
            .map_err(|_| protection_error())
    }
}

// Stores only the current resident-owned connection.
#[derive(Default)]
struct CoreGatewayProtectionConnectionState {
    connection: Option<Arc<dyn CoreGatewayProtectionConnection>>,
}

// Reads the resident's current connection without owning reconnect policy.
struct CoreGatewayProtectionSnapshotClient {
    node_id: NodeId,
    state: Arc<Mutex<CoreGatewayProtectionConnectionState>>,
}

impl GatewayProtectionSnapshotClient for CoreGatewayProtectionSnapshotClient {
    // Polls outside the connection-state lock so invalidation never waits for Node I/O.
    fn poll(
        &self,
        connection_id: &Sha256Digest,
        route: &GatewayRoute,
    ) -> Result<GatewayProtectionPollResponse, GatewayError> {
        let connection = self
            .state
            .lock()
            .map_err(|_| protection_error())?
            .connection
            .clone()
            .ok_or_else(protection_error)?;
        if connection.connection_id() != connection_id {
            return Err(protection_error());
        }
        connection.poll(&self.node_id, route)
    }
}

// Owns route registration, resident reconnect policy, and nonblocking cache reads.
pub struct CoreGatewayNodeProtectionProvider {
    poller: Arc<GatewayNodeProtectionPoller>,
    routes: Mutex<BTreeMap<PlacementGroupId, GatewayRoute>>,
    state: Arc<Mutex<CoreGatewayProtectionConnectionState>>,
    identities: Arc<dyn CoreGatewayProtectionConnectionIdentityProvider>,
    connections: Arc<dyn CoreGatewayProtectionConnectionProvider>,
    resident_healthy: Arc<AtomicBool>,
}

impl CoreGatewayNodeProtectionProvider {
    // Creates one disconnected production provider without opening native I/O.
    pub fn new(
        node_id: NodeId,
        configuration: NodeProtectionLocalClientConfiguration,
        cache_policy: GatewayProtectionCachePolicy,
    ) -> Result<Self, GatewayError> {
        Self::new_with_providers(
            node_id,
            cache_policy,
            Arc::new(SystemGatewayProtectionMonotonicClock::new()),
            Arc::new(SystemCoreGatewayProtectionConnectionIdentityProvider),
            Arc::new(SystemCoreGatewayProtectionConnectionProvider::new(
                configuration,
            )),
        )
    }

    // Creates one disconnected provider with injected clocks and native connection boundaries.
    pub fn new_with_providers(
        node_id: NodeId,
        cache_policy: GatewayProtectionCachePolicy,
        clock: Arc<dyn GatewayProtectionMonotonicClock>,
        identities: Arc<dyn CoreGatewayProtectionConnectionIdentityProvider>,
        connections: Arc<dyn CoreGatewayProtectionConnectionProvider>,
    ) -> Result<Self, GatewayError> {
        let state = Arc::new(Mutex::new(CoreGatewayProtectionConnectionState::default()));
        let client = Arc::new(CoreGatewayProtectionSnapshotClient {
            node_id,
            state: state.clone(),
        });
        let poller = Arc::new(GatewayNodeProtectionPoller::new(
            client,
            clock,
            cache_policy,
        )?);
        Ok(Self {
            poller,
            routes: Mutex::new(BTreeMap::new()),
            state,
            identities,
            connections,
            resident_healthy: Arc::new(AtomicBool::new(true)),
        })
    }

    // Polls every registered route outside any inference request and fails closed as one set.
    pub fn poll_once(&self) -> Result<(), GatewayError> {
        let routes = self
            .routes
            .lock()
            .map_err(|_| protection_error())?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        if routes.is_empty() {
            return Ok(());
        }
        let connection_id = self.open_connection_if_needed()?;
        for route in routes {
            if self.poller.poll(&route).is_err() {
                self.connection_did_fail(&connection_id)?;
                return Err(protection_error());
            }
        }
        Ok(())
    }

    // Opens one fresh authenticated connection and publishes no cache until a poll succeeds.
    fn open_connection_if_needed(&self) -> Result<Sha256Digest, GatewayError> {
        if let Some(identity) = self.current_connection_identity()? {
            return Ok(identity);
        }
        let identity = self.identities.next()?;
        let connection = self.connections.connect(identity.clone())?;
        if connection.connection_id() != &identity {
            return Err(protection_error());
        }
        let mut state = self.state.lock().map_err(|_| protection_error())?;
        if state.connection.is_none() {
            state.connection = Some(connection);
            drop(state);
            self.poller.connection_did_open(identity.clone())?;
            return Ok(identity);
        }
        state
            .connection
            .as_ref()
            .map(|current| current.connection_id().clone())
            .ok_or_else(protection_error)
    }

    // Returns the current connection identity without waiting for transport I/O.
    fn current_connection_identity(&self) -> Result<Option<Sha256Digest>, GatewayError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| protection_error())?
            .connection
            .as_ref()
            .map(|connection| connection.connection_id().clone()))
    }

    // Drops one ambiguous connection and immediately clears every cached snapshot.
    fn connection_did_fail(&self, connection_id: &Sha256Digest) -> Result<(), GatewayError> {
        let mut state = self.state.lock().map_err(|_| protection_error())?;
        if state
            .connection
            .as_ref()
            .is_some_and(|connection| connection.connection_id() == connection_id)
        {
            state.connection = None;
        }
        drop(state);
        self.poller.connection_did_close(connection_id)
    }
}

impl GatewayProtectionLeaseProvider for CoreGatewayNodeProtectionProvider {
    // Registers the current route and returns only the already-received monotonic cache.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        if !self.resident_healthy.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut routes = self.routes.lock().map_err(|_| protection_error())?;
        if !routes.contains_key(route.placement_group_id())
            && routes.len() >= MAXIMUM_REGISTERED_ROUTES
        {
            return Err(protection_error());
        }
        routes.insert(route.placement_group_id().clone(), route.clone());
        drop(routes);
        self.poller.snapshot(route)
    }
}

// Owns the one bounded background poll loop used by a Gateway process.
pub struct CoreGatewayProtectionResident {
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl CoreGatewayProtectionResident {
    // Starts one resident after validating its positive short polling cadence.
    pub fn start(
        provider: Arc<CoreGatewayNodeProtectionProvider>,
        poll_interval: Duration,
    ) -> Result<Self, GatewayError> {
        if poll_interval.is_zero() || poll_interval > MAXIMUM_POLL_INTERVAL {
            return Err(protection_error());
        }
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        provider.resident_healthy.store(true, Ordering::Release);
        let resident_healthy = provider.resident_healthy.clone();
        let worker_provider = provider.clone();
        let worker = thread::Builder::new()
            .name("li_gateway_protection_resident".to_string())
            .spawn(move || {
                let _health = CoreGatewayProtectionResidentHealth::new(resident_healthy);
                while !worker_stopping.load(Ordering::Acquire) {
                    let _ = worker_provider.poll_once();
                    thread::park_timeout(poll_interval);
                }
            })
            .map_err(|_| {
                provider.resident_healthy.store(false, Ordering::Release);
                protection_error()
            })?;
        Ok(Self {
            stopping,
            worker: Some(worker),
        })
    }

    // Requests shutdown and wakes the resident immediately.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.worker.as_ref() {
            worker.thread().unpark();
        }
    }

    // Completes bounded resident shutdown after any in-flight configured IPC timeout.
    pub fn join(&mut self) -> Result<(), GatewayError> {
        self.stop();
        self.worker
            .take()
            .ok_or_else(protection_error)?
            .join()
            .map_err(|_| protection_error())
    }
}

// Clears process-local safety immediately whenever the polling worker exits or panics.
struct CoreGatewayProtectionResidentHealth(Arc<AtomicBool>);

impl CoreGatewayProtectionResidentHealth {
    // Arms one worker-exit health guard.
    const fn new(healthy: Arc<AtomicBool>) -> Self {
        Self(healthy)
    }
}

impl Drop for CoreGatewayProtectionResidentHealth {
    // Marks the provider unavailable before Rust unwinds a failed resident.
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Drop for CoreGatewayProtectionResident {
    // Requests shutdown without hiding an explicit join result from the process owner.
    fn drop(&mut self) {
        self.stop();
    }
}

// Encodes one fixed-size entropy value as its canonical lowercase digest text.
fn hexadecimal_identity(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}

// Returns one stable redacted placement-protection composition failure.
const fn protection_error() -> GatewayError {
    GatewayError::provider(
        "Node protection IPC",
        "authenticated Node protection state is unavailable",
    )
}
