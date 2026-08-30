// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{Sha256Digest, UnixMilliseconds};

use crate::{
    NodeBenchmarkPollingPort, NodeBenchmarkSnapshot, NodeHardwareChange,
    NodeHardwareObservationProvider, NodeManager, NodeManagerError, NodeOutboxEvent,
};

// Supplies outbox acknowledgement time explicitly to the resident node loop.
pub trait NodeDaemonClock: Send + Sync {
    // Returns current non-negative Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, NodeDaemonError>;
}

// Reads production acknowledgement time from the active host.
#[derive(Default)]
pub struct SystemNodeDaemonClock;

impl NodeDaemonClock for SystemNodeDaemonClock {
    // Returns current host time without accepting a pre-epoch or overflowing clock.
    fn now(&self) -> Result<UnixMilliseconds, NodeDaemonError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NodeDaemonError::provider("clock", "system time precedes Unix epoch"))?;
        let milliseconds = u64::try_from(duration.as_millis()).map_err(|_| {
            NodeDaemonError::provider("clock", "system time exceeds timestamp range")
        })?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Delivers one secret-free durable event to its configured private consumer.
pub trait NodeOutboxDeliveryProvider: Send + Sync {
    // Delivers one event idempotently by its deterministic event identity.
    fn deliver(&self, event: &NodeOutboxEvent) -> Result<(), NodeDaemonError>;
}

// Describes one stable resident-node mechanism failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeDaemonError {
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
}

impl NodeDaemonError {
    // Creates one redacted failure at an exact injected boundary.
    pub const fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for NodeDaemonError {
    // Presents stable resident-node language without event payload details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider { capability, reason } => {
                write!(formatter, "node daemon {capability} failed: {reason}")
            }
        }
    }
}

impl Error for NodeDaemonError {}

// Summarizes one independent hardware and durable-delivery cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDaemonTick {
    hardware: Option<NodeHardwareChange>,
    hardware_failed: bool,
    benchmark: Option<NodeBenchmarkSnapshot>,
    benchmark_failed: bool,
    delivered_event_ids: Vec<Sha256Digest>,
    pending_event_ids: Vec<Sha256Digest>,
}

impl NodeDaemonTick {
    // Returns the committed hardware change when refresh succeeded.
    pub const fn hardware(&self) -> Option<&NodeHardwareChange> {
        self.hardware.as_ref()
    }

    // Returns whether hardware refresh failed without terminating delivery.
    pub const fn hardware_failed(&self) -> bool {
        self.hardware_failed
    }

    // Returns the benchmark snapshot advanced during this resident cycle.
    pub const fn benchmark(&self) -> Option<&NodeBenchmarkSnapshot> {
        self.benchmark.as_ref()
    }

    // Returns whether benchmark polling failed without terminating other resident work.
    pub const fn benchmark_failed(&self) -> bool {
        self.benchmark_failed
    }

    // Returns events delivered and acknowledged during this cycle.
    pub fn delivered_event_ids(&self) -> &[Sha256Digest] {
        &self.delivered_event_ids
    }

    // Returns events still pending after delivery or acknowledgement failure.
    pub fn pending_event_ids(&self) -> &[Sha256Digest] {
        &self.pending_event_ids
    }
}

// Owns the resident ordering between local hardware refresh and durable event delivery.
pub struct NodeDaemon {
    manager: Arc<NodeManager>,
    hardware: Arc<dyn NodeHardwareObservationProvider>,
    benchmark: Option<Arc<dyn NodeBenchmarkPollingPort>>,
    delivery: Option<Arc<dyn NodeOutboxDeliveryProvider>>,
    clock: Arc<dyn NodeDaemonClock>,
}

impl NodeDaemon {
    // Creates one resident role from explicit manager and native capabilities.
    pub const fn new(
        manager: Arc<NodeManager>,
        hardware: Arc<dyn NodeHardwareObservationProvider>,
        delivery: Arc<dyn NodeOutboxDeliveryProvider>,
        clock: Arc<dyn NodeDaemonClock>,
    ) -> Self {
        Self {
            manager,
            hardware,
            benchmark: None,
            delivery: Some(delivery),
            clock,
        }
    }

    // Creates one resident whose durable outbox is consumed only through the private API.
    pub const fn new_with_private_outbox(
        manager: Arc<NodeManager>,
        hardware: Arc<dyn NodeHardwareObservationProvider>,
        clock: Arc<dyn NodeDaemonClock>,
    ) -> Self {
        Self {
            manager,
            hardware,
            benchmark: None,
            delivery: None,
            clock,
        }
    }

    // Adds restart-safe benchmark polling to this resident Node role.
    pub fn with_benchmark(mut self, benchmark: Arc<dyn NodeBenchmarkPollingPort>) -> Self {
        self.benchmark = Some(benchmark);
        self
    }

    // Runs one non-fatal hardware refresh followed by at-least-once outbox delivery.
    pub fn tick(&self, hardware_idempotency_key: &str) -> Result<NodeDaemonTick, NodeManagerError> {
        let local = self.manager.node(self.manager.local_node_id())?;
        let hardware = self.manager.refresh_local_hardware(
            hardware_idempotency_key,
            local.revision(),
            self.hardware.as_ref(),
        );
        let hardware_failed = hardware.is_err();
        let hardware = hardware.ok();
        let benchmark = self
            .benchmark
            .as_ref()
            .map(|benchmark| benchmark.poll_active())
            .transpose();
        let benchmark_failed = benchmark.is_err();
        let benchmark = benchmark.ok().flatten().flatten();
        let mut delivered_event_ids = Vec::new();
        let mut pending_event_ids = Vec::new();
        for versioned in self.manager.pending_outbox_events()? {
            let event_id = versioned.event().event_id().clone();
            let Some(delivery) = &self.delivery else {
                pending_event_ids.push(event_id);
                continue;
            };
            if delivery.deliver(versioned.event()).is_err() {
                pending_event_ids.push(event_id);
                continue;
            }
            let acknowledged_at = match self.clock.now() {
                Ok(acknowledged_at) => acknowledged_at,
                Err(_) => {
                    pending_event_ids.push(event_id);
                    continue;
                }
            };
            let idempotency_key = format!("li_node_outbox_ack:{}", event_id.as_str());
            match self.manager.acknowledge_outbox_event(
                &idempotency_key,
                &event_id,
                versioned.revision(),
                acknowledged_at,
            ) {
                Ok(_) => delivered_event_ids.push(event_id),
                Err(_) => pending_event_ids.push(event_id),
            }
        }
        Ok(NodeDaemonTick {
            hardware,
            hardware_failed,
            benchmark,
            benchmark_failed,
            delivered_event_ids,
            pending_event_ids,
        })
    }

    // Returns the shared NodeManager for private listener and CLI composition.
    pub const fn manager(&self) -> &Arc<NodeManager> {
        &self.manager
    }
}
