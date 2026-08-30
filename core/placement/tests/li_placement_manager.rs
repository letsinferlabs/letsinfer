// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use li_core_interface::{
    BootId, CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership,
    EndpointScheme, EngineDistribution, HardwareObservationId, InterconnectKind,
    InterconnectRequirement, ModelServiceId, NodeAddress, NodeId, Placement, PlacementAssignment,
    PlacementEndpoint, PlacementGroupId, PlacementGroupState, PlacementId, PlacementState,
    PortRange, ResourceIdentity, ResourceLease, ResourceLeaseId, ResourceLeaseState,
    RuntimeCandidateId, RuntimeIdentity, RuntimeInstallationId, RuntimeSource, RuntimeVersion,
    Sha256Digest, TargetId, TaskId, UnixMilliseconds,
};
use li_placement_manager::{
    FilesystemPlacementBenchmarkResetProvider, PlacementAdmissionPolicy,
    PlacementBenchmarkGenerations, PlacementBenchmarkIsolationReceipt,
    PlacementBenchmarkIsolationRequest, PlacementBenchmarkProcessProvider,
    PlacementBenchmarkResetProvider, PlacementBenchmarkResetReceipt,
    PlacementBenchmarkResetRequest, PlacementBenchmarkRestorationReceipt, PlacementClock,
    PlacementError, PlacementEvent, PlacementExecutor, PlacementIdentityProvider,
    PlacementLaunchPlanIdentityProvider, PlacementLink, PlacementLogBatch, PlacementLogCursor,
    PlacementLogReadRequest, PlacementManager, PlacementNodeResources, PlacementObservation,
    PlacementRecord, PlacementRequest, PlacementRuntimeLogProvider, PlacementStore, PlacementTask,
    StoredPlacementLaunchPlanIdentityProvider, VersionedPlacementRecord,
};

// Supplies an exact runtime identity without exposing engine-native semantics.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark-connectx-2")
            .expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark-connectx-2").expect("target"),
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/runtime-artifacts/qwen@sha256:{}",
            "a".repeat(64)
        ))
        .expect("runtime source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/engine-images/qwen@sha256:{}",
                "b".repeat(64)
            ))
            .expect("Engine source"),
            Sha256Digest::parse(&"c".repeat(64)).expect("Engine identity"),
            None,
            Some(Sha256Digest::parse(&"d".repeat(64)).expect("payload")),
        ),
        Sha256Digest::parse(&"a".repeat(64)).expect("runtime digest"),
        Sha256Digest::parse(&"e".repeat(64)).expect("manifest"),
        Sha256Digest::parse(&"f".repeat(64)).expect("execution"),
    )
    .expect("runtime identity")
}

// Returns one deterministic two-node opaque placement request.
fn request(startup_order: Vec<Vec<TaskId>>) -> PlacementRequest {
    let first_node = NodeId::parse(&"1".repeat(32)).expect("first node");
    let second_node = NodeId::parse(&"2".repeat(32)).expect("second node");
    PlacementRequest::new(
        PlacementGroupId::parse(&"8".repeat(32)).expect("group"),
        ModelServiceId::parse(&"3".repeat(32)).expect("service"),
        runtime_identity(),
        li_core_interface::PlacementGroupCapacity::new(
            16,
            8,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Connectx, true, 200_000, 1_500),
        )
        .expect("capacity"),
        vec![
            PlacementTask::new(TaskId::parse("task-0").expect("task"), 1, 2).expect("task"),
            PlacementTask::new(TaskId::parse("task-1").expect("task"), 1, 2).expect("task"),
        ],
        vec![
            PlacementNodeResources::new(
                first_node.clone(),
                RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
                HardwareObservationId::parse(&"6".repeat(32)).expect("hardware observation"),
                BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
                UnixMilliseconds::new(900),
                NodeAddress::parse("spark-a.local").expect("address"),
                vec![
                    DeviceId::parse("GPU-B").expect("GPU"),
                    DeviceId::parse("GPU-A").expect("GPU"),
                ],
                PortRange::new(18_000, 8).expect("ports"),
                Some(li_core_interface::NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
            )
            .expect("first resources"),
            PlacementNodeResources::new(
                second_node.clone(),
                RuntimeInstallationId::parse(&"5".repeat(32)).expect("installation"),
                HardwareObservationId::parse(&"7".repeat(32)).expect("hardware observation"),
                BootId::parse("66666666-7777-8888-9999-000000000000").expect("boot"),
                UnixMilliseconds::new(900),
                NodeAddress::parse("spark-b.local").expect("address"),
                vec![
                    DeviceId::parse("GPU-D").expect("GPU"),
                    DeviceId::parse("GPU-C").expect("GPU"),
                ],
                PortRange::new(19_000, 8).expect("ports"),
                Some(li_core_interface::NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
            )
            .expect("second resources"),
        ],
        TaskId::parse("task-0").expect("endpoint task"),
        second_node.clone(),
        startup_order,
        vec![PlacementLink::new(
            first_node,
            second_node,
            InterconnectKind::Connectx,
            true,
            200_000,
            1_500,
        )
        .expect("link")],
    )
    .expect("request")
}

// Rebuilds one request with explicit observation times and optional provenance collision.
fn request_with_hardware_observations(
    first_observed_at: u64,
    second_observed_at: u64,
    duplicate_observation_identity: bool,
) -> Result<PlacementRequest, PlacementError> {
    let source = request(concurrent_startup_order());
    let nodes = source
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let observation_id = if duplicate_observation_identity && index == 1 {
                source.nodes()[0].hardware_observation_id().clone()
            } else {
                node.hardware_observation_id().clone()
            };
            PlacementNodeResources::new(
                node.node_id().clone(),
                node.runtime_installation_id().clone(),
                observation_id,
                node.boot_id().clone(),
                UnixMilliseconds::new(if index == 0 {
                    first_observed_at
                } else {
                    second_observed_at
                }),
                node.address().clone(),
                node.device_ids().to_vec(),
                node.ports(),
                node.rdma_interface().cloned(),
            )
        })
        .collect::<Result<Vec<_>, PlacementError>>()?;
    PlacementRequest::new(
        source.placement_group_id().clone(),
        source.service_id().clone(),
        source.runtime().clone(),
        source.capacity(),
        source.tasks().to_vec(),
        nodes,
        source.endpoint_task_id().clone(),
        source.endpoint_node_id().clone(),
        source.startup_order().to_vec(),
        source.links().to_vec(),
    )
}

// Returns a two-node parallel request whose non-RDMA resources allow two replicas.
fn replicable_request(character: char) -> PlacementRequest {
    let source = request(concurrent_startup_order());
    let nodes = source
        .nodes()
        .iter()
        .map(|node| {
            PlacementNodeResources::new(
                node.node_id().clone(),
                node.runtime_installation_id().clone(),
                node.hardware_observation_id().clone(),
                node.boot_id().clone(),
                node.observed_at(),
                node.address().clone(),
                node.device_ids().to_vec(),
                node.ports(),
                None,
            )
            .expect("replica resources")
        })
        .collect();
    PlacementRequest::new(
        PlacementGroupId::parse(&character.to_string().repeat(32)).expect("replica group"),
        source.service_id().clone(),
        source.runtime().clone(),
        li_core_interface::PlacementGroupCapacity::new(
            source.capacity().max_connections(),
            source.capacity().max_active_requests(),
            source.capacity().max_context_tokens(),
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("replica capacity"),
        source.tasks().to_vec(),
        nodes,
        source.endpoint_task_id().clone(),
        source.endpoint_node_id().clone(),
        source.startup_order().to_vec(),
        source.links().to_vec(),
    )
    .expect("replicable request")
}

// Returns the ordinary two-task concurrent startup order.
fn concurrent_startup_order() -> Vec<Vec<TaskId>> {
    vec![vec![
        TaskId::parse("task-0").expect("task"),
        TaskId::parse("task-1").expect("task"),
    ]]
}

// Returns the explicit five-minute hardware-freshness policy used by fixtures.
fn admission_policy() -> PlacementAdmissionPolicy {
    PlacementAdmissionPolicy::new(Duration::from_secs(300)).expect("admission policy")
}

// Stores placement aggregates and enforces resource conflicts atomically.
#[derive(Default)]
struct MockStore {
    records: Mutex<BTreeMap<String, VersionedPlacementRecord>>,
    external: Mutex<HashMap<String, Vec<ResourceIdentity>>>,
    fail_occupied: AtomicBool,
    fail_create: AtomicBool,
    fail_read: AtomicBool,
    fail_replace: AtomicBool,
    commit_then_conflict: AtomicBool,
    replace_count: AtomicUsize,
    fail_replace_at: AtomicUsize,
    fail_replace_from: AtomicUsize,
    create_barrier: Mutex<Option<Arc<Barrier>>>,
    replace_barrier: Mutex<Option<Arc<Barrier>>>,
    replace_barrier_count: AtomicUsize,
}

impl MockStore {
    // Adds one externally occupied resource for deterministic allocation tests.
    fn occupy(&self, node_id: &NodeId, resource: ResourceIdentity) {
        self.external
            .lock()
            .expect("external resources")
            .entry(node_id.as_str().to_string())
            .or_default()
            .push(resource);
    }

    // Returns one stored record for assertions.
    fn stored(&self, placement_group_id: &PlacementGroupId) -> VersionedPlacementRecord {
        self.records
            .lock()
            .expect("records")
            .get(placement_group_id.as_str())
            .expect("stored group")
            .clone()
    }

    // Returns every occupied resource while the store lock is held.
    fn occupied_locked(
        records: &BTreeMap<String, VersionedPlacementRecord>,
        external: &HashMap<String, Vec<ResourceIdentity>>,
        node_id: &NodeId,
        excluding: Option<&PlacementGroupId>,
    ) -> Vec<ResourceIdentity> {
        let mut resources = external.get(node_id.as_str()).cloned().unwrap_or_default();
        for value in records.values() {
            if excluding
                .is_some_and(|identity| value.record().group().placement_group_id() == identity)
            {
                continue;
            }
            resources.extend(
                value
                    .record()
                    .leases()
                    .iter()
                    .filter(|lease| {
                        lease.node_id() == node_id && lease.state() != ResourceLeaseState::Released
                    })
                    .map(|lease| lease.resource().clone()),
            );
        }
        resources
    }

    // Requires every new non-released lease to remain unoccupied.
    fn require_available(
        records: &BTreeMap<String, VersionedPlacementRecord>,
        external: &HashMap<String, Vec<ResourceIdentity>>,
        record: &PlacementRecord,
        excluding: Option<&PlacementGroupId>,
    ) -> Result<(), PlacementError> {
        for lease in record
            .leases()
            .iter()
            .filter(|lease| lease.state() != ResourceLeaseState::Released)
        {
            let occupied = Self::occupied_locked(records, external, lease.node_id(), excluding);
            if occupied.iter().any(|resource| resource == lease.resource()) {
                return Err(PlacementError::ResourceConflict);
            }
        }
        Ok(())
    }
}

impl PlacementStore for MockStore {
    // Returns current resources or the configured native-store failure.
    fn occupied_resources(
        &self,
        node_id: &NodeId,
    ) -> Result<Vec<ResourceIdentity>, PlacementError> {
        if self.fail_occupied.load(Ordering::SeqCst) {
            return Err(PlacementError::StoreUnavailable);
        }
        let records = self
            .records
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?;
        let external = self
            .external
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?;
        Ok(Self::occupied_locked(&records, &external, node_id, None))
    }

    // Creates one aggregate while atomically rejecting resource overlap.
    fn create(&self, record: PlacementRecord) -> Result<VersionedPlacementRecord, PlacementError> {
        let barrier = self.create_barrier.lock().expect("barrier").clone();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        if self.fail_create.load(Ordering::SeqCst) {
            return Err(PlacementError::StoreUnavailable);
        }
        let identity = record.group().placement_group_id().clone();
        let mut records = self
            .records
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?;
        let external = self
            .external
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?;
        if records.contains_key(identity.as_str()) {
            return Err(PlacementError::StoreConflict);
        }
        Self::require_available(&records, &external, &record, None)?;
        let stored = VersionedPlacementRecord::new(record, 1);
        records.insert(identity.as_str().to_string(), stored.clone());
        Ok(stored)
    }

    // Returns one stored aggregate by exact group identity.
    fn read(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError> {
        if self.fail_read.load(Ordering::SeqCst) {
            return Err(PlacementError::StoreUnavailable);
        }
        Ok(self
            .records
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?
            .get(placement_group_id.as_str())
            .cloned())
    }

    // Replaces one exact revision while retaining conflict enforcement.
    fn replace(
        &self,
        record: PlacementRecord,
        expected_revision: u64,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        let replace_barrier = self.replace_barrier.lock().expect("barrier").clone();
        if let Some(barrier) = replace_barrier {
            if self.replace_barrier_count.fetch_add(1, Ordering::SeqCst) < 2 {
                barrier.wait();
            }
        }
        let attempt = self.replace_count.fetch_add(1, Ordering::SeqCst) + 1;
        let fail_at = self.fail_replace_at.load(Ordering::SeqCst);
        let fail_from = self.fail_replace_from.load(Ordering::SeqCst);
        if self.fail_replace.load(Ordering::SeqCst)
            || (fail_at != 0 && attempt == fail_at)
            || (fail_from != 0 && attempt >= fail_from)
        {
            return Err(PlacementError::StoreConflict);
        }
        let identity = record.group().placement_group_id().clone();
        let mut records = self
            .records
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?;
        let current = records
            .get(identity.as_str())
            .ok_or(PlacementError::GroupNotFound)?;
        if current.revision() != expected_revision {
            return Err(PlacementError::StoreConflict);
        }
        let external = self
            .external
            .lock()
            .map_err(|_| PlacementError::StoreUnavailable)?;
        Self::require_available(&records, &external, &record, Some(&identity))?;
        let stored = VersionedPlacementRecord::new(record, expected_revision + 1);
        records.insert(identity.as_str().to_string(), stored.clone());
        if self.commit_then_conflict.swap(false, Ordering::SeqCst) {
            Err(PlacementError::StoreConflict)
        } else {
            Ok(stored)
        }
    }
}

// Supplies deterministic unique identities and configurable entropy failure.
struct MockIdentity {
    next: AtomicU64,
    fail: AtomicBool,
}

impl Default for MockIdentity {
    // Creates one deterministic identity sequence.
    fn default() -> Self {
        Self {
            next: AtomicU64::new(10),
            fail: AtomicBool::new(false),
        }
    }
}

impl MockIdentity {
    // Returns the next canonical 128-bit identity string.
    fn value(&self) -> Result<String, PlacementError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlacementError::IdentityUnavailable);
        }
        Ok(format!("{:032x}", self.next.fetch_add(1, Ordering::SeqCst)))
    }
}

impl PlacementIdentityProvider for MockIdentity {
    // Returns one deterministic placement identity without interpreting the task.
    fn placement_id(&self, _task_id: &TaskId) -> Result<PlacementId, PlacementError> {
        PlacementId::parse(&self.value()?).map_err(|_| PlacementError::IdentityUnavailable)
    }

    // Returns one deterministic lease identity without inspecting the resource kind.
    fn resource_lease_id(
        &self,
        _placement_id: &PlacementId,
        _resource: &ResourceIdentity,
    ) -> Result<ResourceLeaseId, PlacementError> {
        ResourceLeaseId::parse(&self.value()?).map_err(|_| PlacementError::IdentityUnavailable)
    }
}

// Supplies deterministic increasing time and configurable clock failure.
struct MockClock {
    next: AtomicU64,
    fail: AtomicBool,
    fail_at: AtomicU64,
}

impl Default for MockClock {
    // Creates one deterministic lifecycle clock.
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1_000),
            fail: AtomicBool::new(false),
            fail_at: AtomicU64::new(u64::MAX),
        }
    }
}

impl PlacementClock for MockClock {
    // Returns one increasing timestamp or the configured clock failure.
    fn now(&self) -> Result<UnixMilliseconds, PlacementError> {
        let value = self.next.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) || value == self.fail_at.load(Ordering::SeqCst) {
            return Err(PlacementError::ClockUnavailable);
        }
        Ok(UnixMilliseconds::new(value))
    }
}

// Mocks every node-execution action at its narrow task boundary.
#[derive(Default)]
struct MockExecutor {
    calls: Mutex<Vec<String>>,
    failures: Mutex<HashSet<String>>,
    observe_failures: Mutex<HashSet<String>>,
    protection_trips: Mutex<HashSet<String>>,
    missing_owner_endpoint: AtomicBool,
    participant_endpoint: AtomicBool,
    unhealthy_endpoint: AtomicBool,
    foreign_endpoint_host: AtomicBool,
    unleased_endpoint_port: AtomicBool,
    oversized_endpoint: AtomicBool,
    start_barrier: Mutex<Option<Arc<Barrier>>>,
    acknowledged: Mutex<Vec<bool>>,
}

impl MockExecutor {
    // Configures one exact action and task failure.
    fn fail(&self, action: &str, task_id: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(format!("{action}:{task_id}"));
    }

    // Returns whether one configured action must fail.
    fn should_fail(&self, action: &str, placement: &Placement) -> bool {
        self.failures.lock().expect("failures").contains(&format!(
            "{action}:{}",
            placement.assignment().task_id().as_str()
        ))
    }

    // Records one stable action trace.
    fn record(&self, action: &str, placement: &Placement) {
        self.calls.lock().expect("calls").push(format!(
            "{action}:{}",
            placement.assignment().task_id().as_str()
        ));
    }

    // Returns one valid endpoint owned by the supplied placement.
    fn endpoint(&self, placement: &Placement, healthy: bool) -> PlacementEndpoint {
        let ports = placement.assignment().resources().ports();
        let host = if self.foreign_endpoint_host.load(Ordering::SeqCst) {
            NodeAddress::parse("foreign.local").expect("foreign address")
        } else {
            placement.assignment().address().clone()
        };
        let port = if self.unleased_endpoint_port.load(Ordering::SeqCst) {
            ports.last() + 1
        } else {
            ports.base()
        };
        let oversized = self.oversized_endpoint.load(Ordering::SeqCst);
        PlacementEndpoint::new(
            placement.placement_id().clone(),
            placement.assignment().node_id().clone(),
            EndpointAddress::new(EndpointScheme::Https, host, port).expect("endpoint address"),
            CredentialId::parse(&"c".repeat(32)).expect("credential"),
            Some(CredentialId::parse(&"d".repeat(32)).expect("CA")),
            None,
            if oversized { 9 } else { 8 },
            if oversized { 262_145 } else { 262_144 },
            EndpointHealth::new(healthy, false, None, Vec::new()).expect("health"),
        )
        .expect("endpoint")
    }

    // Returns the captured execution trace.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}

impl PlacementExecutor for MockExecutor {
    // Records and resolves one deterministic staging action.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.record("stage", placement);
        if self.should_fail("stage", placement) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Sha256Digest::parse(&format!(
                "{:0>64}",
                placement
                    .assignment()
                    .task_id()
                    .as_str()
                    .trim_start_matches("task-")
            ))
            .map_err(|_| PlacementError::ExecutionUnavailable)
        }
    }

    // Records start concurrency and returns only the declared endpoint.
    fn start(
        &self,
        placement: &Placement,
        acknowledge_protection_trip: bool,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        self.record("start", placement);
        self.acknowledged
            .lock()
            .expect("acknowledgements")
            .push(acknowledge_protection_trip);
        let barrier = self.start_barrier.lock().expect("barrier").clone();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        if self.should_fail("start", placement) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        match placement.assignment().endpoint_ownership() {
            EndpointOwnership::Owner if self.missing_owner_endpoint.load(Ordering::SeqCst) => {
                Ok(None)
            }
            EndpointOwnership::Owner => Ok(Some(
                self.endpoint(placement, !self.unhealthy_endpoint.load(Ordering::SeqCst)),
            )),
            EndpointOwnership::Participant if self.participant_endpoint.load(Ordering::SeqCst) => {
                Ok(Some(self.endpoint(placement, true)))
            }
            EndpointOwnership::Participant => Ok(None),
        }
    }

    // Records and resolves one deterministic stop action.
    fn stop(&self, placement: &Placement) -> Result<(), PlacementError> {
        self.record("stop", placement);
        if self.should_fail("stop", placement) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }

    // Records and resolves one deterministic removal action.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError> {
        self.record("remove", placement);
        if self.should_fail("remove", placement) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }

    // Returns current task state, endpoint, or the configured observation failure.
    fn observe(&self, placement: &Placement) -> Result<PlacementObservation, PlacementError> {
        self.record("observe", placement);
        let task_id = placement.assignment().task_id().as_str();
        if self
            .observe_failures
            .lock()
            .expect("observation failures")
            .contains(task_id)
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let endpoint = match placement.assignment().endpoint_ownership() {
            EndpointOwnership::Owner if placement.state() == PlacementState::Running => {
                Some(self.endpoint(placement, true))
            }
            EndpointOwnership::Participant if self.participant_endpoint.load(Ordering::SeqCst) => {
                Some(self.endpoint(placement, true))
            }
            _ => None,
        };
        Ok(PlacementObservation::new(
            placement.state(),
            endpoint,
            self.protection_trips
                .lock()
                .expect("protection trips")
                .contains(task_id),
        ))
    }
}

// Records the exact endpoint-owner placement selected for opaque runtime log access.
#[derive(Default)]
struct MockLogs {
    placement_ids: Mutex<Vec<PlacementId>>,
}

impl PlacementRuntimeLogProvider for MockLogs {
    // Returns one deterministic opaque batch bound to the supplied placement identity.
    fn read(
        &self,
        placement: &Placement,
        request: &PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError> {
        self.placement_ids
            .lock()
            .expect("placement identities")
            .push(placement.placement_id().clone());
        PlacementLogBatch::new(
            request.placement_group_id().clone(),
            placement.placement_id().clone(),
            PlacementLogCursor::new(
                Sha256Digest::parse(&"9".repeat(64)).expect("source"),
                "fixture-position".to_string(),
            )?,
            b"opaque runtime output\n".to_vec(),
            false,
        )
    }
}

// Persists exact benchmark reset receipts and supplies deterministic native generations.
struct MockBenchmarkResetProvider {
    isolations: Mutex<HashMap<String, PlacementBenchmarkIsolationReceipt>>,
    receipts: Mutex<HashMap<String, PlacementBenchmarkResetReceipt>>,
    restorations: Mutex<HashMap<String, PlacementBenchmarkRestorationReceipt>>,
    calls: Mutex<Vec<String>>,
    next_generation: AtomicU64,
    current: Mutex<PlacementBenchmarkGenerations>,
    fail_store: AtomicBool,
    fail_process: AtomicBool,
    fail_commit: AtomicBool,
    fail_restore: AtomicBool,
    unchanged_store: AtomicBool,
    unchanged_process: AtomicBool,
}

impl Default for MockBenchmarkResetProvider {
    // Creates one running process/store baseline and a disjoint generation sequence.
    fn default() -> Self {
        Self {
            isolations: Mutex::new(HashMap::new()),
            receipts: Mutex::new(HashMap::new()),
            restorations: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            next_generation: AtomicU64::new(3),
            current: Mutex::new(PlacementBenchmarkGenerations::new(
                Sha256Digest::parse(&"1".repeat(64)).expect("process generation"),
                Sha256Digest::parse(&"2".repeat(64)).expect("store generation"),
            )),
            fail_store: AtomicBool::new(false),
            fail_process: AtomicBool::new(false),
            fail_commit: AtomicBool::new(false),
            fail_restore: AtomicBool::new(false),
            unchanged_store: AtomicBool::new(false),
            unchanged_process: AtomicBool::new(false),
        }
    }
}

impl MockBenchmarkResetProvider {
    // Returns one new canonical generation digest.
    fn generation(&self) -> Sha256Digest {
        Sha256Digest::parse(&format!(
            "{:064x}",
            self.next_generation.fetch_add(1, Ordering::SeqCst)
        ))
        .expect("generation")
    }

    // Returns the exact provider call trace.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}

impl PlacementBenchmarkResetProvider for MockBenchmarkResetProvider {
    // Captures one exact original generation pair and replays it across manager restart.
    fn prepare_isolation(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<PlacementBenchmarkIsolationReceipt, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("prepare_isolation".to_string());
        let mut isolations = self.isolations.lock().expect("isolations");
        if let Some(existing) = isolations.get(request.isolation_id().as_str()) {
            return if existing.request() == request {
                Ok(existing.clone())
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        let current = self.current.lock().expect("current").clone();
        let receipt = PlacementBenchmarkIsolationReceipt::new(
            request.clone(),
            running.revision(),
            current.process_generation_sha256().clone(),
            current.store_generation_sha256().clone(),
        )?;
        isolations.insert(request.isolation_id().as_str().to_string(), receipt.clone());
        Ok(receipt)
    }

    // Returns the exact prepared resident snapshot when one exists.
    fn isolation_receipt(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
    ) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        Ok(self
            .isolations
            .lock()
            .expect("isolations")
            .get(request.isolation_id().as_str())
            .filter(|receipt| receipt.request() == request)
            .cloned())
    }

    // Returns one and only one prepared transaction for the requested group.
    fn active_isolation(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        let matching = self
            .isolations
            .lock()
            .expect("isolations")
            .values()
            .filter(|receipt| receipt.request().placement_group_id() == placement_group_id)
            .cloned()
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [] => Ok(None),
            [receipt] => Ok(Some(receipt.clone())),
            _ => Err(PlacementError::StoreConflict),
        }
    }

    // Returns the exact committed restoration when one exists.
    fn restoration_receipt(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
    ) -> Result<Option<PlacementBenchmarkRestorationReceipt>, PlacementError> {
        Ok(self
            .restorations
            .lock()
            .expect("restorations")
            .get(request.isolation_id().as_str())
            .filter(|receipt| receipt.isolation().request() == request)
            .cloned())
    }

    // Replays only a previously committed exact reset receipt.
    fn receipt(
        &self,
        reset_id: &Sha256Digest,
    ) -> Result<Option<PlacementBenchmarkResetReceipt>, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("receipt".to_string());
        Ok(self
            .receipts
            .lock()
            .expect("receipts")
            .get(reset_id.as_str())
            .cloned())
    }

    // Returns the exact process/store baseline observed before manager mutation.
    fn generations(
        &self,
        _request: &PlacementBenchmarkResetRequest,
        _running: &VersionedPlacementRecord,
    ) -> Result<PlacementBenchmarkGenerations, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("generations".to_string());
        Ok(self.current.lock().expect("current").clone())
    }

    // Produces one independently generated empty store or the configured provider failure.
    fn reset_store(
        &self,
        _request: &PlacementBenchmarkResetRequest,
        _stopped: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("reset_store".to_string());
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        if self.unchanged_store.load(Ordering::SeqCst) {
            return Ok(self
                .current
                .lock()
                .expect("current")
                .store_generation_sha256()
                .clone());
        }
        Ok(self.generation())
    }

    // Produces one fresh native process identity or the configured provider failure.
    fn process_generation(
        &self,
        _request: &PlacementBenchmarkResetRequest,
        _running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("process_generation".to_string());
        if self.fail_process.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        if self.unchanged_process.load(Ordering::SeqCst) {
            return Ok(self
                .current
                .lock()
                .expect("current")
                .process_generation_sha256()
                .clone());
        }
        Ok(self.generation())
    }

    // Commits one exact receipt idempotently and advances the observed running baseline.
    fn commit(
        &self,
        receipt: PlacementBenchmarkResetReceipt,
    ) -> Result<PlacementBenchmarkResetReceipt, PlacementError> {
        self.calls.lock().expect("calls").push("commit".to_string());
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(PlacementError::StoreUnavailable);
        }
        let mut receipts = self.receipts.lock().expect("receipts");
        if let Some(existing) = receipts.get(receipt.reset_id().as_str()) {
            return if existing == &receipt {
                Ok(existing.clone())
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        receipts.insert(receipt.reset_id().as_str().to_string(), receipt.clone());
        *self.current.lock().expect("current") = PlacementBenchmarkGenerations::new(
            receipt.process_generation_sha256().clone(),
            receipt.store_generation_sha256().clone(),
        );
        Ok(receipt)
    }

    // Returns the original store generation or the configured restoration failure.
    fn restore_store(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
        _stopped: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("restore_store".to_string());
        if self.fail_restore.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.isolation_receipt(request)?
            .map(|receipt| receipt.resident_store_generation_sha256().clone())
            .ok_or(PlacementError::StoreConflict)
    }

    // Produces one fresh resident process generation after the original store restarts.
    fn restored_process_generation(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
        _running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("restored_process_generation".to_string());
        if self.fail_process.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(self.generation())
    }

    // Commits one exact terminal restoration idempotently.
    fn commit_restoration(
        &self,
        receipt: PlacementBenchmarkRestorationReceipt,
    ) -> Result<PlacementBenchmarkRestorationReceipt, PlacementError> {
        self.calls
            .lock()
            .expect("calls")
            .push("commit_restoration".to_string());
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(PlacementError::StoreUnavailable);
        }
        let key = receipt
            .isolation()
            .request()
            .isolation_id()
            .as_str()
            .to_string();
        let mut restorations = self.restorations.lock().expect("restorations");
        if let Some(existing) = restorations.get(&key) {
            return if existing == &receipt {
                Ok(existing.clone())
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        restorations.insert(key, receipt.clone());
        Ok(receipt)
    }
}

// Produces one deterministic distinct aggregate process generation per observation.
struct MockBenchmarkProcessProvider(AtomicU64);

impl PlacementBenchmarkProcessProvider for MockBenchmarkProcessProvider {
    // Returns a canonical digest without inspecting native state in filesystem tests.
    fn generation(
        &self,
        _running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        Sha256Digest::parse(&format!("{:064x}", self.0.fetch_add(1, Ordering::SeqCst)))
            .map_err(|_| PlacementError::ExecutionUnavailable)
    }
}

// Groups one manager and retained deterministic boundaries.
struct Fixture {
    manager: PlacementManager,
    store: Arc<MockStore>,
    executor: Arc<MockExecutor>,
    identity: Arc<MockIdentity>,
    clock: Arc<MockClock>,
}

// Creates one complete deterministic placement-manager fixture.
fn fixture() -> Fixture {
    let store = Arc::new(MockStore::default());
    let executor = Arc::new(MockExecutor::default());
    let identity = Arc::new(MockIdentity::default());
    let clock = Arc::new(MockClock::default());
    let manager = PlacementManager::new(
        store.clone(),
        executor.clone(),
        identity.clone(),
        clock.clone(),
        admission_policy(),
    );
    Fixture {
        manager,
        store,
        executor,
        identity,
        clock,
    }
}

// Stages one ordinary group and returns its exact identity.
fn staged(fixture: &Fixture) -> PlacementGroupId {
    fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("stage")
        .record()
        .record()
        .group()
        .placement_group_id()
        .clone()
}

// Starts one ordinary staged group and returns its exact identity.
fn running(fixture: &Fixture) -> PlacementGroupId {
    let identity = staged(fixture);
    fixture.manager.start(&identity).expect("start");
    identity
}

// Selects exactly the endpoint owner and rejects log access without a native provider.
#[test]
fn runtime_logs_are_owned_by_the_exact_endpoint_placement() {
    let store = Arc::new(MockStore::default());
    let logs = Arc::new(MockLogs::default());
    let manager = PlacementManager::new(
        store.clone(),
        Arc::new(MockExecutor::default()),
        Arc::new(MockIdentity::default()),
        Arc::new(MockClock::default()),
        admission_policy(),
    )
    .with_log_provider(logs.clone());
    let group = manager
        .stage(request(concurrent_startup_order()))
        .expect("stage")
        .record()
        .record()
        .group()
        .placement_group_id()
        .clone();
    let request = PlacementLogReadRequest::new(group.clone(), None, 200, 64 * 1024, Duration::ZERO)
        .expect("log request");
    let batch = manager.read_logs(request.clone()).expect("logs");
    assert_eq!(batch.payload(), b"opaque runtime output\n");
    let expected_owner = store
        .stored(&group)
        .record()
        .placements()
        .iter()
        .find(|placement| placement.assignment().endpoint_ownership() == EndpointOwnership::Owner)
        .expect("endpoint owner")
        .placement_id()
        .clone();
    assert_eq!(
        *logs.placement_ids.lock().expect("placement identities"),
        [expected_owner]
    );
    let unavailable = PlacementManager::new(
        store,
        Arc::new(MockExecutor::default()),
        Arc::new(MockIdentity::default()),
        Arc::new(MockClock::default()),
        admission_policy(),
    );
    assert_eq!(
        unavailable.read_logs(request).expect_err("provider"),
        PlacementError::ExecutionUnavailable
    );
}

// Rebuilds one placement around an explicit observation and endpoint-owner flag.
fn placement_with_assignment(
    placement: &Placement,
    hardware_observation_id: HardwareObservationId,
    endpoint_ownership: EndpointOwnership,
) -> Placement {
    let assignment = placement.assignment();
    Placement::new(
        placement.placement_id().clone(),
        placement.placement_group_id().clone(),
        PlacementAssignment::new(
            assignment.node_id().clone(),
            assignment.runtime_installation_id().clone(),
            hardware_observation_id,
            assignment.hardware_boot_id().clone(),
            assignment.hardware_observed_at(),
            assignment.task_id().clone(),
            assignment.address().clone(),
            assignment.resources().clone(),
            endpoint_ownership,
        ),
        placement.state(),
        placement.active_operation_id().cloned(),
        placement.last_failure().cloned(),
        placement.timestamps(),
    )
    .expect("rebuilt placement")
}

// Rejects missing task coverage before reserving any resources.
#[test]
fn request_rejects_incomplete_startup_order() {
    let result = PlacementRequest::new(
        PlacementGroupId::parse(&"8".repeat(32)).expect("group"),
        ModelServiceId::parse(&"3".repeat(32)).expect("service"),
        runtime_identity(),
        li_core_interface::PlacementGroupCapacity::new(
            1,
            1,
            1,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("capacity"),
        vec![PlacementTask::new(TaskId::parse("task-0").expect("task"), 1, 1).expect("task")],
        vec![PlacementNodeResources::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
            HardwareObservationId::parse(&"6".repeat(32)).expect("hardware observation"),
            BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            UnixMilliseconds::new(900),
            NodeAddress::parse("node.local").expect("address"),
            vec![DeviceId::parse("GPU-A").expect("GPU")],
            PortRange::new(18_000, 2).expect("ports"),
            None,
        )
        .expect("resources")],
        TaskId::parse("task-0").expect("task"),
        NodeId::parse(&"1".repeat(32)).expect("node"),
        Vec::new(),
        Vec::new(),
    );
    assert!(matches!(result, Err(PlacementError::InvalidRequest { .. })));
}

// Rejects a disconnected topology before identity generation or persistence.
#[test]
fn request_rejects_missing_required_interconnect() {
    let value = request(concurrent_startup_order());
    let result = PlacementRequest::new(
        value.placement_group_id().clone(),
        value.service_id().clone(),
        value.runtime().clone(),
        value.capacity(),
        value.tasks().to_vec(),
        value.nodes().to_vec(),
        value.endpoint_task_id().clone(),
        value.endpoint_node_id().clone(),
        value.startup_order().to_vec(),
        Vec::new(),
    );
    assert_eq!(
        result.expect_err("missing link must fail"),
        PlacementError::TopologyUnavailable
    );
}

// Requires an exact positive millisecond policy no longer than one day.
#[test]
fn admission_policy_rejects_unbounded_or_ambiguous_durations() {
    for duration in [
        Duration::ZERO,
        Duration::from_micros(1),
        Duration::from_secs(86_401),
    ] {
        assert!(matches!(
            PlacementAdmissionPolicy::new(duration),
            Err(PlacementError::InvalidRequest { .. })
        ));
    }
    assert_eq!(
        PlacementAdmissionPolicy::new(Duration::from_secs(86_400))
            .expect("bounded policy")
            .maximum_hardware_observation_age_milliseconds(),
        86_400_000
    );
}

// Rejects reused, future, and expired hardware provenance before allocation mutation.
#[test]
fn staging_rejects_ambiguous_or_stale_hardware_observations() {
    assert!(matches!(
        request_with_hardware_observations(900, 900, true),
        Err(PlacementError::InvalidRequest { .. })
    ));

    for (now, first_observed_at, second_observed_at) in [(1_000, 1_001, 900), (301_001, 900, 900)] {
        let fixture = fixture();
        fixture.clock.next.store(now, Ordering::SeqCst);
        assert_eq!(
            fixture
                .manager
                .stage(
                    request_with_hardware_observations(
                        first_observed_at,
                        second_observed_at,
                        false,
                    )
                    .expect("request"),
                )
                .expect_err("hardware observation must fail"),
            PlacementError::HardwareObservationUnavailable
        );
        assert_eq!(fixture.identity.next.load(Ordering::SeqCst), 10);
        assert!(fixture.store.records.lock().expect("records").is_empty());
        assert!(fixture.executor.calls().is_empty());
    }

    let boundary = fixture();
    boundary.clock.next.store(300_900, Ordering::SeqCst);
    assert_eq!(
        boundary
            .manager
            .stage(request_with_hardware_observations(900, 900, false).expect("boundary request"))
            .expect("inclusive freshness boundary")
            .record()
            .record()
            .group()
            .state(),
        PlacementGroupState::Staged
    );
}

// Maps the endpoint task to the selected node and allocates lowest free resources.
#[test]
fn staging_allocates_exact_resources_deterministically() {
    let fixture = fixture();
    let endpoint_node = NodeId::parse(&"2".repeat(32)).expect("node");
    fixture.store.occupy(
        &endpoint_node,
        ResourceIdentity::Accelerator(DeviceId::parse("GPU-C").expect("GPU")),
    );
    fixture.store.occupy(
        &endpoint_node,
        ResourceIdentity::Port(li_core_interface::NetworkPort::new(19_000).expect("port")),
    );
    let change = fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("stage");
    let record = change.record().record();
    assert_eq!(record.group().state(), PlacementGroupState::Staged);
    let endpoint = record
        .placements()
        .iter()
        .find(|placement| placement.assignment().endpoint_ownership() == EndpointOwnership::Owner)
        .expect("endpoint placement");
    assert_eq!(endpoint.assignment().node_id(), &endpoint_node);
    assert_eq!(
        endpoint.assignment().resources().device_ids(),
        &[DeviceId::parse("GPU-D").expect("GPU")]
    );
    assert_eq!(
        endpoint.assignment().hardware_observation_id(),
        &HardwareObservationId::parse(&"7".repeat(32)).expect("hardware observation")
    );
    assert_eq!(
        endpoint.assignment().hardware_boot_id(),
        &BootId::parse("66666666-7777-8888-9999-000000000000").expect("boot")
    );
    assert_eq!(
        endpoint.assignment().hardware_observed_at(),
        UnixMilliseconds::new(900)
    );
    assert_eq!(endpoint.assignment().resources().ports().base(), 19_001);
    assert!(record
        .leases()
        .iter()
        .all(|lease| lease.state() == ResourceLeaseState::Reserved));
    assert_eq!(record.launch_plan_identities().len(), 2);
    assert!(matches!(change.event(), PlacementEvent::GroupStaged { .. }));
}

// Replays one exact staged identity without allocating or executing a second group.
#[test]
fn staging_exact_identity_replay_is_side_effect_free() {
    let fixture = fixture();
    let request = request(concurrent_startup_order());
    let first = fixture.manager.stage(request.clone()).expect("first stage");
    let calls = fixture.executor.calls();
    let replay = fixture.manager.stage(request).expect("replayed stage");
    assert_eq!(replay.record(), first.record());
    assert_eq!(fixture.executor.calls(), calls);
    assert_eq!(fixture.store.records.lock().expect("records").len(), 1);
}

// Rejects reuse of one exact group identity for a different normalized request.
#[test]
fn staging_exact_identity_conflicts_with_different_request() {
    let fixture = fixture();
    let request = request(concurrent_startup_order());
    fixture.manager.stage(request.clone()).expect("first stage");
    let conflicting = PlacementRequest::new(
        request.placement_group_id().clone(),
        ModelServiceId::parse(&"a".repeat(32)).expect("other service"),
        request.runtime().clone(),
        request.capacity(),
        request.tasks().to_vec(),
        request.nodes().to_vec(),
        request.endpoint_task_id().clone(),
        request.endpoint_node_id().clone(),
        request.startup_order().to_vec(),
        request.links().to_vec(),
    )
    .expect("conflicting request");
    assert_eq!(
        fixture.manager.stage(conflicting),
        Err(PlacementError::StoreConflict)
    );
    assert_eq!(fixture.store.records.lock().expect("records").len(), 1);
}

// Keeps replication as distinct groups while preserving opaque task-N parallel assignments.
#[test]
fn replication_allocates_disjoint_groups_without_rewriting_runtime_tasks() {
    let fixture = fixture();
    let first = fixture
        .manager
        .stage(replicable_request('8'))
        .expect("first replica");
    let second = fixture
        .manager
        .stage(replicable_request('9'))
        .expect("second replica");
    let first = first.record().record();
    let second = second.record().record();
    assert_ne!(
        first.group().placement_group_id(),
        second.group().placement_group_id()
    );
    assert_eq!(first.group().service_id(), second.group().service_id());
    assert_eq!(first.group().runtime(), second.group().runtime());
    for record in [first, second] {
        assert_eq!(
            record
                .placements()
                .iter()
                .map(|placement| placement.assignment().task_id().as_str())
                .collect::<Vec<_>>(),
            ["task-0", "task-1"]
        );
    }
    let resource_key = |lease: &ResourceLease| {
        let resource = match lease.resource() {
            ResourceIdentity::Accelerator(device) => format!("gpu:{}", device.as_str()),
            ResourceIdentity::Port(port) => format!("port:{}", port.value()),
            ResourceIdentity::RdmaInterface(interface) => {
                format!("rdma:{}", interface.as_str())
            }
        };
        format!("{}:{resource}", lease.node_id().as_str())
    };
    let first_resources = first
        .leases()
        .iter()
        .map(resource_key)
        .collect::<HashSet<_>>();
    let second_resources = second
        .leases()
        .iter()
        .map(resource_key)
        .collect::<HashSet<_>>();
    assert!(first_resources.is_disjoint(&second_resources));
}

// Rejects ambiguous provenance, endpoint ownership, and unrelated resource leases.
#[test]
fn placement_record_rejects_cross_placement_identity_and_resource_corruption() {
    let fixture = fixture();
    let identity = staged(&fixture);
    let stored = fixture.store.stored(&identity);
    let record = stored.record();

    let mut duplicate_observation = record.placements().to_vec();
    duplicate_observation[1] = placement_with_assignment(
        &duplicate_observation[1],
        duplicate_observation[0]
            .assignment()
            .hardware_observation_id()
            .clone(),
        duplicate_observation[1].assignment().endpoint_ownership(),
    );
    assert!(matches!(
        PlacementRecord::new(
            record.group().clone(),
            duplicate_observation,
            record.leases().to_vec(),
            record.startup_order().to_vec(),
            record.launch_plan_identities().to_vec(),
        ),
        Err(PlacementError::InvalidRequest { .. })
    ));

    let no_owner = record
        .placements()
        .iter()
        .map(|placement| {
            placement_with_assignment(
                placement,
                placement.assignment().hardware_observation_id().clone(),
                EndpointOwnership::Participant,
            )
        })
        .collect();
    assert!(matches!(
        PlacementRecord::new(
            record.group().clone(),
            no_owner,
            record.leases().to_vec(),
            record.startup_order().to_vec(),
            record.launch_plan_identities().to_vec(),
        ),
        Err(PlacementError::InvalidRequest { .. })
    ));

    let mut unrelated_lease = record.leases().to_vec();
    unrelated_lease.push(ResourceLease::new(
        ResourceLeaseId::parse(&"f".repeat(32)).expect("lease"),
        PlacementId::parse(&"e".repeat(32)).expect("placement"),
        record.placements()[0].assignment().node_id().clone(),
        ResourceIdentity::Port(li_core_interface::NetworkPort::new(30_000).expect("port")),
        ResourceLeaseState::Reserved,
        record.placements()[0].timestamps(),
    ));
    assert!(matches!(
        PlacementRecord::new(
            record.group().clone(),
            record.placements().to_vec(),
            unrelated_lease,
            record.startup_order().to_vec(),
            record.launch_plan_identities().to_vec(),
        ),
        Err(PlacementError::InvalidRequest { .. })
    ));
}

// Reads independently committed launch-plan identities through the aggregate store adapter.
#[test]
fn stored_plan_identity_provider_reads_committed_state() {
    let fixture = fixture();
    let identity = staged(&fixture);
    let stored = fixture.store.stored(&identity);
    let provider = StoredPlacementLaunchPlanIdentityProvider::new(fixture.store.clone());
    for placement in stored.record().placements() {
        assert_eq!(
            provider
                .expected_identity(placement)
                .expect("expected identity"),
            stored
                .record()
                .launch_plan_identity(placement.placement_id())
                .cloned()
        );
    }
}

// Rejects exhausted accelerator and RDMA resources without staging a task.
#[test]
fn staging_rejects_each_exhausted_resource_class() {
    let device_fixture = fixture();
    let endpoint_node = NodeId::parse(&"2".repeat(32)).expect("node");
    for device in ["GPU-C", "GPU-D"] {
        device_fixture.store.occupy(
            &endpoint_node,
            ResourceIdentity::Accelerator(DeviceId::parse(device).expect("GPU")),
        );
    }
    assert_eq!(
        device_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("device exhaustion"),
        PlacementError::ResourceUnavailable
    );

    let port_fixture = fixture();
    for port in 19_000..19_008 {
        port_fixture.store.occupy(
            &endpoint_node,
            ResourceIdentity::Port(
                li_core_interface::NetworkPort::new(port).expect("managed port"),
            ),
        );
    }
    assert_eq!(
        port_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("port exhaustion"),
        PlacementError::ResourceUnavailable
    );

    let rdma_fixture = fixture();
    rdma_fixture.store.occupy(
        &endpoint_node,
        ResourceIdentity::RdmaInterface(
            li_core_interface::NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA"),
        ),
    );
    assert_eq!(
        rdma_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("RDMA exhaustion"),
        PlacementError::ResourceUnavailable
    );
}

// Propagates identity, clock, resource-store, and create-store failures without execution.
#[test]
fn staging_propagates_every_preexecution_boundary_failure() {
    let identity_fixture = fixture();
    identity_fixture.identity.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        identity_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("identity failure"),
        PlacementError::IdentityUnavailable
    );

    let clock_fixture = fixture();
    clock_fixture.clock.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        clock_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("clock failure"),
        PlacementError::ClockUnavailable
    );

    let occupied_fixture = fixture();
    occupied_fixture
        .store
        .fail_occupied
        .store(true, Ordering::SeqCst);
    assert_eq!(
        occupied_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("occupied read failure"),
        PlacementError::StoreUnavailable
    );

    let create_fixture = fixture();
    create_fixture
        .store
        .fail_create
        .store(true, Ordering::SeqCst);
    assert_eq!(
        create_fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("create failure"),
        PlacementError::StoreUnavailable
    );
}

// Persists failed staging and releases every resource after successful cleanup.
#[test]
fn staging_failure_removes_attempted_tasks_and_releases_resources() {
    let fixture = fixture();
    fixture.executor.fail("stage", "task-1");
    let change = fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("failed staging record");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
    assert!(change
        .record()
        .record()
        .leases()
        .iter()
        .all(|lease| lease.state() == ResourceLeaseState::Released));
    assert_eq!(
        fixture.executor.calls(),
        vec![
            "stage:task-0",
            "stage:task-1",
            "remove:task-1",
            "remove:task-0",
        ]
    );
}

// Retains draining ownership when staging rollback cannot prove removal.
#[test]
fn staging_rollback_failure_remains_owned_and_failed() {
    let fixture = fixture();
    fixture.executor.fail("stage", "task-1");
    fixture.executor.fail("remove", "task-1");
    let change = fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("failed staging record");
    let record = change.record().record();
    assert_eq!(record.group().state(), PlacementGroupState::Failed);
    let failed = record
        .placements()
        .iter()
        .find(|placement| placement.assignment().task_id().as_str() == "task-1")
        .expect("failed task");
    assert_eq!(failed.state(), PlacementState::Failed);
    assert!(record.leases().iter().any(|lease| {
        lease.placement_id() == failed.placement_id()
            && lease.state() == ResourceLeaseState::Draining
    }));
}

// Starts same-phase tasks concurrently and publishes one owner endpoint afterward.
#[test]
fn start_runs_declared_phase_concurrently_and_publishes_one_endpoint() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture
        .executor
        .start_barrier
        .lock()
        .expect("barrier")
        .replace(Arc::new(Barrier::new(2)));
    let change = fixture.manager.start(&identity).expect("start");
    let record = change.record().record();
    assert_eq!(record.group().state(), PlacementGroupState::Running);
    assert!(record.group().endpoint().is_some());
    assert!(record
        .placements()
        .iter()
        .all(|placement| placement.state() == PlacementState::Running));
    assert!(record
        .leases()
        .iter()
        .all(|lease| lease.state() == ResourceLeaseState::Active));
    assert!(matches!(
        change.event(),
        PlacementEvent::GroupRunning { .. }
    ));
}

// Rejects every endpoint identity, lease, capacity, and ownership divergence and rolls back.
#[test]
fn start_rejects_every_invalid_endpoint_shape() {
    for configure in 0_u8..6 {
        let fixture = fixture();
        let identity = staged(&fixture);
        match configure {
            0 => fixture
                .executor
                .missing_owner_endpoint
                .store(true, Ordering::SeqCst),
            1 => fixture
                .executor
                .unhealthy_endpoint
                .store(true, Ordering::SeqCst),
            2 => fixture
                .executor
                .participant_endpoint
                .store(true, Ordering::SeqCst),
            3 => fixture
                .executor
                .foreign_endpoint_host
                .store(true, Ordering::SeqCst),
            4 => fixture
                .executor
                .unleased_endpoint_port
                .store(true, Ordering::SeqCst),
            _ => fixture
                .executor
                .oversized_endpoint
                .store(true, Ordering::SeqCst),
        }
        let change = fixture
            .manager
            .start(&identity)
            .expect("failed start record");
        assert_eq!(
            change.record().record().group().state(),
            PlacementGroupState::Failed
        );
        assert!(change.record().record().group().endpoint().is_none());
        assert!(change
            .record()
            .record()
            .leases()
            .iter()
            .all(|lease| lease.state() == ResourceLeaseState::Reserved));
    }
}

// Stops the complete group after one task start failure without publishing an endpoint.
#[test]
fn start_failure_preempts_every_task_and_persists_failure() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.fail("start", "task-1");
    let change = fixture
        .manager
        .start(&identity)
        .expect("failed start record");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
    assert!(change.record().record().group().endpoint().is_none());
    assert_eq!(
        fixture
            .executor
            .calls()
            .iter()
            .filter(|call| call.starts_with("stop:"))
            .count(),
        2
    );
}

// Retains draining resources when start rollback cannot stop one task.
#[test]
fn start_rollback_failure_does_not_release_uncertain_resources() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.fail("start", "task-1");
    fixture.executor.fail("stop", "task-0");
    let change = fixture
        .manager
        .start(&identity)
        .expect("failed start record");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
    assert!(change
        .record()
        .record()
        .leases()
        .iter()
        .any(|lease| lease.state() == ResourceLeaseState::Draining));
}

// Starts a reconstructed staged record through a newly composed manager instance.
#[test]
fn restart_reconstructs_staged_state_from_the_store() {
    let fixture = fixture();
    let identity = staged(&fixture);
    let restarted = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    );
    assert_eq!(
        restarted
            .start(&identity)
            .expect("restart start")
            .record()
            .record()
            .group()
            .state(),
        PlacementGroupState::Running
    );
}

// Honors forward start and reverse stop ordering across runtime-declared phases.
#[test]
fn lifecycle_honors_opaque_phase_order_in_both_directions() {
    let fixture = fixture();
    let identity = fixture
        .manager
        .stage(request(vec![
            vec![TaskId::parse("task-0").expect("task")],
            vec![TaskId::parse("task-1").expect("task")],
        ]))
        .expect("stage")
        .record()
        .record()
        .group()
        .placement_group_id()
        .clone();
    fixture.executor.calls.lock().expect("calls").clear();
    fixture.manager.start(&identity).expect("start");
    assert_eq!(
        fixture.executor.calls(),
        vec!["start:task-0", "start:task-1"]
    );
    fixture.executor.calls.lock().expect("calls").clear();
    fixture.manager.stop(&identity).expect("stop");
    assert_eq!(fixture.executor.calls(), vec!["stop:task-1", "stop:task-0"]);
}

// Returns stable not-found and read-boundary failures without invoking execution.
#[test]
fn lifecycle_propagates_every_store_read_failure() {
    let fixture = fixture();
    let missing = PlacementGroupId::parse(&"f".repeat(32)).expect("group");
    assert_eq!(
        fixture.manager.start(&missing).expect_err("missing group"),
        PlacementError::GroupNotFound
    );
    let identity = staged(&fixture);
    fixture.store.fail_read.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture.manager.start(&identity).expect_err("read failure"),
        PlacementError::StoreUnavailable
    );
}

// Rejects a regressing lifecycle clock as a typed failure instead of panicking.
#[test]
fn lifecycle_fails_closed_when_time_moves_before_creation() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.clock.next.store(1, Ordering::SeqCst);
    assert_eq!(
        fixture
            .manager
            .start(&identity)
            .expect_err("regressing clock"),
        PlacementError::ClockUnavailable
    );
}

// Makes repeated start and stop calls idempotent without new store revisions.
#[test]
fn completed_start_and_stop_transitions_are_idempotent() {
    let fixture = fixture();
    let identity = running(&fixture);
    let running_revision = fixture.store.stored(&identity).revision();
    assert_eq!(
        fixture
            .manager
            .start(&identity)
            .expect("replayed start")
            .record()
            .revision(),
        running_revision
    );
    let stopped = fixture.manager.stop(&identity).expect("stop");
    let stopped_revision = stopped.record().revision();
    assert_eq!(
        fixture
            .manager
            .stop(&identity)
            .expect("replayed stop")
            .record()
            .revision(),
        stopped_revision
    );
}

// Persists failed stop state while continuing to stop every required placement.
#[test]
fn stop_failure_attempts_every_task_and_retains_draining_ownership() {
    let fixture = fixture();
    let identity = running(&fixture);
    fixture.executor.fail("stop", "task-0");
    let change = fixture.manager.stop(&identity).expect("failed stop record");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
    assert!(change
        .record()
        .record()
        .leases()
        .iter()
        .any(|lease| lease.state() == ResourceLeaseState::Draining));
    assert_eq!(
        fixture
            .executor
            .calls()
            .iter()
            .filter(|call| call.starts_with("stop:"))
            .count(),
        2
    );
}

// Recovers one failed group with explicit protection acknowledgement on every task.
#[test]
fn recovery_preserves_identity_and_passes_one_explicit_acknowledgement() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.fail("start", "task-1");
    fixture.manager.start(&identity).expect("failed start");
    fixture.executor.failures.lock().expect("failures").clear();
    let change = fixture.manager.recover(&identity, true).expect("recover");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Running
    );
    assert_eq!(
        change.record().record().group().placement_group_id(),
        &identity
    );
    let acknowledgements = fixture.executor.acknowledged.lock().expect("acks");
    assert!(acknowledgements.iter().rev().take(2).all(|value| *value));
    assert!(matches!(
        change.event(),
        PlacementEvent::GroupRecovered { .. }
    ));
}

// Removes a stopped group and releases every exact resource idempotently.
#[test]
fn removal_releases_exact_resources_and_replays_without_execution() {
    let fixture = fixture();
    let identity = running(&fixture);
    fixture.manager.stop(&identity).expect("stop");
    let removed = fixture.manager.remove(&identity).expect("remove");
    assert_eq!(
        removed.record().record().group().state(),
        PlacementGroupState::Removed
    );
    assert!(removed
        .record()
        .record()
        .leases()
        .iter()
        .all(|lease| lease.state() == ResourceLeaseState::Released));
    let calls = fixture.executor.calls().len();
    let replayed = fixture.manager.remove(&identity).expect("replayed remove");
    assert_eq!(replayed.record().revision(), removed.record().revision());
    assert_eq!(fixture.executor.calls().len(), calls);
}

// Keeps failed removal resources draining until terminal cleanup can be retried.
#[test]
fn removal_failure_never_claims_resource_release() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.fail("remove", "task-1");
    let change = fixture
        .manager
        .remove(&identity)
        .expect("failed removal record");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
    assert!(change
        .record()
        .record()
        .leases()
        .iter()
        .any(|lease| lease.state() == ResourceLeaseState::Draining));
}

// Retries only the failed removal task without reacquiring released resources.
#[test]
fn removal_retry_preserves_completed_cleanup() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.fail("remove", "task-1");
    fixture.manager.remove(&identity).expect("failed removal");
    fixture.executor.failures.lock().expect("failures").clear();
    fixture.executor.calls.lock().expect("calls").clear();
    let removed = fixture.manager.remove(&identity).expect("retry removal");
    assert_eq!(
        removed.record().record().group().state(),
        PlacementGroupState::Removed
    );
    assert_eq!(fixture.executor.calls(), vec!["remove:task-1"]);
    assert!(removed
        .record()
        .record()
        .leases()
        .iter()
        .all(|lease| lease.state() == ResourceLeaseState::Released));
}

// Finalizes a cleaned staging failure without reacquiring released resources.
#[test]
fn removal_after_clean_staging_failure_is_execution_free() {
    let fixture = fixture();
    fixture.executor.fail("stage", "task-1");
    let failed = fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("failed staging");
    let identity = failed
        .record()
        .record()
        .group()
        .placement_group_id()
        .clone();
    fixture.executor.failures.lock().expect("failures").clear();
    fixture.executor.calls.lock().expect("calls").clear();
    assert_eq!(
        fixture.manager.stop(&identity).expect_err("released stop"),
        PlacementError::InvalidTransition
    );
    let removed = fixture.manager.remove(&identity).expect("remove record");
    assert_eq!(
        removed.record().record().group().state(),
        PlacementGroupState::Removed
    );
    assert!(fixture.executor.calls().is_empty());
}

// Leaves an unchanged live observation at the same optimistic revision.
#[test]
fn reconciliation_is_idempotent_for_an_unchanged_running_group() {
    let fixture = fixture();
    let identity = running(&fixture);
    let revision = fixture.store.stored(&identity).revision();
    let change = fixture.manager.reconcile(&identity).expect("reconcile");
    assert_eq!(change.record().revision(), revision);
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Running
    );
}

// Marks the atomic group failed when one required node becomes unreachable.
#[test]
fn reconciliation_fails_the_complete_group_on_one_unreachable_task() {
    let fixture = fixture();
    let identity = running(&fixture);
    fixture
        .executor
        .observe_failures
        .lock()
        .expect("observation failures")
        .insert("task-1".to_string());
    let change = fixture.manager.reconcile(&identity).expect("reconcile");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
    assert!(change
        .record()
        .record()
        .placements()
        .iter()
        .any(|placement| {
            placement.assignment().task_id().as_str() == "task-1"
                && placement.state() == PlacementState::Unreachable
        }));
}

// Treats a latched protection trip as a failed group requiring explicit recovery.
#[test]
fn reconciliation_never_hides_a_latched_protection_trip() {
    let fixture = fixture();
    let identity = running(&fixture);
    fixture
        .executor
        .protection_trips
        .lock()
        .expect("trips")
        .insert("task-0".to_string());
    let change = fixture.manager.reconcile(&identity).expect("reconcile");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
}

// Rejects an endpoint emitted by a participant during live reconciliation.
#[test]
fn reconciliation_rejects_participant_endpoint_publication() {
    let fixture = fixture();
    let identity = running(&fixture);
    fixture
        .executor
        .participant_endpoint
        .store(true, Ordering::SeqCst);
    let change = fixture.manager.reconcile(&identity).expect("reconcile");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Failed
    );
}

// Propagates optimistic replacement conflict without emitting a completed event.
#[test]
fn lifecycle_propagates_store_conflict() {
    let fixture = fixture();
    fixture.store.fail_replace.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("replace conflict"),
        PlacementError::StoreConflict
    );
    assert!(fixture
        .executor
        .calls()
        .iter()
        .any(|call| call == "remove:task-0"));
}

// Removes staged material when time fails after native staging but before persistence.
#[test]
fn lifecycle_cleans_material_after_poststage_clock_failure() {
    let fixture = fixture();
    fixture.clock.fail_at.store(1_001, Ordering::SeqCst);
    assert_eq!(
        fixture
            .manager
            .stage(request(concurrent_startup_order()))
            .expect_err("clock failure"),
        PlacementError::ClockUnavailable
    );
    assert_eq!(fixture.executor.calls(), ["stage:task-0", "remove:task-0"]);
}

// Accepts a concurrent replay only when the committed launch-plan identity agrees.
#[test]
fn lifecycle_recovers_matching_postcommit_store_conflict() {
    let fixture = fixture();
    fixture
        .store
        .commit_then_conflict
        .store(true, Ordering::SeqCst);
    let change = fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("matching replay");
    assert_eq!(change.record().record().launch_plan_identities().len(), 2);
    assert!(!fixture
        .executor
        .calls()
        .iter()
        .any(|call| call == "remove:task-0"));
}

// Retries one uncertain final stage commit without duplicating native staging.
#[test]
fn final_stage_commit_retries_same_revision_without_duplicate_execution() {
    let fixture = fixture();
    fixture.store.fail_replace_at.store(3, Ordering::SeqCst);
    let change = fixture
        .manager
        .stage(request(concurrent_startup_order()))
        .expect("retried final stage");
    assert_eq!(
        change.record().record().group().state(),
        PlacementGroupState::Staged
    );
    assert_eq!(
        fixture
            .executor
            .calls()
            .iter()
            .filter(|call| call.starts_with("stage:"))
            .count(),
        2
    );
    assert!(!fixture
        .executor
        .calls()
        .iter()
        .any(|call| call.starts_with("remove:")));
}

// Reconciles an initial transition committed before its response and recovers the whole group.
#[test]
fn restart_recovers_starting_state_left_by_ambiguous_initial_commit() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.calls.lock().expect("calls").clear();
    fixture
        .store
        .commit_then_conflict
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .manager
            .start(&identity)
            .expect_err("ambiguous starting commit"),
        PlacementError::StoreConflict
    );
    assert!(fixture.executor.calls().is_empty());
    assert_eq!(
        fixture.store.stored(&identity).record().group().state(),
        PlacementGroupState::Starting
    );

    let restarted = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    );
    assert_eq!(
        restarted
            .reconcile(&identity)
            .expect("reconcile")
            .record()
            .record()
            .group()
            .state(),
        PlacementGroupState::Failed
    );
    assert_eq!(
        restarted
            .recover(&identity, true)
            .expect("recover")
            .record()
            .record()
            .group()
            .state(),
        PlacementGroupState::Running
    );
}

// Preempts live tasks when final persistence remains unavailable and supports restart recovery.
#[test]
fn final_start_persistence_failure_rolls_back_and_recovers_after_restart() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture.executor.calls.lock().expect("calls").clear();
    fixture.store.fail_replace_from.store(5, Ordering::SeqCst);
    assert_eq!(
        fixture
            .manager
            .start(&identity)
            .expect_err("persistent final store failure"),
        PlacementError::StoreConflict
    );
    assert_eq!(
        fixture
            .executor
            .calls()
            .iter()
            .filter(|call| call.starts_with("stop:"))
            .count(),
        2
    );
    assert_eq!(
        fixture.store.stored(&identity).record().group().state(),
        PlacementGroupState::Starting
    );

    fixture.store.fail_replace_from.store(0, Ordering::SeqCst);
    let restarted = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    );
    restarted.reconcile(&identity).expect("reconcile");
    assert_eq!(
        restarted
            .recover(&identity, true)
            .expect("recover")
            .record()
            .record()
            .group()
            .state(),
        PlacementGroupState::Running
    );
}

// Serializes concurrent start and remove so no split lifecycle or resource state is committed.
#[test]
fn concurrent_start_and_remove_have_one_atomic_winner() {
    let fixture = fixture();
    let identity = staged(&fixture);
    fixture
        .store
        .replace_barrier
        .lock()
        .expect("barrier")
        .replace(Arc::new(Barrier::new(2)));
    fixture
        .store
        .replace_barrier_count
        .store(0, Ordering::SeqCst);
    let competing = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    );
    let (start, remove) = std::thread::scope(|scope| {
        let start = scope.spawn(|| fixture.manager.start(&identity));
        let remove = scope.spawn(|| competing.remove(&identity));
        (
            start.join().expect("start thread"),
            remove.join().expect("remove thread"),
        )
    });
    assert_eq!(usize::from(start.is_ok()) + usize::from(remove.is_ok()), 1);
    assert_eq!(
        start
            .err()
            .or_else(|| remove.err())
            .expect("losing conflict"),
        PlacementError::StoreConflict
    );
    let record = fixture.store.stored(&identity);
    match record.record().group().state() {
        PlacementGroupState::Running => assert!(record
            .record()
            .leases()
            .iter()
            .all(|lease| lease.state() == ResourceLeaseState::Active)),
        PlacementGroupState::Removed => assert!(record
            .record()
            .leases()
            .iter()
            .all(|lease| lease.state() == ResourceLeaseState::Released)),
        state => panic!("unexpected split lifecycle state: {state:?}"),
    }
}

// Gives one concurrent exact-ID stage the aggregate and permits exact replay afterward.
#[test]
fn concurrent_exact_identity_stage_has_one_winner_and_replays() {
    let store = Arc::new(MockStore::default());
    store
        .create_barrier
        .lock()
        .expect("barrier")
        .replace(Arc::new(Barrier::new(2)));
    let first = PlacementManager::new(
        store.clone(),
        Arc::new(MockExecutor::default()),
        Arc::new(MockIdentity::default()),
        Arc::new(MockClock::default()),
        admission_policy(),
    );
    let second = PlacementManager::new(
        store,
        Arc::new(MockExecutor::default()),
        Arc::new(MockIdentity {
            next: AtomicU64::new(1_000),
            fail: AtomicBool::new(false),
        }),
        Arc::new(MockClock::default()),
        admission_policy(),
    );
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first_handle = scope.spawn(|| first.stage(request(concurrent_startup_order())));
        let second_handle = scope.spawn(|| second.stage(request(concurrent_startup_order())));
        (
            first_handle.join().expect("first thread"),
            second_handle.join().expect("second thread"),
        )
    });
    assert_eq!(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
        1
    );
    let error = first_result
        .err()
        .or_else(|| second_result.err())
        .expect("conflict");
    assert_eq!(error, PlacementError::StoreConflict);
    assert!(first.stage(request(concurrent_startup_order())).is_ok());
}

// Resets every ordered benchmark boundary exactly once and replays across manager restart.
#[test]
fn benchmark_reset_binds_fresh_generations_revisions_and_durable_replay() {
    let fixture = fixture();
    let group = running(&fixture);
    let provider = Arc::new(MockBenchmarkResetProvider::default());
    let manager = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(provider.clone());
    let isolation_request = PlacementBenchmarkIsolationRequest::new(
        Sha256Digest::parse(&"e".repeat(64)).expect("isolation"),
        group.clone(),
    );
    let isolation = manager
        .prepare_benchmark_isolation(isolation_request.clone())
        .expect("isolation");
    let previous = fixture.store.stored(&group);
    assert_eq!(isolation.prepared_revision(), previous.revision());
    let first_request = PlacementBenchmarkResetRequest::new(
        Sha256Digest::parse(&"a".repeat(64)).expect("reset"),
        group.clone(),
        previous.revision(),
        "short",
        1,
        2,
    )
    .expect("first request");
    let first = manager
        .reset_for_benchmark(first_request.clone())
        .expect("first reset");
    assert_eq!(first.previous_revision(), previous.revision());
    assert!(first.next_revision() > first.previous_revision());
    assert_ne!(
        first.process_generation_sha256(),
        &Sha256Digest::parse(&"1".repeat(64)).expect("previous process")
    );
    assert_ne!(
        first.store_generation_sha256(),
        &Sha256Digest::parse(&"2".repeat(64)).expect("previous store")
    );
    assert_eq!(
        fixture.store.stored(&group).record().group().state(),
        PlacementGroupState::Running
    );
    assert_eq!(
        provider.calls(),
        [
            "prepare_isolation",
            "receipt",
            "generations",
            "reset_store",
            "process_generation",
            "commit"
        ]
    );

    let restarted = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(provider.clone());
    assert_eq!(
        restarted
            .reset_for_benchmark(first_request)
            .expect("restart replay"),
        first
    );
    let second_request = PlacementBenchmarkResetRequest::new(
        Sha256Digest::parse(&"b".repeat(64)).expect("reset"),
        group.clone(),
        first.next_revision(),
        "32k",
        2,
        2,
    )
    .expect("second request");
    let second = restarted
        .reset_for_benchmark(second_request)
        .expect("second reset");
    assert_ne!(
        second.process_generation_sha256(),
        first.process_generation_sha256()
    );
    assert_ne!(
        second.store_generation_sha256(),
        first.store_generation_sha256()
    );
    assert_eq!(second.previous_revision(), first.next_revision());
    let restoration = restarted
        .restore_benchmark_isolation(isolation_request.clone())
        .expect("restoration");
    assert_eq!(
        restoration.isolation().resident_store_generation_sha256(),
        isolation.resident_store_generation_sha256()
    );
    assert_ne!(
        restoration.restored_process_generation_sha256(),
        isolation.resident_process_generation_sha256()
    );
    assert_eq!(
        restarted
            .restore_benchmark_isolation(isolation_request)
            .expect("restoration replay"),
        restoration
    );
}

// Contains every meaningful reset drift or provider failure without a reusable dirty receipt.
#[test]
fn benchmark_reset_rejects_drift_and_contains_partial_failures() {
    for failure in [
        "store",
        "start",
        "process",
        "commit",
        "unchanged-store",
        "unchanged-process",
    ] {
        let fixture = fixture();
        let group = running(&fixture);
        let provider = Arc::new(MockBenchmarkResetProvider::default());
        match failure {
            "store" => provider.fail_store.store(true, Ordering::SeqCst),
            "start" => {
                fixture.executor.fail("start", "task-0");
                fixture.executor.fail("start", "task-1");
            }
            "process" => provider.fail_process.store(true, Ordering::SeqCst),
            "commit" => provider.fail_commit.store(true, Ordering::SeqCst),
            "unchanged-store" => provider.unchanged_store.store(true, Ordering::SeqCst),
            "unchanged-process" => provider.unchanged_process.store(true, Ordering::SeqCst),
            _ => unreachable!(),
        }
        let manager = PlacementManager::new(
            fixture.store.clone(),
            fixture.executor.clone(),
            fixture.identity.clone(),
            fixture.clock.clone(),
            admission_policy(),
        )
        .with_benchmark_reset_provider(provider.clone());
        manager
            .prepare_benchmark_isolation(PlacementBenchmarkIsolationRequest::new(
                Sha256Digest::parse(&"e".repeat(64)).expect("isolation"),
                group.clone(),
            ))
            .expect("isolation");
        let previous = fixture.store.stored(&group);
        let request = PlacementBenchmarkResetRequest::new(
            Sha256Digest::parse(&"c".repeat(64)).expect("reset"),
            group.clone(),
            previous.revision(),
            "short",
            1,
            1,
        )
        .expect("request");
        assert!(
            manager.reset_for_benchmark(request.clone()).is_err(),
            "{failure} unexpectedly succeeded"
        );
        assert!(provider
            .receipt(request.reset_id())
            .expect("receipt read")
            .is_none());
        assert_ne!(
            fixture.store.stored(&group).record().group().state(),
            PlacementGroupState::Running,
            "{failure} must leave the dirty or unproven group contained"
        );
    }

    let fixture = fixture();
    let group = running(&fixture);
    let manager = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(Arc::new(MockBenchmarkResetProvider::default()));
    let current = fixture.store.stored(&group);
    manager
        .prepare_benchmark_isolation(PlacementBenchmarkIsolationRequest::new(
            Sha256Digest::parse(&"e".repeat(64)).expect("isolation"),
            group.clone(),
        ))
        .expect("isolation");
    let stale = PlacementBenchmarkResetRequest::new(
        Sha256Digest::parse(&"d".repeat(64)).expect("reset"),
        group,
        current.revision() + 1,
        "short",
        1,
        1,
    )
    .expect("stale request");
    assert_eq!(
        manager
            .reset_for_benchmark(stale)
            .expect_err("revision drift"),
        PlacementError::StoreConflict
    );
}

// Retries terminal restoration after partial failure without losing the original store snapshot.
#[test]
fn benchmark_isolation_restoration_contains_failure_and_replays_after_restart() {
    let fixture = fixture();
    let group = running(&fixture);
    let provider = Arc::new(MockBenchmarkResetProvider::default());
    let manager = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(provider.clone());
    let isolation_request = PlacementBenchmarkIsolationRequest::new(
        Sha256Digest::parse(&"e".repeat(64)).expect("isolation"),
        group.clone(),
    );
    let isolation = manager
        .prepare_benchmark_isolation(isolation_request.clone())
        .expect("isolation");
    let current = fixture.store.stored(&group);
    manager
        .reset_for_benchmark(
            PlacementBenchmarkResetRequest::new(
                Sha256Digest::parse(&"a".repeat(64)).expect("reset"),
                group.clone(),
                current.revision(),
                "short",
                1,
                1,
            )
            .expect("reset request"),
        )
        .expect("reset");
    provider.fail_restore.store(true, Ordering::SeqCst);
    assert_eq!(
        manager
            .restore_benchmark_isolation(isolation_request.clone())
            .expect_err("restore failure"),
        PlacementError::ExecutionUnavailable
    );
    assert_eq!(
        fixture.store.stored(&group).record().group().state(),
        PlacementGroupState::Stopped
    );
    provider.fail_restore.store(false, Ordering::SeqCst);
    let restarted = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(provider);
    let restored = restarted
        .restore_benchmark_isolation(isolation_request.clone())
        .expect("retry restoration");
    assert_eq!(
        restored.isolation().resident_store_generation_sha256(),
        isolation.resident_store_generation_sha256()
    );
    assert_eq!(
        restarted
            .restore_benchmark_isolation(isolation_request)
            .expect("replay"),
        restored
    );
}

// Swaps only stable per-placement roots and restores their original inode and cache contents.
#[test]
fn filesystem_benchmark_isolation_preserves_resident_store_across_restart() {
    let fixture = fixture();
    let group = running(&fixture);
    let temporary = tempfile::tempdir().expect("temporary directory");
    let state_root = temporary.path().join("benchmark_state");
    let cache_root = temporary.path().join("runtime_cache");
    for root in [&state_root, &cache_root] {
        fs::create_dir(root).expect("private root");
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let owner_user_id = fs::metadata(&state_root).expect("root owner").uid();
    let record = fixture.store.stored(&group);
    let mut resident_files = Vec::new();
    for placement in record.record().placements() {
        let installation =
            cache_root.join(placement.assignment().runtime_installation_id().as_str());
        if !installation.exists() {
            fs::create_dir(&installation).expect("installation cache");
            fs::set_permissions(&installation, fs::Permissions::from_mode(0o700))
                .expect("installation mode");
        }
        let placement_root = installation.join(placement.placement_id().as_str());
        fs::create_dir(&placement_root).expect("placement cache");
        fs::set_permissions(&placement_root, fs::Permissions::from_mode(0o700))
            .expect("placement mode");
        let resident = placement_root.join("resident.cache");
        fs::write(&resident, placement.placement_id().as_str()).expect("resident cache");
        resident_files.push(resident);
    }
    let processes = Arc::new(MockBenchmarkProcessProvider(AtomicU64::new(1)));
    let provider = Arc::new(
        FilesystemPlacementBenchmarkResetProvider::new(
            state_root.clone(),
            cache_root.clone(),
            owner_user_id,
            processes.clone(),
        )
        .expect("filesystem provider"),
    );
    let manager = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(provider);
    let isolation_request = PlacementBenchmarkIsolationRequest::new(
        Sha256Digest::parse(&"e".repeat(64)).expect("isolation"),
        group.clone(),
    );
    let isolation = manager
        .prepare_benchmark_isolation(isolation_request.clone())
        .expect("isolation");
    let current = fixture.store.stored(&group);
    let first = manager
        .reset_for_benchmark(
            PlacementBenchmarkResetRequest::new(
                Sha256Digest::parse(&"a".repeat(64)).expect("reset"),
                group.clone(),
                current.revision(),
                "short",
                1,
                2,
            )
            .expect("reset request"),
        )
        .expect("reset");
    assert!(resident_files.iter().all(|path| !path.exists()));
    let short_files = resident_files
        .iter()
        .map(|path| path.parent().expect("cache root").join("short.cache"))
        .collect::<Vec<_>>();
    for path in &short_files {
        fs::write(path, b"short-prefix-state").expect("short cache state");
    }
    let current = fixture.store.stored(&group);
    let second = manager
        .reset_for_benchmark(
            PlacementBenchmarkResetRequest::new(
                Sha256Digest::parse(&"b".repeat(64)).expect("reset"),
                group.clone(),
                current.revision(),
                "32k",
                2,
                2,
            )
            .expect("reset request"),
        )
        .expect("second reset");
    assert!(short_files.iter().all(|path| !path.exists()));
    assert_ne!(
        first.store_generation_sha256(),
        second.store_generation_sha256()
    );
    assert_ne!(
        first.process_generation_sha256(),
        second.process_generation_sha256()
    );

    let restarted_provider = Arc::new(
        FilesystemPlacementBenchmarkResetProvider::new(
            state_root,
            cache_root,
            owner_user_id,
            processes,
        )
        .expect("restarted provider"),
    );
    let restarted = PlacementManager::new(
        fixture.store.clone(),
        fixture.executor.clone(),
        fixture.identity.clone(),
        fixture.clock.clone(),
        admission_policy(),
    )
    .with_benchmark_reset_provider(restarted_provider);
    let restored = restarted
        .restore_benchmark_isolation(isolation_request.clone())
        .expect("restoration");
    assert_eq!(
        restored.isolation().resident_store_generation_sha256(),
        isolation.resident_store_generation_sha256()
    );
    assert!(resident_files.iter().all(|path| path.exists()));
    assert_eq!(
        restarted
            .restore_benchmark_isolation(isolation_request)
            .expect("restoration replay"),
        restored
    );
}

// Rejects aliases, weak ownership boundaries, and overlapping state/cache authority.
#[test]
fn filesystem_benchmark_isolation_rejects_unsafe_roots() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let state_root = temporary.path().join("state");
    let cache_root = temporary.path().join("cache");
    for root in [&state_root, &cache_root] {
        fs::create_dir(root).expect("root");
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let owner_user_id = fs::metadata(&state_root).expect("owner").uid();
    let processes = Arc::new(MockBenchmarkProcessProvider(AtomicU64::new(1)));
    assert!(FilesystemPlacementBenchmarkResetProvider::new(
        cache_root.join("state"),
        cache_root.clone(),
        owner_user_id,
        processes.clone(),
    )
    .is_err());
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o750)).expect("weak mode");
    assert!(FilesystemPlacementBenchmarkResetProvider::new(
        state_root.clone(),
        cache_root.clone(),
        owner_user_id,
        processes.clone(),
    )
    .is_err());
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).expect("private mode");
    let alias = temporary.path().join("cache_alias");
    std::os::unix::fs::symlink(&cache_root, &alias).expect("cache alias");
    assert!(FilesystemPlacementBenchmarkResetProvider::new(
        state_root,
        alias,
        owner_user_id,
        processes,
    )
    .is_err());
}
