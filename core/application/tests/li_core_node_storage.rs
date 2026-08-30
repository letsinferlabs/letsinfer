// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_core_application::{
    CoreNodeStorageCategoryCleanupPort, CoreNodeStorageCleanup, CoreNodeStorageCleanupReceiptStore,
    CoreNodeStorageEntry, CoreNodeStorageEntryProvider, CoreNodeStorageFilesystem,
    CoreNodeStorageMeasurement, CoreNodeStorageRoot, FilesystemCoreNodeStorageCleanupReceiptStore,
    FilesystemCoreNodeStorageObservationProvider, ManagedCoreNodeStorageCleanupPort,
};
use li_core_interface::{OperationId, Sha256Digest};
use li_node_manager::{
    NodeStorageCategory, NodeStorageCleanReceipt, NodeStorageCleanRequest, NodeStorageCleanupPort,
    NodeStorageCoordinator, NodeStorageError, NodeStorageObservationProvider,
};

// Supplies deterministic filesystem capacity and no-follow tree measurements.
struct FilesystemMock {
    capacity: Result<(u64, u64), NodeStorageError>,
    measurements: BTreeMap<PathBuf, Result<CoreNodeStorageMeasurement, NodeStorageError>>,
}

impl CoreNodeStorageFilesystem for FilesystemMock {
    // Returns the configured containing-filesystem observation.
    fn capacity(&self, _path: &Path) -> Result<(u64, u64), NodeStorageError> {
        self.capacity
    }

    // Returns one exact configured path result without touching the host filesystem.
    fn measure(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<CoreNodeStorageMeasurement, NodeStorageError> {
        self.measurements
            .get(path)
            .cloned()
            .unwrap_or(Ok(CoreNodeStorageMeasurement::default()))
    }
}

// Supplies manager-reviewed inactive entries and exact active/retained protection roots.
struct EntryMock {
    entries: Result<Vec<CoreNodeStorageEntry>, NodeStorageError>,
    protected: Result<Vec<PathBuf>, NodeStorageError>,
}

impl CoreNodeStorageEntryProvider for EntryMock {
    // Returns the configured inactive manager projection.
    fn entries(&self) -> Result<Vec<CoreNodeStorageEntry>, NodeStorageError> {
        self.entries.clone()
    }

    // Returns the configured active or retained manager projection.
    fn protected_paths(&self) -> Result<Vec<PathBuf>, NodeStorageError> {
        self.protected.clone()
    }
}

// Records exact owner-routed cleanup attempts and returns ordered outcomes.
struct CleanupOwnerMock {
    calls: Mutex<Vec<(OperationId, Sha256Digest)>>,
    results: Mutex<VecDeque<Result<CoreNodeStorageCleanup, NodeStorageError>>>,
}

impl CleanupOwnerMock {
    // Creates one deterministic manager-owner cleanup port.
    fn new(
        results: impl IntoIterator<Item = Result<CoreNodeStorageCleanup, NodeStorageError>>,
    ) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            results: Mutex::new(results.into_iter().collect()),
        }
    }
}

impl CoreNodeStorageCategoryCleanupPort for CleanupOwnerMock {
    // Records one exact plan-bound owner cleanup.
    fn clean(
        &self,
        operation_id: &OperationId,
        plan_digest: &Sha256Digest,
    ) -> Result<CoreNodeStorageCleanup, NodeStorageError> {
        self.calls
            .lock()
            .expect("calls")
            .push((operation_id.clone(), plan_digest.clone()));
        self.results
            .lock()
            .expect("results")
            .pop_front()
            .expect("prepared cleanup result")
    }
}

// Persists one aggregate receipt and exposes it to deterministic replay.
#[derive(Default)]
struct ReceiptStoreMock {
    receipt: Mutex<Option<NodeStorageCleanReceipt>>,
}

impl CoreNodeStorageCleanupReceiptStore for ReceiptStoreMock {
    // Returns the committed receipt only for its exact operation identity.
    fn read(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<NodeStorageCleanReceipt>, NodeStorageError> {
        Ok(self
            .receipt
            .lock()
            .expect("receipt")
            .clone()
            .filter(|receipt| receipt.operation_id() == operation_id))
    }

    // Commits one receipt or returns the already identical result.
    fn save(
        &self,
        receipt: &NodeStorageCleanReceipt,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        let mut stored = self.receipt.lock().expect("receipt");
        match stored.as_ref() {
            Some(existing) if existing != receipt => Err(NodeStorageError::InvalidProjection),
            Some(existing) => Ok(existing.clone()),
            None => {
                *stored = Some(receipt.clone());
                Ok(receipt.clone())
            }
        }
    }
}

// Creates one exact operation identity.
fn operation(character: char) -> OperationId {
    OperationId::parse(&character.to_string().repeat(32)).expect("operation")
}

// Creates one exact digest identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one truthful observer with model bytes non-reclaimable and two owned candidates.
fn observer(protected: Vec<PathBuf>) -> FilesystemCoreNodeStorageObservationProvider {
    let home = PathBuf::from("/var/lib/letsinfer");
    let models = home.join("runtime_installations");
    let caches = home.join("runtime_cache");
    let benchmarks = home.join("benchmark_evidence");
    let inactive_cache = caches.join("runtime-a/placement-a");
    let completed_benchmark = benchmarks.join("a.json");
    let filesystem = Arc::new(FilesystemMock {
        capacity: Ok((100_000, 40_000)),
        measurements: BTreeMap::from([
            (
                models.clone(),
                Ok(CoreNodeStorageMeasurement::new(30_000, 28_000, 10)),
            ),
            (
                caches.clone(),
                Ok(CoreNodeStorageMeasurement::new(20_000, 18_000, 8)),
            ),
            (
                benchmarks.clone(),
                Ok(CoreNodeStorageMeasurement::new(10_000, 9_000, 4)),
            ),
            (
                inactive_cache.clone(),
                Ok(CoreNodeStorageMeasurement::new(5_000, 4_500, 2)),
            ),
            (
                completed_benchmark.clone(),
                Ok(CoreNodeStorageMeasurement::new(2_000, 1_900, 1)),
            ),
        ]),
    });
    let entries = Arc::new(EntryMock {
        entries: Ok(vec![
            CoreNodeStorageEntry::new(
                NodeStorageCategory::Caches,
                inactive_cache,
                "stopped placement cache",
                Vec::new(),
            )
            .expect("cache entry"),
            CoreNodeStorageEntry::new(
                NodeStorageCategory::Benchmarks,
                completed_benchmark,
                "completed benchmark evidence",
                Vec::new(),
            )
            .expect("benchmark entry"),
        ]),
        protected: Ok(protected),
    });
    FilesystemCoreNodeStorageObservationProvider::new(
        home,
        501,
        vec![
            CoreNodeStorageRoot::new(NodeStorageCategory::Models, models).expect("models"),
            CoreNodeStorageRoot::new(NodeStorageCategory::Caches, caches).expect("caches"),
            CoreNodeStorageRoot::new(NodeStorageCategory::Benchmarks, benchmarks)
                .expect("benchmarks"),
        ],
        entries,
        filesystem,
    )
    .expect("observer")
}

// Proves one ordinary snapshot measures all categories without advertising model reclamation.
#[test]
fn snapshot_is_truthful_and_stable() {
    let observer = observer(Vec::new());
    let first = observer.snapshot().expect("first snapshot");
    let second = observer.snapshot().expect("second snapshot");
    assert_eq!(first, second);
    assert_eq!(first.capacity_bytes(), 100_000);
    assert_eq!(first.available_bytes(), 40_000);
    let models = first
        .usage()
        .iter()
        .find(|usage| usage.category() == NodeStorageCategory::Models)
        .expect("models");
    assert_eq!(models.allocated_bytes(), 30_000);
    assert_eq!(models.reclaimable_bytes(), 0);
    assert_eq!(first.candidates().len(), 2);
    assert_eq!(
        first
            .candidates()
            .iter()
            .map(|candidate| candidate.allocated_bytes())
            .sum::<u64>(),
        7_000
    );
}

// Proves a candidate intersecting active placement data fails closed before cleanup review.
#[test]
fn active_data_cannot_enter_a_cleanup_plan() {
    let observer = observer(vec![PathBuf::from(
        "/var/lib/letsinfer/runtime_cache/runtime-a/placement-a",
    )]);
    assert_eq!(
        observer.snapshot(),
        Err(NodeStorageError::ProviderUnavailable)
    );
}

// Proves changed plans, selected owner dispatch, and aggregate replay remain exact.
#[test]
fn selected_cleanup_is_plan_bound_and_replays_without_owner_calls() {
    let cache = Arc::new(CleanupOwnerMock::new([Ok(CoreNodeStorageCleanup::new(
        1,
        5_000,
        Vec::new(),
    )
    .expect("cache cleanup"))]));
    let benchmark = Arc::new(CleanupOwnerMock::new([Ok(CoreNodeStorageCleanup::new(
        1,
        2_000,
        Vec::new(),
    )
    .expect("benchmark cleanup"))]));
    let receipts = Arc::new(ReceiptStoreMock::default());
    let cleanup = ManagedCoreNodeStorageCleanupPort::new(
        [
            (
                NodeStorageCategory::Caches,
                cache.clone() as Arc<dyn CoreNodeStorageCategoryCleanupPort>,
            ),
            (
                NodeStorageCategory::Benchmarks,
                benchmark.clone() as Arc<dyn CoreNodeStorageCategoryCleanupPort>,
            ),
        ],
        receipts,
    )
    .expect("cleanup");
    let snapshot = observer(Vec::new()).snapshot().expect("snapshot");
    let request = NodeStorageCleanRequest::new(
        operation('1'),
        snapshot.plan_digest().clone(),
        [NodeStorageCategory::Caches],
    )
    .expect("request");
    let first = cleanup.clean(&request).expect("first cleanup");
    let replay = cleanup.clean(&request).expect("replay cleanup");
    assert_eq!(first.reclaimed_bytes(), 5_000);
    assert!(!first.replayed());
    assert!(replay.replayed());
    assert_eq!(cache.calls.lock().expect("cache calls").len(), 1);
    assert!(benchmark.calls.lock().expect("benchmark calls").is_empty());

    let changed =
        NodeStorageCleanRequest::new(operation('1'), digest('f'), [NodeStorageCategory::Caches])
            .expect("changed request");
    assert_eq!(cleanup.clean(&changed), Err(NodeStorageError::PlanChanged));
}

// Proves malformed roots and provider failures never become empty or partial snapshots.
#[test]
fn unsafe_roots_and_provider_failures_fail_closed() {
    assert_eq!(
        CoreNodeStorageRoot::new(NodeStorageCategory::Caches, PathBuf::from("relative/cache")),
        Err(NodeStorageError::ProviderUnavailable)
    );
    let home = PathBuf::from("/var/lib/letsinfer");
    let result = FilesystemCoreNodeStorageObservationProvider::new(
        home.clone(),
        501,
        vec![
            CoreNodeStorageRoot::new(NodeStorageCategory::Caches, home.join("cache"))
                .expect("cache"),
            CoreNodeStorageRoot::new(NodeStorageCategory::Benchmarks, home.join("cache/jobs"))
                .expect("nested"),
        ],
        Arc::new(EntryMock {
            entries: Ok(Vec::new()),
            protected: Ok(Vec::new()),
        }),
        Arc::new(FilesystemMock {
            capacity: Ok((1, 1)),
            measurements: BTreeMap::new(),
        }),
    );
    assert!(result.is_err());

    let failing = FilesystemCoreNodeStorageObservationProvider::new(
        home.clone(),
        501,
        vec![
            CoreNodeStorageRoot::new(NodeStorageCategory::Caches, home.join("cache"))
                .expect("cache"),
        ],
        Arc::new(EntryMock {
            entries: Err(NodeStorageError::ProviderUnavailable),
            protected: Ok(Vec::new()),
        }),
        Arc::new(FilesystemMock {
            capacity: Ok((10, 5)),
            measurements: BTreeMap::from([(
                home.join("cache"),
                Ok(CoreNodeStorageMeasurement::new(1, 1, 1)),
            )]),
        }),
    )
    .expect("failing observer");
    assert_eq!(
        failing.snapshot(),
        Err(NodeStorageError::ProviderUnavailable)
    );
}

// Proves coordinator drift prevents owner dispatch even when cleanup itself is available.
#[test]
fn reviewed_plan_drift_never_reaches_an_owner() {
    struct DriftObserver(Mutex<VecDeque<li_node_manager::NodeStorageSnapshot>>);
    impl NodeStorageObservationProvider for DriftObserver {
        // Returns each prepared snapshot exactly once.
        fn snapshot(&self) -> Result<li_node_manager::NodeStorageSnapshot, NodeStorageError> {
            self.0
                .lock()
                .expect("snapshots")
                .pop_front()
                .ok_or(NodeStorageError::ProviderUnavailable)
        }
    }
    let first = observer(Vec::new()).snapshot().expect("first");
    let second_observer = observer(Vec::new());
    let second = second_observer.snapshot().expect("second");
    let drift = li_node_manager::NodeStorageSnapshot::new(
        second.capacity_bytes(),
        second.available_bytes(),
        second.usage().to_vec(),
        second.candidates().to_vec(),
        digest('e'),
    )
    .expect("drift");
    let observation = Arc::new(DriftObserver(Mutex::new(VecDeque::from([drift]))));
    let owner = Arc::new(CleanupOwnerMock::new([Ok(CoreNodeStorageCleanup::new(
        1,
        5_000,
        Vec::new(),
    )
    .expect("cleanup"))]));
    let cleanup = Arc::new(
        ManagedCoreNodeStorageCleanupPort::new(
            [(
                NodeStorageCategory::Caches,
                owner.clone() as Arc<dyn CoreNodeStorageCategoryCleanupPort>,
            )],
            Arc::new(ReceiptStoreMock::default()),
        )
        .expect("cleanup port"),
    );
    let coordinator = NodeStorageCoordinator::new(observation, cleanup);
    let request = NodeStorageCleanRequest::new(
        operation('2'),
        first.plan_digest().clone(),
        [NodeStorageCategory::Caches],
    )
    .expect("request");
    assert_eq!(
        coordinator.clean(&request),
        Err(NodeStorageError::PlanChanged)
    );
    assert!(owner.calls.lock().expect("calls").is_empty());
}

// Proves the production receipt store publishes owner-only bytes and rejects unsafe roots.
#[test]
fn filesystem_receipt_store_is_atomic_and_owner_bound() {
    let temporary = tempfile::tempdir().expect("temporary");
    let root = temporary.path().join("receipts");
    fs::create_dir(&root).expect("receipt root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let owner_user_id = unsafe { libc::geteuid() };
    let store = FilesystemCoreNodeStorageCleanupReceiptStore::new(root.clone(), owner_user_id)
        .expect("store");
    let receipt =
        NodeStorageCleanReceipt::new(operation('7'), digest('7'), 2, 7_000, Vec::new(), false)
            .expect("receipt");
    assert_eq!(store.save(&receipt), Ok(receipt.clone()));
    assert_eq!(store.save(&receipt), Ok(receipt.clone()));
    assert_eq!(
        store.read(receipt.operation_id()),
        Ok(Some(receipt.clone()))
    );
    let metadata =
        fs::symlink_metadata(root.join(format!("{}.json", receipt.operation_id().as_str())))
            .expect("receipt metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("unsafe root");
    assert!(FilesystemCoreNodeStorageCleanupReceiptStore::new(root, owner_user_id).is_err());
}
