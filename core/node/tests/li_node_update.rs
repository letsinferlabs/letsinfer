// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    ActivatedCoreUpdate, CoreInstallation, CoreUpdateAdmissionLease, CoreUpdateAdmissionProvider,
    CoreUpdateArtifactProvider, CoreUpdateDisposition, CoreUpdateError, CoreUpdateManager,
    CoreUpdateNodeRole, CoreUpdatePhase, CoreUpdatePruneProvider, CoreUpdateReadinessPolicy,
    CoreUpdateResidentService, CoreUpdateServiceContext, CoreUpdateServiceMode,
    CoreUpdateServicePlatform, CoreUpdateServiceProvider, CoreUpdateServiceSnapshotRecord,
    CoreUpdateServiceState, CoreVersion, PreparedCoreUpdate, SystemCoreUpdateReadinessClock,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    ArtifactNodeCoreUpdateAvailabilityProvider, DatabaseCoreUpdateStore, NodeCoreUpdateApiPort,
    NodeCoreUpdateAvailabilityProvider, NodeCoreUpdateCheck, NodeCoreUpdateCheckDisposition,
    NodeCoreUpdateCoordinator, NodeUpdateError,
};

// Returns one canonical digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one immutable Core installation fixture.
fn installation(version: &str, identity: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(identity),
    )
}

// Holds one successful update admission for the complete manager call.
struct AdmissionLease;

impl CoreUpdateAdmissionLease for AdmissionLease {}

// Supplies one deterministic admission decision.
struct Admission;

impl CoreUpdateAdmissionProvider for Admission {
    // Grants one bounded in-process fixture lease.
    fn acquire(
        &self,
        _update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
        Ok(Box::new(AdmissionLease))
    }
}

// Synchronizes one admission boundary without timing assumptions.
#[derive(Default)]
struct AdmissionGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl AdmissionGate {
    // Waits until the first update owns the manager and enters admission.
    fn wait_until_entered(&self) {
        let mut state = self.state.lock().expect("admission gate");
        while !state.0 {
            state = self.changed.wait(state).expect("admission entered");
        }
    }

    // Releases the admitted update after its concurrent caller is observed.
    fn release(&self) {
        let mut state = self.state.lock().expect("admission gate");
        state.1 = true;
        self.changed.notify_all();
    }
}

// Holds the manager at admission so a second call deterministically observes Busy.
struct BlockingAdmission {
    gate: Arc<AdmissionGate>,
}

impl CoreUpdateAdmissionProvider for BlockingAdmission {
    // Signals ownership and waits for the test-controlled release.
    fn acquire(
        &self,
        _update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
        let mut state = self.gate.state.lock().expect("admission gate");
        state.0 = true;
        self.gate.changed.notify_all();
        while !state.1 {
            state = self.gate.changed.wait(state).expect("admission release");
        }
        Ok(Box::new(AdmissionLease))
    }
}

// Owns fixture active-pointer state and exact prepare-failure injection.
struct Artifacts {
    active: Mutex<CoreInstallation>,
    candidate: CoreInstallation,
    fail_prepare: AtomicBool,
    fail_discard: AtomicBool,
    mutations: AtomicUsize,
}

impl CoreUpdateArtifactProvider for Artifacts {
    // Returns the exact active fixture installation.
    fn current(&self, _update_id: &Sha256Digest) -> Result<CoreInstallation, CoreUpdateError> {
        Ok(self.active.lock().expect("active").clone())
    }

    // Returns one exact candidate or one deterministic signed-provider failure.
    fn prepare(
        &self,
        _update_id: &Sha256Digest,
        requested_version: Option<&CoreVersion>,
        _current: &CoreInstallation,
    ) -> Result<PreparedCoreUpdate, CoreUpdateError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        if self.fail_prepare.swap(false, Ordering::SeqCst) {
            return Err(CoreUpdateError::provider(
                "release signature",
                "signed release is unavailable",
            ));
        }
        if requested_version.is_some_and(|version| version != self.candidate.version()) {
            return Err(CoreUpdateError::provider(
                "release identity",
                "requested release identity differs",
            ));
        }
        Ok(PreparedCoreUpdate::new(digest('a'), self.candidate.clone()))
    }

    // Records cleanup of one read-only or failed prepared fixture.
    fn discard(
        &self,
        _update_id: &Sha256Digest,
        _prepared: &PreparedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        if self.fail_discard.swap(false, Ordering::SeqCst) {
            return Err(CoreUpdateError::provider(
                "availability cleanup",
                "verified candidate cleanup is unavailable",
            ));
        }
        Ok(())
    }

    // Moves the fixture active pointer and returns its exact reversible receipt.
    fn activate(
        &self,
        _update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
        current: &CoreInstallation,
    ) -> Result<ActivatedCoreUpdate, CoreUpdateError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        *self.active.lock().expect("active") = prepared.installation().clone();
        ActivatedCoreUpdate::new(
            digest('b'),
            current.clone(),
            prepared.installation().clone(),
        )
    }

    // Restores the previous fixture installation.
    fn rollback(
        &self,
        _update_id: &Sha256Digest,
        activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        *self.active.lock().expect("active") = activation.previous().clone();
        Ok(())
    }

    // Records irreversible fixture activation completion.
    fn commit(
        &self,
        _update_id: &Sha256Digest,
        _activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// Supplies native service facts, mutations, and one durable receipt without touching the host.
struct Services {
    current_identity: Sha256Digest,
    snapshot: Mutex<Option<CoreUpdateServiceSnapshotRecord>>,
}

impl CoreUpdateServiceProvider for Services {
    // Returns the fixed Linux main-node context used by this Node composition fixture.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError> {
        Ok(CoreUpdateServiceContext::new(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        ))
    }

    // Returns the previously stored native service receipt when present.
    fn snapshot_record(
        &self,
        _update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError> {
        Ok(self.snapshot.lock().expect("service snapshot").clone())
    }

    // Stores and returns one exact native service receipt.
    fn store_snapshot_record(
        &self,
        snapshot: CoreUpdateServiceSnapshotRecord,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
        *self.snapshot.lock().expect("service snapshot") = Some(snapshot.clone());
        Ok(snapshot)
    }

    // Returns one loaded and active fixture service state.
    fn observe_service(
        &self,
        service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        CoreUpdateServiceState::new(
            service,
            Some(self.current_identity.clone()),
            Some(self.current_identity.clone()),
        )
    }

    // Accepts one manager-selected fixture service rebind.
    fn rebind_service(
        &self,
        _service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        _installation: &CoreInstallation,
        _active: bool,
    ) -> Result<(), CoreUpdateError> {
        Ok(())
    }

    // Returns one ready native fact within the manager-owned deadline.
    fn service_is_ready_with_timeout(
        &self,
        _service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        _installation: Option<&CoreInstallation>,
        _active: bool,
        _timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        Ok(true)
    }

    // Accepts one exact manager-selected fixture restoration.
    fn restore_service(
        &self,
        _state: &CoreUpdateServiceState,
        _installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        Ok(())
    }
}

// Records deterministic prune calls and supports one cleanup retry.
#[derive(Default)]
struct Pruner {
    fail_once: AtomicBool,
    calls: AtomicUsize,
}

impl CoreUpdatePruneProvider for Pruner {
    // Prunes one fixture identity or returns one scheduled cleanup failure.
    fn prune(
        &self,
        _update_id: &Sha256Digest,
        _active: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_once.swap(false, Ordering::SeqCst) {
            Err(CoreUpdateError::provider("prune", "cleanup unavailable"))
        } else {
            Ok(())
        }
    }
}

// Returns fixture availability and records exact requested-version forwarding.
struct Availability {
    current: CoreInstallation,
    available: CoreInstallation,
    requested: Mutex<Vec<Option<CoreVersion>>>,
    fail: AtomicBool,
}

impl NodeCoreUpdateAvailabilityProvider for Availability {
    // Returns one verified fixture check without entering manager mutation.
    fn check(
        &self,
        requested_version: Option<&CoreVersion>,
    ) -> Result<NodeCoreUpdateCheck, CoreUpdateError> {
        self.requested
            .lock()
            .expect("requested versions")
            .push(requested_version.cloned());
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(CoreUpdateError::provider(
                "release signature",
                "verification unavailable",
            ));
        }
        if requested_version.is_some_and(|version| version != self.available.version()) {
            return Err(CoreUpdateError::provider(
                "release identity",
                "requested release differs",
            ));
        }
        Ok(NodeCoreUpdateCheck::new(
            self.current.clone(),
            self.available.clone(),
        ))
    }
}

// Owns one manager-backed coordinator fixture and its observable providers.
struct Fixture {
    coordinator: NodeCoreUpdateCoordinator,
    artifacts: Arc<Artifacts>,
    availability: Arc<Availability>,
    pruner: Arc<Pruner>,
}

// Composes one real CoreUpdateManager without filesystem, network, or service mutation.
fn fixture(directory: &tempfile::TempDir) -> Fixture {
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let current = installation("1.0.0", '1');
    let available = installation("1.1.0", '2');
    let artifacts = Arc::new(Artifacts {
        active: Mutex::new(current.clone()),
        candidate: available.clone(),
        fail_prepare: AtomicBool::new(false),
        fail_discard: AtomicBool::new(false),
        mutations: AtomicUsize::new(0),
    });
    let pruner = Arc::new(Pruner::default());
    let manager = Arc::new(CoreUpdateManager::new(
        Arc::new(DatabaseCoreUpdateStore::new(database)),
        Arc::new(Admission),
        artifacts.clone(),
        Arc::new(Services {
            current_identity: current.source_identity().clone(),
            snapshot: Mutex::new(None),
        }),
        pruner.clone(),
        Arc::new(SystemCoreUpdateReadinessClock::new()),
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    ));
    let availability = Arc::new(Availability {
        current,
        available,
        requested: Mutex::new(Vec::new()),
        fail: AtomicBool::new(false),
    });
    Fixture {
        coordinator: NodeCoreUpdateCoordinator::new(manager, availability.clone()),
        artifacts,
        availability,
        pruner,
    }
}

// Proves availability is exact, mutation-free, and preserves signed-provider failures.
#[test]
fn check_forwards_exact_version_without_manager_mutation() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    let requested = CoreVersion::parse("1.1.0").expect("version");
    let check = fixture
        .coordinator
        .check(Some(requested.clone()))
        .expect("check");
    assert_eq!(
        check.disposition(),
        NodeCoreUpdateCheckDisposition::UpdateAvailable
    );
    assert_eq!(
        fixture
            .availability
            .requested
            .lock()
            .expect("requests")
            .as_slice(),
        &[Some(requested)]
    );
    assert_eq!(fixture.artifacts.mutations.load(Ordering::SeqCst), 0);

    fixture.availability.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture.coordinator.check(None),
        Err(NodeUpdateError::Core(CoreUpdateError::Provider {
            capability: "release signature",
            ..
        }))
    ));
    assert_eq!(fixture.artifacts.mutations.load(Ordering::SeqCst), 0);
}

// Verifies signed availability through prepare/discard without moving the active installation.
#[test]
fn artifact_availability_verifies_and_discards_without_activation() {
    let current = installation("1.0.0", '1');
    let available = installation("1.1.0", '2');
    let artifacts = Arc::new(Artifacts {
        active: Mutex::new(current.clone()),
        candidate: available.clone(),
        fail_prepare: AtomicBool::new(false),
        fail_discard: AtomicBool::new(false),
        mutations: AtomicUsize::new(0),
    });
    let provider = ArtifactNodeCoreUpdateAvailabilityProvider::new(artifacts.clone());
    let check = provider
        .check(Some(available.version()))
        .expect("signed availability");
    assert_eq!(check.current(), &current);
    assert_eq!(check.available(), &available);
    assert_eq!(
        check.disposition(),
        NodeCoreUpdateCheckDisposition::UpdateAvailable
    );
    assert_eq!(*artifacts.active.lock().expect("active"), current);
    assert_eq!(artifacts.mutations.load(Ordering::SeqCst), 2);
}

// Preserves prepare and cleanup failures while proving neither path can activate Core.
#[test]
fn artifact_availability_fails_closed_at_prepare_and_discard() {
    for failure in ["prepare", "discard"] {
        let current = installation("1.0.0", '1');
        let artifacts = Arc::new(Artifacts {
            active: Mutex::new(current.clone()),
            candidate: installation("1.1.0", '2'),
            fail_prepare: AtomicBool::new(failure == "prepare"),
            fail_discard: AtomicBool::new(failure == "discard"),
            mutations: AtomicUsize::new(0),
        });
        let provider = ArtifactNodeCoreUpdateAvailabilityProvider::new(artifacts.clone());
        assert!(provider.check(None).is_err(), "{failure}");
        assert_eq!(*artifacts.active.lock().expect("active"), current);
        assert_eq!(
            artifacts.mutations.load(Ordering::SeqCst),
            if failure == "prepare" { 1 } else { 2 }
        );
    }
}

// Projects success, terminal replay, request conflict, and pre-cutover rollback exactly.
#[test]
fn update_preserves_manager_terminal_and_failure_contracts() {
    let directory = tempfile::tempdir().expect("directory");
    let environment = fixture(&directory);
    let requested = CoreVersion::parse("1.1.0").expect("version");
    let changed = environment
        .coordinator
        .update("core-1.1.0", Some(requested.clone()))
        .expect("update");
    assert_eq!(changed.disposition(), CoreUpdateDisposition::Updated);
    assert_eq!(changed.phase(), CoreUpdatePhase::Succeeded);
    let mutation_count = environment.artifacts.mutations.load(Ordering::SeqCst);
    let replay = environment
        .coordinator
        .update("core-1.1.0", Some(requested))
        .expect("replay");
    assert_eq!(replay, changed);
    assert_eq!(
        environment.artifacts.mutations.load(Ordering::SeqCst),
        mutation_count
    );
    assert_eq!(
        environment.coordinator.update(
            "core-1.1.0",
            Some(CoreVersion::parse("1.2.0").expect("version")),
        ),
        Err(NodeUpdateError::Core(CoreUpdateError::IdempotencyConflict))
    );

    let failed_directory = tempfile::tempdir().expect("failed directory");
    let failed = fixture(&failed_directory);
    failed.artifacts.fail_prepare.store(true, Ordering::SeqCst);
    assert!(matches!(
        failed.coordinator.update("signed-failure", None),
        Err(NodeUpdateError::Core(CoreUpdateError::RolledBack { .. }))
    ));
}

// Projects post-commit cleanup pending and its exact idempotent retry.
#[test]
fn update_retries_post_cutover_cleanup_through_the_same_manager() {
    let directory = tempfile::tempdir().expect("directory");
    let fixture = fixture(&directory);
    fixture.pruner.fail_once.store(true, Ordering::SeqCst);
    let pending = fixture
        .coordinator
        .update("cleanup", None)
        .expect("cleanup pending");
    assert_eq!(pending.disposition(), CoreUpdateDisposition::CleanupPending);
    assert_eq!(pending.phase(), CoreUpdatePhase::CleanupPending);
    let complete = fixture
        .coordinator
        .update("cleanup", None)
        .expect("cleanup retry");
    assert_eq!(complete.disposition(), CoreUpdateDisposition::Updated);
    assert_eq!(complete.phase(), CoreUpdatePhase::Succeeded);
    assert_eq!(fixture.pruner.calls.load(Ordering::SeqCst), 2);
}

// Preserves CoreUpdateManager's single-writer Busy decision through the Node adapter.
#[test]
fn concurrent_updates_have_one_admitted_writer() {
    let directory = tempfile::tempdir().expect("directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let current = installation("1.0.0", '1');
    let available = installation("1.1.0", '2');
    let artifacts = Arc::new(Artifacts {
        active: Mutex::new(current.clone()),
        candidate: available.clone(),
        fail_prepare: AtomicBool::new(false),
        fail_discard: AtomicBool::new(false),
        mutations: AtomicUsize::new(0),
    });
    let gate = Arc::new(AdmissionGate::default());
    let manager = Arc::new(CoreUpdateManager::new(
        Arc::new(DatabaseCoreUpdateStore::new(database)),
        Arc::new(BlockingAdmission { gate: gate.clone() }),
        artifacts,
        Arc::new(Services {
            current_identity: current.source_identity().clone(),
            snapshot: Mutex::new(None),
        }),
        Arc::new(Pruner::default()),
        Arc::new(SystemCoreUpdateReadinessClock::new()),
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    ));
    let coordinator = Arc::new(NodeCoreUpdateCoordinator::new(
        manager,
        Arc::new(Availability {
            current,
            available,
            requested: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
        }),
    ));
    let worker = {
        let coordinator = coordinator.clone();
        thread::spawn(move || coordinator.update("first", None))
    };
    gate.wait_until_entered();
    assert_eq!(
        coordinator.update("second", None),
        Err(NodeUpdateError::Core(CoreUpdateError::Busy))
    );
    gate.release();
    assert!(worker.join().expect("update worker").is_ok());
}
