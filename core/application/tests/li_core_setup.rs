// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use li_core_application::{
    ApplicationCoreSetupServiceProvider, CoreServiceCutoverReceipt, CoreServiceCutoverRecovery,
    CoreServiceSetupError, CoreServiceSetupNodeIdentity, CoreSetup, CoreSetupConfigurationProvider,
    CoreSetupDisposition, CoreSetupError, CoreSetupExecutionLock, CoreSetupExecutionLockProvider,
    CoreSetupIdentityClock, CoreSetupIdentityDatabaseOperation, CoreSetupIdentityDatabaseProvider,
    CoreSetupIdentityProvider, CoreSetupIdentitySourceError, CoreSetupInstalledConfigurations,
    CoreSetupInstalledServices, CoreSetupJournal, CoreSetupJournalStore,
    CoreSetupMachineIdentityProvider, CoreSetupMaterialProvider, CoreSetupNetworkPlan,
    CoreSetupPhase, CoreSetupPreparedIdentity, CoreSetupPreparedMaterial, CoreSetupProviderError,
    CoreSetupReceipt, CoreSetupRequest, CoreSetupServiceApplication, CoreSetupServiceProvider,
    CoreSetupStoreError, DatabaseCoreSetupIdentityProvider, VersionedCoreSetupJournal,
    CORE_SETUP_RESULT_SCHEMA_NAME, CORE_SETUP_RESULT_SCHEMA_VERSION,
    MAXIMUM_CORE_SETUP_RESULT_BYTES,
};
use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeRole, Sha256Digest,
    UnixMilliseconds,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    DatabaseNodeSetupIdentityStore, NodeSetupIdentity, NodeSetupIdentityError,
    NodeSetupIdentityInput,
};
use serde_json::{json, Value};

// Selects one deterministic provider or journal failure boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    Identity,
    IdentityRecovery,
    IdentityMismatch,
    IdentityDrift,
    Material,
    MaterialRecovery,
    MaterialDrift,
    MaterialAlias,
    Configurations,
    ConfigurationRecovery,
    ConfigurationDrift,
    Services,
    ServiceRecovery,
    ServiceDrift,
    Verification,
    IdentityRollback,
    MaterialRollback,
    ConfigurationRollback,
}

// Stores exact provider calls and the optional single-use failure.
#[derive(Default)]
struct TestProviderState {
    calls: Vec<&'static str>,
    failures: Vec<FailurePoint>,
    entered_barrier: Option<Arc<Barrier>>,
    release_barrier: Option<Arc<Barrier>>,
    service_recovery: Option<CoreServiceCutoverRecovery>,
}

impl TestProviderState {
    // Consumes one selected failure without affecting later replay attempts.
    fn take(&mut self, point: FailurePoint) -> bool {
        if let Some(index) = self.failures.iter().position(|value| *value == point) {
            self.failures.remove(index);
            true
        } else {
            false
        }
    }
}

// Holds one process-wide nonblocking setup lock for deterministic concurrency tests.
#[derive(Default)]
struct TestLockProvider {
    held: Arc<AtomicBool>,
}

// Releases the exact injected setup lock when orchestration returns.
struct TestLock {
    held: Arc<AtomicBool>,
}

impl CoreSetupExecutionLock for TestLock {}

impl Drop for TestLock {
    // Releases one lock only after every provider and journal operation completes.
    fn drop(&mut self) {
        self.held.store(false, Ordering::Release);
    }
}

impl CoreSetupExecutionLockProvider for TestLockProvider {
    // Acquires one deterministic nonblocking lock or reports active ownership.
    fn try_acquire(&self) -> Result<Box<dyn CoreSetupExecutionLock>, CoreSetupError> {
        self.held
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CoreSetupError::Busy)?;
        Ok(Box::new(TestLock {
            held: self.held.clone(),
        }))
    }
}

// Stores one optimistic in-memory journal set with injected publication failures.
#[derive(Default)]
struct TestStoreState {
    journals: BTreeMap<String, VersionedCoreSetupJournal>,
    fail_replacement: Option<(CoreSetupPhase, CoreSetupStoreError)>,
    fail_remove: bool,
}

// Supplies deterministic durable-journal semantics without mocking orchestration results.
#[derive(Default)]
struct TestStore {
    state: Mutex<TestStoreState>,
}

impl TestStore {
    // Selects one single-use journal replacement failure.
    fn fail_replacement(&self, phase: CoreSetupPhase) {
        self.fail_replacement_with(phase, CoreSetupStoreError::Unavailable);
    }

    // Selects one single-use journal replacement failure and its exact classification.
    fn fail_replacement_with(&self, phase: CoreSetupPhase, error: CoreSetupStoreError) {
        self.state.lock().expect("store").fail_replacement = Some((phase, error));
    }

    // Selects one single-use compensated-journal removal failure.
    fn fail_remove(&self) {
        self.state.lock().expect("store").fail_remove = true;
    }

    // Returns one current phase for crash-boundary assertions.
    fn phase(&self, request_id: &Sha256Digest) -> Option<CoreSetupPhase> {
        self.state
            .lock()
            .expect("store")
            .journals
            .get(request_id.as_str())
            .map(|value| value.journal().phase())
    }

    // Inserts one journal under an independently selected lookup key to model corrupt storage.
    fn seed_under(&self, key: &Sha256Digest, journal: CoreSetupJournal) {
        self.state.lock().expect("store").journals.insert(
            key.as_str().to_string(),
            VersionedCoreSetupJournal::new(journal, 1).expect("journal"),
        );
    }

    // Returns one exact stored journal for deterministic corruption reconstruction.
    fn journal(&self, key: &Sha256Digest) -> CoreSetupJournal {
        self.state
            .lock()
            .expect("store")
            .journals
            .get(key.as_str())
            .expect("journal")
            .journal()
            .clone()
    }
}

impl CoreSetupJournalStore for TestStore {
    // Returns exactly one incomplete journal or rejects ambiguous recovery state.
    fn recovery(&self) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CoreSetupStoreError::Unavailable)?;
        let mut recovery = None;
        for journal in state.journals.values() {
            if journal.journal().phase() == CoreSetupPhase::Completed {
                continue;
            }
            if recovery.replace(journal.clone()).is_some() {
                return Err(CoreSetupStoreError::Corrupt);
            }
        }
        Ok(recovery)
    }

    // Reads one exact committed in-memory journal.
    fn read(
        &self,
        request_id: &Sha256Digest,
    ) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| CoreSetupStoreError::Unavailable)?
            .journals
            .get(request_id.as_str())
            .cloned())
    }

    // Creates once or returns the authoritative journal from a prior invocation.
    fn create(
        &self,
        journal: CoreSetupJournal,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoreSetupStoreError::Unavailable)?;
        if let Some(existing) = state.journals.get(journal.request_id().as_str()) {
            return Ok(existing.clone());
        }
        let versioned = VersionedCoreSetupJournal::new(journal, 1)?;
        state.journals.insert(
            versioned.journal().request_id().as_str().to_string(),
            versioned.clone(),
        );
        Ok(versioned)
    }

    // Replaces only the exact current optimistic revision.
    fn replace(
        &self,
        journal: CoreSetupJournal,
        expected_revision: u64,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoreSetupStoreError::Unavailable)?;
        if state
            .fail_replacement
            .as_ref()
            .is_some_and(|(phase, _)| *phase == journal.phase())
        {
            let (_, error) = state
                .fail_replacement
                .take()
                .expect("selected replacement failure");
            return Err(error);
        }
        let current = state
            .journals
            .get(journal.request_id().as_str())
            .ok_or(CoreSetupStoreError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(CoreSetupStoreError::Conflict);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(CoreSetupStoreError::Corrupt)?;
        let versioned = VersionedCoreSetupJournal::new(journal, revision)?;
        state.journals.insert(
            versioned.journal().request_id().as_str().to_string(),
            versioned.clone(),
        );
        Ok(versioned)
    }

    // Removes only the exact current optimistic revision after compensation.
    fn remove(
        &self,
        request_id: &Sha256Digest,
        expected_revision: u64,
    ) -> Result<(), CoreSetupStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoreSetupStoreError::Unavailable)?;
        if state.fail_remove {
            state.fail_remove = false;
            return Err(CoreSetupStoreError::Unavailable);
        }
        let current = state
            .journals
            .get(request_id.as_str())
            .ok_or(CoreSetupStoreError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(CoreSetupStoreError::Conflict);
        }
        state.journals.remove(request_id.as_str());
        Ok(())
    }
}

// Supplies deterministic public identity mutation and compensation.
struct TestIdentityProvider {
    state: Arc<Mutex<TestProviderState>>,
}

impl CoreSetupIdentityProvider for TestIdentityProvider {
    // Returns one exact request-bound identity or the selected pre-mutation failure.
    fn prepare(
        &self,
        request: &CoreSetupRequest,
    ) -> Result<CoreSetupPreparedIdentity, CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("identity.prepare");
        if state.take(FailurePoint::IdentityRecovery) {
            return Err(CoreSetupProviderError::recovery_required(
                "node identity",
                "identity preparation is ambiguous",
            ));
        }
        if state.take(FailurePoint::Identity) {
            return Err(CoreSetupProviderError::unchanged(
                "node identity",
                "identity preparation failed",
            ));
        }
        let entered_barrier = state.entered_barrier.clone();
        let release_barrier = state.release_barrier.clone();
        let has_drift = state.take(FailurePoint::IdentityDrift);
        let has_mismatch = state.take(FailurePoint::IdentityMismatch);
        drop(state);
        if let Some(barrier) = entered_barrier {
            barrier.wait();
        }
        if let Some(barrier) = release_barrier {
            barrier.wait();
        }
        let receipt = if has_drift {
            receipt('9')
        } else {
            receipt('1')
        };
        let display_name = if has_mismatch {
            DisplayName::parse("Foreign").expect("foreign name")
        } else {
            request.display_name().clone()
        };
        Ok(CoreSetupPreparedIdentity::new(
            receipt,
            NodeId::parse(&identity('a', 32)).expect("node"),
            MachineId::parse(&identity('b', 32)).expect("machine"),
            InstallationId::parse(&identity('c', 64)).expect("installation"),
            display_name,
            match request.context().role() {
                CoreUpdateNodeRole::Main => NodeRole::Main,
                CoreUpdateNodeRole::Child => NodeRole::Child,
            },
            request.control_address().clone(),
        ))
    }

    // Records exact identity rollback or returns the selected compensation failure.
    fn rollback(&self, _receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("identity.rollback");
        if state.take(FailurePoint::IdentityRollback) {
            return Err(CoreSetupProviderError::recovery_required(
                "node identity",
                "identity rollback failed",
            ));
        }
        Ok(())
    }
}

// Supplies deterministic private material references without storing secret bytes in setup state.
struct TestMaterialProvider {
    state: Arc<Mutex<TestProviderState>>,
}

impl CoreSetupMaterialProvider for TestMaterialProvider {
    // Returns role-correct private file references or the selected pre-mutation failure.
    fn prepare(
        &self,
        request: &CoreSetupRequest,
        _identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("material.prepare");
        if state.take(FailurePoint::MaterialRecovery) {
            return Err(CoreSetupProviderError::recovery_required(
                "private material",
                "material preparation is ambiguous",
            ));
        }
        if state.take(FailurePoint::Material) {
            return Err(CoreSetupProviderError::rolled_back(
                "private material",
                "material preparation failed",
            ));
        }
        let receipt = if state.take(FailurePoint::MaterialDrift) {
            receipt('8')
        } else {
            receipt('2')
        };
        let pairing_path = if state.take(FailurePoint::MaterialAlias) {
            "/var/lib/letsinfer/li_core.sqlite3"
        } else {
            "/var/lib/letsinfer/pairing.key"
        };
        Ok(CoreSetupPreparedMaterial::new_with_benchmark_signing(
            receipt,
            "/var/lib/letsinfer/li_core.sqlite3".into(),
            pairing_path.into(),
            (request.context().role() == CoreUpdateNodeRole::Main)
                .then(|| "/var/lib/letsinfer/api.key".into()),
            benchmark_signing_material(),
            pairing_trust_material(),
            node_trust_material(),
            gateway_trust_material(),
            (request.context().platform() == CoreUpdateServicePlatform::Linux)
                .then(watchdog_trust_material),
            digest('d'),
        ))
    }

    // Records exact material rollback or returns the selected compensation failure.
    fn rollback(&self, _receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("material.rollback");
        if state.take(FailurePoint::MaterialRollback) {
            return Err(CoreSetupProviderError::recovery_required(
                "private material",
                "material rollback failed",
            ));
        }
        Ok(())
    }
}

// Supplies deterministic complete configuration mutation and compensation.
struct TestConfigurationProvider {
    state: Arc<Mutex<TestProviderState>>,
}

impl CoreSetupConfigurationProvider for TestConfigurationProvider {
    // Returns one configuration receipt or the selected internally rolled-back failure.
    fn install(
        &self,
        _request: &CoreSetupRequest,
        _identity: &CoreSetupPreparedIdentity,
        _material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupInstalledConfigurations, CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("configuration.install");
        if state.take(FailurePoint::ConfigurationRecovery) {
            return Err(CoreSetupProviderError::recovery_required(
                "configurations",
                "configuration installation is ambiguous",
            ));
        }
        if state.take(FailurePoint::Configurations) {
            return Err(CoreSetupProviderError::rolled_back(
                "configurations",
                "configuration installation failed",
            ));
        }
        let receipt = if state.take(FailurePoint::ConfigurationDrift) {
            receipt('7')
        } else {
            receipt('3')
        };
        Ok(CoreSetupInstalledConfigurations::new(receipt))
    }

    // Records exact configuration rollback or returns the selected compensation failure.
    fn rollback(&self, _receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("configuration.rollback");
        if state.take(FailurePoint::ConfigurationRollback) {
            return Err(CoreSetupProviderError::recovery_required(
                "configurations",
                "configuration rollback failed",
            ));
        }
        Ok(())
    }
}

// Supplies deterministic resident activation, replay, and semantic verification.
struct TestServiceProvider {
    state: Arc<Mutex<TestProviderState>>,
}

impl CoreSetupServiceProvider for TestServiceProvider {
    // Reports only an explicitly selected interrupted native restoration.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        let recovery = state
            .service_recovery
            .unwrap_or(CoreServiceCutoverRecovery::None);
        if recovery != CoreServiceCutoverRecovery::None {
            state.calls.push("services.recovery");
        }
        Ok(recovery)
    }

    // Advances the selected native restoration without clearing its durable checkpoint.
    fn resume_recovery(&self) -> Result<(), CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("services.resume_recovery");
        state.service_recovery = Some(CoreServiceCutoverRecovery::Restored);
        Ok(())
    }

    // Clears the selected restored checkpoint after reversible compensation completes.
    fn complete_recovery(&self) -> Result<(), CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("services.complete_recovery");
        state.service_recovery = None;
        Ok(())
    }

    // Returns one committed service receipt or the selected classified cutover failure.
    fn apply(
        &self,
        _request: &CoreSetupRequest,
        _identity: &CoreSetupPreparedIdentity,
        _material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupInstalledServices, CoreSetupProviderError> {
        let mut state = self.state.lock().expect("providers");
        state.calls.push("services.apply");
        if state.take(FailurePoint::ServiceRecovery) {
            return Err(CoreSetupProviderError::recovery_required(
                "resident services",
                "service cutover is ambiguous",
            ));
        }
        if state.take(FailurePoint::Verification) {
            return Err(CoreSetupProviderError::recovery_required(
                "resident services",
                "service readiness failed",
            ));
        }
        if state.take(FailurePoint::Services) {
            return Err(CoreSetupProviderError::rolled_back(
                "resident services",
                "service activation failed",
            ));
        }
        let receipt = if state.take(FailurePoint::ServiceDrift) {
            receipt('6')
        } else {
            receipt('4')
        };
        Ok(CoreSetupInstalledServices::new(receipt))
    }
}

// Groups one complete deterministic orchestration fixture.
struct Fixture {
    setup: Arc<CoreSetup>,
    store: Arc<TestStore>,
    providers: Arc<Mutex<TestProviderState>>,
}

// Stores deterministic calls and one optional native service-application failure.
struct TestServiceApplication {
    context: CoreUpdateServiceContext,
    receipt: CoreServiceCutoverReceipt,
    failure: Mutex<Option<CoreServiceSetupError>>,
    calls: Mutex<usize>,
}

impl TestServiceApplication {
    // Creates one exact native service application fixture.
    fn new(context: CoreUpdateServiceContext) -> Self {
        Self {
            context,
            receipt: CoreServiceCutoverReceipt::new(digest('5')),
            failure: Mutex::new(None),
            calls: Mutex::new(0),
        }
    }

    // Creates one fixture that fails its next native application call.
    fn failing(context: CoreUpdateServiceContext, error: CoreServiceSetupError) -> Self {
        let application = Self::new(context);
        *application.failure.lock().expect("failure") = Some(error);
        application
    }

    // Returns the exact number of delegated native applications.
    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls")
    }
}

impl CoreSetupServiceApplication for TestServiceApplication {
    // Returns the immutable platform and role selected by this fixture.
    fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Returns one exact receipt or consumes the selected native setup failure.
    fn apply(
        &self,
        _installation: &CoreInstallation,
        _identity: &CoreServiceSetupNodeIdentity,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError> {
        *self.calls.lock().expect("calls") += 1;
        if let Some(error) = self.failure.lock().expect("failure").take() {
            return Err(error);
        }
        Ok(self.receipt.clone())
    }

    // Reports no interrupted recovery state in the ordinary adapter fixture.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError> {
        Ok(CoreServiceCutoverRecovery::None)
    }

    // Rejects unreachable recovery mutation in the ordinary adapter fixture.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError> {
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "test recovery is unavailable",
        })
    }

    // Accepts idempotent terminal cleanup when no recovery record exists.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError> {
        Ok(())
    }
}

// Opens real bootstrap stores while exposing only their operation lifetime to the test.
struct TrackingIdentityDatabaseProvider {
    database_file: PathBuf,
    active: Arc<AtomicBool>,
    opens: Arc<AtomicUsize>,
}

impl CoreSetupIdentityDatabaseProvider for TrackingIdentityDatabaseProvider {
    // Opens one real writer and marks it active until the operation explicitly closes.
    fn open(&self) -> Result<Box<dyn CoreSetupIdentityDatabaseOperation>, NodeSetupIdentityError> {
        self.active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| NodeSetupIdentityError::RecoveryRequired)?;
        self.opens.fetch_add(1, Ordering::SeqCst);
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(self.database_file.clone()))
                .map_err(|_| NodeSetupIdentityError::Unavailable)?,
        );
        Ok(Box::new(TrackingIdentityDatabaseOperation {
            store: Some(DatabaseNodeSetupIdentityStore::new(database.clone())),
            database: Some(database),
            active: self.active.clone(),
        }))
    }
}

// Retains one tracked real database writer only through a single bootstrap operation.
struct TrackingIdentityDatabaseOperation {
    store: Option<DatabaseNodeSetupIdentityStore>,
    database: Option<Arc<DatabaseManager>>,
    active: Arc<AtomicBool>,
}

impl CoreSetupIdentityDatabaseOperation for TrackingIdentityDatabaseOperation {
    // Delegates setup preparation to the real atomic Node adapter.
    fn prepare(
        &self,
        input: NodeSetupIdentityInput,
    ) -> Result<NodeSetupIdentity, NodeSetupIdentityError> {
        self.store
            .as_ref()
            .ok_or(NodeSetupIdentityError::RecoveryRequired)?
            .prepare(input)
    }

    // Delegates exact compensation to the real atomic Node adapter.
    fn rollback(&self, receipt_identity: &Sha256Digest) -> Result<(), NodeSetupIdentityError> {
        self.store
            .as_ref()
            .ok_or(NodeSetupIdentityError::RecoveryRequired)?
            .rollback(receipt_identity)
    }

    // Joins the real writer before releasing the test's active-operation marker.
    fn close(mut self: Box<Self>) -> Result<(), NodeSetupIdentityError> {
        self.store.take();
        let database = self
            .database
            .take()
            .ok_or(NodeSetupIdentityError::RecoveryRequired)?;
        let result = Arc::try_unwrap(database)
            .map_err(|_| NodeSetupIdentityError::RecoveryRequired)?
            .close()
            .map_err(|_| NodeSetupIdentityError::RecoveryRequired);
        self.active.store(false, Ordering::SeqCst);
        result
    }
}

// Supplies one fixed machine identity for the operation-lifetime setup proof.
struct TrackingMachineIdentity;

impl CoreSetupMachineIdentityProvider for TrackingMachineIdentity {
    // Returns one exact stable machine identity without native I/O.
    fn machine_id(&self) -> Result<MachineId, CoreSetupIdentitySourceError> {
        MachineId::parse(&"b".repeat(32)).map_err(|_| CoreSetupIdentitySourceError::Invalid)
    }
}

// Supplies one fixed setup timestamp for the operation-lifetime setup proof.
struct TrackingIdentityClock;

impl CoreSetupIdentityClock for TrackingIdentityClock {
    // Returns one exact non-negative setup timestamp.
    fn now(&self) -> Result<UnixMilliseconds, CoreSetupIdentitySourceError> {
        Ok(UnixMilliseconds::new(5_000))
    }
}

// Rejects any service application entered while the setup bootstrap writer remains live.
struct DatabaseClosedServiceApplication {
    context: CoreUpdateServiceContext,
    active: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl CoreSetupServiceApplication for DatabaseClosedServiceApplication {
    // Returns the immutable standalone-main context selected by this fixture.
    fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Proves the bootstrap writer is closed before accepting the exact prepared Node identity.
    fn apply(
        &self,
        _installation: &CoreInstallation,
        identity: &CoreServiceSetupNodeIdentity,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError> {
        assert!(!self.active.load(Ordering::SeqCst));
        assert_eq!(identity.role(), NodeRole::Main);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CoreServiceCutoverReceipt::new(digest('5')))
    }

    // Reports no interrupted native restoration for an ordinary setup.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError> {
        Ok(CoreServiceCutoverRecovery::None)
    }

    // Rejects unreachable recovery mutation in this ordinary setup fixture.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError> {
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "test recovery is unavailable",
        })
    }

    // Accepts idempotent cleanup when no recovery record exists.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError> {
        Ok(())
    }
}

impl Fixture {
    // Creates one fixture with every narrow capability injected independently.
    fn new() -> Self {
        let providers = Arc::new(Mutex::new(TestProviderState::default()));
        let store = Arc::new(TestStore::default());
        let setup = Arc::new(CoreSetup::new(
            Arc::new(TestLockProvider::default()),
            store.clone(),
            Arc::new(TestIdentityProvider {
                state: providers.clone(),
            }),
            Arc::new(TestMaterialProvider {
                state: providers.clone(),
            }),
            Arc::new(TestConfigurationProvider {
                state: providers.clone(),
            }),
            Arc::new(TestServiceProvider {
                state: providers.clone(),
            }),
        ));
        Self {
            setup,
            store,
            providers,
        }
    }

    // Selects one single-use provider failure.
    fn fail(&self, point: FailurePoint) {
        self.providers
            .lock()
            .expect("providers")
            .failures
            .push(point);
    }

    // Selects one exact interrupted service-restoration phase.
    fn recover_services(&self, recovery: CoreServiceCutoverRecovery) {
        self.providers.lock().expect("providers").service_recovery = Some(recovery);
    }

    // Returns the exact provider call sequence.
    fn calls(&self) -> Vec<&'static str> {
        self.providers.lock().expect("providers").calls.clone()
    }
}

// Restores the prior source transaction before committing the current request in one invocation.
#[test]
fn interrupted_service_recovery_precedes_source_bound_journal_validation() {
    let fixture = Fixture::new();
    let prior = request(
        7,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let journal = recoverable_journal(&prior);
    fixture.store.seed_under(prior.request_id(), journal);
    fixture.recover_services(CoreServiceCutoverRecovery::Restoring);

    let current = request(
        8,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let result = fixture.setup.setup(&current).expect("recovered setup");
    assert_eq!(result.status(), CoreSetupDisposition::Installed);
    assert_eq!(
        fixture.calls(),
        vec![
            "services.recovery",
            "services.resume_recovery",
            "configuration.rollback",
            "material.rollback",
            "identity.rollback",
            "services.complete_recovery",
            "identity.prepare",
            "material.prepare",
            "configuration.install",
            "services.apply",
        ]
    );
    assert_eq!(fixture.store.phase(prior.request_id()), None);
    assert_eq!(
        fixture.store.phase(current.request_id()),
        Some(CoreSetupPhase::Completed)
    );
}

// Replays compensation from Restored when journal retirement failed without restoring twice.
#[test]
fn interrupted_service_recovery_retries_outer_compensation_idempotently() {
    let fixture = Fixture::new();
    let prior = request(
        7,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    fixture
        .store
        .seed_under(prior.request_id(), recoverable_journal(&prior));
    fixture.store.fail_remove();
    fixture.recover_services(CoreServiceCutoverRecovery::Restoring);
    let current = request(
        8,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );

    assert_eq!(
        fixture.setup.setup(&current),
        Err(CoreSetupError::RecoveryRequired {
            capability: "setup journal",
            reason: "compensated interrupted setup state could not be retired",
        })
    );
    let result = fixture.setup.setup(&current).expect("recovered setup");
    assert_eq!(result.status(), CoreSetupDisposition::Installed);
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|call| **call == "services.resume_recovery")
            .count(),
        1
    );
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|call| **call == "configuration.rollback")
            .count(),
        2
    );
    assert_eq!(fixture.store.phase(prior.request_id()), None);
    assert_eq!(
        fixture.store.phase(current.request_id()),
        Some(CoreSetupPhase::Completed)
    );
}

// Proves the setup bootstrap writer is closed before resident service activation begins.
#[test]
fn setup_closes_identity_database_operation_before_services_apply() {
    let temporary = tempfile::tempdir().expect("temporary database root");
    let active = Arc::new(AtomicBool::new(false));
    let opens = Arc::new(AtomicUsize::new(0));
    let service_calls = Arc::new(AtomicUsize::new(0));
    let providers = Arc::new(Mutex::new(TestProviderState::default()));
    let store = Arc::new(TestStore::default());
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let setup = CoreSetup::new(
        Arc::new(TestLockProvider::default()),
        store.clone(),
        Arc::new(DatabaseCoreSetupIdentityProvider::with_database_provider(
            Arc::new(TrackingIdentityDatabaseProvider {
                database_file: temporary.path().join("core.sqlite3"),
                active: active.clone(),
                opens: opens.clone(),
            }),
            Arc::new(TrackingMachineIdentity),
            Arc::new(TrackingIdentityClock),
        )),
        Arc::new(TestMaterialProvider {
            state: providers.clone(),
        }),
        Arc::new(TestConfigurationProvider { state: providers }),
        Arc::new(ApplicationCoreSetupServiceProvider::with_application(
            Arc::new(DatabaseClosedServiceApplication {
                context,
                active: active.clone(),
                calls: service_calls.clone(),
            }),
        )),
    );
    let request = request(
        4,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );

    let result = setup.setup(&request).expect("setup");
    assert_eq!(result.status(), CoreSetupDisposition::Installed);
    assert!(!active.load(Ordering::SeqCst));
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    assert_eq!(service_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.phase(request.request_id()),
        Some(CoreSetupPhase::Completed)
    );
}

// Proves all four platform/role combinations produce the exact resident and exposure contract.
#[test]
fn setup_supports_every_standalone_main_platform_service_set() {
    for (index, platform, role, expected_services, has_public_endpoint) in [
        (
            1,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            json!(["li_node", "li_watchdog", "li_gateway"]),
            true,
        ),
        (
            3,
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
            json!(["li_node", "li_gateway"]),
            true,
        ),
    ] {
        let fixture = Fixture::new();
        let request = request(index, platform, role);
        let result = fixture.setup.setup(&request).expect("setup");
        let value: Value =
            serde_json::from_slice(&result.encoded_json().expect("JSON")).expect("result document");
        assert_eq!(value["services"], expected_services);
        assert_eq!(value["inference_endpoint"].is_string(), has_public_endpoint);
        assert_eq!(
            value["inference_endpoint"],
            json!("http://homeai.local:11434")
        );
        assert_eq!(value["api_key_file"].is_string(), has_public_endpoint);
        assert_eq!(value["role"], role_name(role));
        assert_eq!(result.status(), CoreSetupDisposition::Installed);
        assert_eq!(
            fixture
                .calls()
                .iter()
                .filter(|call| **call == "services.apply")
                .count(),
            1
        );
        assert_eq!(
            fixture.store.phase(request.request_id()),
            Some(CoreSetupPhase::Completed)
        );
    }
}

// Proves committed replay performs one health check and no native mutation.
#[test]
fn committed_setup_replays_without_native_mutation() {
    let fixture = Fixture::new();
    let request = request(
        5,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let installed = fixture.setup.setup(&request).expect("installed");
    let calls = fixture.calls();
    let replayed = fixture.setup.setup(&request).expect("replayed");
    assert_eq!(installed.status(), CoreSetupDisposition::Installed);
    assert_eq!(replayed.status(), CoreSetupDisposition::Replayed);
    let mut expected_calls = calls;
    expected_calls.push("services.apply");
    assert_eq!(fixture.calls(), expected_calls);
    assert_eq!(installed.display_name(), replayed.display_name());
    assert_eq!(
        installed.inference_endpoint(),
        replayed.inference_endpoint()
    );
}

// Proves unhealthy completed replay fails recovery-owned without reentering mutation providers.
#[test]
fn committed_replay_requires_fresh_resident_health() {
    let fixture = Fixture::new();
    let request = request(
        36,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    fixture.setup.setup(&request).expect("installed");
    let calls = fixture.calls();
    fixture.fail(FailurePoint::Verification);
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "resident services",
            ..
        })
    ));
    let additional = &fixture.calls()[calls.len()..];
    assert_eq!(additional, &["services.apply"]);
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::Completed)
    );
}

// Proves one idempotency key cannot replay a materially different setup request.
#[test]
fn setup_rejects_idempotency_conflict_before_provider_reentry() {
    let fixture = Fixture::new();
    let request = request(
        6,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    fixture.setup.setup(&request).expect("installed");
    let changed = CoreSetupRequest::new(
        request.request_id().clone(),
        request.context(),
        request.installation().clone(),
        DisplayName::parse("Different").expect("name"),
        request.control_address().clone(),
        request.network(),
    );
    let calls = fixture.calls();
    assert_eq!(
        fixture.setup.setup(&changed),
        Err(CoreSetupError::IdempotencyConflict)
    );
    assert_eq!(fixture.calls(), calls);
}

// Proves listener policy rejects implicit, colliding, and platform-incoherent ports before locking.
#[test]
fn setup_rejects_invalid_listener_plans_before_mutation() {
    let fixture = Fixture::new();
    let linux_main = request(
        7,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let linux_child = request(
        22,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Child,
    );
    let macos_main = request(
        23,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    for (ordinary, network) in [
        (
            &linux_main,
            CoreSetupNetworkPlan::new(
                address(0),
                address(9444),
                Some(address(11434)),
                Some(address(7443)),
            ),
        ),
        (
            &linux_main,
            CoreSetupNetworkPlan::new(
                address(9443),
                address(9443),
                Some(address(11434)),
                Some(address(7443)),
            ),
        ),
        (
            &linux_main,
            CoreSetupNetworkPlan::new(address(9443), address(9444), None, Some(address(7443))),
        ),
        (
            &linux_child,
            CoreSetupNetworkPlan::new(
                address(9443),
                address(9444),
                Some(address(11434)),
                Some(address(7443)),
            ),
        ),
        (
            &linux_main,
            CoreSetupNetworkPlan::new(address(9443), address(9444), Some(address(11434)), None),
        ),
        (
            &macos_main,
            CoreSetupNetworkPlan::new(
                address(9443),
                address(9444),
                Some(address(11434)),
                Some(address(7443)),
            ),
        ),
    ] {
        let invalid = CoreSetupRequest::new(
            ordinary.request_id().clone(),
            ordinary.context(),
            ordinary.installation().clone(),
            ordinary.display_name().clone(),
            ordinary.control_address().clone(),
            network,
        );
        assert!(matches!(
            fixture.setup.setup(&invalid),
            Err(CoreSetupError::InvalidContract { .. })
        ));
    }
    assert!(fixture.calls().is_empty());
}

// Proves setup accepts only canonical DNS names and routable IPv4 authorities.
#[test]
fn setup_accepts_url_authority_safe_control_addresses() {
    for (index, control_address) in [(41, "192.168.1.10"), (42, "homeai-node-2.local")] {
        let fixture = Fixture::new();
        let ordinary = request(
            index,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        );
        let request = CoreSetupRequest::new(
            ordinary.request_id().clone(),
            ordinary.context(),
            ordinary.installation().clone(),
            ordinary.display_name().clone(),
            NodeAddress::parse(control_address).expect("control address"),
            ordinary.network(),
        );
        let result = fixture.setup.setup(&request).expect("setup");
        assert_eq!(
            result.inference_endpoint(),
            Some(format!("http://{control_address}:11434").as_str())
        );
    }
}

// Proves unsafe control-address text is rejected before journal or provider mutation.
#[test]
fn setup_rejects_unsafe_control_addresses_before_mutation() {
    let fixture = Fixture::new();
    for (index, control_address) in [
        (50, "bad/path"),
        (51, "localhost"),
        (52, "2001:db8::1"),
        (53, "127.0.0.1"),
        (54, "0.0.0.0"),
        (55, "224.0.0.1"),
        (56, "HomeAI.local"),
    ] {
        let ordinary = request(
            index,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        );
        let request = CoreSetupRequest::new(
            ordinary.request_id().clone(),
            ordinary.context(),
            ordinary.installation().clone(),
            ordinary.display_name().clone(),
            NodeAddress::parse(control_address).expect("syntactic Node address"),
            ordinary.network(),
        );
        assert!(matches!(
            fixture.setup.setup(&request),
            Err(CoreSetupError::InvalidContract {
                reason: "setup control address must be a routable URL authority",
            })
        ));
        assert_eq!(fixture.store.phase(request.request_id()), None);
        assert!(fixture.calls().is_empty());
    }
}

// Proves identity failure retires the prepared journal without calling later providers.
#[test]
fn identity_failure_compensates_the_journal() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::Identity);
    let request = request(
        8,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "node identity",
            ..
        })
    ));
    assert_eq!(fixture.calls(), vec!["identity.prepare"]);
    assert_eq!(fixture.store.phase(request.request_id()), None);
}

// Proves a provider-returned identity mismatch is compensated before the journal retires.
#[test]
fn prepared_identity_mismatch_rolls_back_its_exact_receipt() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::IdentityMismatch);
    let request = request(
        31,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "node identity",
            ..
        })
    ));
    assert_eq!(
        fixture.calls(),
        vec!["identity.prepare", "identity.rollback"]
    );
    assert_eq!(fixture.store.phase(request.request_id()), None);
}

// Proves material failure rolls back identity before retiring the setup journal.
#[test]
fn material_failure_rolls_back_identity() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::Material);
    let request = request(
        9,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "private material",
            ..
        })
    ));
    assert_eq!(
        fixture.calls(),
        vec!["identity.prepare", "material.prepare", "identity.rollback"]
    );
    assert_eq!(fixture.store.phase(request.request_id()), None);
}

// Proves database, pairing, and API-key roles cannot alias one private material path.
#[test]
fn aliased_private_material_paths_are_compensated_before_configuration() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::MaterialAlias);
    let request = request(
        37,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "private material",
            reason: "private material paths must be distinct",
        })
    ));
    assert_eq!(
        fixture.calls(),
        vec![
            "identity.prepare",
            "material.prepare",
            "material.rollback",
            "identity.rollback",
        ]
    );
}

// Proves configuration failure compensates private material then identity in reverse order.
#[test]
fn configuration_failure_rolls_back_prior_phases_in_reverse_order() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::Configurations);
    let request = request(
        10,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "configurations",
            ..
        })
    ));
    assert_eq!(
        fixture.calls(),
        vec![
            "identity.prepare",
            "material.prepare",
            "configuration.install",
            "material.rollback",
            "identity.rollback",
        ]
    );
}

// Proves internally rolled-back service failure compensates every earlier reversible phase.
#[test]
fn service_failure_rolls_back_configuration_material_and_identity() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::Services);
    let request = request(
        11,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "resident services",
            ..
        })
    ));
    assert_eq!(
        &fixture.calls()[3..],
        &[
            "services.apply",
            "configuration.rollback",
            "material.rollback",
            "identity.rollback",
        ]
    );
}

// Proves ambiguous service mutation preserves prior state for explicit recovery.
#[test]
fn ambiguous_service_failure_never_claims_rollback() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::ServiceRecovery);
    let request = request(
        12,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "resident services",
            ..
        })
    ));
    assert!(!fixture
        .calls()
        .iter()
        .any(|call| call.ends_with("rollback")));
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::ConfigurationsInstalled)
    );
}

// Proves any reverse-order compensation failure escalates to recovery-required.
#[test]
fn rollback_failure_is_never_reported_as_successful_compensation() {
    for (index, point) in [
        (13, FailurePoint::ConfigurationRollback),
        (14, FailurePoint::MaterialRollback),
        (15, FailurePoint::IdentityRollback),
    ] {
        let fixture = Fixture::new();
        fixture.fail(FailurePoint::Services);
        let request = request(
            index,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        );
        fixture.fail(point);
        assert!(matches!(
            fixture.setup.setup(&request),
            Err(CoreSetupError::RecoveryRequired {
                capability: "setup rollback",
                ..
            })
        ));
        assert_eq!(
            &fixture.calls()[3..],
            &[
                "services.apply",
                "configuration.rollback",
                "material.rollback",
                "identity.rollback",
            ]
        );
        assert_eq!(
            fixture.store.phase(request.request_id()),
            Some(CoreSetupPhase::ConfigurationsInstalled)
        );
    }
}

// Proves journal failure after identity mutation rolls it back and retires incomplete state.
#[test]
fn reversible_journal_failure_compensates_the_completed_phase() {
    let fixture = Fixture::new();
    fixture
        .store
        .fail_replacement(CoreSetupPhase::IdentityPrepared);
    let request = request(
        16,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RolledBack {
            capability: "setup journal",
            ..
        })
    ));
    assert_eq!(
        fixture.calls(),
        vec!["identity.prepare", "identity.rollback"]
    );
    assert_eq!(fixture.store.phase(request.request_id()), None);
}

// Proves an impossible optimistic conflict preserves all state for explicit recovery.
#[test]
fn journal_revision_conflict_requires_recovery_without_compensation() {
    let fixture = Fixture::new();
    fixture.store.fail_replacement_with(
        CoreSetupPhase::IdentityPrepared,
        CoreSetupStoreError::Conflict,
    );
    let request = request(
        24,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "setup journal",
            ..
        })
    ));
    assert_eq!(fixture.calls(), vec!["identity.prepare"]);
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::Prepared)
    );
}

// Proves restart resumes idempotently from every durable incomplete pre-service phase.
#[test]
fn setup_resumes_from_every_durable_pre_service_phase() {
    for (index, failure, expected_phase) in [
        (25, FailurePoint::IdentityRecovery, CoreSetupPhase::Prepared),
        (
            26,
            FailurePoint::MaterialRecovery,
            CoreSetupPhase::IdentityPrepared,
        ),
        (
            27,
            FailurePoint::ConfigurationRecovery,
            CoreSetupPhase::MaterialPrepared,
        ),
        (
            28,
            FailurePoint::ServiceRecovery,
            CoreSetupPhase::ConfigurationsInstalled,
        ),
    ] {
        let fixture = Fixture::new();
        fixture.fail(failure);
        let request = request(
            index,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        );
        assert!(matches!(
            fixture.setup.setup(&request),
            Err(CoreSetupError::RecoveryRequired { .. })
        ));
        assert_eq!(
            fixture.store.phase(request.request_id()),
            Some(expected_phase)
        );
        let resumed = fixture.setup.setup(&request).expect("resumed setup");
        assert_eq!(resumed.status(), CoreSetupDisposition::Installed);
        assert_eq!(
            fixture.store.phase(request.request_id()),
            Some(CoreSetupPhase::Completed)
        );
    }
}

// Proves every resumed provider must reproduce its exact durable receipt and public closure.
#[test]
fn setup_rejects_provider_receipt_drift_at_every_replayed_phase() {
    for (index, first_failure, drift, phase, capability) in [
        (
            32,
            FailurePoint::MaterialRecovery,
            FailurePoint::IdentityDrift,
            CoreSetupPhase::IdentityPrepared,
            "node identity",
        ),
        (
            33,
            FailurePoint::ConfigurationRecovery,
            FailurePoint::MaterialDrift,
            CoreSetupPhase::MaterialPrepared,
            "private material",
        ),
        (
            34,
            FailurePoint::ServiceRecovery,
            FailurePoint::ConfigurationDrift,
            CoreSetupPhase::ConfigurationsInstalled,
            "configurations",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.fail(first_failure);
        let request = request(
            index,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        );
        assert!(matches!(
            fixture.setup.setup(&request),
            Err(CoreSetupError::RecoveryRequired { .. })
        ));
        fixture.fail(drift);
        assert!(matches!(
            fixture.setup.setup(&request),
            Err(CoreSetupError::RecoveryRequired {
                capability: observed,
                reason: "provider replay does not match its durable setup receipt",
            }) if observed == capability
        ));
        assert_eq!(fixture.store.phase(request.request_id()), Some(phase));
    }

    let fixture = Fixture::new();
    fixture.store.fail_replacement(CoreSetupPhase::Completed);
    let request = request(
        35,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired { .. })
    ));
    fixture.fail(FailurePoint::ServiceDrift);
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "resident services",
            reason: "provider replay does not match its durable setup receipt",
        })
    ));
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::ServicesInstalled)
    );
}

// Proves journal failure after service commit retains its exact crash-recovery boundary.
#[test]
fn service_journal_failure_requires_recovery_and_resumes_idempotently() {
    let fixture = Fixture::new();
    fixture
        .store
        .fail_replacement(CoreSetupPhase::ServicesInstalled);
    let request = request(
        17,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "setup journal",
            ..
        })
    ));
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::ConfigurationsInstalled)
    );
    let recovered = fixture.setup.setup(&request).expect("recovered setup");
    assert_eq!(recovered.status(), CoreSetupDisposition::Installed);
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::Completed)
    );
}

// Proves final journal ambiguity cannot turn semantically ready services into claimed success.
#[test]
fn completion_journal_failure_requires_recovery() {
    let fixture = Fixture::new();
    fixture.store.fail_replacement(CoreSetupPhase::Completed);
    let request = request(
        18,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "setup journal",
            ..
        })
    ));
    assert_eq!(
        fixture.store.phase(request.request_id()),
        Some(CoreSetupPhase::ServicesInstalled)
    );
    fixture.setup.setup(&request).expect("completion replay");
}

// Proves a store returning the wrong journal identity is corruption, not caller conflict.
#[test]
fn corrupted_journal_identity_fails_closed_before_provider_work() {
    let fixture = Fixture::new();
    let request = request(
        29,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    fixture.store.seed_under(
        request.request_id(),
        CoreSetupJournal::prepared(digest('f'), digest('a')),
    );
    assert_eq!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt))
    );
    assert!(fixture.calls().is_empty());
}

// Proves completed replay rejects wrong standalone-main endpoint and resident projections.
#[test]
fn corrupted_completed_result_fails_before_health_or_mutation() {
    for (index, role, field, replacement) in [
        (
            38,
            CoreUpdateNodeRole::Main,
            "inference_endpoint",
            json!(null),
        ),
        (
            39,
            CoreUpdateNodeRole::Main,
            "services",
            json!(["li_node", "li_gateway"]),
        ),
    ] {
        let fixture = Fixture::new();
        let request = request(index, CoreUpdateServicePlatform::Linux, role);
        let result = fixture.setup.setup(&request).expect("setup");
        let current = fixture.store.journal(request.request_id());
        let mut value: Value =
            serde_json::from_slice(&result.encoded_json().expect("JSON")).expect("document");
        value[field] = replacement;
        let corrupted = li_core_application::CoreSetupResult::decoded_json(
            &serde_json::to_vec(&value).expect("corrupted JSON"),
        )
        .expect("structurally decodable result");
        let restored = CoreSetupJournal::restored(
            current.request_id().clone(),
            current.request_identity().clone(),
            CoreSetupPhase::Completed,
            current.identity().cloned(),
            current.material().cloned(),
            current.configurations().cloned(),
            current.services().cloned(),
            Some(corrupted),
        )
        .expect("structural journal");
        fixture.store.seed_under(request.request_id(), restored);
        let call_count = fixture.calls().len();
        assert_eq!(
            fixture.setup.setup(&request),
            Err(CoreSetupError::Store(CoreSetupStoreError::Corrupt))
        );
        assert_eq!(fixture.calls().len(), call_count);
    }
}

// Proves compensated native state whose journal cannot retire remains recovery-owned.
#[test]
fn compensated_journal_removal_failure_requires_recovery() {
    let fixture = Fixture::new();
    fixture.fail(FailurePoint::Material);
    fixture.store.fail_remove();
    let request = request(
        19,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    assert!(matches!(
        fixture.setup.setup(&request),
        Err(CoreSetupError::RecoveryRequired {
            capability: "setup journal",
            ..
        })
    ));
}

// Proves a concurrent invocation cannot enter journal or provider mutation while setup owns lock.
#[test]
fn concurrent_setup_has_one_mutation_owner() {
    let fixture = Fixture::new();
    let entered_barrier = Arc::new(Barrier::new(2));
    let release_barrier = Arc::new(Barrier::new(2));
    {
        let mut providers = fixture.providers.lock().expect("providers");
        providers.entered_barrier = Some(entered_barrier.clone());
        providers.release_barrier = Some(release_barrier.clone());
    }
    let request = request(
        20,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let setup = fixture.setup.clone();
    let first_request = request.clone();
    let first = thread::spawn(move || setup.setup(&first_request));
    entered_barrier.wait();
    assert_eq!(fixture.setup.setup(&request), Err(CoreSetupError::Busy));
    release_barrier.wait();
    {
        let mut providers = fixture.providers.lock().expect("providers");
        providers.entered_barrier = None;
        providers.release_barrier = None;
    }
    assert!(first.join().expect("first invocation").is_ok());
}

// Proves output is closed, installer-compatible, nested-schema JSON with no plaintext token.
#[test]
fn setup_result_schema_and_secret_boundary_are_exact() {
    let fixture = Fixture::new();
    let request = request(
        21,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let result = fixture.setup.setup(&request).expect("setup");
    let bytes = result.encoded_json().expect("JSON");
    assert!(bytes.len() <= MAXIMUM_CORE_SETUP_RESULT_BYTES);
    let text = String::from_utf8(bytes.clone()).expect("UTF-8");
    assert!(!text.contains("li_deadbeef_plaintext-token"));
    let value: Value = serde_json::from_slice(&bytes).expect("document");
    assert_eq!(value["schema"]["name"], CORE_SETUP_RESULT_SCHEMA_NAME);
    assert_eq!(value["schema"]["version"], CORE_SETUP_RESULT_SCHEMA_VERSION);
    assert_eq!(value["display_name"], "Home AI");
    assert_eq!(value["role"], "main");
    assert!(value["api_key_file"].is_string());
    assert!(value["inference_endpoint"].is_string());
    let expected = [
        "api_key_file",
        "control_address",
        "display_name",
        "inference_endpoint",
        "installation_id",
        "machine_id",
        "node_id",
        "role",
        "schema",
        "services",
        "status",
    ];
    let mut keys = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, expected);
}

// Proves the distributed schema retains exact identity, closure, and role constraints.
#[test]
fn distributed_setup_result_schema_matches_the_producer() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_result_v1.schema.json"
    ))
    .expect("schema");
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        CORE_SETUP_RESULT_SCHEMA_NAME
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        CORE_SETUP_RESULT_SCHEMA_VERSION
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["role"]["enum"],
        json!(["main", "child"])
    );
    assert_eq!(
        schema["properties"]["services"]["items"]["enum"],
        json!(["li_node", "li_gateway", "li_watchdog"])
    );

    let fixture = Fixture::new();
    let request = request(
        30,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let result = fixture.setup.setup(&request).expect("setup");
    let value: Value =
        serde_json::from_slice(&result.encoded_json().expect("JSON")).expect("document");
    assert!(matches_committed_schema(&schema, &value));

    let mut mutations = Vec::new();
    let mut missing = value.clone();
    missing.as_object_mut().expect("object").remove("node_id");
    mutations.push(missing);
    let mut additional = value.clone();
    additional["token"] = json!("li_deadbeef_plaintext-token");
    mutations.push(additional);
    let mut version = value.clone();
    version["schema"]["version"] = json!(2);
    mutations.push(version);
    let mut main_without_key = value.clone();
    main_without_key["api_key_file"] = Value::Null;
    mutations.push(main_without_key);
    let mut main_without_endpoint = value.clone();
    main_without_endpoint["inference_endpoint"] = Value::Null;
    mutations.push(main_without_endpoint);
    let mut main_with_https_endpoint = value.clone();
    main_with_https_endpoint["inference_endpoint"] = json!("https://homeai.local:11434");
    mutations.push(main_with_https_endpoint);
    let mut service_order = value.clone();
    service_order["services"] = json!(["li_node", "li_gateway", "li_watchdog"]);
    mutations.push(service_order);
    let mut child_with_exposure = value;
    child_with_exposure["role"] = json!("child");
    mutations.push(child_with_exposure);
    for mutation in mutations {
        assert!(!matches_committed_schema(&schema, &mutation));
    }
}

// Proves the production service adapter delegates one authoritative cutover invocation.
#[test]
fn application_service_adapter_preserves_context_and_receipt() {
    let request = request(
        40,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Child,
    );
    let application = Arc::new(TestServiceApplication::new(request.context()));
    let provider = ApplicationCoreSetupServiceProvider::with_application(application.clone());
    let identity = prepared_identity(&request);
    let material = prepared_material(&request);
    let services = provider
        .apply(&request, &identity, &material)
        .expect("service application");
    assert_eq!(services.receipt().identity(), &digest('5'));
    assert_eq!(application.calls(), 1);
}

// Proves the production service adapter rejects foreign platform or role before native work.
#[test]
fn application_service_adapter_rejects_context_drift() {
    let request = request(
        41,
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    let application = Arc::new(TestServiceApplication::new(CoreUpdateServiceContext::new(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    )));
    let provider = ApplicationCoreSetupServiceProvider::with_application(application.clone());
    assert!(matches!(
        provider.apply(
            &request,
            &prepared_identity(&request),
            &prepared_material(&request),
        ),
        Err(CoreSetupProviderError::Unchanged {
            capability: "resident services",
            ..
        })
    ));
    assert_eq!(application.calls(), 0);
}

// Proves the service adapter never weakens native rollback or recovery classification.
#[test]
fn application_service_adapter_preserves_failure_classification() {
    let request = request(
        42,
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
    );
    for (error, expected) in [
        (
            CoreServiceSetupError::InvalidContract {
                reason: "invalid service contract",
            },
            "unchanged",
        ),
        (
            CoreServiceSetupError::Provider {
                capability: "native service",
                reason: "native boundary failed",
            },
            "recovery",
        ),
        (
            CoreServiceSetupError::RolledBack {
                reason: "native service rolled back",
            },
            "rolled_back",
        ),
        (
            CoreServiceSetupError::RecoveryRequired {
                reason: "native recovery required",
            },
            "recovery",
        ),
    ] {
        let application = Arc::new(TestServiceApplication::failing(request.context(), error));
        let provider = ApplicationCoreSetupServiceProvider::with_application(application);
        let observed = provider
            .apply(
                &request,
                &prepared_identity(&request),
                &prepared_material(&request),
            )
            .expect_err("classified failure");
        let classification = match observed {
            CoreSetupProviderError::Unchanged { .. } => "unchanged",
            CoreSetupProviderError::RolledBack { .. } => "rolled_back",
            CoreSetupProviderError::RecoveryRequired { .. } => "recovery",
        };
        assert_eq!(classification, expected);
    }
}

// Applies the committed setup-result schema's closed structural and cross-field constraints.
fn matches_committed_schema(schema: &Value, document: &Value) -> bool {
    let Some(object) = document.as_object() else {
        return false;
    };
    let Some(required) = schema["required"].as_array() else {
        return false;
    };
    let required = required
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if object.len() != required.len() || required.iter().any(|name| !object.contains_key(*name)) {
        return false;
    }
    if document["schema"]["name"] != schema["properties"]["schema"]["properties"]["name"]["const"]
        || document["schema"]["version"]
            != schema["properties"]["schema"]["properties"]["version"]["const"]
    {
        return false;
    }
    let is_identity = |value: &Value, length: usize| {
        value.as_str().is_some_and(|text| {
            text.len() == length
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    };
    if !is_identity(&document["node_id"], 32)
        || !is_identity(&document["machine_id"], 32)
        || !is_identity(&document["installation_id"], 64)
    {
        return false;
    }
    let valid_name = document["display_name"].as_str().is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 128
            && !value.chars().any(|character| character.is_control())
    });
    let valid_control = document["control_address"].as_str().is_some_and(|value| {
        !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_whitespace)
    });
    if !valid_name || !valid_control {
        return false;
    }
    let Some(role) = document["role"].as_str() else {
        return false;
    };
    if !schema["properties"]["role"]["enum"]
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value == role))
    {
        return false;
    }
    let key = document["api_key_file"].as_str();
    let endpoint = document["inference_endpoint"].as_str();
    let role_shape = match role {
        "main" => {
            key.is_some_and(valid_absolute_path)
                && endpoint.is_some_and(|value| value.starts_with("http://"))
        }
        "child" => document["api_key_file"].is_null() && document["inference_endpoint"].is_null(),
        _ => false,
    };
    if !role_shape {
        return false;
    }
    let Some(services) = document["services"].as_array() else {
        return false;
    };
    services
        == &json!(["li_node", "li_watchdog", "li_gateway"])
            .as_array()
            .expect("Linux services")
            .clone()
        || services
            == &json!(["li_node", "li_gateway"])
                .as_array()
                .expect("macOS services")
                .clone()
}

// Returns whether one output path satisfies the committed absolute-path boundary.
fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() >= 2
        && value.len() <= 4096
        && !value.contains('\0')
        && !value.split('/').any(|component| component == "..")
}

// Creates the exact public identity returned by the deterministic identity provider.
fn prepared_identity(request: &CoreSetupRequest) -> CoreSetupPreparedIdentity {
    CoreSetupPreparedIdentity::new(
        receipt('1'),
        NodeId::parse(&identity('a', 32)).expect("node"),
        MachineId::parse(&identity('b', 32)).expect("machine"),
        InstallationId::parse(&identity('c', 64)).expect("installation"),
        request.display_name().clone(),
        match request.context().role() {
            CoreUpdateNodeRole::Main => NodeRole::Main,
            CoreUpdateNodeRole::Child => NodeRole::Child,
        },
        request.control_address().clone(),
    )
}

// Creates the exact secret-free private material projection used by adapter tests.
fn prepared_material(request: &CoreSetupRequest) -> CoreSetupPreparedMaterial {
    CoreSetupPreparedMaterial::new_with_benchmark_signing(
        receipt('2'),
        "/var/lib/letsinfer/li_core.sqlite3".into(),
        "/var/lib/letsinfer/pairing.key".into(),
        (request.context().role() == CoreUpdateNodeRole::Main)
            .then(|| "/var/lib/letsinfer/api.key".into()),
        benchmark_signing_material(),
        pairing_trust_material(),
        node_trust_material(),
        gateway_trust_material(),
        (request.context().platform() == CoreUpdateServicePlatform::Linux)
            .then(watchdog_trust_material),
        digest('d'),
    )
}

// Builds one complete reversible journal stopped immediately before resident services.
fn recoverable_journal(request: &CoreSetupRequest) -> CoreSetupJournal {
    let identity = prepared_identity(request);
    let material = prepared_material(request);
    CoreSetupJournal::restored(
        request.request_id().clone(),
        digest('f'),
        CoreSetupPhase::ConfigurationsInstalled,
        Some(identity),
        Some(material),
        Some(CoreSetupInstalledConfigurations::new(receipt('3'))),
        None,
        None,
    )
    .expect("recoverable journal")
}

// Returns one exact secret-free dedicated benchmark-signing projection.
fn benchmark_signing_material() -> li_core_application::CoreSetupBenchmarkSigningMaterial {
    li_core_application::CoreSetupBenchmarkSigningMaterial::new(
        "/var/lib/letsinfer/trust/benchmark-signing.key".into(),
        "/var/lib/letsinfer/trust/benchmark-signing.pub".into(),
        digest('9'),
    )
}

// Returns one exact secret-free pairing trust projection for setup tests.
fn pairing_trust_material() -> li_core_application::CoreSetupPairingTrustMaterial {
    li_core_application::CoreSetupPairingTrustMaterial::new(
        "/var/lib/letsinfer/trust/site.key".into(),
        "/var/lib/letsinfer/trust/site.pub".into(),
        "/var/lib/letsinfer/trust/site-ca.crt".into(),
        "/var/lib/letsinfer/trust/node.crt".into(),
        digest('a'),
        digest('b'),
    )
}

// Returns one exact secret-free Node remote trust projection for setup tests.
fn node_trust_material() -> li_core_application::CoreSetupNodeTrustMaterial {
    li_core_application::CoreSetupNodeTrustMaterial::new(
        "/var/lib/letsinfer/trust/node-ca.key".into(),
        "/var/lib/letsinfer/trust/node-ca.crt".into(),
        "/var/lib/letsinfer/trust/node-server.crt".into(),
        "/var/lib/letsinfer/trust/node-server.key".into(),
        "/var/lib/letsinfer/trust/node-client.crt".into(),
        "/var/lib/letsinfer/trust/node-client.key".into(),
        digest('c'),
        digest('d'),
    )
}

// Returns one exact secret-free Gateway private-relay trust projection for setup tests.
fn gateway_trust_material() -> li_core_application::CoreSetupGatewayTrustMaterial {
    li_core_application::CoreSetupGatewayTrustMaterial::new(
        "/var/lib/letsinfer/trust/gateway-ca.key".into(),
        "/var/lib/letsinfer/trust/gateway-ca.crt".into(),
        "/var/lib/letsinfer/trust/gateway-server.crt".into(),
        "/var/lib/letsinfer/trust/gateway-server.key".into(),
        "/var/lib/letsinfer/trust/gateway-client.crt".into(),
        "/var/lib/letsinfer/trust/gateway-client.key".into(),
        digest('e'),
        digest('f'),
    )
}

// Returns one exact Linux Watchdog and Core-health trust projection for setup tests.
fn watchdog_trust_material() -> li_core_application::CoreSetupWatchdogTrustMaterial {
    li_core_application::CoreSetupWatchdogTrustMaterial::new(
        "/var/lib/letsinfer/trust/watchdog-ca.key".into(),
        "/var/lib/letsinfer/trust/watchdog-ca.crt".into(),
        "/var/lib/letsinfer/trust/watchdog-server.crt".into(),
        "/var/lib/letsinfer/trust/watchdog-server.key".into(),
        "/var/lib/letsinfer/trust/watchdog-controller.crt".into(),
        "/var/lib/letsinfer/trust/watchdog-controller.key".into(),
        "/var/lib/letsinfer/trust/watchdog-controllers.allow".into(),
        digest('1'),
        digest('2'),
    )
}

// Creates one exact request with ports determined entirely by test input.
fn request(
    index: u8,
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
) -> CoreSetupRequest {
    let request_character = char::from_digit(u32::from(index % 10), 10).unwrap_or('0');
    let public = (role == CoreUpdateNodeRole::Main).then(|| address(11434));
    let watchdog = (platform == CoreUpdateServicePlatform::Linux).then(|| address(7443));
    CoreSetupRequest::new(
        digest(request_character),
        CoreUpdateServiceContext::new(platform, role),
        CoreInstallation::new(
            CoreVersion::parse("0.12.0-rc.1").expect("version"),
            digest('e'),
        ),
        DisplayName::parse("Home AI").expect("display name"),
        NodeAddress::parse("homeai.local").expect("address"),
        CoreSetupNetworkPlan::new(address(9443), address(9444), public, watchdog),
    )
}

// Creates one loopback listener address with an explicitly supplied port.
const fn address(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

// Creates one canonical hexadecimal identity fixture.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Creates one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Creates one opaque provider receipt fixture.
fn receipt(character: char) -> CoreSetupReceipt {
    CoreSetupReceipt::new(digest(character))
}

// Returns the stable role spelling expected at the JSON boundary.
const fn role_name(role: CoreUpdateNodeRole) -> &'static str {
    match role {
        CoreUpdateNodeRole::Main => "main",
        CoreUpdateNodeRole::Child => "child",
    }
}
