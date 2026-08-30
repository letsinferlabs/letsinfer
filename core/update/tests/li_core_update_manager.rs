// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    ActivatedCoreUpdate, CoreInstallation, CoreUpdateAdmissionLease, CoreUpdateAdmissionProvider,
    CoreUpdateArtifactProvider, CoreUpdateDisposition, CoreUpdateError, CoreUpdateEvent,
    CoreUpdateManager, CoreUpdateNodeRole, CoreUpdatePhase, CoreUpdatePruneProvider,
    CoreUpdateReadinessClock, CoreUpdateReadinessPolicy, CoreUpdateRecord,
    CoreUpdateResidentService, CoreUpdateServiceContext, CoreUpdateServiceMode,
    CoreUpdateServicePlatform, CoreUpdateServiceProvider, CoreUpdateServiceSnapshotRecord,
    CoreUpdateServiceState, CoreUpdateStore, CoreUpdateStoreError, CoreVersion, PreparedCoreUpdate,
    SystemCoreUpdateReadinessClock, VersionedCoreUpdateRecord,
};
use sha2::{Digest, Sha256};

// Stores deterministic provider failures by exact capability name.
#[derive(Default)]
struct FailurePlan(Mutex<BTreeMap<&'static str, usize>>);

impl FailurePlan {
    // Schedules one capability to fail the requested number of times.
    fn fail(&self, capability: &'static str, count: usize) {
        self.0
            .lock()
            .expect("failure plan")
            .insert(capability, count);
    }

    // Returns one redacted failure while the scheduled count remains positive.
    fn check(&self, capability: &'static str) -> Result<(), CoreUpdateError> {
        let mut failures = self.0.lock().expect("failure plan");
        let Some(remaining) = failures.get_mut(capability) else {
            return Ok(());
        };
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(CoreUpdateError::provider(capability, "mock failure"))
    }
}

// Stores complete optimistic journals for deterministic manager tests.
#[derive(Default)]
struct MemoryStore {
    records: Mutex<HashMap<String, (CoreUpdateRecord, u64)>>,
    replace_calls: AtomicUsize,
    fail_replace_call: Mutex<Option<usize>>,
    fail_after_replace_call: Mutex<Option<usize>>,
    response_tamper: AtomicUsize,
}

const TAMPER_READ_ZERO_REVISION: usize = 1;
const TAMPER_CREATE_FOREIGN_RECORD: usize = 2;
const TAMPER_REPLACE_RECORD: usize = 3;
const TAMPER_REPLACE_REVISION: usize = 4;

impl MemoryStore {
    // Schedules one exact replacement call to fail once.
    fn fail_replace_call(&self, call: usize) {
        *self.fail_replace_call.lock().expect("failure call") = Some(call);
    }

    // Schedules one exact replacement to commit before reporting an unavailable result.
    fn fail_after_replace_call(&self, call: usize) {
        *self
            .fail_after_replace_call
            .lock()
            .expect("postcommit failure call") = Some(call);
    }
}

impl CoreUpdateStore for MemoryStore {
    // Returns one cloned journal snapshot by replay identity.
    fn read(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VersionedCoreUpdateRecord>, CoreUpdateStoreError> {
        let stored = self
            .records
            .lock()
            .map_err(|_| CoreUpdateStoreError::Unavailable)?
            .get(idempotency_key)
            .map(|(record, revision)| VersionedCoreUpdateRecord::new(record.clone(), *revision));
        Ok(stored.map(|stored| {
            if self.response_tamper.load(Ordering::SeqCst) == TAMPER_READ_ZERO_REVISION {
                VersionedCoreUpdateRecord::new(stored.record().clone(), 0)
            } else {
                stored
            }
        }))
    }

    // Creates one revision-one journal exactly once.
    fn create(
        &self,
        record: CoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| CoreUpdateStoreError::Unavailable)?;
        if records.contains_key(record.idempotency_key()) {
            return Err(CoreUpdateStoreError::Conflict);
        }
        records.insert(record.idempotency_key().to_string(), (record.clone(), 1));
        if self.response_tamper.load(Ordering::SeqCst) == TAMPER_CREATE_FOREIGN_RECORD {
            Ok(VersionedCoreUpdateRecord::new(
                requested_record("foreign-update", None),
                1,
            ))
        } else {
            Ok(VersionedCoreUpdateRecord::new(record, 1))
        }
    }

    // Replaces one exact optimistic revision and increments it once.
    fn replace(
        &self,
        record: CoreUpdateRecord,
        expected_revision: u64,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateStoreError> {
        let call = self.replace_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mut failure = self
            .fail_replace_call
            .lock()
            .map_err(|_| CoreUpdateStoreError::Unavailable)?;
        if failure.is_some_and(|expected| expected == call) {
            *failure = None;
            return Err(CoreUpdateStoreError::Unavailable);
        }
        drop(failure);
        let mut records = self
            .records
            .lock()
            .map_err(|_| CoreUpdateStoreError::Unavailable)?;
        let stored = records
            .get_mut(record.idempotency_key())
            .ok_or(CoreUpdateStoreError::Corrupt)?;
        if stored.1 != expected_revision {
            return Err(CoreUpdateStoreError::Conflict);
        }
        stored.0 = record.clone();
        stored.1 += 1;
        let revision = stored.1;
        let mut postcommit_failure_call = self
            .fail_after_replace_call
            .lock()
            .map_err(|_| CoreUpdateStoreError::Unavailable)?;
        let postcommit_failure = postcommit_failure_call.is_some_and(|expected| expected == call);
        if postcommit_failure {
            *postcommit_failure_call = None;
        }
        drop(postcommit_failure_call);
        if postcommit_failure {
            return Err(CoreUpdateStoreError::Unavailable);
        }
        match self.response_tamper.load(Ordering::SeqCst) {
            TAMPER_REPLACE_RECORD => Ok(VersionedCoreUpdateRecord::new(
                requested_record(
                    record.idempotency_key(),
                    record.requested_version().map(CoreVersion::as_str),
                ),
                revision,
            )),
            TAMPER_REPLACE_REVISION => {
                Ok(VersionedCoreUpdateRecord::new(record, expected_revision))
            }
            _ => Ok(VersionedCoreUpdateRecord::new(record, revision)),
        }
    }
}

// Authorizes updates through one injected deterministic admission boundary.
struct AdmissionMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
}

// Holds one deterministic update admission until the manager call returns.
struct AdmissionLease;

impl CoreUpdateAdmissionLease for AdmissionLease {}

// Records when one global admission lease releases after all provider work.
struct TrackingAdmissionLease {
    events: Arc<Mutex<Vec<String>>>,
}

impl CoreUpdateAdmissionLease for TrackingAdmissionLease {}

impl Drop for TrackingAdmissionLease {
    // Records lease release only after its complete manager call leaves mutation scope.
    fn drop(&mut self) {
        record_event(&self.events, "admission.release");
    }
}

// Acquires one observable global lease for exact lifetime assertions.
struct TrackingAdmission {
    events: Arc<Mutex<Vec<String>>>,
}

impl CoreUpdateAdmissionProvider for TrackingAdmission {
    // Records acquisition and returns one lease owning the same event stream.
    fn acquire(
        &self,
        _update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
        record_event(&self.events, "admission");
        Ok(Box::new(TrackingAdmissionLease {
            events: self.events.clone(),
        }))
    }
}

impl CoreUpdateAdmissionProvider for AdmissionMock {
    // Records and acquires one deterministic update admission lease.
    fn acquire(
        &self,
        _update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
        record_event(&self.events, "admission");
        self.failures.check("admission")?;
        Ok(Box::new(AdmissionLease))
    }
}

// Owns deterministic immutable release preparation and active-pointer state.
struct ArtifactMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    initial: CoreInstallation,
    active: Mutex<CoreInstallation>,
    candidate: CoreInstallation,
    mismatch_activation: AtomicBool,
}

impl ArtifactMock {
    // Enables one deliberately inconsistent activation receipt.
    fn mismatch_activation(&self) {
        self.mismatch_activation.store(true, Ordering::SeqCst);
    }
}

impl CoreUpdateArtifactProvider for ArtifactMock {
    // Returns the current immutable installation from mock active-pointer state.
    fn current(&self, _update_id: &Sha256Digest) -> Result<CoreInstallation, CoreUpdateError> {
        record_event(&self.events, "artifact.current");
        self.failures.check("artifact.current")?;
        Ok(self.active.lock().expect("active Core").clone())
    }

    // Returns one deterministic verified candidate receipt.
    fn prepare(
        &self,
        _update_id: &Sha256Digest,
        _requested_version: Option<&CoreVersion>,
        _current: &CoreInstallation,
    ) -> Result<PreparedCoreUpdate, CoreUpdateError> {
        record_event(&self.events, "artifact.prepare");
        self.failures.check("artifact.prepare")?;
        Ok(PreparedCoreUpdate::new(digest('a'), self.candidate.clone()))
    }

    // Discards one prepared workspace without changing the active installation.
    fn discard(
        &self,
        _update_id: &Sha256Digest,
        _prepared: &PreparedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        record_event(&self.events, "artifact.discard");
        self.failures.check("artifact.discard")
    }

    // Activates the candidate idempotently and returns one exact handoff receipt.
    fn activate(
        &self,
        _update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
        current: &CoreInstallation,
    ) -> Result<ActivatedCoreUpdate, CoreUpdateError> {
        record_event(&self.events, "artifact.activate");
        self.failures.check("artifact.activate")?;
        *self.active.lock().expect("active Core") = prepared.installation().clone();
        let previous = if self.mismatch_activation.load(Ordering::SeqCst) {
            installation("9.9.9", '9')
        } else {
            current.clone()
        };
        ActivatedCoreUpdate::new(digest('b'), previous, prepared.installation().clone())
    }

    // Restores the initial active installation for any exact test activation.
    fn rollback(
        &self,
        _update_id: &Sha256Digest,
        _activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        record_event(&self.events, "artifact.rollback");
        self.failures.check("artifact.rollback")?;
        *self.active.lock().expect("active Core") = self.initial.clone();
        Ok(())
    }

    // Commits one verified active pointer without changing its identity.
    fn commit(
        &self,
        _update_id: &Sha256Digest,
        _activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        record_event(&self.events, "artifact.commit");
        self.failures.check("artifact.commit")
    }
}

// Supplies deterministic monotonic observations and exact wait-fault injection.
struct ClockMock {
    milliseconds: AtomicU64,
    observations: Mutex<VecDeque<Result<u64, CoreUpdateError>>>,
    waits: Mutex<Vec<u64>>,
    advance_after_wait: AtomicBool,
    fail_wait: AtomicBool,
}

impl ClockMock {
    // Creates one clock that advances only through manager-requested waits.
    fn new() -> Self {
        Self {
            milliseconds: AtomicU64::new(0),
            observations: Mutex::new(VecDeque::new()),
            waits: Mutex::new(Vec::new()),
            advance_after_wait: AtomicBool::new(true),
            fail_wait: AtomicBool::new(false),
        }
    }
}

impl CoreUpdateReadinessClock for ClockMock {
    // Returns one scripted or current monotonic millisecond observation.
    fn monotonic_milliseconds(&self) -> Result<u64, CoreUpdateError> {
        self.observations
            .lock()
            .expect("clock observations")
            .pop_front()
            .unwrap_or_else(|| Ok(self.milliseconds.load(Ordering::SeqCst)))
    }

    // Records one wait and advances time unless a deterministic clock fault is active.
    fn wait(&self, milliseconds: u64) -> Result<(), CoreUpdateError> {
        self.waits.lock().expect("clock waits").push(milliseconds);
        if self.fail_wait.swap(false, Ordering::SeqCst) {
            return Err(CoreUpdateError::provider(
                "readiness clock",
                "mock wait failure",
            ));
        }
        if self.advance_after_wait.load(Ordering::SeqCst) {
            self.milliseconds.fetch_add(milliseconds, Ordering::SeqCst);
        }
        Ok(())
    }
}

// Returns native service facts and applies only manager-selected mutations or receipts.
struct ServiceMock {
    context: CoreUpdateServiceContext,
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    clock: Arc<ClockMock>,
    states: Mutex<BTreeMap<CoreUpdateResidentService, CoreUpdateServiceState>>,
    snapshots: Mutex<BTreeMap<String, CoreUpdateServiceSnapshotRecord>>,
    store_result: Mutex<Option<CoreUpdateServiceSnapshotRecord>>,
    readiness: Mutex<VecDeque<bool>>,
    ready: AtomicBool,
    readiness_elapsed_milliseconds: AtomicU64,
    readiness_timeouts: Mutex<Vec<Duration>>,
    rebinds: Mutex<Vec<(CoreUpdateResidentService, CoreUpdateServiceMode)>>,
    readiness_calls: Mutex<Vec<(CoreUpdateResidentService, CoreUpdateServiceMode)>>,
    restores: Mutex<Vec<(CoreUpdateResidentService, CoreInstallation)>>,
}

impl ServiceMock {
    // Creates one complete native service fixture without embedding product policy.
    fn new(
        context: CoreUpdateServiceContext,
        current: &CoreInstallation,
        events: Arc<Mutex<Vec<String>>>,
        failures: Arc<FailurePlan>,
        clock: Arc<ClockMock>,
    ) -> Self {
        Self {
            context,
            events,
            failures,
            clock,
            states: Mutex::new(service_states(context, current.source_identity())),
            snapshots: Mutex::new(BTreeMap::new()),
            store_result: Mutex::new(None),
            readiness: Mutex::new(VecDeque::new()),
            ready: AtomicBool::new(true),
            readiness_elapsed_milliseconds: AtomicU64::new(0),
            readiness_timeouts: Mutex::new(Vec::new()),
            rebinds: Mutex::new(Vec::new()),
            readiness_calls: Mutex::new(Vec::new()),
            restores: Mutex::new(Vec::new()),
        }
    }
}

impl CoreUpdateServiceProvider for ServiceMock {
    // Returns the immutable native platform and role facts.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError> {
        self.failures.check("service.context")?;
        Ok(self.context)
    }

    // Returns one exact durable native-state receipt by update identity.
    fn snapshot_record(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError> {
        self.failures.check("service.snapshot.read")?;
        Ok(self
            .snapshots
            .lock()
            .expect("service snapshots")
            .get(update_id.as_str())
            .cloned())
    }

    // Stores one native-state receipt exactly once without judging its contents.
    fn store_snapshot_record(
        &self,
        snapshot: CoreUpdateServiceSnapshotRecord,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
        record_event(&self.events, "service.snapshot");
        self.failures.check("service.snapshot")?;
        if let Some(stored) = self.store_result.lock().expect("store result").take() {
            return Ok(stored);
        }
        let mut snapshots = self.snapshots.lock().expect("service snapshots");
        if let Some(existing) = snapshots.get(snapshot.update_id().as_str()) {
            return Ok(existing.clone());
        }
        snapshots.insert(snapshot.update_id().as_str().to_string(), snapshot.clone());
        Ok(snapshot)
    }

    // Returns one exact native service observation selected by the manager.
    fn observe_service(
        &self,
        service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        self.failures.check("service.observe")?;
        self.states
            .lock()
            .expect("service states")
            .get(&service)
            .cloned()
            .ok_or_else(|| CoreUpdateError::provider("service observation", "service is absent"))
    }

    // Applies one manager-selected binding and records its exact service and mode.
    fn rebind_service(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: &CoreInstallation,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        if service == CoreUpdateResidentService::Node {
            record_event(&self.events, "service.rebind");
        }
        self.rebinds
            .lock()
            .expect("service rebinds")
            .push((service, mode));
        self.failures.check("service.rebind")?;
        let identity = installation.source_identity().clone();
        self.states.lock().expect("service states").insert(
            service,
            CoreUpdateServiceState::new(
                service,
                Some(identity.clone()),
                active.then_some(identity),
            )?,
        );
        Ok(())
    }

    // Returns one exact native readiness fact within the supplied manager deadline.
    fn service_is_ready_with_timeout(
        &self,
        service: CoreUpdateResidentService,
        mode: CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        if service == CoreUpdateResidentService::Node {
            record_event(&self.events, "service.verify");
        }
        self.readiness_timeouts
            .lock()
            .expect("readiness timeouts")
            .push(timeout);
        self.readiness_calls
            .lock()
            .expect("readiness calls")
            .push((service, mode));
        self.failures.check("service.verify")?;
        self.clock.milliseconds.fetch_add(
            self.readiness_elapsed_milliseconds.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        let ready = self
            .readiness
            .lock()
            .expect("readiness sequence")
            .pop_front()
            .unwrap_or_else(|| self.ready.load(Ordering::SeqCst));
        let expected = installation.map(CoreInstallation::source_identity);
        let observed = self
            .states
            .lock()
            .expect("service states")
            .get(&service)
            .cloned()
            .ok_or_else(|| CoreUpdateError::provider("service readiness", "service is absent"))?;
        Ok(ready
            && observed.loaded_identity() == expected
            && observed.active_identity() == active.then_some(expected).flatten())
    }

    // Applies one exact prior state without deciding whether restoration is complete.
    fn restore_service(
        &self,
        state: &CoreUpdateServiceState,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        if state.service() == CoreUpdateResidentService::Node {
            record_event(&self.events, "service.restore");
        }
        self.restores
            .lock()
            .expect("service restores")
            .push((state.service(), installation.clone()));
        self.failures.check("service.restore")?;
        self.states
            .lock()
            .expect("service states")
            .insert(state.service(), state.clone());
        Ok(())
    }
}

// Owns deterministic post-commit pruning.
struct PruneMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
}

impl CoreUpdatePruneProvider for PruneMock {
    // Records one exact unreferenced-identity prune.
    fn prune(
        &self,
        _update_id: &Sha256Digest,
        _active: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        record_event(&self.events, "prune");
        self.failures.check("prune")
    }
}

// Groups one manager with its deterministic observable test capabilities.
struct TestEnvironment {
    manager: CoreUpdateManager,
    store: Arc<MemoryStore>,
    failures: Arc<FailurePlan>,
    events: Arc<Mutex<Vec<String>>>,
    artifacts: Arc<ArtifactMock>,
    services: Arc<ServiceMock>,
    clock: Arc<ClockMock>,
}

// Creates one complete deterministic manager composition.
fn environment(current: CoreInstallation, candidate: CoreInstallation) -> TestEnvironment {
    environment_with_policy(
        current,
        candidate,
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    )
}

// Creates one manager composition with explicit platform, role, and readiness policy.
fn environment_with_policy(
    current: CoreInstallation,
    candidate: CoreInstallation,
    context: CoreUpdateServiceContext,
    readiness: CoreUpdateReadinessPolicy,
) -> TestEnvironment {
    let store = Arc::new(MemoryStore::default());
    let failures = Arc::new(FailurePlan::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let clock = Arc::new(ClockMock::new());
    let admission = Arc::new(AdmissionMock {
        events: Arc::clone(&events),
        failures: Arc::clone(&failures),
    });
    let services = Arc::new(ServiceMock::new(
        context,
        &current,
        Arc::clone(&events),
        Arc::clone(&failures),
        Arc::clone(&clock),
    ));
    let artifacts = Arc::new(ArtifactMock {
        events: Arc::clone(&events),
        failures: Arc::clone(&failures),
        initial: current.clone(),
        active: Mutex::new(current),
        candidate,
        mismatch_activation: AtomicBool::new(false),
    });
    let pruner = Arc::new(PruneMock {
        events: Arc::clone(&events),
        failures: Arc::clone(&failures),
    });
    let manager = CoreUpdateManager::new(
        store.clone(),
        admission,
        artifacts.clone(),
        services.clone(),
        pruner,
        clock.clone(),
        readiness,
    );
    TestEnvironment {
        manager,
        store,
        failures,
        events,
        artifacts,
        services,
        clock,
    }
}

// Returns one validated requested journal for a deterministic replay identity.
fn requested_record(idempotency_key: &str, version: Option<&str>) -> CoreUpdateRecord {
    CoreUpdateRecord::restore(
        update_id(idempotency_key),
        idempotency_key,
        version.map(|value| CoreVersion::parse(value).expect("version")),
        CoreUpdatePhase::Requested,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("requested record")
}

// Derives the production update identity for one deterministic replay key.
fn update_id(idempotency_key: &str) -> Sha256Digest {
    let mut digest = Sha256::new();
    let domain = b"li_core_update_v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((idempotency_key.len() as u64).to_be_bytes());
    digest.update(idempotency_key.as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).expect("update identity")
}

// Returns one exact immutable Core installation fixture.
fn installation(version: &str, identity_character: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(identity_character),
    )
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns the complete ordinary native state map for one platform context.
fn service_states(
    context: CoreUpdateServiceContext,
    identity: &Sha256Digest,
) -> BTreeMap<CoreUpdateResidentService, CoreUpdateServiceState> {
    let mut services = vec![CoreUpdateResidentService::Node];
    if context.platform() == CoreUpdateServicePlatform::Linux {
        services.push(CoreUpdateResidentService::Watchdog);
    }
    services.push(CoreUpdateResidentService::Gateway);
    services
        .into_iter()
        .map(|service| {
            (
                service,
                CoreUpdateServiceState::new(
                    service,
                    Some(identity.clone()),
                    Some(identity.clone()),
                )
                .expect("service state"),
            )
        })
        .collect()
}

// Appends one externally observable provider action.
fn record_event(events: &Mutex<Vec<String>>, event: &str) {
    events.lock().expect("events").push(event.to_string());
}

// Returns the current deterministic provider event sequence.
fn events(environment: &TestEnvironment) -> Vec<String> {
    environment.events.lock().expect("events").clone()
}

// Executes the complete ordered handoff and commits one success journal.
#[test]
fn successful_update_follows_exact_handoff_order() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    let change = environment
        .manager
        .update(
            "update-core",
            Some(CoreVersion::parse("1.1.0").expect("version")),
        )
        .expect("update");
    assert_eq!(change.disposition(), CoreUpdateDisposition::Updated);
    assert_eq!(change.installation(), &installation("1.1.0", '2'));
    assert_eq!(
        change.event(),
        Some(&CoreUpdateEvent::CoreUpdated {
            source_identity: digest('2'),
        })
    );
    assert_eq!(
        events(&environment),
        [
            "admission",
            "artifact.current",
            "artifact.prepare",
            "service.snapshot",
            "artifact.activate",
            "service.rebind",
            "service.verify",
            "artifact.commit",
            "prune",
        ]
    );
    assert_eq!(
        environment
            .manager
            .record("update-core")
            .expect("record")
            .expect("stored")
            .record()
            .phase(),
        CoreUpdatePhase::Succeeded
    );
}

// Proves CoreUpdateManager alone selects each platform service set and role-dependent Gateway mode.
#[test]
fn manager_owns_the_complete_platform_and_role_service_plan() {
    for (platform, role, expected) in [
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            vec![
                (CoreUpdateResidentService::Node, CoreUpdateServiceMode::Node),
                (
                    CoreUpdateResidentService::Watchdog,
                    CoreUpdateServiceMode::Watchdog,
                ),
                (
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateServiceMode::PublicGateway,
                ),
            ],
        ),
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Child,
            vec![
                (CoreUpdateResidentService::Node, CoreUpdateServiceMode::Node),
                (
                    CoreUpdateResidentService::Watchdog,
                    CoreUpdateServiceMode::Watchdog,
                ),
                (
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateServiceMode::PrivateGateway,
                ),
            ],
        ),
        (
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
            vec![
                (CoreUpdateResidentService::Node, CoreUpdateServiceMode::Node),
                (
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateServiceMode::PublicGateway,
                ),
            ],
        ),
        (
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Child,
            vec![
                (CoreUpdateResidentService::Node, CoreUpdateServiceMode::Node),
                (
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateServiceMode::PrivateGateway,
                ),
            ],
        ),
    ] {
        let context = CoreUpdateServiceContext::new(platform, role);
        let environment = environment_with_policy(
            installation("1.0.0", '1'),
            installation("1.1.0", '2'),
            context,
            CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
        );
        let key = format!("service-plan-{platform:?}-{role:?}");
        environment.manager.update(&key, None).expect("update");
        assert_eq!(
            *environment.services.rebinds.lock().expect("rebinds"),
            expected
        );
        assert_eq!(
            *environment
                .services
                .readiness_calls
                .lock()
                .expect("readiness calls"),
            expected
        );
        let stored = environment
            .services
            .snapshots
            .lock()
            .expect("snapshots")
            .get(update_id(&key).as_str())
            .cloned()
            .expect("snapshot");
        assert_eq!(
            stored
                .services()
                .iter()
                .map(CoreUpdateServiceState::service)
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|(service, _)| *service)
                .collect::<Vec<_>>()
        );
    }
}

// Rejects wrong, missing, inactive, and extra native service facts before Core activation.
#[test]
fn manager_rejects_every_inadmissible_service_snapshot_shape() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    for failure in ["wrong", "missing", "unloaded", "inactive", "extra"] {
        let current = installation("1.0.0", '1');
        let environment = environment_with_policy(
            current.clone(),
            installation("1.1.0", '2'),
            context,
            CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
        );
        let key = format!("service-state-{failure}");
        match failure {
            "wrong" => {
                environment.services.states.lock().expect("states").insert(
                    CoreUpdateResidentService::Node,
                    CoreUpdateServiceState::new(
                        CoreUpdateResidentService::Gateway,
                        Some(current.source_identity().clone()),
                        Some(current.source_identity().clone()),
                    )
                    .expect("wrong state"),
                );
            }
            "missing" => {
                environment
                    .services
                    .states
                    .lock()
                    .expect("states")
                    .remove(&CoreUpdateResidentService::Gateway);
            }
            "inactive" => {
                environment.services.states.lock().expect("states").insert(
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateServiceState::new(
                        CoreUpdateResidentService::Gateway,
                        Some(current.source_identity().clone()),
                        None,
                    )
                    .expect("inactive state"),
                );
            }
            "unloaded" => {
                environment.services.states.lock().expect("states").insert(
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateServiceState::new(CoreUpdateResidentService::Gateway, None, None)
                        .expect("unloaded state"),
                );
            }
            "extra" => {
                let mut states = vec![
                    CoreUpdateResidentService::Node,
                    CoreUpdateResidentService::Watchdog,
                    CoreUpdateResidentService::Gateway,
                    CoreUpdateResidentService::Gateway,
                ]
                .into_iter()
                .map(|service| {
                    CoreUpdateServiceState::new(
                        service,
                        Some(current.source_identity().clone()),
                        Some(current.source_identity().clone()),
                    )
                    .expect("service state")
                })
                .collect::<Vec<_>>();
                let snapshot = CoreUpdateServiceSnapshotRecord::new(
                    update_id(&key),
                    current.clone(),
                    context,
                    std::mem::take(&mut states),
                )
                .expect("extra snapshot");
                environment
                    .services
                    .snapshots
                    .lock()
                    .expect("snapshots")
                    .insert(update_id(&key).as_str().to_string(), snapshot);
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            environment.manager.update(&key, None),
            Err(CoreUpdateError::RolledBack { .. })
        ));
        let observed = events(&environment);
        assert!(!observed.contains(&"artifact.activate".to_string()));
        assert!(!observed.contains(&"service.rebind".to_string()));
        assert!(observed.contains(&"artifact.discard".to_string()));
    }
}

// Rejects persisted order, membership, activity, and conflicting store-return mutations.
#[test]
fn manager_revalidates_every_durable_service_receipt_boundary() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    for failure in ["wrong-order", "missing", "inactive"] {
        let current = installation("1.0.0", '1');
        let environment = environment_with_policy(
            current.clone(),
            installation("1.1.0", '2'),
            context,
            CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
        );
        let key = format!("durable-service-state-{failure}");
        let mut states = [
            CoreUpdateResidentService::Node,
            CoreUpdateResidentService::Watchdog,
            CoreUpdateResidentService::Gateway,
        ]
        .into_iter()
        .map(|service| {
            CoreUpdateServiceState::new(
                service,
                Some(current.source_identity().clone()),
                Some(current.source_identity().clone()),
            )
            .expect("service state")
        })
        .collect::<Vec<_>>();
        match failure {
            "wrong-order" => states.swap(1, 2),
            "missing" => {
                states.pop();
            }
            "inactive" => {
                states[2] = CoreUpdateServiceState::new(
                    CoreUpdateResidentService::Gateway,
                    Some(current.source_identity().clone()),
                    None,
                )
                .expect("inactive state");
            }
            _ => unreachable!(),
        }
        let snapshot =
            CoreUpdateServiceSnapshotRecord::new(update_id(&key), current, context, states)
                .expect("durable snapshot");
        environment
            .services
            .snapshots
            .lock()
            .expect("snapshots")
            .insert(update_id(&key).as_str().to_string(), snapshot);
        assert!(matches!(
            environment.manager.update(&key, None),
            Err(CoreUpdateError::RolledBack { .. })
        ));
        assert!(!events(&environment).contains(&"artifact.activate".to_string()));
    }

    let current = installation("1.0.0", '1');
    let conflicting = environment_with_policy(
        current.clone(),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    );
    let key = "conflicting-service-store-result";
    let foreign_current = installation("9.9.9", '9');
    let foreign_states = [
        CoreUpdateResidentService::Node,
        CoreUpdateResidentService::Watchdog,
        CoreUpdateResidentService::Gateway,
    ]
    .into_iter()
    .map(|service| {
        CoreUpdateServiceState::new(
            service,
            Some(foreign_current.source_identity().clone()),
            Some(foreign_current.source_identity().clone()),
        )
        .expect("foreign state")
    })
    .collect();
    *conflicting
        .services
        .store_result
        .lock()
        .expect("store result") = Some(
        CoreUpdateServiceSnapshotRecord::new(
            update_id(key),
            foreign_current,
            context,
            foreign_states,
        )
        .expect("conflicting receipt"),
    );
    assert!(matches!(
        conflicting.manager.update(key, None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert!(!events(&conflicting).contains(&"artifact.activate".to_string()));
}

// Requires consecutive complete readiness observations and fails at the exact global deadline.
#[test]
fn manager_owns_readiness_stability_and_deadline_completion() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Child);
    let stable = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(50, 10, 2).expect("readiness policy"),
    );
    *stable.services.readiness.lock().expect("readiness") =
        VecDeque::from([true, true, false, true, true, true, true]);
    assert_eq!(
        stable
            .manager
            .update("unstable-then-stable", None)
            .expect("stable update")
            .disposition(),
        CoreUpdateDisposition::Updated
    );
    assert_eq!(*stable.clock.waits.lock().expect("waits"), [10, 10, 10]);

    let deadline = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 2).expect("readiness policy"),
    );
    deadline.services.ready.store(false, Ordering::SeqCst);
    assert!(matches!(
        deadline.manager.update("readiness-deadline", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert_eq!(*deadline.clock.waits.lock().expect("waits"), [10, 10, 10]);
    assert_eq!(
        *deadline.artifacts.active.lock().expect("active Core"),
        installation("1.0.0", '1')
    );
    assert_eq!(
        *deadline.services.restores.lock().expect("restores"),
        [
            (CoreUpdateResidentService::Node, installation("1.0.0", '1')),
            (
                CoreUpdateResidentService::Gateway,
                installation("1.0.0", '1')
            ),
        ]
    );
}

// Rolls back on observation deadline, clock failure, regression, or non-advancing wait.
#[test]
fn manager_fails_closed_at_every_readiness_clock_fault() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);

    let consumed = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    consumed
        .services
        .readiness_elapsed_milliseconds
        .store(30, Ordering::SeqCst);
    assert!(matches!(
        consumed.manager.update("clock-deadline", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert_eq!(
        consumed
            .services
            .readiness_timeouts
            .lock()
            .expect("timeouts")[0],
        Duration::from_millis(30)
    );
    assert!(consumed.clock.waits.lock().expect("waits").is_empty());

    let unavailable = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    unavailable
        .clock
        .observations
        .lock()
        .expect("observations")
        .push_back(Err(CoreUpdateError::provider(
            "readiness clock",
            "mock observation failure",
        )));
    assert!(matches!(
        unavailable.manager.update("clock-unavailable", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));

    let regressed_before_observation = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    *regressed_before_observation
        .clock
        .observations
        .lock()
        .expect("observations") = VecDeque::from([Ok(10), Ok(9)]);
    assert!(matches!(
        regressed_before_observation
            .manager
            .update("clock-regressed-before-observation", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));

    let regressed = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    *regressed.clock.observations.lock().expect("observations") =
        VecDeque::from([Ok(10), Ok(10), Ok(9)]);
    assert!(matches!(
        regressed.manager.update("clock-regressed", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));

    let regressed_after_observation = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 2).expect("readiness policy"),
    );
    *regressed_after_observation
        .clock
        .observations
        .lock()
        .expect("observations") = VecDeque::from([Ok(10), Ok(10), Ok(10), Ok(10), Ok(10), Ok(9)]);
    assert!(matches!(
        regressed_after_observation
            .manager
            .update("clock-regressed-after-observation", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));

    let stalled = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    stalled.services.ready.store(false, Ordering::SeqCst);
    stalled
        .clock
        .advance_after_wait
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        stalled.manager.update("clock-stalled", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert_eq!(*stalled.clock.waits.lock().expect("waits"), [10]);

    let wait_failed = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        context,
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    wait_failed.services.ready.store(false, Ordering::SeqCst);
    wait_failed.clock.fail_wait.store(true, Ordering::SeqCst);
    assert!(matches!(
        wait_failed.manager.update("clock-wait-failed", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
}

// Rejects invalid manager readiness bounds and deadline arithmetic overflow.
#[test]
fn manager_readiness_policy_and_deadline_bounds_fail_closed() {
    for (timeout, poll, stable) in [
        (0, 1, 1),
        (300_001, 1, 1),
        (10, 0, 1),
        (10, 11, 1),
        (10, 1, 0),
        (10, 1, 101),
    ] {
        assert!(
            CoreUpdateReadinessPolicy::new(timeout, poll, stable).is_err(),
            "accepted {timeout}/{poll}/{stable}"
        );
    }

    let overflow = environment_with_policy(
        installation("1.0.0", '1'),
        installation("1.1.0", '2'),
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        CoreUpdateReadinessPolicy::new(30, 10, 1).expect("readiness policy"),
    );
    overflow
        .clock
        .observations
        .lock()
        .expect("observations")
        .push_back(Ok(u64::MAX - 10));
    assert!(matches!(
        overflow.manager.update("clock-deadline-overflow", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert_eq!(
        overflow
            .manager
            .record("clock-deadline-overflow")
            .expect("record")
            .expect("stored")
            .record()
            .failure()
            .expect("failure")
            .message(),
        "Core service readiness deadline overflowed"
    );
}

// Uses process-monotonic time and rejects waits outside the manager readiness bound.
#[test]
fn system_readiness_clock_is_monotonic_and_bounded() {
    let clock = SystemCoreUpdateReadinessClock::new();
    let before = clock.monotonic_milliseconds().expect("before");
    clock.wait(1).expect("bounded wait");
    let after = clock.monotonic_milliseconds().expect("after");
    assert!(after >= before);
    assert!(clock.wait(0).is_err());
    assert!(clock.wait(300_001).is_err());
}

// Holds global update ownership through commit and pruning before releasing it.
#[test]
fn global_admission_lease_spans_the_complete_mutating_handoff() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    let manager = CoreUpdateManager::new(
        environment.store.clone(),
        Arc::new(TrackingAdmission {
            events: environment.events.clone(),
        }),
        environment.artifacts.clone(),
        environment.services.clone(),
        Arc::new(PruneMock {
            events: environment.events.clone(),
            failures: environment.failures.clone(),
        }),
        environment.clock.clone(),
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    );
    manager.update("leased-update", None).expect("update");
    assert_eq!(
        events(&environment),
        [
            "admission",
            "artifact.current",
            "artifact.prepare",
            "service.snapshot",
            "artifact.activate",
            "service.rebind",
            "service.verify",
            "artifact.commit",
            "prune",
            "admission.release",
        ]
    );
}

// Discards a verified no-op candidate without touching services or pruning.
#[test]
fn current_release_completes_without_service_mutation() {
    let current = installation("1.0.0", '1');
    let environment = environment(current.clone(), current.clone());
    let change = environment
        .manager
        .update("current-core", None)
        .expect("current");
    assert_eq!(change.disposition(), CoreUpdateDisposition::Current);
    assert_eq!(change.installation(), &current);
    assert_eq!(
        events(&environment),
        [
            "admission",
            "artifact.current",
            "artifact.prepare",
            "artifact.discard",
        ]
    );
    assert_eq!(
        environment
            .manager
            .record("current-core")
            .expect("record")
            .expect("stored")
            .record()
            .phase(),
        CoreUpdatePhase::Current
    );
}

// Rolls back every failure boundary that occurs before active-pointer mutation.
#[test]
fn pre_activation_failure_matrix_never_rebinds_services() {
    for capability in [
        "admission",
        "artifact.current",
        "artifact.prepare",
        "service.snapshot",
        "artifact.activate",
    ] {
        let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
        environment.failures.fail(capability, 1);
        assert!(matches!(
            environment.manager.update(capability, None),
            Err(CoreUpdateError::RolledBack { .. })
        ));
        let observed = events(&environment);
        assert!(!observed.contains(&"service.rebind".to_string()));
        assert!(!observed.contains(&"prune".to_string()));
        assert_eq!(
            environment
                .manager
                .record(capability)
                .expect("record")
                .expect("stored")
                .record()
                .phase(),
            CoreUpdatePhase::RolledBack
        );
        assert_eq!(
            environment.artifacts.active.lock().expect("active").clone(),
            installation("1.0.0", '1')
        );
    }
}

// Restores services and the previous Core for every post-activation failure.
#[test]
fn post_activation_failure_matrix_restores_previous_core() {
    for capability in ["service.rebind", "service.verify", "artifact.commit"] {
        let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
        environment.failures.fail(capability, 1);
        assert!(matches!(
            environment.manager.update(capability, None),
            Err(CoreUpdateError::RolledBack { .. })
        ));
        let observed = events(&environment);
        assert!(observed.contains(&"service.restore".to_string()));
        assert!(observed.contains(&"artifact.rollback".to_string()));
        assert!(!observed.contains(&"prune".to_string()));
        assert_eq!(
            environment.artifacts.active.lock().expect("active").clone(),
            installation("1.0.0", '1')
        );
    }
}

// Marks recovery required when either compensation boundary cannot restore state.
#[test]
fn rollback_failure_matrix_records_recovery_required() {
    for capability in ["service.restore", "artifact.rollback"] {
        let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
        environment.failures.fail("service.rebind", 1);
        environment.failures.fail(capability, 1);
        assert!(matches!(
            environment.manager.update(capability, None),
            Err(CoreUpdateError::RecoveryRequired { .. })
        ));
        assert_eq!(
            environment
                .manager
                .record(capability)
                .expect("record")
                .expect("stored")
                .record()
                .phase(),
            CoreUpdatePhase::RecoveryRequired
        );
    }
}

// Attempts every Linux restoration with the exact previous Core after the first restore fails.
#[test]
fn restoration_attempts_the_complete_exact_previous_service_plan() {
    let previous = installation("1.0.0", '1');
    let environment = environment(previous.clone(), installation("1.1.0", '2'));
    environment.failures.fail("service.rebind", 1);
    environment.failures.fail("service.restore", 1);
    assert!(matches!(
        environment.manager.update("restore-all-services", None),
        Err(CoreUpdateError::RecoveryRequired { .. })
    ));
    assert_eq!(
        *environment.services.restores.lock().expect("restores"),
        [
            (CoreUpdateResidentService::Node, previous.clone()),
            (CoreUpdateResidentService::Watchdog, previous.clone()),
            (CoreUpdateResidentService::Gateway, previous),
        ]
    );
}

// Preserves the verified new Core when pruning fails and retries cleanup idempotently.
#[test]
fn prune_failure_is_cleanup_pending_then_recovers() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    environment.failures.fail("prune", 1);
    let pending = environment
        .manager
        .update("cleanup", None)
        .expect("cleanup pending");
    assert_eq!(pending.disposition(), CoreUpdateDisposition::CleanupPending);
    assert_eq!(
        environment.artifacts.active.lock().expect("active").clone(),
        installation("1.1.0", '2')
    );
    assert!(!events(&environment).contains(&"artifact.rollback".to_string()));

    let completed = environment
        .manager
        .update("cleanup", None)
        .expect("cleanup retry");
    assert_eq!(completed.disposition(), CoreUpdateDisposition::Updated);
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "prune")
            .count(),
        2
    );
    assert_eq!(
        environment
            .manager
            .record("cleanup")
            .expect("record")
            .expect("stored")
            .record()
            .phase(),
        CoreUpdatePhase::Succeeded
    );
}

// Replays terminal state without external work and rejects a changed request.
#[test]
fn terminal_replay_is_quiet_and_version_conflict_fails() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    let requested = CoreVersion::parse("1.1.0").expect("version");
    environment
        .manager
        .update("replay", Some(requested.clone()))
        .expect("first");
    let before = events(&environment);
    let replay = environment
        .manager
        .update("replay", Some(requested))
        .expect("replay");
    assert!(replay.event().is_none());
    assert_eq!(events(&environment), before);
    assert_eq!(
        environment.manager.update(
            "replay",
            Some(CoreVersion::parse("1.2.0").expect("different version")),
        ),
        Err(CoreUpdateError::IdempotencyConflict)
    );
}

// Reconciles a mutation that committed durably before its store result became unavailable.
#[test]
fn ambiguous_postcommit_store_failure_replays_without_duplicate_provider_work() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    environment.store.fail_after_replace_call(1);
    let change = environment
        .manager
        .update("ambiguous-commit", None)
        .expect("reconciled update");
    assert_eq!(change.disposition(), CoreUpdateDisposition::Updated);
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "artifact.prepare")
            .count(),
        1
    );
}

// Rejects foreign records, zero revisions, altered content, and stale mutation revisions.
#[test]
fn manager_rejects_every_untrusted_store_result_shape() {
    let foreign = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    foreign
        .store
        .response_tamper
        .store(TAMPER_CREATE_FOREIGN_RECORD, Ordering::SeqCst);
    assert_eq!(
        foreign.manager.update("foreign-create", None),
        Err(CoreUpdateError::Store(CoreUpdateStoreError::Corrupt))
    );
    assert!(events(&foreign).is_empty());

    let zero = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    zero.store
        .create(requested_record("zero-read", None))
        .expect("requested record");
    zero.store
        .response_tamper
        .store(TAMPER_READ_ZERO_REVISION, Ordering::SeqCst);
    assert_eq!(
        zero.manager.update("zero-read", None),
        Err(CoreUpdateError::Store(CoreUpdateStoreError::Corrupt))
    );
    assert!(events(&zero).is_empty());

    for tamper in [TAMPER_REPLACE_RECORD, TAMPER_REPLACE_REVISION] {
        let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
        environment
            .store
            .response_tamper
            .store(tamper, Ordering::SeqCst);
        assert_eq!(
            environment.manager.update("tampered-replace", None),
            Err(CoreUpdateError::Store(CoreUpdateStoreError::Corrupt))
        );
        assert_eq!(
            events(&environment),
            ["admission", "artifact.current", "artifact.prepare"]
        );
    }
}

// Resumes after a journal-write failure without duplicating or compensating activation.
#[test]
fn restart_resumes_idempotent_activation_after_store_failure() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    environment.store.fail_replace_call(3);
    assert_eq!(
        environment.manager.update("restart", None),
        Err(CoreUpdateError::Store(CoreUpdateStoreError::Unavailable))
    );
    assert_eq!(
        environment
            .manager
            .record("restart")
            .expect("record")
            .expect("stored")
            .record()
            .phase(),
        CoreUpdatePhase::ServicesSnapshotted
    );
    assert!(!events(&environment).contains(&"artifact.rollback".to_string()));

    let resumed_manager = CoreUpdateManager::new(
        environment.store.clone(),
        Arc::new(AdmissionMock {
            events: Arc::clone(&environment.events),
            failures: Arc::clone(&environment.failures),
        }),
        environment.artifacts.clone(),
        environment.services.clone(),
        Arc::new(PruneMock {
            events: Arc::clone(&environment.events),
            failures: Arc::clone(&environment.failures),
        }),
        environment.clock.clone(),
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    );
    assert_eq!(
        resumed_manager
            .update("restart", None)
            .expect("resumed")
            .disposition(),
        CoreUpdateDisposition::Updated
    );
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "artifact.activate")
            .count(),
        2
    );
}

// Resumes a durable rollback intent when its terminal journal write was interrupted.
#[test]
fn restart_completes_idempotent_rollback_after_store_failure() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    environment.failures.fail("service.rebind", 1);
    environment.store.fail_replace_call(5);
    assert_eq!(
        environment.manager.update("rollback-restart", None),
        Err(CoreUpdateError::Store(CoreUpdateStoreError::Unavailable))
    );
    assert_eq!(
        environment
            .manager
            .record("rollback-restart")
            .expect("record")
            .expect("stored")
            .record()
            .phase(),
        CoreUpdatePhase::RollingBack
    );
    assert!(matches!(
        environment.manager.update("rollback-restart", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "service.restore")
            .count(),
        2
    );
    assert_eq!(
        events(&environment)
            .iter()
            .filter(|event| event.as_str() == "artifact.rollback")
            .count(),
        2
    );
    assert_eq!(
        environment
            .manager
            .record("rollback-restart")
            .expect("record")
            .expect("stored")
            .record()
            .phase(),
        CoreUpdatePhase::RolledBack
    );
}

// Rejects malformed versions and a provider that violates a pinned version request.
#[test]
fn version_and_candidate_identity_matrix_fails_closed() {
    for invalid in [
        "", "v1.2.3", "1.2", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3 a",
    ] {
        assert!(CoreVersion::parse(invalid).is_err(), "accepted {invalid}");
    }
    for valid in ["0.1.0", "1.2.3-rc.1", "1.2.3--preview", "1.2.3+build-x.7"] {
        assert!(CoreVersion::parse(valid).is_ok(), "rejected {valid}");
    }

    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    assert!(matches!(
        environment.manager.update(
            "wrong-version",
            Some(CoreVersion::parse("1.2.0").expect("version")),
        ),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert!(events(&environment).contains(&"artifact.discard".to_string()));
}

// Rejects a mismatched activation receipt and compensates its external mutation.
#[test]
fn activation_receipt_mismatch_rolls_back() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    environment.artifacts.mismatch_activation();
    assert!(matches!(
        environment.manager.update("bad-activation", None),
        Err(CoreUpdateError::RolledBack { .. })
    ));
    assert!(events(&environment).contains(&"service.restore".to_string()));
    assert!(events(&environment).contains(&"artifact.rollback".to_string()));
    assert_eq!(
        environment.artifacts.active.lock().expect("active").clone(),
        installation("1.0.0", '1')
    );
}

// Blocks a second update immediately while the first owns manager mutation.
#[test]
fn concurrent_update_returns_busy_without_entering_providers() {
    let store = Arc::new(MemoryStore::default());
    let failures = Arc::new(FailurePlan::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new((Mutex::new(false), Condvar::new()));

    struct BlockingAdmission {
        entered: Arc<Barrier>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl CoreUpdateAdmissionProvider for BlockingAdmission {
        // Holds one admitted update until the test releases its ownership boundary.
        fn acquire(
            &self,
            _update_id: &Sha256Digest,
        ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
            self.entered.wait();
            let (lock, condition) = &*self.release;
            let mut released = lock.lock().expect("release");
            while !*released {
                released = condition.wait(released).expect("release wait");
            }
            Ok(Box::new(AdmissionLease))
        }
    }

    let artifacts = Arc::new(ArtifactMock {
        events: Arc::clone(&events),
        failures: Arc::clone(&failures),
        initial: installation("1.0.0", '1'),
        active: Mutex::new(installation("1.0.0", '1')),
        candidate: installation("1.1.0", '2'),
        mismatch_activation: AtomicBool::new(false),
    });
    let clock = Arc::new(ClockMock::new());
    let services = Arc::new(ServiceMock::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &installation("1.0.0", '1'),
        Arc::clone(&events),
        Arc::clone(&failures),
        clock.clone(),
    ));
    let manager = Arc::new(CoreUpdateManager::new(
        store,
        Arc::new(BlockingAdmission {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        }),
        artifacts,
        services,
        Arc::new(PruneMock { events, failures }),
        clock,
        CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
    ));
    let worker_manager = Arc::clone(&manager);
    let worker = thread::spawn(move || worker_manager.update("first", None));
    entered.wait();
    assert_eq!(manager.update("second", None), Err(CoreUpdateError::Busy));
    let (lock, condition) = &*release;
    *lock.lock().expect("release") = true;
    condition.notify_all();
    assert_eq!(
        worker.join().expect("worker").expect("first").disposition(),
        CoreUpdateDisposition::Updated
    );
}

// Gives two manager instances one CAS winner and lets the loser replay authoritative success.
#[test]
fn concurrent_managers_have_one_journal_winner_and_one_safe_replay() {
    struct BarrierAdmission {
        barrier: Arc<Barrier>,
    }

    impl CoreUpdateAdmissionProvider for BarrierAdmission {
        // Aligns two independent managers after they read the same requested revision.
        fn acquire(
            &self,
            _update_id: &Sha256Digest,
        ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
            self.barrier.wait();
            Ok(Box::new(AdmissionLease))
        }
    }

    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    let barrier = Arc::new(Barrier::new(2));
    let managers = (0..2)
        .map(|_| {
            Arc::new(CoreUpdateManager::new(
                environment.store.clone(),
                Arc::new(BarrierAdmission {
                    barrier: barrier.clone(),
                }),
                environment.artifacts.clone(),
                environment.services.clone(),
                Arc::new(PruneMock {
                    events: environment.events.clone(),
                    failures: environment.failures.clone(),
                }),
                environment.clock.clone(),
                CoreUpdateReadinessPolicy::new(50, 10, 1).expect("readiness policy"),
            ))
        })
        .collect::<Vec<_>>();
    let workers = managers
        .iter()
        .map(|manager| {
            let manager = manager.clone();
            thread::spawn(move || manager.update("shared-update", None))
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("update worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(CoreUpdateError::Store(CoreUpdateStoreError::Conflict))
                )
            })
            .count(),
        1
    );
    assert_eq!(
        managers[0]
            .update("shared-update", None)
            .expect("authoritative replay")
            .disposition(),
        CoreUpdateDisposition::Updated
    );
    assert!(!events(&environment).contains(&"artifact.rollback".to_string()));
}

// Exposes journal status without invoking any external update capability.
#[test]
fn record_read_is_quiet_and_missing_safe() {
    let environment = environment(installation("1.0.0", '1'), installation("1.1.0", '2'));
    assert!(environment
        .manager
        .record("missing")
        .expect("missing")
        .is_none());
    assert!(events(&environment).is_empty());
}
