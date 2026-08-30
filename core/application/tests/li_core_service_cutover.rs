// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use li_core_application::{
    CoreProcessLayout, CoreProcessPlatform, CoreServiceCutoverBegin, CoreServiceCutoverNativeHost,
    CoreServiceCutoverNativeSnapshot, CoreServiceCutoverPhase, CoreServiceCutoverProvider,
    CoreServiceCutoverReceipt, CoreServiceCutoverRecord, CoreServiceCutoverRecovery,
    CoreServiceCutoverStore, CoreServiceDefinition, CoreServiceDefinitionProvider,
    CoreServiceSetupError, DurableCoreServiceCutoverProvider,
};

// Restores and retains the terminal checkpoint until outer setup compensation completes.
#[test]
fn explicit_recovery_retains_restored_authority_until_completion() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let restoring = record_in_phase(
        prepared_record(context, installation("1.2.3", 'a'), &definitions),
        CoreServiceCutoverPhase::Restoring,
    );
    let (cutover, store, events) =
        provider(Some(restoring), CutoverFailure::None, CutoverFailure::None);

    assert_eq!(
        cutover.recovery().expect("recovery"),
        CoreServiceCutoverRecovery::Restoring
    );
    cutover.resume_recovery().expect("restore");
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Restored)
    );
    assert_eq!(
        cutover.recovery().expect("restored"),
        CoreServiceCutoverRecovery::Restored
    );
    cutover.complete_recovery().expect("complete");
    assert!(store.record.lock().expect("record").is_none());
    assert_eq!(
        events.lock().expect("events").as_slice(),
        [
            CutoverEvent::Read,
            CutoverEvent::Read,
            CutoverEvent::Restore,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            ),
            CutoverEvent::Read,
            CutoverEvent::Read,
            CutoverEvent::Remove,
        ]
    );
}
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};

// Records every persistence and native cutover boundary in one deterministic sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CutoverEvent {
    Read,
    Create,
    Transition(CoreServiceCutoverPhase, CoreServiceCutoverPhase),
    Remove,
    Snapshot(CoreUpdateServiceContext),
    Retire,
    Restore,
}

// Selects one deterministic cutover failure or conflicting store result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CutoverFailure {
    None,
    CreateConflict,
    TransitionConflict,
    TransitionToRestoring,
    TransitionToRestored,
    Remove,
    Snapshot,
    Retire,
    RetireAndRestore,
    RetirementConflict,
    Restore,
}

// Stores one authoritative in-memory record while preserving exact operation order.
struct StoreMock {
    record: Mutex<Option<CoreServiceCutoverRecord>>,
    failure: CutoverFailure,
    events: Arc<Mutex<Vec<CutoverEvent>>>,
}

impl StoreMock {
    // Creates one store fixture around optional durable replay state.
    fn new(
        record: Option<CoreServiceCutoverRecord>,
        failure: CutoverFailure,
        events: Arc<Mutex<Vec<CutoverEvent>>>,
    ) -> Self {
        Self {
            record: Mutex::new(record),
            failure,
            events,
        }
    }
}

impl CoreServiceCutoverStore for StoreMock {
    // Returns the current authoritative record after logging the read boundary.
    fn read(&self) -> Result<Option<CoreServiceCutoverRecord>, CoreServiceSetupError> {
        self.events.lock().expect("events").push(CutoverEvent::Read);
        Ok(self.record.lock().expect("record").clone())
    }

    // Creates one record or returns a deterministic conflicting durable value.
    fn create(
        &self,
        record: CoreServiceCutoverRecord,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(CutoverEvent::Create);
        let stored = if self.failure == CutoverFailure::CreateConflict {
            conflicting_record(&record)
        } else {
            record
        };
        *self.record.lock().expect("record") = Some(stored.clone());
        Ok(stored)
    }

    // Applies one expected transition or returns an injected failure or conflict.
    fn transition(
        &self,
        receipt: &CoreServiceCutoverReceipt,
        expected: CoreServiceCutoverPhase,
        next: CoreServiceCutoverPhase,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(CutoverEvent::Transition(expected, next));
        let current = self
            .record
            .lock()
            .expect("record")
            .clone()
            .expect("current record");
        assert_eq!(current.receipt_id(), receipt.receipt_id());
        assert_eq!(current.phase(), expected);
        if (self.failure == CutoverFailure::TransitionToRestoring
            && next == CoreServiceCutoverPhase::Restoring)
            || (self.failure == CutoverFailure::TransitionToRestored
                && next == CoreServiceCutoverPhase::Restored)
        {
            return Err(CoreServiceSetupError::provider(
                "test store",
                "injected transition failure",
            ));
        }
        let transitioned = if self.failure == CutoverFailure::TransitionConflict {
            record_in_phase(conflicting_record(&current), next)
        } else {
            current.transitioned(expected, next).expect("transition")
        };
        *self.record.lock().expect("record") = Some(transitioned.clone());
        Ok(transitioned)
    }

    // Removes only the exact receipt after logging terminal replay cleanup.
    fn remove(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(CutoverEvent::Remove);
        let mut record = self.record.lock().expect("record");
        assert_eq!(
            record.as_ref().map(CoreServiceCutoverRecord::receipt_id),
            Some(receipt.receipt_id())
        );
        if self.failure == CutoverFailure::Remove {
            return Err(CoreServiceSetupError::provider(
                "test store",
                "injected remove failure",
            ));
        }
        *record = None;
        Ok(())
    }
}

// Captures, retires, and restores one opaque deterministic native snapshot.
struct NativeHostMock {
    failure: CutoverFailure,
    events: Arc<Mutex<Vec<CutoverEvent>>>,
}

impl NativeHostMock {
    // Creates one native host fixture with an injected lifecycle outcome.
    fn new(failure: CutoverFailure, events: Arc<Mutex<Vec<CutoverEvent>>>) -> Self {
        Self { failure, events }
    }
}

impl CoreServiceCutoverNativeHost for NativeHostMock {
    // Returns one platform-bound snapshot or fails before service mutation.
    fn snapshot(
        &self,
        context: CoreUpdateServiceContext,
    ) -> Result<CoreServiceCutoverNativeSnapshot, CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(CutoverEvent::Snapshot(context));
        if self.failure == CutoverFailure::Snapshot {
            return Err(CoreServiceSetupError::provider(
                "test host",
                "injected snapshot failure",
            ));
        }
        CoreServiceCutoverNativeSnapshot::new(b"native-snapshot".to_vec())
    }

    // Records idempotent retirement or returns the injected mutation failure.
    fn retire(
        &self,
        _snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(CutoverEvent::Retire);
        if self.failure == CutoverFailure::RetirementConflict {
            return Err(CoreServiceSetupError::RolledBack {
                reason: "native service state changed before retirement",
            });
        }
        if matches!(
            self.failure,
            CutoverFailure::Retire | CutoverFailure::RetireAndRestore
        ) {
            return Err(CoreServiceSetupError::provider(
                "test host",
                "injected retirement failure",
            ));
        }
        Ok(())
    }

    // Reuses the same injected native result while exercising the explicit replay port.
    fn resume_retirement(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError> {
        self.retire(snapshot)
    }

    // Records whole-set restoration or returns the injected compensation failure.
    fn restore(
        &self,
        _snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(CutoverEvent::Restore);
        if matches!(
            self.failure,
            CutoverFailure::Restore | CutoverFailure::RetireAndRestore
        ) {
            return Err(CoreServiceSetupError::provider(
                "test host",
                "injected restoration failure",
            ));
        }
        Ok(())
    }
}

// Clears a newly proposed snapshot conflict without restoring bytes that were never retired.
#[test]
fn fresh_retirement_conflict_clears_only_the_unaccepted_record() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Macos);
    let (provider, store, events) = provider(
        None,
        CutoverFailure::None,
        CutoverFailure::RetirementConflict,
    );
    assert_eq!(
        provider.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RolledBack {
            reason: "native service state changed before retirement",
        })
    );
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Snapshot(context),
            CutoverEvent::Create,
            CutoverEvent::Retire,
            CutoverEvent::Remove,
        ]
    );
    assert!(store.record.lock().expect("record").is_none());
}

// Retains a prepared replay conflict because an earlier retirement may have been partial.
#[test]
fn prepared_retirement_conflict_requires_recovery_without_restoration() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Macos);
    let record = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let (provider, store, events) = provider(
        Some(record.clone()),
        CutoverFailure::None,
        CutoverFailure::RetirementConflict,
    );
    assert_eq!(
        provider.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "prepared native service state changed before retirement",
        })
    );
    assert_eq!(history(&events), [CutoverEvent::Read, CutoverEvent::Retire]);
    assert_eq!(*store.record.lock().expect("record"), Some(record));
}

// Creates one immutable installation fixture.
fn installation(version: &str, identity: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(identity),
    )
}

// Creates one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Generates the exact deterministic resident definition set for one platform.
fn definitions(platform: CoreProcessPlatform) -> Vec<CoreServiceDefinition> {
    let layout = CoreProcessLayout::new(
        platform,
        std::path::PathBuf::from("/opt/letsinfer/core/versions/1.2.3/identity"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        std::path::PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    layout
        .commands()
        .expect("commands")
        .iter()
        .map(|command| {
            CoreServiceDefinitionProvider
                .definition(platform, command)
                .expect("definition")
        })
        .collect()
}

// Creates one prepared durable record fixture.
fn prepared_record(
    context: CoreUpdateServiceContext,
    installation: CoreInstallation,
    definitions: &[CoreServiceDefinition],
) -> CoreServiceCutoverRecord {
    CoreServiceCutoverRecord::new(
        context,
        installation,
        definitions,
        CoreServiceCutoverNativeSnapshot::new(b"native-snapshot".to_vec()).expect("snapshot"),
    )
    .expect("record")
}

// Creates a different valid record for conflicting authoritative-store tests.
fn conflicting_record(record: &CoreServiceCutoverRecord) -> CoreServiceCutoverRecord {
    let platform = match record.context().platform() {
        CoreUpdateServicePlatform::Linux => CoreProcessPlatform::Linux,
        CoreUpdateServicePlatform::Macos => CoreProcessPlatform::Macos,
    };
    prepared_record(
        record.context(),
        installation("9.9.9", '9'),
        &definitions(platform),
    )
}

// Returns one fixture advanced through the exact legal path to a requested phase.
fn record_in_phase(
    record: CoreServiceCutoverRecord,
    phase: CoreServiceCutoverPhase,
) -> CoreServiceCutoverRecord {
    match phase {
        CoreServiceCutoverPhase::Prepared => record,
        CoreServiceCutoverPhase::Restoring => record
            .transitioned(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            )
            .expect("restoring"),
        CoreServiceCutoverPhase::Restored => record
            .transitioned(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            )
            .expect("restoring")
            .transitioned(
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            )
            .expect("restored"),
        CoreServiceCutoverPhase::Committed => record
            .transitioned(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Committed,
            )
            .expect("committed"),
    }
}

// Composes one provider with observable persistence and native adapters.
fn provider(
    record: Option<CoreServiceCutoverRecord>,
    store_failure: CutoverFailure,
    host_failure: CutoverFailure,
) -> (
    DurableCoreServiceCutoverProvider,
    Arc<StoreMock>,
    Arc<Mutex<Vec<CutoverEvent>>>,
) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(StoreMock::new(record, store_failure, events.clone()));
    let host = Arc::new(NativeHostMock::new(host_failure, events.clone()));
    (
        DurableCoreServiceCutoverProvider::new(store.clone(), host),
        store,
        events,
    )
}

// Returns a copy of the complete operation history.
fn history(events: &Arc<Mutex<Vec<CutoverEvent>>>) -> Vec<CutoverEvent> {
    events.lock().expect("events").clone()
}

// Persists the native snapshot before mutation and replays prepared retirement idempotently.
#[test]
fn begin_orders_snapshot_create_retire_and_replays_without_resnapshot() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let installation = installation("1.2.3", 'a');
    let definitions = definitions(CoreProcessPlatform::Linux);
    let (provider, _, events) = provider(None, CutoverFailure::None, CutoverFailure::None);
    let first = provider
        .begin(context, &installation, &definitions)
        .expect("first begin");
    assert!(matches!(first, CoreServiceCutoverBegin::Prepared(_)));
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Snapshot(context),
            CutoverEvent::Create,
            CutoverEvent::Retire,
        ]
    );
    events.lock().expect("events").clear();
    let replay = provider
        .begin(context, &installation, &definitions)
        .expect("replay begin");
    assert_eq!(replay, first);
    assert_eq!(history(&events), [CutoverEvent::Read, CutoverEvent::Retire]);
}

// Refuses a foreign request while a prepared snapshot still owns recovery authority.
#[test]
fn prepared_conflict_requires_recovery_before_native_mutation() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let existing = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let (provider, _, events) =
        provider(Some(existing), CutoverFailure::None, CutoverFailure::None);
    assert!(matches!(
        provider.begin(context, &installation("2.0.0", 'b'), &definitions),
        Err(CoreServiceSetupError::RecoveryRequired { .. })
    ));
    assert_eq!(history(&events), [CutoverEvent::Read]);
}

// Persists restoration phases before clearing the completed rollback record.
#[test]
fn retirement_failure_compensates_through_durable_restoration_phases() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Child);
    let definitions = definitions(CoreProcessPlatform::Macos);
    let (provider, store, events) = provider(None, CutoverFailure::None, CutoverFailure::Retire);
    assert_eq!(
        provider.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RolledBack {
            reason: "native service retirement failed",
        })
    );
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Snapshot(context),
            CutoverEvent::Create,
            CutoverEvent::Retire,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
            CutoverEvent::Restore,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            ),
            CutoverEvent::Remove,
        ]
    );
    assert!(store.record.lock().expect("record").is_none());
}

// Retains restoring recovery authority when retirement compensation cannot complete.
#[test]
fn failed_compensation_retains_the_restoring_record() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let existing = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let (provider, store, events) = provider(
        Some(existing),
        CutoverFailure::None,
        CutoverFailure::RetireAndRestore,
    );
    assert!(matches!(
        provider.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RecoveryRequired { .. })
    ));
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Retire,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
            CutoverEvent::Restore
        ]
    );
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Restoring)
    );
}

// Rejects a conflicting create result before retiring any native service.
#[test]
fn conflicting_store_create_never_mutates_native_services() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let (provider, _, events) =
        provider(None, CutoverFailure::CreateConflict, CutoverFailure::None);
    assert!(matches!(
        provider.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RecoveryRequired { .. })
    ));
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Snapshot(context),
            CutoverEvent::Create,
        ]
    );
}

// Stops before persistence and retirement when native observation cannot complete.
#[test]
fn snapshot_failure_performs_no_service_mutation() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let (cutover, store, events) = provider(None, CutoverFailure::None, CutoverFailure::Snapshot);
    assert!(matches!(
        cutover.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::Provider {
            capability: "test host",
            ..
        })
    ));
    assert_eq!(
        history(&events),
        [CutoverEvent::Read, CutoverEvent::Snapshot(context)]
    );
    assert!(store.record.lock().expect("record").is_none());
}

// Commits once durably and treats a repeated commit as a read-only replay.
#[test]
fn commit_is_durable_and_idempotent() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Macos);
    let record = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(record.receipt_id().clone());
    let (provider, store, events) =
        provider(Some(record), CutoverFailure::None, CutoverFailure::None);
    provider.commit(&receipt).expect("commit");
    provider.commit(&receipt).expect("commit replay");
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Committed,
            ),
            CutoverEvent::Read,
        ]
    );
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Committed)
    );
}

// Requires recovery when the store cannot return the exact committed record.
#[test]
fn conflicting_commit_result_is_never_accepted() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Macos);
    let prepared = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(prepared.receipt_id().clone());
    let (cutover, _, events) = provider(
        Some(prepared),
        CutoverFailure::TransitionConflict,
        CutoverFailure::None,
    );
    assert!(matches!(
        cutover.commit(&receipt),
        Err(CoreServiceSetupError::RecoveryRequired { .. })
    ));
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Committed,
            ),
        ]
    );
}

// Reuses a matching committed record without retiring services and replaces a foreign one safely.
#[test]
fn committed_replay_never_retires_verified_services() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let current_installation = installation("1.2.3", 'a');
    let committed = record_in_phase(
        prepared_record(context, current_installation.clone(), &definitions),
        CoreServiceCutoverPhase::Committed,
    );
    let (cutover, _, events) =
        provider(Some(committed), CutoverFailure::None, CutoverFailure::None);
    let begin = cutover
        .begin(context, &current_installation, &definitions)
        .expect("matching replay");
    assert!(matches!(
        begin,
        CoreServiceCutoverBegin::AlreadyCommitted(_)
    ));
    assert_eq!(history(&events), [CutoverEvent::Read]);
    events.lock().expect("events").clear();
    cutover
        .begin(context, &installation("2.0.0", 'b'), &definitions)
        .expect("replacement begin");
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Remove,
            CutoverEvent::Snapshot(context),
            CutoverEvent::Create,
            CutoverEvent::Retire,
        ]
    );
}

// Persists restoring and restored checkpoints before clearing completed recovery state.
#[test]
fn restore_orders_phases_and_replays_without_native_mutation() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Child);
    let definitions = definitions(CoreProcessPlatform::Macos);
    let prepared = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(prepared.receipt_id().clone());
    let (cutover, store, events) =
        provider(Some(prepared), CutoverFailure::None, CutoverFailure::None);
    cutover.restore(&receipt).expect("restore");
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
            CutoverEvent::Restore,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            ),
            CutoverEvent::Remove,
        ]
    );
    assert!(store.record.lock().expect("record").is_none());

    let committed = record_in_phase(
        prepared_record(context, installation("1.2.3", 'a'), &definitions),
        CoreServiceCutoverPhase::Committed,
    );
    let receipt = CoreServiceCutoverReceipt::new(committed.receipt_id().clone());
    let (cutover, _, events) =
        provider(Some(committed), CutoverFailure::None, CutoverFailure::None);
    assert!(matches!(
        cutover.restore(&receipt),
        Err(CoreServiceSetupError::InvalidContract { .. })
    ));
    assert_eq!(history(&events), [CutoverEvent::Read]);
}

// Leaves restoring durable when native restoration fails after the intent transition.
#[test]
fn native_restoration_failure_retains_restoring_authority() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let prepared = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(prepared.receipt_id().clone());
    let (cutover, store, events) = provider(
        Some(prepared),
        CutoverFailure::None,
        CutoverFailure::Restore,
    );
    assert!(matches!(
        cutover.restore(&receipt),
        Err(CoreServiceSetupError::Provider {
            capability: "test host",
            ..
        })
    ));
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
            CutoverEvent::Restore,
        ]
    );
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Restoring)
    );
}

// Stops before native restoration when the durable restoring intent cannot persist.
#[test]
fn restoring_transition_failure_prevents_native_restore() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let prepared = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(prepared.receipt_id().clone());
    let (cutover, store, events) = provider(
        Some(prepared),
        CutoverFailure::TransitionToRestoring,
        CutoverFailure::None,
    );
    assert!(cutover.restore(&receipt).is_err());
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
        ]
    );
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Prepared)
    );
}

// Replays idempotent native restoration after a crash before restored phase persistence.
#[test]
fn restored_transition_failure_replays_without_retirement() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let prepared = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(prepared.receipt_id().clone());
    let (cutover, store, events) = provider(
        Some(prepared),
        CutoverFailure::TransitionToRestored,
        CutoverFailure::None,
    );
    assert_eq!(
        cutover.restore(&receipt),
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "restored service cutover phase could not be persisted",
        })
    );
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Restoring)
    );
    events.lock().expect("events").clear();
    let restoring = store.record.lock().expect("record").clone();
    let (replay, replay_store, replay_events) =
        provider(restoring, CutoverFailure::None, CutoverFailure::None);
    assert!(matches!(
        replay.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RolledBack { .. })
    ));
    assert_eq!(
        history(&replay_events),
        [
            CutoverEvent::Read,
            CutoverEvent::Restore,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            ),
            CutoverEvent::Remove,
        ]
    );
    assert!(!history(&replay_events).contains(&CutoverEvent::Retire));
    assert!(replay_store.record.lock().expect("record").is_none());
}

// Retains the restored checkpoint when cleanup fails after native restoration succeeds.
#[test]
fn direct_restoration_cleanup_failure_retains_restored_checkpoint() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let prepared = prepared_record(context, installation("1.2.3", 'a'), &definitions);
    let receipt = CoreServiceCutoverReceipt::new(prepared.receipt_id().clone());
    let (cutover, store, events) =
        provider(Some(prepared), CutoverFailure::Remove, CutoverFailure::None);
    assert_eq!(
        cutover.restore(&receipt),
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "restored service cutover record could not be cleared",
        })
    );
    assert_eq!(
        history(&events),
        [
            CutoverEvent::Read,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
            CutoverEvent::Restore,
            CutoverEvent::Transition(
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            ),
            CutoverEvent::Remove,
        ]
    );
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Restored)
    );
}

// Clears terminal restored evidence without repeating restoration or native retirement.
#[test]
fn begin_from_restored_state_never_retires_restored_services() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let restored = record_in_phase(
        prepared_record(context, installation("1.2.3", 'a'), &definitions),
        CoreServiceCutoverPhase::Restored,
    );
    let (cutover, store, events) =
        provider(Some(restored), CutoverFailure::None, CutoverFailure::None);
    assert!(matches!(
        cutover.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RolledBack { .. })
    ));
    assert_eq!(history(&events), [CutoverEvent::Read, CutoverEvent::Remove]);
    assert!(store.record.lock().expect("record").is_none());
}

// Retains the restored checkpoint when its exact cleanup cannot be persisted.
#[test]
fn restored_cleanup_failure_requires_recovery_without_native_mutation() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let restored = record_in_phase(
        prepared_record(context, installation("1.2.3", 'a'), &definitions),
        CoreServiceCutoverPhase::Restored,
    );
    let (cutover, store, events) =
        provider(Some(restored), CutoverFailure::Remove, CutoverFailure::None);
    assert_eq!(
        cutover.begin(context, &installation("1.2.3", 'a'), &definitions),
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "completed service restoration could not be cleared",
        })
    );
    assert_eq!(history(&events), [CutoverEvent::Read, CutoverEvent::Remove]);
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .map(CoreServiceCutoverRecord::phase),
        Some(CoreServiceCutoverPhase::Restored)
    );
}

// Rejects a platform-mismatched replacement set before persistence or native observation.
#[test]
fn definition_set_mismatch_fails_before_snapshot() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let linux = definitions(CoreProcessPlatform::Linux);
    let (provider, _, events) = provider(None, CutoverFailure::None, CutoverFailure::None);
    assert!(matches!(
        provider.begin(context, &installation("1.2.3", 'a'), &linux),
        Err(CoreServiceSetupError::InvalidContract { .. })
    ));
    assert!(history(&events).is_empty());
}

// Round-trips the closed nested-schema JSON record in every lifecycle phase.
#[test]
fn durable_record_json_round_trips_every_phase() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let definitions = definitions(CoreProcessPlatform::Linux);
    let prepared = prepared_record(context, installation("1.2.3-rc.4", 'a'), &definitions);
    for phase in [
        CoreServiceCutoverPhase::Prepared,
        CoreServiceCutoverPhase::Restoring,
        CoreServiceCutoverPhase::Restored,
        CoreServiceCutoverPhase::Committed,
    ] {
        let record = record_in_phase(prepared.clone(), phase);
        let bytes = record.encoded_json().expect("encode");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["schema"]["name"], "li_core_service_cutover");
        assert_eq!(value["schema"]["version"], 1);
        assert_eq!(
            value["definitions"].as_array().expect("definitions").len(),
            3
        );
        assert_eq!(
            CoreServiceCutoverRecord::decode_json(&bytes).expect("decode"),
            record
        );
    }
}

// Rejects unknown fields, unsupported schema, noncanonical base64, and tampered receipts.
#[test]
fn durable_record_json_fails_closed_on_structural_and_identity_mutation() {
    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Child);
    let record = prepared_record(
        context,
        installation("1.2.3", 'a'),
        &definitions(CoreProcessPlatform::Macos),
    );
    let original: serde_json::Value =
        serde_json::from_slice(&record.encoded_json().expect("encode")).expect("JSON");
    for mutation in ["unknown", "schema", "base64", "receipt"] {
        let mut value = original.clone();
        match mutation {
            "unknown" => {
                value
                    .as_object_mut()
                    .expect("object")
                    .insert("unexpected".to_string(), serde_json::json!(true));
            }
            "schema" => value["schema"]["version"] = serde_json::json!(2),
            "base64" => value["native_snapshot"]["bytes_base64"] = serde_json::json!("@@=="),
            "receipt" => value["receipt_id"] = serde_json::json!("f".repeat(64)),
            _ => unreachable!(),
        }
        assert!(CoreServiceCutoverRecord::decode_json(
            &serde_json::to_vec(&value).expect("mutated JSON")
        )
        .is_err());
    }
}

// Proves the distributed schema matches every phase and exact Linux startup identity order.
#[test]
fn top_level_cutover_schema_matches_runtime_state_machine() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_service_cutover_v1.schema.json"
    ))
    .expect("schema");
    assert_eq!(
        schema["properties"]["phase"]["enum"],
        serde_json::json!(["prepared", "restoring", "restored", "committed"])
    );
    let linux = schema["allOf"][0]["then"]["properties"]["definitions"]["prefixItems"]
        .as_array()
        .expect("Linux definitions");
    assert_eq!(
        linux
            .iter()
            .map(|item| item["properties"]["service_identity"]["const"]
                .as_str()
                .expect("service identity"))
            .collect::<Vec<_>>(),
        [
            "li_node.service",
            "li_watchdog.service",
            "li_gateway.service",
        ]
    );
}
