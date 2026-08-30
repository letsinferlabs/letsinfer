// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use li_core_application::{
    ApplicationCoreUpdateAdmissionProvider, ApplicationCoreUpdateJournalSource,
    ApplicationCoreUpdateOperationSource, ApplicationCoreUpdatePruneReferenceProvider,
    CoreSetupError, CoreSetupExecutionLock, CoreSetupExecutionLockProvider,
};
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateAdmissionLease, CoreUpdateAdmissionProvider, CoreUpdateError,
    CoreUpdatePhase, CoreUpdatePruneReferenceProvider, CoreUpdateRecord, CoreUpdateStore,
    CoreVersion, PreparedCoreUpdate,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::DatabaseCoreUpdateStore;
use sha2::{Digest, Sha256};

// Returns one canonical digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Derives the manager's exact replay identity for one fixture key.
fn update_id(key: &str) -> Sha256Digest {
    let mut digest = Sha256::new();
    let domain = b"li_core_update_v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((key.len() as u64).to_be_bytes());
    digest.update(key.as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).expect("update identity")
}

// Returns one immutable Core installation fixture.
fn installation(version: &str, character: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(character),
    )
}

// Holds one inert cross-process lock fixture.
struct SetupLock;

impl CoreSetupExecutionLock for SetupLock {}

// Supplies one deterministic setup/update lock decision and call count.
struct SetupLocks {
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl CoreSetupExecutionLockProvider for SetupLocks {
    // Grants or rejects one fixture lock without blocking.
    fn try_acquire(&self) -> Result<Box<dyn CoreSetupExecutionLock>, CoreSetupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(CoreSetupError::Busy)
        } else {
            Ok(Box::new(SetupLock))
        }
    }
}

// Supplies one exact Node operation observation.
struct Operations {
    active: AtomicBool,
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl ApplicationCoreUpdateOperationSource for Operations {
    // Returns the configured active or unavailable operation state.
    fn has_active_operation(&self) -> Result<bool, CoreUpdateError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(CoreUpdateError::provider(
                "test operations",
                "operation state is unavailable",
            ))
        } else {
            Ok(self.active.load(Ordering::SeqCst))
        }
    }
}

// Supplies one exact durable journal conflict observation.
struct Journals {
    conflict: AtomicBool,
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl ApplicationCoreUpdateJournalSource for Journals {
    // Returns the configured conflict or unavailable journal state.
    fn has_conflicting_journal(&self, _update_id: &Sha256Digest) -> Result<bool, CoreUpdateError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(CoreUpdateError::provider(
                "test journals",
                "journal state is unavailable",
            ))
        } else {
            Ok(self.conflict.load(Ordering::SeqCst))
        }
    }
}

// Builds one admission fixture with independently controlled boundaries.
fn admission(
    lock_failure: bool,
    active_operation: bool,
    operation_failure: bool,
    journal_conflict: bool,
    journal_failure: bool,
) -> (
    ApplicationCoreUpdateAdmissionProvider,
    Arc<SetupLocks>,
    Arc<Operations>,
    Arc<Journals>,
) {
    let locks = Arc::new(SetupLocks {
        fail: AtomicBool::new(lock_failure),
        calls: AtomicUsize::new(0),
    });
    let operations = Arc::new(Operations {
        active: AtomicBool::new(active_operation),
        fail: AtomicBool::new(operation_failure),
        calls: AtomicUsize::new(0),
    });
    let journals = Arc::new(Journals {
        conflict: AtomicBool::new(journal_conflict),
        fail: AtomicBool::new(journal_failure),
        calls: AtomicUsize::new(0),
    });
    (
        ApplicationCoreUpdateAdmissionProvider::new(
            locks.clone(),
            operations.clone(),
            journals.clone(),
        ),
        locks,
        operations,
        journals,
    )
}

// Proves every admission failure stops before the next authority is consulted.
#[test]
fn admission_fails_closed_in_lock_operation_and_journal_order() {
    for (values, expected_calls) in [
        ((true, false, false, false, false), (1, 0, 0)),
        ((false, true, false, false, false), (1, 1, 0)),
        ((false, false, true, false, false), (1, 1, 0)),
        ((false, false, false, true, false), (1, 1, 1)),
        ((false, false, false, false, true), (1, 1, 1)),
    ] {
        let (provider, locks, operations, journals) =
            admission(values.0, values.1, values.2, values.3, values.4);
        assert!(provider.acquire(&digest('1')).is_err());
        assert_eq!(locks.calls.load(Ordering::SeqCst), expected_calls.0);
        assert_eq!(operations.calls.load(Ordering::SeqCst), expected_calls.1);
        assert_eq!(journals.calls.load(Ordering::SeqCst), expected_calls.2);
    }
}

// Grants ownership only after all three explicit admission authorities agree.
#[test]
fn admission_grants_one_complete_lease_after_all_checks() {
    let (provider, locks, operations, journals) = admission(false, false, false, false, false);
    let lease: Box<dyn CoreUpdateAdmissionLease> =
        provider.acquire(&digest('1')).expect("admission");
    drop(lease);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 1);
    assert_eq!(operations.calls.load(Ordering::SeqCst), 1);
    assert_eq!(journals.calls.load(Ordering::SeqCst), 1);
}

// Opens one isolated shared database and strict update store.
fn update_store(directory: &tempfile::TempDir) -> Arc<DatabaseCoreUpdateStore> {
    Arc::new(DatabaseCoreUpdateStore::new(Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    )))
}

// Creates one nonterminal prepared journal carrying previous, candidate, and workspace identities.
fn prepared_record(key: &str) -> CoreUpdateRecord {
    CoreUpdateRecord::restore(
        update_id(key),
        key,
        Some(CoreVersion::parse("1.1.0").expect("version")),
        CoreUpdatePhase::Prepared,
        Some(installation("1.0.0", '1')),
        Some(PreparedCoreUpdate::new(
            digest('2'),
            installation("1.1.0", '3'),
        )),
        None,
        None,
        None,
    )
    .expect("prepared record")
}

// Binds admission conflicts and prune retention to the same validated durable journal set.
#[test]
fn database_journals_block_foreign_updates_and_retain_exact_recovery_state() {
    let directory = tempfile::tempdir().expect("directory");
    let updates = update_store(&directory);
    let record = prepared_record("prepared");
    updates.create(record.clone()).expect("create");
    assert!(!updates
        .has_conflicting_journal(record.update_id())
        .expect("same update"));
    assert!(updates
        .has_conflicting_journal(&digest('f'))
        .expect("foreign update"));

    let references = ApplicationCoreUpdatePruneReferenceProvider::new(updates)
        .references(&digest('f'), &installation("2.0.0", '4'))
        .expect("references");
    assert_eq!(
        references.core_installations(),
        &[installation("1.0.0", '1'), installation("1.1.0", '3')]
    );
    assert_eq!(references.update_workspaces(), &[update_id("prepared")]);
}
