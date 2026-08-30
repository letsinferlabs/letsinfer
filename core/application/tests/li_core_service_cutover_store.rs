// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, hard_link};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use li_core_application::{
    CoreProcessLayout, CoreProcessPlatform, CoreServiceCutoverNativeSnapshot,
    CoreServiceCutoverPhase, CoreServiceCutoverReceipt, CoreServiceCutoverRecord,
    CoreServiceCutoverStore, CoreServiceDefinition, CoreServiceDefinitionProvider,
    SystemCoreServiceCutoverStore,
};
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};

// Creates one owner-private store tree inside an isolated temporary directory.
fn store_fixture() -> (
    tempfile::TempDir,
    PathBuf,
    u32,
    SystemCoreServiceCutoverStore,
) {
    let temporary = tempfile::tempdir().expect("temporary");
    let home = temporary.path().join("letsinfer");
    let state = home.join("state");
    let cutover = state.join("service_cutover");
    for directory in [&home, &state, &cutover] {
        fs::create_dir(directory).expect("directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    let owner = fs::metadata(&home).expect("metadata").uid();
    let store =
        SystemCoreServiceCutoverStore::new(home.clone(), owner).expect("system store fixture");
    (temporary, home, owner, store)
}

// Creates one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one immutable installation fixture.
fn installation(version: &str, identity: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(identity),
    )
}

// Generates one exact platform resident definition set.
fn definitions(platform: CoreProcessPlatform) -> Vec<CoreServiceDefinition> {
    let layout = CoreProcessLayout::new(
        platform,
        PathBuf::from("/opt/letsinfer/core/versions/1.2.3/identity"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
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

// Creates one prepared record with distinct installation and snapshot identities.
fn record(version: &str, identity: char, snapshot: &[u8]) -> CoreServiceCutoverRecord {
    CoreServiceCutoverRecord::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        installation(version, identity),
        &definitions(CoreProcessPlatform::Linux),
        CoreServiceCutoverNativeSnapshot::new(snapshot.to_vec()).expect("snapshot"),
    )
    .expect("record")
}

// Returns the fixed record path beneath one store home.
fn record_path(home: &Path) -> PathBuf {
    home.join("state/service_cutover/li_core_service_cutover.json")
}

// Persists, restarts, commits, and removes one exact owner-only record.
#[test]
fn system_store_round_trips_every_lifecycle_phase_with_private_files() {
    let (_temporary, home, owner, store) = store_fixture();
    assert_eq!(store.read().expect("empty read"), None);
    let proposed = record("1.2.3", 'a', b"native-a");
    let stored = store.create(proposed.clone()).expect("create");
    assert_eq!(stored, proposed);
    assert_eq!(store.read().expect("read"), Some(proposed.clone()));
    let path = record_path(&home);
    let metadata = fs::metadata(&path).expect("record metadata");
    assert_eq!(metadata.uid(), owner);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let restarted = SystemCoreServiceCutoverStore::new(home.clone(), owner).expect("restart");
    assert_eq!(
        restarted.read().expect("restart read"),
        Some(proposed.clone())
    );
    let receipt = CoreServiceCutoverReceipt::new(proposed.receipt_id().clone());
    let committed = restarted
        .transition(
            &receipt,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Committed,
        )
        .expect("commit");
    assert_eq!(committed.phase(), CoreServiceCutoverPhase::Committed);
    assert!(restarted
        .transition(
            &receipt,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Committed,
        )
        .is_err());
    restarted.remove(&receipt).expect("remove");
    assert_eq!(restarted.read().expect("final read"), None);
    let lock = home.join("state/service_cutover/.li_core_service_cutover.lock");
    let metadata = fs::metadata(lock).expect("lock metadata");
    assert_eq!(metadata.uid(), owner);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

// Serializes concurrent creates so every caller receives one authoritative winner.
#[test]
fn concurrent_create_returns_one_exact_authoritative_record() {
    let (_temporary, _home, _owner, store) = store_fixture();
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(3));
    let first = record("1.2.3", 'a', b"native-a");
    let second = record("2.0.0", 'b', b"native-b");
    let workers = [first.clone(), second.clone()]
        .into_iter()
        .map(|candidate| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.create(candidate).expect("concurrent create")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(results[0], results[1]);
    assert!(results[0] == first || results[0] == second);
    assert_eq!(store.read().expect("read"), Some(results[0].clone()));
}

// Rejects receipt confusion without changing the authoritative record.
#[test]
fn receipt_mismatch_cannot_commit_or_remove_another_record() {
    let (_temporary, _home, _owner, store) = store_fixture();
    let proposed = record("1.2.3", 'a', b"native-a");
    store.create(proposed.clone()).expect("create");
    let foreign = CoreServiceCutoverReceipt::new(digest('f'));
    assert!(store
        .transition(
            &foreign,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Committed,
        )
        .is_err());
    assert!(store.remove(&foreign).is_err());
    assert_eq!(store.read().expect("read"), Some(proposed));
}

// Persists only the exact prepared-to-restoring-to-restored lifecycle edges.
#[test]
fn restoration_transitions_require_the_expected_phase() {
    let (_temporary, _home, _owner, store) = store_fixture();
    let proposed = record("1.2.3", 'a', b"native-a");
    store.create(proposed.clone()).expect("create");
    let receipt = CoreServiceCutoverReceipt::new(proposed.receipt_id().clone());
    assert!(store
        .transition(
            &receipt,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Restored,
        )
        .is_err());
    let restoring = store
        .transition(
            &receipt,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Restoring,
        )
        .expect("restoring");
    assert_eq!(restoring.phase(), CoreServiceCutoverPhase::Restoring);
    assert!(store
        .transition(
            &receipt,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Committed,
        )
        .is_err());
    let restored = store
        .transition(
            &receipt,
            CoreServiceCutoverPhase::Restoring,
            CoreServiceCutoverPhase::Restored,
        )
        .expect("restored");
    assert_eq!(restored.phase(), CoreServiceCutoverPhase::Restored);
    assert_eq!(store.read().expect("read"), Some(restored));
}

// Fails closed for loose modes, symlinks, hardlinks, malformed bytes, and oversized records.
#[test]
fn unsafe_record_files_are_never_read_or_replaced() {
    let (_temporary, home, owner, store) = store_fixture();
    let path = record_path(&home);
    let source = home.join("state/service_cutover/source");

    fs::write(&path, b"{}").expect("loose record");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose mode");
    assert!(store.read().is_err());
    fs::remove_file(&path).expect("remove loose record");

    fs::write(&source, b"{}").expect("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
    symlink(&source, &path).expect("symlink");
    assert!(store.read().is_err());
    fs::remove_file(&path).expect("remove symlink");

    hard_link(&source, &path).expect("hardlink");
    assert!(store.read().is_err());
    fs::remove_file(&path).expect("remove hardlink");
    fs::remove_file(&source).expect("remove source");

    fs::write(&path, b"not-json").expect("malformed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("malformed mode");
    assert!(store.read().is_err());
    fs::remove_file(&path).expect("remove malformed");

    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    fs::write(&path, oversized).expect("oversized");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("oversized mode");
    assert!(store.read().is_err());
    assert!(SystemCoreServiceCutoverStore::new(home, owner).is_ok());
}

// Rejects missing, loose, foreign-shaped, and symlinked private directory chains.
#[test]
fn store_requires_the_exact_owner_private_directory_chain() {
    let temporary = tempfile::tempdir().expect("temporary");
    let owner = fs::metadata(temporary.path()).expect("metadata").uid();
    let missing = temporary.path().join("missing");
    assert!(SystemCoreServiceCutoverStore::new(missing, owner).is_err());

    let home = temporary.path().join("home");
    let state = home.join("state");
    let cutover = state.join("service_cutover");
    fs::create_dir(&home).expect("home");
    fs::create_dir(&state).expect("state");
    fs::create_dir(&cutover).expect("cutover");
    for directory in [&home, &state, &cutover] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).expect("loose state");
    assert!(SystemCoreServiceCutoverStore::new(home.clone(), owner).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("private state");
    fs::remove_dir(&cutover).expect("remove cutover");
    symlink(temporary.path(), &cutover).expect("cutover symlink");
    assert!(SystemCoreServiceCutoverStore::new(home, owner).is_err());
}
