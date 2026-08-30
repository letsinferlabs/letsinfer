// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateResidentService, CoreUpdateServiceContext,
    CoreUpdateServicePlatform, CoreUpdateServiceSnapshotRecord, CoreUpdateServiceSnapshotStore,
    CoreUpdateServiceState, CoreVersion,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::DatabaseCoreUpdateServiceSnapshotStore;
use rusqlite::{params, Connection};

// Returns one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Opens one isolated database with a short deterministic write-lock bound.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path).with_busy_timeout(Duration::from_millis(20)),
        )
        .expect("database"),
    )
}

// Returns one complete role-appropriate service snapshot fixture.
fn snapshot(
    update_character: char,
    source_character: char,
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
) -> CoreUpdateServiceSnapshotRecord {
    let current = CoreInstallation::new(
        CoreVersion::parse("1.0.0").expect("version"),
        digest(source_character),
    );
    let context = CoreUpdateServiceContext::new(platform, role);
    let mut services = vec![CoreUpdateResidentService::Node];
    if platform == CoreUpdateServicePlatform::Linux {
        services.push(CoreUpdateResidentService::Watchdog);
    }
    services.push(CoreUpdateResidentService::Gateway);
    let services = services
        .into_iter()
        .map(|service| {
            CoreUpdateServiceState::new(
                service,
                Some(current.source_identity().clone()),
                Some(current.source_identity().clone()),
            )
            .expect("service")
        })
        .collect();
    CoreUpdateServiceSnapshotRecord::new(digest(update_character), current, context, services)
        .expect("snapshot")
}

// Round-trips every platform-role shape and reconstructs exact state after restart.
#[test]
fn snapshot_store_round_trips_role_matrix_and_restart() {
    for (index, (platform, role)) in [
        (CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        (CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child),
        (CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        (CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Child),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("core.sqlite3");
        let expected = snapshot(
            char::from_digit(u32::try_from(index + 1).expect("index"), 10).expect("character"),
            '8',
            platform,
            role,
        );
        {
            let store = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
            assert_eq!(store.read(expected.update_id()).expect("empty"), None);
            assert_eq!(store.store(expected.clone()).expect("store"), expected);
            assert_eq!(store.store(expected.clone()).expect("replay"), expected);
        }
        let reopened = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
        assert_eq!(
            reopened.read(expected.update_id()).expect("read"),
            Some(expected)
        );
    }
}

// Commits one of two divergent concurrent snapshots and rejects the other exactly.
#[test]
fn snapshot_store_has_one_winner_for_divergent_replay_identity() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Arc::new(DatabaseCoreUpdateServiceSnapshotStore::new(database(
        &directory.path().join("core.sqlite3"),
    )));
    let barrier = Arc::new(Barrier::new(3));
    let handles = ['7', '8']
        .into_iter()
        .map(|source| {
            let store = store.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let proposed = snapshot(
                    '1',
                    source,
                    CoreUpdateServicePlatform::Linux,
                    CoreUpdateNodeRole::Main,
                );
                barrier.wait();
                store.store(proposed)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    let authoritative = store.read(&digest('1')).expect("read").expect("snapshot");
    assert!(results
        .iter()
        .any(|result| result.as_ref().ok() == Some(&authoritative)));
}

// Rejects a content mutation whose stored receipt no longer authenticates the snapshot.
#[test]
fn snapshot_store_rejects_semantic_database_corruption() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("core.sqlite3");
    let expected = snapshot(
        '1',
        '7',
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Child,
    );
    {
        let store = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
        store.store(expected.clone()).expect("store");
    }
    let connection = Connection::open(&path).expect("connection");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records
             WHERE collection = ?1 AND identifier = ?2",
            params![
                "core_update_service_snapshots",
                expected.update_id().as_str()
            ],
            |row| row.get(0),
        )
        .expect("payload");
    let mut document: serde_json::Value = serde_json::from_slice(&payload).expect("document");
    document["current_source_identity"] =
        serde_json::Value::String(digest('6').as_str().to_string());
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1
             WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&document).expect("payload"),
                "core_update_service_snapshots",
                expected.update_id().as_str()
            ],
        )
        .expect("corrupt");
    drop(connection);
    let reopened = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
    let error = reopened.read(expected.update_id()).expect_err("corruption");
    assert!(error.to_string().contains("snapshot is corrupt"));
}

// Rejects the retired singular-runtime snapshot instead of reviving cross-manager ownership.
#[test]
fn snapshot_store_rejects_retired_runtime_schema() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("core.sqlite3");
    let expected = snapshot(
        '2',
        '7',
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
    );
    {
        let store = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
        store.store(expected.clone()).expect("store");
    }
    let connection = Connection::open(&path).expect("connection");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records
             WHERE collection = ?1 AND identifier = ?2",
            params![
                "core_update_service_snapshots",
                expected.update_id().as_str()
            ],
            |row| row.get(0),
        )
        .expect("payload");
    let mut document: serde_json::Value = serde_json::from_slice(&payload).expect("document");
    document["schema"]["version"] = serde_json::Value::from(1);
    document["runtime"] = serde_json::json!({
        "selection_identity": digest('9').as_str(),
        "loaded_identity": null,
        "active_identity": null,
        "intended_active": false
    });
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1
             WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&document).expect("payload"),
                "core_update_service_snapshots",
                expected.update_id().as_str()
            ],
        )
        .expect("replace");
    drop(connection);
    let reopened = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
    assert!(reopened.read(expected.update_id()).is_err());
}

// Keeps the Update-owned checked-in snapshot schema aligned with the persisted codec.
#[test]
fn checked_in_snapshot_schema_matches_the_database_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/update/li_core_update_service_snapshot_v2.schema.json"
    ))
    .expect("snapshot schema");
    assert_eq!(
        schema["$id"],
        serde_json::json!(
            "https://letsinfer.ai/schemas/update/li_core_update_service_snapshot_v2.schema.json"
        )
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        serde_json::json!("li_core_update_service_snapshot")
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        serde_json::json!(2)
    );
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    assert_eq!(
        schema["properties"]["schema"]["additionalProperties"],
        serde_json::json!(false)
    );
}

// Maps a deterministic native write-lock failure to one redacted store boundary.
#[test]
fn snapshot_store_redacts_database_write_failure() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("core.sqlite3");
    let store = DatabaseCoreUpdateServiceSnapshotStore::new(database(&path));
    let connection = Connection::open(&path).expect("connection");
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .expect("write lock");
    let error = store
        .store(snapshot(
            '1',
            '7',
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        ))
        .expect_err("locked");
    assert_eq!(
        error.to_string(),
        "Core update service snapshot store failed: durable service snapshot state is unavailable"
    );
    connection.execute_batch("ROLLBACK").expect("rollback");
}
