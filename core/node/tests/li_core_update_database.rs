// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    ActivatedCoreUpdate, CoreInstallation, CoreServiceSnapshot, CoreUpdatePhase, CoreUpdateRecord,
    CoreUpdateStore, CoreUpdateStoreError, CoreVersion, PreparedCoreUpdate,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::DatabaseCoreUpdateStore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Opens one isolated database manager with deterministic native time.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path)
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    )
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns the deterministic manager update identity for one replay key.
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
fn installation(version: &str, character: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        digest(character),
    )
}

// Returns one validated requested update journal.
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

// Returns one structurally complete successful update journal.
fn succeeded_record(idempotency_key: &str) -> CoreUpdateRecord {
    let current = installation("1.0.0", '1');
    let candidate = installation("1.1.0", '2');
    CoreUpdateRecord::restore(
        update_id(idempotency_key),
        idempotency_key,
        Some(CoreVersion::parse("1.1.0").expect("version")),
        CoreUpdatePhase::Succeeded,
        Some(current.clone()),
        Some(PreparedCoreUpdate::new(digest('3'), candidate.clone())),
        Some(CoreServiceSnapshot::new(digest('4'))),
        Some(ActivatedCoreUpdate::new(digest('5'), current, candidate).expect("activation")),
        None,
    )
    .expect("succeeded record")
}

// Creates, replaces, and replays exact journals with optimistic revisions.
#[test]
fn update_store_enforces_create_replace_and_replay_contracts() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory.path().join("core.sqlite3"));
    let store = DatabaseCoreUpdateStore::new(database);
    let requested = requested_record("update", Some("1.1.0"));
    let created = store.create(requested.clone()).expect("create");
    assert_eq!(created.revision(), 1);
    let replay = store.create(requested).expect("create replay");
    assert_eq!(replay.revision(), 1);
    assert_eq!(
        store.create(requested_record("update", Some("1.2.0"))),
        Err(CoreUpdateStoreError::Conflict)
    );

    let succeeded = succeeded_record("update");
    let replaced = store.replace(succeeded.clone(), 1).expect("replace");
    assert_eq!(replaced.revision(), 2);
    let replace_replay = store.replace(succeeded.clone(), 1).expect("replace replay");
    assert_eq!(replace_replay.revision(), 2);
    assert_eq!(
        store.replace(requested_record("update", Some("1.1.0")), 1),
        Err(CoreUpdateStoreError::Conflict)
    );
    assert_eq!(
        store
            .read("update")
            .expect("read")
            .expect("stored")
            .record(),
        &succeeded
    );
    let records = store.records().expect("all records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record(), &succeeded);
}

// Reconstructs a complete terminal journal after DatabaseManager restart.
#[test]
fn update_store_round_trips_complete_journal_after_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let database_manager = database(&path);
    let store = DatabaseCoreUpdateStore::new(Arc::clone(&database_manager));
    let expected = succeeded_record("restart");
    store.create(expected.clone()).expect("create");
    drop(store);
    Arc::try_unwrap(database_manager)
        .map_err(|_| "database reference")
        .expect("database ownership")
        .close()
        .expect("close");

    let database_manager = database(&path);
    let reopened = DatabaseCoreUpdateStore::new(database_manager);
    assert_eq!(
        reopened
            .read("restart")
            .expect("read")
            .expect("stored")
            .record(),
        &expected
    );
}

// Rejects a structurally corrupted persisted phase instead of fabricating receipts.
#[test]
fn update_store_fails_closed_on_semantic_corruption() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let database_manager = database(&path);
    let store = DatabaseCoreUpdateStore::new(Arc::clone(&database_manager));
    store
        .create(requested_record("corrupt", None))
        .expect("create");
    drop(store);
    Arc::try_unwrap(database_manager)
        .map_err(|_| "database reference")
        .expect("database ownership")
        .close()
        .expect("close");

    let connection = Connection::open(&path).expect("SQLite");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
            params!["core_updates", "corrupt"],
            |row| row.get(0),
        )
        .expect("payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    value["phase"] = serde_json::Value::String("succeeded".to_string());
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&value).expect("encoded"),
                "core_updates",
                "corrupt"
            ],
        )
        .expect("corrupt payload");
    drop(connection);

    let database_manager = database(&path);
    let reopened = DatabaseCoreUpdateStore::new(database_manager);
    assert_eq!(reopened.read("corrupt"), Err(CoreUpdateStoreError::Corrupt));
    assert_eq!(reopened.records(), Err(CoreUpdateStoreError::Corrupt));
}

// Rejects foreign schema identity and unknown fields without reviving an older journal shape.
#[test]
fn update_store_rejects_schema_and_unknown_field_tampering() {
    for mutation in 0..3 {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("core.sqlite3");
        {
            let store = DatabaseCoreUpdateStore::new(database(&path));
            store
                .create(requested_record("schema-tamper", None))
                .expect("create");
        }
        let connection = Connection::open(&path).expect("SQLite");
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["core_updates", "schema-tamper"],
                |row| row.get(0),
            )
            .expect("payload");
        let mut document: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
        match mutation {
            0 => document["schema"]["name"] = serde_json::json!("foreign_update_record"),
            1 => document["schema"]["version"] = serde_json::json!(2),
            2 => document["unexpected"] = serde_json::json!(true),
            _ => unreachable!("closed mutation matrix"),
        }
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
                params![
                    serde_json::to_vec(&document).expect("encoded"),
                    "core_updates",
                    "schema-tamper"
                ],
            )
            .expect("tamper payload");
        drop(connection);
        let reopened = DatabaseCoreUpdateStore::new(database(&path));
        assert_eq!(
            reopened.read("schema-tamper"),
            Err(CoreUpdateStoreError::Corrupt)
        );
    }
}

// Keeps the Update-owned checked-in journal schema aligned with the persisted codec.
#[test]
fn checked_in_update_schema_matches_the_database_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/update/li_core_update_record_v1.schema.json"
    ))
    .expect("update schema");
    assert_eq!(
        schema["$id"],
        serde_json::json!(
            "https://letsinfer.ai/schemas/update/li_core_update_record_v1.schema.json"
        )
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        serde_json::json!("li_core_update_record")
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        serde_json::json!(1)
    );
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    assert_eq!(
        schema["properties"]["schema"]["additionalProperties"],
        serde_json::json!(false)
    );
}
