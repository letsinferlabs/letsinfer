// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    DatabaseNodeProtectionSessionGenerationStore, NODE_PROTECTION_SESSION_GENERATION_SCHEMA_NAME,
    NODE_PROTECTION_SESSION_GENERATION_SCHEMA_VERSION,
};
use rusqlite::Connection;
use tempfile::TempDir;

// Supplies deterministic database commit time.
struct FixedClock;

impl DatabaseClock for FixedClock {
    // Returns one fixed valid commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(1_000)
    }
}

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical Node identity.
fn node_id() -> NodeId {
    NodeId::parse(&identity('1', 32)).expect("node")
}

// Returns one canonical Core installation identity.
fn installation_id() -> InstallationId {
    InstallationId::parse(&identity('2', 64)).expect("installation")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Opens one real private DatabaseManager at the deterministic fixture path.
fn database(root: &TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(root.path().join("li_core.db"))
                .with_clock(Arc::new(FixedClock)),
        )
        .expect("database"),
    )
}

// Proves an exact duplicate begin retry does not advance durable generation or identity.
#[test]
fn duplicate_begin_retry_replays_one_generation() {
    let root = TempDir::new().expect("temporary directory");
    let database = database(&root);
    let store = DatabaseNodeProtectionSessionGenerationStore::new(database.clone());
    let first = store
        .allocate(
            "begin-a",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('4'),
        )
        .expect("first allocation");
    let replay = store
        .allocate(
            "begin-a",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('4'),
        )
        .expect("replay allocation");

    assert_eq!(first, replay);
    assert_eq!(first.watchdog_session_generation().get(), 1);
    let connection = Connection::open(root.path().join("li_core.db")).expect("reader");
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM li_database_records WHERE identifier LIKE 'li_node_protection_session_generation_%'",
            [],
            |row| row.get(0),
        )
        .expect("revision");
    assert_eq!(revision, 1);
}

// Proves Node restart preserves generation and makes A to B to A identities non-replayable.
#[test]
fn restart_advances_generation_and_binds_nonce_to_generation() {
    let root = TempDir::new().expect("temporary directory");
    let first_session_id = {
        let database = database(&root);
        let store = DatabaseNodeProtectionSessionGenerationStore::new(database);
        let authority = store
            .allocate(
                "begin-a",
                &node_id(),
                &installation_id(),
                &digest('3'),
                &digest('4'),
            )
            .expect("first allocation");
        store.recover(&node_id()).expect("restart recovery");
        authority.watchdog_session_id().clone()
    };
    let database = database(&root);
    let store = DatabaseNodeProtectionSessionGenerationStore::new(database);
    let second = store
        .allocate(
            "begin-b",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('5'),
        )
        .expect("second allocation");
    store.retire("end-b", &second).expect("second retirement");
    let third = store
        .allocate(
            "begin-a-again",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('4'),
        )
        .expect("third allocation");

    assert_eq!(second.watchdog_session_generation().get(), 2);
    assert_eq!(third.watchdog_session_generation().get(), 3);
    assert_ne!(third.watchdog_session_id(), &first_session_id);
    assert_ne!(third.watchdog_session_id(), second.watchdog_session_id());
}

// Proves terminal retirement rejects a static begin replay but permits a fresh resident session.
#[test]
fn retired_session_rejects_static_begin_and_advances_only_for_fresh_nonce() {
    let root = TempDir::new().expect("temporary directory");
    let database = database(&root);
    let store = DatabaseNodeProtectionSessionGenerationStore::new(database);
    let first = store
        .allocate(
            "begin-a",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('4'),
        )
        .expect("first allocation");
    store.retire("end-a", &first).expect("retirement");

    assert!(store
        .allocate(
            "begin-a",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('4'),
        )
        .is_err());
    let second = store
        .allocate(
            "begin-b",
            &node_id(),
            &installation_id(),
            &digest('3'),
            &digest('5'),
        )
        .expect("fresh allocation");
    assert_eq!(second.watchdog_session_generation().get(), 2);
}

// Proves the checked-in persistence schema remains closed and matches implementation identity.
#[test]
fn checked_in_generation_schema_is_closed_and_current() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/node/li_node_protection_session_generation_v1.schema.json"
    ))
    .expect("schema");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        NODE_PROTECTION_SESSION_GENERATION_SCHEMA_NAME
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        NODE_PROTECTION_SESSION_GENERATION_SCHEMA_VERSION
    );
    assert!(schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .any(|field| field == "state"));
}
