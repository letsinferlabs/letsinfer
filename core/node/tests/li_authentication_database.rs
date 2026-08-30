// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyMaterialProvider, ApiKeyModelScope, ApiKeyPolicy,
    AuthenticationClock, AuthenticationError, AuthenticationManager, AuthenticationRecord,
    AuthenticationStore, AuthenticationStoreError,
};
use li_core_interface::{ApiKeyId, DisplayName, LogicalModelName, UnixMilliseconds};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::DatabaseAuthenticationStore;
use rusqlite::{params, Connection};

// Supplies deterministic unique bytes for integration key material.
struct TestMaterial {
    next_value: AtomicU8,
}

impl TestMaterial {
    // Creates deterministic material beginning with one exact byte.
    fn new(first_value: u8) -> Self {
        Self {
            next_value: AtomicU8::new(first_value),
        }
    }
}

impl ApiKeyMaterialProvider for TestMaterial {
    // Fills each requested buffer with the next deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        destination.fill(self.next_value.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Supplies mutable deterministic time to integration tests.
struct TestClock {
    value: AtomicU64,
}

impl TestClock {
    // Creates one deterministic authentication clock.
    fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
        }
    }
}

impl AuthenticationClock for TestClock {
    // Returns the currently configured timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(self.value.load(Ordering::SeqCst)))
    }
}

// Opens one isolated real DatabaseManager.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1)),
        )
        .expect("database manager"),
    )
}

// Returns one unrestricted policy fixture.
fn policy() -> ApiKeyPolicy {
    ApiKeyPolicy::new(
        ApiKeyModelScope::all(),
        None,
        ApiKeyLimits::default(),
        None,
        None,
    )
}

// Returns one deterministic private store record without plaintext secret material.
fn record(character: char, name: &str, revoked_at: Option<u64>) -> AuthenticationRecord {
    AuthenticationRecord::new(
        ApiKey::new(
            ApiKeyId::parse(&character.to_string().repeat(32)).expect("API key identity"),
            DisplayName::parse(name).expect("name"),
            policy(),
            UnixMilliseconds::new(1_000),
            revoked_at.map(UnixMilliseconds::new),
            None,
        )
        .expect("API key"),
        [3; 16],
        [4; 32],
    )
}

// Persists key policy and verifier state without writing the bearer secret.
#[test]
fn authentication_manager_uses_real_database_without_storing_secret() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory);
    let store = Arc::new(DatabaseAuthenticationStore::new(database.clone()));
    let manager = AuthenticationManager::new(
        store.clone(),
        Arc::new(TestMaterial::new(1)),
        Arc::new(TestClock::new(1_000)),
    );
    let mut created = manager
        .create(DisplayName::parse("Local client").expect("name"), policy())
        .expect("create API key");
    let token = created.value_mut().take_token().expect("issued token");
    let secret = token.rsplit('_').next().expect("secret");
    assert!(manager
        .authenticate(&token, &LogicalModelName::parse("qwen3.8").expect("model"))
        .is_ok());
    for path in [
        directory.path().join("core.sqlite3"),
        directory.path().join("core.sqlite3-wal"),
        directory.path().join("core.sqlite3-shm"),
    ] {
        if path.is_file() {
            let bytes = std::fs::read(path).expect("database bytes");
            assert!(!contains_bytes(&bytes, token.as_bytes()));
            assert!(!contains_bytes(&bytes, secret.as_bytes()));
        }
    }

    drop(manager);
    let reconstructed = AuthenticationManager::new(
        store,
        Arc::new(TestMaterial::new(20)),
        Arc::new(TestClock::new(1_100)),
    );
    assert!(reconstructed
        .authenticate(&token, &LogicalModelName::parse("qwen3.8").expect("model"))
        .is_ok());
}

// Rolls back revocation when the replacement identity already exists.
#[test]
fn authentication_store_rotates_both_records_atomically() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory);
    let store = DatabaseAuthenticationStore::new(database);
    let old = store.create(record('a', "Old", None)).expect("old key");
    store
        .create(record('b', "Existing", None))
        .expect("existing replacement");
    assert_eq!(
        store
            .rotate(
                record('a', "Old", Some(2_000)),
                old.revision(),
                record('b', "Replacement", None),
            )
            .expect_err("rotation must roll back"),
        AuthenticationStoreError::Conflict
    );
    let observed = store
        .read(&ApiKeyId::parse(&"a".repeat(32)).expect("old identity"))
        .expect("read old key")
        .expect("old key");
    assert!(observed.record().api_key().revoked_at().is_none());
    assert_eq!(observed.revision(), 1);
}

// Rejects nested schema, unknown-field, identity, and policy corruption after restart.
#[test]
fn authentication_store_rejects_persisted_schema_and_semantic_tampering() {
    for mutation in 0..5 {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("core.sqlite3");
        let key_id = ApiKeyId::parse(&"a".repeat(32)).expect("key identity");
        {
            let store = DatabaseAuthenticationStore::new(database(&directory));
            store
                .create(record('a', "Stored key", None))
                .expect("stored key");
        }
        let connection = Connection::open(&path).expect("raw database");
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["authentication", key_id.as_str()],
                |row| row.get(0),
            )
            .expect("payload");
        let mut document: serde_json::Value =
            serde_json::from_slice(&payload).expect("authentication document");
        match mutation {
            0 => document["schema"]["name"] = serde_json::json!("foreign.authentication"),
            1 => document["schema"]["version"] = serde_json::json!(2),
            2 => document["unexpected"] = serde_json::json!(true),
            3 => document["concurrency"] = serde_json::json!(0),
            4 => document["key_id"] = serde_json::json!("b".repeat(32)),
            _ => unreachable!("closed mutation matrix"),
        }
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
                params![
                    serde_json::to_vec(&document).expect("mutated payload"),
                    "authentication",
                    key_id.as_str()
                ],
            )
            .expect("tamper payload");
        drop(connection);

        let reopened = DatabaseAuthenticationStore::new(database(&directory));
        assert_eq!(
            reopened.read(&key_id).expect_err("tampering must fail"),
            AuthenticationStoreError::Corrupt
        );
    }
}

// Keeps the AuthenticationManager-owned checked-in schema aligned with the persisted codec.
#[test]
fn checked_in_authentication_schema_matches_the_database_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/authentication/li_authentication_record_v1.schema.json"
    ))
    .expect("authentication schema");
    assert_eq!(
        schema["$id"],
        serde_json::json!(
            "https://letsinfer.ai/schemas/authentication/li_authentication_record_v1.schema.json"
        )
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        serde_json::json!("li_authentication_record")
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

// Returns whether one exact byte sequence occurs in a larger buffer.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
