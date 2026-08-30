// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_database::{
    DatabaseClock, DatabaseCollection, DatabaseCommand, DatabaseConfiguration, DatabaseError,
    DatabaseManager, DatabaseRecord, DatabaseRevision,
};
use li_node_manager::{
    DatabaseNodeSetupIdentityStore, NodeManager, NodeSetupIdentityError, NodeSetupIdentityInput,
    NODE_SETUP_IDENTITY_SCHEMA_NAME, NODE_SETUP_IDENTITY_SCHEMA_VERSION,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Supplies deterministic monotonically increasing DatabaseManager commit times.
struct TestDatabaseClock {
    next: AtomicI64,
    available: AtomicBool,
}

impl TestDatabaseClock {
    // Creates one clock beginning at the supplied non-negative millisecond.
    const fn new(first: i64) -> Self {
        Self {
            next: AtomicI64::new(first),
            available: AtomicBool::new(true),
        }
    }

    // Selects whether subsequent database commits receive a valid timestamp.
    fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }
}

impl DatabaseClock for TestDatabaseClock {
    // Returns one distinct commit time for each transaction.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        if !self.available.load(Ordering::SeqCst) {
            return Err(DatabaseError::Unavailable {
                reason: "injected commit clock failure",
            });
        }
        Ok(self.next.fetch_add(1, Ordering::SeqCst))
    }
}

// Stores one unrelated record proving setup rollback never deletes the database or foreign state.
#[derive(Clone, Deserialize, Serialize)]
struct UnrelatedRecord {
    record_id: String,
    value: String,
}

impl DatabaseRecord for UnrelatedRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Services;

    // Returns the unrelated fixture identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Proves fresh preparation atomically creates the marker, local identity, active Node, and outbox.
#[test]
fn setup_identity_creates_one_exact_four_record_closure() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let database = open_database(&path);
    let store = DatabaseNodeSetupIdentityStore::new(database);
    let prepared = store
        .prepare(input('1', "Home AI", NodeRole::Main))
        .expect("prepare");
    assert_eq!(prepared.node().identity().machine_id(), &machine_id());
    assert_eq!(
        prepared.node().identity().installation_id(),
        &installation_id()
    );
    assert_eq!(prepared.node().display_name().as_str(), "Home AI");
    assert_eq!(prepared.node().role(), NodeRole::Main);
    assert_eq!(prepared.node().state(), NodeState::Active);
    assert!(prepared.node().latest_hardware_observation_id().is_none());
    assert_eq!(record_count(&path), 4);
    assert_eq!(collection_count(&path, "configuration"), 2);
    assert_eq!(collection_count(&path, "nodes"), 1);
    assert_eq!(collection_count(&path, "outbox"), 1);
}

// Proves a process crash after provider return replays the same receipt and closure after restart.
#[test]
fn setup_identity_restarts_before_setup_journal_advance() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let database = open_database(&path);
    let store = DatabaseNodeSetupIdentityStore::new(database.clone());
    let first = store
        .prepare(input('2', "Home AI", NodeRole::Child))
        .expect("first prepare");
    drop(store);
    Arc::try_unwrap(database)
        .map_err(|_| "shared database")
        .expect("database owner")
        .close()
        .expect("database close");

    let restarted = DatabaseNodeSetupIdentityStore::new(open_database(&path));
    let replay = restarted
        .prepare(input('2', "Home AI", NodeRole::Child))
        .expect("replay");
    assert_eq!(replay, first);
    assert_eq!(record_count(&path), 4);
}

// Proves concurrent identical preparation has one physical commit and one exact returned closure.
#[test]
fn setup_identity_concurrent_same_request_has_one_winner() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let store = Arc::new(DatabaseNodeSetupIdentityStore::new(open_database(&path)));
    let entered = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let entered = entered.clone();
        workers.push(thread::spawn(move || {
            entered.wait();
            store.prepare(input('3', "Home AI", NodeRole::Main))
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker").expect("prepare"))
        .collect::<Vec<_>>();
    assert_eq!(results[0], results[1]);
    assert_eq!(record_count(&path), 4);
    assert_eq!(
        idempotency_count(&path, "li_core_setup_identity_prepare:%"),
        1
    );
}

// Proves divergent concurrent requests never merge their public identity fields.
#[test]
fn setup_identity_concurrent_divergent_requests_have_one_authority() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let store = Arc::new(DatabaseNodeSetupIdentityStore::new(open_database(&path)));
    let entered = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for (request, name, role) in [
        ('4', "Main", NodeRole::Main),
        ('5', "Child", NodeRole::Child),
    ] {
        let store = store.clone();
        let entered = entered.clone();
        workers.push(thread::spawn(move || {
            entered.wait();
            store.prepare(input(request, name, role))
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(NodeSetupIdentityError::Conflict))
            .count(),
        1
    );
    assert_eq!(record_count(&path), 4);
}

// Proves every explicit request identity field is immutable after the first preparation.
#[test]
fn setup_identity_replay_rejects_every_explicit_input_drift() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let store = DatabaseNodeSetupIdentityStore::new(open_database(&path));
    store
        .prepare(input('9', "Home AI", NodeRole::Main))
        .expect("prepare");
    let before = record_documents(&path);
    for divergent in [
        explicit_input('8', 'e', 'f', "Home AI", NodeRole::Main, "homeai.local"),
        explicit_input('9', 'd', 'f', "Home AI", NodeRole::Main, "homeai.local"),
        explicit_input('9', 'e', 'c', "Home AI", NodeRole::Main, "homeai.local"),
        explicit_input('9', 'e', 'f', "Other", NodeRole::Main, "homeai.local"),
        explicit_input('9', 'e', 'f', "Home AI", NodeRole::Child, "homeai.local"),
        explicit_input('9', 'e', 'f', "Home AI", NodeRole::Main, "other.local"),
    ] {
        assert_eq!(
            store.prepare(divergent),
            Err(NodeSetupIdentityError::Conflict)
        );
        assert_eq!(record_documents(&path), before);
    }
}

// Proves exact rollback removes all owned records, preserves foreign state, and replays safely.
#[test]
fn setup_identity_rollback_is_atomic_owned_and_idempotent() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let database = open_database(&path);
    database
        .write(DatabaseCommand::save(
            "unrelated-create",
            UnrelatedRecord {
                record_id: "unrelated".to_string(),
                value: "preserve".to_string(),
            },
            DatabaseRevision::Missing,
        ))
        .expect("unrelated record");
    let store = DatabaseNodeSetupIdentityStore::new(database);
    let prepared = store
        .prepare(input('6', "Home AI", NodeRole::Main))
        .expect("prepare");
    assert_eq!(record_count(&path), 5);
    store
        .rollback(prepared.receipt_identity())
        .expect("rollback");
    assert_eq!(record_count(&path), 1);
    assert_eq!(collection_count(&path, "services"), 1);
    store
        .rollback(prepared.receipt_identity())
        .expect("rollback replay");
    assert_eq!(record_count(&path), 1);
    let retried = store
        .prepare(input('6', "Home AI", NodeRole::Main))
        .expect("retry after rollback");
    assert_ne!(retried.receipt_identity(), prepared.receipt_identity());
    assert_eq!(record_count(&path), 5);
    store
        .rollback(retried.receipt_identity())
        .expect("retry rollback");
    assert_eq!(record_count(&path), 1);
    assert!(path.exists());
}

// Proves injected database failures never leave a partial creation or partial rollback.
#[test]
fn setup_identity_database_failures_are_atomic_and_require_recovery() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let clock = Arc::new(TestDatabaseClock::new(10_000));
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(&path)
                .with_busy_timeout(Duration::from_secs(2))
                .with_clock(clock.clone()),
        )
        .expect("database"),
    );
    let store = DatabaseNodeSetupIdentityStore::new(database);
    clock.set_available(false);
    assert_eq!(
        store.prepare(input('d', "Home AI", NodeRole::Main)),
        Err(NodeSetupIdentityError::RecoveryRequired)
    );
    assert_eq!(record_count(&path), 0);

    clock.set_available(true);
    let prepared = store
        .prepare(input('d', "Home AI", NodeRole::Main))
        .expect("prepare after recovery");
    let before = record_documents(&path);
    clock.set_available(false);
    assert_eq!(
        store.rollback(prepared.receipt_identity()),
        Err(NodeSetupIdentityError::RecoveryRequired)
    );
    assert_eq!(record_documents(&path), before);
    clock.set_available(true);
    store
        .rollback(prepared.receipt_identity())
        .expect("rollback after recovery");
    assert_eq!(record_count(&path), 0);
}

// Proves exact pre-existing NodeManager state replays without acquiring deletion ownership.
#[test]
fn setup_identity_preexisting_replay_and_rollback_are_non_mutating() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let (manager, _) =
        NodeManager::open(open_database(&path), preexisting_node(), "preexisting-node")
            .expect("node manager");
    manager.close().expect("manager close");
    let before = record_documents(&path);
    let store = DatabaseNodeSetupIdentityStore::new(open_database(&path));
    let observed = store
        .prepare(input('7', "Home AI", NodeRole::Main))
        .expect("observed");
    assert_eq!(observed.node(), &preexisting_node());
    store
        .rollback(observed.receipt_identity())
        .expect("non-owned rollback");
    assert_eq!(record_documents(&path), before);
}

// Proves a foreign receipt cannot delete setup-owned or pre-existing identity state.
#[test]
fn setup_identity_rollback_rejects_a_foreign_receipt_without_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let store = DatabaseNodeSetupIdentityStore::new(open_database(&path));
    store
        .prepare(input('8', "Home AI", NodeRole::Main))
        .expect("prepare");
    let before = record_documents(&path);
    assert_eq!(
        store.rollback(&digest('9')),
        Err(NodeSetupIdentityError::ReceiptMismatch)
    );
    assert_eq!(record_documents(&path), before);
}

// Proves revision or content drift in any owned record prevents every rollback deletion.
#[test]
fn setup_identity_rollback_requires_recovery_after_any_owned_drift() {
    for (index, target, content_drift) in [
        (0, "marker", false),
        (1, "local", false),
        (2, "node", false),
        (3, "outbox", false),
        (4, "marker", true),
        (5, "local", true),
        (6, "node", true),
        (7, "outbox", true),
        (8, "marker_deleted", false),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("core.sqlite3");
        let database = open_database(&path);
        let store = DatabaseNodeSetupIdentityStore::new(database.clone());
        let prepared = store
            .prepare(input(
                char::from_digit(index + 1, 10).expect("request"),
                "Home AI",
                NodeRole::Main,
            ))
            .expect("prepare");
        drop(store);
        Arc::try_unwrap(database)
            .map_err(|_| "shared database")
            .expect("database owner")
            .close()
            .expect("database close");
        drift_owned_record(
            &path,
            prepared.node().identity().node_id(),
            target,
            content_drift,
        );
        let store = DatabaseNodeSetupIdentityStore::new(open_database(&path));
        let before = record_documents(&path);
        assert!(matches!(
            store.rollback(prepared.receipt_identity()),
            Err(NodeSetupIdentityError::Corrupt | NodeSetupIdentityError::RecoveryRequired)
        ));
        assert_eq!(record_documents(&path), before, "target {target}");
    }
}

// Proves restart rejects unknown fields, unsupported schema, and every ownership-boundary loss.
#[test]
fn setup_identity_restart_rejects_corrupt_and_incomplete_state() {
    for mutation in ["unknown", "schema", "delete_marker", "delete_node"] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("core.sqlite3");
        let database = open_database(&path);
        let store = DatabaseNodeSetupIdentityStore::new(database.clone());
        let prepared = store
            .prepare(input('b', "Home AI", NodeRole::Main))
            .expect("prepare");
        drop(store);
        Arc::try_unwrap(database)
            .map_err(|_| "shared database")
            .expect("database owner")
            .close()
            .expect("database close");
        mutate_database(&path, prepared.node().identity().node_id(), mutation);
        let store = DatabaseNodeSetupIdentityStore::new(open_database(&path));
        assert!(matches!(
            store.prepare(input('b', "Home AI", NodeRole::Main)),
            Err(NodeSetupIdentityError::Corrupt | NodeSetupIdentityError::RecoveryRequired)
        ));
    }
}

// Proves the private payload and checked-in schema own the same exact closed field set.
#[test]
fn setup_identity_marker_matches_its_top_level_schema() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("core.sqlite3");
    let store = DatabaseNodeSetupIdentityStore::new(open_database(&path));
    store
        .prepare(input('c', "Home AI", NodeRole::Child))
        .expect("prepare");
    let payload = marker_payload(&path);
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/node/li_node_setup_identity_v1.schema.json"
    ))
    .expect("schema JSON");
    let object = payload.as_object().expect("marker object");
    let required = schema["required"].as_array().expect("required fields");
    assert_eq!(object.len(), required.len());
    assert!(required
        .iter()
        .all(|field| object.contains_key(field.as_str().expect("field"))));
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(payload["schema"]["name"], NODE_SETUP_IDENTITY_SCHEMA_NAME);
    assert_eq!(
        payload["schema"]["version"],
        NODE_SETUP_IDENTITY_SCHEMA_VERSION
    );
    let text = serde_json::to_string(&payload).expect("marker JSON");
    for forbidden in ["private_key", "api_key", "pairing_secret", "password"] {
        assert!(!text.contains(forbidden));
    }
}

// Opens one DatabaseManager with deterministic native timing and bounded contention.
fn open_database(path: &Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path)
                .with_busy_timeout(Duration::from_secs(2))
                .with_clock(Arc::new(TestDatabaseClock::new(10_000))),
        )
        .expect("database"),
    )
}

// Creates one explicit setup identity input without native discovery.
fn input(request: char, display_name: &str, role: NodeRole) -> NodeSetupIdentityInput {
    explicit_input(request, 'e', 'f', display_name, role, "homeai.local")
}

// Creates one fully selected input for immutable-field drift matrices.
fn explicit_input(
    request: char,
    machine: char,
    installation: char,
    display_name: &str,
    role: NodeRole,
    control_address: &str,
) -> NodeSetupIdentityInput {
    NodeSetupIdentityInput::new(
        digest(request),
        MachineId::parse(&machine.to_string().repeat(32)).expect("machine"),
        InstallationId::parse(&installation.to_string().repeat(64)).expect("installation"),
        DisplayName::parse(display_name).expect("display name"),
        role,
        NodeAddress::parse(control_address).expect("control address"),
        UnixMilliseconds::new(5_000),
    )
}

// Creates one exact pre-existing active local NodeManager snapshot.
fn preexisting_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"d".repeat(32)).expect("node"),
            machine_id(),
            installation_id(),
        ),
        DisplayName::parse("Home AI").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("control address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Returns one deterministic physical-machine identity.
fn machine_id() -> MachineId {
    MachineId::parse(&"e".repeat(32)).expect("machine")
}

// Returns one deterministic immutable installation identity.
fn installation_id() -> InstallationId {
    InstallationId::parse(&"f".repeat(64)).expect("installation")
}

// Returns one canonical SHA-256 identity fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Counts every live typed record without inspecting DatabaseManager internals.
fn record_count(path: &Path) -> i64 {
    Connection::open(path)
        .expect("SQLite")
        .query_row("SELECT COUNT(*) FROM li_database_records", [], |row| {
            row.get(0)
        })
        .expect("record count")
}

// Counts live records in one stable private collection.
fn collection_count(path: &Path, collection: &str) -> i64 {
    Connection::open(path)
        .expect("SQLite")
        .query_row(
            "SELECT COUNT(*) FROM li_database_records WHERE collection = ?1",
            params![collection],
            |row| row.get(0),
        )
        .expect("collection count")
}

// Counts persisted idempotency results with one exact key prefix.
fn idempotency_count(path: &Path, pattern: &str) -> i64 {
    Connection::open(path)
        .expect("SQLite")
        .query_row(
            "SELECT COUNT(*) FROM li_database_idempotency WHERE idempotency_key LIKE ?1",
            params![pattern],
            |row| row.get(0),
        )
        .expect("idempotency count")
}

// Returns every live record identity and exact payload for non-mutation comparisons.
fn record_documents(path: &Path) -> Vec<(String, String, i64, Vec<u8>)> {
    let connection = Connection::open(path).expect("SQLite");
    let mut statement = connection
        .prepare(
            "SELECT collection, identifier, revision, payload
             FROM li_database_records ORDER BY collection, identifier",
        )
        .expect("record query");
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("record rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("record documents")
}

// Reads the strict private setup marker payload as JSON.
fn marker_payload(path: &Path) -> Value {
    let bytes: Vec<u8> = Connection::open(path)
        .expect("SQLite")
        .query_row(
            "SELECT payload FROM li_database_records
             WHERE collection = 'configuration' AND identifier = 'li_core_setup_identity'",
            [],
            |row| row.get(0),
        )
        .expect("marker payload");
    serde_json::from_slice(&bytes).expect("marker JSON")
}

// Applies one direct corruption boundary while the DatabaseManager is closed.
fn mutate_database(path: &Path, node_id: &NodeId, mutation: &str) {
    let connection = Connection::open(path).expect("SQLite");
    match mutation {
        "unknown" | "schema" => {
            let mut payload = marker_payload(path);
            if mutation == "unknown" {
                payload["unknown"] = Value::Bool(true);
            } else {
                payload["schema"]["version"] = Value::from(2);
            }
            connection
                .execute(
                    "UPDATE li_database_records SET payload = ?1
                     WHERE collection = 'configuration'
                       AND identifier = 'li_core_setup_identity'",
                    params![serde_json::to_vec(&payload).expect("payload")],
                )
                .expect("marker mutation");
        }
        "delete_node" => {
            connection
                .execute(
                    "DELETE FROM li_database_records
                     WHERE collection = 'nodes' AND identifier = ?1",
                    params![node_id.as_str()],
                )
                .expect("node deletion");
        }
        "delete_marker" => {
            connection
                .execute(
                    "DELETE FROM li_database_records
                     WHERE collection = 'configuration'
                       AND identifier = 'li_core_setup_identity'",
                    [],
                )
                .expect("marker deletion");
        }
        _ => panic!("unknown mutation"),
    }
}

// Mutates one exact setup-owned record revision or payload while the manager is closed.
fn drift_owned_record(path: &Path, node_id: &NodeId, target: &str, content_drift: bool) {
    let connection = Connection::open(path).expect("SQLite");
    if target == "marker_deleted" {
        connection
            .execute(
                "DELETE FROM li_database_records
                 WHERE collection = 'configuration'
                   AND identifier = 'li_core_setup_identity'",
                [],
            )
            .expect("marker deletion");
        return;
    }
    let (collection, identifier) = match target {
        "marker" => ("configuration", "li_core_setup_identity".to_string()),
        "local" => ("configuration", "local_node_identity".to_string()),
        "node" => ("nodes", node_id.as_str().to_string()),
        "outbox" => {
            let identifier = connection
                .query_row(
                    "SELECT identifier FROM li_database_records WHERE collection = 'outbox'",
                    [],
                    |row| row.get(0),
                )
                .expect("outbox identity");
            ("outbox", identifier)
        }
        _ => panic!("unknown drift target"),
    };
    if content_drift {
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1
                 WHERE collection = ?2 AND identifier = ?3",
                params![b"{}".to_vec(), collection, identifier],
            )
            .expect("content drift");
    } else {
        connection
            .execute(
                "UPDATE li_database_records SET revision = 2
                 WHERE collection = ?1 AND identifier = ?2",
                params![collection, identifier],
            )
            .expect("revision drift");
    }
}
