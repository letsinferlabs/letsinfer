// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use li_database::{
    DatabaseClock, DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition,
    DatabaseConfiguration, DatabaseError, DatabaseManager, DatabaseMutation, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

// Keeps the dedicated benchmark collection identity stable across persistence releases.
#[test]
fn benchmark_collection_has_one_closed_storage_identity() {
    assert_eq!(DatabaseCollection::Benchmarks.to_string(), "benchmarks");
    assert_eq!(
        DatabaseCollection::GatewayExposure.to_string(),
        "gateway_exposure"
    );
    assert_eq!(
        DatabaseCollection::CommandAuditSessions.to_string(),
        "command_audit_sessions"
    );
    assert_eq!(
        DatabaseCollection::GatewayUsage.to_string(),
        "gateway_usage"
    );
    assert_eq!(
        DatabaseCollection::PeerCredentials.to_string(),
        "peer_credentials"
    );
    assert_eq!(DatabaseCollection::Pairings.to_string(), "pairings");
    assert_eq!(DatabaseCollection::Controllers.to_string(), "controllers");
    assert_eq!(
        DatabaseCollection::PairingReplays.to_string(),
        "pairing_replays"
    );
    assert_eq!(
        DatabaseCollection::CoreUpdateServiceSnapshots.to_string(),
        "core_update_service_snapshots"
    );
}

// Represents one peer credential fixture in its dedicated database collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestPeerCredential {
    identifier: String,
    leaf_sha256: String,
}

impl DatabaseRecord for TestPeerCredential {
    const COLLECTION: DatabaseCollection = DatabaseCollection::PeerCredentials;

    // Returns the fixture's stable peer-certificate identity.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Represents one deterministic node value used to exercise the typed contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestNode {
    identifier: String,
    display_name: String,
}

impl TestNode {
    // Creates one canonical fixture record.
    fn new(identifier: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            display_name: display_name.into(),
        }
    }
}

impl DatabaseRecord for TestNode {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Nodes;

    // Returns the fixture's stable node identity.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Represents one deterministic service value used in cross-collection transactions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestService {
    identifier: String,
    model: String,
}

impl TestService {
    // Creates one canonical service fixture.
    fn new(identifier: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            model: model.into(),
        }
    }
}

impl DatabaseRecord for TestService {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Services;

    // Returns the fixture's stable service identity.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Supplies deterministic increasing timestamps to the production write path.
struct TestClock {
    next_value: AtomicI64,
}

impl TestClock {
    // Creates a clock beginning at one exact timestamp.
    fn new(first_value: i64) -> Self {
        Self {
            next_value: AtomicI64::new(first_value),
        }
    }
}

impl DatabaseClock for TestClock {
    // Returns one unique timestamp for every newly committed command.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.next_value.fetch_add(1, Ordering::SeqCst))
    }
}

// Opens one isolated manager with deterministic native dependencies.
fn manager(
    directory: &tempfile::TempDir,
    busy_timeout: Duration,
) -> Result<DatabaseManager, DatabaseError> {
    DatabaseManager::open(
        DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
            .with_write_queue_capacity(8)
            .with_busy_timeout(busy_timeout)
            .with_clock(Arc::new(TestClock::new(1_000))),
    )
}

// Returns one exact stored record from the typed query result.
fn one_record(result: DatabaseResult<TestNode>) -> li_database::DatabaseStoredRecord<TestNode> {
    match result {
        DatabaseResult::Record(record) => record,
        DatabaseResult::Records(_) => panic!("expected one record"),
    }
}

// Persists and reads one typed record without exposing SQLite to the caller.
#[test]
fn manager_creates_reads_and_updates_typed_records() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    let created = manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    assert_eq!(created.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(created.commit().mutation, DatabaseMutation::Created);
    assert_eq!(created.commit().revision, 1);
    let connection =
        Connection::open(directory.path().join("core.sqlite3")).expect("inspection connection");
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(journal_mode, "wal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(directory.path().join("core.sqlite3"))
            .expect("database metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let stored = one_record(
        manager
            .read(DatabaseQuery::record("node-a"))
            .expect("read node"),
    );
    assert_eq!(stored.value, TestNode::new("node-a", "Node A"));
    assert_eq!(stored.revision, 1);

    let updated = manager
        .write(DatabaseCommand::save(
            "update-node-a",
            TestNode::new("node-a", "Primary Node"),
            DatabaseRevision::Exact(1),
        ))
        .expect("update node");
    assert_eq!(updated.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(updated.commit().mutation, DatabaseMutation::Updated);
    assert_eq!(updated.commit().revision, 2);
    assert_eq!(
        one_record(
            manager
                .read(DatabaseQuery::record("node-a"))
                .expect("read updated node")
        )
        .value
        .display_name,
        "Primary Node"
    );
}

// Proves peer credentials remain isolated from an identical identity in another collection.
#[test]
fn peer_credential_collection_is_physically_isolated() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    manager
        .write(DatabaseCommand::save(
            "create-shared-node",
            TestNode::new("shared", "Node"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    manager
        .write(DatabaseCommand::save(
            "create-shared-peer",
            TestPeerCredential {
                identifier: "shared".to_string(),
                leaf_sha256: "a".repeat(64),
            },
            DatabaseRevision::Missing,
        ))
        .expect("create peer credential");

    let DatabaseResult::Record(node) = manager
        .read(DatabaseQuery::<TestNode>::record("shared"))
        .expect("read node")
    else {
        panic!("expected node");
    };
    let DatabaseResult::Record(peer) = manager
        .read(DatabaseQuery::<TestPeerCredential>::record("shared"))
        .expect("read peer credential")
    else {
        panic!("expected peer credential");
    };
    assert_eq!(node.value.display_name, "Node");
    assert_eq!(peer.value.leaf_sha256, "a".repeat(64));
}

// Rejects stale writes and leaves the previously committed value unchanged.
#[test]
fn manager_enforces_optimistic_revisions() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    let error = manager
        .write(DatabaseCommand::save(
            "stale-node-a",
            TestNode::new("node-a", "Stale Node"),
            DatabaseRevision::Exact(9),
        ))
        .expect_err("stale update must fail");
    assert_eq!(
        error,
        DatabaseError::Conflict {
            collection: DatabaseCollection::Nodes,
            identifier: "node-a".to_string(),
            expected: DatabaseRevision::Exact(9),
            observed: Some(1),
        }
    );
    assert_eq!(
        one_record(
            manager
                .read(DatabaseQuery::record("node-a"))
                .expect("read unchanged node")
        )
        .value
        .display_name,
        "Node A"
    );
}

// Returns the original commit for a replay and emits no duplicate event.
#[test]
fn manager_makes_commands_idempotent_after_commit() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    let events = manager.take_event_receiver().expect("event receiver");
    assert_eq!(
        manager
            .take_event_receiver()
            .expect_err("event receiver must have one owner"),
        DatabaseError::InvalidInput {
            field: "event receiver",
            reason: "receiver ownership was already transferred",
        }
    );
    let command = || {
        DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        )
    };
    let first = manager.write(command()).expect("first command");
    let replay = manager.write(command()).expect("command replay");
    assert_eq!(first.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(replay.disposition(), DatabaseCommitDisposition::Replayed);
    assert_eq!(first.commit(), replay.commit());
    assert_eq!(
        events
            .recv_timeout(Duration::from_secs(1))
            .expect("post-commit event")
            .revision,
        1
    );
    assert!(events.try_recv().is_err());

    let error = manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-b", "Node B"),
            DatabaseRevision::Missing,
        ))
        .expect_err("changed replay must fail");
    assert_eq!(
        error,
        DatabaseError::IdempotencyConflict {
            idempotency_key: "create-node-a".to_string(),
        }
    );
}

// Serializes concurrent writes through one bounded owner without losing records.
#[test]
fn manager_serializes_concurrent_writers() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = Arc::new(manager(&directory, Duration::from_secs(1)).expect("database manager"));
    let mut workers = Vec::new();
    for index in 0..16 {
        let manager = Arc::clone(&manager);
        workers.push(thread::spawn(move || {
            manager.write(DatabaseCommand::save(
                format!("create-node-{index}"),
                TestNode::new(format!("node-{index:02}"), format!("Node {index}")),
                DatabaseRevision::Missing,
            ))
        }));
    }
    for worker in workers {
        worker.join().expect("writer thread").expect("write record");
    }
    let records = manager
        .read(DatabaseQuery::<TestNode>::all())
        .expect("read nodes");
    let DatabaseResult::Records(records) = records else {
        panic!("expected record list");
    };
    assert_eq!(records.len(), 16);
    assert_eq!(records[0].value.identifier, "node-00");
    assert_eq!(records[15].value.identifier, "node-15");
}

// Bounds external write-lock contention and remains usable after the lock clears.
#[test]
fn manager_times_out_on_an_external_write_lock() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let manager = manager(&directory, Duration::from_millis(50)).expect("database manager");
    manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("initial write");
    let lock = Connection::open(&path).expect("lock connection");
    lock.execute_batch("BEGIN IMMEDIATE;")
        .expect("external write lock");
    let error = manager
        .write(DatabaseCommand::save(
            "locked-node",
            TestNode::new("node-a", "Updated Node"),
            DatabaseRevision::Exact(1),
        ))
        .expect_err("locked write must time out");
    assert_eq!(
        error,
        DatabaseError::Unavailable {
            reason: "write lock did not become available before the busy timeout",
        }
    );
    assert_eq!(
        one_record(
            manager
                .read(DatabaseQuery::record("node-a"))
                .expect("read while writer is locked")
        )
        .value
        .display_name,
        "Node A"
    );
    lock.execute_batch("ROLLBACK;").expect("release write lock");
    manager
        .write(DatabaseCommand::save(
            "locked-node",
            TestNode::new("node-a", "Updated Node"),
            DatabaseRevision::Exact(1),
        ))
        .expect("write after lock release");
}

// Deletes one exact revision and returns NotFound for later reads.
#[test]
fn manager_deletes_records_atomically() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    let events = manager.take_event_receiver().expect("event receiver");
    assert_eq!(
        events
            .recv_timeout(Duration::from_secs(1))
            .expect("create event")
            .mutation,
        DatabaseMutation::Created
    );
    let deleted = manager
        .write(DatabaseCommand::<TestNode>::delete(
            "delete-node-a",
            "node-a",
            DatabaseRevision::Exact(1),
        ))
        .expect("delete node");
    assert_eq!(deleted.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(deleted.commit().mutation, DatabaseMutation::Deleted);
    assert_eq!(deleted.commit().revision, 2);
    let replay = manager
        .write(DatabaseCommand::<TestNode>::delete(
            "delete-node-a",
            "node-a",
            DatabaseRevision::Exact(1),
        ))
        .expect("replay delete");
    assert_eq!(replay.disposition(), DatabaseCommitDisposition::Replayed);
    assert_eq!(replay.commit(), deleted.commit());
    assert_eq!(
        events
            .recv_timeout(Duration::from_secs(1))
            .expect("delete event")
            .mutation,
        DatabaseMutation::Deleted
    );
    assert!(events.try_recv().is_err());
    assert_eq!(
        manager
            .read(DatabaseQuery::<TestNode>::record("node-a"))
            .expect_err("deleted node must be absent"),
        DatabaseError::NotFound {
            collection: DatabaseCollection::Nodes,
            identifier: "node-a".to_string(),
        }
    );
}

// Refuses a foreign SQLite schema instead of adopting ambiguous state.
#[test]
fn manager_rejects_an_unidentified_existing_database() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let connection = Connection::open(&path).expect("foreign database");
    connection
        .execute_batch("CREATE TABLE foreign_state (value TEXT NOT NULL);")
        .expect("foreign schema");
    drop(connection);
    let error = match manager(&directory, Duration::from_secs(1)) {
        Ok(_) => panic!("foreign database must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        DatabaseError::Corrupt {
            reason: "unidentified SQLite database already contains schema objects",
        }
    );
}

// Rejects malformed stored bytes at the typed decoding boundary.
#[test]
fn manager_rejects_a_corrupt_record_payload() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    let connection = Connection::open(path).expect("corruption connection");
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1
             WHERE collection = 'nodes' AND identifier = 'node-a'",
            [b"{".as_slice()],
        )
        .expect("corrupt payload");
    assert_eq!(
        manager
            .read(DatabaseQuery::<TestNode>::record("node-a"))
            .expect_err("corrupt payload must fail"),
        DatabaseError::Corrupt {
            reason: "stored record payload is invalid",
        }
    );
}

// Reopens the same private schema after a clean writer shutdown.
#[test]
fn manager_reopens_committed_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let first = manager(&directory, Duration::from_secs(1)).expect("database manager");
    first
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    first.close().expect("close database manager");

    let second = manager(&directory, Duration::from_secs(1)).expect("reopened manager");
    assert_eq!(
        one_record(
            second
                .read(DatabaseQuery::record("node-a"))
                .expect("read reopened state")
        )
        .value,
        TestNode::new("node-a", "Node A")
    );
}

// Rejects older and newer schema versions without rewriting their identities.
#[test]
fn manager_rejects_unsupported_schema_versions_without_rewrite() {
    for unsupported_version in [0, 2] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("core.sqlite3");
        manager(&directory, Duration::from_secs(1))
            .expect("database manager")
            .close()
            .expect("close database manager");
        Connection::open(&path)
            .expect("schema connection")
            .execute_batch(&format!("PRAGMA user_version = {unsupported_version};"))
            .expect("unsupported schema version");

        let error = match manager(&directory, Duration::from_secs(1)) {
            Ok(_) => panic!("unsupported schema must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            DatabaseError::Corrupt {
                reason: "database schema version is unsupported by this Core build",
            }
        );
        let observed_version: i64 = Connection::open(&path)
            .expect("inspection connection")
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("schema version");
        assert_eq!(observed_version, unsupported_version);
    }
}

// Rejects a partial current schema without creating its missing storage.
#[test]
fn manager_rejects_a_partial_current_schema_without_rewrite() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    manager(&directory, Duration::from_secs(1))
        .expect("database manager")
        .close()
        .expect("close database manager");
    Connection::open(&path)
        .expect("schema connection")
        .execute_batch("DROP TABLE li_database_idempotency;")
        .expect("partial schema");

    let error = match manager(&directory, Duration::from_secs(1)) {
        Ok(_) => panic!("partial schema must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        DatabaseError::Corrupt {
            reason: "database schema does not exactly match this Core build",
        }
    );
    let remaining_tables: i64 = Connection::open(path)
        .expect("inspection connection")
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .expect("remaining schema");
    assert_eq!(remaining_tables, 1);
}

// Rejects invalid configuration and command identities before mutation.
#[test]
fn manager_rejects_invalid_boundaries() {
    let relative_error = match DatabaseManager::open(DatabaseConfiguration::new("core.sqlite3")) {
        Ok(_) => panic!("relative path must fail"),
        Err(error) => error,
    };
    assert_eq!(
        relative_error,
        DatabaseError::InvalidInput {
            field: "path",
            reason: "path must be absolute",
        }
    );

    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    assert_eq!(
        manager
            .write(DatabaseCommand::save(
                "invalid-node",
                TestNode::new(" node-a", "Node A"),
                DatabaseRevision::Missing,
            ))
            .expect_err("noncanonical identifier must fail"),
        DatabaseError::InvalidInput {
            field: "identifier",
            reason: "identifier must be canonical and contain no control characters",
        }
    );
    assert_eq!(
        manager
            .write(DatabaseCommand::save(
                "invalid\nkey",
                TestNode::new("node-a", "Node A"),
                DatabaseRevision::Missing,
            ))
            .expect_err("control character must fail"),
        DatabaseError::InvalidInput {
            field: "idempotency key",
            reason: "key must be canonical and contain no control characters",
        }
    );
    let DatabaseResult::Records(records) = manager
        .read(DatabaseQuery::<TestNode>::all())
        .expect("read unchanged collection")
    else {
        panic!("expected record list");
    };
    assert!(records.is_empty());
}

// Commits and replays cross-collection mutations as one ordered transaction.
#[test]
fn manager_commits_cross_collection_transaction_atomically() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    let events = manager.take_event_receiver().expect("event receiver");
    let transaction = || {
        DatabaseTransaction::new("create-node-and-service")
            .expect("transaction")
            .save(TestNode::new("node-a", "Node A"), DatabaseRevision::Missing)
            .expect("node mutation")
            .save(
                TestService::new("service-a", "qwen3.8"),
                DatabaseRevision::Missing,
            )
            .expect("service mutation")
    };
    let applied = manager
        .write_transaction(transaction())
        .expect("apply transaction");
    assert_eq!(applied.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(applied.commit().commits().len(), 2);
    assert_eq!(
        one_record(
            manager
                .read(DatabaseQuery::record("node-a"))
                .expect("read node")
        )
        .value,
        TestNode::new("node-a", "Node A")
    );
    let DatabaseResult::Record(service) = manager
        .read(DatabaseQuery::<TestService>::record("service-a"))
        .expect("read service")
    else {
        panic!("expected one service");
    };
    assert_eq!(service.value, TestService::new("service-a", "qwen3.8"));
    assert_eq!(
        events
            .recv_timeout(Duration::from_secs(1))
            .expect("node event")
            .collection,
        DatabaseCollection::Nodes
    );
    assert_eq!(
        events
            .recv_timeout(Duration::from_secs(1))
            .expect("service event")
            .collection,
        DatabaseCollection::Services
    );

    let replayed = manager
        .write_transaction(transaction())
        .expect("replay transaction");
    assert_eq!(replayed.disposition(), DatabaseCommitDisposition::Replayed);
    assert_eq!(replayed.commit(), applied.commit());
    assert!(events.try_recv().is_err());
}

// Rolls back earlier mutations when a later transaction revision conflicts.
#[test]
fn manager_rolls_back_the_complete_transaction() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    manager
        .write(DatabaseCommand::save(
            "create-node-a",
            TestNode::new("node-a", "Node A"),
            DatabaseRevision::Missing,
        ))
        .expect("create node");
    let transaction = DatabaseTransaction::new("failed-transaction")
        .expect("transaction")
        .save(
            TestService::new("service-a", "qwen3.8"),
            DatabaseRevision::Missing,
        )
        .expect("service mutation")
        .save(
            TestNode::new("node-a", "Changed Node"),
            DatabaseRevision::Exact(9),
        )
        .expect("node mutation");
    assert!(matches!(
        manager
            .write_transaction(transaction)
            .expect_err("transaction must fail"),
        DatabaseError::Conflict { .. }
    ));
    assert!(matches!(
        manager.read(DatabaseQuery::<TestService>::record("service-a")),
        Err(DatabaseError::NotFound { .. })
    ));
    assert_eq!(
        one_record(
            manager
                .read(DatabaseQuery::record("node-a"))
                .expect("read unchanged node")
        )
        .value,
        TestNode::new("node-a", "Node A")
    );
}

// Rejects empty batches, duplicate targets, and changed transaction replays.
#[test]
fn manager_rejects_invalid_transaction_boundaries() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, Duration::from_secs(1)).expect("database manager");
    assert_eq!(
        manager
            .write_transaction(DatabaseTransaction::new("empty").expect("transaction"))
            .expect_err("empty transaction must fail"),
        DatabaseError::InvalidInput {
            field: "transaction",
            reason: "transaction must contain at least one mutation",
        }
    );
    let duplicate = match DatabaseTransaction::new("duplicate")
        .expect("transaction")
        .save(TestNode::new("node-a", "Node A"), DatabaseRevision::Missing)
        .expect("first mutation")
        .save(
            TestNode::new("node-a", "Changed Node"),
            DatabaseRevision::Missing,
        ) {
        Ok(_) => panic!("duplicate target must fail"),
        Err(error) => error,
    };
    assert_eq!(
        duplicate,
        DatabaseError::InvalidInput {
            field: "transaction",
            reason: "transaction contains duplicate record targets",
        }
    );

    let first = DatabaseTransaction::new("replay")
        .expect("transaction")
        .save(TestNode::new("node-a", "Node A"), DatabaseRevision::Missing)
        .expect("first mutation");
    manager.write_transaction(first).expect("first transaction");
    let changed = DatabaseTransaction::new("replay")
        .expect("transaction")
        .save(TestNode::new("node-b", "Node B"), DatabaseRevision::Missing)
        .expect("changed mutation");
    assert_eq!(
        manager
            .write_transaction(changed)
            .expect_err("changed replay must fail"),
        DatabaseError::IdempotencyConflict {
            idempotency_key: "replay".to_string(),
        }
    );
}
