// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditAppendDisposition,
    AuditAppendRequest, AuditCheckpointCryptography, AuditCheckpointPolicy, AuditClock,
    AuditCorrelationId, AuditError, AuditEventId, AuditIdentityProvider, AuditManager, AuditOrigin,
    AuditOriginInterface, AuditOutcome, AuditReplayId, AuditStore, AuditStoreError, AuditTarget,
    AuditUnixNanoseconds,
};
use li_core_interface::{NodeId, Sha256Digest};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::DatabaseAuditStore;
use rusqlite::{params, Connection};

// Supplies deterministic increasing commit timestamps to DatabaseManager.
struct DatabaseClockMock {
    next: AtomicI64,
}

impl DatabaseClock for DatabaseClockMock {
    // Returns one unique non-negative database timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.next.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic increasing audit timestamps.
struct AuditClockMock {
    next: AtomicU64,
}

impl AuditClock for AuditClockMock {
    // Returns one unique positive audit timestamp.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError> {
        AuditUnixNanoseconds::new(self.next.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deliberately non-lexical event identities to exercise sequence ordering.
struct IdentityMock {
    identities: Mutex<Vec<String>>,
    calls: AtomicUsize,
}

impl IdentityMock {
    // Creates one deterministic identity source in caller-supplied order.
    fn new(identities: &[&str]) -> Self {
        Self {
            identities: Mutex::new(
                identities
                    .iter()
                    .rev()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
        }
    }
}

impl AuditIdentityProvider for IdentityMock {
    // Returns the next exact fixture identity.
    fn event_id(&self) -> Result<AuditEventId, AuditError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let value = self
            .identities
            .lock()
            .expect("identity lock")
            .pop()
            .expect("fixture identity");
        AuditEventId::parse(&value)
    }
}

// Signs and verifies checkpoints with an exact deterministic byte projection.
#[derive(Default)]
struct CryptographyMock;

impl AuditCheckpointCryptography for CryptographyMock {
    // Returns the exact hash bytes as a deterministic opaque signature.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
        Ok(event_hash.to_vec())
    }

    // Accepts only the deterministic signature projection.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError> {
        Ok(event_hash == signature)
    }
}

// Opens one isolated database using the same production writer with deterministic time.
fn open_database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path)
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(DatabaseClockMock {
                    next: AtomicI64::new(10_000),
                })),
        )
        .expect("database"),
    )
}

// Creates one AuditManager over the production DatabaseAuditStore.
fn audit_manager(
    store: Arc<DatabaseAuditStore>,
    identities: &[&str],
    checkpoint_interval: u64,
) -> AuditManager {
    AuditManager::new(
        NodeId::parse(&"1".repeat(32)).expect("node"),
        store,
        Arc::new(AuditClockMock {
            next: AtomicU64::new(1_000_000),
        }),
        Arc::new(IdentityMock::new(identities)),
        Arc::new(CryptographyMock),
        AuditCheckpointPolicy::new(checkpoint_interval).expect("checkpoint policy"),
    )
}

// Creates one complete deterministic action request.
fn request(replay: &str, correlation: char, action: &str) -> AuditAppendRequest {
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    AuditAppendRequest::new(
        AuditReplayId::parse(replay).expect("replay"),
        AuditCorrelationId::parse(&correlation.to_string().repeat(32)).expect("correlation"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("taimur").expect("actor"),
        ),
        AuditOrigin::new(node_id, AuditOriginInterface::Cli),
        AuditAction::parse(action).expect("action"),
        AuditTarget::parse("fixture.model").expect("target"),
        None,
        None,
        AuditOutcome::Success,
        None,
    )
    .expect("request")
}

// Persists ordered events, an atomic checkpoint, replay identity, and restart state.
#[test]
fn database_store_appends_replays_and_restarts_in_sequence_order() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("core.sqlite3");
    let database = open_database(&path);
    let store = Arc::new(DatabaseAuditStore::new(Arc::clone(&database)));
    let manager = audit_manager(Arc::clone(&store), &[&"f".repeat(32), &"a".repeat(32)], 2);
    let first_request = request("first", '2', "model.install");
    let first = manager.append(first_request.clone()).expect("first append");
    let replay = manager.append(first_request).expect("replay append");
    assert_eq!(first.disposition(), AuditAppendDisposition::Applied);
    assert_eq!(replay.disposition(), AuditAppendDisposition::Replayed);
    let second = manager
        .append(request("second", '3', "model.remove"))
        .expect("second append");
    assert!(second.entry().checkpoint().is_some());
    assert_eq!(manager.verify().expect("verification").events(), 2);
    assert_eq!(manager.list(2).expect("list")[0].sequence(), 2);
    drop(manager);
    drop(store);
    drop(database);

    let reopened_database = open_database(&path);
    let reopened_store = Arc::new(DatabaseAuditStore::new(Arc::clone(&reopened_database)));
    let reopened = audit_manager(Arc::clone(&reopened_store), &[&"b".repeat(32)], 2);
    let ledger = reopened_store.ledger().expect("reopened ledger");
    assert_eq!(
        ledger
            .entries()
            .iter()
            .map(|entry| entry.event().event_id().as_str())
            .collect::<Vec<_>>(),
        vec!["f".repeat(32), "a".repeat(32)]
    );
    assert_eq!(
        reopened
            .verify()
            .expect("restart verification")
            .checkpoints(),
        1
    );
}

// Rejects stale optimistic appends and semantic reuse of one replay identity.
#[test]
fn database_store_rejects_stale_revision_and_replay_conflict() {
    let directory = tempfile::tempdir().expect("directory");
    let database = open_database(&directory.path().join("core.sqlite3"));
    let store = Arc::new(DatabaseAuditStore::new(database));
    let manager = audit_manager(Arc::clone(&store), &[&"a".repeat(32)], 100);
    let receipt = manager
        .append(request("first", '2', "model.install"))
        .expect("append");
    let stale = store
        .append(
            0,
            &AuditReplayId::parse("stale").expect("stale replay"),
            receipt.request_sha256(),
            receipt.entry().clone(),
        )
        .expect_err("stale revision");
    assert_eq!(stale, AuditStoreError::Conflict);
    let conflict = store
        .append(
            1,
            &AuditReplayId::parse("first").expect("first replay"),
            &Sha256Digest::parse(&"f".repeat(64)).expect("different request"),
            receipt.entry().clone(),
        )
        .expect_err("replay conflict");
    assert_eq!(conflict, AuditStoreError::ReplayConflict);
}

// Fails closed when owner-level database tampering changes a stored event sequence.
#[test]
fn database_store_rejects_semantically_corrupt_persistence() {
    for scenario in ["event_sequence", "missing_replay"] {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("core.sqlite3");
        {
            let database = open_database(&path);
            let store = Arc::new(DatabaseAuditStore::new(database));
            audit_manager(store, &[&"a".repeat(32)], 100)
                .append(request("first", '2', "model.install"))
                .expect("append");
        }
        let connection = Connection::open(&path).expect("raw database");
        match scenario {
            "event_sequence" => {
                let payload: Vec<u8> = connection
                    .query_row(
                        "SELECT payload FROM li_database_records WHERE collection=?1",
                        params!["audit_events"],
                        |row| row.get(0),
                    )
                    .expect("event payload");
                let mut value: serde_json::Value =
                    serde_json::from_slice(&payload).expect("event JSON");
                value["sequence"] = serde_json::json!(2);
                connection
                    .execute(
                        "UPDATE li_database_records SET payload=?1 WHERE collection=?2",
                        params![serde_json::to_vec(&value).expect("payload"), "audit_events"],
                    )
                    .expect("tamper event");
            }
            "missing_replay" => {
                connection
                    .execute(
                        "DELETE FROM li_database_records WHERE collection='audit_replays'",
                        [],
                    )
                    .expect("remove replay");
            }
            _ => unreachable!("closed corruption matrix"),
        }
        drop(connection);

        let database = open_database(&path);
        let store = DatabaseAuditStore::new(database);
        assert_eq!(
            store.ledger().expect_err("corruption"),
            AuditStoreError::Corrupt,
            "{scenario}"
        );
    }
}
