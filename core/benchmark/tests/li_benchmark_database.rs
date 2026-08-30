// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_benchmark_manager::{
    BenchmarkAuthorization, BenchmarkEvidence, BenchmarkExecutionOutcome, BenchmarkFailure,
    BenchmarkFailureCategory, BenchmarkGitRevision, BenchmarkJobPhase, BenchmarkJobRecord,
    BenchmarkKind, BenchmarkPublication, BenchmarkRecordSchema, BenchmarkRequest,
    BenchmarkRestoration, BenchmarkScope, BenchmarkSignature, BenchmarkStore, BenchmarkStoreError,
    BenchmarkSubject, BenchmarkTelemetryReceipt, DatabaseBenchmarkStore, PreparedBenchmark,
    RunningBenchmark, SealedBenchmarkEvidence,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

// Supplies deterministic increasing commit timestamps to the production DatabaseManager.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique positive commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Opens one isolated DatabaseManager with bounded lock waiting and deterministic time.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path)
                .with_busy_timeout(Duration::from_millis(10))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    )
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Applies the manager's domain-separated replay identity algorithm.
fn replay_digest(idempotency_key: &str) -> Sha256Digest {
    let mut digest = Sha256::new();
    let domain = b"li_benchmark_replay_v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((idempotency_key.len() as u64).to_be_bytes());
    digest.update(idempotency_key.as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).expect("replay digest")
}

// Returns the operation identity derived from one replay digest.
fn job_id(replay_sha256: &Sha256Digest) -> OperationId {
    OperationId::parse(&replay_sha256.as_str()[..32]).expect("job identity")
}

// Creates one ordinary exact runtime benchmark request.
fn request(model: &str) -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
            LogicalModelName::parse(model).expect("model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
            digest('4'),
            digest('5'),
            digest('6'),
        ),
    )
    .expect("request")
}

// Creates one valid requested journal for direct store-contract testing.
fn requested(idempotency_key: &str, model: &str) -> BenchmarkJobRecord {
    let replay_sha256 = replay_digest(idempotency_key);
    let request = request(model);
    BenchmarkJobRecord::restore(
        job_id(&replay_sha256),
        replay_sha256,
        request.sha256().expect("request digest"),
        request,
        BenchmarkAuthorization::new(digest('7')),
        BenchmarkJobPhase::Requested,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(1_000),
    )
    .expect("requested journal")
}

// Creates one complete terminal community-verification journal with a durable readback receipt.
fn published_verification(idempotency_key: &str) -> BenchmarkJobRecord {
    let replay_sha256 = replay_digest(idempotency_key);
    let candidate = RuntimeCandidateId::parse("engine--owner--model--target").expect("candidate");
    let kind = BenchmarkKind::verification(
        123,
        BenchmarkGitRevision::parse(&"a".repeat(40)).expect("proposal head"),
        candidate.clone(),
        OperationId::parse(&"e".repeat(32)).expect("transaction"),
        digest('9'),
        digest('8'),
        42,
        digest('d'),
        Some(digest('c')),
    )
    .expect("verification kind");
    let request = BenchmarkRequest::new(
        kind,
        BenchmarkScope::Complete,
        request("model").subject().clone(),
    )
    .expect("verification request");
    let outcome = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: digest('a'),
        results_sha256: digest('c'),
        record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
    };
    let restoration = BenchmarkRestoration::new(digest('f'));
    let evidence = SealedBenchmarkEvidence::new(
        BenchmarkEvidence::new(
            digest('b'),
            digest('c'),
            BenchmarkRecordSchema::CommunityVerificationV1,
            4096,
        )
        .expect("evidence"),
        BenchmarkSignature::new(digest('d'), "c2lnbmF0dXJl").expect("signature"),
    );
    let publication = BenchmarkPublication::new(
        digest('1'),
        digest('b'),
        digest('2'),
        123,
        BenchmarkGitRevision::parse(&"a".repeat(40)).expect("proposal head"),
        candidate,
        Some(digest('3')),
        Some(digest('4')),
        digest('5'),
        digest('f'),
        digest('b'),
        digest('d'),
        digest('d'),
        11,
        "https://github.com/letsinferlabs/runtimes/pull/123#issuecomment-11".to_string(),
    )
    .expect("publication");
    BenchmarkJobRecord::restore(
        job_id(&replay_sha256),
        replay_sha256,
        request.sha256().expect("request digest"),
        request,
        BenchmarkAuthorization::new(digest('7')),
        BenchmarkJobPhase::Completed,
        Some(PreparedBenchmark::new(digest('8'))),
        Some(RunningBenchmark::new(digest('9'))),
        None,
        None,
        Some(outcome),
        Some(BenchmarkTelemetryReceipt::new(digest('e'), 12)),
        Some(restoration),
        Some(evidence),
        Some(publication),
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(2_000),
    )
    .expect("published verification")
}

// Advances one requested fixture to a valid prepared journal.
fn prepared(record: &BenchmarkJobRecord, receipt: char, updated_at: u64) -> BenchmarkJobRecord {
    BenchmarkJobRecord::restore(
        record.job_id().clone(),
        record.replay_sha256().clone(),
        record.request_sha256().clone(),
        record.request().clone(),
        record.authorization().clone(),
        BenchmarkJobPhase::Prepared,
        Some(PreparedBenchmark::new(digest(receipt))),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        record.created_at(),
        UnixMilliseconds::new(updated_at),
    )
    .expect("prepared journal")
}

// Advances one requested fixture to a complete sealed terminal journal.
fn completed(record: &BenchmarkJobRecord, schema: BenchmarkRecordSchema) -> BenchmarkJobRecord {
    let evidence =
        BenchmarkEvidence::new(digest('b'), digest('c'), schema, 4096).expect("evidence");
    let signature = BenchmarkSignature::new(digest('d'), "c2lnbmF0dXJl").expect("signature");
    let (phase, outcome) = if schema == BenchmarkRecordSchema::CoreLocalFailureV1 {
        (
            BenchmarkJobPhase::Failed,
            BenchmarkExecutionOutcome::Failed {
                raw_evidence_sha256: None,
                failure: BenchmarkFailure::new(
                    BenchmarkFailureCategory::Crash,
                    "measuring",
                    "worker exited",
                )
                .expect("failure"),
            },
        )
    } else {
        (
            BenchmarkJobPhase::Completed,
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('a'),
                results_sha256: digest('c'),
                record_schema: schema,
            },
        )
    };
    BenchmarkJobRecord::restore(
        record.job_id().clone(),
        record.replay_sha256().clone(),
        record.request_sha256().clone(),
        record.request().clone(),
        record.authorization().clone(),
        phase,
        Some(PreparedBenchmark::new(digest('8'))),
        Some(RunningBenchmark::new(digest('9'))),
        None,
        None,
        Some(outcome),
        Some(BenchmarkTelemetryReceipt::new(digest('e'), 12)),
        Some(BenchmarkRestoration::new(digest('f'))),
        Some(SealedBenchmarkEvidence::new(evidence, signature)),
        None,
        record.created_at(),
        UnixMilliseconds::new(2_000),
    )
    .expect("completed journal")
}

// Rewrites one stored JSON payload through an isolated test-only SQLite connection.
fn mutate_payload(
    path: &std::path::Path,
    identifier: &str,
    mutation: impl FnOnce(&mut serde_json::Value),
) {
    let connection = Connection::open(path).expect("SQLite");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
            params!["benchmarks", identifier],
            |row| row.get(0),
        )
        .expect("payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    mutation(&mut value);
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&value).expect("encoded payload"),
                "benchmarks",
                identifier
            ],
        )
        .expect("mutate payload");
}

// Round-trips both successful schemas and the distinct Core-local failure identity.
#[test]
fn database_store_round_trips_every_terminal_evidence_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let database_manager = database(&path);
    let store = DatabaseBenchmarkStore::new(Arc::clone(&database_manager));
    let mut expected = Vec::new();

    for (index, schema) in [
        BenchmarkRecordSchema::OciExecutionPayloadV7,
        BenchmarkRecordSchema::NativeExecutionPayloadV8,
        BenchmarkRecordSchema::CoreLocalFailureV1,
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("ordinary-{index}");
        let requested = requested(&key, &format!("model-{index}"));
        let created = store.create(requested.clone()).expect("create");
        assert_eq!(created.revision(), 1);
        assert_eq!(
            store.active().expect("active").expect("journal").record(),
            &requested
        );

        let completed = completed(&requested, schema);
        let terminal = store.replace(completed.clone(), 1).expect("complete");
        assert_eq!(terminal.revision(), 2);
        assert!(store.active().expect("active").is_none());
        let restored = store
            .read(completed.job_id())
            .expect("read")
            .expect("journal");
        assert_eq!(restored.record(), &completed);
        assert_eq!(
            restored
                .record()
                .evidence()
                .expect("sealed evidence")
                .evidence()
                .schema(),
            schema
        );
        expected.push((completed.job_id().clone(), completed, schema));
    }
    drop(store);
    Arc::try_unwrap(database_manager)
        .map_err(|_| "database reference")
        .expect("database ownership")
        .close()
        .expect("close database");

    let reopened = DatabaseBenchmarkStore::new(database(&path));
    for (job_id, expected, schema) in expected {
        let restored = reopened.read(&job_id).expect("read").expect("journal");
        assert_eq!(restored.record(), &expected);
        assert_eq!(
            restored
                .record()
                .evidence()
                .expect("sealed evidence")
                .evidence()
                .schema(),
            schema
        );
    }
}

// Round-trips the complete signed-comment receipt and rejects any stored identity drift.
#[test]
fn database_store_round_trips_and_revalidates_publication_receipt() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let database_manager = database(&path);
    let store = DatabaseBenchmarkStore::new(Arc::clone(&database_manager));
    let published = published_verification("published");
    let requested = BenchmarkJobRecord::restore(
        published.job_id().clone(),
        published.replay_sha256().clone(),
        published.request_sha256().clone(),
        published.request().clone(),
        published.authorization().clone(),
        BenchmarkJobPhase::Requested,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        published.created_at(),
        published.created_at(),
    )
    .expect("requested verification");
    store.create(requested).expect("create verification");
    store
        .replace(published.clone(), 1)
        .expect("publish verification");
    assert_eq!(
        store
            .read(published.job_id())
            .expect("read publication")
            .expect("publication")
            .record(),
        &published
    );
    drop(store);
    Arc::try_unwrap(database_manager)
        .map_err(|_| "database reference")
        .expect("database ownership")
        .close()
        .expect("close database");

    let reopened = DatabaseBenchmarkStore::new(database(&path));
    assert_eq!(
        reopened
            .read(published.job_id())
            .expect("read reopened publication")
            .expect("reopened publication")
            .record(),
        &published
    );
    mutate_payload(
        &path,
        &format!("li_benchmark_job_v1:{}", published.job_id().as_str()),
        |value| {
            value["publication"]["comment_id"] = serde_json::Value::from(12);
        },
    );
    assert_eq!(
        reopened.read(published.job_id()),
        Err(BenchmarkStoreError::Corrupt)
    );
}

// Resolves read replay and exact replace replay while rejecting divergent reuse.
#[test]
fn database_store_enforces_replay_and_idempotency_contracts() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = DatabaseBenchmarkStore::new(database(&directory.path().join("core.sqlite3")));
    let requested = requested("replay", "qwen");
    store.create(requested.clone()).expect("create");
    assert_eq!(
        store.create(requested.clone()),
        Err(BenchmarkStoreError::Conflict)
    );
    assert_eq!(
        store
            .read_replay(requested.replay_sha256())
            .expect("read replay")
            .expect("journal")
            .record(),
        &requested
    );

    let prepared_record = prepared(&requested, '8', 1_100);
    let replaced = store.replace(prepared_record.clone(), 1).expect("replace");
    assert_eq!(replaced.revision(), 2);
    let replay = store
        .replace(prepared_record.clone(), 1)
        .expect("replace replay");
    assert_eq!(replay.revision(), 2);
    assert_eq!(replay.record(), &prepared_record);
    assert_eq!(
        store.replace(prepared(&requested, '9', 1_100), 1),
        Err(BenchmarkStoreError::Conflict)
    );
}

// Rolls back a competing creation while preserving the first active owner.
#[test]
fn database_store_atomically_excludes_a_second_active_benchmark() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = DatabaseBenchmarkStore::new(database(&directory.path().join("core.sqlite3")));
    let first = requested("first", "qwen");
    let second = requested("second", "deepseek");
    store.create(first.clone()).expect("first create");
    assert_eq!(
        store.create(second.clone()),
        Err(BenchmarkStoreError::Conflict)
    );
    assert!(store.read(second.job_id()).expect("second read").is_none());
    assert_eq!(
        store.active().expect("active").expect("journal").record(),
        &first
    );
}

// Preserves optimistic revisions and releases the active pointer only with terminal state.
#[test]
fn database_store_rejects_stale_revision_without_splitting_active_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = DatabaseBenchmarkStore::new(database(&directory.path().join("core.sqlite3")));
    let requested = requested("revision", "qwen");
    store.create(requested.clone()).expect("create");
    let first_prepared = prepared(&requested, '8', 1_100);
    store
        .replace(first_prepared.clone(), 1)
        .expect("first replace");
    assert_eq!(
        store.replace(prepared(&requested, '9', 1_200), 1),
        Err(BenchmarkStoreError::Conflict)
    );
    let active = store.active().expect("active").expect("journal");
    assert_eq!(active.revision(), 2);
    assert_eq!(active.record(), &first_prepared);

    let terminal = completed(&requested, BenchmarkRecordSchema::OciExecutionPayloadV7);
    assert_eq!(
        store.replace(terminal.clone(), 1),
        Err(BenchmarkStoreError::Conflict)
    );
    store.replace(terminal, 2).expect("terminal replace");
    assert!(store.active().expect("active").is_none());
}

// Fails closed on unknown persistence schema and an active pointer with no matching journal.
#[test]
fn database_store_rejects_corrupt_journal_and_active_pointer() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let store = DatabaseBenchmarkStore::new(database(&path));
    let requested_record = requested("corrupt", "qwen");
    store.create(requested_record.clone()).expect("create");
    let identifier = format!("li_benchmark_job_v1:{}", requested_record.job_id().as_str());
    mutate_payload(&path, &identifier, |value| {
        value["schema"]["version"] = serde_json::Value::from(2);
    });
    assert_eq!(
        store.read(requested_record.job_id()),
        Err(BenchmarkStoreError::Corrupt)
    );

    let other = requested("missing-pointer-target", "other");
    mutate_payload(&path, "li_benchmark_active_v1", |value| {
        value["job_id"] = serde_json::Value::String(other.job_id().as_str().to_string());
        value["replay_sha256"] =
            serde_json::Value::String(other.replay_sha256().as_str().to_string());
    });
    assert_eq!(store.active(), Err(BenchmarkStoreError::Corrupt));
}

// Rejects a second active-pointer row even when both rows name the same valid journal.
#[test]
fn database_store_rejects_ambiguous_active_ownership() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let store = DatabaseBenchmarkStore::new(database(&path));
    store
        .create(requested("ambiguous", "qwen"))
        .expect("create");

    let connection = Connection::open(&path).expect("SQLite");
    let (record_version, revision, payload, created_at, updated_at): (i64, i64, Vec<u8>, i64, i64) =
        connection
            .query_row(
                "SELECT record_version, revision, payload, created_at_unix_ms, updated_at_unix_ms
                 FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["benchmarks", "li_benchmark_active_v1"],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("active payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    value["identifier"] = serde_json::Value::String("li_benchmark_active_v1_duplicate".to_string());
    connection
        .execute(
            "INSERT INTO li_database_records (
                collection, identifier, record_version, revision, payload,
                created_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "benchmarks",
                "li_benchmark_active_v1_duplicate",
                record_version,
                revision,
                serde_json::to_vec(&value).expect("encoded payload"),
                created_at,
                updated_at
            ],
        )
        .expect("duplicate active pointer");
    drop(connection);

    assert_eq!(store.active(), Err(BenchmarkStoreError::Corrupt));
}

// Maps bounded SQLite write lock exhaustion to unavailable without partial state.
#[test]
fn database_store_reports_storage_failure_without_partial_creation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let store = DatabaseBenchmarkStore::new(database(&path));
    let lock = Connection::open(&path).expect("SQLite lock connection");
    lock.execute_batch("BEGIN IMMEDIATE").expect("writer lock");
    let requested = requested("locked", "qwen");
    assert_eq!(
        store.create(requested.clone()),
        Err(BenchmarkStoreError::Unavailable)
    );
    lock.execute_batch("ROLLBACK").expect("release lock");
    assert!(store.read(requested.job_id()).expect("read").is_none());
    assert!(store.active().expect("active").is_none());
}
