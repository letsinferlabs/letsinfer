// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use li_benchmark_manager::{
    BenchmarkEvidence, BenchmarkExecutionOutcome, BenchmarkFailure, BenchmarkFailureCategory,
    BenchmarkGitRevision, BenchmarkKind, BenchmarkRecordSchema, BenchmarkRequest,
    BenchmarkRestoration, BenchmarkScope, BenchmarkSignature, BenchmarkStoreError,
    BenchmarkSubject, BenchmarkTelemetryReceipt, BenchmarkVerificationArmState,
    BenchmarkVerificationChildResult, BenchmarkVerificationHandoffReceipt,
    BenchmarkVerificationPhase, BenchmarkVerificationStore, BenchmarkVerificationTransaction,
    DatabaseBenchmarkVerificationStore, PreparedBenchmark, RunningBenchmark,
    SealedBenchmarkEvidence,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};

// Returns one exact lowercase digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one exact candidate or baseline subject.
fn subject(character: char) -> BenchmarkSubject {
    BenchmarkSubject::new(
        InstallationId::parse(&"1".repeat(64)).expect("installation"),
        RuntimeInstallationId::parse(&character.to_string().repeat(32)).expect("runtime"),
        LogicalModelName::parse("model").expect("model"),
        PlacementGroupId::parse(&character.to_string().repeat(32)).expect("group"),
        digest(character),
        digest('4'),
        digest('5'),
    )
}

// Returns one complete local baseline request.
fn baseline() -> BenchmarkRequest {
    BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject('2'))
        .expect("baseline")
}

// Returns one complete proposal candidate request.
fn candidate() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            41,
            BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
            OperationId::parse(&"b".repeat(32)).expect("transaction"),
            digest('c'),
            digest('d'),
            73,
            digest('6'),
            None,
        )
        .expect("kind"),
        BenchmarkScope::Complete,
        subject('3'),
    )
    .expect("candidate")
}

// Returns one valid prepared parent transaction with selectable cancellation intent.
fn transaction(cancelled: bool) -> BenchmarkVerificationTransaction {
    let candidate = candidate();
    BenchmarkVerificationTransaction::restore(
        OperationId::parse(&"7".repeat(32)).expect("job"),
        candidate.sha256().expect("request digest"),
        BenchmarkVerificationHandoffReceipt::new(
            OperationId::parse(&"8".repeat(32)).expect("transaction"),
            digest('8'),
            digest('9'),
            baseline(),
            candidate,
        )
        .expect("handoff"),
        BenchmarkVerificationPhase::Prepared,
        BenchmarkVerificationArmState::prepared(PreparedBenchmark::new(digest('a'))),
        None,
        None,
        None,
        cancelled,
        None,
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(if cancelled { 1_001 } else { 1_000 }),
    )
    .expect("transaction")
}

// Returns one persisted recovery-required parent transaction after baseline restoration failed.
fn restoration_failed_transaction() -> BenchmarkVerificationTransaction {
    let candidate = candidate();
    let failure = BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256: Some(digest('d')),
        failure: BenchmarkFailure::new(
            BenchmarkFailureCategory::Crash,
            "baseline",
            "baseline failed",
        )
        .expect("failure"),
    };
    let result = BenchmarkVerificationChildResult::new(
        failure,
        BenchmarkTelemetryReceipt::new(digest('e'), 1),
        BenchmarkRestoration::new(digest('f')),
        SealedBenchmarkEvidence::new(
            BenchmarkEvidence::new(
                digest('d'),
                digest('d'),
                BenchmarkRecordSchema::CoreLocalFailureV1,
                100,
            )
            .expect("evidence"),
            BenchmarkSignature::new(digest('1'), "c2lnbmF0dXJl").expect("signature"),
        ),
        1,
    )
    .expect("result");
    BenchmarkVerificationTransaction::restore(
        OperationId::parse(&"7".repeat(32)).expect("job"),
        candidate.sha256().expect("request digest"),
        BenchmarkVerificationHandoffReceipt::new(
            OperationId::parse(&"8".repeat(32)).expect("transaction"),
            digest('8'),
            digest('9'),
            baseline(),
            candidate,
        )
        .expect("handoff"),
        BenchmarkVerificationPhase::RestorationFailed,
        BenchmarkVerificationArmState::restore(
            PreparedBenchmark::new(digest('a')),
            Some(RunningBenchmark::new(digest('b'))),
            Some(result),
        )
        .expect("baseline"),
        None,
        None,
        None,
        false,
        None,
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(1_001),
    )
    .expect("transaction")
}

// Opens one shared durable database fixture.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path.join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1)),
        )
        .expect("database"),
    )
}

// Persists create/replace/reopen exactly and rejects stale optimistic replacement.
#[test]
fn verification_store_round_trips_restart_and_revision_conflict() {
    let directory = tempfile::tempdir().expect("temporary");
    let first_database = database(directory.path());
    let first = DatabaseBenchmarkVerificationStore::new(first_database.clone());
    let created = first.create(transaction(false)).expect("create");
    assert_eq!(created.revision(), 1);
    let replaced = first
        .replace(transaction(true), created.revision())
        .expect("replace");
    assert_eq!(replaced.revision(), 2);
    assert!(replaced.transaction().cancellation_requested());
    assert_eq!(
        first.replace(transaction(false), created.revision()),
        Err(BenchmarkStoreError::Conflict)
    );
    drop(first);
    drop(first_database);

    let reopened = DatabaseBenchmarkVerificationStore::new(database(directory.path()));
    let restored = reopened
        .read(transaction(false).job_id())
        .expect("read")
        .expect("transaction");
    assert_eq!(restored, replaced);
}

// Preserves recovery-required state and its exact handoff identity across database restart.
#[test]
fn verification_store_reopens_restoration_failure_for_later_handoff_recovery() {
    let directory = tempfile::tempdir().expect("temporary");
    let first_database = database(directory.path());
    let first = DatabaseBenchmarkVerificationStore::new(first_database.clone());
    let expected = first
        .create(restoration_failed_transaction())
        .expect("create");
    drop(first);
    drop(first_database);

    let reopened = DatabaseBenchmarkVerificationStore::new(database(directory.path()));
    let restored = reopened
        .read(expected.transaction().job_id())
        .expect("read")
        .expect("transaction");
    assert_eq!(restored, expected);
    assert_eq!(
        restored.transaction().phase(),
        BenchmarkVerificationPhase::RestorationFailed
    );
    assert_eq!(
        restored.transaction().handoff().transaction_id(),
        &OperationId::parse(&"8".repeat(32)).expect("transaction")
    );
}

// Rejects impossible phase/receipt combinations before they can enter DatabaseManager.
#[test]
fn verification_transaction_reconstruction_rejects_phase_drift() {
    let candidate = candidate();
    assert_eq!(
        BenchmarkVerificationTransaction::restore(
            OperationId::parse(&"7".repeat(32)).expect("job"),
            candidate.sha256().expect("request digest"),
            BenchmarkVerificationHandoffReceipt::new(
                OperationId::parse(&"8".repeat(32)).expect("transaction"),
                digest('8'),
                digest('9'),
                baseline(),
                candidate,
            )
            .expect("handoff"),
            BenchmarkVerificationPhase::CandidateRunning,
            BenchmarkVerificationArmState::prepared(PreparedBenchmark::new(digest('a'))),
            None,
            None,
            None,
            false,
            None,
            UnixMilliseconds::new(1_000),
            UnixMilliseconds::new(1_000),
        ),
        Err(BenchmarkStoreError::Corrupt)
    );
}
