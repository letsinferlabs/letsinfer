// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use li_benchmark_manager::{
    decode_benchmark_telemetry_state, encode_benchmark_telemetry_state, BenchmarkKind,
    BenchmarkProgress, BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRunPlan, BenchmarkScope,
    BenchmarkSubject, BenchmarkTelemetryState,
};
use li_core_application::{
    CoreBenchmarkPortError, CoreBenchmarkTelemetryAtomicPublisher,
    CoreBenchmarkTelemetryPersistencePort, FilesystemCoreBenchmarkTelemetryPersistence,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeInstallationId,
    Sha256Digest, TechnicalName, UnixMilliseconds,
};
use sha2::{Digest, Sha256};

// Retains one owner-private filesystem root for a production-store fixture.
struct PersistenceFixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    owner_user_id: u32,
}

impl PersistenceFixture {
    // Creates one canonical owner-only telemetry directory beneath an isolated root.
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("telemetry");
        fs::create_dir(&root).expect("telemetry directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("telemetry directory mode");
        let owner_user_id = fs::symlink_metadata(&root).expect("root metadata").uid();
        Self {
            _temporary: temporary,
            root,
            owner_user_id,
        }
    }

    // Constructs one production store over the retained owner-private root.
    fn store(&self) -> FilesystemCoreBenchmarkTelemetryPersistence {
        FilesystemCoreBenchmarkTelemetryPersistence::new(self.root.clone(), self.owner_user_id)
            .expect("telemetry store")
    }

    // Returns one active telemetry file path for an exact benchmark operation.
    fn state_path(&self, job_id: &OperationId) -> PathBuf {
        self.root
            .join(format!("li_benchmark_telemetry_{}.json", job_id.as_str()))
    }

    // Returns one attempt-owned temporary path for an exact benchmark operation.
    fn temporary_path(&self, job_id: &OperationId) -> PathBuf {
        self.root
            .join(format!(".li_benchmark_telemetry_{}.tmp", job_id.as_str()))
    }
}

// Records one publication attempt and fails before active-file replacement.
#[derive(Default)]
struct FailingPublisher {
    calls: AtomicUsize,
}

impl CoreBenchmarkTelemetryAtomicPublisher for FailingPublisher {
    // Rejects one exact activation after the store has synchronized its temporary bytes.
    fn publish(
        &self,
        _temporary: &Path,
        _destination: &Path,
    ) -> Result<(), CoreBenchmarkPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CoreBenchmarkPortError::Unavailable)
    }
}

// Parses one deterministic SHA-256 fixture identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Parses one deterministic operation identity.
fn operation(character: char) -> OperationId {
    OperationId::parse(&character.to_string().repeat(32)).expect("operation")
}

// Creates one immutable local benchmark run plan for telemetry persistence.
fn plan() -> BenchmarkRunPlan {
    let subject = BenchmarkSubject::new(
        InstallationId::parse(&"1".repeat(64)).expect("installation"),
        RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
        LogicalModelName::parse("fixture-model").expect("model"),
        PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
        digest('4'),
        digest('5'),
        digest('6'),
    );
    let request = BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject)
        .expect("request");
    BenchmarkRunPlan::new(
        &request,
        BenchmarkRecordSchema::NativeExecutionPayloadV8,
        2,
        60_000,
        5_000,
        1_000,
    )
    .expect("plan")
}

// Creates one exact first-open telemetry state with no sampled windows.
fn opened_state(character: char) -> BenchmarkTelemetryState {
    let job_id = operation(character);
    let session_receipt_id = digest('8');
    let samples_sha256 = framed_digest(
        "li-benchmark-telemetry-samples-v1",
        &[job_id.as_str(), session_receipt_id.as_str(), "0"],
    );
    BenchmarkTelemetryState::new(
        job_id,
        plan(),
        digest('7'),
        session_receipt_id,
        UnixMilliseconds::new(10_000),
        None,
        0,
        samples_sha256,
        None,
        None,
        None,
    )
    .expect("opened telemetry")
}

// Advances one open timeline through its first complete telemetry window.
fn synchronized_state(
    state: &BenchmarkTelemetryState,
    digest_character: char,
) -> BenchmarkTelemetryState {
    state
        .synchronized(
            UnixMilliseconds::new(11_000),
            digest(digest_character),
            BenchmarkProgress::new(
                TechnicalName::parse("measuring").expect("phase"),
                1,
                state.plan().total_cells(),
            )
            .expect("progress"),
        )
        .expect("synchronized telemetry")
}

// Hashes one internal fixture identity with the production length-framing contract.
fn framed_digest(contract: &str, fields: &[&str]) -> Sha256Digest {
    let mut digest = Sha256::new();
    for field in std::iter::once(contract).chain(fields.iter().copied()) {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).expect("framed digest")
}

// Proves first open is durable, exact replay is idempotent, and divergent replay conflicts.
#[test]
fn open_replays_only_the_exact_existing_timeline() {
    let fixture = PersistenceFixture::new();
    let store = fixture.store();
    let state = opened_state('a');
    assert_eq!(store.read(state.job_id()), Ok(None));
    assert_eq!(store.open(state.clone()), Ok(state.clone()));
    assert_eq!(store.open(state.clone()), Ok(state.clone()));

    let conflicting = BenchmarkTelemetryState::new(
        state.job_id().clone(),
        state.plan().clone(),
        digest('9'),
        state.session_receipt_id().clone(),
        state.opened_at(),
        None,
        0,
        state.samples_sha256().clone(),
        None,
        None,
        None,
    )
    .expect("conflicting telemetry");
    assert_eq!(
        store.open(conflicting),
        Err(CoreBenchmarkPortError::Conflict)
    );
    let path = fixture.state_path(state.job_id());
    let metadata = fs::symlink_metadata(&path).expect("state metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let bytes = fs::read(path).expect("state bytes");
    assert_eq!(
        bytes,
        encode_benchmark_telemetry_state(&state).expect("canonical bytes")
    );
}

// Proves replacement compares the exact prior identities and never publishes stale work.
#[test]
fn replace_is_exactly_optimistic_and_conflicts_without_mutation() {
    let fixture = PersistenceFixture::new();
    let store = fixture.store();
    let opened = opened_state('b');
    store.open(opened.clone()).expect("open");
    let synchronized = synchronized_state(&opened, 'a');
    assert_eq!(
        store.replace(
            synchronized.clone(),
            opened.samples_sha256(),
            opened.sealed_receipt_id(),
        ),
        Ok(synchronized.clone())
    );

    let stale = synchronized_state(&opened, 'b');
    assert_eq!(
        store.replace(stale, opened.samples_sha256(), opened.sealed_receipt_id(),),
        Err(CoreBenchmarkPortError::Conflict)
    );
    assert_eq!(store.read(opened.job_id()), Ok(Some(synchronized)));
}

// Proves a new process composition reconstructs the exact codec-validated persisted timeline.
#[test]
fn restart_reads_the_complete_committed_timeline() {
    let fixture = PersistenceFixture::new();
    let state = opened_state('c');
    fixture.store().open(state.clone()).expect("open");

    let restarted = fixture.store();
    assert_eq!(restarted.read(state.job_id()), Ok(Some(state.clone())));
    let bytes = fs::read(fixture.state_path(state.job_id())).expect("state bytes");
    assert_eq!(
        decode_benchmark_telemetry_state(&bytes).expect("decoded state"),
        state
    );
}

// Proves corrupt bytes, links, foreign ownership expectations, and broad modes fail closed.
#[test]
fn unsafe_or_corrupt_filesystem_state_is_rejected() {
    let fixture = PersistenceFixture::new();
    let store = fixture.store();

    let corrupt = opened_state('d');
    store.open(corrupt.clone()).expect("corrupt fixture open");
    fs::write(fixture.state_path(corrupt.job_id()), b"{}").expect("corrupt persisted document");
    assert_eq!(
        store.read(corrupt.job_id()),
        Err(CoreBenchmarkPortError::InvalidState)
    );

    let linked = opened_state('e');
    let outside = fixture._temporary.path().join("outside.json");
    fs::write(&outside, b"{}").expect("outside bytes");
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("outside mode");
    symlink(&outside, fixture.state_path(linked.job_id())).expect("state symlink");
    assert_eq!(
        store.read(linked.job_id()),
        Err(CoreBenchmarkPortError::InvalidState)
    );

    let broad = opened_state('f');
    store.open(broad.clone()).expect("broad fixture open");
    fs::set_permissions(
        fixture.state_path(broad.job_id()),
        fs::Permissions::from_mode(0o644),
    )
    .expect("broad state mode");
    assert_eq!(
        store.read(broad.job_id()),
        Err(CoreBenchmarkPortError::InvalidState)
    );

    assert!(matches!(
        FilesystemCoreBenchmarkTelemetryPersistence::new(
            fixture.root.clone(),
            fixture.owner_user_id ^ 1,
        ),
        Err(CoreBenchmarkPortError::InvalidState)
    ));
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).expect("broad root mode");
    assert!(matches!(
        FilesystemCoreBenchmarkTelemetryPersistence::new(
            fixture.root.clone(),
            fixture.owner_user_id,
        ),
        Err(CoreBenchmarkPortError::InvalidState)
    ));
}

// Proves failure before atomic activation preserves old bytes and removes attempt-owned state.
#[test]
fn atomic_publication_failure_rolls_back_to_the_previous_timeline() {
    let fixture = PersistenceFixture::new();
    let opened = opened_state('1');
    fixture.store().open(opened.clone()).expect("open");
    let replacement = synchronized_state(&opened, 'c');
    let publisher = Arc::new(FailingPublisher::default());
    let failing = FilesystemCoreBenchmarkTelemetryPersistence::with_publisher(
        fixture.root.clone(),
        fixture.owner_user_id,
        publisher.clone(),
    )
    .expect("failing store");

    assert_eq!(
        failing.replace(
            replacement,
            opened.samples_sha256(),
            opened.sealed_receipt_id(),
        ),
        Err(CoreBenchmarkPortError::Unavailable)
    );
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);
    assert!(!fixture.temporary_path(opened.job_id()).exists());
    assert_eq!(fixture.store().read(opened.job_id()), Ok(Some(opened)));
}
