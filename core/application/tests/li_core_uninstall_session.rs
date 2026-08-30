// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreUninstallBoundary, CoreUninstallBoundaryReceipt, CoreUninstallModelDisposition,
    CoreUninstallOwnedTarget, CoreUninstallPlan, CoreUninstallSession,
    CoreUninstallSessionDisposition, CoreUninstallSessionError, CoreUninstallSessionIdSource,
    CoreUninstallSessionPhase, CoreUninstallSessionRetention, CoreUninstallTargetKind,
    FilesystemCoreUninstallSessionOwner, SystemCoreUninstallSessionIdSource,
};
use li_core_interface::Sha256Digest;
use tempfile::TempDir;

// Supplies a closed identity sequence and exposes whether a reopen incorrectly consumed one.
struct SessionIdSourceMock {
    identities: Mutex<VecDeque<Sha256Digest>>,
}

impl SessionIdSourceMock {
    // Creates one deterministic source from exact hexadecimal identity prefixes.
    fn new(prefixes: &[char]) -> Self {
        Self {
            identities: Mutex::new(prefixes.iter().map(|prefix| digest(*prefix)).collect()),
        }
    }

    // Returns the number of identities not yet consumed by a first admission.
    fn remaining(&self) -> usize {
        self.identities.lock().expect("identities").len()
    }
}

impl CoreUninstallSessionIdSource for SessionIdSourceMock {
    // Removes exactly one fixture identity or reports deterministic exhaustion.
    fn next_session_id(&self) -> Result<Sha256Digest, CoreUninstallSessionError> {
        self.identities
            .lock()
            .map_err(|_| CoreUninstallSessionError::IdentityUnavailable)?
            .pop_front()
            .ok_or(CoreUninstallSessionError::IdentityUnavailable)
    }
}

// Owns one canonical owner-private state root for production-shaped filesystem tests.
struct SessionFixture {
    _temporary: TempDir,
    root: PathBuf,
}

impl SessionFixture {
    // Creates an existing canonical 0700 state root under the platform temporary directory.
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = fs::canonicalize(temporary.path()).expect("canonical root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        Self {
            _temporary: temporary,
            root,
        }
    }
}

// Returns one deterministic SHA-256 domain value.
fn digest(prefix: char) -> Sha256Digest {
    Sha256Digest::parse(&prefix.to_string().repeat(64)).expect("digest")
}

// Creates one production owner from an injected deterministic source.
fn owner(root: &Path, source: Arc<SessionIdSourceMock>) -> FilesystemCoreUninstallSessionOwner {
    FilesystemCoreUninstallSessionOwner::new(root.to_path_buf(), unsafe { libc::getuid() }, source)
        .expect("session owner")
}

// Writes an exact owner-private fixture document without replacing journal validation logic.
fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("private file");
    file.write_all(bytes).expect("write fixture");
    file.sync_all().expect("sync fixture");
}

// Replaces one unlocked journal fixture while retaining exact owner-only metadata.
fn replace_private(path: &Path, bytes: &[u8]) {
    fs::remove_file(path).expect("remove fixture");
    write_private(path, bytes);
}

// Creates one exact target without copying the production plan validator.
fn target(
    kind: CoreUninstallTargetKind,
    identity: impl Into<String>,
    proof: char,
) -> CoreUninstallOwnedTarget {
    CoreUninstallOwnedTarget::new(kind, identity, digest(proof)).expect("target")
}

// Creates one complete plan with at least one target assigned to every mutation boundary.
fn fixture_plan(disposition: CoreUninstallModelDisposition) -> CoreUninstallPlan {
    let mut targets = vec![
        target(CoreUninstallTargetKind::ActiveBenchmark, "benchmark:a", '1'),
        target(CoreUninstallTargetKind::PublicExposure, "exposure:a", '2'),
        target(CoreUninstallTargetKind::PlacementGroup, "placement:a", '3'),
        target(CoreUninstallTargetKind::ModelService, "model:a", '4'),
        target(CoreUninstallTargetKind::PlatformService, "service:a", '5'),
        target(
            CoreUninstallTargetKind::RuntimeInstallation,
            "runtime:a",
            '6',
        ),
        target(
            CoreUninstallTargetKind::ManagedContainer,
            "container:a",
            '7',
        ),
        target(CoreUninstallTargetKind::ManagedImage, "image:a", '8'),
        target(CoreUninstallTargetKind::OwnerRoot, "owner:a", '9'),
        target(
            CoreUninstallTargetKind::CoreConfiguration,
            "configuration:a",
            'f',
        ),
        target(CoreUninstallTargetKind::CoreInstallation, "core:a", 'a'),
        target(CoreUninstallTargetKind::Launcher, "launcher:a", 'b'),
    ];
    if disposition == CoreUninstallModelDisposition::RemoveModels {
        targets.push(target(CoreUninstallTargetKind::ModelRoot, "models:a", 'c'));
    }
    CoreUninstallPlan::new(digest('f'), disposition, Duration::from_secs(30), targets)
        .expect("plan")
}

// Creates all seven exact boundary receipts in their irreversible order.
fn fixture_receipts(plan: &CoreUninstallPlan) -> Vec<CoreUninstallBoundaryReceipt> {
    [
        CoreUninstallBoundary::BenchmarkExit,
        CoreUninstallBoundary::PublicExposure,
        CoreUninstallBoundary::Workloads,
        CoreUninstallBoundary::RuntimeArtifacts,
        CoreUninstallBoundary::PlatformServices,
        CoreUninstallBoundary::OwnerData,
        CoreUninstallBoundary::ImmutableCore,
    ]
    .into_iter()
    .map(|boundary| CoreUninstallBoundaryReceipt::completed(plan, boundary).expect("receipt"))
    .collect()
}

// Drives one session to an exact durable phase without bypassing its public transition API.
fn drive_to_phase(
    session: &mut CoreUninstallSession,
    plan: &CoreUninstallPlan,
    phase: CoreUninstallSessionPhase,
) {
    if phase == CoreUninstallSessionPhase::Admitting {
        return;
    }
    session.persist_plan(plan).expect("persist plan");
    if phase == CoreUninstallSessionPhase::Planned {
        return;
    }
    let receipts = fixture_receipts(plan);
    for receipt in &receipts[..4] {
        session
            .append_receipt(receipt)
            .expect("pre-service receipt");
    }
    session
        .advance_phase(CoreUninstallSessionPhase::ServicesRetiring)
        .expect("services retiring");
    if phase == CoreUninstallSessionPhase::ServicesRetiring {
        return;
    }
    session
        .append_receipt(&receipts[4])
        .expect("service receipt");
    session
        .advance_phase(CoreUninstallSessionPhase::ServicesRetired)
        .expect("services retired");
    if phase == CoreUninstallSessionPhase::ServicesRetired {
        return;
    }
    session
        .advance_phase(CoreUninstallSessionPhase::CoreRetiring)
        .expect("core retiring");
    session
        .append_receipt(&receipts[5])
        .expect("owner-data receipt");
}

// Proves first admission is durable and process interruption reopens the exact same identity.
#[test]
fn create_and_process_death_reopen_one_exact_session() {
    let _production_identity_source = SystemCoreUninstallSessionIdSource;
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['a', 'b']));
    let owner = owner(&fixture.root, source.clone());

    let first = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("first session");
    assert_eq!(first.session_id(), &digest('a'));
    assert_eq!(first.retention(), CoreUninstallSessionRetention::KeepModels);
    assert_eq!(
        first.disposition(),
        CoreUninstallSessionDisposition::Applied
    );
    assert!(first.owns_process_lock());
    assert!(owner.journal_path().is_file());
    let journal_metadata = fs::symlink_metadata(owner.journal_path()).expect("journal metadata");
    assert_eq!(journal_metadata.uid(), unsafe { libc::getuid() });
    assert_eq!(journal_metadata.mode() & 0o7777, 0o600);
    assert_eq!(journal_metadata.nlink(), 1);
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(owner.journal_path()).expect("journal bytes"))
            .expect("journal document");
    assert_eq!(journal.as_object().expect("journal object").len(), 6);
    assert_eq!(journal["schema"]["name"], "li_core_uninstall_session");
    assert_eq!(journal["schema"]["version"], 1);
    assert_eq!(journal["session_id"], "a".repeat(64));
    assert_eq!(journal["retention"], "keep_models");
    assert_eq!(journal["phase"], "admitting");
    assert!(journal["plan"].is_null());
    assert_eq!(journal["receipts"], serde_json::json!([]));
    drop(first);

    let reopened = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("reopened session");
    assert_eq!(reopened.session_id(), &digest('a'));
    assert_eq!(
        reopened.disposition(),
        CoreUninstallSessionDisposition::Reopened
    );
    assert_eq!(source.remaining(), 1);
}

// Proves the OS lock rejects a concurrent CLI process without waiting or changing the journal.
#[test]
fn active_raii_session_rejects_lock_contention() {
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['a', 'b']));
    let owner = owner(&fixture.root, source.clone());
    let active = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("active session");

    assert!(matches!(
        owner.begin(CoreUninstallSessionRetention::KeepModels),
        Err(CoreUninstallSessionError::OperationConflict)
    ));
    assert_eq!(source.remaining(), 1);
    assert_eq!(active.session_id(), &digest('a'));
}

// Proves a recovered journal cannot be reopened under a different model-retention policy.
#[test]
fn recovered_policy_mismatch_conflicts_without_consuming_identity() {
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['a', 'b']));
    let owner = owner(&fixture.root, source.clone());
    owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("first session")
        .preserve_for_service_recovery();

    assert!(matches!(
        owner.begin(CoreUninstallSessionRetention::RemoveModels),
        Err(CoreUninstallSessionError::OperationConflict)
    ));
    assert_eq!(source.remaining(), 1);
}

// Proves foreign schema, malformed, oversized, unsafe-mode, and symbolic journals fail closed.
#[test]
fn unsafe_and_corrupt_journals_are_rejected_as_one_closed_matrix() {
    let cases: &[(&str, &[u8], u32, bool)] = &[
        (
            "foreign-schema",
            br#"{"schema":{"name":"foreign","version":1},"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retention":"keep_models","phase":"admitting","plan":null,"receipts":[]}"#,
            0o600,
            false,
        ),
        (
            "foreign-version",
            br#"{"schema":{"name":"li_core_uninstall_session","version":2},"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retention":"keep_models","phase":"admitting","plan":null,"receipts":[]}"#,
            0o600,
            false,
        ),
        (
            "unknown-field",
            br#"{"schema":{"name":"li_core_uninstall_session","version":1},"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retention":"keep_models","phase":"admitting","plan":null,"receipts":[],"foreign":true}"#,
            0o600,
            false,
        ),
        ("malformed", b"{", 0o600, false),
        (
            "unsafe-mode",
            br#"{"schema":{"name":"li_core_uninstall_session","version":1},"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retention":"keep_models","phase":"admitting","plan":null,"receipts":[]}"#,
            0o644,
            false,
        ),
        ("symbolic", b"{}", 0o600, true),
    ];
    for (name, bytes, mode, symbolic) in cases {
        let fixture = SessionFixture::new();
        let source = Arc::new(SessionIdSourceMock::new(&['b']));
        let owner = owner(&fixture.root, source.clone());
        let journal = owner.journal_path();
        if *symbolic {
            let target = fixture.root.join("foreign.json");
            write_private(&target, bytes);
            symlink(&target, &journal).expect("journal symlink");
        } else {
            write_private(&journal, bytes);
            fs::set_permissions(&journal, fs::Permissions::from_mode(*mode)).expect("journal mode");
        }

        assert!(
            owner
                .begin(CoreUninstallSessionRetention::KeepModels)
                .is_err(),
            "case={name}"
        );
        assert_eq!(source.remaining(), 1, "case={name}");
    }

    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['b']));
    let owner = owner(&fixture.root, source.clone());
    write_private(&owner.journal_path(), &vec![b'x'; 16 * 1_024 * 1_024 + 1]);
    assert!(matches!(
        owner.begin(CoreUninstallSessionRetention::KeepModels),
        Err(CoreUninstallSessionError::InvalidJournal)
    ));
    assert_eq!(source.remaining(), 1);
}

// Proves symbolic, unsafe-mode, and foreign-owner roots are rejected before lock creation.
#[test]
fn unsafe_state_roots_are_rejected_before_admission() {
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['a']));
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).expect("unsafe mode");
    assert!(matches!(
        FilesystemCoreUninstallSessionOwner::new(
            fixture.root.clone(),
            unsafe { libc::getuid() },
            source.clone(),
        ),
        Err(CoreUninstallSessionError::InvalidStateRoot)
    ));
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).expect("private mode");
    assert!(matches!(
        FilesystemCoreUninstallSessionOwner::new(
            fixture.root.clone(),
            unsafe { libc::getuid() }.saturating_add(1),
            source,
        ),
        Err(CoreUninstallSessionError::InvalidStateRoot)
    ));
    let target = fixture.root.join("target");
    let symbolic = fixture.root.join("symbolic");
    fs::create_dir(&target).expect("target root");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("target mode");
    symlink(&target, &symbolic).expect("symbolic root");
    assert!(matches!(
        FilesystemCoreUninstallSessionOwner::new(
            symbolic,
            unsafe { libc::getuid() },
            Arc::new(SessionIdSourceMock::new(&['b'])),
        ),
        Err(CoreUninstallSessionError::InvalidStateRoot)
    ));
}

// Proves the journal survives an ambiguous Node attempt and is available to the next process.
#[test]
fn ambiguous_node_attempt_survives_with_the_preexchanged_identity() {
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['c']));
    let owner = owner(&fixture.root, source.clone());
    let attempt = owner
        .begin(CoreUninstallSessionRetention::RemoveModels)
        .expect("durable attempt");
    let sent_identity = attempt.session_id().clone();
    drop(attempt);

    let recovery = owner
        .begin(CoreUninstallSessionRetention::RemoveModels)
        .expect("recovery");
    assert_eq!(recovery.session_id(), &sent_identity);
    assert_eq!(
        recovery.disposition(),
        CoreUninstallSessionDisposition::Reopened
    );
    assert_eq!(source.remaining(), 0);
}

// Proves every phase reopens with the exact plan and contiguous receipt prefix after a crash.
#[test]
fn every_recovery_phase_reopens_without_losing_domain_identity() {
    let plan = fixture_plan(CoreUninstallModelDisposition::RemoveModels);
    for (phase, receipt_count) in [
        (CoreUninstallSessionPhase::Admitting, 0),
        (CoreUninstallSessionPhase::Planned, 0),
        (CoreUninstallSessionPhase::ServicesRetiring, 4),
        (CoreUninstallSessionPhase::ServicesRetired, 5),
        (CoreUninstallSessionPhase::CoreRetiring, 6),
    ] {
        let fixture = SessionFixture::new();
        let source = Arc::new(SessionIdSourceMock::new(&['d', 'e']));
        let owner = owner(&fixture.root, source.clone());
        let mut first = owner
            .begin(CoreUninstallSessionRetention::RemoveModels)
            .expect("first session");
        drive_to_phase(&mut first, &plan, phase);
        let before = first.recovery_state().expect("recovery state");
        assert_eq!(before.phase(), phase);
        assert_eq!(before.receipts().len(), receipt_count);
        assert_eq!(
            before.plan(),
            (phase != CoreUninstallSessionPhase::Admitting).then_some(&plan)
        );
        first.preserve_for_service_recovery();

        let reopened = owner
            .begin(CoreUninstallSessionRetention::RemoveModels)
            .expect("reopened session");
        let after = reopened.recovery_state().expect("reopened state");
        assert_eq!(after, before, "phase={phase:?}");
        assert_eq!(after.session_id(), &digest('d'));
        assert_eq!(
            after.retention(),
            CoreUninstallSessionRetention::RemoveModels
        );
        assert_eq!(source.remaining(), 1);
    }
}

// Proves receipts and phases accept exact replay but reject gaps, foreign plans, and skips.
#[test]
fn phase_and_receipt_apis_are_contiguous_monotonic_and_plan_bound() {
    let fixture = SessionFixture::new();
    let owner = owner(&fixture.root, Arc::new(SessionIdSourceMock::new(&['a'])));
    let plan = fixture_plan(CoreUninstallModelDisposition::RemoveModels);
    let foreign = CoreUninstallPlan::new(
        digest('e'),
        CoreUninstallModelDisposition::RemoveModels,
        Duration::from_secs(30),
        plan.targets().to_vec(),
    )
    .expect("foreign plan");
    let receipts = fixture_receipts(&plan);
    let foreign_receipt =
        CoreUninstallBoundaryReceipt::completed(&foreign, CoreUninstallBoundary::BenchmarkExit)
            .expect("foreign receipt");
    let mut session = owner
        .begin(CoreUninstallSessionRetention::RemoveModels)
        .expect("session");

    assert!(session
        .advance_phase(CoreUninstallSessionPhase::ServicesRetiring)
        .is_err());
    session.persist_plan(&plan).expect("plan");
    session.persist_plan(&plan).expect("plan replay");
    assert!(session.persist_plan(&foreign).is_err());
    assert!(session.append_receipt(&receipts[1]).is_err());
    assert!(session.append_receipt(&foreign_receipt).is_err());
    session.append_receipt(&receipts[0]).expect("first receipt");
    session
        .append_receipt(&receipts[0])
        .expect("receipt replay");
    assert!(session
        .advance_phase(CoreUninstallSessionPhase::ServicesRetired)
        .is_err());
    for receipt in &receipts[1..4] {
        session.append_receipt(receipt).expect("ordered receipt");
    }
    session
        .advance_phase(CoreUninstallSessionPhase::ServicesRetiring)
        .expect("services retiring");
    assert!(session.append_receipt(&receipts[5]).is_err());
    assert!(session.retire_after_node_cancel().is_err());
}

// Rejects every persisted policy, plan, receipt, gap, and phase mutation on reopen.
#[test]
fn recovered_wire_document_rejects_tamper_and_noncontiguous_state() {
    for case in [
        "plan-digest",
        "target-digest",
        "receipt-digest",
        "receipt-gap",
        "policy",
        "phase",
    ] {
        let fixture = SessionFixture::new();
        let source = Arc::new(SessionIdSourceMock::new(&['a', 'b']));
        let owner = owner(&fixture.root, source.clone());
        let plan = fixture_plan(CoreUninstallModelDisposition::RemoveModels);
        let receipts = fixture_receipts(&plan);
        let mut session = owner
            .begin(CoreUninstallSessionRetention::RemoveModels)
            .expect("session");
        session.persist_plan(&plan).expect("plan");
        session.append_receipt(&receipts[0]).expect("receipt zero");
        session.append_receipt(&receipts[1]).expect("receipt one");
        session.preserve_for_service_recovery();
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(owner.journal_path()).expect("journal bytes"))
                .expect("journal");
        match case {
            "plan-digest" => document["plan"]["plan_id"] = serde_json::json!("e".repeat(64)),
            "target-digest" => {
                document["plan"]["targets"][0]["ownership_sha256"] =
                    serde_json::json!("e".repeat(64));
            }
            "receipt-digest" => {
                document["receipts"][0]["target_set_sha256"] = serde_json::json!("e".repeat(64));
            }
            "receipt-gap" => document["receipts"]
                .as_array_mut()
                .expect("receipts")
                .swap(0, 1),
            "policy" => document["retention"] = serde_json::json!("keep_models"),
            "phase" => document["phase"] = serde_json::json!("services_retired"),
            _ => unreachable!(),
        }
        replace_private(
            &owner.journal_path(),
            &serde_json::to_vec(&document).expect("mutated document"),
        );

        assert!(
            matches!(
                owner.begin(CoreUninstallSessionRetention::RemoveModels),
                Err(CoreUninstallSessionError::InvalidJournal)
            ),
            "case={case}"
        );
        assert_eq!(source.remaining(), 1, "case={case}");
    }
}

// Reconciles safe atomic-rewrite residue and proves the journal admits all 4096 plan targets.
#[test]
fn atomic_rewrite_residue_is_removed_without_losing_the_maximum_plan() {
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['a', 'b']));
    let owner = owner(&fixture.root, source.clone());
    let targets = (0..4_096)
        .map(|index| {
            target(
                CoreUninstallTargetKind::OwnerRoot,
                format!("{index:04}:{}", "\\".repeat(1_019)),
                'd',
            )
        })
        .collect();
    let plan = CoreUninstallPlan::new(
        digest('f'),
        CoreUninstallModelDisposition::KeepModels,
        Duration::from_secs(30),
        targets,
    )
    .expect("maximum plan");
    let mut first = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("session");
    first.persist_plan(&plan).expect("persist maximum plan");
    first.preserve_for_service_recovery();
    let temporary = fixture.root.join(".li_core_uninstall_session_v1.tmp");
    write_private(&temporary, b"safe interrupted rewrite");

    let reopened = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("reopened maximum plan");
    assert!(!temporary.exists());
    assert_eq!(
        reopened
            .recovery_state()
            .expect("recovery")
            .plan()
            .expect("plan")
            .targets()
            .len(),
        4_096
    );
    assert!(fs::metadata(owner.journal_path()).expect("journal").len() < 16 * 1_024 * 1_024);
    assert_eq!(source.remaining(), 1);
}

// Proves only confirmed matching cancellation retires the journal and enables a fresh identity.
#[test]
fn exact_retirement_removes_journal_and_next_begin_is_fresh() {
    let fixture = SessionFixture::new();
    let source = Arc::new(SessionIdSourceMock::new(&['a', 'b']));
    let owner = owner(&fixture.root, source);
    let first = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("first session");
    assert!(owner.journal_path().is_file());
    first
        .retire_after_node_cancel()
        .expect("confirmed cancellation retirement");
    assert!(!owner.journal_path().exists());

    let second = owner
        .begin(CoreUninstallSessionRetention::KeepModels)
        .expect("fresh session");
    assert_eq!(second.session_id(), &digest('b'));
    assert_eq!(
        second.disposition(),
        CoreUninstallSessionDisposition::Applied
    );
}
