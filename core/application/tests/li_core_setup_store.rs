// SPDX-License-Identifier: AGPL-3.0-only

use std::env;
use std::fs::{self, File};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use li_core_application::{
    CoreSetupBenchmarkSigningMaterial, CoreSetupError, CoreSetupExecutionLockProvider,
    CoreSetupInstalledConfigurations, CoreSetupInstalledServices, CoreSetupJournal,
    CoreSetupJournalStore, CoreSetupPhase, CoreSetupPreparedIdentity, CoreSetupPreparedMaterial,
    CoreSetupReceipt, CoreSetupResult, CoreSetupStoreError, SystemCoreSetupExecutionLockProvider,
    SystemCoreSetupJournalStore, VersionedCoreSetupJournal, CORE_SETUP_JOURNAL_SCHEMA_NAME,
    CORE_SETUP_JOURNAL_SCHEMA_VERSION,
};
use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeRole, Sha256Digest,
};
use serde_json::{json, Value};
use tempfile::TempDir;

const LOCK_CHILD_ROOT: &str = "LI_CORE_SETUP_LOCK_CHILD_ROOT";
const LOCK_CHILD_MARKER: &str = "LI_CORE_SETUP_LOCK_CHILD_MARKER";
const LOCK_CHILD_RELEASE: &str = "LI_CORE_SETUP_LOCK_CHILD_RELEASE";

// Owns one exact private root and production store for a native integration test.
struct StoreFixture {
    _temporary: TempDir,
    root: PathBuf,
    store: SystemCoreSetupJournalStore,
    request_id: Sha256Digest,
}

impl StoreFixture {
    // Creates one exact owner-private root without relying on provider directory creation.
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary directory")
            .join("setup");
        fs::create_dir(&root).expect("private root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root mode");
        let store = SystemCoreSetupJournalStore::new(root.clone(), effective_user())
            .expect("journal store");
        Self {
            _temporary: temporary,
            root,
            store,
            request_id: digest('f'),
        }
    }

    // Returns the fixed request-addressed authoritative journal path.
    fn journal_file(&self) -> PathBuf {
        journal_file(&self.root, &self.request_id)
    }

    // Returns the fixed request-addressed pending journal path.
    fn pending_file(&self) -> PathBuf {
        pending_file(&self.root, &self.request_id)
    }
}

// Proves a restarted production store preserves every exact closure and revision.
#[test]
fn journal_round_trips_and_restarts_at_every_durable_phase() {
    let fixture = StoreFixture::new();
    let phases = phases();
    for (index, phase) in phases.into_iter().enumerate() {
        let expected = journal(phase);
        let written = if index == 0 {
            fixture.store.create(expected.clone()).expect("create")
        } else {
            fixture
                .store
                .replace(expected.clone(), index as u64)
                .expect("replace")
        };
        assert_eq!(written.revision(), index as u64 + 1);
        assert_eq!(written.journal(), &expected);
        let restarted = SystemCoreSetupJournalStore::new(fixture.root.clone(), effective_user())
            .expect("restarted store");
        assert_eq!(
            restarted.read(&fixture.request_id).expect("read"),
            Some(written)
        );
    }
}

// Selects exactly one incomplete native journal while ignoring completed setup history.
#[test]
fn recovery_enumeration_is_bounded_to_one_incomplete_journal() {
    let fixture = StoreFixture::new();
    advance_request(&fixture.store, 'f', CoreSetupPhase::Completed);
    assert_eq!(fixture.store.recovery().expect("completed history"), None);

    let incomplete = advance_request(&fixture.store, 'd', CoreSetupPhase::ConfigurationsInstalled);
    assert_eq!(
        fixture.store.recovery().expect("one incomplete"),
        Some(incomplete)
    );

    advance_request(&fixture.store, 'c', CoreSetupPhase::ConfigurationsInstalled);
    assert_eq!(fixture.store.recovery(), Err(CoreSetupStoreError::Corrupt));
}

// Proves staged creates and every staged phase replacement recover after a process crash.
#[test]
fn journal_reconciles_a_crash_before_every_atomic_publication() {
    for (index, phase) in phases().into_iter().enumerate() {
        let source = StoreFixture::new();
        let source_state = advance_to(&source, phase);
        let destination = StoreFixture::new();
        if index > 0 {
            advance_to(&destination, phases()[index - 1]);
        }
        write_private(
            &destination.pending_file(),
            &fs::read(source.journal_file()).expect("staged source"),
        );
        let restarted =
            SystemCoreSetupJournalStore::new(destination.root.clone(), effective_user())
                .expect("restarted store");
        assert_eq!(
            restarted.read(&destination.request_id).expect("reconcile"),
            Some(source_state)
        );
        assert!(!destination.pending_file().exists());
    }
}

// Proves a crash after visible publication only retires an identical staged duplicate.
#[test]
fn journal_reconciles_an_ambiguous_success_without_replacing_state() {
    let fixture = StoreFixture::new();
    let expected = advance_to(&fixture, CoreSetupPhase::ConfigurationsInstalled);
    write_private(
        &fixture.pending_file(),
        &fs::read(fixture.journal_file()).expect("authoritative bytes"),
    );
    let observed = fixture.store.read(&fixture.request_id).expect("reconcile");
    assert_eq!(observed, Some(expected));
    assert!(!fixture.pending_file().exists());
}

// Proves optimistic replacement, removal, zero, stale, and skipped revisions fail closed.
#[test]
fn journal_enforces_exact_create_replace_and_remove_cas() {
    let fixture = StoreFixture::new();
    let prepared = fixture
        .store
        .create(journal(CoreSetupPhase::Prepared))
        .expect("create");
    assert_eq!(
        fixture
            .store
            .create(journal(CoreSetupPhase::IdentityPrepared)),
        Err(CoreSetupStoreError::Corrupt)
    );
    assert_eq!(
        fixture
            .store
            .create(journal(CoreSetupPhase::Prepared))
            .expect("idempotent create"),
        prepared
    );
    assert_eq!(
        fixture
            .store
            .replace(journal(CoreSetupPhase::IdentityPrepared), 0),
        Err(CoreSetupStoreError::Corrupt)
    );
    assert_eq!(
        fixture
            .store
            .replace(journal(CoreSetupPhase::MaterialPrepared), 1),
        Err(CoreSetupStoreError::Conflict)
    );
    let identity = fixture
        .store
        .replace(journal(CoreSetupPhase::IdentityPrepared), 1)
        .expect("identity replace");
    assert_eq!(identity.revision(), 2);
    assert_eq!(
        fixture
            .store
            .replace(journal(CoreSetupPhase::MaterialPrepared), 1),
        Err(CoreSetupStoreError::Conflict)
    );
    assert_eq!(
        fixture.store.remove(&fixture.request_id, 1),
        Err(CoreSetupStoreError::Conflict)
    );
    fixture
        .store
        .remove(&fixture.request_id, 2)
        .expect("exact removal");
    assert_eq!(
        fixture.store.read(&fixture.request_id).expect("absent"),
        None
    );
}

// Proves the store's native operation lock gives one winner for the same optimistic revision.
#[test]
fn journal_parallel_cas_has_exactly_one_winner() {
    let fixture = StoreFixture::new();
    fixture
        .store
        .create(journal(CoreSetupPhase::Prepared))
        .expect("prepared");
    let entered = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let root = fixture.root.clone();
        let entered = entered.clone();
        workers.push(thread::spawn(move || {
            let store =
                SystemCoreSetupJournalStore::new(root, effective_user()).expect("worker store");
            entered.wait();
            store
                .replace(journal(CoreSetupPhase::IdentityPrepared), 1)
                .is_ok()
        }));
    }
    let winners = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);
    assert_eq!(
        fixture
            .store
            .read(&fixture.request_id)
            .expect("authoritative")
            .expect("journal")
            .revision(),
        2
    );
}

// Proves two parallel processes represented by native descriptors expose one lock winner.
#[test]
fn execution_lock_has_one_parallel_winner_and_releases_cleanly() {
    let fixture = StoreFixture::new();
    let entered = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let root = fixture.root.clone();
        let entered = entered.clone();
        let attempted = attempted.clone();
        workers.push(thread::spawn(move || {
            let provider = SystemCoreSetupExecutionLockProvider::new(root, effective_user())
                .expect("provider");
            entered.wait();
            let lock = provider.try_acquire();
            attempted.wait();
            lock.is_ok()
        }));
    }
    let winners = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);
    let provider =
        SystemCoreSetupExecutionLockProvider::new(fixture.root.clone(), effective_user())
            .expect("provider");
    assert!(provider.try_acquire().is_ok());
}

// Holds the production lock in a child test process for the parent contention proof.
#[test]
fn native_lock_child_holds_owner_lock() {
    let Ok(root) = env::var(LOCK_CHILD_ROOT) else {
        return;
    };
    let marker = PathBuf::from(env::var(LOCK_CHILD_MARKER).expect("marker"));
    let release = PathBuf::from(env::var(LOCK_CHILD_RELEASE).expect("release"));
    let provider = SystemCoreSetupExecutionLockProvider::new(root.into(), effective_user())
        .expect("child provider");
    let _lock = provider.try_acquire().expect("child lock");
    fs::write(marker, b"locked").expect("marker write");
    wait_for_path(&release, "release");
}

// Proves flock ownership excludes a separately executing process, not only Rust threads.
#[test]
fn execution_lock_excludes_a_second_process() {
    let fixture = StoreFixture::new();
    let marker = fixture._temporary.path().join("locked");
    let release = fixture._temporary.path().join("release");
    let mut child = Command::new(env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "native_lock_child_holds_owner_lock",
            "--nocapture",
        ])
        .env(LOCK_CHILD_ROOT, &fixture.root)
        .env(LOCK_CHILD_MARKER, &marker)
        .env(LOCK_CHILD_RELEASE, &release)
        .spawn()
        .expect("lock child");
    wait_for_path(&marker, "lock marker");
    let provider =
        SystemCoreSetupExecutionLockProvider::new(fixture.root.clone(), effective_user())
            .expect("provider");
    assert!(matches!(provider.try_acquire(), Err(CoreSetupError::Busy)));
    fs::write(&release, b"release").expect("release write");
    assert!(child.wait().expect("child status").success());
    assert!(provider.try_acquire().is_ok());
}

// Proves link, type, mode, and size attacks on an authoritative journal all fail closed.
#[test]
fn journal_rejects_unsafe_file_matrices() {
    assert_file_attack(|file, _root| {
        fs::set_permissions(file, fs::Permissions::from_mode(0o640)).expect("unsafe mode");
    });
    assert_file_attack(|file, root| {
        fs::hard_link(file, root.join("journal_alias")).expect("hard link");
    });
    assert_file_attack(|file, root| {
        let target = root.join("journal_target");
        fs::rename(file, &target).expect("target move");
        symlink(&target, file).expect("journal symlink");
    });
    assert_file_attack(|file, _root| {
        fs::remove_file(file).expect("journal removal");
        fs::create_dir(file).expect("journal directory");
    });
    assert_file_attack(|file, _root| {
        let oversized = File::create(file).expect("oversized file");
        oversized.set_len(256 * 1024 + 1).expect("oversized length");
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("oversized mode");
    });
}

// Proves unsafe roots, symlink traversal, foreign ownership, and malformed locks are refused.
#[test]
fn adapters_reject_unsafe_root_and_lock_matrices() {
    let fixture = StoreFixture::new();
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o750)).expect("unsafe root");
    assert!(SystemCoreSetupJournalStore::new(fixture.root.clone(), effective_user()).is_err());

    let fixture = StoreFixture::new();
    assert!(SystemCoreSetupJournalStore::new(
        fixture.root.clone(),
        effective_user().wrapping_add(1),
    )
    .is_err());

    let temporary = tempfile::tempdir().expect("temporary directory");
    let real = temporary.path().join("real");
    fs::create_dir(&real).expect("real root");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("real mode");
    let linked = temporary.path().join("linked");
    symlink(&real, &linked).expect("linked root");
    assert!(SystemCoreSetupJournalStore::new(linked, effective_user()).is_err());

    assert_lock_attack(|lock, _root| {
        fs::write(lock, b"unexpected lock payload").expect("lock payload");
        fs::set_permissions(lock, fs::Permissions::from_mode(0o600)).expect("lock mode");
    });
    assert_lock_attack(|lock, _root| {
        fs::set_permissions(lock, fs::Permissions::from_mode(0o644)).expect("lock mode");
    });
    assert_lock_attack(|lock, root| {
        fs::hard_link(lock, root.join("lock_alias")).expect("lock alias");
    });
    assert_lock_attack(|lock, root| {
        let target = root.join("lock_target");
        fs::rename(lock, &target).expect("lock move");
        symlink(&target, lock).expect("lock symlink");
    });
    assert_store_lock_attack(|lock, _root| {
        fs::set_permissions(lock, fs::Permissions::from_mode(0o644)).expect("store lock mode");
    });
    assert_store_lock_attack(|lock, root| {
        fs::hard_link(lock, root.join("store_lock_alias")).expect("store lock alias");
    });
}

// Proves malformed, duplicate, unknown, unsupported, and incoherent documents are rejected.
#[test]
fn journal_rejects_closed_schema_and_tamper_matrix() {
    for mutation in [
        "unknown_root",
        "schema_name",
        "schema_version",
        "zero_revision",
        "request_alias",
        "phase_shape",
        "unknown_identity",
        "invalid_receipt",
        "material_alias",
        "benchmark_signing_path_alias",
        "benchmark_signing_identity",
        "missing_benchmark_signing",
        "missing_node_trust",
        "unknown_gateway_trust",
        "node_gateway_path_alias",
        "invalid_watchdog_digest",
        "missing_watchdog_field",
        "replayed_result",
        "result_identity",
        "result_role",
        "result_services",
        "result_exposure",
        "result_endpoint_host",
    ] {
        let fixture = StoreFixture::new();
        advance_to(&fixture, CoreSetupPhase::Completed);
        let mut value: Value =
            serde_json::from_slice(&fs::read(fixture.journal_file()).expect("journal document"))
                .expect("journal JSON");
        mutate_document(&mut value, mutation);
        write_private(
            &fixture.journal_file(),
            &serde_json::to_vec(&value).expect("mutated JSON"),
        );
        assert_eq!(
            fixture.store.read(&fixture.request_id),
            Err(CoreSetupStoreError::Corrupt),
            "mutation {mutation}"
        );
    }

    let fixture = StoreFixture::new();
    advance_to(&fixture, CoreSetupPhase::Completed);
    let document = fs::read_to_string(fixture.journal_file()).expect("journal text");
    let duplicate = document.replacen("\"revision\":6", "\"revision\":6,\"revision\":6", 1);
    write_private(&fixture.journal_file(), duplicate.as_bytes());
    assert_eq!(
        fixture.store.read(&fixture.request_id),
        Err(CoreSetupStoreError::Corrupt)
    );
}

// Proves stale or divergent pending records cannot replace authoritative state on restart.
#[test]
fn journal_rejects_stale_and_divergent_pending_records() {
    let fixture = StoreFixture::new();
    advance_to(&fixture, CoreSetupPhase::IdentityPrepared);
    let stale = StoreFixture::new();
    advance_to(&stale, CoreSetupPhase::Prepared);
    write_private(
        &fixture.pending_file(),
        &fs::read(stale.journal_file()).expect("stale document"),
    );
    assert_eq!(
        fixture.store.read(&fixture.request_id),
        Err(CoreSetupStoreError::Corrupt)
    );

    let fixture = StoreFixture::new();
    advance_to(&fixture, CoreSetupPhase::IdentityPrepared);
    let divergent = StoreFixture::new();
    advance_to(&divergent, CoreSetupPhase::MaterialPrepared);
    let mut value: Value =
        serde_json::from_slice(&fs::read(divergent.journal_file()).expect("divergent document"))
            .expect("divergent JSON");
    value["identity"]["receipt_identity"] = Value::String(identity('9', 64));
    write_private(
        &fixture.pending_file(),
        &serde_json::to_vec(&value).expect("divergent JSON"),
    );
    assert_eq!(
        fixture.store.read(&fixture.request_id),
        Err(CoreSetupStoreError::Corrupt)
    );
}

// Proves the durable record contains only closure identities and file references, never secrets.
#[test]
fn journal_never_persists_private_material_bytes_or_native_diagnostics() {
    let fixture = StoreFixture::new();
    advance_to(&fixture, CoreSetupPhase::Completed);
    let bytes = fs::read(fixture.journal_file()).expect("journal bytes");
    let text = String::from_utf8(bytes).expect("journal text");
    for forbidden in [
        "super-secret-pairing-value",
        "super-secret-api-key-value",
        "private_key_pem",
        "native_error",
        fixture.root.to_str().expect("root path"),
    ] {
        assert!(!text.contains(forbidden), "forbidden value {forbidden}");
    }
}

// Proves emitted records conform to the checked-in closed nested schema for every phase.
#[test]
fn checked_in_journal_schema_validates_every_emitted_phase() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_journal_v1.schema.json"
    ))
    .expect("journal schema");
    let result_schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_result_v1.schema.json"
    ))
    .expect("result schema");
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        CORE_SETUP_JOURNAL_SCHEMA_NAME
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        CORE_SETUP_JOURNAL_SCHEMA_VERSION
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["oneOf"].as_array().expect("phase union").len(), 6);
    assert_eq!(
        schema["properties"]["result"]["oneOf"][1]["$ref"],
        "li_core_setup_result_v1.schema.json"
    );
    assert_eq!(
        result_schema["properties"]["schema"]["properties"]["name"]["const"],
        "li_core_setup_result"
    );
    for phase in phases() {
        let fixture = StoreFixture::new();
        advance_to(&fixture, phase);
        let document: Value =
            serde_json::from_slice(&fs::read(fixture.journal_file()).expect("journal document"))
                .expect("journal JSON");
        assert!(schema_matches(&schema, &document, &schema, &result_schema));
        assert!(fixture
            .store
            .read(&fixture.request_id)
            .expect("validated read")
            .is_some());
        for mutation in ["unknown_root", "schema_version"] {
            let mut invalid = document.clone();
            mutate_document(&mut invalid, mutation);
            assert!(
                !schema_matches(&schema, &invalid, &schema, &result_schema),
                "schema accepted {mutation}"
            );
        }
        let mut invalid_shape = document.clone();
        invalid_shape["identity"] = if phase == CoreSetupPhase::Prepared {
            json!({})
        } else {
            Value::Null
        };
        assert!(!schema_matches(
            &schema,
            &invalid_shape,
            &schema,
            &result_schema
        ));
    }
}

// Advances one store through every required predecessor to the selected exact phase.
fn advance_to(fixture: &StoreFixture, target: CoreSetupPhase) -> VersionedCoreSetupJournal {
    let mut current = fixture
        .store
        .create(journal(CoreSetupPhase::Prepared))
        .expect("prepared");
    for phase in phases().into_iter().skip(1) {
        if phase > target {
            break;
        }
        current = fixture
            .store
            .replace(journal(phase), current.revision())
            .expect("phase replacement");
    }
    current
}

// Constructs one exact structurally complete journal at the requested phase.
fn journal(phase: CoreSetupPhase) -> CoreSetupJournal {
    journal_for('f', phase)
}

// Constructs one exact structurally complete journal for an independent request identity.
fn journal_for(request: char, phase: CoreSetupPhase) -> CoreSetupJournal {
    let identity = (phase >= CoreSetupPhase::IdentityPrepared).then(prepared_identity);
    let material = (phase >= CoreSetupPhase::MaterialPrepared).then(prepared_material);
    let configurations = (phase >= CoreSetupPhase::ConfigurationsInstalled)
        .then(|| CoreSetupInstalledConfigurations::new(receipt('3')));
    let services = (phase >= CoreSetupPhase::ServicesInstalled)
        .then(|| CoreSetupInstalledServices::new(receipt('4')));
    let result = (phase == CoreSetupPhase::Completed).then(setup_result);
    CoreSetupJournal::restored(
        digest(request),
        digest('e'),
        phase,
        identity,
        material,
        configurations,
        services,
        result,
    )
    .expect("journal")
}

// Advances one request through every predecessor without disturbing other stored histories.
fn advance_request(
    store: &SystemCoreSetupJournalStore,
    request: char,
    target: CoreSetupPhase,
) -> VersionedCoreSetupJournal {
    let mut current = store
        .create(journal_for(request, CoreSetupPhase::Prepared))
        .expect("prepared request");
    for phase in phases().into_iter().skip(1) {
        if phase > target {
            break;
        }
        current = store
            .replace(journal_for(request, phase), current.revision())
            .expect("request phase");
    }
    current
}

// Creates one public identity closure without any private key bytes.
fn prepared_identity() -> CoreSetupPreparedIdentity {
    CoreSetupPreparedIdentity::new(
        receipt('1'),
        NodeId::parse(&identity('a', 32)).expect("node"),
        MachineId::parse(&identity('b', 32)).expect("machine"),
        InstallationId::parse(&identity('c', 64)).expect("installation"),
        DisplayName::parse("Home AI").expect("display name"),
        NodeRole::Main,
        NodeAddress::parse("homeai.local").expect("control address"),
    )
}

// Creates one secret-free material closure with distinct private file references.
fn prepared_material() -> CoreSetupPreparedMaterial {
    CoreSetupPreparedMaterial::new_with_benchmark_signing(
        receipt('2'),
        "/private/var/lib/letsinfer/li_core.sqlite3".into(),
        "/private/var/lib/letsinfer/pairing.key".into(),
        Some("/private/var/lib/letsinfer/api.key".into()),
        CoreSetupBenchmarkSigningMaterial::new(
            "/private/var/lib/letsinfer/trust/benchmark-signing.key".into(),
            "/private/var/lib/letsinfer/trust/benchmark-signing.pub".into(),
            digest('9'),
        ),
        li_core_application::CoreSetupPairingTrustMaterial::new(
            "/private/var/lib/letsinfer/trust/site.key".into(),
            "/private/var/lib/letsinfer/trust/site.pub".into(),
            "/private/var/lib/letsinfer/trust/site-ca.crt".into(),
            "/private/var/lib/letsinfer/trust/node.crt".into(),
            digest('a'),
            digest('b'),
        ),
        li_core_application::CoreSetupNodeTrustMaterial::new(
            "/private/var/lib/letsinfer/trust/node-ca.key".into(),
            "/private/var/lib/letsinfer/trust/node-ca.crt".into(),
            "/private/var/lib/letsinfer/trust/node-server.crt".into(),
            "/private/var/lib/letsinfer/trust/node-server.key".into(),
            "/private/var/lib/letsinfer/trust/node-client.crt".into(),
            "/private/var/lib/letsinfer/trust/node-client.key".into(),
            digest('c'),
            digest('d'),
        ),
        li_core_application::CoreSetupGatewayTrustMaterial::new(
            "/private/var/lib/letsinfer/trust/gateway-ca.key".into(),
            "/private/var/lib/letsinfer/trust/gateway-ca.crt".into(),
            "/private/var/lib/letsinfer/trust/gateway-server.crt".into(),
            "/private/var/lib/letsinfer/trust/gateway-server.key".into(),
            "/private/var/lib/letsinfer/trust/gateway-client.crt".into(),
            "/private/var/lib/letsinfer/trust/gateway-client.key".into(),
            digest('e'),
            digest('f'),
        ),
        Some(li_core_application::CoreSetupWatchdogTrustMaterial::new(
            "/private/var/lib/letsinfer/trust/watchdog-ca.key".into(),
            "/private/var/lib/letsinfer/trust/watchdog-ca.crt".into(),
            "/private/var/lib/letsinfer/trust/watchdog-server.crt".into(),
            "/private/var/lib/letsinfer/trust/watchdog-server.key".into(),
            "/private/var/lib/letsinfer/trust/watchdog-controller.crt".into(),
            "/private/var/lib/letsinfer/trust/watchdog-controller.key".into(),
            "/private/var/lib/letsinfer/trust/watchdog-controllers.allow".into(),
            digest('1'),
            digest('2'),
        )),
        digest('d'),
    )
}

// Creates one role-consistent installed result through its public strict decoder.
fn setup_result() -> CoreSetupResult {
    let value = json!({
        "schema": {"name": "li_core_setup_result", "version": 1},
        "status": "installed",
        "node_id": identity('a', 32),
        "machine_id": identity('b', 32),
        "installation_id": identity('c', 64),
        "display_name": "Home AI",
        "role": "main",
        "control_address": "homeai.local",
        "api_key_file": "/private/var/lib/letsinfer/api.key",
        "inference_endpoint": "http://homeai.local:11434",
        "services": ["li_node", "li_watchdog", "li_gateway"]
    });
    CoreSetupResult::decoded_json(&serde_json::to_vec(&value).expect("result JSON"))
        .expect("setup result")
}

// Returns every durable phase in exact mutation order.
const fn phases() -> [CoreSetupPhase; 6] {
    [
        CoreSetupPhase::Prepared,
        CoreSetupPhase::IdentityPrepared,
        CoreSetupPhase::MaterialPrepared,
        CoreSetupPhase::ConfigurationsInstalled,
        CoreSetupPhase::ServicesInstalled,
        CoreSetupPhase::Completed,
    ]
}

// Creates one canonical SHA-256 digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Creates one opaque receipt fixture without exposing native provider state.
fn receipt(character: char) -> CoreSetupReceipt {
    CoreSetupReceipt::new(digest(character))
}

// Creates one repeated lower-hex identity of the exact requested length.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns the current effective owner used by native descriptor validation.
fn effective_user() -> u32 {
    unsafe { libc::geteuid() }
}

// Returns one request-addressed authoritative filename below a test root.
fn journal_file(root: &Path, request_id: &Sha256Digest) -> PathBuf {
    root.join(format!(
        "li_core_setup_journal_{}.json",
        request_id.as_str()
    ))
}

// Returns one request-addressed fixed pending filename below a test root.
fn pending_file(root: &Path, request_id: &Sha256Digest) -> PathBuf {
    root.join(format!(
        "li_core_setup_journal_{}.json.pending",
        request_id.as_str()
    ))
}

// Writes one exact owner-private test file used to model a native crash boundary.
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private mode");
}

// Waits a bounded interval for one child-process synchronization path.
fn wait_for_path(path: &Path, label: &str) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {label}");
}

// Applies one filesystem attack and proves the next descriptor-anchored read refuses it.
fn assert_file_attack(attack: impl FnOnce(&Path, &Path)) {
    let fixture = StoreFixture::new();
    advance_to(&fixture, CoreSetupPhase::Prepared);
    attack(&fixture.journal_file(), &fixture.root);
    assert!(fixture.store.read(&fixture.request_id).is_err());
}

// Applies one lock-file attack after first creating the canonical native lock inode.
fn assert_lock_attack(attack: impl FnOnce(&Path, &Path)) {
    let fixture = StoreFixture::new();
    let provider =
        SystemCoreSetupExecutionLockProvider::new(fixture.root.clone(), effective_user())
            .expect("provider");
    drop(provider.try_acquire().expect("initial lock"));
    let lock = fixture.root.join(".li_core_setup.lock");
    attack(&lock, &fixture.root);
    assert!(provider.try_acquire().is_err());
}

// Applies one journal-operation lock attack after the first authoritative store mutation.
fn assert_store_lock_attack(attack: impl FnOnce(&Path, &Path)) {
    let fixture = StoreFixture::new();
    advance_to(&fixture, CoreSetupPhase::Prepared);
    let lock = fixture.root.join(".li_core_setup.journal.lock");
    attack(&lock, &fixture.root);
    assert!(fixture.store.read(&fixture.request_id).is_err());
}

// Mutates one valid completed document at an independently named trust boundary.
fn mutate_document(value: &mut Value, mutation: &str) {
    match mutation {
        "unknown_root" => {
            value["unknown"] = Value::Bool(true);
        }
        "schema_name" => value["schema"]["name"] = Value::String("foreign".into()),
        "schema_version" => value["schema"]["version"] = Value::from(2),
        "zero_revision" => value["revision"] = Value::from(0),
        "request_alias" => value["request_id"] = Value::String(identity('0', 64)),
        "phase_shape" => value["identity"] = Value::Null,
        "unknown_identity" => value["identity"]["unknown"] = Value::Bool(true),
        "invalid_receipt" => value["identity"]["receipt_identity"] = Value::String("x".into()),
        "material_alias" => {
            value["material"]["pairing_setup_secret_file"] =
                value["material"]["database_file"].clone();
        }
        "benchmark_signing_path_alias" => {
            value["material"]["benchmark_signing"]["public_key_file"] =
                value["material"]["benchmark_signing"]["private_key_file"].clone();
        }
        "benchmark_signing_identity" => {
            value["material"]["benchmark_signing"]["public_key_sha256"] = Value::String("x".into());
        }
        "missing_node_trust" => {
            value["material"]
                .as_object_mut()
                .expect("material")
                .remove("node_trust");
        }
        "unknown_gateway_trust" => {
            value["material"]["gateway_trust"]["unknown"] = Value::Bool(true);
        }
        "node_gateway_path_alias" => {
            value["material"]["gateway_trust"]["server_certificate_file"] =
                value["material"]["node_trust"]["server_certificate_file"].clone();
        }
        "invalid_watchdog_digest" => {
            value["material"]["watchdog_trust"]["controller_certificate_sha256"] =
                Value::String("x".into());
        }
        "missing_benchmark_signing" => {
            value["material"]["benchmark_signing"] = Value::Null;
        }
        "missing_watchdog_field" => {
            value["material"]["watchdog_trust"]
                .as_object_mut()
                .expect("Watchdog trust")
                .remove("controller_allowlist_file");
        }
        "replayed_result" => value["result"]["status"] = Value::String("replayed".into()),
        "result_identity" => value["result"]["node_id"] = Value::String(identity('9', 32)),
        "result_role" => value["result"]["role"] = Value::String("child".into()),
        "result_services" => {
            value["result"]["services"] = json!(["li_gateway", "li_node"]);
        }
        "result_exposure" => value["result"]["inference_endpoint"] = Value::Null,
        "result_endpoint_host" => {
            value["result"]["inference_endpoint"] = json!("http://other.local:11434");
        }
        _ => panic!("unknown mutation"),
    }
}

// Evaluates the checked-in schema keywords used by both nested setup documents.
fn schema_matches(schema: &Value, document: &Value, root: &Value, result_root: &Value) -> bool {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return match reference {
            "li_core_setup_result_v1.schema.json" => {
                schema_matches(result_root, document, result_root, result_root)
            }
            value if value.starts_with("#/") => json_pointer(root, &value[1..])
                .is_some_and(|target| schema_matches(target, document, root, result_root)),
            _ => false,
        };
    }
    if schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| !schema_type_matches(kind, document))
    {
        return false;
    }
    if schema.get("const").is_some_and(|value| value != document) {
        return false;
    }
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.contains(document))
    {
        return false;
    }
    if schema
        .get("oneOf")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter(|value| schema_matches(value, document, root, result_root))
                .count()
                != 1
        })
    {
        return false;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| !schema_matches(value, document, root, result_root))
        })
    {
        return false;
    }
    if let Some(condition) = schema.get("if") {
        let branch = if schema_matches(condition, document, root, result_root) {
            schema.get("then")
        } else {
            schema.get("else")
        };
        if branch.is_some_and(|value| !schema_matches(value, document, root, result_root)) {
            return false;
        }
    }
    if let Some(object) = document.as_object() {
        if schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|fields| {
                fields.iter().any(|field| {
                    field
                        .as_str()
                        .is_none_or(|field| !object.contains_key(field))
                })
            })
        {
            return false;
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            if properties.iter().any(|(field, property)| {
                object
                    .get(field)
                    .is_some_and(|value| !schema_matches(property, value, root, result_root))
            }) {
                return false;
            }
            if schema.get("additionalProperties") == Some(&Value::Bool(false))
                && object.keys().any(|field| !properties.contains_key(field))
            {
                return false;
            }
        }
    }
    if let Some(values) = document.as_array() {
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| values.len() < minimum as usize)
            || schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| values.len() > maximum as usize)
        {
            return false;
        }
        if schema.get("uniqueItems") == Some(&Value::Bool(true))
            && values
                .iter()
                .enumerate()
                .any(|(index, value)| values[..index].contains(value))
        {
            return false;
        }
        if schema.get("items").is_some_and(|item| {
            values
                .iter()
                .any(|value| !schema_matches(item, value, root, result_root))
        }) {
            return false;
        }
        if schema
            .get("prefixItems")
            .and_then(Value::as_array)
            .is_some_and(|prefixes| {
                prefixes.iter().enumerate().any(|(index, prefix)| {
                    values
                        .get(index)
                        .is_none_or(|value| !schema_matches(prefix, value, root, result_root))
                })
            })
        {
            return false;
        }
        if schema.get("contains").is_some_and(|target| {
            !values
                .iter()
                .any(|value| schema_matches(target, value, root, result_root))
        }) {
            return false;
        }
    }
    if let Some(value) = document.as_str() {
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| value.chars().count() < minimum as usize)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| value.chars().count() > maximum as usize)
            || schema
                .get("pattern")
                .and_then(Value::as_str)
                .is_some_and(|pattern| !schema_pattern_matches(pattern, value))
        {
            return false;
        }
    }
    if schema
        .get("minimum")
        .and_then(Value::as_i64)
        .is_some_and(|minimum| document.as_i64().is_none_or(|value| value < minimum))
    {
        return false;
    }
    true
}

// Resolves one local JSON pointer without interpreting external resources.
fn json_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    pointer
        .split('/')
        .skip(1)
        .try_fold(root, |value, field| value.get(field))
}

// Matches every primitive type used by the committed setup schemas.
fn schema_type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        _ => false,
    }
}

// Evaluates the closed pattern vocabulary owned by the two setup schemas.
fn schema_pattern_matches(pattern: &str, value: &str) -> bool {
    match pattern {
        "^[0-9a-f]{64}$" => {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }
        "^[0-9a-f]{32}$" => {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }
        "^\\S+$" => !value.chars().any(char::is_whitespace),
        "^http://\\S+$" => value.starts_with("http://") && !value.chars().any(char::is_whitespace),
        "^/(?:[^/\\u0000]+/?)*$" => valid_schema_path(value),
        "^[^\\u0000-\\u001f\\u007f]+$" => !value.chars().any(char::is_control),
        _ => false,
    }
}

// Matches the schema's normal absolute Unicode path boundary.
fn valid_schema_path(value: &str) -> bool {
    let path = Path::new(value);
    value.len() >= 2
        && value.len() <= 4096
        && path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
