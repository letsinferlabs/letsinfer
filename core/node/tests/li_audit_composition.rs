// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditAppendRequest,
    AuditCheckpointCryptography, AuditCheckpointPolicy, AuditClock, AuditCorrelationId, AuditError,
    AuditEventId, AuditIdentityProvider, AuditOrigin, AuditOriginInterface, AuditOutcome,
    AuditReplayId, AuditTarget, AuditUnixNanoseconds,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    NodeAuditCheckpointKeyReferences, NodeAuditCommitModel, NodeAuditComposition,
    NodeAuditCompositionError, NodeAuditCryptographyError, NodeAuditOpenSslRunner, NodeManager,
    OpenSslNodeAuditCheckpointCryptography, SystemNodeAuditOpenSslRunner,
};

// Supplies deterministic database commit time.
struct DatabaseClockMock {
    next: AtomicI64,
}

impl DatabaseClock for DatabaseClockMock {
    // Returns one unique database timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.next.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic audit time.
struct AuditClockMock {
    next: AtomicU64,
}

impl AuditClock for AuditClockMock {
    // Returns one unique positive audit timestamp.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError> {
        AuditUnixNanoseconds::new(self.next.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies one deterministic event identity.
struct IdentityMock;

impl AuditIdentityProvider for IdentityMock {
    // Returns the one stable event identity used by each isolated fixture.
    fn event_id(&self) -> Result<AuditEventId, AuditError> {
        AuditEventId::parse(&"a".repeat(32))
    }
}

// Provides deterministic signatures and an injected signing failure.
#[derive(Default)]
struct CryptographyMock {
    fail_sign: AtomicBool,
}

impl AuditCheckpointCryptography for CryptographyMock {
    // Signs exact hash text unless the injected failure is active.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
        if self.fail_sign.swap(false, Ordering::SeqCst) {
            return Err(AuditError::provider("signing", "fixture failure"));
        }
        Ok(event_hash.to_vec())
    }

    // Verifies the deterministic fixture signature.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError> {
        Ok(event_hash == signature)
    }
}

// Captures OpenSSL key references while returning deterministic signatures.
#[derive(Default)]
struct OpenSslRunnerMock {
    private_key: Mutex<Option<PathBuf>>,
    public_key: Mutex<Option<PathBuf>>,
}

impl NodeAuditOpenSslRunner for OpenSslRunnerMock {
    // Captures the private key path without requesting or receiving key bytes.
    fn sign(
        &self,
        openssl: &Path,
        private_key: &Path,
        event_hash: &[u8],
    ) -> Result<Vec<u8>, NodeAuditCryptographyError> {
        assert_eq!(openssl, Path::new("/usr/bin/openssl"));
        assert_eq!(
            event_hash,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        *self.private_key.lock().expect("private key capture") = Some(private_key.to_path_buf());
        Ok(b"signature".to_vec())
    }

    // Captures the public key path and verifies the deterministic signature.
    fn verify(
        &self,
        openssl: &Path,
        public_key: &Path,
        event_hash: &[u8],
        signature: &[u8],
    ) -> Result<bool, NodeAuditCryptographyError> {
        assert_eq!(openssl, Path::new("/usr/bin/openssl"));
        assert_eq!(
            event_hash,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        *self.public_key.lock().expect("public key capture") = Some(public_key.to_path_buf());
        Ok(signature == b"signature")
    }
}

// Opens one isolated NodeManager with deterministic database dependencies.
fn node_manager(directory: &tempfile::TempDir) -> NodeManager {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(DatabaseClockMock {
                    next: AtomicI64::new(10_000),
                })),
        )
        .expect("database"),
    );
    let node = Node::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    );
    NodeManager::open(database, node, "initialize-node")
        .expect("node manager")
        .0
}

// Creates one ordinary successful audit request for the local node.
fn request(replay_id: &str) -> AuditAppendRequest {
    AuditAppendRequest::new(
        AuditReplayId::parse(replay_id).expect("replay"),
        AuditCorrelationId::parse(&"b".repeat(32)).expect("correlation"),
        AuditActor::new(
            AuditActorType::LocalUser,
            AuditActorId::parse("taimur").expect("actor"),
        ),
        AuditOrigin::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            AuditOriginInterface::Cli,
        ),
        AuditAction::parse("model.install").expect("action"),
        AuditTarget::parse("fixture.model").expect("target"),
        None,
        None,
        AuditOutcome::Success,
        None,
    )
    .expect("request")
}

// Composes local identity, DatabaseAuditStore, and injected providers into AuditManager.
#[test]
fn node_manager_owns_local_audit_identity_and_database_composition() {
    let directory = tempfile::tempdir().expect("directory");
    let node = node_manager(&directory);
    let manager = node.audit_manager_with_dependencies(
        Arc::new(AuditClockMock {
            next: AtomicU64::new(1_000_000),
        }),
        Arc::new(IdentityMock),
        Arc::new(CryptographyMock::default()),
        AuditCheckpointPolicy::production(),
    );
    let receipt = manager.append(request("install")).expect("audit append");
    assert_eq!(receipt.entry().event().node_id(), node.local_node_id());
    assert_eq!(manager.verify().expect("verification").events(), 1);
}

// Reports a durable audit gap explicitly when an already-committed domain change cannot be audited.
#[test]
fn composition_never_claims_cross_manager_atomicity() {
    let directory = tempfile::tempdir().expect("directory");
    let node = node_manager(&directory);
    let cryptography = Arc::new(CryptographyMock::default());
    cryptography.fail_sign.store(true, Ordering::SeqCst);
    let manager = Arc::new(node.audit_manager_with_dependencies(
        Arc::new(AuditClockMock {
            next: AtomicU64::new(1_000_000),
        }),
        Arc::new(IdentityMock),
        cryptography,
        AuditCheckpointPolicy::new(1).expect("checkpoint policy"),
    ));
    let composition = NodeAuditComposition::new(manager);
    assert_eq!(
        composition.commit_model(),
        NodeAuditCommitModel::IndependentDatabaseCommit
    );
    let error = composition
        .record_committed_domain_mutation(request("domain-committed"))
        .expect_err("audit failure");
    assert!(matches!(
        error,
        NodeAuditCompositionError::DomainCommittedAuditFailed { .. }
    ));
    assert_eq!(
        composition
            .manager()
            .verify()
            .expect("empty chain")
            .events(),
        0
    );
}

// Uses only explicit private/public key paths and redacts them from diagnostics.
#[test]
fn openssl_checkpoint_provider_uses_reference_only_keys() {
    let runner = Arc::new(OpenSslRunnerMock::default());
    let private_key = PathBuf::from("/private/letsinfer/site.key");
    let public_key = PathBuf::from("/private/letsinfer/site.pub");
    let provider = OpenSslNodeAuditCheckpointCryptography::new(
        PathBuf::from("/usr/bin/openssl"),
        NodeAuditCheckpointKeyReferences::new(private_key.clone(), public_key.clone())
            .expect("key references"),
        runner.clone(),
    )
    .expect("provider");
    let hash = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let signature = provider.sign(hash).expect("signature");
    assert!(provider.verify(hash, &signature).expect("verification"));
    assert_eq!(
        runner.private_key.lock().expect("private key").as_ref(),
        Some(&private_key)
    );
    assert_eq!(
        runner.public_key.lock().expect("public key").as_ref(),
        Some(&public_key)
    );
    let debug = format!("{provider:?}");
    assert!(!debug.contains("site.key"));
    assert!(!debug.contains("site.pub"));
}

// Rejects hardlinked private key references before any native command can run.
#[test]
fn system_openssl_runner_rejects_hardlinked_private_key() {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempfile::tempdir().expect("directory");
    let workspace = directory.path().join("verification");
    fs::create_dir(&workspace).expect("workspace");
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).expect("workspace mode");
    let private_key = directory.path().join("site.key");
    fs::write(&private_key, b"fixture-private-key").expect("private key");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600)).expect("key mode");
    fs::hard_link(&private_key, directory.path().join("site.key.link")).expect("hardlink");
    let owner = fs::metadata(&workspace).expect("workspace metadata").uid();
    let runner = SystemNodeAuditOpenSslRunner::new(workspace, owner, Duration::from_secs(1))
        .expect("runner");
    let error = runner
        .sign(
            Path::new("/usr/bin/openssl"),
            &private_key,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect_err("hardlinked key");
    assert_eq!(error, NodeAuditCryptographyError::KeyUnavailable);
}

// Executes the exact OpenSSL sign/verify argv and retires its temporary signature file.
#[test]
fn system_openssl_runner_executes_bounded_commands_and_cleans_workspace() {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempfile::tempdir().expect("directory");
    let workspace = directory.path().join("verification");
    fs::create_dir(&workspace).expect("workspace");
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).expect("workspace mode");
    let private_key = directory.path().join("site.key");
    let public_key = directory.path().join("site.pub");
    fs::write(&private_key, b"fixture-private-key").expect("private key");
    fs::write(&public_key, b"fixture-public-key").expect("public key");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600)).expect("private mode");
    fs::set_permissions(&public_key, fs::Permissions::from_mode(0o644)).expect("public mode");
    let openssl = directory.path().join("openssl");
    let script = format!(
        "#!/bin/sh\nset -eu\ncase \"$*\" in\n  \"dgst -sha256 -sign {}\") cat >/dev/null; printf signature ;;\n  \"dgst -sha256 -verify {} -signature \"*) test \"$(cat \"$6\")\" = signature; cat >/dev/null; exit 0 ;;\n  *) exit 2 ;;\nesac\n",
        private_key.display(),
        public_key.display(),
    );
    fs::write(&openssl, script).expect("OpenSSL fixture");
    fs::set_permissions(&openssl, fs::Permissions::from_mode(0o700)).expect("fixture mode");
    let owner = fs::metadata(&workspace).expect("workspace metadata").uid();
    let runner = Arc::new(
        SystemNodeAuditOpenSslRunner::new(workspace.clone(), owner, Duration::from_secs(1))
            .expect("runner"),
    );
    let provider = OpenSslNodeAuditCheckpointCryptography::new(
        openssl,
        NodeAuditCheckpointKeyReferences::new(private_key, public_key).expect("keys"),
        runner,
    )
    .expect("provider");
    let hash = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let signature = provider.sign(hash).expect("signature");
    assert_eq!(signature, b"signature");
    assert!(provider.verify(hash, &signature).expect("verification"));
    assert_eq!(
        fs::read_dir(workspace).expect("workspace entries").count(),
        0
    );
}
