// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use li_authentication_manager::{
    ApiKeyMaterialProvider, AuthenticationClock, AuthenticationError, AuthenticationManager,
    AuthenticationStoreError, ControllerCertificate, ControllerCertificateError,
    ControllerCertificateMaterial, ControllerCertificateProvider, ControllerError,
    ControllerPublicKey, ControllerRole, ControllerState, ControllerStore, PeerCredentialStore,
    VersionedPeerCredential,
};
use li_core_interface::{ControllerId, CredentialId, DisplayName, Sha256Digest, UnixMilliseconds};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    DatabaseAuthenticationStore, DatabaseControllerStore, NodeAuthenticationApiPort,
    NodeAuthenticationCoordinator, NodeControllerAuthorization,
    NodeControllerAuthorizationProjectionPort, NodeControllerEnrollmentCandidate,
};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

const PRIVATE_KEY_SENTINEL: &[u8] = b"controller-private-key-database-sentinel";

// Supplies deterministic public certificates while retaining private material inside the provider.
struct TestCertificateProvider {
    private_key: Vec<u8>,
}

impl TestCertificateProvider {
    // Creates one provider whose private material must never cross its interface.
    fn new() -> Self {
        Self {
            private_key: PRIVATE_KEY_SENTINEL.to_vec(),
        }
    }

    // Returns one deterministic validated public certificate.
    fn certificate(
        &self,
        controller_id: &ControllerId,
        public_key_sha256: Sha256Digest,
        public_material: Vec<u8>,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        debug_assert_eq!(self.private_key, PRIVATE_KEY_SENTINEL);
        ControllerCertificate::new(
            controller_id.clone(),
            digest(&public_material),
            public_key_sha256,
            public_material,
            UnixMilliseconds::new(0),
            UnixMilliseconds::new(10_000),
        )
    }
}

impl ControllerCertificateProvider for TestCertificateProvider {
    // Issues one public certificate without returning the retained private key.
    fn issue(
        &self,
        controller_id: &ControllerId,
        public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        self.certificate(
            controller_id,
            public_key.sha256().clone(),
            format!("public-controller-certificate:{}", controller_id.as_str()).into_bytes(),
        )
    }

    // Validates one imported public certificate without returning the retained private key.
    fn import(
        &self,
        controller_id: &ControllerId,
        material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        self.certificate(
            controller_id,
            digest(material.bytes()),
            material.bytes().to_vec(),
        )
    }
}

// Rejects peer lookups that are outside this controller-only integration fixture.
struct UnavailablePeerCredentialStore;

impl PeerCredentialStore for UnavailablePeerCredentialStore {
    // Rejects certificate matching because this fixture does not compose pairing.
    fn matching_peer_credentials(
        &self,
        _peer_leaf_sha256: &Sha256Digest,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects identity matching because this fixture does not compose pairing.
    fn matching_peer_credential_ids(
        &self,
        _credential_id: &CredentialId,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Supplies deterministic unused API-key material to the complete manager constructor.
struct TestApiKeyMaterial;

impl ApiKeyMaterialProvider for TestApiKeyMaterial {
    // Fills API-key material without contributing controller secret bytes.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        destination.fill(7);
        Ok(())
    }
}

// Supplies one deterministic time inside the test certificate lifetime.
struct TestClock;

impl AuthenticationClock for TestClock {
    // Returns the fixed controller operation timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(1_000))
    }
}

// Records complete authorization projections for deterministic lifecycle assertions.
#[derive(Default)]
struct Projection {
    failures: Mutex<usize>,
    snapshots: Mutex<Vec<Vec<NodeControllerAuthorization>>>,
}

impl Projection {
    // Arms one or more exact deterministic projection failures.
    fn fail(&self, count: usize) {
        *self.failures.lock().expect("projection failures") = count;
    }
}

impl NodeControllerAuthorizationProjectionPort for Projection {
    // Retains one exact stable snapshot without native I/O or asynchronous reload.
    fn reconcile(
        &self,
        controllers: &[NodeControllerAuthorization],
    ) -> Result<(), ControllerError> {
        let mut failures = self.failures.lock().expect("projection failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(ControllerError::ProviderUnavailable);
        }
        drop(failures);
        self.snapshots
            .lock()
            .expect("projection snapshots")
            .push(controllers.to_vec());
        Ok(())
    }
}

// Keeps incomplete projection fail-closed and heals exact add/revoke replays after restart.
#[test]
fn controller_projection_failure_never_widens_live_or_durable_authority() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory);
    let projection = Arc::new(Projection::default());
    projection.fail(1);
    let coordinator = compose_coordinator(database.clone(), projection.clone());
    assert_eq!(
        coordinator.add_controller(enrollment_candidate(), ControllerRole::Administrator),
        Err(ControllerError::ProviderUnavailable)
    );
    assert_eq!(
        coordinator
            .controllers()
            .expect("issued controller after failed projection")[0]
            .state(),
        ControllerState::Issued
    );

    let restarted = compose_coordinator(database.clone(), projection.clone());
    let active = restarted
        .add_controller(enrollment_candidate(), ControllerRole::Administrator)
        .expect("projection retry");
    assert_eq!(active.controller().state(), ControllerState::Active);
    projection.fail(1);
    assert_eq!(
        restarted.revoke_controller(controller_id().as_str()),
        Err(ControllerError::ProviderUnavailable)
    );
    assert_eq!(
        manager(database.clone())
            .controller(&controller_id())
            .expect("controller after failed revocation projection")
            .state(),
        ControllerState::Active
    );
    assert_eq!(
        restarted
            .revoke_controller(controller_id().as_str())
            .expect("revocation retry")
            .state(),
        ControllerState::Revoked
    );
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

// Composes the existing AuthenticationManager with its real controller database adapter.
fn manager(database: Arc<DatabaseManager>) -> AuthenticationManager {
    AuthenticationManager::new_with_controller_store(
        Arc::new(DatabaseAuthenticationStore::new(database.clone())),
        Arc::new(UnavailablePeerCredentialStore),
        Arc::new(DatabaseControllerStore::new(database)),
        Arc::new(TestCertificateProvider::new()),
        Arc::new(TestApiKeyMaterial),
        Arc::new(TestClock),
    )
}

// Composes controller lifecycle with one explicit deterministic live projection.
fn compose_coordinator(
    database: Arc<DatabaseManager>,
    projection: Arc<Projection>,
) -> NodeAuthenticationCoordinator {
    NodeAuthenticationCoordinator::new_with_controller_projection(
        Arc::new(manager(database)),
        projection,
    )
}

// Returns one exact controller identity fixture.
fn controller_id() -> ControllerId {
    ControllerId::parse(&"a".repeat(32)).expect("controller identity")
}

// Returns one bounded deterministic controller public key.
fn public_key() -> ControllerPublicKey {
    ControllerPublicKey::new(vec![9; 96]).expect("public key")
}

// Returns one typed candidate already validated at the transient enrollment boundary.
fn enrollment_candidate() -> NodeControllerEnrollmentCandidate {
    enrollment_candidate_for('a', "Desk Mac")
}

// Returns one independently identified confirmed candidate for concurrency tests.
fn enrollment_candidate_for(character: char, name: &str) -> NodeControllerEnrollmentCandidate {
    NodeControllerEnrollmentCandidate::new(
        ControllerId::parse(&character.to_string().repeat(32)).expect("controller identity"),
        DisplayName::parse(name).expect("controller name"),
        public_key(),
    )
}

// Serializes concurrent controller mutations so no complete active set can be lost in projection.
#[test]
fn controller_projection_serializes_concurrent_one_process_writers() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory);
    let projection = Arc::new(Projection::default());
    let coordinator = Arc::new(compose_coordinator(database, projection.clone()));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (character, name) in [('a', "Desk Mac"), ('b', "Laptop Mac")] {
        let coordinator = coordinator.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            coordinator.add_controller(
                enrollment_candidate_for(character, name),
                ControllerRole::Administrator,
            )
        }));
    }
    barrier.wait();
    for worker in workers {
        assert_eq!(
            worker
                .join()
                .expect("worker")
                .expect("controller")
                .controller()
                .state(),
            ControllerState::Active
        );
    }
    let snapshots = projection.snapshots.lock().expect("projection snapshots");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].len(), 1);
    assert_eq!(snapshots[1].len(), 2);
    assert!(snapshots[1][0].controller_id().as_str() < snapshots[1][1].controller_id().as_str());
}

// Proves confirmed-candidate replay, revocation, and durable restart through real storage.
#[test]
fn node_controller_enrollment_is_atomic_replay_safe_and_restartable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory);
    let projection = Arc::new(Projection::default());
    let coordinator = compose_coordinator(database.clone(), projection.clone());

    let enrolled = coordinator
        .add_controller(enrollment_candidate(), ControllerRole::Administrator)
        .expect("enroll controller");
    assert_eq!(enrolled.controller().state(), ControllerState::Active);
    let replay = coordinator
        .add_controller(enrollment_candidate(), ControllerRole::Administrator)
        .expect("replay enrollment");
    assert_eq!(replay, enrolled);
    assert_eq!(coordinator.controllers().expect("controllers").len(), 1);
    drop(coordinator);

    let restarted = compose_coordinator(database.clone(), projection.clone());
    assert_eq!(
        restarted.controllers().expect("restart list"),
        vec![enrolled.controller().clone()]
    );
    let revoked = restarted
        .revoke_controller("Desk Mac")
        .expect("revoke controller");
    assert_eq!(revoked.state(), ControllerState::Revoked);
    assert_eq!(
        restarted
            .revoke_controller(controller_id().as_str())
            .expect("replay revocation"),
        revoked
    );
    drop(restarted);

    let after_revocation = compose_coordinator(database.clone(), projection.clone());
    assert_eq!(
        after_revocation
            .controllers()
            .expect("restart revoked list"),
        vec![revoked]
    );
    let snapshots = projection.snapshots.lock().expect("projection snapshots");
    assert_eq!(snapshots.len(), 4);
    assert_eq!(snapshots[0].len(), 1);
    assert_eq!(snapshots[1], snapshots[0]);
    assert!(snapshots[2].is_empty());
    assert!(snapshots[3].is_empty());
}

// Persists only public controller material and reconstructs active and revoked state after restart.
#[test]
fn controller_manager_restarts_from_real_database_without_private_material() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let identity = controller_id();
    let fingerprint = {
        let manager = manager(database(&directory));
        manager
            .issue_controller(
                identity.clone(),
                DisplayName::parse("Desk Mac").expect("controller name"),
                ControllerRole::Operator,
                public_key(),
            )
            .expect("issue controller");
        let active = manager
            .activate_controller(&identity)
            .expect("activate controller");
        active.value().certificate().certificate_sha256().clone()
    };

    let reconstructed = manager(database(&directory));
    let principal = reconstructed
        .authorize_controller(&identity, &fingerprint, ControllerRole::Viewer)
        .expect("authorize reconstructed controller");
    assert_eq!(principal.controller_id(), &identity);
    assert_eq!(principal.role(), ControllerRole::Operator);
    assert_eq!(
        reconstructed.controllers().expect("list controllers").len(),
        1
    );
    reconstructed
        .revoke_controller(&identity)
        .expect("revoke controller");
    drop(reconstructed);

    let revoked = manager(database(&directory));
    assert_eq!(
        revoked.controller(&identity).expect("read revoked").state(),
        ControllerState::Revoked
    );
    assert_eq!(
        revoked.authorize_controller(&identity, &fingerprint, ControllerRole::Viewer),
        Err(ControllerError::Unauthorized)
    );
    drop(revoked);

    for path in [
        directory.path().join("core.sqlite3"),
        directory.path().join("core.sqlite3-wal"),
        directory.path().join("core.sqlite3-shm"),
    ] {
        if path.is_file() {
            let bytes = std::fs::read(path).expect("database bytes");
            assert!(!contains_bytes(&bytes, PRIVATE_KEY_SENTINEL));
        }
    }
}

// Rejects closed-schema, lifecycle, certificate, and identity corruption after restart.
#[test]
fn controller_store_rejects_persisted_tampering() {
    for mutation in 0..5 {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("core.sqlite3");
        let identity = controller_id();
        {
            let manager = manager(database(&directory));
            manager
                .issue_controller(
                    identity.clone(),
                    DisplayName::parse("Desk Mac").expect("controller name"),
                    ControllerRole::Operator,
                    public_key(),
                )
                .expect("issue controller");
            manager
                .activate_controller(&identity)
                .expect("activate controller");
        }
        let connection = Connection::open(&path).expect("raw database");
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["controllers", identity.as_str()],
                |row| row.get(0),
            )
            .expect("controller payload");
        let mut document: serde_json::Value =
            serde_json::from_slice(&payload).expect("controller document");
        match mutation {
            0 => document["schema"]["name"] = serde_json::json!("foreign.controller"),
            1 => document["unexpected"] = serde_json::json!(true),
            2 => document["activated_at_unix_milliseconds"] = serde_json::Value::Null,
            3 => document["certificate_public_material_base64"] = serde_json::json!("dGFtcGVyZWQ"),
            4 => document["controller_id"] = serde_json::json!("b".repeat(32)),
            _ => unreachable!("closed mutation matrix"),
        }
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
                params![
                    serde_json::to_vec(&document).expect("mutated payload"),
                    "controllers",
                    identity.as_str()
                ],
            )
            .expect("tamper payload");
        drop(connection);

        let reopened = DatabaseControllerStore::new(database(&directory));
        assert_eq!(
            reopened.read(&identity).expect_err("tampering must fail"),
            AuthenticationStoreError::Corrupt
        );
    }
}

// Keeps the checked-in controller record schema aligned with the strict database codec.
#[test]
fn checked_in_controller_schema_matches_the_database_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/authentication/li_controller_record_v1.schema.json"
    ))
    .expect("controller schema");
    assert_eq!(
        schema["$id"],
        serde_json::json!(
            "https://letsinfer.ai/schemas/authentication/li_controller_record_v1.schema.json"
        )
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        serde_json::json!("li_controller_record")
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

// Computes one canonical lowercase SHA-256 identity for public material.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("SHA-256 identity")
}

// Returns whether one exact byte sequence occurs in a larger buffer.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
