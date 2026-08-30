// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use li_authentication_manager::{
    ApiKeyMaterialProvider, AuthenticationClock, AuthenticationError, AuthenticationManager,
    AuthenticationRecord, AuthenticationRotation, AuthenticationStore, AuthenticationStoreError,
    ControllerCertificate, ControllerCertificateError, ControllerCertificateMaterial,
    ControllerCertificateProvider, ControllerPublicKey, ControllerRole, PeerCredential,
    PeerCredentialDirection, PeerCredentialError, PeerCredentialState, PeerCredentialStore,
    VersionedAuthenticationRecord, VersionedPeerCredential, MAX_PEER_CREDENTIAL_LOOKUP_RESULTS,
};
use li_core_application::{CoreNodePrincipalResolver, DatabasePeerCredentialStore};
use li_core_interface::{
    ApiKeyId, ControllerId, CredentialId, DisplayName, NodeId, Sha256Digest, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseConfiguration,
    DatabaseManager, DatabaseRecord, DatabaseRevision,
};
use li_node_manager::{
    DatabaseAuthenticationStore, DatabaseControllerStore,
    NodePrivateAuthenticatedConnectionHandler, NodePrivatePrincipalResolver,
    NodePrivateRemoteDocumentEndpoint, NodePrivateRemotePrincipal, NodePrivateRemoteSecureStream,
    NodePrivateRemoteTlsError,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

// Keeps unrelated inference API-key storage unavailable in composition tests.
struct UnusedAuthenticationStore;

impl AuthenticationStore for UnusedAuthenticationStore {
    // Rejects an unused API-key read.
    fn read(
        &self,
        _key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key collection read.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key creation.
    fn create(
        &self,
        _record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key replacement.
    fn replace(
        &self,
        _record: AuthenticationRecord,
        _expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key rotation.
    fn rotate(
        &self,
        _revoked: AuthenticationRecord,
        _expected_revision: u64,
        _replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Rejects entropy because peer resolution never creates API-key material.
struct UnusedMaterial;

impl ApiKeyMaterialProvider for UnusedMaterial {
    // Fails any unexpected API-key material request.
    fn fill(&self, _destination: &mut [u8]) -> Result<(), AuthenticationError> {
        Err(AuthenticationError::EntropyUnavailable)
    }
}

// Issues deterministic public controller certificates without retaining a private key.
struct ControllerCertificates;

impl ControllerCertificateProvider for ControllerCertificates {
    // Issues one exact public certificate bound to the supplied key identity.
    fn issue(
        &self,
        controller_id: &ControllerId,
        public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        let material = format!("controller-certificate:{}", controller_id.as_str()).into_bytes();
        ControllerCertificate::new(
            controller_id.clone(),
            Sha256Digest::parse(&format!("{:x}", sha2::Sha256::digest(&material)))
                .expect("certificate digest"),
            public_key.sha256().clone(),
            material,
            UnixMilliseconds::new(100),
            UnixMilliseconds::new(300),
        )
    }

    // Rejects unused imported material in this issuance-only fixture.
    fn import(
        &self,
        _controller_id: &ControllerId,
        _material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        Err(ControllerCertificateError::Invalid)
    }
}

// Supplies one exact resolution time.
struct FixedClock(UnixMilliseconds);

impl AuthenticationClock for FixedClock {
    // Returns the configured deterministic timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(self.0)
    }
}

// Returns one fixed store error for redacted bridge-failure coverage.
struct FailingPeerCredentialStore;

impl PeerCredentialStore for FailingPeerCredentialStore {
    // Returns one unavailable result without inspecting the requested identity.
    fn matching_peer_credentials(
        &self,
        _peer_leaf_sha256: &Sha256Digest,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Returns the same deterministic failure for exact identity authorization.
    fn matching_peer_credential_ids(
        &self,
        _credential_id: &CredentialId,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Rejects any dispatch reached after a relationship should have failed closed.
struct UnreachableEndpoint;

impl NodePrivateRemoteDocumentEndpoint for UnreachableEndpoint {
    // Fails the test if a rejected peer reaches document dispatch.
    fn handle_document(
        &self,
        _principal: &NodePrivateRemotePrincipal,
        _document: &[u8],
    ) -> Result<Vec<u8>, NodePrivateRemoteTlsError> {
        panic!("rejected peer must not reach endpoint dispatch")
    }
}

// Fails any plaintext I/O attempted before relationship authorization completes.
struct UnreadSecureStream;

impl NodePrivateRemoteSecureStream for UnreadSecureStream {
    // Fails the test if the handler reads from an unauthorized peer.
    fn read_bytes(
        &mut self,
        _buffer: &mut [u8],
        _deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError> {
        panic!("rejected peer must not be read")
    }

    // Fails the test if the handler writes to an unauthorized peer.
    fn write_bytes(
        &mut self,
        _buffer: &[u8],
        _deadline: Instant,
    ) -> Result<usize, NodePrivateRemoteTlsError> {
        panic!("rejected peer must not be written")
    }
}

// Mirrors only the closed persisted bucket fields for corruption-boundary fixtures.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerCredentialBucketFixture {
    #[serde(skip)]
    record_identifier: String,
    peer_leaf_sha256: String,
    credentials: Vec<PeerCredentialRecordFixture>,
}

impl DatabaseRecord for PeerCredentialBucketFixture {
    const COLLECTION: DatabaseCollection = DatabaseCollection::PeerCredentials;

    // Returns the independently selected physical record identity.
    fn identifier(&self) -> &str {
        &self.record_identifier
    }
}

// Mirrors one closed persisted lifecycle entry for bounded duplicate fixtures.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PeerCredentialRecordFixture {
    credential_id: String,
    local_node_id: String,
    peer_node_id: String,
    direction: String,
    state: String,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    revoked_at_unix_milliseconds: Option<u64>,
    rotated_to: Option<String>,
}

// Opens one shared production DatabaseManager in an isolated private directory.
fn open_database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1)),
        )
        .expect("database manager"),
    )
}

// Creates one AuthenticationManager over the supplied persisted peer store.
fn authentication(store: Arc<dyn PeerCredentialStore>, now: u64) -> Arc<AuthenticationManager> {
    Arc::new(AuthenticationManager::new_with_peer_credential_store(
        Arc::new(UnusedAuthenticationStore),
        store,
        Arc::new(UnusedMaterial),
        Arc::new(FixedClock(UnixMilliseconds::new(now))),
    ))
}

// Composes distinct peer and controller stores over one shared database authority.
fn authentication_with_controllers(
    database: Arc<DatabaseManager>,
    peer_store: Arc<dyn PeerCredentialStore>,
    now: u64,
) -> Arc<AuthenticationManager> {
    Arc::new(AuthenticationManager::new_with_controller_store(
        Arc::new(DatabaseAuthenticationStore::new(database.clone())),
        peer_store,
        Arc::new(DatabaseControllerStore::new(database)),
        Arc::new(ControllerCertificates),
        Arc::new(UnusedMaterial),
        Arc::new(FixedClock(UnixMilliseconds::new(now))),
    ))
}

// Parses one deterministic credential identity.
fn credential_id(character: char) -> CredentialId {
    CredentialId::parse(&character.to_string().repeat(32)).expect("credential identity")
}

// Parses one deterministic exact certificate-leaf digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("leaf digest")
}

// Parses one deterministic Node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&character.to_string().repeat(32)).expect("Node identity")
}

// Creates one deterministic validated peer credential.
fn credential(
    identity: char,
    leaf: char,
    issued_at: u64,
    expires_at: u64,
    revoked_at: Option<u64>,
    rotated_to: Option<char>,
) -> PeerCredential {
    PeerCredential::new(
        credential_id(identity),
        digest(leaf),
        node_id('1'),
        node_id('2'),
        PeerCredentialDirection::ChildToMain,
        UnixMilliseconds::new(issued_at),
        UnixMilliseconds::new(expires_at),
        revoked_at.map(UnixMilliseconds::new),
        rotated_to.map(credential_id),
    )
    .expect("peer credential")
}

// Projects one credential into the private schema's fixture representation.
fn fixture_record(credential: &PeerCredential) -> PeerCredentialRecordFixture {
    PeerCredentialRecordFixture {
        credential_id: credential.credential_id().as_str().to_string(),
        local_node_id: credential.local_node_id().as_str().to_string(),
        peer_node_id: credential.peer_node_id().as_str().to_string(),
        direction: "child_to_main".to_string(),
        state: match credential.state() {
            PeerCredentialState::Pending => "pending",
            PeerCredentialState::Active => "active",
        }
        .to_string(),
        issued_at_unix_milliseconds: credential.issued_at().value(),
        expires_at_unix_milliseconds: credential.expires_at().value(),
        revoked_at_unix_milliseconds: credential.revoked_at().map(UnixMilliseconds::value),
        rotated_to: credential
            .rotated_to()
            .map(|identity| identity.as_str().to_string()),
    }
}

// Proves one applied/replayed credential resolves through the real Node bridge after restart.
#[test]
fn persisted_active_peer_replays_reconstructs_and_resolves_through_node() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = open_database(&directory);
    let store = Arc::new(DatabasePeerCredentialStore::new(database.clone()));
    let active = credential('a', 'b', 100, 300, None, None);
    let applied = store
        .create(active.clone(), "peer:create:b")
        .expect("create peer credential");
    let replayed = store
        .create(active.clone(), "peer:create:b")
        .expect("replay peer credential");
    assert_eq!(applied.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(replayed.disposition(), DatabaseCommitDisposition::Replayed);
    assert_eq!(applied.credential(), replayed.credential());
    assert_eq!(applied.credential().revision(), 1);

    let authentication_manager = authentication(store.clone(), 200);
    let resolver = CoreNodePrincipalResolver::new(authentication_manager, node_id('1'));
    assert_eq!(
        resolver
            .principal_for_certificate(active.peer_leaf_sha256())
            .expect("Node peer resolution"),
        NodePrivateRemotePrincipal::Peer(credential_id('a'))
    );
    let wrong_resident = Arc::new(CoreNodePrincipalResolver::new(
        authentication(store.clone(), 200),
        node_id('3'),
    ));
    assert_eq!(
        wrong_resident.principal_for_certificate(active.peer_leaf_sha256()),
        Err(NodePrivateRemoteTlsError::PrincipalRejected)
    );
    let handler = NodePrivateAuthenticatedConnectionHandler::new(
        Arc::new(UnreachableEndpoint),
        wrong_resident,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("authenticated handler");
    assert_eq!(
        handler.handle(active.peer_leaf_sha256(), &mut UnreadSecureStream),
        Err(NodePrivateRemoteTlsError::PrincipalRejected)
    );
    drop(handler);
    drop(resolver);
    drop(store);
    let database_manager = match Arc::try_unwrap(database) {
        Ok(database) => database,
        Err(_) => panic!("database must have one lifecycle owner"),
    };
    database_manager.close().expect("close database");

    let reopened = open_database(&directory);
    let reopened_store = Arc::new(DatabasePeerCredentialStore::new(reopened));
    let reconstructed = authentication(reopened_store, 200);
    assert_eq!(
        reconstructed
            .resolve_peer_credential(active.peer_leaf_sha256())
            .expect("reconstructed peer")
            .credential_id(),
        &credential_id('a')
    );
}

// Resolves an exact active controller leaf without falling back from a recognized peer failure.
#[test]
fn node_principal_resolver_keeps_controller_and_peer_authorities_distinct() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = open_database(&directory);
    let peers = Arc::new(DatabasePeerCredentialStore::new(database.clone()));
    let authentication = authentication_with_controllers(database, peers, 200);
    let controller_id = ControllerId::parse(&"c".repeat(32)).expect("controller");
    let controller = authentication
        .enroll_controller(
            controller_id.clone(),
            DisplayName::parse("Desk Mac").expect("name"),
            ControllerRole::Viewer,
            ControllerPublicKey::new(vec![7; 96]).expect("public key"),
        )
        .expect("enroll controller")
        .value()
        .clone();
    let fingerprint = controller.certificate().certificate_sha256().clone();
    let resolver = CoreNodePrincipalResolver::new(authentication.clone(), node_id('1'));
    assert_eq!(
        resolver
            .principal_for_certificate(&fingerprint)
            .expect("controller principal"),
        NodePrivateRemotePrincipal::Controller {
            controller_id: controller_id.clone(),
            certificate_sha256: fingerprint.clone(),
        }
    );
    authentication
        .revoke_controller(&controller_id)
        .expect("revoke controller");
    assert_eq!(
        resolver.principal_for_certificate(&fingerprint),
        Err(NodePrivateRemoteTlsError::PrincipalRejected)
    );
}

// Proves missing and unavailable state collapse to one redacted Node denial.
#[test]
fn node_bridge_denies_missing_and_store_failure_without_identity_details() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePeerCredentialStore::new(open_database(&directory)));
    let leaf = digest('a');
    let missing = authentication(store, 200);
    assert_eq!(
        missing.resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Unrecognized)
    );
    let missing_bridge = CoreNodePrincipalResolver::new(missing, node_id('1'));
    assert_eq!(
        missing_bridge.principal_for_certificate(&leaf),
        Err(NodePrivateRemoteTlsError::PrincipalRejected)
    );

    let failed = authentication(Arc::new(FailingPeerCredentialStore), 200);
    let failed_bridge = CoreNodePrincipalResolver::new(failed, node_id('1'));
    let error = failed_bridge
        .principal_for_certificate(&leaf)
        .expect_err("store failure must deny");
    assert_eq!(error, NodePrivateRemoteTlsError::PrincipalRejected);
    assert!(!error.to_string().contains(leaf.as_str()));
}

// Proves duplicate and mismatched persisted buckets fail before alternate identity fallback.
#[test]
fn database_adapter_rejects_ambiguous_and_corrupt_peer_buckets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = open_database(&directory);
    let leaf = digest('a');
    let first = credential('a', 'a', 100, 300, None, None);
    let second = credential('b', 'a', 100, 300, None, None);
    database
        .write(DatabaseCommand::save(
            "peer:ambiguous:a",
            PeerCredentialBucketFixture {
                record_identifier: leaf.as_str().to_string(),
                peer_leaf_sha256: leaf.as_str().to_string(),
                credentials: vec![fixture_record(&first), fixture_record(&second)],
            },
            DatabaseRevision::Missing,
        ))
        .expect("ambiguous fixture");
    let store = Arc::new(DatabasePeerCredentialStore::new(database.clone()));
    assert_eq!(
        authentication(store, 200).resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Ambiguous)
    );

    let mismatched_query = digest('c');
    database
        .write(DatabaseCommand::save(
            "peer:mismatched:c",
            PeerCredentialBucketFixture {
                record_identifier: mismatched_query.as_str().to_string(),
                peer_leaf_sha256: digest('d').as_str().to_string(),
                credentials: vec![fixture_record(&credential('c', 'd', 100, 300, None, None))],
            },
            DatabaseRevision::Missing,
        ))
        .expect("mismatched fixture");
    let unsupported_direction_leaf = digest('e');
    let mut unsupported_direction = fixture_record(&credential('e', 'e', 100, 300, None, None));
    unsupported_direction.direction = "sideways".to_string();
    database
        .write(DatabaseCommand::save(
            "peer:unsupported-direction:e",
            PeerCredentialBucketFixture {
                record_identifier: unsupported_direction_leaf.as_str().to_string(),
                peer_leaf_sha256: unsupported_direction_leaf.as_str().to_string(),
                credentials: vec![unsupported_direction],
            },
            DatabaseRevision::Missing,
        ))
        .expect("unsupported direction fixture");
    let store = DatabasePeerCredentialStore::new(database);
    assert_eq!(
        store.matching_peer_credentials(&mismatched_query, 2),
        Err(AuthenticationStoreError::Corrupt)
    );
    assert_eq!(
        store.matching_peer_credentials(&mismatched_query, 3),
        Err(AuthenticationStoreError::Corrupt)
    );
    assert_eq!(
        store.matching_peer_credentials(&unsupported_direction_leaf, 2),
        Err(AuthenticationStoreError::Corrupt)
    );
}

// Proves every inactive persisted lifecycle remains denied by the composed manager.
#[test]
fn database_adapter_preserves_expired_revoked_and_rotated_denials() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePeerCredentialStore::new(open_database(&directory)));
    let cases = [
        (
            credential('a', 'a', 100, 200, None, None),
            PeerCredentialError::Expired,
        ),
        (
            credential('b', 'b', 100, 300, Some(150), None),
            PeerCredentialError::Revoked,
        ),
        (
            credential('c', 'c', 100, 300, Some(150), Some('d')),
            PeerCredentialError::Rotated,
        ),
    ];
    for (index, (credential, expected)) in cases.into_iter().enumerate() {
        store
            .create(credential.clone(), format!("peer:lifecycle:{index}"))
            .expect("persist lifecycle");
        assert_eq!(
            authentication(store.clone(), 200)
                .resolve_peer_credential(credential.peer_leaf_sha256()),
            Err(expected)
        );
    }
}

// Proves optimistic replacement conflicts leave the exact prior credential authoritative.
#[test]
fn database_adapter_enforces_revision_and_duplicate_conflicts() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePeerCredentialStore::new(open_database(&directory)));
    let active = credential('a', 'a', 100, 300, None, None);
    store
        .create(active.clone(), "peer:create:a")
        .expect("create active peer");
    let revoked = credential('a', 'a', 100, 300, Some(200), None);
    assert_eq!(
        store.replace(revoked, 9, "peer:revoke:a"),
        Err(AuthenticationStoreError::Conflict)
    );
    assert_eq!(
        store.create(
            credential('b', 'a', 100, 300, None, None),
            "peer:duplicate:a"
        ),
        Err(AuthenticationStoreError::Conflict)
    );
    assert_eq!(
        authentication(store, 200)
            .resolve_peer_credential(active.peer_leaf_sha256())
            .expect("unchanged active peer")
            .credential_id(),
        &credential_id('a')
    );
}

// Proves exact credential-identity authorization uses the persisted adapter and closed bounds.
#[test]
fn database_adapter_authorizes_one_exact_peer_credential_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePeerCredentialStore::new(open_database(&directory)));
    let active = credential('a', 'b', 100, 300, None, None);
    store
        .create(active.clone(), "peer:create:identity")
        .expect("create peer credential");

    assert_eq!(
        authentication(store.clone(), 200)
            .authorize_peer_credential(active.credential_id())
            .expect("authorize exact identity")
            .credential_id(),
        active.credential_id()
    );
    assert_eq!(
        authentication(store.clone(), 200).authorize_peer_credential(&credential_id('c')),
        Err(PeerCredentialError::Unrecognized)
    );
    assert_eq!(
        store.matching_peer_credential_ids(active.credential_id(), 0),
        Err(AuthenticationStoreError::Corrupt)
    );
    assert_eq!(
        store.matching_peer_credential_ids(
            active.credential_id(),
            MAX_PEER_CREDENTIAL_LOOKUP_RESULTS + 1,
        ),
        Err(AuthenticationStoreError::Corrupt)
    );
}

// Proves duplicate identities across leaf buckets fail closed without choosing one credential.
#[test]
fn database_adapter_rejects_ambiguous_peer_credential_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePeerCredentialStore::new(open_database(&directory)));
    let first = credential('a', 'b', 100, 300, None, None);
    let second = credential('a', 'c', 100, 300, None, None);
    store
        .create(first.clone(), "peer:create:first-identity")
        .expect("create first peer credential");
    store
        .create(second, "peer:create:second-identity")
        .expect("create duplicate identity on another leaf");

    let matches = store
        .matching_peer_credential_ids(first.credential_id(), MAX_PEER_CREDENTIAL_LOOKUP_RESULTS)
        .expect("bounded duplicate lookup");
    assert_eq!(matches.len(), 2);
    assert_eq!(
        authentication(store, 200).authorize_peer_credential(first.credential_id()),
        Err(PeerCredentialError::Ambiguous)
    );
}
