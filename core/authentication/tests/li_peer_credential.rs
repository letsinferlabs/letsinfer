// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use li_authentication_manager::{
    ApiKeyMaterialProvider, AuthenticationClock, AuthenticationError, AuthenticationManager,
    AuthenticationRecord, AuthenticationRotation, AuthenticationStore, AuthenticationStoreError,
    PeerCredential, PeerCredentialDirection, PeerCredentialError, PeerCredentialState,
    PeerCredentialStore, VersionedAuthenticationRecord, VersionedPeerCredential,
    MAX_PEER_CREDENTIAL_LOOKUP_RESULTS,
};
use li_core_interface::{ApiKeyId, CredentialId, NodeId, Sha256Digest, UnixMilliseconds};

// Keeps API-key storage inert while exercising the independent peer-credential capability.
struct UnusedAuthenticationStore;

impl AuthenticationStore for UnusedAuthenticationStore {
    // Rejects an unused API-key read at its explicit test boundary.
    fn read(
        &self,
        _key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key collection read at its explicit test boundary.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key creation at its explicit test boundary.
    fn create(
        &self,
        _record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key replacement at its explicit test boundary.
    fn replace(
        &self,
        _record: AuthenticationRecord,
        _expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects an unused API-key rotation at its explicit test boundary.
    fn rotate(
        &self,
        _revoked: AuthenticationRecord,
        _expected_revision: u64,
        _replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Keeps entropy unused while constructing the complete AuthenticationManager owner.
struct UnusedMaterial;

impl ApiKeyMaterialProvider for UnusedMaterial {
    // Rejects any unexpected API-key material request.
    fn fill(&self, _destination: &mut [u8]) -> Result<(), AuthenticationError> {
        Err(AuthenticationError::EntropyUnavailable)
    }
}

// Supplies one deterministic peer-credential observation time.
struct FixedClock(UnixMilliseconds);

impl AuthenticationClock for FixedClock {
    // Returns the exact configured test timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(self.0)
    }
}

// Fails one deterministic clock read before an active credential can resolve.
struct FailingClock;

impl AuthenticationClock for FailingClock {
    // Returns one closed clock failure without inspecting credential state.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Err(AuthenticationError::InvalidPolicy {
            reason: "test clock is unavailable",
        })
    }
}

// Returns configured persisted matches and records every exact bounded lookup.
#[derive(Default)]
struct TestPeerCredentialStore {
    records: Mutex<BTreeMap<String, Vec<VersionedPeerCredential>>>,
    failure: Mutex<Option<AuthenticationStoreError>>,
    calls: Mutex<Vec<(Sha256Digest, usize)>>,
}

impl TestPeerCredentialStore {
    // Installs one exact persisted response under the queried leaf identity.
    fn set(&self, queried_digest: &Sha256Digest, records: Vec<VersionedPeerCredential>) {
        self.records
            .lock()
            .expect("peer records")
            .insert(queried_digest.as_str().to_string(), records);
    }

    // Installs one deterministic storage failure for later lookups.
    fn fail_with(&self, error: AuthenticationStoreError) {
        *self.failure.lock().expect("peer failure") = Some(error);
    }
}

impl PeerCredentialStore for TestPeerCredentialStore {
    // Returns only the configured exact query bucket while retaining the requested bound.
    fn matching_peer_credentials(
        &self,
        peer_leaf_sha256: &Sha256Digest,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        self.calls
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .push((peer_leaf_sha256.clone(), maximum_results));
        if let Some(error) = self
            .failure
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .clone()
        {
            return Err(error);
        }
        Ok(self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .get(peer_leaf_sha256.as_str())
            .cloned()
            .unwrap_or_default())
    }

    // Returns configured matches by exact credential identity for action revalidation.
    fn matching_peer_credential_ids(
        &self,
        credential_id: &CredentialId,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        if let Some(error) = self
            .failure
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .clone()
        {
            return Err(error);
        }
        let matches = self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .values()
            .flatten()
            .filter(|record| record.credential().credential_id() == credential_id)
            .take(maximum_results.saturating_add(1))
            .cloned()
            .collect();
        Ok(matches)
    }
}

// Creates one manager that shares the supplied persisted peer-credential store.
fn manager(store: Arc<TestPeerCredentialStore>, now: u64) -> AuthenticationManager {
    AuthenticationManager::new_with_peer_credential_store(
        Arc::new(UnusedAuthenticationStore),
        store,
        Arc::new(UnusedMaterial),
        Arc::new(FixedClock(UnixMilliseconds::new(now))),
    )
}

// Parses one deterministic credential identity from one repeated hexadecimal character.
fn credential_id(character: char) -> CredentialId {
    CredentialId::parse(&character.to_string().repeat(32)).expect("credential identity")
}

// Parses one deterministic leaf digest from one repeated hexadecimal character.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("leaf digest")
}

// Parses one deterministic Node identity from one repeated hexadecimal character.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&character.to_string().repeat(32)).expect("Node identity")
}

// Creates one validated peer credential from concise deterministic lifecycle values.
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

// Proves the persisted peer model rejects incoherent lifetime and rotation state.
#[test]
fn peer_credential_model_enforces_lifecycle_invariants() {
    let identity = credential_id('a');
    let leaf = digest('b');
    let local_node_id = node_id('1');
    let peer_node_id = node_id('2');
    let invalid = [
        PeerCredential::new(
            identity.clone(),
            leaf.clone(),
            local_node_id.clone(),
            local_node_id.clone(),
            PeerCredentialDirection::ChildToMain,
            UnixMilliseconds::new(100),
            UnixMilliseconds::new(200),
            None,
            None,
        ),
        PeerCredential::new(
            identity.clone(),
            leaf.clone(),
            local_node_id.clone(),
            peer_node_id.clone(),
            PeerCredentialDirection::ChildToMain,
            UnixMilliseconds::new(100),
            UnixMilliseconds::new(100),
            None,
            None,
        ),
        PeerCredential::new(
            identity.clone(),
            leaf.clone(),
            local_node_id.clone(),
            peer_node_id.clone(),
            PeerCredentialDirection::ChildToMain,
            UnixMilliseconds::new(100),
            UnixMilliseconds::new(200),
            Some(UnixMilliseconds::new(99)),
            None,
        ),
        PeerCredential::new(
            identity.clone(),
            leaf.clone(),
            local_node_id.clone(),
            peer_node_id.clone(),
            PeerCredentialDirection::ChildToMain,
            UnixMilliseconds::new(100),
            UnixMilliseconds::new(200),
            None,
            Some(credential_id('c')),
        ),
        PeerCredential::new(
            identity.clone(),
            leaf,
            local_node_id,
            peer_node_id,
            PeerCredentialDirection::ChildToMain,
            UnixMilliseconds::new(100),
            UnixMilliseconds::new(200),
            Some(UnixMilliseconds::new(150)),
            Some(identity),
        ),
    ];
    assert!(invalid
        .into_iter()
        .all(|result| matches!(result, Err(PeerCredentialError::InvalidRecord { .. }))));
}

// Proves one exact active persisted leaf resolves identically across manager reconstruction.
#[test]
fn manager_resolves_one_exact_active_peer_with_a_bounded_lookup() {
    let store = Arc::new(TestPeerCredentialStore::default());
    let leaf = digest('b');
    let active = credential('a', 'b', 100, 300, None, None);
    store.set(&leaf, vec![VersionedPeerCredential::new(active, 4)]);

    let resolved = manager(store.clone(), 200)
        .resolve_peer_credential(&leaf)
        .expect("active peer");
    assert_eq!(resolved.credential_id(), &credential_id('a'));
    assert_eq!(resolved.local_node_id(), &node_id('1'));
    assert_eq!(resolved.peer_node_id(), &node_id('2'));
    assert_eq!(resolved.direction(), PeerCredentialDirection::ChildToMain);
    let authorized = manager(store.clone(), 200)
        .authorize_peer_credential(&credential_id('a'))
        .expect("active identity");
    assert_eq!(authorized, resolved);
    assert_eq!(
        manager(store.clone(), 200)
            .resolve_peer_credential(&leaf)
            .expect("reconstructed active peer"),
        resolved
    );
    assert_eq!(
        store.calls.lock().expect("peer calls").as_slice(),
        [
            (leaf.clone(), MAX_PEER_CREDENTIAL_LOOKUP_RESULTS),
            (leaf, MAX_PEER_CREDENTIAL_LOOKUP_RESULTS),
        ]
    );
}

// Proves inactive and rotated leaves retain distinct decisions without identity fallback.
#[test]
fn manager_rejects_every_inactive_peer_lifecycle() {
    let cases = vec![
        (
            PeerCredential::new_with_state(
                credential_id('f'),
                digest('f'),
                node_id('1'),
                node_id('2'),
                PeerCredentialDirection::ChildToMain,
                PeerCredentialState::Pending,
                UnixMilliseconds::new(100),
                UnixMilliseconds::new(300),
                None,
                None,
            )
            .expect("pending credential"),
            200,
            PeerCredentialError::Pending,
        ),
        (
            credential('a', 'a', 200, 300, None, None),
            199,
            PeerCredentialError::NotYetValid,
        ),
        (
            credential('b', 'b', 100, 200, None, None),
            200,
            PeerCredentialError::Expired,
        ),
        (
            credential('c', 'c', 100, 300, Some(150), None),
            200,
            PeerCredentialError::Revoked,
        ),
        (
            credential('d', 'd', 100, 300, Some(150), Some('e')),
            200,
            PeerCredentialError::Rotated,
        ),
    ];
    for (record, now, expected) in cases {
        let leaf = record.peer_leaf_sha256().clone();
        let identity = record.credential_id().clone();
        let store = Arc::new(TestPeerCredentialStore::default());
        store.set(&leaf, vec![VersionedPeerCredential::new(record, 1)]);
        let manager = manager(store, now);
        assert_eq!(
            manager.resolve_peer_credential(&leaf),
            Err(expected.clone())
        );
        assert_eq!(manager.authorize_peer_credential(&identity), Err(expected));
    }

    let old_leaf = digest('d');
    let replacement_leaf = digest('e');
    let store = Arc::new(TestPeerCredentialStore::default());
    store.set(
        &old_leaf,
        vec![VersionedPeerCredential::new(
            credential('d', 'd', 100, 300, Some(150), Some('e')),
            2,
        )],
    );
    store.set(
        &replacement_leaf,
        vec![VersionedPeerCredential::new(
            credential('e', 'e', 150, 400, None, None),
            1,
        )],
    );
    let manager = manager(store, 200);
    assert_eq!(
        manager.resolve_peer_credential(&old_leaf),
        Err(PeerCredentialError::Rotated)
    );
    assert_eq!(
        manager
            .resolve_peer_credential(&replacement_leaf)
            .expect("replacement leaf")
            .credential_id(),
        &credential_id('e')
    );
}

// Proves missing, duplicate, corrupt, and unavailable lookups all fail closed.
#[test]
fn manager_rejects_ambiguous_corrupt_and_unavailable_peer_state() {
    let leaf = digest('a');
    let empty = Arc::new(TestPeerCredentialStore::default());
    assert_eq!(
        manager(empty, 200).resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Unrecognized)
    );

    let duplicate = Arc::new(TestPeerCredentialStore::default());
    duplicate.set(
        &leaf,
        vec![
            VersionedPeerCredential::new(credential('a', 'a', 100, 300, None, None), 1),
            VersionedPeerCredential::new(credential('b', 'a', 100, 300, None, None), 1),
        ],
    );
    assert_eq!(
        manager(duplicate, 200).resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Ambiguous)
    );

    let mismatched = Arc::new(TestPeerCredentialStore::default());
    mismatched.set(
        &leaf,
        vec![VersionedPeerCredential::new(
            credential('a', 'b', 100, 300, None, None),
            1,
        )],
    );
    assert_eq!(
        manager(mismatched, 200).resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Store(
            AuthenticationStoreError::Corrupt
        ))
    );

    let zero_revision = Arc::new(TestPeerCredentialStore::default());
    zero_revision.set(
        &leaf,
        vec![VersionedPeerCredential::new(
            credential('a', 'a', 100, 300, None, None),
            0,
        )],
    );
    assert_eq!(
        manager(zero_revision, 200).resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Store(
            AuthenticationStoreError::Corrupt
        ))
    );

    for failure in [
        AuthenticationStoreError::Conflict,
        AuthenticationStoreError::Corrupt,
        AuthenticationStoreError::Unavailable,
    ] {
        let unavailable = Arc::new(TestPeerCredentialStore::default());
        unavailable.fail_with(failure.clone());
        assert_eq!(
            manager(unavailable, 200).resolve_peer_credential(&leaf),
            Err(PeerCredentialError::Store(failure))
        );
    }

    let clock_failure = Arc::new(TestPeerCredentialStore::default());
    clock_failure.set(
        &leaf,
        vec![VersionedPeerCredential::new(
            credential('a', 'a', 100, 300, None, None),
            1,
        )],
    );
    let clock_failure = AuthenticationManager::new_with_peer_credential_store(
        Arc::new(UnusedAuthenticationStore),
        clock_failure,
        Arc::new(UnusedMaterial),
        Arc::new(FailingClock),
    );
    assert_eq!(
        clock_failure.resolve_peer_credential(&leaf),
        Err(PeerCredentialError::ClockUnavailable)
    );

    let legacy = AuthenticationManager::new(
        Arc::new(UnusedAuthenticationStore),
        Arc::new(UnusedMaterial),
        Arc::new(FixedClock(UnixMilliseconds::new(200))),
    );
    assert_eq!(
        legacy.resolve_peer_credential(&leaf),
        Err(PeerCredentialError::Store(
            AuthenticationStoreError::Unavailable
        ))
    );
}
