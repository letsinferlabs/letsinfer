// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use li_authentication_manager::{
    ApiKeyMaterialProvider, AuthenticationClock, AuthenticationError, AuthenticationEvent,
    AuthenticationManager, AuthenticationRecord, AuthenticationRotation, AuthenticationStore,
    AuthenticationStoreError, Controller, ControllerCertificate, ControllerCertificateError,
    ControllerCertificateMaterial, ControllerCertificateProvider, ControllerCertificateSource,
    ControllerError, ControllerPublicKey, ControllerRole, ControllerState, ControllerStore,
    PeerCredentialStore, VersionedAuthenticationRecord, VersionedController,
    VersionedPeerCredential,
};
use li_core_interface::{
    ApiKeyId, ControllerId, CredentialId, DisplayName, Sha256Digest, UnixMilliseconds,
};
use sha2::{Digest, Sha256};

const PROVIDER_NORMAL: u8 = 0;
const PROVIDER_INVALID: u8 = 1;
const PROVIDER_UNAVAILABLE: u8 = 2;
const PROVIDER_EXPIRED: u8 = 3;
const PROVIDER_FUTURE: u8 = 4;
const PROVIDER_WRONG_PUBLIC_KEY: u8 = 5;

// Stores controller records behind deterministic optimistic revisions and failure seams.
#[derive(Default)]
struct TestControllerStore {
    records: Mutex<BTreeMap<String, VersionedController>>,
    fail_create: AtomicBool,
    fail_replace: AtomicBool,
    replace_barrier: Mutex<Option<Arc<Barrier>>>,
}

impl TestControllerStore {
    // Installs one deterministic rendezvous immediately before optimistic replacement.
    fn set_replace_barrier(&self, barrier: Arc<Barrier>) {
        *self.replace_barrier.lock().expect("replace barrier") = Some(barrier);
    }
}

impl ControllerStore for TestControllerStore {
    // Returns one cloned controller record when present.
    fn read(
        &self,
        controller_id: &ControllerId,
    ) -> Result<Option<VersionedController>, AuthenticationStoreError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .get(controller_id.as_str())
            .cloned())
    }

    // Returns every cloned record in stable identity order.
    fn all(&self) -> Result<Vec<VersionedController>, AuthenticationStoreError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .values()
            .cloned()
            .collect())
    }

    // Creates one controller identity only when absent.
    fn create(
        &self,
        controller: Controller,
    ) -> Result<VersionedController, AuthenticationStoreError> {
        if self.fail_create.load(Ordering::SeqCst) {
            return Err(AuthenticationStoreError::Unavailable);
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?;
        let identity = controller.controller_id().as_str().to_string();
        if records.contains_key(&identity) {
            return Err(AuthenticationStoreError::Conflict);
        }
        let stored = VersionedController::new(controller, 1);
        records.insert(identity, stored.clone());
        Ok(stored)
    }

    // Replaces one exact controller revision after an optional deterministic rendezvous.
    fn replace(
        &self,
        controller: Controller,
        expected_revision: u64,
    ) -> Result<VersionedController, AuthenticationStoreError> {
        if self.fail_replace.load(Ordering::SeqCst) {
            return Err(AuthenticationStoreError::Unavailable);
        }
        let barrier = self
            .replace_barrier
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .clone();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?;
        let identity = controller.controller_id().as_str().to_string();
        let current = records
            .get(&identity)
            .ok_or(AuthenticationStoreError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(AuthenticationStoreError::Conflict);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(AuthenticationStoreError::Corrupt)?;
        let stored = VersionedController::new(controller, revision);
        records.insert(identity, stored.clone());
        Ok(stored)
    }
}

// Supplies deterministic public certificates while retaining a private sentinel internally.
struct TestCertificateProvider {
    mode: AtomicU8,
    issue_calls: AtomicUsize,
    import_calls: AtomicUsize,
    private_sentinel: Vec<u8>,
}

impl TestCertificateProvider {
    // Creates one provider that returns ordinary current certificates.
    fn new() -> Self {
        Self {
            mode: AtomicU8::new(PROVIDER_NORMAL),
            issue_calls: AtomicUsize::new(0),
            import_calls: AtomicUsize::new(0),
            private_sentinel: b"controller-private-key-sentinel".to_vec(),
        }
    }

    // Selects one deterministic provider outcome.
    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    // Returns one provider-validated fixture with selected lifetime and public-key identity.
    fn certificate(
        &self,
        controller_id: &ControllerId,
        material: Vec<u8>,
        public_key_sha256: Sha256Digest,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == PROVIDER_INVALID {
            return Err(ControllerCertificateError::Invalid);
        }
        if mode == PROVIDER_UNAVAILABLE {
            return Err(ControllerCertificateError::Unavailable);
        }
        let (valid_from, expires_at) = match mode {
            PROVIDER_EXPIRED => (0, 500),
            PROVIDER_FUTURE => (2_000, 3_000),
            _ => (0, 10_000),
        };
        ControllerCertificate::new(
            controller_id.clone(),
            digest(&material),
            if mode == PROVIDER_WRONG_PUBLIC_KEY {
                digest(b"wrong-public-key")
            } else {
                public_key_sha256
            },
            material,
            UnixMilliseconds::new(valid_from),
            UnixMilliseconds::new(expires_at),
        )
    }
}

impl ControllerCertificateProvider for TestCertificateProvider {
    // Issues one deterministic certificate bound to the supplied public-key identity.
    fn issue(
        &self,
        controller_id: &ControllerId,
        public_key: &ControllerPublicKey,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        self.issue_calls.fetch_add(1, Ordering::SeqCst);
        self.certificate(
            controller_id,
            format!(
                "-----BEGIN CERTIFICATE-----\n{}:{}\n-----END CERTIFICATE-----\n",
                controller_id.as_str(),
                public_key.sha256().as_str()
            )
            .into_bytes(),
            public_key.sha256().clone(),
        )
    }

    // Imports the exact supplied certificate bytes with a deterministic public-key projection.
    fn import(
        &self,
        controller_id: &ControllerId,
        material: &ControllerCertificateMaterial,
    ) -> Result<ControllerCertificate, ControllerCertificateError> {
        self.import_calls.fetch_add(1, Ordering::SeqCst);
        self.certificate(
            controller_id,
            material.bytes().to_vec(),
            digest(material.bytes()),
        )
    }
}

// Supplies mutable deterministic time to controller lifecycle tests.
struct TestClock(AtomicU64);

impl AuthenticationClock for TestClock {
    // Returns the currently configured deterministic timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Keeps unrelated inference-key storage unavailable in controller-only tests.
struct UnusedAuthenticationStore;

impl AuthenticationStore for UnusedAuthenticationStore {
    // Rejects unrelated API-key reads.
    fn read(
        &self,
        _key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects unrelated API-key listing.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects unrelated API-key creation.
    fn create(
        &self,
        _record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects unrelated API-key replacement.
    fn replace(
        &self,
        _record: AuthenticationRecord,
        _expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects unrelated API-key rotation.
    fn rotate(
        &self,
        _revoked: AuthenticationRecord,
        _expected_revision: u64,
        _replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Keeps unrelated directional peer persistence unavailable in controller-only tests.
struct UnusedPeerCredentialStore;

impl PeerCredentialStore for UnusedPeerCredentialStore {
    // Rejects unrelated peer digest lookup.
    fn matching_peer_credentials(
        &self,
        _peer_leaf_sha256: &Sha256Digest,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects unrelated peer identity lookup.
    fn matching_peer_credential_ids(
        &self,
        _credential_id: &CredentialId,
        _maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Keeps unrelated API-key entropy unavailable in controller-only tests.
struct UnusedMaterial;

impl ApiKeyMaterialProvider for UnusedMaterial {
    // Rejects unrelated API-key generation.
    fn fill(&self, _destination: &mut [u8]) -> Result<(), AuthenticationError> {
        Err(AuthenticationError::EntropyUnavailable)
    }
}

// Creates one controller-capable manager and retains every deterministic authority.
fn manager() -> (
    AuthenticationManager,
    Arc<TestControllerStore>,
    Arc<TestCertificateProvider>,
    Arc<TestClock>,
) {
    let store = Arc::new(TestControllerStore::default());
    let certificates = Arc::new(TestCertificateProvider::new());
    let clock = Arc::new(TestClock(AtomicU64::new(1_000)));
    (
        configured_manager(store.clone(), certificates.clone(), clock.clone()),
        store,
        certificates,
        clock,
    )
}

// Creates one manager over shared deterministic controller authorities.
fn configured_manager(
    store: Arc<TestControllerStore>,
    certificates: Arc<TestCertificateProvider>,
    clock: Arc<TestClock>,
) -> AuthenticationManager {
    AuthenticationManager::new_with_controller_store(
        Arc::new(UnusedAuthenticationStore),
        Arc::new(UnusedPeerCredentialStore),
        store,
        certificates,
        Arc::new(UnusedMaterial),
        clock,
    )
}

// Returns one canonical controller identity fixture.
fn controller_id(character: char) -> ControllerId {
    ControllerId::parse(&character.to_string().repeat(32)).expect("controller identity")
}

// Returns one bounded deterministic public-key fixture.
fn public_key(character: u8) -> ControllerPublicKey {
    ControllerPublicKey::new(vec![character; 64]).expect("public key")
}

// Returns one bounded deterministic imported certificate fixture.
fn imported_certificate(character: u8) -> ControllerCertificateMaterial {
    ControllerCertificateMaterial::new(
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            char::from(character)
        )
        .into_bytes(),
    )
    .expect("certificate material")
}

// Returns one canonical display-name fixture.
fn name(value: &str) -> DisplayName {
    DisplayName::parse(value).expect("display name")
}

// Returns one canonical digest for deterministic public material.
fn digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(value))).expect("digest")
}

// Covers issue, import, activation, listing, role policy, replay, and restart reconstruction.
#[test]
fn controller_registry_ordinary_paths_are_typed_replay_safe_and_restartable() {
    let (manager, store, certificates, clock) = manager();
    let first_id = controller_id('a');
    let first_key = public_key(1);
    let issued = manager
        .issue_controller(
            first_id.clone(),
            name("Desk Mac"),
            ControllerRole::Viewer,
            first_key.clone(),
        )
        .expect("issue controller");
    assert_eq!(issued.value().state(), ControllerState::Issued);
    assert!(matches!(
        issued.event(),
        Some(AuthenticationEvent::ControllerIssued { .. })
    ));
    let replay = manager
        .issue_controller(
            first_id.clone(),
            name("Desk Mac"),
            ControllerRole::Viewer,
            first_key,
        )
        .expect("issue replay");
    assert!(replay.event().is_none());
    assert_eq!(certificates.issue_calls.load(Ordering::SeqCst), 1);
    clock.0.store(1_100, Ordering::SeqCst);
    let active = manager
        .activate_controller(&first_id)
        .expect("activate controller");
    assert_eq!(active.value().state(), ControllerState::Active);
    assert!(manager
        .authorize_controller(
            &first_id,
            active.value().certificate().certificate_sha256(),
            ControllerRole::Viewer,
        )
        .is_ok());
    assert_eq!(
        manager.authorize_controller(
            &first_id,
            active.value().certificate().certificate_sha256(),
            ControllerRole::Operator,
        ),
        Err(ControllerError::Unauthorized)
    );

    let second_id = controller_id('b');
    let imported = manager
        .import_controller(
            second_id.clone(),
            name("Studio Mac"),
            ControllerRole::Administrator,
            imported_certificate(b'2'),
        )
        .expect("import controller");
    assert!(matches!(
        imported.event(),
        Some(AuthenticationEvent::ControllerImported { .. })
    ));
    let second = manager
        .activate_controller(&second_id)
        .expect("activate imported controller");
    let listed = manager.controllers().expect("list controllers");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].controller_id(), &first_id);
    assert_eq!(manager.controller(&second_id).unwrap(), *second.value());

    let reconstructed = configured_manager(store, certificates, clock);
    let principal = reconstructed
        .authorize_controller(
            &second_id,
            second.value().certificate().certificate_sha256(),
            ControllerRole::Administrator,
        )
        .expect("restart authorization");
    assert_eq!(principal.controller_id(), &second_id);
    assert_eq!(principal.role(), ControllerRole::Administrator);
}

// Rejects implicit divergence and permits only explicit active certificate replacement.
#[test]
fn controller_registration_conflict_and_explicit_replacement_are_closed() {
    let (manager, _, certificates, _) = manager();
    let identity = controller_id('a');
    let first_key = public_key(1);
    manager
        .issue_controller(
            identity.clone(),
            name("Desk Mac"),
            ControllerRole::Operator,
            first_key,
        )
        .expect("issue");
    let first = manager
        .activate_controller(&identity)
        .expect("activate")
        .value()
        .clone();
    assert_eq!(
        manager
            .issue_controller(
                identity.clone(),
                name("Desk Mac"),
                ControllerRole::Administrator,
                public_key(1),
            )
            .expect_err("implicit registration divergence"),
        ControllerError::Store(AuthenticationStoreError::Conflict)
    );

    let replacement_key = public_key(2);
    let replaced = manager
        .replace_controller(
            &identity,
            name("Desk Mac"),
            ControllerRole::Administrator,
            ControllerCertificateSource::Issue(replacement_key.clone()),
        )
        .expect("replace controller");
    assert_eq!(replaced.value().state(), ControllerState::Active);
    assert!(matches!(
        replaced.event(),
        Some(AuthenticationEvent::ControllerReplaced { .. })
    ));
    assert_ne!(
        first.certificate().certificate_sha256(),
        replaced.value().certificate().certificate_sha256()
    );
    assert_eq!(
        manager.authorize_controller(
            &identity,
            first.certificate().certificate_sha256(),
            ControllerRole::Viewer,
        ),
        Err(ControllerError::Unauthorized)
    );
    let replay = manager
        .replace_controller(
            &identity,
            name("Desk Mac"),
            ControllerRole::Administrator,
            ControllerCertificateSource::Issue(replacement_key),
        )
        .expect("replacement replay");
    assert!(replay.event().is_none());
    assert_eq!(certificates.issue_calls.load(Ordering::SeqCst), 2);
}

// Commits confirmed enrollment active in one write and leaves no issued record on failure.
#[test]
fn controller_enrollment_is_atomic_replay_safe_and_fail_closed() {
    let (manager, store, certificates, _) = manager();
    let identity = controller_id('a');
    let key = public_key(1);
    store.fail_create.store(true, Ordering::SeqCst);
    assert_eq!(
        manager
            .enroll_controller(
                identity.clone(),
                name("Desk Mac"),
                ControllerRole::Administrator,
                key.clone(),
            )
            .expect_err("enrollment store failure"),
        ControllerError::Store(AuthenticationStoreError::Unavailable)
    );
    assert!(store.records.lock().expect("records").is_empty());

    store.fail_create.store(false, Ordering::SeqCst);
    let enrolled = manager
        .enroll_controller(
            identity.clone(),
            name("Desk Mac"),
            ControllerRole::Administrator,
            key.clone(),
        )
        .expect("enroll controller");
    assert_eq!(enrolled.value().state(), ControllerState::Active);
    assert!(matches!(
        enrolled.event(),
        Some(AuthenticationEvent::ControllerEnrolled { .. })
    ));
    assert_eq!(store.records.lock().expect("records").len(), 1);
    let replay = manager
        .enroll_controller(
            identity,
            name("Desk Mac"),
            ControllerRole::Administrator,
            key,
        )
        .expect("enrollment replay");
    assert!(replay.event().is_none());
    assert_eq!(certificates.issue_calls.load(Ordering::SeqCst), 2);
}

// Gives concurrent revocation one event winner and one exact idempotent terminal replay.
#[test]
fn controller_revocation_is_idempotent_and_concurrent() {
    let (_, store, certificates, clock) = manager();
    let identity = controller_id('a');
    let setup = configured_manager(store.clone(), certificates.clone(), clock.clone());
    setup
        .issue_controller(
            identity.clone(),
            name("Desk Mac"),
            ControllerRole::Viewer,
            public_key(1),
        )
        .expect("issue");
    setup.activate_controller(&identity).expect("activate");
    clock.0.store(1_500, Ordering::SeqCst);
    store.set_replace_barrier(Arc::new(Barrier::new(2)));
    let first = configured_manager(store.clone(), certificates.clone(), clock.clone());
    let second = configured_manager(store.clone(), certificates, clock);
    let first_id = identity.clone();
    let second_id = identity.clone();
    let first = thread::spawn(move || first.revoke_controller(&first_id));
    let second = thread::spawn(move || second.revoke_controller(&second_id));
    let first = first.join().expect("first join").expect("first revoke");
    let second = second.join().expect("second join").expect("second revoke");
    assert_eq!(
        usize::from(first.event().is_some()) + usize::from(second.event().is_some()),
        1
    );
    assert_eq!(first.value().state(), ControllerState::Revoked);
    assert_eq!(second.value().state(), ControllerState::Revoked);
    let replay = setup.revoke_controller(&identity).expect("revoke replay");
    assert!(replay.event().is_none());
    assert_eq!(
        setup.authorize_controller(
            &identity,
            replay.value().certificate().certificate_sha256(),
            ControllerRole::Viewer,
        ),
        Err(ControllerError::Unauthorized)
    );
}

// Proves provider, lifetime, and store failures leave prior durable authorization unchanged.
#[test]
fn controller_failures_are_redacted_and_rollback_safe() {
    let (manager, store, certificates, _) = manager();
    let identity = controller_id('a');
    for (mode, expected) in [
        (PROVIDER_INVALID, ControllerError::InvalidCertificate),
        (PROVIDER_UNAVAILABLE, ControllerError::ProviderUnavailable),
        (PROVIDER_EXPIRED, ControllerError::CertificateExpired),
        (PROVIDER_FUTURE, ControllerError::CertificateNotYetValid),
        (
            PROVIDER_WRONG_PUBLIC_KEY,
            ControllerError::InvalidCertificate,
        ),
    ] {
        certificates.set_mode(mode);
        assert_eq!(
            manager
                .issue_controller(
                    identity.clone(),
                    name("Desk Mac"),
                    ControllerRole::Viewer,
                    public_key(1),
                )
                .expect_err("certificate provider rejection"),
            expected
        );
        assert!(store.records.lock().expect("records").is_empty());
    }

    certificates.set_mode(PROVIDER_NORMAL);
    manager
        .issue_controller(
            identity.clone(),
            name("Desk Mac"),
            ControllerRole::Viewer,
            public_key(1),
        )
        .expect("issue");
    let active = manager
        .activate_controller(&identity)
        .expect("activate")
        .value()
        .clone();
    store.fail_replace.store(true, Ordering::SeqCst);
    assert_eq!(
        manager
            .replace_controller(
                &identity,
                name("Desk Mac"),
                ControllerRole::Administrator,
                ControllerCertificateSource::Issue(public_key(2)),
            )
            .expect_err("replacement store failure"),
        ControllerError::Store(AuthenticationStoreError::Unavailable)
    );
    assert_eq!(manager.controller(&identity).unwrap(), active);
    store.fail_replace.store(false, Ordering::SeqCst);
    store.fail_create.store(true, Ordering::SeqCst);
    assert_eq!(
        manager
            .import_controller(
                controller_id('b'),
                name("Studio Mac"),
                ControllerRole::Viewer,
                imported_certificate(b'2'),
            )
            .expect_err("import store failure"),
        ControllerError::Store(AuthenticationStoreError::Unavailable)
    );
    assert_eq!(manager.controllers().unwrap().len(), 1);

    let debug = format!("{:?}", public_key(9));
    let error = format!("{:?}", ControllerError::ProviderUnavailable);
    assert!(!debug.contains("controller-private-key-sentinel"));
    assert!(!error.contains("controller-private-key-sentinel"));
    assert_eq!(
        certificates.private_sentinel,
        b"controller-private-key-sentinel".to_vec()
    );
}
