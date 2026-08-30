// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use li_authentication_manager::{
    ApiKeyLimits, ApiKeyMaterialProvider, ApiKeyModelScope, ApiKeyPolicy, AuthenticationClock,
    AuthenticationError, AuthenticationEvent, AuthenticationManager, AuthenticationRecord,
    AuthenticationRotation, AuthenticationStore, AuthenticationStoreError,
    VersionedAuthenticationRecord,
};
use li_core_interface::{ApiKeyId, DisplayName, LogicalModelName, TechnicalName, UnixMilliseconds};

// Stores deterministic authentication records behind the production store contract.
#[derive(Default)]
struct TestStore {
    records: Mutex<BTreeMap<String, VersionedAuthenticationRecord>>,
    response_tamper: AtomicU8,
    replace_barrier: Mutex<Option<Arc<Barrier>>>,
}

const TAMPER_NONE: u8 = 0;
const TAMPER_READ_REVISION: u8 = 1;
const TAMPER_CREATE_RECORD: u8 = 2;
const TAMPER_REPLACE_RECORD: u8 = 3;
const TAMPER_ROTATION_REVOKED: u8 = 4;
const TAMPER_ROTATION_REPLACEMENT: u8 = 5;
const TAMPER_CREATE_REVISION: u8 = 6;
const TAMPER_REPLACE_REVISION: u8 = 7;
const TAMPER_ROTATION_REVOKED_REVISION: u8 = 8;
const TAMPER_ROTATION_REPLACEMENT_REVISION: u8 = 9;

impl TestStore {
    // Installs one deterministic rendezvous immediately before replacement locking.
    fn set_replace_barrier(&self, barrier: Arc<Barrier>) {
        *self.replace_barrier.lock().expect("replace barrier") = Some(barrier);
    }
}

impl AuthenticationStore for TestStore {
    // Returns one cloned record from deterministic in-memory state.
    fn read(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        let stored = self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .get(key_id.as_str())
            .cloned();
        Ok(stored.map(|stored| {
            if self.response_tamper.load(Ordering::SeqCst) == TAMPER_READ_REVISION {
                VersionedAuthenticationRecord::new(stored.record().clone(), 0)
            } else {
                stored
            }
        }))
    }

    // Returns every cloned record in stable key order.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .values()
            .cloned()
            .collect())
    }

    // Creates one record only when its key identity is absent.
    fn create(
        &self,
        record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?;
        let key = record.api_key().key_id().as_str().to_string();
        if records.contains_key(&key)
            || records
                .values()
                .any(|stored| stored.record().api_key().name() == record.api_key().name())
        {
            return Err(AuthenticationStoreError::Conflict);
        }
        let stored = VersionedAuthenticationRecord::new(record, 1);
        records.insert(key, stored.clone());
        match self.response_tamper.load(Ordering::SeqCst) {
            TAMPER_CREATE_RECORD => Ok(tampered_versioned_record(&stored)),
            TAMPER_CREATE_REVISION => Ok(VersionedAuthenticationRecord::new(
                stored.record().clone(),
                0,
            )),
            _ => Ok(stored),
        }
    }

    // Replaces one exact record revision.
    fn replace(
        &self,
        record: AuthenticationRecord,
        expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
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
        let key = record.api_key().key_id().as_str().to_string();
        let current = records
            .get(&key)
            .ok_or(AuthenticationStoreError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(AuthenticationStoreError::Conflict);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(AuthenticationStoreError::Corrupt)?;
        let stored = VersionedAuthenticationRecord::new(record, revision);
        records.insert(key, stored.clone());
        match self.response_tamper.load(Ordering::SeqCst) {
            TAMPER_REPLACE_RECORD => Ok(tampered_versioned_record(&stored)),
            TAMPER_REPLACE_REVISION => Ok(VersionedAuthenticationRecord::new(
                stored.record().clone(),
                expected_revision,
            )),
            _ => Ok(stored),
        }
    }

    // Revokes one key and creates its replacement under the same lock.
    fn rotate(
        &self,
        revoked: AuthenticationRecord,
        expected_revision: u64,
        replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?;
        let revoked_key = revoked.api_key().key_id().as_str().to_string();
        let replacement_key = replacement.api_key().key_id().as_str().to_string();
        let current = records
            .get(&revoked_key)
            .ok_or(AuthenticationStoreError::Conflict)?;
        if current.revision() != expected_revision
            || records.contains_key(&replacement_key)
            || records.iter().any(|(key, stored)| {
                key != &revoked_key
                    && stored.record().api_key().name() == replacement.api_key().name()
            })
        {
            return Err(AuthenticationStoreError::Conflict);
        }
        let revoked = VersionedAuthenticationRecord::new(revoked, expected_revision + 1);
        let replacement = VersionedAuthenticationRecord::new(replacement, 1);
        records.insert(revoked_key, revoked.clone());
        records.insert(replacement_key, replacement.clone());
        match self.response_tamper.load(Ordering::SeqCst) {
            TAMPER_ROTATION_REVOKED => Ok(AuthenticationRotation::new(
                tampered_versioned_record(&revoked),
                replacement,
            )),
            TAMPER_ROTATION_REPLACEMENT => Ok(AuthenticationRotation::new(
                revoked,
                tampered_versioned_record(&replacement),
            )),
            TAMPER_ROTATION_REVOKED_REVISION => Ok(AuthenticationRotation::new(
                VersionedAuthenticationRecord::new(revoked.record().clone(), expected_revision),
                replacement,
            )),
            TAMPER_ROTATION_REPLACEMENT_REVISION => Ok(AuthenticationRotation::new(
                revoked,
                VersionedAuthenticationRecord::new(replacement.record().clone(), 0),
            )),
            _ => Ok(AuthenticationRotation::new(revoked, replacement)),
        }
    }
}

// Changes verifier material while preserving the public key identity and revision.
fn tampered_versioned_record(
    stored: &VersionedAuthenticationRecord,
) -> VersionedAuthenticationRecord {
    let record = stored.record();
    VersionedAuthenticationRecord::new(
        AuthenticationRecord::new(record.api_key().clone(), *record.salt(), [0xff; 32]),
        stored.revision(),
    )
}

// Supplies deterministic unique bytes for key, secret, and salt fixtures.
struct TestMaterial {
    next_value: AtomicU8,
}

impl TestMaterial {
    // Creates deterministic material beginning with one exact byte.
    fn new(first_value: u8) -> Self {
        Self {
            next_value: AtomicU8::new(first_value),
        }
    }
}

impl ApiKeyMaterialProvider for TestMaterial {
    // Fills each requested buffer with the next deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        let value = self.next_value.fetch_add(1, Ordering::SeqCst);
        destination.fill(value);
        Ok(())
    }
}

// Fails every entropy request at its explicit boundary.
struct FailingMaterial;

impl ApiKeyMaterialProvider for FailingMaterial {
    // Returns the stable entropy failure without mutating the destination.
    fn fill(&self, _destination: &mut [u8]) -> Result<(), AuthenticationError> {
        Err(AuthenticationError::EntropyUnavailable)
    }
}

// Supplies mutable deterministic time to lifecycle and authentication tests.
struct TestClock {
    value: AtomicU64,
}

impl TestClock {
    // Creates one clock at an exact Unix timestamp.
    fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
        }
    }

    // Advances the exact time returned by later calls.
    fn set(&self, value: u64) {
        self.value.store(value, Ordering::SeqCst);
    }
}

impl AuthenticationClock for TestClock {
    // Returns the currently configured deterministic timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(self.value.load(Ordering::SeqCst)))
    }
}

// Creates one manager and retains its injected store and clock for assertions.
fn manager() -> (AuthenticationManager, Arc<TestStore>, Arc<TestClock>) {
    let store = Arc::new(TestStore::default());
    let clock = Arc::new(TestClock::new(1_000));
    let manager =
        AuthenticationManager::new(store.clone(), Arc::new(TestMaterial::new(1)), clock.clone());
    (manager, store, clock)
}

// Returns one unrestricted non-expiring policy fixture.
fn unrestricted_policy() -> ApiKeyPolicy {
    ApiKeyPolicy::new(
        ApiKeyModelScope::all(),
        None,
        ApiKeyLimits::default(),
        None,
        None,
    )
}

// Creates, authenticates, lists, and redacts one namespaced API key.
#[test]
fn manager_creates_and_authenticates_a_redacted_key() {
    let (manager, _, _) = manager();
    let mut created = manager
        .create(
            DisplayName::parse("Local client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create API key");
    assert!(matches!(
        created.event(),
        Some(AuthenticationEvent::ApiKeyCreated { .. })
    ));
    let token = created.value_mut().take_token().expect("issued token");
    assert!(created.value_mut().take_token().is_none());
    assert!(token.starts_with("li_"));
    assert_eq!(token.len(), 3 + 32 + 1 + 64);
    let debug = format!("{:?}", created.value());
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&token));

    let principal = manager
        .authenticate(&token, &LogicalModelName::parse("qwen3.8").expect("model"))
        .expect("authenticate");
    assert_eq!(principal.key_id(), created.value().api_key().key_id());
    assert_eq!(manager.api_keys().expect("API keys").len(), 1);
}

// Returns the same generic denial for malformed, unknown, and incorrect secrets.
#[test]
fn manager_hides_credential_failure_details() {
    let (manager, _, _) = manager();
    let mut created = manager
        .create(
            DisplayName::parse("Local client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create API key");
    let token = created.value_mut().take_token().expect("issued token");
    let mut wrong_secret = token.clone();
    wrong_secret.replace_range(token.len() - 1.., "f");
    if wrong_secret == token {
        wrong_secret.replace_range(token.len() - 1.., "e");
    }
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    for candidate in ["", "not-a-key", wrong_secret.as_str()] {
        assert_eq!(
            manager
                .authenticate(candidate, &model)
                .expect_err("credential must fail"),
            AuthenticationError::Unauthorized
        );
    }
    let unknown = format!("li_{}_{}", "a".repeat(32), "b".repeat(64));
    assert_eq!(
        manager
            .authenticate(&unknown, &model)
            .expect_err("unknown key must fail"),
        AuthenticationError::Unauthorized
    );
}

// Enforces model scope, expiration, and revocation without owning live counters.
#[test]
fn manager_enforces_durable_policy_only() {
    let (manager, _, clock) = manager();
    let limits = ApiKeyLimits::new(
        NonZeroU32::new(1),
        NonZeroU64::new(100),
        NonZeroU32::new(1),
        NonZeroU64::new(4_096),
    );
    let policy = ApiKeyPolicy::new(
        ApiKeyModelScope::selected(vec![LogicalModelName::parse("qwen3.8").expect("model")])
            .expect("scope"),
        Some(UnixMilliseconds::new(2_000)),
        limits,
        Some(TechnicalName::parse("home").expect("tenant")),
        Some(TechnicalName::parse("chat").expect("application")),
    );
    let mut created = manager
        .create(DisplayName::parse("Scoped client").expect("name"), policy)
        .expect("create API key");
    let token = created.value_mut().take_token().expect("issued token");
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    for _ in 0..4 {
        let principal = manager.authenticate(&token, &model).expect("authenticate");
        assert_eq!(principal.policy().limits(), limits);
    }
    assert_eq!(
        manager
            .authenticate(
                &token,
                &LogicalModelName::parse("other-model").expect("other model")
            )
            .expect_err("model scope must fail"),
        AuthenticationError::Unauthorized
    );
    clock.set(2_000);
    assert_eq!(
        manager
            .authenticate(&token, &model)
            .expect_err("expired key must fail"),
        AuthenticationError::Unauthorized
    );
}

// Proves discovery can verify one key once while retaining its exact model scope.
#[test]
fn manager_authenticates_identity_before_caller_owned_model_filtering() {
    let (manager, _, clock) = manager();
    let selected = LogicalModelName::parse("qwen3.8").expect("model");
    let policy = ApiKeyPolicy::new(
        ApiKeyModelScope::selected(vec![selected.clone()]).expect("scope"),
        Some(UnixMilliseconds::new(2_000)),
        ApiKeyLimits::default(),
        None,
        None,
    );
    let mut created = manager
        .create(
            DisplayName::parse("Discovery client").expect("name"),
            policy,
        )
        .expect("create API key");
    let token = created.value_mut().take_token().expect("issued token");

    let principal = manager
        .authenticate_identity(&token)
        .expect("authenticate identity");

    assert_eq!(
        principal.policy().model_scope().selected_models(),
        Some([selected].as_slice())
    );
    clock.set(2_000);
    assert_eq!(
        manager
            .authenticate_identity(&token)
            .expect_err("expired identity must fail"),
        AuthenticationError::Unauthorized
    );
}

// Revokes idempotently and emits the lifecycle event exactly once.
#[test]
fn manager_revokes_once_and_fails_authentication_closed() {
    let (manager, _, _) = manager();
    let mut created = manager
        .create(
            DisplayName::parse("Local client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create API key");
    let key_id = created.value().api_key().key_id().clone();
    let token = created.value_mut().take_token().expect("issued token");
    let revoked = manager.revoke(&key_id).expect("revoke");
    assert!(matches!(
        revoked.event(),
        Some(AuthenticationEvent::ApiKeyRevoked { .. })
    ));
    let replay = manager.revoke(&key_id).expect("replay revoke");
    assert!(replay.event().is_none());
    assert_eq!(
        manager
            .authenticate(&token, &LogicalModelName::parse("qwen3.8").expect("model"))
            .expect_err("revoked key must fail"),
        AuthenticationError::Unauthorized
    );
}

// Atomically rotates credentials and preserves the prior policy.
#[test]
fn manager_rotates_without_leaving_both_keys_active() {
    let (manager, _, clock) = manager();
    let mut created = manager
        .create(
            DisplayName::parse("Old client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create API key");
    let old_id = created.value().api_key().key_id().clone();
    let old_token = created.value_mut().take_token().expect("old token");
    clock.set(1_100);
    let mut rotated = manager
        .rotate(
            &old_id,
            DisplayName::parse("New client").expect("replacement name"),
        )
        .expect("rotate");
    let new_token = rotated.value_mut().take_token().expect("new token");
    assert!(matches!(
        rotated.event(),
        Some(AuthenticationEvent::ApiKeyRotated { .. })
    ));
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    assert_eq!(
        manager
            .authenticate(&old_token, &model)
            .expect_err("old key must fail"),
        AuthenticationError::Unauthorized
    );
    assert!(manager.authenticate(&new_token, &model).is_ok());
    assert_eq!(rotated.value().api_key().rotated_from(), Some(&old_id));
}

// Preserves the public name and policy while archiving the revoked rotation predecessor.
#[test]
fn manager_rotates_while_preserving_public_identity() {
    let (manager, _, clock) = manager();
    let policy = ApiKeyPolicy::new(
        ApiKeyModelScope::selected(vec![LogicalModelName::parse("qwen3.8").expect("model")])
            .expect("scope"),
        Some(UnixMilliseconds::new(9_000)),
        ApiKeyLimits::new(NonZeroU32::new(3), None, NonZeroU32::new(2), None),
        Some(TechnicalName::parse("tenant_a").expect("tenant")),
        None,
    );
    let mut created = manager
        .create(
            DisplayName::parse("Public application").expect("name"),
            policy.clone(),
        )
        .expect("create");
    let prior_id = created.value().api_key().key_id().clone();
    let prior_token = created.value_mut().take_token().expect("prior token");
    clock.set(2_000);
    let mut rotated = manager
        .rotate_preserving_name(&prior_id)
        .expect("rotate preserving identity");
    let replacement_token = rotated.value_mut().take_token().expect("replacement token");

    assert_eq!(
        rotated.value().api_key().name().as_str(),
        "Public application"
    );
    assert_eq!(rotated.value().api_key().policy(), &policy);
    assert_eq!(rotated.value().api_key().rotated_from(), Some(&prior_id));
    let archived = manager.api_key(&prior_id).expect("archived predecessor");
    assert!(archived.name().as_str().contains("-revoked-"));
    assert!(archived.revoked_at().is_some());
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    assert_eq!(
        manager
            .authenticate(&prior_token, &model)
            .expect_err("prior token"),
        AuthenticationError::Unauthorized
    );
    assert!(manager.authenticate(&replacement_token, &model).is_ok());
}

// Commits policy mutation once, replays exact state, and keeps verifier bytes usable.
#[test]
fn manager_updates_policy_with_exact_replay_and_conflict_safety() {
    let (manager, _, _) = manager();
    let mut created = manager
        .create(
            DisplayName::parse("Policy client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create");
    let key_id = created.value().api_key().key_id().clone();
    let token = created.value_mut().take_token().expect("token");
    let policy = ApiKeyPolicy::new(
        ApiKeyModelScope::selected(vec![LogicalModelName::parse("deepseek_r1").expect("model")])
            .expect("scope"),
        Some(UnixMilliseconds::new(8_000)),
        ApiKeyLimits::new(None, NonZeroU64::new(4_000), NonZeroU32::new(4), None),
        None,
        Some(TechnicalName::parse("chat").expect("application")),
    );
    let committed = manager
        .update_policy(&key_id, policy.clone())
        .expect("update policy");
    assert!(matches!(
        committed.event(),
        Some(AuthenticationEvent::ApiKeyPolicyUpdated { .. })
    ));
    let replay = manager
        .update_policy(&key_id, policy)
        .expect("replay policy");
    assert!(replay.event().is_none());
    assert!(manager
        .authenticate(
            &token,
            &LogicalModelName::parse("deepseek_r1").expect("model")
        )
        .is_ok());
    assert_eq!(
        manager
            .authenticate(&token, &LogicalModelName::parse("qwen3.8").expect("model"))
            .expect_err("old scope"),
        AuthenticationError::Unauthorized
    );
}

// Shares durable key state across manager reconstruction without copying secrets.
#[test]
fn manager_authenticates_after_reconstruction() {
    let (manager, store, clock) = manager();
    let mut created = manager
        .create(
            DisplayName::parse("Local client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create API key");
    let token = created.value_mut().take_token().expect("issued token");
    let reconstructed = AuthenticationManager::new(store, Arc::new(TestMaterial::new(20)), clock);
    assert!(reconstructed
        .authenticate(&token, &LogicalModelName::parse("qwen3.8").expect("model"))
        .is_ok());
}

// Lets one concurrent revocation emit an event while the other observes it.
#[test]
fn manager_serializes_concurrent_revocation() {
    let (manager, _, _) = manager();
    let manager = Arc::new(manager);
    let created = manager
        .create(
            DisplayName::parse("Local client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create API key");
    let key_id = created.value().api_key().key_id().clone();
    let mut workers = Vec::new();
    for _ in 0..2 {
        let manager = Arc::clone(&manager);
        let key_id = key_id.clone();
        workers.push(thread::spawn(move || manager.revoke(&key_id)));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("revoke worker").expect("revoke"))
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| result.event().is_some())
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.event().is_none())
            .count(),
        1
    );
}

// Rejects every mutation response that differs from the exact private record proposed.
#[test]
fn manager_rejects_tampered_mutation_results() {
    let (creation_manager, store, _) = manager();
    store
        .response_tamper
        .store(TAMPER_CREATE_RECORD, Ordering::SeqCst);
    assert_eq!(
        creation_manager
            .create(
                DisplayName::parse("Tampered creation").expect("name"),
                unrestricted_policy(),
            )
            .expect_err("tampered creation result"),
        AuthenticationError::Store(AuthenticationStoreError::Corrupt)
    );

    for tamper in [
        TAMPER_REPLACE_RECORD,
        TAMPER_ROTATION_REVOKED,
        TAMPER_ROTATION_REPLACEMENT,
    ] {
        let (manager, store, _) = manager();
        let created = manager
            .create(
                DisplayName::parse("Original key").expect("name"),
                unrestricted_policy(),
            )
            .expect("create key");
        let key_id = created.value().api_key().key_id().clone();
        store.response_tamper.store(tamper, Ordering::SeqCst);
        let error = if tamper == TAMPER_REPLACE_RECORD {
            manager.revoke(&key_id).expect_err("tampered revocation")
        } else {
            manager
                .rotate(
                    &key_id,
                    DisplayName::parse("Replacement key").expect("replacement name"),
                )
                .expect_err("tampered rotation")
        };
        assert_eq!(
            error,
            AuthenticationError::Store(AuthenticationStoreError::Corrupt)
        );
    }
}

// Rejects zero or non-advancing revisions for every authentication mutation shape.
#[test]
fn manager_rejects_zero_or_stale_mutation_revisions() {
    let (creation_manager, store, _) = manager();
    store
        .response_tamper
        .store(TAMPER_CREATE_REVISION, Ordering::SeqCst);
    assert_eq!(
        creation_manager
            .create(
                DisplayName::parse("Zero revision").expect("name"),
                unrestricted_policy(),
            )
            .expect_err("zero creation revision"),
        AuthenticationError::Store(AuthenticationStoreError::Corrupt)
    );

    for tamper in [
        TAMPER_REPLACE_REVISION,
        TAMPER_ROTATION_REVOKED_REVISION,
        TAMPER_ROTATION_REPLACEMENT_REVISION,
    ] {
        let (manager, store, _) = manager();
        let created = manager
            .create(
                DisplayName::parse("Original key").expect("name"),
                unrestricted_policy(),
            )
            .expect("create key");
        let key_id = created.value().api_key().key_id().clone();
        store.response_tamper.store(tamper, Ordering::SeqCst);
        let error = if tamper == TAMPER_REPLACE_REVISION {
            manager
                .revoke(&key_id)
                .expect_err("stale replacement revision")
        } else {
            manager
                .rotate(
                    &key_id,
                    DisplayName::parse("Replacement key").expect("replacement name"),
                )
                .expect_err("invalid rotation revision")
        };
        assert_eq!(
            error,
            AuthenticationError::Store(AuthenticationStoreError::Corrupt)
        );
    }
}

// Rejects zero revisions and ambiguous metadata returned by the persistence owner.
#[test]
fn manager_rejects_corrupt_read_and_collection_results() {
    let (manager, store, _) = manager();
    let created = manager
        .create(
            DisplayName::parse("Original key").expect("name"),
            unrestricted_policy(),
        )
        .expect("create key");
    let key_id = created.value().api_key().key_id().clone();
    store
        .response_tamper
        .store(TAMPER_READ_REVISION, Ordering::SeqCst);
    assert_eq!(
        manager.api_key(&key_id).expect_err("zero revision"),
        AuthenticationError::Store(AuthenticationStoreError::Corrupt)
    );

    store.response_tamper.store(TAMPER_NONE, Ordering::SeqCst);
    let existing = store
        .records
        .lock()
        .expect("records")
        .get(key_id.as_str())
        .expect("record")
        .clone();
    store
        .records
        .lock()
        .expect("records")
        .insert("foreign-index".to_string(), existing);
    assert_eq!(
        manager.api_keys().expect_err("duplicate identity"),
        AuthenticationError::Store(AuthenticationStoreError::Corrupt)
    );
}

// Allows exactly one concurrent rotation to own the replacement and revoke the prior key.
#[test]
fn manager_serializes_concurrent_rotation_atomically() {
    let (manager, store, _) = manager();
    let manager = Arc::new(manager);
    let created = manager
        .create(
            DisplayName::parse("Original key").expect("name"),
            unrestricted_policy(),
        )
        .expect("create key");
    let key_id = created.value().api_key().key_id().clone();
    let workers = ["Replacement one", "Replacement two"]
        .into_iter()
        .map(|name| {
            let manager = manager.clone();
            let key_id = key_id.clone();
            thread::spawn(move || {
                manager.rotate(&key_id, DisplayName::parse(name).expect("replacement name"))
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("rotation worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);

    let records = store.records.lock().expect("records");
    assert_eq!(records.len(), 2);
    assert!(records
        .get(key_id.as_str())
        .expect("prior key")
        .record()
        .api_key()
        .revoked_at()
        .is_some());
    assert_eq!(
        records
            .values()
            .filter(|stored| stored.record().api_key().revoked_at().is_none())
            .count(),
        1
    );
}

// Reconciles identical policy races as replay and rejects divergent concurrent state.
#[test]
fn manager_reconciles_concurrent_policy_updates_deterministically() {
    let (initial_manager, store, _) = manager();
    let concurrent_manager = Arc::new(initial_manager);
    let created = concurrent_manager
        .create(
            DisplayName::parse("Concurrent policy").expect("name"),
            unrestricted_policy(),
        )
        .expect("create");
    let key_id = created.value().api_key().key_id().clone();
    let shared_policy = ApiKeyPolicy::new(
        ApiKeyModelScope::all(),
        None,
        ApiKeyLimits::new(None, None, NonZeroU32::new(2), None),
        None,
        None,
    );
    store.set_replace_barrier(Arc::new(Barrier::new(2)));
    let workers = (0..2)
        .map(|_| {
            let manager = concurrent_manager.clone();
            let key_id = key_id.clone();
            let policy = shared_policy.clone();
            thread::spawn(move || manager.update_policy(&key_id, policy))
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker").expect("identical update"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|change| change.event().is_some())
            .count(),
        1
    );

    let (manager, store, _) = manager();
    let manager = Arc::new(manager);
    let created = manager
        .create(
            DisplayName::parse("Divergent policy").expect("name"),
            unrestricted_policy(),
        )
        .expect("create");
    let key_id = created.value().api_key().key_id().clone();
    store.set_replace_barrier(Arc::new(Barrier::new(2)));
    let workers = [2, 4]
        .into_iter()
        .map(|limit| {
            let manager = manager.clone();
            let key_id = key_id.clone();
            thread::spawn(move || {
                manager.update_policy(
                    &key_id,
                    ApiKeyPolicy::new(
                        ApiKeyModelScope::all(),
                        None,
                        ApiKeyLimits::new(None, None, NonZeroU32::new(limit), None),
                        None,
                        None,
                    ),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                result.as_ref().is_err_and(|error| {
                    error == &AuthenticationError::Store(AuthenticationStoreError::Conflict)
                })
            })
            .count(),
        1
    );
}

// Rejects invalid policy and entropy before creating durable state.
#[test]
fn manager_rejects_invalid_policy_and_entropy() {
    assert!(ApiKeyModelScope::selected(Vec::new()).is_err());
    let (manager, _, _) = manager();
    manager
        .create(
            DisplayName::parse("Unique name").expect("name"),
            unrestricted_policy(),
        )
        .expect("first API key");
    assert_eq!(
        manager
            .create(
                DisplayName::parse("Unique name").expect("duplicate name"),
                unrestricted_policy(),
            )
            .expect_err("duplicate name must fail"),
        AuthenticationError::Store(AuthenticationStoreError::Conflict)
    );
    let expired = ApiKeyPolicy::new(
        ApiKeyModelScope::all(),
        Some(UnixMilliseconds::new(1_000)),
        ApiKeyLimits::default(),
        None,
        None,
    );
    assert!(manager
        .create(DisplayName::parse("Expired").expect("name"), expired)
        .is_err());

    let failing = AuthenticationManager::new(
        Arc::new(TestStore::default()),
        Arc::new(FailingMaterial),
        Arc::new(TestClock::new(1_000)),
    );
    assert_eq!(
        failing
            .create(
                DisplayName::parse("No entropy").expect("name"),
                unrestricted_policy(),
            )
            .expect_err("entropy must fail"),
        AuthenticationError::EntropyUnavailable
    );
}
