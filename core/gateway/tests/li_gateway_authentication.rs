// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use li_authentication_manager::{
    ApiKeyLimits, ApiKeyMaterialProvider, ApiKeyModelScope, ApiKeyPolicy, AuthenticationClock,
    AuthenticationError, AuthenticationManager, AuthenticationRecord, AuthenticationRotation,
    AuthenticationStore, AuthenticationStoreError, VersionedAuthenticationRecord,
};
use li_core_interface::{ApiKeyId, DisplayName, LogicalModelName, UnixMilliseconds};
use li_gateway_manager::{
    AuthenticationManagerGatewayProvider, GatewayAuthenticationProvider, GatewayError,
};

// Stores one exact API key while allowing deterministic provider failure injection.
#[derive(Default)]
struct AuthenticationStoreMock {
    record: Mutex<Option<VersionedAuthenticationRecord>>,
    fail: AtomicBool,
}

impl AuthenticationStore for AuthenticationStoreMock {
    // Reads one exact record or returns the injected private storage failure.
    fn read(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuthenticationStoreError::Unavailable);
        }
        Ok(self
            .record
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .as_ref()
            .filter(|stored| stored.record().api_key().key_id() == key_id)
            .cloned())
    }

    // Lists the one exact record when present.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Ok(self
            .record
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?
            .iter()
            .cloned()
            .collect())
    }

    // Creates the one fixture record exactly once.
    fn create(
        &self,
        record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        let mut stored = self
            .record
            .lock()
            .map_err(|_| AuthenticationStoreError::Unavailable)?;
        if stored.is_some() {
            return Err(AuthenticationStoreError::Conflict);
        }
        let created = VersionedAuthenticationRecord::new(record, 1);
        *stored = Some(created.clone());
        Ok(created)
    }

    // Keeps replacement outside this adapter-focused fixture.
    fn replace(
        &self,
        _record: AuthenticationRecord,
        _expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Keeps rotation outside this adapter-focused fixture.
    fn rotate(
        &self,
        _revoked: AuthenticationRecord,
        _expected_revision: u64,
        _replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Supplies deterministic distinct identifier, secret, and salt bytes.
struct MaterialMock(AtomicU8);

impl ApiKeyMaterialProvider for MaterialMock {
    // Fills one complete material field with its next deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        destination.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Supplies one fixed non-expired authentication time.
struct ClockMock;

impl AuthenticationClock for ClockMock {
    // Returns one deterministic timestamp for every adapter call.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(1_000))
    }
}

// Builds one real AuthenticationManager and its Gateway projection.
fn provider() -> (
    AuthenticationManagerGatewayProvider,
    Arc<AuthenticationStoreMock>,
    String,
) {
    let store = Arc::new(AuthenticationStoreMock::default());
    let manager = Arc::new(AuthenticationManager::new(
        store.clone(),
        Arc::new(MaterialMock(AtomicU8::new(1))),
        Arc::new(ClockMock),
    ));
    let mut issued = manager
        .create(
            DisplayName::parse("Gateway client").expect("name"),
            ApiKeyPolicy::new(
                ApiKeyModelScope::all(),
                None,
                ApiKeyLimits::default(),
                None,
                None,
            ),
        )
        .expect("create key");
    let token = issued.value_mut().take_token().expect("token");
    (
        AuthenticationManagerGatewayProvider::new(manager),
        store,
        token,
    )
}

// Projects durable metadata repeatedly without creating or consuming live reservations.
#[test]
fn adapter_returns_only_stable_key_metadata_and_limits() {
    let (provider, store, token) = provider();
    let model = LogicalModelName::parse("qwen3_8").expect("model");
    let first = provider
        .authenticate(&token, &model)
        .expect("first authentication");
    let second = provider
        .authenticate(&token, &model)
        .expect("second authentication");
    assert_eq!(first, second);
    assert_eq!(first.limits(), ApiKeyLimits::default());
    assert_eq!(
        store
            .record
            .lock()
            .expect("record")
            .as_ref()
            .expect("key")
            .revision(),
        1
    );
}

// Redacts unknown credentials and private authority failures at the Gateway boundary.
#[test]
fn adapter_redacts_authentication_and_storage_failures() {
    let (provider, store, token) = provider();
    let model = LogicalModelName::parse("qwen3_8").expect("model");
    assert_eq!(
        provider
            .authenticate("not-a-key", &model)
            .expect_err("invalid token"),
        GatewayError::AuthenticationDenied
    );
    store.fail.store(true, Ordering::SeqCst);
    let error = provider
        .authenticate(&token, &model)
        .expect_err("storage failure");
    let presentation = error.to_string();
    assert!(!presentation.contains(&token));
    assert!(!presentation.contains(token.split('_').nth(1).expect("key identity")));
    assert_eq!(
        presentation,
        "gateway authentication failed: API-key authority is unavailable"
    );
}
