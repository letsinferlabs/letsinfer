// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_authentication_manager::{
    ApiKeyLimits, ApiKeyMaterialProvider, ApiKeyModelScope, ApiKeyPolicy, AuthenticationClock,
    AuthenticationError, AuthenticationManager, AuthenticationRecord, AuthenticationRotation,
    AuthenticationStore, AuthenticationStoreError, VersionedAuthenticationRecord,
};
use li_core_interface::{ApiKeyId, DisplayName, LogicalModelName, UnixMilliseconds};
use li_gateway_manager::{
    AuthenticationManagerGatewayModelListProvider, GatewayHttpError, GatewayHttpModelInventory,
    GatewayHttpModelInventoryEntry, GatewayHttpModelInventoryProvider,
    GatewayHttpModelListProvider,
};

// Stores the minimum deterministic API-key state required by the production adapter.
#[derive(Default)]
struct AuthenticationStoreMock {
    records: Mutex<BTreeMap<String, VersionedAuthenticationRecord>>,
}

impl AuthenticationStore for AuthenticationStoreMock {
    // Returns one exact record from the in-memory fixture.
    fn read(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Ok(self.records.lock().unwrap().get(key_id.as_str()).cloned())
    }

    // Returns all fixture records in stable key order.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Ok(self.records.lock().unwrap().values().cloned().collect())
    }

    // Creates one revision-one fixture record.
    fn create(
        &self,
        record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        let mut records = self.records.lock().unwrap();
        let key = record.api_key().key_id().as_str().to_string();
        if records.contains_key(&key) {
            return Err(AuthenticationStoreError::Conflict);
        }
        let versioned = VersionedAuthenticationRecord::new(record, 1);
        records.insert(key, versioned.clone());
        Ok(versioned)
    }

    // Rejects replacement because discovery tests never mutate key lifecycle state.
    fn replace(
        &self,
        _record: AuthenticationRecord,
        _expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects rotation because discovery tests never mutate key lifecycle state.
    fn rotate(
        &self,
        _revoked: AuthenticationRecord,
        _expected_revision: u64,
        _replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Supplies distinct deterministic bytes for API-key identity, secret, and salt.
struct AuthenticationMaterialMock {
    next: AtomicU8,
}

impl ApiKeyMaterialProvider for AuthenticationMaterialMock {
    // Fills one complete requested value with the next deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        destination.fill(self.next.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Supplies mutable deterministic time to API-key creation and verification.
struct AuthenticationClockMock {
    now: AtomicU64,
}

impl AuthenticationClock for AuthenticationClockMock {
    // Returns the currently configured fixture time.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(self.now.load(Ordering::SeqCst)))
    }
}

// Returns one deterministic current model inventory and records read ordering.
struct InventoryMock {
    calls: AtomicUsize,
    result: Result<GatewayHttpModelInventory, GatewayHttpError>,
}

impl GatewayHttpModelInventoryProvider for InventoryMock {
    // Records one read and returns the configured inventory result.
    fn inventory(&self) -> Result<GatewayHttpModelInventory, GatewayHttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

// Creates one real AuthenticationManager and returns its single issued bearer.
fn authentication(scope: ApiKeyModelScope) -> (Arc<AuthenticationManager>, String) {
    let manager = Arc::new(AuthenticationManager::new(
        Arc::new(AuthenticationStoreMock::default()),
        Arc::new(AuthenticationMaterialMock {
            next: AtomicU8::new(1),
        }),
        Arc::new(AuthenticationClockMock {
            now: AtomicU64::new(1_000),
        }),
    ));
    let policy = ApiKeyPolicy::new(scope, None, ApiKeyLimits::default(), None, None);
    let mut issued = manager
        .create(DisplayName::parse("Discovery client").unwrap(), policy)
        .unwrap();
    let token = issued.value_mut().take_token().unwrap();
    (manager, token)
}

// Creates the canonical two-model inventory shared by discovery tests.
fn inventory() -> GatewayHttpModelInventory {
    GatewayHttpModelInventory::new(
        88,
        vec![
            GatewayHttpModelInventoryEntry::new(
                LogicalModelName::parse("model-a").unwrap(),
                vec![LogicalModelName::parse("alias-a").unwrap()],
            )
            .unwrap(),
            GatewayHttpModelInventoryEntry::new(
                LogicalModelName::parse("model-b").unwrap(),
                Vec::new(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

// Runs the production filtering adapter for one exact durable model scope.
fn listed(scope: ApiKeyModelScope) -> Vec<String> {
    let (authentication, token) = authentication(scope);
    let provider = AuthenticationManagerGatewayModelListProvider::new(
        authentication,
        Arc::new(InventoryMock {
            calls: AtomicUsize::new(0),
            result: Ok(inventory()),
        }),
    );
    provider
        .models(&token)
        .unwrap()
        .models()
        .iter()
        .map(|model| model.as_str().to_string())
        .collect()
}

// Proves unrestricted, canonical, alias-only, and unrelated scopes filter exact names.
#[test]
fn authenticated_model_inventory_applies_durable_scope_once() {
    assert_eq!(
        listed(ApiKeyModelScope::all()),
        ["alias-a", "model-a", "model-b"]
    );
    assert_eq!(
        listed(
            ApiKeyModelScope::selected(vec![LogicalModelName::parse("model-a").unwrap()]).unwrap()
        ),
        ["alias-a", "model-a"]
    );
    assert_eq!(
        listed(
            ApiKeyModelScope::selected(vec![LogicalModelName::parse("alias-a").unwrap()]).unwrap()
        ),
        ["alias-a"]
    );
    assert!(listed(
        ApiKeyModelScope::selected(vec![LogicalModelName::parse("other-model").unwrap()]).unwrap()
    )
    .is_empty());
}

// Proves authentication denies before inventory and provider errors remain redacted.
#[test]
fn model_inventory_failure_boundaries_are_ordered_and_stable() {
    let (authentication, token) = authentication(ApiKeyModelScope::all());
    let inventory = Arc::new(InventoryMock {
        calls: AtomicUsize::new(0),
        result: Err(GatewayHttpError::new(
            503,
            "inventory_unavailable",
            "model inventory is unavailable",
        )),
    });
    let provider =
        AuthenticationManagerGatewayModelListProvider::new(authentication, inventory.clone());

    let denied = provider.models("not-a-key").unwrap_err();
    assert_eq!(denied.status_code(), 401);
    assert_eq!(inventory.calls.load(Ordering::SeqCst), 0);

    let unavailable = provider.models(&token).unwrap_err();
    assert_eq!(unavailable.status_code(), 503);
    assert_eq!(unavailable.code(), "inventory_unavailable");
    assert_eq!(inventory.calls.load(Ordering::SeqCst), 1);
}

// Proves aliases cannot collide with another canonical or alias identity.
#[test]
fn model_inventory_rejects_ambiguous_global_identity() {
    let first = GatewayHttpModelInventoryEntry::new(
        LogicalModelName::parse("model-a").unwrap(),
        vec![LogicalModelName::parse("shared").unwrap()],
    )
    .unwrap();
    let second = GatewayHttpModelInventoryEntry::new(
        LogicalModelName::parse("model-b").unwrap(),
        vec![LogicalModelName::parse("shared").unwrap()],
    )
    .unwrap();
    assert!(GatewayHttpModelInventory::new(1, vec![first, second]).is_err());
    assert!(GatewayHttpModelInventoryEntry::new(
        LogicalModelName::parse("model-a").unwrap(),
        vec![LogicalModelName::parse("model-a").unwrap()],
    )
    .is_err());
}
