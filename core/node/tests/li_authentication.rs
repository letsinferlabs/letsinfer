// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use li_authentication_manager::{
    ApiKeyLimits, ApiKeyMaterialProvider, ApiKeyModelScope, ApiKeyPolicy, AuthenticationClock,
    AuthenticationError, AuthenticationManager, SystemApiKeyMaterialProvider,
};
use li_core_interface::{DisplayName, LogicalModelName, TechnicalName, UnixMilliseconds};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    DatabaseAuthenticationStore, NodeApiKeyPolicyUpdate, NodeAuthenticationApiPort,
    NodeAuthenticationCoordinator,
};

// Supplies distinct deterministic bytes for each exact entropy request.
struct DeterministicMaterial(AtomicU8);

impl ApiKeyMaterialProvider for DeterministicMaterial {
    // Fills one complete destination with the next nonzero byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), AuthenticationError> {
        let value = self.0.fetch_add(1, Ordering::SeqCst);
        destination.fill(value);
        Ok(())
    }
}

// Supplies deterministic mutable authentication time across lifecycle transitions.
struct DeterministicClock(AtomicU64);

impl AuthenticationClock for DeterministicClock {
    // Returns the exact configured timestamp.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Creates one production database-backed coordinator with injected entropy and time.
fn coordinator(
    database: Arc<DatabaseManager>,
    material: Arc<dyn ApiKeyMaterialProvider>,
    clock: Arc<dyn AuthenticationClock>,
) -> NodeAuthenticationCoordinator {
    NodeAuthenticationCoordinator::new(Arc::new(AuthenticationManager::new(
        Arc::new(DatabaseAuthenticationStore::new(database)),
        material,
        clock,
    )))
}

// Returns one unrestricted non-expiring policy.
fn unrestricted_policy() -> ApiKeyPolicy {
    ApiKeyPolicy::new(
        ApiKeyModelScope::all(),
        None,
        ApiKeyLimits::default(),
        None,
        None,
    )
}

// Reads every regular database-directory artifact for plaintext exclusion assertions.
fn database_bytes(directory: &std::path::Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in fs::read_dir(directory).expect("database directory") {
        let entry = entry.expect("directory entry");
        if entry.file_type().expect("file type").is_file() {
            bytes.extend(fs::read(entry.path()).expect("database artifact"));
        }
    }
    bytes
}

// Proves the complete database-backed CLI lifecycle survives restart without secret persistence.
#[test]
fn coordinator_completes_policy_rotation_revocation_and_restart_without_secret_persistence() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database_path = directory.path().join("core.sqlite3");
    let material = Arc::new(DeterministicMaterial(AtomicU8::new(1)));
    let clock = Arc::new(DeterministicClock(AtomicU64::new(1_000)));
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(&database_path)).expect("database"),
    );
    let first = coordinator(database, material.clone(), clock.clone());
    let created = first
        .create(
            DisplayName::parse("Application client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create");
    let key_id = created.api_key().key_id().clone();
    let token = created.take_token().expect("token");
    assert!(created.take_token().is_none());
    assert!(!format!("{created:?}").contains(&token));

    drop(first);
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(&database_path)).expect("restart"),
    );
    let restarted = coordinator(database, material, clock.clone());
    assert_eq!(
        restarted.key(key_id.as_str()).expect("key").key_id(),
        &key_id
    );
    let updated = restarted
        .update(
            "Application client",
            NodeApiKeyPolicyUpdate::new(
                Some(vec![LogicalModelName::parse("qwen3.8").expect("model")]),
                Some(UnixMilliseconds::new(9_000)),
                Some(NonZeroU32::new(60).expect("requests")),
                Some(NonZeroU64::new(60_000).expect("tokens")),
                Some(NonZeroU32::new(4).expect("concurrency")),
                Some(NonZeroU64::new(32_768).expect("context")),
                Some(TechnicalName::parse("tenant_a").expect("tenant")),
                Some(TechnicalName::parse("chat").expect("application")),
            ),
        )
        .expect("update");
    assert_eq!(
        updated.policy().limits().concurrency().map(NonZeroU32::get),
        Some(4)
    );
    let replay = restarted
        .update(
            key_id.as_str(),
            NodeApiKeyPolicyUpdate::new(
                Some(vec![LogicalModelName::parse("qwen3.8").expect("model")]),
                Some(UnixMilliseconds::new(9_000)),
                Some(NonZeroU32::new(60).expect("requests")),
                Some(NonZeroU64::new(60_000).expect("tokens")),
                Some(NonZeroU32::new(4).expect("concurrency")),
                Some(NonZeroU64::new(32_768).expect("context")),
                Some(TechnicalName::parse("tenant_a").expect("tenant")),
                Some(TechnicalName::parse("chat").expect("application")),
            ),
        )
        .expect("update replay");
    assert_eq!(replay, updated);

    clock.0.store(2_000, Ordering::SeqCst);
    let rotated = restarted.rotate(key_id.as_str()).expect("rotate");
    let replacement_token = rotated.take_token().expect("replacement token");
    assert_eq!(rotated.api_key().name().as_str(), "Application client");
    let replacement_id = rotated.api_key().key_id().clone();
    let revoked = restarted
        .revoke(replacement_id.as_str())
        .expect("revoke replacement");
    let revoke_replay = restarted
        .revoke(replacement_id.as_str())
        .expect("revoke replay");
    assert_eq!(revoked, revoke_replay);

    let bytes = database_bytes(directory.path());
    for plaintext in [
        token.as_str(),
        token.rsplit('_').next().expect("secret"),
        replacement_token.as_str(),
        replacement_token
            .rsplit('_')
            .next()
            .expect("replacement secret"),
    ] {
        assert!(!bytes
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_bytes()));
    }
    for text in [
        format!("{created:?}"),
        format!("{rotated:?}"),
        AuthenticationError::Unauthorized.to_string(),
        AuthenticationError::EntropyUnavailable.to_string(),
    ] {
        assert!(!text.contains(&token));
        assert!(!text.contains(&replacement_token));
    }
}

// Proves production entropy composition retains the same one-time response boundary.
#[test]
fn coordinator_accepts_the_system_material_provider_without_exposing_its_secret_in_debug() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let coordinator = coordinator(
        database,
        Arc::new(SystemApiKeyMaterialProvider),
        Arc::new(DeterministicClock(AtomicU64::new(1_000))),
    );
    let issued = coordinator
        .create(
            DisplayName::parse("System client").expect("name"),
            unrestricted_policy(),
        )
        .expect("create");
    assert!(format!("{issued:?}").contains("<redacted>"));
}
