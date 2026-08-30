// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, EngineDistribution, EntityTimestamps,
    EvidenceLabel, GgufFileIdentity, LogicalModelName, ModelArtifact, ModelArtifactFormat, NodeId,
    RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation, RuntimeInstallationId,
    RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId,
    UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::DatabaseRuntimeInstallationStore;
use li_runtime_manager::RuntimeInstallationStore;

// Returns one complete available runtime installation fixture.
fn installation() -> RuntimeInstallation {
    installation_in_state(RuntimeInstallationState::Available)
}

// Returns one complete runtime installation fixture in an explicit lifecycle state.
fn installation_in_state(state: RuntimeInstallationState) -> RuntimeInstallation {
    RuntimeInstallation::new(
        RuntimeInstallationId::parse(&"1".repeat(32)).expect("installation"),
        NodeId::parse(&"2".repeat(32)).expect("node"),
        LogicalModelName::parse("qwen3.8").expect("model"),
        RuntimeIdentity::new(
            RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
            RuntimeVersion::parse("1.0.0").expect("version"),
            TargetId::parse("dgx-spark").expect("target"),
            RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "3".repeat(64)))
                .expect("source"),
            EngineDistribution::oci(
                RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "9".repeat(64)))
                    .expect("Engine source"),
                Sha256Digest::parse(&"a".repeat(64)).expect("Engine identity"),
                None,
                None,
            ),
            Sha256Digest::parse(&"4".repeat(64)).expect("runtime digest"),
            Sha256Digest::parse(&"5".repeat(64)).expect("manifest"),
            Sha256Digest::parse(&"6".repeat(64)).expect("execution"),
        )
        .expect("runtime"),
        vec![
            ModelArtifact::new(
                ArtifactName::parse("model").expect("artifact"),
                ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("URI"),
                ArtifactRevision::parse(&"7".repeat(40)).expect("revision"),
                ModelArtifactFormat::HuggingFaceSnapshot,
            ),
            ModelArtifact::new(
                ArtifactName::parse("weights").expect("artifact"),
                ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("URI"),
                ArtifactRevision::parse(&"7".repeat(40)).expect("revision"),
                ModelArtifactFormat::GgufFile(
                    GgufFileIdentity::new(
                        "model.gguf",
                        Sha256Digest::parse(&"8".repeat(64)).expect("digest"),
                        Some(4096),
                    )
                    .expect("GGUF"),
                ),
            ),
        ],
        EvidenceLabel::Unqualified,
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("runtime installation")
}

// Persists one staging record exactly across a complete DatabaseManager restart.
#[test]
fn runtime_store_restarts_with_staging_state_intact() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let expected = installation_in_state(RuntimeInstallationState::Staging);
    {
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(path.clone())).expect("database"),
        );
        DatabaseRuntimeInstallationStore::new(database)
            .create(expected.clone())
            .expect("create staging");
    }
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(path)).expect("restarted database"),
    );
    let observed = DatabaseRuntimeInstallationStore::new(database)
        .read(expected.installation_id())
        .expect("read staging")
        .expect("staging");
    assert_eq!(observed.installation(), &expected);
    assert_eq!(
        observed.installation().state(),
        RuntimeInstallationState::Staging
    );
}

// Commits one activation by exact revision and preserves Available after restart.
#[test]
fn runtime_store_commits_activation_once_across_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let staging = installation_in_state(RuntimeInstallationState::Staging);
    let available = installation_in_state(RuntimeInstallationState::Available);
    {
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(path.clone())).expect("database"),
        );
        let store = DatabaseRuntimeInstallationStore::new(database);
        let created = store.create(staging).expect("create staging");
        let activated = store
            .replace(available.clone(), created.revision())
            .expect("activate");
        assert_eq!(activated.revision(), 2);
        assert_eq!(
            store
                .replace(available.clone(), created.revision())
                .expect_err("stale activation"),
            li_runtime_manager::RuntimeError::StoreConflict
        );
    }
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(path)).expect("restarted database"),
    );
    let observed = DatabaseRuntimeInstallationStore::new(database)
        .read(available.installation_id())
        .expect("read available")
        .expect("available");
    assert_eq!(observed.installation(), &available);
    assert_eq!(observed.revision(), 2);
}

// Persists, reconstructs, replaces, and deletes one complete runtime installation.
#[test]
fn runtime_store_round_trips_complete_installation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let store = DatabaseRuntimeInstallationStore::new(database);
    let created = store.create(installation()).expect("create");
    assert_eq!(created.revision(), 1);
    let observed = store
        .read(created.installation().installation_id())
        .expect("read")
        .expect("installation");
    assert_eq!(observed.installation(), created.installation());
    let removed = RuntimeInstallation::new(
        observed.installation().installation_id().clone(),
        observed.installation().node_id().clone(),
        observed.installation().logical_model().clone(),
        observed.installation().runtime().clone(),
        observed.installation().artifacts().to_vec(),
        observed.installation().evidence_label(),
        RuntimeInstallationState::Removed,
        None,
        EntityTimestamps::new(
            observed.installation().timestamps().created_at(),
            UnixMilliseconds::new(3_000),
        )
        .expect("timestamps"),
    )
    .expect("removed");
    let removed = store
        .replace(removed, observed.revision())
        .expect("replace");
    store
        .delete(removed.installation().installation_id(), removed.revision())
        .expect("delete");
    assert!(store
        .read(removed.installation().installation_id())
        .expect("read deleted")
        .is_none());
}
