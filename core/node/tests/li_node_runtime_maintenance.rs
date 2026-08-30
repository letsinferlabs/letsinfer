// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, EngineDistribution, EntityTimestamps,
    EvidenceLabel, LogicalModelName, ModelArtifact, ModelArtifactFormat, NodeId,
    RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation, RuntimeInstallationId,
    RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId,
    UnixMilliseconds,
};
use li_node_manager::{
    NodeRuntimeMaintenanceCoordinator, NodeRuntimeMaintenanceError, NodeRuntimeModelRetention,
    NodeRuntimeRemovalDisposition, NodeRuntimeRemovalProvider, MAXIMUM_RUNTIME_INSTALLATIONS,
};
use li_runtime_manager::{RuntimeError, RuntimeInstallationStore, VersionedRuntimeInstallation};

// Stores deterministic runtime records and injected read failures.
struct RuntimeStoreMock {
    records: Vec<VersionedRuntimeInstallation>,
    all_error: Option<RuntimeError>,
    read_error: Option<RuntimeError>,
}

impl RuntimeInstallationStore for RuntimeStoreMock {
    // Returns one matching fixture record unless the read failure is injected.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        if let Some(error) = &self.read_error {
            return Err(error.clone());
        }
        Ok(self
            .records
            .iter()
            .find(|record| record.installation().installation_id() == installation_id)
            .cloned())
    }

    // Returns every fixture record unless the inventory failure is injected.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        self.all_error
            .clone()
            .map_or_else(|| Ok(self.records.clone()), Err)
    }

    // Rejects an unexpected create mutation.
    fn create(
        &self,
        _installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }

    // Rejects an unexpected replace mutation.
    fn replace(
        &self,
        _installation: RuntimeInstallation,
        _expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }

    // Rejects an unexpected delete mutation.
    fn delete(
        &self,
        _installation_id: &RuntimeInstallationId,
        _expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }
}

// Records exact RuntimeManager removal requests and returns one injected result.
struct RuntimeRemovalMock {
    result: Result<(), RuntimeError>,
    calls: Mutex<Vec<RuntimeInstallationId>>,
    finalize_calls: Mutex<Vec<NodeRuntimeModelRetention>>,
}

impl NodeRuntimeRemovalProvider for RuntimeRemovalMock {
    // Records one exact installation identity before returning the configured result.
    fn remove(&self, installation_id: &RuntimeInstallationId) -> Result<(), RuntimeError> {
        self.calls
            .lock()
            .expect("runtime removal calls")
            .push(installation_id.clone());
        self.result.clone()
    }

    // Records one exact finalization policy before returning the configured result.
    fn finalize_cleanup(&self, retention: NodeRuntimeModelRetention) -> Result<(), RuntimeError> {
        self.finalize_calls
            .lock()
            .expect("runtime finalization calls")
            .push(retention);
        self.result.clone()
    }
}

// Returns one complete runtime installation fixture in an explicit lifecycle state.
fn installation(identity: usize, state: RuntimeInstallationState) -> RuntimeInstallation {
    RuntimeInstallation::new(
        RuntimeInstallationId::parse(&format!("{identity:032x}")).expect("installation"),
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
        vec![ModelArtifact::new(
            ArtifactName::parse("model").expect("artifact"),
            ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("URI"),
            ArtifactRevision::parse(&"7".repeat(40)).expect("revision"),
            ModelArtifactFormat::HuggingFaceSnapshot,
        )],
        EvidenceLabel::Unqualified,
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("runtime installation")
}

// Returns one coordinator and the removal mock used to inspect exact mutation calls.
fn coordinator(
    records: Vec<VersionedRuntimeInstallation>,
    all_error: Option<RuntimeError>,
    read_error: Option<RuntimeError>,
    removal_result: Result<(), RuntimeError>,
) -> (NodeRuntimeMaintenanceCoordinator, Arc<RuntimeRemovalMock>) {
    let runtime = Arc::new(RuntimeRemovalMock {
        result: removal_result,
        calls: Mutex::new(Vec::new()),
        finalize_calls: Mutex::new(Vec::new()),
    });
    let store = Arc::new(RuntimeStoreMock {
        records,
        all_error,
        read_error,
    });
    (
        NodeRuntimeMaintenanceCoordinator::new(runtime.clone(), store),
        runtime,
    )
}

// Returns one versioned installation fixture from a numeric canonical identity.
fn record(identity: usize, state: RuntimeInstallationState) -> VersionedRuntimeInstallation {
    VersionedRuntimeInstallation::new(installation(identity, state), 1)
}

// Sorts every identity, accepts the exact bound, and rejects duplicates or an oversized store.
#[test]
fn runtime_identity_inventory_is_complete_sorted_and_bounded() {
    let (ordinary, _) = coordinator(
        vec![
            record(2, RuntimeInstallationState::Available),
            record(1, RuntimeInstallationState::Removed),
        ],
        None,
        None,
        Ok(()),
    );
    assert_eq!(
        ordinary
            .installation_ids()
            .expect("runtime identities")
            .iter()
            .map(RuntimeInstallationId::as_str)
            .collect::<Vec<_>>(),
        vec![
            "00000000000000000000000000000001",
            "00000000000000000000000000000002"
        ]
    );

    let exact_bound = (0..MAXIMUM_RUNTIME_INSTALLATIONS)
        .map(|index| record(index + 1, RuntimeInstallationState::Available))
        .collect();
    let (exact_bound, _) = coordinator(exact_bound, None, None, Ok(()));
    assert_eq!(
        exact_bound.installation_ids().expect("exact bound").len(),
        MAXIMUM_RUNTIME_INSTALLATIONS
    );

    let duplicate = record(1, RuntimeInstallationState::Available);
    let (duplicates, _) = coordinator(vec![duplicate.clone(), duplicate], None, None, Ok(()));
    assert_eq!(
        duplicates.installation_ids(),
        Err(NodeRuntimeMaintenanceError::InvalidProjection)
    );

    let oversized = (0..=MAXIMUM_RUNTIME_INSTALLATIONS)
        .map(|index| record(index + 1, RuntimeInstallationState::Available))
        .collect();
    let (oversized, _) = coordinator(oversized, None, None, Ok(()));
    assert_eq!(
        oversized.installation_ids(),
        Err(NodeRuntimeMaintenanceError::InvalidProjection)
    );
}

// Maps applied, replayed, conflict, and provider outcomes without bypassing runtime ownership.
#[test]
fn runtime_removal_maps_terminal_and_failure_dispositions() {
    let available = record(1, RuntimeInstallationState::Available);
    let identity = available.installation().installation_id().clone();
    let (applied, applied_runtime) = coordinator(vec![available], None, None, Ok(()));
    assert_eq!(
        applied.remove(&identity, NodeRuntimeModelRetention::Remove),
        Ok(NodeRuntimeRemovalDisposition::Applied)
    );
    assert_eq!(
        *applied_runtime.calls.lock().expect("applied calls"),
        vec![identity.clone()]
    );

    let removed = record(1, RuntimeInstallationState::Removed);
    let (replayed, _) = coordinator(vec![removed], None, None, Ok(()));
    assert_eq!(
        replayed.remove(&identity, NodeRuntimeModelRetention::Remove),
        Ok(NodeRuntimeRemovalDisposition::Replayed)
    );

    let (missing, missing_runtime) = coordinator(Vec::new(), None, None, Ok(()));
    assert_eq!(
        missing.remove(&identity, NodeRuntimeModelRetention::Remove),
        Err(NodeRuntimeMaintenanceError::Conflict)
    );
    assert!(missing_runtime
        .calls
        .lock()
        .expect("missing calls")
        .is_empty());

    for (read_error, removal_error, expected) in [
        (
            Some(RuntimeError::StoreConflict),
            None,
            NodeRuntimeMaintenanceError::Conflict,
        ),
        (
            Some(RuntimeError::StoreUnavailable),
            None,
            NodeRuntimeMaintenanceError::ProviderUnavailable,
        ),
        (
            None,
            Some(RuntimeError::StoreConflict),
            NodeRuntimeMaintenanceError::Conflict,
        ),
        (
            None,
            Some(RuntimeError::ArtifactUnavailable),
            NodeRuntimeMaintenanceError::ProviderUnavailable,
        ),
    ] {
        let (failed, _) = coordinator(
            vec![record(1, RuntimeInstallationState::Available)],
            None,
            read_error,
            removal_error.map_or(Ok(()), Err),
        );
        assert_eq!(
            failed.remove(&identity, NodeRuntimeModelRetention::Remove),
            Err(expected)
        );
    }
}

// Requires authoritative terminal state and safely replays exact policy-bound finalization.
#[test]
fn runtime_finalization_rejects_premature_state_and_replays_exact_policy() {
    let (premature, premature_runtime) = coordinator(
        vec![record(1, RuntimeInstallationState::Available)],
        None,
        None,
        Ok(()),
    );
    assert_eq!(
        premature.finalize_cleanup(NodeRuntimeModelRetention::Preserve),
        Err(NodeRuntimeMaintenanceError::Conflict)
    );
    assert!(premature_runtime
        .finalize_calls
        .lock()
        .expect("premature finalization calls")
        .is_empty());

    let (terminal, runtime) = coordinator(
        vec![
            record(2, RuntimeInstallationState::Removed),
            record(1, RuntimeInstallationState::Removed),
        ],
        None,
        None,
        Ok(()),
    );
    for _ in 0..2 {
        terminal
            .finalize_cleanup(NodeRuntimeModelRetention::Preserve)
            .expect("finalize or replay");
    }
    assert_eq!(
        runtime
            .finalize_calls
            .lock()
            .expect("finalization calls")
            .as_slice(),
        [
            NodeRuntimeModelRetention::Preserve,
            NodeRuntimeModelRetention::Preserve
        ]
    );

    let (failed, _) = coordinator(
        vec![record(1, RuntimeInstallationState::Removed)],
        None,
        None,
        Err(RuntimeError::ArtifactUnavailable),
    );
    assert_eq!(
        failed.finalize_cleanup(NodeRuntimeModelRetention::Remove),
        Err(NodeRuntimeMaintenanceError::ProviderUnavailable)
    );
}
