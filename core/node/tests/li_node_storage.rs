// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use li_core_interface::{LogicalModelName, OperationId, Sha256Digest};
use li_node_manager::{
    NodeStorageCandidate, NodeStorageCategory, NodeStorageCleanReceipt, NodeStorageCleanRequest,
    NodeStorageCleanupPort, NodeStorageCoordinator, NodeStorageError,
    NodeStorageObservationProvider, NodeStorageSnapshot, NodeStorageUsage,
};

// Records deterministic storage observations and mutations behind the real coordinator.
struct StorageProviderMock {
    snapshots: Mutex<VecDeque<Result<NodeStorageSnapshot, NodeStorageError>>>,
    receipt: Mutex<Result<NodeStorageCleanReceipt, NodeStorageError>>,
    clean_calls: Mutex<Vec<NodeStorageCleanRequest>>,
}

impl StorageProviderMock {
    // Creates one provider with ordered snapshots and one cleanup result.
    fn new(
        snapshots: impl IntoIterator<Item = Result<NodeStorageSnapshot, NodeStorageError>>,
        receipt: Result<NodeStorageCleanReceipt, NodeStorageError>,
    ) -> Self {
        Self {
            snapshots: Mutex::new(snapshots.into_iter().collect()),
            receipt: Mutex::new(receipt),
            clean_calls: Mutex::new(Vec::new()),
        }
    }

    // Returns every exact cleanup request received by the provider.
    fn clean_calls(&self) -> Vec<NodeStorageCleanRequest> {
        self.clean_calls.lock().expect("clean calls").clone()
    }
}

impl NodeStorageObservationProvider for StorageProviderMock {
    // Returns the next deterministic storage snapshot.
    fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError> {
        self.snapshots
            .lock()
            .expect("snapshots")
            .pop_front()
            .expect("prepared snapshot")
    }
}

impl NodeStorageCleanupPort for StorageProviderMock {
    // Records one request and returns the configured manager-owned mutation receipt.
    fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        self.clean_calls
            .lock()
            .expect("clean calls")
            .push(request.clone());
        self.receipt.lock().expect("receipt").clone()
    }
}

// Creates one fixed SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one exact cleanup operation identity.
fn operation() -> OperationId {
    OperationId::parse(&"1".repeat(32)).expect("operation")
}

// Creates one coherent storage snapshot for a selected plan identity.
fn snapshot(plan: char) -> NodeStorageSnapshot {
    NodeStorageSnapshot::new(
        10_000,
        4_000,
        vec![
            NodeStorageUsage::new(NodeStorageCategory::Models, 3_000, 2_500, 2, 1_000)
                .expect("models"),
            NodeStorageUsage::new(NodeStorageCategory::Caches, 2_000, 1_900, 3, 500)
                .expect("caches"),
            NodeStorageUsage::new(NodeStorageCategory::State, 200, 100, 4, 0).expect("state"),
        ],
        vec![
            NodeStorageCandidate::new(
                NodeStorageCategory::Caches,
                "cache/runtime/stopped",
                500,
                "inactive runtime cache",
                Vec::new(),
            )
            .expect("cache candidate"),
            NodeStorageCandidate::new(
                NodeStorageCategory::Models,
                "models/owner--model/revision",
                1_000,
                "inactive model artifacts",
                vec![LogicalModelName::parse("model").expect("model")],
            )
            .expect("model candidate"),
        ],
        digest(plan),
    )
    .expect("snapshot")
}

// Proves stable ordering and complete non-secret projection through the coordinator.
#[test]
fn coordinator_returns_one_validated_storage_snapshot() {
    let provider = Arc::new(StorageProviderMock::new(
        [Ok(snapshot('a'))],
        Err(NodeStorageError::ProviderUnavailable),
    ));
    let coordinator = NodeStorageCoordinator::new(provider.clone(), provider);
    let actual = coordinator.snapshot().expect("storage snapshot");
    assert_eq!(actual.capacity_bytes(), 10_000);
    assert_eq!(actual.available_bytes(), 4_000);
    assert_eq!(actual.usage().len(), 3);
    assert_eq!(actual.usage()[0].category(), NodeStorageCategory::Models);
    assert_eq!(actual.candidates().len(), 2);
    assert_eq!(
        actual.candidates()[0].category(),
        NodeStorageCategory::Models
    );
    assert_eq!(actual.plan_digest(), &digest('a'));
}

// Proves malformed paths, totals, and non-reclaimable requests fail before a provider call.
#[test]
fn value_contracts_reject_unsafe_or_incoherent_storage_state() {
    assert_eq!(
        NodeStorageCategory::parse("benchmarks"),
        Ok(NodeStorageCategory::Benchmarks)
    );
    assert_eq!(
        NodeStorageCategory::parse("runtime"),
        Err(NodeStorageError::InvalidRequest)
    );
    assert_eq!(
        NodeStorageCandidate::new(
            NodeStorageCategory::Models,
            "../outside",
            1,
            "inactive",
            Vec::new(),
        ),
        Err(NodeStorageError::InvalidProjection)
    );
    assert_eq!(
        NodeStorageUsage::new(NodeStorageCategory::State, 10, 10, 1, 1),
        Err(NodeStorageError::InvalidProjection)
    );
    assert_eq!(
        NodeStorageCleanRequest::new(operation(), digest('a'), [NodeStorageCategory::Core]),
        Err(NodeStorageError::InvalidRequest)
    );
    assert!(NodeStorageSnapshot::new(100, 101, Vec::new(), Vec::new(), digest('a')).is_err());
}

// Proves plan drift and absent selected categories cannot reach cleanup mutation.
#[test]
fn coordinator_rechecks_the_reviewed_plan_before_cleanup() {
    let request =
        NodeStorageCleanRequest::new(operation(), digest('a'), [NodeStorageCategory::Models])
            .expect("request");
    let drifted = Arc::new(StorageProviderMock::new(
        [Ok(snapshot('b'))],
        Err(NodeStorageError::ProviderUnavailable),
    ));
    assert_eq!(
        NodeStorageCoordinator::new(drifted.clone(), drifted.clone()).clean(&request),
        Err(NodeStorageError::PlanChanged)
    );
    assert!(drifted.clean_calls().is_empty());

    let missing =
        NodeStorageCleanRequest::new(operation(), digest('a'), [NodeStorageCategory::Benchmarks])
            .expect("request");
    let provider = Arc::new(StorageProviderMock::new(
        [Ok(snapshot('a'))],
        Err(NodeStorageError::ProviderUnavailable),
    ));
    assert_eq!(
        NodeStorageCoordinator::new(provider.clone(), provider.clone()).clean(&missing),
        Err(NodeStorageError::InvalidRequest)
    );
    assert!(provider.clean_calls().is_empty());
}

// Proves exact success and replay receipts preserve request and model identities.
#[test]
fn coordinator_returns_content_bound_cleanup_receipts() {
    for replayed in [false, true] {
        let request = NodeStorageCleanRequest::new(
            operation(),
            digest('a'),
            [NodeStorageCategory::Models, NodeStorageCategory::Caches],
        )
        .expect("request");
        let receipt = NodeStorageCleanReceipt::new(
            operation(),
            digest('a'),
            2,
            1_500,
            vec![LogicalModelName::parse("model").expect("model")],
            replayed,
        )
        .expect("receipt");
        let provider = Arc::new(StorageProviderMock::new([Ok(snapshot('a'))], Ok(receipt)));
        let actual = NodeStorageCoordinator::new(provider.clone(), provider.clone())
            .clean(&request)
            .expect("cleanup");
        assert_eq!(actual.reclaimed_bytes(), 1_500);
        assert_eq!(actual.removed_targets(), 2);
        assert_eq!(actual.models_to_download()[0].as_str(), "model");
        assert_eq!(actual.replayed(), replayed);
        assert_eq!(provider.clean_calls(), vec![request]);
    }
}

// Proves provider failures and mismatched receipts fail closed without leaking diagnostics.
#[test]
fn coordinator_preserves_provider_and_receipt_failure_boundaries() {
    let request =
        NodeStorageCleanRequest::new(operation(), digest('a'), [NodeStorageCategory::Models])
            .expect("request");
    let unavailable = Arc::new(StorageProviderMock::new(
        [Err(NodeStorageError::ProviderUnavailable)],
        Err(NodeStorageError::ProviderUnavailable),
    ));
    assert_eq!(
        NodeStorageCoordinator::new(unavailable.clone(), unavailable).clean(&request),
        Err(NodeStorageError::ProviderUnavailable)
    );

    let mismatched =
        NodeStorageCleanReceipt::new(operation(), digest('b'), 1, 1, Vec::new(), false)
            .expect("receipt");
    let provider = Arc::new(StorageProviderMock::new(
        [Ok(snapshot('a'))],
        Ok(mismatched),
    ));
    assert_eq!(
        NodeStorageCoordinator::new(provider.clone(), provider).clean(&request),
        Err(NodeStorageError::InvalidProjection)
    );
}
