// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::Ordering;

use li_core_interface::{
    DeviceId, ModelServiceDesiredState, OperationId, PlacementGroupState, PortRange,
    RuntimeInstallationState, Sha256Digest,
};
use li_node_manager::{
    NodeBenchmarkCandidateHandoffError, NodeBenchmarkCandidateHandoffPhase,
    NodeBenchmarkCandidateHandoffRequest, NodeModelPlacementPort, NodeModelRuntimePort,
};
use li_runtime_manager::{RuntimeExactCandidateArtifacts, RuntimeExactEngineArtifact};

#[path = "../../test_support/li_benchmark_candidate_handoff_fixture.rs"]
mod li_benchmark_candidate_handoff_fixture;

use li_benchmark_candidate_handoff_fixture::*;

// Proves candidate execution remains private and restoration preserves exact baseline resources.
#[test]
fn successful_handoff_is_private_and_restores_exact_baseline_resources() {
    let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Running);
    let coordinator = fixture.coordinator();
    let request = fixture.request('a');
    let transaction_id = request.transaction_id().clone();
    let prepared = coordinator.prepare(request).expect("prepare");
    assert_eq!(
        prepared.record().phase(),
        NodeBenchmarkCandidateHandoffPhase::CandidateAcquired
    );
    let prepared_subject = coordinator
        .prepared_subject(&transaction_id)
        .expect("prepared subject");
    assert_eq!(
        prepared_subject.benchmark_contract_sha256(),
        &Sha256Digest::parse(&"a".repeat(64)).expect("candidate benchmark contract")
    );
    assert_eq!(
        prepared_subject.target_contract_sha256(),
        &Sha256Digest::parse(&"b".repeat(64)).expect("candidate target contract")
    );
    assert_ne!(
        prepared_subject.benchmark_contract_sha256(),
        fixture.baseline_subject.benchmark_contract_sha256()
    );
    let receipt = coordinator.activate(&transaction_id).expect("activate");
    assert_eq!(receipt.transaction_id(), &transaction_id);
    assert_eq!(
        fixture.service().service().placement_group_ids(),
        &[fixture.baseline_group_id.clone()]
    );
    assert_ne!(
        receipt.subject().placement_group_id(),
        &fixture.baseline_group_id
    );
    assert_eq!(receipt.subject(), &prepared_subject);
    let completed = coordinator.restore(&transaction_id).expect("restore");
    assert_eq!(
        completed.record().phase(),
        NodeBenchmarkCandidateHandoffPhase::Completed
    );
    let service = fixture.service();
    assert_eq!(
        service.service().placement_group_ids(),
        &[completed.record().restoration_group_id().clone()]
    );
    let restored = fixture
        .placement
        .record(completed.record().restoration_group_id())
        .expect("read")
        .expect("restored");
    let assignment = restored.record().placements()[0].assignment();
    assert_eq!(assignment.node_id(), &node_id());
    assert_eq!(
        assignment.resources().device_ids(),
        &[DeviceId::parse("GPU-fixture").expect("device")]
    );
    assert_eq!(
        assignment.resources().ports(),
        PortRange::new(18_000, 2).expect("ports")
    );
    assert_eq!(
        fixture
            .runtime
            .installation(completed.record().candidate_installation_id())
            .expect("candidate")
            .expect("candidate")
            .installation()
            .state(),
        RuntimeInstallationState::Removed
    );
}

// Keeps finalizer full-subject identity distinct from the native Runtime execution contract.
#[test]
fn handoff_accepts_only_runtime_execution_digest_not_full_candidate_subject_digest() {
    let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Running);
    let candidate = candidate();
    let runtime_execution = candidate.runtime().execution_contract_digest().clone();
    let candidate_subject = Sha256Digest::parse(&"7".repeat(64)).expect("candidate subject");
    assert_ne!(candidate_subject, runtime_execution);
    let artifacts = || {
        RuntimeExactCandidateArtifacts::new(
            "/private/tmp/runtime.letsinfer".into(),
            RuntimeExactEngineArtifact::Reuse,
            Sha256Digest::parse(&"9".repeat(64)).expect("closure"),
        )
        .expect("artifacts")
    };
    assert_eq!(
        NodeBenchmarkCandidateHandoffRequest::new(
            OperationId::parse(&identity('9')).expect("transaction"),
            fixture.baseline_subject.clone(),
            candidate.clone(),
            artifacts(),
            candidate_subject,
        ),
        Err(NodeBenchmarkCandidateHandoffError::InvalidRequest)
    );
    NodeBenchmarkCandidateHandoffRequest::new(
        OperationId::parse(&identity('9')).expect("transaction"),
        fixture.baseline_subject,
        candidate,
        artifacts(),
        runtime_execution,
    )
    .expect("runtime execution identity");
}

// Proves acquisition failure, ambiguous success, hardware drift, and request drift fail closed.
#[test]
fn preparation_and_resource_gate_failure_table_never_releases_baseline() {
    for failure in ["acquisition", "ambiguous", "hardware", "request"] {
        let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Running);
        match failure {
            "acquisition" => fixture
                .runtime
                .fail_acquisition
                .store(true, Ordering::SeqCst),
            "ambiguous" => fixture
                .runtime
                .ambiguous_success
                .store(true, Ordering::SeqCst),
            "hardware" => fixture.hardware.drift.store(true, Ordering::SeqCst),
            "request" => fixture.requests.drift.store(true, Ordering::SeqCst),
            _ => unreachable!(),
        }
        let coordinator = fixture.coordinator();
        let request = fixture.request(match failure {
            "acquisition" => 'b',
            "ambiguous" => 'c',
            "hardware" => 'd',
            _ => 'e',
        });
        let transaction_id = request.transaction_id().clone();
        let result = coordinator.prepare(request);
        if failure == "request" {
            result.expect("prepare before request planning");
            assert_eq!(
                coordinator.activate(&transaction_id),
                Err(NodeBenchmarkCandidateHandoffError::HardwareDrift)
            );
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            fixture
                .placement
                .record(&fixture.baseline_group_id)
                .expect("baseline")
                .expect("baseline")
                .record()
                .group()
                .state(),
            PlacementGroupState::Running
        );
    }
}

// Proves candidate activation failure restores the baseline before reporting the failure.
#[test]
fn activation_failure_restores_before_returning() {
    let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Running);
    let coordinator = fixture.coordinator();
    let request = fixture.request('f');
    let transaction_id = request.transaction_id().clone();
    coordinator.prepare(request).expect("prepare");
    fixture
        .placement
        .fail_next_start
        .store(true, Ordering::SeqCst);
    assert_eq!(
        coordinator.activate(&transaction_id),
        Err(NodeBenchmarkCandidateHandoffError::ActivationFailed)
    );
    assert_eq!(
        coordinator
            .record(&transaction_id)
            .expect("record")
            .expect("record")
            .record()
            .phase(),
        NodeBenchmarkCandidateHandoffPhase::Completed
    );
    assert_eq!(fixture.service().service().placement_group_ids().len(), 1);
}

// Proves cancellation and restart replay at every durable pre-restoration boundary.
#[test]
fn restart_cancellation_phase_table_is_idempotent() {
    let phases = [
        NodeBenchmarkCandidateHandoffPhase::Prepared,
        NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
        NodeBenchmarkCandidateHandoffPhase::BaselineReleasing,
        NodeBenchmarkCandidateHandoffPhase::BaselineReleased,
        NodeBenchmarkCandidateHandoffPhase::CandidateStaged,
        NodeBenchmarkCandidateHandoffPhase::CandidateRunning,
        NodeBenchmarkCandidateHandoffPhase::Restoring,
    ];
    for (index, phase) in phases.into_iter().enumerate() {
        let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Running);
        let first = fixture.coordinator();
        let character = char::from_digit(u32::try_from(index + 1).expect("index"), 16)
            .expect("transaction character");
        let request = fixture.request(character);
        let transaction_id = request.transaction_id().clone();
        first.prepare(request).expect("prepare");
        if !matches!(
            phase,
            NodeBenchmarkCandidateHandoffPhase::Prepared
                | NodeBenchmarkCandidateHandoffPhase::CandidateAcquired
        ) {
            first.activate(&transaction_id).expect("activate");
        }
        fixture.force_phase(&transaction_id, phase);
        drop(first);
        let restarted = fixture.coordinator();
        let completed = restarted.restore(&transaction_id).expect("restart restore");
        assert_eq!(
            completed.record().phase(),
            NodeBenchmarkCandidateHandoffPhase::Completed
        );
        assert_eq!(
            restarted
                .restore(&transaction_id)
                .expect("idempotent restore")
                .record()
                .phase(),
            NodeBenchmarkCandidateHandoffPhase::Completed
        );
    }
}

// Proves a stopped baseline is restored without accidentally starting public inference.
#[test]
fn stopped_baseline_intent_remains_stopped() {
    let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Stopped);
    let coordinator = fixture.coordinator();
    let request = fixture.request('3');
    let transaction_id = request.transaction_id().clone();
    let prepared = coordinator.prepare(request).expect("prepare");
    assert_eq!(
        prepared.record().phase(),
        NodeBenchmarkCandidateHandoffPhase::BaselineActivated
    );
    assert_eq!(
        fixture
            .placement
            .record(&fixture.baseline_group_id)
            .expect("baseline")
            .expect("baseline")
            .record()
            .group()
            .state(),
        PlacementGroupState::Running
    );
    coordinator
        .activate(&transaction_id)
        .expect("candidate runs privately");
    let completed = coordinator.restore(&transaction_id).expect("restore");
    let restored = fixture
        .placement
        .record(completed.record().restoration_group_id())
        .expect("read")
        .expect("restored");
    assert_eq!(
        restored.record().group().state(),
        PlacementGroupState::Stopped
    );
    assert_eq!(
        fixture.service().service().desired_state(),
        ModelServiceDesiredState::Stopped
    );
}

// Restores a temporarily activated stopped baseline when outer admission aborts before cutover.
#[test]
fn stopped_baseline_abort_and_restart_restore_original_intent() {
    let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Stopped);
    let first = fixture.coordinator();
    let request = fixture.request('8');
    let transaction_id = request.transaction_id().clone();
    first.prepare(request).expect("prepare");
    drop(first);
    let restarted = fixture.coordinator();
    let completed = restarted.restore(&transaction_id).expect("abort restore");
    assert_eq!(
        completed.record().phase(),
        NodeBenchmarkCandidateHandoffPhase::Completed
    );
    assert_eq!(
        fixture
            .placement
            .record(&fixture.baseline_group_id)
            .expect("baseline")
            .expect("baseline")
            .record()
            .group()
            .state(),
        PlacementGroupState::Stopped
    );
    assert_eq!(
        fixture.service().service().placement_group_ids(),
        &[fixture.baseline_group_id.clone()]
    );
}

// Proves restoration and candidate-byte cleanup failures remain durable and retryable.
#[test]
fn restoration_failure_boundaries_retry_without_reallocating() {
    let fixture = BenchmarkCandidateHandoffFixture::new(PlacementGroupState::Running);
    let coordinator = fixture.coordinator();
    let request = fixture.request('4');
    let transaction_id = request.transaction_id().clone();
    coordinator.prepare(request).expect("prepare");
    coordinator.activate(&transaction_id).expect("activate");
    fixture
        .placement
        .fail_next_start
        .store(true, Ordering::SeqCst);
    assert_eq!(
        coordinator.restore(&transaction_id),
        Err(NodeBenchmarkCandidateHandoffError::RestorationRequired)
    );
    assert_eq!(
        coordinator
            .record(&transaction_id)
            .expect("record")
            .expect("record")
            .record()
            .phase(),
        NodeBenchmarkCandidateHandoffPhase::Restoring
    );
    fixture.runtime.fail_remove.store(true, Ordering::SeqCst);
    assert_eq!(
        coordinator.restore(&transaction_id),
        Err(NodeBenchmarkCandidateHandoffError::RuntimeUnavailable)
    );
    assert_eq!(
        coordinator
            .record(&transaction_id)
            .expect("record")
            .expect("record")
            .record()
            .phase(),
        NodeBenchmarkCandidateHandoffPhase::BaselineRestored
    );
    assert_eq!(
        coordinator
            .restore(&transaction_id)
            .expect("cleanup retry")
            .record()
            .phase(),
        NodeBenchmarkCandidateHandoffPhase::Completed
    );
}
