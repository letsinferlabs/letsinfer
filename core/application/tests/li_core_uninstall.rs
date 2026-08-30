// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    ApplicationCoreCliUninstall, CoreUninstallBenchmarkPort, CoreUninstallBoundary,
    CoreUninstallBoundaryReceipt, CoreUninstallConfirmation, CoreUninstallCoordinator,
    CoreUninstallError, CoreUninstallExposurePort, CoreUninstallImmutableCorePort,
    CoreUninstallModelDisposition, CoreUninstallMutationBarrierPort, CoreUninstallOwnedTarget,
    CoreUninstallOwnerDataPort, CoreUninstallPlan, CoreUninstallPreflight,
    CoreUninstallPreflightPort, CoreUninstallReceipt, CoreUninstallRequest,
    CoreUninstallRuntimePort, CoreUninstallServicePort, CoreUninstallSessionPhase,
    CoreUninstallSessionRecoveryState, CoreUninstallSessionRetention, CoreUninstallTargetKind,
    CoreUninstallWorkloadPort,
};
use li_core_cli::{
    CommandProgressEvent, CommandProgressPort, NativeUninstallModelDisposition, NativeUninstallPort,
};
use li_core_interface::Sha256Digest;

const MUTATION_ORDER: [CoreUninstallBoundary; 7] = [
    CoreUninstallBoundary::BenchmarkExit,
    CoreUninstallBoundary::PublicExposure,
    CoreUninstallBoundary::Workloads,
    CoreUninstallBoundary::RuntimeArtifacts,
    CoreUninstallBoundary::PlatformServices,
    CoreUninstallBoundary::OwnerData,
    CoreUninstallBoundary::ImmutableCore,
];

// Records every external boundary in the exact order observed by the coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UninstallEvent {
    BarrierBegin,
    BarrierCancel,
    Preflight,
    Boundary(CoreUninstallBoundary),
}

// Discards presentation detail while retaining the real CLI adapter boundary.
struct ProgressMock;

impl CommandProgressPort for ProgressMock {
    // Accepts coordinator progress without creating another assertion surface.
    fn report(&mut self, _event: CommandProgressEvent) {}
}

// Makes the Node-owned exclusion session visible without replacing its lifecycle contract.
struct MutationBarrierMock {
    events: Arc<Mutex<Vec<UninstallEvent>>>,
    retention: Mutex<Option<CoreUninstallSessionRetention>>,
}

impl CoreUninstallMutationBarrierPort for MutationBarrierMock {
    // Begins one deterministic exclusion session before preflight may inventory state.
    fn begin(
        &self,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Result<Sha256Digest, CoreUninstallError> {
        let retention = match model_disposition {
            CoreUninstallModelDisposition::KeepModels => CoreUninstallSessionRetention::KeepModels,
            CoreUninstallModelDisposition::RemoveModels => {
                CoreUninstallSessionRetention::RemoveModels
            }
        };
        *self.retention.lock().expect("retention") = Some(retention);
        self.events
            .lock()
            .expect("events")
            .push(UninstallEvent::BarrierBegin);
        Ok(digest('e'))
    }

    // Returns one fresh deterministic durable state before preflight binds its plan.
    fn recovery_state(
        &self,
        session_id: &Sha256Digest,
    ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallError> {
        Ok(CoreUninstallSessionRecoveryState::admitting(
            session_id.clone(),
            self.retention
                .lock()
                .expect("retention")
                .ok_or(CoreUninstallError::OperationConflict)?,
        ))
    }

    // Accepts the exact plan checkpoint while coordinator tests observe external ports only.
    fn persist_plan(
        &self,
        _session_id: &Sha256Digest,
        _plan: &CoreUninstallPlan,
    ) -> Result<(), CoreUninstallError> {
        Ok(())
    }

    // Accepts one receipt checkpoint while preserving the existing event vocabulary.
    fn append_receipt(
        &self,
        _session_id: &Sha256Digest,
        _receipt: &CoreUninstallBoundaryReceipt,
    ) -> Result<(), CoreUninstallError> {
        Ok(())
    }

    // Accepts one monotonic phase checkpoint while external-order tests remain focused.
    fn advance_phase(
        &self,
        _session_id: &Sha256Digest,
        _phase: CoreUninstallSessionPhase,
    ) -> Result<(), CoreUninstallError> {
        Ok(())
    }

    // Records release only when the Node resident remains available after a stopped teardown.
    fn cancel(&self, session_id: &Sha256Digest) -> Result<(), CoreUninstallError> {
        assert_eq!(session_id, &digest('e'));
        self.events
            .lock()
            .expect("events")
            .push(UninstallEvent::BarrierCancel);
        Ok(())
    }
}

// Simulates a lost plan-publication acknowledgement followed by an unreadable journal.
struct AmbiguousPlanPublicationBarrierMock {
    recovery_calls: Mutex<u8>,
    cancel_calls: Mutex<u8>,
}

impl CoreUninstallMutationBarrierPort for AmbiguousPlanPublicationBarrierMock {
    // Begins the deterministic lease whose ambiguous publication must remain recoverable.
    fn begin(
        &self,
        _model_disposition: CoreUninstallModelDisposition,
    ) -> Result<Sha256Digest, CoreUninstallError> {
        Ok(digest('e'))
    }

    // Returns admitting once, then models an unavailable post-publication observation.
    fn recovery_state(
        &self,
        session_id: &Sha256Digest,
    ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallError> {
        let mut calls = self.recovery_calls.lock().expect("recovery calls");
        *calls += 1;
        if *calls == 1 {
            return Ok(CoreUninstallSessionRecoveryState::admitting(
                session_id.clone(),
                CoreUninstallSessionRetention::KeepModels,
            ));
        }
        Err(CoreUninstallError::OperationConflict)
    }

    // Models failure after the durable publication may already have reached storage.
    fn persist_plan(
        &self,
        _session_id: &Sha256Digest,
        _plan: &CoreUninstallPlan,
    ) -> Result<(), CoreUninstallError> {
        Err(CoreUninstallError::InvalidPlan)
    }

    // Rejects receipt publication because no destructive boundary may be reached.
    fn append_receipt(
        &self,
        _session_id: &Sha256Digest,
        _receipt: &CoreUninstallBoundaryReceipt,
    ) -> Result<(), CoreUninstallError> {
        panic!("receipt publication must not be reached")
    }

    // Rejects phase publication because no destructive boundary may be reached.
    fn advance_phase(
        &self,
        _session_id: &Sha256Digest,
        _phase: CoreUninstallSessionPhase,
    ) -> Result<(), CoreUninstallError> {
        panic!("phase publication must not be reached")
    }

    // Records unsafe lease cancellation after an ambiguous publication outcome.
    fn cancel(&self, _session_id: &Sha256Digest) -> Result<(), CoreUninstallError> {
        *self.cancel_calls.lock().expect("cancel calls") += 1;
        Ok(())
    }
}

// Selects one deterministic preflight result without replacing coordinator behavior.
#[derive(Clone)]
enum PreflightOutcome {
    Ready(CoreUninstallPlan),
    Replayed(CoreUninstallReceipt),
    Rejected,
}

// Supplies one exact plan or receipt while making preflight ordering observable.
struct PreflightMock {
    outcome: PreflightOutcome,
    events: Arc<Mutex<Vec<UninstallEvent>>>,
}

impl CoreUninstallPreflightPort for PreflightMock {
    // Returns the selected ownership result after recording the only preflight call.
    fn preflight(
        &self,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Result<CoreUninstallPreflight, CoreUninstallError> {
        self.events
            .lock()
            .expect("events")
            .push(UninstallEvent::Preflight);
        match &self.outcome {
            PreflightOutcome::Ready(plan) if plan.model_disposition() == model_disposition => {
                Ok(CoreUninstallPreflight::Ready(plan.clone()))
            }
            PreflightOutcome::Replayed(receipt)
                if receipt.models_preserved()
                    == matches!(model_disposition, CoreUninstallModelDisposition::KeepModels) =>
            {
                Ok(CoreUninstallPreflight::Replayed(receipt.clone()))
            }
            PreflightOutcome::Ready(_) | PreflightOutcome::Replayed(_) => {
                Err(CoreUninstallError::PreflightRejected)
            }
            PreflightOutcome::Rejected => Err(CoreUninstallError::PreflightRejected),
        }
    }
}

// Implements all seven narrow mutation ports while retaining one readable failure selector.
struct BoundaryMock {
    failure: Option<CoreUninstallBoundary>,
    invalid_receipt: Option<CoreUninstallBoundary>,
    events: Arc<Mutex<Vec<UninstallEvent>>>,
}

impl BoundaryMock {
    // Completes, fails, or returns a foreign receipt at one exact observed boundary.
    fn complete(
        &self,
        plan: &CoreUninstallPlan,
        boundary: CoreUninstallBoundary,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.events
            .lock()
            .expect("events")
            .push(UninstallEvent::Boundary(boundary));
        if self.failure == Some(boundary) {
            return Err(CoreUninstallError::BoundaryFailed(boundary));
        }
        if self.invalid_receipt == Some(boundary) {
            let disposition = match plan.model_disposition() {
                CoreUninstallModelDisposition::KeepModels => {
                    CoreUninstallModelDisposition::RemoveModels
                }
                CoreUninstallModelDisposition::RemoveModels => {
                    CoreUninstallModelDisposition::KeepModels
                }
            };
            return CoreUninstallBoundaryReceipt::completed(&fixture_plan(disposition), boundary);
        }
        CoreUninstallBoundaryReceipt::completed(plan, boundary)
    }
}

impl CoreUninstallBenchmarkPort for BoundaryMock {
    // Completes the bounded benchmark-exit boundary selected by the fixture.
    fn stop_and_wait(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::BenchmarkExit)
    }
}

impl CoreUninstallExposurePort for BoundaryMock {
    // Completes the public-exposure boundary selected by the fixture.
    fn disable(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::PublicExposure)
    }
}

impl CoreUninstallWorkloadPort for BoundaryMock {
    // Completes the placement and model shutdown boundary selected by the fixture.
    fn shutdown(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::Workloads)
    }
}

impl CoreUninstallServicePort for BoundaryMock {
    // Completes the platform service retirement boundary selected by the fixture.
    fn retire(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::PlatformServices)
    }
}

impl CoreUninstallRuntimePort for BoundaryMock {
    // Completes the managed runtime artifact boundary selected by the fixture.
    fn clean(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::RuntimeArtifacts)
    }
}

impl CoreUninstallOwnerDataPort for BoundaryMock {
    // Completes the model-aware owner-data boundary selected by the fixture.
    fn clean(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::OwnerData)
    }
}

impl CoreUninstallImmutableCorePort for BoundaryMock {
    // Completes the final immutable Core and launcher boundary selected by the fixture.
    fn retire(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.complete(plan, CoreUninstallBoundary::ImmutableCore)
    }
}

// Creates one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one exact owned target with a distinct deterministic ownership proof.
fn target(kind: CoreUninstallTargetKind, identity: &str, proof: char) -> CoreUninstallOwnedTarget {
    CoreUninstallOwnedTarget::new(kind, identity, digest(proof)).expect("target")
}

// Creates one complete ownership plan containing every supported external category.
fn fixture_plan(disposition: CoreUninstallModelDisposition) -> CoreUninstallPlan {
    let mut targets = vec![
        target(
            CoreUninstallTargetKind::ActiveBenchmark,
            "benchmark:active",
            '0',
        ),
        target(
            CoreUninstallTargetKind::PublicExposure,
            "exposure:tailscale",
            '1',
        ),
        target(
            CoreUninstallTargetKind::PlacementGroup,
            "placement-group:alpha",
            '2',
        ),
        target(
            CoreUninstallTargetKind::ModelService,
            "model-service:alpha",
            '3',
        ),
        target(
            CoreUninstallTargetKind::RuntimeInstallation,
            "runtime:alpha",
            '5',
        ),
        target(
            CoreUninstallTargetKind::PlatformService,
            "service:li_node",
            '4',
        ),
        target(
            CoreUninstallTargetKind::ManagedContainer,
            "container:alpha",
            '6',
        ),
        target(
            CoreUninstallTargetKind::ManagedImage,
            "image:sha256-alpha",
            '7',
        ),
        target(CoreUninstallTargetKind::OwnerRoot, "owner-root:state", '8'),
        target(CoreUninstallTargetKind::CoreInstallation, "core:v1", 'a'),
        target(CoreUninstallTargetKind::Launcher, "launcher:letsinfer", 'b'),
    ];
    if disposition == CoreUninstallModelDisposition::RemoveModels {
        targets.push(target(
            CoreUninstallTargetKind::ModelRoot,
            "model-root:models",
            '9',
        ));
    }
    CoreUninstallPlan::new(digest('f'), disposition, Duration::from_secs(30), targets)
        .expect("plan")
}

// Creates the exact terminal receipt for one plan without invoking a mutation mock.
fn completed_receipt(plan: &CoreUninstallPlan) -> CoreUninstallReceipt {
    CoreUninstallReceipt::completed(
        plan,
        [
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::BenchmarkExit)
                .expect("benchmark receipt"),
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::PublicExposure)
                .expect("exposure receipt"),
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::Workloads)
                .expect("workload receipt"),
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::RuntimeArtifacts)
                .expect("runtime receipt"),
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::PlatformServices)
                .expect("service receipt"),
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::OwnerData)
                .expect("owner receipt"),
            CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::ImmutableCore)
                .expect("core receipt"),
        ],
    )
    .expect("complete receipt")
}

// Composes one coordinator whose complete external history remains observable.
fn coordinator(
    outcome: PreflightOutcome,
    failure: Option<CoreUninstallBoundary>,
    invalid_receipt: Option<CoreUninstallBoundary>,
) -> (CoreUninstallCoordinator, Arc<Mutex<Vec<UninstallEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let preflight = Arc::new(PreflightMock {
        outcome,
        events: events.clone(),
    });
    let boundaries = Arc::new(BoundaryMock {
        failure,
        invalid_receipt,
        events: events.clone(),
    });
    let mutation_barrier = Arc::new(MutationBarrierMock {
        events: events.clone(),
        retention: Mutex::new(None),
    });
    (
        CoreUninstallCoordinator::new(
            mutation_barrier,
            preflight,
            boundaries.clone(),
            boundaries.clone(),
            boundaries.clone(),
            boundaries.clone(),
            boundaries.clone(),
            boundaries.clone(),
            boundaries,
        ),
        events,
    )
}

// Returns the complete immutable event history for one fixture.
fn history(events: &Arc<Mutex<Vec<UninstallEvent>>>) -> Vec<UninstallEvent> {
    events.lock().expect("events").clone()
}

// Returns the exact ordinary external sequence shared by both model dispositions.
fn complete_history() -> Vec<UninstallEvent> {
    [UninstallEvent::BarrierBegin, UninstallEvent::Preflight]
        .into_iter()
        .chain(MUTATION_ORDER.map(UninstallEvent::Boundary))
        .collect()
}

// Proves ordinary keep and remove flows share safe ordering and return stable typed receipts.
#[test]
fn ordinary_flows_preserve_policy_and_complete_every_boundary_in_order() {
    for (disposition, models_preserved, retained_runtime_count) in [
        (CoreUninstallModelDisposition::KeepModels, true, 1),
        (CoreUninstallModelDisposition::RemoveModels, false, 1),
    ] {
        let plan = fixture_plan(disposition);
        let (coordinator, events) = coordinator(PreflightOutcome::Ready(plan.clone()), None, None);
        let result = coordinator
            .uninstall(&CoreUninstallRequest::new(
                CoreUninstallConfirmation::Confirmed,
                disposition,
            ))
            .expect("uninstall");

        assert!(!result.replayed());
        assert_eq!(result.receipt().plan_id(), plan.plan_id());
        assert_eq!(result.receipt(), &completed_receipt(&plan));
        assert_eq!(result.receipt().models_preserved(), models_preserved);
        assert_eq!(
            result
                .receipt()
                .target_count(CoreUninstallTargetKind::RuntimeInstallation),
            retained_runtime_count
        );
        assert_eq!(
            result
                .receipt()
                .target_count(CoreUninstallTargetKind::ManagedContainer),
            1
        );
        assert_eq!(result.receipt().boundaries().len(), 7);
        result.receipt().validate().expect("receipt");
        assert_eq!(history(&events), complete_history());
    }
}

// Proves declined confirmation and rejected ownership preflight perform no mutation.
#[test]
fn confirmation_and_preflight_rejections_stop_before_the_first_mutation() {
    let plan = fixture_plan(CoreUninstallModelDisposition::KeepModels);
    let (declined, declined_events) = coordinator(PreflightOutcome::Ready(plan), None, None);
    assert_eq!(
        declined.uninstall(&CoreUninstallRequest::new(
            CoreUninstallConfirmation::Declined,
            CoreUninstallModelDisposition::KeepModels,
        )),
        Err(CoreUninstallError::ConfirmationRequired)
    );
    assert!(history(&declined_events).is_empty());

    let (rejected, rejected_events) = coordinator(PreflightOutcome::Rejected, None, None);
    assert_eq!(
        rejected.uninstall(&CoreUninstallRequest::new(
            CoreUninstallConfirmation::Confirmed,
            CoreUninstallModelDisposition::KeepModels,
        )),
        Err(CoreUninstallError::PreflightRejected)
    );
    assert_eq!(
        history(&rejected_events),
        vec![
            UninstallEvent::BarrierBegin,
            UninstallEvent::Preflight,
            UninstallEvent::BarrierCancel,
        ]
    );
}

// Proves an ambiguous durable-plan publication never releases the matching Node lease.
#[test]
fn ambiguous_plan_publication_preserves_the_mutation_lease() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(AmbiguousPlanPublicationBarrierMock {
        recovery_calls: Mutex::new(0),
        cancel_calls: Mutex::new(0),
    });
    let preflight = Arc::new(PreflightMock {
        outcome: PreflightOutcome::Ready(fixture_plan(CoreUninstallModelDisposition::KeepModels)),
        events: events.clone(),
    });
    let boundaries = Arc::new(BoundaryMock {
        failure: None,
        invalid_receipt: None,
        events,
    });
    let coordinator = CoreUninstallCoordinator::new(
        barrier.clone(),
        preflight,
        boundaries.clone(),
        boundaries.clone(),
        boundaries.clone(),
        boundaries.clone(),
        boundaries.clone(),
        boundaries.clone(),
        boundaries,
    );

    assert_eq!(
        coordinator.uninstall(&CoreUninstallRequest::new(
            CoreUninstallConfirmation::Confirmed,
            CoreUninstallModelDisposition::KeepModels,
        )),
        Err(CoreUninstallError::OperationConflict)
    );
    assert_eq!(
        *barrier.cancel_calls.lock().expect("cancel calls"),
        0,
        "an unknown publication outcome must preserve the lease for recovery"
    );
}

// Proves every external failure stops at its exact boundary and never calls a later port.
#[test]
fn external_failure_table_stops_at_the_exact_irreversible_boundary() {
    let cases = std::iter::once(CoreUninstallBoundary::Preflight)
        .chain(MUTATION_ORDER)
        .collect::<Vec<_>>();
    for failure in cases {
        let plan = fixture_plan(CoreUninstallModelDisposition::RemoveModels);
        let outcome = if failure == CoreUninstallBoundary::Preflight {
            PreflightOutcome::Rejected
        } else {
            PreflightOutcome::Ready(plan)
        };
        let port_failure = (failure != CoreUninstallBoundary::Preflight).then_some(failure);
        let (coordinator, events) = coordinator(outcome, port_failure, None);
        let result = coordinator.uninstall(&CoreUninstallRequest::new(
            CoreUninstallConfirmation::Confirmed,
            CoreUninstallModelDisposition::RemoveModels,
        ));
        let expected_error = if failure == CoreUninstallBoundary::Preflight {
            CoreUninstallError::PreflightRejected
        } else {
            CoreUninstallError::BoundaryFailed(failure)
        };
        assert_eq!(result, Err(expected_error), "failure={failure:?}");

        let mut expected_events = vec![UninstallEvent::BarrierBegin, UninstallEvent::Preflight];
        if let Some(index) = MUTATION_ORDER
            .iter()
            .position(|boundary| *boundary == failure)
        {
            expected_events.extend(
                MUTATION_ORDER[..=index]
                    .iter()
                    .copied()
                    .map(UninstallEvent::Boundary),
            );
        }
        if failure == CoreUninstallBoundary::Preflight {
            expected_events.push(UninstallEvent::BarrierCancel);
        }
        assert_eq!(history(&events), expected_events, "failure={failure:?}");
    }
}

// Proves an already completed exact request returns its original receipt without new teardown.
#[test]
fn terminal_replay_is_idempotent_and_does_not_reenter_mutation_ports() {
    let plan = fixture_plan(CoreUninstallModelDisposition::KeepModels);
    let receipt = completed_receipt(&plan);
    let (coordinator, events) =
        coordinator(PreflightOutcome::Replayed(receipt.clone()), None, None);
    let result = coordinator
        .uninstall(&CoreUninstallRequest::new(
            CoreUninstallConfirmation::Confirmed,
            CoreUninstallModelDisposition::KeepModels,
        ))
        .expect("replay");

    assert!(result.replayed());
    assert_eq!(result.receipt(), &receipt);
    assert_eq!(
        history(&events),
        vec![
            UninstallEvent::BarrierBegin,
            UninstallEvent::Preflight,
            UninstallEvent::BarrierCancel,
        ]
    );
}

// Proves a foreign boundary receipt cannot advance teardown into a later destructive port.
#[test]
fn foreign_boundary_receipt_is_rejected_before_the_next_port() {
    let plan = fixture_plan(CoreUninstallModelDisposition::KeepModels);
    let (coordinator, events) = coordinator(
        PreflightOutcome::Ready(plan),
        None,
        Some(CoreUninstallBoundary::Workloads),
    );
    assert_eq!(
        coordinator.uninstall(&CoreUninstallRequest::new(
            CoreUninstallConfirmation::Confirmed,
            CoreUninstallModelDisposition::KeepModels,
        )),
        Err(CoreUninstallError::InvalidReceipt(
            CoreUninstallBoundary::Workloads
        ))
    );
    assert_eq!(
        history(&events),
        vec![
            UninstallEvent::BarrierBegin,
            UninstallEvent::Preflight,
            UninstallEvent::Boundary(CoreUninstallBoundary::BenchmarkExit),
            UninstallEvent::Boundary(CoreUninstallBoundary::PublicExposure),
            UninstallEvent::Boundary(CoreUninstallBoundary::Workloads),
        ]
    );
}

// Proves ambiguous target identity is rejected while constructing the all-target plan.
#[test]
fn preflight_plan_rejects_duplicate_targets_before_orchestration() {
    let duplicate = target(
        CoreUninstallTargetKind::ManagedContainer,
        "duplicate:target",
        '1',
    );
    assert_eq!(
        CoreUninstallPlan::new(
            digest('f'),
            CoreUninstallModelDisposition::RemoveModels,
            Duration::from_secs(30),
            vec![
                duplicate,
                target(
                    CoreUninstallTargetKind::ManagedImage,
                    "duplicate:target",
                    '2',
                ),
            ],
        ),
        Err(CoreUninstallError::InvalidPlan)
    );
}

// Accepts RuntimeManager-owned selective cleanup but rejects direct model-root deletion.
#[test]
fn preservation_plan_rejects_every_model_byte_deletion_target() {
    assert!(CoreUninstallPlan::new(
        digest('f'),
        CoreUninstallModelDisposition::KeepModels,
        Duration::from_secs(30),
        vec![target(
            CoreUninstallTargetKind::RuntimeInstallation,
            "preserved:runtime",
            '1'
        )],
    )
    .is_ok());
    assert_eq!(
        CoreUninstallPlan::new(
            digest('f'),
            CoreUninstallModelDisposition::KeepModels,
            Duration::from_secs(30),
            vec![target(
                CoreUninstallTargetKind::ModelRoot,
                "preserved:model",
                '1'
            )],
        ),
        Err(CoreUninstallError::InvalidPlan)
    );
}

// Projects keep/remove policy, first-boundary failures, timeout, and replay through the CLI port.
#[test]
fn application_cli_adapter_is_truthful_for_policy_failures_and_replay() {
    for (disposition, native, preserved, removed_targets) in [
        (
            CoreUninstallModelDisposition::KeepModels,
            NativeUninstallModelDisposition::KeepModels,
            true,
            11,
        ),
        (
            CoreUninstallModelDisposition::RemoveModels,
            NativeUninstallModelDisposition::RemoveModels,
            false,
            12,
        ),
    ] {
        let plan = fixture_plan(disposition);
        let (coordinator, events) = coordinator(PreflightOutcome::Ready(plan), None, None);
        let adapter = ApplicationCoreCliUninstall::new(Arc::new(coordinator));
        let mut progress = ProgressMock;
        let completed = adapter
            .uninstall(native, &mut progress)
            .expect("native uninstall");
        assert_eq!(completed.models_preserved(), preserved);
        assert_eq!(completed.removed_targets(), removed_targets);
        assert_eq!(completed.removed_containers(), 1);
        assert_eq!(completed.removed_images(), 1);
        assert!(!completed.replayed());
        let completed_history = history(&events);

        let replay = adapter
            .uninstall(native, &mut progress)
            .expect("native replay");
        assert!(replay.replayed());
        assert_eq!(replay.receipt_id(), completed.receipt_id());
        assert_eq!(history(&events), completed_history);
    }

    for (failure, expected_code) in [
        (
            CoreUninstallBoundary::Preflight,
            "uninstall.preflight_rejected",
        ),
        (
            CoreUninstallBoundary::BenchmarkExit,
            "uninstall.benchmark_timeout",
        ),
    ] {
        let outcome = if failure == CoreUninstallBoundary::Preflight {
            PreflightOutcome::Rejected
        } else {
            PreflightOutcome::Ready(fixture_plan(CoreUninstallModelDisposition::RemoveModels))
        };
        let boundary_failure = (failure != CoreUninstallBoundary::Preflight).then_some(failure);
        let (coordinator, events) = coordinator(outcome, boundary_failure, None);
        let adapter = ApplicationCoreCliUninstall::new(Arc::new(coordinator));
        let error = adapter
            .uninstall(
                NativeUninstallModelDisposition::RemoveModels,
                &mut ProgressMock,
            )
            .expect_err("boundary failure");
        assert_eq!(error.code(), expected_code);
        let expected = if failure == CoreUninstallBoundary::Preflight {
            vec![
                UninstallEvent::BarrierBegin,
                UninstallEvent::Preflight,
                UninstallEvent::BarrierCancel,
            ]
        } else {
            vec![
                UninstallEvent::BarrierBegin,
                UninstallEvent::Preflight,
                UninstallEvent::Boundary(CoreUninstallBoundary::BenchmarkExit),
            ]
        };
        assert_eq!(history(&events), expected);
    }
}
