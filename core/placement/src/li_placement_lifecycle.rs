// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use li_core_interface::{
    EndpointOwnership, EntityTimestamps, FailureDescription, ModelServiceDesiredState, Placement,
    PlacementEndpoint, PlacementGroup, PlacementGroupId, PlacementGroupState, PlacementId,
    PlacementState, ResourceLease, ResourceLeaseState, TechnicalName, UnixMilliseconds,
};

use crate::{
    allocate, li_placement_allocator::bound_node_order, PlacementAdmissionPolicy, PlacementChange,
    PlacementClock, PlacementError, PlacementEvent, PlacementExecutor, PlacementIdentityProvider,
    PlacementObservation, PlacementRecord, PlacementRequest, PlacementStore,
    VersionedPlacementRecord,
};

// Identifies one shell-free task action executed across a phase.
#[derive(Clone, Copy, Eq, PartialEq)]
enum PlacementAction {
    Stop,
    Remove,
}

// Owns allocation, execution, persistence, identity, and time capabilities.
pub(crate) struct PlacementLifecycle {
    store: Arc<dyn PlacementStore>,
    executor: Arc<dyn PlacementExecutor>,
    identity: Arc<dyn PlacementIdentityProvider>,
    clock: Arc<dyn PlacementClock>,
    admission: PlacementAdmissionPolicy,
}

impl PlacementLifecycle {
    // Creates one complete placement-group lifecycle owner.
    pub(crate) fn new(
        store: Arc<dyn PlacementStore>,
        executor: Arc<dyn PlacementExecutor>,
        identity: Arc<dyn PlacementIdentityProvider>,
        clock: Arc<dyn PlacementClock>,
        admission: PlacementAdmissionPolicy,
    ) -> Self {
        Self {
            store,
            executor,
            identity,
            clock,
            admission,
        }
    }

    // Allocates, stages, and persists one complete placement group.
    pub(crate) fn stage(
        &self,
        request: PlacementRequest,
    ) -> Result<PlacementChange, PlacementError> {
        if let Some(current) = self.store.read(request.placement_group_id())? {
            if current.record().group().state() == PlacementGroupState::Staged
                && placement_record_matches_request(current.record(), &request)?
            {
                return Ok(change(current, PlacementEventKind::Staged));
            }
            return Err(PlacementError::StoreConflict);
        }
        let mut current = allocate(
            &request,
            self.store.as_ref(),
            self.identity.as_ref(),
            self.clock.as_ref(),
            self.admission,
        )?;
        let mut completed = Vec::new();
        for index in 0..current.record().placements().len() {
            let placement = current.record().placements()[index].clone();
            match self.executor.stage(&placement) {
                Ok(plan_identity) => {
                    let transition = (|| {
                        let now = self.clock.now()?;
                        let mut placements = current.record().placements().to_vec();
                        placements[index] =
                            placement_with_state(&placement, PlacementState::Staged, None, now)?;
                        let record = record_with(
                            current.record(),
                            placements,
                            current.record().leases().to_vec(),
                            PlacementGroupState::Staging,
                            ModelServiceDesiredState::Running,
                            None,
                            None,
                            now,
                        )?
                        .recording_launch_plan_identity(
                            placement.placement_id().clone(),
                            plan_identity.clone(),
                        )?;
                        match self.store.replace(record, current.revision()) {
                            Ok(stored) => Ok(stored),
                            Err(error) => {
                                let replay = self
                                    .store
                                    .read(current.record().group().placement_group_id())?;
                                if let Some(replay) = replay {
                                    if replay
                                        .record()
                                        .launch_plan_identity(placement.placement_id())
                                        == Some(&plan_identity)
                                    {
                                        return Ok(replay);
                                    }
                                }
                                Err(error)
                            }
                        }
                    })();
                    match transition {
                        Ok(stored) => {
                            completed.push(index);
                            current = stored;
                        }
                        Err(error) => {
                            let _ = self.executor.remove(&placement);
                            return Err(error);
                        }
                    }
                }
                Err(_) => {
                    return self.stage_failed(current, index, completed);
                }
            }
        }
        let now = self.clock.now()?;
        let record = record_with(
            current.record(),
            current.record().placements().to_vec(),
            leases_with_uniform_state(
                current.record().leases(),
                ResourceLeaseState::Reserved,
                now,
            )?,
            PlacementGroupState::Staged,
            ModelServiceDesiredState::Running,
            None,
            None,
            now,
        )?;
        let stored = self.replace_resolving_uncertainty(record, current.revision())?;
        Ok(change(stored, PlacementEventKind::Staged))
    }

    // Starts every runtime-declared phase and publishes one complete endpoint.
    pub(crate) fn start(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        let current = self.required_record(placement_group_id)?;
        if current.record().group().state() == PlacementGroupState::Running {
            return Ok(change(current, PlacementEventKind::Running));
        }
        if !matches!(
            current.record().group().state(),
            PlacementGroupState::Staged | PlacementGroupState::Stopped
        ) {
            return Err(PlacementError::InvalidTransition);
        }
        self.start_record(current, false, PlacementEventKind::Running)
    }

    // Stops every placement in reverse phase order and retains reserved resources.
    pub(crate) fn stop(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        let current = self.required_record(placement_group_id)?;
        if current.record().group().state() == PlacementGroupState::Stopped {
            return Ok(change(current, PlacementEventKind::Stopped));
        }
        if current.record().group().state() == PlacementGroupState::Removed {
            return Err(PlacementError::InvalidTransition);
        }
        if current
            .record()
            .leases()
            .iter()
            .any(|lease| lease.state() == ResourceLeaseState::Released)
        {
            return Err(PlacementError::InvalidTransition);
        }
        self.stop_record(
            current,
            ModelServiceDesiredState::Stopped,
            PlacementEventKind::Stopped,
        )
    }

    // Recovers one failed atomic group and optionally acknowledges native protection trips.
    pub(crate) fn recover(
        &self,
        placement_group_id: &PlacementGroupId,
        acknowledge_protection_trips: bool,
    ) -> Result<PlacementChange, PlacementError> {
        let current = self.required_record(placement_group_id)?;
        if current.record().group().state() != PlacementGroupState::Failed
            || current
                .record()
                .leases()
                .iter()
                .any(|lease| lease.state() == ResourceLeaseState::Released)
        {
            return Err(PlacementError::InvalidTransition);
        }
        let stopped = self.stop_record(
            current,
            ModelServiceDesiredState::Running,
            PlacementEventKind::Stopped,
        )?;
        if stopped.record().record().group().state() != PlacementGroupState::Stopped {
            return Ok(stopped);
        }
        self.start_record(
            stopped.record().clone(),
            acknowledge_protection_trips,
            PlacementEventKind::Recovered,
        )
    }

    // Removes every placement and releases only this group's exact resources.
    pub(crate) fn remove(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        let mut current = self.required_record(placement_group_id)?;
        if current.record().group().state() == PlacementGroupState::Removed {
            return Ok(change(current, PlacementEventKind::Removed));
        }
        if matches!(
            current.record().group().state(),
            PlacementGroupState::Running
                | PlacementGroupState::Starting
                | PlacementGroupState::Recovering
                | PlacementGroupState::Degraded
        ) {
            let stopped = self.stop_record(
                current,
                ModelServiceDesiredState::Removed,
                PlacementEventKind::Stopped,
            )?;
            if stopped.record().record().group().state() != PlacementGroupState::Stopped {
                return Ok(stopped);
            }
            current = stopped.record().clone();
        }
        let now = self.clock.now()?;
        let placements = current
            .record()
            .placements()
            .iter()
            .map(|placement| {
                if placement.state() == PlacementState::Removed {
                    Ok(placement.clone())
                } else {
                    placement_with_state(placement, PlacementState::Removing, None, now)
                }
            })
            .collect::<Result<Vec<_>, PlacementError>>()?;
        let record = record_with(
            current.record(),
            placements,
            leases_preserving_released(
                current.record().leases(),
                ResourceLeaseState::Draining,
                now,
            )?,
            PlacementGroupState::Removing,
            ModelServiceDesiredState::Removed,
            None,
            None,
            now,
        )?;
        current = self.store.replace(record, current.revision())?;
        let (succeeded, failed) =
            self.run_void_phases(current.record(), PlacementAction::Remove, true);
        let now = self.clock.now()?;
        let failure = if failed.is_empty() {
            None
        } else {
            Some(failure(
                "placement_remove_failed",
                "Placement-group removal failed",
            )?)
        };
        let placements = action_placements(
            current.record().placements(),
            &succeeded,
            &failed,
            PlacementState::Removed,
            now,
            failure.as_ref(),
        )?;
        let leases = leases_for_action(
            current.record().leases(),
            &succeeded,
            ResourceLeaseState::Released,
            ResourceLeaseState::Draining,
            now,
        )?;
        let state = if failed.is_empty() {
            PlacementGroupState::Removed
        } else {
            PlacementGroupState::Failed
        };
        let record = record_with(
            current.record(),
            placements,
            leases,
            state,
            ModelServiceDesiredState::Removed,
            None,
            failure,
            now,
        )?;
        let stored = self.replace_resolving_uncertainty(record, current.revision())?;
        Ok(change(
            stored,
            if failed.is_empty() {
                PlacementEventKind::Removed
            } else {
                PlacementEventKind::Failed
            },
        ))
    }

    // Reconciles current node observations into one atomic group snapshot.
    pub(crate) fn reconcile(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        let current = self.required_record(placement_group_id)?;
        if current.record().group().state() == PlacementGroupState::Removed {
            return Ok(change(current, PlacementEventKind::Observed));
        }
        let observations = self.run_observation_phase(current.record().placements());
        if observations_match(current.record(), &observations) {
            return Ok(change(current, PlacementEventKind::Observed));
        }
        let now = self.clock.now()?;
        let mut endpoint = None;
        let mut placements = Vec::with_capacity(current.record().placements().len());
        let mut all_running = true;
        for (placement, observation) in current.record().placements().iter().zip(observations) {
            match observation {
                Ok(observation) => {
                    let valid_endpoint = validated_endpoint(
                        placement,
                        observation.endpoint().cloned(),
                        current.record().group().capacity(),
                    );
                    let tripped = observation.protection_trip_latched();
                    let state = if tripped {
                        all_running = false;
                        PlacementState::Failed
                    } else {
                        if observation.state() != PlacementState::Running {
                            all_running = false;
                        }
                        observation.state()
                    };
                    match valid_endpoint {
                        Ok(value)
                            if placement.assignment().endpoint_ownership()
                                == EndpointOwnership::Owner
                                && state == PlacementState::Running =>
                        {
                            endpoint = value
                        }
                        Ok(_) => {}
                        Err(_) => all_running = false,
                    }
                    let placement_failure = if tripped || state == PlacementState::Failed {
                        Some(failure(
                            "placement_observation_failed",
                            "Placement observation requires recovery",
                        )?)
                    } else {
                        None
                    };
                    placements.push(placement_with_state(
                        placement,
                        state,
                        placement_failure,
                        now,
                    )?);
                }
                Err(_) => {
                    all_running = false;
                    placements.push(placement_with_state(
                        placement,
                        PlacementState::Unreachable,
                        Some(failure(
                            "placement_unreachable",
                            "Placement node is unreachable",
                        )?),
                        now,
                    )?);
                }
            }
        }
        if endpoint.is_none() {
            all_running = false;
        }
        let group_failure = if all_running {
            None
        } else {
            Some(failure(
                "placement_group_incomplete",
                "Placement group is not completely available",
            )?)
        };
        let group_state = if all_running {
            PlacementGroupState::Running
        } else {
            PlacementGroupState::Failed
        };
        let lease_states: HashMap<PlacementId, ResourceLeaseState> = placements
            .iter()
            .map(|placement| {
                (
                    placement.placement_id().clone(),
                    if placement.state() == PlacementState::Running {
                        ResourceLeaseState::Active
                    } else {
                        ResourceLeaseState::Draining
                    },
                )
            })
            .collect();
        let leases = leases_with_states(current.record().leases(), &lease_states, now)?;
        let record = record_with(
            current.record(),
            placements,
            leases,
            group_state,
            current.record().group().desired_state(),
            endpoint,
            group_failure,
            now,
        )?;
        let stored = self.replace_resolving_uncertainty(record, current.revision())?;
        Ok(change(stored, PlacementEventKind::Observed))
    }

    // Returns one required placement aggregate from the injected store.
    fn required_record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        self.store
            .read(placement_group_id)?
            .ok_or(PlacementError::GroupNotFound)
    }

    // Resolves an ambiguous final commit by exact replay or one same-revision retry.
    fn replace_resolving_uncertainty(
        &self,
        record: PlacementRecord,
        expected_revision: u64,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        match self.store.replace(record.clone(), expected_revision) {
            Ok(stored) => Ok(stored),
            Err(first_error) => match self.store.read(record.group().placement_group_id()) {
                Ok(Some(stored)) if stored.record() == &record => Ok(stored),
                Ok(Some(stored)) if stored.revision() == expected_revision => self
                    .store
                    .replace(record, expected_revision)
                    .map_err(|_| first_error),
                Ok(_) | Err(_) => Err(first_error),
            },
        }
    }

    // Persists staging failure after symmetric removal of every attempted task.
    fn stage_failed(
        &self,
        mut current: VersionedPlacementRecord,
        failing_index: usize,
        mut completed: Vec<usize>,
    ) -> Result<PlacementChange, PlacementError> {
        completed.push(failing_index);
        let mut cleanup_failed = Vec::new();
        for index in completed.iter().rev().copied() {
            if self
                .executor
                .remove(&current.record().placements()[index])
                .is_err()
            {
                cleanup_failed.push(index);
            }
        }
        let now = self.clock.now()?;
        let lifecycle_failure = failure(
            if cleanup_failed.is_empty() {
                "placement_staging_failed"
            } else {
                "placement_stage_rollback_failed"
            },
            if cleanup_failed.is_empty() {
                "Placement-group staging failed"
            } else {
                "Placement-group staging rollback failed"
            },
        )?;
        let placements = current
            .record()
            .placements()
            .iter()
            .enumerate()
            .map(|(index, placement)| {
                let state = if cleanup_failed.contains(&index) {
                    PlacementState::Failed
                } else if completed.contains(&index) {
                    PlacementState::Removed
                } else {
                    PlacementState::Failed
                };
                placement_with_state(
                    placement,
                    state,
                    (state == PlacementState::Failed).then(|| lifecycle_failure.clone()),
                    now,
                )
            })
            .collect::<Result<Vec<_>, PlacementError>>()?;
        let successful_cleanup: Vec<PlacementId> = current
            .record()
            .placements()
            .iter()
            .enumerate()
            .filter(|(index, _)| !cleanup_failed.contains(index))
            .map(|(_, placement)| placement.placement_id().clone())
            .collect();
        let leases = leases_for_action(
            current.record().leases(),
            &successful_cleanup,
            ResourceLeaseState::Released,
            ResourceLeaseState::Draining,
            now,
        )?;
        let record = record_with(
            current.record(),
            placements,
            leases,
            PlacementGroupState::Failed,
            ModelServiceDesiredState::Stopped,
            None,
            Some(lifecycle_failure),
            now,
        )?;
        current = self.store.replace(record, current.revision())?;
        Ok(change(current, PlacementEventKind::Failed))
    }

    // Starts one existing stopped or staged record through every declared phase.
    fn start_record(
        &self,
        mut current: VersionedPlacementRecord,
        acknowledge_protection_trips: bool,
        success_event: PlacementEventKind,
    ) -> Result<PlacementChange, PlacementError> {
        let now = self.clock.now()?;
        let placements = current
            .record()
            .placements()
            .iter()
            .map(|placement| placement_with_state(placement, PlacementState::Starting, None, now))
            .collect::<Result<Vec<_>, PlacementError>>()?;
        let state = if success_event == PlacementEventKind::Recovered {
            PlacementGroupState::Recovering
        } else {
            PlacementGroupState::Starting
        };
        let record = record_with(
            current.record(),
            placements,
            leases_with_uniform_state(
                current.record().leases(),
                ResourceLeaseState::Reserved,
                now,
            )?,
            state,
            ModelServiceDesiredState::Running,
            None,
            None,
            now,
        )?;
        current = self.store.replace(record, current.revision())?;
        let mut endpoint = None;
        let mut started = Vec::new();
        for phase in phase_indices(current.record(), false)? {
            let results = self.run_start_phase(
                current.record().placements(),
                &phase,
                acknowledge_protection_trips,
            );
            let mut failed = false;
            for (index, result) in results {
                match result.and_then(|value| {
                    validated_endpoint(
                        &current.record().placements()[index],
                        value,
                        current.record().group().capacity(),
                    )
                }) {
                    Ok(value) => {
                        if value.is_some() {
                            endpoint = value;
                        }
                        started.push(index);
                    }
                    Err(_) => failed = true,
                }
            }
            if failed {
                return self.start_failed(current, &started);
            }
        }
        if endpoint.is_none() {
            return self.start_failed(current, &started);
        }
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(_) => return self.start_failed(current, &started),
        };
        let placements = current
            .record()
            .placements()
            .iter()
            .map(|placement| placement_with_state(placement, PlacementState::Running, None, now))
            .collect::<Result<Vec<_>, PlacementError>>()?;
        let record = match record_with(
            current.record(),
            placements,
            leases_with_uniform_state(current.record().leases(), ResourceLeaseState::Active, now)?,
            PlacementGroupState::Running,
            ModelServiceDesiredState::Running,
            endpoint,
            None,
            now,
        ) {
            Ok(record) => record,
            Err(_) => return self.start_failed(current, &started),
        };
        match self.replace_resolving_uncertainty(record, current.revision()) {
            Ok(stored) => Ok(change(stored, success_event)),
            Err(_) => self.start_failed(current, &started),
        }
    }

    // Preempts the complete group after any task start or endpoint failure.
    fn start_failed(
        &self,
        current: VersionedPlacementRecord,
        _started: &[usize],
    ) -> Result<PlacementChange, PlacementError> {
        let (stopped, stop_failed) =
            self.run_void_phases(current.record(), PlacementAction::Stop, true);
        let now = self.clock.now()?;
        let lifecycle_failure = failure(
            if stop_failed.is_empty() {
                "placement_start_failed"
            } else {
                "placement_start_rollback_failed"
            },
            if stop_failed.is_empty() {
                "Placement-group start failed"
            } else {
                "Placement-group start rollback failed"
            },
        )?;
        let placements = action_placements(
            current.record().placements(),
            &stopped,
            &stop_failed,
            PlacementState::Stopped,
            now,
            Some(&lifecycle_failure),
        )?;
        let leases = leases_for_action(
            current.record().leases(),
            &stopped,
            ResourceLeaseState::Reserved,
            ResourceLeaseState::Draining,
            now,
        )?;
        let record = record_with(
            current.record(),
            placements,
            leases,
            PlacementGroupState::Failed,
            ModelServiceDesiredState::Stopped,
            None,
            Some(lifecycle_failure),
            now,
        )?;
        let stored = self.replace_resolving_uncertainty(record, current.revision())?;
        Ok(change(stored, PlacementEventKind::Failed))
    }

    // Stops one existing aggregate and preserves exact assignments as reservations.
    fn stop_record(
        &self,
        mut current: VersionedPlacementRecord,
        desired_state: ModelServiceDesiredState,
        success_event: PlacementEventKind,
    ) -> Result<PlacementChange, PlacementError> {
        let now = self.clock.now()?;
        let placements = current
            .record()
            .placements()
            .iter()
            .map(|placement| placement_with_state(placement, PlacementState::Stopping, None, now))
            .collect::<Result<Vec<_>, PlacementError>>()?;
        let record = record_with(
            current.record(),
            placements,
            leases_with_uniform_state(
                current.record().leases(),
                ResourceLeaseState::Draining,
                now,
            )?,
            PlacementGroupState::Stopping,
            desired_state,
            None,
            None,
            now,
        )?;
        current = self.store.replace(record, current.revision())?;
        let (stopped, failed) = self.run_void_phases(current.record(), PlacementAction::Stop, true);
        let now = self.clock.now()?;
        let lifecycle_failure = if failed.is_empty() {
            None
        } else {
            Some(failure(
                "placement_stop_failed",
                "Placement-group stop failed",
            )?)
        };
        let placements = action_placements(
            current.record().placements(),
            &stopped,
            &failed,
            PlacementState::Stopped,
            now,
            lifecycle_failure.as_ref(),
        )?;
        let leases = leases_for_action(
            current.record().leases(),
            &stopped,
            ResourceLeaseState::Reserved,
            ResourceLeaseState::Draining,
            now,
        )?;
        let state = if failed.is_empty() {
            PlacementGroupState::Stopped
        } else {
            PlacementGroupState::Failed
        };
        let record = record_with(
            current.record(),
            placements,
            leases,
            state,
            desired_state,
            None,
            lifecycle_failure,
            now,
        )?;
        let stored = self.replace_resolving_uncertainty(record, current.revision())?;
        Ok(change(
            stored,
            if failed.is_empty() {
                success_event
            } else {
                PlacementEventKind::Failed
            },
        ))
    }

    // Starts every placement in one phase concurrently and returns stable index order.
    fn run_start_phase(
        &self,
        placements: &[Placement],
        indices: &[usize],
        acknowledge_protection_trips: bool,
    ) -> Vec<(usize, Result<Option<PlacementEndpoint>, PlacementError>)> {
        let mut results = thread::scope(|scope| {
            let handles = indices
                .iter()
                .copied()
                .map(|index| {
                    let executor = self.executor.clone();
                    let placement = placements[index].clone();
                    (
                        index,
                        scope.spawn(move || {
                            executor.start(&placement, acknowledge_protection_trips)
                        }),
                    )
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|(index, handle)| {
                    (
                        index,
                        handle
                            .join()
                            .unwrap_or(Err(PlacementError::ExecutionUnavailable)),
                    )
                })
                .collect::<Vec<_>>()
        });
        results.sort_by_key(|(index, _)| *index);
        results
    }

    // Executes stop or removal across every phase and returns stable result sets.
    fn run_void_phases(
        &self,
        record: &PlacementRecord,
        action: PlacementAction,
        reverse: bool,
    ) -> (Vec<PlacementId>, Vec<PlacementId>) {
        let mut succeeded = Vec::new();
        let mut failed = Vec::new();
        let Ok(phases) = phase_indices(record, reverse) else {
            return (succeeded, record.group().placement_ids().to_vec());
        };
        for phase in phases {
            let mut pending = Vec::new();
            for index in phase {
                if action == PlacementAction::Remove
                    && record.placements()[index].state() == PlacementState::Removed
                {
                    succeeded.push(record.placements()[index].placement_id().clone());
                } else {
                    pending.push(index);
                }
            }
            let mut results = thread::scope(|scope| {
                let handles = pending
                    .iter()
                    .copied()
                    .map(|index| {
                        let executor = self.executor.clone();
                        let placement = record.placements()[index].clone();
                        (
                            index,
                            scope.spawn(move || match action {
                                PlacementAction::Stop => executor.stop(&placement),
                                PlacementAction::Remove => executor.remove(&placement),
                            }),
                        )
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|(index, handle)| {
                        (
                            index,
                            handle
                                .join()
                                .unwrap_or(Err(PlacementError::ExecutionUnavailable)),
                        )
                    })
                    .collect::<Vec<_>>()
            });
            results.sort_by_key(|(index, _)| *index);
            for (index, result) in results {
                if result.is_ok() {
                    succeeded.push(record.placements()[index].placement_id().clone());
                } else {
                    failed.push(record.placements()[index].placement_id().clone());
                }
            }
        }
        (succeeded, failed)
    }

    // Observes every placement concurrently without allowing one node to hide another.
    fn run_observation_phase(
        &self,
        placements: &[Placement],
    ) -> Vec<Result<PlacementObservation, PlacementError>> {
        thread::scope(|scope| {
            let handles = placements
                .iter()
                .cloned()
                .map(|placement| {
                    let executor = self.executor.clone();
                    scope.spawn(move || executor.observe(&placement))
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or(Err(PlacementError::ExecutionUnavailable))
                })
                .collect()
        })
    }
}

// Verifies one staged aggregate is the exact allocation of a replayed request.
fn placement_record_matches_request(
    record: &PlacementRecord,
    request: &PlacementRequest,
) -> Result<bool, PlacementError> {
    let group = record.group();
    if group.placement_group_id() != request.placement_group_id()
        || group.service_id() != request.service_id()
        || group.runtime() != request.runtime()
        || group.capacity() != request.capacity()
        || record.placements().len() != request.tasks().len()
    {
        return Ok(false);
    }
    let node_order = bound_node_order(request)?;
    for ((task, node_index), placement) in request
        .tasks()
        .iter()
        .zip(node_order)
        .zip(record.placements())
    {
        let node = &request.nodes()[node_index];
        let assignment = placement.assignment();
        let resources = assignment.resources();
        let ports = resources.ports();
        let expected_rdma_interface = request
            .capacity()
            .interconnect()
            .rdma_required()
            .then(|| node.rdma_interface())
            .flatten();
        let expected_endpoint_ownership = if task.task_id() == request.endpoint_task_id() {
            EndpointOwnership::Owner
        } else {
            EndpointOwnership::Participant
        };
        if assignment.task_id() != task.task_id()
            || assignment.node_id() != node.node_id()
            || assignment.runtime_installation_id() != node.runtime_installation_id()
            || assignment.hardware_observation_id() != node.hardware_observation_id()
            || assignment.hardware_boot_id() != node.boot_id()
            || assignment.hardware_observed_at() != node.observed_at()
            || assignment.address() != node.address()
            || assignment.endpoint_ownership() != expected_endpoint_ownership
            || resources.device_ids().len() != usize::from(task.device_count())
            || resources
                .device_ids()
                .iter()
                .any(|device_id| !node.device_ids().contains(device_id))
            || ports.count() != task.port_count()
            || ports.base() < node.ports().base()
            || ports.last() > node.ports().last()
            || resources.rdma_interface() != expected_rdma_interface
        {
            return Ok(false);
        }
    }
    let replayed_startup_order = record
        .startup_order()
        .iter()
        .map(|phase| {
            phase
                .iter()
                .map(|placement_id| {
                    record
                        .placements()
                        .iter()
                        .find(|placement| placement.placement_id() == placement_id)
                        .map(|placement| placement.assignment().task_id())
                        .ok_or(PlacementError::StoreConflict)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(replayed_startup_order
        .iter()
        .zip(request.startup_order())
        .all(|(replayed, expected)| {
            replayed.len() == expected.len()
                && replayed
                    .iter()
                    .zip(expected)
                    .all(|(replayed, expected)| *replayed == expected)
        })
        && replayed_startup_order.len() == request.startup_order().len())
}

// Identifies one internal event projection without duplicating public payloads.
#[derive(Clone, Copy, Eq, PartialEq)]
enum PlacementEventKind {
    Staged,
    Running,
    Stopped,
    Recovered,
    Removed,
    Failed,
    Observed,
}

// Creates one public event from the aggregate's exact identity.
fn change(record: VersionedPlacementRecord, kind: PlacementEventKind) -> PlacementChange {
    let placement_group_id = record.record().group().placement_group_id().clone();
    let event = match kind {
        PlacementEventKind::Staged => PlacementEvent::GroupStaged { placement_group_id },
        PlacementEventKind::Running => PlacementEvent::GroupRunning { placement_group_id },
        PlacementEventKind::Stopped => PlacementEvent::GroupStopped { placement_group_id },
        PlacementEventKind::Recovered => PlacementEvent::GroupRecovered { placement_group_id },
        PlacementEventKind::Removed => PlacementEvent::GroupRemoved { placement_group_id },
        PlacementEventKind::Failed => PlacementEvent::GroupFailed { placement_group_id },
        PlacementEventKind::Observed => PlacementEvent::GroupObserved { placement_group_id },
    };
    PlacementChange::new(record, event)
}

// Returns placement indices in runtime-declared forward or reverse phases.
fn phase_indices(
    record: &PlacementRecord,
    reverse: bool,
) -> Result<Vec<Vec<usize>>, PlacementError> {
    let by_identity: HashMap<&PlacementId, usize> = record
        .placements()
        .iter()
        .enumerate()
        .map(|(index, placement)| (placement.placement_id(), index))
        .collect();
    let source: Box<dyn Iterator<Item = &Vec<PlacementId>>> = if reverse {
        Box::new(record.startup_order().iter().rev())
    } else {
        Box::new(record.startup_order().iter())
    };
    source
        .map(|phase| {
            let identities: Box<dyn Iterator<Item = &PlacementId>> = if reverse {
                Box::new(phase.iter().rev())
            } else {
                Box::new(phase.iter())
            };
            identities
                .map(|placement_id| {
                    by_identity
                        .get(placement_id)
                        .copied()
                        .ok_or(PlacementError::InvalidRequest {
                            reason: "placement phase references an unknown placement",
                        })
                })
                .collect()
        })
        .collect()
}

// Rebuilds one immutable placement at a new lifecycle state.
fn placement_with_state(
    current: &Placement,
    state: PlacementState,
    failure: Option<FailureDescription>,
    updated_at: UnixMilliseconds,
) -> Result<Placement, PlacementError> {
    Placement::new(
        current.placement_id().clone(),
        current.placement_group_id().clone(),
        current.assignment().clone(),
        state,
        current.active_operation_id().cloned(),
        failure,
        EntityTimestamps::new(current.timestamps().created_at(), updated_at)
            .map_err(|_| PlacementError::ClockUnavailable)?,
    )
    .map_err(|_| PlacementError::InvalidTransition)
}

// Rebuilds one aggregate around explicit placement, lease, and group state.
#[allow(clippy::too_many_arguments)]
fn record_with(
    current: &PlacementRecord,
    placements: Vec<Placement>,
    leases: Vec<ResourceLease>,
    state: PlacementGroupState,
    desired_state: ModelServiceDesiredState,
    endpoint: Option<PlacementEndpoint>,
    failure: Option<FailureDescription>,
    updated_at: UnixMilliseconds,
) -> Result<PlacementRecord, PlacementError> {
    let group = PlacementGroup::new(
        current.group().placement_group_id().clone(),
        current.group().service_id().clone(),
        current.group().runtime().clone(),
        current.group().placement_ids().to_vec(),
        current.group().endpoint_placement_id().clone(),
        endpoint,
        current.group().capacity(),
        desired_state,
        state,
        failure,
        EntityTimestamps::new(current.group().timestamps().created_at(), updated_at)
            .map_err(|_| PlacementError::ClockUnavailable)?,
    )
    .map_err(|_| PlacementError::InvalidTransition)?;
    PlacementRecord::new(
        group,
        placements,
        leases,
        current.startup_order().to_vec(),
        current.launch_plan_identities().to_vec(),
    )
}

// Rebuilds every lease at one uniform lifecycle state.
fn leases_with_uniform_state(
    leases: &[ResourceLease],
    state: ResourceLeaseState,
    updated_at: UnixMilliseconds,
) -> Result<Vec<ResourceLease>, PlacementError> {
    leases
        .iter()
        .map(|lease| lease_with_state(lease, state, updated_at))
        .collect()
}

// Rebuilds every non-released lease without reacquiring completed cleanup.
fn leases_preserving_released(
    leases: &[ResourceLease],
    state: ResourceLeaseState,
    updated_at: UnixMilliseconds,
) -> Result<Vec<ResourceLease>, PlacementError> {
    leases
        .iter()
        .map(|lease| {
            if lease.state() == ResourceLeaseState::Released {
                Ok(lease.clone())
            } else {
                lease_with_state(lease, state, updated_at)
            }
        })
        .collect()
}

// Rebuilds leases from placement-specific lifecycle states.
fn leases_with_states(
    leases: &[ResourceLease],
    states: &HashMap<PlacementId, ResourceLeaseState>,
    updated_at: UnixMilliseconds,
) -> Result<Vec<ResourceLease>, PlacementError> {
    leases
        .iter()
        .map(|lease| {
            lease_with_state(
                lease,
                states
                    .get(lease.placement_id())
                    .copied()
                    .unwrap_or(lease.state()),
                updated_at,
            )
        })
        .collect()
}

// Rebuilds leases according to one completed action's success set.
fn leases_for_action(
    leases: &[ResourceLease],
    succeeded: &[PlacementId],
    succeeded_state: ResourceLeaseState,
    failed_state: ResourceLeaseState,
    updated_at: UnixMilliseconds,
) -> Result<Vec<ResourceLease>, PlacementError> {
    leases
        .iter()
        .map(|lease| {
            lease_with_state(
                lease,
                if succeeded.contains(lease.placement_id()) {
                    succeeded_state
                } else {
                    failed_state
                },
                updated_at,
            )
        })
        .collect()
}

// Rebuilds one immutable resource lease at a new lifecycle state.
fn lease_with_state(
    current: &ResourceLease,
    state: ResourceLeaseState,
    updated_at: UnixMilliseconds,
) -> Result<ResourceLease, PlacementError> {
    Ok(ResourceLease::new(
        current.lease_id().clone(),
        current.placement_id().clone(),
        current.node_id().clone(),
        current.resource().clone(),
        state,
        EntityTimestamps::new(current.timestamps().created_at(), updated_at)
            .map_err(|_| PlacementError::ClockUnavailable)?,
    ))
}

// Rebuilds placements from one action's exact success and failure sets.
fn action_placements(
    placements: &[Placement],
    succeeded: &[PlacementId],
    failed: &[PlacementId],
    success_state: PlacementState,
    updated_at: UnixMilliseconds,
    failure: Option<&FailureDescription>,
) -> Result<Vec<Placement>, PlacementError> {
    placements
        .iter()
        .map(|placement| {
            if succeeded.contains(placement.placement_id()) {
                placement_with_state(placement, success_state, None, updated_at)
            } else if failed.contains(placement.placement_id()) {
                placement_with_state(
                    placement,
                    PlacementState::Failed,
                    failure.cloned(),
                    updated_at,
                )
            } else {
                placement_with_state(
                    placement,
                    PlacementState::Failed,
                    failure.cloned(),
                    updated_at,
                )
            }
        })
        .collect()
}

// Validates that an executor publishes an endpoint only from the declared owner.
fn validated_endpoint(
    placement: &Placement,
    endpoint: Option<PlacementEndpoint>,
    capacity: li_core_interface::PlacementGroupCapacity,
) -> Result<Option<PlacementEndpoint>, PlacementError> {
    match placement.assignment().endpoint_ownership() {
        EndpointOwnership::Owner => {
            let endpoint = endpoint.ok_or(PlacementError::EndpointUnavailable)?;
            let ports = placement.assignment().resources().ports();
            if endpoint.placement_id() != placement.placement_id()
                || endpoint.node_id() != placement.assignment().node_id()
                || endpoint.address().host() != placement.assignment().address()
                || endpoint.address().port() < ports.base()
                || endpoint.address().port() > ports.last()
                || endpoint.max_active_requests() > capacity.max_active_requests()
                || endpoint.max_context_tokens() > capacity.max_context_tokens()
                || !endpoint.health().healthy()
            {
                return Err(PlacementError::EndpointUnavailable);
            }
            Ok(Some(endpoint))
        }
        EndpointOwnership::Participant if endpoint.is_none() => Ok(None),
        EndpointOwnership::Participant => Err(PlacementError::EndpointUnavailable),
    }
}

// Returns whether observations reproduce the current placement and endpoint state exactly.
fn observations_match(
    current: &PlacementRecord,
    observations: &[Result<PlacementObservation, PlacementError>],
) -> bool {
    if observations.len() != current.placements().len()
        || matches!(
            current.group().state(),
            PlacementGroupState::Staging
                | PlacementGroupState::Starting
                | PlacementGroupState::Stopping
                | PlacementGroupState::Recovering
                | PlacementGroupState::Removing
        )
    {
        return false;
    }
    current
        .placements()
        .iter()
        .zip(observations)
        .all(|(placement, observation)| {
            observation.as_ref().is_ok_and(|observation| {
                !observation.protection_trip_latched()
                    && observation.state() == placement.state()
                    && observation.endpoint()
                        == current
                            .group()
                            .endpoint()
                            .filter(|endpoint| endpoint.placement_id() == placement.placement_id())
            })
        })
}

// Creates one bounded stable lifecycle failure.
fn failure(code: &str, message: &str) -> Result<FailureDescription, PlacementError> {
    FailureDescription::new(
        TechnicalName::parse(code).map_err(|_| PlacementError::InvalidTransition)?,
        message,
    )
    .map_err(|_| PlacementError::InvalidTransition)
}
