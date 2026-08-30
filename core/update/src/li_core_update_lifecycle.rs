// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::FailureDescription;

use crate::{
    failure_description, update_identity, ActivatedCoreUpdate, CoreInstallation,
    CoreServiceSnapshot, CoreUpdateAdmissionProvider, CoreUpdateArtifactProvider, CoreUpdateChange,
    CoreUpdateDisposition, CoreUpdateError, CoreUpdateEvent, CoreUpdateNodeRole, CoreUpdatePhase,
    CoreUpdatePruneProvider, CoreUpdateRecord, CoreUpdateResidentService, CoreUpdateServiceContext,
    CoreUpdateServiceMode, CoreUpdateServicePlatform, CoreUpdateServiceProvider,
    CoreUpdateServiceSnapshotRecord, CoreUpdateServiceState, CoreUpdateStore, CoreUpdateStoreError,
    CoreVersion, VersionedCoreUpdateRecord,
};

const MAXIMUM_READINESS_TIMEOUT_MILLISECONDS: u64 = 300_000;
const MAXIMUM_STABLE_READINESS_OBSERVATIONS: u32 = 100;

// Supplies monotonic time and bounded waiting to the manager-owned completion policy.
pub trait CoreUpdateReadinessClock: Send + Sync {
    // Returns one monotonic millisecond observation.
    fn monotonic_milliseconds(&self) -> Result<u64, CoreUpdateError>;

    // Waits for at most one manager-selected readiness interval.
    fn wait(&self, milliseconds: u64) -> Result<(), CoreUpdateError>;
}

// Supplies process-monotonic readiness time and bounded native waits.
pub struct SystemCoreUpdateReadinessClock {
    origin: Instant,
}

impl SystemCoreUpdateReadinessClock {
    // Creates one monotonic clock whose values are meaningful only within this process.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemCoreUpdateReadinessClock {
    // Creates the ordinary process-monotonic readiness clock.
    fn default() -> Self {
        Self::new()
    }
}

impl CoreUpdateReadinessClock for SystemCoreUpdateReadinessClock {
    // Returns elapsed monotonic milliseconds without consulting wall-clock time.
    fn monotonic_milliseconds(&self) -> Result<u64, CoreUpdateError> {
        u64::try_from(self.origin.elapsed().as_millis()).map_err(|_| {
            CoreUpdateError::provider("readiness clock", "monotonic time exceeded its range")
        })
    }

    // Waits for one positive interval within the manager's global readiness bound.
    fn wait(&self, milliseconds: u64) -> Result<(), CoreUpdateError> {
        if milliseconds == 0 || milliseconds > MAXIMUM_READINESS_TIMEOUT_MILLISECONDS {
            return Err(CoreUpdateError::provider(
                "readiness clock",
                "wait interval is outside the readiness bound",
            ));
        }
        std::thread::sleep(Duration::from_millis(milliseconds));
        Ok(())
    }
}

// Defines one bounded consecutive-readiness requirement owned by CoreUpdateManager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreUpdateReadinessPolicy {
    timeout_milliseconds: u64,
    poll_milliseconds: u64,
    stable_observations: u32,
}

impl CoreUpdateReadinessPolicy {
    // Creates one bounded readiness policy suitable for the resident control plane.
    pub fn new(
        timeout_milliseconds: u64,
        poll_milliseconds: u64,
        stable_observations: u32,
    ) -> Result<Self, CoreUpdateError> {
        if timeout_milliseconds == 0
            || timeout_milliseconds > MAXIMUM_READINESS_TIMEOUT_MILLISECONDS
            || poll_milliseconds == 0
            || poll_milliseconds > timeout_milliseconds
            || stable_observations == 0
            || stable_observations > MAXIMUM_STABLE_READINESS_OBSERVATIONS
        {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core service readiness bounds are invalid",
            });
        }
        Ok(Self {
            timeout_milliseconds,
            poll_milliseconds,
            stable_observations,
        })
    }
}

// Owns CoreUpdateManager's service-set, role-mode, admission, and completion decisions.
struct CoreUpdateServiceLifecycle {
    provider: Arc<dyn CoreUpdateServiceProvider>,
    clock: Arc<dyn CoreUpdateReadinessClock>,
    readiness: CoreUpdateReadinessPolicy,
}

impl CoreUpdateServiceLifecycle {
    // Creates one manager-owned service lifecycle over facts and native mutation capabilities.
    const fn new(
        provider: Arc<dyn CoreUpdateServiceProvider>,
        clock: Arc<dyn CoreUpdateReadinessClock>,
        readiness: CoreUpdateReadinessPolicy,
    ) -> Self {
        Self {
            provider,
            clock,
            readiness,
        }
    }

    // Captures the exact admissible resident set once for restart-safe restoration.
    fn snapshot(
        &self,
        update_id: &li_core_interface::Sha256Digest,
        current: &CoreInstallation,
    ) -> Result<CoreServiceSnapshot, CoreUpdateError> {
        let context = self.provider.context()?;
        if let Some(existing) = self.provider.snapshot_record(update_id)? {
            validate_service_snapshot(&existing)?;
            if existing.update_id() != update_id
                || existing.current() != current
                || existing.context() != context
            {
                return Err(CoreUpdateError::InvalidContract {
                    reason: "Core service snapshot conflicts with its replay identity",
                });
            }
            return Ok(CoreServiceSnapshot::new(existing.receipt_id().clone()));
        }
        let mut services = Vec::new();
        for service in expected_services(context) {
            let state = self.provider.observe_service(service)?;
            if state.service() != service {
                return Err(CoreUpdateError::InvalidContract {
                    reason: "native service observation returned the wrong identity",
                });
            }
            require_active_service_state(&state)?;
            services.push(state);
        }
        let proposed = CoreUpdateServiceSnapshotRecord::new(
            update_id.clone(),
            current.clone(),
            context,
            services,
        )?;
        let stored = self.provider.store_snapshot_record(proposed.clone())?;
        validate_service_snapshot(&stored)?;
        if stored != proposed {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core service snapshot store returned conflicting state",
            });
        }
        Ok(CoreServiceSnapshot::new(stored.receipt_id().clone()))
    }

    // Rebinds exactly the manager-selected platform and role service plan.
    fn rebind(
        &self,
        update_id: &li_core_interface::Sha256Digest,
        installation: &CoreInstallation,
        snapshot: &CoreServiceSnapshot,
    ) -> Result<(), CoreUpdateError> {
        let record = self.required_snapshot(update_id, snapshot)?;
        if installation == record.current() {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core service rebind candidate matches the previous installation",
            });
        }
        for state in record.services() {
            self.provider.rebind_service(
                state.service(),
                service_mode(record.context(), state.service())?,
                installation,
                state.was_active(),
            )?;
        }
        Ok(())
    }

    // Requires consecutive complete manager-selected readiness observations.
    fn verify(
        &self,
        update_id: &li_core_interface::Sha256Digest,
        installation: &CoreInstallation,
        snapshot: &CoreServiceSnapshot,
    ) -> Result<(), CoreUpdateError> {
        let record = self.required_snapshot(update_id, snapshot)?;
        let started = self.clock.monotonic_milliseconds()?;
        let deadline = started
            .checked_add(self.readiness.timeout_milliseconds)
            .ok_or(CoreUpdateError::InvalidContract {
                reason: "Core service readiness deadline overflowed",
            })?;
        let mut consecutive = 0_u32;
        let mut last_observed = started;
        loop {
            let (ready, observed_at) =
                self.readiness_observation(installation, &record, last_observed, deadline)?;
            last_observed = observed_at;
            if ready {
                consecutive += 1;
                if consecutive >= self.readiness.stable_observations {
                    return Ok(());
                }
            } else {
                consecutive = 0;
            }
            let observed = self.clock.monotonic_milliseconds()?;
            if observed < last_observed {
                return Err(CoreUpdateError::provider(
                    "readiness clock",
                    "monotonic time regressed after service observation",
                ));
            }
            if observed >= deadline {
                return Err(service_readiness_deadline_error());
            }
            let wait = self
                .readiness
                .poll_milliseconds
                .min(deadline.saturating_sub(observed));
            self.clock.wait(wait)?;
            let advanced = self.clock.monotonic_milliseconds()?;
            if advanced <= observed {
                return Err(CoreUpdateError::provider(
                    "readiness clock",
                    "monotonic time did not advance after a bounded wait",
                ));
            }
            last_observed = advanced;
        }
    }

    // Restores every exact prior state and reports incomplete recovery after all attempts.
    fn restore(
        &self,
        update_id: &li_core_interface::Sha256Digest,
        previous: &CoreInstallation,
        snapshot: &CoreServiceSnapshot,
    ) -> Result<(), CoreUpdateError> {
        let record = self.required_snapshot(update_id, snapshot)?;
        if record.current() != previous {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core service restoration installation does not match its snapshot",
            });
        }
        let mut failed = false;
        for state in record.services() {
            if self.provider.restore_service(state, previous).is_err() {
                failed = true;
            }
        }
        if failed {
            return Err(CoreUpdateError::provider(
                "service restoration",
                "one or more exact prior service states could not be restored",
            ));
        }
        Ok(())
    }

    // Loads one exact durable receipt and rejects context or content drift.
    fn required_snapshot(
        &self,
        update_id: &li_core_interface::Sha256Digest,
        snapshot: &CoreServiceSnapshot,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
        let record =
            self.provider
                .snapshot_record(update_id)?
                .ok_or(CoreUpdateError::InvalidContract {
                    reason: "Core service snapshot state is unavailable",
                })?;
        validate_service_snapshot(&record)?;
        if record.update_id() != update_id || record.receipt_id() != snapshot.receipt_id() {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core service snapshot receipt does not match durable state",
            });
        }
        if self.provider.context()? != record.context() {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core service platform or node role changed during update",
            });
        }
        Ok(record)
    }

    // Tests every expected binding once within the one global manager deadline.
    fn readiness_observation(
        &self,
        installation: &CoreInstallation,
        record: &CoreUpdateServiceSnapshotRecord,
        minimum_observed: u64,
        deadline: u64,
    ) -> Result<(bool, u64), CoreUpdateError> {
        let mut last_observed = self.clock.monotonic_milliseconds()?;
        if last_observed < minimum_observed {
            return Err(CoreUpdateError::provider(
                "readiness clock",
                "monotonic time regressed before service observation",
            ));
        }
        for state in record.services() {
            if last_observed >= deadline {
                return Err(service_readiness_deadline_error());
            }
            let ready = self.provider.service_is_ready_with_timeout(
                state.service(),
                service_mode(record.context(), state.service())?,
                Some(installation),
                state.was_active(),
                Duration::from_millis(deadline.saturating_sub(last_observed)),
            )?;
            let observed = self.clock.monotonic_milliseconds()?;
            if observed < last_observed {
                return Err(CoreUpdateError::provider(
                    "readiness clock",
                    "monotonic time regressed during service observation",
                ));
            }
            if observed >= deadline {
                return Err(service_readiness_deadline_error());
            }
            last_observed = observed;
            if !ready {
                return Ok((false, last_observed));
            }
        }
        Ok((true, last_observed))
    }
}

// Returns the exact resident service order for one supported native platform.
fn expected_services(context: CoreUpdateServiceContext) -> Vec<CoreUpdateResidentService> {
    let mut services = vec![CoreUpdateResidentService::Node];
    if context.platform() == CoreUpdateServicePlatform::Linux {
        services.push(CoreUpdateResidentService::Watchdog);
    }
    services.push(CoreUpdateResidentService::Gateway);
    services
}

// Resolves the exact manager-owned mode for one resident service and local role.
fn service_mode(
    context: CoreUpdateServiceContext,
    service: CoreUpdateResidentService,
) -> Result<CoreUpdateServiceMode, CoreUpdateError> {
    match service {
        CoreUpdateResidentService::Node => Ok(CoreUpdateServiceMode::Node),
        CoreUpdateResidentService::Gateway => match context.role() {
            CoreUpdateNodeRole::Main => Ok(CoreUpdateServiceMode::PublicGateway),
            CoreUpdateNodeRole::Child => Ok(CoreUpdateServiceMode::PrivateGateway),
        },
        CoreUpdateResidentService::Watchdog
            if context.platform() == CoreUpdateServicePlatform::Linux =>
        {
            Ok(CoreUpdateServiceMode::Watchdog)
        }
        CoreUpdateResidentService::Watchdog => Err(CoreUpdateError::InvalidContract {
            reason: "macOS Core service state cannot contain a separate Watchdog",
        }),
    }
}

// Requires one native observation to be loaded and active before update mutation.
fn require_active_service_state(state: &CoreUpdateServiceState) -> Result<(), CoreUpdateError> {
    if !state.was_loaded() || !state.was_active() {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core update requires every resident service to be loaded and active",
        });
    }
    Ok(())
}

// Requires one exact ordered, active platform service set at every manager boundary.
fn validate_service_snapshot(
    record: &CoreUpdateServiceSnapshotRecord,
) -> Result<(), CoreUpdateError> {
    let expected = expected_services(record.context());
    if record.services().len() != expected.len()
        || record
            .services()
            .iter()
            .zip(expected)
            .any(|(state, service)| state.service() != service)
    {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core service snapshot is not the exact role-appropriate service set",
        });
    }
    for state in record.services() {
        require_active_service_state(state)?;
    }
    Ok(())
}

// Creates one stable failure when native observation consumes the manager deadline.
fn service_readiness_deadline_error() -> CoreUpdateError {
    CoreUpdateError::provider(
        "service readiness",
        "role-appropriate services did not become stably ready",
    )
}

// Owns resumable update phase ordering while providers own external mechanisms.
pub(crate) struct CoreUpdateLifecycle {
    store: Arc<dyn CoreUpdateStore>,
    admission: Arc<dyn CoreUpdateAdmissionProvider>,
    artifacts: Arc<dyn CoreUpdateArtifactProvider>,
    services: CoreUpdateServiceLifecycle,
    pruner: Arc<dyn CoreUpdatePruneProvider>,
}

impl CoreUpdateLifecycle {
    // Creates one lifecycle from explicit persistence and external capabilities.
    pub(crate) const fn new(
        store: Arc<dyn CoreUpdateStore>,
        admission: Arc<dyn CoreUpdateAdmissionProvider>,
        artifacts: Arc<dyn CoreUpdateArtifactProvider>,
        services: Arc<dyn CoreUpdateServiceProvider>,
        pruner: Arc<dyn CoreUpdatePruneProvider>,
        clock: Arc<dyn CoreUpdateReadinessClock>,
        readiness: CoreUpdateReadinessPolicy,
    ) -> Self {
        Self {
            store,
            admission,
            artifacts,
            services: CoreUpdateServiceLifecycle::new(services, clock, readiness),
            pruner,
        }
    }

    // Applies or resumes one exact replay-key update through its terminal phase.
    pub(crate) fn update(
        &self,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
    ) -> Result<CoreUpdateChange, CoreUpdateError> {
        let mut versioned = self.open_record(idempotency_key, requested_version)?;
        let _admission = match versioned.record().phase() {
            CoreUpdatePhase::Current
            | CoreUpdatePhase::Succeeded
            | CoreUpdatePhase::RolledBack
            | CoreUpdatePhase::RecoveryRequired => None,
            _ => match self.admission.acquire(versioned.record().update_id()) {
                Ok(lease) => Some(lease),
                Err(error) if versioned.record().phase() == CoreUpdatePhase::Requested => {
                    return self.rollback_failure(
                        versioned.record().clone(),
                        versioned.revision(),
                        error,
                    );
                }
                Err(error) => return Err(error),
            },
        };
        loop {
            match versioned.record().phase() {
                CoreUpdatePhase::Requested => {
                    versioned = self.prepare(versioned)?;
                }
                CoreUpdatePhase::Prepared => {
                    if installations_are_equal(versioned.record())? {
                        return self.complete_current(versioned);
                    }
                    versioned = self.snapshot_services(versioned)?;
                }
                CoreUpdatePhase::ServicesSnapshotted => {
                    versioned = self.activate(versioned)?;
                }
                CoreUpdatePhase::Activated => {
                    versioned = self.rebind_services(versioned)?;
                }
                CoreUpdatePhase::ServicesRebound => {
                    versioned = self.verify_services(versioned)?;
                }
                CoreUpdatePhase::Verified => {
                    versioned = self.commit(versioned)?;
                }
                CoreUpdatePhase::Committed => return self.prune(versioned, true),
                CoreUpdatePhase::RollingBack => return self.complete_rollback(versioned),
                CoreUpdatePhase::CleanupPending => return self.prune(versioned, false),
                CoreUpdatePhase::Current => {
                    return terminal_change(
                        versioned.record(),
                        CoreUpdateDisposition::Current,
                        None,
                    )
                }
                CoreUpdatePhase::Succeeded => {
                    return terminal_change(
                        versioned.record(),
                        CoreUpdateDisposition::Updated,
                        None,
                    )
                }
                CoreUpdatePhase::RolledBack => {
                    return Err(CoreUpdateError::RolledBack {
                        failure: required_failure(versioned.record())?.clone(),
                    })
                }
                CoreUpdatePhase::RecoveryRequired => {
                    return Err(CoreUpdateError::RecoveryRequired {
                        failure: required_failure(versioned.record())?.clone(),
                    })
                }
            }
        }
    }

    // Returns one durable journal without invoking an external provider.
    pub(crate) fn record(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VersionedCoreUpdateRecord>, CoreUpdateError> {
        self.read_record(idempotency_key)
    }

    // Opens an existing matching journal or creates one deterministic request.
    fn open_record(
        &self,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        if let Some(versioned) = self.read_record(idempotency_key)? {
            require_same_request(versioned.record(), requested_version.as_ref())?;
            return Ok(versioned);
        }
        let requested = CoreUpdateRecord::requested(
            update_identity(idempotency_key)?,
            idempotency_key,
            requested_version.clone(),
        )?;
        match self.store.create(requested.clone()) {
            Ok(versioned) => {
                require_store_result(&versioned, idempotency_key, Some(&requested), 0)?;
                Ok(versioned)
            }
            Err(CoreUpdateStoreError::Conflict) => {
                let versioned = self
                    .read_record(idempotency_key)?
                    .ok_or(CoreUpdateStoreError::Conflict)?;
                require_same_request(versioned.record(), requested_version.as_ref())?;
                Ok(versioned)
            }
            Err(error) => Err(error.into()),
        }
    }

    // Resolves, verifies, and journals one candidate before any active mutation.
    fn prepare(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let current = match self.artifacts.current(record.update_id()) {
            Ok(current) => current,
            Err(error) => return self.rollback_failure(record, versioned.revision(), error),
        };
        let prepared =
            match self
                .artifacts
                .prepare(record.update_id(), record.requested_version(), &current)
            {
                Ok(prepared) => prepared,
                Err(error) => return self.rollback_failure(record, versioned.revision(), error),
            };
        record.current = Some(current);
        record.prepared = Some(prepared);
        if record.requested_version().is_some_and(|requested| {
            Some(requested)
                != record
                    .prepared()
                    .map(|value| value.installation().version())
        }) {
            return self.rollback_failure(
                record,
                versioned.revision(),
                CoreUpdateError::InvalidContract {
                    reason: "prepared Core version does not match the pinned request",
                },
            );
        }
        record.phase = CoreUpdatePhase::Prepared;
        record.failure = None;
        self.replace_record(record, versioned.revision())
    }

    // Captures exact service intent before moving the active Core pointer.
    fn snapshot_services(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let current = required_current(&record)?.clone();
        let snapshot = match self.services.snapshot(record.update_id(), &current) {
            Ok(snapshot) => snapshot,
            Err(error) => return self.rollback_failure(record, versioned.revision(), error),
        };
        record.service_snapshot = Some(snapshot);
        record.phase = CoreUpdatePhase::ServicesSnapshotted;
        self.replace_record(record, versioned.revision())
    }

    // Moves the immutable active pointer and journals its reversible receipt.
    fn activate(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let current = required_current(&record)?.clone();
        let prepared = required_prepared(&record)?.clone();
        let activation = match self
            .artifacts
            .activate(record.update_id(), &prepared, &current)
        {
            Ok(activation) => activation,
            Err(error) => return self.rollback_failure(record, versioned.revision(), error),
        };
        record.activation = Some(activation);
        if let Err(error) = require_activation(
            required_activation(&record)?,
            &current,
            prepared.installation(),
        ) {
            return self.rollback_failure(record, versioned.revision(), error);
        }
        record.phase = CoreUpdatePhase::Activated;
        self.replace_record(record, versioned.revision())
    }

    // Rebinds every role-appropriate resident service after candidate activation.
    fn rebind_services(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let activation = required_activation(&record)?.clone();
        let snapshot = required_snapshot(&record)?.clone();
        if let Err(error) =
            self.services
                .rebind(record.update_id(), activation.installation(), &snapshot)
        {
            return self.rollback_failure(record, versioned.revision(), error);
        }
        record.phase = CoreUpdatePhase::ServicesRebound;
        self.replace_record(record, versioned.revision())
    }

    // Requires bounded stable service readiness before committing the handoff.
    fn verify_services(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let activation = required_activation(&record)?.clone();
        let snapshot = required_snapshot(&record)?.clone();
        if let Err(error) =
            self.services
                .verify(record.update_id(), activation.installation(), &snapshot)
        {
            return self.rollback_failure(record, versioned.revision(), error);
        }
        record.phase = CoreUpdatePhase::Verified;
        self.replace_record(record, versioned.revision())
    }

    // Makes the verified active pointer authoritative before any destructive prune.
    fn commit(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let activation = required_activation(&record)?.clone();
        if let Err(error) = self.artifacts.commit(record.update_id(), &activation) {
            return self.rollback_failure(record, versioned.revision(), error);
        }
        record.phase = CoreUpdatePhase::Committed;
        self.replace_record(record, versioned.revision())
    }

    // Prunes only after commit and preserves the working Core on cleanup failure.
    fn prune(
        &self,
        versioned: VersionedCoreUpdateRecord,
        first_attempt: bool,
    ) -> Result<CoreUpdateChange, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let installation = required_activation(&record)?.installation().clone();
        match self.pruner.prune(record.update_id(), &installation) {
            Ok(()) => {
                record.phase = CoreUpdatePhase::Succeeded;
                record.failure = None;
                let stored = self.replace_record(record, versioned.revision())?;
                terminal_change(
                    stored.record(),
                    CoreUpdateDisposition::Updated,
                    Some(CoreUpdateEvent::CoreUpdated {
                        source_identity: installation.source_identity().clone(),
                    }),
                )
            }
            Err(error) => {
                if first_attempt {
                    record.phase = CoreUpdatePhase::CleanupPending;
                    record.failure = Some(failure_description("core_cleanup_pending", &error)?);
                    let stored = self.replace_record(record, versioned.revision())?;
                    terminal_change(
                        stored.record(),
                        CoreUpdateDisposition::CleanupPending,
                        Some(CoreUpdateEvent::CoreCleanupPending {
                            source_identity: installation.source_identity().clone(),
                        }),
                    )
                } else {
                    terminal_change(&record, CoreUpdateDisposition::CleanupPending, None)
                }
            }
        }
    }

    // Discards a no-op candidate and commits one current terminal record.
    fn complete_current(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<CoreUpdateChange, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let prepared = required_prepared(&record)?.clone();
        if let Err(error) = self.artifacts.discard(record.update_id(), &prepared) {
            return self.rollback_failure(record, versioned.revision(), error);
        }
        let current = required_current(&record)?.clone();
        record.prepared = None;
        record.phase = CoreUpdatePhase::Current;
        record.failure = None;
        let stored = self.replace_record(record, versioned.revision())?;
        terminal_change(
            stored.record(),
            CoreUpdateDisposition::Current,
            Some(CoreUpdateEvent::CoreCurrent {
                source_identity: current.source_identity().clone(),
            }),
        )
    }

    // Compensates every acquired boundary and journals rollback or recovery state.
    fn rollback_failure<Value>(
        &self,
        mut record: CoreUpdateRecord,
        expected_revision: u64,
        error: CoreUpdateError,
    ) -> Result<Value, CoreUpdateError> {
        let failure = failure_description("core_update_failed", &error)?;
        record.failure = Some(failure);
        record.phase = CoreUpdatePhase::RollingBack;
        let stored = self.replace_record(record, expected_revision)?;
        self.complete_rollback(stored)
    }

    // Completes idempotent compensation from one durable rollback intent.
    fn complete_rollback<Value>(
        &self,
        versioned: VersionedCoreUpdateRecord,
    ) -> Result<Value, CoreUpdateError> {
        let mut record = versioned.record().clone();
        let failure = required_failure(&record)?.clone();
        let mut recovery_failed = false;
        if let Some(activation) = record.activation.as_ref() {
            match (record.current.as_ref(), record.service_snapshot.as_ref()) {
                (Some(previous), Some(snapshot)) => {
                    if self
                        .services
                        .restore(record.update_id(), previous, snapshot)
                        .is_err()
                    {
                        recovery_failed = true;
                    }
                }
                _ => recovery_failed = true,
            }
            if self
                .artifacts
                .rollback(record.update_id(), activation)
                .is_err()
            {
                recovery_failed = true;
            }
        } else if let Some(prepared) = record.prepared.as_ref() {
            if self
                .artifacts
                .discard(record.update_id(), prepared)
                .is_err()
            {
                recovery_failed = true;
            }
        }
        record.phase = if recovery_failed {
            CoreUpdatePhase::RecoveryRequired
        } else {
            CoreUpdatePhase::RolledBack
        };
        self.replace_record(record, versioned.revision())?;
        if recovery_failed {
            Err(CoreUpdateError::RecoveryRequired { failure })
        } else {
            Err(CoreUpdateError::RolledBack { failure })
        }
    }

    // Reads one exact journal and rejects foreign identity or zero-revision state.
    fn read_record(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VersionedCoreUpdateRecord>, CoreUpdateError> {
        let stored = self.store.read(idempotency_key)?;
        if let Some(stored) = stored.as_ref() {
            require_store_result(stored, idempotency_key, None, 0)?;
        }
        Ok(stored)
    }

    // Reconciles one exact mutation after an ambiguous store result without advancing twice.
    fn replace_record(
        &self,
        record: CoreUpdateRecord,
        expected_revision: u64,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateError> {
        let idempotency_key = record.idempotency_key().to_string();
        match self.store.replace(record.clone(), expected_revision) {
            Ok(stored) => {
                require_store_result(&stored, &idempotency_key, Some(&record), expected_revision)?;
                Ok(stored)
            }
            Err(original) => {
                let observed = self.read_record(&idempotency_key)?;
                if let Some(observed) = observed {
                    if original == CoreUpdateStoreError::Unavailable
                        && observed.record() == &record
                        && observed.revision() > expected_revision
                    {
                        return Ok(observed);
                    }
                    if observed.revision() == expected_revision
                        && original == CoreUpdateStoreError::Conflict
                    {
                        let retried = self.store.replace(record.clone(), expected_revision)?;
                        require_store_result(
                            &retried,
                            &idempotency_key,
                            Some(&record),
                            expected_revision,
                        )?;
                        return Ok(retried);
                    }
                }
                Err(original.into())
            }
        }
    }
}

// Requires one store result to preserve exact ownership, content, and revision progress.
fn require_store_result(
    stored: &VersionedCoreUpdateRecord,
    idempotency_key: &str,
    expected: Option<&CoreUpdateRecord>,
    prior_revision: u64,
) -> Result<(), CoreUpdateError> {
    if stored.revision() <= prior_revision
        || stored.record().idempotency_key() != idempotency_key
        || expected.is_some_and(|expected| stored.record() != expected)
    {
        return Err(CoreUpdateStoreError::Corrupt.into());
    }
    Ok(())
}

// Requires replay to preserve the originally requested version exactly.
fn require_same_request(
    record: &CoreUpdateRecord,
    requested_version: Option<&CoreVersion>,
) -> Result<(), CoreUpdateError> {
    if record.requested_version() != requested_version {
        return Err(CoreUpdateError::IdempotencyConflict);
    }
    Ok(())
}

// Returns whether the prepared identity is already the exact active Core.
fn installations_are_equal(record: &CoreUpdateRecord) -> Result<bool, CoreUpdateError> {
    Ok(required_current(record)? == required_prepared(record)?.installation())
}

// Requires one current installation at every post-prepare phase.
fn required_current(record: &CoreUpdateRecord) -> Result<&CoreInstallation, CoreUpdateError> {
    record.current().ok_or(CoreUpdateError::InvalidContract {
        reason: "Core update journal has no current installation",
    })
}

// Requires one prepared candidate at every pre-commit phase.
fn required_prepared(
    record: &CoreUpdateRecord,
) -> Result<&crate::PreparedCoreUpdate, CoreUpdateError> {
    record.prepared().ok_or(CoreUpdateError::InvalidContract {
        reason: "Core update journal has no prepared candidate",
    })
}

// Requires one service snapshot after the snapshot phase.
fn required_snapshot(
    record: &CoreUpdateRecord,
) -> Result<&crate::CoreServiceSnapshot, CoreUpdateError> {
    record
        .service_snapshot()
        .ok_or(CoreUpdateError::InvalidContract {
            reason: "Core update journal has no service snapshot",
        })
}

// Requires one activation receipt after active pointer mutation.
fn required_activation(record: &CoreUpdateRecord) -> Result<&ActivatedCoreUpdate, CoreUpdateError> {
    record.activation().ok_or(CoreUpdateError::InvalidContract {
        reason: "Core update journal has no activation receipt",
    })
}

// Requires provider activation identity to match the prepared handoff exactly.
fn require_activation(
    activation: &ActivatedCoreUpdate,
    current: &CoreInstallation,
    prepared: &CoreInstallation,
) -> Result<(), CoreUpdateError> {
    if activation.previous() != current || activation.installation() != prepared {
        return Err(CoreUpdateError::InvalidContract {
            reason: "Core activation receipt does not match the prepared handoff",
        });
    }
    Ok(())
}

// Requires a durable terminal failure description.
fn required_failure(record: &CoreUpdateRecord) -> Result<&FailureDescription, CoreUpdateError> {
    record.failure().ok_or(CoreUpdateError::InvalidContract {
        reason: "terminal Core update failure has no description",
    })
}

// Returns one terminal change from a structurally complete journal.
fn terminal_change(
    record: &CoreUpdateRecord,
    disposition: CoreUpdateDisposition,
    event: Option<CoreUpdateEvent>,
) -> Result<CoreUpdateChange, CoreUpdateError> {
    let installation = match disposition {
        CoreUpdateDisposition::Current => required_current(record)?.clone(),
        CoreUpdateDisposition::Updated | CoreUpdateDisposition::CleanupPending => {
            required_activation(record)?.installation().clone()
        }
    };
    Ok(CoreUpdateChange::new(installation, disposition, event))
}
