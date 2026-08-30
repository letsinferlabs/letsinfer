// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    BootId, EndpointOwnership, Placement, PlacementEndpoint, PlacementState, Sha256Digest,
    TechnicalName,
};

use crate::{PlacementError, PlacementExecutor, PlacementObservation};

// Identifies one exact Linux container process protected by Watchdog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxProtectedProcessIdentity {
    container_name: TechnicalName,
    container_id: Sha256Digest,
    process_id: u32,
    process_start_ticks: u64,
    boot_id: BootId,
    cgroup: String,
}

impl LinuxProtectedProcessIdentity {
    // Creates one complete process identity suitable for pidfd-safe protection.
    pub fn new(
        container_name: TechnicalName,
        container_id: Sha256Digest,
        process_id: u32,
        process_start_ticks: u64,
        boot_id: BootId,
        cgroup: &str,
    ) -> Result<Self, PlacementError> {
        if process_id <= 1
            || process_start_ticks == 0
            || !is_linux_boot_id(boot_id.as_str())
            || cgroup.is_empty()
            || cgroup.len() > 4_095
            || !cgroup.starts_with("/sys/fs/cgroup/")
            || cgroup.chars().any(|character| {
                character.is_control() || character.is_whitespace() || character == '='
            })
            || cgroup.split('/').any(|component| component == "..")
        {
            return Err(PlacementError::InvalidRequest {
                reason: "protected process identity is incomplete or unsafe",
            });
        }
        Ok(Self {
            container_name,
            container_id,
            process_id,
            process_start_ticks,
            boot_id,
            cgroup: cgroup.to_string(),
        })
    }

    // Returns the exact managed container name.
    pub const fn container_name(&self) -> &TechnicalName {
        &self.container_name
    }

    // Returns the exact immutable container identity.
    pub const fn container_id(&self) -> &Sha256Digest {
        &self.container_id
    }

    // Returns the host process identifier.
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    // Returns the Linux process start ticks used to reject PID reuse.
    pub const fn process_start_ticks(&self) -> u64 {
        self.process_start_ticks
    }

    // Returns the host boot identity that scopes the process.
    pub const fn boot_id(&self) -> &BootId {
        &self.boot_id
    }

    // Returns the exact cgroup path containing the protected process.
    pub fn cgroup(&self) -> &str {
        &self.cgroup
    }
}

// Returns whether one boot identity is a canonical lowercase UUID.
fn is_linux_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

// Returns the exact li_-namespaced container name for one placement.
pub(crate) fn linux_placement_container_name(
    placement: &Placement,
) -> Result<TechnicalName, PlacementError> {
    TechnicalName::parse(&format!(
        "li_placement_{}",
        placement.placement_id().as_str()
    ))
    .map_err(|_| PlacementError::ProtectionUnsafe)
}

// Identifies one opaque Watchdog protection generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementProtectionGeneration(String);

impl PlacementProtectionGeneration {
    // Parses one canonical generation without creating native state.
    pub fn parse(value: &str) -> Result<Self, PlacementError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PlacementError::InvalidRequest {
                reason: "protection generation must be 32 lowercase hexadecimal characters",
            });
        }
        Ok(Self(value.to_string()))
    }

    // Returns the opaque generation text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Describes one explicit Watchdog protection phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementProtectionPhase {
    Unconfigured,
    Pending,
    Starting,
    Armed,
    Disarmed,
}

// Describes current Watchdog protection without exposing native files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementProtectionStatus {
    phase: PlacementProtectionPhase,
    trip_latched: bool,
}

// Binds one durable protection generation to its exact active Linux process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementProtectedTarget {
    generation: PlacementProtectionGeneration,
    phase: PlacementProtectionPhase,
    process: LinuxProtectedProcessIdentity,
}

impl PlacementProtectedTarget {
    // Creates one target only for a process-bound starting or armed descriptor.
    pub fn new(
        generation: PlacementProtectionGeneration,
        phase: PlacementProtectionPhase,
        process: LinuxProtectedProcessIdentity,
    ) -> Result<Self, PlacementError> {
        if !matches!(
            phase,
            PlacementProtectionPhase::Starting | PlacementProtectionPhase::Armed
        ) {
            return Err(PlacementError::ProtectionUnsafe);
        }
        Ok(Self {
            generation,
            phase,
            process,
        })
    }

    // Returns the opaque protection generation owned by Placement.
    pub const fn generation(&self) -> &PlacementProtectionGeneration {
        &self.generation
    }

    // Returns the exact process-bound protection phase.
    pub const fn phase(&self) -> PlacementProtectionPhase {
        self.phase
    }

    // Returns the complete PID-reuse-safe process identity.
    pub const fn process(&self) -> &LinuxProtectedProcessIdentity {
        &self.process
    }
}

// Resolves one explicitly selected placement to its durable active protection descriptor.
pub trait LinuxPlacementProtectedTargetProvider: Send + Sync {
    // Returns the exact starting or armed target, or absence for a non-active slot.
    fn active_target(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementProtectedTarget>, PlacementError>;
}

impl PlacementProtectionStatus {
    // Creates one explicit protection observation.
    pub const fn new(phase: PlacementProtectionPhase, trip_latched: bool) -> Self {
        Self {
            phase,
            trip_latched,
        }
    }

    // Returns the latest acknowledged protection phase.
    pub const fn phase(self) -> PlacementProtectionPhase {
        self.phase
    }

    // Returns whether a durable trip blocks ordinary recovery.
    pub const fn trip_latched(self) -> bool {
        self.trip_latched
    }
}

// Identifies the observed execution state of one staged Linux placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxPlacementExecutionState {
    Absent,
    Staged,
    Running,
    Stopped,
    Removed,
    Failed,
}

// Describes current process and endpoint readiness from the execution provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxPlacementExecutionObservation {
    state: LinuxPlacementExecutionState,
    process: Option<LinuxProtectedProcessIdentity>,
    ready: bool,
    endpoint: Option<PlacementEndpoint>,
}

impl LinuxPlacementExecutionObservation {
    // Creates one coherent execution observation without applying protection policy.
    pub fn new(
        state: LinuxPlacementExecutionState,
        process: Option<LinuxProtectedProcessIdentity>,
        ready: bool,
        endpoint: Option<PlacementEndpoint>,
    ) -> Result<Self, PlacementError> {
        if (state == LinuxPlacementExecutionState::Running && process.is_none())
            || (state != LinuxPlacementExecutionState::Running && (ready || endpoint.is_some()))
        {
            return Err(PlacementError::InvalidRequest {
                reason: "Linux placement execution observation is incoherent",
            });
        }
        Ok(Self {
            state,
            process,
            ready,
            endpoint,
        })
    }

    // Returns the observed native execution state.
    pub const fn state(&self) -> LinuxPlacementExecutionState {
        self.state
    }

    // Returns the exact running process identity when one exists.
    pub const fn process(&self) -> Option<&LinuxProtectedProcessIdentity> {
        self.process.as_ref()
    }

    // Returns whether runtime-owned readiness succeeded.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    // Returns the endpoint observed on the declared owner.
    pub const fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }
}

// Defines shell-free process operations for one sealed Linux placement.
pub trait LinuxPlacementExecutionProvider: Send + Sync {
    // Stages exact inputs and returns their immutable launch-plan identity.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError>;

    // Starts the exact sealed argv and returns its complete process identity.
    fn start(&self, placement: &Placement)
        -> Result<LinuxProtectedProcessIdentity, PlacementError>;

    // Waits for bounded runtime-owned readiness without publishing the endpoint.
    fn wait_until_ready(
        &self,
        placement: &Placement,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<bool, PlacementError>;

    // Returns the authenticated endpoint after readiness succeeds.
    fn endpoint(
        &self,
        placement: &Placement,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<Option<PlacementEndpoint>, PlacementError>;

    // Stops and removes only process state created by an incomplete start.
    fn rollback_start(
        &self,
        placement: &Placement,
        process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<(), PlacementError>;

    // Stops one exact managed process while preserving staged inputs.
    fn stop(&self, placement: &Placement) -> Result<(), PlacementError>;

    // Removes staged inputs and task-scoped credentials after process absence.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError>;

    // Observes actual process and readiness state without mutation.
    fn observe(
        &self,
        placement: &Placement,
    ) -> Result<LinuxPlacementExecutionObservation, PlacementError>;
}

// Defines the narrow resident Watchdog lifecycle consumed by placement execution.
pub trait LinuxPlacementProtectionProvider: Send + Sync {
    // Creates one pending protection generation before process launch.
    fn begin(&self, placement: &Placement)
        -> Result<PlacementProtectionGeneration, PlacementError>;

    // Binds starting protection to the exact process identity.
    fn bind_starting(
        &self,
        placement: &Placement,
        generation: &PlacementProtectionGeneration,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError>;

    // Arms protection only after the exact process becomes ready.
    fn arm(
        &self,
        placement: &Placement,
        generation: &PlacementProtectionGeneration,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError>;

    // Disarms protection and waits for Watchdog acknowledgement.
    fn disarm(&self, placement: &Placement) -> Result<PlacementProtectionStatus, PlacementError>;

    // Returns current phase and durable-trip state for one exact slot.
    fn status(
        &self,
        placement: &Placement,
        process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<PlacementProtectionStatus, PlacementError>;

    // Clears only this placement's explicit durable trip.
    fn acknowledge_trip(&self, placement: &Placement) -> Result<bool, PlacementError>;

    // Removes one proven-disarmed protection slot idempotently.
    fn retire(&self, placement: &Placement) -> Result<(), PlacementError>;
}

// Orders Linux execution and resident Watchdog protection for PlacementManager.
pub struct LinuxPlacementExecutor {
    execution: Arc<dyn LinuxPlacementExecutionProvider>,
    protection: Arc<dyn LinuxPlacementProtectionProvider>,
}

impl LinuxPlacementExecutor {
    // Creates one executor from explicit process and protection capabilities.
    pub const fn new(
        execution: Arc<dyn LinuxPlacementExecutionProvider>,
        protection: Arc<dyn LinuxPlacementProtectionProvider>,
    ) -> Self {
        Self {
            execution,
            protection,
        }
    }

    // Completes one protected start and publishes no endpoint before arming.
    fn start_protected(
        &self,
        placement: &Placement,
        acknowledge_protection_trip: bool,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        let mut protection = self.protection.status(placement, None)?;
        if !matches!(
            protection.phase(),
            PlacementProtectionPhase::Unconfigured | PlacementProtectionPhase::Disarmed
        ) {
            return Err(PlacementError::ProtectionUnsafe);
        }
        if protection.trip_latched() {
            if !acknowledge_protection_trip || !self.protection.acknowledge_trip(placement)? {
                return Err(PlacementError::ProtectionUnsafe);
            }
            protection = self.protection.status(placement, None)?;
            if protection.trip_latched() {
                return Err(PlacementError::ProtectionUnsafe);
            }
        } else if acknowledge_protection_trip {
            self.protection.acknowledge_trip(placement)?;
        }
        let generation = self.protection.begin(placement)?;
        let process = match self.execution.start(placement) {
            Ok(process) => process,
            Err(error) => {
                self.rollback_incomplete_start(placement, None);
                return Err(error);
            }
        };
        if process.container_name() != &linux_placement_container_name(placement)? {
            self.rollback_incomplete_start(placement, Some(&process));
            return Err(PlacementError::ProtectionUnsafe);
        }
        let result = self
            .protection
            .bind_starting(placement, &generation, &process)
            .and_then(|_| {
                self.execution
                    .wait_until_ready(placement, &process)
                    .and_then(|ready| {
                        if ready {
                            Ok(())
                        } else {
                            Err(PlacementError::ExecutionUnavailable)
                        }
                    })
            })
            .and_then(|_| self.protection.arm(placement, &generation, &process))
            .and_then(|_| self.execution.endpoint(placement, &process))
            .and_then(|endpoint| Self::validated_endpoint(placement, endpoint));
        match result {
            Ok(endpoint) => Ok(endpoint),
            Err(error) => {
                self.rollback_incomplete_start(placement, Some(&process));
                Err(error)
            }
        }
    }

    // Best-effort rolls back one incomplete start without clearing a real trip.
    fn rollback_incomplete_start(
        &self,
        placement: &Placement,
        process: Option<&LinuxProtectedProcessIdentity>,
    ) {
        let trip_latched = self
            .protection
            .status(placement, process)
            .map(PlacementProtectionStatus::trip_latched)
            .unwrap_or(false);
        if !trip_latched {
            let _ = self.protection.disarm(placement);
        }
        let _ = self.execution.rollback_start(placement, process);
    }

    // Validates one running endpoint against placement ownership and identity.
    fn validated_endpoint(
        placement: &Placement,
        endpoint: Option<PlacementEndpoint>,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        match placement.assignment().endpoint_ownership() {
            EndpointOwnership::Owner => {
                let endpoint = endpoint.ok_or(PlacementError::EndpointUnavailable)?;
                if endpoint.placement_id() != placement.placement_id()
                    || endpoint.node_id() != placement.assignment().node_id()
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
}

impl PlacementExecutor for LinuxPlacementExecutor {
    // Stages exact sealed inputs and returns identity without changing protection.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.execution.stage(placement)
    }

    // Starts one exact placement through pending, starting, ready, and armed phases.
    fn start(
        &self,
        placement: &Placement,
        acknowledge_protection_trip: bool,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        self.start_protected(placement, acknowledge_protection_trip)
    }

    // Disarms and receives Watchdog acknowledgement before stopping the process.
    fn stop(&self, placement: &Placement) -> Result<(), PlacementError> {
        let status = self.protection.disarm(placement)?;
        if status.phase() != PlacementProtectionPhase::Disarmed {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.execution.stop(placement)
    }

    // Retires only an absent, disarmed slot before removing staged inputs.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError> {
        let execution = self.execution.observe(placement)?;
        if execution.state() == LinuxPlacementExecutionState::Running {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let mut protection = self.protection.status(placement, execution.process())?;
        if !matches!(
            protection.phase(),
            PlacementProtectionPhase::Unconfigured | PlacementProtectionPhase::Disarmed
        ) {
            return Err(PlacementError::ProtectionUnsafe);
        }
        if protection.trip_latched() {
            if !self.protection.acknowledge_trip(placement)? {
                return Err(PlacementError::ProtectionUnsafe);
            }
            protection = self.protection.status(placement, execution.process())?;
            if protection.phase() != PlacementProtectionPhase::Disarmed || protection.trip_latched()
            {
                return Err(PlacementError::ProtectionUnsafe);
            }
        }
        self.protection.retire(placement)?;
        self.execution.remove(placement)
    }

    // Combines live execution, readiness, endpoint, and Watchdog state.
    fn observe(&self, placement: &Placement) -> Result<PlacementObservation, PlacementError> {
        let execution = self.execution.observe(placement)?;
        let protection = self.protection.status(placement, execution.process())?;
        if protection.trip_latched() {
            return Ok(PlacementObservation::new(
                PlacementState::Failed,
                None,
                true,
            ));
        }
        let (state, endpoint) = match execution.state() {
            LinuxPlacementExecutionState::Running
                if execution.ready() && protection.phase() == PlacementProtectionPhase::Armed =>
            {
                (
                    PlacementState::Running,
                    Self::validated_endpoint(placement, execution.endpoint().cloned())?,
                )
            }
            LinuxPlacementExecutionState::Running | LinuxPlacementExecutionState::Failed => {
                (PlacementState::Failed, None)
            }
            LinuxPlacementExecutionState::Staged => (PlacementState::Staged, None),
            LinuxPlacementExecutionState::Stopped => (PlacementState::Stopped, None),
            LinuxPlacementExecutionState::Removed => (PlacementState::Removed, None),
            LinuxPlacementExecutionState::Absent => match placement.state() {
                PlacementState::Staged => (PlacementState::Staged, None),
                PlacementState::Stopped => (PlacementState::Stopped, None),
                PlacementState::Removed => (PlacementState::Removed, None),
                _ => (PlacementState::Failed, None),
            },
        };
        Ok(PlacementObservation::new(state, endpoint, false))
    }
}
