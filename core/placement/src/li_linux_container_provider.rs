// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{
    BootId, EndpointOwnership, Placement, PlacementEndpoint, PlacementId, RuntimeInstallationId,
    Sha256Digest, TaskId, TechnicalName,
};
use li_runtime_manager::RuntimeExecutionImageReference;
use serde::Deserialize;

use crate::li_linux_placement_executor::linux_placement_container_name;
use crate::{
    LinuxPlacementExecutionObservation, LinuxPlacementExecutionProvider,
    LinuxPlacementExecutionState, LinuxProtectedProcessIdentity, PlacementError, PlacementLogBatch,
    PlacementLogCursor, PlacementLogReadRequest, PlacementRuntimeLogProvider, ShellFreeCommand,
    ShellFreeCommandRunner,
};

const MANAGED_LABEL: &str = "ai.letsinfer.managed";
const GROUP_LABEL: &str = "ai.letsinfer.placement_group_id";
const PLACEMENT_LABEL: &str = "ai.letsinfer.placement_id";
const NODE_LABEL: &str = "ai.letsinfer.node_id";
const TASK_LABEL: &str = "ai.letsinfer.task_id";
const MAX_INSPECT_BYTES: usize = 1024 * 1024;
const MAXIMUM_DOCKER_LOG_READ_BYTES: usize = 16 * 1024 * 1024;

// Describes one bounded runtime-owned readiness mechanism.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxContainerReadiness {
    Endpoint {
        attempts: u16,
        interval: Duration,
    },
    Exec {
        arguments: Vec<String>,
        attempts: u16,
        interval: Duration,
    },
}

impl LinuxContainerReadiness {
    // Creates one bounded authenticated endpoint readiness contract.
    pub fn endpoint(attempts: u16, interval: Duration) -> Result<Self, PlacementError> {
        validate_readiness(attempts, interval)?;
        Ok(Self::Endpoint { attempts, interval })
    }

    // Creates one bounded shell-free in-container readiness contract.
    pub fn exec(
        arguments: Vec<String>,
        attempts: u16,
        interval: Duration,
    ) -> Result<Self, PlacementError> {
        validate_readiness(attempts, interval)?;
        validate_readiness_arguments(&arguments)?;
        Ok(Self::Exec {
            arguments,
            attempts,
            interval,
        })
    }

    // Returns the bounded number of readiness attempts.
    pub const fn attempts(&self) -> u16 {
        match self {
            Self::Endpoint { attempts, .. } | Self::Exec { attempts, .. } => *attempts,
        }
    }

    // Returns the interval between readiness attempts.
    pub const fn interval(&self) -> Duration {
        match self {
            Self::Endpoint { interval, .. } | Self::Exec { interval, .. } => *interval,
        }
    }
}

// Seals one placement's exact Docker command, identity, readiness, and endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxContainerLaunchPlan {
    placement_id: PlacementId,
    runtime_installation_id: RuntimeInstallationId,
    task_id: TaskId,
    container_name: TechnicalName,
    image_reference: RuntimeExecutionImageReference,
    image_id: Sha256Digest,
    create_command: ShellFreeCommand,
    readiness: LinuxContainerReadiness,
    endpoint: Option<PlacementEndpoint>,
    expected_labels: BTreeMap<String, String>,
}

impl LinuxContainerLaunchPlan {
    // Creates one immutable plan and verifies every protected Docker identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new<ImageReference>(
        placement: &Placement,
        image_reference: ImageReference,
        image_id: Sha256Digest,
        create_command: ShellFreeCommand,
        readiness: LinuxContainerReadiness,
        endpoint: Option<PlacementEndpoint>,
    ) -> Result<Self, PlacementError>
    where
        ImageReference: Into<RuntimeExecutionImageReference>,
    {
        let image_reference = image_reference.into();
        if !valid_image_reference(&image_reference, &image_id) {
            return Err(PlacementError::InvalidRequest {
                reason: "Linux container image reference must be digest-pinned",
            });
        }
        let container_name = linux_placement_container_name(placement)?;
        let expected_labels = expected_labels(placement);
        validate_create_command(
            &create_command,
            &container_name,
            &image_reference,
            &expected_labels,
        )?;
        if create_command
            .environment()
            .iter()
            .any(|value| !value.is_core_owned())
        {
            return Err(PlacementError::InvalidRequest {
                reason: "Docker client environment must be Core-owned",
            });
        }
        validate_endpoint(placement, endpoint.as_ref())?;
        if matches!(readiness, LinuxContainerReadiness::Endpoint { .. }) && endpoint.is_none() {
            return Err(PlacementError::EndpointUnavailable);
        }
        Ok(Self {
            placement_id: placement.placement_id().clone(),
            runtime_installation_id: placement.assignment().runtime_installation_id().clone(),
            task_id: placement.assignment().task_id().clone(),
            container_name,
            image_reference,
            image_id,
            create_command,
            readiness,
            endpoint,
            expected_labels,
        })
    }

    // Requires this sealed plan to match one exact immutable placement assignment.
    pub fn validate_for(&self, placement: &Placement) -> Result<(), PlacementError> {
        if &self.placement_id != placement.placement_id()
            || &self.runtime_installation_id != placement.assignment().runtime_installation_id()
            || &self.task_id != placement.assignment().task_id()
            || self.container_name != linux_placement_container_name(placement)?
        {
            return Err(PlacementError::InvalidRequest {
                reason: "Linux container launch plan differs from its placement",
            });
        }
        validate_endpoint(placement, self.endpoint.as_ref())
    }

    // Returns the exact protected container name.
    pub const fn container_name(&self) -> &TechnicalName {
        &self.container_name
    }

    // Returns the exact placement identity sealed by this plan.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the exact runtime installation consumed by this plan.
    pub const fn runtime_installation_id(&self) -> &RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the opaque runtime task identity sealed by this plan.
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    // Returns the digest-pinned OCI image reference.
    pub const fn image_reference(&self) -> &RuntimeExecutionImageReference {
        &self.image_reference
    }

    // Returns the exact locally inspected image identity.
    pub const fn image_id(&self) -> &Sha256Digest {
        &self.image_id
    }

    // Returns the complete shell-free Docker create command.
    pub const fn create_command(&self) -> &ShellFreeCommand {
        &self.create_command
    }

    // Returns the runtime-owned readiness contract.
    pub const fn readiness(&self) -> &LinuxContainerReadiness {
        &self.readiness
    }

    // Returns the endpoint published only after readiness and protection.
    pub const fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }

    // Returns exact protected labels required on the container.
    pub const fn expected_labels(&self) -> &BTreeMap<String, String> {
        &self.expected_labels
    }
}

// Describes one exact Docker container inspection result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerContainerObservation {
    container_name: TechnicalName,
    container_id: Sha256Digest,
    image_id: Sha256Digest,
    running: bool,
    process_id: u32,
    labels: BTreeMap<String, String>,
}

impl DockerContainerObservation {
    // Creates one bounded Docker observation without trusting its labels.
    pub fn new(
        container_name: TechnicalName,
        container_id: Sha256Digest,
        image_id: Sha256Digest,
        running: bool,
        process_id: u32,
        labels: BTreeMap<String, String>,
    ) -> Result<Self, PlacementError> {
        if running != (process_id > 1)
            || labels.len() > 128
            || labels.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 255
                    || value.len() > 1024
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(Self {
            container_name,
            container_id,
            image_id,
            running,
            process_id,
            labels,
        })
    }

    // Returns the exact inspected container name.
    pub const fn container_name(&self) -> &TechnicalName {
        &self.container_name
    }

    // Returns the exact immutable container identity.
    pub const fn container_id(&self) -> &Sha256Digest {
        &self.container_id
    }

    // Returns the exact local image identity.
    pub const fn image_id(&self) -> &Sha256Digest {
        &self.image_id
    }

    // Returns whether Docker reports the container process running.
    pub const fn running(&self) -> bool {
        self.running
    }

    // Returns the container init process identifier when running.
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    // Returns bounded inspected labels.
    pub const fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
}

// Supplies sealed plans and owns staged placement inputs.
pub trait LinuxPlacementMaterialProvider: Send + Sync {
    // Stages exact inputs and returns their immutable launch-plan identity.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError>;

    // Returns the exact sealed plan when staging is complete.
    fn plan(
        &self,
        placement: &Placement,
    ) -> Result<Option<LinuxContainerLaunchPlan>, PlacementError>;

    // Removes only exact staged inputs after process absence.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError>;
}

// Defines exact Docker operations independently of plan and placement policy.
pub trait LinuxDockerClient: Send + Sync {
    // Returns one exact container observation or verified absence.
    fn inspect(
        &self,
        plan: &LinuxContainerLaunchPlan,
    ) -> Result<Option<DockerContainerObservation>, PlacementError>;

    // Creates and starts one container from the sealed command.
    fn create_and_start(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError>;

    // Starts one exact validated stopped container.
    fn start(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError>;

    // Stops one exact container without a broad prune.
    fn stop(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError>;

    // Removes one exact stopped container without touching its image.
    fn remove(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError>;

    // Executes one fixed readiness argv inside the exact container.
    fn exec_readiness(
        &self,
        plan: &LinuxContainerLaunchPlan,
        arguments: &[String],
    ) -> Result<bool, PlacementError>;
}

// Returns one exact Docker log source batch before Placement-level projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerLogRead {
    source_identity: Sha256Digest,
    position: String,
    payload: Vec<u8>,
    truncated: bool,
}

impl DockerLogRead {
    // Returns the exact inspected Docker source identity.
    pub const fn source_identity(&self) -> &Sha256Digest {
        &self.source_identity
    }

    // Returns the provider cursor position for the next inclusive Docker read.
    pub fn position(&self) -> &str {
        &self.position
    }

    // Returns runtime-owned bytes without interpreting Engine content.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    // Returns whether older bytes were omitted by the response byte bound.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

// Reads bounded Docker local-driver output without interpreting runtime content.
pub trait LinuxDockerLogClient: Send + Sync {
    // Returns one immediate cursor-bound log batch for an exact validated container.
    fn read_logs(
        &self,
        plan: &LinuxContainerLaunchPlan,
        cursor: Option<&PlacementLogCursor>,
        maximum_lines: u32,
        maximum_bytes: usize,
    ) -> Result<DockerLogRead, PlacementError>;
}

// Adapts sealed Linux placement material and Docker's bounded local log driver.
pub struct DockerLinuxPlacementLogProvider {
    material: Arc<dyn LinuxPlacementMaterialProvider>,
    docker: Arc<dyn LinuxDockerLogClient>,
    waiter: Arc<dyn LinuxPlacementWaiter>,
}

impl DockerLinuxPlacementLogProvider {
    // Creates one provider from sealed material, Docker log access, and bounded waiting.
    pub const fn new(
        material: Arc<dyn LinuxPlacementMaterialProvider>,
        docker: Arc<dyn LinuxDockerLogClient>,
        waiter: Arc<dyn LinuxPlacementWaiter>,
    ) -> Self {
        Self {
            material,
            docker,
            waiter,
        }
    }

    // Reads once from the exact sealed container behind one placement.
    fn read_once(
        &self,
        placement: &Placement,
        request: &PlacementLogReadRequest,
    ) -> Result<DockerLogRead, PlacementError> {
        let plan = self
            .material
            .plan(placement)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        plan.validate_for(placement)?;
        self.docker.read_logs(
            &plan,
            request.cursor(),
            request.maximum_lines(),
            request.maximum_bytes(),
        )
    }
}

impl PlacementRuntimeLogProvider for DockerLinuxPlacementLogProvider {
    // Reads one bounded batch and performs at most one explicit long-poll wait.
    fn read(
        &self,
        placement: &Placement,
        request: &PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError> {
        let mut read = self.read_once(placement, request)?;
        if read.payload.is_empty() && !request.wait().is_zero() {
            self.waiter.wait(request.wait());
            read = self.read_once(placement, request)?;
        }
        PlacementLogBatch::new(
            placement.placement_group_id().clone(),
            placement.placement_id().clone(),
            PlacementLogCursor::new(read.source_identity, read.position)?,
            read.payload,
            read.truncated,
        )
    }
}

// Supplies exact boot, process-start, and cgroup facts for one inspected container.
pub trait LinuxProcessIdentityProvider: Send + Sync {
    // Binds one running Docker observation to current procfs identity.
    fn identity(
        &self,
        observation: &DockerContainerObservation,
    ) -> Result<LinuxProtectedProcessIdentity, PlacementError>;
}

// Checks one authenticated endpoint without interpreting model output.
pub trait LinuxEndpointReadinessProvider: Send + Sync {
    // Returns whether one exact endpoint satisfies its health contract now.
    fn is_ready(&self, endpoint: &PlacementEndpoint) -> Result<bool, PlacementError>;
}

// Waits one bounded readiness polling interval.
pub trait LinuxPlacementWaiter: Send + Sync {
    // Waits for one exact duration supplied by a validated readiness plan.
    fn wait(&self, duration: Duration);
}

// Sleeps using the host monotonic process wait facility.
#[derive(Default)]
pub struct SystemLinuxPlacementWaiter;

impl LinuxPlacementWaiter for SystemLinuxPlacementWaiter {
    // Sleeps for one validated bounded readiness interval.
    fn wait(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

// Owns bounded readiness polling across endpoint and exec mechanisms.
pub struct PollingLinuxContainerReadinessProvider {
    endpoints: Arc<dyn LinuxEndpointReadinessProvider>,
    waiter: Arc<dyn LinuxPlacementWaiter>,
}

impl PollingLinuxContainerReadinessProvider {
    // Creates one readiness owner from explicit endpoint and wait capabilities.
    pub const fn new(
        endpoints: Arc<dyn LinuxEndpointReadinessProvider>,
        waiter: Arc<dyn LinuxPlacementWaiter>,
    ) -> Self {
        Self { endpoints, waiter }
    }

    // Waits until one bounded readiness contract succeeds or exhausts its attempts.
    pub fn wait_until_ready(
        &self,
        plan: &LinuxContainerLaunchPlan,
        docker: &dyn LinuxDockerClient,
    ) -> Result<bool, PlacementError> {
        for attempt in 0..plan.readiness().attempts() {
            if self.is_ready(plan, docker)? {
                return Ok(true);
            }
            if attempt + 1 < plan.readiness().attempts() {
                self.waiter.wait(plan.readiness().interval());
            }
        }
        Ok(false)
    }

    // Checks one readiness contract exactly once.
    pub fn is_ready(
        &self,
        plan: &LinuxContainerLaunchPlan,
        docker: &dyn LinuxDockerClient,
    ) -> Result<bool, PlacementError> {
        match plan.readiness() {
            LinuxContainerReadiness::Endpoint { .. } => self
                .endpoints
                .is_ready(plan.endpoint().ok_or(PlacementError::EndpointUnavailable)?),
            LinuxContainerReadiness::Exec { arguments, .. } => {
                docker.exec_readiness(plan, arguments)
            }
        }
    }
}

// Executes one sealed Linux placement through Docker and procfs identity.
pub struct DockerLinuxPlacementExecutionProvider {
    material: Arc<dyn LinuxPlacementMaterialProvider>,
    docker: Arc<dyn LinuxDockerClient>,
    identities: Arc<dyn LinuxProcessIdentityProvider>,
    readiness: Arc<PollingLinuxContainerReadinessProvider>,
}

impl DockerLinuxPlacementExecutionProvider {
    // Creates one provider from explicit material, Docker, identity, and readiness capabilities.
    pub const fn new(
        material: Arc<dyn LinuxPlacementMaterialProvider>,
        docker: Arc<dyn LinuxDockerClient>,
        identities: Arc<dyn LinuxProcessIdentityProvider>,
        readiness: Arc<PollingLinuxContainerReadinessProvider>,
    ) -> Self {
        Self {
            material,
            docker,
            identities,
            readiness,
        }
    }

    // Returns one required sealed plan matching the supplied placement.
    fn required_plan(
        &self,
        placement: &Placement,
    ) -> Result<LinuxContainerLaunchPlan, PlacementError> {
        let plan = self
            .material
            .plan(placement)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        plan.validate_for(placement)?;
        Ok(plan)
    }

    // Requires one Docker observation to match all protected plan identity.
    fn validate_observation(
        plan: &LinuxContainerLaunchPlan,
        observation: &DockerContainerObservation,
    ) -> Result<(), PlacementError> {
        if observation.container_name() != plan.container_name()
            || observation.image_id() != plan.image_id()
            || plan
                .expected_labels()
                .iter()
                .any(|(key, value)| observation.labels().get(key) != Some(value))
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(())
    }
}

impl LinuxPlacementExecutionProvider for DockerLinuxPlacementExecutionProvider {
    // Stages exact inputs and returns the material owner's durable plan identity.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.material.stage(placement)
    }

    // Creates, restarts, or reuses only one exact validated container.
    fn start(
        &self,
        placement: &Placement,
    ) -> Result<LinuxProtectedProcessIdentity, PlacementError> {
        let plan = self.required_plan(placement)?;
        match self.docker.inspect(&plan)? {
            None => self.docker.create_and_start(&plan)?,
            Some(observation) => {
                Self::validate_observation(&plan, &observation)?;
                if !observation.running() {
                    self.docker.start(&plan)?;
                }
            }
        }
        let observation = self
            .docker
            .inspect(&plan)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        Self::validate_observation(&plan, &observation)?;
        if !observation.running() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.identities.identity(&observation)
    }

    // Polls the sealed runtime-owned readiness contract to its exact bound.
    fn wait_until_ready(
        &self,
        placement: &Placement,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<bool, PlacementError> {
        let plan = self.required_plan(placement)?;
        if process.container_name() != plan.container_name() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.readiness.wait_until_ready(&plan, self.docker.as_ref())
    }

    // Returns the sealed endpoint without performing a second routing decision.
    fn endpoint(
        &self,
        placement: &Placement,
        process: &LinuxProtectedProcessIdentity,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        let plan = self.required_plan(placement)?;
        if process.container_name() != plan.container_name() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(plan.endpoint().cloned())
    }

    // Stops and removes only the exact container created by an incomplete start.
    fn rollback_start(
        &self,
        placement: &Placement,
        _process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<(), PlacementError> {
        let plan = self.required_plan(placement)?;
        if let Some(observation) = self.docker.inspect(&plan)? {
            Self::validate_observation(&plan, &observation)?;
            if observation.running() {
                self.docker.stop(&plan)?;
            }
            self.docker.remove(&plan)?;
        }
        Ok(())
    }

    // Stops and removes one exact validated container while preserving staged inputs.
    fn stop(&self, placement: &Placement) -> Result<(), PlacementError> {
        self.rollback_start(placement, None)
    }

    // Removes staged inputs only after exact container absence is proven.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError> {
        let Some(plan) = self.material.plan(placement)? else {
            if matches!(
                placement.state(),
                li_core_interface::PlacementState::Pending
                    | li_core_interface::PlacementState::Staging
                    | li_core_interface::PlacementState::Failed
                    | li_core_interface::PlacementState::Removed
            ) {
                return self.material.remove(placement);
            }
            return Err(PlacementError::ExecutionUnavailable);
        };
        plan.validate_for(placement)?;
        if self.docker.inspect(&plan)?.is_some() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.material.remove(placement)
    }

    // Observes exact container identity, procfs process identity, readiness, and endpoint.
    fn observe(
        &self,
        placement: &Placement,
    ) -> Result<LinuxPlacementExecutionObservation, PlacementError> {
        let Some(plan) = self.material.plan(placement)? else {
            return LinuxPlacementExecutionObservation::new(
                LinuxPlacementExecutionState::Absent,
                None,
                false,
                None,
            );
        };
        plan.validate_for(placement)?;
        let Some(observation) = self.docker.inspect(&plan)? else {
            let state = match placement.state() {
                li_core_interface::PlacementState::Stopped => LinuxPlacementExecutionState::Stopped,
                li_core_interface::PlacementState::Removed => LinuxPlacementExecutionState::Removed,
                _ => LinuxPlacementExecutionState::Staged,
            };
            return LinuxPlacementExecutionObservation::new(state, None, false, None);
        };
        Self::validate_observation(&plan, &observation)?;
        if !observation.running() {
            return LinuxPlacementExecutionObservation::new(
                LinuxPlacementExecutionState::Failed,
                None,
                false,
                None,
            );
        }
        let process = self.identities.identity(&observation)?;
        let ready = self.readiness.is_ready(&plan, self.docker.as_ref())?;
        LinuxPlacementExecutionObservation::new(
            LinuxPlacementExecutionState::Running,
            Some(process),
            ready,
            ready.then(|| plan.endpoint().cloned()).flatten(),
        )
    }
}

// Executes fixed Docker CLI argv through the shell-free command runner.
pub struct SystemDockerClient {
    runner: Arc<dyn ShellFreeCommandRunner>,
}

impl SystemDockerClient {
    // Creates one Docker client from the single shell-free process owner.
    pub const fn new(runner: Arc<dyn ShellFreeCommandRunner>) -> Self {
        Self { runner }
    }

    // Executes one fixed Docker subcommand derived from the sealed create command.
    fn run(
        &self,
        plan: &LinuxContainerLaunchPlan,
        arguments: Vec<String>,
        maximum_stdout_bytes: usize,
    ) -> Result<crate::ShellFreeCommandOutput, PlacementError> {
        let command = plan.create_command().with_arguments(arguments)?;
        self.runner.run(&command, maximum_stdout_bytes)
    }

    // Runs one fixed Docker subcommand and retains both bounded runtime output streams.
    fn run_combined(
        &self,
        plan: &LinuxContainerLaunchPlan,
        arguments: Vec<String>,
        maximum_output_bytes: usize,
    ) -> Result<crate::ShellFreeCommandOutput, PlacementError> {
        let command = plan.create_command().with_arguments(arguments)?;
        self.runner.run_combined(&command, maximum_output_bytes)
    }

    // Requires one Docker subcommand to exit successfully.
    fn require_success(output: crate::ShellFreeCommandOutput) -> Result<(), PlacementError> {
        if output.status() == 0 {
            Ok(())
        } else {
            Err(PlacementError::ExecutionUnavailable)
        }
    }
}

impl LinuxDockerClient for SystemDockerClient {
    // Lists by exact name before parsing one bounded Docker inspection object.
    fn inspect(
        &self,
        plan: &LinuxContainerLaunchPlan,
    ) -> Result<Option<DockerContainerObservation>, PlacementError> {
        let name = plan.container_name().as_str();
        let listed = self.run(
            plan,
            vec![
                "container".to_string(),
                "ls".to_string(),
                "--all".to_string(),
                "--quiet".to_string(),
                "--no-trunc".to_string(),
                "--filter".to_string(),
                format!("name=^/{name}$"),
            ],
            256,
        )?;
        if listed.status() != 0 {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let listed = std::str::from_utf8(listed.stdout())
            .map_err(|_| PlacementError::ExecutionUnavailable)?
            .trim();
        if listed.is_empty() {
            return Ok(None);
        }
        let identities = listed.lines().collect::<Vec<_>>();
        if identities.len() != 1 || identities[0].len() != 64 {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Sha256Digest::parse(identities[0]).map_err(|_| PlacementError::ExecutionUnavailable)?;
        let inspected = self.run(
            plan,
            vec![
                "container".to_string(),
                "inspect".to_string(),
                "--format".to_string(),
                "{{json .}}".to_string(),
                "--".to_string(),
                identities[0].to_string(),
            ],
            MAX_INSPECT_BYTES,
        )?;
        if inspected.status() != 0 {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let observation = parse_docker_inspection(inspected.stdout())?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        if observation.container_id().as_str() != identities[0] {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(Some(observation))
    }

    // Runs the exact sealed Docker create command without a shell.
    fn create_and_start(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        Self::require_success(
            self.runner
                .run(plan.create_command(), 256)
                .map_err(|_| PlacementError::ExecutionUnavailable)?,
        )
    }

    // Starts one exact stopped container by protected name.
    fn start(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        Self::require_success(self.run(
            plan,
            vec![
                "container".to_string(),
                "start".to_string(),
                plan.container_name().as_str().to_string(),
            ],
            256,
        )?)
    }

    // Stops one exact container with a bounded graceful timeout.
    fn stop(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        Self::require_success(self.run(
            plan,
            vec![
                "container".to_string(),
                "stop".to_string(),
                "--time".to_string(),
                "30".to_string(),
                plan.container_name().as_str().to_string(),
            ],
            256,
        )?)
    }

    // Removes one exact stopped container without image or global pruning.
    fn remove(&self, plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        Self::require_success(self.run(
            plan,
            vec![
                "container".to_string(),
                "rm".to_string(),
                plan.container_name().as_str().to_string(),
            ],
            256,
        )?)
    }

    // Runs one validated readiness argv inside the exact container.
    fn exec_readiness(
        &self,
        plan: &LinuxContainerLaunchPlan,
        arguments: &[String],
    ) -> Result<bool, PlacementError> {
        validate_readiness_arguments(arguments)?;
        let mut command = vec![
            "container".to_string(),
            "exec".to_string(),
            plan.container_name().as_str().to_string(),
        ];
        command.extend_from_slice(arguments);
        Ok(self.run(plan, command, 256)?.status() == 0)
    }
}

impl LinuxDockerLogClient for SystemDockerClient {
    // Reads one bounded timestamped batch after revalidating exact protected container identity.
    fn read_logs(
        &self,
        plan: &LinuxContainerLaunchPlan,
        cursor: Option<&PlacementLogCursor>,
        maximum_lines: u32,
        maximum_bytes: usize,
    ) -> Result<DockerLogRead, PlacementError> {
        let observation = <Self as LinuxDockerClient>::inspect(self, plan)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        if observation.container_name() != plan.container_name()
            || observation.image_id() != plan.image_id()
            || plan
                .expected_labels()
                .iter()
                .any(|(key, value)| observation.labels().get(key) != Some(value))
            || cursor.is_some_and(|cursor| cursor.source_identity() != observation.container_id())
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let parsed_cursor = cursor.map(parse_docker_log_cursor).transpose()?;
        let mut arguments = vec![
            "container".to_string(),
            "logs".to_string(),
            "--timestamps".to_string(),
            "--tail".to_string(),
            maximum_lines.to_string(),
        ];
        if let Some((timestamp, _)) = &parsed_cursor {
            arguments.extend(["--since".to_string(), timestamp.clone()]);
        }
        arguments.push(plan.container_name().as_str().to_string());
        let output = self.run_combined(plan, arguments, MAXIMUM_DOCKER_LOG_READ_BYTES)?;
        if output.status() != 0 {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let (position, payload, truncated) =
            parse_docker_log_output(output.stdout(), parsed_cursor.as_ref(), maximum_bytes)?;
        Ok(DockerLogRead {
            source_identity: observation.container_id().clone(),
            position,
            payload,
            truncated,
        })
    }
}

// Reads exact process identity fields from injected procfs inputs.
pub trait LinuxProcessIdentityIo: Send + Sync {
    // Returns the current host boot identity.
    fn boot_id(&self) -> Result<String, PlacementError>;

    // Returns one bounded `/proc/PID/stat` payload.
    fn process_stat(&self, process_id: u32) -> Result<String, PlacementError>;

    // Returns one bounded `/proc/PID/cgroup` payload.
    fn process_cgroup(&self, process_id: u32) -> Result<String, PlacementError>;
}

// Reads Linux process identity from the active procfs mount.
#[derive(Default)]
pub struct SystemLinuxProcessIdentityIo;

impl LinuxProcessIdentityIo for SystemLinuxProcessIdentityIo {
    // Reads the canonical current Linux boot UUID.
    fn boot_id(&self) -> Result<String, PlacementError> {
        read_bounded_text(Path::new("/proc/sys/kernel/random/boot_id"), 128)
    }

    // Reads one exact bounded process-stat record.
    fn process_stat(&self, process_id: u32) -> Result<String, PlacementError> {
        read_bounded_text(
            &Path::new("/proc").join(process_id.to_string()).join("stat"),
            4_096,
        )
    }

    // Reads one exact bounded process-cgroup record.
    fn process_cgroup(&self, process_id: u32) -> Result<String, PlacementError> {
        read_bounded_text(
            &Path::new("/proc")
                .join(process_id.to_string())
                .join("cgroup"),
            8_192,
        )
    }
}

// Binds Docker inspection to Linux PID-reuse-safe process identity.
pub struct ProcfsLinuxProcessIdentityProvider {
    io: Arc<dyn LinuxProcessIdentityIo>,
}

impl ProcfsLinuxProcessIdentityProvider {
    // Creates one identity provider from an explicit procfs capability.
    pub const fn new(io: Arc<dyn LinuxProcessIdentityIo>) -> Self {
        Self { io }
    }
}

impl LinuxProcessIdentityProvider for ProcfsLinuxProcessIdentityProvider {
    // Reconstructs process start, boot, and unified cgroup identity exactly.
    fn identity(
        &self,
        observation: &DockerContainerObservation,
    ) -> Result<LinuxProtectedProcessIdentity, PlacementError> {
        if !observation.running() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let process_id = observation.process_id();
        LinuxProtectedProcessIdentity::new(
            observation.container_name().clone(),
            observation.container_id().clone(),
            process_id,
            parse_process_start_ticks(&self.io.process_stat(process_id)?)?,
            BootId::parse(self.io.boot_id()?.trim())
                .map_err(|_| PlacementError::ExecutionUnavailable)?,
            &parse_process_cgroup(&self.io.process_cgroup(process_id)?)?,
        )
    }
}

// Stores the Docker JSON fields required for exact identity checks.
#[derive(Deserialize)]
struct DockerInspectionDocument {
    #[serde(rename = "Id")]
    container_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "State")]
    state: DockerStateDocument,
    #[serde(rename = "Config")]
    configuration: DockerConfigurationDocument,
}

// Stores Docker process state without accepting additional policy.
#[derive(Deserialize)]
struct DockerStateDocument {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "Pid")]
    process_id: u32,
}

// Stores Docker labels required for sealed identity verification.
#[derive(Deserialize)]
struct DockerConfigurationDocument {
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
}

// Parses one bounded Docker inspection object into validated identity.
fn parse_docker_inspection(
    payload: &[u8],
) -> Result<Option<DockerContainerObservation>, PlacementError> {
    let document: DockerInspectionDocument =
        serde_json::from_slice(payload).map_err(|_| PlacementError::ExecutionUnavailable)?;
    let name = document
        .name
        .strip_prefix('/')
        .ok_or(PlacementError::ExecutionUnavailable)?;
    Ok(Some(DockerContainerObservation::new(
        TechnicalName::parse(name).map_err(|_| PlacementError::ExecutionUnavailable)?,
        Sha256Digest::parse(&document.container_id)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        Sha256Digest::parse(
            document
                .image
                .strip_prefix("sha256:")
                .ok_or(PlacementError::ExecutionUnavailable)?,
        )
        .map_err(|_| PlacementError::ExecutionUnavailable)?,
        document.state.running,
        document.state.process_id,
        document.configuration.labels.unwrap_or_default(),
    )?))
}

// Returns exact protected labels for one placement identity.
fn expected_labels(placement: &Placement) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.to_string(), "true".to_string()),
        (
            GROUP_LABEL.to_string(),
            placement.placement_group_id().as_str().to_string(),
        ),
        (
            PLACEMENT_LABEL.to_string(),
            placement.placement_id().as_str().to_string(),
        ),
        (
            NODE_LABEL.to_string(),
            placement.assignment().node_id().as_str().to_string(),
        ),
        (
            TASK_LABEL.to_string(),
            placement.assignment().task_id().as_str().to_string(),
        ),
    ])
}

// Parses one provider-issued Docker timestamp and same-timestamp occurrence cursor.
fn parse_docker_log_cursor(cursor: &PlacementLogCursor) -> Result<(String, usize), PlacementError> {
    let (timestamp, occurrence) = cursor
        .position()
        .rsplit_once('|')
        .ok_or(PlacementError::ExecutionUnavailable)?;
    if !valid_docker_timestamp(timestamp) {
        return Err(PlacementError::ExecutionUnavailable);
    }
    let occurrence = occurrence
        .parse::<usize>()
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    if occurrence > 10_000 {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok((timestamp.to_string(), occurrence))
}

// Filters Docker's inclusive `--since` result and preserves runtime bytes after timestamps.
fn parse_docker_log_output(
    payload: &[u8],
    cursor: Option<&(String, usize)>,
    maximum_bytes: usize,
) -> Result<(String, Vec<u8>, bool), PlacementError> {
    let mut output = Vec::new();
    let mut last_timestamp = cursor
        .map(|(timestamp, _)| timestamp.clone())
        .unwrap_or_else(|| "1970-01-01T00:00:00.000000000Z".to_string());
    let mut last_occurrence = cursor.map_or(0, |(_, occurrence)| *occurrence);
    let mut observed_timestamp = String::new();
    let mut observed_occurrence = 0_usize;
    for line in payload.split_inclusive(|byte| *byte == b'\n') {
        let separator = line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(PlacementError::ExecutionUnavailable)?;
        let timestamp = std::str::from_utf8(&line[..separator])
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if !valid_docker_timestamp(timestamp) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        if observed_timestamp == timestamp {
            observed_occurrence = observed_occurrence
                .checked_add(1)
                .ok_or(PlacementError::ExecutionUnavailable)?;
        } else {
            observed_timestamp.clear();
            observed_timestamp.push_str(timestamp);
            observed_occurrence = 1;
        }
        if cursor.is_some_and(|(position, occurrence)| {
            timestamp < position.as_str()
                || (timestamp == position.as_str() && observed_occurrence <= *occurrence)
        }) {
            continue;
        }
        output.extend_from_slice(&line[separator + 1..]);
        last_timestamp.clear();
        last_timestamp.push_str(timestamp);
        last_occurrence = observed_occurrence;
    }
    let truncated = output.len() > maximum_bytes;
    if truncated {
        let start = output.len() - maximum_bytes;
        let boundary = output[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(start, |offset| start + offset + 1);
        output.drain(..boundary);
    }
    Ok((
        format!("{last_timestamp}|{last_occurrence}"),
        output,
        truncated,
    ))
}

// Accepts only Docker's canonical bounded RFC3339 timestamp alphabet.
fn valid_docker_timestamp(value: &str) -> bool {
    (20..=64).contains(&value.len())
        && value.ends_with('Z')
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'.' | b'T' | b'Z' | b'+')
        })
}

// Requires one create command to bind every protected Docker identity exactly once.
fn validate_create_command(
    command: &ShellFreeCommand,
    container_name: &TechnicalName,
    image_reference: &RuntimeExecutionImageReference,
    expected_labels: &BTreeMap<String, String>,
) -> Result<(), PlacementError> {
    if command
        .executable()
        .file_name()
        .and_then(|value| value.to_str())
        != Some("docker")
        || command.arguments().first().map(String::as_str) != Some("run")
        || command
            .arguments()
            .iter()
            .filter(|value| value.as_str() == "--detach")
            .count()
            != 1
        || argument_value(command.arguments(), "--name")? != container_name.as_str()
        || argument_value(command.arguments(), "--restart")? != "no"
        || argument_value(command.arguments(), "--log-driver")? != "local"
        || repeated_argument_values(command.arguments(), "--log-opt")?
            != ["max-size=8m", "max-file=2"]
        || command
            .arguments()
            .iter()
            .filter(|value| value.as_str() == image_reference.as_str())
            .count()
            != 1
    {
        return Err(PlacementError::InvalidRequest {
            reason: "sealed Docker command lacks exact protected identity",
        });
    }
    let labels = repeated_argument_values(command.arguments(), "--label")?;
    if command.arguments().iter().any(|argument| {
        argument.starts_with("--name=")
            || argument.starts_with("--restart=")
            || argument.starts_with("--detach=")
            || argument.starts_with("--log-driver=")
            || argument.starts_with("--log-opt=")
            || argument == "--rm"
            || argument == "-l"
            || expected_labels.keys().any(|key| {
                argument
                    .strip_prefix("--label=")
                    .is_some_and(|value| value.starts_with(&format!("{key}=")))
            })
    }) {
        return Err(PlacementError::InvalidRequest {
            reason: "sealed Docker command contains alternate protected options",
        });
    }
    for (key, value) in expected_labels {
        let owned = labels
            .iter()
            .filter(|candidate| candidate.starts_with(&format!("{key}=")))
            .copied()
            .collect::<Vec<_>>();
        let expected = format!("{key}={value}");
        if owned.len() != 1 || owned[0] != expected {
            return Err(PlacementError::InvalidRequest {
                reason: "sealed Docker command lacks exact protected labels",
            });
        }
    }
    Ok(())
}

// Accepts either one signed digest-pinned source or its matching local config identity.
fn valid_image_reference(
    image_reference: &RuntimeExecutionImageReference,
    image_id: &Sha256Digest,
) -> bool {
    match image_reference.local_config_digest() {
        Some(config_digest) => {
            config_digest == image_id
                && image_reference.as_str() == format!("sha256:{}", config_digest.as_str())
        }
        None => image_reference.as_str().contains("@sha256:"),
    }
}

// Returns the unique value following one protected command option.
fn argument_value<'a>(arguments: &'a [String], option: &str) -> Result<&'a str, PlacementError> {
    let indices = arguments
        .iter()
        .enumerate()
        .filter(|(_, value)| value.as_str() == option)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if indices.len() != 1 || indices[0] + 1 >= arguments.len() {
        return Err(PlacementError::InvalidRequest {
            reason: "sealed Docker option is missing or duplicated",
        });
    }
    Ok(arguments[indices[0] + 1].as_str())
}

// Returns every value following one repeatable protected command option.
fn repeated_argument_values<'a>(
    arguments: &'a [String],
    option: &str,
) -> Result<Vec<&'a str>, PlacementError> {
    let mut values = Vec::new();
    for (index, value) in arguments.iter().enumerate() {
        if value == option {
            values.push(arguments.get(index + 1).map(String::as_str).ok_or(
                PlacementError::InvalidRequest {
                    reason: "sealed Docker repeatable option is incomplete",
                },
            )?);
        }
    }
    Ok(values)
}

// Requires endpoint presence to agree with exact placement ownership.
fn validate_endpoint(
    placement: &Placement,
    endpoint: Option<&PlacementEndpoint>,
) -> Result<(), PlacementError> {
    match placement.assignment().endpoint_ownership() {
        EndpointOwnership::Owner => {
            let endpoint = endpoint.ok_or(PlacementError::EndpointUnavailable)?;
            if endpoint.placement_id() != placement.placement_id()
                || endpoint.node_id() != placement.assignment().node_id()
            {
                return Err(PlacementError::EndpointUnavailable);
            }
        }
        EndpointOwnership::Participant if endpoint.is_some() => {
            return Err(PlacementError::EndpointUnavailable)
        }
        EndpointOwnership::Participant => {}
    }
    Ok(())
}

// Requires one bounded readiness polling contract.
fn validate_readiness(attempts: u16, interval: Duration) -> Result<(), PlacementError> {
    if attempts == 0
        || attempts > 3_600
        || interval.is_zero()
        || interval > Duration::from_secs(60)
        || Duration::from_millis(interval.as_millis() as u64) != interval
    {
        return Err(PlacementError::InvalidRequest {
            reason: "Linux container readiness bound is invalid",
        });
    }
    Ok(())
}

// Requires bounded shell-free in-container readiness argv.
fn validate_readiness_arguments(arguments: &[String]) -> Result<(), PlacementError> {
    let executable = arguments.first().map(Path::new);
    let forbidden = ["bash", "dash", "env", "fish", "ksh", "sh", "zsh"];
    if arguments.is_empty()
        || arguments.len() > 128
        || arguments.iter().map(String::len).sum::<usize>() > 16 * 1024
        || arguments.iter().any(|value| {
            value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
        })
        || executable.is_none_or(|value| !value.is_absolute())
        || executable
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .is_some_and(|value| forbidden.contains(&value))
    {
        return Err(PlacementError::InvalidRequest {
            reason: "Linux container readiness argv is invalid or unbounded",
        });
    }
    Ok(())
}

// Reads one bounded procfs text file.
fn read_bounded_text(path: &Path, maximum_bytes: usize) -> Result<String, PlacementError> {
    let file = File::open(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
    let mut payload = Vec::new();
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    if payload.is_empty() || payload.len() > maximum_bytes {
        return Err(PlacementError::ExecutionUnavailable);
    }
    String::from_utf8(payload).map_err(|_| PlacementError::ExecutionUnavailable)
}

// Parses Linux process field 22 without misreading spaces in the comm field.
fn parse_process_start_ticks(payload: &str) -> Result<u64, PlacementError> {
    let closing = payload
        .rfind(')')
        .ok_or(PlacementError::ExecutionUnavailable)?;
    let fields = payload
        .get(closing + 2..)
        .ok_or(PlacementError::ExecutionUnavailable)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let value = fields
        .get(19)
        .ok_or(PlacementError::ExecutionUnavailable)?
        .parse::<u64>()
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    if value == 0 {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(value)
}

// Parses one canonical unified-cgroup membership.
fn parse_process_cgroup(payload: &str) -> Result<String, PlacementError> {
    let relative = payload
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(PlacementError::ExecutionUnavailable)?;
    if !relative.starts_with('/')
        || relative.split('/').any(|component| component == "..")
        || relative.chars().any(char::is_control)
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(format!("/sys/fs/cgroup{relative}"))
}
