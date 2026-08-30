// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{
    EndpointOwnership, Placement, PlacementEndpoint, PlacementState, Sha256Digest, TechnicalName,
};
use sha2::{Digest, Sha256};

use crate::li_shell_free_command::validate_system_executable;
use crate::{
    PlacementError, PlacementExecutor, PlacementLogBatch, PlacementLogCursor,
    PlacementLogReadRequest, PlacementObservation, PlacementRuntimeLogProvider, ShellFreeCommand,
    ShellFreeCommandOutput, ShellFreeCommandRunner,
};

const MAX_PLIST_BYTES: usize = 1024 * 1024;
const MAX_LAUNCHCTL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAXIMUM_MACOS_LOG_RETAINED_BYTES: usize = 16 * 1024 * 1024;
const MACOS_LOG_COMPACTION_TARGET_BYTES: usize = 8 * 1024 * 1024;
const MACOS_LOG_CURSOR_ANCHOR_BYTES: usize = 64;

// Seals one native placement's exact launchd command, label, endpoint, and readiness bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosLaunchAgentPlan {
    placement_id: li_core_interface::PlacementId,
    runtime_installation_id: li_core_interface::RuntimeInstallationId,
    task_id: li_core_interface::TaskId,
    label: TechnicalName,
    command: ShellFreeCommand,
    executable_identity: Sha256Digest,
    endpoint: Option<PlacementEndpoint>,
    readiness_attempts: u16,
    readiness_interval: Duration,
    log_path: Option<PathBuf>,
}

impl MacosLaunchAgentPlan {
    // Creates one immutable native placement plan without invoking launchd.
    pub fn new(
        placement: &Placement,
        command: ShellFreeCommand,
        executable_identity: Sha256Digest,
        endpoint: Option<PlacementEndpoint>,
        readiness_attempts: u16,
        readiness_interval: Duration,
    ) -> Result<Self, PlacementError> {
        if readiness_attempts == 0
            || readiness_attempts > 3_600
            || readiness_interval.is_zero()
            || readiness_interval > Duration::from_secs(60)
            || Duration::from_millis(readiness_interval.as_millis() as u64) != readiness_interval
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS launchd readiness bound is invalid",
            });
        }
        validate_endpoint(placement, endpoint.as_ref())?;
        Ok(Self {
            placement_id: placement.placement_id().clone(),
            runtime_installation_id: placement.assignment().runtime_installation_id().clone(),
            task_id: placement.assignment().task_id().clone(),
            label: launch_agent_label(placement)?,
            command,
            executable_identity,
            endpoint,
            readiness_attempts,
            readiness_interval,
            log_path: None,
        })
    }

    // Binds both native output streams to one exact Core-owned private log destination.
    pub fn with_log_root(mut self, log_root: PathBuf) -> Result<Self, PlacementError> {
        if !log_root.is_absolute()
            || log_root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS placement log root is invalid",
            });
        }
        self.log_path =
            Some(log_root.join(format!("li_placement_{}.log", self.placement_id.as_str())));
        Ok(self)
    }

    // Requires this plan to match one exact immutable placement assignment.
    pub fn validate_for(&self, placement: &Placement) -> Result<(), PlacementError> {
        if &self.placement_id != placement.placement_id()
            || &self.runtime_installation_id != placement.assignment().runtime_installation_id()
            || &self.task_id != placement.assignment().task_id()
            || self.label != launch_agent_label(placement)?
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS launchd plan differs from its placement",
            });
        }
        validate_endpoint(placement, self.endpoint.as_ref())
    }

    // Returns the exact reverse-DNS launchd label.
    pub const fn label(&self) -> &TechnicalName {
        &self.label
    }

    // Returns the exact placement identity sealed by this plan.
    pub const fn placement_id(&self) -> &li_core_interface::PlacementId {
        &self.placement_id
    }

    // Returns the exact runtime installation consumed by this plan.
    pub const fn runtime_installation_id(&self) -> &li_core_interface::RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the opaque runtime task identity sealed by this plan.
    pub const fn task_id(&self) -> &li_core_interface::TaskId {
        &self.task_id
    }

    // Returns the complete shell-free native Engine command.
    pub const fn command(&self) -> &ShellFreeCommand {
        &self.command
    }

    // Returns the verified runtime executable identity sealed before launchd activation.
    pub const fn executable_identity(&self) -> &Sha256Digest {
        &self.executable_identity
    }

    // Returns the endpoint published only after service and health readiness.
    pub const fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }

    // Returns the bounded readiness attempt count.
    pub const fn readiness_attempts(&self) -> u16 {
        self.readiness_attempts
    }

    // Returns the bounded readiness polling interval.
    pub const fn readiness_interval(&self) -> Duration {
        self.readiness_interval
    }

    // Returns the exact Core-owned combined output path when native logging is configured.
    pub const fn log_path(&self) -> Option<&PathBuf> {
        self.log_path.as_ref()
    }
}

// Identifies current launchd registration and process state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosLaunchAgentStatus {
    Unconfigured,
    Inactive,
    Active,
    Failed,
}

// Supplies sealed native plans and owns staged placement inputs.
pub trait MacosPlacementMaterialProvider: Send + Sync {
    // Stages exact inputs and returns their immutable launch-plan identity.
    fn stage(
        &self,
        placement: &Placement,
    ) -> Result<li_core_interface::Sha256Digest, PlacementError>;

    // Returns the exact sealed plan when staging is complete.
    fn plan(&self, placement: &Placement) -> Result<Option<MacosLaunchAgentPlan>, PlacementError>;

    // Removes only exact staged inputs after launchd process absence.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError>;
}

// Defines exact launchd registration and process-state operations.
pub trait MacosLaunchAgentService: Send + Sync {
    // Installs and starts one exact launch agent idempotently.
    fn install(&self, plan: &MacosLaunchAgentPlan) -> Result<(), PlacementError>;

    // Removes one exact launch agent and its owned plist idempotently.
    fn remove(&self, plan: &MacosLaunchAgentPlan) -> Result<(), PlacementError>;

    // Returns current registration and process state for one exact plan.
    fn status(&self, plan: &MacosLaunchAgentPlan)
        -> Result<MacosLaunchAgentStatus, PlacementError>;
}

// Checks one authenticated native Engine endpoint.
pub trait MacosEndpointReadinessProvider: Send + Sync {
    // Returns whether one exact endpoint satisfies its health contract now.
    fn is_ready(&self, endpoint: &PlacementEndpoint) -> Result<bool, PlacementError>;
}

// Waits one bounded macOS readiness polling interval.
pub trait MacosPlacementWaiter: Send + Sync {
    // Waits for one exact duration supplied by a validated launch plan.
    fn wait(&self, duration: Duration);
}

// Sleeps using the host process wait facility.
#[derive(Default)]
pub struct SystemMacosPlacementWaiter;

impl MacosPlacementWaiter for SystemMacosPlacementWaiter {
    // Sleeps for one validated bounded readiness interval.
    fn wait(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

// Executes one native placement through launchd without a separate Watchdog process.
pub struct MacosPlacementExecutor {
    material: Arc<dyn MacosPlacementMaterialProvider>,
    launchd: Arc<dyn MacosLaunchAgentService>,
    endpoints: Arc<dyn MacosEndpointReadinessProvider>,
    waiter: Arc<dyn MacosPlacementWaiter>,
}

impl MacosPlacementExecutor {
    // Creates one executor from explicit material, launchd, endpoint, and wait capabilities.
    pub const fn new(
        material: Arc<dyn MacosPlacementMaterialProvider>,
        launchd: Arc<dyn MacosLaunchAgentService>,
        endpoints: Arc<dyn MacosEndpointReadinessProvider>,
        waiter: Arc<dyn MacosPlacementWaiter>,
    ) -> Self {
        Self {
            material,
            launchd,
            endpoints,
            waiter,
        }
    }

    // Returns one required sealed plan matching the supplied placement.
    fn required_plan(&self, placement: &Placement) -> Result<MacosLaunchAgentPlan, PlacementError> {
        let plan = self
            .material
            .plan(placement)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        plan.validate_for(placement)?;
        Ok(plan)
    }

    // Returns whether launchd and the optional endpoint are both ready now.
    fn is_ready(&self, plan: &MacosLaunchAgentPlan) -> Result<bool, PlacementError> {
        if self.launchd.status(plan)? != MacosLaunchAgentStatus::Active {
            return Ok(false);
        }
        self.endpoint_is_ready(plan)
    }

    // Returns whether the optional endpoint is ready after launchd is known active.
    fn endpoint_is_ready(&self, plan: &MacosLaunchAgentPlan) -> Result<bool, PlacementError> {
        match plan.endpoint() {
            Some(endpoint) => self.endpoints.is_ready(endpoint),
            None => Ok(true),
        }
    }

    // Waits to one exact plan bound without hiding endpoint errors.
    fn wait_until_ready(&self, plan: &MacosLaunchAgentPlan) -> Result<bool, PlacementError> {
        for attempt in 0..plan.readiness_attempts() {
            if self.is_ready(plan)? {
                return Ok(true);
            }
            if attempt + 1 < plan.readiness_attempts() {
                self.waiter.wait(plan.readiness_interval());
            }
        }
        Ok(false)
    }
}

impl PlacementExecutor for MacosPlacementExecutor {
    // Stages exact native inputs and returns identity without changing launchd state.
    fn stage(
        &self,
        placement: &Placement,
    ) -> Result<li_core_interface::Sha256Digest, PlacementError> {
        self.material.stage(placement)
    }

    // Installs one exact launch agent and publishes its endpoint only after readiness.
    fn start(
        &self,
        placement: &Placement,
        _acknowledge_protection_trip: bool,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        let plan = self.required_plan(placement)?;
        if self.launchd.status(&plan)? != MacosLaunchAgentStatus::Active {
            self.launchd.install(&plan)?;
        }
        match self.wait_until_ready(&plan) {
            Ok(true) => Ok(plan.endpoint().cloned()),
            Ok(false) => {
                let _ = self.launchd.remove(&plan);
                Err(PlacementError::ExecutionUnavailable)
            }
            Err(error) => {
                let _ = self.launchd.remove(&plan);
                Err(error)
            }
        }
    }

    // Removes one exact launchd agent while preserving staged inputs.
    fn stop(&self, placement: &Placement) -> Result<(), PlacementError> {
        let plan = self.required_plan(placement)?;
        self.launchd.remove(&plan)
    }

    // Removes staged inputs only after launchd reports the agent inactive.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError> {
        let Some(plan) = self.material.plan(placement)? else {
            if matches!(
                placement.state(),
                PlacementState::Pending
                    | PlacementState::Staging
                    | PlacementState::Failed
                    | PlacementState::Removed
            ) {
                return self.material.remove(placement);
            }
            return Err(PlacementError::ExecutionUnavailable);
        };
        plan.validate_for(placement)?;
        if self.launchd.status(&plan)? == MacosLaunchAgentStatus::Active {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.material.remove(placement)
    }

    // Combines durable placement intent with actual launchd and endpoint state.
    fn observe(&self, placement: &Placement) -> Result<PlacementObservation, PlacementError> {
        let Some(plan) = self.material.plan(placement)? else {
            let state = if placement.state() == PlacementState::Removed {
                PlacementState::Removed
            } else {
                PlacementState::Failed
            };
            return Ok(PlacementObservation::new(state, None, false));
        };
        plan.validate_for(placement)?;
        let (state, endpoint) = match self.launchd.status(&plan)? {
            MacosLaunchAgentStatus::Active if self.endpoint_is_ready(&plan)? => {
                (PlacementState::Running, plan.endpoint().cloned())
            }
            MacosLaunchAgentStatus::Active | MacosLaunchAgentStatus::Failed => {
                (PlacementState::Failed, None)
            }
            MacosLaunchAgentStatus::Inactive | MacosLaunchAgentStatus::Unconfigured => {
                match placement.state() {
                    PlacementState::Staged => (PlacementState::Staged, None),
                    PlacementState::Stopped => (PlacementState::Stopped, None),
                    PlacementState::Removed => (PlacementState::Removed, None),
                    _ => (PlacementState::Failed, None),
                }
            }
        };
        Ok(PlacementObservation::new(state, endpoint, false))
    }
}

// Defines exact owner-checked plist file operations.
pub trait MacosLaunchAgentIo: Send + Sync {
    // Reads one private plist or reports exact absence.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError>;

    // Atomically writes one private plist and syncs its directory.
    fn write_atomic_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Removes one exact private plist and reports whether it existed.
    fn remove_private_file(&self, path: &Path, owner_user_id: u32) -> Result<bool, PlacementError>;

    // Creates or compacts one exact owner-only runtime log destination.
    fn prepare_private_log_file(
        &self,
        _path: &Path,
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }

    // Reads one bounded owner-only runtime log batch through a no-follow descriptor.
    fn read_private_log_file(
        &self,
        _path: &Path,
        _owner_user_id: u32,
        _cursor: Option<&PlacementLogCursor>,
        _maximum_lines: u32,
        _maximum_bytes: usize,
    ) -> Result<MacosPrivateLogRead, PlacementError> {
        Err(PlacementError::ExecutionUnavailable)
    }
}

// Carries one bounded private-file result before Placement identity projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosPrivateLogRead {
    source_identity: Sha256Digest,
    position: String,
    payload: Vec<u8>,
    truncated: bool,
}

// Performs owner-checked, no-follow, durable LaunchAgents file operations.
#[derive(Default)]
pub struct SystemMacosLaunchAgentIo {
    temporary_counter: AtomicU64,
}

impl MacosLaunchAgentIo for SystemMacosLaunchAgentIo {
    // Reads one bounded private plist through a no-follow descriptor.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        };
        let metadata = file
            .metadata()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        validate_private_plist(&metadata, owner_user_id, maximum_bytes)?;
        let mut payload = Vec::new();
        file.take(maximum_bytes as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if payload.len() > maximum_bytes {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(Some(payload))
    }

    // Writes one private plist through an exclusive same-directory temporary.
    fn write_atomic_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if payload.is_empty() || payload.len() > MAX_PLIST_BYTES {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let parent = path.parent().ok_or(PlacementError::ExecutionUnavailable)?;
        ensure_launch_agents_directory(parent, owner_user_id)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_private_plist(&metadata, owner_user_id, MAX_PLIST_BYTES)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(PlacementError::ExecutionUnavailable)?;
        let counter = self.temporary_counter.fetch_add(1, Ordering::SeqCst);
        let temporary = parent.join(format!(
            ".{name}.li_incoming_{}_{}",
            std::process::id(),
            counter
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            file.write_all(payload)
                .and_then(|_| file.sync_all())
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            drop(file);
            fs::rename(&temporary, path).map_err(|_| PlacementError::ExecutionUnavailable)?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    // Removes one exact private plist without following a symlink.
    fn remove_private_file(&self, path: &Path, owner_user_id: u32) -> Result<bool, PlacementError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        };
        validate_private_plist(&metadata, owner_user_id, MAX_PLIST_BYTES)?;
        fs::remove_file(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(path.parent().ok_or(PlacementError::ExecutionUnavailable)?)?;
        Ok(true)
    }

    // Creates and bounds one exact private runtime log without following links.
    fn prepare_private_log_file(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        let parent = path.parent().ok_or(PlacementError::ExecutionUnavailable)?;
        ensure_private_log_directory(parent, owner_user_id)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_private_log(&metadata, owner_user_id)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        validate_private_log(
            &file
                .metadata()
                .map_err(|_| PlacementError::ExecutionUnavailable)?,
            owner_user_id,
        )?;
        compact_private_log(&mut file)?;
        Ok(())
    }

    // Reads and cursors one exact private runtime log after bounding its retention.
    fn read_private_log_file(
        &self,
        path: &Path,
        owner_user_id: u32,
        cursor: Option<&PlacementLogCursor>,
        maximum_lines: u32,
        maximum_bytes: usize,
    ) -> Result<MacosPrivateLogRead, PlacementError> {
        validate_private_log_directory(
            path.parent().ok_or(PlacementError::ExecutionUnavailable)?,
            owner_user_id,
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        validate_private_log(&metadata, owner_user_id)?;
        let source_identity = private_log_source_identity(&metadata)?;
        if cursor.is_some_and(|value| value.source_identity() != &source_identity) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let retention_truncated = compact_private_log(&mut file)?;
        let mut retained = Vec::new();
        file.seek(SeekFrom::Start(0))
            .and_then(|_| {
                file.take(MAXIMUM_MACOS_LOG_RETAINED_BYTES as u64 + 1)
                    .read_to_end(&mut retained)
            })
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if retained.len() > MAXIMUM_MACOS_LOG_RETAINED_BYTES {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let requested_start = match cursor {
            Some(value) => validate_private_log_cursor(value, &retained)?,
            None => 0,
        };
        let start = if cursor.is_some() {
            requested_start
        } else {
            bounded_log_tail_start(&retained, maximum_lines, maximum_bytes)
        };
        let end = bounded_log_batch_end(&retained, start, maximum_lines, maximum_bytes);
        let position = private_log_cursor_position(end, &retained);
        Ok(MacosPrivateLogRead {
            source_identity,
            position,
            payload: retained[start..end].to_vec(),
            truncated: retention_truncated || start > requested_start || end < retained.len(),
        })
    }
}

// Adapts sealed macOS placement material to one owner-only bounded file reader.
pub struct FilesystemMacosPlacementLogProvider {
    material: Arc<dyn MacosPlacementMaterialProvider>,
    io: Arc<dyn MacosLaunchAgentIo>,
    waiter: Arc<dyn MacosPlacementWaiter>,
    owner_user_id: u32,
}

impl FilesystemMacosPlacementLogProvider {
    // Creates one provider from sealed material, private I/O, bounded waiting, and owner identity.
    pub const fn new(
        material: Arc<dyn MacosPlacementMaterialProvider>,
        io: Arc<dyn MacosLaunchAgentIo>,
        waiter: Arc<dyn MacosPlacementWaiter>,
        owner_user_id: u32,
    ) -> Self {
        Self {
            material,
            io,
            waiter,
            owner_user_id,
        }
    }

    // Reads once from the exact Core-owned destination sealed with one placement.
    fn read_once(
        &self,
        placement: &Placement,
        request: &PlacementLogReadRequest,
    ) -> Result<MacosPrivateLogRead, PlacementError> {
        let plan = self
            .material
            .plan(placement)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
        plan.validate_for(placement)?;
        let path = plan
            .log_path()
            .ok_or(PlacementError::ExecutionUnavailable)?;
        self.io.read_private_log_file(
            path,
            self.owner_user_id,
            request.cursor(),
            request.maximum_lines(),
            request.maximum_bytes(),
        )
    }
}

impl PlacementRuntimeLogProvider for FilesystemMacosPlacementLogProvider {
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

// Controls exact launchd jobs through fixed shell-free launchctl argv.
pub struct SystemMacosLaunchAgentService {
    launch_agents_root: PathBuf,
    owner_user_id: u32,
    launchctl: ShellFreeCommand,
    runner: Arc<dyn ShellFreeCommandRunner>,
    io: Arc<dyn MacosLaunchAgentIo>,
}

impl SystemMacosLaunchAgentService {
    // Creates one user-domain launchd service owner from explicit native capabilities.
    pub fn new(
        launch_agents_root: PathBuf,
        owner_user_id: u32,
        launchctl: ShellFreeCommand,
        runner: Arc<dyn ShellFreeCommandRunner>,
        io: Arc<dyn MacosLaunchAgentIo>,
    ) -> Result<Self, PlacementError> {
        if !launch_agents_root.is_absolute()
            || launch_agents_root
                .file_name()
                .and_then(|value| value.to_str())
                != Some("LaunchAgents")
            || launchctl
                .executable()
                .file_name()
                .and_then(|value| value.to_str())
                != Some("launchctl")
            || launchctl
                .environment()
                .iter()
                .any(|value| !value.is_core_owned())
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS launchd service configuration is invalid",
            });
        }
        Ok(Self {
            launch_agents_root,
            owner_user_id,
            launchctl,
            runner,
            io,
        })
    }

    // Returns the exact owned plist path for one launch plan.
    fn plist_path(&self, plan: &MacosLaunchAgentPlan) -> PathBuf {
        self.launch_agents_root
            .join(format!("{}.plist", plan.label().as_str()))
    }

    // Returns the exact launchd GUI-domain target for one plan.
    fn target(&self, plan: &MacosLaunchAgentPlan) -> String {
        format!("gui/{}/{}", self.owner_user_id, plan.label().as_str())
    }

    // Executes one fixed launchctl subcommand through the shell-free runner.
    fn run(&self, arguments: Vec<String>) -> Result<ShellFreeCommandOutput, PlacementError> {
        let command = self.launchctl.with_arguments(arguments)?;
        self.runner.run(&command, MAX_LAUNCHCTL_OUTPUT_BYTES)
    }

    // Requires one fixed launchctl mutation to succeed.
    fn require_success(output: ShellFreeCommandOutput) -> Result<(), PlacementError> {
        if output.status() == 0 {
            Ok(())
        } else {
            Err(PlacementError::ExecutionUnavailable)
        }
    }
}

impl MacosLaunchAgentService for SystemMacosLaunchAgentService {
    // Installs an exact immutable plist and starts its user-domain launch agent.
    fn install(&self, plan: &MacosLaunchAgentPlan) -> Result<(), PlacementError> {
        validate_system_executable(plan.command().executable())?;
        if let Some(log_path) = plan.log_path() {
            self.io
                .prepare_private_log_file(log_path, self.owner_user_id)?;
        }
        let path = self.plist_path(plan);
        let expected = macos_launch_agent_plist(plan)?;
        let existing = self
            .io
            .read_private_file(&path, MAX_PLIST_BYTES, self.owner_user_id)?;
        if existing
            .as_deref()
            .is_some_and(|value| value != expected.as_bytes())
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        if self.status(plan)? == MacosLaunchAgentStatus::Active {
            return if existing.as_deref() == Some(expected.as_bytes()) {
                Ok(())
            } else {
                Err(PlacementError::ExecutionUnavailable)
            };
        }
        let created = existing.is_none();
        if created {
            self.io
                .write_atomic_private_file(&path, expected.as_bytes(), self.owner_user_id)?;
        }
        let kickstart = || {
            Self::require_success(self.run(vec![
                "kickstart".to_string(),
                "-k".to_string(),
                self.target(plan),
            ])?)
        };
        let result = if created {
            Self::require_success(self.run(vec![
                "bootstrap".to_string(),
                format!("gui/{}", self.owner_user_id),
                path.to_string_lossy().into_owned(),
            ])?)
            .and_then(|_| kickstart())
        } else {
            match kickstart() {
                Ok(()) => Ok(()),
                Err(_) => {
                    let _ = self.run(vec!["bootout".to_string(), self.target(plan)]);
                    Self::require_success(self.run(vec![
                        "bootstrap".to_string(),
                        format!("gui/{}", self.owner_user_id),
                        path.to_string_lossy().into_owned(),
                    ])?)
                    .and_then(|_| kickstart())
                }
            }
        };
        if result.is_err() && created {
            let _ = self.run(vec!["bootout".to_string(), self.target(plan)]);
            let _ = self.io.remove_private_file(&path, self.owner_user_id);
        }
        result
    }

    // Boots out one exact job before removing only its owned plist.
    fn remove(&self, plan: &MacosLaunchAgentPlan) -> Result<(), PlacementError> {
        let status = self.status(plan)?;
        if status != MacosLaunchAgentStatus::Unconfigured {
            let bootout = self.run(vec!["bootout".to_string(), self.target(plan)])?;
            if bootout.status() != 0
                && (status != MacosLaunchAgentStatus::Inactive
                    || self
                        .run(vec!["print".to_string(), self.target(plan)])?
                        .status()
                        == 0)
            {
                return Err(PlacementError::ExecutionUnavailable);
            }
        }
        self.io
            .remove_private_file(&self.plist_path(plan), self.owner_user_id)?;
        Ok(())
    }

    // Reads one bounded launchctl print result without inferring success from a plist.
    fn status(
        &self,
        plan: &MacosLaunchAgentPlan,
    ) -> Result<MacosLaunchAgentStatus, PlacementError> {
        let plist_exists = self
            .io
            .read_private_file(&self.plist_path(plan), MAX_PLIST_BYTES, self.owner_user_id)?
            .is_some();
        let output = self.run(vec!["print".to_string(), self.target(plan)])?;
        if output.status() != 0 {
            return Ok(if plist_exists {
                MacosLaunchAgentStatus::Inactive
            } else {
                MacosLaunchAgentStatus::Unconfigured
            });
        }
        let text = std::str::from_utf8(output.stdout())
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if text.lines().any(|line| line.trim() == "state = running") {
            Ok(MacosLaunchAgentStatus::Active)
        } else if text.lines().any(|line| {
            let line = line.trim();
            line == "state = exited" || line.starts_with("last exit code =")
        }) {
            Ok(MacosLaunchAgentStatus::Failed)
        } else {
            Ok(MacosLaunchAgentStatus::Inactive)
        }
    }
}

// Returns the exact existing external launchd label for one placement.
fn launch_agent_label(placement: &Placement) -> Result<TechnicalName, PlacementError> {
    TechnicalName::parse(&format!(
        "ai.letsinfer.engine.{}",
        placement.placement_id().as_str()
    ))
    .map_err(|_| PlacementError::ExecutionUnavailable)
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

// Encodes one deterministic owner-only launchd plist without executing source text.
pub fn macos_launch_agent_plist(plan: &MacosLaunchAgentPlan) -> Result<String, PlacementError> {
    let arguments = std::iter::once(plan.command().executable().to_string_lossy().into_owned())
        .chain(plan.command().arguments().iter().cloned())
        .map(|value| format!("    <string>{}</string>\n", xml_escape(&value)))
        .collect::<String>();
    let environment = plan
        .command()
        .environment()
        .iter()
        .map(|value| {
            format!(
                "    <key>{}</key>\n    <string>{}</string>\n",
                xml_escape(value.name()),
                xml_escape(value.value())
            )
        })
        .collect::<String>();
    let log_path = plan.log_path().map_or_else(
        || "/dev/null".to_string(),
        |path| path.to_string_lossy().into_owned(),
    );
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n{}  </array>\n  <key>EnvironmentVariables</key>\n  <dict>\n{}  </dict>\n  <key>WorkingDirectory</key>\n  <string>{}</string>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <false/>\n  <key>StandardOutPath</key>\n  <string>{}</string>\n  <key>StandardErrorPath</key>\n  <string>{}</string>\n</dict>\n</plist>\n",
        xml_escape(plan.label().as_str()),
        arguments,
        environment,
        xml_escape(&plan.command().working_directory().to_string_lossy()),
        xml_escape(&log_path),
        xml_escape(&log_path),
    );
    if plist.len() > MAX_PLIST_BYTES {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(plist)
}

// Escapes one bounded plist string value without accepting markup.
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// Creates or validates one user-owned LaunchAgents directory.
fn ensure_launch_agents_directory(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.uid() != owner_user_id {
                return Err(PlacementError::ExecutionUnavailable);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
        }
        Err(_) => return Err(PlacementError::ExecutionUnavailable),
    }
    Ok(())
}

// Requires one owner-only regular plist with no group or world access.
fn validate_private_plist(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), PlacementError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Creates or validates one owner-only runtime log directory.
fn ensure_private_log_directory(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_log_directory_metadata(&metadata, owner_user_id),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            validate_private_log_directory(path, owner_user_id)
        }
        Err(_) => Err(PlacementError::ExecutionUnavailable),
    }
}

// Requires one existing owner-only runtime log directory without following a link.
fn validate_private_log_directory(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
    validate_private_log_directory_metadata(&metadata, owner_user_id)
}

// Requires exact directory type, ownership, and private permission bits.
fn validate_private_log_directory_metadata(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), PlacementError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Requires one owner-only regular runtime log descriptor.
fn validate_private_log(metadata: &fs::Metadata, owner_user_id: u32) -> Result<(), PlacementError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Compacts an oversized runtime log in place to a bounded newest-line suffix.
fn compact_private_log(file: &mut File) -> Result<bool, PlacementError> {
    let length = file
        .metadata()
        .map_err(|_| PlacementError::ExecutionUnavailable)?
        .len() as usize;
    if length <= MAXIMUM_MACOS_LOG_RETAINED_BYTES {
        return Ok(false);
    }
    let start = length.saturating_sub(MACOS_LOG_COMPACTION_TARGET_BYTES);
    let mut retained = Vec::new();
    file.seek(SeekFrom::Start(start as u64))
        .and_then(|_| {
            file.take(MACOS_LOG_COMPACTION_TARGET_BYTES as u64)
                .read_to_end(&mut retained)
        })
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    if start > 0 {
        let boundary = retained
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(retained.len(), |offset| offset + 1);
        retained.drain(..boundary);
    }
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&retained))
        .and_then(|_| file.set_len(retained.len() as u64))
        .and_then(|_| file.sync_all())
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    Ok(true)
}

// Derives one stable source identity from the exact open file object.
fn private_log_source_identity(metadata: &fs::Metadata) -> Result<Sha256Digest, PlacementError> {
    let mut digest = Sha256::new();
    digest.update(metadata.dev().to_be_bytes());
    digest.update(metadata.ino().to_be_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| PlacementError::ExecutionUnavailable)
}

// Validates one byte-offset cursor and its retained-prefix anchor.
fn validate_private_log_cursor(
    cursor: &PlacementLogCursor,
    payload: &[u8],
) -> Result<usize, PlacementError> {
    let (offset, anchor) = cursor
        .position()
        .split_once('|')
        .ok_or(PlacementError::ExecutionUnavailable)?;
    let offset = offset
        .parse::<usize>()
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    if offset > payload.len() || anchor != private_log_cursor_anchor(offset, payload) {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(offset)
}

// Returns the newest complete-line start within both requested response bounds.
fn bounded_log_tail_start(payload: &[u8], maximum_lines: u32, maximum_bytes: usize) -> usize {
    let byte_start = payload.len().saturating_sub(maximum_bytes);
    let line_start = payload
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(maximum_lines as usize)
        .map_or(0, |(index, _)| index + 1);
    let mut start = byte_start.max(line_start);
    if start > 0 && payload.get(start.wrapping_sub(1)) != Some(&b'\n') {
        start = payload[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(payload.len(), |offset| start + offset + 1);
    }
    start
}

// Returns one forward batch end bounded independently by line and byte limits.
fn bounded_log_batch_end(
    payload: &[u8],
    start: usize,
    maximum_lines: u32,
    maximum_bytes: usize,
) -> usize {
    let byte_end = start.saturating_add(maximum_bytes).min(payload.len());
    payload[start..byte_end]
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(maximum_lines.saturating_sub(1) as usize)
        .map_or(byte_end, |(offset, _)| start + offset + 1)
}

// Encodes one byte offset with an anchor over the immediately preceding retained bytes.
fn private_log_cursor_position(offset: usize, payload: &[u8]) -> String {
    format!("{offset}|{}", private_log_cursor_anchor(offset, payload))
}

// Hashes the bounded prefix suffix that proves one cursor has not been truncated underneath.
fn private_log_cursor_anchor(offset: usize, payload: &[u8]) -> String {
    let start = offset.saturating_sub(MACOS_LOG_CURSOR_ANCHOR_BYTES);
    let mut digest = Sha256::new();
    digest.update(&payload[start..offset]);
    format!("{:x}", digest.finalize())
}

// Syncs one LaunchAgents directory after an atomic plist mutation.
fn sync_directory(path: &Path) -> Result<(), PlacementError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PlacementError::ExecutionUnavailable)
}
