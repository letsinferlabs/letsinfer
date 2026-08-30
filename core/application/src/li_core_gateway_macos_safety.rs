// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "macos")]

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{InstallationId, NodeId, UnixMilliseconds};
use li_gateway_manager::{
    GatewayClock, GatewayError, GatewayMacOsPlacementSafetyLease,
    GatewayMacOsPlacementSafetyProvider, GatewayMacOsPlacementSafetySnapshot, GatewayRoute,
};
use li_placement_manager::{
    macos_launch_agent_plist, FilesystemPlacementMaterialReader, MacosLaunchAgentPlan,
    PlacementBenchmarkProcessProvider, PlacementError, ShellFreeCommand, ShellFreeCommandRunner,
    VersionedPlacementRecord,
};
use sha2::{Digest, Sha256};

use crate::li_core_native_service_supervisor::parse_launchd_loaded_job;

const MAXIMUM_LAUNCHCTL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAXIMUM_PLIST_BYTES: usize = 1024 * 1024;
const MAXIMUM_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

// Supplies one exact Node-owned placement projection without exposing database access to Gateway.
pub(crate) trait CoreGatewayMacOsSafetyInputPort: Send + Sync {
    // Returns complete placement and launch-plan bindings for one selected group.
    fn input(
        &self,
        placement_group_id: &li_core_interface::PlacementGroupId,
    ) -> Result<li_node_manager::NodeGatewayMacOsSafetyInput, GatewayError>;
}

impl CoreGatewayMacOsSafetyInputPort for crate::li_core_gateway_node_client::CoreGatewayNodeClient {
    // Delegates the typed owner-UID local Node capability.
    fn input(
        &self,
        placement_group_id: &li_core_interface::PlacementGroupId,
    ) -> Result<li_node_manager::NodeGatewayMacOsSafetyInput, GatewayError> {
        self.macos_safety_input(placement_group_id)
    }
}

#[cfg(test)]
impl CoreGatewayMacOsSafetyInputPort for li_node_manager::DatabasePlacementStore {
    // Keeps native observation tests focused while using the same Node-owned projection logic.
    fn input(
        &self,
        placement_group_id: &li_core_interface::PlacementGroupId,
    ) -> Result<li_node_manager::NodeGatewayMacOsSafetyInput, GatewayError> {
        self.gateway_macos_safety_input(placement_group_id)
            .map_err(|_| safety_error())
    }
}

// Carries one no-follow plist read with the metadata required for exact admission.
#[derive(Clone)]
struct CoreGatewayMacOsPlistObservation {
    bytes: Vec<u8>,
    is_regular: bool,
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
}

// Carries one kernel process identity and the hash of its current executable bytes.
#[derive(Clone)]
struct CoreGatewayMacOsProcessObservation {
    executable: PathBuf,
    executable_identity: li_core_interface::Sha256Digest,
    owner_user_id: u32,
    start_time: UnixMilliseconds,
}

// Isolates exact plist and process observations for deterministic admission tests.
trait CoreGatewayMacOsSafetyIo: Send + Sync {
    // Reads one bounded launch-agent plist without following its final path.
    fn plist(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreGatewayMacOsPlistObservation, GatewayError>;

    // Reads one exact live process and hashes its stable executable descriptor.
    fn process(&self, process_id: u32) -> Result<CoreGatewayMacOsProcessObservation, GatewayError>;
}

// Reads native safety observations directly from the current macOS host.
struct SystemCoreGatewayMacOsSafetyIo;

// Carries one fully matched process result into the expiring Gateway lease.
struct CoreGatewayMacOsLoadedProcess {
    process_id: u32,
    executable_identity: li_core_interface::Sha256Digest,
    start_time: UnixMilliseconds,
}

// Reuses exact launchd/plist/process admission to identify benchmark process generations.
pub(crate) struct SystemCoreMacosPlacementBenchmarkProcessProvider {
    owner_user_id: u32,
    launch_agents_root: PathBuf,
    material: FilesystemPlacementMaterialReader,
    launchctl: ShellFreeCommand,
    runner: Arc<dyn ShellFreeCommandRunner>,
    io: Arc<dyn CoreGatewayMacOsSafetyIo>,
}

impl SystemCoreMacosPlacementBenchmarkProcessProvider {
    // Creates one read-only process observer from the same sealed material and launchctl identity.
    pub(crate) fn new(
        owner_user_id: u32,
        launch_agents_root: PathBuf,
        material: FilesystemPlacementMaterialReader,
        launchctl: ShellFreeCommand,
        runner: Arc<dyn ShellFreeCommandRunner>,
    ) -> Self {
        Self {
            owner_user_id,
            launch_agents_root,
            material,
            launchctl,
            runner,
            io: Arc::new(SystemCoreGatewayMacOsSafetyIo),
        }
    }
}

impl PlacementBenchmarkProcessProvider for SystemCoreMacosPlacementBenchmarkProcessProvider {
    // Hashes exact sealed launch plan, executable, PID, and start-time identity for every placement.
    fn generation(
        &self,
        running: &VersionedPlacementRecord,
    ) -> Result<li_core_interface::Sha256Digest, PlacementError> {
        if running.record().placements().is_empty() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut digest = Sha256::new();
        benchmark_generation_field(&mut digest, "li-placement-macos-process-generation-v1");
        benchmark_generation_field(
            &mut digest,
            running.record().group().placement_group_id().as_str(),
        );
        for placement in running.record().placements() {
            let plan = self
                .material
                .macos_plan(placement)
                .map_err(|_| PlacementError::ExecutionUnavailable)?
                .ok_or(PlacementError::ExecutionUnavailable)?;
            let target = format!("gui/{}/{}", self.owner_user_id, plan.label().as_str());
            let output = self.runner.run(
                &self
                    .launchctl
                    .with_arguments(vec!["print".to_string(), target.clone()])?,
                MAXIMUM_LAUNCHCTL_OUTPUT_BYTES,
            )?;
            if output.status() != 0 {
                return Err(PlacementError::ExecutionUnavailable);
            }
            let text = std::str::from_utf8(output.stdout())
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            let process = observe_loaded_plan(
                &plan,
                self.owner_user_id,
                &self.launch_agents_root,
                &target,
                text,
                self.io.as_ref(),
            )
            .map_err(|_| PlacementError::ExecutionUnavailable)?
            .ok_or(PlacementError::ExecutionUnavailable)?;
            let launch_generation = running
                .record()
                .launch_plan_identity(placement.placement_id())
                .ok_or(PlacementError::ExecutionUnavailable)?;
            for value in [
                placement.placement_id().as_str().to_string(),
                plan.label().as_str().to_string(),
                launch_generation.as_str().to_string(),
                process.executable_identity.as_str().to_string(),
                process.process_id.to_string(),
                process.start_time.value().to_string(),
            ] {
                benchmark_generation_field(&mut digest, &value);
            }
        }
        li_core_interface::Sha256Digest::parse(&format!("{:x}", digest.finalize()))
            .map_err(|_| PlacementError::ExecutionUnavailable)
    }
}

// Observes exact committed macOS placement plans and their live launchd processes.
pub(crate) struct SystemCoreGatewayMacOsSafetyProvider {
    node_id: NodeId,
    installation_id: InstallationId,
    owner_user_id: u32,
    launch_agents_root: PathBuf,
    lease_milliseconds: u64,
    placements: Arc<dyn CoreGatewayMacOsSafetyInputPort>,
    material: FilesystemPlacementMaterialReader,
    launchctl: ShellFreeCommand,
    runner: Arc<dyn ShellFreeCommandRunner>,
    clock: Arc<dyn GatewayClock>,
    io: Arc<dyn CoreGatewayMacOsSafetyIo>,
}

impl SystemCoreGatewayMacOsSafetyProvider {
    // Creates one native observer from explicit store, filesystem, process, command, and clock inputs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        node_id: NodeId,
        installation_id: InstallationId,
        owner_user_id: u32,
        launch_agents_root: PathBuf,
        lease_milliseconds: u64,
        placements: Arc<dyn CoreGatewayMacOsSafetyInputPort>,
        material: FilesystemPlacementMaterialReader,
        launchctl: ShellFreeCommand,
        runner: Arc<dyn ShellFreeCommandRunner>,
        clock: Arc<dyn GatewayClock>,
    ) -> Result<Self, GatewayError> {
        Self::with_io(
            node_id,
            installation_id,
            owner_user_id,
            launch_agents_root,
            lease_milliseconds,
            placements,
            material,
            launchctl,
            runner,
            clock,
            Arc::new(SystemCoreGatewayMacOsSafetyIo),
        )
    }

    // Creates one native observer with injected read-only operating-system observations.
    #[allow(clippy::too_many_arguments)]
    fn with_io(
        node_id: NodeId,
        installation_id: InstallationId,
        owner_user_id: u32,
        launch_agents_root: PathBuf,
        lease_milliseconds: u64,
        placements: Arc<dyn CoreGatewayMacOsSafetyInputPort>,
        material: FilesystemPlacementMaterialReader,
        launchctl: ShellFreeCommand,
        runner: Arc<dyn ShellFreeCommandRunner>,
        clock: Arc<dyn GatewayClock>,
        io: Arc<dyn CoreGatewayMacOsSafetyIo>,
    ) -> Result<Self, GatewayError> {
        if lease_milliseconds == 0 || lease_milliseconds > 60_000 {
            return Err(safety_error());
        }
        Ok(Self {
            node_id,
            installation_id,
            owner_user_id,
            launch_agents_root,
            lease_milliseconds,
            placements,
            material,
            launchctl,
            runner,
            clock,
            io,
        })
    }

    // Observes one exact launchd job and its kernel process identity.
    fn lease(
        &self,
        group_id: &li_core_interface::PlacementGroupId,
        placement: &li_core_interface::Placement,
        launch_generation: li_core_interface::Sha256Digest,
        observed_at: UnixMilliseconds,
    ) -> Result<Option<GatewayMacOsPlacementSafetyLease>, GatewayError> {
        let Some(plan) = self
            .material
            .macos_plan_with_expected_identity(placement, &launch_generation)
            .map_err(|_| safety_error())?
        else {
            return Ok(None);
        };
        let target = format!("gui/{}/{}", self.owner_user_id, plan.label().as_str());
        let output = self
            .runner
            .run(
                &self
                    .launchctl
                    .with_arguments(vec!["print".to_string(), target.clone()])
                    .map_err(|_| safety_error())?,
                MAXIMUM_LAUNCHCTL_OUTPUT_BYTES,
            )
            .map_err(|_| safety_error())?;
        if output.status() != 0 {
            return Ok(None);
        }
        let text = std::str::from_utf8(output.stdout()).map_err(|_| safety_error())?;
        let Some(process) = observe_loaded_plan(
            &plan,
            self.owner_user_id,
            &self.launch_agents_root,
            &target,
            text,
            self.io.as_ref(),
        )?
        else {
            return Ok(None);
        };
        let expires_at = UnixMilliseconds::new(
            observed_at
                .value()
                .checked_add(self.lease_milliseconds)
                .ok_or_else(safety_error)?,
        );
        GatewayMacOsPlacementSafetyLease::new(
            self.node_id.clone(),
            group_id.clone(),
            placement.placement_id().clone(),
            self.installation_id.clone(),
            process.executable_identity,
            plan.label().as_str(),
            launch_generation,
            process.process_id,
            process.start_time,
            observed_at,
            expires_at,
        )
        .map(Some)
    }
}

// Proves the canonical plist, loaded launchd identity, and live process match one sealed plan.
fn observe_loaded_plan(
    plan: &MacosLaunchAgentPlan,
    owner_user_id: u32,
    launch_agents_root: &Path,
    target: &str,
    launchctl_output: &str,
    io: &dyn CoreGatewayMacOsSafetyIo,
) -> Result<Option<CoreGatewayMacOsLoadedProcess>, GatewayError> {
    let plist_path = launch_agents_root.join(format!("{}.plist", plan.label().as_str()));
    let plist = io.plist(&plist_path, MAXIMUM_PLIST_BYTES)?;
    let expected_plist = macos_launch_agent_plist(plan).map_err(|_| safety_error())?;
    if !plist.is_regular
        || plist.owner_user_id != owner_user_id
        || plist.mode != 0o600
        || plist.link_count != 1
        || plist.bytes != expected_plist.as_bytes()
    {
        return Err(safety_error());
    }
    let loaded = parse_launchd_loaded_job(launchctl_output, target).map_err(|_| safety_error())?;
    let executable = plan
        .command()
        .executable()
        .to_str()
        .ok_or_else(safety_error)?;
    let expected_arguments = std::iter::once(executable.to_string())
        .chain(plan.command().arguments().iter().cloned())
        .collect::<Vec<_>>();
    let environment_matches = loaded.environment().is_some_and(|environment| {
        plan.command()
            .environment()
            .iter()
            .all(|value| environment.get(value.name()).map(String::as_str) == Some(value.value()))
    });
    let working_directory_matches = loaded
        .working_directory()
        .is_some_and(|directory| directory == plan.command().working_directory());
    if !loaded.is_running()
        || loaded.path() != plist_path
        || loaded.program() != plan.command().executable()
        || loaded.arguments() != expected_arguments
        || !environment_matches
        || !working_directory_matches
    {
        return Ok(None);
    }
    let Some(process_id) = loaded.process_id() else {
        return Ok(None);
    };
    let process = io.process(process_id)?;
    if process.owner_user_id != owner_user_id
        || process.executable != plan.command().executable()
        || &process.executable_identity != plan.executable_identity()
    {
        return Ok(None);
    }
    Ok(Some(CoreGatewayMacOsLoadedProcess {
        process_id,
        executable_identity: process.executable_identity,
        start_time: process.start_time,
    }))
}

impl GatewayMacOsPlacementSafetyProvider for SystemCoreGatewayMacOsSafetyProvider {
    // Returns a complete group snapshot only when every local launchd process is exact and live.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayMacOsPlacementSafetySnapshot>, GatewayError> {
        let input = self.placements.input(route.placement_group_id())?;
        let observed_at = self.clock.now()?;
        let expected = input
            .placements()
            .iter()
            .map(|value| {
                (
                    value.placement().placement_id().clone(),
                    value.placement().assignment().node_id().clone(),
                )
            })
            .collect::<Vec<_>>();
        let mut leases = Vec::with_capacity(input.placements().len());
        for value in input.placements() {
            let placement = value.placement();
            if placement.assignment().node_id() != &self.node_id {
                return Ok(None);
            }
            let Some(lease) = self.lease(
                input.placement_group_id(),
                placement,
                value.launch_plan_identity().clone(),
                observed_at,
            )?
            else {
                return Ok(None);
            };
            leases.push(lease);
        }
        GatewayMacOsPlacementSafetySnapshot::new(
            input.placement_group_id().clone(),
            expected,
            leases,
        )
        .map(Some)
    }
}

impl CoreGatewayMacOsSafetyIo for SystemCoreGatewayMacOsSafetyIo {
    // Reads bytes and metadata from the same bounded no-follow plist descriptor.
    fn plist(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreGatewayMacOsPlistObservation, GatewayError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PLIST_BYTES {
            return Err(safety_error());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| safety_error())?;
        let metadata = file.metadata().map_err(|_| safety_error())?;
        if metadata.len() == 0 || metadata.len() > maximum_bytes as u64 {
            return Err(safety_error());
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| safety_error())?;
        if bytes.len() > maximum_bytes {
            return Err(safety_error());
        }
        Ok(CoreGatewayMacOsPlistObservation {
            bytes,
            is_regular: metadata.is_file(),
            owner_user_id: metadata.uid(),
            mode: metadata.mode() & 0o777,
            link_count: metadata.nlink(),
        })
    }

    // Reads one kernel process identity and hashes the executable reached by its exact path.
    fn process(&self, process_id: u32) -> Result<CoreGatewayMacOsProcessObservation, GatewayError> {
        let (executable, owner_user_id, start_time) = process_identity(process_id)?;
        let executable_identity = executable_identity(&executable)?;
        Ok(CoreGatewayMacOsProcessObservation {
            executable,
            executable_identity,
            owner_user_id,
            start_time,
        })
    }
}

// Reads exact executable path, owner, and start time for one live native process.
fn process_identity(process_id: u32) -> Result<(PathBuf, u32, UnixMilliseconds), GatewayError> {
    let mut path = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: The fixed writable buffer remains valid for the complete kernel call.
    let length = unsafe {
        libc::proc_pidpath(
            process_id as libc::c_int,
            path.as_mut_ptr().cast(),
            path.len() as u32,
        )
    };
    if length <= 0 || length as usize >= path.len() {
        return Err(safety_error());
    }
    path[length as usize] = 0;
    let executable = PathBuf::from(
        CStr::from_bytes_until_nul(&path)
            .map_err(|_| safety_error())?
            .to_str()
            .map_err(|_| safety_error())?,
    );
    // SAFETY: Zero is a valid initial byte representation and the kernel fills the exact struct.
    let mut information = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    // SAFETY: The structure pointer and byte count match PROC_PIDTBSDINFO.
    let size = unsafe {
        libc::proc_pidinfo(
            process_id as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut information as *mut libc::proc_bsdinfo).cast(),
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if size as usize != std::mem::size_of::<libc::proc_bsdinfo>()
        || information.pbi_pid != process_id
    {
        return Err(safety_error());
    }
    let milliseconds = information
        .pbi_start_tvsec
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(information.pbi_start_tvusec / 1_000))
        .ok_or_else(safety_error)?;
    Ok((
        executable,
        information.pbi_uid,
        UnixMilliseconds::new(milliseconds),
    ))
}

// Hashes one stable no-follow executable descriptor before admitting its process.
fn executable_identity(path: &Path) -> Result<li_core_interface::Sha256Digest, GatewayError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| safety_error())?;
    let before = file.metadata().map_err(|_| safety_error())?;
    if !before.is_file() || before.len() == 0 || before.len() > MAXIMUM_EXECUTABLE_BYTES {
        return Err(safety_error());
    }
    let mut digest = Sha256::new();
    let copied = std::io::copy(
        &mut file.by_ref().take(MAXIMUM_EXECUTABLE_BYTES + 1),
        &mut digest,
    )
    .map_err(|_| safety_error())?;
    let after = file.metadata().map_err(|_| safety_error())?;
    if copied != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(safety_error());
    }
    li_core_interface::Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| safety_error())
}

// Adds one unambiguous field to a complete native placement-process generation.
fn benchmark_generation_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

// Returns one stable fail-closed native safety-provider error.
fn safety_error() -> GatewayError {
    GatewayError::provider(
        "macOS placement safety",
        "native observation is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::time::Duration;

    use li_core_interface::{
        BootId, DeviceId, EndpointOwnership, EntityTimestamps, HardwareObservationId, NodeAddress,
        NodeId, Placement, PlacementAssignment, PlacementGroupId, PlacementId, PlacementResources,
        PlacementState, PortRange, RuntimeInstallationId, Sha256Digest, TaskId, UnixMilliseconds,
    };
    use li_placement_manager::{MacosLaunchAgentPlan, ShellFreeCommand, ShellFreeEnvironmentValue};

    use super::{
        observe_loaded_plan, CoreGatewayMacOsPlistObservation, CoreGatewayMacOsProcessObservation,
        CoreGatewayMacOsSafetyIo, GatewayError, SystemCoreGatewayMacOsSafetyIo,
    };

    const OWNER_USER_ID: u32 = 501;

    // Returns one exact participant placement that requires no endpoint fixture.
    fn placement() -> Placement {
        Placement::new(
            PlacementId::parse(&"1".repeat(32)).expect("placement"),
            PlacementGroupId::parse(&"2".repeat(32)).expect("group"),
            PlacementAssignment::new(
                NodeId::parse(&"3".repeat(32)).expect("node"),
                RuntimeInstallationId::parse(&"4".repeat(32)).expect("runtime"),
                HardwareObservationId::parse(&"5".repeat(32)).expect("hardware"),
                BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
                UnixMilliseconds::new(900),
                TaskId::parse("task-0").expect("task"),
                NodeAddress::parse("mac.local").expect("address"),
                PlacementResources::new(
                    PortRange::new(18_000, 2).expect("ports"),
                    vec![DeviceId::parse("Built-In").expect("device")],
                    None,
                )
                .expect("resources"),
                EndpointOwnership::Participant,
            ),
            PlacementState::Running,
            None,
            None,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
                .expect("timestamps"),
        )
        .expect("placement")
    }

    // Returns one sealed command and its expected executable content identity.
    fn plan() -> MacosLaunchAgentPlan {
        let placement = placement();
        MacosLaunchAgentPlan::new(
            &placement,
            ShellFreeCommand::new(
                PathBuf::from("/usr/bin/printf"),
                vec!["serve".to_string(), "--native".to_string()],
                vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "native")
                    .expect("runtime")],
                vec![ShellFreeEnvironmentValue::protected(
                    "LETSINFER_TASK_ID",
                    "task-0",
                )
                .expect("Core")],
                PathBuf::from("/tmp"),
            )
            .expect("command"),
            Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
            None,
            3,
            Duration::from_millis(10),
        )
        .expect("plan")
    }

    // Supplies exact preconfigured plist and process observations without native mutation.
    struct SafetyIoMock {
        plist: CoreGatewayMacOsPlistObservation,
        process: CoreGatewayMacOsProcessObservation,
        plist_failure: bool,
        process_failure: bool,
    }

    impl CoreGatewayMacOsSafetyIo for SafetyIoMock {
        // Returns the configured plist observation without reading the host filesystem.
        fn plist(
            &self,
            _path: &std::path::Path,
            _maximum_bytes: usize,
        ) -> Result<CoreGatewayMacOsPlistObservation, GatewayError> {
            if self.plist_failure {
                Err(super::safety_error())
            } else {
                Ok(self.plist.clone())
            }
        }

        // Returns the configured process observation without consulting the kernel.
        fn process(
            &self,
            _process_id: u32,
        ) -> Result<CoreGatewayMacOsProcessObservation, GatewayError> {
            if self.process_failure {
                Err(super::safety_error())
            } else {
                Ok(self.process.clone())
            }
        }
    }

    // Builds launchctl's represented identity for the exact fixture plan.
    fn loaded_identity(
        plan: &MacosLaunchAgentPlan,
        root: &std::path::Path,
        target: &str,
    ) -> String {
        format!(
            "{target} = {{\n\tpath = {}\n\tstate = running\n\tprogram = {}\n\targuments = {{\n\t\t{}\n\t\tserve\n\t\t--native\n\t}}\n\tenvironment = {{\n\t\tRUNTIME_MODE => native\n\t\tLETSINFER_TASK_ID => task-0\n\t\tXPC_SERVICE_NAME => {target}\n\t}}\n\tworking directory = /tmp\n\tpid = 42\n\tlast exit code = 1\n\tresource coalition = {{\n\t\tstate = active\n\t}}\n\tjetsam coalition = {{\n\t\tstate = active\n\t}}\n}}\n",
            root.join(format!("{}.plist", plan.label().as_str())).display(),
            plan.command().executable().display(),
            plan.command().executable().display(),
        )
    }

    // Creates the exact canonical mock observations for one plan.
    fn observations(plan: &MacosLaunchAgentPlan) -> SafetyIoMock {
        SafetyIoMock {
            plist: CoreGatewayMacOsPlistObservation {
                bytes: li_placement_manager::macos_launch_agent_plist(plan)
                    .expect("plist")
                    .into_bytes(),
                is_regular: true,
                owner_user_id: OWNER_USER_ID,
                mode: 0o600,
                link_count: 1,
            },
            process: CoreGatewayMacOsProcessObservation {
                executable: plan.command().executable().to_path_buf(),
                executable_identity: plan.executable_identity().clone(),
                owner_user_id: OWNER_USER_ID,
                start_time: UnixMilliseconds::new(900),
            },
            plist_failure: false,
            process_failure: false,
        }
    }

    // Returns whether every native observation produces one complete admitted process.
    fn is_admitted(
        plan: &MacosLaunchAgentPlan,
        root: &std::path::Path,
        target: &str,
        output: &str,
        io: &SafetyIoMock,
    ) -> bool {
        matches!(
            observe_loaded_plan(plan, OWNER_USER_ID, root, target, output, io),
            Ok(Some(_))
        )
    }

    // Proves exact canonical plan, plist, launchd, process, and executable identity admission.
    #[test]
    fn exact_sealed_plan_observation_is_admitted_without_launchd_mutation() {
        let plan = plan();
        let root = PathBuf::from("/Users/test/Library/LaunchAgents");
        let target = format!("gui/{OWNER_USER_ID}/{}", plan.label().as_str());
        let output = loaded_identity(&plan, &root, &target);
        let io = observations(&plan);
        let admitted = observe_loaded_plan(&plan, OWNER_USER_ID, &root, &target, &output, &io)
            .expect("observation")
            .expect("admitted");
        assert_eq!(admitted.process_id, 42);
        assert_eq!(admitted.executable_identity, *plan.executable_identity());
        assert_eq!(admitted.start_time, UnixMilliseconds::new(900));
    }

    // Rejects every meaningful disk, loaded-job, and live-process substitution independently.
    #[test]
    fn sealed_plan_admission_rejects_native_identity_drift() {
        let plan = plan();
        let root = PathBuf::from("/Users/test/Library/LaunchAgents");
        let target = format!("gui/{OWNER_USER_ID}/{}", plan.label().as_str());
        let exact_output = loaded_identity(&plan, &root, &target);

        let mut io = observations(&plan);
        io.plist.bytes.push(b' ');
        assert!(!is_admitted(&plan, &root, &target, &exact_output, &io));
        for mutation in ["type", "owner", "mode", "link"] {
            let mut io = observations(&plan);
            match mutation {
                "type" => io.plist.is_regular = false,
                "owner" => io.plist.owner_user_id += 1,
                "mode" => io.plist.mode = 0o644,
                "link" => io.plist.link_count = 2,
                _ => unreachable!(),
            }
            assert!(!is_admitted(&plan, &root, &target, &exact_output, &io));
        }

        let plist_path = root.join(format!("{}.plist", plan.label().as_str()));
        for output in [
            exact_output.replace(plist_path.to_string_lossy().as_ref(), "/tmp/foreign.plist"),
            exact_output.replace("program = /usr/bin/printf", "program = /usr/bin/false"),
            exact_output.replace("\t\tserve\n\t\t--native", "\t\t--native\n\t\tserve"),
            exact_output.replace("RUNTIME_MODE => native", "RUNTIME_MODE => foreign"),
            exact_output.replace(
                "\tenvironment = {\n\t\tRUNTIME_MODE => native\n\t\tLETSINFER_TASK_ID => task-0\n\t\tXPC_SERVICE_NAME => ",
                "\tignored environment = {\n\t\tRUNTIME_MODE => native\n\t\tLETSINFER_TASK_ID => task-0\n\t\tXPC_SERVICE_NAME => ",
            ),
            exact_output.replace(
                "working directory = /tmp",
                "working directory = /private/tmp",
            ),
            exact_output.replace("\tworking directory = /tmp\n", ""),
            exact_output.replace("state = running", "state = exited"),
            exact_output.replace("state = running", "state = waiting"),
            exact_output.replace("\tpid = 42\n", ""),
            exact_output.replace("\tpid = 42\n", "\tpid = 42\n\tpid = 43\n"),
            exact_output.replacen(target.as_str(), "gui/501/ai.letsinfer.engine.foreign", 1),
            String::new(),
        ] {
            assert!(!is_admitted(
                &plan,
                &root,
                &target,
                &output,
                &observations(&plan),
            ));
        }

        for mutation in ["path", "owner", "digest"] {
            let mut io = observations(&plan);
            match mutation {
                "path" => io.process.executable = PathBuf::from("/usr/bin/false"),
                "owner" => io.process.owner_user_id += 1,
                "digest" => {
                    io.process.executable_identity =
                        Sha256Digest::parse(&"8".repeat(64)).expect("foreign digest")
                }
                _ => unreachable!(),
            }
            assert!(!is_admitted(&plan, &root, &target, &exact_output, &io));
        }
        let mut io = observations(&plan);
        io.plist_failure = true;
        assert!(!is_admitted(&plan, &root, &target, &exact_output, &io));
        let mut io = observations(&plan);
        io.process_failure = true;
        assert!(!is_admitted(&plan, &root, &target, &exact_output, &io));
    }

    // Proves production plist reads are bounded, preserve exact metadata, and reject symlinks.
    #[test]
    fn system_plist_observation_is_no_follow_and_metadata_exact() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("agent.plist");
        fs::write(&path, b"plist").expect("write plist");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let io = SystemCoreGatewayMacOsSafetyIo;
        let observation = io.plist(&path, 64).expect("observation");
        assert_eq!(observation.bytes, b"plist");
        assert!(observation.is_regular);
        assert_eq!(observation.mode, 0o600);
        assert_eq!(observation.link_count, 1);

        let link = directory.path().join("agent-link.plist");
        symlink(&path, &link).expect("symlink");
        assert!(io.plist(&link, 64).is_err());
        assert!(io.plist(&path, 4).is_err());
    }
}
