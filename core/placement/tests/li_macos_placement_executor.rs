// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme,
    EntityTimestamps, NodeAddress, NodeId, Placement, PlacementAssignment, PlacementEndpoint,
    PlacementGroupId, PlacementId, PlacementResources, PlacementState, PortRange,
    RuntimeInstallationId, Sha256Digest, TaskId, UnixMilliseconds,
};
use li_placement_manager::{
    FilesystemMacosPlacementLogProvider, MacosEndpointReadinessProvider, MacosLaunchAgentIo,
    MacosLaunchAgentPlan, MacosLaunchAgentService, MacosLaunchAgentStatus, MacosPlacementExecutor,
    MacosPlacementMaterialProvider, MacosPlacementWaiter, PlacementError, PlacementExecutor,
    PlacementLogReadRequest, PlacementRuntimeLogProvider, ShellFreeCommand, ShellFreeCommandOutput,
    ShellFreeCommandRunner, ShellFreeEnvironmentValue, SystemMacosLaunchAgentIo,
    SystemMacosLaunchAgentService,
};

// Returns one exact macOS placement fixture.
fn placement(endpoint_owner: bool, state: PlacementState) -> Placement {
    Placement::new(
        PlacementId::parse(&"1".repeat(32)).expect("placement"),
        PlacementGroupId::parse(&"2".repeat(32)).expect("group"),
        PlacementAssignment::new(
            NodeId::parse(&"3".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            li_core_interface::UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("mac.local").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 2).expect("ports"),
                vec![DeviceId::parse("Built-In").expect("GPU")],
                None,
            )
            .expect("resources"),
            if endpoint_owner {
                EndpointOwnership::Owner
            } else {
                EndpointOwnership::Participant
            },
        ),
        state,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns one exact endpoint matching the fixture placement.
fn endpoint(placement: &Placement) -> PlacementEndpoint {
    PlacementEndpoint::new(
        placement.placement_id().clone(),
        placement.assignment().node_id().clone(),
        EndpointAddress::new(
            EndpointScheme::Https,
            placement.assignment().address().clone(),
            18_000,
        )
        .expect("address"),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        Some(CredentialId::parse(&"6".repeat(32)).expect("CA")),
        None,
        4,
        262_144,
        EndpointHealth::new(true, false, None, Vec::new()).expect("health"),
    )
    .expect("endpoint")
}

// Returns one sealed native Engine command containing runtime and Core environment.
fn engine_command() -> ShellFreeCommand {
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec!["serve".to_string(), "--native".to_string()],
        vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "native").expect("runtime")],
        vec![
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
            ShellFreeEnvironmentValue::protected("LETSINFER_TASK_ID", "task-0").expect("protected"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("command")
}

// Returns one complete sealed launch-agent plan.
fn plan(placement: &Placement) -> MacosLaunchAgentPlan {
    MacosLaunchAgentPlan::new(
        placement,
        engine_command(),
        Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
        (placement.assignment().endpoint_ownership() == EndpointOwnership::Owner)
            .then(|| endpoint(placement)),
        3,
        Duration::from_millis(1),
    )
    .expect("plan")
}

// Mocks staged native material and plan reconstruction.
struct MockMaterial {
    value: Mutex<Option<MacosLaunchAgentPlan>>,
    failures: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
}

impl MockMaterial {
    // Creates one staged native material provider.
    fn new(plan: MacosLaunchAgentPlan) -> Self {
        Self {
            value: Mutex::new(Some(plan)),
            failures: Mutex::new(HashSet::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    // Configures one exact material boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Records one material call and returns configured failure state.
    fn begin(&self, action: &str) -> Result<(), PlacementError> {
        self.calls.lock().expect("calls").push(action.to_string());
        if self.failures.lock().expect("failures").contains(action) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }
}

impl MacosPlacementMaterialProvider for MockMaterial {
    // Records exact native staging.
    fn stage(&self, _placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.begin("stage")?;
        Ok(Sha256Digest::parse(&"d".repeat(64)).expect("plan identity"))
    }

    // Returns the staged exact launch-agent plan.
    fn plan(&self, _placement: &Placement) -> Result<Option<MacosLaunchAgentPlan>, PlacementError> {
        self.begin("plan")?;
        Ok(self.value.lock().expect("plan").clone())
    }

    // Records exact staged-input removal.
    fn remove(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.begin("remove")
    }
}

// Mocks launchd lifecycle with ordered status observations.
struct MockLaunchd {
    statuses: Mutex<VecDeque<Result<MacosLaunchAgentStatus, PlacementError>>>,
    failures: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
}

impl Default for MockLaunchd {
    // Creates one launchd mock whose unstated status is active.
    fn default() -> Self {
        Self {
            statuses: Mutex::new(VecDeque::new()),
            failures: Mutex::new(HashSet::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl MockLaunchd {
    // Configures one exact launchd boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Records one launchd call and returns configured failure state.
    fn begin(&self, action: &str) -> Result<(), PlacementError> {
        self.calls.lock().expect("calls").push(action.to_string());
        if self.failures.lock().expect("failures").contains(action) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }
}

impl MacosLaunchAgentService for MockLaunchd {
    // Records exact launch-agent installation.
    fn install(&self, _plan: &MacosLaunchAgentPlan) -> Result<(), PlacementError> {
        self.begin("install")
    }

    // Records exact launch-agent removal.
    fn remove(&self, _plan: &MacosLaunchAgentPlan) -> Result<(), PlacementError> {
        self.begin("remove")
    }

    // Returns the next deterministic launchd status.
    fn status(
        &self,
        _plan: &MacosLaunchAgentPlan,
    ) -> Result<MacosLaunchAgentStatus, PlacementError> {
        self.begin("status")?;
        self.statuses
            .lock()
            .expect("statuses")
            .pop_front()
            .unwrap_or(Ok(MacosLaunchAgentStatus::Active))
    }
}

// Mocks endpoint readiness with ordered values.
#[derive(Default)]
struct MockEndpoints {
    values: Mutex<VecDeque<Result<bool, PlacementError>>>,
}

impl MacosEndpointReadinessProvider for MockEndpoints {
    // Returns the next deterministic endpoint readiness result.
    fn is_ready(&self, _endpoint: &PlacementEndpoint) -> Result<bool, PlacementError> {
        self.values
            .lock()
            .expect("values")
            .pop_front()
            .unwrap_or(Ok(true))
    }
}

// Records deterministic readiness wait intervals.
#[derive(Default)]
struct MockWaiter(AtomicUsize);

impl MacosPlacementWaiter for MockWaiter {
    // Records one bounded wait without sleeping.
    fn wait(&self, _duration: Duration) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Groups one macOS executor and its retained deterministic boundaries.
struct Fixture {
    executor: MacosPlacementExecutor,
    material: Arc<MockMaterial>,
    launchd: Arc<MockLaunchd>,
    endpoints: Arc<MockEndpoints>,
    waiter: Arc<MockWaiter>,
    placement: Placement,
}

// Creates one ordinary endpoint-owning native executor fixture.
fn fixture() -> Fixture {
    let placement = placement(true, PlacementState::Staged);
    let material = Arc::new(MockMaterial::new(plan(&placement)));
    let launchd = Arc::new(MockLaunchd::default());
    let endpoints = Arc::new(MockEndpoints::default());
    let waiter = Arc::new(MockWaiter::default());
    let executor = MacosPlacementExecutor::new(
        material.clone(),
        launchd.clone(),
        endpoints.clone(),
        waiter.clone(),
    );
    Fixture {
        executor,
        material,
        launchd,
        endpoints,
        waiter,
        placement,
    }
}

// Mocks owner-checked plist file storage.
#[derive(Default)]
struct MockIo {
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    failures: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
}

impl MockIo {
    // Configures one exact plist I/O boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Records one plist I/O call and returns configured failure state.
    fn begin(&self, action: &str) -> Result<(), PlacementError> {
        self.calls.lock().expect("calls").push(action.to_string());
        if self.failures.lock().expect("failures").contains(action) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }
}

impl MacosLaunchAgentIo for MockIo {
    // Returns one exact stored plist or configured read failure.
    fn read_private_file(
        &self,
        path: &Path,
        _maximum_bytes: usize,
        _owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        self.begin("read")?;
        Ok(self.files.lock().expect("files").get(path).cloned())
    }

    // Stores one exact plist or configured write failure.
    fn write_atomic_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        self.begin("write")?;
        self.files
            .lock()
            .expect("files")
            .insert(path.to_path_buf(), payload.to_vec());
        Ok(())
    }

    // Removes one exact plist or configured removal failure.
    fn remove_private_file(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        self.begin("remove")?;
        Ok(self.files.lock().expect("files").remove(path).is_some())
    }
}

// Mocks shell-free launchctl results and captures exact argv.
#[derive(Default)]
struct MockRunner {
    results: Mutex<VecDeque<Result<ShellFreeCommandOutput, PlacementError>>>,
    calls: Mutex<Vec<ShellFreeCommand>>,
}

impl ShellFreeCommandRunner for MockRunner {
    // Records exact launchctl argv and returns the next deterministic result.
    fn run(
        &self,
        command: &ShellFreeCommand,
        _maximum_stdout_bytes: usize,
    ) -> Result<ShellFreeCommandOutput, PlacementError> {
        self.calls.lock().expect("calls").push(command.clone());
        self.results
            .lock()
            .expect("results")
            .pop_front()
            .unwrap_or(Ok(ShellFreeCommandOutput::new(0, Vec::new())))
    }
}

// Returns one Core-owned shell-free launchctl command root.
fn launchctl_command() -> ShellFreeCommand {
    ShellFreeCommand::new(
        PathBuf::from("/bin/launchctl"),
        Vec::new(),
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::core("HOME", "/Users/fixture").expect("home"),
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("launchctl")
}

// Seals exact launchd label, endpoint ownership, and readiness bounds.
#[test]
fn launch_agent_plan_validates_identity_and_endpoint() {
    let owner = placement(true, PlacementState::Staged);
    let plan = plan(&owner);
    assert_eq!(
        plan.label().as_str(),
        format!("ai.letsinfer.engine.{}", "1".repeat(32))
    );
    plan.validate_for(&owner).expect("valid plan");
    assert!(plan
        .validate_for(&placement(false, PlacementState::Staged))
        .is_err());
    assert!(MacosLaunchAgentPlan::new(
        &owner,
        engine_command(),
        Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
        None,
        3,
        Duration::from_millis(1),
    )
    .is_err());
    assert!(MacosLaunchAgentPlan::new(
        &owner,
        engine_command(),
        Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
        Some(endpoint(&owner)),
        0,
        Duration::ZERO,
    )
    .is_err());

    let logged = plan
        .clone()
        .with_log_root(PathBuf::from("/Users/fixture/.letsinfer/logs"))
        .expect("log root");
    let plist = li_placement_manager::macos_launch_agent_plist(&logged).expect("plist");
    let expected = format!(
        "/Users/fixture/.letsinfer/logs/li_placement_{}.log",
        owner.placement_id().as_str()
    );
    assert_eq!(logged.log_path(), Some(&PathBuf::from(&expected)));
    assert_eq!(plist.matches(&expected).count(), 2);
}

// Delegates staging without touching launchd.
#[test]
fn native_staging_uses_only_the_material_provider() {
    let fixture = fixture();
    fixture.executor.stage(&fixture.placement).expect("stage");
    assert_eq!(*fixture.material.calls.lock().expect("calls"), ["stage"]);
    assert!(fixture.launchd.calls.lock().expect("calls").is_empty());
}

// Installs an unconfigured agent and reuses an already active exact agent.
#[test]
fn native_start_installs_or_reuses_exact_launch_agent() {
    let unconfigured = fixture();
    unconfigured
        .launchd
        .statuses
        .lock()
        .expect("statuses")
        .extend([
            Ok(MacosLaunchAgentStatus::Unconfigured),
            Ok(MacosLaunchAgentStatus::Active),
        ]);
    assert!(unconfigured
        .executor
        .start(&unconfigured.placement, false)
        .expect("start")
        .is_some());
    assert_eq!(
        *unconfigured.launchd.calls.lock().expect("calls"),
        ["status", "install", "status"]
    );

    let active = fixture();
    active.launchd.statuses.lock().expect("statuses").extend([
        Ok(MacosLaunchAgentStatus::Active),
        Ok(MacosLaunchAgentStatus::Active),
    ]);
    active
        .executor
        .start(&active.placement, false)
        .expect("reuse");
    assert!(!active
        .launchd
        .calls
        .lock()
        .expect("calls")
        .contains(&"install".to_string()));
}

// Removes the exact launch agent after readiness timeout or endpoint failure.
#[test]
fn native_start_rolls_back_every_readiness_failure() {
    let timeout = fixture();
    timeout.launchd.statuses.lock().expect("statuses").extend([
        Ok(MacosLaunchAgentStatus::Unconfigured),
        Ok(MacosLaunchAgentStatus::Active),
        Ok(MacosLaunchAgentStatus::Active),
        Ok(MacosLaunchAgentStatus::Active),
    ]);
    timeout
        .endpoints
        .values
        .lock()
        .expect("values")
        .extend([Ok(false), Ok(false), Ok(false)]);
    assert!(timeout.executor.start(&timeout.placement, false).is_err());
    assert_eq!(timeout.waiter.0.load(Ordering::SeqCst), 2);
    assert!(timeout
        .launchd
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));

    let endpoint = fixture();
    endpoint.launchd.statuses.lock().expect("statuses").extend([
        Ok(MacosLaunchAgentStatus::Active),
        Ok(MacosLaunchAgentStatus::Active),
    ]);
    endpoint
        .endpoints
        .values
        .lock()
        .expect("values")
        .push_back(Err(PlacementError::EndpointUnavailable));
    assert_eq!(
        endpoint
            .executor
            .start(&endpoint.placement, false)
            .expect_err("endpoint"),
        PlacementError::EndpointUnavailable
    );
}

// Propagates material, status, install, stop, and cleanup boundaries without fallback.
#[test]
fn native_executor_fails_at_every_external_boundary() {
    let staging = fixture();
    staging.material.fail("stage");
    assert!(staging.executor.stage(&staging.placement).is_err());

    let plan = fixture();
    plan.material.fail("plan");
    assert!(plan.executor.start(&plan.placement, false).is_err());

    let status = fixture();
    status.launchd.fail("status");
    assert!(status.executor.start(&status.placement, false).is_err());

    let install = fixture();
    install
        .launchd
        .statuses
        .lock()
        .expect("statuses")
        .push_back(Ok(MacosLaunchAgentStatus::Unconfigured));
    install.launchd.fail("install");
    assert!(install.executor.start(&install.placement, false).is_err());

    let stop = fixture();
    stop.launchd.fail("remove");
    assert!(stop.executor.stop(&stop.placement).is_err());

    let cleanup = fixture();
    cleanup
        .launchd
        .statuses
        .lock()
        .expect("statuses")
        .push_back(Ok(MacosLaunchAgentStatus::Inactive));
    cleanup.material.fail("remove");
    assert!(cleanup.executor.remove(&cleanup.placement).is_err());
}

// Stops exact launchd state and removes material only after process absence.
#[test]
fn native_stop_and_remove_preserve_lifecycle_order() {
    let stopped = fixture();
    stopped.executor.stop(&stopped.placement).expect("stop");
    assert_eq!(*stopped.launchd.calls.lock().expect("calls"), ["remove"]);

    let unstaged = fixture();
    *unstaged.material.value.lock().expect("plan") = None;
    let unstaged_placement = placement(true, PlacementState::Staging);
    unstaged
        .executor
        .remove(&unstaged_placement)
        .expect("unstaged cleanup");
    assert!(unstaged
        .material
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));

    let active = fixture();
    active
        .launchd
        .statuses
        .lock()
        .expect("statuses")
        .push_back(Ok(MacosLaunchAgentStatus::Active));
    assert!(active.executor.remove(&active.placement).is_err());

    let inactive = fixture();
    inactive
        .launchd
        .statuses
        .lock()
        .expect("statuses")
        .push_back(Ok(MacosLaunchAgentStatus::Inactive));
    inactive
        .executor
        .remove(&inactive.placement)
        .expect("remove");
    assert!(inactive
        .material
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));
}

// Observes unstaged, active, failed, staged, stopped, and removed launchd states.
#[test]
fn native_observation_covers_every_launchd_state() {
    let unstaged = fixture();
    *unstaged.material.value.lock().expect("plan") = None;
    assert_eq!(
        unstaged
            .executor
            .observe(&unstaged.placement)
            .expect("unstaged")
            .state(),
        PlacementState::Failed
    );

    for (status, durable, expected) in [
        (
            MacosLaunchAgentStatus::Active,
            PlacementState::Staged,
            PlacementState::Running,
        ),
        (
            MacosLaunchAgentStatus::Failed,
            PlacementState::Running,
            PlacementState::Failed,
        ),
        (
            MacosLaunchAgentStatus::Inactive,
            PlacementState::Staged,
            PlacementState::Staged,
        ),
        (
            MacosLaunchAgentStatus::Unconfigured,
            PlacementState::Stopped,
            PlacementState::Stopped,
        ),
        (
            MacosLaunchAgentStatus::Unconfigured,
            PlacementState::Removed,
            PlacementState::Removed,
        ),
    ] {
        let fixture = fixture();
        let placement = placement(true, durable);
        *fixture.material.value.lock().expect("plan") = Some(plan(&placement));
        fixture
            .launchd
            .statuses
            .lock()
            .expect("statuses")
            .push_back(Ok(status));
        assert_eq!(
            fixture
                .executor
                .observe(&placement)
                .expect("observation")
                .state(),
            expected
        );
    }
}

// System launchd service emits deterministic plist and fixed bootstrap/kickstart argv.
#[test]
fn system_launchd_service_installs_exact_plist_without_shell() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    let io = Arc::new(MockIo::default());
    let runner = Arc::new(MockRunner::default());
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    let service = SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        runner.clone(),
        io.clone(),
    )
    .expect("service");
    service.install(&plan).expect("install");
    let path = PathBuf::from(format!(
        "/Users/fixture/Library/LaunchAgents/{}.plist",
        plan.label().as_str()
    ));
    let plist = String::from_utf8(
        io.files
            .lock()
            .expect("files")
            .get(&path)
            .expect("plist")
            .clone(),
    )
    .expect("UTF-8");
    assert!(plist.contains("<string>/usr/bin/printf</string>"));
    assert!(plist.contains("<key>LETSINFER_TASK_ID</key>"));
    assert!(plist.contains("<key>RUNTIME_MODE</key>"));
    let calls = runner.calls.lock().expect("calls");
    assert_eq!(calls[0].arguments()[0], "print");
    assert_eq!(calls[1].arguments()[0], "bootstrap");
    assert_eq!(calls[2].arguments()[0], "kickstart");
}

// System launchd service reuses exact active bytes and rejects a foreign plist.
#[test]
fn system_launchd_service_reuses_exact_bytes_and_rejects_foreign_state() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    let path = PathBuf::from(format!(
        "/Users/fixture/Library/LaunchAgents/{}.plist",
        plan.label().as_str()
    ));
    let io = Arc::new(MockIo::default());
    let runner = Arc::new(MockRunner::default());
    let service = SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        runner.clone(),
        io.clone(),
    )
    .expect("service");
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    service.install(&plan).expect("first install");
    runner.calls.lock().expect("calls").clear();
    runner
        .results
        .lock()
        .expect("results")
        .push_back(Ok(ShellFreeCommandOutput::new(
            0,
            b"state = running\n".to_vec(),
        )));
    service.install(&plan).expect("reuse");
    assert_eq!(runner.calls.lock().expect("calls").len(), 1);

    io.files
        .lock()
        .expect("files")
        .insert(path, b"foreign".to_vec());
    assert_eq!(
        service.install(&plan).expect_err("foreign plist"),
        PlacementError::ExecutionUnavailable
    );

    let missing_io = Arc::new(MockIo::default());
    let active_runner = Arc::new(MockRunner::default());
    active_runner
        .results
        .lock()
        .expect("results")
        .push_back(Ok(ShellFreeCommandOutput::new(
            0,
            b"state = running\n".to_vec(),
        )));
    let active_without_plist = SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        active_runner,
        missing_io,
    )
    .expect("service");
    assert_eq!(
        active_without_plist
            .install(&plan)
            .expect_err("active job without plist"),
        PlacementError::ExecutionUnavailable
    );
}

// System launchd service rolls back a newly written plist after mutation failure.
#[test]
fn system_launchd_service_rolls_back_partial_installation() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    let io = Arc::new(MockIo::default());
    let runner = Arc::new(MockRunner::default());
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    let service = SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        runner,
        io.clone(),
    )
    .expect("service");
    assert!(service.install(&plan).is_err());
    assert!(io.files.lock().expect("files").is_empty());
    assert!(io
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));
}

// System launchd service repairs an exact unloaded plist through fixed mutations.
#[test]
fn system_launchd_service_repairs_exact_unloaded_job() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    let io = Arc::new(MockIo::default());
    let initial_runner = Arc::new(MockRunner::default());
    initial_runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        initial_runner,
        io.clone(),
    )
    .expect("service")
    .install(&plan)
    .expect("initial install");

    let runner = Arc::new(MockRunner::default());
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    let service = SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        runner.clone(),
        io,
    )
    .expect("service");
    service.install(&plan).expect("repair");
    assert_eq!(
        runner
            .calls
            .lock()
            .expect("calls")
            .iter()
            .map(|command| command.arguments()[0].as_str())
            .collect::<Vec<_>>(),
        ["print", "kickstart", "bootout", "bootstrap", "kickstart"]
    );
}

// System launchd removal distinguishes an unloaded plist from a live bootout failure.
#[test]
fn system_launchd_service_removes_unloaded_job_but_preserves_live_failure() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    let io = Arc::new(MockIo::default());
    let initial_runner = Arc::new(MockRunner::default());
    initial_runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        initial_runner,
        io.clone(),
    )
    .expect("service")
    .install(&plan)
    .expect("install");

    let unloaded_runner = Arc::new(MockRunner::default());
    unloaded_runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
    ]);
    SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        unloaded_runner,
        io.clone(),
    )
    .expect("service")
    .remove(&plan)
    .expect("remove unloaded");
    assert!(io.files.lock().expect("files").is_empty());

    let replacement_runner = Arc::new(MockRunner::default());
    replacement_runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
        Ok(ShellFreeCommandOutput::new(0, Vec::new())),
    ]);
    SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        replacement_runner,
        io.clone(),
    )
    .expect("service")
    .install(&plan)
    .expect("replace");
    let live_runner = Arc::new(MockRunner::default());
    live_runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(
            0,
            b"state = running\n".to_vec(),
        )),
        Ok(ShellFreeCommandOutput::new(1, Vec::new())),
    ]);
    assert!(SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        launchctl_command(),
        live_runner,
        io.clone(),
    )
    .expect("service")
    .remove(&plan)
    .is_err());
    assert!(!io.files.lock().expect("files").is_empty());
}

// System launchd service parses active, failed, inactive, and unconfigured states exactly.
#[test]
fn system_launchd_status_is_strict_and_bounded() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    for (status, stdout, expected) in [
        (
            0,
            b"state = running\n".to_vec(),
            MacosLaunchAgentStatus::Active,
        ),
        (
            0,
            b"state = exited\n".to_vec(),
            MacosLaunchAgentStatus::Failed,
        ),
        (
            0,
            b"state = waiting\n".to_vec(),
            MacosLaunchAgentStatus::Inactive,
        ),
        (1, Vec::new(), MacosLaunchAgentStatus::Unconfigured),
    ] {
        let io = Arc::new(MockIo::default());
        let runner = Arc::new(MockRunner::default());
        runner
            .results
            .lock()
            .expect("results")
            .push_back(Ok(ShellFreeCommandOutput::new(status, stdout)));
        let service = SystemMacosLaunchAgentService::new(
            PathBuf::from("/Users/fixture/Library/LaunchAgents"),
            501,
            launchctl_command(),
            runner,
            io,
        )
        .expect("service");
        assert_eq!(service.status(&plan).expect("status"), expected);
    }
}

// System plist I/O enforces owner-only regular files and rejects symlinks.
#[test]
fn system_launch_agent_io_enforces_private_file_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    let root = directory.path().join("LaunchAgents");
    fs::create_dir(&root).expect("root");
    let path = root.join("ai.letsinfer.engine.fixture.plist");
    let io = SystemMacosLaunchAgentIo::default();
    io.write_atomic_private_file(&path, b"plist\n", owner)
        .expect("write");
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        io.read_private_file(&path, 32, owner)
            .expect("read")
            .expect("payload"),
        b"plist\n"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
    assert!(io.read_private_file(&path, 32, owner).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
    let link = root.join("foreign.plist");
    std::os::unix::fs::symlink(&path, &link).expect("symlink");
    assert!(io.read_private_file(&link, 32, owner).is_err());
    assert!(io.remove_private_file(&path, owner).expect("remove"));
}

// Preserves opaque bytes across cursors and rejects cursors invalidated by bounded compaction.
#[test]
fn macos_log_provider_cursors_and_compacts_exact_private_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    let log_root = directory.path().join("logs");
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement).with_log_root(log_root).expect("log root");
    let log_path = plan.log_path().expect("log path").clone();
    let io = Arc::new(SystemMacosLaunchAgentIo::default());
    io.prepare_private_log_file(&log_path, owner)
        .expect("prepare");
    assert_eq!(
        fs::metadata(&log_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    OpenOptions::new()
        .append(true)
        .open(&log_path)
        .and_then(|mut file| file.write_all(b"first\nsecond\nthird\n"))
        .expect("append");
    let material = Arc::new(MockMaterial::new(plan));
    let provider = FilesystemMacosPlacementLogProvider::new(
        material,
        io.clone(),
        Arc::new(MockWaiter::default()),
        owner,
    );
    let first = provider
        .read(
            &placement,
            &PlacementLogReadRequest::new(
                placement.placement_group_id().clone(),
                None,
                2,
                1_024,
                Duration::ZERO,
            )
            .expect("request"),
        )
        .expect("first batch");
    assert_eq!(first.payload(), b"second\nthird\n");
    assert!(first.is_truncated());
    OpenOptions::new()
        .append(true)
        .open(&log_path)
        .and_then(|mut file| file.write_all(b"fourth\n"))
        .expect("append");
    let replay = provider
        .read(
            &placement,
            &PlacementLogReadRequest::new(
                placement.placement_group_id().clone(),
                Some(first.cursor().clone()),
                2,
                1_024,
                Duration::ZERO,
            )
            .expect("request"),
        )
        .expect("replay");
    assert_eq!(replay.payload(), b"fourth\n");

    let oversized = b"rotated runtime output\n".repeat(800_000);
    OpenOptions::new()
        .append(true)
        .open(&log_path)
        .and_then(|mut file| file.write_all(&oversized))
        .expect("oversized append");
    let stale = PlacementLogReadRequest::new(
        placement.placement_group_id().clone(),
        Some(replay.cursor().clone()),
        2,
        1_024,
        Duration::ZERO,
    )
    .expect("request");
    assert_eq!(
        provider.read(&placement, &stale).expect_err("stale cursor"),
        PlacementError::ExecutionUnavailable
    );
    assert!(fs::metadata(&log_path).expect("metadata").len() <= 8 * 1024 * 1024);
}

// Denies unsafe owner, mode, and symlink states through one redacted native failure.
#[test]
fn macos_log_provider_denies_unsafe_files_without_path_disclosure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement)
        .with_log_root(directory.path().join("logs"))
        .expect("log root");
    let log_path = plan.log_path().expect("log path").clone();
    let material = Arc::new(MockMaterial::new(plan));
    let io = Arc::new(SystemMacosLaunchAgentIo::default());
    io.prepare_private_log_file(&log_path, owner)
        .expect("prepare");
    let request = PlacementLogReadRequest::new(
        placement.placement_group_id().clone(),
        None,
        2,
        1_024,
        Duration::ZERO,
    )
    .expect("request");
    let wrong_owner = FilesystemMacosPlacementLogProvider::new(
        material.clone(),
        io.clone(),
        Arc::new(MockWaiter::default()),
        owner.saturating_add(1),
    );
    assert_eq!(
        wrong_owner.read(&placement, &request).expect_err("owner"),
        PlacementError::ExecutionUnavailable
    );

    let provider = FilesystemMacosPlacementLogProvider::new(
        material,
        io,
        Arc::new(MockWaiter::default()),
        owner,
    );
    fs::set_permissions(&log_path, fs::Permissions::from_mode(0o644)).expect("permissions");
    assert_eq!(
        provider.read(&placement, &request).expect_err("mode"),
        PlacementError::ExecutionUnavailable
    );
    fs::remove_file(&log_path).expect("remove");
    let foreign = directory.path().join("foreign.log");
    fs::write(&foreign, b"private runtime output").expect("foreign");
    std::os::unix::fs::symlink(&foreign, &log_path).expect("symlink");
    let error = provider.read(&placement, &request).expect_err("symlink");
    assert_eq!(error, PlacementError::ExecutionUnavailable);
    assert!(!format!("{error:?}").contains(log_path.to_string_lossy().as_ref()));
    assert!(!format!("{error:?}").contains("private runtime output"));
}

// System launchd service propagates every injected plist I/O failure.
#[test]
fn system_launchd_service_fails_at_each_plist_boundary() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    for boundary in ["read", "write", "remove"] {
        let io = Arc::new(MockIo::default());
        io.fail(boundary);
        let runner = Arc::new(MockRunner::default());
        if boundary == "write" {
            runner
                .results
                .lock()
                .expect("results")
                .push_back(Ok(ShellFreeCommandOutput::new(1, Vec::new())));
        }
        let service = SystemMacosLaunchAgentService::new(
            PathBuf::from("/Users/fixture/Library/LaunchAgents"),
            501,
            launchctl_command(),
            runner,
            io,
        )
        .expect("service");
        let result = if boundary == "remove" {
            service.remove(&plan)
        } else {
            service.install(&plan)
        };
        assert!(result.is_err(), "{boundary}");
    }
}

// System launchd service rejects noncanonical root, executable, and runtime-owned environment.
#[test]
fn system_launchd_service_rejects_unsafe_configuration() {
    let io = Arc::new(MockIo::default());
    let runner = Arc::new(MockRunner::default());
    assert!(SystemMacosLaunchAgentService::new(
        PathBuf::from("relative/LaunchAgents"),
        501,
        launchctl_command(),
        runner.clone(),
        io.clone(),
    )
    .is_err());
    let runtime_environment = ShellFreeCommand::new(
        PathBuf::from("/bin/launchctl"),
        Vec::new(),
        vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "unsafe").expect("runtime")],
        Vec::new(),
        PathBuf::from("/tmp"),
    )
    .expect("command");
    assert!(SystemMacosLaunchAgentService::new(
        PathBuf::from("/Users/fixture/Library/LaunchAgents"),
        501,
        runtime_environment,
        runner,
        io,
    )
    .is_err());
}
