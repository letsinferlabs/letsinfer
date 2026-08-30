// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    BootId, CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership,
    EndpointScheme, EntityTimestamps, NetworkInterfaceName, NodeAddress, NodeId, Placement,
    PlacementAssignment, PlacementEndpoint, PlacementGroupId, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeInstallationId, RuntimeSource, Sha256Digest, TaskId,
    TechnicalName, UnixMilliseconds,
};
use li_placement_manager::{
    DockerContainerObservation, DockerLinuxPlacementExecutionProvider,
    DockerLinuxPlacementLogProvider, LinuxContainerLaunchPlan, LinuxContainerReadiness,
    LinuxDockerClient, LinuxDockerLogClient, LinuxEndpointReadinessProvider,
    LinuxPlacementExecutionProvider, LinuxPlacementExecutionState, LinuxPlacementMaterialProvider,
    LinuxPlacementWaiter, LinuxProcessIdentityIo, LinuxProcessIdentityProvider,
    LinuxProtectedProcessIdentity, PlacementError, PlacementLogCursor, PlacementLogReadRequest,
    PlacementRuntimeLogProvider, PollingLinuxContainerReadinessProvider,
    ProcfsLinuxProcessIdentityProvider, ShellFreeCommand, ShellFreeCommandOutput,
    ShellFreeCommandRunner, ShellFreeEnvironmentValue, SystemDockerClient,
};

// Returns one exact placement fixture with configurable ownership and durable state.
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
            NodeAddress::parse("spark.local").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 2).expect("ports"),
                vec![DeviceId::parse("GPU-A").expect("GPU")],
                Some(NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
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

// Returns the exact li_-namespaced container name for fixtures.
fn container_name() -> String {
    format!("li_placement_{}", "1".repeat(32))
}

// Returns exact protected Docker labels for fixtures.
fn labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ai.letsinfer.managed".to_string(), "true".to_string()),
        (
            "ai.letsinfer.placement_group_id".to_string(),
            "2".repeat(32),
        ),
        ("ai.letsinfer.placement_id".to_string(), "1".repeat(32)),
        ("ai.letsinfer.node_id".to_string(), "3".repeat(32)),
        ("ai.letsinfer.task_id".to_string(), "task-0".to_string()),
    ])
}

// Returns one exact endpoint matching the fixture placement.
fn endpoint(placement: &Placement) -> PlacementEndpoint {
    PlacementEndpoint::new(
        placement.placement_id().clone(),
        placement.assignment().node_id().clone(),
        EndpointAddress::new(
            EndpointScheme::Https,
            placement.assignment().address().clone(),
            placement.assignment().resources().ports().base(),
        )
        .expect("endpoint address"),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        Some(CredentialId::parse(&"6".repeat(32)).expect("CA")),
        None,
        4,
        262_144,
        EndpointHealth::new(true, false, None, Vec::new()).expect("health"),
    )
    .expect("endpoint")
}

// Returns one shell-free Docker create command with exact protected identity.
fn create_command(placement: &Placement) -> ShellFreeCommand {
    let image = format!("ghcr.io/letsinferlabs/engine@sha256:{}", "a".repeat(64));
    let mut arguments = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--name".to_string(),
        container_name(),
        "--restart".to_string(),
        "no".to_string(),
        "--log-driver".to_string(),
        "local".to_string(),
        "--log-opt".to_string(),
        "max-size=8m".to_string(),
        "--log-opt".to_string(),
        "max-file=2".to_string(),
    ];
    for (key, value) in labels() {
        arguments.extend(["--label".to_string(), format!("{key}={value}")]);
    }
    arguments.extend([image, "/opt/letsinfer/bin/engine-adapter".to_string()]);
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/docker"),
        arguments,
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::core("HOME", "/home/fixture").expect("home"),
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
            ShellFreeEnvironmentValue::protected(
                "LETSINFER_PLACEMENT_ID",
                placement.placement_id().as_str(),
            )
            .expect("protected"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("command")
}

// Returns one complete sealed launch plan for an owner or participant.
fn plan(placement: &Placement) -> LinuxContainerLaunchPlan {
    LinuxContainerLaunchPlan::new(
        placement,
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/engine@sha256:{}",
            "a".repeat(64)
        ))
        .expect("image reference"),
        Sha256Digest::parse(&"b".repeat(64)).expect("image identity"),
        create_command(placement),
        if placement.assignment().endpoint_ownership() == EndpointOwnership::Owner {
            LinuxContainerReadiness::endpoint(3, Duration::from_millis(1)).expect("readiness")
        } else {
            LinuxContainerReadiness::exec(
                vec!["/opt/runtime/ready".to_string()],
                3,
                Duration::from_millis(1),
            )
            .expect("readiness")
        },
        (placement.assignment().endpoint_ownership() == EndpointOwnership::Owner)
            .then(|| endpoint(placement)),
    )
    .expect("plan")
}

// Returns one valid running or stopped Docker observation.
fn observation(running: bool) -> DockerContainerObservation {
    DockerContainerObservation::new(
        TechnicalName::parse(&container_name()).expect("name"),
        Sha256Digest::parse(&"c".repeat(64)).expect("container"),
        Sha256Digest::parse(&"b".repeat(64)).expect("image"),
        running,
        if running { 1_234 } else { 0 },
        labels(),
    )
    .expect("observation")
}

// Returns one exact process identity for a running fixture container.
fn process() -> LinuxProtectedProcessIdentity {
    LinuxProtectedProcessIdentity::new(
        TechnicalName::parse(&container_name()).expect("name"),
        Sha256Digest::parse(&"c".repeat(64)).expect("container"),
        1_234,
        9_876,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/user.slice/fixture.scope",
    )
    .expect("process")
}

// Mocks sealed material staging and plan reconstruction.
struct MockMaterial {
    value: Mutex<Option<LinuxContainerLaunchPlan>>,
    failures: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
}

impl MockMaterial {
    // Creates one staged material provider containing an exact plan.
    fn new(plan: LinuxContainerLaunchPlan) -> Self {
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

impl LinuxPlacementMaterialProvider for MockMaterial {
    // Records exact staging and returns its configured result.
    fn stage(&self, _placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.begin("stage")?;
        Ok(Sha256Digest::parse(&"d".repeat(64)).expect("plan identity"))
    }

    // Returns the staged sealed plan or its configured failure.
    fn plan(
        &self,
        _placement: &Placement,
    ) -> Result<Option<LinuxContainerLaunchPlan>, PlacementError> {
        self.begin("plan")?;
        Ok(self.value.lock().expect("plan").clone())
    }

    // Records exact staged-input removal.
    fn remove(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.begin("remove")
    }
}

// Mocks exact Docker lifecycle and readiness operations.
#[derive(Default)]
struct MockDocker {
    inspections: Mutex<VecDeque<Option<DockerContainerObservation>>>,
    readiness: Mutex<VecDeque<bool>>,
    failures: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
}

impl MockDocker {
    // Configures one exact Docker boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Records one Docker call and returns configured failure state.
    fn begin(&self, action: &str) -> Result<(), PlacementError> {
        self.calls.lock().expect("calls").push(action.to_string());
        if self.failures.lock().expect("failures").contains(action) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }

    // Replaces the ordered inspection results.
    fn set_inspections(&self, values: Vec<Option<DockerContainerObservation>>) {
        *self.inspections.lock().expect("inspections") = values.into();
    }
}

impl LinuxDockerClient for MockDocker {
    // Returns the next exact inspection result.
    fn inspect(
        &self,
        _plan: &LinuxContainerLaunchPlan,
    ) -> Result<Option<DockerContainerObservation>, PlacementError> {
        self.begin("inspect")?;
        Ok(self
            .inspections
            .lock()
            .expect("inspections")
            .pop_front()
            .unwrap_or(None))
    }

    // Records exact container creation.
    fn create_and_start(&self, _plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        self.begin("create")
    }

    // Records exact existing-container start.
    fn start(&self, _plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        self.begin("start")
    }

    // Records exact container stop.
    fn stop(&self, _plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        self.begin("stop")
    }

    // Records exact container removal.
    fn remove(&self, _plan: &LinuxContainerLaunchPlan) -> Result<(), PlacementError> {
        self.begin("remove")
    }

    // Returns the next deterministic in-container readiness result.
    fn exec_readiness(
        &self,
        _plan: &LinuxContainerLaunchPlan,
        _arguments: &[String],
    ) -> Result<bool, PlacementError> {
        self.begin("exec_readiness")?;
        Ok(self
            .readiness
            .lock()
            .expect("readiness")
            .pop_front()
            .unwrap_or(true))
    }
}

// Mocks exact procfs identity reconstruction.
struct MockIdentity {
    fail: AtomicBool,
    calls: AtomicUsize,
}

impl Default for MockIdentity {
    // Creates one successful deterministic identity provider.
    fn default() -> Self {
        Self {
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
}

impl LinuxProcessIdentityProvider for MockIdentity {
    // Returns one exact identity or the configured procfs failure.
    fn identity(
        &self,
        _observation: &DockerContainerObservation,
    ) -> Result<LinuxProtectedProcessIdentity, PlacementError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(process())
        }
    }
}

// Mocks endpoint readiness with an ordered result sequence.
#[derive(Default)]
struct MockEndpointReadiness {
    values: Mutex<VecDeque<Result<bool, PlacementError>>>,
}

impl LinuxEndpointReadinessProvider for MockEndpointReadiness {
    // Returns the next deterministic endpoint readiness result.
    fn is_ready(&self, _endpoint: &PlacementEndpoint) -> Result<bool, PlacementError> {
        self.values
            .lock()
            .expect("endpoint readiness")
            .pop_front()
            .unwrap_or(Ok(true))
    }
}

// Records deterministic readiness wait intervals.
#[derive(Default)]
struct MockWaiter(AtomicUsize);

impl LinuxPlacementWaiter for MockWaiter {
    // Records one bounded wait without sleeping.
    fn wait(&self, _duration: Duration) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Groups one Docker execution provider and its retained deterministic boundaries.
struct Fixture {
    provider: DockerLinuxPlacementExecutionProvider,
    material: Arc<MockMaterial>,
    docker: Arc<MockDocker>,
    identity: Arc<MockIdentity>,
    endpoints: Arc<MockEndpointReadiness>,
    waiter: Arc<MockWaiter>,
    placement: Placement,
}

// Creates one ordinary endpoint-owning Docker execution fixture.
fn fixture() -> Fixture {
    let placement = placement(true, PlacementState::Staged);
    let material = Arc::new(MockMaterial::new(plan(&placement)));
    let docker = Arc::new(MockDocker::default());
    let identity = Arc::new(MockIdentity::default());
    let endpoints = Arc::new(MockEndpointReadiness::default());
    let waiter = Arc::new(MockWaiter::default());
    let readiness = Arc::new(PollingLinuxContainerReadinessProvider::new(
        endpoints.clone(),
        waiter.clone(),
    ));
    let provider = DockerLinuxPlacementExecutionProvider::new(
        material.clone(),
        docker.clone(),
        identity.clone(),
        readiness,
    );
    Fixture {
        provider,
        material,
        docker,
        identity,
        endpoints,
        waiter,
        placement,
    }
}

// Mocks shell-free native command results while preserving exact argv calls.
#[derive(Default)]
struct MockRunner {
    results: Mutex<VecDeque<Result<ShellFreeCommandOutput, PlacementError>>>,
    calls: Mutex<Vec<ShellFreeCommand>>,
}

impl ShellFreeCommandRunner for MockRunner {
    // Records exact argv and returns the next deterministic command result.
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

// Mocks exact procfs text inputs.
struct MockProcessIo {
    boot_id: String,
    stat: String,
    cgroup: String,
}

impl LinuxProcessIdentityIo for MockProcessIo {
    // Returns the configured host boot identity.
    fn boot_id(&self) -> Result<String, PlacementError> {
        Ok(self.boot_id.clone())
    }

    // Returns the configured process-stat payload.
    fn process_stat(&self, _process_id: u32) -> Result<String, PlacementError> {
        Ok(self.stat.clone())
    }

    // Returns the configured process-cgroup payload.
    fn process_cgroup(&self, _process_id: u32) -> Result<String, PlacementError> {
        Ok(self.cgroup.clone())
    }
}

// Returns one valid Linux procfs stat fixture with field 22 set.
fn process_stat() -> String {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "9876";
    format!("1234 (engine adapter) {}\n", fields.join(" "))
}

// Queues one exact protected inspection and one timestamped Docker log result.
fn push_docker_log_read(runner: &MockRunner, status: i32, payload: &[u8]) {
    let document = serde_json::json!({
        "Id": "c".repeat(64),
        "Name": format!("/{}", container_name()),
        "Image": format!("sha256:{}", "b".repeat(64)),
        "State": {"Running": true, "Pid": 1234},
        "Config": {"Labels": labels()},
    });
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(
            0,
            format!("{}\n", "c".repeat(64)).into_bytes(),
        )),
        Ok(ShellFreeCommandOutput::new(
            0,
            serde_json::to_vec(&document).expect("JSON"),
        )),
        Ok(ShellFreeCommandOutput::new(status, payload.to_vec())),
    ]);
}

// Accepts one exact plan and rejects every protected identity mutation.
#[test]
fn launch_plan_seals_docker_identity_and_endpoint_ownership() {
    let owner = placement(true, PlacementState::Staged);
    let valid = plan(&owner);
    valid.validate_for(&owner).expect("valid plan");
    let changed = placement(false, PlacementState::Staged);
    assert!(valid.validate_for(&changed).is_err());

    let participant = placement(false, PlacementState::Staged);
    assert!(LinuxContainerLaunchPlan::new(
        &participant,
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/engine@sha256:{}",
            "a".repeat(64)
        ))
        .expect("reference"),
        Sha256Digest::parse(&"b".repeat(64)).expect("image"),
        create_command(&participant),
        LinuxContainerReadiness::endpoint(1, Duration::from_millis(1)).expect("readiness"),
        None,
    )
    .is_err());
    assert!(LinuxContainerReadiness::exec(
        vec!["/bin/sh".to_string(), "-c".to_string(), "ready".to_string()],
        1,
        Duration::from_millis(1),
    )
    .is_err());

    let runtime_host_environment = ShellFreeCommand::new(
        PathBuf::from("/usr/bin/docker"),
        create_command(&owner).arguments().to_vec(),
        vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "serve").expect("runtime")],
        Vec::new(),
        PathBuf::from("/tmp"),
    )
    .expect("command");
    assert!(LinuxContainerLaunchPlan::new(
        &owner,
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/engine@sha256:{}",
            "a".repeat(64)
        ))
        .expect("reference"),
        Sha256Digest::parse(&"b".repeat(64)).expect("image"),
        runtime_host_environment,
        LinuxContainerReadiness::endpoint(1, Duration::from_millis(1)).expect("readiness"),
        Some(endpoint(&owner)),
    )
    .is_err());
}

// Rejects missing, duplicated, alternate, or changed protected Docker options.
#[test]
fn launch_plan_rejects_every_protected_command_mutation() {
    let placement = placement(true, PlacementState::Staged);
    let image_reference = RuntimeSource::parse(&format!(
        "ghcr.io/letsinferlabs/engine@sha256:{}",
        "a".repeat(64)
    ))
    .expect("reference");
    for mutation in [
        "name",
        "restart",
        "label",
        "image",
        "alternate",
        "duplicate_label",
        "detach_equals",
        "automatic_remove",
        "short_label",
        "log_driver",
        "log_size",
        "log_files",
    ] {
        let mut arguments = create_command(&placement).arguments().to_vec();
        match mutation {
            "name" => {
                let index = arguments
                    .iter()
                    .position(|value| value == "--name")
                    .expect("name");
                arguments[index + 1] = "li_placement_foreign".to_string();
            }
            "restart" => {
                let index = arguments
                    .iter()
                    .position(|value| value == "--restart")
                    .expect("restart");
                arguments[index + 1] = "always".to_string();
            }
            "label" => {
                let index = arguments
                    .iter()
                    .position(|value| value == "ai.letsinfer.managed=true")
                    .expect("label");
                arguments[index] = "ai.letsinfer.managed=false".to_string();
            }
            "image" => {
                let index = arguments
                    .iter()
                    .position(|value| value == image_reference.as_str())
                    .expect("image");
                arguments[index] = format!("ghcr.io/foreign@sha256:{}", "a".repeat(64));
            }
            "alternate" => arguments.push("--label=ai.letsinfer.managed=false".to_string()),
            "duplicate_label" => arguments.extend([
                "--label".to_string(),
                "ai.letsinfer.managed=false".to_string(),
            ]),
            "detach_equals" => arguments.push("--detach=false".to_string()),
            "automatic_remove" => arguments.push("--rm".to_string()),
            "log_driver" => {
                let index = arguments
                    .iter()
                    .position(|value| value == "--log-driver")
                    .expect("log driver");
                arguments[index + 1] = "json-file".to_string();
            }
            "log_size" => {
                let index = arguments
                    .iter()
                    .position(|value| value == "max-size=8m")
                    .expect("log size");
                arguments[index] = "max-size=unlimited".to_string();
            }
            "log_files" => arguments.push("--log-opt=max-file=100".to_string()),
            _ => arguments.extend(["-l".to_string(), "ai.letsinfer.managed=false".to_string()]),
        }
        let command = create_command(&placement)
            .with_arguments(arguments)
            .expect("mutated command");
        assert!(
            LinuxContainerLaunchPlan::new(
                &placement,
                image_reference.clone(),
                Sha256Digest::parse(&"b".repeat(64)).expect("image"),
                command,
                LinuxContainerReadiness::endpoint(1, Duration::from_millis(1)).expect("readiness"),
                Some(endpoint(&placement)),
            )
            .is_err(),
            "{mutation}"
        );
    }
}

// Runs bounded endpoint and exec readiness without changing plan identity.
#[test]
fn readiness_polling_covers_endpoint_and_exec_modes() {
    let fixture = fixture();
    fixture
        .endpoints
        .values
        .lock()
        .expect("values")
        .extend([Ok(false), Ok(true)]);
    let owner_plan = plan(&fixture.placement);
    let readiness = PollingLinuxContainerReadinessProvider::new(
        fixture.endpoints.clone(),
        fixture.waiter.clone(),
    );
    assert!(readiness
        .wait_until_ready(&owner_plan, fixture.docker.as_ref())
        .expect("endpoint readiness"));
    assert_eq!(fixture.waiter.0.load(Ordering::SeqCst), 1);

    let participant = placement(false, PlacementState::Staged);
    let plan = plan(&participant);
    fixture
        .docker
        .readiness
        .lock()
        .expect("readiness")
        .extend([false, true]);
    assert!(readiness
        .wait_until_ready(&plan, fixture.docker.as_ref())
        .expect("exec readiness"));
}

// Creates a missing container, starts a stopped container, and reuses a running one.
#[test]
fn execution_start_covers_every_exact_container_state() {
    let missing = fixture();
    missing
        .docker
        .set_inspections(vec![None, Some(observation(true))]);
    assert_eq!(
        missing.provider.start(&missing.placement).expect("create"),
        process()
    );
    assert_eq!(
        *missing.docker.calls.lock().expect("calls"),
        ["inspect", "create", "inspect"]
    );

    let stopped = fixture();
    stopped
        .docker
        .set_inspections(vec![Some(observation(false)), Some(observation(true))]);
    stopped.provider.start(&stopped.placement).expect("restart");
    assert_eq!(
        *stopped.docker.calls.lock().expect("calls"),
        ["inspect", "start", "inspect"]
    );

    let running = fixture();
    running
        .docker
        .set_inspections(vec![Some(observation(true)), Some(observation(true))]);
    running.provider.start(&running.placement).expect("reuse");
    assert_eq!(
        *running.docker.calls.lock().expect("calls"),
        ["inspect", "inspect"]
    );
}

// Rejects changed image, label, plan, Docker, and procfs identity at start.
#[test]
fn execution_start_fails_at_every_external_or_identity_boundary() {
    let changed = fixture();
    let mut changed_labels = labels();
    changed_labels.insert("ai.letsinfer.node_id".to_string(), "9".repeat(32));
    let changed_observation = DockerContainerObservation::new(
        TechnicalName::parse(&container_name()).expect("name"),
        Sha256Digest::parse(&"c".repeat(64)).expect("container"),
        Sha256Digest::parse(&"b".repeat(64)).expect("image"),
        true,
        1_234,
        changed_labels,
    )
    .expect("observation");
    changed
        .docker
        .set_inspections(vec![Some(changed_observation)]);
    assert_eq!(
        changed
            .provider
            .start(&changed.placement)
            .expect_err("labels"),
        PlacementError::ExecutionUnavailable
    );

    for boundary in ["inspect", "create", "start"] {
        let fixture = fixture();
        fixture.docker.fail(boundary);
        fixture.docker.set_inspections(if boundary == "create" {
            vec![None]
        } else if boundary == "start" {
            vec![Some(observation(false))]
        } else {
            Vec::new()
        });
        assert!(
            fixture.provider.start(&fixture.placement).is_err(),
            "{boundary}"
        );
    }

    let identity = fixture();
    identity
        .docker
        .set_inspections(vec![Some(observation(true)), Some(observation(true))]);
    identity.identity.fail.store(true, Ordering::SeqCst);
    assert!(identity.provider.start(&identity.placement).is_err());

    let material = fixture();
    material.material.fail("plan");
    assert!(material.provider.start(&material.placement).is_err());
}

// Delegates staging, readiness, and endpoint access through exact sealed plan boundaries.
#[test]
fn execution_stage_readiness_and_endpoint_are_narrow_and_deterministic() {
    let fixture = fixture();
    fixture.provider.stage(&fixture.placement).expect("stage");
    assert_eq!(*fixture.material.calls.lock().expect("calls"), ["stage"]);
    fixture
        .endpoints
        .values
        .lock()
        .expect("values")
        .extend([Ok(false), Ok(true)]);
    assert!(fixture
        .provider
        .wait_until_ready(&fixture.placement, &process())
        .expect("ready"));
    assert!(fixture
        .provider
        .endpoint(&fixture.placement, &process())
        .expect("endpoint")
        .is_some());
}

// Propagates staging, readiness, stop, removal, and material-cleanup failures exactly.
#[test]
fn execution_fails_at_every_remaining_external_boundary() {
    let staging = fixture();
    staging.material.fail("stage");
    assert_eq!(
        staging
            .provider
            .stage(&staging.placement)
            .expect_err("staging"),
        PlacementError::ExecutionUnavailable
    );

    let readiness = fixture();
    readiness
        .endpoints
        .values
        .lock()
        .expect("values")
        .push_back(Err(PlacementError::EndpointUnavailable));
    assert_eq!(
        readiness
            .provider
            .wait_until_ready(&readiness.placement, &process())
            .expect_err("readiness"),
        PlacementError::EndpointUnavailable
    );

    for boundary in ["stop", "remove"] {
        let cleanup = fixture();
        cleanup.docker.fail(boundary);
        cleanup
            .docker
            .set_inspections(vec![Some(observation(true))]);
        assert!(
            cleanup.provider.stop(&cleanup.placement).is_err(),
            "{boundary}"
        );
    }

    let material_cleanup = fixture();
    material_cleanup.material.fail("remove");
    material_cleanup.docker.set_inspections(vec![None]);
    assert_eq!(
        material_cleanup
            .provider
            .remove(&material_cleanup.placement)
            .expect_err("material cleanup"),
        PlacementError::ExecutionUnavailable
    );

    let participant = placement(false, PlacementState::Staged);
    let material = Arc::new(MockMaterial::new(plan(&participant)));
    let docker = Arc::new(MockDocker::default());
    docker.fail("exec_readiness");
    let provider = DockerLinuxPlacementExecutionProvider::new(
        material,
        docker,
        Arc::new(MockIdentity::default()),
        Arc::new(PollingLinuxContainerReadinessProvider::new(
            Arc::new(MockEndpointReadiness::default()),
            Arc::new(MockWaiter::default()),
        )),
    );
    assert_eq!(
        provider
            .wait_until_ready(&participant, &process())
            .expect_err("exec readiness"),
        PlacementError::ExecutionUnavailable
    );
}

// Stops and removes only the exact observed container during rollback and planned stop.
#[test]
fn execution_rollback_and_stop_use_exact_container_only() {
    for operation in ["rollback", "stop"] {
        let fixture = fixture();
        fixture
            .docker
            .set_inspections(vec![Some(observation(true))]);
        if operation == "rollback" {
            fixture
                .provider
                .rollback_start(&fixture.placement, Some(&process()))
                .expect("rollback");
        } else {
            fixture.provider.stop(&fixture.placement).expect("stop");
        }
        assert_eq!(
            *fixture.docker.calls.lock().expect("calls"),
            ["inspect", "stop", "remove"]
        );
    }
    let stopped = fixture();
    stopped
        .docker
        .set_inspections(vec![Some(observation(false))]);
    stopped
        .provider
        .stop(&stopped.placement)
        .expect("stopped cleanup");
    assert_eq!(
        *stopped.docker.calls.lock().expect("calls"),
        ["inspect", "remove"]
    );
}

// Removes staged material only after Docker proves exact container absence.
#[test]
fn execution_removal_requires_container_absence() {
    let unstaged = fixture();
    *unstaged.material.value.lock().expect("plan") = None;
    let unstaged_placement = placement(true, PlacementState::Staging);
    unstaged
        .provider
        .remove(&unstaged_placement)
        .expect("unstaged cleanup");
    assert!(unstaged
        .material
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));

    let absent = fixture();
    absent.docker.set_inspections(vec![None]);
    absent.provider.remove(&absent.placement).expect("remove");
    assert!(absent
        .material
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));

    let present = fixture();
    present
        .docker
        .set_inspections(vec![Some(observation(false))]);
    assert_eq!(
        present
            .provider
            .remove(&present.placement)
            .expect_err("present"),
        PlacementError::ExecutionUnavailable
    );
    assert!(!present
        .material
        .calls
        .lock()
        .expect("calls")
        .contains(&"remove".to_string()));
}

// Observes unstaged, staged, stopped, failed, running, and not-ready states exactly.
#[test]
fn execution_observation_covers_every_process_state() {
    let unstaged = fixture();
    *unstaged.material.value.lock().expect("plan") = None;
    assert_eq!(
        unstaged
            .provider
            .observe(&unstaged.placement)
            .expect("unstaged")
            .state(),
        LinuxPlacementExecutionState::Absent
    );

    for (durable, expected) in [
        (PlacementState::Staged, LinuxPlacementExecutionState::Staged),
        (
            PlacementState::Stopped,
            LinuxPlacementExecutionState::Stopped,
        ),
    ] {
        let fixture = fixture();
        let placement = placement(true, durable);
        *fixture.material.value.lock().expect("plan") = Some(plan(&placement));
        fixture.docker.set_inspections(vec![None]);
        assert_eq!(
            fixture
                .provider
                .observe(&placement)
                .expect("absent")
                .state(),
            expected
        );
    }

    let stopped = fixture();
    stopped
        .docker
        .set_inspections(vec![Some(observation(false))]);
    assert_eq!(
        stopped
            .provider
            .observe(&stopped.placement)
            .expect("stopped container")
            .state(),
        LinuxPlacementExecutionState::Failed
    );

    let running = fixture();
    running
        .docker
        .set_inspections(vec![Some(observation(true))]);
    assert!(running
        .provider
        .observe(&running.placement)
        .expect("running")
        .ready());

    let not_ready = fixture();
    not_ready
        .docker
        .set_inspections(vec![Some(observation(true))]);
    not_ready
        .endpoints
        .values
        .lock()
        .expect("values")
        .push_back(Ok(false));
    let observed = not_ready
        .provider
        .observe(&not_ready.placement)
        .expect("not ready");
    assert!(!observed.ready());
    assert!(observed.endpoint().is_none());
}

// System Docker client uses only fixed shell-free subcommands and strict JSON identity.
#[test]
fn system_docker_client_parses_absence_and_exact_inspection() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    let runner = Arc::new(MockRunner::default());
    let client = SystemDockerClient::new(runner.clone());
    runner
        .results
        .lock()
        .expect("results")
        .push_back(Ok(ShellFreeCommandOutput::new(0, Vec::new())));
    assert!(client.inspect(&plan).expect("absence").is_none());

    let document = serde_json::json!({
        "Id": "c".repeat(64),
        "Name": format!("/{}", container_name()),
        "Image": format!("sha256:{}", "b".repeat(64)),
        "State": {"Running": true, "Pid": 1234},
        "Config": {"Labels": labels()},
    });
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(
            0,
            format!("{}\n", "c".repeat(64)).into_bytes(),
        )),
        Ok(ShellFreeCommandOutput::new(
            0,
            serde_json::to_vec(&document).expect("JSON"),
        )),
    ]);
    assert_eq!(
        client.inspect(&plan).expect("inspect"),
        Some(observation(true))
    );
    let calls = runner.calls.lock().expect("calls");
    assert!(calls
        .iter()
        .all(|command| command.executable() == PathBuf::from("/usr/bin/docker")));
    assert!(calls
        .last()
        .expect("inspect call")
        .arguments()
        .contains(&"--".to_string()));
}

// Rejects Docker list ambiguity, invalid JSON, and changed inspect/list identity.
#[test]
fn system_docker_client_fails_closed_on_every_inspection_mismatch() {
    let placement = placement(true, PlacementState::Staged);
    let plan = plan(&placement);
    for listed in [
        "not-a-container-id\n".to_string(),
        format!("{}\n{}\n", "c".repeat(64), "d".repeat(64)),
    ] {
        let runner = Arc::new(MockRunner::default());
        runner
            .results
            .lock()
            .expect("results")
            .push_back(Ok(ShellFreeCommandOutput::new(0, listed.into_bytes())));
        assert!(SystemDockerClient::new(runner).inspect(&plan).is_err());
    }

    let runner = Arc::new(MockRunner::default());
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(
            0,
            format!("{}\n", "c".repeat(64)).into_bytes(),
        )),
        Ok(ShellFreeCommandOutput::new(0, b"invalid-json".to_vec())),
    ]);
    assert!(SystemDockerClient::new(runner).inspect(&plan).is_err());

    let changed = serde_json::json!({
        "Id": "d".repeat(64),
        "Name": format!("/{}", container_name()),
        "Image": format!("sha256:{}", "b".repeat(64)),
        "State": {"Running": true, "Pid": 1234},
        "Config": {"Labels": labels()},
    });
    let runner = Arc::new(MockRunner::default());
    runner.results.lock().expect("results").extend([
        Ok(ShellFreeCommandOutput::new(
            0,
            format!("{}\n", "c".repeat(64)).into_bytes(),
        )),
        Ok(ShellFreeCommandOutput::new(
            0,
            serde_json::to_vec(&changed).expect("JSON"),
        )),
    ]);
    assert!(SystemDockerClient::new(runner).inspect(&plan).is_err());
}

// System Docker client executes fixed create/start/stop/remove/readiness argv without a shell.
#[test]
fn system_docker_client_uses_only_exact_fixed_mutations() {
    let placement = placement(false, PlacementState::Staged);
    let plan = plan(&placement);
    let runner = Arc::new(MockRunner::default());
    let client = SystemDockerClient::new(runner.clone());
    client.create_and_start(&plan).expect("create");
    client.start(&plan).expect("start");
    client.stop(&plan).expect("stop");
    client.remove(&plan).expect("remove");
    assert!(client
        .exec_readiness(&plan, &["/opt/runtime/ready".to_string()])
        .expect("readiness"));
    let calls = runner.calls.lock().expect("calls");
    assert_eq!(calls[0], *plan.create_command());
    assert_eq!(calls[1].arguments()[..2], ["container", "start"]);
    assert_eq!(calls[2].arguments()[..2], ["container", "stop"]);
    assert_eq!(calls[3].arguments()[..2], ["container", "rm"]);
    assert_eq!(calls[4].arguments()[..2], ["container", "exec"]);
}

// Reads opaque Docker bytes with replay-free cursors, one bounded wait, and redacted failures.
#[test]
fn docker_log_provider_preserves_cursor_replay_wait_and_failure_boundaries() {
    let placement = placement(true, PlacementState::Running);
    let material = Arc::new(MockMaterial::new(plan(&placement)));
    let runner = Arc::new(MockRunner::default());
    let docker = Arc::new(SystemDockerClient::new(runner.clone()));
    let waiter = Arc::new(MockWaiter::default());
    let provider = DockerLinuxPlacementLogProvider::new(material, docker.clone(), waiter.clone());
    let request = PlacementLogReadRequest::new(
        placement.placement_group_id().clone(),
        None,
        2,
        1_024,
        Duration::from_millis(50),
    )
    .expect("request");
    push_docker_log_read(&runner, 0, b"");
    push_docker_log_read(
        &runner,
        0,
        b"2026-08-29T12:00:00.000000001Z first\n2026-08-29T12:00:00.000000002Z second\n",
    );
    let first = provider.read(&placement, &request).expect("first batch");
    assert_eq!(first.payload(), b"first\nsecond\n");
    assert_eq!(waiter.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        first.cursor().position(),
        "2026-08-29T12:00:00.000000002Z|1"
    );

    push_docker_log_read(
        &runner,
        0,
        b"2026-08-29T12:00:00.000000002Z second\n2026-08-29T12:00:00.000000003Z third\n",
    );
    let replay = <SystemDockerClient as LinuxDockerLogClient>::read_logs(
        docker.as_ref(),
        &plan(&placement),
        Some(first.cursor()),
        2,
        1_024,
    )
    .expect("cursor replay");
    assert_eq!(replay.payload(), b"third\n");
    assert!(!replay.is_truncated());

    push_docker_log_read(&runner, 0, b"malformed runtime bytes\n");
    assert_eq!(
        <SystemDockerClient as LinuxDockerLogClient>::read_logs(
            docker.as_ref(),
            &plan(&placement),
            None,
            2,
            1_024,
        )
        .expect_err("malformed log protocol"),
        PlacementError::ExecutionUnavailable
    );

    push_docker_log_read(&runner, 1, b"private native failure");
    assert_eq!(
        <SystemDockerClient as LinuxDockerLogClient>::read_logs(
            docker.as_ref(),
            &plan(&placement),
            None,
            2,
            1_024,
        )
        .expect_err("native failure"),
        PlacementError::ExecutionUnavailable
    );
    assert!(!format!("{:?}", PlacementError::ExecutionUnavailable).contains("private"));

    push_docker_log_read(&runner, 0, b"");
    let foreign = PlacementLogCursor::new(
        Sha256Digest::parse(&"d".repeat(64)).expect("foreign source"),
        "2026-08-29T12:00:00.000000003Z|1".to_string(),
    )
    .expect("foreign cursor");
    assert_eq!(
        <SystemDockerClient as LinuxDockerLogClient>::read_logs(
            docker.as_ref(),
            &plan(&placement),
            Some(&foreign),
            2,
            1_024,
        )
        .expect_err("foreign source"),
        PlacementError::ExecutionUnavailable
    );
}

// Procfs identity parsing preserves spaces in comm and rejects every malformed native fact.
#[test]
fn procfs_identity_provider_parses_and_rejects_exact_native_facts() {
    let valid = ProcfsLinuxProcessIdentityProvider::new(Arc::new(MockProcessIo {
        boot_id: "11111111-2222-3333-4444-555555555555\n".to_string(),
        stat: process_stat(),
        cgroup: "0::/user.slice/fixture.scope\n".to_string(),
    }));
    assert_eq!(
        valid.identity(&observation(true)).expect("identity"),
        process()
    );

    for (stat, cgroup, boot) in [
        (
            "invalid".to_string(),
            "0::/scope\n".to_string(),
            "11111111-2222-3333-4444-555555555555".to_string(),
        ),
        (
            process_stat(),
            "1:name=/legacy\n".to_string(),
            "11111111-2222-3333-4444-555555555555".to_string(),
        ),
        (
            process_stat(),
            "0::/../escape\n".to_string(),
            "11111111-2222-3333-4444-555555555555".to_string(),
        ),
        (
            process_stat(),
            "0::/scope\n".to_string(),
            "invalid".to_string(),
        ),
    ] {
        let provider = ProcfsLinuxProcessIdentityProvider::new(Arc::new(MockProcessIo {
            boot_id: boot,
            stat,
            cgroup,
        }));
        assert!(provider.identity(&observation(true)).is_err());
    }
    assert!(valid.identity(&observation(false)).is_err());
}
