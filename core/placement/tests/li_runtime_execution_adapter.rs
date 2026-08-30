// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    CredentialId, DeviceId, EndpointOwnership, EntityTimestamps, LogicalModelName, NodeAddress,
    NodeId, Placement, PlacementAssignment, PlacementGroupId, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeInstallationId, RuntimeSource, Sha256Digest, TaskId,
    TechnicalName, UnixMilliseconds,
};
use li_placement_manager::{
    LinuxContainerReadiness, LinuxRuntimePlacementEnvironment,
    MacosRuntimeExecutableIdentityProvider, MacosRuntimePlacementEnvironment,
    PlacementCredentialReferences, PlacementError, PlacementLaunchPlanResolver,
    ResolvedPlacementLaunchPlan, RuntimeManagerPlacementExecutionAdapter,
    RuntimePlacementExecutionProvider, RuntimePlacementLaunchPlanResolver, ShellFreeCommand,
    ShellFreeEnvironmentValue, SystemMacosRuntimeExecutableIdentityProvider,
};

// Returns one fixed verified executable identity without reading fixture paths.
struct MockMacosExecutableIdentity;

impl MacosRuntimeExecutableIdentityProvider for MockMacosExecutableIdentity {
    // Binds every fixture command to one exact deterministic content identity.
    fn identity(&self, _executable: &Path) -> Result<Sha256Digest, PlacementError> {
        Sha256Digest::parse(&"9".repeat(64)).map_err(|_| PlacementError::ExecutionUnavailable)
    }
}

// Creates one deterministic native environment for manifest-adapter tests.
fn macos_environment() -> MacosRuntimePlacementEnvironment {
    MacosRuntimePlacementEnvironment::with_executable_identity_provider(Arc::new(
        MockMacosExecutableIdentity,
    ))
}
use li_runtime_manager::{
    RuntimeError, RuntimeExecutionContainer, RuntimeExecutionDistribution,
    RuntimeExecutionImageReference, RuntimeExecutionManifest, RuntimeExecutionManifestProvider,
    RuntimeExecutionPlatform, RuntimeExecutionReadiness, RuntimeExecutionServing,
    RuntimeExecutionTask, RuntimeTaskLauncher,
};

// Returns one exact placement with configurable task, ports, devices, and endpoint ownership.
fn placement(task: &str, port_count: u16, device_count: usize, endpoint_owner: bool) -> Placement {
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
            TaskId::parse(task).expect("task"),
            NodeAddress::parse("node.local").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, port_count).expect("ports"),
                (0..device_count)
                    .map(|index| DeviceId::parse(&format!("GPU-{index}")).expect("GPU"))
                    .collect(),
                None,
            )
            .expect("resources"),
            if endpoint_owner {
                EndpointOwnership::Owner
            } else {
                EndpointOwnership::Participant
            },
        ),
        PlacementState::Staging,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns exact reference-only credential inputs for one placement.
fn credentials(placement: &Placement) -> PlacementCredentialReferences {
    PlacementCredentialReferences::new(
        placement.placement_id().clone(),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        CredentialId::parse(&"6".repeat(32)).expect("CA"),
        PathBuf::from("/private/li_engine_credential"),
        PathBuf::from("/private/li_engine_tls_certificate.pem"),
        PathBuf::from("/private/li_engine_tls_private_key.pem"),
        Sha256Digest::parse(&"7".repeat(64)).expect("certificate"),
        Sha256Digest::parse(&"8".repeat(64)).expect("bundle"),
    )
    .expect("credentials")
}

// Returns one Core-owned Docker client command root.
fn docker() -> ShellFreeCommand {
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/docker"),
        Vec::new(),
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::core("HOME", "/home/fixture").expect("HOME"),
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("PATH"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("Docker")
}

// Returns one validated opaque runtime task.
fn task(
    task_id: &str,
    launcher: RuntimeTaskLauncher,
    readiness: RuntimeExecutionReadiness,
    port_count: u16,
    device_count: u16,
    endpoint_owner: bool,
) -> RuntimeExecutionTask {
    RuntimeExecutionTask::new(
        TaskId::parse(task_id).expect("task"),
        launcher,
        vec![("TASK_MODE".to_string(), task_id.to_string())],
        port_count,
        device_count,
        endpoint_owner,
        readiness,
    )
    .expect("task")
}

// Returns one complete typed execution manifest for deterministic adapter tests.
fn manifest(
    platform: RuntimeExecutionPlatform,
    distribution: RuntimeExecutionDistribution,
    task: RuntimeExecutionTask,
    startup_timeout: Duration,
) -> RuntimeExecutionManifest {
    RuntimeExecutionManifest::new(
        RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
        LogicalModelName::parse("fixture-model").expect("model"),
        platform,
        TechnicalName::parse("vllm").expect("engine"),
        distribution,
        vec!["--fixture".to_string()],
        vec![("ENGINE_MODE".to_string(), "fixture".to_string())],
        "vllm".to_string(),
        true,
        RuntimeExecutionContainer::new(
            64 * 1024 * 1024 * 1024,
            if platform == RuntimeExecutionPlatform::MacosArm64 {
                0
            } else {
                8 * 1024 * 1024 * 1024
            },
            startup_timeout,
            (platform != RuntimeExecutionPlatform::MacosArm64).then(|| "0-7".to_string()),
        )
        .expect("container"),
        RuntimeExecutionServing::new(128, 8, 262_144, "/v1/letsinfer/token-count".to_string())
            .expect("serving"),
        PathBuf::from("/managed/runtime"),
        PathBuf::from("/managed/models"),
        PathBuf::from("/managed/engine"),
        PathBuf::from("/managed/cache"),
        vec![task.clone()],
        vec![vec![task.task_id().clone()]],
    )
    .expect("manifest")
}

// Returns one ordinary digest-pinned OCI execution distribution.
fn oci_distribution() -> RuntimeExecutionDistribution {
    let reference = RuntimeSource::parse(&format!(
        "ghcr.io/letsinferlabs/engine-images@sha256:{}",
        "9".repeat(64)
    ))
    .expect("reference");
    RuntimeExecutionDistribution::Oci {
        identity_reference: reference.clone(),
        execution_reference: RuntimeExecutionImageReference::distribution(&reference),
        immutable_id: Sha256Digest::parse(&"a".repeat(64)).expect("image ID"),
    }
}

// Returns one exact-candidate distribution launched only by its installation-bound config ID.
fn local_oci_distribution() -> RuntimeExecutionDistribution {
    let reference = RuntimeSource::parse(&format!(
        "ghcr.io/letsinferlabs/engine-images@sha256:{}",
        "9".repeat(64)
    ))
    .expect("reference");
    let immutable_id = Sha256Digest::parse(&"a".repeat(64)).expect("image ID");
    RuntimeExecutionDistribution::Oci {
        identity_reference: reference,
        execution_reference: RuntimeExecutionImageReference::local_config(immutable_id.clone()),
        immutable_id,
    }
}

// Supplies one deterministic typed manager result or configured failure.
struct MockManifests {
    value: Mutex<Option<RuntimeExecutionManifest>>,
    should_fail: AtomicBool,
}

impl MockManifests {
    // Creates one deterministic manager-result fixture.
    fn new(value: RuntimeExecutionManifest) -> Self {
        Self {
            value: Mutex::new(Some(value)),
            should_fail: AtomicBool::new(false),
        }
    }
}

impl RuntimeExecutionManifestProvider for MockManifests {
    // Returns the configured typed result without reading native state.
    fn manifest(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(RuntimeError::ExecutionManifestUnavailable);
        }
        self.value
            .lock()
            .expect("manifest")
            .clone()
            .ok_or(RuntimeError::ExecutionManifestUnavailable)
    }
}

// Creates one Linux adapter and retains its typed manager-result mock.
fn linux_adapter(
    manifest: RuntimeExecutionManifest,
) -> (
    Arc<RuntimeManagerPlacementExecutionAdapter>,
    Arc<MockManifests>,
) {
    let manifests = Arc::new(MockManifests::new(manifest));
    let environment = LinuxRuntimePlacementEnvironment::new(
        docker(),
        8 * 1024 * 1024 * 1024,
        1_000,
        1_000,
        vec![PathBuf::from("/dev/infiniband/rdma_cm")],
        BTreeMap::from([("fixture.runtime".to_string(), "true".to_string())]),
        vec!["--ulimit".to_string(), "memlock=1024:1024".to_string()],
    )
    .expect("environment");
    (
        Arc::new(RuntimeManagerPlacementExecutionAdapter::new(
            manifests.clone(),
            Some(environment),
            None,
        )),
        manifests,
    )
}

// Resolves one verified Linux manifest through the final sealed Docker plan.
#[test]
fn linux_manifest_reaches_one_sealed_protocol_owned_plan() {
    let placement = placement("task-0", 1, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(900),
    );
    let (adapter, _) = linux_adapter(runtime);
    let resolver = RuntimePlacementLaunchPlanResolver::new(adapter);
    let ResolvedPlacementLaunchPlan::Linux(plan) = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("plan")
    else {
        panic!("expected Linux plan");
    };
    let arguments = plan.create_command().arguments();
    for expected in [
        "LETSINFER_ENGINE_PROTOCOL=2",
        "LETSINFER_RUNTIME_CONFIG=/opt/letsinfer/runtime-pack/runtime.json",
        "LETSINFER_API_KEY_FILE=/run/secrets/li_engine_credential",
        "LETSINFER_SERVED_MODEL=fixture-model",
    ] {
        assert!(
            arguments.iter().any(|value| value == expected),
            "{expected}"
        );
    }
    assert_eq!(
        arguments.last().map(String::as_str),
        Some("serve"),
        "manifest launch must end in fixed adapter argv"
    );
    assert!(arguments
        .iter()
        .any(|value| value == "/opt/letsinfer/bin/engine-adapter"));
    assert!(arguments.iter().any(|value| {
        value == &format!("/managed/cache/{}/{}:/root", "4".repeat(32), "1".repeat(32))
    }));
    assert!(matches!(
        plan.readiness(),
        LinuxContainerReadiness::Endpoint { attempts: 900, interval }
            if *interval == Duration::from_secs(1)
    ));
    assert_eq!(plan.endpoint().expect("endpoint").max_active_requests(), 8);
    assert_eq!(
        plan.image_reference().as_str(),
        format!(
            "ghcr.io/letsinferlabs/engine-images@sha256:{}",
            "9".repeat(64)
        )
    );
    assert!(plan.image_reference().local_config_digest().is_none());
}

// Launches one verifier candidate by local config while retaining its signed OCI identity.
#[test]
fn exact_candidate_uses_local_config_without_mutating_runtime_identity() {
    let placement = placement("task-0", 1, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        local_oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(900),
    );
    let RuntimeExecutionDistribution::Oci {
        identity_reference,
        execution_reference,
        immutable_id,
    } = runtime.distribution()
    else {
        panic!("expected OCI distribution");
    };
    assert_eq!(
        identity_reference.as_str(),
        format!(
            "ghcr.io/letsinferlabs/engine-images@sha256:{}",
            "9".repeat(64)
        )
    );
    assert_eq!(
        execution_reference.as_str(),
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
        execution_reference.local_config_digest(),
        Some(immutable_id)
    );

    let (adapter, _) = linux_adapter(runtime);
    let resolver = RuntimePlacementLaunchPlanResolver::new(adapter);
    let ResolvedPlacementLaunchPlan::Linux(plan) = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("local config plan")
    else {
        panic!("expected Linux plan");
    };
    assert_eq!(
        plan.image_reference().as_str(),
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
        plan.image_reference().local_config_digest(),
        Some(&Sha256Digest::parse(&"a".repeat(64)).expect("image ID"))
    );
    assert_eq!(
        plan.create_command()
            .arguments()
            .iter()
            .filter(|argument| argument.as_str() == format!("sha256:{}", "a".repeat(64)))
            .count(),
        1
    );
    assert!(!plan.create_command().arguments().iter().any(|argument| {
        argument
            == &format!(
                "ghcr.io/letsinferlabs/engine-images@sha256:{}",
                "9".repeat(64)
            )
    }));
}

// Preserves runtime-owned command and exec readiness without exposing engine semantics.
#[test]
fn runtime_command_and_exec_readiness_remain_opaque() {
    let placement = placement("task-0", 2, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxX86_64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::RuntimeCommand(vec![
                "/opt/letsinfer/bin/worker".to_string(),
                "serve".to_string(),
            ]),
            RuntimeExecutionReadiness::Exec {
                command: vec!["/opt/letsinfer/bin/worker".to_string(), "ready".to_string()],
                interval: Duration::from_secs(2),
                timeout: Duration::from_secs(5),
                retries: 30,
            },
            2,
            1,
            true,
        ),
        Duration::from_secs(600),
    );
    let (adapter, _) = linux_adapter(runtime);
    let resolver = RuntimePlacementLaunchPlanResolver::new(adapter);
    let ResolvedPlacementLaunchPlan::Linux(plan) = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("plan")
    else {
        panic!("expected Linux plan");
    };
    assert!(matches!(
        plan.readiness(),
        LinuxContainerReadiness::Exec { arguments, attempts: 30, interval }
            if arguments == &["/opt/letsinfer/bin/worker", "ready"]
                && *interval == Duration::from_secs(2)
    ));
    assert_eq!(
        plan.create_command().arguments().last().map(String::as_str),
        Some("serve")
    );
}

// Resolves one verified native archive through a shell-free macOS launchd plan.
#[test]
fn macos_manifest_reaches_one_shell_free_native_plan() {
    let placement = placement("task-0", 2, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::MacosArm64,
        RuntimeExecutionDistribution::NativeArchive {
            entrypoint: PathBuf::from("adapter/engine-adapter"),
            upstream_executable: PathBuf::from("llama-server"),
            port_count: 2,
        },
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            2,
            1,
            true,
        ),
        Duration::from_secs(900),
    );
    let manifests = Arc::new(MockManifests::new(runtime));
    let adapter = Arc::new(RuntimeManagerPlacementExecutionAdapter::new(
        manifests,
        None,
        Some(macos_environment()),
    ));
    let resolver = RuntimePlacementLaunchPlanResolver::new(adapter);
    let ResolvedPlacementLaunchPlan::Macos(plan) = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("plan")
    else {
        panic!("expected macOS plan");
    };
    assert_eq!(
        plan.command().executable(),
        Path::new("/managed/runtime/adapter/engine-adapter")
    );
    assert_eq!(plan.command().arguments(), &["serve"]);
    for expected in [
        "LETSINFER_NATIVE_ENGINE_ROOT",
        "LETSINFER_NATIVE_UPSTREAM_EXECUTABLE",
        "LETSINFER_RUNTIME_CONFIG",
        "LETSINFER_SERVED_MODEL",
    ] {
        assert!(plan
            .command()
            .environment()
            .iter()
            .any(|value| value.name() == expected));
    }
    assert!(plan.command().environment().iter().any(|value| {
        value.name() == "LETSINFER_CACHE_ROOT"
            && value.value() == format!("/managed/cache/{}/{}", "4".repeat(32), "1".repeat(32))
    }));
    assert_eq!(
        plan.log_path(),
        Some(&PathBuf::from(format!(
            "/managed/cache/{}/{}/logs/li_placement_{}.log",
            "4".repeat(32),
            "1".repeat(32),
            "1".repeat(32)
        )))
    );
    assert_eq!(plan.readiness_attempts(), 900);
    assert_eq!(plan.readiness_interval(), Duration::from_secs(1));
}

// Converts the maximum accepted startup window into an exact bounded polling schedule.
#[test]
fn long_startup_window_remains_bounded_without_shortening_it() {
    let placement = placement("task-0", 1, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(86_400),
    );
    let (adapter, _) = linux_adapter(runtime);
    let execution = adapter.execution(&placement).expect("execution");
    let li_placement_manager::RuntimePlacementExecution::Linux { launch: _, .. } = execution else {
        panic!("expected Linux execution");
    };
    let resolver = RuntimePlacementLaunchPlanResolver::new(adapter);
    let ResolvedPlacementLaunchPlan::Linux(plan) = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("plan")
    else {
        panic!("expected Linux plan");
    };
    assert!(matches!(
        plan.readiness(),
        LinuxContainerReadiness::Endpoint { attempts: 3_600, interval }
            if *interval == Duration::from_secs(24)
    ));
}

// Maps RuntimeManager failure to one stable execution error without leaking details.
#[test]
fn runtime_manager_failure_is_fail_closed() {
    let placement = placement("task-0", 1, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(10),
    );
    let (adapter, manifests) = linux_adapter(runtime);
    manifests.should_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        adapter.execution(&placement).expect_err("failure"),
        PlacementError::ExecutionUnavailable
    );
}

// Rejects missing platform composition before constructing any launch plan.
#[test]
fn missing_platform_environment_is_explicit() {
    let placement = placement("task-0", 1, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(10),
    );
    let adapter = RuntimeManagerPlacementExecutionAdapter::new(
        Arc::new(MockManifests::new(runtime)),
        None,
        None,
    );
    assert_eq!(
        adapter.execution(&placement).expect_err("environment"),
        PlacementError::ExecutionUnavailable
    );
}

// Rejects missing tasks, resource-count divergence, and endpoint-owner divergence.
#[test]
fn exact_task_binding_matrix_rejects_every_divergence() {
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(10),
    );
    for (name, placement) in [
        ("task", placement("task-1", 1, 1, true)),
        ("ports", placement("task-0", 2, 1, true)),
        ("devices", placement("task-0", 1, 2, true)),
        ("endpoint", placement("task-0", 1, 1, false)),
    ] {
        let (adapter, _) = linux_adapter(runtime.clone());
        assert!(
            matches!(
                adapter.execution(&placement),
                Err(PlacementError::InvalidRequest { .. })
            ),
            "divergence={name}"
        );
    }
}

// Rejects native embedded applications until an independently supervised app provider exists.
#[test]
fn embedded_application_execution_fails_without_hidden_fallback() {
    let placement = placement("task-0", 1, 1, true);
    let runtime = manifest(
        RuntimeExecutionPlatform::MacosArm64,
        RuntimeExecutionDistribution::EmbeddedApplication {
            bundle_id: "ai.letsinfer.fixture".to_string(),
            embedded_engine: "fixture".to_string(),
            payload_id: li_core_interface::Sha256Digest::parse(&"6".repeat(64)).expect("payload"),
            source_revision: li_core_interface::ArtifactRevision::parse(&"7".repeat(40))
                .expect("revision"),
            minimum_version: li_core_interface::RuntimeVersion::parse("1.0.0").expect("version"),
            entrypoint: PathBuf::from("adapter/engine-adapter"),
            port_count: 1,
        },
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(10),
    );
    let adapter = RuntimeManagerPlacementExecutionAdapter::new(
        Arc::new(MockManifests::new(runtime)),
        None,
        Some(macos_environment()),
    );
    assert_eq!(
        adapter.execution(&placement).expect_err("unsupported app"),
        PlacementError::ExecutionUnavailable
    );
}

// Rejects protected Docker options and invalid host identities at their constructors.
#[test]
fn platform_environment_validation_is_not_deferred() {
    let _ = MacosRuntimePlacementEnvironment::default();
    assert!(LinuxRuntimePlacementEnvironment::ordinary(docker(), 0, 1_000).is_err());
    let environment = LinuxRuntimePlacementEnvironment::new(
        docker(),
        1,
        1_000,
        1_000,
        Vec::new(),
        BTreeMap::new(),
        vec!["--name".to_string(), "foreign".to_string()],
    )
    .expect("outer environment");
    let runtime = manifest(
        RuntimeExecutionPlatform::LinuxArm64,
        oci_distribution(),
        task(
            "task-0",
            RuntimeTaskLauncher::Manifest,
            RuntimeExecutionReadiness::Manifest,
            1,
            1,
            true,
        ),
        Duration::from_secs(10),
    );
    let adapter = RuntimeManagerPlacementExecutionAdapter::new(
        Arc::new(MockManifests::new(runtime)),
        Some(environment),
        None,
    );
    assert!(matches!(
        adapter.execution(&placement("task-0", 1, 1, true)),
        Err(PlacementError::InvalidRequest { .. })
    ));
}

// Binds one stable owner-controlled executable and rejects content, mode, and link substitution.
#[test]
fn system_macos_executable_identity_is_exact_and_no_follow() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let executable = directory.path().join("engine-adapter");
    fs::write(&executable, b"first executable").expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("permissions");
    let provider = SystemMacosRuntimeExecutableIdentityProvider;
    let first = provider.identity(&executable).expect("first identity");
    assert_eq!(provider.identity(&executable).expect("replay"), first);

    fs::write(&executable, b"second executable").expect("replace bytes");
    let second = provider.identity(&executable).expect("second identity");
    assert_ne!(second, first);
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o722)).expect("unsafe mode");
    assert!(provider.identity(&executable).is_err());

    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("safe mode");
    let link = directory.path().join("engine-link");
    symlink(&executable, &link).expect("symlink");
    assert!(provider.identity(&link).is_err());
}
