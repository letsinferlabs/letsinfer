// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    compose_core_model_placement, ApplicationCoreSetup, CoreModelPlacementCompositionInput,
    CoreModelPlacementPlatformInput, CoreNativeServiceCommandOutput,
    CoreNativeServiceCommandRunner, CoreSetupCliConfigurationTemplate, CoreSetupCompositionError,
    CoreSetupCompositionInput, CoreSetupCompositionRoots, CoreSetupConfigurationLocation,
    CoreSetupGatewayConfigurationTemplate, CoreSetupGatewayHealthInput,
    CoreSetupGatewayProtectionInput, CoreSetupGatewayTrustPaths, CoreSetupMaterialPaths,
    CoreSetupNetworkPlan, CoreSetupNodeBenchmarkTemplate, CoreSetupNodeConfigurationTemplate,
    CoreSetupNodeHardwareInput, CoreSetupNodeLocalApiInput, CoreSetupNodeModelInput,
    CoreSetupNodePairingPlatformInput, CoreSetupNodePlacementSafetyTemplate,
    CoreSetupNodeProtectionExecutableInput, CoreSetupNodeTrustPaths, CoreSetupNodeUpdateInput,
    CoreSetupPairingTrustPaths, CoreSetupPersistencePreflight, CoreSetupPlatformInput,
    CoreSetupRequest, CoreSetupResult, CoreSetupTransaction, CoreSetupWatchdogCapabilityError,
    CoreSetupWatchdogCapabilityPreflight, CoreSetupWatchdogConfigurationTemplate,
    CoreSetupWatchdogHealthInput, CoreSetupWatchdogTrustPaths, SystemCoreSetupPersistencePreflight,
};

// Creates one complete platform-exact native model composition fixture.
fn model_input(platform: CoreUpdateServicePlatform, root: &Path) -> CoreSetupNodeModelInput {
    let macos = platform == CoreUpdateServicePlatform::Macos;
    CoreSetupNodeModelInput {
        catalog_source:
            "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json"
                .to_string(),
        catalog_cache_root: root.join("catalog_cache"),
        catalog_hydration_root: root.join("catalog_hydration"),
        http_workspace_root: root.join("http_workspace"),
        installation_root: root.join("runtime_installations"),
        runtime_cache_root: root.join("cache"),
        curl_command: PathBuf::from("/usr/bin/curl"),
        docker_command: PathBuf::from("/usr/bin/docker"),
        command_working_directory: root.join("command_workspace"),
        placement_material_root: root.join("placement_material"),
        placement_secret_root: root.join("placement_secrets"),
        placement_tls_workspace_root: root.join("placement_tls_staging"),
        first_port: 18_000,
        port_count: 32,
        endpoint_timeout_milliseconds: 1_000,
        maximum_hardware_age_milliseconds: 60_000,
        group_id: 20,
        launch_agents_root: macos.then(|| root.join("LaunchAgents")),
        launchctl_command: macos.then(|| PathBuf::from("/bin/launchctl")),
    }
}
use li_core_interface::{
    CpuArchitecture, CredentialId, DisplayName, NodeAddress, NodeId, PlacementGroupId,
    ResourceIdentity, RuntimeInstallationId, Sha256Digest,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};
use li_placement_manager::{
    PlacementError, PlacementRecord, PlacementStore, VersionedPlacementRecord,
};
use li_runtime_manager::{
    RuntimeError, RuntimeExecutionManifest, RuntimeExecutionManifestProvider,
};
use li_watchdog_manager::WatchdogSafetyThresholds;
use tempfile::TempDir;

// Names every Node model root that setup must own before resident composition.
const NODE_MODEL_PRIVATE_ROOT_NAMES: [&str; 9] = [
    "catalog_cache",
    "catalog_hydration",
    "http_workspace",
    "runtime_installations",
    "cache",
    "command_workspace",
    "placement_material",
    "placement_secrets",
    "placement_tls_staging",
];

// Stores a deterministic setup result or failure and counts every transaction entry.
struct TestSetupTransaction {
    outcomes: Mutex<VecDeque<Result<CoreSetupResult, li_core_application::CoreSetupError>>>,
    invocations: AtomicUsize,
}

// Returns one deterministic boot-persistence result and counts every preflight invocation.
struct TestPersistencePreflight {
    result: Result<(), CoreSetupCompositionError>,
    invocations: AtomicUsize,
}

// Returns one deterministic Watchdog capability observation and counts every native boundary.
struct TestWatchdogCapabilityPreflight {
    result: Result<Option<u32>, CoreSetupWatchdogCapabilityError>,
    invocations: AtomicUsize,
}

// Rejects every aggregate operation because production composition must not access placement state.
struct UnavailablePlacementStore;

impl PlacementStore for UnavailablePlacementStore {
    // Rejects construction-time resource discovery.
    fn occupied_resources(
        &self,
        _node_id: &NodeId,
    ) -> Result<Vec<ResourceIdentity>, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }

    // Rejects construction-time placement creation.
    fn create(&self, _record: PlacementRecord) -> Result<VersionedPlacementRecord, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }

    // Rejects construction-time aggregate reads.
    fn read(
        &self,
        _placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }

    // Rejects construction-time placement replacement.
    fn replace(
        &self,
        _record: PlacementRecord,
        _expected_revision: u64,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }
}

// Rejects every manifest read because production composition must not resolve a runtime.
struct UnavailableRuntimeExecutionManifests;

impl RuntimeExecutionManifestProvider for UnavailableRuntimeExecutionManifests {
    // Rejects construction-time execution-manifest reads.
    fn manifest(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        Err(RuntimeError::ExecutionManifestUnavailable)
    }
}

// Stores one exact native persistence command invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TestNativeCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    maximum_output_bytes: usize,
}

// Returns deterministic native command outputs and records every shell-free invocation.
struct TestNativeCommandRunner {
    outcomes: Mutex<VecDeque<CoreNativeServiceCommandOutput>>,
    commands: Mutex<Vec<TestNativeCommand>>,
}

impl TestNativeCommandRunner {
    // Creates one runner from an exact ordered native result sequence.
    fn new(outcomes: Vec<CoreNativeServiceCommandOutput>) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from(outcomes)),
            commands: Mutex::new(Vec::new()),
        }
    }

    // Returns every observed native invocation in order.
    fn commands(&self) -> Vec<TestNativeCommand> {
        self.commands.lock().expect("commands").clone()
    }
}

impl CoreNativeServiceCommandRunner for TestNativeCommandRunner {
    // Records one fixed executable and argv before returning the injected result.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<CoreNativeServiceCommandOutput, li_core_update_manager::CoreUpdateError> {
        self.commands
            .lock()
            .expect("commands")
            .push(TestNativeCommand {
                executable: executable.to_path_buf(),
                arguments: arguments.to_vec(),
                timeout,
                maximum_output_bytes: maximum_stdout_bytes,
            });
        Ok(self
            .outcomes
            .lock()
            .expect("outcomes")
            .pop_front()
            .expect("injected native command output"))
    }
}

impl TestPersistencePreflight {
    // Creates one accepting or rejecting read-only persistence capability.
    fn new(result: Result<(), CoreSetupCompositionError>) -> Self {
        Self {
            result,
            invocations: AtomicUsize::new(0),
        }
    }

    // Returns how many times the application checked boot persistence.
    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }
}

impl CoreSetupPersistencePreflight for TestPersistencePreflight {
    // Returns the injected capability result without performing native work.
    fn verify(
        &self,
        _context: CoreUpdateServiceContext,
        _owner_user_id: u32,
    ) -> Result<(), CoreSetupCompositionError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

impl TestWatchdogCapabilityPreflight {
    // Creates one available, unsupported, zero-device, or failed Watchdog capability.
    fn new(result: Result<Option<u32>, CoreSetupWatchdogCapabilityError>) -> Self {
        Self {
            result,
            invocations: AtomicUsize::new(0),
        }
    }

    // Returns how many times setup observed the native Watchdog capability.
    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }
}

impl CoreSetupWatchdogCapabilityPreflight for TestWatchdogCapabilityPreflight {
    // Returns the injected NVML observation without loading a native driver.
    fn physical_device_count(&self) -> Result<Option<u32>, CoreSetupWatchdogCapabilityError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.result
    }
}

impl TestSetupTransaction {
    // Creates one exact ordered transaction outcome sequence.
    fn new(outcomes: Vec<Result<CoreSetupResult, li_core_application::CoreSetupError>>) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from(outcomes)),
            invocations: AtomicUsize::new(0),
        }
    }

    // Returns how many requests crossed the application preflight boundary.
    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }
}

impl CoreSetupTransaction for TestSetupTransaction {
    // Returns the next injected result without mocking the application preflight or JSON codec.
    fn setup(
        &self,
        _request: &CoreSetupRequest,
    ) -> Result<CoreSetupResult, li_core_application::CoreSetupError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.outcomes
            .lock()
            .expect("outcomes")
            .pop_front()
            .expect("injected outcome")
    }
}

// Proves Linux linger and macOS GUI-domain checks bind exact native commands and bounds.
#[test]
fn system_persistence_preflight_uses_exact_platform_commands() {
    let linux_runner = Arc::new(TestNativeCommandRunner::new(vec![
        CoreNativeServiceCommandOutput::new(0, Vec::new()),
        CoreNativeServiceCommandOutput::new(0, b"yes\n".to_vec()),
    ]));
    let linux = SystemCoreSetupPersistencePreflight::with_runner(linux_runner.clone());
    linux
        .verify(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            501,
        )
        .expect("Linux persistence");
    assert_eq!(
        linux_runner.commands(),
        vec![
            native_command("/usr/bin/systemctl", &["--user", "show-environment"]),
            native_command(
                "/usr/bin/loginctl",
                &["show-user", "501", "--property", "Linger", "--value"],
            ),
        ]
    );

    let macos_runner = Arc::new(TestNativeCommandRunner::new(vec![
        CoreNativeServiceCommandOutput::new(0, b"502\n".to_vec()),
        CoreNativeServiceCommandOutput::new(0, b"Aqua\n".to_vec()),
    ]));
    let macos = SystemCoreSetupPersistencePreflight::with_runner(macos_runner.clone());
    macos
        .verify(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Macos,
                CoreUpdateNodeRole::Main,
            ),
            502,
        )
        .expect("macOS persistence");
    assert_eq!(
        macos_runner.commands(),
        vec![
            native_command("/bin/launchctl", &["manageruid"]),
            native_command("/bin/launchctl", &["managername"]),
        ]
    );
}

// Rejects unavailable user buses, disabled linger, malformed linger, and absent GUI domains.
#[test]
fn system_persistence_preflight_fails_closed_for_every_unavailable_state() {
    let cases = [
        vec![CoreNativeServiceCommandOutput::new(1, Vec::new())],
        vec![
            CoreNativeServiceCommandOutput::new(0, Vec::new()),
            CoreNativeServiceCommandOutput::new(1, Vec::new()),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, Vec::new()),
            CoreNativeServiceCommandOutput::new(0, b"no\n".to_vec()),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, Vec::new()),
            CoreNativeServiceCommandOutput::new(0, b"yes\nextra\n".to_vec()),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, Vec::new()),
            CoreNativeServiceCommandOutput::new(0, vec![0xff]),
        ],
    ];
    for outcomes in cases {
        let preflight = SystemCoreSetupPersistencePreflight::with_runner(Arc::new(
            TestNativeCommandRunner::new(outcomes),
        ));
        assert_eq!(
            preflight.verify(
                CoreUpdateServiceContext::new(
                    CoreUpdateServicePlatform::Linux,
                    CoreUpdateNodeRole::Main,
                ),
                501,
            ),
            Err(CoreSetupCompositionError::BootPersistenceUnavailable)
        );
    }

    let macos_cases = [
        vec![CoreNativeServiceCommandOutput::new(1, Vec::new())],
        vec![CoreNativeServiceCommandOutput::new(0, b"502\n".to_vec())],
        vec![CoreNativeServiceCommandOutput::new(
            0,
            b"501\nextra\n".to_vec(),
        )],
        vec![CoreNativeServiceCommandOutput::new(0, vec![0xff])],
        vec![CoreNativeServiceCommandOutput::new_with_stderr(
            0,
            b"501\n".to_vec(),
            b"diagnostic".to_vec(),
        )],
        vec![
            CoreNativeServiceCommandOutput::new(0, b"501\n".to_vec()),
            CoreNativeServiceCommandOutput::new(1, Vec::new()),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, b"501\n".to_vec()),
            CoreNativeServiceCommandOutput::new(0, b"Background\n".to_vec()),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, b"501\n".to_vec()),
            CoreNativeServiceCommandOutput::new(0, b"Aqua\nextra\n".to_vec()),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, b"501\n".to_vec()),
            CoreNativeServiceCommandOutput::new(0, vec![0xff]),
        ],
        vec![
            CoreNativeServiceCommandOutput::new(0, b"501\n".to_vec()),
            CoreNativeServiceCommandOutput::new_with_stderr(
                0,
                b"Aqua\n".to_vec(),
                b"diagnostic".to_vec(),
            ),
        ],
    ];
    for outcomes in macos_cases {
        let preflight = SystemCoreSetupPersistencePreflight::with_runner(Arc::new(
            TestNativeCommandRunner::new(outcomes),
        ));
        assert_eq!(
            preflight.verify(
                CoreUpdateServiceContext::new(
                    CoreUpdateServicePlatform::Macos,
                    CoreUpdateNodeRole::Main,
                ),
                501,
            ),
            Err(CoreSetupCompositionError::BootPersistenceUnavailable)
        );
    }
}

// Retains one real temporary layout and its immutable production composition input.
struct ProductionFixture {
    _temporary: TempDir,
    gateway_telemetry_directory: PathBuf,
    input: CoreSetupCompositionInput,
}

// Composes the concrete Linux and macOS provider graphs without reading their deferred inputs.
#[test]
fn production_composition_constructs_both_supported_platforms() {
    for platform in [
        CoreUpdateServicePlatform::Linux,
        CoreUpdateServicePlatform::Macos,
    ] {
        let fixture = production_fixture(platform);
        let gateway_telemetry_directory = fixture.gateway_telemetry_directory.clone();
        let watchdog_capability = Arc::new(TestWatchdogCapabilityPreflight::new(Ok(Some(2))));
        let application = ApplicationCoreSetup::compose_with_preflights(
            fixture.input,
            accepting_persistence(),
            watchdog_capability.clone(),
        )
        .expect("composition");
        assert_eq!(
            application.context(),
            CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main)
        );
        let metadata =
            fs::symlink_metadata(gateway_telemetry_directory).expect("Gateway telemetry directory");
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            watchdog_capability.invocations(),
            usize::from(platform == CoreUpdateServicePlatform::Linux)
        );
    }
}

// Creates the exact Linux Watchdog protection root with private ownership before startup.
#[test]
fn production_composition_creates_linux_watchdog_protection_root() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let protection_root = layout.material_root.join("watchdog/protected-placements");
    let input = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
    )
    .expect("composition input");
    assert!(!protection_root.exists());

    let _application = ApplicationCoreSetup::compose_with_preflights(
        input,
        accepting_persistence(),
        accepting_watchdog_capability(),
    )
    .expect("composition");

    let metadata = fs::symlink_metadata(protection_root).expect("Watchdog protection root");
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
}

// Prepares and replays every Node model root that requires setup-owned private storage.
#[test]
fn production_setup_prepares_required_node_model_roots_and_replay() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let runtime_cache_root = layout.letsinfer_home.join("cache");
    let required_roots = NODE_MODEL_PRIVATE_ROOT_NAMES
        .map(|relative_root| layout.letsinfer_home.join(relative_root));
    let protection_root = layout.material_root.join("watchdog/protected-placements");
    for root in &required_roots {
        assert!(!root.exists());
    }

    let first_input = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
    )
    .expect("first composition input");
    let first = ApplicationCoreSetup::compose_with_preflights(
        first_input,
        accepting_persistence(),
        accepting_watchdog_capability(),
    )
    .expect("first composition");
    let first_identities = required_roots
        .iter()
        .map(|root| {
            let metadata = private_directory_metadata(root);
            (metadata.dev(), metadata.ino())
        })
        .collect::<Vec<_>>();
    let sentinels = required_roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            let sentinel = root.join(format!("existing-state-{index}"));
            fs::write(&sentinel, b"preserve on replay").expect("root sentinel");
            sentinel
        })
        .collect::<Vec<_>>();
    drop(first);

    let replay_input = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
    )
    .expect("replay composition input");
    let replay = ApplicationCoreSetup::compose_with_preflights(
        replay_input,
        accepting_persistence(),
        accepting_watchdog_capability(),
    )
    .expect("replay composition");
    for ((root, sentinel), (first_device, first_inode)) in
        required_roots.iter().zip(&sentinels).zip(first_identities)
    {
        let replay_metadata = private_directory_metadata(root);
        assert_eq!(replay_metadata.dev(), first_device);
        assert_eq!(replay_metadata.ino(), first_inode);
        assert_eq!(
            fs::read(sentinel).expect("replayed root sentinel"),
            b"preserve on replay"
        );
    }

    let _placement = compose_core_model_placement(
        CoreModelPlacementCompositionInput {
            owner_user_id: layout.owner_user_id,
            material_root: layout.letsinfer_home.join("placement_material"),
            runtime_cache_root: runtime_cache_root.clone(),
            secret_root: layout.letsinfer_home.join("placement_secrets"),
            tls_workspace_root: layout.letsinfer_home.join("placement_tls_staging"),
            openssl_command: PathBuf::from("/usr/bin/openssl"),
            command_working_directory: layout.letsinfer_home.join("command_workspace"),
            endpoint_timeout: Duration::from_secs(1),
            maximum_hardware_age: Duration::from_secs(60),
            platform: CoreModelPlacementPlatformInput::Linux {
                docker_command: PathBuf::from("/usr/bin/docker"),
                protection_root,
                user_id: layout.owner_user_id,
                group_id: 20,
            },
        },
        Arc::new(UnavailablePlacementStore),
        Arc::new(UnavailableRuntimeExecutionManifests),
    )
    .expect("placement composition");
    private_directory_metadata(&layout.letsinfer_home.join("benchmark_isolation"));
    drop(replay);
}

// Prepares the same Node model root closure on macOS without changing replayed identities.
#[test]
fn production_setup_prepares_required_node_model_roots_on_macos() {
    let temporary = private_temporary();
    let platform = CoreUpdateServicePlatform::Macos;
    let layout = layout(temporary.path(), platform);
    let required_roots = NODE_MODEL_PRIVATE_ROOT_NAMES
        .map(|relative_root| layout.letsinfer_home.join(relative_root));
    for root in &required_roots {
        assert!(!root.exists());
    }

    let first_input = composition_input(
        CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, platform),
    )
    .expect("first macOS composition input");
    let first = ApplicationCoreSetup::compose_with_preflights(
        first_input,
        accepting_persistence(),
        accepting_watchdog_capability(),
    )
    .expect("first macOS composition");
    let first_identities = required_roots
        .iter()
        .map(|root| {
            let metadata = private_directory_metadata(root);
            (metadata.dev(), metadata.ino())
        })
        .collect::<Vec<_>>();
    let sentinels = required_roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            let sentinel = root.join(format!("existing-macos-state-{index}"));
            fs::write(&sentinel, b"preserve macOS replay").expect("macOS root sentinel");
            sentinel
        })
        .collect::<Vec<_>>();
    drop(first);

    let replay_input = composition_input(
        CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, platform),
    )
    .expect("replay macOS composition input");
    let replay = ApplicationCoreSetup::compose_with_preflights(
        replay_input,
        accepting_persistence(),
        accepting_watchdog_capability(),
    )
    .expect("replay macOS composition");
    for ((root, sentinel), (first_device, first_inode)) in
        required_roots.iter().zip(&sentinels).zip(first_identities)
    {
        let replay_metadata = private_directory_metadata(root);
        assert_eq!(replay_metadata.dev(), first_device);
        assert_eq!(replay_metadata.ino(), first_inode);
        assert_eq!(
            fs::read(sentinel).expect("replayed macOS root sentinel"),
            b"preserve macOS replay"
        );
    }
    drop(replay);
}

// Rejects a Watchdog protection root not owned directly by its state directory.
#[test]
fn composition_preflight_binds_watchdog_protection_root_to_data_directory() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let database_file = layout.material_paths.database_file().to_path_buf();
    let service_root = layout.home_directory.join(".config/systemd/user");
    let home_entries = directory_entry_count(&layout.letsinfer_home);
    let error = composition_input_with_watchdog_protection_root(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
        layout
            .material_root
            .join("watchdog/nested/protected-placements"),
    )
    .err()
    .expect("Watchdog protection-root divergence");

    assert_eq!(
        error,
        CoreSetupCompositionError::InvalidContract {
            reason: "Watchdog protection root parent does not match its data directory"
        }
    );
    assert!(!database_file.exists());
    assert!(!service_root.exists());
    assert_eq!(directory_entry_count(&layout.letsinfer_home), home_entries);
    assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
    assert_eq!(directory_entry_count(layout.configuration.directory()), 0);
}

// Rejects divergent Watchdog and Gateway telemetry before creating any native setup state.
#[test]
fn composition_preflight_binds_watchdog_metrics_to_gateway_telemetry() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let database_file = layout.material_paths.database_file().to_path_buf();
    let service_root = layout.home_directory.join(".config/systemd/user");
    let error = composition_input_with_watchdog_metrics(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
        layout
            .material_root
            .join("watchdog/divergent-gateway-metrics.json"),
    )
    .err()
    .expect("telemetry divergence");
    assert_eq!(
        error,
        CoreSetupCompositionError::InvalidContract {
            reason: "Watchdog gateway metrics do not match Gateway telemetry"
        }
    );
    assert!(!database_file.exists());
    assert!(!service_root.exists());
}

// Rejects either divergent Watchdog runtime root before creating any native setup state.
#[test]
fn composition_preflight_binds_watchdog_runtime_roots_to_node_model() {
    for (divergent_installation, reason) in [
        (
            true,
            "Watchdog runtime installation root does not match Node model",
        ),
        (
            false,
            "Watchdog runtime cache root does not match Node model",
        ),
    ] {
        let temporary = private_temporary();
        let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
        let database_file = layout.material_paths.database_file().to_path_buf();
        let service_root = layout.home_directory.join(".config/systemd/user");
        let runtime_installation_root = layout.letsinfer_home.join(if divergent_installation {
            "divergent-runtimes"
        } else {
            "runtime_installations"
        });
        let runtime_cache_root = layout.letsinfer_home.join(if divergent_installation {
            "cache"
        } else {
            "divergent-cache"
        });
        let error = composition_input_with_watchdog_runtime_roots(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            &layout,
            platform_input(&layout, CoreUpdateServicePlatform::Linux),
            runtime_installation_root,
            runtime_cache_root,
        )
        .err()
        .expect("runtime root divergence");

        assert_eq!(error, CoreSetupCompositionError::InvalidContract { reason });
        assert!(!database_file.exists());
        assert!(!service_root.exists());
        assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
        assert_eq!(directory_entry_count(layout.configuration.directory()), 0);
    }
}

// Rejects the initial child role before creating a database or native service-manager layout.
#[test]
fn composition_preflight_rejects_child_before_native_mutation() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let database_file = layout.material_paths.database_file().to_path_buf();
    let service_root = layout.home_directory.join(".config/systemd/user");
    let error = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
    )
    .err()
    .expect("child rejection");
    assert_eq!(
        error,
        CoreSetupCompositionError::InvalidContract {
            reason: "initial Core setup requires the standalone main role"
        }
    );
    assert!(!database_file.exists());
    assert!(!service_root.exists());
}

// Rejects a foreign configured owner before the database or any setup-owned file is created.
#[test]
fn production_composition_rejects_foreign_owner_before_native_mutation() {
    let temporary = private_temporary();
    let mut layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    layout.owner_user_id = layout.owner_user_id.saturating_add(1);
    layout.configuration = CoreSetupConfigurationLocation::new(
        layout.configuration.directory().to_path_buf(),
        layout.owner_user_id,
    )
    .expect("foreign configuration location");
    let database_file = layout.material_paths.database_file().to_path_buf();
    let service_root = layout.home_directory.join(".config/systemd/user");
    let input = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
    )
    .expect("composition input");
    assert!(matches!(
        ApplicationCoreSetup::compose(input),
        Err(CoreSetupCompositionError::InvalidContract {
            reason: "configured owner does not match the effective user"
        })
    ));
    assert!(!database_file.exists());
    assert!(!service_root.exists());
    assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
    assert_eq!(directory_entry_count(layout.configuration.directory()), 0);
}

// Fails an unavailable linger or GUI domain before any production provider creates state.
#[test]
fn production_composition_requires_boot_persistence_before_native_mutation() {
    for platform in [
        CoreUpdateServicePlatform::Linux,
        CoreUpdateServicePlatform::Macos,
    ] {
        let temporary = private_temporary();
        let layout = layout(temporary.path(), platform);
        let database_file = layout.material_paths.database_file().to_path_buf();
        let service_root = match platform {
            CoreUpdateServicePlatform::Linux => layout.home_directory.join(".config/systemd/user"),
            CoreUpdateServicePlatform::Macos => layout.home_directory.join("Library/LaunchAgents"),
        };
        let input = composition_input(
            CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
            &layout,
            platform_input(&layout, platform),
        )
        .expect("composition input");
        let persistence = Arc::new(TestPersistencePreflight::new(Err(
            CoreSetupCompositionError::BootPersistenceUnavailable,
        )));
        assert!(matches!(
            ApplicationCoreSetup::compose_with_preflights(
                input,
                persistence.clone(),
                accepting_watchdog_capability(),
            ),
            Err(CoreSetupCompositionError::BootPersistenceUnavailable)
        ));
        assert_eq!(persistence.invocations(), 1);
        assert!(!database_file.exists());
        assert!(!service_root.exists());
        assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
        assert_eq!(directory_entry_count(layout.configuration.directory()), 0);
    }
}

// Rejects unsupported or zero-device Linux NVML before any setup-owned path is mutated.
#[test]
fn production_composition_requires_positive_linux_watchdog_capability_before_mutation() {
    for result in [Ok(None), Ok(Some(0))] {
        let temporary = private_temporary();
        let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
        let database_file = layout.material_paths.database_file().to_path_buf();
        let service_root = layout.home_directory.join(".config/systemd/user");
        let input = composition_input(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            &layout,
            platform_input(&layout, CoreUpdateServicePlatform::Linux),
        )
        .expect("composition input");
        let capability = Arc::new(TestWatchdogCapabilityPreflight::new(result));

        assert!(matches!(
            ApplicationCoreSetup::compose_with_preflights(
                input,
                accepting_persistence(),
                capability.clone(),
            ),
            Err(CoreSetupCompositionError::WatchdogCapabilityUnavailable)
        ));
        assert_eq!(capability.invocations(), 1);
        assert!(!database_file.exists());
        assert!(!service_root.exists());
        assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
        assert_eq!(directory_entry_count(layout.configuration.directory()), 0);
    }
}

// Redacts a Linux NVML provider failure and preserves the same mutation-free boundary.
#[test]
fn production_composition_redacts_watchdog_provider_failure_before_mutation() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let database_file = layout.material_paths.database_file().to_path_buf();
    let service_root = layout.home_directory.join(".config/systemd/user");
    let input = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, CoreUpdateServicePlatform::Linux),
    )
    .expect("composition input");
    let capability = Arc::new(TestWatchdogCapabilityPreflight::new(Err(
        CoreSetupWatchdogCapabilityError::ProviderUnavailable,
    )));

    let error = match ApplicationCoreSetup::compose_with_preflights(
        input,
        accepting_persistence(),
        capability.clone(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("Watchdog provider failure must reject composition"),
    };
    assert_eq!(
        error,
        CoreSetupCompositionError::WatchdogCapabilityUnavailable
    );
    assert_eq!(
        error.to_string(),
        "Core Linux Watchdog hardware capability is unavailable"
    );
    assert_eq!(capability.invocations(), 1);
    assert!(!database_file.exists());
    assert!(!service_root.exists());
    assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
    assert_eq!(directory_entry_count(layout.configuration.directory()), 0);
}

// Rejects every unsafe Node model private root before database or service-state mutation.
#[test]
fn production_composition_rejects_unsafe_node_model_roots_before_database_mutation() {
    for relative_root in NODE_MODEL_PRIVATE_ROOT_NAMES {
        let temporary = private_temporary();
        let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
        let database_file = layout.material_paths.database_file().to_path_buf();
        let private_root = layout.letsinfer_home.join(relative_root);
        let redirected = layout
            .home_directory
            .join(format!("redirected-{relative_root}"));
        create_private_directory(&redirected);
        symlink(&redirected, &private_root).expect("private root symlink");
        let service_root = layout.home_directory.join(".config/systemd/user");
        let input = composition_input(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            &layout,
            platform_input(&layout, CoreUpdateServicePlatform::Linux),
        )
        .expect("composition input");

        assert!(matches!(
            ApplicationCoreSetup::compose_with_preflights(
                input,
                accepting_persistence(),
                accepting_watchdog_capability(),
            ),
            Err(CoreSetupCompositionError::ResidentServicesUnavailable)
        ));
        assert!(!database_file.exists());
        assert!(!service_root.exists());
        assert_eq!(directory_entry_count(&layout.setup_state_directory), 0);
        assert!(fs::symlink_metadata(private_root)
            .expect("private root metadata")
            .file_type()
            .is_symlink());
        for sibling in NODE_MODEL_PRIVATE_ROOT_NAMES {
            if sibling != relative_root {
                assert!(!layout.letsinfer_home.join(sibling).exists());
            }
        }
    }
}

// Rejects native platform substitution and an escaped database path before provider construction.
#[test]
fn composition_preflight_binds_platform_and_material_root_exactly() {
    let temporary = private_temporary();
    let linux = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let macos_native = CoreSetupPlatformInput::macos(
        PathBuf::from("/usr/sbin/ioreg"),
        Duration::from_secs(5),
        Duration::from_millis(10),
    )
    .expect("macOS native input");
    let mismatch = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &linux,
        macos_native,
    )
    .err()
    .expect("platform mismatch");
    assert_eq!(
        mismatch,
        CoreSetupCompositionError::InvalidContract {
            reason: "native setup input does not match the selected platform"
        }
    );

    let mismatched_health = CoreSetupPlatformInput::linux(
        PathBuf::from("/etc/machine-id"),
        CoreSetupWatchdogHealthInput::new(
            linux.material_root.join("trust/other-watchdog-ca.crt"),
            linux.material_root.join("trust/watchdog-controller.crt"),
            linux.material_root.join("trust/watchdog-controller.key"),
        )
        .expect("mismatched health paths"),
    )
    .expect("Linux native input");
    let error = composition_input(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        &linux,
        mismatched_health,
    )
    .err()
    .expect("health mismatch rejection");
    assert_eq!(
        error,
        CoreSetupCompositionError::InvalidContract {
            reason: "Watchdog health material does not match generated trust"
        }
    );
    assert!(!linux.material_paths.database_file().exists());
}

// Rejects every caller-selected Linux identity path outside the trusted system source.
#[test]
fn linux_platform_input_requires_the_exact_system_machine_identity_file() {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), CoreUpdateServicePlatform::Linux);
    let error = CoreSetupPlatformInput::linux(
        layout.material_root.join("machine-id"),
        CoreSetupWatchdogHealthInput::new(
            layout.material_root.join("trust/watchdog-ca.crt"),
            layout.material_root.join("trust/watchdog-controller.crt"),
            layout.material_root.join("trust/watchdog-controller.key"),
        )
        .expect("Watchdog health paths"),
    )
    .expect_err("alternate machine identity path");
    assert_eq!(
        error,
        CoreSetupCompositionError::InvalidContract {
            reason: "Linux machine identity path is invalid"
        }
    );
}

// Rejects every one of the 19 macOS and 26 Linux material roles when it escapes the root.
#[test]
fn composition_preflight_rejects_every_escaped_material_role() {
    for (platform, expected_paths) in [
        (CoreUpdateServicePlatform::Macos, 19_usize),
        (CoreUpdateServicePlatform::Linux, 26_usize),
    ] {
        let temporary = private_temporary();
        let mut layout = layout(temporary.path(), platform);
        assert_eq!(layout.material_paths.all_paths().len(), expected_paths);
        for escape_index in 0..expected_paths {
            layout.material_paths =
                material_paths_with_escape(&layout.material_root, platform, Some(escape_index));
            let error = composition_input(
                CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
                &layout,
                platform_input(&layout, platform),
            )
            .err()
            .expect("escaped material rejection");
            assert_eq!(
                error,
                CoreSetupCompositionError::InvalidContract {
                    reason: "private material path is outside its explicit root"
                },
                "material path {escape_index} on {platform:?}"
            );
        }
    }
}

// Rejects every pairwise ancestor overlap across independently owned mutable roots.
#[test]
fn composition_roots_reject_every_independent_ancestor_overlap() {
    let temporary = private_temporary();
    let root = temporary.path().canonicalize().expect("canonical root");
    let owner_user_id = unsafe { libc::geteuid() };
    for left in 0..4 {
        for right in (left + 1)..4 {
            for descendant_is_right in [true, false] {
                let mut values = [
                    root.join("setup"),
                    root.join("material"),
                    root.join("workspace"),
                    root.join("configuration"),
                ];
                if descendant_is_right {
                    values[right] = values[left].join("nested");
                } else {
                    values[left] = values[right].join("nested");
                }
                let configuration =
                    CoreSetupConfigurationLocation::new(values[3].clone(), owner_user_id)
                        .expect("configuration location");
                assert_eq!(
                    CoreSetupCompositionRoots::new(
                        root.join("letsinfer"),
                        root.join("home"),
                        values[0].clone(),
                        values[1].clone(),
                        values[2].clone(),
                        configuration,
                    ),
                    Err(CoreSetupCompositionError::InvalidContract {
                        reason: "Core setup roots are ambiguous"
                    }),
                    "overlap pair {left}/{right}, descendant_is_right={descendant_is_right}"
                );
            }
        }
    }
}

// Prevents request platform or role substitution before the durable transaction is entered.
#[test]
fn application_preflight_binds_the_exact_composed_context() {
    let transaction = Arc::new(TestSetupTransaction::new(Vec::new()));
    let application = ApplicationCoreSetup::with_transaction(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        unsafe { libc::geteuid() },
        accepting_persistence(),
        accepting_watchdog_capability(),
        transaction.clone(),
    )
    .expect("application");
    for request in [
        request(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child),
        request(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
    ] {
        assert_eq!(
            application.setup(&request),
            Err(CoreSetupCompositionError::InvalidContract {
                reason: "setup request does not match the composed standalone main"
            })
        );
    }
    assert_eq!(transaction.invocations(), 0);
}

// Preserves installed and replayed status through the exact newline-terminated JSON boundary.
#[test]
fn application_json_preserves_installed_and_replayed_results() {
    let transaction = Arc::new(TestSetupTransaction::new(vec![
        Ok(result("installed", CoreUpdateServicePlatform::Linux)),
        Ok(result("replayed", CoreUpdateServicePlatform::Linux)),
    ]));
    let watchdog_capability = Arc::new(TestWatchdogCapabilityPreflight::new(Ok(Some(1))));
    let application = ApplicationCoreSetup::with_transaction(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        unsafe { libc::geteuid() },
        accepting_persistence(),
        watchdog_capability.clone(),
        transaction.clone(),
    )
    .expect("application");
    let request = request(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    for expected in ["installed", "replayed"] {
        let bytes = application.setup_json(&request).expect("JSON result");
        assert_eq!(bytes.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["schema"]["name"], "li_core_setup_result");
        assert_eq!(value["schema"]["version"], 1);
        assert_eq!(value["status"], expected);
        assert_eq!(
            value["services"],
            serde_json::json!(["li_node", "li_watchdog", "li_gateway"])
        );
    }
    assert_eq!(watchdog_capability.invocations(), 2);
    assert_eq!(transaction.invocations(), 2);
}

// Maps orchestration failures exactly while keeping native paths and secret-shaped values absent.
#[test]
fn application_error_mapping_is_exact_and_redacted() {
    let setup_error = li_core_application::CoreSetupError::Provider {
        capability: "resident services",
        reason: "service readiness is unavailable",
    };
    let transaction = Arc::new(TestSetupTransaction::new(vec![Err(setup_error.clone())]));
    let application = ApplicationCoreSetup::with_transaction(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        unsafe { libc::geteuid() },
        accepting_persistence(),
        accepting_watchdog_capability(),
        transaction,
    )
    .expect("application");
    let error = application
        .setup(&request(
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
        ))
        .expect_err("setup failure");
    assert_eq!(error, CoreSetupCompositionError::Setup(setup_error));
    let message = error.to_string();
    assert!(message.contains("resident services"));
    assert!(!message.contains("/private/"));
    assert!(!message.contains("super-secret"));
}

// Prevents an unavailable persistence domain from entering an already-composed transaction.
#[test]
fn application_rechecks_boot_persistence_before_the_transaction() {
    let transaction = Arc::new(TestSetupTransaction::new(Vec::new()));
    let persistence = Arc::new(TestPersistencePreflight::new(Err(
        CoreSetupCompositionError::BootPersistenceUnavailable,
    )));
    let application = ApplicationCoreSetup::with_transaction(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        unsafe { libc::geteuid() },
        persistence.clone(),
        accepting_watchdog_capability(),
        transaction.clone(),
    )
    .expect("application");
    assert_eq!(
        application.setup(&request(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        )),
        Err(CoreSetupCompositionError::BootPersistenceUnavailable)
    );
    assert_eq!(persistence.invocations(), 1);
    assert_eq!(transaction.invocations(), 0);
}

// Rechecks Linux NVML immediately before setup and never enters a stale-capability transaction.
#[test]
fn application_rechecks_watchdog_capability_before_the_transaction() {
    let transaction = Arc::new(TestSetupTransaction::new(Vec::new()));
    let capability = Arc::new(TestWatchdogCapabilityPreflight::new(Ok(None)));
    let application = ApplicationCoreSetup::with_transaction(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        unsafe { libc::geteuid() },
        accepting_persistence(),
        capability.clone(),
        transaction.clone(),
    )
    .expect("application");

    assert_eq!(
        application.setup(&request(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        )),
        Err(CoreSetupCompositionError::WatchdogCapabilityUnavailable)
    );
    assert_eq!(capability.invocations(), 1);
    assert_eq!(transaction.invocations(), 0);
}

// Keeps macOS free of a synthetic Watchdog requirement at both application boundaries.
#[test]
fn application_bypasses_watchdog_capability_on_macos() {
    let transaction = Arc::new(TestSetupTransaction::new(vec![Ok(result(
        "installed",
        CoreUpdateServicePlatform::Macos,
    ))]));
    let capability = Arc::new(TestWatchdogCapabilityPreflight::new(Err(
        CoreSetupWatchdogCapabilityError::ProviderUnavailable,
    )));
    let application = ApplicationCoreSetup::with_transaction(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        unsafe { libc::geteuid() },
        accepting_persistence(),
        capability.clone(),
        transaction.clone(),
    )
    .expect("application");

    application
        .setup(&request(
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
        ))
        .expect("macOS setup");
    assert_eq!(capability.invocations(), 0);
    assert_eq!(transaction.invocations(), 1);
}

// Holds explicit test paths before constructing the production input value.
struct TestLayout {
    owner_user_id: u32,
    letsinfer_home: PathBuf,
    home_directory: PathBuf,
    setup_state_directory: PathBuf,
    material_root: PathBuf,
    trust_workspace_root: PathBuf,
    configuration: CoreSetupConfigurationLocation,
    material_paths: CoreSetupMaterialPaths,
}

// Creates one complete production fixture for a selected supported platform.
fn production_fixture(platform: CoreUpdateServicePlatform) -> ProductionFixture {
    let temporary = private_temporary();
    let layout = layout(temporary.path(), platform);
    let input = composition_input(
        CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
        &layout,
        platform_input(&layout, platform),
    )
    .expect("composition input");
    ProductionFixture {
        _temporary: temporary,
        gateway_telemetry_directory: layout.material_root.join("gateway"),
        input,
    }
}

// Creates all installer-owned roots without creating any Core setup output.
fn layout(root: &Path, platform: CoreUpdateServicePlatform) -> TestLayout {
    let root = root.canonicalize().expect("canonical temporary root");
    let owner_user_id = unsafe { libc::geteuid() };
    let home_directory = root.join("home");
    let letsinfer_home = home_directory.join(".letsinfer");
    let setup_state_directory = letsinfer_home.join("state/setup");
    let state_directory = letsinfer_home.join("state");
    let material_root = letsinfer_home.join("private");
    let trust_workspace_root = letsinfer_home.join("trust_workspace");
    let configuration_directory = letsinfer_home.join("configuration");
    for directory in [
        &home_directory,
        &letsinfer_home,
        &state_directory,
        &setup_state_directory,
        &material_root,
        &configuration_directory,
    ] {
        create_private_directory(directory);
    }
    let configuration = CoreSetupConfigurationLocation::new(configuration_directory, owner_user_id)
        .expect("configuration location");
    TestLayout {
        owner_user_id,
        letsinfer_home,
        home_directory,
        setup_state_directory,
        material_paths: material_paths_with_escape(&material_root, platform, None),
        material_root,
        trust_workspace_root,
        configuration,
    }
}

// Creates the complete immutable composition input from one explicit test layout.
fn composition_input(
    context: CoreUpdateServiceContext,
    layout: &TestLayout,
    platform: CoreSetupPlatformInput,
) -> Result<CoreSetupCompositionInput, CoreSetupCompositionError> {
    composition_input_with_watchdog_bindings(
        context,
        layout,
        platform,
        layout.material_root.join("gateway/telemetry.json"),
        layout.letsinfer_home.join("runtime_installations"),
        layout.letsinfer_home.join("cache"),
        layout.material_root.join("watchdog/protected-placements"),
    )
}

// Creates one composition input with an explicit Watchdog view of Gateway telemetry.
fn composition_input_with_watchdog_metrics(
    context: CoreUpdateServiceContext,
    layout: &TestLayout,
    platform: CoreSetupPlatformInput,
    watchdog_gateway_metrics_path: PathBuf,
) -> Result<CoreSetupCompositionInput, CoreSetupCompositionError> {
    composition_input_with_watchdog_bindings(
        context,
        layout,
        platform,
        watchdog_gateway_metrics_path,
        layout.letsinfer_home.join("runtime_installations"),
        layout.letsinfer_home.join("cache"),
        layout.material_root.join("watchdog/protected-placements"),
    )
}

// Creates one composition input with explicit Watchdog views of Node runtime storage.
fn composition_input_with_watchdog_runtime_roots(
    context: CoreUpdateServiceContext,
    layout: &TestLayout,
    platform: CoreSetupPlatformInput,
    runtime_installation_root: PathBuf,
    runtime_cache_root: PathBuf,
) -> Result<CoreSetupCompositionInput, CoreSetupCompositionError> {
    composition_input_with_watchdog_bindings(
        context,
        layout,
        platform,
        layout.material_root.join("gateway/telemetry.json"),
        runtime_installation_root,
        runtime_cache_root,
        layout.material_root.join("watchdog/protected-placements"),
    )
}

// Creates one composition input with an explicit Watchdog placement-protection root.
fn composition_input_with_watchdog_protection_root(
    context: CoreUpdateServiceContext,
    layout: &TestLayout,
    platform: CoreSetupPlatformInput,
    watchdog_protection_root: PathBuf,
) -> Result<CoreSetupCompositionInput, CoreSetupCompositionError> {
    composition_input_with_watchdog_bindings(
        context,
        layout,
        platform,
        layout.material_root.join("gateway/telemetry.json"),
        layout.letsinfer_home.join("runtime_installations"),
        layout.letsinfer_home.join("cache"),
        watchdog_protection_root,
    )
}

// Creates one composition input with every Watchdog cross-process path supplied explicitly.
fn composition_input_with_watchdog_bindings(
    context: CoreUpdateServiceContext,
    layout: &TestLayout,
    platform: CoreSetupPlatformInput,
    watchdog_gateway_metrics_path: PathBuf,
    runtime_installation_root: PathBuf,
    runtime_cache_root: PathBuf,
    watchdog_protection_root: PathBuf,
) -> Result<CoreSetupCompositionInput, CoreSetupCompositionError> {
    CoreSetupCompositionInput::new(
        context,
        layout.owner_user_id,
        CoreSetupCompositionRoots::new(
            layout.letsinfer_home.clone(),
            layout.home_directory.clone(),
            layout.setup_state_directory.clone(),
            layout.material_root.clone(),
            layout.trust_workspace_root.clone(),
            layout.configuration.clone(),
        )?,
        layout.material_paths.clone(),
        digest('9'),
        CoreSetupCliConfigurationTemplate::new(
            PathBuf::from("/dev/urandom"),
            PathBuf::from("/usr/local/bin/letsinfer"),
            Some(PathBuf::from("/usr/bin/sudo")),
            5_000,
            1_048_576,
        ),
        node_template(context.platform(), layout),
        gateway_template(&layout.material_root),
        watchdog_template_with_protection_root(
            context.platform(),
            &layout.material_root,
            watchdog_gateway_metrics_path,
            runtime_installation_root,
            runtime_cache_root,
            watchdog_protection_root,
        ),
        PathBuf::from("/usr/bin/openssl"),
        platform,
    )
}

// Creates one native platform input bound to the same explicit material paths.
fn platform_input(
    layout: &TestLayout,
    platform: CoreUpdateServicePlatform,
) -> CoreSetupPlatformInput {
    match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupPlatformInput::linux(
            PathBuf::from("/etc/machine-id"),
            CoreSetupWatchdogHealthInput::new(
                layout.material_root.join("trust/watchdog-ca.crt"),
                layout.material_root.join("trust/watchdog-controller.crt"),
                layout.material_root.join("trust/watchdog-controller.key"),
            )
            .expect("Watchdog health paths"),
        )
        .expect("Linux platform input"),
        CoreUpdateServicePlatform::Macos => CoreSetupPlatformInput::macos(
            PathBuf::from("/usr/sbin/ioreg"),
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .expect("macOS platform input"),
    }
}

// Creates one complete private-material destination closure beneath an explicit root.
fn material_paths_with_escape(
    material_root: &Path,
    platform: CoreUpdateServicePlatform,
    escape_index: Option<usize>,
) -> CoreSetupMaterialPaths {
    let selected_path = |index: usize, relative: &str| {
        if escape_index == Some(index) {
            material_root
                .parent()
                .expect("material parent")
                .join("escaped")
                .join(relative)
        } else {
            material_root.join(relative)
        }
    };
    CoreSetupMaterialPaths::new(
        selected_path(0, "state/core.sqlite3"),
        selected_path(1, "trust/pairing.key"),
        selected_path(2, "trust/api.key"),
        CoreSetupPairingTrustPaths::new(
            selected_path(3, "trust/site.key"),
            selected_path(4, "trust/site.pub"),
            selected_path(5, "trust/site-ca.crt"),
            selected_path(6, "trust/node.crt"),
        ),
        CoreSetupNodeTrustPaths::new(
            selected_path(7, "trust/node-ca.key"),
            selected_path(8, "trust/node-ca.crt"),
            selected_path(9, "trust/node-server.crt"),
            selected_path(10, "trust/node-server.key"),
            selected_path(11, "trust/node-client.crt"),
            selected_path(12, "trust/node-client.key"),
        ),
        CoreSetupGatewayTrustPaths::new(
            selected_path(13, "trust/gateway-ca.key"),
            selected_path(14, "trust/gateway-ca.crt"),
            selected_path(15, "trust/gateway-server.crt"),
            selected_path(16, "trust/gateway-server.key"),
            selected_path(17, "trust/gateway-client.crt"),
            selected_path(18, "trust/gateway-client.key"),
        ),
        (platform == CoreUpdateServicePlatform::Linux).then(|| {
            CoreSetupWatchdogTrustPaths::new(
                selected_path(19, "trust/watchdog-ca.key"),
                selected_path(20, "trust/watchdog-ca.crt"),
                selected_path(21, "trust/watchdog-server.crt"),
                selected_path(22, "trust/watchdog-server.key"),
                selected_path(23, "trust/watchdog-controller.crt"),
                selected_path(24, "trust/watchdog-controller.key"),
                selected_path(25, "trust/watchdog-controllers.allow"),
            )
        }),
    )
    .expect("material paths")
}

// Creates one complete platform-exact Node configuration template.
fn node_template(
    platform: CoreUpdateServicePlatform,
    layout: &TestLayout,
) -> CoreSetupNodeConfigurationTemplate {
    let root = &layout.letsinfer_home;
    let state = root.join("state");
    let hardware = match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupNodeHardwareInput::Linux {
            architecture: CpuArchitecture::X86_64,
            boot_id_file: PathBuf::from("/proc/sys/kernel/random/boot_id"),
            cpu_information_file: PathBuf::from("/proc/cpuinfo"),
            memory_information_file: PathBuf::from("/proc/meminfo"),
            nvidia_smi_command: Some(PathBuf::from("/usr/bin/nvidia-smi")),
            rdma_command: Some(PathBuf::from("/usr/bin/rdma")),
        },
        CoreUpdateServicePlatform::Macos => CoreSetupNodeHardwareInput::MacosArm64 {
            sysctl_command: PathBuf::from("/usr/sbin/sysctl"),
            metal_probe_command: PathBuf::from("/opt/letsinfer/bin/li_hardware_macos_probe"),
        },
    };
    let pairing = match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupNodePairingPlatformInput::Linux {
            discovery_command: PathBuf::from("/usr/bin/avahi-publish-service"),
            direct_link_sys_class: PathBuf::from("/sys/class"),
            direct_link_ip_command: PathBuf::from("/usr/sbin/ip"),
        },
        CoreUpdateServicePlatform::Macos => CoreSetupNodePairingPlatformInput::Macos {
            discovery_command: PathBuf::from("/usr/bin/dns-sd"),
        },
    };
    let placement_safety = match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupNodePlacementSafetyTemplate::Linux {
            maximum_workers: 8,
            read_timeout_milliseconds: 1_000,
            write_timeout_milliseconds: 1_000,
            accept_poll_interval_milliseconds: 50,
            gateway: protection_executable("li_gateway", '4', '5'),
            watchdog: protection_executable("li_watchdog", '6', '7'),
            lease_milliseconds: 3_000,
        },
        CoreUpdateServicePlatform::Macos => CoreSetupNodePlacementSafetyTemplate::MacosLaunchd,
    };
    CoreSetupNodeConfigurationTemplate::new(
        CoreSetupNodeUpdateInput {
            release_platform: match platform {
                CoreUpdateServicePlatform::Linux => "linux_x86_64",
                CoreUpdateServicePlatform::Macos => "macos_arm64",
            }
            .to_string(),
            letsinfer_home: layout.letsinfer_home.clone(),
            home_directory: layout.home_directory.clone(),
            setup_state_directory: layout.setup_state_directory.clone(),
            configuration_root: layout.configuration.directory().to_path_buf(),
            curl_command: PathBuf::from("/usr/bin/curl"),
            ssh_keygen_command: PathBuf::from("/usr/bin/ssh-keygen"),
            allowed_signers_file: layout.letsinfer_home.join("trust/release-allowed-signers"),
            supervisor_command: match platform {
                CoreUpdateServicePlatform::Linux => PathBuf::from("/usr/bin/systemctl"),
                CoreUpdateServicePlatform::Macos => PathBuf::from("/bin/launchctl"),
            },
            readiness_timeout_milliseconds: 30_000,
            readiness_poll_milliseconds: 100,
            stable_readiness_observations: 2,
        },
        model_input(platform, root),
        (platform == CoreUpdateServicePlatform::Linux).then(|| {
            CoreSetupNodeBenchmarkTemplate::new(
                root.join("bin/li_benchmark_worker"),
                PathBuf::from("/usr/bin/gh"),
                root.join("benchmark_tasks"),
                root.join("benchmark_telemetry"),
                root.join("benchmark_evidence"),
                root.join("benchmark_signing"),
                60_000,
                5_000,
                5_000,
            )
        }),
        hardware,
        pairing,
        PathBuf::from("/usr/bin/openssl"),
        root.join("private/pairing_workspace"),
        1_000,
        CoreSetupNodeLocalApiInput::new(state.join("node.sock"), 8, 5_000, 5_000, 100),
        placement_safety,
        16,
        100,
        5_000,
        5_000,
        5_000,
    )
}

// Creates one deterministic immutable service executable identity.
fn protection_executable(
    name: &str,
    digest_character: char,
    principal_character: char,
) -> CoreSetupNodeProtectionExecutableInput {
    CoreSetupNodeProtectionExecutableInput::new(
        PathBuf::from(format!("/opt/letsinfer/bin/{name}")),
        Sha256Digest::parse(&digest_character.to_string().repeat(64)).expect("digest"),
        CredentialId::parse(&principal_character.to_string().repeat(32)).expect("principal"),
    )
}

// Creates one Gateway template whose durable state is accessed through the local Node API.
fn gateway_template(material_root: &Path) -> CoreSetupGatewayConfigurationTemplate {
    let installation_root = material_root.parent().expect("installation root");
    let state = installation_root.join("state");
    CoreSetupGatewayConfigurationTemplate::new(
        CoreSetupGatewayHealthInput::new(state.join("gateway_health.sock"), 8, 1_000, 1_000, 10),
        CoreSetupGatewayProtectionInput::new(
            state.join("node_protection.sock"),
            1_000,
            1_000,
            3_000,
            1_000,
        ),
        material_root.join("gateway/telemetry.json"),
        1_000,
        30_000,
        64,
        32,
    )
}

// Creates one Linux Watchdog template with an explicit protection-root binding.
fn watchdog_template_with_protection_root(
    platform: CoreUpdateServicePlatform,
    material_root: &Path,
    gateway_metrics_path: PathBuf,
    runtime_installation_root: PathBuf,
    runtime_cache_root: PathBuf,
    protection_root_path: PathBuf,
) -> Option<CoreSetupWatchdogConfigurationTemplate> {
    (platform == CoreUpdateServicePlatform::Linux).then(|| {
        let watchdog_root = material_root.join("watchdog");
        CoreSetupWatchdogConfigurationTemplate::new(
            watchdog_root.clone(),
            watchdog_root.join("controller-snapshot.json"),
            watchdog_root.join("site-state.json"),
            gateway_metrics_path,
            protection_root_path,
            runtime_installation_root,
            runtime_cache_root,
            5_000,
            8,
            WatchdogSafetyThresholds::new(
                3_000_000_000,
                2_000_000_000,
                1_000_000_000,
                1_000_000,
                100_000,
                10_000,
                3,
                5_000,
            )
            .expect("Watchdog thresholds"),
        )
    })
}

// Creates one exact standalone-main setup request for a selected platform.
fn request(platform: CoreUpdateServicePlatform, role: CoreUpdateNodeRole) -> CoreSetupRequest {
    CoreSetupRequest::new(
        digest('1'),
        CoreUpdateServiceContext::new(platform, role),
        CoreInstallation::new(CoreVersion::parse("1.0.0").expect("version"), digest('2')),
        DisplayName::parse("Home AI").expect("display name"),
        NodeAddress::parse("homeai.local").expect("Node address"),
        CoreSetupNetworkPlan::new(
            SocketAddr::from(([127, 0, 0, 1], 9_443)),
            SocketAddr::from(([127, 0, 0, 1], 9_444)),
            (role == CoreUpdateNodeRole::Main).then(|| SocketAddr::from(([0, 0, 0, 0], 8_080))),
            (platform == CoreUpdateServicePlatform::Linux)
                .then(|| SocketAddr::from(([127, 0, 0, 1], 9_445))),
        ),
    )
}

// Decodes one exact final setup result through the production result codec.
fn result(status: &str, platform: CoreUpdateServicePlatform) -> CoreSetupResult {
    let services = match platform {
        CoreUpdateServicePlatform::Linux => {
            serde_json::json!(["li_node", "li_watchdog", "li_gateway"])
        }
        CoreUpdateServicePlatform::Macos => serde_json::json!(["li_node", "li_gateway"]),
    };
    let document = serde_json::json!({
        "schema": {"name": "li_core_setup_result", "version": 1},
        "status": status,
        "node_id": "3".repeat(32),
        "machine_id": "4".repeat(32),
        "installation_id": "2".repeat(64),
        "display_name": "Home AI",
        "role": "main",
        "control_address": "homeai.local",
        "api_key_file": "/private/api.key",
        "inference_endpoint": "http://homeai.local:8080",
        "services": services
    });
    CoreSetupResult::decoded_json(&serde_json::to_vec(&document).expect("result JSON"))
        .expect("setup result")
}

// Returns one repeated lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one private temporary root with explicit owner-only mode.
fn private_temporary() -> TempDir {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("temporary permissions");
    temporary
}

// Creates one owner-only directory chain used as an explicit installer input.
fn create_private_directory(path: &Path) {
    fs::create_dir_all(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("private directory permissions");
}

// Returns metadata only after proving one setup-owned private directory contract.
fn private_directory_metadata(path: &Path) -> fs::Metadata {
    let metadata = fs::symlink_metadata(path).expect("private directory metadata");
    assert!(metadata.file_type().is_dir());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    metadata
}

// Builds one expected bounded native persistence invocation.
fn native_command(executable: &str, arguments: &[&str]) -> TestNativeCommand {
    TestNativeCommand {
        executable: PathBuf::from(executable),
        arguments: arguments.iter().map(|value| (*value).to_string()).collect(),
        timeout: Duration::from_secs(5),
        maximum_output_bytes: 64 * 1024,
    }
}

// Returns the exact number of entries in one test-owned pre-existing directory.
fn directory_entry_count(path: &Path) -> usize {
    fs::read_dir(path)
        .expect("directory entries")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entry")
        .len()
}

// Creates one accepting deterministic persistence capability for non-native tests.
fn accepting_persistence() -> Arc<dyn CoreSetupPersistencePreflight> {
    Arc::new(TestPersistencePreflight::new(Ok(())))
}

// Creates one deterministic positive Linux Watchdog capability for non-native tests.
fn accepting_watchdog_capability() -> Arc<dyn CoreSetupWatchdogCapabilityPreflight> {
    Arc::new(TestWatchdogCapabilityPreflight::new(Ok(Some(1))))
}
