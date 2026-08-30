// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::fs::hard_link;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use li_core_application::{
    ApplicationCoreSetupConfigurationInputProvider, ApplicationCoreSetupConfigurationProvider,
    CoreSetupCliConfigurationTemplate, CoreSetupCliInput, CoreSetupConfigurationBinding,
    CoreSetupConfigurationError, CoreSetupConfigurationFile, CoreSetupConfigurationInput,
    CoreSetupConfigurationInputProvider, CoreSetupConfigurationInstallStatus,
    CoreSetupConfigurationInstaller, CoreSetupConfigurationIo, CoreSetupConfigurationLocation,
    CoreSetupConfigurationLock, CoreSetupConfigurationProvider,
    CoreSetupGatewayConfigurationTemplate, CoreSetupGatewayHealthInput, CoreSetupGatewayInput,
    CoreSetupGatewayListenerInput, CoreSetupGatewayPrivateListenerInput,
    CoreSetupGatewayProtectionInput, CoreSetupNodeBenchmarkInput, CoreSetupNodeBenchmarkTemplate,
    CoreSetupNodeConfigurationTemplate, CoreSetupNodeHardwareInput, CoreSetupNodeInput,
    CoreSetupNodeLocalApiInput, CoreSetupNodeModelInput, CoreSetupNodePairingInput,
    CoreSetupNodePairingPlatformInput, CoreSetupNodePlacementSafetyInput,
    CoreSetupNodePlacementSafetyTemplate, CoreSetupNodeProtectionExecutableInput,
    CoreSetupNodeRemoteApiInput, CoreSetupNodeUpdateInput, CoreSetupPreparedIdentity,
    CoreSetupPreparedMaterial, CoreSetupProviderError, CoreSetupReceipt, CoreSetupRequest,
    CoreSetupWatchdogConfigurationTemplate, CoreSetupWatchdogInput, CoreSetupWatchdogPathsInput,
    CoreSetupWatchdogProtectionInput, SystemCoreSetupConfigurationIo,
    CORE_CLI_CONFIGURATION_FILENAME, GATEWAY_CONFIGURATION_FILENAME, NODE_CONFIGURATION_FILENAME,
    WATCHDOG_CONFIGURATION_FILENAME,
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
        runtime_cache_root: root.join("runtime_cache"),
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

// Creates one complete Linux benchmark contract or explicit macOS absence.
fn benchmark_input(
    platform: CoreUpdateServicePlatform,
    state: &Path,
    trust: &Path,
) -> Option<CoreSetupNodeBenchmarkInput> {
    (platform == CoreUpdateServicePlatform::Linux).then(|| {
        CoreSetupNodeBenchmarkInput::new(
            PathBuf::from("/opt/letsinfer/bin/li_benchmark_worker"),
            PathBuf::from("/usr/bin/gh"),
            state.join("benchmark_tasks"),
            state.join("benchmark_telemetry"),
            state.join("benchmark_evidence"),
            state.join("benchmark_signing"),
            trust.join("benchmark-signing.key"),
            trust.join("benchmark-signing.pub"),
            604_800_000,
            30_000,
            "127.0.0.1".to_owned(),
            9_445,
            "127.0.0.1".to_owned(),
            trust.join("watchdog_controllers_ca.pem"),
            trust.join("watchdog-ca.key"),
            state.join("watchdog_controllers.json"),
            state.join("watchdog_controller_snapshot.json"),
            trust.join("watchdog_server.pem"),
            trust.join("watchdog_server.key"),
            trust.join("watchdog-controller.crt"),
            trust.join("watchdog-controller.key"),
            5_000,
        )
    })
}

// Creates one Linux benchmark template or explicit macOS absence.
fn benchmark_template(
    platform: CoreUpdateServicePlatform,
    state: &Path,
) -> Option<CoreSetupNodeBenchmarkTemplate> {
    (platform == CoreUpdateServicePlatform::Linux).then(|| {
        CoreSetupNodeBenchmarkTemplate::new(
            PathBuf::from("/opt/letsinfer/bin/li_benchmark_worker"),
            PathBuf::from("/usr/bin/gh"),
            state.join("benchmark_tasks"),
            state.join("benchmark_telemetry"),
            state.join("benchmark_evidence"),
            state.join("benchmark_signing"),
            604_800_000,
            30_000,
            5_000,
        )
    })
}

// Creates one exact signed Core-update composition fixture for generated Node configuration.
fn update_input(
    platform: CoreUpdateServicePlatform,
    configuration_root: &Path,
) -> CoreSetupNodeUpdateInput {
    CoreSetupNodeUpdateInput {
        release_platform: match platform {
            CoreUpdateServicePlatform::Linux => "linux_x86_64",
            CoreUpdateServicePlatform::Macos => "macos_arm64",
        }
        .to_string(),
        letsinfer_home: PathBuf::from("/var/lib/letsinfer"),
        home_directory: match platform {
            CoreUpdateServicePlatform::Linux => PathBuf::from("/home/test"),
            CoreUpdateServicePlatform::Macos => PathBuf::from("/Users/test"),
        },
        setup_state_directory: PathBuf::from("/var/lib/letsinfer/setup"),
        configuration_root: configuration_root.to_path_buf(),
        curl_command: PathBuf::from("/usr/bin/curl"),
        ssh_keygen_command: PathBuf::from("/usr/bin/ssh-keygen"),
        allowed_signers_file: PathBuf::from("/var/lib/letsinfer/trust/release-allowed-signers"),
        supervisor_command: match platform {
            CoreUpdateServicePlatform::Linux => PathBuf::from("/usr/bin/systemctl"),
            CoreUpdateServicePlatform::Macos => PathBuf::from("/bin/launchctl"),
        },
        readiness_timeout_milliseconds: 30_000,
        readiness_poll_milliseconds: 100,
        stable_readiness_observations: 2,
    }
}
use li_core_interface::{
    CpuArchitecture, CredentialId, DisplayName, InstallationId, MachineId, NodeAddress, NodeId,
    NodeRole, Sha256Digest,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode, GatewayNativeFile,
    GatewayNativeFileIo, GatewayNativeIoError,
};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference, NodeHardwareConfiguration,
    NodePairingPlatform,
};
use li_watchdog_manager::{WatchdogConfiguration, WatchdogSafetyThresholds};

// Selects one deterministic failure immediately before or after a visibility boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationFailure {
    ActivationBefore(usize),
    ActivationAfter(usize),
    ActivationCollision(usize),
    SyncBefore(usize),
    SyncAfter(usize),
    RemovalBefore(usize),
    RemovalAfter(usize),
}

// Stores one injected configuration-file observation.
#[derive(Clone)]
struct TestFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    is_stable: bool,
    bytes: Vec<u8>,
}

impl TestFile {
    // Creates one exact safe setup-owned file.
    fn safe(owner_user_id: u32, bytes: Vec<u8>) -> Self {
        Self {
            owner_user_id,
            mode: 0o600,
            link_count: 1,
            is_regular_file: true,
            is_stable: true,
            bytes,
        }
    }

    // Projects the injected file through the production observation contract.
    fn observation(&self) -> CoreSetupConfigurationFile {
        CoreSetupConfigurationFile::new(
            self.owner_user_id,
            self.mode,
            self.link_count,
            self.is_regular_file,
            self.is_stable,
            self.bytes.clone(),
        )
    }
}

// Stores the deterministic native boundary state shared by one test installer.
#[derive(Default)]
struct TestIoState {
    files: BTreeMap<PathBuf, TestFile>,
    failure: Option<PublicationFailure>,
    mutations: usize,
    syncs: usize,
    locks: usize,
    activations: usize,
    removals: usize,
}

// Injects exact filesystem observations and ambiguous publication boundaries.
#[derive(Default)]
struct TestIo {
    state: Mutex<TestIoState>,
}

impl TestIo {
    // Selects one single-use publication failure.
    fn fail_once(&self, failure: PublicationFailure) {
        self.state.lock().expect("state").failure = Some(failure);
    }

    // Returns one exact stored file when present.
    fn file(&self, path: &Path) -> Option<TestFile> {
        self.state.lock().expect("state").files.get(path).cloned()
    }

    // Inserts one injected file without counting setup mutation.
    fn insert(&self, path: PathBuf, file: TestFile) {
        self.state.lock().expect("state").files.insert(path, file);
    }

    // Removes one injected file without counting setup mutation.
    fn remove(&self, path: &Path) {
        self.state.lock().expect("state").files.remove(path);
    }

    // Returns the number of stage and activation mutations made by setup.
    fn mutations(&self) -> usize {
        self.state.lock().expect("state").mutations
    }

    // Returns the number of durable-directory sync attempts.
    fn syncs(&self) -> usize {
        self.state.lock().expect("state").syncs
    }

    // Returns the number of setup transactions that reached the lock boundary.
    fn locks(&self) -> usize {
        self.state.lock().expect("state").locks
    }

    // Consumes only the selected single-use failure phase.
    fn take_failure(state: &mut TestIoState, phase: PublicationFailure) -> bool {
        if state.failure == Some(phase) {
            state.failure = None;
            true
        } else {
            false
        }
    }
}

// Holds one deterministic mock setup lock for the requested transaction scope.
struct TestLock;

impl CoreSetupConfigurationLock for TestLock {}

impl CoreSetupConfigurationIo for TestIo {
    // Records one deterministic lock acquisition.
    fn acquire_lock(
        &self,
        _directory: &Path,
        _owner_user_id: u32,
    ) -> Result<Box<dyn CoreSetupConfigurationLock>, CoreSetupConfigurationError> {
        self.state.lock().expect("state").locks += 1;
        Ok(Box::new(TestLock))
    }

    // Returns one injected optional no-follow file observation.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<CoreSetupConfigurationFile>, CoreSetupConfigurationError> {
        let file = self.state.lock().expect("state").files.get(path).cloned();
        if file
            .as_ref()
            .is_some_and(|file| file.bytes.len() > maximum_bytes)
        {
            return Err(CoreSetupConfigurationError::provider(
                "injected file exceeds its bound",
            ));
        }
        Ok(file.map(|file| file.observation()))
    }

    // Creates one exact owner-only synchronized temporary file.
    fn stage(
        &self,
        path: &Path,
        bytes: &[u8],
        owner_user_id: u32,
    ) -> Result<(), CoreSetupConfigurationError> {
        let mut state = self.state.lock().expect("state");
        if state.files.contains_key(path) {
            return Err(CoreSetupConfigurationError::provider(
                "injected stage collision",
            ));
        }
        state.files.insert(
            path.to_path_buf(),
            TestFile::safe(owner_user_id, bytes.to_vec()),
        );
        state.mutations += 1;
        Ok(())
    }

    // Moves one temporary file before or after the selected injected failure.
    fn activate(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<(), CoreSetupConfigurationError> {
        let mut state = self.state.lock().expect("state");
        state.activations += 1;
        let activation = state.activations;
        if Self::take_failure(&mut state, PublicationFailure::ActivationBefore(activation)) {
            return Err(CoreSetupConfigurationError::provider(
                "injected activation failure",
            ));
        }
        if Self::take_failure(
            &mut state,
            PublicationFailure::ActivationCollision(activation),
        ) {
            state.files.insert(
                destination.to_path_buf(),
                TestFile::safe(501, b"foreign destination".to_vec()),
            );
            return Err(CoreSetupConfigurationError::provider(
                "injected activation collision",
            ));
        }
        let file = state.files.remove(source).ok_or_else(|| {
            CoreSetupConfigurationError::provider("injected temporary file is unavailable")
        })?;
        state.files.insert(destination.to_path_buf(), file);
        state.mutations += 1;
        if Self::take_failure(&mut state, PublicationFailure::ActivationAfter(activation)) {
            return Err(CoreSetupConfigurationError::provider(
                "injected activation failure",
            ));
        }
        Ok(())
    }

    // Removes one exact injected file while rejecting metadata or content drift.
    fn remove_exact(
        &self,
        path: &Path,
        expected: &[u8],
        owner_user_id: u32,
    ) -> Result<(), CoreSetupConfigurationError> {
        let mut state = self.state.lock().expect("state");
        state.removals += 1;
        let removal = state.removals;
        if Self::take_failure(&mut state, PublicationFailure::RemovalBefore(removal)) {
            return Err(CoreSetupConfigurationError::recovery_required(
                "injected removal failure",
            ));
        }
        let file = state.files.get(path).ok_or_else(|| {
            CoreSetupConfigurationError::recovery_required("injected remove target is unavailable")
        })?;
        if file.owner_user_id != owner_user_id
            || file.mode != 0o600
            || file.link_count != 1
            || !file.is_regular_file
            || !file.is_stable
            || file.bytes != expected
        {
            return Err(CoreSetupConfigurationError::recovery_required(
                "injected remove target is divergent",
            ));
        }
        state.files.remove(path);
        state.mutations += 1;
        if Self::take_failure(&mut state, PublicationFailure::RemovalAfter(removal)) {
            return Err(CoreSetupConfigurationError::recovery_required(
                "injected removal failure",
            ));
        }
        Ok(())
    }

    // Records or withholds one directory sync before returning the selected failure.
    fn sync_directory(&self, _path: &Path) -> Result<(), CoreSetupConfigurationError> {
        let mut state = self.state.lock().expect("state");
        let synchronization = state.syncs + 1;
        if Self::take_failure(&mut state, PublicationFailure::SyncBefore(synchronization)) {
            return Err(CoreSetupConfigurationError::provider(
                "injected sync failure",
            ));
        }
        state.syncs += 1;
        if Self::take_failure(&mut state, PublicationFailure::SyncAfter(synchronization)) {
            return Err(CoreSetupConfigurationError::provider(
                "injected sync failure",
            ));
        }
        Ok(())
    }
}

// Supplies one generated Node document through its existing parser boundary.
struct NodeFileProvider {
    owner_user_id: u32,
    bytes: Vec<u8>,
}

impl NodeConfigurationFileProvider for NodeFileProvider {
    // Returns one safe owner-bound generated Node configuration.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        Ok(NodeConfigurationFile::new(
            self.owner_user_id,
            0o600,
            1,
            true,
            self.bytes.clone(),
        ))
    }
}

// Supplies one generated Gateway document through its existing parser boundary.
struct GatewayFileProvider {
    owner_user_id: u32,
    bytes: Vec<u8>,
}

// Returns one caller-constructed input for adapter substitution and closure-denial tests.
struct StaticConfigurationInputProvider {
    provider_identity: Sha256Digest,
    input: CoreSetupConfigurationInput,
}

impl CoreSetupConfigurationInputProvider for StaticConfigurationInputProvider {
    // Returns the immutable implementation identity bound to the substituted input.
    fn provider_identity(&self) -> &Sha256Digest {
        &self.provider_identity
    }

    // Returns the exact injected input without consulting host state.
    fn input(
        &self,
        _request: &CoreSetupRequest,
        _identity: &CoreSetupPreparedIdentity,
        _material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupConfigurationInput, CoreSetupProviderError> {
        Ok(self.input.clone())
    }
}

impl GatewayNativeFileIo for GatewayFileProvider {
    // Returns one safe owner-bound generated Gateway configuration.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        GatewayNativeFile::new(self.owner_user_id, 0o600, 1, self.bytes.clone())
    }
}

// Creates one complete explicit configuration input for the selected platform and role.
fn input(
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
    configuration_directory: PathBuf,
    owner_user_id: u32,
) -> CoreSetupConfigurationInput {
    input_with_public_listener(
        platform,
        role,
        configuration_directory,
        owner_user_id,
        role == CoreUpdateNodeRole::Main,
    )
}

// Creates one fixture with independently selected public exposure for contradiction tests.
fn input_with_public_listener(
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
    configuration_directory: PathBuf,
    owner_user_id: u32,
    has_public_listener: bool,
) -> CoreSetupConfigurationInput {
    input_with_options(
        platform,
        role,
        configuration_directory,
        owner_user_id,
        has_public_listener,
        &"c".repeat(64),
        None,
    )
}

// Creates one fixture with explicit exposure and immutable Core source identity.
fn input_with_options(
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
    configuration_directory: PathBuf,
    owner_user_id: u32,
    has_public_listener: bool,
    core_source_identity: &str,
    node_server_certificate_file: Option<PathBuf>,
) -> CoreSetupConfigurationInput {
    let state = PathBuf::from("/var/lib/letsinfer/state");
    let trust = PathBuf::from("/var/lib/letsinfer/trust");
    let database = state.join("core.sqlite");
    let telemetry = state.join("gateway_telemetry.json");
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
    let node = CoreSetupNodeInput::new(
        database.clone(),
        update_input(platform, &configuration_directory),
        model_input(platform, &state),
        benchmark_input(platform, &state, &trust),
        trust.join("pairing_setup.key"),
        pairing_input(platform, &trust),
        hardware,
        placement_safety_input(platform, &state, core_source_identity),
        1_000,
        CoreSetupNodeLocalApiInput::new(state.join("node.sock"), 8, 5_000, 5_000, 100),
        CoreSetupNodeRemoteApiInput::new(
            SocketAddr::from(([127, 0, 0, 1], 9_443)),
            16,
            100,
            5_000,
            5_000,
            5_000,
            node_server_certificate_file.unwrap_or_else(|| trust.join("node_server.pem")),
            trust.join("node_server.key"),
            trust.join("node_clients_ca.pem"),
        ),
    );
    let public_listener = has_public_listener
        .then(|| CoreSetupGatewayListenerInput::new(SocketAddr::from(([0, 0, 0, 0], 8_080)), 64));
    let gateway = CoreSetupGatewayInput::new(
        NodeId::parse(&"b".repeat(32)).expect("Node identity"),
        CoreVersion::parse("1.2.3").expect("Core version"),
        Sha256Digest::parse(core_source_identity).expect("Core source identity"),
        CoreSetupGatewayHealthInput::new(state.join("gateway_health.sock"), 8, 1_000, 1_000, 10),
        CoreSetupGatewayProtectionInput::new(
            state.join("node_protection.sock"),
            1_000,
            1_000,
            3_000,
            1_000,
        ),
        state.join("node.sock"),
        telemetry.clone(),
        1_000,
        30_000,
        public_listener,
        CoreSetupGatewayPrivateListenerInput::new(
            CoreSetupGatewayListenerInput::new(SocketAddr::from(([127, 0, 0, 1], 9_444)), 32),
            trust.join("gateway_server.pem"),
            trust.join("gateway_server.key"),
            trust.join("gateway_clients_ca.pem"),
            trust.join("gateway_client.pem"),
        ),
    );
    let watchdog = (platform == CoreUpdateServicePlatform::Linux).then(|| {
        CoreSetupWatchdogInput::new(
            InstallationId::parse(&"a".repeat(64)).expect("installation identity"),
            NodeId::parse(&"b".repeat(32)).expect("Node identity"),
            CoreVersion::parse("1.2.3").expect("Core version"),
            Sha256Digest::parse(core_source_identity).expect("Core source identity"),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9_445,
            CoreSetupWatchdogPathsInput::new(
                state.join("watchdog"),
                trust.join("watchdog_server.pem"),
                trust.join("watchdog_server.key"),
                trust.join("watchdog_controllers_ca.pem"),
                state.join("watchdog_controllers.json"),
                state.join("watchdog_controller_snapshot.json"),
                state.join("site_state.json"),
                telemetry,
                state.join("protected_placements"),
                database,
                PathBuf::from("/opt/letsinfer/runtimes"),
                PathBuf::from("/var/cache/letsinfer/runtimes"),
            ),
            CoreSetupWatchdogProtectionInput::new(state.join("node_protection.sock"), 1_000, 1_000),
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
            .expect("thresholds"),
        )
    });
    CoreSetupConfigurationInput::new(
        CoreUpdateServiceContext::new(platform, role),
        configuration_directory,
        owner_user_id,
        CoreSetupCliInput::new(
            state.join("node.sock"),
            PathBuf::from("/dev/urandom"),
            PathBuf::from("/usr/local/bin/letsinfer"),
            Some(PathBuf::from("/usr/bin/sudo")),
            5_000,
            1_048_576,
        ),
        node,
        gateway,
        watchdog,
    )
}

// Creates one exact installed protection executable and role-specific principal.
fn protection_executable_input(
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

// Creates the platform-specific placement-safety input without native discovery.
fn placement_safety_input(
    platform: CoreUpdateServicePlatform,
    state: &Path,
    core_source_identity: &str,
) -> CoreSetupNodePlacementSafetyInput {
    match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupNodePlacementSafetyInput::Linux {
            socket_path: state.join("node_protection.sock"),
            maximum_workers: 8,
            read_timeout_milliseconds: 1_000,
            write_timeout_milliseconds: 1_000,
            accept_poll_interval_milliseconds: 50,
            protection_root: state.join("protected_placements"),
            watchdog_source_identity: Sha256Digest::parse(core_source_identity)
                .expect("Core source identity"),
            gateway: protection_executable_input("li_gateway", '4', '5'),
            watchdog: protection_executable_input("li_watchdog", '6', '7'),
            lease_milliseconds: 3_000,
        },
        CoreUpdateServicePlatform::Macos => CoreSetupNodePlacementSafetyInput::MacosLaunchd,
    }
}

// Creates the platform-specific placement-safety template used by the concrete provider.
fn placement_safety_template(
    platform: CoreUpdateServicePlatform,
) -> CoreSetupNodePlacementSafetyTemplate {
    match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupNodePlacementSafetyTemplate::Linux {
            maximum_workers: 8,
            read_timeout_milliseconds: 1_000,
            write_timeout_milliseconds: 1_000,
            accept_poll_interval_milliseconds: 50,
            gateway: protection_executable_input("li_gateway", '4', '5'),
            watchdog: protection_executable_input("li_watchdog", '6', '7'),
            lease_milliseconds: 3_000,
        },
        CoreUpdateServicePlatform::Macos => CoreSetupNodePlacementSafetyTemplate::MacosLaunchd,
    }
}

// Returns one complete native/trust pairing input without consulting the test host.
fn pairing_input(platform: CoreUpdateServicePlatform, trust: &Path) -> CoreSetupNodePairingInput {
    let native = match platform {
        CoreUpdateServicePlatform::Linux => CoreSetupNodePairingPlatformInput::Linux {
            discovery_command: PathBuf::from("/usr/bin/avahi-publish-service"),
            direct_link_sys_class: PathBuf::from("/sys/class"),
            direct_link_ip_command: PathBuf::from("/usr/sbin/ip"),
        },
        CoreUpdateServicePlatform::Macos => CoreSetupNodePairingPlatformInput::Macos {
            discovery_command: PathBuf::from("/usr/bin/dns-sd"),
        },
    };
    CoreSetupNodePairingInput::new(
        native,
        PathBuf::from("/usr/bin/openssl"),
        trust.join("pairing_trust_staging"),
        trust.join("site.key"),
        trust.join("site.pub"),
        trust.join("site-ca.crt"),
        trust.join("node.crt"),
        Sha256Digest::parse(&"1".repeat(64)).expect("public key identity"),
        Sha256Digest::parse(&"2".repeat(64)).expect("certificate identity"),
    )
}

// Binds one fixture to its complete exact secret, trust, database, and provider identities.
fn binding(input: &CoreSetupConfigurationInput) -> CoreSetupConfigurationBinding {
    let state = PathBuf::from("/var/lib/letsinfer/state");
    let trust = PathBuf::from("/var/lib/letsinfer/trust");
    let mut files = vec![
        state.join("core.sqlite"),
        trust.join("pairing_setup.key"),
        trust.join("benchmark-signing.key"),
        trust.join("benchmark-signing.pub"),
        trust.join("site.key"),
        trust.join("site.pub"),
        trust.join("site-ca.crt"),
        trust.join("node.crt"),
        trust.join("node_server.pem"),
        trust.join("node_server.key"),
        trust.join("node_clients_ca.pem"),
        trust.join("gateway_server.pem"),
        trust.join("gateway_server.key"),
        trust.join("gateway_clients_ca.pem"),
        trust.join("gateway_client.pem"),
    ];
    if input.context().platform() == CoreUpdateServicePlatform::Linux {
        files.extend([
            trust.join("watchdog-ca.key"),
            trust.join("watchdog_server.pem"),
            trust.join("watchdog_server.key"),
            trust.join("watchdog_controllers_ca.pem"),
            trust.join("watchdog-controller.crt"),
            trust.join("watchdog-controller.key"),
            state.join("watchdog_controllers.json"),
        ]);
    }
    CoreSetupConfigurationBinding::new(
        Sha256Digest::parse(&"3".repeat(64)).expect("request identity"),
        Sha256Digest::parse(&"4".repeat(64)).expect("identity receipt"),
        Sha256Digest::parse(&"5".repeat(64)).expect("material receipt"),
        Sha256Digest::parse(&"6".repeat(64)).expect("material identity"),
        Sha256Digest::parse(&"7".repeat(64)).expect("provider identity"),
        files,
    )
    .expect("configuration binding")
}

// Returns one canonical SHA-256 fixture for provider-bound setup values.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one exact setup request for the selected resident platform and role.
fn setup_request(
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
) -> CoreSetupRequest {
    CoreSetupRequest::new(
        digest('8'),
        CoreUpdateServiceContext::new(platform, role),
        CoreInstallation::new(CoreVersion::parse("1.2.3").expect("version"), digest('c')),
        DisplayName::parse("Home AI").expect("display name"),
        NodeAddress::parse("homeai.local").expect("Node address"),
        li_core_application::CoreSetupNetworkPlan::new(
            SocketAddr::from(([127, 0, 0, 1], 9_443)),
            SocketAddr::from(([127, 0, 0, 1], 9_444)),
            (role == CoreUpdateNodeRole::Main).then(|| SocketAddr::from(([0, 0, 0, 0], 8_080))),
            (platform == CoreUpdateServicePlatform::Linux)
                .then(|| SocketAddr::from(([127, 0, 0, 1], 9_445))),
        ),
    )
}

// Creates one request-matched public identity closure for provider tests.
fn setup_identity(request: &CoreSetupRequest) -> CoreSetupPreparedIdentity {
    CoreSetupPreparedIdentity::new(
        CoreSetupReceipt::new(digest('9')),
        NodeId::parse(&"b".repeat(32)).expect("Node identity"),
        MachineId::parse(&"a".repeat(32)).expect("machine identity"),
        InstallationId::parse(&"d".repeat(64)).expect("installation identity"),
        request.display_name().clone(),
        match request.context().role() {
            CoreUpdateNodeRole::Main => NodeRole::Main,
            CoreUpdateNodeRole::Child => NodeRole::Child,
        },
        request.control_address().clone(),
    )
}

// Creates one exact role- and platform-matched private material closure for provider tests.
fn setup_material(request: &CoreSetupRequest) -> CoreSetupPreparedMaterial {
    setup_material_with_shape(
        request.context().role() == CoreUpdateNodeRole::Main,
        request.context().platform() == CoreUpdateServicePlatform::Linux,
    )
}

// Creates one material closure with independently selectable role/platform members for denials.
fn setup_material_with_shape(has_api_key: bool, has_watchdog: bool) -> CoreSetupPreparedMaterial {
    let state = PathBuf::from("/var/lib/letsinfer/state");
    let trust = PathBuf::from("/var/lib/letsinfer/trust");
    CoreSetupPreparedMaterial::new_with_benchmark_signing(
        CoreSetupReceipt::new(digest('0')),
        state.join("core.sqlite"),
        trust.join("pairing_setup.key"),
        has_api_key.then(|| state.join("api.key")),
        li_core_application::CoreSetupBenchmarkSigningMaterial::new(
            trust.join("benchmark-signing.key"),
            trust.join("benchmark-signing.pub"),
            digest('e'),
        ),
        li_core_application::CoreSetupPairingTrustMaterial::new(
            trust.join("site.key"),
            trust.join("site.pub"),
            trust.join("site-ca.crt"),
            trust.join("node.crt"),
            digest('1'),
            digest('2'),
        ),
        li_core_application::CoreSetupNodeTrustMaterial::new(
            trust.join("node-ca.key"),
            trust.join("node_clients_ca.pem"),
            trust.join("node_server.pem"),
            trust.join("node_server.key"),
            trust.join("node-client.crt"),
            trust.join("node-client.key"),
            digest('3'),
            digest('4'),
        ),
        li_core_application::CoreSetupGatewayTrustMaterial::new(
            trust.join("gateway-ca.key"),
            trust.join("gateway_clients_ca.pem"),
            trust.join("gateway_server.pem"),
            trust.join("gateway_server.key"),
            trust.join("gateway_client.pem"),
            trust.join("gateway-client.key"),
            digest('5'),
            digest('6'),
        ),
        has_watchdog.then(|| {
            li_core_application::CoreSetupWatchdogTrustMaterial::new(
                trust.join("watchdog-ca.key"),
                trust.join("watchdog_controllers_ca.pem"),
                trust.join("watchdog_server.pem"),
                trust.join("watchdog_server.key"),
                trust.join("watchdog-controller.crt"),
                trust.join("watchdog-controller.key"),
                state.join("watchdog_controllers.json"),
                digest('7'),
                digest('8'),
            )
        }),
        digest('d'),
    )
}

// Creates one concrete no-discovery input builder for a selected platform and fixed location.
fn concrete_input_provider(
    platform: CoreUpdateServicePlatform,
    location: CoreSetupConfigurationLocation,
    provider_identity: Sha256Digest,
) -> Arc<ApplicationCoreSetupConfigurationInputProvider> {
    let state = PathBuf::from("/var/lib/letsinfer/state");
    let trust = PathBuf::from("/var/lib/letsinfer/trust");
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
    let watchdog = (platform == CoreUpdateServicePlatform::Linux).then(|| {
        CoreSetupWatchdogConfigurationTemplate::new(
            state.join("watchdog"),
            state.join("watchdog_controller_snapshot.json"),
            state.join("site_state.json"),
            state.join("gateway_telemetry.json"),
            state.join("protected_placements"),
            PathBuf::from("/opt/letsinfer/runtimes"),
            PathBuf::from("/var/cache/letsinfer/runtimes"),
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
            .expect("thresholds"),
        )
    });
    let update = update_input(platform, location.directory());
    Arc::new(ApplicationCoreSetupConfigurationInputProvider::new(
        provider_identity,
        location,
        CoreSetupCliConfigurationTemplate::new(
            PathBuf::from("/dev/urandom"),
            PathBuf::from("/usr/local/bin/letsinfer"),
            Some(PathBuf::from("/usr/bin/sudo")),
            5_000,
            1_048_576,
        ),
        CoreSetupNodeConfigurationTemplate::new(
            update,
            model_input(platform, &state),
            benchmark_template(platform, &state),
            hardware,
            pairing,
            PathBuf::from("/usr/bin/openssl"),
            trust.join("pairing_trust_staging"),
            1_000,
            CoreSetupNodeLocalApiInput::new(state.join("node.sock"), 8, 5_000, 5_000, 100),
            placement_safety_template(platform),
            16,
            100,
            5_000,
            5_000,
            5_000,
        ),
        CoreSetupGatewayConfigurationTemplate::new(
            CoreSetupGatewayHealthInput::new(
                state.join("gateway_health.sock"),
                8,
                1_000,
                1_000,
                10,
            ),
            CoreSetupGatewayProtectionInput::new(
                state.join("node_protection.sock"),
                1_000,
                1_000,
                3_000,
                1_000,
            ),
            state.join("gateway_telemetry.json"),
            1_000,
            30_000,
            64,
            32,
        ),
        watchdog,
    ))
}

// Returns one authoritative path beneath the fixture's configuration directory.
fn configuration_path(directory: &Path, filename: &str) -> PathBuf {
    directory.join(filename)
}

// Returns the fixed same-directory pending path used for interrupted activation.
fn pending_path(directory: &Path, filename: &str) -> PathBuf {
    directory.join(format!(".{filename}.pending"))
}

// Installs one fixture into deterministic memory and returns its exact generated bytes.
fn generated_files(input: &CoreSetupConfigurationInput) -> BTreeMap<PathBuf, TestFile> {
    let io = Arc::new(TestIo::default());
    CoreSetupConfigurationInstaller::with_io(io.clone())
        .install(input, &binding(input))
        .expect("install");
    let files = io.state.lock().expect("state").files.clone();
    files
}

// Proves one generated Node, Gateway, and optional Watchdog document through strict parsers.
fn assert_parser_round_trip(
    files: &BTreeMap<PathBuf, TestFile>,
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
) {
    let directory = match files
        .keys()
        .find(|path| path.ends_with(NODE_CONFIGURATION_FILENAME))
        .and_then(|path| path.parent())
    {
        Some(path) => path,
        None => panic!("Node configuration path"),
    };
    let node_path = configuration_path(directory, NODE_CONFIGURATION_FILENAME);
    let node = NodeConfiguration::load(
        &NodeConfigurationFileReference::new(node_path.clone(), 501).expect("Node reference"),
        &NodeFileProvider {
            owner_user_id: 501,
            bytes: files.get(&node_path).expect("Node document").bytes.clone(),
        },
    )
    .expect("Node parser");
    match (platform, node.hardware()) {
        (CoreUpdateServicePlatform::Linux, NodeHardwareConfiguration::Linux { .. })
        | (CoreUpdateServicePlatform::Macos, NodeHardwareConfiguration::MacosArm64 { .. }) => {}
        _ => panic!("Node hardware platform mismatch"),
    }
    assert_eq!(
        node.pairing_setup_secret_file(),
        Path::new("/var/lib/letsinfer/trust/pairing_setup.key")
    );
    match (platform, node.pairing().platform()) {
        (
            CoreUpdateServicePlatform::Linux,
            NodePairingPlatform::Linux {
                sys_class,
                ip_command,
            },
        ) => {
            assert_eq!(sys_class, Path::new("/sys/class"));
            assert_eq!(ip_command, Path::new("/usr/sbin/ip"));
            assert_eq!(
                node.pairing().discovery_command(),
                Path::new("/usr/bin/avahi-publish-service")
            );
        }
        (CoreUpdateServicePlatform::Macos, NodePairingPlatform::Macos) => {
            assert_eq!(
                node.pairing().discovery_command(),
                Path::new("/usr/bin/dns-sd")
            );
        }
        _ => panic!("Node pairing platform mismatch"),
    }
    assert_eq!(
        node.pairing().trust_workspace(),
        Path::new("/var/lib/letsinfer/trust/pairing_trust_staging")
    );

    let cli_path = configuration_path(directory, CORE_CLI_CONFIGURATION_FILENAME);
    let cli: serde_json::Value =
        serde_json::from_slice(&files.get(&cli_path).expect("CLI document").bytes)
            .expect("CLI JSON");
    assert_eq!(
        cli["schema"],
        serde_json::json!({"name": "li_core_cli_configuration", "version": 4})
    );
    assert_eq!(
        cli["local_node_socket"],
        node.local_server().socket_path().to_string_lossy().as_ref()
    );
    assert_eq!(cli["entropy_source"], "/dev/urandom");
    assert_eq!(
        cli["uninstall"]["launcher_file"],
        "/usr/local/bin/letsinfer"
    );
    assert_eq!(cli["uninstall"]["privilege_command"], "/usr/bin/sudo");
    assert!(cli["remote_main"].is_null());

    let gateway_path = configuration_path(directory, GATEWAY_CONFIGURATION_FILENAME);
    let gateway = GatewayConfiguration::load(
        &GatewayConfigurationFile::new(501, gateway_path.clone()).expect("Gateway reference"),
        &GatewayFileProvider {
            owner_user_id: 501,
            bytes: files
                .get(&gateway_path)
                .expect("Gateway document")
                .bytes
                .clone(),
        },
    )
    .expect("Gateway parser");
    assert_eq!(
        gateway.mode(),
        match role {
            CoreUpdateNodeRole::Main => GatewayConfigurationMode::Main,
            CoreUpdateNodeRole::Child => GatewayConfigurationMode::Child,
        }
    );
    assert_eq!(
        gateway.public_listener().is_some(),
        role == CoreUpdateNodeRole::Main
    );
    assert_eq!(gateway.node_id().as_str(), "b".repeat(32));
    assert_eq!(gateway.core_version().as_str(), "1.2.3");
    assert_eq!(gateway.core_source_identity().as_str(), "c".repeat(64));
    assert_eq!(
        gateway.health().socket_path(),
        Path::new("/var/lib/letsinfer/state/gateway_health.sock")
    );
    assert_eq!(gateway.health().owner_user_id(), 501);
    assert_eq!(gateway.health().maximum_workers(), 8);
    assert_eq!(
        gateway.health().read_timeout(),
        std::time::Duration::from_secs(1)
    );
    assert_eq!(
        gateway.health().write_timeout(),
        std::time::Duration::from_secs(1)
    );
    assert_eq!(
        gateway.health().accept_poll_interval(),
        std::time::Duration::from_millis(10)
    );

    let watchdog_path = configuration_path(directory, WATCHDOG_CONFIGURATION_FILENAME);
    match platform {
        CoreUpdateServicePlatform::Linux => {
            let watchdog = WatchdogConfiguration::parse(
                &files.get(&watchdog_path).expect("Watchdog document").bytes,
            )
            .expect("Watchdog parser");
            assert_eq!(watchdog.core_source_identity().as_str(), "c".repeat(64));
            assert_eq!(watchdog.node_id(), gateway.node_id());
            assert_eq!(watchdog.core_release(), gateway.core_version().as_str());
            assert_eq!(
                watchdog.core_source_identity(),
                gateway.core_source_identity()
            );
            assert_eq!(watchdog.installation_id(), "a".repeat(64));
            assert_ne!(
                watchdog.core_source_identity().as_str(),
                watchdog.installation_id()
            );
            assert_eq!(watchdog.node_database_path(), node.database_file());
            assert_eq!(watchdog.gateway_metrics_path(), gateway.telemetry_file());
        }
        CoreUpdateServicePlatform::Macos => assert!(!files.contains_key(&watchdog_path)),
    }
}

#[test]
// Retains the separate Core source identity, rejects omission, and never overwrites another source.
fn watchdog_core_source_identity_is_required_and_divergence_is_immutable() {
    let directory = PathBuf::from("/configuration");
    let original = input_with_options(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
        true,
        &"c".repeat(64),
        None,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    installer
        .install(&original, &binding(&original))
        .expect("original source");
    let watchdog_path = configuration_path(&directory, WATCHDOG_CONFIGURATION_FILENAME);
    let original_bytes = io.file(&watchdog_path).expect("Watchdog file").bytes;
    let document: serde_json::Value =
        serde_json::from_slice(&original_bytes).expect("Watchdog JSON");
    assert_eq!(document["installation_id"], "a".repeat(64));
    assert_eq!(document["core_source_identity"], "c".repeat(64));

    let mut missing = document.clone();
    missing
        .as_object_mut()
        .expect("Watchdog object")
        .remove("core_source_identity");
    assert!(WatchdogConfiguration::parse(
        &serde_json::to_vec(&missing).expect("missing-source JSON")
    )
    .is_err());

    let other_source = input_with_options(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory,
        501,
        true,
        &"d".repeat(64),
        None,
    );
    let before = io.mutations();
    assert_eq!(
        installer
            .install(&other_source, &binding(&other_source))
            .expect_err("source divergence")
            .reason(),
        "configuration intent content is divergent"
    );
    assert_eq!(io.mutations(), before);
    assert_eq!(
        io.file(&watchdog_path).expect("unchanged Watchdog").bytes,
        original_bytes
    );
}

#[test]
// Covers both platforms and roles, deterministic bytes, strict parsers, and private child Gateway.
fn platform_role_matrix_is_deterministic_and_schema_parser_closed() {
    for platform in [
        CoreUpdateServicePlatform::Linux,
        CoreUpdateServicePlatform::Macos,
    ] {
        for role in [CoreUpdateNodeRole::Main, CoreUpdateNodeRole::Child] {
            let directory = PathBuf::from("/configuration");
            let input = input(platform, role, directory.clone(), 501);
            let first = generated_files(&input);
            let second = generated_files(&input);
            assert_eq!(
                first
                    .iter()
                    .map(|(path, file)| (path, file.bytes.as_slice()))
                    .collect::<Vec<_>>(),
                second
                    .iter()
                    .map(|(path, file)| (path, file.bytes.as_slice()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                first
                    .keys()
                    .filter(|path| {
                        path.extension().and_then(|value| value.to_str()) == Some("json")
                            && !path
                                .file_name()
                                .and_then(|value| value.to_str())
                                .is_some_and(|value| value.starts_with('.'))
                    })
                    .count(),
                if platform == CoreUpdateServicePlatform::Linux {
                    4
                } else {
                    3
                }
            );
            let gateway: serde_json::Value = serde_json::from_slice(
                &first
                    .get(&configuration_path(
                        &directory,
                        GATEWAY_CONFIGURATION_FILENAME,
                    ))
                    .expect("Gateway bytes")
                    .bytes,
            )
            .expect("Gateway JSON");
            assert_eq!(
                gateway["schema"],
                serde_json::json!({"name": "li_gateway_configuration", "version": 5})
            );
            assert_eq!(
                gateway["node_protection"],
                if platform == CoreUpdateServicePlatform::Linux {
                    serde_json::json!({
                        "socket_path": "/var/lib/letsinfer/state/node_protection.sock",
                        "read_timeout_milliseconds": 1000,
                        "write_timeout_milliseconds": 1000,
                        "maximum_cache_milliseconds": 3000,
                        "poll_interval_milliseconds": 1000
                    })
                } else {
                    serde_json::Value::Null
                }
            );
            assert_eq!(gateway["node_id"], "b".repeat(32));
            assert_eq!(gateway["core_release"], "1.2.3");
            assert_eq!(gateway["core_source_identity"], "c".repeat(64));
            assert_eq!(
                gateway["health"]["socket_path"],
                "/var/lib/letsinfer/state/gateway_health.sock"
            );
            assert_eq!(
                gateway.get("public_listener").is_some(),
                role == CoreUpdateNodeRole::Main
            );
            let all_bytes = first
                .values()
                .flat_map(|file| file.bytes.iter().copied())
                .collect::<Vec<_>>();
            assert!(!all_bytes
                .windows(17)
                .any(|window| window == b"PRIVATE KEY BYTES"));
            assert_parser_round_trip(&first, platform, role);
        }
    }
}

#[test]
// Binds every durable configuration-transaction schema to its closed producer identity.
fn checked_in_transaction_schemas_match_the_durable_documents() {
    let intent: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_configuration_intent_v1.schema.json"
    ))
    .expect("intent schema");
    let receipt: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_configuration_receipt_v1.schema.json"
    ))
    .expect("receipt schema");
    let rollback: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_configuration_rollback_v1.schema.json"
    ))
    .expect("rollback schema");

    for (schema, name) in [
        (&intent, "li_core_setup_configuration_intent"),
        (&receipt, "li_core_setup_configuration_receipt"),
        (&rollback, "li_core_setup_configuration_rollback"),
    ] {
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["schema"]["properties"]["name"]["const"],
            name
        );
        assert_eq!(
            schema["properties"]["schema"]["properties"]["version"]["const"],
            1
        );
        assert_eq!(
            schema["properties"]["schema"]["additionalProperties"],
            false
        );
    }
    assert_eq!(
        rollback["properties"]["intent"]["$ref"],
        "li_core_setup_configuration_intent_v1.schema.json"
    );
}

#[test]
// Rejects platform and role contradictions before acquiring the native lock or mutating files.
fn platform_and_role_mismatches_fail_before_io() {
    let directory = PathBuf::from("/configuration");
    let platform_mismatch = CoreSetupConfigurationInput::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        directory.clone(),
        501,
        CoreSetupCliInput::new(
            PathBuf::from("/state/node.sock"),
            PathBuf::from("/dev/urandom"),
            PathBuf::from("/usr/local/bin/letsinfer"),
            Some(PathBuf::from("/usr/bin/sudo")),
            5_000,
            1_048_576,
        ),
        match input(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            directory.clone(),
            501,
        ) {
            value => {
                let CoreSetupConfigurationInput { .. } = value;
                CoreSetupNodeInput::new(
                    PathBuf::from("/state/core.sqlite"),
                    update_input(CoreUpdateServicePlatform::Linux, &directory),
                    model_input(CoreUpdateServicePlatform::Linux, Path::new("/state")),
                    benchmark_input(
                        CoreUpdateServicePlatform::Linux,
                        Path::new("/state"),
                        Path::new("/trust"),
                    ),
                    PathBuf::from("/trust/pairing_setup.key"),
                    pairing_input(CoreUpdateServicePlatform::Linux, Path::new("/trust")),
                    CoreSetupNodeHardwareInput::Linux {
                        architecture: CpuArchitecture::Arm64,
                        boot_id_file: PathBuf::from("/proc/boot"),
                        cpu_information_file: PathBuf::from("/proc/cpu"),
                        memory_information_file: PathBuf::from("/proc/memory"),
                        nvidia_smi_command: None,
                        rdma_command: None,
                    },
                    placement_safety_input(
                        CoreUpdateServicePlatform::Linux,
                        Path::new("/state"),
                        &"c".repeat(64),
                    ),
                    1_000,
                    CoreSetupNodeLocalApiInput::new(PathBuf::from("/state/node.sock"), 1, 1, 1, 1),
                    CoreSetupNodeRemoteApiInput::new(
                        SocketAddr::from(([127, 0, 0, 1], 1)),
                        1,
                        1,
                        1,
                        1,
                        1,
                        PathBuf::from("/trust/node.pem"),
                        PathBuf::from("/trust/node.key"),
                        PathBuf::from("/trust/ca.pem"),
                    ),
                )
            }
        },
        CoreSetupGatewayInput::new(
            NodeId::parse(&"b".repeat(32)).expect("Node identity"),
            CoreVersion::parse("1.2.3").expect("Core version"),
            Sha256Digest::parse(&"c".repeat(64)).expect("Core source identity"),
            CoreSetupGatewayHealthInput::new(
                PathBuf::from("/state/gateway_health.sock"),
                1,
                1,
                1,
                1,
            ),
            CoreSetupGatewayProtectionInput::new(
                PathBuf::from("/state/node_protection.sock"),
                1,
                1,
                3,
                1,
            ),
            PathBuf::from("/state/node.sock"),
            PathBuf::from("/state/telemetry.json"),
            1_000,
            0,
            Some(CoreSetupGatewayListenerInput::new(
                SocketAddr::from(([0, 0, 0, 0], 80)),
                1,
            )),
            CoreSetupGatewayPrivateListenerInput::new(
                CoreSetupGatewayListenerInput::new(SocketAddr::from(([127, 0, 0, 1], 81)), 1),
                PathBuf::from("/trust/gateway.pem"),
                PathBuf::from("/trust/gateway.key"),
                PathBuf::from("/trust/gateway_ca.pem"),
                PathBuf::from("/trust/gateway_client.pem"),
            ),
        ),
        None,
    );
    let main_without_public = input_with_public_listener(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
        false,
    );
    let child_with_public = input_with_public_listener(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Child,
        directory,
        501,
        true,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    assert!(installer
        .install(&platform_mismatch, &binding(&platform_mismatch))
        .is_err());
    assert!(installer
        .install(&main_without_public, &binding(&main_without_public))
        .is_err());
    assert!(installer
        .install(&child_with_public, &binding(&child_with_public))
        .is_err());
    assert_eq!(io.locks(), 0);
}

#[test]
// Replays exact bytes, rejects divergence, and preflights every document before any mutation.
fn exact_replay_and_divergence_are_fail_closed_before_mutation() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    assert_eq!(
        installer
            .install(&input, &binding(&input))
            .expect("install")
            .status(),
        CoreSetupConfigurationInstallStatus::Installed
    );
    let after_install = io.mutations();
    assert_eq!(
        installer
            .install(&input, &binding(&input))
            .expect("replay")
            .status(),
        CoreSetupConfigurationInstallStatus::Replayed
    );
    assert_eq!(io.mutations(), after_install);
    assert!(io.syncs() >= 5);

    let gateway_path = configuration_path(&directory, GATEWAY_CONFIGURATION_FILENAME);
    let mut gateway = io.file(&gateway_path).expect("Gateway file");
    gateway.bytes.push(b' ');
    io.insert(gateway_path, gateway);
    io.remove(&configuration_path(&directory, NODE_CONFIGURATION_FILENAME));
    io.remove(&configuration_path(
        &directory,
        WATCHDOG_CONFIGURATION_FILENAME,
    ));
    let before_divergence = io.mutations();
    assert_eq!(
        installer
            .install(&input, &binding(&input))
            .expect_err("divergence")
            .reason(),
        "configuration replay state is incomplete"
    );
    assert_eq!(io.mutations(), before_divergence);
    assert!(io
        .file(&configuration_path(&directory, NODE_CONFIGURATION_FILENAME))
        .is_none());
}

#[test]
// Rejects every unsafe owner, mode, link, type, and stability class for final and pending files.
fn every_unsafe_metadata_class_fails_for_authoritative_and_pending_files() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
    );
    let generated = generated_files(&input);
    let desired = generated
        .get(&configuration_path(&directory, NODE_CONFIGURATION_FILENAME))
        .expect("Node file")
        .bytes
        .clone();
    for pending in [false, true] {
        for unsafe_class in 0..5 {
            let io = Arc::new(TestIo::default());
            let mut file = TestFile::safe(501, desired.clone());
            match unsafe_class {
                0 => file.owner_user_id = 502,
                1 => file.mode = 0o644,
                2 => file.link_count = 2,
                3 => file.is_regular_file = false,
                4 => file.is_stable = false,
                _ => unreachable!(),
            }
            let path = if pending {
                pending_path(&directory, NODE_CONFIGURATION_FILENAME)
            } else {
                configuration_path(&directory, NODE_CONFIGURATION_FILENAME)
            };
            io.insert(path, file);
            let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
            let error = installer
                .install(&input, &binding(&input))
                .expect_err("unsafe metadata");
            assert_eq!(
                error.reason(),
                if pending {
                    "configuration pending state exists without its intent"
                } else {
                    "configuration file metadata is unsafe"
                }
            );
            assert_eq!(io.mutations(), 0);
        }
    }
}

#[test]
// Reconciles activation failures based on exact visible state and resumes safe pending bytes.
fn interrupted_activation_is_reconciled_without_overwrite() {
    for failure in [
        PublicationFailure::ActivationBefore(3),
        PublicationFailure::ActivationAfter(3),
    ] {
        let directory = PathBuf::from("/configuration");
        let input = input(
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Child,
            directory.clone(),
            501,
        );
        let io = Arc::new(TestIo::default());
        io.fail_once(failure);
        let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
        let first = installer.install(&input, &binding(&input));
        match failure {
            PublicationFailure::ActivationBefore(_) => {
                assert!(first.is_err());
                assert!(io
                    .file(&pending_path(&directory, NODE_CONFIGURATION_FILENAME))
                    .is_some());
                assert_eq!(
                    installer
                        .install(&input, &binding(&input))
                        .expect("resumed install")
                        .status(),
                    CoreSetupConfigurationInstallStatus::Installed
                );
            }
            PublicationFailure::ActivationAfter(_) => {
                assert_eq!(
                    first.expect("reconciled visible activation").status(),
                    CoreSetupConfigurationInstallStatus::Installed
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            installer
                .install(&input, &binding(&input))
                .expect("exact replay")
                .status(),
            CoreSetupConfigurationInstallStatus::Replayed
        );
    }
}

#[test]
// Preserves a foreign destination created after planning and leaves exact pending bytes recoverable.
fn activation_collision_never_replaces_foreign_destination() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Child,
        directory.clone(),
        501,
    );
    let io = Arc::new(TestIo::default());
    io.fail_once(PublicationFailure::ActivationCollision(3));
    let error = CoreSetupConfigurationInstaller::with_io(io.clone())
        .install(&input, &binding(&input))
        .expect_err("collision");
    assert_eq!(
        error.reason(),
        "configuration activation published divergent state"
    );
    assert_eq!(
        io.file(&configuration_path(&directory, NODE_CONFIGURATION_FILENAME))
            .expect("foreign destination")
            .bytes,
        b"foreign destination"
    );
    assert!(io
        .file(&pending_path(&directory, NODE_CONFIGURATION_FILENAME))
        .is_some());
}

#[test]
// Replays visible files after failures immediately before or after directory durability.
fn interrupted_directory_sync_is_reconciled_by_exact_replay() {
    for failure in [
        PublicationFailure::SyncBefore(6),
        PublicationFailure::SyncAfter(6),
    ] {
        let directory = PathBuf::from("/configuration");
        let input = input(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            directory.clone(),
            501,
        );
        let io = Arc::new(TestIo::default());
        io.fail_once(failure);
        let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
        assert!(installer.install(&input, &binding(&input)).is_err());
        assert!(io
            .file(&configuration_path(&directory, NODE_CONFIGURATION_FILENAME))
            .is_some());
        assert_eq!(
            installer
                .install(&input, &binding(&input))
                .expect("reconciled install")
                .status(),
            CoreSetupConfigurationInstallStatus::Installed
        );
        assert_eq!(
            installer
                .install(&input, &binding(&input))
                .expect("durable replay")
                .status(),
            CoreSetupConfigurationInstallStatus::Replayed
        );
    }
}

#[test]
// Exercises production owner-only modes, exact replay, divergence, and persistent lock behavior.
fn production_io_installs_owner_only_files_and_never_overwrites_divergence() {
    let temporary = tempfile::tempdir().expect("temporary");
    let directory = temporary.path().join("configuration");
    fs::create_dir(&directory).expect("configuration directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
    let directory = directory.canonicalize().expect("canonical directory");
    let owner_user_id = fs::metadata(&directory).expect("directory metadata").uid();
    let input = input(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Child,
        directory.clone(),
        owner_user_id,
    );
    let installer = CoreSetupConfigurationInstaller::new();
    let installation = installer
        .install(&input, &binding(&input))
        .expect("production install");
    assert_eq!(
        installation.status(),
        CoreSetupConfigurationInstallStatus::Installed
    );
    assert_eq!(installation.files().len(), 4);
    for path in installation.files() {
        let metadata = fs::metadata(path).expect("configuration metadata");
        assert_eq!(metadata.uid(), owner_user_id);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(metadata.file_type().is_file());
    }
    assert_eq!(
        installer
            .install(&input, &binding(&input))
            .expect("production replay")
            .status(),
        CoreSetupConfigurationInstallStatus::Replayed
    );
    fs::write(
        configuration_path(&directory, GATEWAY_CONFIGURATION_FILENAME),
        b"divergent",
    )
    .expect("divergence");
    assert_eq!(
        installer
            .install(&input, &binding(&input))
            .expect_err("divergence")
            .reason(),
        "configuration replay state is divergent"
    );
}

#[test]
// Proves the production platform rename primitive refuses a destination collision atomically.
fn production_activation_is_atomic_and_no_replace() {
    let temporary = tempfile::tempdir().expect("temporary");
    let directory = temporary.path().join("configuration");
    fs::create_dir(&directory).expect("configuration directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
    let directory = directory.canonicalize().expect("canonical directory");
    let owner = fs::metadata(&directory).expect("owner").uid();
    let source = directory.join(".li_node.json.pending");
    let destination = directory.join(NODE_CONFIGURATION_FILENAME);
    let io = SystemCoreSetupConfigurationIo::default();
    let _lock = io.acquire_lock(&directory, owner).expect("lock");
    io.stage(&source, b"desired", owner).expect("stage");
    fs::write(&destination, b"foreign").expect("foreign destination");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).expect("foreign mode");
    assert!(io.activate(&source, &destination).is_err());
    assert_eq!(fs::read(&destination).expect("foreign bytes"), b"foreign");
    assert_eq!(fs::read(&source).expect("pending bytes"), b"desired");

    let displaced = temporary.path().join("displaced_configuration");
    fs::rename(&directory, &displaced).expect("displace locked directory");
    fs::create_dir(&directory).expect("replacement directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    let anchored = directory.join(".descriptor_anchored.pending");
    io.stage(&anchored, b"anchored", owner)
        .expect("descriptor-anchored stage");
    assert!(!anchored.exists());
    assert_eq!(
        fs::read(displaced.join(".descriptor_anchored.pending")).expect("anchored bytes"),
        b"anchored"
    );
}

#[test]
// Rejects real symlinks, hard links, non-regular files, loose modes, and unsafe directories.
fn production_io_rejects_every_native_unsafe_path_class() {
    enum UnsafePath {
        Symlink,
        HardLink,
        Directory,
        LooseMode,
    }
    for unsafe_path in [
        UnsafePath::Symlink,
        UnsafePath::HardLink,
        UnsafePath::Directory,
        UnsafePath::LooseMode,
    ] {
        let temporary = tempfile::tempdir().expect("temporary");
        let directory = temporary.path().join("configuration");
        fs::create_dir(&directory).expect("configuration directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
        let directory = directory.canonicalize().expect("canonical directory");
        let owner = fs::metadata(&directory).expect("owner").uid();
        let path = configuration_path(&directory, NODE_CONFIGURATION_FILENAME);
        match unsafe_path {
            UnsafePath::Symlink => {
                let source = directory.join("source");
                fs::write(&source, b"source").expect("source");
                symlink(source, &path).expect("symlink");
            }
            UnsafePath::HardLink => {
                let source = directory.join("source");
                fs::write(&source, b"source").expect("source");
                fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
                    .expect("source mode");
                hard_link(source, &path).expect("hard link");
            }
            UnsafePath::Directory => fs::create_dir(&path).expect("directory collision"),
            UnsafePath::LooseMode => {
                fs::write(&path, b"source").expect("source");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose mode");
            }
        }
        let input = input(
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Child,
            directory,
            owner,
        );
        assert!(CoreSetupConfigurationInstaller::new()
            .install(&input, &binding(&input))
            .is_err());
    }

    let temporary = tempfile::tempdir().expect("temporary");
    let directory = temporary.path().join("configuration");
    fs::create_dir(&directory).expect("configuration directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
        .expect("unsafe directory mode");
    let directory = directory.canonicalize().expect("canonical directory");
    let owner = fs::metadata(&directory).expect("owner").uid();
    let input = input(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Child,
        directory,
        owner,
    );
    assert_eq!(
        CoreSetupConfigurationInstaller::new()
            .install(&input, &binding(&input))
            .expect_err("unsafe directory")
            .reason(),
        "configuration directory metadata is unsafe"
    );
}

#[test]
// Resumes before and after every authoritative activation in the complete Linux transaction.
fn every_activation_boundary_is_reconciled_without_replacing_state() {
    for activation in 1..=6 {
        let directory = PathBuf::from("/configuration");
        let input = input(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            directory.clone(),
            501,
        );
        let io = Arc::new(TestIo::default());
        io.fail_once(PublicationFailure::ActivationBefore(activation));
        let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
        let error = installer
            .install(&input, &binding(&input))
            .expect_err("activation interruption");
        assert!(error.requires_recovery());
        if activation > 1 {
            assert!(io
                .file(&directory.join(".li_core_setup_configuration.intent.json"))
                .is_some());
        }
        assert_eq!(
            installer
                .install(&input, &binding(&input))
                .expect("activation recovery")
                .status(),
            CoreSetupConfigurationInstallStatus::Installed
        );

        let after_io = Arc::new(TestIo::default());
        after_io.fail_once(PublicationFailure::ActivationAfter(activation));
        let after_installer = CoreSetupConfigurationInstaller::with_io(after_io);
        assert_eq!(
            after_installer
                .install(&input, &binding(&input))
                .expect("ambiguous visible activation")
                .status(),
            CoreSetupConfigurationInstallStatus::Installed
        );
    }
}

#[test]
// Resumes every stage and activation directory-durability boundary in fixed transaction order.
fn every_directory_durability_boundary_is_reconciled() {
    for synchronization in 1..=13 {
        for failure in [
            PublicationFailure::SyncBefore(synchronization),
            PublicationFailure::SyncAfter(synchronization),
        ] {
            let directory = PathBuf::from("/configuration");
            let input = input(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Child,
                directory,
                501,
            );
            let io = Arc::new(TestIo::default());
            io.fail_once(failure);
            let installer = CoreSetupConfigurationInstaller::with_io(io);
            let error = installer
                .install(&input, &binding(&input))
                .expect_err("directory durability interruption");
            assert!(
                error.requires_recovery(),
                "unexpected failure classification at {failure:?}: {error}"
            );
            installer
                .install(&input, &binding(&input))
                .expect("directory durability recovery");
        }
    }
}

#[test]
// Preserves exact pre-existing documents and removes only setup-owned files during rollback.
fn rollback_preserves_preexisting_files_and_removes_owned_files() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
    );
    let generated = generated_files(&input);
    let io = Arc::new(TestIo::default());
    for filename in [
        CORE_CLI_CONFIGURATION_FILENAME,
        NODE_CONFIGURATION_FILENAME,
        GATEWAY_CONFIGURATION_FILENAME,
        WATCHDOG_CONFIGURATION_FILENAME,
    ] {
        let path = configuration_path(&directory, filename);
        io.insert(
            path.clone(),
            generated.get(&path).expect("generated file").clone(),
        );
    }
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    let installation = installer
        .install(&input, &binding(&input))
        .expect("pre-existing install");
    installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            installation.receipt_identity(),
        )
        .expect("pre-existing rollback");
    for filename in [
        CORE_CLI_CONFIGURATION_FILENAME,
        NODE_CONFIGURATION_FILENAME,
        GATEWAY_CONFIGURATION_FILENAME,
        WATCHDOG_CONFIGURATION_FILENAME,
    ] {
        assert!(io.file(&configuration_path(&directory, filename)).is_some());
    }

    let owned_io = Arc::new(TestIo::default());
    let owned_installer = CoreSetupConfigurationInstaller::with_io(owned_io.clone());
    let owned = owned_installer
        .install(&input, &binding(&input))
        .expect("owned install");
    owned_installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            owned.receipt_identity(),
        )
        .expect("owned rollback");
    assert!(owned_io.state.lock().expect("state").files.is_empty());
}

#[test]
// Resumes before and after every reverse-order removal while retaining exact receipt ownership.
fn every_rollback_removal_boundary_is_reconciled() {
    for removal in 1..=7 {
        for failure in [
            PublicationFailure::RemovalBefore(removal),
            PublicationFailure::RemovalAfter(removal),
        ] {
            let directory = PathBuf::from("/configuration");
            let input = input(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
                directory.clone(),
                501,
            );
            let io = Arc::new(TestIo::default());
            let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
            let installation = installer
                .install(&input, &binding(&input))
                .expect("install before rollback");
            io.fail_once(failure);
            assert!(installer
                .rollback(
                    &directory,
                    501,
                    binding(&input).provider_identity(),
                    installation.receipt_identity(),
                )
                .is_err());
            installer
                .rollback(
                    &directory,
                    501,
                    binding(&input).provider_identity(),
                    installation.receipt_identity(),
                )
                .expect("rollback recovery");
            assert!(io.state.lock().expect("state").files.is_empty());
        }
    }
}

#[test]
// Builds and installs every role/platform projection through the concrete production input builder.
fn concrete_provider_projects_every_platform_and_role_before_intent() {
    for platform in [
        CoreUpdateServicePlatform::Linux,
        CoreUpdateServicePlatform::Macos,
    ] {
        for role in [CoreUpdateNodeRole::Main, CoreUpdateNodeRole::Child] {
            let directory = PathBuf::from("/configuration");
            let location =
                CoreSetupConfigurationLocation::new(directory.clone(), 501).expect("location");
            let inputs = concrete_input_provider(platform, location.clone(), digest('7'));
            let io = Arc::new(TestIo::default());
            let provider = ApplicationCoreSetupConfigurationProvider::with_installer(
                location,
                inputs,
                CoreSetupConfigurationInstaller::with_io(io.clone()),
            );
            let request = setup_request(platform, role);
            let identity = setup_identity(&request);
            let material = setup_material(&request);
            let receipt = provider
                .install(&request, &identity, &material)
                .expect("provider install");
            assert_eq!(
                io.state
                    .lock()
                    .expect("state")
                    .files
                    .keys()
                    .filter(|path| {
                        path.file_name()
                            .and_then(|value| value.to_str())
                            .is_some_and(|value| {
                                matches!(
                                    value,
                                    CORE_CLI_CONFIGURATION_FILENAME
                                        | NODE_CONFIGURATION_FILENAME
                                        | GATEWAY_CONFIGURATION_FILENAME
                                        | WATCHDOG_CONFIGURATION_FILENAME
                                )
                            })
                    })
                    .count(),
                if platform == CoreUpdateServicePlatform::Linux {
                    4
                } else {
                    3
                }
            );
            provider
                .rollback(receipt.receipt())
                .expect("provider rollback");
            assert!(io.state.lock().expect("state").files.is_empty());
        }
    }
}

#[test]
// Rejects missing and extra role/platform material members before lock or durable intent.
fn provider_rejects_material_shape_substitution_before_mutation() {
    for (platform, role, has_api_key, has_watchdog) in [
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            false,
            true,
        ),
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Child,
            true,
            true,
        ),
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            true,
            false,
        ),
        (
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
            true,
            true,
        ),
    ] {
        let directory = PathBuf::from("/configuration");
        let location = CoreSetupConfigurationLocation::new(directory, 501).expect("location");
        let inputs = concrete_input_provider(platform, location.clone(), digest('7'));
        let io = Arc::new(TestIo::default());
        let provider = ApplicationCoreSetupConfigurationProvider::with_installer(
            location,
            inputs,
            CoreSetupConfigurationInstaller::with_io(io.clone()),
        );
        let request = setup_request(platform, role);
        let error = provider
            .install(
                &request,
                &setup_identity(&request),
                &setup_material_with_shape(has_api_key, has_watchdog),
            )
            .expect_err("material shape substitution");
        assert!(matches!(
            error,
            li_core_application::CoreSetupProviderError::Unchanged { .. }
        ));
        assert_eq!(io.locks(), 0);
        assert!(io.state.lock().expect("state").files.is_empty());
    }
}

#[test]
// Rejects one provider-substituted credential path before acquiring the transaction lock.
fn provider_rejects_unprovisioned_path_substitution_before_intent() {
    let directory = PathBuf::from("/configuration");
    let location = CoreSetupConfigurationLocation::new(directory.clone(), 501).expect("location");
    let inputs = Arc::new(StaticConfigurationInputProvider {
        provider_identity: digest('7'),
        input: input_with_options(
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
            directory,
            501,
            true,
            &"c".repeat(64),
            Some(PathBuf::from("/substituted/node_server.pem")),
        ),
    });
    let io = Arc::new(TestIo::default());
    let provider = ApplicationCoreSetupConfigurationProvider::with_installer(
        location,
        inputs,
        CoreSetupConfigurationInstaller::with_io(io.clone()),
    );
    let request = setup_request(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let error = provider
        .install(
            &request,
            &setup_identity(&request),
            &setup_material(&request),
        )
        .expect_err("unprovisioned path substitution");
    assert!(matches!(error, CoreSetupProviderError::Unchanged { .. }));
    assert_eq!(io.locks(), 0);
    assert!(io.state.lock().expect("state").files.is_empty());
}

#[test]
// Rejects provider substitution and receipt substitution without altering authoritative files.
fn provider_and_receipt_substitution_require_recovery() {
    let directory = PathBuf::from("/configuration");
    let location = CoreSetupConfigurationLocation::new(directory, 501).expect("location");
    let io = Arc::new(TestIo::default());
    let request = setup_request(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main);
    let identity = setup_identity(&request);
    let material = setup_material(&request);
    let first = ApplicationCoreSetupConfigurationProvider::with_installer(
        location.clone(),
        concrete_input_provider(
            CoreUpdateServicePlatform::Macos,
            location.clone(),
            digest('7'),
        ),
        CoreSetupConfigurationInstaller::with_io(io.clone()),
    );
    let receipt = first
        .install(&request, &identity, &material)
        .expect("first provider");
    let before = io.mutations();
    let substitute = ApplicationCoreSetupConfigurationProvider::with_installer(
        location.clone(),
        concrete_input_provider(CoreUpdateServicePlatform::Macos, location, digest('e')),
        CoreSetupConfigurationInstaller::with_io(io.clone()),
    );
    assert!(matches!(
        substitute
            .install(&request, &identity, &material)
            .expect_err("provider substitution"),
        li_core_application::CoreSetupProviderError::RecoveryRequired { .. }
    ));
    assert!(matches!(
        first
            .rollback(&CoreSetupReceipt::new(digest('f')))
            .expect_err("receipt substitution"),
        li_core_application::CoreSetupProviderError::RecoveryRequired { .. }
    ));
    assert_eq!(io.mutations(), before);
    first.rollback(receipt.receipt()).expect("exact rollback");
}

#[test]
// Rejects traversal, redundant, relative, root, and trailing-slash configuration locations.
fn configuration_location_rejects_every_noncanonical_alias() {
    for path in [
        "configuration",
        "/",
        "/configuration/../other",
        "/configuration/./other",
        "/configuration//other",
        "/configuration/",
    ] {
        assert!(CoreSetupConfigurationLocation::new(PathBuf::from(path), 501).is_err());
    }
    assert!(CoreSetupConfigurationLocation::new(PathBuf::from("/configuration"), 501).is_ok());
}

#[test]
// Acts as the separately executed process that must observe the retained production lock busy.
fn production_cross_process_lock_child() {
    let Some(directory) = std::env::var_os("LI_CONFIGURATION_LOCK_CHILD_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let owner = fs::metadata(&directory).expect("directory metadata").uid();
    assert!(SystemCoreSetupConfigurationIo::default()
        .acquire_lock(&directory, owner)
        .is_err());
}

#[test]
// Proves the fixed descriptor lock excludes a separately opened configuration transaction process.
fn production_lock_excludes_a_separate_process() {
    let temporary = tempfile::tempdir().expect("temporary");
    let directory = temporary.path().join("configuration");
    fs::create_dir(&directory).expect("configuration directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
    let directory = directory.canonicalize().expect("canonical directory");
    let owner = fs::metadata(&directory).expect("directory metadata").uid();
    let io = SystemCoreSetupConfigurationIo::default();
    let lock = io.acquire_lock(&directory, owner).expect("parent lock");
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "production_cross_process_lock_child",
            "--nocapture",
        ])
        .env("LI_CONFIGURATION_LOCK_CHILD_DIRECTORY", &directory)
        .status()
        .expect("child process");
    assert!(status.success());
    drop(lock);
    assert!(io.acquire_lock(&directory, owner).is_ok());
}

#[test]
// Rejects structural and identity mutation in both durable transaction documents without mutation.
fn durable_intent_and_receipt_mutation_matrix_is_fail_closed() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Child,
        directory.clone(),
        501,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    installer
        .install(&input, &binding(&input))
        .expect("initial install");
    for (filename, mutation) in [
        (".li_core_setup_configuration.intent.json", 0_u8),
        (".li_core_setup_configuration.intent.json", 1_u8),
        (".li_core_setup_configuration.intent.json", 2_u8),
        (".li_core_setup_configuration.receipt.json", 0_u8),
        (".li_core_setup_configuration.receipt.json", 1_u8),
    ] {
        let path = directory.join(filename);
        let original = io.file(&path).expect("transaction file");
        let mut document: serde_json::Value =
            serde_json::from_slice(&original.bytes).expect("transaction JSON");
        match mutation {
            0 => {
                document
                    .as_object_mut()
                    .expect("object")
                    .insert("unknown".to_owned(), serde_json::json!(true));
            }
            1 if filename.contains("intent") => {
                document["provider_identity"] = serde_json::json!("f".repeat(64));
            }
            1 => document["intent_sha256"] = serde_json::json!("f".repeat(64)),
            2 => document["documents"][0]["owned"] = serde_json::json!(false),
            _ => unreachable!(),
        }
        let mut bytes = serde_json::to_vec_pretty(&document).expect("mutated JSON");
        bytes.push(b'\n');
        io.insert(path.clone(), TestFile::safe(501, bytes));
        let before = io.mutations();
        assert!(installer
            .install(&input, &binding(&input))
            .expect_err("transaction mutation")
            .requires_recovery());
        assert_eq!(io.mutations(), before);
        io.insert(path, original);
    }
}

#[test]
// Detects one drifted owned file before deleting any member of the resident configuration set.
fn rollback_preflights_owned_drift_before_configuration_deletion() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    let installation = installer
        .install(&input, &binding(&input))
        .expect("install");
    let gateway_path = directory.join(GATEWAY_CONFIGURATION_FILENAME);
    io.insert(
        gateway_path.clone(),
        TestFile::safe(501, b"drifted".to_vec()),
    );
    assert!(installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            installation.receipt_identity(),
        )
        .expect_err("drifted rollback")
        .requires_recovery());
    assert!(io
        .file(&directory.join(NODE_CONFIGURATION_FILENAME))
        .is_some());
    assert!(io.file(&gateway_path).is_some());
    assert!(io
        .file(&directory.join(WATCHDOG_CONFIGURATION_FILENAME))
        .is_some());
}

#[test]
// Rejects live-intent drift after rollback begins before deleting any resident configuration.
fn rollback_rejects_intent_drift_before_resuming_deletion() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    let installation = installer
        .install(&input, &binding(&input))
        .expect("install");
    io.fail_once(PublicationFailure::RemovalBefore(1));
    assert!(installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            installation.receipt_identity(),
        )
        .is_err());

    let intent_path = directory.join(".li_core_setup_configuration.intent.json");
    let original = io.file(&intent_path).expect("intent");
    let mut document: serde_json::Value =
        serde_json::from_slice(&original.bytes).expect("intent JSON");
    document["provider_identity"] = serde_json::json!("f".repeat(64));
    let mut bytes = serde_json::to_vec_pretty(&document).expect("mutated intent JSON");
    bytes.push(b'\n');
    io.insert(intent_path, TestFile::safe(501, bytes));
    let before = io.mutations();
    assert!(installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            installation.receipt_identity(),
        )
        .expect_err("intent drift")
        .requires_recovery());
    assert_eq!(io.mutations(), before);
    for filename in [
        CORE_CLI_CONFIGURATION_FILENAME,
        NODE_CONFIGURATION_FILENAME,
        GATEWAY_CONFIGURATION_FILENAME,
        WATCHDOG_CONFIGURATION_FILENAME,
    ] {
        assert!(io.file(&directory.join(filename)).is_some());
    }
}

#[test]
// Rejects structural rollback-owner corruption before removing any resident configuration.
fn rollback_marker_unknown_field_fails_closed_before_deletion() {
    let directory = PathBuf::from("/configuration");
    let input = input(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        directory.clone(),
        501,
    );
    let io = Arc::new(TestIo::default());
    let installer = CoreSetupConfigurationInstaller::with_io(io.clone());
    let installation = installer
        .install(&input, &binding(&input))
        .expect("install");
    io.fail_once(PublicationFailure::RemovalBefore(1));
    assert!(installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            installation.receipt_identity(),
        )
        .is_err());

    let rollback_path = directory.join(".li_core_setup_configuration.rollback.json");
    let original = io.file(&rollback_path).expect("rollback marker");
    let mut document: serde_json::Value =
        serde_json::from_slice(&original.bytes).expect("rollback JSON");
    document["unknown"] = serde_json::json!(true);
    let mut bytes = serde_json::to_vec_pretty(&document).expect("mutated rollback JSON");
    bytes.push(b'\n');
    io.insert(rollback_path, TestFile::safe(501, bytes));
    let before = io.mutations();
    assert!(installer
        .rollback(
            &directory,
            501,
            binding(&input).provider_identity(),
            installation.receipt_identity(),
        )
        .expect_err("rollback marker mutation")
        .requires_recovery());
    assert_eq!(io.mutations(), before);
    for filename in [
        CORE_CLI_CONFIGURATION_FILENAME,
        NODE_CONFIGURATION_FILENAME,
        GATEWAY_CONFIGURATION_FILENAME,
        WATCHDOG_CONFIGURATION_FILENAME,
    ] {
        assert!(io.file(&directory.join(filename)).is_some());
    }
}
