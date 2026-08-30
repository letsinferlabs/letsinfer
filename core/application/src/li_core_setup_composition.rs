// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use li_pairing_manager::SystemPairingNativeCommandRunner;
use li_watchdog_manager::{DynamicWatchdogNvmlPort, WatchdogLinuxCapability};

use crate::{
    ApplicationCoreSetupConfigurationInputProvider, ApplicationCoreSetupConfigurationProvider,
    ApplicationCoreSetupMaterialProvider, ApplicationCoreSetupServiceProvider,
    CoreGatewayServiceHealth, CoreNativeServiceCommandRunner, CoreNodeServiceHealth,
    CoreResidentProcess, CoreServiceSetupError, CoreServiceSetupNodeIdentity,
    CoreServiceSetupObservation, CoreServiceSetupResidentHealth, CoreSetup,
    CoreSetupCliConfigurationTemplate, CoreSetupConfigurationLocation, CoreSetupError,
    CoreSetupGatewayConfigurationTemplate, CoreSetupMaterialPaths,
    CoreSetupNodeConfigurationTemplate, CoreSetupRequest, CoreSetupResult,
    CoreSetupWatchdogConfigurationTemplate, CoreWatchdogHealthTlsFiles, CoreWatchdogServiceHealth,
    DatabaseCoreSetupIdentityProvider, LinuxCoreSetupMachineIdentityProvider,
    MacosCoreSetupMachineIdentityProvider, OpenSslCoreSetupResidentTrustIssuer,
    SystemCoreNativeServiceCommandRunner, SystemCoreServiceSetupComposition,
    SystemCoreSetupExecutionLockProvider, SystemCoreSetupIdentityClock,
    SystemCoreSetupJournalStore, SystemCoreSetupMachineIdentityCommandRunner,
    SystemCoreSetupMachineIdentityFileReader, SystemCoreSetupMaterialEntropy,
    SystemCoreSetupMaterialIo, SystemCoreSetupTrustWorkspaceIo, GATEWAY_CONFIGURATION_FILENAME,
    NODE_CONFIGURATION_FILENAME, WATCHDOG_CONFIGURATION_FILENAME,
};

const LINUX_MACHINE_IDENTITY_FILE: &str = "/etc/machine-id";

const PERSISTENCE_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
const PERSISTENCE_PREFLIGHT_MAXIMUM_OUTPUT_BYTES: usize = 64 * 1024;

// Carries the exact Linux Watchdog health paths before production TLS loading begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogHealthInput {
    authority_certificate_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
}

impl CoreSetupWatchdogHealthInput {
    // Creates one distinct canonical Watchdog health path set without reading credential files.
    pub fn new(
        authority_certificate_file: PathBuf,
        controller_certificate_file: PathBuf,
        controller_private_key_file: PathBuf,
    ) -> Result<Self, CoreSetupCompositionError> {
        let paths = [
            authority_certificate_file.as_path(),
            controller_certificate_file.as_path(),
            controller_private_key_file.as_path(),
        ];
        if paths.iter().any(|path| !is_normal_absolute_path(path))
            || paths[0] == paths[1]
            || paths[0] == paths[2]
            || paths[1] == paths[2]
        {
            return Err(composition_contract_error(
                "Watchdog health material paths are invalid",
            ));
        }
        Ok(Self {
            authority_certificate_file,
            controller_certificate_file,
            controller_private_key_file,
        })
    }

    // Requires health to consume the exact authority and controller identities setup generates.
    fn matches(&self, material: &crate::CoreSetupWatchdogTrustPaths) -> bool {
        self.authority_certificate_file == material.authority_certificate_file()
            && self.controller_certificate_file == material.controller_certificate_file()
            && self.controller_private_key_file == material.controller_private_key_file()
    }

    // Creates the deferred production TLS file input after owner and path binding are proven.
    fn tls_files(
        &self,
        owner_user_id: u32,
    ) -> Result<CoreWatchdogHealthTlsFiles, CoreSetupCompositionError> {
        CoreWatchdogHealthTlsFiles::new(
            owner_user_id,
            self.authority_certificate_file.clone(),
            self.controller_certificate_file.clone(),
            self.controller_private_key_file.clone(),
        )
        .map_err(|_| composition_contract_error("Watchdog health material paths are invalid"))
    }
}

// Carries the exact native machine-identity and Linux health inputs selected by the installer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupPlatformInput {
    Linux {
        machine_identity_file: PathBuf,
        watchdog_health: CoreSetupWatchdogHealthInput,
    },
    Macos {
        machine_identity_command: PathBuf,
        command_timeout: Duration,
        command_poll_interval: Duration,
    },
}

impl CoreSetupPlatformInput {
    // Creates one Linux input without discovering its machine identity or Watchdog credentials.
    pub fn linux(
        machine_identity_file: PathBuf,
        watchdog_health: CoreSetupWatchdogHealthInput,
    ) -> Result<Self, CoreSetupCompositionError> {
        if machine_identity_file != Path::new(LINUX_MACHINE_IDENTITY_FILE) {
            return Err(composition_contract_error(
                "Linux machine identity path is invalid",
            ));
        }
        Ok(Self::Linux {
            machine_identity_file,
            watchdog_health,
        })
    }

    // Creates one macOS input from an exact shell-free ioreg command and bounded polling policy.
    pub fn macos(
        machine_identity_command: PathBuf,
        command_timeout: Duration,
        command_poll_interval: Duration,
    ) -> Result<Self, CoreSetupCompositionError> {
        if !is_normal_absolute_path(&machine_identity_command)
            || machine_identity_command
                .file_name()
                .and_then(|name| name.to_str())
                != Some("ioreg")
            || command_timeout.is_zero()
            || command_poll_interval.is_zero()
            || command_poll_interval > command_timeout
        {
            return Err(composition_contract_error(
                "macOS machine identity command is invalid",
            ));
        }
        Ok(Self::Macos {
            machine_identity_command,
            command_timeout,
            command_poll_interval,
        })
    }

    // Returns the platform represented by the exact native input variant.
    const fn platform(&self) -> CoreUpdateServicePlatform {
        match self {
            Self::Linux { .. } => CoreUpdateServicePlatform::Linux,
            Self::Macos { .. } => CoreUpdateServicePlatform::Macos,
        }
    }
}

// Carries every caller-selected root without assigning one installation layout implicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupCompositionRoots {
    letsinfer_home: PathBuf,
    home_directory: PathBuf,
    setup_state_directory: PathBuf,
    material_root: PathBuf,
    trust_workspace_root: PathBuf,
    configuration: CoreSetupConfigurationLocation,
}

impl CoreSetupCompositionRoots {
    // Creates one explicit root set after rejecting aliases, traversal, and the filesystem root.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        letsinfer_home: PathBuf,
        home_directory: PathBuf,
        setup_state_directory: PathBuf,
        material_root: PathBuf,
        trust_workspace_root: PathBuf,
        configuration: CoreSetupConfigurationLocation,
    ) -> Result<Self, CoreSetupCompositionError> {
        let roots = [
            letsinfer_home.as_path(),
            home_directory.as_path(),
            setup_state_directory.as_path(),
            material_root.as_path(),
            trust_workspace_root.as_path(),
            configuration.directory(),
        ];
        if roots
            .iter()
            .any(|path| !is_normal_absolute_path(path) || *path == Path::new("/"))
        {
            return Err(composition_contract_error("Core setup roots are invalid"));
        }
        let independently_owned = [
            setup_state_directory.as_path(),
            material_root.as_path(),
            trust_workspace_root.as_path(),
            configuration.directory(),
        ];
        if independently_owned.iter().enumerate().any(|(index, path)| {
            independently_owned[..index]
                .iter()
                .any(|other| path.starts_with(other) || other.starts_with(path))
        }) {
            return Err(composition_contract_error("Core setup roots are ambiguous"));
        }
        Ok(Self {
            letsinfer_home,
            home_directory,
            setup_state_directory,
            material_root,
            trust_workspace_root,
            configuration,
        })
    }
}

// Carries every native value needed to compose standalone-main setup without path discovery.
pub struct CoreSetupCompositionInput {
    context: CoreUpdateServiceContext,
    owner_user_id: u32,
    roots: CoreSetupCompositionRoots,
    material_paths: CoreSetupMaterialPaths,
    configuration_provider_identity: Sha256Digest,
    cli_configuration: CoreSetupCliConfigurationTemplate,
    node_configuration: CoreSetupNodeConfigurationTemplate,
    gateway_configuration: CoreSetupGatewayConfigurationTemplate,
    watchdog_configuration: Option<CoreSetupWatchdogConfigurationTemplate>,
    openssl_command: PathBuf,
    platform: CoreSetupPlatformInput,
}

impl CoreSetupCompositionInput {
    // Creates one closed production input and validates all platform policy before native mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: CoreUpdateServiceContext,
        owner_user_id: u32,
        roots: CoreSetupCompositionRoots,
        material_paths: CoreSetupMaterialPaths,
        configuration_provider_identity: Sha256Digest,
        cli_configuration: CoreSetupCliConfigurationTemplate,
        node_configuration: CoreSetupNodeConfigurationTemplate,
        gateway_configuration: CoreSetupGatewayConfigurationTemplate,
        watchdog_configuration: Option<CoreSetupWatchdogConfigurationTemplate>,
        openssl_command: PathBuf,
        platform: CoreSetupPlatformInput,
    ) -> Result<Self, CoreSetupCompositionError> {
        if context.role() != CoreUpdateNodeRole::Main {
            return Err(composition_contract_error(
                "initial Core setup requires the standalone main role",
            ));
        }
        if context.platform() != platform.platform() {
            return Err(composition_contract_error(
                "native setup input does not match the selected platform",
            ));
        }
        let expects_watchdog = context.platform() == CoreUpdateServicePlatform::Linux;
        if watchdog_configuration.is_some() != expects_watchdog
            || material_paths.watchdog_trust().is_some() != expects_watchdog
        {
            return Err(composition_contract_error(
                "Watchdog setup input does not match the selected platform",
            ));
        }
        if let Some(watchdog) = watchdog_configuration.as_ref() {
            if watchdog.protection_root_path().parent() != Some(watchdog.data_directory()) {
                return Err(composition_contract_error(
                    "Watchdog protection root parent does not match its data directory",
                ));
            }
            if watchdog.gateway_metrics_path() != gateway_configuration.telemetry_file() {
                return Err(composition_contract_error(
                    "Watchdog gateway metrics do not match Gateway telemetry",
                ));
            }
            if watchdog.runtime_installation_root()
                != node_configuration.runtime_installation_root()
            {
                return Err(composition_contract_error(
                    "Watchdog runtime installation root does not match Node model",
                ));
            }
            if watchdog.runtime_cache_root() != node_configuration.runtime_cache_root() {
                return Err(composition_contract_error(
                    "Watchdog runtime cache root does not match Node model",
                ));
            }
        }
        if roots.configuration.owner_user_id() != owner_user_id {
            return Err(composition_contract_error(
                "configuration ownership does not match Core setup",
            ));
        }
        if !is_normal_absolute_path(&openssl_command)
            || openssl_command.file_name().and_then(|name| name.to_str()) != Some("openssl")
        {
            return Err(composition_contract_error(
                "OpenSSL setup command is invalid",
            ));
        }
        if !material_paths.is_contained_by(&roots.material_root) {
            return Err(composition_contract_error(
                "private material path is outside its explicit root",
            ));
        }
        if let (
            CoreSetupPlatformInput::Linux {
                watchdog_health, ..
            },
            Some(watchdog_material),
        ) = (&platform, material_paths.watchdog_trust())
        {
            if !watchdog_health.matches(watchdog_material) {
                return Err(composition_contract_error(
                    "Watchdog health material does not match generated trust",
                ));
            }
        }
        Ok(Self {
            context,
            owner_user_id,
            roots,
            material_paths,
            configuration_provider_identity,
            cli_configuration,
            node_configuration,
            gateway_configuration,
            watchdog_configuration,
            openssl_command,
            platform,
        })
    }
}

// Describes one stable composition or setup boundary without native paths or diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupCompositionError {
    InvalidContract { reason: &'static str },
    SetupStateUnavailable,
    DatabaseUnavailable,
    MaterialUnavailable,
    BootPersistenceUnavailable,
    WatchdogCapabilityUnavailable,
    ResidentServicesUnavailable,
    Setup(CoreSetupError),
}

impl fmt::Display for CoreSetupCompositionError {
    // Presents one redacted production setup failure suitable for the installer display boundary.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "Core setup composition is invalid: {reason}")
            }
            Self::SetupStateUnavailable => {
                formatter.write_str("Core setup durable state is unavailable")
            }
            Self::DatabaseUnavailable => formatter.write_str("Core database is unavailable"),
            Self::MaterialUnavailable => {
                formatter.write_str("Core private material composition is unavailable")
            }
            Self::BootPersistenceUnavailable => {
                formatter.write_str("Core user-service boot persistence is unavailable")
            }
            Self::WatchdogCapabilityUnavailable => {
                formatter.write_str("Core Linux Watchdog hardware capability is unavailable")
            }
            Self::ResidentServicesUnavailable => {
                formatter.write_str("Core resident service composition is unavailable")
            }
            Self::Setup(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CoreSetupCompositionError {}

// Verifies the native user-service domain and boot persistence before any setup mutation.
pub trait CoreSetupPersistencePreflight: Send + Sync {
    // Proves the exact platform service domain can keep Core resident after logout and reboot.
    fn verify(
        &self,
        context: CoreUpdateServiceContext,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupCompositionError>;
}

// Performs the production systemd-linger or launchd-GUI read-only capability check.
pub struct SystemCoreSetupPersistencePreflight {
    runner: Arc<dyn CoreNativeServiceCommandRunner>,
}

impl SystemCoreSetupPersistencePreflight {
    // Creates one production preflight from the fixed shell-free native command runner.
    pub fn new() -> Self {
        Self {
            runner: Arc::new(SystemCoreNativeServiceCommandRunner),
        }
    }

    // Creates one preflight with an injected shell-free runner for deterministic verification.
    pub fn with_runner(runner: Arc<dyn CoreNativeServiceCommandRunner>) -> Self {
        Self { runner }
    }

    // Runs one exact bounded read-only native service capability command.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
    ) -> Result<crate::CoreNativeServiceCommandOutput, CoreSetupCompositionError> {
        self.runner
            .run(
                executable,
                arguments,
                PERSISTENCE_PREFLIGHT_TIMEOUT,
                PERSISTENCE_PREFLIGHT_MAXIMUM_OUTPUT_BYTES,
            )
            .map_err(|_| CoreSetupCompositionError::BootPersistenceUnavailable)
    }
}

impl Default for SystemCoreSetupPersistencePreflight {
    // Creates the ordinary production persistence preflight.
    fn default() -> Self {
        Self::new()
    }
}

impl CoreSetupPersistencePreflight for SystemCoreSetupPersistencePreflight {
    // Proves Linux user-bus lingering or the macOS graphical launchd domain without mutation.
    fn verify(
        &self,
        context: CoreUpdateServiceContext,
        owner_user_id: u32,
    ) -> Result<(), CoreSetupCompositionError> {
        match context.platform() {
            CoreUpdateServicePlatform::Linux => {
                let bus = self.run(
                    Path::new("/usr/bin/systemctl"),
                    &["--user".to_string(), "show-environment".to_string()],
                )?;
                if bus.status() != 0 {
                    return Err(CoreSetupCompositionError::BootPersistenceUnavailable);
                }
                let linger = self.run(
                    Path::new("/usr/bin/loginctl"),
                    &[
                        "show-user".to_string(),
                        owner_user_id.to_string(),
                        "--property".to_string(),
                        "Linger".to_string(),
                        "--value".to_string(),
                    ],
                )?;
                if linger.status() != 0 || single_line(linger.stdout()) != Some("yes") {
                    return Err(CoreSetupCompositionError::BootPersistenceUnavailable);
                }
                Ok(())
            }
            CoreUpdateServicePlatform::Macos => {
                let manager_user_id =
                    self.run(Path::new("/bin/launchctl"), &["manageruid".to_string()])?;
                if manager_user_id.status() != 0
                    || manager_user_id.stdout() != format!("{owner_user_id}\n").as_bytes()
                    || !manager_user_id.stderr().is_empty()
                {
                    return Err(CoreSetupCompositionError::BootPersistenceUnavailable);
                }
                let manager_name =
                    self.run(Path::new("/bin/launchctl"), &["managername".to_string()])?;
                if manager_name.status() != 0
                    || manager_name.stdout() != b"Aqua\n"
                    || !manager_name.stderr().is_empty()
                {
                    return Err(CoreSetupCompositionError::BootPersistenceUnavailable);
                }
                Ok(())
            }
        }
    }
}

// Names one redacted native Watchdog capability observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreSetupWatchdogCapabilityError {
    ProviderUnavailable,
}

// Observes the exact native capability required by the Linux Watchdog process.
pub trait CoreSetupWatchdogCapabilityPreflight: Send + Sync {
    // Returns a positive physical GPU count, unsupported capability, or provider failure.
    fn physical_device_count(&self) -> Result<Option<u32>, CoreSetupWatchdogCapabilityError>;
}

// Loads and initializes the same dynamic NVML contract used by the resident Watchdog.
#[derive(Default)]
pub struct SystemCoreSetupWatchdogCapabilityPreflight;

impl CoreSetupWatchdogCapabilityPreflight for SystemCoreSetupWatchdogCapabilityPreflight {
    // Opens NVML, resolves its ABI, initializes it, and enumerates its physical devices.
    fn physical_device_count(&self) -> Result<Option<u32>, CoreSetupWatchdogCapabilityError> {
        match DynamicWatchdogNvmlPort::open()
            .map_err(|_| CoreSetupWatchdogCapabilityError::ProviderUnavailable)?
        {
            WatchdogLinuxCapability::Available(nvml) => Ok(Some(nvml.physical_device_count())),
            WatchdogLinuxCapability::Unsupported => Ok(None),
        }
    }
}

// Isolates the complete setup transaction behind the installer-facing application boundary.
pub trait CoreSetupTransaction: Send + Sync {
    // Runs one exact durable setup request and returns its typed final result.
    fn setup(&self, request: &CoreSetupRequest) -> Result<CoreSetupResult, CoreSetupError>;
}

impl CoreSetupTransaction for CoreSetup {
    // Delegates to the production orchestration owner without changing lifecycle semantics.
    fn setup(&self, request: &CoreSetupRequest) -> Result<CoreSetupResult, CoreSetupError> {
        CoreSetup::setup(self, request)
    }
}

// Owns the production composition and the only installer-facing setup invocation surface.
pub struct ApplicationCoreSetup {
    context: CoreUpdateServiceContext,
    owner_user_id: u32,
    persistence: Arc<dyn CoreSetupPersistencePreflight>,
    watchdog_capability: Arc<dyn CoreSetupWatchdogCapabilityPreflight>,
    transaction: Arc<dyn CoreSetupTransaction>,
}

impl ApplicationCoreSetup {
    // Composes every production provider from exact installer-supplied native inputs.
    pub fn compose(input: CoreSetupCompositionInput) -> Result<Self, CoreSetupCompositionError> {
        Self::compose_with_preflights(
            input,
            Arc::new(SystemCoreSetupPersistencePreflight::new()),
            Arc::new(SystemCoreSetupWatchdogCapabilityPreflight),
        )
    }

    // Composes production providers with injected persistence and production Watchdog capability.
    pub fn compose_with_persistence_preflight(
        input: CoreSetupCompositionInput,
        persistence: Arc<dyn CoreSetupPersistencePreflight>,
    ) -> Result<Self, CoreSetupCompositionError> {
        Self::compose_with_preflights(
            input,
            persistence,
            Arc::new(SystemCoreSetupWatchdogCapabilityPreflight),
        )
    }

    // Composes production providers after both injected read-only native capability checks.
    pub fn compose_with_preflights(
        input: CoreSetupCompositionInput,
        persistence: Arc<dyn CoreSetupPersistencePreflight>,
        watchdog_capability: Arc<dyn CoreSetupWatchdogCapabilityPreflight>,
    ) -> Result<Self, CoreSetupCompositionError> {
        let context = input.context;
        let owner_user_id = input.owner_user_id;
        let database_file = input.material_paths.database_file().to_path_buf();
        let mut resident_private_roots = input.node_configuration.private_roots();
        resident_private_roots.push(input.gateway_configuration.telemetry_directory());
        if let Some(watchdog) = input.watchdog_configuration.as_ref() {
            resident_private_roots.push(watchdog.protection_root_path().to_path_buf());
        }
        if owner_user_id != unsafe { libc::geteuid() } {
            return Err(composition_contract_error(
                "configured owner does not match the effective user",
            ));
        }
        persistence.verify(context, owner_user_id)?;
        verify_watchdog_capability(context, watchdog_capability.as_ref())?;
        let configuration = input.roots.configuration.clone();
        let locks = Arc::new(
            SystemCoreSetupExecutionLockProvider::new(
                input.roots.setup_state_directory.clone(),
                owner_user_id,
            )
            .map_err(|_| CoreSetupCompositionError::SetupStateUnavailable)?,
        );
        let journal = Arc::new(
            SystemCoreSetupJournalStore::new(
                input.roots.setup_state_directory.clone(),
                owner_user_id,
            )
            .map_err(|_| CoreSetupCompositionError::SetupStateUnavailable)?,
        );
        let issuer = Arc::new(
            OpenSslCoreSetupResidentTrustIssuer::new(
                input.openssl_command,
                input.roots.trust_workspace_root,
                owner_user_id,
                Arc::new(SystemPairingNativeCommandRunner),
                Arc::new(SystemCoreSetupTrustWorkspaceIo),
            )
            .map_err(|_| CoreSetupCompositionError::MaterialUnavailable)?,
        );
        let material_io = Arc::new(
            SystemCoreSetupMaterialIo::new(input.roots.material_root, owner_user_id)
                .map_err(|_| CoreSetupCompositionError::MaterialUnavailable)?,
        );
        let materials = Arc::new(ApplicationCoreSetupMaterialProvider::new(
            input.material_paths,
            Arc::new(SystemCoreSetupMaterialEntropy),
            issuer,
            material_io,
        ));
        let configuration_inputs = Arc::new(ApplicationCoreSetupConfigurationInputProvider::new(
            input.configuration_provider_identity,
            configuration.clone(),
            input.cli_configuration,
            input.node_configuration,
            input.gateway_configuration,
            input.watchdog_configuration,
        ));
        let configurations = Arc::new(ApplicationCoreSetupConfigurationProvider::new(
            configuration.clone(),
            configuration_inputs,
        ));
        let resident_health = Arc::new(ApplicationCoreSetupResidentHealth::new(
            context.platform(),
            configuration.directory().to_path_buf(),
            owner_user_id,
            watchdog_health_tls(&input.platform, owner_user_id)?,
        ));
        let service_application = Arc::new(
            SystemCoreServiceSetupComposition::compose(
                context,
                input.roots.letsinfer_home,
                configuration.directory().to_path_buf(),
                input.roots.home_directory,
                &resident_private_roots,
                owner_user_id,
                resident_health,
            )
            .map_err(|_| CoreSetupCompositionError::ResidentServicesUnavailable)?,
        );
        let services = Arc::new(ApplicationCoreSetupServiceProvider::new(
            service_application,
        ));
        let machine_identity = machine_identity_provider(input.platform);
        let identities = Arc::new(DatabaseCoreSetupIdentityProvider::new(
            database_file,
            machine_identity,
            Arc::new(SystemCoreSetupIdentityClock),
        ));
        let transaction = CoreSetup::new(
            locks,
            journal,
            identities,
            materials,
            configurations,
            services,
        );
        Ok(Self {
            context,
            owner_user_id,
            persistence,
            watchdog_capability,
            transaction: Arc::new(transaction),
        })
    }

    // Creates one application with an injected transaction for deterministic boundary testing.
    pub fn with_transaction(
        context: CoreUpdateServiceContext,
        owner_user_id: u32,
        persistence: Arc<dyn CoreSetupPersistencePreflight>,
        watchdog_capability: Arc<dyn CoreSetupWatchdogCapabilityPreflight>,
        transaction: Arc<dyn CoreSetupTransaction>,
    ) -> Result<Self, CoreSetupCompositionError> {
        if context.role() != CoreUpdateNodeRole::Main {
            return Err(composition_contract_error(
                "initial Core setup requires the standalone main role",
            ));
        }
        Ok(Self {
            context,
            owner_user_id,
            persistence,
            watchdog_capability,
            transaction,
        })
    }

    // Returns the exact standalone-main context fixed at production composition.
    pub const fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Runs one request only when its complete platform and role match the composed application.
    pub fn setup(
        &self,
        request: &CoreSetupRequest,
    ) -> Result<CoreSetupResult, CoreSetupCompositionError> {
        self.validate_request(request)?;
        self.persistence.verify(self.context, self.owner_user_id)?;
        verify_watchdog_capability(self.context, self.watchdog_capability.as_ref())?;
        self.transaction
            .setup(request)
            .map_err(CoreSetupCompositionError::Setup)
    }

    // Encodes the typed result as the closed newline-terminated installer JSON contract.
    pub fn setup_json(
        &self,
        request: &CoreSetupRequest,
    ) -> Result<Vec<u8>, CoreSetupCompositionError> {
        self.setup(request)?
            .encoded_json()
            .map_err(CoreSetupCompositionError::Setup)
    }

    // Rejects child initialization and platform substitution before entering the transaction.
    fn validate_request(
        &self,
        request: &CoreSetupRequest,
    ) -> Result<(), CoreSetupCompositionError> {
        if request.context() != self.context || request.context().role() != CoreUpdateNodeRole::Main
        {
            return Err(composition_contract_error(
                "setup request does not match the composed standalone main",
            ));
        }
        Ok(())
    }
}

// Requires exact Linux NVML initialization and device enumeration without probing it on macOS.
fn verify_watchdog_capability(
    context: CoreUpdateServiceContext,
    capability: &dyn CoreSetupWatchdogCapabilityPreflight,
) -> Result<(), CoreSetupCompositionError> {
    if context.platform() == CoreUpdateServicePlatform::Macos {
        return Ok(());
    }
    match capability.physical_device_count() {
        Ok(Some(count)) if count > 0 => Ok(()),
        Ok(Some(_) | None) | Err(CoreSetupWatchdogCapabilityError::ProviderUnavailable) => {
            Err(CoreSetupCompositionError::WatchdogCapabilityUnavailable)
        }
    }
}

// Parses one exact optional-line command response without accepting control or extra lines.
fn single_line(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.contains(['\n', '\r']) {
        return None;
    }
    Some(text)
}

// Loads process-owned health inputs only after configuration and material are committed.
struct ApplicationCoreSetupResidentHealth {
    platform: CoreUpdateServicePlatform,
    configuration_root: PathBuf,
    owner_user_id: u32,
    watchdog_health_tls: Option<CoreWatchdogHealthTlsFiles>,
}

impl ApplicationCoreSetupResidentHealth {
    // Creates one lazy health router without reading configuration or credential files early.
    const fn new(
        platform: CoreUpdateServicePlatform,
        configuration_root: PathBuf,
        owner_user_id: u32,
        watchdog_health_tls: Option<CoreWatchdogHealthTlsFiles>,
    ) -> Self {
        Self {
            platform,
            configuration_root,
            owner_user_id,
            watchdog_health_tls,
        }
    }

    // Routes one resident observation with the optional exact setup Node identity.
    fn observe_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if context.platform() != self.platform || timeout.is_zero() {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "resident health request does not match setup composition",
            });
        }
        match process {
            CoreResidentProcess::Node => CoreNodeServiceHealth::load(
                self.configuration_root.join(NODE_CONFIGURATION_FILENAME),
                self.owner_user_id,
            )?
            .observe_with_identity(context, process, identity, timeout),
            CoreResidentProcess::Gateway => CoreGatewayServiceHealth::load(
                self.configuration_root.join(GATEWAY_CONFIGURATION_FILENAME),
                self.owner_user_id,
            )?
            .observe(context, process, timeout),
            CoreResidentProcess::Watchdog => {
                let files = self.watchdog_health_tls.clone().ok_or(
                    CoreServiceSetupError::InvalidContract {
                        reason: "Watchdog health material is unavailable",
                    },
                )?;
                CoreWatchdogServiceHealth::load(
                    self.configuration_root
                        .join(WATCHDOG_CONFIGURATION_FILENAME),
                    self.owner_user_id,
                    files,
                )?
                .observe(context, process, timeout)
            }
        }
    }
}

impl CoreServiceSetupResidentHealth for ApplicationCoreSetupResidentHealth {
    // Routes each independently supervised service through its exact production health contract.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.observe_identity(context, process, None, timeout)
    }

    // Preserves the prepared setup identity only for the Node readiness observation.
    fn observe_with_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.observe_identity(context, process, identity, timeout)
    }
}

// Builds the exact native machine identity source selected by the validated platform input.
fn machine_identity_provider(
    platform: CoreSetupPlatformInput,
) -> Arc<dyn crate::CoreSetupMachineIdentityProvider> {
    match platform {
        CoreSetupPlatformInput::Linux {
            machine_identity_file: _,
            ..
        } => Arc::new(LinuxCoreSetupMachineIdentityProvider::system(Arc::new(
            SystemCoreSetupMachineIdentityFileReader,
        ))),
        CoreSetupPlatformInput::Macos {
            machine_identity_command,
            command_timeout,
            command_poll_interval,
        } => Arc::new(MacosCoreSetupMachineIdentityProvider::system(
            machine_identity_command,
            command_timeout,
            command_poll_interval,
            Arc::new(SystemCoreSetupMachineIdentityCommandRunner),
        )),
    }
}

// Projects the Linux-only health credentials without allowing a macOS Watchdog fallback.
fn watchdog_health_tls(
    platform: &CoreSetupPlatformInput,
    owner_user_id: u32,
) -> Result<Option<CoreWatchdogHealthTlsFiles>, CoreSetupCompositionError> {
    match platform {
        CoreSetupPlatformInput::Linux {
            watchdog_health, ..
        } => watchdog_health.tls_files(owner_user_id).map(Some),
        CoreSetupPlatformInput::Macos { .. } => Ok(None),
    }
}

// Returns whether one native path is canonical absolute UTF-8 without redundant components.
fn is_normal_absolute_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && text.starts_with('/')
        && text.len() > 1
        && !text.ends_with('/')
        && !text.contains("//")
        && !text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Creates one stable contract error before any production provider performs native work.
const fn composition_contract_error(reason: &'static str) -> CoreSetupCompositionError {
    CoreSetupCompositionError::InvalidContract { reason }
}
