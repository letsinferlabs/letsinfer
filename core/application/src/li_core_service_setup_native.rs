// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode,
    SystemGatewayNativeFileIo,
};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationFileReference, SystemNodeConfigurationFileProvider,
};
use li_watchdog_manager::{SystemWatchdogConfigurationFileProvider, WatchdogConfigurationLoader};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner, CoreProcessPlatform,
    CoreResidentProcess, CoreResidentProcessCommand, CoreServiceCutoverProvider,
    CoreServiceDefinition, CoreServiceSetup, CoreServiceSetupError, CoreServiceSetupHealthProvider,
    CoreServiceSetupNodeIdentity, CoreServiceSetupObservation, CoreServiceSetupPreflight,
    DurableCoreServiceCutoverProvider, SystemCoreNativeServiceCommandRunner,
    SystemCoreNativeServiceIo, SystemCoreNativeServiceSupervisor, SystemCoreServiceCutoverFileIo,
    SystemCoreServiceCutoverNativeHost, SystemCoreServiceCutoverStore,
};

const CORE_RELEASE_MANIFEST_NAME: &str = "li_core_release_manifest_v1.json";
const CORE_RELEASE_MANIFEST_SCHEMA_NAME: &str = "li_core_release_manifest";
const CORE_RELEASE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_RELEASE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_RESIDENT_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const NATIVE_COMMAND_TIMEOUT_SECONDS: u64 = 5;
const NATIVE_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const IMMUTABLE_FILE_MODE: u32 = 0o444;
const IMMUTABLE_EXECUTABLE_MODE: u32 = 0o555;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MAXIMUM_SOURCE_FILES: usize = 20_000;
const MAXIMUM_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;

// Supplies role-aware health without conflating an unavailable check with success.
pub trait CoreServiceSetupResidentHealth: Send + Sync {
    // Observes one resident through its concrete process-owned health contract.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError>;

    // Adds setup-owned identity binding while preserving role-only non-setup observations.
    fn observe_with_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        _identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.observe(context, process, timeout)
    }
}

// Verifies exact resident inputs and the native user service-manager capability.
pub struct SystemCoreServiceSetupPreflight {
    platform: CoreProcessPlatform,
    service_root: PathBuf,
    owner_user_id: u32,
    runner: Arc<dyn CoreNativeServiceCommandRunner>,
}

impl SystemCoreServiceSetupPreflight {
    // Creates one preflight only for the effective user and a canonical existing service root.
    pub fn new(
        platform: CoreProcessPlatform,
        service_root: PathBuf,
        owner_user_id: u32,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
    ) -> Result<Self, CoreServiceSetupError> {
        require_effective_owner(owner_user_id)?;
        validate_owned_directory(&service_root, owner_user_id)?;
        Ok(Self {
            platform,
            service_root,
            owner_user_id,
            runner,
        })
    }

    // Executes one bounded fixed native preflight command without a shell.
    fn run(
        &self,
        executable: &Path,
        arguments: Vec<String>,
    ) -> Result<CoreNativeServiceCommandOutput, CoreServiceSetupError> {
        self.runner
            .run(
                executable,
                &arguments,
                Duration::from_secs(NATIVE_COMMAND_TIMEOUT_SECONDS),
                NATIVE_COMMAND_OUTPUT_BYTES,
            )
            .map_err(|_| preflight_error("native service capability is unavailable"))
    }

    // Proves the active user systemd bus and exact lingering state.
    fn verify_systemd(&self) -> Result<(), CoreServiceSetupError> {
        if self
            .run(
                Path::new("/usr/bin/systemctl"),
                vec!["--user".to_string(), "show-environment".to_string()],
            )?
            .status()
            != 0
        {
            return Err(preflight_error("systemd user bus is unavailable"));
        }
        let linger = self.run(
            Path::new("/usr/bin/loginctl"),
            vec![
                "show-user".to_string(),
                self.owner_user_id.to_string(),
                "--property".to_string(),
                "Linger".to_string(),
                "--value".to_string(),
            ],
        )?;
        if linger.status() != 0 || output_text(&linger)? != "yes" {
            return Err(preflight_error("systemd user lingering is unavailable"));
        }
        Ok(())
    }

    // Proves the active launchd graphical user domain.
    fn verify_launchd(&self) -> Result<(), CoreServiceSetupError> {
        let manager_user_id =
            self.run(Path::new("/bin/launchctl"), vec!["manageruid".to_string()])?;
        if manager_user_id.status() != 0
            || manager_user_id.stdout() != format!("{}\n", self.owner_user_id).as_bytes()
            || !manager_user_id.stderr().is_empty()
        {
            return Err(preflight_error("launchd GUI domain is unavailable"));
        }
        let manager_name =
            self.run(Path::new("/bin/launchctl"), vec!["managername".to_string()])?;
        if manager_name.status() != 0
            || manager_name.stdout() != b"Aqua\n"
            || !manager_name.stderr().is_empty()
        {
            return Err(preflight_error("launchd GUI domain is unavailable"));
        }
        Ok(())
    }

    // Loads every process-owned closed configuration through its production parser.
    fn verify_configurations(
        &self,
        context: CoreUpdateServiceContext,
        commands: &[CoreResidentProcessCommand],
    ) -> Result<(), CoreServiceSetupError> {
        for command in commands {
            match command.process() {
                CoreResidentProcess::Node => {
                    let reference = NodeConfigurationFileReference::new(
                        command.configuration().to_path_buf(),
                        self.owner_user_id,
                    )
                    .map_err(|_| preflight_error("Node configuration is invalid"))?;
                    NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider)
                        .map_err(|_| preflight_error("Node configuration is invalid"))?;
                }
                CoreResidentProcess::Gateway => {
                    let reference = GatewayConfigurationFile::new(
                        self.owner_user_id,
                        command.configuration().to_path_buf(),
                    )
                    .map_err(|_| preflight_error("Gateway configuration is invalid"))?;
                    let configuration =
                        GatewayConfiguration::load(&reference, &SystemGatewayNativeFileIo)
                            .map_err(|_| preflight_error("Gateway configuration is invalid"))?;
                    let expected_mode = match context.role() {
                        CoreUpdateNodeRole::Main => GatewayConfigurationMode::Main,
                        CoreUpdateNodeRole::Child => GatewayConfigurationMode::Child,
                    };
                    if configuration.mode() != expected_mode {
                        return Err(preflight_error(
                            "Gateway configuration does not match the node role",
                        ));
                    }
                }
                CoreResidentProcess::Watchdog => {
                    WatchdogConfigurationLoader::new(
                        command.configuration().to_path_buf(),
                        self.owner_user_id,
                        Box::new(SystemWatchdogConfigurationFileProvider),
                    )
                    .and_then(|loader| loader.load())
                    .map_err(|_| preflight_error("Watchdog configuration is invalid"))?;
                }
            }
        }
        Ok(())
    }
}

impl CoreServiceSetupPreflight for SystemCoreServiceSetupPreflight {
    // Verifies immutable binaries, configurations, service root, and native user domain.
    fn verify(
        &self,
        context: CoreUpdateServiceContext,
        installation: &CoreInstallation,
        commands: &[CoreResidentProcessCommand],
    ) -> Result<(), CoreServiceSetupError> {
        require_effective_owner(self.owner_user_id)?;
        if process_platform(context.platform()) != self.platform || commands.is_empty() {
            return Err(preflight_error("resident preflight platform is invalid"));
        }
        validate_owned_directory(&self.service_root, self.owner_user_id)?;
        verify_immutable_residents(self.platform, installation, commands, self.owner_user_id)?;
        self.verify_configurations(context, commands)?;
        match self.platform {
            CoreProcessPlatform::Linux => self.verify_systemd(),
            CoreProcessPlatform::Macos => self.verify_launchd(),
        }
    }
}

// Combines exact role health with the native systemd memory counter.
pub struct SystemCoreServiceSetupHealthProvider {
    platform: CoreProcessPlatform,
    runner: Arc<dyn CoreNativeServiceCommandRunner>,
    resident: Arc<dyn CoreServiceSetupResidentHealth>,
}

impl SystemCoreServiceSetupHealthProvider {
    // Creates one health provider without substituting a placeholder role-health implementation.
    pub fn new(
        platform: CoreProcessPlatform,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
        resident: Arc<dyn CoreServiceSetupResidentHealth>,
    ) -> Self {
        Self {
            platform,
            runner,
            resident,
        }
    }
}

impl CoreServiceSetupHealthProvider for SystemCoreServiceSetupHealthProvider {
    // Delegates each exact role to the process-owned concrete health adapter.
    fn resident_health(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if process_platform(context.platform()) != self.platform || timeout.is_zero() {
            return Err(preflight_error("resident health contract is invalid"));
        }
        self.resident.observe(context, process, timeout)
    }

    // Preserves one exact setup Node identity through the native health router.
    fn resident_health_with_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if process_platform(context.platform()) != self.platform || timeout.is_zero() {
            return Err(preflight_error("resident health contract is invalid"));
        }
        self.resident
            .observe_with_identity(context, process, identity, timeout)
    }

    // Compares systemd MemoryCurrent with the exact ceiling emitted into the same definition.
    fn memory_envelope(
        &self,
        context: CoreUpdateServiceContext,
        definition: &CoreServiceDefinition,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if process_platform(context.platform()) != self.platform || timeout.is_zero() {
            return Err(preflight_error("resident memory contract is invalid"));
        }
        let Some(maximum) = definition.memory_max_bytes() else {
            return Ok(CoreServiceSetupObservation::Unsupported);
        };
        let output = self
            .runner
            .run(
                Path::new("/usr/bin/systemctl"),
                &[
                    "--user".to_string(),
                    "show".to_string(),
                    definition.service_identity().to_string(),
                    "--property".to_string(),
                    "MemoryCurrent".to_string(),
                    "--value".to_string(),
                ],
                timeout.min(Duration::from_secs(NATIVE_COMMAND_TIMEOUT_SECONDS)),
                NATIVE_COMMAND_OUTPUT_BYTES,
            )
            .map_err(|_| preflight_error("resident memory could not be observed"))?;
        let current = output_text(&output)?
            .parse::<u64>()
            .map_err(|_| preflight_error("resident memory counter is invalid"))?;
        if output.status() != 0 {
            return Err(preflight_error("resident memory could not be observed"));
        }
        Ok(if current < maximum {
            CoreServiceSetupObservation::Ready
        } else {
            CoreServiceSetupObservation::NotReady
        })
    }
}

// Owns the fully wired production setup transaction while leaving role health explicit.
pub struct SystemCoreServiceSetupComposition;

impl SystemCoreServiceSetupComposition {
    // Safely creates required private roots and composes supervisor, store, host, and setup.
    #[allow(clippy::too_many_arguments)]
    pub fn compose(
        context: CoreUpdateServiceContext,
        letsinfer_home: PathBuf,
        configuration_root: PathBuf,
        home_directory: PathBuf,
        required_private_roots: &[PathBuf],
        owner_user_id: u32,
        resident_health: Arc<dyn CoreServiceSetupResidentHealth>,
    ) -> Result<CoreServiceSetup, CoreServiceSetupError> {
        require_effective_owner(owner_user_id)?;
        let platform = process_platform(context.platform());
        let mut private_roots = required_private_roots.to_vec();
        if platform == CoreProcessPlatform::Macos {
            private_roots.push(letsinfer_home.join("logs"));
        }
        validate_required_private_roots(&letsinfer_home, &private_roots, owner_user_id)?;
        let service_root = service_root(platform, &home_directory);
        create_owned_directory_chain(&home_directory, &service_root, owner_user_id)?;
        create_private_directory_chain(
            &letsinfer_home,
            &letsinfer_home.join("state").join("service_cutover"),
            owner_user_id,
        )?;
        for root in &private_roots {
            create_private_directory_chain(&letsinfer_home, root, owner_user_id)?;
        }
        let executable = match platform {
            CoreProcessPlatform::Linux => PathBuf::from("/usr/bin/systemctl"),
            CoreProcessPlatform::Macos => PathBuf::from("/bin/launchctl"),
        };
        let runner: Arc<dyn CoreNativeServiceCommandRunner> =
            Arc::new(SystemCoreNativeServiceCommandRunner);
        let supervisor = Arc::new(
            SystemCoreNativeServiceSupervisor::new(
                platform,
                home_directory.clone(),
                owner_user_id,
                executable.clone(),
                runner.clone(),
                Arc::new(SystemCoreNativeServiceIo),
            )
            .map_err(|_| preflight_error("native supervisor could not be composed"))?,
        );
        let store = Arc::new(SystemCoreServiceCutoverStore::new(
            letsinfer_home.clone(),
            owner_user_id,
        )?);
        let host = Arc::new(SystemCoreServiceCutoverNativeHost::new(
            context.platform(),
            home_directory,
            owner_user_id,
            executable,
            runner.clone(),
            Arc::new(SystemCoreServiceCutoverFileIo),
        )?);
        let cutover: Arc<dyn CoreServiceCutoverProvider> =
            Arc::new(DurableCoreServiceCutoverProvider::new(store, host));
        let preflight = Arc::new(SystemCoreServiceSetupPreflight::new(
            platform,
            service_root,
            owner_user_id,
            runner.clone(),
        )?);
        let health = Arc::new(SystemCoreServiceSetupHealthProvider::new(
            platform,
            runner,
            resident_health,
        ));
        CoreServiceSetup::new(
            context,
            letsinfer_home,
            configuration_root,
            supervisor,
            cutover,
            preflight,
            health,
        )
    }
}

// Validates the complete private-root plan before setup creates any native directory.
fn validate_required_private_roots(
    letsinfer_home: &Path,
    required_private_roots: &[PathBuf],
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    if !is_safe_absolute_path(letsinfer_home)
        || required_private_roots.iter().any(|path| {
            !is_safe_absolute_path(path)
                || path == letsinfer_home
                || !path.starts_with(letsinfer_home)
        })
        || required_private_roots
            .iter()
            .enumerate()
            .any(|(index, path)| {
                required_private_roots[..index]
                    .iter()
                    .any(|other| path.starts_with(other) || other.starts_with(path))
            })
    {
        return Err(preflight_error("private service directory plan is invalid"));
    }
    validate_private_directory(letsinfer_home, owner_user_id)?;
    for destination in required_private_roots {
        validate_existing_private_directory_prefix(letsinfer_home, destination, owner_user_id)?;
    }
    Ok(())
}

// Rejects every existing non-private path component while allowing one missing suffix.
fn validate_existing_private_directory_prefix(
    existing_root: &Path,
    destination: &Path,
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    let relative = destination
        .strip_prefix(existing_root)
        .map_err(|_| preflight_error("private service directory plan is invalid"))?;
    let mut current = existing_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(preflight_error("private service directory plan is invalid"));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => validate_private_directory(&current, owner_user_id)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(preflight_error("service directory is unavailable")),
        }
    }
    Ok(())
}

// Stores the closed native Core release manifest used for resident binary verification.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseManifestDocument {
    schema: CoreReleaseManifestSchema,
    release: CoreReleaseManifestRelease,
    platform: CoreReleaseManifestPlatform,
    files: Vec<CoreReleaseManifestFile>,
}

// Stores the exact native Core release manifest schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseManifestSchema {
    name: String,
    version: u32,
}

// Stores the exact native Core release version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseManifestRelease {
    version: String,
}

// Stores one supported native Core release platform.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseManifestPlatform {
    os: String,
    architecture: String,
}

// Stores one exact native Core release file record.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseManifestFile {
    path: String,
    bytes: u64,
    mode: u32,
    sha256: String,
}

// Carries one normalized executable record from the signed native release manifest.
struct ResidentManifestRecord {
    bytes: u64,
    mode: u32,
    sha256: Sha256Digest,
}

// Verifies every required resident binary against the exact native release identity.
fn verify_immutable_residents(
    platform: CoreProcessPlatform,
    installation: &CoreInstallation,
    commands: &[CoreResidentProcessCommand],
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    let root = installation_root(commands)?;
    validate_immutable_root(&root, owner_user_id)?;
    validate_immutable_directory(&root.join("bin"), owner_user_id)?;
    let manifest = read_exact_file(
        &root.join(CORE_RELEASE_MANIFEST_NAME),
        owner_user_id,
        IMMUTABLE_FILE_MODE,
        MAXIMUM_RELEASE_MANIFEST_BYTES,
    )?;
    if digest(&manifest)? != *installation.source_identity() {
        return Err(preflight_error(
            "Core release identity does not match its manifest",
        ));
    }
    let records = resident_manifest_records(&manifest, installation, platform)?;
    let mut observed = BTreeSet::new();
    for command in commands {
        let relative = PathBuf::from("bin").join(command.process().executable_name());
        if !observed.insert(relative.clone()) {
            return Err(preflight_error(
                "resident executable identity is duplicated",
            ));
        }
        let record = records
            .get(&relative)
            .ok_or_else(|| preflight_error("resident executable is absent from the manifest"))?;
        if command.executable() != root.join(&relative) {
            return Err(preflight_error("resident executable path is invalid"));
        }
        let binary = read_exact_file(
            command.executable(),
            owner_user_id,
            IMMUTABLE_EXECUTABLE_MODE,
            MAXIMUM_RESIDENT_BINARY_BYTES,
        )?;
        if record.mode != 0o755
            || binary.len() as u64 != record.bytes
            || digest(&binary)? != record.sha256
        {
            return Err(preflight_error("resident executable identity is invalid"));
        }
    }
    Ok(())
}

// Parses one closed native release manifest and selects unique executable records.
fn resident_manifest_records(
    bytes: &[u8],
    installation: &CoreInstallation,
    platform: CoreProcessPlatform,
) -> Result<BTreeMap<PathBuf, ResidentManifestRecord>, CoreServiceSetupError> {
    let document: CoreReleaseManifestDocument = serde_json::from_slice(bytes)
        .map_err(|_| preflight_error("Core release manifest is invalid"))?;
    if document.schema.name != CORE_RELEASE_MANIFEST_SCHEMA_NAME
        || document.schema.version != CORE_RELEASE_MANIFEST_SCHEMA_VERSION
        || document.release.version != installation.version().as_str()
        || !release_platform_matches(platform, &document.platform)
        || document.files.is_empty()
        || document.files.len() > MAXIMUM_SOURCE_FILES
    {
        return Err(preflight_error("Core release manifest is invalid"));
    }
    let mut records = BTreeMap::new();
    let mut total_bytes = 0_u64;
    for file in document.files {
        let path = PathBuf::from(file.path);
        if !is_safe_relative_path(&path)
            || path == Path::new(CORE_RELEASE_MANIFEST_NAME)
            || !matches!(file.mode, 0o644 | 0o755)
        {
            return Err(preflight_error("Core release manifest is invalid"));
        }
        total_bytes = total_bytes
            .checked_add(file.bytes)
            .filter(|value| *value <= MAXIMUM_SOURCE_BYTES)
            .ok_or_else(|| preflight_error("Core release manifest is invalid"))?;
        let sha256 = Sha256Digest::parse(&file.sha256)
            .map_err(|_| preflight_error("Core release manifest is invalid"))?;
        if records
            .insert(
                path,
                ResidentManifestRecord {
                    bytes: file.bytes,
                    mode: file.mode,
                    sha256,
                },
            )
            .is_some()
        {
            return Err(preflight_error("Core release manifest path is duplicated"));
        }
    }
    Ok(records)
}

// Requires one manifest platform supported by the selected native service implementation.
fn release_platform_matches(
    platform: CoreProcessPlatform,
    manifest: &CoreReleaseManifestPlatform,
) -> bool {
    match platform {
        CoreProcessPlatform::Linux => {
            manifest.os == "linux" && matches!(manifest.architecture.as_str(), "arm64" | "x86_64")
        }
        CoreProcessPlatform::Macos => manifest.os == "macos" && manifest.architecture == "arm64",
    }
}

// Requires one exact immutable owner-bound installation root.
fn validate_immutable_root(path: &Path, owner_user_id: u32) -> Result<(), CoreServiceSetupError> {
    validate_owned_directory(path, owner_user_id)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| preflight_error("resident installation root is unavailable"))?;
    if metadata.permissions().mode() & 0o777 != IMMUTABLE_EXECUTABLE_MODE {
        return Err(preflight_error(
            "resident installation root is not immutable",
        ));
    }
    Ok(())
}

// Requires one owner-bound symlink-free immutable directory beneath an installation root.
fn validate_immutable_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    validate_owned_directory(path, owner_user_id)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| preflight_error("resident installation directory is unavailable"))?;
    if metadata.permissions().mode() & 0o777 != IMMUTABLE_EXECUTABLE_MODE {
        return Err(preflight_error(
            "resident installation directory is not immutable",
        ));
    }
    Ok(())
}

// Derives one common installation root from the complete resident command set.
fn installation_root(
    commands: &[CoreResidentProcessCommand],
) -> Result<PathBuf, CoreServiceSetupError> {
    let first = commands
        .first()
        .and_then(|command| command.executable().parent())
        .and_then(Path::parent)
        .ok_or_else(|| preflight_error("resident installation root is invalid"))?
        .to_path_buf();
    if commands.iter().any(|command| {
        command
            .executable()
            .parent()
            .and_then(Path::parent)
            .is_none_or(|root| root != first)
    }) {
        return Err(preflight_error("resident installation roots are ambiguous"));
    }
    Ok(first)
}

// Reads one bounded owner-bound immutable file through a no-follow stable descriptor.
fn read_exact_file(
    path: &Path,
    owner_user_id: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, CoreServiceSetupError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| preflight_error("resident input is unavailable"))?;
    let before = file
        .metadata()
        .map_err(|_| preflight_error("resident input metadata is unavailable"))?;
    if !before.file_type().is_file()
        || before.uid() != owner_user_id
        || before.nlink() != 1
        || before.permissions().mode() & 0o777 != mode
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(preflight_error("resident input identity is unsafe"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| preflight_error("resident input could not be read"))?;
    let after = file
        .metadata()
        .map_err(|_| preflight_error("resident input metadata is unavailable"))?;
    if bytes.is_empty()
        || bytes.len() as u64 != before.len()
        || bytes.len() as u64 > maximum_bytes
        || !after.file_type().is_file()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(preflight_error("resident input changed while it was read"));
    }
    Ok(bytes)
}

// Creates missing private directories without accepting any existing symlink or unsafe owner.
fn create_owned_directory_chain(
    existing_root: &Path,
    destination: &Path,
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    create_directory_chain(existing_root, destination, owner_user_id, false)
}

// Creates one owner-only directory chain and rejects every pre-existing permissive component.
fn create_private_directory_chain(
    existing_root: &Path,
    destination: &Path,
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    create_directory_chain(existing_root, destination, owner_user_id, true)
}

// Creates one validated directory chain through the requested ownership policy.
fn create_directory_chain(
    existing_root: &Path,
    destination: &Path,
    owner_user_id: u32,
    require_private_mode: bool,
) -> Result<(), CoreServiceSetupError> {
    if !is_safe_absolute_path(existing_root)
        || !is_safe_absolute_path(destination)
        || !destination.starts_with(existing_root)
    {
        return Err(preflight_error("service directory path is invalid"));
    }
    if require_private_mode {
        validate_private_directory(existing_root, owner_user_id)?;
    } else {
        validate_owned_directory(existing_root, owner_user_id)?;
    }
    let relative = destination
        .strip_prefix(existing_root)
        .map_err(|_| preflight_error("service directory path is invalid"))?;
    let mut current = existing_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(preflight_error("service directory path is invalid"));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) if require_private_mode => validate_private_directory(&current, owner_user_id)?,
            Ok(_) => validate_owned_directory(&current, owner_user_id)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|_| preflight_error("service directory could not be created"))?;
                fs::set_permissions(&current, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                    .map_err(|_| preflight_error("service directory mode could not be set"))?;
                if require_private_mode {
                    validate_private_directory(&current, owner_user_id)?;
                } else {
                    validate_owned_directory(&current, owner_user_id)?;
                }
                sync_directory(
                    current
                        .parent()
                        .ok_or_else(|| preflight_error("service directory path is invalid"))?,
                )?;
            }
            Err(_) => return Err(preflight_error("service directory is unavailable")),
        }
    }
    Ok(())
}

// Requires one exact owner-only directory while preserving the broader native service policy.
fn validate_private_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    validate_owned_directory(path, owner_user_id)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| preflight_error("service directory is unavailable"))?;
    if metadata.permissions().mode() & 0o7777 != PRIVATE_DIRECTORY_MODE {
        return Err(preflight_error("service directory identity is unsafe"));
    }
    Ok(())
}

// Requires one exact owner-controlled non-writable directory and a symlink-free component chain.
fn validate_owned_directory(path: &Path, owner_user_id: u32) -> Result<(), CoreServiceSetupError> {
    if !is_safe_absolute_path(path) {
        return Err(preflight_error("service directory path is invalid"));
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(component) = component else {
            return Err(preflight_error("service directory path is invalid"));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| preflight_error("service directory is unavailable"))?;
        if !metadata.file_type().is_dir() {
            return Err(preflight_error("service directory identity is unsafe"));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| preflight_error("service directory is unavailable"))?;
    if metadata.uid() != owner_user_id || metadata.permissions().mode() & 0o022 != 0 {
        return Err(preflight_error("service directory identity is unsafe"));
    }
    Ok(())
}

// Persists one newly created child directory through its already-validated parent.
fn sync_directory(path: &Path) -> Result<(), CoreServiceSetupError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| preflight_error("service directory could not be persisted"))
}

// Returns the canonical per-user native service root for one platform.
fn service_root(platform: CoreProcessPlatform, home_directory: &Path) -> PathBuf {
    match platform {
        CoreProcessPlatform::Linux => home_directory.join(".config/systemd/user"),
        CoreProcessPlatform::Macos => home_directory.join("Library/LaunchAgents"),
    }
}

// Requires composition to target the effective user used by the native command environment.
fn require_effective_owner(owner_user_id: u32) -> Result<(), CoreServiceSetupError> {
    if owner_user_id != unsafe { libc::geteuid() } {
        return Err(preflight_error(
            "configured owner does not match the effective user",
        ));
    }
    Ok(())
}

// Maps one update platform identity to its resident process platform.
const fn process_platform(platform: CoreUpdateServicePlatform) -> CoreProcessPlatform {
    match platform {
        CoreUpdateServicePlatform::Linux => CoreProcessPlatform::Linux,
        CoreUpdateServicePlatform::Macos => CoreProcessPlatform::Macos,
    }
}

// Returns one bounded UTF-8 command output without accepting additional lines.
fn output_text(output: &CoreNativeServiceCommandOutput) -> Result<&str, CoreServiceSetupError> {
    let text = std::str::from_utf8(output.stdout())
        .map(str::trim)
        .map_err(|_| preflight_error("native service output is invalid"))?;
    if text.is_empty() || text.lines().count() != 1 {
        return Err(preflight_error("native service output is invalid"));
    }
    Ok(text)
}

// Computes one canonical lower-hex SHA-256 identity.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, CoreServiceSetupError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| preflight_error("resident input digest is invalid"))
}

// Returns whether one source-manifest path contains only ordinary relative components.
fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

// Returns whether one path is absolute and already lexically normalized.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Creates one stable redacted production-preflight failure.
const fn preflight_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::provider("service preflight", reason)
}
