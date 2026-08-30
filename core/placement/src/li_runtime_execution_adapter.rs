// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{EndpointOwnership, Placement, Sha256Digest};
use li_runtime_manager::{
    RuntimeExecutionDistribution, RuntimeExecutionManifest, RuntimeExecutionManifestProvider,
    RuntimeExecutionPlatform, RuntimeExecutionReadiness, RuntimeExecutionTask, RuntimeTaskLauncher,
};
use sha2::{Digest, Sha256};

use crate::{
    LinuxRuntimeLaunchTemplate, MacosRuntimeLaunchTemplate, PlacementError,
    RuntimePlacementExecution, RuntimePlacementExecutionProvider, RuntimePlacementReadiness,
    RuntimeServingContract, ShellFreeCommand, ShellFreeEnvironmentValue,
};

const ENGINE_ADAPTER: &str = "/opt/letsinfer/bin/engine-adapter";
const TEMPORARY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAXIMUM_NATIVE_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

// Supplies fixed host-owned Linux process inputs outside runtime artifact authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxRuntimePlacementEnvironment {
    docker: ShellFreeCommand,
    temporary_bytes: u64,
    user_id: u32,
    group_id: u32,
    device_nodes: Vec<PathBuf>,
    additional_labels: BTreeMap<String, String>,
    additional_options: Vec<String>,
}

impl LinuxRuntimePlacementEnvironment {
    // Creates one explicit Linux host execution environment without probing native state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        docker: ShellFreeCommand,
        temporary_bytes: u64,
        user_id: u32,
        group_id: u32,
        device_nodes: Vec<PathBuf>,
        additional_labels: BTreeMap<String, String>,
        additional_options: Vec<String>,
    ) -> Result<Self, PlacementError> {
        if temporary_bytes == 0 || user_id == 0 || group_id == 0 {
            return Err(PlacementError::InvalidRequest {
                reason: "Linux runtime placement environment is incomplete",
            });
        }
        Ok(Self {
            docker,
            temporary_bytes,
            user_id,
            group_id,
            device_nodes,
            additional_labels,
            additional_options,
        })
    }

    // Creates the ordinary bounded Linux environment with no extra device policy.
    pub fn ordinary(
        docker: ShellFreeCommand,
        user_id: u32,
        group_id: u32,
    ) -> Result<Self, PlacementError> {
        Self::new(
            docker,
            TEMPORARY_BYTES,
            user_id,
            group_id,
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
    }
}

// Supplies the verified content identity of one resolved native runtime executable.
pub trait MacosRuntimeExecutableIdentityProvider: Send + Sync {
    // Hashes one exact executable only after RuntimeManager returned a verified manifest.
    fn identity(&self, executable: &Path) -> Result<Sha256Digest, PlacementError>;
}

// Reads one stable owner-controlled executable through a no-follow descriptor.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemMacosRuntimeExecutableIdentityProvider;

impl MacosRuntimeExecutableIdentityProvider for SystemMacosRuntimeExecutableIdentityProvider {
    // Binds the resolved command to the exact executable bytes present during plan sealing.
    fn identity(&self, executable: &Path) -> Result<Sha256Digest, PlacementError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(executable)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        let before = file
            .metadata()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if !before.is_file()
            || before.uid() != unsafe { libc::geteuid() }
            || before.permissions().mode() & 0o111 == 0
            || before.permissions().mode() & 0o022 != 0
            || before.len() == 0
            || before.len() > MAXIMUM_NATIVE_EXECUTABLE_BYTES
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut digest = Sha256::new();
        let copied = std::io::copy(
            &mut file.by_ref().take(MAXIMUM_NATIVE_EXECUTABLE_BYTES + 1),
            &mut digest,
        )
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
        let after = file
            .metadata()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if copied != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Sha256Digest::parse(&format!("{:x}", digest.finalize()))
            .map_err(|_| PlacementError::ExecutionUnavailable)
    }
}

// Marks that verified native executable Engine adapters may run on a macOS host.
#[derive(Clone)]
pub struct MacosRuntimePlacementEnvironment {
    executable_identities: Arc<dyn MacosRuntimeExecutableIdentityProvider>,
}

impl MacosRuntimePlacementEnvironment {
    // Creates the production macOS executable-identity capability.
    pub fn new() -> Self {
        Self {
            executable_identities: Arc::new(SystemMacosRuntimeExecutableIdentityProvider),
        }
    }

    // Creates one deterministic environment from an injected executable-identity provider.
    pub fn with_executable_identity_provider(
        executable_identities: Arc<dyn MacosRuntimeExecutableIdentityProvider>,
    ) -> Self {
        Self {
            executable_identities,
        }
    }
}

impl Default for MacosRuntimePlacementEnvironment {
    // Uses the production no-follow executable identity provider.
    fn default() -> Self {
        Self::new()
    }
}

// Adapts RuntimeManager's verified task result into PlacementManager launch inputs.
pub struct RuntimeManagerPlacementExecutionAdapter {
    manifests: Arc<dyn RuntimeExecutionManifestProvider>,
    linux: Option<LinuxRuntimePlacementEnvironment>,
    macos: Option<MacosRuntimePlacementEnvironment>,
}

impl RuntimeManagerPlacementExecutionAdapter {
    // Creates one adapter from explicit manager output and platform composition inputs.
    pub const fn new(
        manifests: Arc<dyn RuntimeExecutionManifestProvider>,
        linux: Option<LinuxRuntimePlacementEnvironment>,
        macos: Option<MacosRuntimePlacementEnvironment>,
    ) -> Self {
        Self {
            manifests,
            linux,
            macos,
        }
    }
}

impl RuntimePlacementExecutionProvider for RuntimeManagerPlacementExecutionAdapter {
    // Resolves one exact installed opaque task without reading runtime storage directly.
    fn execution(
        &self,
        placement: &Placement,
    ) -> Result<RuntimePlacementExecution, PlacementError> {
        let manifest = self
            .manifests
            .manifest(placement.assignment().runtime_installation_id())
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if manifest.installation_id() != placement.assignment().runtime_installation_id() {
            return Err(PlacementError::InvalidRequest {
                reason: "runtime execution manifest belongs to another installation",
            });
        }
        let task = manifest
            .task(placement.assignment().task_id())
            .cloned()
            .ok_or(PlacementError::InvalidRequest {
                reason: "runtime execution manifest does not contain the placement task",
            })?;
        validate_task_binding(placement, &task)?;
        match manifest.platform() {
            RuntimeExecutionPlatform::LinuxArm64 | RuntimeExecutionPlatform::LinuxX86_64 => {
                linux_execution(
                    placement,
                    manifest,
                    task,
                    self.linux
                        .as_ref()
                        .ok_or(PlacementError::ExecutionUnavailable)?,
                )
            }
            RuntimeExecutionPlatform::MacosArm64 => macos_execution(
                placement,
                manifest,
                task,
                self.macos
                    .as_ref()
                    .ok_or(PlacementError::ExecutionUnavailable)?,
            ),
        }
    }
}

// Converts one verified OCI task into a bounded Linux launch template.
fn linux_execution(
    placement: &Placement,
    manifest: RuntimeExecutionManifest,
    task: RuntimeExecutionTask,
    environment: &LinuxRuntimePlacementEnvironment,
) -> Result<RuntimePlacementExecution, PlacementError> {
    let RuntimeExecutionDistribution::Oci {
        execution_reference,
        immutable_id,
        ..
    } = manifest.distribution().clone()
    else {
        return Err(PlacementError::InvalidRequest {
            reason: "Linux runtime execution requires an OCI Engine",
        });
    };
    let command = task_command(&task)?;
    let runtime_environment = task
        .environment()
        .iter()
        .map(|(name, value)| ShellFreeEnvironmentValue::runtime(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    let cache_root = placement_cache_root(&manifest, placement);
    let launch = LinuxRuntimeLaunchTemplate::new(
        environment.docker.clone(),
        execution_reference,
        immutable_id,
        command,
        runtime_environment,
        linux_readiness(&manifest, &task)?,
        manifest.runtime_root().to_path_buf(),
        manifest.model_root().to_path_buf(),
        cache_root,
        manifest.container().memory_bytes(),
        manifest.container().shared_memory_bytes(),
        environment.temporary_bytes,
        environment.user_id,
        environment.group_id,
        manifest.container().cpuset().map(str::to_string),
        environment.device_nodes.clone(),
        environment.additional_labels.clone(),
        environment.additional_options.clone(),
    )?;
    Ok(RuntimePlacementExecution::Linux {
        runtime_installation_id: manifest.installation_id().clone(),
        task_id: task.task_id().clone(),
        port_count: task.port_count(),
        device_count: task.device_count(),
        serving: serving_contract(placement, &manifest)?,
        launch,
    })
}

// Converts one verified native task into a shell-free macOS launch template.
fn macos_execution(
    placement: &Placement,
    manifest: RuntimeExecutionManifest,
    task: RuntimeExecutionTask,
    environment: &MacosRuntimePlacementEnvironment,
) -> Result<RuntimePlacementExecution, PlacementError> {
    if !matches!(task.launcher(), RuntimeTaskLauncher::Manifest)
        || !matches!(task.readiness(), RuntimeExecutionReadiness::Manifest)
    {
        return Err(PlacementError::InvalidRequest {
            reason: "macOS runtime execution requires the sealed manifest launcher",
        });
    }
    let cache_root = placement_cache_root(&manifest, placement);
    let (executable, arguments, core_environment) = native_command(&manifest, &cache_root)?;
    let executable_identity = environment.executable_identities.identity(&executable)?;
    let runtime_environment = task
        .environment()
        .iter()
        .map(|(name, value)| ShellFreeEnvironmentValue::runtime(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    let command = ShellFreeCommand::new(
        executable,
        arguments,
        runtime_environment,
        Vec::new(),
        manifest.runtime_root().to_path_buf(),
    )?;
    let (attempts, interval) = readiness_schedule(manifest.container().startup_timeout())?;
    let launch = MacosRuntimeLaunchTemplate::new(command, attempts, interval)?
        .with_core_environment(core_environment)?
        .with_log_root(cache_root.join("logs"))?;
    Ok(RuntimePlacementExecution::Macos {
        runtime_installation_id: manifest.installation_id().clone(),
        task_id: task.task_id().clone(),
        port_count: task.port_count(),
        device_count: task.device_count(),
        executable_identity,
        serving: serving_contract(placement, &manifest)?,
        launch,
    })
}

// Builds one native adapter argv and its explicit Core-owned path environment.
fn native_command(
    manifest: &RuntimeExecutionManifest,
    cache_root: &Path,
) -> Result<(PathBuf, Vec<String>, Vec<ShellFreeEnvironmentValue>), PlacementError> {
    let mut core_environment = vec![
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_NATIVE_ENGINE_ROOT",
            path_string(manifest.engine_root())?,
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_RUNTIME_ROOT",
            path_string(manifest.runtime_root())?,
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_RUNTIME_CONFIG",
            path_string(&manifest.runtime_root().join("runtime.json"))?,
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_MODEL_ROOT",
            path_string(manifest.model_root())?,
        )?,
        ShellFreeEnvironmentValue::protected("LETSINFER_CACHE_ROOT", path_string(cache_root)?)?,
    ];
    match manifest.distribution() {
        RuntimeExecutionDistribution::NativeArchive {
            entrypoint,
            upstream_executable,
            ..
        } => {
            core_environment.push(ShellFreeEnvironmentValue::protected(
                "LETSINFER_NATIVE_UPSTREAM_EXECUTABLE",
                path_string(
                    &manifest
                        .engine_root()
                        .join("upstream")
                        .join(upstream_executable),
                )?,
            )?);
            Ok((
                manifest.runtime_root().join(entrypoint),
                vec!["serve".to_string()],
                core_environment,
            ))
        }
        RuntimeExecutionDistribution::PythonStandalone {
            entrypoint,
            interpreter,
            ..
        } => {
            let adapter_root = manifest
                .runtime_root()
                .join(entrypoint)
                .parent()
                .ok_or(PlacementError::ExecutionUnavailable)?
                .to_path_buf();
            core_environment.extend([
                ShellFreeEnvironmentValue::core(
                    "PYTHONPATH",
                    &format!(
                        "{}:{}",
                        path_string(&adapter_root)?,
                        path_string(&manifest.engine_root().join("site-packages"))?
                    ),
                )?,
                ShellFreeEnvironmentValue::core("PYTHONDONTWRITEBYTECODE", "1")?,
                ShellFreeEnvironmentValue::core("PYTHONNOUSERSITE", "1")?,
                ShellFreeEnvironmentValue::core("PYTHONSAFEPATH", "1")?,
            ]);
            Ok((
                manifest.engine_root().join(interpreter),
                vec![
                    path_string(&manifest.runtime_root().join(entrypoint))?.to_string(),
                    "serve".to_string(),
                ],
                core_environment,
            ))
        }
        RuntimeExecutionDistribution::EmbeddedApplication { .. }
        | RuntimeExecutionDistribution::Oci { .. } => Err(PlacementError::ExecutionUnavailable),
    }
}

// Returns the one stable mutable cache root owned by an exact placement.
fn placement_cache_root(manifest: &RuntimeExecutionManifest, placement: &Placement) -> PathBuf {
    manifest
        .cache_root()
        .join(placement.assignment().runtime_installation_id().as_str())
        .join(placement.placement_id().as_str())
}

// Converts one task launcher into exact shell-free engine argv.
fn task_command(task: &RuntimeExecutionTask) -> Result<Vec<String>, PlacementError> {
    match task.launcher() {
        RuntimeTaskLauncher::Manifest => Ok(vec![ENGINE_ADAPTER.to_string(), "serve".to_string()]),
        RuntimeTaskLauncher::RuntimeCommand(arguments) => Ok(arguments.clone()),
    }
}

// Converts runtime readiness into the bounded Linux executor contract.
fn linux_readiness(
    manifest: &RuntimeExecutionManifest,
    task: &RuntimeExecutionTask,
) -> Result<RuntimePlacementReadiness, PlacementError> {
    match task.readiness() {
        RuntimeExecutionReadiness::Manifest => {
            let (attempts, interval) = readiness_schedule(manifest.container().startup_timeout())?;
            Ok(RuntimePlacementReadiness::Endpoint { attempts, interval })
        }
        RuntimeExecutionReadiness::Exec {
            command,
            interval,
            retries,
            ..
        } => Ok(RuntimePlacementReadiness::Exec {
            arguments: command.clone(),
            attempts: *retries,
            interval: *interval,
        }),
    }
}

// Converts one startup duration into at most 3,600 exact readiness attempts.
fn readiness_schedule(timeout: Duration) -> Result<(u16, Duration), PlacementError> {
    let seconds = timeout.as_secs();
    if timeout.subsec_nanos() != 0 || seconds == 0 || seconds > 86_400 {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime startup timeout is invalid",
        });
    }
    let interval_seconds = seconds.div_ceil(3_600).max(1);
    let attempts = seconds.div_ceil(interval_seconds);
    Ok((
        u16::try_from(attempts).map_err(|_| PlacementError::ExecutionUnavailable)?,
        Duration::from_secs(interval_seconds),
    ))
}

// Creates the generic endpoint contract from runtime limits and exact node assignment.
fn serving_contract(
    placement: &Placement,
    manifest: &RuntimeExecutionManifest,
) -> Result<RuntimeServingContract, PlacementError> {
    RuntimeServingContract::new(
        placement.assignment().address().clone(),
        manifest.serving().max_active_requests(),
        manifest.serving().max_context_tokens(),
        Some(manifest.serving().token_count_path().to_string()),
    )
    .map(|serving| serving.with_served_model(manifest.logical_model().clone()))
}

// Requires the runtime task's resource and endpoint shape to match its placement assignment.
fn validate_task_binding(
    placement: &Placement,
    task: &RuntimeExecutionTask,
) -> Result<(), PlacementError> {
    let endpoint_owner = placement.assignment().endpoint_ownership() == EndpointOwnership::Owner;
    if task.port_count() != placement.assignment().resources().ports().count()
        || usize::from(task.device_count()) != placement.assignment().resources().device_ids().len()
        || task.is_endpoint_owner() != endpoint_owner
    {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime task contract differs from placement resources",
        });
    }
    Ok(())
}

// Returns one UTF-8 path without lossy conversion.
fn path_string(path: &Path) -> Result<&str, PlacementError> {
    path.to_str().ok_or(PlacementError::ExecutionUnavailable)
}
