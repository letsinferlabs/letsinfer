// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{
    ArtifactRevision, CpuArchitecture, EngineDistribution, LogicalModelName, ModelArtifactFormat,
    NativeEngineKind, OperatingSystem, PlatformIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest,
    TaskId, TechnicalName,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{li_runtime_catalog_schema::parse_closed_json, RuntimeError, RuntimeInstallationStore};

const RUNTIME_SCHEMA_VERSION: u64 = 6;
const ENGINE_PROTOCOL_VERSION: u64 = 2;
const ORCHESTRATION_SCHEMA_VERSION: u64 = 3;
const MAX_MANIFEST_BYTES: usize = 1 << 20;
const MAX_TASKS: usize = 64;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 16 * 1024;
const TOKEN_COUNT_PATH: &str = "/v1/letsinfer/token-count";

// Identifies the platform implementation selected by one verified runtime manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeExecutionPlatform {
    LinuxArm64,
    LinuxX86_64,
    MacosArm64,
}

impl RuntimeExecutionPlatform {
    // Returns the shared platform identity used by hardware and installation contracts.
    pub const fn identity(self) -> PlatformIdentity {
        match self {
            Self::LinuxArm64 => {
                PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64)
            }
            Self::LinuxX86_64 => {
                PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::X86_64)
            }
            Self::MacosArm64 => {
                PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64)
            }
        }
    }
}

// Carries the immutable executable delivery details required during placement staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeExecutionDistribution {
    Oci {
        identity_reference: RuntimeSource,
        execution_reference: RuntimeExecutionImageReference,
        immutable_id: Sha256Digest,
    },
    NativeArchive {
        entrypoint: PathBuf,
        upstream_executable: PathBuf,
        port_count: u16,
    },
    PythonStandalone {
        entrypoint: PathBuf,
        interpreter: PathBuf,
        port_count: u16,
    },
    EmbeddedApplication {
        bundle_id: String,
        embedded_engine: String,
        payload_id: Sha256Digest,
        source_revision: ArtifactRevision,
        minimum_version: RuntimeVersion,
        entrypoint: PathBuf,
        port_count: u16,
    },
}

// Carries either the signed distribution reference or an installation-bound local config ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExecutionImageReference {
    value: String,
    local_config_digest: Option<Sha256Digest>,
}

impl RuntimeExecutionImageReference {
    // Preserves one ordinary signed catalog distribution reference.
    pub fn distribution(reference: &RuntimeSource) -> Self {
        Self {
            value: reference.as_str().to_string(),
            local_config_digest: None,
        }
    }

    // Binds one verifier installation to its exact already-validated local config identity.
    pub fn local_config(digest: Sha256Digest) -> Self {
        Self {
            value: format!("sha256:{}", digest.as_str()),
            local_config_digest: Some(digest),
        }
    }

    // Returns the exact Docker image argument.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    // Returns the local config identity only for an exact verifier installation.
    pub const fn local_config_digest(&self) -> Option<&Sha256Digest> {
        self.local_config_digest.as_ref()
    }
}

impl From<RuntimeSource> for RuntimeExecutionImageReference {
    // Converts one validated signed distribution reference without changing its identity.
    fn from(reference: RuntimeSource) -> Self {
        Self::distribution(&reference)
    }
}

impl RuntimeExecutionDistribution {
    // Returns the number of ports required by one single-task distribution.
    pub const fn port_count(&self) -> u16 {
        match self {
            Self::Oci { .. } => 1,
            Self::NativeArchive { port_count, .. }
            | Self::PythonStandalone { port_count, .. }
            | Self::EmbeddedApplication { port_count, .. } => *port_count,
        }
    }
}

// Describes how one opaque runtime task starts without assigning engine semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeTaskLauncher {
    Manifest,
    RuntimeCommand(Vec<String>),
}

// Describes the bounded readiness mechanism declared by one runtime task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeExecutionReadiness {
    Manifest,
    Exec {
        command: Vec<String>,
        interval: Duration,
        timeout: Duration,
        retries: u16,
    },
}

// Carries one exact opaque task from a verified runtime execution contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExecutionTask {
    task_id: TaskId,
    launcher: RuntimeTaskLauncher,
    environment: Vec<(String, String)>,
    port_count: u16,
    device_count: u16,
    endpoint_owner: bool,
    readiness: RuntimeExecutionReadiness,
}

impl RuntimeExecutionTask {
    // Creates one bounded opaque task for production parsing or deterministic manager mocks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        launcher: RuntimeTaskLauncher,
        environment: Vec<(String, String)>,
        port_count: u16,
        device_count: u16,
        endpoint_owner: bool,
        readiness: RuntimeExecutionReadiness,
    ) -> Result<Self, RuntimeError> {
        validate_environment_pairs(&environment)?;
        if environment
            .iter()
            .any(|(name, _)| !is_task_environment_name(name))
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        if port_count == 0 || port_count > 32 || device_count == 0 || device_count > 64 {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        match &launcher {
            RuntimeTaskLauncher::Manifest => {
                if !matches!(readiness, RuntimeExecutionReadiness::Manifest) {
                    return Err(RuntimeError::ExecutionManifestInvalid);
                }
            }
            RuntimeTaskLauncher::RuntimeCommand(arguments) => {
                validate_argument_values(arguments, true)?;
                let RuntimeExecutionReadiness::Exec {
                    command,
                    interval,
                    timeout,
                    retries,
                } = &readiness
                else {
                    return Err(RuntimeError::ExecutionManifestInvalid);
                };
                validate_argument_values(command, true)?;
                if interval.is_zero()
                    || *interval > Duration::from_secs(60)
                    || timeout.is_zero()
                    || *timeout > Duration::from_secs(30)
                    || *retries == 0
                    || *retries > 600
                {
                    return Err(RuntimeError::ExecutionManifestInvalid);
                }
            }
        }
        Ok(Self {
            task_id,
            launcher,
            environment,
            port_count,
            device_count,
            endpoint_owner,
            readiness,
        })
    }

    // Returns the opaque task identity without interpreting rank or role.
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    // Returns the runtime-owned launch mechanism.
    pub const fn launcher(&self) -> &RuntimeTaskLauncher {
        &self.launcher
    }

    // Returns the sorted runtime-owned environment.
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    // Returns the exact contiguous port count required by the task.
    pub const fn port_count(&self) -> u16 {
        self.port_count
    }

    // Returns the exact accelerator count required by the task.
    pub const fn device_count(&self) -> u16 {
        self.device_count
    }

    // Returns whether this task owns the placement-group endpoint.
    pub const fn is_endpoint_owner(&self) -> bool {
        self.endpoint_owner
    }

    // Returns the runtime-owned readiness contract.
    pub const fn readiness(&self) -> &RuntimeExecutionReadiness {
        &self.readiness
    }
}

// Carries the bounded process envelope declared by one runtime release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExecutionContainer {
    memory_bytes: u64,
    shared_memory_bytes: u64,
    startup_timeout: Duration,
    cpuset: Option<String>,
}

impl RuntimeExecutionContainer {
    // Creates one positive bounded process envelope for production or deterministic mocks.
    pub fn new(
        memory_bytes: u64,
        shared_memory_bytes: u64,
        startup_timeout: Duration,
        cpuset: Option<String>,
    ) -> Result<Self, RuntimeError> {
        if memory_bytes == 0
            || startup_timeout.is_zero()
            || startup_timeout > Duration::from_secs(86_400)
            || startup_timeout.subsec_nanos() != 0
            || cpuset.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 1024
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'-'))
            })
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        Ok(Self {
            memory_bytes,
            shared_memory_bytes,
            startup_timeout,
            cpuset,
        })
    }

    // Returns the process memory ceiling in bytes.
    pub const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    // Returns the shared-memory allocation in bytes.
    pub const fn shared_memory_bytes(&self) -> u64 {
        self.shared_memory_bytes
    }

    // Returns the bounded startup window.
    pub const fn startup_timeout(&self) -> Duration {
        self.startup_timeout
    }

    // Returns the optional canonical CPU set.
    pub fn cpuset(&self) -> Option<&str> {
        self.cpuset.as_deref()
    }
}

// Carries generic serving limits without gateway routing state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExecutionServing {
    max_connections: u32,
    max_active_requests: u32,
    max_context_tokens: u64,
    token_count_path: String,
}

impl RuntimeExecutionServing {
    // Creates one coherent set of generic serving limits.
    pub fn new(
        max_connections: u32,
        max_active_requests: u32,
        max_context_tokens: u64,
        token_count_path: String,
    ) -> Result<Self, RuntimeError> {
        if max_connections == 0
            || max_active_requests == 0
            || max_active_requests > max_connections
            || max_context_tokens == 0
            || !token_count_path.starts_with('/')
            || token_count_path.len() > 255
            || token_count_path.chars().any(char::is_control)
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        Ok(Self {
            max_connections,
            max_active_requests,
            max_context_tokens,
            token_count_path,
        })
    }

    // Returns the listener connection ceiling.
    pub const fn max_connections(&self) -> u32 {
        self.max_connections
    }

    // Returns the runtime's active-request ceiling.
    pub const fn max_active_requests(&self) -> u32 {
        self.max_active_requests
    }

    // Returns the runtime's maximum served context.
    pub const fn max_context_tokens(&self) -> u64 {
        self.max_context_tokens
    }

    // Returns the protocol-owned token-count endpoint path.
    pub fn token_count_path(&self) -> &str {
        &self.token_count_path
    }
}

// Binds one Available installation to its verified platform-neutral execution inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExecutionManifest {
    installation_id: RuntimeInstallationId,
    logical_model: LogicalModelName,
    platform: RuntimeExecutionPlatform,
    engine_id: TechnicalName,
    distribution: RuntimeExecutionDistribution,
    engine_arguments: Vec<String>,
    engine_environment: Vec<(String, String)>,
    cache_provider: String,
    persistent_cache: bool,
    container: RuntimeExecutionContainer,
    serving: RuntimeExecutionServing,
    runtime_root: PathBuf,
    model_root: PathBuf,
    engine_root: PathBuf,
    cache_root: PathBuf,
    tasks: Vec<RuntimeExecutionTask>,
    startup_order: Vec<Vec<TaskId>>,
    benchmark: Option<RuntimeBenchmarkContract>,
}

// Carries exact benchmark and physical-target identities from one verified runtime document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBenchmarkContract {
    contract_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
    document: Vec<u8>,
    declared_cells: Vec<TechnicalName>,
}

impl RuntimeBenchmarkContract {
    // Creates one bounded benchmark projection from already-verified runtime bytes.
    pub fn new(
        contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
        document: Vec<u8>,
        declared_cells: Vec<TechnicalName>,
    ) -> Result<Self, RuntimeError> {
        let unique = declared_cells.iter().collect::<HashSet<_>>();
        if document.is_empty()
            || document.len() > MAX_MANIFEST_BYTES
            || sha256(&document) != contract_sha256
            || declared_cells.is_empty()
            || declared_cells.len() > 4096
            || unique.len() != declared_cells.len()
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        Ok(Self {
            contract_sha256,
            target_contract_sha256,
            document,
            declared_cells,
        })
    }

    // Returns the Python-canonical benchmark contract identity.
    pub const fn contract_sha256(&self) -> &Sha256Digest {
        &self.contract_sha256
    }

    // Returns the Python-canonical physical target contract identity.
    pub const fn target_contract_sha256(&self) -> &Sha256Digest {
        &self.target_contract_sha256
    }

    // Returns the complete canonical schema-8 contract consumed by the native worker.
    pub fn document(&self) -> &[u8] {
        &self.document
    }

    // Returns every model-neutral workload cell in stable contract order.
    pub fn declared_cells(&self) -> &[TechnicalName] {
        &self.declared_cells
    }
}

impl RuntimeExecutionManifest {
    // Creates one complete typed execution result for production parsing or manager mocks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: RuntimeInstallationId,
        logical_model: LogicalModelName,
        platform: RuntimeExecutionPlatform,
        engine_id: TechnicalName,
        distribution: RuntimeExecutionDistribution,
        engine_arguments: Vec<String>,
        engine_environment: Vec<(String, String)>,
        cache_provider: String,
        persistent_cache: bool,
        container: RuntimeExecutionContainer,
        serving: RuntimeExecutionServing,
        runtime_root: PathBuf,
        model_root: PathBuf,
        engine_root: PathBuf,
        cache_root: PathBuf,
        tasks: Vec<RuntimeExecutionTask>,
        startup_order: Vec<Vec<TaskId>>,
    ) -> Result<Self, RuntimeError> {
        validate_argument_values(&engine_arguments, false)?;
        validate_environment_pairs(&engine_environment)?;
        validate_technical(&cache_provider)?;
        let roots = [&runtime_root, &model_root, &engine_root, &cache_root];
        if roots.iter().any(|path| !is_safe_absolute_path(path))
            || roots
                .iter()
                .enumerate()
                .any(|(index, path)| roots.iter().skip(index + 1).any(|other| path == other))
            || tasks.is_empty()
            || tasks.len() > MAX_TASKS
            || tasks
                .iter()
                .enumerate()
                .any(|(index, task)| task.task_id().as_str() != format!("task-{index}"))
            || tasks.iter().filter(|task| task.is_endpoint_owner()).count() != 1
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        let expected: HashSet<TaskId> = tasks.iter().map(|task| task.task_id().clone()).collect();
        let observed: Vec<TaskId> = startup_order.iter().flatten().cloned().collect();
        if startup_order.is_empty()
            || startup_order.iter().any(Vec::is_empty)
            || observed.len() != expected.len()
            || observed.iter().collect::<HashSet<_>>().len() != observed.len()
            || observed.iter().any(|task| !expected.contains(task))
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        validate_typed_distribution(platform, &distribution)?;
        if matches!(
            platform,
            RuntimeExecutionPlatform::LinuxArm64 | RuntimeExecutionPlatform::LinuxX86_64
        ) && container.shared_memory_bytes() == 0
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        Ok(Self {
            installation_id,
            logical_model,
            platform,
            engine_id,
            distribution,
            engine_arguments,
            engine_environment,
            cache_provider,
            persistent_cache,
            container,
            serving,
            runtime_root,
            model_root,
            engine_root,
            cache_root,
            tasks,
            startup_order,
            benchmark: None,
        })
    }

    // Binds the exact parsed benchmark projection without weakening constructor validation.
    pub fn with_benchmark(mut self, benchmark: RuntimeBenchmarkContract) -> Self {
        self.benchmark = Some(benchmark);
        self
    }

    // Returns the host-local installation identity.
    pub const fn installation_id(&self) -> &RuntimeInstallationId {
        &self.installation_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the exact platform selected by the runtime target.
    pub const fn platform(&self) -> RuntimeExecutionPlatform {
        self.platform
    }

    // Returns the verified bounded Engine identity declared by the runtime manifest.
    pub const fn engine_id(&self) -> &TechnicalName {
        &self.engine_id
    }

    // Returns the immutable Engine delivery contract.
    pub const fn distribution(&self) -> &RuntimeExecutionDistribution {
        &self.distribution
    }

    // Rebinds only execution to one exact local OCI config while retaining signed identity.
    fn binding_local_oci_config(mut self, digest: Sha256Digest) -> Result<Self, RuntimeError> {
        let RuntimeExecutionDistribution::Oci {
            execution_reference,
            immutable_id,
            ..
        } = &mut self.distribution
        else {
            return Err(RuntimeError::ExecutionManifestInvalid);
        };
        if immutable_id != &digest {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        *execution_reference = RuntimeExecutionImageReference::local_config(digest);
        Ok(self)
    }

    // Returns runtime-owned upstream engine arguments.
    pub fn engine_arguments(&self) -> &[String] {
        &self.engine_arguments
    }

    // Returns sorted runtime-owned upstream engine environment.
    pub fn engine_environment(&self) -> &[(String, String)] {
        &self.engine_environment
    }

    // Returns the runtime-declared exact cache provider identity.
    pub fn cache_provider(&self) -> &str {
        &self.cache_provider
    }

    // Returns whether the runtime uses its persistent cache mount.
    pub const fn has_persistent_cache(&self) -> bool {
        self.persistent_cache
    }

    // Returns the bounded process envelope.
    pub const fn container(&self) -> &RuntimeExecutionContainer {
        &self.container
    }

    // Returns generic serving limits.
    pub const fn serving(&self) -> &RuntimeExecutionServing {
        &self.serving
    }

    // Returns the verified immutable runtime-pack root.
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    // Returns the verified immutable model-artifact root.
    pub fn model_root(&self) -> &Path {
        &self.model_root
    }

    // Returns the verified immutable Engine root.
    pub fn engine_root(&self) -> &Path {
        &self.engine_root
    }

    // Returns the explicit mutable runtime cache root.
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    // Returns every opaque task in canonical task order.
    pub fn tasks(&self) -> &[RuntimeExecutionTask] {
        &self.tasks
    }

    // Returns the runtime-owned concurrent startup phases.
    pub fn startup_order(&self) -> &[Vec<TaskId>] {
        &self.startup_order
    }

    // Returns one exact task without assigning it additional meaning.
    pub fn task(&self, task_id: &TaskId) -> Option<&RuntimeExecutionTask> {
        self.tasks.iter().find(|task| task.task_id() == task_id)
    }

    // Returns the exact current benchmark contract when the runtime declares one.
    pub const fn benchmark(&self) -> Option<&RuntimeBenchmarkContract> {
        self.benchmark.as_ref()
    }
}

// Supplies one immutable installation snapshot without exposing persistence details.
pub trait RuntimeInstallationProvider: Send + Sync {
    // Returns one installation when its exact identity exists.
    fn installation(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<RuntimeInstallation>, RuntimeError>;
}

// Adapts RuntimeManager's optimistic store to the narrow execution read capability.
pub struct StoredRuntimeInstallationProvider {
    store: Arc<dyn RuntimeInstallationStore>,
}

impl StoredRuntimeInstallationProvider {
    // Creates one read adapter over the NodeManager-owned installation store.
    pub const fn new(store: Arc<dyn RuntimeInstallationStore>) -> Self {
        Self { store }
    }
}

impl RuntimeInstallationProvider for StoredRuntimeInstallationProvider {
    // Returns only the installation snapshot from one versioned store result.
    fn installation(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<RuntimeInstallation>, RuntimeError> {
        Ok(self
            .store
            .read(installation_id)?
            .map(|value| value.installation().clone()))
    }
}

// Defines the exact native file read consumed by the execution-manifest provider.
pub trait RuntimeExecutionManifestIo: Send + Sync {
    // Reads one bounded regular manifest without following the final path as a symlink.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError>;
}

// Reads owner-controlled runtime manifests from the host filesystem.
pub struct SystemRuntimeExecutionManifestIo;

impl RuntimeExecutionManifestIo for SystemRuntimeExecutionManifestIo {
    // Opens one bounded regular file with no-follow behavior on Unix.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
        read_system_manifest(path, maximum_bytes)
    }
}

// Supplies a typed execution manifest only after exact installation verification.
pub trait RuntimeExecutionManifestProvider: Send + Sync {
    // Returns one typed execution contract for an Available installation.
    fn manifest(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError>;
}

// Owns exact manifest reads, identity validation, and typed execution projection.
pub struct FilesystemRuntimeExecutionManifestProvider {
    installation_root: PathBuf,
    cache_root: PathBuf,
    installations: Arc<dyn RuntimeInstallationProvider>,
    io: Arc<dyn RuntimeExecutionManifestIo>,
}

impl FilesystemRuntimeExecutionManifestProvider {
    // Creates one provider from explicit managed roots and injected native capabilities.
    pub fn new(
        installation_root: PathBuf,
        cache_root: PathBuf,
        installations: Arc<dyn RuntimeInstallationProvider>,
        io: Arc<dyn RuntimeExecutionManifestIo>,
    ) -> Result<Self, RuntimeError> {
        if !installation_root.is_absolute()
            || !cache_root.is_absolute()
            || installation_root == cache_root
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        Ok(Self {
            installation_root,
            cache_root,
            installations,
            io,
        })
    }
}

impl RuntimeExecutionManifestProvider for FilesystemRuntimeExecutionManifestProvider {
    // Verifies persisted state, exact bytes, identities, and the execution digest before parsing.
    fn manifest(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        let installation = self
            .installations
            .installation(installation_id)?
            .ok_or(RuntimeError::InstallationNotFound)?;
        if installation.state() != RuntimeInstallationState::Available
            || installation.installation_id() != installation_id
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        let installation_root = self.installation_root.join(installation_id.as_str());
        let runtime_root = installation_root.join("runtime");
        let model_root = installation_root.join("models");
        let engine_root = installation_root.join("engine");
        let bytes = self
            .io
            .read(&runtime_root.join("runtime.json"), MAX_MANIFEST_BYTES)?;
        if bytes.is_empty()
            || bytes.len() > MAX_MANIFEST_BYTES
            || sha256(&bytes) != *installation.runtime().manifest_digest()
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        let manifest = parse_manifest(
            &bytes,
            &installation,
            runtime_root,
            model_root,
            engine_root,
            self.cache_root.clone(),
        )?;
        let exact_config = match installation.runtime().engine_distribution() {
            EngineDistribution::Oci { immutable_id, .. } => {
                crate::li_runtime_artifact_provider::exact_engine_execution_config(
                    &self.installation_root,
                    installation_id,
                    immutable_id,
                )?
            }
            EngineDistribution::Native { .. } => None,
        };
        match exact_config {
            Some(digest) => manifest.binding_local_oci_config(digest),
            None => Ok(manifest),
        }
    }
}

// Reads one bounded regular file and rejects owner or mode changes on Unix.
fn read_system_manifest(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
    if maximum_bytes == 0 {
        return Err(RuntimeError::ExecutionManifestUnavailable);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| RuntimeError::ExecutionManifestUnavailable)?;
    validate_open_manifest(&file, maximum_bytes)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::ExecutionManifestUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(RuntimeError::ExecutionManifestUnavailable);
    }
    Ok(bytes)
}

// Requires one opened manifest to remain regular, bounded, private, and user-owned.
fn validate_open_manifest(file: &File, maximum_bytes: usize) -> Result<(), RuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ExecutionManifestUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes as u64 {
        return Err(RuntimeError::ExecutionManifestUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(RuntimeError::ExecutionManifestUnavailable);
        }
    }
    Ok(())
}

// Parses one exact schema-6 document into its bounded typed execution projection.
fn parse_manifest(
    bytes: &[u8],
    installation: &RuntimeInstallation,
    runtime_root: PathBuf,
    model_root: PathBuf,
    engine_root: PathBuf,
    cache_root: PathBuf,
) -> Result<RuntimeExecutionManifest, RuntimeError> {
    let value = parse_closed_json(bytes).map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    let root = object(&value)?;
    exact_fields(
        root,
        &[
            "schema_version",
            "id",
            "version",
            "logical_model",
            "target",
            "engine",
            "model",
            "artifacts",
            "container",
            "cache",
            "serving",
            "benchmark",
        ],
        &["orchestration"],
    )?;
    if unsigned(root, "schema_version")? != RUNTIME_SCHEMA_VERSION
        || string(root, "id")? != installation.runtime().candidate_id().as_str()
        || string(root, "version")? != installation.runtime().version().as_str()
        || string(root, "logical_model")? != installation.logical_model().as_str()
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let target_value = required(root, "target")?;
    let (platform, device_count, strategy, node_count) = parse_target(target_value, installation)?;
    let (engine_id, distribution, engine_arguments, engine_environment, cache_provider) =
        parse_engine(required(root, "engine")?, installation, platform)?;
    validate_model(required(root, "model")?, installation)?;
    validate_artifacts(required(root, "artifacts")?, installation)?;
    let container = parse_container(required(root, "container")?, platform)?;
    let persistent_cache = parse_cache(required(root, "cache")?, &cache_provider)?;
    let serving = parse_serving(required(root, "serving")?)?;
    let benchmark = parse_benchmark(
        required(root, "benchmark")?,
        canonical_sha256(target_value)?,
    )?;
    let (tasks, startup_order, execution_value) = if strategy == "single" {
        if root.contains_key("orchestration") || node_count != 1 {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        single_task(distribution.port_count(), device_count)?
    } else {
        let orchestration = required(root, "orchestration")?;
        parse_orchestration(orchestration, node_count, device_count)?
    };
    if canonical_sha256(&execution_value)? != *installation.runtime().execution_contract_digest() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let manifest = RuntimeExecutionManifest::new(
        installation.installation_id().clone(),
        installation.logical_model().clone(),
        platform,
        engine_id,
        distribution,
        engine_arguments,
        engine_environment,
        cache_provider,
        persistent_cache,
        container,
        serving,
        runtime_root,
        model_root,
        engine_root,
        cache_root,
        tasks,
        startup_order,
    )?;
    Ok(match benchmark {
        Some(benchmark) => manifest.with_benchmark(benchmark),
        None => manifest,
    })
}

// Parses the current schema-8 benchmark contract into exact identities and stable cell names.
fn parse_benchmark(
    value: &Value,
    target_contract_sha256: Sha256Digest,
) -> Result<Option<RuntimeBenchmarkContract>, RuntimeError> {
    let benchmark = object(value)?;
    if benchmark.is_empty() {
        return Ok(None);
    }
    exact_fields(benchmark, &["contract"], &[])?;
    let contract_value = required(benchmark, "contract")?;
    let contract = object(contract_value)?;
    if unsigned(contract, "schema_version")? != 8 {
        return Ok(None);
    }
    validate_benchmark_contract(contract)?;
    let domains = string_values(required(contract, "domains")?)?;
    let mut cells = Vec::new();
    let short = object(required(contract, "short")?)?;
    let short_domains = string_values(required(short, "domains")?)?;
    let short_concurrencies = positive_u16_values(required(short, "concurrencies")?)?;
    append_benchmark_cells(&mut cells, "short", &short_domains, &short_concurrencies)?;
    let ttft = object(required(contract, "ttft_cache")?)?;
    let ttft_domain = technical_value(string(ttft, "prompt_domain")?)?;
    for phase in ["ttftcold", "ttftwarm"] {
        cells.push(
            TechnicalName::parse(&format!("{phase}-{ttft_domain}-c1"))
                .map_err(|_| RuntimeError::ExecutionManifestInvalid)?,
        );
    }
    let cases = required(contract, "cases")?
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    for case in cases {
        let case = object(case)?;
        let case_id = technical_value(string(case, "id")?)?;
        let concurrencies = positive_u16_values(required(case, "concurrencies")?)?;
        append_benchmark_cells(&mut cells, &case_id, &domains, &concurrencies)?;
    }
    let document = canonical_bytes(contract_value)?;
    RuntimeBenchmarkContract::new(sha256(&document), target_contract_sha256, document, cells)
        .map(Some)
}

// Validates every closed schema-8 benchmark field before retaining its executable contract.
fn validate_benchmark_contract(contract: &Map<String, Value>) -> Result<(), RuntimeError> {
    exact_fields(
        contract,
        &[
            "schema_version",
            "suite",
            "generator",
            "domains",
            "execution",
            "tokenizer",
            "request",
            "short",
            "ttft_cache",
            "sample_interval_seconds",
            "cases",
        ],
        &[],
    )?;
    if string(contract, "suite")? != "letsinfer-code-prose-v1" {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let generator = object(required(contract, "generator")?)?;
    exact_fields(generator, &["id", "version"], &[])?;
    if string(generator, "id")? != "letsinfer-code-prose" || unsigned(generator, "version")? != 8 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    validate_benchmark_domains(required(contract, "domains")?, false)?;
    validate_benchmark_execution(required(contract, "execution")?)?;
    validate_benchmark_tokenizer(required(contract, "tokenizer")?)?;
    validate_benchmark_request(required(contract, "request")?, false)?;
    validate_benchmark_short(required(contract, "short")?)?;
    validate_benchmark_ttft(required(contract, "ttft_cache")?)?;
    bounded(unsigned(contract, "sample_interval_seconds")?, 1, 60)?;
    validate_benchmark_cases(required(contract, "cases")?)
}

// Requires one ordered benchmark domain set from the schema's closed alternatives.
fn validate_benchmark_domains(value: &Value, require_both: bool) -> Result<(), RuntimeError> {
    let domains = string_values(value)?;
    let valid = domains == ["code"] || domains == ["prose"] || domains == ["code", "prose"];
    if !valid || (require_both && domains != ["code", "prose"]) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Requires the exact isolation and shared-prefix execution vocabulary.
fn validate_benchmark_execution(value: &Value) -> Result<(), RuntimeError> {
    let execution = object(value)?;
    exact_fields(
        execution,
        &[
            "isolation",
            "prefix_state",
            "samples_per_cell",
            "stream_prefix",
        ],
        &[],
    )?;
    if !matches!(
        string(execution, "isolation")?,
        "fresh-matrix" | "fresh-context"
    ) || string(execution, "prefix_state")? != "shared"
        || unsigned(execution, "samples_per_cell")? != 1
        || string(execution, "stream_prefix")? != "shared-body"
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Requires exact Engine-rendered token-count capability and immutable payload identities.
fn validate_benchmark_tokenizer(value: &Value) -> Result<(), RuntimeError> {
    let tokenizer = object(value)?;
    exact_fields(
        tokenizer,
        &[
            "capability",
            "model_sha256",
            "engine_payload_sha256",
            "render_contract",
        ],
        &[],
    )?;
    if string(tokenizer, "capability")? != "engine-rendered-chat-count-v1"
        || string(tokenizer, "render_contract")? != "openai-chat-user-v1"
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    digest(string(tokenizer, "model_sha256")?)?;
    digest(string(tokenizer, "engine_payload_sha256")?)?;
    Ok(())
}

// Requires one complete generation request and the TTFT request's sealed constants.
fn validate_benchmark_request(value: &Value, ttft: bool) -> Result<(), RuntimeError> {
    let request = object(value)?;
    exact_fields(
        request,
        &[
            "output_tokens",
            "min_completion_tokens",
            "require_natural_stop",
            "temperature",
            "seed",
        ],
        &[],
    )?;
    let output_tokens = positive(unsigned(request, "output_tokens")?)?;
    let minimum_completion_tokens = positive(unsigned(request, "min_completion_tokens")?)?;
    if minimum_completion_tokens > output_tokens
        || required(request, "temperature")?
            .as_f64()
            .is_none_or(|value| value < 0.0)
        || required(request, "seed")?.as_u64().is_none()
        || (ttft
            && (output_tokens != 1
                || minimum_completion_tokens != 1
                || boolean(request, "require_natural_stop")?
                || required(request, "temperature")?.as_f64() != Some(0.0)))
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    boolean(request, "require_natural_stop")?;
    Ok(())
}

// Requires the schema's fixed short-workload domain and concurrency matrix.
fn validate_benchmark_short(value: &Value) -> Result<(), RuntimeError> {
    let short = object(value)?;
    exact_fields(
        short,
        &["domains", "prompt_tokens", "concurrencies", "request"],
        &[],
    )?;
    validate_benchmark_domains(required(short, "domains")?, true)?;
    positive(unsigned(short, "prompt_tokens")?)?;
    if positive_u16_values(required(short, "concurrencies")?)? != [1, 2, 4] {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    validate_benchmark_request(required(short, "request")?, false)
}

// Requires the exact cold/warm 64K TTFT cache workload.
fn validate_benchmark_ttft(value: &Value) -> Result<(), RuntimeError> {
    let ttft = object(value)?;
    exact_fields(
        ttft,
        &["prompt_tokens", "prompt_domain", "repetitions", "request"],
        &[],
    )?;
    if unsigned(ttft, "prompt_tokens")? != 64_000
        || string(ttft, "prompt_domain")? != "code"
        || unsigned(ttft, "repetitions")? != 2
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    validate_benchmark_request(required(ttft, "request")?, true)
}

// Requires non-empty uniquely identified cases and bounded unique concurrencies.
fn validate_benchmark_cases(value: &Value) -> Result<(), RuntimeError> {
    let cases = value
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if cases.is_empty() || cases.len() > 128 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let mut identifiers = HashSet::new();
    for value in cases {
        let case = object(value)?;
        exact_fields(case, &["id", "prompt_tokens", "concurrencies"], &[])?;
        let identifier = technical_value(string(case, "id")?)?;
        positive(unsigned(case, "prompt_tokens")?)?;
        let concurrencies = positive_u16_values(required(case, "concurrencies")?)?;
        if !identifiers.insert(identifier) || concurrencies.iter().any(|value| *value > 128) {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        let unique = concurrencies.iter().collect::<HashSet<_>>();
        if unique.len() != concurrencies.len() {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
    }
    Ok(())
}

// Appends the cross product of one contract lane, its domains, and exact concurrencies.
fn append_benchmark_cells(
    cells: &mut Vec<TechnicalName>,
    lane: &str,
    domains: &[String],
    concurrencies: &[u16],
) -> Result<(), RuntimeError> {
    for concurrency in concurrencies {
        for domain in domains {
            cells.push(
                TechnicalName::parse(&format!("{lane}-{domain}-c{concurrency}"))
                    .map_err(|_| RuntimeError::ExecutionManifestInvalid)?,
            );
        }
    }
    Ok(())
}

// Parses one non-empty ordered array of canonical technical names.
fn string_values(value: &Value) -> Result<Vec<String>, RuntimeError> {
    let values = value
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if values.is_empty() || values.len() > 128 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(RuntimeError::ExecutionManifestInvalid)
                .and_then(technical_value)
                .map(str::to_string)
        })
        .collect()
}

// Parses one non-empty ordered array of supported benchmark concurrencies.
fn positive_u16_values(value: &Value) -> Result<Vec<u16>, RuntimeError> {
    let values = value
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if values.is_empty() || values.len() > 128 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or(RuntimeError::ExecutionManifestInvalid)
                .and_then(|value| positive_u16(value, 1024))
        })
        .collect()
}

// Returns one canonical technical-name value without retaining interface errors.
fn technical_value(value: &str) -> Result<&str, RuntimeError> {
    TechnicalName::parse(value).map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    Ok(value)
}

// Reuses the production execution parser to validate one reconstructed installation snapshot.
pub(crate) fn validate_runtime_installation_manifest(
    bytes: &[u8],
    installation: &RuntimeInstallation,
) -> Result<(), RuntimeError> {
    parse_manifest(
        bytes,
        installation,
        PathBuf::from("/li_runtime_installation/runtime"),
        PathBuf::from("/li_runtime_installation/models"),
        PathBuf::from("/li_runtime_installation/engine"),
        PathBuf::from("/li_runtime_installation/cache"),
    )?;
    Ok(())
}

// Validates the complete target shape and returns only execution-relevant facts.
fn parse_target(
    value: &Value,
    installation: &RuntimeInstallation,
) -> Result<(RuntimeExecutionPlatform, u16, String, u16), RuntimeError> {
    let target = object(value)?;
    exact_fields(
        target,
        &["id", "platform", "accelerator", "memory", "placement"],
        &[],
    )?;
    if string(target, "id")? != installation.runtime().target_id().as_str() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let platform = parse_platform(string(target, "platform")?)?;
    let accelerator = object(required(target, "accelerator")?)?;
    exact_fields(
        accelerator,
        &["vendor", "architecture", "count", "partitioning"],
        &["minimum_memory_gib"],
    )?;
    validate_technical(string(accelerator, "vendor")?)?;
    validate_technical(string(accelerator, "architecture")?)?;
    let device_count = positive_u16(unsigned(accelerator, "count")?, 64)?;
    if !matches!(string(accelerator, "partitioning")?, "full-device" | "mig") {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    if accelerator.contains_key("minimum_memory_gib") {
        positive(unsigned(accelerator, "minimum_memory_gib")?)?;
    }
    let memory = object(required(target, "memory")?)?;
    exact_fields(memory, &["topology", "minimum_total_gib"], &[])?;
    if !matches!(string(memory, "topology")?, "unified" | "discrete") {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    positive(unsigned(memory, "minimum_total_gib")?)?;
    let placement = object(required(target, "placement")?)?;
    exact_fields(placement, &["strategy", "node_count", "interconnect"], &[])?;
    let strategy = string(placement, "strategy")?;
    if !matches!(strategy, "single" | "parallel") {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let node_count = positive_u16(unsigned(placement, "node_count")?, MAX_TASKS as u64)?;
    if strategy == "single" && node_count != 1 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    validate_interconnect(required(placement, "interconnect")?, strategy)?;
    Ok((platform, device_count, strategy.to_string(), node_count))
}

// Validates target interconnect fields without assigning topology resources.
fn validate_interconnect(value: &Value, strategy: &str) -> Result<(), RuntimeError> {
    let interconnect = object(value)?;
    exact_fields(
        interconnect,
        &["kind", "rdma_required", "minimum_speed_mbps", "minimum_mtu"],
        &[],
    )?;
    let kind = string(interconnect, "kind")?;
    if !matches!(kind, "any" | "connectx" | "ethernet" | "wifi" | "other") {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let rdma = boolean(interconnect, "rdma_required")?;
    let speed = unsigned(interconnect, "minimum_speed_mbps")?;
    let mtu = unsigned(interconnect, "minimum_mtu")?;
    if strategy != "parallel" && (kind != "any" || rdma || speed != 0 || mtu != 0) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Validates the Engine protocol and immutable distribution against persisted identity.
fn parse_engine(
    value: &Value,
    installation: &RuntimeInstallation,
    platform: RuntimeExecutionPlatform,
) -> Result<
    (
        TechnicalName,
        RuntimeExecutionDistribution,
        Vec<String>,
        Vec<(String, String)>,
        String,
    ),
    RuntimeError,
> {
    let engine = object(value)?;
    exact_fields(
        engine,
        &[
            "id",
            "protocol",
            "distribution",
            "model_format",
            "cache_provider",
            "arguments",
            "environment",
        ],
        &[],
    )?;
    let engine_id = TechnicalName::parse(string(engine, "id")?)
        .map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    validate_technical(string(engine, "model_format")?)?;
    let cache_provider = string(engine, "cache_provider")?.to_string();
    validate_technical(&cache_provider)?;
    let protocol = object(required(engine, "protocol")?)?;
    exact_fields(protocol, &["version"], &[])?;
    if unsigned(protocol, "version")? != ENGINE_PROTOCOL_VERSION {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let arguments = parse_arguments(required(engine, "arguments")?, false)?;
    let environment = parse_environment(required(engine, "environment")?)?;
    let distribution = parse_distribution(
        required(engine, "distribution")?,
        installation.runtime().engine_distribution(),
        platform,
    )?;
    Ok((
        engine_id,
        distribution,
        arguments,
        environment,
        cache_provider,
    ))
}

// Parses one closed OCI or native Engine execution delivery mechanism.
fn parse_distribution(
    value: &Value,
    expected: &EngineDistribution,
    platform: RuntimeExecutionPlatform,
) -> Result<RuntimeExecutionDistribution, RuntimeError> {
    let distribution = object(value)?;
    match string(distribution, "kind")? {
        "oci-container" => parse_oci_distribution(distribution, expected),
        "native-archive" => parse_native_distribution(
            distribution,
            expected,
            platform,
            NativeEngineKind::NativeArchive,
        ),
        "python-standalone" => parse_native_distribution(
            distribution,
            expected,
            platform,
            NativeEngineKind::PythonStandalone,
        ),
        "embedded-application" => parse_native_distribution(
            distribution,
            expected,
            platform,
            NativeEngineKind::EmbeddedApplication,
        ),
        _ => Err(RuntimeError::ExecutionManifestInvalid),
    }
}

// Parses and matches one digest-pinned OCI distribution.
fn parse_oci_distribution(
    distribution: &Map<String, Value>,
    expected: &EngineDistribution,
) -> Result<RuntimeExecutionDistribution, RuntimeError> {
    exact_fields(
        distribution,
        &["kind", "reference", "immutable_id"],
        &["base", "payload_id"],
    )?;
    let reference = RuntimeSource::parse(string(distribution, "reference")?)
        .map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    let immutable_id = prefixed_digest(string(distribution, "immutable_id")?)?;
    let base = distribution
        .get("base")
        .map(|value| value.as_str().ok_or(RuntimeError::ExecutionManifestInvalid))
        .transpose()?
        .map(RuntimeSource::parse)
        .transpose()
        .map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    let payload = distribution
        .get("payload_id")
        .map(|value| value.as_str().ok_or(RuntimeError::ExecutionManifestInvalid))
        .transpose()?
        .map(prefixed_digest)
        .transpose()?;
    let EngineDistribution::Oci {
        reference: expected_reference,
        immutable_id: expected_id,
        base: expected_base,
        payload_id: expected_payload,
    } = expected
    else {
        return Err(RuntimeError::ExecutionManifestInvalid);
    };
    if &reference != expected_reference
        || &immutable_id != expected_id
        || base.as_ref() != expected_base.as_ref()
        || payload.as_ref() != expected_payload.as_ref()
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(RuntimeExecutionDistribution::Oci {
        execution_reference: RuntimeExecutionImageReference::distribution(&reference),
        identity_reference: reference,
        immutable_id,
    })
}

// Parses and matches one native Engine distribution plus its execution paths.
fn parse_native_distribution(
    distribution: &Map<String, Value>,
    expected: &EngineDistribution,
    platform: RuntimeExecutionPlatform,
    kind: NativeEngineKind,
) -> Result<RuntimeExecutionDistribution, RuntimeError> {
    let common = [
        "kind",
        "platform",
        "payload_id",
        "source_revision",
        "entrypoint",
        "port_count",
    ];
    let optional = match kind {
        NativeEngineKind::NativeArchive => &["archive", "upstream_executable"][..],
        NativeEngineKind::PythonStandalone => &["python", "requirements_lock"][..],
        NativeEngineKind::EmbeddedApplication => &[
            "bundle_id",
            "signing_policy",
            "minimum_version",
            "embedded_engine",
        ][..],
    };
    exact_fields(distribution, &common, optional)?;
    if string(distribution, "platform")? != platform_name(platform) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let payload = prefixed_digest(string(distribution, "payload_id")?)?;
    let source_revision = string(distribution, "source_revision")?;
    if !is_lower_hex(source_revision, 40) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let entrypoint = relative_path(string(distribution, "entrypoint")?)?;
    let port_count = positive_u16(unsigned(distribution, "port_count")?, 4)?;
    let EngineDistribution::Native {
        kind: expected_kind,
        platform: expected_platform,
        payload_id: expected_payload,
        source_revision: expected_revision,
    } = expected
    else {
        return Err(RuntimeError::ExecutionManifestInvalid);
    };
    if *expected_kind != kind
        || *expected_platform != platform.identity()
        || expected_payload != &payload
        || expected_revision.as_str() != source_revision
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    match kind {
        NativeEngineKind::NativeArchive => {
            if port_count < 2 {
                return Err(RuntimeError::ExecutionManifestInvalid);
            }
            validate_native_archive(required(distribution, "archive")?)?;
            Ok(RuntimeExecutionDistribution::NativeArchive {
                entrypoint,
                upstream_executable: relative_path(string(distribution, "upstream_executable")?)?,
                port_count,
            })
        }
        NativeEngineKind::PythonStandalone => {
            if port_count < 2 || relative_path(string(distribution, "requirements_lock")?).is_err()
            {
                return Err(RuntimeError::ExecutionManifestInvalid);
            }
            validate_python_distribution(required(distribution, "python")?)?;
            Ok(RuntimeExecutionDistribution::PythonStandalone {
                entrypoint,
                interpreter: PathBuf::from("python/bin/python3"),
                port_count,
            })
        }
        NativeEngineKind::EmbeddedApplication => {
            if string(distribution, "signing_policy")? != "deployment-managed"
                || RuntimeVersion::parse(string(distribution, "minimum_version")?).is_err()
            {
                return Err(RuntimeError::ExecutionManifestInvalid);
            }
            let bundle_id = string(distribution, "bundle_id")?;
            let embedded_engine = string(distribution, "embedded_engine")?;
            if !is_bundle_id(bundle_id) || validate_technical(embedded_engine).is_err() {
                return Err(RuntimeError::ExecutionManifestInvalid);
            }
            Ok(RuntimeExecutionDistribution::EmbeddedApplication {
                bundle_id: bundle_id.to_string(),
                embedded_engine: embedded_engine.to_string(),
                payload_id: payload,
                source_revision: expected_revision.clone(),
                minimum_version: RuntimeVersion::parse(string(distribution, "minimum_version")?)
                    .map_err(|_| RuntimeError::ExecutionManifestInvalid)?,
                entrypoint,
                port_count,
            })
        }
    }
}

// Validates one bounded credential-free native archive source.
fn validate_native_archive(value: &Value) -> Result<(), RuntimeError> {
    let archive = object(value)?;
    exact_fields(
        archive,
        &["url", "sha256", "bytes", "format", "strip_prefix"],
        &[],
    )?;
    let url = string(archive, "url")?;
    if !is_credential_free_https_url(url)
        || !is_lower_hex(string(archive, "sha256")?, 64)
        || bounded(unsigned(archive, "bytes")?, 1, 1 << 30).is_err()
        || !matches!(string(archive, "format")?, "tar.gz" | "zip")
        || relative_path(string(archive, "strip_prefix")?).is_err()
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Returns whether one bounded URL has HTTPS authority and no credentials or fragment.
fn is_credential_free_https_url(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    !authority.is_empty()
        && value.len() <= 2_048
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        && !value.contains('@')
        && !value.contains('#')
}

// Validates one exact CPython standalone identity and its immutable archive.
fn validate_python_distribution(value: &Value) -> Result<(), RuntimeError> {
    let python = object(value)?;
    exact_fields(python, &["implementation", "version", "archive"], &[])?;
    let version = string(python, "version")?;
    let components: Vec<&str> = version.split('.').collect();
    if string(python, "implementation")? != "cpython"
        || components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
        || components[0] != "3"
        || components[1]
            .parse::<u8>()
            .ok()
            .is_none_or(|minor| !(8..=19).contains(&minor))
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    validate_native_archive(required(python, "archive")?)
}

// Requires the manifest's primary model identity to match persisted artifacts.
fn validate_model(value: &Value, installation: &RuntimeInstallation) -> Result<(), RuntimeError> {
    let model = object(value)?;
    exact_fields(model, &["uri", "artifact", "acquisition"], &[])?;
    if !required(model, "acquisition")?.is_object() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let artifact_name = string(model, "artifact")?;
    let artifact = installation
        .artifacts()
        .iter()
        .find(|artifact| artifact.name().as_str() == artifact_name)
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if artifact.uri().as_str() != string(model, "uri")? {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Requires every source artifact identity to equal persisted installation state.
fn validate_artifacts(
    value: &Value,
    installation: &RuntimeInstallation,
) -> Result<(), RuntimeError> {
    let values = value
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if values.len() != installation.artifacts().len() || values.is_empty() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    for (value, expected) in values.iter().zip(installation.artifacts()) {
        let artifact = object(value)?;
        let format = string(artifact, "format")?;
        let required_fields = ["name", "uri", "format", "revision"];
        match expected.format() {
            ModelArtifactFormat::HuggingFaceSnapshot => {
                exact_fields(artifact, &required_fields, &[])?;
                if format != "huggingface-snapshot" {
                    return Err(RuntimeError::ExecutionManifestInvalid);
                }
            }
            ModelArtifactFormat::GgufFile(file) => {
                exact_fields(artifact, &required_fields, &["filename", "sha256", "bytes"])?;
                if format != "gguf-file"
                    || string(artifact, "filename")? != file.filename()
                    || string(artifact, "sha256")? != file.digest().as_str()
                    || artifact.get("bytes").and_then(Value::as_u64) != file.bytes()
                {
                    return Err(RuntimeError::ExecutionManifestInvalid);
                }
            }
        }
        if string(artifact, "name")? != expected.name().as_str()
            || string(artifact, "uri")? != expected.uri().as_str()
            || string(artifact, "revision")? != expected.revision().as_str()
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
    }
    Ok(())
}

// Parses the bounded process envelope used by platform placement executors.
fn parse_container(
    value: &Value,
    platform: RuntimeExecutionPlatform,
) -> Result<RuntimeExecutionContainer, RuntimeError> {
    let container = object(value)?;
    exact_fields(
        container,
        &[
            "memory_bytes",
            "shm_bytes",
            "min_available_gib",
            "runtime_min_available_gib",
            "startup_timeout_seconds",
        ],
        &["cpuset_cpus"],
    )?;
    let memory_bytes = positive(unsigned(container, "memory_bytes")?)?;
    let shared_memory_bytes = unsigned(container, "shm_bytes")?;
    if matches!(
        platform,
        RuntimeExecutionPlatform::LinuxArm64 | RuntimeExecutionPlatform::LinuxX86_64
    ) && shared_memory_bytes == 0
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    positive(unsigned(container, "min_available_gib")?)?;
    positive(unsigned(container, "runtime_min_available_gib")?)?;
    let timeout = positive(unsigned(container, "startup_timeout_seconds")?)?;
    if timeout > 86_400 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let cpuset = container
        .get("cpuset_cpus")
        .map(|value| value.as_str().ok_or(RuntimeError::ExecutionManifestInvalid))
        .transpose()?
        .map(str::to_string);
    if cpuset.as_ref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 1024
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'-'))
    }) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    RuntimeExecutionContainer::new(
        memory_bytes,
        shared_memory_bytes,
        Duration::from_secs(timeout),
        cpuset,
    )
}

// Validates cache identity and returns whether a persistent mount is required.
fn parse_cache(value: &Value, engine_provider: &str) -> Result<bool, RuntimeError> {
    let cache = object(value)?;
    exact_fields(
        cache,
        &[
            "provider",
            "persistent",
            "prewarm",
            "replay_output_policy",
            "config",
        ],
        &[],
    )?;
    if string(cache, "provider")? != engine_provider
        || !required(cache, "prewarm")?.is_boolean()
        || !required(cache, "config")?.is_object()
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let persistent = boolean(cache, "persistent")?;
    let replay = required(cache, "replay_output_policy")?;
    if persistent {
        if !matches!(
            replay.as_str(),
            Some("all-phases-exact" | "restored-repeat-exact")
        ) {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
    } else if !replay.is_null() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(persistent)
}

// Parses generic serving limits without interpreting qualification metadata.
fn parse_serving(value: &Value) -> Result<RuntimeExecutionServing, RuntimeError> {
    let serving = object(value)?;
    exact_fields(
        serving,
        &[
            "max_connections",
            "max_active_requests",
            "max_context_tokens",
            "gate",
        ],
        &[],
    )?;
    let max_connections = positive_u32(unsigned(serving, "max_connections")?)?;
    let max_active_requests = positive_u32(unsigned(serving, "max_active_requests")?)?;
    let max_context_tokens = positive(unsigned(serving, "max_context_tokens")?)?;
    if max_active_requests > max_connections
        || !(required(serving, "gate")?.is_null() || required(serving, "gate")?.is_object())
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    RuntimeExecutionServing::new(
        max_connections,
        max_active_requests,
        max_context_tokens,
        TOKEN_COUNT_PATH.to_string(),
    )
}

// Synthesizes the stable one-task execution contract used by single-node runtimes.
fn single_task(
    port_count: u16,
    device_count: u16,
) -> Result<(Vec<RuntimeExecutionTask>, Vec<Vec<TaskId>>, Value), RuntimeError> {
    let task_id = TaskId::parse("task-0").map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    Ok((
        vec![RuntimeExecutionTask::new(
            task_id.clone(),
            RuntimeTaskLauncher::Manifest,
            Vec::new(),
            port_count,
            device_count,
            true,
            RuntimeExecutionReadiness::Manifest,
        )?],
        vec![vec![task_id]],
        serde_json::json!({"contract": "letsinfer-single-task-v1"}),
    ))
}

// Parses the complete runtime-owned parallel task and startup contract.
fn parse_orchestration(
    value: &Value,
    node_count: u16,
    device_count: u16,
) -> Result<(Vec<RuntimeExecutionTask>, Vec<Vec<TaskId>>, Value), RuntimeError> {
    let orchestration = object(value)?;
    exact_fields(
        orchestration,
        &[
            "schema_version",
            "failure_policy",
            "endpoint_owner",
            "startup_order",
            "tasks",
        ],
        &[],
    )?;
    if unsigned(orchestration, "schema_version")? != ORCHESTRATION_SCHEMA_VERSION
        || string(orchestration, "failure_policy")? != "whole-group"
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let values = required(orchestration, "tasks")?
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if values.len() != usize::from(node_count) || values.is_empty() || values.len() > MAX_TASKS {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let endpoint_owner = string(orchestration, "endpoint_owner")?;
    let mut tasks = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let task = object(value)?;
        let expected_task = format!("task-{index}");
        if string(task, "task_id")? != expected_task {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        let task_id =
            TaskId::parse(&expected_task).map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
        let launcher_name = string(task, "launcher")?;
        let launcher = if launcher_name == "manifest" {
            exact_fields(
                task,
                &[
                    "task_id",
                    "launcher",
                    "environment",
                    "port_count",
                    "readiness",
                ],
                &[],
            )?;
            RuntimeTaskLauncher::Manifest
        } else if launcher_name == "runtime-command" {
            exact_fields(
                task,
                &[
                    "task_id",
                    "launcher",
                    "environment",
                    "port_count",
                    "readiness",
                    "command",
                ],
                &[],
            )?;
            RuntimeTaskLauncher::RuntimeCommand(parse_arguments(required(task, "command")?, true)?)
        } else {
            return Err(RuntimeError::ExecutionManifestInvalid);
        };
        let readiness = parse_readiness(required(task, "readiness")?, launcher_name)?;
        tasks.push(RuntimeExecutionTask::new(
            task_id,
            launcher,
            parse_task_environment(required(task, "environment")?)?,
            positive_u16(unsigned(task, "port_count")?, 32)?,
            device_count,
            expected_task == endpoint_owner,
            readiness,
        )?);
    }
    if tasks.iter().filter(|task| task.is_endpoint_owner()).count() != 1 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let startup_order = parse_startup_order(required(orchestration, "startup_order")?, &tasks)?;
    if canonical_bytes(value)?.len() > 64 * 1024 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok((tasks, startup_order, value.clone()))
}

// Parses one sealed manifest or bounded exec readiness contract.
fn parse_readiness(
    value: &Value,
    launcher: &str,
) -> Result<RuntimeExecutionReadiness, RuntimeError> {
    let readiness = object(value)?;
    if launcher == "manifest" {
        exact_fields(readiness, &["kind"], &[])?;
        if string(readiness, "kind")? != "manifest" {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        return Ok(RuntimeExecutionReadiness::Manifest);
    }
    exact_fields(
        readiness,
        &[
            "kind",
            "command",
            "interval_seconds",
            "timeout_seconds",
            "retries",
        ],
        &[],
    )?;
    if string(readiness, "kind")? != "exec" {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let interval = bounded(unsigned(readiness, "interval_seconds")?, 1, 60)?;
    let timeout = bounded(unsigned(readiness, "timeout_seconds")?, 1, 30)?;
    let retries = positive_u16(unsigned(readiness, "retries")?, 600)?;
    Ok(RuntimeExecutionReadiness::Exec {
        command: parse_arguments(required(readiness, "command")?, true)?,
        interval: Duration::from_secs(interval),
        timeout: Duration::from_secs(timeout),
        retries,
    })
}

// Parses startup phases and proves every opaque task appears exactly once.
fn parse_startup_order(
    value: &Value,
    tasks: &[RuntimeExecutionTask],
) -> Result<Vec<Vec<TaskId>>, RuntimeError> {
    let phases = value
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if phases.is_empty() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let task_ids: HashSet<&TaskId> = tasks.iter().map(RuntimeExecutionTask::task_id).collect();
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(phases.len());
    for phase in phases {
        let values = phase
            .as_array()
            .ok_or(RuntimeError::ExecutionManifestInvalid)?;
        if values.is_empty() {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        let mut parsed = Vec::with_capacity(values.len());
        for value in values {
            let task_id = TaskId::parse(
                value
                    .as_str()
                    .ok_or(RuntimeError::ExecutionManifestInvalid)?,
            )
            .map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
            if !task_ids.contains(&task_id) || !seen.insert(task_id.clone()) {
                return Err(RuntimeError::ExecutionManifestInvalid);
            }
            parsed.push(task_id);
        }
        result.push(parsed);
    }
    if seen.len() != tasks.len() {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(result)
}

// Parses one bounded argv and optionally requires a safe absolute executable.
fn parse_arguments(value: &Value, require_executable: bool) -> Result<Vec<String>, RuntimeError> {
    let values = value
        .as_array()
        .ok_or(RuntimeError::ExecutionManifestInvalid)?;
    if values.len() > MAX_ARGUMENTS || (require_executable && values.is_empty()) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let mut total = 0;
    let mut arguments = Vec::with_capacity(values.len());
    for value in values {
        let argument = value
            .as_str()
            .ok_or(RuntimeError::ExecutionManifestInvalid)?;
        total += argument.len();
        if argument.is_empty()
            || argument.len() > 4_096
            || argument.contains('\0')
            || total > MAX_ARGUMENT_BYTES
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        arguments.push(argument.to_string());
    }
    if require_executable {
        validate_executable(&arguments[0])?;
    }
    Ok(arguments)
}

// Validates already-typed argv values used by deterministic manager mocks.
fn validate_argument_values(
    values: &[String],
    require_executable: bool,
) -> Result<(), RuntimeError> {
    if values.len() > MAX_ARGUMENTS || (require_executable && values.is_empty()) {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let mut total = 0;
    for value in values {
        total += value.len();
        if value.is_empty()
            || value.len() > 4_096
            || value.contains('\0')
            || total > MAX_ARGUMENT_BYTES
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
    }
    if require_executable {
        validate_executable(&values[0])?;
    }
    Ok(())
}

// Rejects relative executables, parent traversal, shells, and dispatchers.
fn validate_executable(value: &str) -> Result<(), RuntimeError> {
    let path = Path::new(value);
    let forbidden = ["bash", "dash", "env", "fish", "ksh", "sh", "zsh"];
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| forbidden.contains(&name))
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Parses a sorted bounded environment without Core-owned names or secret markers.
fn parse_environment(value: &Value) -> Result<Vec<(String, String)>, RuntimeError> {
    let environment = object(value)?;
    if environment.len() > MAX_ENVIRONMENT {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let mut total = 0;
    let mut result = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let value = value
            .as_str()
            .ok_or(RuntimeError::ExecutionManifestInvalid)?;
        total += name.len() + value.len();
        if !is_environment_name(name)
            || name.starts_with("LETSINFER_")
            || value.contains('\0')
            || value.contains(concat!("PRIVATE", " KEY"))
            || total > MAX_ENVIRONMENT_BYTES
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        result.push((name.clone(), value.to_string()));
    }
    Ok(result)
}

// Parses orchestration environment using its stricter uppercase wire contract.
fn parse_task_environment(value: &Value) -> Result<Vec<(String, String)>, RuntimeError> {
    let environment = parse_environment(value)?;
    if environment
        .iter()
        .any(|(name, _)| !is_task_environment_name(name))
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(environment)
}

// Validates sorted already-typed environment values used by deterministic manager mocks.
fn validate_environment_pairs(values: &[(String, String)]) -> Result<(), RuntimeError> {
    if values.len() > MAX_ENVIRONMENT {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    let mut total = 0;
    let mut previous: Option<&str> = None;
    for (name, value) in values {
        total += name.len() + value.len();
        if !is_environment_name(name)
            || name.starts_with("LETSINFER_")
            || previous.is_some_and(|previous| previous >= name.as_str())
            || value.contains('\0')
            || value.contains(concat!("PRIVATE", " KEY"))
            || total > MAX_ENVIRONMENT_BYTES
        {
            return Err(RuntimeError::ExecutionManifestInvalid);
        }
        previous = Some(name);
    }
    Ok(())
}

// Parses one supported runtime target platform.
fn parse_platform(value: &str) -> Result<RuntimeExecutionPlatform, RuntimeError> {
    match value {
        "linux/arm64" => Ok(RuntimeExecutionPlatform::LinuxArm64),
        "linux/x86_64" => Ok(RuntimeExecutionPlatform::LinuxX86_64),
        "macos/arm64" => Ok(RuntimeExecutionPlatform::MacosArm64),
        _ => Err(RuntimeError::ExecutionManifestInvalid),
    }
}

// Returns the canonical string identity for one supported platform.
const fn platform_name(platform: RuntimeExecutionPlatform) -> &'static str {
    match platform {
        RuntimeExecutionPlatform::LinuxArm64 => "linux/arm64",
        RuntimeExecutionPlatform::LinuxX86_64 => "linux/x86_64",
        RuntimeExecutionPlatform::MacosArm64 => "macos/arm64",
    }
}

// Returns one exact object or a stable invalid-manifest error.
fn object(value: &Value) -> Result<&Map<String, Value>, RuntimeError> {
    value
        .as_object()
        .ok_or(RuntimeError::ExecutionManifestInvalid)
}

// Returns one required field without accepting a fabricated default.
fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, RuntimeError> {
    object
        .get(name)
        .ok_or(RuntimeError::ExecutionManifestInvalid)
}

// Returns one required string field.
fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, RuntimeError> {
    required(object, name)?
        .as_str()
        .ok_or(RuntimeError::ExecutionManifestInvalid)
}

// Returns one required unsigned integer field.
fn unsigned(object: &Map<String, Value>, name: &str) -> Result<u64, RuntimeError> {
    required(object, name)?
        .as_u64()
        .ok_or(RuntimeError::ExecutionManifestInvalid)
}

// Returns one required boolean field.
fn boolean(object: &Map<String, Value>, name: &str) -> Result<bool, RuntimeError> {
    required(object, name)?
        .as_bool()
        .ok_or(RuntimeError::ExecutionManifestInvalid)
}

// Requires an exact field set with explicitly enumerated optional fields.
fn exact_fields(
    object: &Map<String, Value>,
    required_fields: &[&str],
    optional_fields: &[&str],
) -> Result<(), RuntimeError> {
    if required_fields
        .iter()
        .any(|field| !object.contains_key(*field))
        || object.keys().any(|field| {
            !required_fields.contains(&field.as_str()) && !optional_fields.contains(&field.as_str())
        })
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Converts one positive bounded integer to a u16.
fn positive_u16(value: u64, maximum: u64) -> Result<u16, RuntimeError> {
    let value = bounded(value, 1, maximum)?;
    u16::try_from(value).map_err(|_| RuntimeError::ExecutionManifestInvalid)
}

// Converts one positive bounded integer to a u32.
fn positive_u32(value: u64) -> Result<u32, RuntimeError> {
    if value == 0 {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    u32::try_from(value).map_err(|_| RuntimeError::ExecutionManifestInvalid)
}

// Requires one positive integer without changing its identity.
fn positive(value: u64) -> Result<u64, RuntimeError> {
    if value == 0 {
        Err(RuntimeError::ExecutionManifestInvalid)
    } else {
        Ok(value)
    }
}

// Requires one integer within an inclusive bounded range.
fn bounded(value: u64, minimum: u64, maximum: u64) -> Result<u64, RuntimeError> {
    if value < minimum || value > maximum {
        Err(RuntimeError::ExecutionManifestInvalid)
    } else {
        Ok(value)
    }
}

// Parses one lowercase unprefixed SHA-256 identity from a closed contract.
fn digest(value: &str) -> Result<Sha256Digest, RuntimeError> {
    Sha256Digest::parse(value).map_err(|_| RuntimeError::ExecutionManifestInvalid)
}

// Parses one sha256-prefixed digest into the shared wire identity.
fn prefixed_digest(value: &str) -> Result<Sha256Digest, RuntimeError> {
    Sha256Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::ExecutionManifestInvalid)?,
    )
    .map_err(|_| RuntimeError::ExecutionManifestInvalid)
}

// Parses one contained relative path without platform-dependent normalization.
fn relative_path(value: &str) -> Result<PathBuf, RuntimeError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 1024
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(path.to_path_buf())
}

// Validates a typed distribution supplied by production parsing or deterministic mocks.
fn validate_typed_distribution(
    platform: RuntimeExecutionPlatform,
    distribution: &RuntimeExecutionDistribution,
) -> Result<(), RuntimeError> {
    match (platform, distribution) {
        (
            RuntimeExecutionPlatform::LinuxArm64 | RuntimeExecutionPlatform::LinuxX86_64,
            RuntimeExecutionDistribution::Oci {
                identity_reference,
                execution_reference,
                immutable_id,
            },
        ) if valid_oci_execution_reference(
            identity_reference,
            execution_reference,
            immutable_id,
        ) =>
        {
            Ok(())
        }
        (
            RuntimeExecutionPlatform::MacosArm64,
            RuntimeExecutionDistribution::NativeArchive {
                entrypoint,
                upstream_executable,
                port_count,
            },
        ) if is_safe_relative_path(entrypoint)
            && is_safe_relative_path(upstream_executable)
            && (2..=4).contains(port_count) =>
        {
            Ok(())
        }
        (
            RuntimeExecutionPlatform::MacosArm64,
            RuntimeExecutionDistribution::PythonStandalone {
                entrypoint,
                interpreter,
                port_count,
            },
        ) if is_safe_relative_path(entrypoint)
            && is_safe_relative_path(interpreter)
            && (2..=4).contains(port_count) =>
        {
            Ok(())
        }
        (
            RuntimeExecutionPlatform::MacosArm64,
            RuntimeExecutionDistribution::EmbeddedApplication {
                bundle_id,
                embedded_engine,
                payload_id: _,
                source_revision: _,
                minimum_version: _,
                entrypoint,
                port_count,
            },
        ) if is_bundle_id(bundle_id)
            && validate_technical(embedded_engine).is_ok()
            && is_safe_relative_path(entrypoint)
            && (1..=4).contains(port_count) =>
        {
            Ok(())
        }
        _ => Err(RuntimeError::ExecutionManifestInvalid),
    }
}

// Requires signed identity to remain stable while allowing one exact local config execution ID.
fn valid_oci_execution_reference(
    identity_reference: &RuntimeSource,
    execution_reference: &RuntimeExecutionImageReference,
    immutable_id: &Sha256Digest,
) -> bool {
    if !identity_reference.as_str().contains("@sha256:") {
        return false;
    }
    match execution_reference.local_config_digest() {
        Some(config_digest) => {
            config_digest == immutable_id
                && execution_reference.as_str() == format!("sha256:{}", config_digest.as_str())
        }
        None => execution_reference.as_str() == identity_reference.as_str(),
    }
}

// Returns whether one relative path is contained and normalization-free.
fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

// Returns whether one absolute managed path is normalization-free.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Validates one lowercase bounded technical name.
fn validate_technical(value: &str) -> Result<(), RuntimeError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(RuntimeError::ExecutionManifestInvalid);
    }
    Ok(())
}

// Returns whether one environment name is portable and bounded.
fn is_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

// Returns whether one orchestration environment name uses its uppercase wire alphabet.
fn is_task_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

// Returns whether one value is an exact lowercase hexadecimal identity.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one embedded application bundle identity is canonical.
fn is_bundle_id(value: &str) -> bool {
    value.contains('.')
        && value.len() <= 255
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

// Returns the exact SHA-256 identity of one byte sequence.
fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 encoder produces one canonical digest")
}

// Serializes one JSON value into the Python-compatible canonical byte contract.
fn canonical_bytes(value: &Value) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| RuntimeError::ExecutionManifestInvalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Returns the canonical execution-contract SHA-256.
fn canonical_sha256(value: &Value) -> Result<Sha256Digest, RuntimeError> {
    Ok(sha256(&canonical_bytes(value)?))
}
