// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

mod li_docker_runtime_engine_fetcher;
mod li_huggingface_model_fetcher;
mod li_native_runtime_engine_fetcher;
mod li_oci_runtime_pack_fetcher;
mod li_runtime_artifact_provider;
mod li_runtime_artifact_verifier;
mod li_runtime_catalog_hydrator;
mod li_runtime_catalog_provider;
mod li_runtime_catalog_schema;
mod li_runtime_embedded_application;
mod li_runtime_execution_manifest;
mod li_runtime_http_client;
mod li_runtime_lifecycle;

pub use li_docker_runtime_engine_fetcher::{
    DockerRuntimeEngineFetcher, DockerRuntimeEngineIo, RuntimeEngineCommand,
    RuntimeEngineCommandOutput, RuntimeEngineCommandRunner, SystemDockerRuntimeEngineIo,
    SystemRuntimeEngineCommandRunner,
};
pub use li_huggingface_model_fetcher::{
    HuggingFaceRuntimeModelFetcher, RuntimeModelArtifactIo, SystemRuntimeModelArtifactIo,
};
pub use li_native_runtime_engine_fetcher::{
    NativeRuntimeEngineFetcher, NativeRuntimeEngineIo, SystemNativeRuntimeEngineIo,
};
pub use li_oci_runtime_pack_fetcher::{
    OciRuntimePackFetcher, RuntimePackArtifactIo, RuntimePackDocuments, SystemRuntimePackArtifactIo,
};
pub use li_runtime_artifact_provider::{
    ComposedRuntimeArtifactFetcher, ComposedRuntimeEngineFetcher,
    FilesystemRuntimeArtifactProvider, RuntimeArtifactFetcher, RuntimeArtifactVerifier,
    RuntimeEngineArtifactFetcher, RuntimeModelArtifactFetcher, RuntimePackArtifactFetcher,
};
pub use li_runtime_artifact_verifier::{
    FilesystemRuntimeArtifactVerifier, RuntimeArtifactClosureIo, SystemRuntimeArtifactClosureIo,
};
pub use li_runtime_catalog_hydrator::{
    FilesystemRuntimeCatalogHydrationWorkspace, OciRuntimeCatalogCandidateHydrator,
    RuntimeCatalogHydrationWorkspace, RuntimeCatalogPackProvider,
};
pub use li_runtime_catalog_provider::{
    Ed25519RuntimeCatalogSignatureVerifier, FilesystemRuntimeCatalogCache, RuntimeCatalogAuthor,
    RuntimeCatalogAuthorKind, RuntimeCatalogCache, RuntimeCatalogCacheEntry,
    RuntimeCatalogCandidateHydrator, RuntimeCatalogClock, RuntimeCatalogEngineDistribution,
    RuntimeCatalogInterconnectKind, RuntimeCatalogListEntry, RuntimeCatalogListing,
    RuntimeCatalogLoadOptions, RuntimeCatalogPlacement, RuntimeCatalogRevocationAnchor,
    RuntimeCatalogSignatureKind, RuntimeCatalogSignatureVerifier, RuntimeCatalogSnapshot,
    RuntimeCatalogTarget, RuntimeCatalogTrustProvider, RuntimeCatalogTrustRoot,
    SignedRuntimeCatalogProvider, StaticRuntimeCatalogTrustProvider, SystemRuntimeCatalogClock,
};
pub use li_runtime_embedded_application::{
    RuntimeEmbeddedApplicationAcquisition, RuntimeEmbeddedApplicationAcquisitionRequest,
    RuntimeEmbeddedApplicationExecution, RuntimeEmbeddedApplicationExecutionRequest,
    RuntimeEmbeddedApplicationProvider,
};
pub use li_runtime_execution_manifest::{
    FilesystemRuntimeExecutionManifestProvider, RuntimeBenchmarkContract,
    RuntimeExecutionContainer, RuntimeExecutionDistribution, RuntimeExecutionImageReference,
    RuntimeExecutionManifest, RuntimeExecutionManifestIo, RuntimeExecutionManifestProvider,
    RuntimeExecutionPlatform, RuntimeExecutionReadiness, RuntimeExecutionServing,
    RuntimeExecutionTask, RuntimeInstallationProvider, RuntimeTaskLauncher,
    StoredRuntimeInstallationProvider, SystemRuntimeExecutionManifestIo,
};
pub use li_runtime_http_client::{
    CurlRuntimeHttpClient, RandomRuntimeHttpIdentityProvider, RuntimeBearerToken,
    RuntimeHttpClient, RuntimeHttpCommand, RuntimeHttpCommandOutput, RuntimeHttpCommandRunner,
    RuntimeHttpDownload, RuntimeHttpIdentityProvider, RuntimeHttpRequest, RuntimeHttpResponse,
    RuntimeHttpWorkspaceIo, SystemRuntimeHttpCommandRunner, SystemRuntimeHttpWorkspaceIo,
};
use li_runtime_lifecycle::RuntimeLifecycle;
pub use li_runtime_lifecycle::{
    RuntimeArtifactProvider, RuntimeChange, RuntimeClock, RuntimeEvent,
    RuntimeInstallationIdentityProvider, RuntimeInstallationStore, SystemRuntimeClock,
    SystemRuntimeInstallationIdentityProvider, VersionedRuntimeInstallation,
};

use li_core_interface::{
    AcceleratorVendor, ByteCount, ComputeCapability, CpuArchitecture, EvidenceLabel,
    HardwareObservation, LogicalModelName, MemoryTopology, ModelArtifact, NodeId, OperatingSystem,
    RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation, RuntimeInstallationId,
    RuntimeInstallationState, Sha256Digest, TechnicalName,
};

const ENGINE_PROTOCOL_VERSION: u16 = 2;

// Identifies how one trusted verifier Engine artifact is acquired without catalog selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeExactEngineArtifact {
    Reuse,
    BuiltOci {
        archive_file: PathBuf,
        config_digest: Sha256Digest,
        local_tag: String,
    },
    BuiltNative,
}

impl RuntimeExactEngineArtifact {
    // Returns the retained OCI archive only when preparation supplied one.
    pub fn archive_file(&self) -> Option<&Path> {
        match self {
            Self::BuiltOci { archive_file, .. } => Some(archive_file),
            Self::Reuse | Self::BuiltNative => None,
        }
    }
}

// Identifies one durable private Engine cleanup without retaining verifier artifact paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExactEngineCleanup {
    reference: String,
    local_tag: String,
    config_digest: Sha256Digest,
}

// Persists exact preexisting and transaction-created OCI image ownership across restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExactEngineOwnership {
    cleanup: RuntimeExactEngineCleanup,
    preexisting_config: bool,
    preexisting_reference: bool,
    preexisting_local_tag: bool,
    created_config: bool,
    created_reference: bool,
    created_local_tag: bool,
    acquired: bool,
}

impl RuntimeExactEngineOwnership {
    // Records the exact Docker state observed before any verifier image mutation.
    pub fn prepared(
        cleanup: RuntimeExactEngineCleanup,
        preexisting_config: bool,
        preexisting_reference: bool,
        preexisting_local_tag: bool,
    ) -> Result<Self, RuntimeError> {
        if (preexisting_reference || preexisting_local_tag) && !preexisting_config {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(Self {
            cleanup,
            preexisting_config,
            preexisting_reference,
            preexisting_local_tag,
            created_config: false,
            created_reference: false,
            created_local_tag: false,
            acquired: false,
        })
    }

    // Restores one closed marker while rechecking all ownership implications.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        cleanup: RuntimeExactEngineCleanup,
        preexisting_config: bool,
        preexisting_reference: bool,
        preexisting_local_tag: bool,
        created_config: bool,
        created_reference: bool,
        created_local_tag: bool,
        acquired: bool,
    ) -> Result<Self, RuntimeError> {
        if (preexisting_reference || preexisting_local_tag) && !preexisting_config
            || created_config && preexisting_config
            || created_reference && preexisting_reference
            || created_local_tag && preexisting_local_tag
            || !acquired && (created_config || created_reference || created_local_tag)
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(Self {
            cleanup,
            preexisting_config,
            preexisting_reference,
            preexisting_local_tag,
            created_config,
            created_reference,
            created_local_tag,
            acquired,
        })
    }

    // Completes one prepared marker only with identities proven created by this transaction.
    pub fn acquired(
        &self,
        created_config: bool,
        created_reference: bool,
        created_local_tag: bool,
    ) -> Result<Self, RuntimeError> {
        Self::restore(
            self.cleanup.clone(),
            self.preexisting_config,
            self.preexisting_reference,
            self.preexisting_local_tag,
            created_config,
            created_reference,
            created_local_tag,
            true,
        )
    }

    // Returns the exact built OCI cleanup identity.
    pub const fn cleanup(&self) -> &RuntimeExactEngineCleanup {
        &self.cleanup
    }

    // Returns whether the image configuration existed before this transaction.
    pub const fn preexisting_config(&self) -> bool {
        self.preexisting_config
    }

    // Returns whether the candidate reference existed before this transaction.
    pub const fn preexisting_reference(&self) -> bool {
        self.preexisting_reference
    }

    // Returns whether the finalizer local tag existed before this transaction.
    pub const fn preexisting_local_tag(&self) -> bool {
        self.preexisting_local_tag
    }

    // Returns whether this transaction introduced the image configuration.
    pub const fn created_config(&self) -> bool {
        self.created_config
    }

    // Returns whether this transaction introduced the candidate reference.
    pub const fn created_reference(&self) -> bool {
        self.created_reference
    }

    // Returns whether this transaction introduced the finalizer local tag.
    pub const fn created_local_tag(&self) -> bool {
        self.created_local_tag
    }

    // Returns whether acquisition completed and ownership may be cleaned.
    pub const fn is_acquired(&self) -> bool {
        self.acquired
    }
}

impl RuntimeExactEngineCleanup {
    // Creates one exact built-OCI cleanup identity after acquisition-mode validation.
    pub fn new(
        reference: String,
        local_tag: String,
        config_digest: Sha256Digest,
    ) -> Result<Self, RuntimeError> {
        if reference.is_empty()
            || reference.len() > 4096
            || local_tag.is_empty()
            || local_tag.len() > 255
            || reference.chars().any(char::is_whitespace)
            || local_tag.chars().any(char::is_whitespace)
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(Self {
            reference,
            local_tag,
            config_digest,
        })
    }

    // Returns the candidate Engine reference bound during acquisition.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    // Returns the trusted-finalizer local image tag.
    pub fn local_tag(&self) -> &str {
        &self.local_tag
    }

    // Returns the exact loaded image configuration identity.
    pub const fn config_digest(&self) -> &Sha256Digest {
        &self.config_digest
    }
}

// Carries only preparation-verified resident artifact inputs into RuntimeManager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExactCandidateArtifacts {
    runtime_pack_file: PathBuf,
    engine: RuntimeExactEngineArtifact,
    closure_sha256: Sha256Digest,
}

impl RuntimeExactCandidateArtifacts {
    // Creates one path-bounded artifact closure without accepting relative or aliased paths.
    pub fn new(
        runtime_pack_file: PathBuf,
        engine: RuntimeExactEngineArtifact,
        closure_sha256: Sha256Digest,
    ) -> Result<Self, RuntimeError> {
        let engine_valid = match &engine {
            RuntimeExactEngineArtifact::BuiltOci {
                archive_file,
                local_tag,
                ..
            } => {
                absolute_normal_path(archive_file)
                    && !local_tag.is_empty()
                    && local_tag.len() <= 255
                    && !local_tag.chars().any(char::is_whitespace)
            }
            RuntimeExactEngineArtifact::Reuse | RuntimeExactEngineArtifact::BuiltNative => true,
        };
        if !absolute_normal_path(&runtime_pack_file) || !engine_valid {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(Self {
            runtime_pack_file,
            engine,
            closure_sha256,
        })
    }

    // Returns the retained verified runtime pack.
    pub fn runtime_pack_file(&self) -> &Path {
        &self.runtime_pack_file
    }

    // Returns the closed Engine acquisition mode.
    pub const fn engine(&self) -> &RuntimeExactEngineArtifact {
        &self.engine
    }

    // Returns the trusted-finalizer closure identity.
    pub const fn closure_sha256(&self) -> &Sha256Digest {
        &self.closure_sha256
    }
}

// Identifies the accelerator vendor required by one runtime target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeAcceleratorVendor {
    Nvidia,
    Apple,
    Other(TechnicalName),
}

// Identifies the exact accelerator partitioning mode required by one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAcceleratorPartitioning {
    FullDevice,
    Mig,
}

// Describes stable per-node hardware requirements for runtime installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTarget {
    operating_system: OperatingSystem,
    architecture: CpuArchitecture,
    accelerator_vendor: RuntimeAcceleratorVendor,
    compute_architecture: TechnicalName,
    accelerator_count: u16,
    accelerator_partitioning: RuntimeAcceleratorPartitioning,
    memory_topology: MemoryTopology,
    minimum_accelerator_memory_bytes: Option<ByteCount>,
    minimum_host_memory_bytes: ByteCount,
}

impl RuntimeTarget {
    // Creates one coherent static target without checking live availability.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operating_system: OperatingSystem,
        architecture: CpuArchitecture,
        accelerator_vendor: RuntimeAcceleratorVendor,
        compute_architecture: TechnicalName,
        accelerator_count: u16,
        memory_topology: MemoryTopology,
        minimum_framebuffer_bytes: Option<ByteCount>,
        minimum_host_memory_bytes: ByteCount,
    ) -> Result<Self, RuntimeError> {
        if accelerator_count == 0 {
            return Err(RuntimeError::InvalidCandidate {
                reason: "runtime target requires at least one accelerator",
            });
        }
        if memory_topology == MemoryTopology::Discrete && minimum_framebuffer_bytes.is_none() {
            return Err(RuntimeError::InvalidCandidate {
                reason: "discrete runtime target requires framebuffer capacity",
            });
        }
        if memory_topology == MemoryTopology::Unified && minimum_framebuffer_bytes.is_some() {
            return Err(RuntimeError::InvalidCandidate {
                reason: "unified runtime target cannot require discrete framebuffer",
            });
        }
        Ok(Self {
            operating_system,
            architecture,
            accelerator_vendor,
            compute_architecture,
            accelerator_count,
            accelerator_partitioning: RuntimeAcceleratorPartitioning::FullDevice,
            memory_topology,
            minimum_accelerator_memory_bytes: minimum_framebuffer_bytes,
            minimum_host_memory_bytes,
        })
    }

    // Returns the required operating system.
    pub const fn operating_system(&self) -> OperatingSystem {
        self.operating_system
    }

    // Returns the required CPU architecture.
    pub const fn architecture(&self) -> CpuArchitecture {
        self.architecture
    }

    // Creates one catalog target while preserving its signed partitioning identity.
    #[allow(clippy::too_many_arguments)]
    fn from_catalog(
        operating_system: OperatingSystem,
        architecture: CpuArchitecture,
        accelerator_vendor: RuntimeAcceleratorVendor,
        compute_architecture: TechnicalName,
        accelerator_count: u16,
        accelerator_partitioning: RuntimeAcceleratorPartitioning,
        memory_topology: MemoryTopology,
        minimum_accelerator_memory_bytes: Option<ByteCount>,
        minimum_host_memory_bytes: ByteCount,
    ) -> Result<Self, RuntimeError> {
        let mut target = Self::new(
            operating_system,
            architecture,
            accelerator_vendor,
            compute_architecture,
            accelerator_count,
            memory_topology,
            (memory_topology == MemoryTopology::Discrete)
                .then_some(minimum_accelerator_memory_bytes)
                .flatten(),
            minimum_host_memory_bytes,
        )?;
        target.accelerator_partitioning = accelerator_partitioning;
        target.minimum_accelerator_memory_bytes = minimum_accelerator_memory_bytes;
        Ok(target)
    }
}

// Describes one exact catalog or direct runtime candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCandidate {
    logical_model: LogicalModelName,
    runtime: RuntimeIdentity,
    artifacts: Vec<ModelArtifact>,
    target: RuntimeTarget,
    evidence_label: EvidenceLabel,
    engine_protocol: u16,
    recommended: bool,
    revoked: bool,
}

impl RuntimeCandidate {
    // Creates one candidate with exact artifacts and target requirements.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        logical_model: LogicalModelName,
        runtime: RuntimeIdentity,
        artifacts: Vec<ModelArtifact>,
        target: RuntimeTarget,
        evidence_label: EvidenceLabel,
        engine_protocol: u16,
        recommended: bool,
        revoked: bool,
    ) -> Result<Self, RuntimeError> {
        if artifacts.is_empty() {
            return Err(RuntimeError::InvalidCandidate {
                reason: "runtime candidate requires model artifacts",
            });
        }
        Ok(Self {
            logical_model,
            runtime,
            artifacts,
            target,
            evidence_label,
            engine_protocol,
            recommended,
            revoked,
        })
    }

    // Returns the logical model exposed to users.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the exact runtime identity.
    pub const fn runtime(&self) -> &RuntimeIdentity {
        &self.runtime
    }

    // Returns exact model artifacts required by the runtime.
    pub fn artifacts(&self) -> &[ModelArtifact] {
        &self.artifacts
    }

    // Returns the descriptive evidence label.
    pub const fn evidence_label(&self) -> EvidenceLabel {
        self.evidence_label
    }

    // Returns the stable target requirements used during artifact acquisition.
    pub const fn target(&self) -> &RuntimeTarget {
        &self.target
    }
}

// Identifies one static incompatibility without referencing current free resources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeIncompatibility {
    OperatingSystem,
    Architecture,
    HostMemory,
    AcceleratorCount,
    AcceleratorVendor,
    AcceleratorPartitioning,
    ComputeArchitecture,
    MemoryTopology,
    FramebufferCapacity,
    EngineProtocol,
}

// Describes whether exact candidate bytes match stable observed hardware.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeInstallability {
    Installable {
        evidence_label: EvidenceLabel,
    },
    Incompatible {
        reasons: Vec<RuntimeIncompatibility>,
    },
}

// Describes whether one replacement is ready for NodeManager reference handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeUpdateDisposition {
    Ready,
    Failed,
}

// Keeps the current installation authoritative while returning one verified replacement result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeUpdateHandoff {
    current_installation_id: RuntimeInstallationId,
    replacement: RuntimeChange,
    disposition: RuntimeUpdateDisposition,
}

impl RuntimeUpdateHandoff {
    // Creates one handoff only from a terminal replacement installation result.
    fn new(
        current_installation_id: RuntimeInstallationId,
        replacement: RuntimeChange,
    ) -> Result<Self, RuntimeError> {
        let disposition = match replacement.installation().installation().state() {
            RuntimeInstallationState::Available => RuntimeUpdateDisposition::Ready,
            RuntimeInstallationState::Failed => RuntimeUpdateDisposition::Failed,
            _ => return Err(RuntimeError::LifecycleUnavailable),
        };
        Ok(Self {
            current_installation_id,
            replacement,
            disposition,
        })
    }

    // Returns the still-authoritative installation that NodeManager may later replace.
    pub const fn current_installation_id(&self) -> &RuntimeInstallationId {
        &self.current_installation_id
    }

    // Returns the independently installed replacement result.
    pub const fn replacement(&self) -> &RuntimeChange {
        &self.replacement
    }

    // Returns whether the replacement is ready or failed before handoff.
    pub const fn disposition(&self) -> RuntimeUpdateDisposition {
        self.disposition
    }

    // Consumes the handoff and returns its replacement lifecycle result.
    pub fn into_replacement(self) -> RuntimeChange {
        self.replacement
    }
}

// Defines the already-verified catalog capability consumed by RuntimeManager.
pub trait RuntimeCatalogProvider: Send + Sync {
    // Returns candidates in signed catalog preference order for one logical model.
    fn candidates(&self, model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError>;
}

// Describes one stable runtime selection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    CatalogUnavailable,
    CatalogInvalid,
    CatalogSignatureInvalid,
    CatalogTrustUnavailable,
    CatalogCacheUnavailable,
    CatalogTargetAmbiguous,
    InvalidCandidate {
        reason: &'static str,
    },
    CandidateNotFound,
    CandidateRevoked,
    Incompatible {
        reasons: Vec<RuntimeIncompatibility>,
    },
    LifecycleUnavailable,
    ArtifactUnavailable,
    StoreUnavailable,
    StoreConflict,
    InstallationNotFound,
    InstallationUnavailable,
    NoUpdateAvailable,
    ExecutionUnavailable,
    ExecutionManifestUnavailable,
    ExecutionManifestInvalid,
    DownloadUnavailable,
    DownloadInvalid,
    ModelAcquisitionUnavailable,
    ModelAcquisitionInvalid,
    RuntimePackAcquisitionUnavailable,
    RuntimePackAcquisitionInvalid,
    EngineAcquisitionUnavailable,
    EngineAcquisitionInvalid,
    EmbeddedApplicationUnavailable,
    EmbeddedApplicationInvalid,
}

impl fmt::Display for RuntimeError {
    // Presents stable runtime selection language without leaking catalog contents.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogUnavailable => formatter.write_str("runtime catalog is unavailable"),
            Self::CatalogInvalid => formatter.write_str("runtime catalog is invalid"),
            Self::CatalogSignatureInvalid => {
                formatter.write_str("runtime catalog signature is invalid")
            }
            Self::CatalogTrustUnavailable => {
                formatter.write_str("runtime catalog trust is unavailable")
            }
            Self::CatalogCacheUnavailable => {
                formatter.write_str("runtime catalog cache is unavailable")
            }
            Self::CatalogTargetAmbiguous => {
                formatter.write_str("runtime catalog target is ambiguous for observed hardware")
            }
            Self::InvalidCandidate { reason } => {
                write!(formatter, "runtime candidate is invalid: {reason}")
            }
            Self::CandidateNotFound => formatter.write_str("runtime candidate was not found"),
            Self::CandidateRevoked => formatter.write_str("runtime candidate is revoked"),
            Self::Incompatible { .. } => {
                formatter.write_str("runtime candidate is incompatible with observed hardware")
            }
            Self::LifecycleUnavailable => {
                formatter.write_str("runtime installation lifecycle is unavailable")
            }
            Self::ArtifactUnavailable => {
                formatter.write_str("runtime artifacts are unavailable or invalid")
            }
            Self::StoreUnavailable => {
                formatter.write_str("runtime installation storage is unavailable")
            }
            Self::StoreConflict => formatter.write_str("runtime installation changed concurrently"),
            Self::InstallationNotFound => formatter.write_str("runtime installation was not found"),
            Self::InstallationUnavailable => {
                formatter.write_str("runtime installation is not available for update")
            }
            Self::NoUpdateAvailable => {
                formatter.write_str("runtime installation is already current")
            }
            Self::ExecutionUnavailable => {
                formatter.write_str("runtime execution capability is unavailable")
            }
            Self::ExecutionManifestUnavailable => {
                formatter.write_str("runtime execution manifest is unavailable")
            }
            Self::ExecutionManifestInvalid => {
                formatter.write_str("runtime execution manifest is invalid")
            }
            Self::DownloadUnavailable => {
                formatter.write_str("immutable runtime download is unavailable")
            }
            Self::DownloadInvalid => formatter.write_str("immutable runtime download is invalid"),
            Self::ModelAcquisitionUnavailable => {
                formatter.write_str("exact model acquisition is unavailable")
            }
            Self::ModelAcquisitionInvalid => {
                formatter.write_str("exact model acquisition is invalid")
            }
            Self::RuntimePackAcquisitionUnavailable => {
                formatter.write_str("immutable runtime-pack acquisition is unavailable")
            }
            Self::RuntimePackAcquisitionInvalid => {
                formatter.write_str("immutable runtime-pack acquisition is invalid")
            }
            Self::EngineAcquisitionUnavailable => {
                formatter.write_str("immutable Engine acquisition is unavailable")
            }
            Self::EngineAcquisitionInvalid => {
                formatter.write_str("immutable Engine acquisition is invalid")
            }
            Self::EmbeddedApplicationUnavailable => {
                formatter.write_str("embedded application capability is unavailable")
            }
            Self::EmbeddedApplicationInvalid => {
                formatter.write_str("embedded application identity is invalid")
            }
        }
    }
}

impl Error for RuntimeError {}

// Owns runtime selection and static installability judgment.
pub struct RuntimeManager {
    catalog: Arc<dyn RuntimeCatalogProvider>,
    lifecycle: Option<RuntimeLifecycle>,
    executions: Option<Arc<dyn RuntimeExecutionManifestProvider>>,
    embedded_application: Option<Arc<dyn RuntimeEmbeddedApplicationProvider>>,
}

impl RuntimeManager {
    // Creates one manager from an already-verified catalog provider.
    pub const fn new(catalog: Arc<dyn RuntimeCatalogProvider>) -> Self {
        Self {
            catalog,
            lifecycle: None,
            executions: None,
            embedded_application: None,
        }
    }

    // Creates one manager with immutable acquisition and installation capabilities.
    pub fn with_lifecycle(
        catalog: Arc<dyn RuntimeCatalogProvider>,
        artifacts: Arc<dyn RuntimeArtifactProvider>,
        store: Arc<dyn RuntimeInstallationStore>,
        identity: Arc<dyn RuntimeInstallationIdentityProvider>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Self {
        Self {
            catalog,
            lifecycle: Some(RuntimeLifecycle::new(artifacts, store, identity, clock)),
            executions: None,
            embedded_application: None,
        }
    }

    // Adds the verified execution-manifest capability without changing lifecycle ownership.
    pub fn with_execution_provider(
        mut self,
        executions: Arc<dyn RuntimeExecutionManifestProvider>,
    ) -> Self {
        self.executions = Some(executions);
        self
    }

    // Adds the independently supervised embedded-application ownership boundary.
    pub fn with_embedded_application_provider(
        mut self,
        provider: Arc<dyn RuntimeEmbeddedApplicationProvider>,
    ) -> Self {
        self.embedded_application = Some(provider);
        self
    }

    // Returns one verified typed execution manifest for an Available installation.
    pub fn execution_manifest(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        self.executions
            .as_ref()
            .ok_or(RuntimeError::ExecutionUnavailable)?
            .manifest(installation_id)
    }

    // Transfers one verified embedded execution to its explicit application provider.
    pub fn execute_embedded_application(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeEmbeddedApplicationExecution, RuntimeError> {
        let manifest = self.execution_manifest(installation_id)?;
        let request = RuntimeEmbeddedApplicationExecutionRequest::from_manifest(&manifest)?;
        let execution = self
            .embedded_application
            .as_ref()
            .ok_or(RuntimeError::EmbeddedApplicationUnavailable)?
            .execute(&request)?;
        execution.validate(&request)?;
        Ok(execution)
    }

    // Selects an exact compatible candidate or validates an explicit candidate identity.
    pub fn select(
        &self,
        model: &LogicalModelName,
        explicit_candidate: Option<&RuntimeCandidateId>,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeCandidate, RuntimeError> {
        let candidates = self.catalog.candidates(model)?;
        let compatible_targets: HashSet<_> = candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    self.assess(candidate, hardware),
                    RuntimeInstallability::Installable { .. }
                )
            })
            .map(|candidate| candidate.runtime().target_id())
            .collect();
        if compatible_targets.len() > 1 {
            return Err(RuntimeError::CatalogTargetAmbiguous);
        }
        if let Some(explicit_candidate) = explicit_candidate {
            let candidate = candidates
                .into_iter()
                .find(|candidate| candidate.runtime().candidate_id() == explicit_candidate)
                .ok_or(RuntimeError::CandidateNotFound)?;
            return require_installable(candidate, hardware);
        }
        let mut compatible = Vec::new();
        for candidate in candidates
            .into_iter()
            .filter(|candidate| !candidate.revoked)
        {
            if matches!(
                self.assess(&candidate, hardware),
                RuntimeInstallability::Installable { .. }
            ) {
                compatible.push(candidate);
            }
        }
        compatible
            .into_iter()
            .find(|candidate| candidate.recommended)
            .ok_or(RuntimeError::CandidateNotFound)
    }

    // Assesses static compatibility without checking qualification or live allocation.
    pub fn assess(
        &self,
        candidate: &RuntimeCandidate,
        hardware: &HardwareObservation,
    ) -> RuntimeInstallability {
        let mut reasons = Vec::new();
        if hardware.platform().operating_system() != candidate.target.operating_system {
            reasons.push(RuntimeIncompatibility::OperatingSystem);
        }
        if hardware.platform().architecture() != candidate.target.architecture {
            reasons.push(RuntimeIncompatibility::Architecture);
        }
        if hardware.memory_bytes() < candidate.target.minimum_host_memory_bytes {
            reasons.push(RuntimeIncompatibility::HostMemory);
        }
        if hardware.accelerators().len() < usize::from(candidate.target.accelerator_count) {
            reasons.push(RuntimeIncompatibility::AcceleratorCount);
        }
        let matching: Vec<_> = hardware
            .accelerators()
            .iter()
            .filter(|accelerator| {
                vendor_matches(accelerator.vendor(), &candidate.target.accelerator_vendor)
            })
            .collect();
        if matching.len() < usize::from(candidate.target.accelerator_count) {
            reasons.push(RuntimeIncompatibility::AcceleratorVendor);
        }
        if candidate.target.accelerator_partitioning != RuntimeAcceleratorPartitioning::FullDevice {
            reasons.push(RuntimeIncompatibility::AcceleratorPartitioning);
        }
        if matching
            .iter()
            .filter(|accelerator| {
                compute_matches(
                    accelerator.compute(),
                    &candidate.target.compute_architecture,
                )
            })
            .count()
            < usize::from(candidate.target.accelerator_count)
        {
            reasons.push(RuntimeIncompatibility::ComputeArchitecture);
        }
        if matching
            .iter()
            .filter(|accelerator| {
                accelerator.memory().topology() == candidate.target.memory_topology
            })
            .count()
            < usize::from(candidate.target.accelerator_count)
        {
            reasons.push(RuntimeIncompatibility::MemoryTopology);
        }
        if let Some(minimum) = candidate.target.minimum_accelerator_memory_bytes {
            let sufficient = match candidate.target.memory_topology {
                MemoryTopology::Discrete => {
                    matching
                        .iter()
                        .filter(|accelerator| {
                            accelerator
                                .memory()
                                .framebuffer_bytes()
                                .is_some_and(|value| value >= minimum)
                        })
                        .count()
                        >= usize::from(candidate.target.accelerator_count)
                }
                MemoryTopology::Unified => hardware.memory_bytes() >= minimum,
                MemoryTopology::Unknown => false,
            };
            if !sufficient {
                reasons.push(RuntimeIncompatibility::FramebufferCapacity);
            }
        }
        if candidate.engine_protocol != ENGINE_PROTOCOL_VERSION {
            reasons.push(RuntimeIncompatibility::EngineProtocol);
        }
        if reasons.is_empty() {
            RuntimeInstallability::Installable {
                evidence_label: candidate.evidence_label,
            }
        } else {
            RuntimeInstallability::Incompatible { reasons }
        }
    }

    // Selects and completes one immutable runtime installation lifecycle.
    pub fn install(
        &self,
        node_id: NodeId,
        model: &LogicalModelName,
        explicit_candidate: Option<&RuntimeCandidateId>,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeChange, RuntimeError> {
        let candidate = self.select(model, explicit_candidate, hardware)?;
        self.lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .install(node_id, candidate)
    }

    // Installs one preparation-trusted exact candidate without mutable catalog reselection.
    pub fn install_exact_candidate(
        &self,
        node_id: NodeId,
        installation_id: RuntimeInstallationId,
        candidate: RuntimeCandidate,
        artifacts: RuntimeExactCandidateArtifacts,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeChange, RuntimeError> {
        let candidate = require_installable(candidate, hardware)?;
        validate_exact_artifacts(&candidate, &artifacts)?;
        self.lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .install_exact(node_id, installation_id, candidate, artifacts)
    }

    // Installs one different selected runtime while retaining the current installation.
    pub fn update(
        &self,
        current: &RuntimeInstallation,
        explicit_candidate: Option<&RuntimeCandidateId>,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeChange, RuntimeError> {
        self.prepare_update(current, explicit_candidate, hardware)
            .map(RuntimeUpdateHandoff::into_replacement)
    }

    // Installs one replacement while leaving current references and bytes untouched.
    pub fn prepare_update(
        &self,
        current: &RuntimeInstallation,
        explicit_candidate: Option<&RuntimeCandidateId>,
        hardware: &HardwareObservation,
    ) -> Result<RuntimeUpdateHandoff, RuntimeError> {
        if current.state() != RuntimeInstallationState::Available {
            return Err(RuntimeError::InstallationUnavailable);
        }
        let candidate = self.select(current.logical_model(), explicit_candidate, hardware)?;
        if candidate.runtime() == current.runtime() {
            return Err(RuntimeError::NoUpdateAvailable);
        }
        let replacement = self
            .lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .install(current.node_id().clone(), candidate)?;
        RuntimeUpdateHandoff::new(current.installation_id().clone(), replacement)
    }

    // Removes one exact runtime installation and its materialized artifacts.
    pub fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeChange, RuntimeError> {
        self.lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .remove(installation_id, false)
    }

    // Removes one installation while retaining its verified model closure for exact reuse.
    pub fn remove_preserving_models(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeChange, RuntimeError> {
        self.lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .remove(installation_id, true)
    }

    // Closes provider residue after every installation has reached terminal Removed state.
    pub fn finalize_cleanup(&self, preserve_models: bool) -> Result<(), RuntimeError> {
        self.lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .finalize_cleanup(preserve_models)
    }

    // Prunes only installations not retained by active NodeManager references.
    pub fn prune(
        &self,
        retained: &HashSet<RuntimeInstallationId>,
    ) -> Result<Vec<RuntimeInstallationId>, RuntimeError> {
        self.lifecycle
            .as_ref()
            .ok_or(RuntimeError::LifecycleUnavailable)?
            .prune(retained)
    }
}

// Requires a prepared Engine closure to preserve the candidate's immutable distribution identity.
fn validate_exact_artifacts(
    candidate: &RuntimeCandidate,
    artifacts: &RuntimeExactCandidateArtifacts,
) -> Result<(), RuntimeError> {
    match (
        candidate.runtime().engine_distribution(),
        artifacts.engine(),
    ) {
        (
            li_core_interface::EngineDistribution::Oci { immutable_id, .. },
            RuntimeExactEngineArtifact::BuiltOci { config_digest, .. },
        ) if immutable_id == config_digest => Ok(()),
        (li_core_interface::EngineDistribution::Oci { .. }, RuntimeExactEngineArtifact::Reuse)
        | (
            li_core_interface::EngineDistribution::Native { .. },
            RuntimeExactEngineArtifact::BuiltNative,
        ) => Ok(()),
        _ => Err(RuntimeError::ArtifactUnavailable),
    }
}

// Returns whether one artifact path is absolute, normal, and below the filesystem root.
fn absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Requires one selected candidate to be non-revoked and statically installable.
fn require_installable(
    candidate: RuntimeCandidate,
    hardware: &HardwareObservation,
) -> Result<RuntimeCandidate, RuntimeError> {
    if candidate.revoked {
        return Err(RuntimeError::CandidateRevoked);
    }
    let manager = RuntimeManager::new(Arc::new(EmptyCatalog));
    match manager.assess(&candidate, hardware) {
        RuntimeInstallability::Installable { .. } => Ok(candidate),
        RuntimeInstallability::Incompatible { reasons } => {
            Err(RuntimeError::Incompatible { reasons })
        }
    }
}

// Supplies no catalog values for the private assessment helper.
struct EmptyCatalog;

impl RuntimeCatalogProvider for EmptyCatalog {
    // Returns no candidates because assessment does not query this provider.
    fn candidates(&self, _model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        Ok(Vec::new())
    }
}

// Returns whether one observed vendor satisfies one runtime target vendor.
fn vendor_matches(observed: &AcceleratorVendor, required: &RuntimeAcceleratorVendor) -> bool {
    match (observed, required) {
        (AcceleratorVendor::Nvidia, RuntimeAcceleratorVendor::Nvidia)
        | (AcceleratorVendor::Apple, RuntimeAcceleratorVendor::Apple) => true,
        (AcceleratorVendor::Other(observed), RuntimeAcceleratorVendor::Other(required)) => {
            observed == required
        }
        _ => false,
    }
}

// Returns whether one observed compute identity matches the runtime architecture.
fn compute_matches(observed: &ComputeCapability, required: &TechnicalName) -> bool {
    match observed {
        ComputeCapability::Cuda { architecture, .. } => architecture == required,
        ComputeCapability::Metal { family, .. } => family == required,
        ComputeCapability::Other { capability, .. } => capability.as_ref() == Some(required),
    }
}
