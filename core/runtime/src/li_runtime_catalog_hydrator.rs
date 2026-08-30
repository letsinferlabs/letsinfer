// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, DirBuilder};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, CpuArchitecture, EngineDistribution,
    EntityTimestamps, EvidenceLabel, GgufFileIdentity, ModelArtifact, ModelArtifactFormat,
    NativeEngineKind, NodeId, OperatingSystem, PlatformIdentity, RuntimeIdentity,
    RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState, RuntimeSource,
    RuntimeVersion, Sha256Digest, UnixMilliseconds,
};
use serde_json::{Map, Value};

use crate::li_runtime_catalog_schema::parse_closed_json;
use crate::li_runtime_execution_manifest::validate_runtime_installation_manifest;
use crate::{
    OciRuntimePackFetcher, RuntimeCandidate, RuntimeCatalogCandidateHydrator,
    RuntimeCatalogInterconnectKind, RuntimeCatalogListEntry, RuntimeError, RuntimePackDocuments,
};

const MAXIMUM_WORKSPACE_ATTEMPTS: usize = 16;
const WORKSPACE_PREFIX: &str = ".li_runtime_catalog_hydration_";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

// Acquires and clears one immutable pack without coupling hydration to OCI mechanics.
pub trait RuntimeCatalogPackProvider: Send + Sync {
    // Materializes and verifies one exact source into an empty private workspace.
    fn documents(
        &self,
        source: &li_core_interface::RuntimeSource,
        workspace: &Path,
    ) -> Result<RuntimePackDocuments, RuntimeError>;

    // Clears only the exact materialized pack entries from one private workspace.
    fn clear(&self, workspace: &Path) -> Result<(), RuntimeError>;
}

impl RuntimeCatalogPackProvider for OciRuntimePackFetcher {
    // Delegates immutable registry acquisition to the production OCI provider.
    fn documents(
        &self,
        source: &li_core_interface::RuntimeSource,
        workspace: &Path,
    ) -> Result<RuntimePackDocuments, RuntimeError> {
        OciRuntimePackFetcher::documents(self, source, workspace)
    }

    // Delegates bounded no-follow cleanup to the production pack filesystem provider.
    fn clear(&self, workspace: &Path) -> Result<(), RuntimeError> {
        OciRuntimePackFetcher::clear(self, workspace)
    }
}

// Owns ephemeral private directories independently of runtime-pack acquisition.
pub trait RuntimeCatalogHydrationWorkspace: Send + Sync {
    // Creates one unique empty owner-only workspace.
    fn create(&self) -> Result<PathBuf, RuntimeError>;

    // Removes one exact empty workspace without following or recursively deleting it.
    fn remove(&self, workspace: &Path) -> Result<(), RuntimeError>;
}

// Creates hydration workspaces beneath one explicitly managed private root.
pub struct FilesystemRuntimeCatalogHydrationWorkspace {
    root: PathBuf,
}

impl FilesystemRuntimeCatalogHydrationWorkspace {
    // Creates one workspace provider without touching the configured root.
    pub fn new(root: PathBuf) -> Result<Self, RuntimeError> {
        if !is_absolute_normal_path(&root) {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(Self { root })
    }

    // Requires the configured parent to remain an owner-only ordinary directory.
    fn validate_root(&self) -> Result<(), RuntimeError> {
        validate_private_directory(&self.root)
    }
}

impl RuntimeCatalogHydrationWorkspace for FilesystemRuntimeCatalogHydrationWorkspace {
    // Creates one unpredictable directory with atomic non-replacement semantics.
    fn create(&self) -> Result<PathBuf, RuntimeError> {
        self.validate_root()?;
        for _attempt in 0..MAXIMUM_WORKSPACE_ATTEMPTS {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
            let identity = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let workspace = self.root.join(format!("{WORKSPACE_PREFIX}{identity}"));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(PRIVATE_DIRECTORY_MODE);
            }
            match builder.create(&workspace) {
                Ok(()) => {
                    validate_private_directory(&workspace)?;
                    return Ok(workspace);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(RuntimeError::CatalogCacheUnavailable),
            }
        }
        Err(RuntimeError::CatalogCacheUnavailable)
    }

    // Removes one empty direct child only after revalidating root, identity, and ownership.
    fn remove(&self, workspace: &Path) -> Result<(), RuntimeError> {
        self.validate_root()?;
        let parent = workspace
            .parent()
            .ok_or(RuntimeError::CatalogCacheUnavailable)?;
        let name = workspace
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(RuntimeError::CatalogCacheUnavailable)?;
        if parent != self.root || !name.starts_with(WORKSPACE_PREFIX) {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        validate_private_directory(workspace)?;
        if workspace
            .read_dir()
            .map_err(|_| RuntimeError::CatalogCacheUnavailable)?
            .next()
            .is_some()
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        fs::remove_dir(workspace).map_err(|_| RuntimeError::CatalogCacheUnavailable)
    }
}

// Hydrates one signed release through a fully verified immutable runtime pack.
pub struct OciRuntimeCatalogCandidateHydrator {
    packs: Arc<dyn RuntimeCatalogPackProvider>,
    workspaces: Arc<dyn RuntimeCatalogHydrationWorkspace>,
}

impl OciRuntimeCatalogCandidateHydrator {
    // Creates one hydrator from explicit immutable-pack and ephemeral-workspace capabilities.
    pub const fn new(
        packs: Arc<dyn RuntimeCatalogPackProvider>,
        workspaces: Arc<dyn RuntimeCatalogHydrationWorkspace>,
    ) -> Self {
        Self { packs, workspaces }
    }

    // Clears acquired bytes and removes their exact now-empty workspace.
    fn cleanup(&self, workspace: &Path) -> Result<(), RuntimeError> {
        self.packs.clear(workspace)?;
        self.workspaces.remove(workspace)
    }
}

impl RuntimeCatalogCandidateHydrator for OciRuntimeCatalogCandidateHydrator {
    // Acquires, verifies, parses, cross-checks, and then removes one runtime pack.
    fn hydrate(&self, release: &RuntimeCatalogListEntry) -> Result<RuntimeCandidate, RuntimeError> {
        let workspace = self.workspaces.create()?;
        let hydrated = self
            .packs
            .documents(release.source(), &workspace)
            .and_then(|documents| candidate(release, &documents));
        let cleanup = self.cleanup(&workspace);
        match (hydrated, cleanup) {
            (Ok(candidate), Ok(())) => Ok(candidate),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

// Builds one candidate only after exact runtime bytes preserve every signed projection.
fn candidate(
    release: &RuntimeCatalogListEntry,
    documents: &RuntimePackDocuments,
) -> Result<RuntimeCandidate, RuntimeError> {
    let value = parse_closed_json(documents.runtime()).map_err(|_| RuntimeError::CatalogInvalid)?;
    let root = value.as_object().ok_or(RuntimeError::CatalogInvalid)?;
    require_release_identity(root, release)?;
    require_target_identity(root, release)?;
    let artifacts = parse_artifacts(root)?;
    let distribution = parse_engine_distribution(root)?;
    let execution = root
        .get("orchestration")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"contract": "letsinfer-single-task-v1"}));
    let runtime = RuntimeIdentity::new(
        release.candidate_id().clone(),
        RuntimeVersion::parse(release.version()).map_err(|_| RuntimeError::CatalogInvalid)?,
        release.target().id().clone(),
        release.source().clone(),
        distribution,
        documents.descriptor_digest().clone(),
        crate::li_runtime_catalog_provider::sha256_digest(documents.runtime()),
        crate::li_runtime_catalog_provider::sha256_digest(
            &crate::li_runtime_catalog_provider::canonical_json_bytes(&execution)?,
        ),
    )
    .map_err(|_| RuntimeError::CatalogInvalid)?;
    validate_complete_runtime(release, documents.runtime(), &runtime, &artifacts)?;
    RuntimeCandidate::new(
        release.logical_model().clone(),
        runtime,
        artifacts,
        release.target().runtime_target()?,
        EvidenceLabel::Qualified,
        2,
        release.is_recommended(),
        false,
    )
    .map_err(|_| RuntimeError::CatalogInvalid)
}

// Parses every exact model artifact identity from one schema-6 runtime document.
fn parse_artifacts(root: &Map<String, Value>) -> Result<Vec<ModelArtifact>, RuntimeError> {
    let values = root
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or(RuntimeError::CatalogInvalid)?;
    if values.is_empty() || values.len() > 64 {
        return Err(RuntimeError::CatalogInvalid);
    }
    values
        .iter()
        .map(|value| {
            let object = value.as_object().ok_or(RuntimeError::CatalogInvalid)?;
            let format = match string(object, "format")? {
                "huggingface-snapshot" => {
                    exact_fields(object, &["name", "uri", "format", "revision"])?;
                    ModelArtifactFormat::HuggingFaceSnapshot
                }
                "gguf-file" => {
                    let fields = if object.contains_key("bytes") {
                        &[
                            "name", "uri", "format", "revision", "filename", "sha256", "bytes",
                        ][..]
                    } else {
                        &["name", "uri", "format", "revision", "filename", "sha256"][..]
                    };
                    exact_fields(object, fields)?;
                    let bytes = match object.get("bytes") {
                        Some(value) => Some(
                            value
                                .as_u64()
                                .filter(|value| *value > 0)
                                .ok_or(RuntimeError::CatalogInvalid)?,
                        ),
                        None => None,
                    };
                    ModelArtifactFormat::GgufFile(
                        GgufFileIdentity::new(
                            string(object, "filename")?,
                            Sha256Digest::parse(string(object, "sha256")?)
                                .map_err(|_| RuntimeError::CatalogInvalid)?,
                            bytes,
                        )
                        .map_err(|_| RuntimeError::CatalogInvalid)?,
                    )
                }
                _ => return Err(RuntimeError::CatalogInvalid),
            };
            Ok(ModelArtifact::new(
                ArtifactName::parse(string(object, "name")?)
                    .map_err(|_| RuntimeError::CatalogInvalid)?,
                ArtifactUri::parse(string(object, "uri")?)
                    .map_err(|_| RuntimeError::CatalogInvalid)?,
                ArtifactRevision::parse(string(object, "revision")?)
                    .map_err(|_| RuntimeError::CatalogInvalid)?,
                format,
            ))
        })
        .collect()
}

// Parses the closed OCI or native Engine distribution from one schema-6 runtime document.
fn parse_engine_distribution(
    root: &Map<String, Value>,
) -> Result<EngineDistribution, RuntimeError> {
    let distribution = root
        .get("engine")
        .and_then(Value::as_object)
        .and_then(|engine| engine.get("distribution"))
        .and_then(Value::as_object)
        .ok_or(RuntimeError::CatalogInvalid)?;
    match string(distribution, "kind")? {
        "oci-container" => {
            let fields = match (
                distribution.contains_key("base"),
                distribution.contains_key("payload_id"),
            ) {
                (true, true) => &["kind", "reference", "immutable_id", "base", "payload_id"][..],
                (true, false) => &["kind", "reference", "immutable_id", "base"][..],
                (false, true) => &["kind", "reference", "immutable_id", "payload_id"][..],
                (false, false) => &["kind", "reference", "immutable_id"][..],
            };
            exact_fields(distribution, fields)?;
            Ok(EngineDistribution::oci(
                RuntimeSource::parse(string(distribution, "reference")?)
                    .map_err(|_| RuntimeError::CatalogInvalid)?,
                prefixed_digest(string(distribution, "immutable_id")?)?,
                distribution
                    .get("base")
                    .map(|value| value.as_str().ok_or(RuntimeError::CatalogInvalid))
                    .transpose()?
                    .map(RuntimeSource::parse)
                    .transpose()
                    .map_err(|_| RuntimeError::CatalogInvalid)?,
                distribution
                    .get("payload_id")
                    .map(|value| value.as_str().ok_or(RuntimeError::CatalogInvalid))
                    .transpose()?
                    .map(prefixed_digest)
                    .transpose()?,
            ))
        }
        kind @ ("native-archive" | "python-standalone" | "embedded-application") => {
            exact_fields(
                distribution,
                &["kind", "platform", "payload_id", "source_revision"],
            )?;
            let (operating_system, architecture) = match string(distribution, "platform")? {
                "macos/arm64" => (OperatingSystem::Macos, CpuArchitecture::Arm64),
                _ => return Err(RuntimeError::CatalogInvalid),
            };
            let kind = match kind {
                "native-archive" => NativeEngineKind::NativeArchive,
                "python-standalone" => NativeEngineKind::PythonStandalone,
                "embedded-application" => NativeEngineKind::EmbeddedApplication,
                _ => unreachable!(),
            };
            Ok(EngineDistribution::native(
                kind,
                PlatformIdentity::new(operating_system, architecture),
                prefixed_digest(string(distribution, "payload_id")?)?,
                ArtifactRevision::parse(string(distribution, "source_revision")?)
                    .map_err(|_| RuntimeError::CatalogInvalid)?,
            ))
        }
        _ => Err(RuntimeError::CatalogInvalid),
    }
}

// Parses one Engine sha256-prefixed immutable identity.
fn prefixed_digest(value: &str) -> Result<Sha256Digest, RuntimeError> {
    Sha256Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::CatalogInvalid)?,
    )
    .map_err(|_| RuntimeError::CatalogInvalid)
}

// Requires one JSON object to contain exactly the declared fields.
fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), RuntimeError> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Requires the runtime document's top-level identities to equal the signed release.
fn require_release_identity(
    root: &Map<String, Value>,
    release: &RuntimeCatalogListEntry,
) -> Result<(), RuntimeError> {
    let engine = object(required(root, "engine")?)?;
    if unsigned(root, "schema_version")? != 6
        || string(root, "id")? != release.candidate_id().as_str()
        || string(root, "version")? != release.version()
        || string(root, "logical_model")? != release.logical_model().as_str()
        || string(engine, "id")? != release.engine().as_str()
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Requires every static target and placement field to equal the signed catalog target.
fn require_target_identity(
    root: &Map<String, Value>,
    release: &RuntimeCatalogListEntry,
) -> Result<(), RuntimeError> {
    let expected = release.target();
    let target = object(required(root, "target")?)?;
    let accelerator = object(required(target, "accelerator")?)?;
    let memory = object(required(target, "memory")?)?;
    let placement = object(required(target, "placement")?)?;
    let interconnect = object(required(placement, "interconnect")?)?;
    let partitioning = match expected.accelerator_partitioning {
        crate::RuntimeAcceleratorPartitioning::FullDevice => "full-device",
        crate::RuntimeAcceleratorPartitioning::Mig => "mig",
    };
    let topology = match expected.memory_topology {
        li_core_interface::MemoryTopology::Unified => "unified",
        li_core_interface::MemoryTopology::Discrete => "discrete",
        li_core_interface::MemoryTopology::Unknown => return Err(RuntimeError::CatalogInvalid),
    };
    let strategy = if expected.placement.parallel {
        "parallel"
    } else {
        "single"
    };
    let interconnect_kind = match expected.placement.interconnect {
        RuntimeCatalogInterconnectKind::Any => "any",
        RuntimeCatalogInterconnectKind::Connectx => "connectx",
        RuntimeCatalogInterconnectKind::Ethernet => "ethernet",
        RuntimeCatalogInterconnectKind::Wifi => "wifi",
        RuntimeCatalogInterconnectKind::Other => "other",
    };
    let minimum_accelerator = accelerator
        .get("minimum_memory_gib")
        .and_then(Value::as_u64);
    if string(target, "id")? != expected.id.as_str()
        || string(target, "platform")?
            != format!("{}/{}", expected.operating_system, expected.architecture)
        || string(accelerator, "vendor")? != expected.accelerator_vendor
        || string(accelerator, "architecture")? != expected.compute_architecture
        || unsigned(accelerator, "count")? != expected.accelerator_count
        || string(accelerator, "partitioning")? != partitioning
        || minimum_accelerator != expected.minimum_accelerator_memory_gib
        || string(memory, "topology")? != topology
        || unsigned(memory, "minimum_total_gib")? != expected.minimum_total_memory_gib
        || string(placement, "strategy")? != strategy
        || unsigned(placement, "node_count")? != u64::from(expected.placement.node_count)
        || string(interconnect, "kind")? != interconnect_kind
        || boolean(interconnect, "rdma_required")? != expected.placement.rdma_required
        || unsigned(interconnect, "minimum_speed_mbps")? != expected.placement.minimum_speed_mbps
        || unsigned(interconnect, "minimum_mtu")? != u64::from(expected.placement.minimum_mtu)
    {
        return Err(RuntimeError::CatalogInvalid);
    }
    Ok(())
}

// Reuses the complete execution parser so hydration cannot accept a partial schema-6 document.
fn validate_complete_runtime(
    release: &RuntimeCatalogListEntry,
    bytes: &[u8],
    runtime: &RuntimeIdentity,
    artifacts: &[li_core_interface::ModelArtifact],
) -> Result<(), RuntimeError> {
    let installation = RuntimeInstallation::new(
        RuntimeInstallationId::parse(&"0".repeat(32)).map_err(|_| RuntimeError::CatalogInvalid)?,
        NodeId::parse(&"0".repeat(32)).map_err(|_| RuntimeError::CatalogInvalid)?,
        release.logical_model().clone(),
        runtime.clone(),
        artifacts.to_vec(),
        EvidenceLabel::Qualified,
        RuntimeInstallationState::Available,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(0), UnixMilliseconds::new(0))
            .map_err(|_| RuntimeError::CatalogInvalid)?,
    )
    .map_err(|_| RuntimeError::CatalogInvalid)?;
    validate_runtime_installation_manifest(bytes, &installation)
        .map_err(|_| RuntimeError::CatalogInvalid)
}

// Returns one required field without accepting absence.
fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, RuntimeError> {
    object.get(name).ok_or(RuntimeError::CatalogInvalid)
}

// Returns one exact object field.
fn object(value: &Value) -> Result<&Map<String, Value>, RuntimeError> {
    value.as_object().ok_or(RuntimeError::CatalogInvalid)
}

// Returns one exact string field.
fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, RuntimeError> {
    required(object, name)?
        .as_str()
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns one exact unsigned integer field.
fn unsigned(object: &Map<String, Value>, name: &str) -> Result<u64, RuntimeError> {
    required(object, name)?
        .as_u64()
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns one exact Boolean field.
fn boolean(object: &Map<String, Value>, name: &str) -> Result<bool, RuntimeError> {
    required(object, name)?
        .as_bool()
        .ok_or(RuntimeError::CatalogInvalid)
}

// Returns whether one configured workspace root is absolute and normalization-free.
fn is_absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

// Requires one ordinary owner-only directory without following its final component.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::CatalogCacheUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
    }
    Ok(())
}
