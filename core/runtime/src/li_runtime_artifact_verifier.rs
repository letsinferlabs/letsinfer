// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{
    CpuArchitecture, EngineDistribution, ModelArtifact, ModelArtifactFormat, NativeEngineKind,
    OperatingSystem, RuntimeVersion, Sha256Digest,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    li_runtime_catalog_schema::parse_closed_json,
    li_runtime_embedded_application::version_at_least, NativeRuntimeEngineIo,
    RuntimeArtifactVerifier, RuntimeCandidate, RuntimeError, RuntimePackArtifactIo,
};

const MAX_RECEIPT_BYTES: usize = 16 * 1024 * 1024;
const MAX_MODEL_FILES: usize = 10_000;

// Defines offline root, model-receipt, and Engine-receipt verification operations.
pub trait RuntimeArtifactClosureIo: Send + Sync {
    // Requires the exact runtime/models/engine root and expected model directories.
    fn verify_layout(&self, candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError>;

    // Verifies one complete model artifact against its exact local receipt and bytes.
    fn verify_model(&self, artifact: &ModelArtifact, root: &Path) -> Result<(), RuntimeError>;

    // Verifies one Engine receipt and optional recomputed native tree identity.
    fn verify_engine(
        &self,
        candidate: &RuntimeCandidate,
        root: &Path,
        native_tree_sha256: Option<&Sha256Digest>,
        native_distribution: Option<&Value>,
    ) -> Result<(), RuntimeError>;
}

// Implements strict offline receipt and file verification on the host filesystem.
pub struct SystemRuntimeArtifactClosureIo;

impl RuntimeArtifactClosureIo for SystemRuntimeArtifactClosureIo {
    // Requires a closed three-directory installation layout with exact model names.
    fn verify_layout(&self, candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(root)?;
        let root_entries = directory_names(root)?;
        if root_entries
            != HashSet::from([
                "runtime".to_string(),
                "models".to_string(),
                "engine".to_string(),
            ])
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        for name in ["runtime", "models", "engine"] {
            validate_private_directory(&root.join(name))?;
        }
        let expected_models: HashSet<String> = candidate
            .artifacts()
            .iter()
            .map(|artifact| artifact.name().as_str().to_string())
            .collect();
        if directory_names(&root.join("models"))? != expected_models {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        for artifact in candidate.artifacts() {
            validate_private_directory(&root.join("models").join(artifact.name().as_str()))?;
        }
        Ok(())
    }

    // Verifies one exact model receipt, closed file inventory, modes, sizes, and digests.
    fn verify_model(&self, artifact: &ModelArtifact, root: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(root)?;
        let receipt_path = root.join("li_model_artifact_receipt_v1.json");
        let receipt = parse_closed_json(&read_bounded(&receipt_path, MAX_RECEIPT_BYTES)?)
            .map_err(|_| RuntimeError::ArtifactUnavailable)?;
        let object = receipt
            .as_object()
            .ok_or(RuntimeError::ArtifactUnavailable)?;
        exact_fields(object, &["schema", "artifact", "files"])?;
        validate_schema(object.get("schema"), "li_model_artifact_receipt", 1)?;
        validate_artifact_identity(
            object
                .get("artifact")
                .ok_or(RuntimeError::ArtifactUnavailable)?,
            artifact,
        )?;
        let files = object
            .get("files")
            .and_then(Value::as_array)
            .ok_or(RuntimeError::ArtifactUnavailable)?;
        if files.is_empty() || files.len() > MAX_MODEL_FILES {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        let mut expected = HashSet::new();
        for value in files {
            let record = value.as_object().ok_or(RuntimeError::ArtifactUnavailable)?;
            exact_fields(record, &["path", "bytes", "sha256"])?;
            let relative = safe_relative(Path::new(string(record, "path")?))?;
            if relative == Path::new("li_model_artifact_receipt_v1.json")
                || !expected.insert(relative.clone())
            {
                return Err(RuntimeError::ArtifactUnavailable);
            }
            let bytes = unsigned(record, "bytes")?;
            let digest = Sha256Digest::parse(string(record, "sha256")?)
                .map_err(|_| RuntimeError::ArtifactUnavailable)?;
            verify_model_file(&root.join(&relative), bytes, &digest)?;
        }
        let mut actual = source_files(root, MAX_MODEL_FILES + 1)?;
        actual.remove(Path::new("li_model_artifact_receipt_v1.json"));
        if actual != expected {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        Ok(())
    }

    // Verifies exact OCI or native Engine receipt identity without network access.
    fn verify_engine(
        &self,
        candidate: &RuntimeCandidate,
        root: &Path,
        native_tree_sha256: Option<&Sha256Digest>,
        native_distribution: Option<&Value>,
    ) -> Result<(), RuntimeError> {
        validate_private_directory(root)?;
        match candidate.runtime().engine_distribution() {
            EngineDistribution::Oci {
                reference,
                immutable_id,
                ..
            } => {
                if native_tree_sha256.is_some()
                    || native_distribution.is_some()
                    || directory_names(root)?
                        != HashSet::from(["li_engine_oci_v1.json".to_string()])
                {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                let receipt = parse_closed_json(&read_bounded(
                    &root.join("li_engine_oci_v1.json"),
                    MAX_RECEIPT_BYTES,
                )?)
                .map_err(|_| RuntimeError::ArtifactUnavailable)?;
                let receipt = receipt
                    .as_object()
                    .ok_or(RuntimeError::ArtifactUnavailable)?;
                exact_fields(
                    receipt,
                    &["schema", "reference", "immutable_id", "platform"],
                )?;
                validate_schema(receipt.get("schema"), "li_engine_oci_receipt", 1)?;
                if string(receipt, "reference")? != reference.as_str()
                    || string(receipt, "immutable_id")?
                        != format!("sha256:{}", immutable_id.as_str())
                    || string(receipt, "platform")? != target_platform(candidate)?
                {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
            }
            EngineDistribution::Native {
                kind,
                platform,
                payload_id,
                source_revision,
            } => {
                let tree = native_tree_sha256.ok_or(RuntimeError::ArtifactUnavailable)?;
                let expected_distribution = native_distribution
                    .and_then(Value::as_object)
                    .ok_or(RuntimeError::ArtifactUnavailable)?;
                let receipt = parse_closed_json(&read_bounded(
                    &root.join("li_native_engine_receipt_v1.json"),
                    MAX_RECEIPT_BYTES,
                )?)
                .map_err(|_| RuntimeError::ArtifactUnavailable)?;
                let receipt = receipt
                    .as_object()
                    .ok_or(RuntimeError::ArtifactUnavailable)?;
                exact_fields(receipt, &["schema", "distribution", "tree_sha256"])?;
                validate_schema(receipt.get("schema"), "li_native_engine_receipt", 1)?;
                if string(receipt, "tree_sha256")? != tree.as_str() {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                let distribution = receipt
                    .get("distribution")
                    .and_then(Value::as_object)
                    .ok_or(RuntimeError::ArtifactUnavailable)?;
                if distribution != expected_distribution {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                if string(distribution, "kind")? != native_kind(*kind)
                    || string(distribution, "platform")?
                        != platform_name(platform.operating_system(), platform.architecture())?
                    || string(distribution, "payload_id")?
                        != format!("sha256:{}", payload_id.as_str())
                    || string(distribution, "source_revision")? != source_revision.as_str()
                {
                    return Err(RuntimeError::ArtifactUnavailable);
                }
                if *kind == NativeEngineKind::EmbeddedApplication {
                    validate_embedded_application_receipt(candidate, root, distribution)?;
                }
            }
        }
        Ok(())
    }
}

// Verifies the app-owned receipt remains bound to the exact native distribution and runtime.
fn validate_embedded_application_receipt(
    candidate: &RuntimeCandidate,
    root: &Path,
    distribution: &Map<String, Value>,
) -> Result<(), RuntimeError> {
    if directory_names(root)?
        != HashSet::from([
            "li_native_engine_receipt_v1.json".to_string(),
            "li_runtime_embedded_application_receipt_v1.json".to_string(),
        ])
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let receipt = parse_closed_json(&read_bounded(
        &root.join("li_runtime_embedded_application_receipt_v1.json"),
        MAX_RECEIPT_BYTES,
    )?)
    .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let receipt = receipt
        .as_object()
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    exact_fields(
        receipt,
        &[
            "schema",
            "candidate_id",
            "version",
            "logical_model",
            "target_id",
            "runtime_digest",
            "manifest_digest",
            "payload_id",
            "source_revision",
            "bundle_id",
            "embedded_engine",
            "minimum_version",
            "application_version",
            "entrypoint",
            "port_count",
        ],
    )?;
    validate_schema(
        receipt.get("schema"),
        "li_runtime_embedded_application_receipt",
        1,
    )?;
    let minimum = RuntimeVersion::parse(string(receipt, "minimum_version")?)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let application = RuntimeVersion::parse(string(receipt, "application_version")?)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if string(receipt, "candidate_id")? != candidate.runtime().candidate_id().as_str()
        || string(receipt, "version")? != candidate.runtime().version().as_str()
        || string(receipt, "logical_model")? != candidate.logical_model().as_str()
        || string(receipt, "target_id")? != candidate.runtime().target_id().as_str()
        || string(receipt, "runtime_digest")? != candidate.runtime().runtime_digest().as_str()
        || string(receipt, "manifest_digest")? != candidate.runtime().manifest_digest().as_str()
        || string(receipt, "payload_id")?
            != string(distribution, "payload_id")?
                .strip_prefix("sha256:")
                .ok_or(RuntimeError::ArtifactUnavailable)?
        || string(receipt, "source_revision")? != string(distribution, "source_revision")?
        || string(receipt, "bundle_id")? != string(distribution, "bundle_id")?
        || string(receipt, "embedded_engine")? != string(distribution, "embedded_engine")?
        || minimum.as_str() != string(distribution, "minimum_version")?
        || string(receipt, "entrypoint")? != string(distribution, "entrypoint")?
        || unsigned(receipt, "port_count")? != unsigned(distribution, "port_count")?
        || !version_at_least(&application, &minimum)
            .map_err(|_| RuntimeError::ArtifactUnavailable)?
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(())
}

// Verifies one complete staged or installed RuntimeManager artifact closure.
pub struct FilesystemRuntimeArtifactVerifier {
    runtime_packs: Arc<dyn RuntimePackArtifactIo>,
    native_engines: Arc<dyn NativeRuntimeEngineIo>,
    closure: Arc<dyn RuntimeArtifactClosureIo>,
}

impl FilesystemRuntimeArtifactVerifier {
    // Creates one verifier from independently testable pack, native-tree, and closure ports.
    pub const fn new(
        runtime_packs: Arc<dyn RuntimePackArtifactIo>,
        native_engines: Arc<dyn NativeRuntimeEngineIo>,
        closure: Arc<dyn RuntimeArtifactClosureIo>,
    ) -> Self {
        Self {
            runtime_packs,
            native_engines,
            closure,
        }
    }
}

impl RuntimeArtifactVerifier for FilesystemRuntimeArtifactVerifier {
    // Verifies the exact model directory set and every artifact receipt and byte.
    fn verify_models(&self, artifacts: &[ModelArtifact], root: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(root)?;
        let expected = artifacts
            .iter()
            .map(|artifact| artifact.name().as_str().to_string())
            .collect::<HashSet<_>>();
        if directory_names(root)? != expected {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        for artifact in artifacts {
            self.closure
                .verify_model(artifact, &root.join(artifact.name().as_str()))?;
        }
        Ok(())
    }

    // Verifies exact layout, runtime pack, every model receipt, and Engine receipt/tree.
    fn verify(&self, candidate: &RuntimeCandidate, root: &Path) -> Result<(), RuntimeError> {
        self.closure.verify_layout(candidate, root)?;
        self.runtime_packs
            .verify_descriptor(&root.join("runtime"), candidate.runtime().runtime_digest())?;
        for artifact in candidate.artifacts() {
            self.closure.verify_model(
                artifact,
                &root.join("models").join(artifact.name().as_str()),
            )?;
        }
        let (native_tree, native_distribution) = match candidate.runtime().engine_distribution() {
            EngineDistribution::Oci { .. } => (None, None),
            EngineDistribution::Native { .. } => {
                let distribution = verified_native_distribution(
                    candidate,
                    &root.join("runtime"),
                    self.native_engines.as_ref(),
                )?;
                (
                    Some(self.native_engines.tree_sha256(&root.join("engine"))?),
                    Some(distribution),
                )
            }
        };
        self.closure.verify_engine(
            candidate,
            &root.join("engine"),
            native_tree.as_ref(),
            native_distribution.as_ref(),
        )
    }
}

// Recomputes native payload identity from the installed runtime configuration.
fn verified_native_distribution(
    candidate: &RuntimeCandidate,
    runtime_root: &Path,
    native_engines: &dyn NativeRuntimeEngineIo,
) -> Result<Value, RuntimeError> {
    let bytes = native_engines
        .read_runtime_config(runtime_root)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let runtime = parse_closed_json(&bytes).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let distribution = runtime
        .get("engine")
        .and_then(Value::as_object)
        .and_then(|engine| engine.get("distribution"))
        .cloned()
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    let object = distribution
        .as_object()
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    let entrypoint = safe_relative(Path::new(string(object, "entrypoint")?))?;
    let requirements = (string(object, "kind")? == "python-standalone")
        .then(|| string(object, "requirements_lock"))
        .transpose()?
        .map(Path::new)
        .map(safe_relative)
        .transpose()?;
    let calculated = native_engines
        .payload_id(
            runtime_root,
            &distribution,
            &entrypoint,
            requirements.as_deref(),
        )
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    let EngineDistribution::Native { payload_id, .. } = candidate.runtime().engine_distribution()
    else {
        return Err(RuntimeError::ArtifactUnavailable);
    };
    if calculated != *payload_id
        || string(object, "payload_id")? != format!("sha256:{}", payload_id.as_str())
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(distribution)
}

// Validates one exact nested schema identity.
fn validate_schema(value: Option<&Value>, name: &str, version: u64) -> Result<(), RuntimeError> {
    let value = value
        .and_then(Value::as_object)
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    exact_fields(value, &["name", "version"])?;
    if string(value, "name")? != name || unsigned(value, "version")? != version {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(())
}

// Requires one model receipt identity to equal its persisted artifact contract.
fn validate_artifact_identity(value: &Value, artifact: &ModelArtifact) -> Result<(), RuntimeError> {
    let value = value.as_object().ok_or(RuntimeError::ArtifactUnavailable)?;
    exact_fields(value, &["name", "uri", "revision", "format"])?;
    if string(value, "name")? != artifact.name().as_str()
        || string(value, "uri")? != artifact.uri().as_str()
        || string(value, "revision")? != artifact.revision().as_str()
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let format = value
        .get("format")
        .and_then(Value::as_object)
        .ok_or(RuntimeError::ArtifactUnavailable)?;
    match artifact.format() {
        ModelArtifactFormat::HuggingFaceSnapshot => {
            exact_fields(format, &["kind"])?;
            if string(format, "kind")? != "huggingface-snapshot" {
                return Err(RuntimeError::ArtifactUnavailable);
            }
        }
        ModelArtifactFormat::GgufFile(file) => {
            exact_fields(format, &["kind", "filename", "sha256", "bytes"])?;
            if string(format, "kind")? != "gguf-file"
                || string(format, "filename")? != file.filename()
                || string(format, "sha256")? != file.digest().as_str()
                || format.get("bytes").and_then(Value::as_u64) != file.bytes()
            {
                return Err(RuntimeError::ArtifactUnavailable);
            }
        }
    }
    Ok(())
}

// Verifies one owner-only model file's exact size and SHA-256.
fn verify_model_file(
    path: &Path,
    expected_bytes: u64,
    expected_digest: &Sha256Digest,
) -> Result<(), RuntimeError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| RuntimeError::ArtifactUnavailable)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if sha256_digest(digest.finalize().as_slice()) != *expected_digest {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(())
}

// Returns every regular file below one root without following links.
fn source_files(root: &Path, maximum: usize) -> Result<HashSet<PathBuf>, RuntimeError> {
    let mut files = HashSet::new();
    collect_files(root, root, maximum, &mut files)?;
    Ok(files)
}

// Recursively collects a bounded regular file inventory.
fn collect_files(
    root: &Path,
    current: &Path,
    maximum: usize,
    files: &mut HashSet<PathBuf>,
) -> Result<(), RuntimeError> {
    for entry in current
        .read_dir()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?
    {
        let path = entry.map_err(|_| RuntimeError::ArtifactUnavailable)?.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        if metadata.is_dir() {
            validate_private_directory(&path)?;
            collect_files(root, &path, maximum, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| RuntimeError::ArtifactUnavailable)?
                .to_path_buf();
            if !files.insert(relative) || files.len() > maximum {
                return Err(RuntimeError::ArtifactUnavailable);
            }
        } else {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(())
}

// Returns exact directory-entry names while rejecting files and links.
fn directory_names(path: &Path) -> Result<HashSet<String>, RuntimeError> {
    let mut names = HashSet::new();
    for entry in path
        .read_dir()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?
    {
        let entry = entry.map_err(|_| RuntimeError::ArtifactUnavailable)?;
        let metadata = entry
            .file_type()
            .map_err(|_| RuntimeError::ArtifactUnavailable)?;
        if !metadata.is_dir() && path.file_name().is_some_and(|name| name == "models") {
            return Err(RuntimeError::ArtifactUnavailable);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RuntimeError::ArtifactUnavailable)?;
        if !names.insert(name) {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(names)
}

// Returns the exact Core target platform spelling used in Engine receipts.
fn target_platform(candidate: &RuntimeCandidate) -> Result<&'static str, RuntimeError> {
    platform_name(
        candidate.target().operating_system(),
        candidate.target().architecture(),
    )
}

// Returns one canonical platform identity.
fn platform_name(
    operating_system: OperatingSystem,
    architecture: CpuArchitecture,
) -> Result<&'static str, RuntimeError> {
    match (operating_system, architecture) {
        (OperatingSystem::Linux, CpuArchitecture::Arm64) => Ok("linux/arm64"),
        (OperatingSystem::Linux, CpuArchitecture::X86_64) => Ok("linux/x86_64"),
        (OperatingSystem::Macos, CpuArchitecture::Arm64) => Ok("macos/arm64"),
        _ => Err(RuntimeError::ArtifactUnavailable),
    }
}

// Returns the exact published native Engine kind spelling.
fn native_kind(kind: NativeEngineKind) -> &'static str {
    match kind {
        NativeEngineKind::NativeArchive => "native-archive",
        NativeEngineKind::PythonStandalone => "python-standalone",
        NativeEngineKind::EmbeddedApplication => "embedded-application",
    }
}

// Requires one exact JSON object field set.
fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), RuntimeError> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(())
}

// Returns one required string field.
fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, RuntimeError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::ArtifactUnavailable)
}

// Returns one required unsigned integer field.
fn unsigned(object: &Map<String, Value>, name: &str) -> Result<u64, RuntimeError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(RuntimeError::ArtifactUnavailable)
}

// Parses one contained relative path without normalization ambiguity.
fn safe_relative(path: &Path) -> Result<PathBuf, RuntimeError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(path.to_path_buf())
}

// Requires one no-follow owner-only directory.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::ArtifactUnavailable);
        }
    }
    Ok(())
}

// Opens one regular file without following the final path.
fn open_no_follow(path: &Path) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| RuntimeError::ArtifactUnavailable)
}

// Reads one bounded no-follow regular file.
fn read_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if !metadata.is_file() || metadata.len() > maximum_bytes as u64 {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::ArtifactUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(RuntimeError::ArtifactUnavailable);
    }
    Ok(bytes)
}

// Converts finalized SHA-256 bytes into the shared identity type.
fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(
        &bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("SHA-256 encoder produces one canonical digest")
}
