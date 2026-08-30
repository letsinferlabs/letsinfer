// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use flate2::read::GzDecoder;
use li_core_interface::{
    CpuArchitecture, EngineDistribution, NativeEngineKind, OperatingSystem, Sha256Digest,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    li_runtime_catalog_schema::parse_closed_json, RuntimeCandidate,
    RuntimeEmbeddedApplicationAcquisitionRequest, RuntimeEmbeddedApplicationProvider,
    RuntimeEngineArtifactFetcher, RuntimeEngineCommand, RuntimeEngineCommandRunner, RuntimeError,
    RuntimeHttpClient, RuntimeHttpRequest,
};

const MAX_RUNTIME_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1 << 30;
const MAX_ARCHIVE_ENTRIES: usize = 20_000;
const MAX_ARCHIVE_FILES: usize = 10_000;
const MAX_EXPANDED_BYTES: u64 = 2 << 30;
const MAX_STAGED_FILES: usize = 100_000;
const MAX_STAGED_BYTES: u64 = 4 << 30;
const MAX_ADAPTER_FILES: usize = 256;
const MAX_COMMAND_OUTPUT: usize = 4 * 1024;
const MATERIALIZER: &str = "letsinfer-native-engine-v5";

// Defines private native Engine parsing, extraction, identity, and receipt operations.
pub trait NativeRuntimeEngineIo: Send + Sync {
    // Requires one empty private Engine destination.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError>;

    // Reads one bounded runtime configuration without following its final path.
    fn read_runtime_config(&self, runtime_root: &Path) -> Result<Vec<u8>, RuntimeError>;

    // Calculates the exact native payload identity from runtime-owned adapter inputs.
    fn payload_id(
        &self,
        runtime_root: &Path,
        distribution: &Value,
        entrypoint: &Path,
        requirements_lock: Option<&Path>,
    ) -> Result<Sha256Digest, RuntimeError>;

    // Creates one exact private directory below the Engine destination.
    fn create_directory(&self, path: &Path) -> Result<(), RuntimeError>;

    // Extracts one bounded archive below its declared prefix without preserving links.
    fn extract_archive(
        &self,
        archive: &Path,
        destination: &Path,
        format: &str,
        strip_prefix: &Path,
    ) -> Result<(), RuntimeError>;

    // Removes one exact downloaded archive.
    fn remove_archive(&self, archive: &Path) -> Result<(), RuntimeError>;

    // Requires one regular executable without following the final path.
    fn validate_executable(&self, executable: &Path) -> Result<(), RuntimeError>;

    // Returns the exact staged tree identity before its receipt is written.
    fn tree_sha256(&self, destination: &Path) -> Result<Sha256Digest, RuntimeError>;

    // Writes one atomic secret-free native Engine receipt.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError>;

    // Writes one atomic app-owned acquisition receipt into the staged Engine tree.
    fn write_embedded_application_receipt(
        &self,
        destination: &Path,
        receipt: &[u8],
    ) -> Result<(), RuntimeError>;

    // Removes every contained acquisition entry while retaining the destination root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError>;
}

// Implements bounded no-follow native Engine materialization on the host filesystem.
pub struct SystemNativeRuntimeEngineIo;

impl NativeRuntimeEngineIo for SystemNativeRuntimeEngineIo {
    // Requires one owner-only empty destination created by RuntimeManager staging.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if destination
            .read_dir()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
            .next()
            .is_some()
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(())
    }

    // Reads one exact owner-controlled runtime.json file.
    fn read_runtime_config(&self, runtime_root: &Path) -> Result<Vec<u8>, RuntimeError> {
        validate_private_directory(runtime_root)?;
        read_bounded(&runtime_root.join("runtime.json"), MAX_RUNTIME_CONFIG_BYTES)
    }

    // Binds distribution metadata to the complete adapter and optional requirements closure.
    fn payload_id(
        &self,
        runtime_root: &Path,
        distribution: &Value,
        entrypoint: &Path,
        requirements_lock: Option<&Path>,
    ) -> Result<Sha256Digest, RuntimeError> {
        let mut subject = distribution
            .as_object()
            .cloned()
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        subject.remove("payload_id");
        subject.insert(
            "materializer".to_string(),
            Value::String(MATERIALIZER.to_string()),
        );
        let entrypoint = runtime_root.join(entrypoint);
        let adapter_root = entrypoint
            .parent()
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        let mut records = tree_records(runtime_root, adapter_root, MAX_ADAPTER_FILES, u64::MAX)?;
        if !records.iter().any(|record| {
            record
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| runtime_root.join(path) == entrypoint)
        }) {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        records.sort_by(|left, right| {
            left.get("path")
                .and_then(Value::as_str)
                .cmp(&right.get("path").and_then(Value::as_str))
        });
        subject.insert("adapter_files".to_string(), Value::Array(records));
        if let Some(requirements_lock) = requirements_lock {
            let digest = hash_file(&runtime_root.join(requirements_lock), u64::MAX)?.1;
            subject.insert(
                "requirements_lock_sha256".to_string(),
                Value::String(digest.as_str().to_string()),
            );
        }
        canonical_sha256(&Value::Object(subject))
    }

    // Creates one owner-only directory and rejects any existing foreign state.
    fn create_directory(&self, path: &Path) -> Result<(), RuntimeError> {
        if path.exists() || path.is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        validate_private_directory(
            path.parent()
                .ok_or(RuntimeError::EngineAcquisitionInvalid)?,
        )?;
        fs::create_dir(path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        set_mode(path, 0o700)
    }

    // Extracts one qualified tar.gz or ZIP archive through its exact safe provider.
    fn extract_archive(
        &self,
        archive: &Path,
        destination: &Path,
        format: &str,
        strip_prefix: &Path,
    ) -> Result<(), RuntimeError> {
        match format {
            "tar.gz" => extract_tar_gz(archive, destination, strip_prefix),
            "zip" => extract_zip(archive, destination, strip_prefix),
            _ => Err(RuntimeError::EngineAcquisitionInvalid),
        }
    }

    // Removes one exact regular archive without following links.
    fn remove_archive(&self, archive: &Path) -> Result<(), RuntimeError> {
        let metadata = fs::symlink_metadata(archive)
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        fs::remove_file(archive).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
    }

    // Requires one user-owned executable regular file.
    fn validate_executable(&self, executable: &Path) -> Result<(), RuntimeError> {
        let file = open_no_follow(executable)?;
        let metadata = file
            .metadata()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o111 == 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
        }
        Ok(())
    }

    // Hashes the complete staged tree using the production v1 record contract.
    fn tree_sha256(&self, destination: &Path) -> Result<Sha256Digest, RuntimeError> {
        let records = tree_records(destination, destination, MAX_STAGED_FILES, MAX_STAGED_BYTES)?;
        if records.is_empty() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        canonical_sha256(&serde_json::json!({
            "contract": "letsinfer-native-staged-tree-v1",
            "files": records
        }))
    }

    // Writes and atomically activates one bounded canonical receipt.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError> {
        write_private_receipt(
            destination,
            ".li_native_engine_receipt_v1.json.incoming",
            "li_native_engine_receipt_v1.json",
            receipt,
        )
    }

    // Persists only the identity receipt returned by the supervised application.
    fn write_embedded_application_receipt(
        &self,
        destination: &Path,
        receipt: &[u8],
    ) -> Result<(), RuntimeError> {
        write_private_receipt(
            destination,
            ".li_runtime_embedded_application_receipt_v1.json.incoming",
            "li_runtime_embedded_application_receipt_v1.json",
            receipt,
        )
    }

    // Removes only regular files and private directories below the exact root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        clear_directory(destination)
    }
}

// Materializes native-archive and Python-standalone Engines from exact runtime-owned inputs.
pub struct NativeRuntimeEngineFetcher {
    http: Arc<dyn RuntimeHttpClient>,
    runner: Arc<dyn RuntimeEngineCommandRunner>,
    io: Arc<dyn NativeRuntimeEngineIo>,
    embedded_application: Option<Arc<dyn RuntimeEmbeddedApplicationProvider>>,
}

impl NativeRuntimeEngineFetcher {
    // Creates one provider from explicit HTTP, process, and private-filesystem capabilities.
    pub const fn new(
        http: Arc<dyn RuntimeHttpClient>,
        runner: Arc<dyn RuntimeEngineCommandRunner>,
        io: Arc<dyn NativeRuntimeEngineIo>,
    ) -> Self {
        Self {
            http,
            runner,
            io,
            embedded_application: None,
        }
    }

    // Adds the explicit app-owned acquisition boundary without introducing a host fallback.
    pub fn with_embedded_application_provider(
        mut self,
        provider: Arc<dyn RuntimeEmbeddedApplicationProvider>,
    ) -> Self {
        self.embedded_application = Some(provider);
        self
    }

    // Materializes one exact native Engine and records its complete staged tree identity.
    fn acquire(
        &self,
        candidate: &RuntimeCandidate,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.io.prepare_destination(destination)?;
        let bytes = self.io.read_runtime_config(runtime_root)?;
        let plan = parse_plan(candidate, &bytes)?;
        let payload = self.io.payload_id(
            runtime_root,
            &plan.distribution,
            &plan.entrypoint,
            plan.requirements_lock(),
        )?;
        if payload != plan.payload_id {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let result = (|| {
            match &plan.kind {
                NativePlanKind::Archive {
                    archive,
                    upstream_executable,
                } => {
                    self.io
                        .validate_executable(&runtime_root.join(&plan.entrypoint))?;
                    let archive_path = destination.join(".li_native_engine_archive");
                    self.download_archive(archive, &archive_path)?;
                    let upstream = destination.join("upstream");
                    self.io.create_directory(&upstream)?;
                    self.io.extract_archive(
                        &archive_path,
                        &upstream,
                        &archive.format,
                        &archive.strip_prefix,
                    )?;
                    self.io.remove_archive(&archive_path)?;
                    self.io
                        .validate_executable(&upstream.join(upstream_executable))?;
                }
                NativePlanKind::Python {
                    archive,
                    version,
                    requirements_lock,
                } => {
                    let archive_path = destination.join(".li_native_python_archive");
                    self.download_archive(archive, &archive_path)?;
                    let python = destination.join("python");
                    self.io.create_directory(&python)?;
                    self.io.extract_archive(
                        &archive_path,
                        &python,
                        &archive.format,
                        &archive.strip_prefix,
                    )?;
                    self.io.remove_archive(&archive_path)?;
                    let interpreter = python.join("bin/python3");
                    self.io.validate_executable(&interpreter)?;
                    self.verify_python(&interpreter, version, destination)?;
                    let packages = destination.join("site-packages");
                    self.io.create_directory(&packages)?;
                    self.install_requirements(
                        &interpreter,
                        &packages,
                        &runtime_root.join(requirements_lock),
                        destination,
                    )?;
                }
                NativePlanKind::Embedded { request } => {
                    let acquisition = self
                        .embedded_application
                        .as_ref()
                        .ok_or(RuntimeError::EmbeddedApplicationUnavailable)?
                        .acquire(request)?;
                    acquisition.validate(request)?;
                    let receipt = request.receipt_value(acquisition.application_version())?;
                    self.io.write_embedded_application_receipt(
                        destination,
                        &canonical_bytes(&receipt)?,
                    )?;
                }
            }
            let tree_sha256 = self.io.tree_sha256(destination)?;
            let receipt = canonical_receipt(&plan.distribution, &tree_sha256)?;
            self.io.write_receipt(destination, &receipt)
        })();
        if result.is_err() {
            let _ = self.io.clear_destination(destination);
        }
        result
    }

    // Downloads one exact bounded archive and verifies its declared size and SHA-256.
    fn download_archive(
        &self,
        archive: &NativeArchive,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        let request = RuntimeHttpRequest::new(&archive.url, None, None, false, 24 * 60 * 60)
            .map_err(map_download_error)?;
        let download = self
            .http
            .download(&request, destination, archive.bytes)
            .map_err(map_download_error)?;
        if download.bytes() != archive.bytes || download.sha256() != &archive.sha256 {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(())
    }

    // Verifies one staged CPython interpreter reports the exact manifest version.
    fn verify_python(
        &self,
        interpreter: &Path,
        version: &str,
        working_directory: &Path,
    ) -> Result<(), RuntimeError> {
        let output = self.runner.run(
            &RuntimeEngineCommand::new(
                interpreter.to_path_buf(),
                vec![
                    "-c".to_string(),
                    "import platform; print(platform.python_version())".to_string(),
                ],
                Vec::new(),
                working_directory.to_path_buf(),
            )?,
            MAX_COMMAND_OUTPUT,
        )?;
        if output.status() != 0
            || std::str::from_utf8(output.stdout())
                .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?
                .trim()
                != version
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(())
    }

    // Installs one hash-locked dependency closure into the staged native Engine.
    fn install_requirements(
        &self,
        interpreter: &Path,
        packages: &Path,
        requirements_lock: &Path,
        working_directory: &Path,
    ) -> Result<(), RuntimeError> {
        let environment = vec![
            (
                "HOME".to_string(),
                path_string(working_directory)?.to_string(),
            ),
            ("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string()),
            ("PYTHONNOUSERSITE".to_string(), "1".to_string()),
            ("PYTHONSAFEPATH".to_string(), "1".to_string()),
        ];
        let output = self.runner.run(
            &RuntimeEngineCommand::new(
                interpreter.to_path_buf(),
                vec![
                    "-m".to_string(),
                    "pip".to_string(),
                    "install".to_string(),
                    "--quiet".to_string(),
                    "--disable-pip-version-check".to_string(),
                    "--no-deps".to_string(),
                    "--require-hashes".to_string(),
                    "--target".to_string(),
                    path_string(packages)?.to_string(),
                    "-r".to_string(),
                    path_string(requirements_lock)?.to_string(),
                ],
                environment,
                working_directory.to_path_buf(),
            )?,
            MAX_COMMAND_OUTPUT,
        )?;
        if output.status() != 0 {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        Ok(())
    }
}

impl RuntimeEngineArtifactFetcher for NativeRuntimeEngineFetcher {
    // Acquires one exact native Engine from its verified runtime configuration.
    fn fetch(
        &self,
        candidate: &RuntimeCandidate,
        runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.acquire(candidate, runtime_root, destination)
    }
}

// Carries one complete native Engine materialization plan.
struct NativePlan {
    distribution: Value,
    payload_id: Sha256Digest,
    entrypoint: PathBuf,
    kind: NativePlanKind,
}

impl NativePlan {
    // Returns the requirements lock only for Python-standalone materialization.
    fn requirements_lock(&self) -> Option<&Path> {
        match &self.kind {
            NativePlanKind::Python {
                requirements_lock, ..
            } => Some(requirements_lock),
            _ => None,
        }
    }
}

// Selects the exact native materialization mechanism without fallback.
enum NativePlanKind {
    Archive {
        archive: NativeArchive,
        upstream_executable: PathBuf,
    },
    Python {
        archive: NativeArchive,
        version: String,
        requirements_lock: PathBuf,
    },
    Embedded {
        request: RuntimeEmbeddedApplicationAcquisitionRequest,
    },
}

// Carries one exact immutable native archive identity.
struct NativeArchive {
    url: String,
    sha256: Sha256Digest,
    bytes: u64,
    format: String,
    strip_prefix: PathBuf,
}

// Parses one full runtime-owned native distribution and matches persisted compact identity.
fn parse_plan(candidate: &RuntimeCandidate, bytes: &[u8]) -> Result<NativePlan, RuntimeError> {
    let value = parse_closed_json(bytes).map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
    let runtime = value
        .as_object()
        .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
    if runtime.get("id").and_then(Value::as_str)
        != Some(candidate.runtime().candidate_id().as_str())
        || runtime.get("version").and_then(Value::as_str)
            != Some(candidate.runtime().version().as_str())
        || runtime.get("logical_model").and_then(Value::as_str)
            != Some(candidate.logical_model().as_str())
        || runtime
            .get("target")
            .and_then(Value::as_object)
            .and_then(|target| target.get("id"))
            .and_then(Value::as_str)
            != Some(candidate.runtime().target_id().as_str())
    {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let distribution = runtime
        .get("engine")
        .and_then(Value::as_object)
        .and_then(|engine| engine.get("distribution"))
        .cloned()
        .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
    let object = distribution
        .as_object()
        .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
    let kind_name = string(object, "kind")?;
    let kind = match kind_name {
        "native-archive" => NativeEngineKind::NativeArchive,
        "python-standalone" => NativeEngineKind::PythonStandalone,
        "embedded-application" => NativeEngineKind::EmbeddedApplication,
        _ => return Err(RuntimeError::EngineAcquisitionInvalid),
    };
    let EngineDistribution::Native {
        kind: expected_kind,
        platform: expected_platform,
        payload_id: expected_payload,
        source_revision,
    } = candidate.runtime().engine_distribution()
    else {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    };
    let platform = target_platform(candidate)?;
    let payload_id = prefixed_digest(string(object, "payload_id")?)?;
    if kind != *expected_kind
        || platform != string(object, "platform")?
        || expected_platform.operating_system() != OperatingSystem::Macos
        || expected_platform.architecture() != CpuArchitecture::Arm64
        || payload_id != *expected_payload
        || string(object, "source_revision")? != source_revision.as_str()
    {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let entrypoint = safe_relative(Path::new(string(object, "entrypoint")?))?;
    let port_count = unsigned(object, "port_count")?;
    if !(1..=4).contains(&port_count) {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let kind = match kind {
        NativeEngineKind::NativeArchive => {
            exact_fields(
                object,
                &[
                    "kind",
                    "platform",
                    "payload_id",
                    "source_revision",
                    "entrypoint",
                    "port_count",
                    "archive",
                    "upstream_executable",
                ],
            )?;
            if port_count < 2 {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            NativePlanKind::Archive {
                archive: parse_archive(
                    object
                        .get("archive")
                        .ok_or(RuntimeError::EngineAcquisitionInvalid)?,
                )?,
                upstream_executable: safe_relative(Path::new(string(
                    object,
                    "upstream_executable",
                )?))?,
            }
        }
        NativeEngineKind::PythonStandalone => {
            exact_fields(
                object,
                &[
                    "kind",
                    "platform",
                    "payload_id",
                    "source_revision",
                    "entrypoint",
                    "port_count",
                    "python",
                    "requirements_lock",
                ],
            )?;
            if port_count < 2 {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            let python = object
                .get("python")
                .and_then(Value::as_object)
                .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
            exact_fields(python, &["implementation", "version", "archive"])?;
            if string(python, "implementation")? != "cpython" {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            let version = string(python, "version")?;
            validate_python_version(version)?;
            NativePlanKind::Python {
                archive: parse_archive(
                    python
                        .get("archive")
                        .ok_or(RuntimeError::EngineAcquisitionInvalid)?,
                )?,
                version: version.to_string(),
                requirements_lock: safe_relative(Path::new(string(object, "requirements_lock")?))?,
            }
        }
        NativeEngineKind::EmbeddedApplication => {
            exact_fields(
                object,
                &[
                    "kind",
                    "platform",
                    "payload_id",
                    "source_revision",
                    "entrypoint",
                    "port_count",
                    "bundle_id",
                    "signing_policy",
                    "minimum_version",
                    "embedded_engine",
                ],
            )?;
            if platform != "macos/arm64"
                || string(object, "signing_policy")? != "deployment-managed"
            {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            NativePlanKind::Embedded {
                request: RuntimeEmbeddedApplicationAcquisitionRequest::new(
                    candidate.runtime().candidate_id().clone(),
                    candidate.runtime().version().clone(),
                    candidate.logical_model().clone(),
                    candidate.runtime().target_id().clone(),
                    candidate.runtime().runtime_digest().clone(),
                    candidate.runtime().manifest_digest().clone(),
                    payload_id.clone(),
                    source_revision.clone(),
                    string(object, "bundle_id")?.to_string(),
                    li_core_interface::TechnicalName::parse(string(object, "embedded_engine")?)
                        .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?,
                    li_core_interface::RuntimeVersion::parse(string(object, "minimum_version")?)
                        .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?,
                    entrypoint.clone(),
                    port_count as u16,
                )?,
            }
        }
    };
    Ok(NativePlan {
        distribution,
        payload_id,
        entrypoint,
        kind,
    })
}

// Parses one exact bounded HTTPS archive identity.
fn parse_archive(value: &Value) -> Result<NativeArchive, RuntimeError> {
    let object = value
        .as_object()
        .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
    exact_fields(
        object,
        &["url", "sha256", "bytes", "format", "strip_prefix"],
    )?;
    let url = string(object, "url")?;
    RuntimeHttpRequest::https(url, None).map_err(map_download_error)?;
    let bytes = unsigned(object, "bytes")?;
    if bytes == 0 || bytes > MAX_ARCHIVE_BYTES {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let format = string(object, "format")?;
    if !matches!(format, "tar.gz" | "zip") {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(NativeArchive {
        url: url.to_string(),
        sha256: Sha256Digest::parse(string(object, "sha256")?)
            .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?,
        bytes,
        format: format.to_string(),
        strip_prefix: safe_relative(Path::new(string(object, "strip_prefix")?))?,
    })
}

// Returns the candidate's canonical native platform identity.
fn target_platform(candidate: &RuntimeCandidate) -> Result<&'static str, RuntimeError> {
    match (
        candidate.target().operating_system(),
        candidate.target().architecture(),
    ) {
        (OperatingSystem::Macos, CpuArchitecture::Arm64) => Ok("macos/arm64"),
        _ => Err(RuntimeError::EngineAcquisitionInvalid),
    }
}

// Validates one exact supported CPython version.
fn validate_python_version(value: &str) -> Result<(), RuntimeError> {
    let components: Vec<&str> = value.split('.').collect();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
        || components[0] != "3"
        || components[1]
            .parse::<u8>()
            .ok()
            .is_none_or(|minor| !(8..=19).contains(&minor))
    {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(())
}

// Extracts one bounded tar.gz archive and resolves safe links as regular copies.
fn extract_tar_gz(
    archive: &Path,
    destination: &Path,
    strip_prefix: &Path,
) -> Result<(), RuntimeError> {
    validate_private_directory(destination)?;
    let file = open_no_follow(archive)?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
    let mut links = BTreeMap::new();
    let mut seen_files = HashSet::new();
    let mut entries_count = 0_usize;
    let mut files = 0_usize;
    let mut total = 0_u64;
    for entry in entries {
        let mut entry = entry.map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
        entries_count += 1;
        if entries_count > MAX_ARCHIVE_ENTRIES {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let archive_path = safe_relative(
            entry
                .path()
                .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?
                .as_ref(),
        )?;
        let Some(relative) = strip_archive_prefix(&archive_path, strip_prefix)? else {
            continue;
        };
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            create_private_parents(destination, &relative)?;
            continue;
        }
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let raw_target = entry
                .link_name()
                .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?
                .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
            let archive_target = safe_relative(
                &archive_path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .join(raw_target),
            )?;
            let target = strip_archive_prefix(&archive_target, strip_prefix)?
                .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
            if seen_files.contains(&relative) || links.insert(relative, target).is_some() {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            continue;
        }
        if !entry_type.is_file()
            || links.contains_key(&relative)
            || !seen_files.insert(relative.clone())
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        files += 1;
        let bytes = entry
            .header()
            .size()
            .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
        total = total
            .checked_add(bytes)
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        if files > MAX_ARCHIVE_FILES || total > MAX_EXPANDED_BYTES {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let target = destination.join(&relative);
        if target.exists() || target.is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        create_private_parents(
            destination,
            relative.parent().unwrap_or_else(|| Path::new("")),
        )?;
        let mode = if entry
            .header()
            .mode()
            .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?
            & 0o111
            != 0
        {
            0o755
        } else {
            0o644
        };
        let mut output = create_new_file(&target, mode)?;
        let copied = std::io::copy(&mut entry, &mut output)
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if copied != bytes {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        output
            .sync_all()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        set_mode(&target, mode)?;
    }
    for (relative, mut target_relative) in links.clone() {
        let mut visited = HashSet::new();
        while let Some(next) = links.get(&target_relative) {
            if !visited.insert(target_relative.clone()) {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            target_relative = next.clone();
        }
        let source = destination.join(&target_relative);
        let source_file = open_no_follow(&source)?;
        let metadata = source_file
            .metadata()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if !metadata.is_file() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let target = destination.join(&relative);
        if target.exists() || target.is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        create_private_parents(
            destination,
            relative.parent().unwrap_or_else(|| Path::new("")),
        )?;
        fs::copy(&source, &target).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            set_mode(&target, metadata.permissions().mode() & 0o777)?;
        }
    }
    if files == 0 {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(())
}

// Extracts one bounded ZIP archive without links, traversal, or metadata authority.
fn extract_zip(
    archive: &Path,
    destination: &Path,
    strip_prefix: &Path,
) -> Result<(), RuntimeError> {
    validate_private_directory(destination)?;
    let file = open_no_follow(archive)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
    if archive.len() == 0 || archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let mut seen = HashSet::new();
    let mut files = 0_usize;
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
        if entry.encrypted() || entry.is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let enclosed = entry
            .enclosed_name()
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        let archive_path = safe_relative(&enclosed)?;
        let Some(relative) = strip_archive_prefix(&archive_path, strip_prefix)? else {
            continue;
        };
        if entry.is_dir() {
            create_private_parents(destination, &relative)?;
            continue;
        }
        if !entry.is_file() || !seen.insert(relative.clone()) {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        files += 1;
        let bytes = entry.size();
        total = total
            .checked_add(bytes)
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        if files > MAX_ARCHIVE_FILES || total > MAX_EXPANDED_BYTES {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let target = destination.join(&relative);
        if target.exists() || target.is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        create_private_parents(
            destination,
            relative.parent().unwrap_or_else(|| Path::new("")),
        )?;
        let mode = if entry.unix_mode().unwrap_or(0) & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        let mut output = create_new_file(&target, mode)?;
        let copied = std::io::copy(&mut entry, &mut output)
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if copied != bytes {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        output
            .sync_all()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        set_mode(&target, mode)?;
    }
    if files == 0 {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(())
}

// Removes one exact archive prefix and returns None for its root entry.
fn strip_archive_prefix(path: &Path, prefix: &Path) -> Result<Option<PathBuf>, RuntimeError> {
    let Ok(relative) = path.strip_prefix(prefix) else {
        return Ok(None);
    };
    if relative.as_os_str().is_empty() {
        Ok(None)
    } else {
        safe_relative(relative).map(Some)
    }
}

// Returns deterministic regular-file records for one contained tree.
fn tree_records(
    root: &Path,
    tree: &Path,
    maximum_files: usize,
    maximum_bytes: u64,
) -> Result<Vec<Value>, RuntimeError> {
    let mut files = Vec::new();
    collect_files(tree, &mut files)?;
    files.sort();
    let mut total = 0_u64;
    let mut records = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
        if relative == Path::new("li_native_engine_receipt_v1.json")
            || relative == Path::new(".li_native_engine_receipt_v1.json.incoming")
            || relative
                .components()
                .any(|component| component.as_os_str() == "__pycache__")
        {
            continue;
        }
        if records.len() >= maximum_files {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let (bytes, digest, executable) = file_record(&path, maximum_bytes)?;
        total = total
            .checked_add(bytes)
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        if total > maximum_bytes {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        records.push(serde_json::json!({
            "path": path_string(relative)?,
            "bytes": bytes,
            "executable": executable,
            "sha256": digest.as_str()
        }));
    }
    Ok(records)
}

// Recursively collects regular files without following links.
fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), RuntimeError> {
    for entry in path
        .read_dir()
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
    {
        let path = entry
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
            .path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        if metadata.is_dir() {
            collect_files(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        } else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
    }
    Ok(())
}

// Returns exact file size, SHA-256, and executable identity.
fn file_record(path: &Path, maximum_bytes: u64) -> Result<(u64, Sha256Digest, bool), RuntimeError> {
    let file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    let (_, digest) = hash_open_file(file, maximum_bytes)?;
    Ok((metadata.len(), digest, executable))
}

// Hashes one exact regular file without following its final path.
fn hash_file(path: &Path, maximum_bytes: u64) -> Result<(u64, Sha256Digest), RuntimeError> {
    hash_open_file(open_no_follow(path)?, maximum_bytes)
}

// Hashes one already-open bounded file.
fn hash_open_file(mut file: File, maximum_bytes: u64) -> Result<(u64, Sha256Digest), RuntimeError> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        if total > maximum_bytes {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        digest.update(&buffer[..count]);
    }
    Ok((total, sha256_digest(digest.finalize().as_slice())))
}

// Encodes one deterministic li_-namespaced native Engine receipt.
fn canonical_receipt(
    distribution: &Value,
    tree_sha256: &Sha256Digest,
) -> Result<Vec<u8>, RuntimeError> {
    let value = serde_json::json!({
        "schema": {"name": "li_native_engine_receipt", "version": 1},
        "distribution": distribution,
        "tree_sha256": tree_sha256.as_str()
    });
    canonical_bytes(&value)
}

// Returns canonical JSON bytes with the shared trailing-newline contract.
fn canonical_bytes(value: &Value) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Returns the canonical JSON SHA-256.
fn canonical_sha256(value: &Value) -> Result<Sha256Digest, RuntimeError> {
    Ok(sha256(&canonical_bytes(value)?))
}

// Returns the exact SHA-256 identity of one byte sequence.
fn sha256(bytes: &[u8]) -> Sha256Digest {
    sha256_digest(Sha256::digest(bytes).as_slice())
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

// Parses one sha256-prefixed digest.
fn prefixed_digest(value: &str) -> Result<Sha256Digest, RuntimeError> {
    Sha256Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?,
    )
    .map_err(|_| RuntimeError::EngineAcquisitionInvalid)
}

// Returns one required string field.
fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, RuntimeError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::EngineAcquisitionInvalid)
}

// Returns one required unsigned integer field.
fn unsigned(object: &Map<String, Value>, name: &str) -> Result<u64, RuntimeError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(RuntimeError::EngineAcquisitionInvalid)
}

// Requires one exact JSON object field set.
fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), RuntimeError> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(())
}

// Maps HTTP failures into the native Engine boundary.
fn map_download_error(error: RuntimeError) -> RuntimeError {
    match error {
        RuntimeError::DownloadUnavailable => RuntimeError::EngineAcquisitionUnavailable,
        _ => RuntimeError::EngineAcquisitionInvalid,
    }
}

// Reads one bounded no-follow regular file.
fn read_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    if !metadata.is_file() || metadata.len() > maximum_bytes as u64 {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(bytes)
}

// Parses one contained relative path without normalization ambiguity.
fn safe_relative(path: &Path) -> Result<PathBuf, RuntimeError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(path.to_path_buf())
}

// Creates one private relative directory chain without following links.
fn create_private_parents(root: &Path, relative: &Path) -> Result<(), RuntimeError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        };
        current.push(component);
        if current.exists() || current.is_symlink() {
            validate_private_directory(&current)?;
        } else {
            fs::create_dir(&current).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
            set_mode(&current, 0o700)?;
        }
    }
    Ok(())
}

// Requires one no-follow owner-only directory.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
    }
    Ok(())
}

// Removes every safe contained entry from one private directory.
fn clear_directory(path: &Path) -> Result<(), RuntimeError> {
    let entries = path
        .read_dir()
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    for entry in entries {
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        if metadata.is_dir() {
            clear_directory(&path)?;
            fs::remove_dir(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        } else if metadata.is_file() {
            fs::remove_file(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        } else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
    }
    Ok(())
}

// Creates one no-follow regular file with an exact mode.
fn create_new_file(path: &Path, mode: u32) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
}

// Writes one bounded atomic private receipt without following or replacing existing state.
fn write_private_receipt(
    destination: &Path,
    incoming_name: &str,
    final_name: &str,
    receipt: &[u8],
) -> Result<(), RuntimeError> {
    validate_private_directory(destination)?;
    if receipt.is_empty() || receipt.len() > 64 * 1024 {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let incoming = destination.join(incoming_name);
    let final_path = destination.join(final_name);
    if incoming.exists() || incoming.is_symlink() || final_path.exists() || final_path.is_symlink()
    {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    let mut file = create_new_file(&incoming, 0o600)?;
    file.write_all(receipt)
        .and_then(|_| file.sync_all())
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    fs::rename(&incoming, &final_path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
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
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
}

// Sets one exact owner-controlled Unix mode.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
}

// Leaves modes to the future Windows provider.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), RuntimeError> {
    Ok(())
}

// Returns one UTF-8 path without lossy conversion.
fn path_string(path: &Path) -> Result<&str, RuntimeError> {
    path.to_str().ok_or(RuntimeError::EngineAcquisitionInvalid)
}
