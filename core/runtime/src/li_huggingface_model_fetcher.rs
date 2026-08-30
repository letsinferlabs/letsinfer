// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{ModelArtifact, ModelArtifactFormat, Sha256Digest};
use serde_json::Value;

use crate::{
    li_runtime_catalog_schema::parse_closed_json, RuntimeError, RuntimeHttpClient,
    RuntimeHttpRequest, RuntimeModelArtifactFetcher,
};

const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
const MAX_TOTAL_BYTES: u64 = 1 << 40;
const MAX_PAGES: usize = 256;

// Defines private model destination operations behind one deterministic boundary.
pub trait RuntimeModelArtifactIo: Send + Sync {
    // Requires one empty private artifact destination.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError>;

    // Creates every missing private directory for one contained relative parent.
    fn create_parent(&self, destination: &Path, relative: &Path) -> Result<(), RuntimeError>;

    // Seals one downloaded regular file as owner-only immutable input.
    fn seal_file(&self, path: &Path) -> Result<(), RuntimeError>;

    // Writes one atomic exact artifact/file receipt after every download succeeds.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError>;

    // Removes every contained artifact entry while retaining the destination root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError>;
}

// Implements private no-follow model destination operations on the host filesystem.
pub struct SystemRuntimeModelArtifactIo;

impl RuntimeModelArtifactIo for SystemRuntimeModelArtifactIo {
    // Requires one owner-only empty destination created by RuntimeManager staging.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if destination
            .read_dir()
            .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?
            .next()
            .is_some()
        {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        Ok(())
    }

    // Creates one relative directory chain without following existing links.
    fn create_parent(&self, destination: &Path, relative: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        let mut current = destination.to_path_buf();
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(RuntimeError::ModelAcquisitionInvalid);
            };
            current.push(component);
            if current.exists() || current.is_symlink() {
                validate_private_directory(&current)?;
            } else {
                fs::create_dir(&current).map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
                set_mode(&current, 0o700)?;
            }
        }
        Ok(())
    }

    // Restricts one exact regular file and synchronizes its complete bytes.
    fn seal_file(&self, path: &Path) -> Result<(), RuntimeError> {
        let file = open_no_follow(path)?;
        let metadata = file
            .metadata()
            .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        if !metadata.is_file() {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        }
        file.sync_all()
            .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)
    }

    // Writes and atomically activates one bounded li_-namespaced model receipt.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if receipt.is_empty() || receipt.len() > 16 * 1024 * 1024 {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        let incoming = destination.join(".li_model_artifact_receipt_v1.json.incoming");
        let final_path = destination.join("li_model_artifact_receipt_v1.json");
        if incoming.exists()
            || incoming.is_symlink()
            || final_path.exists()
            || final_path.is_symlink()
        {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&incoming)
            .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        use std::io::Write;
        file.write_all(receipt)
            .and_then(|_| file.sync_all())
            .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        fs::rename(&incoming, &final_path).map_err(|_| RuntimeError::ModelAcquisitionUnavailable)
    }

    // Removes only regular files and private directories below the exact root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        clear_directory(destination)
    }
}

// Acquires exact public Hugging Face revisions without executing repository code.
pub struct HuggingFaceRuntimeModelFetcher {
    http: Arc<dyn RuntimeHttpClient>,
    io: Arc<dyn RuntimeModelArtifactIo>,
}

impl HuggingFaceRuntimeModelFetcher {
    // Creates one model fetcher from explicit HTTP and private-filesystem capabilities.
    pub const fn new(
        http: Arc<dyn RuntimeHttpClient>,
        io: Arc<dyn RuntimeModelArtifactIo>,
    ) -> Self {
        Self { http, io }
    }

    // Resolves one immutable revision inventory before downloading any file.
    fn inventory(&self, artifact: &ModelArtifact) -> Result<Vec<SnapshotFile>, RuntimeError> {
        let repository = repository(artifact)?;
        let filename = match artifact.format() {
            ModelArtifactFormat::HuggingFaceSnapshot => None,
            ModelArtifactFormat::GgufFile(file) => Some(file.filename()),
        };
        let (owner, name) = repository
            .split_once('/')
            .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
        let mut url = format!(
            "https://huggingface.co/api/models/{}/{}/tree/{}?recursive=true&limit=1000",
            percent_encode(owner),
            percent_encode(name),
            artifact.revision().as_str(),
        );
        let mut pages = HashSet::new();
        let mut paths = HashSet::new();
        let mut records = Vec::new();
        let mut total = 0_u64;
        let mut complete = false;
        for _page in 0..MAX_PAGES {
            if !pages.insert(url.clone()) {
                return Err(RuntimeError::ModelAcquisitionInvalid);
            }
            let response = self
                .http
                .get(
                    &RuntimeHttpRequest::https(&url, Some("application/json".to_string()))
                        .map_err(map_download_error)?,
                    MAX_METADATA_BYTES,
                )
                .map_err(map_download_error)?;
            if response.status() != 200 {
                return Err(RuntimeError::ModelAcquisitionUnavailable);
            }
            let values = parse_closed_json(response.body())
                .map_err(|_| RuntimeError::ModelAcquisitionInvalid)?;
            let values = values
                .as_array()
                .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
            for value in values {
                let entry = value
                    .as_object()
                    .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
                match entry.get("type").and_then(Value::as_str) {
                    Some("directory") => continue,
                    Some("file") => {}
                    _ => return Err(RuntimeError::ModelAcquisitionInvalid),
                }
                let path = safe_relative(
                    entry
                        .get("path")
                        .and_then(Value::as_str)
                        .ok_or(RuntimeError::ModelAcquisitionInvalid)?,
                )?;
                if filename.is_some_and(|filename| path != Path::new(filename)) {
                    continue;
                }
                if !paths.insert(path.clone()) {
                    return Err(RuntimeError::ModelAcquisitionInvalid);
                }
                let bytes = entry
                    .get("size")
                    .and_then(Value::as_u64)
                    .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
                total = total
                    .checked_add(bytes)
                    .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
                if records.len() >= MAX_FILES || total > MAX_TOTAL_BYTES {
                    return Err(RuntimeError::ModelAcquisitionInvalid);
                }
                records.push(SnapshotFile {
                    path,
                    bytes,
                    sha256: lfs_digest(entry.get("lfs"))?,
                });
            }
            let Some(next) = next_link(response.header("link"))? else {
                complete = true;
                break;
            };
            RuntimeHttpRequest::https(&next, None).map_err(map_download_error)?;
            url = next;
        }
        if !complete {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        records.sort_by(|left, right| left.path.cmp(&right.path));
        if records.is_empty()
            || filename.is_some_and(|filename| {
                records.len() != 1 || records[0].path != Path::new(filename)
            })
        {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        Ok(records)
    }

    // Downloads one closed inventory and validates every available immutable identity.
    fn acquire(&self, artifact: &ModelArtifact, destination: &Path) -> Result<(), RuntimeError> {
        self.io.prepare_destination(destination)?;
        let records = self.inventory(artifact)?;
        let repository = repository(artifact)?;
        let gguf = match artifact.format() {
            ModelArtifactFormat::HuggingFaceSnapshot => None,
            ModelArtifactFormat::GgufFile(file) => Some(file),
        };
        let result = (|| {
            let mut acquired = Vec::new();
            for record in records {
                if let Some(file) = gguf {
                    if record.path == Path::new(file.filename())
                        && (record
                            .sha256
                            .as_ref()
                            .is_some_and(|digest| digest != file.digest())
                            || file.bytes().is_some_and(|bytes| bytes != record.bytes))
                    {
                        return Err(RuntimeError::ModelAcquisitionInvalid);
                    }
                }
                let relative_parent = record.path.parent().unwrap_or_else(|| Path::new(""));
                self.io.create_parent(destination, relative_parent)?;
                let target = destination.join(&record.path);
                let request = RuntimeHttpRequest::new(
                    &format!(
                        "https://huggingface.co/{repository}/resolve/{}/{}?download=true",
                        artifact.revision().as_str(),
                        encoded_path(&record.path)?,
                    ),
                    None,
                    None,
                    false,
                    7 * 24 * 60 * 60,
                )
                .map_err(map_download_error)?;
                let download = self
                    .http
                    .download(&request, &target, record.bytes.max(1))
                    .map_err(map_download_error)?;
                let expected = gguf
                    .filter(|file| record.path == Path::new(file.filename()))
                    .map(|file| file.digest())
                    .or(record.sha256.as_ref());
                if download.bytes() != record.bytes
                    || expected.is_some_and(|digest| download.sha256() != digest)
                {
                    return Err(RuntimeError::ModelAcquisitionInvalid);
                }
                self.io.seal_file(&target)?;
                acquired.push(serde_json::json!({
                    "path": path_string(&record.path)?,
                    "bytes": download.bytes(),
                    "sha256": download.sha256().as_str()
                }));
            }
            self.io
                .write_receipt(destination, &model_receipt(artifact, acquired)?)
        })();
        if result.is_err() {
            let _ = self.io.clear_destination(destination);
        }
        result
    }
}

impl RuntimeModelArtifactFetcher for HuggingFaceRuntimeModelFetcher {
    // Acquires one exact model artifact through the closed public HTTP protocol.
    fn fetch(&self, artifact: &ModelArtifact, destination: &Path) -> Result<(), RuntimeError> {
        self.acquire(artifact, destination)
    }
}

// Describes one exact immutable snapshot file before acquisition starts.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotFile {
    path: PathBuf,
    bytes: u64,
    sha256: Option<Sha256Digest>,
}

// Returns one exact owner/repository identity from an hf:// artifact URI.
fn repository(artifact: &ModelArtifact) -> Result<&str, RuntimeError> {
    let value = artifact
        .uri()
        .as_str()
        .strip_prefix("hf://")
        .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
    let (owner, repository) = value
        .split_once('/')
        .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
    if owner.is_empty()
        || repository.is_empty()
        || repository.contains('/')
        || !owner.bytes().all(is_repository_byte)
        || !repository.bytes().all(is_repository_byte)
    {
        return Err(RuntimeError::ModelAcquisitionInvalid);
    }
    Ok(value)
}

// Returns whether one repository byte is portable in a Hugging Face identity.
fn is_repository_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

// Parses one contained Hugging Face path without filesystem normalization.
fn safe_relative(value: &str) -> Result<PathBuf, RuntimeError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4_096
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::ModelAcquisitionInvalid);
    }
    Ok(path.to_path_buf())
}

// Returns one optional exact LFS SHA-256 from a metadata entry.
fn lfs_digest(value: Option<&Value>) -> Result<Option<Sha256Digest>, RuntimeError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_object()
        .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
    let digest = value
        .get("oid")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::ModelAcquisitionInvalid)?
        .strip_prefix("sha256:")
        .ok_or(RuntimeError::ModelAcquisitionInvalid)?;
    Sha256Digest::parse(digest)
        .map(Some)
        .map_err(|_| RuntimeError::ModelAcquisitionInvalid)
}

// Returns the next exact pagination URL from one strict RFC-5988-shaped header.
fn next_link(value: Option<&str>) -> Result<Option<String>, RuntimeError> {
    let Some(value) = value else {
        return Ok(None);
    };
    for item in value.split(',') {
        let item = item.trim();
        if let Some(url) = item
            .strip_prefix('<')
            .and_then(|value| value.strip_suffix(">; rel=\"next\""))
        {
            return Ok(Some(url.to_string()));
        }
    }
    if value.contains("rel=\"next\"") {
        return Err(RuntimeError::ModelAcquisitionInvalid);
    }
    Ok(None)
}

// Percent-encodes one URL component using the RFC-3986 unreserved alphabet.
fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

// Percent-encodes every already-validated path component independently.
fn encoded_path(path: &Path) -> Result<String, RuntimeError> {
    path.components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .map(percent_encode)
                .ok_or(RuntimeError::ModelAcquisitionInvalid),
            _ => Err(RuntimeError::ModelAcquisitionInvalid),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

// Encodes one exact artifact/file identity for restart verification without network access.
fn model_receipt(artifact: &ModelArtifact, files: Vec<Value>) -> Result<Vec<u8>, RuntimeError> {
    let format = match artifact.format() {
        ModelArtifactFormat::HuggingFaceSnapshot => serde_json::json!({
            "kind": "huggingface-snapshot"
        }),
        ModelArtifactFormat::GgufFile(file) => serde_json::json!({
            "kind": "gguf-file",
            "filename": file.filename(),
            "sha256": file.digest().as_str(),
            "bytes": file.bytes()
        }),
    };
    let value = serde_json::json!({
        "schema": {"name": "li_model_artifact_receipt", "version": 1},
        "artifact": {
            "name": artifact.name().as_str(),
            "uri": artifact.uri().as_str(),
            "revision": artifact.revision().as_str(),
            "format": format
        },
        "files": files
    });
    let mut bytes =
        serde_json::to_vec(&value).map_err(|_| RuntimeError::ModelAcquisitionInvalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Returns one UTF-8 contained path without lossy conversion.
fn path_string(path: &Path) -> Result<&str, RuntimeError> {
    path.to_str().ok_or(RuntimeError::ModelAcquisitionInvalid)
}

// Maps transport errors into the model acquisition boundary without leaking URLs or tokens.
fn map_download_error(error: RuntimeError) -> RuntimeError {
    match error {
        RuntimeError::DownloadUnavailable => RuntimeError::ModelAcquisitionUnavailable,
        _ => RuntimeError::ModelAcquisitionInvalid,
    }
}

// Requires one no-follow owner-only directory.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::ModelAcquisitionInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
    }
    Ok(())
}

// Removes every safe contained entry from one private directory.
fn clear_directory(path: &Path) -> Result<(), RuntimeError> {
    let entries = path
        .read_dir()
        .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
    for entry in entries {
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
        if metadata.is_dir() {
            clear_directory(&path)?;
            fs::remove_dir(&path).map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        } else if metadata.is_file() {
            fs::remove_file(&path).map_err(|_| RuntimeError::ModelAcquisitionUnavailable)?;
        } else {
            return Err(RuntimeError::ModelAcquisitionInvalid);
        }
    }
    Ok(())
}

// Opens one existing regular file without following the final path.
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
        .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)
}

// Sets one exact owner-controlled Unix mode.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| RuntimeError::ModelAcquisitionUnavailable)
}

// Leaves modes to the future Windows provider.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), RuntimeError> {
    Ok(())
}
