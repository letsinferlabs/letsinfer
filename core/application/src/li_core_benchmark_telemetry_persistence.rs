// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_benchmark_manager::{
    decode_benchmark_telemetry_state, encode_benchmark_telemetry_state, BenchmarkTelemetryState,
    BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES,
};
use li_core_interface::{OperationId, Sha256Digest};

use crate::{CoreBenchmarkPortError, CoreBenchmarkTelemetryPersistencePort};

const LOCK_FILENAME: &str = ".li_benchmark_telemetry.lock";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

// Activates one completely synchronized telemetry document without owning store policy.
pub trait CoreBenchmarkTelemetryAtomicPublisher: Send + Sync {
    // Moves one attempt-owned private file over its exact active destination atomically.
    fn publish(&self, temporary: &Path, destination: &Path) -> Result<(), CoreBenchmarkPortError>;
}

// Publishes telemetry documents through the native same-filesystem rename primitive.
#[derive(Default)]
pub struct SystemCoreBenchmarkTelemetryAtomicPublisher;

impl CoreBenchmarkTelemetryAtomicPublisher for SystemCoreBenchmarkTelemetryAtomicPublisher {
    // Activates one synchronized temporary file without copying or following links.
    fn publish(&self, temporary: &Path, destination: &Path) -> Result<(), CoreBenchmarkPortError> {
        fs::rename(temporary, destination).map_err(|_| CoreBenchmarkPortError::Unavailable)
    }
}

// Persists complete telemetry timelines as owner-only no-follow atomic files.
pub struct FilesystemCoreBenchmarkTelemetryPersistence {
    root: PathBuf,
    owner_user_id: u32,
    publisher: Arc<dyn CoreBenchmarkTelemetryAtomicPublisher>,
}

impl FilesystemCoreBenchmarkTelemetryPersistence {
    // Creates one production store from an existing exact owner-only directory.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, CoreBenchmarkPortError> {
        Self::with_publisher(
            root,
            owner_user_id,
            Arc::new(SystemCoreBenchmarkTelemetryAtomicPublisher),
        )
    }

    // Creates one store with an explicit atomic publication mechanism for deterministic testing.
    pub fn with_publisher(
        root: PathBuf,
        owner_user_id: u32,
        publisher: Arc<dyn CoreBenchmarkTelemetryAtomicPublisher>,
    ) -> Result<Self, CoreBenchmarkPortError> {
        if !safe_absolute_path(&root) {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        require_private_directory(&root, owner_user_id)?;
        Ok(Self {
            root,
            owner_user_id,
            publisher,
        })
    }

    // Resolves one closed active filename from its canonical operation identity.
    fn state_path(&self, job_id: &OperationId) -> PathBuf {
        self.root
            .join(format!("li_benchmark_telemetry_{}.json", job_id.as_str()))
    }

    // Resolves one attempt-owned temporary filename from its canonical operation identity.
    fn temporary_path(&self, job_id: &OperationId) -> PathBuf {
        self.root
            .join(format!(".li_benchmark_telemetry_{}.tmp", job_id.as_str()))
    }

    // Acquires one process-safe root lock before reading or mutating a timeline.
    fn acquire_lock(&self) -> Result<TelemetryPersistenceLock, CoreBenchmarkPortError> {
        require_private_directory(&self.root, self.owner_user_id)?;
        let path = self.root.join(LOCK_FILENAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        require_private_file(
            &file.metadata().map_err(unavailable)?,
            self.owner_user_id,
            true,
        )?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        require_private_directory(&self.root, self.owner_user_id)?;
        require_private_file(
            &file.metadata().map_err(unavailable)?,
            self.owner_user_id,
            true,
        )?;
        Ok(TelemetryPersistenceLock { file })
    }

    // Reads and validates one exact state while its caller retains the root lock.
    fn read_locked(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, CoreBenchmarkPortError> {
        require_private_directory(&self.root, self.owner_user_id)?;
        let path = self.state_path(job_id);
        let observed = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CoreBenchmarkPortError::Unavailable),
        };
        require_private_file(&observed, self.owner_user_id, false)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let opened = file.metadata().map_err(unavailable)?;
        require_private_file(&opened, self.owner_user_id, false)?;
        if observed.dev() != opened.dev() || observed.ino() != opened.ino() {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take((BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() as u64 != opened.len() {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        let state = decode_benchmark_telemetry_state(&bytes)
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        if state.job_id() != job_id {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        Ok(Some(state))
    }

    // Atomically publishes one encoded state while retaining the exact root lock.
    fn write_locked(
        &self,
        state: &BenchmarkTelemetryState,
        bytes: &[u8],
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError> {
        require_private_directory(&self.root, self.owner_user_id)?;
        let destination = self.state_path(state.job_id());
        let temporary = self.temporary_path(state.job_id());
        remove_temporary_file(&temporary, self.owner_user_id)?;
        if let Err(error) = write_private_file(&temporary, bytes, self.owner_user_id) {
            remove_temporary_file(&temporary, self.owner_user_id)?;
            sync_directory(&self.root)?;
            return Err(error);
        }
        if let Err(error) = self.publisher.publish(&temporary, &destination) {
            remove_temporary_file(&temporary, self.owner_user_id)?;
            sync_directory(&self.root)?;
            return Err(error);
        }
        sync_directory(&self.root)?;
        self.read_locked(state.job_id())?
            .filter(|persisted| persisted == state)
            .ok_or(CoreBenchmarkPortError::InvalidState)
    }
}

impl CoreBenchmarkTelemetryPersistencePort for FilesystemCoreBenchmarkTelemetryPersistence {
    // Returns one complete timeline without exposing native path or codec failures.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, CoreBenchmarkPortError> {
        let _lock = self.acquire_lock()?;
        self.read_locked(job_id)
    }

    // Creates one timeline or returns its exact existing replay without replacing a conflict.
    fn open(
        &self,
        state: BenchmarkTelemetryState,
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError> {
        let bytes = encoded_state(&state)?;
        let _lock = self.acquire_lock()?;
        if let Some(existing) = self.read_locked(state.job_id())? {
            return if existing == state {
                Ok(existing)
            } else {
                Err(CoreBenchmarkPortError::Conflict)
            };
        }
        self.write_locked(&state, &bytes)
    }

    // Replaces only the timeline matching both optimistic identities under one root lock.
    fn replace(
        &self,
        state: BenchmarkTelemetryState,
        expected_samples_sha256: &Sha256Digest,
        expected_sealed_receipt_id: Option<&Sha256Digest>,
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError> {
        let bytes = encoded_state(&state)?;
        let _lock = self.acquire_lock()?;
        let current = self
            .read_locked(state.job_id())?
            .ok_or(CoreBenchmarkPortError::Conflict)?;
        if current.samples_sha256() != expected_samples_sha256
            || current.sealed_receipt_id() != expected_sealed_receipt_id
        {
            return Err(CoreBenchmarkPortError::Conflict);
        }
        if current == state {
            return Ok(current);
        }
        self.write_locked(&state, &bytes)
    }
}

// Owns one exclusive native lock until its exact store operation completes.
struct TelemetryPersistenceLock {
    file: File,
}

impl Drop for TelemetryPersistenceLock {
    // Releases the process-safe lock without panicking during error cleanup.
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

// Encodes one complete timeline through the benchmark crate's canonical closed codec.
fn encoded_state(state: &BenchmarkTelemetryState) -> Result<Vec<u8>, CoreBenchmarkPortError> {
    encode_benchmark_telemetry_state(state).map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Creates and synchronizes one exact owner-only single-link temporary file.
fn write_private_file(
    path: &Path,
    bytes: &[u8],
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkPortError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(unavailable)?;
    require_private_file(&file.metadata().map_err(unavailable)?, owner_user_id, true)?;
    file.write_all(bytes).map_err(unavailable)?;
    file.sync_all().map_err(unavailable)?;
    require_private_file(&file.metadata().map_err(unavailable)?, owner_user_id, false)
}

// Removes only one exact attempt-owned owner-private temporary file when present.
fn remove_temporary_file(path: &Path, owner_user_id: u32) -> Result<(), CoreBenchmarkPortError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CoreBenchmarkPortError::Unavailable),
    };
    require_private_file(&metadata, owner_user_id, true)?;
    fs::remove_file(path).map_err(unavailable)
}

// Requires one existing owner-only directory without following symbolic links.
fn require_private_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkPortError> {
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    Ok(())
}

// Requires one owner-only single-link regular file under the telemetry byte bound.
fn require_private_file(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    allow_empty: bool,
) -> Result<(), CoreBenchmarkPortError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
        || (!allow_empty && metadata.len() == 0)
        || metadata.len() > BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES as u64
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    Ok(())
}

// Synchronizes one exact telemetry directory after a visible namespace mutation.
fn sync_directory(path: &Path) -> Result<(), CoreBenchmarkPortError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(unavailable)
}

// Returns whether one configured root is absolute, normalized, and narrower than filesystem root.
fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Redacts one native I/O failure at the Application persistence boundary.
fn unavailable(_error: std::io::Error) -> CoreBenchmarkPortError {
    CoreBenchmarkPortError::Unavailable
}
