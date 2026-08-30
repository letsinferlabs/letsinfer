// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::li_watchdog_controller_registry::WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES;
use crate::{WatchdogControllerSnapshotProvider, WatchdogError};

const WATCHDOG_CONTROLLER_SNAPSHOT_MODE: u32 = 0o600;
static WATCHDOG_CONTROLLER_SNAPSHOT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(1);

// Captures one no-follow snapshot file observation for production or mocks.
#[derive(Debug, Eq, PartialEq)]
pub struct WatchdogControllerSnapshotFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    bytes: Vec<u8>,
}

impl WatchdogControllerSnapshotFile {
    // Creates one raw observation whose metadata is judged by the persistence provider.
    pub fn new(
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        is_regular_file: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_user_id,
            mode,
            link_count,
            is_regular_file,
            bytes,
        }
    }
}

impl Drop for WatchdogControllerSnapshotFile {
    // Clears the temporary restart-state copy before releasing its allocation.
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

// Isolates exact no-follow reads and atomic durable replacement from registry policy.
pub trait WatchdogControllerSnapshotIo: Send + Sync {
    // Reads one bounded final component or reports that it does not exist.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<WatchdogControllerSnapshotFile>, WatchdogError>;

    // Replaces one file atomically only after fully synchronizing private temporary bytes.
    fn replace_atomically(
        &self,
        path: &Path,
        owner_user_id: u32,
        mode: u32,
        bytes: &[u8],
    ) -> Result<(), WatchdogError>;
}

// Implements strict snapshot I/O directly over Unix descriptors and rename.
pub struct SystemWatchdogControllerSnapshotIo;

impl WatchdogControllerSnapshotIo for SystemWatchdogControllerSnapshotIo {
    // Reads one descriptor-stable private regular file without following its final component.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<WatchdogControllerSnapshotFile>, WatchdogError> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(snapshot_io_error("snapshot file is unavailable")),
        };
        let metadata = file
            .metadata()
            .map_err(|_| snapshot_io_error("snapshot metadata is unavailable"))?;
        let maximum_bytes_u64 = u64::try_from(maximum_bytes)
            .map_err(|_| snapshot_io_error("snapshot size bound is invalid"))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes_u64 {
            return Err(snapshot_io_error("snapshot metadata is unsafe"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum_bytes_u64.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| snapshot_io_error("snapshot file cannot be read"))?;
        let final_metadata = file
            .metadata()
            .map_err(|_| snapshot_io_error("snapshot metadata is unavailable"))?;
        if bytes.len() as u64 != metadata.len()
            || bytes.len() > maximum_bytes
            || !same_snapshot_observation(&metadata, &final_metadata)
        {
            bytes.fill(0);
            return Err(snapshot_io_error("snapshot changed while being read"));
        }
        Ok(Some(WatchdogControllerSnapshotFile::new(
            metadata.uid(),
            metadata.mode() & 0o7777,
            metadata.nlink(),
            metadata.is_file(),
            bytes,
        )))
    }

    // Writes, synchronizes, renames, and directory-synchronizes one exact private snapshot.
    fn replace_atomically(
        &self,
        path: &Path,
        owner_user_id: u32,
        mode: u32,
        bytes: &[u8],
    ) -> Result<(), WatchdogError> {
        if mode != WATCHDOG_CONTROLLER_SNAPSHOT_MODE
            || bytes.is_empty()
            || bytes.len() > WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES
            || unsafe { libc::geteuid() } != owner_user_id
        {
            return Err(snapshot_io_error(
                "snapshot replacement contract is invalid",
            ));
        }
        let parent = canonical_snapshot_parent(path, owner_user_id)?;
        let temporary = temporary_snapshot_path(path)?;
        let result =
            write_and_replace_snapshot(path, &temporary, &parent, owner_user_id, mode, bytes);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

// Owns optimistic snapshot replacement for one exact installation path.
pub struct FilesystemWatchdogControllerSnapshotProvider {
    path: PathBuf,
    owner_user_id: u32,
    io: std::sync::Arc<dyn WatchdogControllerSnapshotIo>,
    mutation: Mutex<()>,
}

impl FilesystemWatchdogControllerSnapshotProvider {
    // Creates one provider from an absolute normalized snapshot path and injected I/O.
    pub fn new(
        path: PathBuf,
        owner_user_id: u32,
        io: std::sync::Arc<dyn WatchdogControllerSnapshotIo>,
    ) -> Result<Self, WatchdogError> {
        if !is_normal_absolute_path(&path) || path.file_name().is_none() {
            return Err(snapshot_io_error("snapshot path is invalid"));
        }
        Ok(Self {
            path,
            owner_user_id,
            io,
            mutation: Mutex::new(()),
        })
    }

    // Reads and validates one current owner-only canonical snapshot observation.
    fn current_snapshot(&self) -> Result<Option<Vec<u8>>, WatchdogError> {
        let file = self
            .io
            .read_no_follow(&self.path, WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES)
            .map_err(|_| snapshot_io_error("snapshot file is unavailable"))?;
        let Some(file) = file else {
            return Ok(None);
        };
        if file.owner_user_id != self.owner_user_id
            || file.mode != WATCHDOG_CONTROLLER_SNAPSHOT_MODE
            || file.link_count != 1
            || !file.is_regular_file
            || file.bytes.is_empty()
            || file.bytes.len() > WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES
        {
            return Err(snapshot_io_error("snapshot metadata is unsafe"));
        }
        Ok(Some(file.bytes.clone()))
    }
}

impl WatchdogControllerSnapshotProvider for FilesystemWatchdogControllerSnapshotProvider {
    // Loads the exact current snapshot before registry construction.
    fn load(&self) -> Result<Option<Vec<u8>>, WatchdogError> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        self.current_snapshot()
    }

    // Replaces only an unchanged predecessor and verifies the complete durable result.
    fn commit(
        &self,
        expected_snapshot: Option<&[u8]>,
        snapshot: &[u8],
    ) -> Result<(), WatchdogError> {
        if snapshot.is_empty() || snapshot.len() > WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES {
            return Err(snapshot_io_error("snapshot replacement bytes are invalid"));
        }
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let current = self.current_snapshot()?;
        if current.as_deref() != expected_snapshot {
            return Err(snapshot_io_error("snapshot revision conflicts"));
        }
        self.io.replace_atomically(
            &self.path,
            self.owner_user_id,
            WATCHDOG_CONTROLLER_SNAPSHOT_MODE,
            snapshot,
        )?;
        if self.current_snapshot()?.as_deref() != Some(snapshot) {
            return Err(snapshot_io_error("snapshot replacement was not durable"));
        }
        Ok(())
    }
}

// Writes one temporary snapshot and commits it only after every durability boundary succeeds.
fn write_and_replace_snapshot(
    path: &Path,
    temporary: &Path,
    parent: &Path,
    owner_user_id: u32,
    mode: u32,
    bytes: &[u8],
) -> Result<(), WatchdogError> {
    let mut temporary_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(|_| snapshot_io_error("snapshot temporary file cannot be created"))?;
    temporary_file
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|_| temporary_file.write_all(bytes))
        .and_then(|_| temporary_file.sync_all())
        .map_err(|_| snapshot_io_error("snapshot temporary file cannot be synchronized"))?;
    validate_private_snapshot_file(&temporary_file, owner_user_id, mode, bytes.len())?;
    fs::rename(temporary, path)
        .map_err(|_| snapshot_io_error("snapshot cannot be atomically replaced"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(parent)
        .map_err(|_| snapshot_io_error("snapshot directory cannot be opened"))?;
    directory
        .sync_all()
        .map_err(|_| snapshot_io_error("snapshot directory cannot be synchronized"))?;
    Ok(())
}

// Validates the exact private file identity after its temporary bytes are synchronized.
fn validate_private_snapshot_file(
    file: &File,
    owner_user_id: u32,
    mode: u32,
    expected_bytes: usize,
) -> Result<(), WatchdogError> {
    let metadata = file
        .metadata()
        .map_err(|_| snapshot_io_error("snapshot temporary metadata is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
        || metadata.len() != expected_bytes as u64
    {
        return Err(snapshot_io_error("snapshot temporary metadata is unsafe"));
    }
    Ok(())
}

// Resolves one non-writable owner-bound parent without permitting path aliases.
fn canonical_snapshot_parent(path: &Path, owner_user_id: u32) -> Result<PathBuf, WatchdogError> {
    let parent = path
        .parent()
        .ok_or_else(|| snapshot_io_error("snapshot parent is invalid"))?;
    let canonical = fs::canonicalize(parent)
        .map_err(|_| snapshot_io_error("snapshot parent is unavailable"))?;
    if canonical != parent {
        return Err(snapshot_io_error("snapshot parent path is not canonical"));
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| snapshot_io_error("snapshot parent metadata is unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != owner_user_id || metadata.mode() & 0o022 != 0 {
        return Err(snapshot_io_error("snapshot parent metadata is unsafe"));
    }
    Ok(canonical)
}

// Creates one process-local create-new temporary name beside the exact target.
fn temporary_snapshot_path(path: &Path) -> Result<PathBuf, WatchdogError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| snapshot_io_error("snapshot file name is invalid"))?;
    let identifier = WATCHDOG_CONTROLLER_SNAPSHOT_TEMPORARY_ID
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| snapshot_io_error("snapshot temporary identity is exhausted"))?;
    Ok(path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), identifier)))
}

// Returns whether one path is absolute and contains no parent, current, or prefix aliases.
fn is_normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Returns whether one descriptor retained its complete relevant identity during a bounded read.
fn same_snapshot_observation(initial: &fs::Metadata, final_metadata: &fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
        && initial.ctime() == final_metadata.ctime()
        && initial.ctime_nsec() == final_metadata.ctime_nsec()
}

// Creates one stable redacted snapshot persistence failure.
const fn snapshot_io_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("controller snapshot", reason)
}
