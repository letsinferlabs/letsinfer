// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::WatchdogError;

pub(crate) const WATCHDOG_DIRECTORY_MODE: u32 = 0o700;
pub(crate) const WATCHDOG_STORAGE_FILE_MODE: u32 = 0o600;

// Creates or validates the private Watchdog storage directory and synchronizes its identity.
pub(crate) fn prepare_watchdog_directory(path: &Path) -> Result<File, WatchdogError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_directory_metadata(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(WATCHDOG_DIRECTORY_MODE);
            builder
                .create(path)
                .map_err(|_| storage_io_error("storage directory could not be created"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(WATCHDOG_DIRECTORY_MODE))
                .map_err(|_| storage_io_error("storage directory mode could not be fixed"))?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| storage_io_error("storage directory could not be inspected"))?;
            validate_directory_metadata(&metadata)?;
        }
        Err(_) => return Err(storage_io_error("storage directory could not be inspected")),
    }

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| storage_io_error("storage directory could not be opened safely"))?;
    validate_directory_metadata(
        &directory
            .metadata()
            .map_err(|_| storage_io_error("storage directory could not be verified"))?,
    )?;
    directory
        .sync_all()
        .map_err(|_| storage_io_error("storage directory could not be synchronized"))?;
    Ok(directory)
}

// Opens or atomically creates one owner-bound regular Watchdog storage file.
pub(crate) fn open_watchdog_file(path: &Path) -> Result<(File, bool), WatchdogError> {
    match open_existing_watchdog_file(path) {
        Ok(file) => {
            validate_storage_file(&file)?;
            Ok((file, false))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            let created = options
                .read(true)
                .write(true)
                .create_new(true)
                .mode(WATCHDOG_STORAGE_FILE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path);
            match created {
                Ok(file) => {
                    file.set_permissions(fs::Permissions::from_mode(WATCHDOG_STORAGE_FILE_MODE))
                        .map_err(|_| storage_io_error("storage file mode could not be fixed"))?;
                    validate_storage_file(&file)?;
                    Ok((file, true))
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let file = open_existing_watchdog_file(path)
                        .map_err(|_| storage_io_error("storage file could not be opened safely"))?;
                    validate_storage_file(&file)?;
                    Ok((file, false))
                }
                Err(_) => Err(storage_io_error("storage file could not be created safely")),
            }
        }
        Err(_) => Err(storage_io_error("storage file could not be opened safely")),
    }
}

// Opens one existing regular file without following its final path component.
fn open_existing_watchdog_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

// Requires the exact owner and mode on one non-symlink storage directory.
fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), WatchdogError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_user_id()
        || !has_exact_watchdog_mode(metadata.mode(), WATCHDOG_DIRECTORY_MODE)
    {
        return Err(storage_io_error(
            "storage directory ownership or mode is unsafe",
        ));
    }
    Ok(())
}

// Requires one owner-bound, single-link, exact-mode regular storage file.
pub(crate) fn validate_storage_file(file: &File) -> Result<(), WatchdogError> {
    let metadata = file
        .metadata()
        .map_err(|_| storage_io_error("storage file metadata is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_user_id()
        || !has_exact_watchdog_mode(metadata.mode(), WATCHDOG_STORAGE_FILE_MODE)
        || metadata.nlink() != 1
    {
        return Err(storage_io_error(
            "storage file ownership, mode, or link count is unsafe",
        ));
    }
    Ok(())
}

// Requires ordinary permission bits without accepting any Unix special mode bit.
const fn has_exact_watchdog_mode(mode: u32, expected: u32) -> bool {
    mode & 0o7777 == expected
}

// Returns the service user's effective identity for native ownership checks.
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and does not retain memory.
    unsafe { libc::geteuid() }
}

// Creates one stable redacted native storage failure.
pub(crate) const fn storage_io_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("storage", reason)
}

#[cfg(test)]
mod tests {
    use super::{has_exact_watchdog_mode, WATCHDOG_DIRECTORY_MODE, WATCHDOG_STORAGE_FILE_MODE};

    // Proves every Unix special bit invalidates owner-only directory and file modes.
    #[test]
    fn exact_mode_rejects_every_special_permission_bit() {
        for special_bit in [0o1000, 0o2000, 0o4000] {
            assert!(!has_exact_watchdog_mode(
                WATCHDOG_DIRECTORY_MODE | special_bit,
                WATCHDOG_DIRECTORY_MODE,
            ));
            assert!(!has_exact_watchdog_mode(
                WATCHDOG_STORAGE_FILE_MODE | special_bit,
                WATCHDOG_STORAGE_FILE_MODE,
            ));
        }
    }
}
