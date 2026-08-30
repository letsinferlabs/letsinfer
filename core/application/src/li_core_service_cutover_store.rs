// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::{
    CoreServiceCutoverPhase, CoreServiceCutoverReceipt, CoreServiceCutoverRecord,
    CoreServiceCutoverStore, CoreServiceSetupError,
};

const CUTOVER_DIRECTORY_MODE: u32 = 0o700;
const CUTOVER_FILE_MODE: u32 = 0o600;
const MAXIMUM_CUTOVER_RECORD_BYTES: u64 = 2 * 1024 * 1024;

// Isolates the two atomic-publication operations that may fail after visible mutation.
trait CoreServiceCutoverStoreIo: Send + Sync {
    // Atomically activates one fully synchronized same-directory record.
    fn activate(&self, source: &Path, destination: &Path) -> Result<(), CoreServiceSetupError>;

    // Synchronizes the containing directory after record activation or removal.
    fn sync_directory(&self, path: &Path) -> Result<(), CoreServiceSetupError>;
}

// Performs production record activation and directory persistence.
struct SystemCoreServiceCutoverStoreIo;

impl CoreServiceCutoverStoreIo for SystemCoreServiceCutoverStoreIo {
    // Renames one staged record over the authoritative stable path.
    fn activate(&self, source: &Path, destination: &Path) -> Result<(), CoreServiceSetupError> {
        fs::rename(source, destination)
            .map_err(|_| store_error("service cutover record could not be activated"))
    }

    // Persists one already-validated private directory.
    fn sync_directory(&self, path: &Path) -> Result<(), CoreServiceSetupError> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| store_error("service cutover directory could not be persisted"))
    }
}

// Persists one cutover record under a process-safe owner-only lock.
pub struct SystemCoreServiceCutoverStore {
    directories: [PathBuf; 3],
    record_path: PathBuf,
    lock_path: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn CoreServiceCutoverStoreIo>,
}

impl SystemCoreServiceCutoverStore {
    // Creates one store only after every fixed private directory already exists safely.
    pub fn new(letsinfer_home: PathBuf, owner_user_id: u32) -> Result<Self, CoreServiceSetupError> {
        Self::new_with_io(
            letsinfer_home,
            owner_user_id,
            Arc::new(SystemCoreServiceCutoverStoreIo),
        )
    }

    // Creates one store with an injected atomic activation and sync boundary.
    fn new_with_io(
        letsinfer_home: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn CoreServiceCutoverStoreIo>,
    ) -> Result<Self, CoreServiceSetupError> {
        if !is_safe_absolute_path(&letsinfer_home) || letsinfer_home == Path::new("/") {
            return Err(store_error("service cutover home is invalid"));
        }
        let state_root = letsinfer_home.join("state");
        let cutover_root = state_root.join("service_cutover");
        let directories = [letsinfer_home, state_root, cutover_root.clone()];
        validate_directories(&directories, owner_user_id)?;
        let store = Self {
            directories,
            record_path: cutover_root.join("li_core_service_cutover.json"),
            lock_path: cutover_root.join(".li_core_service_cutover.lock"),
            owner_user_id,
            io,
        };
        store.ensure_lock_file()?;
        Ok(store)
    }

    // Creates or reopens the fixed no-follow lock file and validates its exact ownership.
    fn ensure_lock_file(&self) -> Result<(), CoreServiceSetupError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(CUTOVER_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.lock_path)
            .map_err(|_| store_error("service cutover lock is unavailable"))?;
        validate_owned_file(&file, self.owner_user_id, false, 0)?;
        Ok(())
    }

    // Executes one complete store operation under the fixed advisory process lock.
    fn with_lock<Value>(
        &self,
        operation: impl FnOnce() -> Result<Value, CoreServiceSetupError>,
    ) -> Result<Value, CoreServiceSetupError> {
        validate_directories(&self.directories, self.owner_user_id)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.lock_path)
            .map_err(|_| store_error("service cutover lock is unavailable"))?;
        validate_owned_file(&lock, self.owner_user_id, false, 0)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(store_error("service cutover lock could not be acquired"));
        }
        let result = operation();
        let unlock = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
        if unlock != 0 && result.is_ok() {
            return Err(store_error("service cutover lock could not be released"));
        }
        result
    }

    // Reads and validates the optional record while the process lock is held.
    fn read_unlocked(&self) -> Result<Option<CoreServiceCutoverRecord>, CoreServiceSetupError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.record_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(store_error("service cutover record is unavailable")),
        };
        validate_owned_file(
            &file,
            self.owner_user_id,
            true,
            MAXIMUM_CUTOVER_RECORD_BYTES,
        )?;
        let mut bytes = Vec::new();
        file.take(MAXIMUM_CUTOVER_RECORD_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| store_error("service cutover record could not be read"))?;
        if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_CUTOVER_RECORD_BYTES {
            return Err(store_error("service cutover record is invalid"));
        }
        CoreServiceCutoverRecord::decode_json(&bytes)
            .map(Some)
            .map_err(|_| store_error("service cutover record is invalid"))
    }

    // Proves one record or absence is durable and unchanged before it becomes authoritative.
    fn read_durable_unlocked(
        &self,
    ) -> Result<Option<CoreServiceCutoverRecord>, CoreServiceSetupError> {
        let observed = self.read_unlocked()?;
        self.io.sync_directory(&self.directories[2]).map_err(|_| {
            CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record durability is ambiguous",
            }
        })?;
        match self.read_unlocked() {
            Ok(verified) if verified == observed => Ok(verified),
            _ => Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record read is ambiguous",
            }),
        }
    }

    // Atomically replaces the record and persists both file and containing directory.
    fn write_unlocked(
        &self,
        record: &CoreServiceCutoverRecord,
    ) -> Result<(), CoreServiceSetupError> {
        let bytes = record.encoded_json()?;
        if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_CUTOVER_RECORD_BYTES {
            return Err(store_error("service cutover record is invalid"));
        }
        if let Some(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.record_path)
            .ok()
        {
            validate_owned_file(
                &file,
                self.owner_user_id,
                true,
                MAXIMUM_CUTOVER_RECORD_BYTES,
            )?;
        } else if fs::symlink_metadata(&self.record_path).is_ok() {
            return Err(store_error("service cutover record path is unsafe"));
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| store_error("service cutover temporary identity is unavailable"))?;
        let temporary = self.directories[2].join(format!(
            ".li_core_service_cutover_{}.tmp",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(CUTOVER_FILE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
                .map_err(|_| store_error("service cutover record could not be staged"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| store_error("service cutover record could not be persisted"))?;
            validate_owned_file(
                &file,
                self.owner_user_id,
                true,
                MAXIMUM_CUTOVER_RECORD_BYTES,
            )?;
            drop(file);
            self.io.activate(&temporary, &self.record_path)?;
            self.io.sync_directory(&self.directories[2])
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    // Removes one exact record and persists its containing directory.
    fn remove_unlocked(
        &self,
        receipt: &CoreServiceCutoverReceipt,
    ) -> Result<(), CoreServiceSetupError> {
        let record =
            self.read_durable_unlocked()?
                .ok_or(CoreServiceSetupError::InvalidContract {
                    reason: "service cutover record is unavailable",
                })?;
        if record.receipt_id() != receipt.receipt_id() {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service cutover receipt does not match durable state",
            });
        }
        fs::remove_file(&self.record_path)
            .map_err(|_| store_error("service cutover record could not be removed"))?;
        self.io.sync_directory(&self.directories[2])
    }

    // Reconciles failures that may have occurred before or after atomic record activation.
    fn write_reconciled(
        &self,
        previous: Option<&CoreServiceCutoverRecord>,
        desired: &CoreServiceCutoverRecord,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        let write = self.write_unlocked(desired);
        let observed = self.read_unlocked();
        match observed {
            Ok(Some(record)) if record == *desired && write.is_ok() => Ok(record),
            Ok(Some(record)) if record == *desired => {
                self.io.sync_directory(&self.directories[2]).map_err(|_| {
                    CoreServiceSetupError::RecoveryRequired {
                        reason: "service cutover record durability is ambiguous",
                    }
                })?;
                match self.read_unlocked() {
                    Ok(Some(verified)) if verified == *desired => Ok(verified),
                    _ => Err(CoreServiceSetupError::RecoveryRequired {
                        reason: "service cutover record write is ambiguous",
                    }),
                }
            }
            Ok(record) if write.is_err() && record.as_ref() == previous => {
                Err(write.expect_err("failed write has one error"))
            }
            Ok(_) | Err(_) => Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record write is ambiguous",
            }),
        }
    }
}

impl CoreServiceCutoverStore for SystemCoreServiceCutoverStore {
    // Reads the optional authoritative record under the process lock.
    fn read(&self) -> Result<Option<CoreServiceCutoverRecord>, CoreServiceSetupError> {
        self.with_lock(|| self.read_durable_unlocked())
    }

    // Creates once or returns the authoritative existing record after a concurrent race.
    fn create(
        &self,
        record: CoreServiceCutoverRecord,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        self.with_lock(|| {
            if let Some(existing) = self.read_durable_unlocked()? {
                return Ok(existing);
            }
            self.write_reconciled(None, &record)
        })
    }

    // Atomically applies one allowed expected-phase transition for the exact current receipt.
    fn transition(
        &self,
        receipt: &CoreServiceCutoverReceipt,
        expected: CoreServiceCutoverPhase,
        next: CoreServiceCutoverPhase,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        self.with_lock(|| {
            let record =
                self.read_durable_unlocked()?
                    .ok_or(CoreServiceSetupError::InvalidContract {
                        reason: "service cutover record is unavailable",
                    })?;
            if record.receipt_id() != receipt.receipt_id() {
                return Err(CoreServiceSetupError::InvalidContract {
                    reason: "service cutover receipt does not match durable state",
                });
            }
            if record.phase() != expected {
                return Err(CoreServiceSetupError::InvalidContract {
                    reason: "service cutover phase differs from expected state",
                });
            }
            let transitioned = record.transitioned(expected, next)?;
            self.write_reconciled(Some(&record), &transitioned)
        })
    }

    // Removes only the exact current receipt under the process lock.
    fn remove(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        self.with_lock(|| self.remove_unlocked(receipt))
    }
}

// Requires one canonical absolute path without parent traversal.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Validates every owner-private non-symlink directory in the fixed store chain.
fn validate_directories(
    directories: &[PathBuf; 3],
    owner_user_id: u32,
) -> Result<(), CoreServiceSetupError> {
    for directory in directories {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| store_error("service cutover directory is unavailable"))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner_user_id
            || metadata.permissions().mode() & 0o777 != CUTOVER_DIRECTORY_MODE
        {
            return Err(store_error("service cutover directory is unsafe"));
        }
    }
    Ok(())
}

// Validates one open owner-only regular file without trusting path metadata.
fn validate_owned_file(
    file: &File,
    owner_user_id: u32,
    require_nonempty: bool,
    maximum_bytes: u64,
) -> Result<(), CoreServiceSetupError> {
    let metadata = file
        .metadata()
        .map_err(|_| store_error("service cutover file metadata is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != CUTOVER_FILE_MODE
        || (require_nonempty && metadata.len() == 0)
        || (maximum_bytes > 0 && metadata.len() > maximum_bytes)
    {
        return Err(store_error("service cutover file is unsafe"));
    }
    Ok(())
}

// Creates one stable redacted system-store failure.
fn store_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::provider("service cutover store", reason)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use li_core_interface::Sha256Digest;
    use li_core_update_manager::{
        CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
        CoreVersion,
    };

    use super::*;
    use crate::{
        CoreProcessLayout, CoreProcessPlatform, CoreServiceCutoverNativeSnapshot,
        CoreServiceDefinitionProvider,
    };

    // Selects one ambiguous native publication failure boundary.
    #[derive(Clone, Copy)]
    enum PublicationFailure {
        ActivationBefore,
        ActivationAfter,
        SyncBefore,
        SyncAfter,
        SyncAlwaysBefore,
    }

    // Injects failures immediately before or after visible activation and directory sync.
    struct StoreIo {
        failure: PublicationFailure,
        sync_calls: AtomicUsize,
    }

    impl CoreServiceCutoverStoreIo for StoreIo {
        // Applies or withholds atomic activation before returning one injected failure.
        fn activate(&self, source: &Path, destination: &Path) -> Result<(), CoreServiceSetupError> {
            if matches!(self.failure, PublicationFailure::ActivationBefore) {
                return Err(store_error("injected activation failure"));
            }
            fs::rename(source, destination)
                .map_err(|_| store_error("test activation could not complete"))?;
            if matches!(self.failure, PublicationFailure::ActivationAfter) {
                return Err(store_error("injected activation failure"));
            }
            Ok(())
        }

        // Applies or withholds directory sync before returning one injected failure.
        fn sync_directory(&self, path: &Path) -> Result<(), CoreServiceSetupError> {
            let attempt = self.sync_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(self.failure, PublicationFailure::SyncAlwaysBefore)
                || (matches!(self.failure, PublicationFailure::SyncBefore) && attempt == 1)
            {
                return Err(store_error("injected sync failure"));
            }
            File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| store_error("test directory sync could not complete"))?;
            if matches!(self.failure, PublicationFailure::SyncAfter) && attempt == 1 {
                return Err(store_error("injected sync failure"));
            }
            Ok(())
        }
    }

    // Creates one private store tree with an injected publication boundary.
    fn store_fixture(
        failure: PublicationFailure,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        SystemCoreServiceCutoverStore,
        Arc<StoreIo>,
    ) {
        let temporary = tempfile::tempdir().expect("temporary");
        let home = temporary.path().join("letsinfer");
        let state = home.join("state");
        let cutover = state.join("service_cutover");
        for directory in [&home, &state, &cutover] {
            fs::create_dir(directory).expect("directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let owner_user_id = fs::metadata(&home).expect("metadata").uid();
        let io = Arc::new(StoreIo {
            failure,
            sync_calls: AtomicUsize::new(0),
        });
        let store =
            SystemCoreServiceCutoverStore::new_with_io(home.clone(), owner_user_id, io.clone())
                .expect("store");
        (temporary, home, store, io)
    }

    // Creates one complete prepared Linux cutover record.
    fn record() -> CoreServiceCutoverRecord {
        let layout = CoreProcessLayout::new(
            CoreProcessPlatform::Linux,
            PathBuf::from("/opt/letsinfer/core/versions/1.2.3/identity"),
            PathBuf::from("/var/lib/letsinfer/configuration"),
            PathBuf::from("/var/lib/letsinfer/logs"),
        )
        .expect("layout");
        let definitions = layout
            .commands()
            .expect("commands")
            .iter()
            .map(|command| {
                CoreServiceDefinitionProvider
                    .definition(CoreProcessPlatform::Linux, command)
                    .expect("definition")
            })
            .collect::<Vec<_>>();
        CoreServiceCutoverRecord::new(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            CoreInstallation::new(
                CoreVersion::parse("1.2.3").expect("version"),
                Sha256Digest::parse(&"a".repeat(64)).expect("identity"),
            ),
            &definitions,
            CoreServiceCutoverNativeSnapshot::new(b"native-snapshot".to_vec()).expect("snapshot"),
        )
        .expect("record")
    }

    // Returns temporary record paths without including the fixed lock file.
    fn temporary_records(home: &Path) -> Vec<PathBuf> {
        fs::read_dir(home.join("state/service_cutover"))
            .expect("entries")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(".li_core_service_cutover_") && name.ends_with(".tmp")
                    })
            })
            .collect()
    }

    // Reconciles every ambiguous post-activation failure and cleans pre-activation staging.
    #[test]
    fn create_reconciles_before_and_after_activation_and_sync() {
        for failure in [
            PublicationFailure::ActivationBefore,
            PublicationFailure::ActivationAfter,
            PublicationFailure::SyncBefore,
            PublicationFailure::SyncAfter,
        ] {
            let (_temporary, home, store, io) = store_fixture(failure);
            let proposed = record();
            let result = store.create(proposed.clone());
            if matches!(failure, PublicationFailure::ActivationBefore) {
                assert!(result.is_err());
                assert_eq!(store.read().expect("read"), None);
            } else {
                assert_eq!(result.expect("reconciled create"), proposed.clone());
                assert_eq!(store.read().expect("read"), Some(proposed));
            }
            if matches!(
                failure,
                PublicationFailure::SyncBefore | PublicationFailure::SyncAfter
            ) {
                assert_eq!(io.sync_calls.load(Ordering::SeqCst), 4);
            }
            assert!(temporary_records(&home).is_empty());
        }
    }

    // Refuses visible-but-unproven record durability when every directory sync attempt fails.
    #[test]
    fn create_requires_a_successful_directory_sync_after_visible_activation() {
        let (_temporary, home, store, io) = store_fixture(PublicationFailure::SyncAlwaysBefore);
        let proposed = record();
        assert_eq!(
            store.write_reconciled(None, &proposed),
            Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record durability is ambiguous",
            })
        );
        assert_eq!(io.sync_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            store.read_unlocked().expect("visible bytes"),
            Some(proposed.clone())
        );
        assert_eq!(
            store.read(),
            Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record durability is ambiguous",
            })
        );
        assert_eq!(
            store.create(proposed.clone()),
            Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record durability is ambiguous",
            })
        );
        let receipt = CoreServiceCutoverReceipt::new(proposed.receipt_id().clone());
        assert_eq!(
            store.transition(
                &receipt,
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            ),
            Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record durability is ambiguous",
            })
        );
        assert_eq!(
            store.remove(&receipt),
            Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover record durability is ambiguous",
            })
        );
        assert_eq!(
            store.read_unlocked().expect("retained bytes"),
            Some(proposed)
        );
        assert!(temporary_records(&home).is_empty());
    }
}
