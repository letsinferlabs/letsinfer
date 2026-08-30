// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use li_core_interface::{NodeId, PairingInviteId, Sha256Digest};
use serde::{Deserialize, Serialize};

use crate::{
    CorePairingActivationError, CorePairingActivationPhase, CorePairingActivationRecord,
    CorePairingActivationStore,
};

const SCHEMA_NAME: &str = "li_core_pairing_activation";
const SCHEMA_VERSION: u32 = 1;
const JOURNAL_NAME: &str = "li_core_pairing_activation.json";
const PENDING_NAME: &str = ".li_core_pairing_activation.pending";
const LOCK_NAME: &str = ".li_core_pairing_activation.lock";
const MAXIMUM_JOURNAL_BYTES: usize = 64 * 1024;

// Stores the required nested schema identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSchema {
    name: String,
    version: u32,
}

// Stores the complete secret-free child activation recovery record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredActivation {
    schema: StoredSchema,
    request_identity: String,
    invite_id: String,
    main_node_id: Option<String>,
    configuration_receipt: Option<String>,
    phase: String,
}

// Persists one activation journal through owner-only no-follow atomic replacement.
pub struct SystemCorePairingActivationStore {
    root: PathBuf,
    owner_user_id: u32,
}

impl SystemCorePairingActivationStore {
    // Creates or validates one exact owner-only activation state directory.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, CorePairingActivationError> {
        if !safe_absolute_path(&root) {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        match fs::symlink_metadata(&root) {
            Ok(metadata) => validate_directory(&metadata, owner_user_id)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .recursive(false)
                    .mode(0o700)
                    .create(&root)
                    .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
                validate_directory(
                    &fs::symlink_metadata(&root)
                        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?,
                    owner_user_id,
                )?;
                sync_directory(
                    root.parent()
                        .ok_or(CorePairingActivationError::ConfigurationUnavailable)?,
                )?;
            }
            Err(_) => return Err(CorePairingActivationError::ConfigurationUnavailable),
        }
        Ok(Self {
            root,
            owner_user_id,
        })
    }

    // Acquires one process-safe owner-only journal lock.
    fn acquire_lock(&self) -> Result<ActivationLock, CorePairingActivationError> {
        let path = self.root.join(LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        validate_file(
            &file
                .metadata()
                .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?,
            self.owner_user_id,
            true,
        )?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        Ok(ActivationLock { file })
    }

    // Reads and decodes the current exact journal under its caller-owned lock.
    fn load_locked(
        &self,
    ) -> Result<Option<CorePairingActivationRecord>, CorePairingActivationError> {
        let path = self.root.join(JOURNAL_NAME);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CorePairingActivationError::ConfigurationUnavailable),
        };
        validate_file(
            &file
                .metadata()
                .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?,
            self.owner_user_id,
            false,
        )?;
        let mut bytes = Vec::new();
        file.take(MAXIMUM_JOURNAL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_JOURNAL_BYTES {
            return Err(CorePairingActivationError::RecoveryRequired);
        }
        let stored: StoredActivation = serde_json::from_slice(&bytes)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?;
        stored_record(stored).map(Some)
    }

    // Atomically replaces the durable journal and synchronizes its containing directory.
    fn write_locked(
        &self,
        record: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError> {
        let mut bytes = serde_json::to_vec_pretty(&stored_activation(record))
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        bytes.push(b'\n');
        if bytes.len() > MAXIMUM_JOURNAL_BYTES {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        let pending = self.root.join(PENDING_NAME);
        let active = self.root.join(JOURNAL_NAME);
        match fs::remove_file(&pending) {
            Ok(()) => sync_directory(&self.root)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CorePairingActivationError::ConfigurationUnavailable),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&pending)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        fs::rename(&pending, &active)
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        sync_directory(&self.root)
    }
}

impl CorePairingActivationStore for SystemCorePairingActivationStore {
    // Reads the current record while excluding concurrent processes.
    fn load(&self) -> Result<Option<CorePairingActivationRecord>, CorePairingActivationError> {
        let _lock = self.acquire_lock()?;
        self.load_locked()
    }

    // Creates one exact initial record only when the journal is absent.
    fn create(
        &self,
        record: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError> {
        let _lock = self.acquire_lock()?;
        if self.load_locked()?.is_some() {
            return Err(CorePairingActivationError::StateConflict);
        }
        self.write_locked(record)
    }

    // Replaces one exact expected phase under the same process-safe lock.
    fn replace(
        &self,
        expected: CorePairingActivationPhase,
        replacement: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError> {
        let _lock = self.acquire_lock()?;
        let current = self
            .load_locked()?
            .ok_or(CorePairingActivationError::StateConflict)?;
        if current.phase() != expected
            || current.request_identity() != replacement.request_identity()
            || current.invite_id() != replacement.invite_id()
        {
            return Err(CorePairingActivationError::StateConflict);
        }
        self.write_locked(replacement)
    }
}

// Owns one exclusive flock until its exact store operation completes.
struct ActivationLock {
    file: File,
}

impl Drop for ActivationLock {
    // Releases the process-safe lock without panicking during cleanup.
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

// Projects one typed record into the closed persistence document.
fn stored_activation(record: &CorePairingActivationRecord) -> StoredActivation {
    StoredActivation {
        schema: StoredSchema {
            name: SCHEMA_NAME.to_string(),
            version: SCHEMA_VERSION,
        },
        request_identity: record.request_identity().as_str().to_string(),
        invite_id: record.invite_id().as_str().to_string(),
        main_node_id: record
            .main_node_id()
            .map(|value| value.as_str().to_string()),
        configuration_receipt: record
            .configuration_receipt()
            .map(|value| value.as_str().to_string()),
        phase: phase_name(record.phase()).to_string(),
    }
}

// Reconstructs one typed record and rejects every unknown schema or phase.
fn stored_record(
    stored: StoredActivation,
) -> Result<CorePairingActivationRecord, CorePairingActivationError> {
    if stored.schema.name != SCHEMA_NAME || stored.schema.version != SCHEMA_VERSION {
        return Err(CorePairingActivationError::RecoveryRequired);
    }
    Ok(CorePairingActivationRecord::decoded(
        Sha256Digest::parse(&stored.request_identity)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        PairingInviteId::parse(&stored.invite_id)
            .map_err(|_| CorePairingActivationError::RecoveryRequired)?,
        stored
            .main_node_id
            .map(|value| {
                NodeId::parse(&value).map_err(|_| CorePairingActivationError::RecoveryRequired)
            })
            .transpose()?,
        stored
            .configuration_receipt
            .map(|value| {
                Sha256Digest::parse(&value)
                    .map_err(|_| CorePairingActivationError::RecoveryRequired)
            })
            .transpose()?,
        phase(&stored.phase)?,
    ))
}

// Returns the stable persisted name for one activation phase.
const fn phase_name(phase: CorePairingActivationPhase) -> &'static str {
    match phase {
        CorePairingActivationPhase::Requested => "requested",
        CorePairingActivationPhase::CredentialsVerified => "credentials_verified",
        CorePairingActivationPhase::ConfigurationPrepared => "configuration_prepared",
        CorePairingActivationPhase::RoleCommitted => "role_committed",
        CorePairingActivationPhase::ConfigurationCommitted => "configuration_committed",
        CorePairingActivationPhase::ServicesActivated => "services_activated",
        CorePairingActivationPhase::Completed => "completed",
        CorePairingActivationPhase::Compensating => "compensating",
        CorePairingActivationPhase::RolledBack => "rolled_back",
        CorePairingActivationPhase::RecoveryRequired => "recovery_required",
    }
}

// Parses one exact persisted phase without compatibility fallbacks.
fn phase(value: &str) -> Result<CorePairingActivationPhase, CorePairingActivationError> {
    match value {
        "requested" => Ok(CorePairingActivationPhase::Requested),
        "credentials_verified" => Ok(CorePairingActivationPhase::CredentialsVerified),
        "configuration_prepared" => Ok(CorePairingActivationPhase::ConfigurationPrepared),
        "role_committed" => Ok(CorePairingActivationPhase::RoleCommitted),
        "configuration_committed" => Ok(CorePairingActivationPhase::ConfigurationCommitted),
        "services_activated" => Ok(CorePairingActivationPhase::ServicesActivated),
        "completed" => Ok(CorePairingActivationPhase::Completed),
        "compensating" => Ok(CorePairingActivationPhase::Compensating),
        "rolled_back" => Ok(CorePairingActivationPhase::RolledBack),
        "recovery_required" => Ok(CorePairingActivationPhase::RecoveryRequired),
        _ => Err(CorePairingActivationError::RecoveryRequired),
    }
}

// Requires one owner-only directory without symlink or group/other access.
fn validate_directory(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), CorePairingActivationError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(CorePairingActivationError::ConfigurationUnavailable);
    }
    Ok(())
}

// Requires one owner-only single-link regular file with its exact expected mutability.
fn validate_file(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    allow_empty: bool,
) -> Result<(), CorePairingActivationError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || (!allow_empty && metadata.len() == 0)
        || metadata.len() > MAXIMUM_JOURNAL_BYTES as u64
    {
        return Err(CorePairingActivationError::ConfigurationUnavailable);
    }
    Ok(())
}

// Synchronizes one exact directory after visible activation.
fn sync_directory(path: &Path) -> Result<(), CorePairingActivationError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)
}

// Returns whether one state root is absolute and lexically normalized.
fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}
