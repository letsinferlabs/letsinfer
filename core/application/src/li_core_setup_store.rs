// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeRole, Sha256Digest,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::{
    CoreSetupError, CoreSetupExecutionLock, CoreSetupExecutionLockProvider,
    CoreSetupInstalledConfigurations, CoreSetupInstalledServices, CoreSetupJournal,
    CoreSetupJournalStore, CoreSetupPhase, CoreSetupPreparedIdentity, CoreSetupPreparedMaterial,
    CoreSetupReceipt, CoreSetupResult, CoreSetupStoreError, VersionedCoreSetupJournal,
    CORE_SETUP_RESULT_SCHEMA_NAME, CORE_SETUP_RESULT_SCHEMA_VERSION,
};

pub const CORE_SETUP_JOURNAL_SCHEMA_NAME: &str = "li_core_setup_journal";
pub const CORE_SETUP_JOURNAL_SCHEMA_VERSION: u32 = 1;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAXIMUM_JOURNAL_BYTES: usize = 256 * 1024;
const MAXIMUM_SETUP_DIRECTORY_ENTRIES: usize = 256;
const LOCK_FILENAME: &str = ".li_core_setup.lock";
const STORE_LOCK_FILENAME: &str = ".li_core_setup.journal.lock";
const JOURNAL_FILENAME_PREFIX: &str = "li_core_setup_journal_";
const JOURNAL_FILENAME_SUFFIX: &str = ".json";
const PENDING_FILENAME_SUFFIX: &str = ".pending";

// Holds one owner-safe descriptor chain through a complete native operation.
struct CoreSetupRootGuard {
    directories: Vec<File>,
}

// Owns one duplicated descriptor while libc enumerates its already-validated directory.
struct CoreSetupDirectoryStream(*mut libc::DIR);

impl Drop for CoreSetupDirectoryStream {
    // Closes the stream and its fdopendir-owned duplicate descriptor exactly once.
    fn drop(&mut self) {
        let _ = unsafe { libc::closedir(self.0) };
    }
}

// Enumerates one validated root through a duplicate descriptor without reopening its pathname.
fn directory_entry_names(root: &File) -> Result<Vec<OsString>, CoreSetupStoreError> {
    let descriptor = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let _ = unsafe { libc::close(descriptor) };
        return Err(CoreSetupStoreError::Unavailable);
    }
    let stream = CoreSetupDirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            return if current_errno() == 0 {
                Ok(names)
            } else {
                Err(CoreSetupStoreError::Unavailable)
            };
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if names.len() >= MAXIMUM_SETUP_DIRECTORY_ENTRIES {
            return Err(CoreSetupStoreError::Corrupt);
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
}

// Clears the platform errno slot before one readdir call whose null result may mean EOF.
fn clear_errno() {
    unsafe {
        *errno_location() = 0;
    }
}

// Returns the current platform errno value after a native directory operation.
fn current_errno() -> i32 {
    unsafe { *errno_location() }
}

// Returns the supported Unix platform's process-local errno slot.
#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

// Returns the supported Unix platform's process-local errno slot.
#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

impl CoreSetupRootGuard {
    // Opens every root component without following links and returns its final directory.
    fn acquire(root: &Path, owner_user_id: u32) -> Result<Self, CoreSetupStoreError> {
        let components = normal_components(root)?;
        if components.is_empty() {
            return Err(CoreSetupStoreError::Unavailable);
        }
        let mut directories = Vec::with_capacity(components.len() + 1);
        directories.push(open_root_directory()?);
        validate_ancestor_directory(directories.last().ok_or(CoreSetupStoreError::Unavailable)?)?;
        for (index, component) in components.iter().enumerate() {
            let directory = open_child_directory(
                directories.last().ok_or(CoreSetupStoreError::Unavailable)?,
                component,
            )?;
            if index + 1 == components.len() {
                validate_private_directory(&directory, owner_user_id)?;
            } else {
                validate_ancestor_directory(&directory)?;
            }
            directories.push(directory);
        }
        Ok(Self { directories })
    }

    // Returns the final owner-private directory descriptor.
    fn root(&self) -> Result<&File, CoreSetupStoreError> {
        self.directories
            .last()
            .ok_or(CoreSetupStoreError::Unavailable)
    }
}

// Holds the native lock descriptor and protected directory chain until setup returns.
struct SystemCoreSetupExecutionLock {
    lock: File,
    _root: CoreSetupRootGuard,
}

impl CoreSetupExecutionLock for SystemCoreSetupExecutionLock {}

impl Drop for SystemCoreSetupExecutionLock {
    // Releases the native advisory lock before its descriptor closes.
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

// Supplies one nonblocking owner-private cross-process setup lock.
pub struct SystemCoreSetupExecutionLockProvider {
    root: PathBuf,
    owner_user_id: u32,
}

impl SystemCoreSetupExecutionLockProvider {
    // Creates one provider only for the effective owner and an existing safe private root.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, CoreSetupError> {
        require_effective_owner(owner_user_id).map_err(lock_contract_error)?;
        CoreSetupRootGuard::acquire(&root, owner_user_id).map_err(lock_contract_error)?;
        Ok(Self {
            root,
            owner_user_id,
        })
    }
}

impl CoreSetupExecutionLockProvider for SystemCoreSetupExecutionLockProvider {
    // Acquires the fixed lock without blocking behind another setup process.
    fn try_acquire(&self) -> Result<Box<dyn CoreSetupExecutionLock>, CoreSetupError> {
        require_effective_owner(self.owner_user_id).map_err(lock_contract_error)?;
        let root = CoreSetupRootGuard::acquire(&self.root, self.owner_user_id)
            .map_err(lock_contract_error)?;
        let lock =
            open_or_create_private_file(root.root().map_err(lock_contract_error)?, LOCK_FILENAME)
                .map_err(lock_provider_error)?;
        validate_lock_file(&lock, self.owner_user_id).map_err(lock_contract_error)?;
        let status = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if status != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(CoreSetupError::Busy);
            }
            return Err(lock_provider_error(CoreSetupStoreError::Unavailable));
        }
        validate_lock_file(&lock, self.owner_user_id).map_err(lock_contract_error)?;
        Ok(Box::new(SystemCoreSetupExecutionLock { lock, _root: root }))
    }
}

// Persists one complete secret-free setup journal through descriptor-anchored native I/O.
pub struct SystemCoreSetupJournalStore {
    root: PathBuf,
    owner_user_id: u32,
}

impl SystemCoreSetupJournalStore {
    // Creates one store only for the effective owner and an existing safe private root.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, CoreSetupStoreError> {
        require_effective_owner(owner_user_id)?;
        CoreSetupRootGuard::acquire(&root, owner_user_id)?;
        Ok(Self {
            root,
            owner_user_id,
        })
    }

    // Reads one authoritative document and returns its typed journal and revision.
    fn read_from_root(
        &self,
        root: &File,
        request_id: &Sha256Digest,
    ) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError> {
        let filename = journal_filename(request_id)?;
        let Some(bytes) = read_optional_private_file(root, &filename, self.owner_user_id)? else {
            return Ok(None);
        };
        let document = decode_journal_document(&bytes)?;
        if document.journal().request_id() != request_id {
            return Err(CoreSetupStoreError::Corrupt);
        }
        Ok(Some(document))
    }

    // Enumerates the bounded exact journal identities present in the private setup root.
    fn journal_request_ids(
        &self,
        root: &File,
    ) -> Result<BTreeSet<Sha256Digest>, CoreSetupStoreError> {
        let mut identities = BTreeSet::new();
        for name in directory_entry_names(root)? {
            let name = name
                .into_string()
                .map_err(|_| CoreSetupStoreError::Corrupt)?;
            let Some(suffix) = name.strip_prefix(JOURNAL_FILENAME_PREFIX) else {
                continue;
            };
            let identity = suffix
                .strip_suffix(&format!(
                    "{JOURNAL_FILENAME_SUFFIX}{PENDING_FILENAME_SUFFIX}"
                ))
                .or_else(|| suffix.strip_suffix(JOURNAL_FILENAME_SUFFIX))
                .ok_or(CoreSetupStoreError::Corrupt)?;
            identities
                .insert(Sha256Digest::parse(identity).map_err(|_| CoreSetupStoreError::Corrupt)?);
        }
        Ok(identities)
    }

    // Reads and validates one optional fixed pending document.
    fn read_pending(
        &self,
        root: &File,
        request_id: &Sha256Digest,
    ) -> Result<Option<(VersionedCoreSetupJournal, Vec<u8>)>, CoreSetupStoreError> {
        let filename = pending_filename(request_id)?;
        let Some(bytes) = read_optional_private_file(root, &filename, self.owner_user_id)? else {
            return Ok(None);
        };
        let document = decode_journal_document(&bytes)?;
        if document.journal().request_id() != request_id {
            return Err(CoreSetupStoreError::Corrupt);
        }
        Ok(Some((document, bytes)))
    }

    // Stages one exact pending document or validates crash-replayed staged bytes.
    fn stage(
        &self,
        root: &File,
        request_id: &Sha256Digest,
        bytes: &[u8],
    ) -> Result<(), CoreSetupStoreError> {
        if let Some((_, existing)) = self.read_pending(root, request_id)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err(CoreSetupStoreError::Corrupt)
            };
        }
        create_private_file(
            root,
            &pending_filename(request_id)?,
            bytes,
            self.owner_user_id,
        )?;
        sync_directory(root)
    }

    // Removes one exact pending document and persists its absence.
    fn remove_pending(
        &self,
        root: &File,
        request_id: &Sha256Digest,
    ) -> Result<(), CoreSetupStoreError> {
        let filename = pending_filename(request_id)?;
        if self.read_pending(root, request_id)?.is_some() {
            unlink_file(root, &filename)?;
            sync_directory(root)?;
        }
        Ok(())
    }

    // Recovers one staged create or replacement before exposing durable state.
    fn reconcile(
        &self,
        root: &File,
        request_id: &Sha256Digest,
    ) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError> {
        let authoritative = self.read_from_root(root, request_id)?;
        let Some((pending, pending_bytes)) = self.read_pending(root, request_id)? else {
            return Ok(authoritative);
        };
        match authoritative {
            None if pending.revision() == 1
                && pending.journal().phase() == CoreSetupPhase::Prepared =>
            {
                self.publish_create(root, request_id, &pending, &pending_bytes)
                    .map(Some)
            }
            None => Err(CoreSetupStoreError::Corrupt),
            Some(current) if current == pending => {
                self.remove_pending(root, request_id)?;
                Ok(Some(current))
            }
            Some(current) if valid_successor(&current, &pending) => self
                .publish_replace(root, request_id, &current, &pending, &pending_bytes)
                .map(Some),
            Some(_) => Err(CoreSetupStoreError::Corrupt),
        }
    }

    // Reconciles a create publication against authoritative and pending state.
    fn publish_create(
        &self,
        root: &File,
        request_id: &Sha256Digest,
        desired: &VersionedCoreSetupJournal,
        bytes: &[u8],
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        self.stage(root, request_id, bytes)?;
        let source = pending_filename(request_id)?;
        let destination = journal_filename(request_id)?;
        let activation = activate_create(root, &source, &destination);
        let observed = self.read_from_root(root, request_id);
        match observed {
            Ok(Some(observed)) if observed == *desired => {
                self.remove_pending(root, request_id)?;
                sync_directory(root)?;
                Ok(observed)
            }
            Ok(Some(_)) => Err(CoreSetupStoreError::Conflict),
            Ok(None) => match activation {
                Ok(()) | Err(_) => Err(CoreSetupStoreError::Unavailable),
            },
            Err(_) => Err(CoreSetupStoreError::Corrupt),
        }
    }

    // Reconciles an atomic replacement against old, desired, and pending state.
    fn publish_replace(
        &self,
        root: &File,
        request_id: &Sha256Digest,
        current: &VersionedCoreSetupJournal,
        desired: &VersionedCoreSetupJournal,
        bytes: &[u8],
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        self.stage(root, request_id, bytes)?;
        let source = pending_filename(request_id)?;
        let destination = journal_filename(request_id)?;
        let activation = activate_replace(root, &source, &destination);
        let observed = self.read_from_root(root, request_id);
        match observed {
            Ok(Some(observed)) if observed == *desired => {
                self.remove_pending(root, request_id)?;
                sync_directory(root)?;
                Ok(observed)
            }
            Ok(Some(observed)) if observed == *current && activation.is_err() => {
                Err(CoreSetupStoreError::Unavailable)
            }
            Ok(Some(_)) => Err(CoreSetupStoreError::Conflict),
            Ok(None) | Err(_) => Err(CoreSetupStoreError::Corrupt),
        }
    }
}

impl CoreSetupJournalStore for SystemCoreSetupJournalStore {
    // Returns exactly one incomplete journal or rejects ambiguous recovery ownership.
    fn recovery(&self) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError> {
        require_effective_owner(self.owner_user_id)?;
        let guard = CoreSetupRootGuard::acquire(&self.root, self.owner_user_id)?;
        let root = guard.root()?;
        let _operation = acquire_store_operation_lock(root, self.owner_user_id)?;
        let mut recovery = None;
        for request_id in self.journal_request_ids(root)? {
            let Some(journal) = self.reconcile(root, &request_id)? else {
                continue;
            };
            if journal.journal().phase() == CoreSetupPhase::Completed {
                continue;
            }
            if recovery.replace(journal).is_some() {
                return Err(CoreSetupStoreError::Corrupt);
            }
        }
        Ok(recovery)
    }

    // Reads one exact bounded journal through an owner-validated directory descriptor.
    fn read(
        &self,
        request_id: &Sha256Digest,
    ) -> Result<Option<VersionedCoreSetupJournal>, CoreSetupStoreError> {
        require_effective_owner(self.owner_user_id)?;
        let guard = CoreSetupRootGuard::acquire(&self.root, self.owner_user_id)?;
        let root = guard.root()?;
        let _operation = acquire_store_operation_lock(root, self.owner_user_id)?;
        self.reconcile(root, request_id)
    }

    // Creates revision one exactly once and reconciles interrupted publication.
    fn create(
        &self,
        journal: CoreSetupJournal,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        require_effective_owner(self.owner_user_id)?;
        let guard = CoreSetupRootGuard::acquire(&self.root, self.owner_user_id)?;
        let root = guard.root()?;
        let _operation = acquire_store_operation_lock(root, self.owner_user_id)?;
        if journal.phase() != CoreSetupPhase::Prepared {
            return Err(CoreSetupStoreError::Corrupt);
        }
        if let Some(existing) = self.reconcile(root, journal.request_id())? {
            return Ok(existing);
        }
        let desired = VersionedCoreSetupJournal::new(journal, 1)?;
        let bytes = encode_journal_document(&desired)?;
        self.publish_create(root, desired.journal().request_id(), &desired, &bytes)
    }

    // Atomically replaces one exact nonzero revision and reconciles interrupted publication.
    fn replace(
        &self,
        journal: CoreSetupJournal,
        expected_revision: u64,
    ) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
        if expected_revision == 0 {
            return Err(CoreSetupStoreError::Corrupt);
        }
        require_effective_owner(self.owner_user_id)?;
        let guard = CoreSetupRootGuard::acquire(&self.root, self.owner_user_id)?;
        let root = guard.root()?;
        let _operation = acquire_store_operation_lock(root, self.owner_user_id)?;
        let current = self
            .reconcile(root, journal.request_id())?
            .ok_or(CoreSetupStoreError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(CoreSetupStoreError::Conflict);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(CoreSetupStoreError::Corrupt)?;
        let desired = VersionedCoreSetupJournal::new(journal, revision)?;
        if !valid_successor(&current, &desired) {
            return Err(CoreSetupStoreError::Conflict);
        }
        let bytes = encode_journal_document(&desired)?;
        self.publish_replace(
            root,
            desired.journal().request_id(),
            &current,
            &desired,
            &bytes,
        )
    }

    // Removes one exact optimistic revision and reconciles an ambiguous native unlink.
    fn remove(
        &self,
        request_id: &Sha256Digest,
        expected_revision: u64,
    ) -> Result<(), CoreSetupStoreError> {
        if expected_revision == 0 {
            return Err(CoreSetupStoreError::Corrupt);
        }
        require_effective_owner(self.owner_user_id)?;
        let guard = CoreSetupRootGuard::acquire(&self.root, self.owner_user_id)?;
        let root = guard.root()?;
        let _operation = acquire_store_operation_lock(root, self.owner_user_id)?;
        let current = self
            .reconcile(root, request_id)?
            .ok_or(CoreSetupStoreError::Conflict)?;
        if current.revision() != expected_revision {
            return Err(CoreSetupStoreError::Conflict);
        }
        let filename = journal_filename(request_id)?;
        let removal = unlink_file(root, &filename);
        match self.read_from_root(root, request_id) {
            Ok(None) => {
                self.remove_pending(root, request_id)?;
                sync_directory(root)
            }
            Ok(Some(_)) if removal.is_err() => Err(CoreSetupStoreError::Unavailable),
            Ok(Some(_)) => Err(CoreSetupStoreError::Corrupt),
            Err(_) => Err(CoreSetupStoreError::Corrupt),
        }
    }
}

// Projects one closed nested schema identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalSchemaDocument {
    name: String,
    version: u32,
}

// Projects one secret-free prepared public identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalIdentityDocument {
    receipt_identity: String,
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    control_address: String,
}

// Projects private material references and identities without credential bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalMaterialDocument {
    receipt_identity: String,
    database_file: String,
    pairing_setup_secret_file: String,
    api_key_file: Option<String>,
    benchmark_signing: JournalBenchmarkSigningDocument,
    pairing_trust: JournalPairingTrustDocument,
    node_trust: JournalNodeTrustDocument,
    gateway_trust: JournalGatewayTrustDocument,
    watchdog_trust: Option<JournalWatchdogTrustDocument>,
    material_identity: String,
}

// Projects dedicated benchmark-signing references and the verified DER public identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalBenchmarkSigningDocument {
    private_key_file: String,
    public_key_file: String,
    public_key_sha256: String,
}

// Projects exact pairing trust references and verified public identities without secret bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalPairingTrustDocument {
    site_private_key_file: String,
    site_public_key_file: String,
    site_ca_certificate_file: String,
    local_control_certificate_file: String,
    public_key_sha256: String,
    certificate_sha256: String,
}

// Projects complete Node remote trust references and public leaf identities without bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalNodeTrustDocument {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    client_certificate_file: String,
    client_private_key_file: String,
    server_certificate_sha256: String,
    client_certificate_sha256: String,
}

// Projects complete Gateway relay trust references and public leaf identities without bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalGatewayTrustDocument {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    relay_client_certificate_file: String,
    relay_client_private_key_file: String,
    server_certificate_sha256: String,
    relay_client_certificate_sha256: String,
}

// Projects Linux Watchdog and Core-health trust references and public identities without bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalWatchdogTrustDocument {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
    controller_allowlist_file: String,
    server_certificate_sha256: String,
    controller_certificate_sha256: String,
}

// Projects one configuration or service phase receipt.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalReceiptDocument {
    receipt_identity: String,
}

// Projects the complete strict setup journal persisted by the native store.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalDocument {
    schema: JournalSchemaDocument,
    revision: u64,
    request_id: String,
    request_identity: String,
    phase: CoreSetupPhase,
    identity: Option<JournalIdentityDocument>,
    material: Option<JournalMaterialDocument>,
    configurations: Option<JournalReceiptDocument>,
    services: Option<JournalReceiptDocument>,
    result: Option<CoreSetupResult>,
}

// Converts one typed journal into canonical bounded JSON with every nullable field present.
fn encode_journal_document(
    versioned: &VersionedCoreSetupJournal,
) -> Result<Vec<u8>, CoreSetupStoreError> {
    let journal = versioned.journal();
    let document = JournalDocument {
        schema: JournalSchemaDocument {
            name: CORE_SETUP_JOURNAL_SCHEMA_NAME.to_string(),
            version: CORE_SETUP_JOURNAL_SCHEMA_VERSION,
        },
        revision: versioned.revision(),
        request_id: journal.request_id().as_str().to_string(),
        request_identity: journal.request_identity().as_str().to_string(),
        phase: journal.phase(),
        identity: journal.identity().map(identity_document),
        material: journal.material().map(material_document).transpose()?,
        configurations: journal
            .configurations()
            .map(|value| JournalReceiptDocument {
                receipt_identity: value.receipt().identity().as_str().to_string(),
            }),
        services: journal.services().map(|value| JournalReceiptDocument {
            receipt_identity: value.receipt().identity().as_str().to_string(),
        }),
        result: journal.result().cloned(),
    };
    let mut bytes = serde_json::to_vec(&document).map_err(|_| CoreSetupStoreError::Corrupt)?;
    bytes.push(b'\n');
    if bytes.len() > MAXIMUM_JOURNAL_BYTES {
        return Err(CoreSetupStoreError::Corrupt);
    }
    Ok(bytes)
}

// Decodes one duplicate-free closed document and reconstructs every validated closure.
fn decode_journal_document(bytes: &[u8]) -> Result<VersionedCoreSetupJournal, CoreSetupStoreError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_JOURNAL_BYTES {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let value = closed_json(bytes)?;
    validate_document_keys(&value)?;
    let document: JournalDocument =
        serde_json::from_value(value).map_err(|_| CoreSetupStoreError::Corrupt)?;
    if document.schema.name != CORE_SETUP_JOURNAL_SCHEMA_NAME
        || document.schema.version != CORE_SETUP_JOURNAL_SCHEMA_VERSION
        || document.revision == 0
    {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let request_id =
        Sha256Digest::parse(&document.request_id).map_err(|_| CoreSetupStoreError::Corrupt)?;
    let request_identity = Sha256Digest::parse(&document.request_identity)
        .map_err(|_| CoreSetupStoreError::Corrupt)?;
    let identity = document.identity.map(prepared_identity).transpose()?;
    let material = document.material.map(prepared_material).transpose()?;
    let configurations = document
        .configurations
        .map(|value| receipt(&value.receipt_identity).map(CoreSetupInstalledConfigurations::new))
        .transpose()?;
    let services = document
        .services
        .map(|value| receipt(&value.receipt_identity).map(CoreSetupInstalledServices::new))
        .transpose()?;
    let journal = CoreSetupJournal::restored(
        request_id,
        request_identity,
        document.phase,
        identity,
        material,
        configurations,
        services,
        document.result,
    )?;
    validate_completed_closure(&journal)?;
    VersionedCoreSetupJournal::new(journal, document.revision)
}

// Requires one staged replacement to be the exact next durable closure.
fn valid_successor(
    current: &VersionedCoreSetupJournal,
    pending: &VersionedCoreSetupJournal,
) -> bool {
    let Some(next_revision) = current.revision().checked_add(1) else {
        return false;
    };
    if pending.revision() != next_revision
        || pending.journal().request_id() != current.journal().request_id()
        || pending.journal().request_identity() != current.journal().request_identity()
    {
        return false;
    }
    let current = current.journal();
    let pending = pending.journal();
    match current.phase() {
        CoreSetupPhase::Prepared => pending.phase() == CoreSetupPhase::IdentityPrepared,
        CoreSetupPhase::IdentityPrepared => {
            pending.phase() == CoreSetupPhase::MaterialPrepared
                && pending.identity() == current.identity()
        }
        CoreSetupPhase::MaterialPrepared => {
            pending.phase() == CoreSetupPhase::ConfigurationsInstalled
                && pending.identity() == current.identity()
                && pending.material() == current.material()
        }
        CoreSetupPhase::ConfigurationsInstalled => {
            pending.phase() == CoreSetupPhase::ServicesInstalled
                && pending.identity() == current.identity()
                && pending.material() == current.material()
                && pending.configurations() == current.configurations()
        }
        CoreSetupPhase::ServicesInstalled => {
            pending.phase() == CoreSetupPhase::Completed
                && pending.identity() == current.identity()
                && pending.material() == current.material()
                && pending.configurations() == current.configurations()
                && pending.services() == current.services()
        }
        CoreSetupPhase::Completed => false,
    }
}

// Binds one committed installer result to the exact durable identity and material closure.
fn validate_completed_closure(journal: &CoreSetupJournal) -> Result<(), CoreSetupStoreError> {
    let Some(result) = journal.result() else {
        return Ok(());
    };
    let identity = journal.identity().ok_or(CoreSetupStoreError::Corrupt)?;
    let material = journal.material().ok_or(CoreSetupStoreError::Corrupt)?;
    let value = serde_json::to_value(result).map_err(|_| CoreSetupStoreError::Corrupt)?;
    let role = role_name(identity.role());
    let expected_api_key = material
        .api_key_file()
        .map(path_text)
        .transpose()?
        .map(Value::String)
        .unwrap_or(Value::Null);
    if value["status"] != "installed"
        || value["node_id"] != identity.node_id().as_str()
        || value["machine_id"] != identity.machine_id().as_str()
        || value["installation_id"] != identity.installation_id().as_str()
        || value["display_name"] != identity.display_name().as_str()
        || value["role"] != role
        || value["control_address"] != identity.control_address().as_str()
        || value["api_key_file"] != expected_api_key
    {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let services = value["services"]
        .as_array()
        .ok_or(CoreSetupStoreError::Corrupt)?;
    let macos_services = ["li_node", "li_gateway"];
    let linux_services = ["li_node", "li_watchdog", "li_gateway"];
    let service_names = services
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or(CoreSetupStoreError::Corrupt)?;
    if service_names != macos_services && service_names != linux_services {
        return Err(CoreSetupStoreError::Corrupt);
    }
    match identity.role() {
        NodeRole::Main => {
            let endpoint = value["inference_endpoint"]
                .as_str()
                .ok_or(CoreSetupStoreError::Corrupt)?;
            if material.api_key_file().is_none()
                || !inference_endpoint_matches_control_address(endpoint, identity.control_address())
            {
                return Err(CoreSetupStoreError::Corrupt);
            }
        }
        NodeRole::Child
            if material.api_key_file().is_some()
                || !value["api_key_file"].is_null()
                || !value["inference_endpoint"].is_null() =>
        {
            return Err(CoreSetupStoreError::Corrupt)
        }
        NodeRole::Child => {}
    }
    Ok(())
}

// Binds one main HTTP endpoint to the exact persisted control-address authority.
fn inference_endpoint_matches_control_address(
    endpoint: &str,
    control_address: &NodeAddress,
) -> bool {
    endpoint
        .strip_prefix("http://")
        .and_then(|authority| authority.strip_prefix(control_address.as_str()))
        .and_then(|port| port.strip_prefix(':'))
        .is_some_and(|port| {
            port.parse::<u16>()
                .is_ok_and(|value| value != 0 && value.to_string() == port)
        })
}

// Converts one prepared identity into its closed durable projection.
fn identity_document(identity: &CoreSetupPreparedIdentity) -> JournalIdentityDocument {
    JournalIdentityDocument {
        receipt_identity: identity.receipt().identity().as_str().to_string(),
        node_id: identity.node_id().as_str().to_string(),
        machine_id: identity.machine_id().as_str().to_string(),
        installation_id: identity.installation_id().as_str().to_string(),
        display_name: identity.display_name().as_str().to_string(),
        role: role_name(identity.role()).to_string(),
        control_address: identity.control_address().as_str().to_string(),
    }
}

// Converts one private material projection without reading any referenced file.
fn material_document(
    material: &CoreSetupPreparedMaterial,
) -> Result<JournalMaterialDocument, CoreSetupStoreError> {
    Ok(JournalMaterialDocument {
        receipt_identity: material.receipt().identity().as_str().to_string(),
        database_file: path_text(material.database_file())?,
        pairing_setup_secret_file: path_text(material.pairing_setup_secret_file())?,
        api_key_file: material.api_key_file().map(path_text).transpose()?,
        benchmark_signing: {
            let signing = material
                .benchmark_signing()
                .ok_or(CoreSetupStoreError::Corrupt)?;
            JournalBenchmarkSigningDocument {
                private_key_file: path_text(signing.private_key_file())?,
                public_key_file: path_text(signing.public_key_file())?,
                public_key_sha256: signing.public_key_sha256().as_str().to_string(),
            }
        },
        pairing_trust: JournalPairingTrustDocument {
            site_private_key_file: path_text(material.pairing_trust().site_private_key_file())?,
            site_public_key_file: path_text(material.pairing_trust().site_public_key_file())?,
            site_ca_certificate_file: path_text(
                material.pairing_trust().site_ca_certificate_file(),
            )?,
            local_control_certificate_file: path_text(
                material.pairing_trust().local_control_certificate_file(),
            )?,
            public_key_sha256: material
                .pairing_trust()
                .public_key_sha256()
                .as_str()
                .to_string(),
            certificate_sha256: material
                .pairing_trust()
                .certificate_sha256()
                .as_str()
                .to_string(),
        },
        node_trust: JournalNodeTrustDocument {
            authority_private_key_file: path_text(
                material.node_trust().authority_private_key_file(),
            )?,
            authority_certificate_file: path_text(
                material.node_trust().authority_certificate_file(),
            )?,
            server_certificate_file: path_text(material.node_trust().server_certificate_file())?,
            server_private_key_file: path_text(material.node_trust().server_private_key_file())?,
            client_certificate_file: path_text(material.node_trust().client_certificate_file())?,
            client_private_key_file: path_text(material.node_trust().client_private_key_file())?,
            server_certificate_sha256: material
                .node_trust()
                .server_certificate_sha256()
                .as_str()
                .to_string(),
            client_certificate_sha256: material
                .node_trust()
                .client_certificate_sha256()
                .as_str()
                .to_string(),
        },
        gateway_trust: JournalGatewayTrustDocument {
            authority_private_key_file: path_text(
                material.gateway_trust().authority_private_key_file(),
            )?,
            authority_certificate_file: path_text(
                material.gateway_trust().authority_certificate_file(),
            )?,
            server_certificate_file: path_text(material.gateway_trust().server_certificate_file())?,
            server_private_key_file: path_text(material.gateway_trust().server_private_key_file())?,
            relay_client_certificate_file: path_text(
                material.gateway_trust().relay_client_certificate_file(),
            )?,
            relay_client_private_key_file: path_text(
                material.gateway_trust().relay_client_private_key_file(),
            )?,
            server_certificate_sha256: material
                .gateway_trust()
                .server_certificate_sha256()
                .as_str()
                .to_string(),
            relay_client_certificate_sha256: material
                .gateway_trust()
                .relay_client_certificate_sha256()
                .as_str()
                .to_string(),
        },
        watchdog_trust: material
            .watchdog_trust()
            .map(|trust| {
                Ok(JournalWatchdogTrustDocument {
                    authority_private_key_file: path_text(trust.authority_private_key_file())?,
                    authority_certificate_file: path_text(trust.authority_certificate_file())?,
                    server_certificate_file: path_text(trust.server_certificate_file())?,
                    server_private_key_file: path_text(trust.server_private_key_file())?,
                    controller_certificate_file: path_text(trust.controller_certificate_file())?,
                    controller_private_key_file: path_text(trust.controller_private_key_file())?,
                    controller_allowlist_file: path_text(trust.controller_allowlist_file())?,
                    server_certificate_sha256: trust
                        .server_certificate_sha256()
                        .as_str()
                        .to_string(),
                    controller_certificate_sha256: trust
                        .controller_certificate_sha256()
                        .as_str()
                        .to_string(),
                })
            })
            .transpose()?,
        material_identity: material.material_identity().as_str().to_string(),
    })
}

// Reconstructs one validated secret-free public identity closure.
fn prepared_identity(
    document: JournalIdentityDocument,
) -> Result<CoreSetupPreparedIdentity, CoreSetupStoreError> {
    Ok(CoreSetupPreparedIdentity::new(
        receipt(&document.receipt_identity)?,
        NodeId::parse(&document.node_id).map_err(|_| CoreSetupStoreError::Corrupt)?,
        MachineId::parse(&document.machine_id).map_err(|_| CoreSetupStoreError::Corrupt)?,
        InstallationId::parse(&document.installation_id)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
        DisplayName::parse(&document.display_name).map_err(|_| CoreSetupStoreError::Corrupt)?,
        parse_role(&document.role)?,
        NodeAddress::parse(&document.control_address).map_err(|_| CoreSetupStoreError::Corrupt)?,
    ))
}

// Reconstructs private material references without opening or reading credential files.
fn prepared_material(
    document: JournalMaterialDocument,
) -> Result<CoreSetupPreparedMaterial, CoreSetupStoreError> {
    let database_file = parsed_private_path(&document.database_file)?;
    let pairing_setup_secret_file = parsed_private_path(&document.pairing_setup_secret_file)?;
    let api_key_file = document
        .api_key_file
        .map(|value| parsed_private_path(&value))
        .transpose()?;
    let benchmark_signing = crate::li_core_setup::CoreSetupBenchmarkSigningMaterial::new(
        parsed_private_path(&document.benchmark_signing.private_key_file)?,
        parsed_private_path(&document.benchmark_signing.public_key_file)?,
        Sha256Digest::parse(&document.benchmark_signing.public_key_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
    );
    let pairing_trust = crate::CoreSetupPairingTrustMaterial::new(
        parsed_private_path(&document.pairing_trust.site_private_key_file)?,
        parsed_private_path(&document.pairing_trust.site_public_key_file)?,
        parsed_private_path(&document.pairing_trust.site_ca_certificate_file)?,
        parsed_private_path(&document.pairing_trust.local_control_certificate_file)?,
        Sha256Digest::parse(&document.pairing_trust.public_key_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
        Sha256Digest::parse(&document.pairing_trust.certificate_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
    );
    let node_trust = crate::CoreSetupNodeTrustMaterial::new(
        parsed_private_path(&document.node_trust.authority_private_key_file)?,
        parsed_private_path(&document.node_trust.authority_certificate_file)?,
        parsed_private_path(&document.node_trust.server_certificate_file)?,
        parsed_private_path(&document.node_trust.server_private_key_file)?,
        parsed_private_path(&document.node_trust.client_certificate_file)?,
        parsed_private_path(&document.node_trust.client_private_key_file)?,
        Sha256Digest::parse(&document.node_trust.server_certificate_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
        Sha256Digest::parse(&document.node_trust.client_certificate_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
    );
    let gateway_trust = crate::CoreSetupGatewayTrustMaterial::new(
        parsed_private_path(&document.gateway_trust.authority_private_key_file)?,
        parsed_private_path(&document.gateway_trust.authority_certificate_file)?,
        parsed_private_path(&document.gateway_trust.server_certificate_file)?,
        parsed_private_path(&document.gateway_trust.server_private_key_file)?,
        parsed_private_path(&document.gateway_trust.relay_client_certificate_file)?,
        parsed_private_path(&document.gateway_trust.relay_client_private_key_file)?,
        Sha256Digest::parse(&document.gateway_trust.server_certificate_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
        Sha256Digest::parse(&document.gateway_trust.relay_client_certificate_sha256)
            .map_err(|_| CoreSetupStoreError::Corrupt)?,
    );
    let watchdog_trust = document
        .watchdog_trust
        .map(|trust| {
            Ok(crate::CoreSetupWatchdogTrustMaterial::new(
                parsed_private_path(&trust.authority_private_key_file)?,
                parsed_private_path(&trust.authority_certificate_file)?,
                parsed_private_path(&trust.server_certificate_file)?,
                parsed_private_path(&trust.server_private_key_file)?,
                parsed_private_path(&trust.controller_certificate_file)?,
                parsed_private_path(&trust.controller_private_key_file)?,
                parsed_private_path(&trust.controller_allowlist_file)?,
                Sha256Digest::parse(&trust.server_certificate_sha256)
                    .map_err(|_| CoreSetupStoreError::Corrupt)?,
                Sha256Digest::parse(&trust.controller_certificate_sha256)
                    .map_err(|_| CoreSetupStoreError::Corrupt)?,
            ))
        })
        .transpose()?;
    let mut paths = vec![
        database_file.as_path(),
        pairing_setup_secret_file.as_path(),
        pairing_trust.site_private_key_file(),
        pairing_trust.site_public_key_file(),
        pairing_trust.site_ca_certificate_file(),
        pairing_trust.local_control_certificate_file(),
        node_trust.authority_private_key_file(),
        node_trust.authority_certificate_file(),
        node_trust.server_certificate_file(),
        node_trust.server_private_key_file(),
        node_trust.client_certificate_file(),
        node_trust.client_private_key_file(),
        gateway_trust.authority_private_key_file(),
        gateway_trust.authority_certificate_file(),
        gateway_trust.server_certificate_file(),
        gateway_trust.server_private_key_file(),
        gateway_trust.relay_client_certificate_file(),
        gateway_trust.relay_client_private_key_file(),
    ];
    if let Some(path) = api_key_file.as_deref() {
        paths.push(path);
    }
    paths.extend([
        benchmark_signing.private_key_file(),
        benchmark_signing.public_key_file(),
    ]);
    if let Some(trust) = watchdog_trust.as_ref() {
        paths.extend([
            trust.authority_private_key_file(),
            trust.authority_certificate_file(),
            trust.server_certificate_file(),
            trust.server_private_key_file(),
            trust.controller_certificate_file(),
            trust.controller_private_key_file(),
            trust.controller_allowlist_file(),
        ]);
    }
    if paths
        .iter()
        .enumerate()
        .any(|(index, path)| paths[..index].contains(path))
    {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let receipt = receipt(&document.receipt_identity)?;
    let material_identity = Sha256Digest::parse(&document.material_identity)
        .map_err(|_| CoreSetupStoreError::Corrupt)?;
    Ok(CoreSetupPreparedMaterial::new_with_benchmark_signing(
        receipt,
        database_file,
        pairing_setup_secret_file,
        api_key_file,
        benchmark_signing,
        pairing_trust,
        node_trust,
        gateway_trust,
        watchdog_trust,
        material_identity,
    ))
}

// Requires every object to contain exactly the schema-owned field set.
fn validate_document_keys(value: &Value) -> Result<(), CoreSetupStoreError> {
    require_keys(
        value,
        &[
            "schema",
            "revision",
            "request_id",
            "request_identity",
            "phase",
            "identity",
            "material",
            "configurations",
            "services",
            "result",
        ],
    )?;
    require_keys(&value["schema"], &["name", "version"])?;
    if !value["identity"].is_null() {
        require_keys(
            &value["identity"],
            &[
                "receipt_identity",
                "node_id",
                "machine_id",
                "installation_id",
                "display_name",
                "role",
                "control_address",
            ],
        )?;
    }
    if !value["material"].is_null() {
        require_keys(
            &value["material"],
            &[
                "receipt_identity",
                "database_file",
                "pairing_setup_secret_file",
                "api_key_file",
                "benchmark_signing",
                "pairing_trust",
                "node_trust",
                "gateway_trust",
                "watchdog_trust",
                "material_identity",
            ],
        )?;
        require_keys(
            &value["material"]["benchmark_signing"],
            &["private_key_file", "public_key_file", "public_key_sha256"],
        )?;
        require_keys(
            &value["material"]["pairing_trust"],
            &[
                "site_private_key_file",
                "site_public_key_file",
                "site_ca_certificate_file",
                "local_control_certificate_file",
                "public_key_sha256",
                "certificate_sha256",
            ],
        )?;
        require_keys(
            &value["material"]["node_trust"],
            &[
                "authority_private_key_file",
                "authority_certificate_file",
                "server_certificate_file",
                "server_private_key_file",
                "client_certificate_file",
                "client_private_key_file",
                "server_certificate_sha256",
                "client_certificate_sha256",
            ],
        )?;
        require_keys(
            &value["material"]["gateway_trust"],
            &[
                "authority_private_key_file",
                "authority_certificate_file",
                "server_certificate_file",
                "server_private_key_file",
                "relay_client_certificate_file",
                "relay_client_private_key_file",
                "server_certificate_sha256",
                "relay_client_certificate_sha256",
            ],
        )?;
        if !value["material"]["watchdog_trust"].is_null() {
            require_keys(
                &value["material"]["watchdog_trust"],
                &[
                    "authority_private_key_file",
                    "authority_certificate_file",
                    "server_certificate_file",
                    "server_private_key_file",
                    "controller_certificate_file",
                    "controller_private_key_file",
                    "controller_allowlist_file",
                    "server_certificate_sha256",
                    "controller_certificate_sha256",
                ],
            )?;
        }
    }
    for field in ["configurations", "services"] {
        if !value[field].is_null() {
            require_keys(&value[field], &["receipt_identity"])?;
        }
    }
    if !value["result"].is_null() {
        require_keys(
            &value["result"],
            &[
                "schema",
                "status",
                "node_id",
                "machine_id",
                "installation_id",
                "display_name",
                "role",
                "control_address",
                "api_key_file",
                "inference_endpoint",
                "services",
            ],
        )?;
        require_keys(&value["result"]["schema"], &["name", "version"])?;
        if value["result"]["schema"]["name"] != CORE_SETUP_RESULT_SCHEMA_NAME
            || value["result"]["schema"]["version"] != CORE_SETUP_RESULT_SCHEMA_VERSION
        {
            return Err(CoreSetupStoreError::Corrupt);
        }
    }
    Ok(())
}

// Requires one object to contain exactly the supplied unique field names.
fn require_keys(value: &Value, expected: &[&str]) -> Result<(), CoreSetupStoreError> {
    let object = value.as_object().ok_or(CoreSetupStoreError::Corrupt)?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(CoreSetupStoreError::Corrupt);
    }
    Ok(())
}

// Parses one JSON value while rejecting repeated keys at every object depth.
fn closed_json(bytes: &[u8]) -> Result<Value, CoreSetupStoreError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = ClosedJsonValue::deserialize(&mut deserializer)
        .map_err(|_| CoreSetupStoreError::Corrupt)?;
    deserializer
        .end()
        .map_err(|_| CoreSetupStoreError::Corrupt)?;
    Ok(value.0)
}

// Wraps one JSON value whose recursive decoder rejects duplicate object keys.
struct ClosedJsonValue(Value);

impl<'de> Deserialize<'de> for ClosedJsonValue {
    // Decodes any JSON type through one duplicate-aware recursive visitor.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ClosedJsonVisitor)
    }
}

// Visits every JSON type while preserving its exact serde_json representation.
struct ClosedJsonVisitor;

impl<'de> Visitor<'de> for ClosedJsonVisitor {
    type Value = ClosedJsonValue;

    // Describes the complete JSON value accepted by this visitor.
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }

    // Preserves one JSON null.
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::Null))
    }

    // Preserves one JSON boolean.
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::Bool(value)))
    }

    // Preserves one unsigned JSON integer.
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::from(value)))
    }

    // Preserves one signed JSON integer.
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::from(value)))
    }

    // Preserves one finite JSON number.
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(ClosedJsonValue)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    // Preserves one borrowed JSON string.
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::String(value.to_string())))
    }

    // Preserves one owned JSON string.
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(ClosedJsonValue(Value::String(value)))
    }

    // Preserves one array while recursively applying duplicate detection.
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<ClosedJsonValue>()? {
            values.push(value.0);
        }
        Ok(ClosedJsonValue(Value::Array(values)))
    }

    // Preserves one object and rejects its first repeated field name.
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = map.next_entry::<String, ClosedJsonValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(de::Error::custom("duplicate JSON key"));
            }
        }
        Ok(ClosedJsonValue(Value::Object(values)))
    }
}

// Opens one existing or newly created owner-private regular file relative to the safe root.
fn open_or_create_private_file(root: &File, name: &str) -> Result<File, CoreSetupStoreError> {
    let name = contained_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            PRIVATE_FILE_MODE,
        )
    };
    file_from_descriptor(descriptor)
}

// Serializes each journal read-reconciliation and mutation across native processes.
fn acquire_store_operation_lock(
    root: &File,
    owner_user_id: u32,
) -> Result<File, CoreSetupStoreError> {
    let lock = open_or_create_private_file(root, STORE_LOCK_FILENAME)?;
    validate_lock_file(&lock, owner_user_id)?;
    let status = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    if status != 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    validate_lock_file(&lock, owner_user_id)?;
    Ok(lock)
}

// Creates and synchronizes one absent owner-private regular file below the safe root.
fn create_private_file(
    root: &File,
    name: &str,
    bytes: &[u8],
    owner_user_id: u32,
) -> Result<(), CoreSetupStoreError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_JOURNAL_BYTES {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let name = contained_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            PRIVATE_FILE_MODE,
        )
    };
    let mut file = file_from_descriptor(descriptor)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| CoreSetupStoreError::Unavailable)
        .and_then(|_| validate_private_file(&file, owner_user_id, true));
    if result.is_err() {
        let _ = unlink_name(root, &name);
    }
    result
}

// Reads one optional stable owner-private regular file without following its final component.
fn read_optional_private_file(
    root: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<Option<Vec<u8>>, CoreSetupStoreError> {
    let name = contained_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(CoreSetupStoreError::Unavailable);
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_file(&file, owner_user_id, true)?;
    let before = file
        .metadata()
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAXIMUM_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_JOURNAL_BYTES {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let after = file
        .metadata()
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    if !same_file(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(CoreSetupStoreError::Corrupt);
    }
    Ok(Some(bytes))
}

// Opens every absolute root component as an ordinary no-follow directory name.
fn normal_components(path: &Path) -> Result<Vec<&OsStr>, CoreSetupStoreError> {
    if !path.is_absolute() {
        return Err(CoreSetupStoreError::Unavailable);
    }
    let mut values = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => values.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(CoreSetupStoreError::Unavailable)
            }
        }
    }
    Ok(values)
}

// Opens the immutable filesystem root for descriptor-anchored traversal.
fn open_root_directory() -> Result<File, CoreSetupStoreError> {
    let root = CString::new("/").map_err(|_| CoreSetupStoreError::Unavailable)?;
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

// Opens one child directory relative to its already-proven parent descriptor.
fn open_child_directory(parent: &File, name: &OsStr) -> Result<File, CoreSetupStoreError> {
    let name = CString::new(name.as_bytes()).map_err(|_| CoreSetupStoreError::Unavailable)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

// Transfers one successful native descriptor into exactly one automatic close owner.
fn file_from_descriptor(descriptor: libc::c_int) -> Result<File, CoreSetupStoreError> {
    if descriptor < 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

// Requires one exact owner-private final root directory.
fn validate_private_directory(
    directory: &File,
    owner_user_id: u32,
) -> Result<(), CoreSetupStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(CoreSetupStoreError::Unavailable);
    }
    Ok(())
}

// Requires one immutable or root-sticky ancestor directory.
fn validate_ancestor_directory(directory: &File) -> Result<(), CoreSetupStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_dir()
        || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & libc::S_ISVTX as u32 != 0))
    {
        return Err(CoreSetupStoreError::Unavailable);
    }
    Ok(())
}

// Requires one stable owner-only, single-link, bounded regular file descriptor.
fn validate_private_file(
    file: &File,
    owner_user_id: u32,
    require_nonempty: bool,
) -> Result<(), CoreSetupStoreError> {
    let metadata = file
        .metadata()
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
        || metadata.len() > MAXIMUM_JOURNAL_BYTES as u64
        || (require_nonempty && metadata.len() == 0)
    {
        return Err(CoreSetupStoreError::Corrupt);
    }
    Ok(())
}

// Requires the shared setup lock to remain an empty exact private regular file.
fn validate_lock_file(file: &File, owner_user_id: u32) -> Result<(), CoreSetupStoreError> {
    validate_private_file(file, owner_user_id, false)?;
    let metadata = file
        .metadata()
        .map_err(|_| CoreSetupStoreError::Unavailable)?;
    if metadata.len() != 0 {
        return Err(CoreSetupStoreError::Corrupt);
    }
    Ok(())
}

// Returns whether two metadata observations retain exact file identity and contents.
fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;

    use super::directory_entry_names;

    // Keeps enumeration bound to the validated descriptor after its former pathname is replaced.
    #[test]
    fn directory_enumeration_does_not_reopen_a_swapped_path() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path().join("setup");
        let moved = temporary.path().join("setup-original");
        fs::create_dir(&root).expect("setup root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("setup mode");
        File::create(root.join("original")).expect("original entry");
        let descriptor = File::open(&root).expect("root descriptor");

        fs::rename(&root, &moved).expect("move original root");
        fs::create_dir(&root).expect("replacement root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        File::create(root.join("replacement")).expect("replacement entry");

        let names = directory_entry_names(&descriptor).expect("descriptor enumeration");
        assert!(names.iter().any(|name| name == "original"));
        assert!(!names.iter().any(|name| name == "replacement"));
    }
}

// Creates one fixed request-addressed authoritative journal filename.
fn journal_filename(request_id: &Sha256Digest) -> Result<String, CoreSetupStoreError> {
    let filename = format!(
        "{JOURNAL_FILENAME_PREFIX}{}{JOURNAL_FILENAME_SUFFIX}",
        request_id.as_str()
    );
    contained_name(&filename)?;
    Ok(filename)
}

// Creates one fixed same-root pending journal filename.
fn pending_filename(request_id: &Sha256Digest) -> Result<String, CoreSetupStoreError> {
    Ok(format!(
        "{}{PENDING_FILENAME_SUFFIX}",
        journal_filename(request_id)?
    ))
}

// Converts one trusted contained name into a native relative C string.
fn contained_name(name: &str) -> Result<CString, CoreSetupStoreError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(CoreSetupStoreError::Corrupt);
    }
    CString::new(name).map_err(|_| CoreSetupStoreError::Corrupt)
}

// Atomically publishes one absent journal without replacing concurrent state.
#[cfg(target_os = "linux")]
fn activate_create(
    root: &File,
    source: &str,
    destination: &str,
) -> Result<(), CoreSetupStoreError> {
    let source = contained_name(source)?;
    let destination = contained_name(destination)?;
    let status = unsafe {
        libc::renameat2(
            root.as_raw_fd(),
            source.as_ptr(),
            root.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    sync_directory(root)
}

// Atomically publishes one absent journal without replacing concurrent state.
#[cfg(target_os = "macos")]
fn activate_create(
    root: &File,
    source: &str,
    destination: &str,
) -> Result<(), CoreSetupStoreError> {
    let source = contained_name(source)?;
    let destination = contained_name(destination)?;
    let status = unsafe {
        libc::renameatx_np(
            root.as_raw_fd(),
            source.as_ptr(),
            root.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if status != 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    sync_directory(root)
}

// Atomically replaces one exact journal path below the same protected directory.
fn activate_replace(
    root: &File,
    source: &str,
    destination: &str,
) -> Result<(), CoreSetupStoreError> {
    let source = contained_name(source)?;
    let destination = contained_name(destination)?;
    let status = unsafe {
        libc::renameat(
            root.as_raw_fd(),
            source.as_ptr(),
            root.as_raw_fd(),
            destination.as_ptr(),
        )
    };
    if status != 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    sync_directory(root)
}

// Removes one contained journal name relative to the protected directory.
fn unlink_file(root: &File, name: &str) -> Result<(), CoreSetupStoreError> {
    let name = contained_name(name)?;
    unlink_name(root, &name)
}

// Removes one already-validated native contained name.
fn unlink_name(root: &File, name: &CString) -> Result<(), CoreSetupStoreError> {
    let status = unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) };
    if status != 0 {
        return Err(CoreSetupStoreError::Unavailable);
    }
    Ok(())
}

// Persists one protected directory after publication or removal.
fn sync_directory(root: &File) -> Result<(), CoreSetupStoreError> {
    root.sync_all()
        .map_err(|_| CoreSetupStoreError::Unavailable)
}

// Requires the configured owner to be the process effective user.
fn require_effective_owner(owner_user_id: u32) -> Result<(), CoreSetupStoreError> {
    if unsafe { libc::geteuid() } != owner_user_id {
        return Err(CoreSetupStoreError::Unavailable);
    }
    Ok(())
}

// Converts one store contract failure into stable setup-construction language.
fn lock_contract_error(_error: CoreSetupStoreError) -> CoreSetupError {
    CoreSetupError::InvalidContract {
        reason: "setup persistence root is unsafe",
    }
}

// Converts one native lock failure into stable redacted provider language.
fn lock_provider_error(_error: CoreSetupStoreError) -> CoreSetupError {
    CoreSetupError::Provider {
        capability: "setup lock",
        reason: "cross-process setup ownership is unavailable",
    }
}

// Parses one opaque SHA-256 provider receipt.
fn receipt(value: &str) -> Result<CoreSetupReceipt, CoreSetupStoreError> {
    Sha256Digest::parse(value)
        .map(CoreSetupReceipt::new)
        .map_err(|_| CoreSetupStoreError::Corrupt)
}

// Parses one exact main or child identity role.
fn parse_role(value: &str) -> Result<NodeRole, CoreSetupStoreError> {
    match value {
        "main" => Ok(NodeRole::Main),
        "child" => Ok(NodeRole::Child),
        _ => Err(CoreSetupStoreError::Corrupt),
    }
}

// Returns the stable durable spelling for one node role.
const fn role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "main",
        NodeRole::Child => "child",
    }
}

// Parses one bounded normal absolute private file reference.
fn parsed_private_path(value: &str) -> Result<PathBuf, CoreSetupStoreError> {
    if value.is_empty() || value.len() > 4096 {
        return Err(CoreSetupStoreError::Corrupt);
    }
    let path = PathBuf::from(value);
    if path == Path::new("/")
        || !path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(CoreSetupStoreError::Corrupt);
    }
    Ok(path)
}

// Converts one Unicode private path into a bounded durable reference.
fn path_text(path: &Path) -> Result<String, CoreSetupStoreError> {
    let value = path.to_str().ok_or(CoreSetupStoreError::Corrupt)?;
    parsed_private_path(value)?;
    Ok(value.to_string())
}
