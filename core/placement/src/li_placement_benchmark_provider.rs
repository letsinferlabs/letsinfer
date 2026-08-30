// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{Placement, PlacementGroupId, Sha256Digest, UnixMilliseconds};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    PlacementBenchmarkGenerations, PlacementBenchmarkIsolationReceipt,
    PlacementBenchmarkIsolationRequest, PlacementBenchmarkProcessProvider,
    PlacementBenchmarkResetProvider, PlacementBenchmarkResetReceipt,
    PlacementBenchmarkResetRequest, PlacementBenchmarkRestorationReceipt, PlacementError,
    VersionedPlacementRecord,
};

const ACTIVE_FILE_NAME: &str = "active.json";
const MAXIMUM_DOCUMENT_BYTES: usize = 16 * 1024;
const SCHEMA_VERSION: u8 = 1;

// Persists one Node-wide cache-isolation transaction over stable per-placement cache roots.
pub struct FilesystemPlacementBenchmarkResetProvider {
    state_root: PathBuf,
    cache_root: PathBuf,
    owner_user_id: u32,
    processes: Arc<dyn PlacementBenchmarkProcessProvider>,
}

impl FilesystemPlacementBenchmarkResetProvider {
    // Creates one provider from distinct private state and stable per-placement cache roots.
    pub fn new(
        state_root: PathBuf,
        cache_root: PathBuf,
        owner_user_id: u32,
        processes: Arc<dyn PlacementBenchmarkProcessProvider>,
    ) -> Result<Self, PlacementError> {
        if owner_user_id == 0
            || !safe_absolute_path(&state_root)
            || !safe_absolute_path(&cache_root)
            || state_root == cache_root
            || state_root.starts_with(&cache_root)
            || cache_root.starts_with(&state_root)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "benchmark isolation roots are invalid",
            });
        }
        ensure_private_directory(&state_root, owner_user_id)?;
        require_private_directory(&cache_root, owner_user_id)?;
        Ok(Self {
            state_root,
            cache_root,
            owner_user_id,
            processes,
        })
    }

    // Returns the sole durable active transaction document.
    fn active(&self) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        let Some(document) = read_document::<IsolationDocument>(
            &self.state_root.join(ACTIVE_FILE_NAME),
            self.owner_user_id,
        )?
        else {
            return Ok(None);
        };
        isolation_from_document(document).map(Some)
    }

    // Returns one reset receipt path keyed only by its canonical digest identity.
    fn reset_file(&self, reset_id: &Sha256Digest) -> PathBuf {
        self.state_root
            .join(format!("reset_{}.json", reset_id.as_str()))
    }

    // Returns one terminal restoration path keyed by the isolation identity.
    fn restoration_file(&self, isolation_id: &Sha256Digest) -> PathBuf {
        self.state_root
            .join(format!("restoration_{}.json", isolation_id.as_str()))
    }

    // Returns every stable cache root in immutable placement order.
    fn placement_roots(&self, record: &VersionedPlacementRecord) -> Vec<PlacementCacheRoot> {
        record
            .record()
            .placements()
            .iter()
            .map(|placement| PlacementCacheRoot {
                placement: placement.clone(),
                active: self
                    .cache_root
                    .join(placement.assignment().runtime_installation_id().as_str())
                    .join(placement.placement_id().as_str()),
            })
            .collect()
    }

    // Observes one aggregate cache-root inode generation without hashing mutable cache contents.
    fn store_generation(
        &self,
        record: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        let roots = self.placement_roots(record);
        if roots.is_empty() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut digest = Sha256::new();
        framed(&mut digest, "li-placement-benchmark-store-generation-v1");
        framed(
            &mut digest,
            record.record().group().placement_group_id().as_str(),
        );
        for root in roots {
            let metadata = private_directory_metadata(&root.active, self.owner_user_id)?;
            framed(&mut digest, root.placement.placement_id().as_str());
            framed(&mut digest, &metadata.dev().to_string());
            framed(&mut digest, &metadata.ino().to_string());
        }
        Sha256Digest::parse(&format!("{:x}", digest.finalize()))
            .map_err(|_| PlacementError::ExecutionUnavailable)
    }

    // Atomically replaces every group cache root and rolls back completed renames on failure.
    fn replace_roots(
        &self,
        reset_id: &Sha256Digest,
        record: &VersionedPlacementRecord,
    ) -> Result<(), PlacementError> {
        let isolation = self.active()?.ok_or(PlacementError::StoreConflict)?;
        let mut completed = Vec::new();
        for root in self.placement_roots(record) {
            let parent = root
                .active
                .parent()
                .ok_or(PlacementError::ExecutionUnavailable)?;
            require_private_directory(parent, self.owner_user_id)?;
            private_directory_metadata(&root.active, self.owner_user_id)?;
            let resident = parent.join(format!(
                ".li_benchmark_{}_resident_{}",
                isolation.request().isolation_id().as_str(),
                root.placement.placement_id().as_str()
            ));
            let previous = if resident.exists() {
                parent.join(format!(
                    ".li_benchmark_{}_{}_{}",
                    isolation.request().isolation_id().as_str(),
                    reset_id.as_str(),
                    root.placement.placement_id().as_str()
                ))
            } else {
                resident
            };
            if previous.exists() {
                rollback_root_replacements(&completed, self.owner_user_id);
                return Err(PlacementError::StoreConflict);
            }
            fs::rename(&root.active, &previous)
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            if let Err(error) = create_private_directory(&root.active, self.owner_user_id) {
                let _ = fs::rename(&previous, &root.active);
                rollback_root_replacements(&completed, self.owner_user_id);
                return Err(error);
            }
            completed.push((root.active, previous));
        }
        Ok(())
    }

    // Restores every original root, retaining isolated generations for explicit later pruning.
    fn restore_roots(
        &self,
        isolation: &PlacementBenchmarkIsolationReceipt,
        record: &VersionedPlacementRecord,
    ) -> Result<(), PlacementError> {
        let mut completed = Vec::new();
        for root in self.placement_roots(record) {
            let parent = root
                .active
                .parent()
                .ok_or(PlacementError::ExecutionUnavailable)?;
            let resident = parent.join(format!(
                ".li_benchmark_{}_resident_{}",
                isolation.request().isolation_id().as_str(),
                root.placement.placement_id().as_str()
            ));
            if !resident.exists() {
                continue;
            }
            private_directory_metadata(&root.active, self.owner_user_id)?;
            private_directory_metadata(&resident, self.owner_user_id)?;
            let terminal = parent.join(format!(
                ".li_benchmark_{}_terminal_{}",
                isolation.request().isolation_id().as_str(),
                root.placement.placement_id().as_str()
            ));
            if terminal.exists() {
                rollback_root_restorations(&completed);
                return Err(PlacementError::StoreConflict);
            }
            fs::rename(&root.active, &terminal)
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            if let Err(error) = fs::rename(&resident, &root.active) {
                let _ = fs::rename(&terminal, &root.active);
                rollback_root_restorations(&completed);
                return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                    PlacementError::StoreConflict
                } else {
                    PlacementError::ExecutionUnavailable
                });
            }
            completed.push((root.active, resident, terminal));
        }
        Ok(())
    }
}

impl PlacementBenchmarkResetProvider for FilesystemPlacementBenchmarkResetProvider {
    // Persists one exact resident snapshot before any cache-root rename can occur.
    fn prepare_isolation(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<PlacementBenchmarkIsolationReceipt, PlacementError> {
        if let Some(existing) = self.active()? {
            return if existing.request() == request
                && existing.prepared_revision() == running.revision()
            {
                Ok(existing)
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        let receipt = PlacementBenchmarkIsolationReceipt::new(
            request.clone(),
            running.revision(),
            self.processes.generation(running)?,
            self.store_generation(running)?,
        )?;
        write_new_document(
            &self.state_root.join(ACTIVE_FILE_NAME),
            &isolation_document(&receipt),
            self.owner_user_id,
        )?;
        Ok(receipt)
    }

    // Returns the durable original resident snapshot when its exact request matches.
    fn isolation_receipt(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
    ) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        Ok(self
            .active()?
            .filter(|receipt| receipt.request() == request))
    }

    // Returns the sole active transaction only for the requested placement group.
    fn active_isolation(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<PlacementBenchmarkIsolationReceipt>, PlacementError> {
        Ok(self
            .active()?
            .filter(|receipt| receipt.request().placement_group_id() == placement_group_id))
    }

    // Returns one exact terminal restoration receipt after restart.
    fn restoration_receipt(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
    ) -> Result<Option<PlacementBenchmarkRestorationReceipt>, PlacementError> {
        let Some(document) = read_document::<RestorationDocument>(
            &self.restoration_file(request.isolation_id()),
            self.owner_user_id,
        )?
        else {
            return Ok(None);
        };
        let receipt = restoration_from_document(document)?;
        if receipt.isolation().request() != request {
            return Ok(None);
        }
        if self
            .active()?
            .is_some_and(|active| active.request() == request)
        {
            fs::remove_file(self.state_root.join(ACTIVE_FILE_NAME))
                .map_err(|_| PlacementError::StoreUnavailable)?;
        }
        Ok(Some(receipt))
    }

    // Returns one previously committed reset receipt without trusting filenames as content.
    fn receipt(
        &self,
        reset_id: &Sha256Digest,
    ) -> Result<Option<PlacementBenchmarkResetReceipt>, PlacementError> {
        let Some(document) =
            read_document::<ResetDocument>(&self.reset_file(reset_id), self.owner_user_id)?
        else {
            return Ok(None);
        };
        let receipt = reset_from_document(document)?;
        if receipt.reset_id() != reset_id {
            return Err(PlacementError::StoreConflict);
        }
        Ok(Some(receipt))
    }

    // Observes the current native process and exact active cache-root inode generation.
    fn generations(
        &self,
        _request: &PlacementBenchmarkResetRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<PlacementBenchmarkGenerations, PlacementError> {
        Ok(PlacementBenchmarkGenerations::new(
            self.processes.generation(running)?,
            self.store_generation(running)?,
        ))
    }

    // Swaps every stopped placement to one new empty owner-only cache directory.
    fn reset_store(
        &self,
        request: &PlacementBenchmarkResetRequest,
        stopped: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.replace_roots(request.reset_id(), stopped)?;
        self.store_generation(stopped)
    }

    // Delegates exact process identity to the composed Linux or macOS observer.
    fn process_generation(
        &self,
        _request: &PlacementBenchmarkResetRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.processes.generation(running)
    }

    // Persists one reset receipt exactly once and rejects any same-name content drift.
    fn commit(
        &self,
        receipt: PlacementBenchmarkResetReceipt,
    ) -> Result<PlacementBenchmarkResetReceipt, PlacementError> {
        let path = self.reset_file(receipt.reset_id());
        let document = reset_document(&receipt);
        match write_new_document(&path, &document, self.owner_user_id) {
            Ok(()) => Ok(receipt),
            Err(PlacementError::StoreConflict) => {
                let existing = self
                    .receipt(receipt.reset_id())?
                    .ok_or(PlacementError::StoreConflict)?;
                (existing == receipt)
                    .then_some(existing)
                    .ok_or(PlacementError::StoreConflict)
            }
            Err(error) => Err(error),
        }
    }

    // Restores the exact original inode generation while the group remains stopped.
    fn restore_store(
        &self,
        request: &PlacementBenchmarkIsolationRequest,
        stopped: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        let isolation = self
            .isolation_receipt(request)?
            .ok_or(PlacementError::StoreConflict)?;
        self.restore_roots(&isolation, stopped)?;
        self.store_generation(stopped)
    }

    // Delegates restored resident process proof to the same platform observer.
    fn restored_process_generation(
        &self,
        _request: &PlacementBenchmarkIsolationRequest,
        running: &VersionedPlacementRecord,
    ) -> Result<Sha256Digest, PlacementError> {
        self.processes.generation(running)
    }

    // Commits restoration before removing the active transaction marker.
    fn commit_restoration(
        &self,
        receipt: PlacementBenchmarkRestorationReceipt,
    ) -> Result<PlacementBenchmarkRestorationReceipt, PlacementError> {
        let path = self.restoration_file(receipt.isolation().request().isolation_id());
        let document = restoration_document(&receipt);
        match write_new_document(&path, &document, self.owner_user_id) {
            Ok(()) => {}
            Err(PlacementError::StoreConflict) => {
                let existing = self
                    .restoration_receipt(receipt.isolation().request())?
                    .ok_or(PlacementError::StoreConflict)?;
                if existing != receipt {
                    return Err(PlacementError::StoreConflict);
                }
            }
            Err(error) => return Err(error),
        }
        match fs::remove_file(self.state_root.join(ACTIVE_FILE_NAME)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlacementError::StoreUnavailable),
        }
        Ok(receipt)
    }
}

// Associates one immutable placement with its stable active cache path.
struct PlacementCacheRoot {
    placement: Placement,
    active: PathBuf,
}

// Stores one closed resident snapshot document.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IsolationDocument {
    schema_name: String,
    schema_version: u8,
    isolation_id: String,
    placement_group_id: String,
    prepared_revision: u64,
    resident_process_generation_sha256: String,
    resident_store_generation_sha256: String,
    receipt_sha256: String,
}

// Stores one closed reset receipt document.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResetDocument {
    schema_name: String,
    schema_version: u8,
    reset_id: String,
    placement_group_id: String,
    context: String,
    context_index: u32,
    context_count: u32,
    expected_revision: u64,
    previous_revision: u64,
    next_revision: u64,
    store_generation_sha256: String,
    process_generation_sha256: String,
    reset_at_unix_milliseconds: u64,
    receipt_sha256: String,
}

// Stores one closed terminal restoration receipt document.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestorationDocument {
    schema_name: String,
    schema_version: u8,
    isolation: IsolationDocument,
    previous_revision: u64,
    next_revision: u64,
    restored_process_generation_sha256: String,
    restored_at_unix_milliseconds: u64,
    receipt_sha256: String,
}

// Projects one resident snapshot into private persistence fields.
fn isolation_document(receipt: &PlacementBenchmarkIsolationReceipt) -> IsolationDocument {
    IsolationDocument {
        schema_name: "li-placement-benchmark-isolation".to_string(),
        schema_version: SCHEMA_VERSION,
        isolation_id: receipt.request().isolation_id().as_str().to_string(),
        placement_group_id: receipt.request().placement_group_id().as_str().to_string(),
        prepared_revision: receipt.prepared_revision(),
        resident_process_generation_sha256: receipt
            .resident_process_generation_sha256()
            .as_str()
            .to_string(),
        resident_store_generation_sha256: receipt
            .resident_store_generation_sha256()
            .as_str()
            .to_string(),
        receipt_sha256: receipt.receipt_sha256().as_str().to_string(),
    }
}

// Reconstructs one resident snapshot and verifies its complete digest.
fn isolation_from_document(
    document: IsolationDocument,
) -> Result<PlacementBenchmarkIsolationReceipt, PlacementError> {
    if document.schema_name != "li-placement-benchmark-isolation"
        || document.schema_version != SCHEMA_VERSION
    {
        return Err(PlacementError::StoreUnavailable);
    }
    let receipt = PlacementBenchmarkIsolationReceipt::new(
        PlacementBenchmarkIsolationRequest::new(
            digest(&document.isolation_id)?,
            PlacementGroupId::parse(&document.placement_group_id)
                .map_err(|_| PlacementError::StoreUnavailable)?,
        ),
        document.prepared_revision,
        digest(&document.resident_process_generation_sha256)?,
        digest(&document.resident_store_generation_sha256)?,
    )?;
    if receipt.receipt_sha256().as_str() != document.receipt_sha256 {
        return Err(PlacementError::StoreConflict);
    }
    Ok(receipt)
}

// Projects one reset receipt into private persistence fields.
fn reset_document(receipt: &PlacementBenchmarkResetReceipt) -> ResetDocument {
    ResetDocument {
        schema_name: "li-placement-benchmark-reset".to_string(),
        schema_version: SCHEMA_VERSION,
        reset_id: receipt.reset_id().as_str().to_string(),
        placement_group_id: receipt.placement_group_id().as_str().to_string(),
        context: receipt.context().to_string(),
        context_index: receipt.context_index(),
        context_count: receipt.context_count(),
        expected_revision: receipt.expected_revision(),
        previous_revision: receipt.previous_revision(),
        next_revision: receipt.next_revision(),
        store_generation_sha256: receipt.store_generation_sha256().as_str().to_string(),
        process_generation_sha256: receipt.process_generation_sha256().as_str().to_string(),
        reset_at_unix_milliseconds: receipt.reset_at().value(),
        receipt_sha256: receipt.receipt_sha256().as_str().to_string(),
    }
}

// Reconstructs one reset receipt and verifies its complete digest.
fn reset_from_document(
    document: ResetDocument,
) -> Result<PlacementBenchmarkResetReceipt, PlacementError> {
    if document.schema_name != "li-placement-benchmark-reset"
        || document.schema_version != SCHEMA_VERSION
    {
        return Err(PlacementError::StoreUnavailable);
    }
    let request = PlacementBenchmarkResetRequest::new(
        digest(&document.reset_id)?,
        PlacementGroupId::parse(&document.placement_group_id)
            .map_err(|_| PlacementError::StoreUnavailable)?,
        document.expected_revision,
        &document.context,
        document.context_index,
        document.context_count,
    )?;
    let receipt = PlacementBenchmarkResetReceipt::new(
        &request,
        document.previous_revision,
        document.next_revision,
        digest(&document.store_generation_sha256)?,
        digest(&document.process_generation_sha256)?,
        UnixMilliseconds::new(document.reset_at_unix_milliseconds),
    )?;
    if receipt.receipt_sha256().as_str() != document.receipt_sha256 {
        return Err(PlacementError::StoreConflict);
    }
    Ok(receipt)
}

// Projects one terminal restoration into private persistence fields.
fn restoration_document(receipt: &PlacementBenchmarkRestorationReceipt) -> RestorationDocument {
    RestorationDocument {
        schema_name: "li-placement-benchmark-restoration".to_string(),
        schema_version: SCHEMA_VERSION,
        isolation: isolation_document(receipt.isolation()),
        previous_revision: receipt.previous_revision(),
        next_revision: receipt.next_revision(),
        restored_process_generation_sha256: receipt
            .restored_process_generation_sha256()
            .as_str()
            .to_string(),
        restored_at_unix_milliseconds: receipt.restored_at().value(),
        receipt_sha256: receipt.receipt_sha256().as_str().to_string(),
    }
}

// Reconstructs one terminal restoration and verifies its complete digest.
fn restoration_from_document(
    document: RestorationDocument,
) -> Result<PlacementBenchmarkRestorationReceipt, PlacementError> {
    if document.schema_name != "li-placement-benchmark-restoration"
        || document.schema_version != SCHEMA_VERSION
    {
        return Err(PlacementError::StoreUnavailable);
    }
    let receipt = PlacementBenchmarkRestorationReceipt::new(
        isolation_from_document(document.isolation)?,
        document.previous_revision,
        document.next_revision,
        digest(&document.restored_process_generation_sha256)?,
        UnixMilliseconds::new(document.restored_at_unix_milliseconds),
    )?;
    if receipt.receipt_sha256().as_str() != document.receipt_sha256 {
        return Err(PlacementError::StoreConflict);
    }
    Ok(receipt)
}

// Writes one canonical owner-only document without replacing an existing identity.
fn write_new_document<T: Serialize>(
    path: &Path,
    document: &T,
    owner_user_id: u32,
) -> Result<(), PlacementError> {
    let mut payload = serde_json::to_vec(document).map_err(|_| PlacementError::StoreUnavailable)?;
    payload.push(b'\n');
    if payload.len() > MAXIMUM_DOCUMENT_BYTES {
        return Err(PlacementError::StoreUnavailable);
    }
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(PlacementError::StoreConflict)
        }
        Err(_) => return Err(PlacementError::StoreUnavailable),
    };
    file.write_all(&payload)
        .and_then(|_| file.sync_all())
        .map_err(|_| PlacementError::StoreUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| PlacementError::StoreUnavailable)?;
    if metadata.uid() != owner_user_id || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1
    {
        return Err(PlacementError::StoreUnavailable);
    }
    Ok(())
}

// Reads one bounded no-follow owner-only document.
fn read_document<T: for<'de> Deserialize<'de>>(
    path: &Path,
    owner_user_id: u32,
) -> Result<Option<T>, PlacementError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(PlacementError::StoreUnavailable),
    };
    let metadata = file
        .metadata()
        .map_err(|_| PlacementError::StoreUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_DOCUMENT_BYTES as u64
    {
        return Err(PlacementError::StoreUnavailable);
    }
    let mut payload = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|_| PlacementError::StoreUnavailable)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|_| PlacementError::StoreUnavailable)
}

// Creates one empty owner-only cache directory at an exact absent path.
fn create_private_directory(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    fs::create_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| PlacementError::ExecutionUnavailable)?;
    private_directory_metadata(path, owner_user_id).map(|_| ())
}

// Requires one exact directory without following a symbolic alias.
fn private_directory_metadata(
    path: &Path,
    owner_user_id: u32,
) -> Result<fs::Metadata, PlacementError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() < 2
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(metadata)
}

// Requires one existing private root before provider construction can succeed.
fn require_private_directory(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    private_directory_metadata(path, owner_user_id).map(|_| ())
}

// Creates one absent private state root or validates the exact existing directory.
fn ensure_private_directory(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_private_directory(path, owner_user_id),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            require_private_directory(
                path.parent().ok_or(PlacementError::StoreUnavailable)?,
                owner_user_id,
            )?;
            create_private_directory(path, owner_user_id)
        }
        Err(_) => Err(PlacementError::StoreUnavailable),
    }
}

// Rolls completed fresh-root swaps back in reverse order after a partial failure.
fn rollback_root_replacements(completed: &[(PathBuf, PathBuf)], owner_user_id: u32) {
    for (active, previous) in completed.iter().rev() {
        if private_directory_metadata(active, owner_user_id).is_ok()
            && fs::read_dir(active)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
        {
            let _ = fs::remove_dir(active);
            let _ = fs::rename(previous, active);
        }
    }
}

// Rolls completed resident restorations back when a later placement cannot restore.
fn rollback_root_restorations(completed: &[(PathBuf, PathBuf, PathBuf)]) {
    for (active, resident, terminal) in completed.iter().rev() {
        let _ = fs::rename(active, resident);
        let _ = fs::rename(terminal, active);
    }
}

// Parses one canonical digest from private persistence.
fn digest(value: &str) -> Result<Sha256Digest, PlacementError> {
    Sha256Digest::parse(value).map_err(|_| PlacementError::StoreUnavailable)
}

// Returns whether one path is absolute, normalized, and free of platform prefixes.
fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            !matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
}

// Adds one unambiguous UTF-8 field to an aggregate generation digest.
fn framed(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}
