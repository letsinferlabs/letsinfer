// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{LogicalModelName, OperationId, Sha256Digest};
use li_node_manager::{
    NodeStorageCandidate, NodeStorageCategory, NodeStorageCleanReceipt, NodeStorageCleanRequest,
    NodeStorageCleanupPort, NodeStorageError, NodeStorageObservationProvider, NodeStorageSnapshot,
    NodeStorageUsage,
};
use sha2::{Digest, Sha256};

const STORAGE_RECEIPT_SCHEMA_NAME: &str = "li_node_storage_cleanup_receipt";
const STORAGE_RECEIPT_SCHEMA_VERSION: u16 = 1;
const MAXIMUM_STORAGE_RECEIPT_BYTES: usize = 64 * 1024;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

// Maps one manager-owned category to its exact local filesystem root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreNodeStorageRoot {
    category: NodeStorageCategory,
    path: PathBuf,
}

impl CoreNodeStorageRoot {
    // Creates one explicit category root before native filesystem access begins.
    pub fn new(category: NodeStorageCategory, path: PathBuf) -> Result<Self, NodeStorageError> {
        if !safe_absolute_path(&path) {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        Ok(Self { category, path })
    }

    // Returns the stable category represented by this root.
    pub const fn category(&self) -> NodeStorageCategory {
        self.category
    }

    // Returns the exact configured root without resolving symbolic links.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// Describes one manager-reviewed inactive target for read-only measurement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreNodeStorageEntry {
    category: NodeStorageCategory,
    path: PathBuf,
    reason: String,
    models: Vec<LogicalModelName>,
}

impl CoreNodeStorageEntry {
    // Creates one exact inactive entry while leaving lifecycle admission with its owner.
    pub fn new(
        category: NodeStorageCategory,
        path: PathBuf,
        reason: impl Into<String>,
        models: Vec<LogicalModelName>,
    ) -> Result<Self, NodeStorageError> {
        let reason = reason.into();
        if !category.is_reclaimable()
            || !safe_absolute_path(&path)
            || reason.is_empty()
            || reason.len() > 512
        {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        Ok(Self {
            category,
            path,
            reason,
            models,
        })
    }

    // Returns the exact owner category.
    pub const fn category(&self) -> NodeStorageCategory {
        self.category
    }

    // Returns the exact inactive target path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // Returns the bounded explanation supplied by the lifecycle owner.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    // Returns models that require exact reacquisition after cleanup.
    pub fn models(&self) -> &[LogicalModelName] {
        &self.models
    }
}

// Stores one recursive no-follow measurement without retaining path content.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoreNodeStorageMeasurement {
    allocated_bytes: u64,
    logical_bytes: u64,
    files: u64,
}

impl CoreNodeStorageMeasurement {
    // Creates one checked native measurement for deterministic providers and tests.
    pub const fn new(allocated_bytes: u64, logical_bytes: u64, files: u64) -> Self {
        Self {
            allocated_bytes,
            logical_bytes,
            files,
        }
    }

    // Adds one child measurement without accepting integer overflow.
    fn checked_add(self, child: Self) -> Result<Self, NodeStorageError> {
        Ok(Self {
            allocated_bytes: self
                .allocated_bytes
                .checked_add(child.allocated_bytes)
                .ok_or(NodeStorageError::ProviderUnavailable)?,
            logical_bytes: self
                .logical_bytes
                .checked_add(child.logical_bytes)
                .ok_or(NodeStorageError::ProviderUnavailable)?,
            files: self
                .files
                .checked_add(child.files)
                .ok_or(NodeStorageError::ProviderUnavailable)?,
        })
    }
}

// Isolates no-follow filesystem observation from storage-plan policy.
pub trait CoreNodeStorageFilesystem: Send + Sync {
    // Returns total and available bytes for the filesystem containing one root.
    fn capacity(&self, path: &Path) -> Result<(u64, u64), NodeStorageError>;

    // Measures one exact tree without following a symbolic link.
    fn measure(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<CoreNodeStorageMeasurement, NodeStorageError>;
}

// Performs bounded read-only storage observation on Unix hosts.
#[derive(Default)]
pub struct SystemCoreNodeStorageFilesystem;

impl CoreNodeStorageFilesystem for SystemCoreNodeStorageFilesystem {
    // Reads native filesystem capacity without mutating the containing volume.
    fn capacity(&self, path: &Path) -> Result<(u64, u64), NodeStorageError> {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| NodeStorageError::ProviderUnavailable)?;
        let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        let value = unsafe { value.assume_init() };
        let block_size = u64::from(value.f_frsize);
        let capacity = u64::from(value.f_blocks)
            .checked_mul(block_size)
            .ok_or(NodeStorageError::ProviderUnavailable)?;
        let available = u64::from(value.f_bavail)
            .checked_mul(block_size)
            .ok_or(NodeStorageError::ProviderUnavailable)?;
        if capacity == 0 || available > capacity {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        Ok((capacity, available))
    }

    // Recursively lstat-observes only owner-bound regular files and directories.
    fn measure(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<CoreNodeStorageMeasurement, NodeStorageError> {
        measure_path(path, owner_user_id)
    }
}

// Supplies exact inactive entries after Runtime, Placement, and Benchmark admission.
pub trait CoreNodeStorageEntryProvider: Send + Sync {
    // Returns every currently inactive owner-reviewed entry in stable identity order.
    fn entries(&self) -> Result<Vec<CoreNodeStorageEntry>, NodeStorageError>;

    // Returns every active or retained root that cleanup must never intersect.
    fn protected_paths(&self) -> Result<Vec<PathBuf>, NodeStorageError>;
}

// Supplies no reclaimable targets until an exact manager-owned cleanup primitive is composed.
#[derive(Default)]
pub struct ReadOnlyCoreNodeStorageEntryProvider;

impl CoreNodeStorageEntryProvider for ReadOnlyCoreNodeStorageEntryProvider {
    // Returns no candidates because read-only observation never implies deletion authority.
    fn entries(&self) -> Result<Vec<CoreNodeStorageEntry>, NodeStorageError> {
        Ok(Vec::new())
    }

    // Returns no target roots because this provider never proposes a cleanup intersection.
    fn protected_paths(&self) -> Result<Vec<PathBuf>, NodeStorageError> {
        Ok(Vec::new())
    }
}

// Observes configured roots and manager-approved inactive entries without mutation.
pub struct FilesystemCoreNodeStorageObservationProvider {
    home: PathBuf,
    owner_user_id: u32,
    roots: Vec<CoreNodeStorageRoot>,
    entries: Arc<dyn CoreNodeStorageEntryProvider>,
    filesystem: Arc<dyn CoreNodeStorageFilesystem>,
}

impl FilesystemCoreNodeStorageObservationProvider {
    // Creates one closed local observation graph with non-overlapping contained roots.
    pub fn new(
        home: PathBuf,
        owner_user_id: u32,
        mut roots: Vec<CoreNodeStorageRoot>,
        entries: Arc<dyn CoreNodeStorageEntryProvider>,
        filesystem: Arc<dyn CoreNodeStorageFilesystem>,
    ) -> Result<Self, NodeStorageError> {
        if !safe_absolute_path(&home) || roots.is_empty() {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        roots.sort_by(|left, right| left.path().cmp(right.path()));
        if roots
            .iter()
            .any(|root| root.path() == home || !root.path().starts_with(&home))
            || roots.windows(2).any(|pair| {
                pair[0].path() == pair[1].path()
                    || pair[1].path().starts_with(pair[0].path())
                    || pair[0].path().starts_with(pair[1].path())
            })
        {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        Ok(Self {
            home,
            owner_user_id,
            roots,
            entries,
            filesystem,
        })
    }

    // Builds one exact snapshot after revalidating every owner-approved target.
    fn observed_snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError> {
        let (capacity_bytes, available_bytes) = self.filesystem.capacity(&self.home)?;
        let mut totals = BTreeMap::<NodeStorageCategory, CoreNodeStorageMeasurement>::new();
        for root in &self.roots {
            let measured = self.filesystem.measure(root.path(), self.owner_user_id)?;
            let current = totals.get(&root.category()).copied().unwrap_or_default();
            totals.insert(root.category(), current.checked_add(measured)?);
        }

        let mut entries = self.entries.entries()?;
        let mut protected = self.entries.protected_paths()?;
        protected.sort();
        if protected.iter().any(|path| {
            !safe_absolute_path(path)
                || !self
                    .roots
                    .iter()
                    .any(|root| path.starts_with(root.path()) && path != root.path())
        }) || protected.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        entries.sort_by(|left, right| left.path().cmp(right.path()));
        if entries
            .windows(2)
            .any(|pair| pair[0].path() == pair[1].path())
        {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        let mut candidates = Vec::with_capacity(entries.len());
        let mut reclaimable = BTreeMap::<NodeStorageCategory, u64>::new();
        let mut plan = Sha256::new();
        plan.update(b"li_node_storage_plan_v1\0");
        for entry in entries {
            if protected
                .iter()
                .any(|active| entry.path().starts_with(active) || active.starts_with(entry.path()))
            {
                return Err(NodeStorageError::ProviderUnavailable);
            }
            let root = self
                .roots
                .iter()
                .find(|root| {
                    root.category() == entry.category() && entry.path().starts_with(root.path())
                })
                .ok_or(NodeStorageError::ProviderUnavailable)?;
            if entry.path() == root.path() {
                return Err(NodeStorageError::ProviderUnavailable);
            }
            let measured = self.filesystem.measure(entry.path(), self.owner_user_id)?;
            if measured.allocated_bytes == 0 {
                return Err(NodeStorageError::ProviderUnavailable);
            }
            let relative = entry
                .path()
                .strip_prefix(&self.home)
                .map_err(|_| NodeStorageError::ProviderUnavailable)?
                .to_str()
                .ok_or(NodeStorageError::ProviderUnavailable)?;
            let relative = relative.trim_start_matches('/');
            framed_digest_field(&mut plan, entry.category().as_str().as_bytes());
            framed_digest_field(&mut plan, relative.as_bytes());
            framed_digest_field(&mut plan, &measured.allocated_bytes.to_be_bytes());
            let total = reclaimable.get(&entry.category()).copied().unwrap_or(0);
            reclaimable.insert(
                entry.category(),
                total
                    .checked_add(measured.allocated_bytes)
                    .ok_or(NodeStorageError::ProviderUnavailable)?,
            );
            candidates.push(NodeStorageCandidate::new(
                entry.category(),
                relative,
                measured.allocated_bytes,
                entry.reason(),
                entry.models().to_vec(),
            )?);
        }
        let usage = totals
            .into_iter()
            .map(|(category, measured)| {
                NodeStorageUsage::new(
                    category,
                    measured.allocated_bytes,
                    measured.logical_bytes,
                    measured.files,
                    reclaimable.get(&category).copied().unwrap_or(0),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        NodeStorageSnapshot::new(
            capacity_bytes,
            available_bytes,
            usage,
            candidates,
            parsed_digest(plan.finalize())?,
        )
    }
}

impl NodeStorageObservationProvider for FilesystemCoreNodeStorageObservationProvider {
    // Returns one complete no-follow observation and immutable cleanup-plan identity.
    fn snapshot(&self) -> Result<NodeStorageSnapshot, NodeStorageError> {
        self.observed_snapshot()
    }
}

// Returns one manager-owned category cleanup outcome before Node aggregation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreNodeStorageCleanup {
    removed_targets: u64,
    reclaimed_bytes: u64,
    models_to_download: Vec<LogicalModelName>,
}

impl CoreNodeStorageCleanup {
    // Creates one checked owner receipt for an exact selected category.
    pub fn new(
        removed_targets: u64,
        reclaimed_bytes: u64,
        models_to_download: Vec<LogicalModelName>,
    ) -> Result<Self, NodeStorageError> {
        if (removed_targets == 0) != (reclaimed_bytes == 0) {
            return Err(NodeStorageError::InvalidProjection);
        }
        Ok(Self {
            removed_targets,
            reclaimed_bytes,
            models_to_download,
        })
    }
}

// Routes one selected category only through its owning manager.
pub trait CoreNodeStorageCategoryCleanupPort: Send + Sync {
    // Applies the exact reviewed category plan idempotently.
    fn clean(
        &self,
        operation_id: &OperationId,
        plan_digest: &Sha256Digest,
    ) -> Result<CoreNodeStorageCleanup, NodeStorageError>;
}

// Persists aggregate cleanup receipts independently of manager-owned bytes.
pub trait CoreNodeStorageCleanupReceiptStore: Send + Sync {
    // Returns one already committed exact receipt when present.
    fn read(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<NodeStorageCleanReceipt>, NodeStorageError>;

    // Commits one complete cross-manager receipt without replacing a conflict.
    fn save(
        &self,
        receipt: &NodeStorageCleanReceipt,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError>;
}

// Rejects every cleanup while production composition remains explicitly observation-only.
#[derive(Default)]
pub struct ReadOnlyCoreNodeStorageCleanupPort;

impl NodeStorageCleanupPort for ReadOnlyCoreNodeStorageCleanupPort {
    // Refuses mutation because a zero-candidate plan has no valid selected category.
    fn clean(
        &self,
        _request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        Err(NodeStorageError::InvalidRequest)
    }
}

// Persists aggregate cleanup receipts as owner-only no-follow atomic files.
pub struct FilesystemCoreNodeStorageCleanupReceiptStore {
    root: PathBuf,
    owner_user_id: u32,
}

impl FilesystemCoreNodeStorageCleanupReceiptStore {
    // Creates one receipt store only from an existing exact private directory.
    pub fn new(root: PathBuf, owner_user_id: u32) -> Result<Self, NodeStorageError> {
        if !safe_absolute_path(&root) {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        require_private_directory(&root, owner_user_id)?;
        Ok(Self {
            root,
            owner_user_id,
        })
    }

    // Resolves one canonical receipt path from its closed operation identity.
    fn receipt_path(&self, operation_id: &OperationId) -> PathBuf {
        self.root.join(format!("{}.json", operation_id.as_str()))
    }

    // Resolves one attempt-owned temporary path from its closed operation identity.
    fn temporary_path(&self, operation_id: &OperationId) -> PathBuf {
        self.root
            .join(format!(".{}.receipt.tmp", operation_id.as_str()))
    }

    // Reads one exact receipt file without following its final component.
    fn read_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<NodeStorageCleanReceipt>, NodeStorageError> {
        require_private_directory(&self.root, self.owner_user_id)?;
        let path = self.receipt_path(operation_id);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(NodeStorageError::ProviderUnavailable),
        };
        let metadata = file
            .metadata()
            .map_err(|_| NodeStorageError::ProviderUnavailable)?;
        if !private_file_metadata(&metadata, self.owner_user_id)
            || metadata.len() == 0
            || metadata.len() > MAXIMUM_STORAGE_RECEIPT_BYTES as u64
        {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAXIMUM_STORAGE_RECEIPT_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| NodeStorageError::ProviderUnavailable)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        let wire: StorageReceiptDocument =
            serde_json::from_slice(&bytes).map_err(|_| NodeStorageError::ProviderUnavailable)?;
        let receipt = wire.into_receipt()?;
        if receipt.operation_id() != operation_id {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        Ok(Some(receipt))
    }
}

impl CoreNodeStorageCleanupReceiptStore for FilesystemCoreNodeStorageCleanupReceiptStore {
    // Returns one previously committed exact receipt without filesystem mutation.
    fn read(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<NodeStorageCleanReceipt>, NodeStorageError> {
        self.read_receipt(operation_id)
    }

    // Durably publishes one complete receipt without replacing an existing identity.
    fn save(
        &self,
        receipt: &NodeStorageCleanReceipt,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        if let Some(existing) = self.read_receipt(receipt.operation_id())? {
            return if existing == *receipt {
                Ok(existing)
            } else {
                Err(NodeStorageError::InvalidProjection)
            };
        }
        let destination = self.receipt_path(receipt.operation_id());
        let temporary = self.temporary_path(receipt.operation_id());
        remove_owned_temporary(&temporary, self.owner_user_id)?;
        let bytes = serde_json::to_vec(&StorageReceiptDocument::from_receipt(receipt))
            .map_err(|_| NodeStorageError::ProviderUnavailable)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| NodeStorageError::ProviderUnavailable)?;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.sync_all())
            .map_err(|_| NodeStorageError::ProviderUnavailable)?;
        if fs::hard_link(&temporary, &destination).is_err() {
            remove_owned_temporary(&temporary, self.owner_user_id)?;
            let existing = self
                .read_receipt(receipt.operation_id())?
                .ok_or(NodeStorageError::ProviderUnavailable)?;
            return if existing == *receipt {
                Ok(existing)
            } else {
                Err(NodeStorageError::InvalidProjection)
            };
        }
        fs::remove_file(&temporary).map_err(|_| NodeStorageError::ProviderUnavailable)?;
        sync_directory(&self.root)?;
        self.read_receipt(receipt.operation_id())?
            .filter(|stored| stored == receipt)
            .ok_or(NodeStorageError::ProviderUnavailable)
    }
}

// Stores one closed durable cleanup receipt document.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StorageReceiptDocument {
    schema_name: String,
    schema_version: u16,
    operation_id: String,
    plan_sha256: String,
    removed_targets: u64,
    reclaimed_bytes: u64,
    models_to_download: Vec<String>,
}

impl StorageReceiptDocument {
    // Projects one validated receipt into its exact private persistence schema.
    fn from_receipt(receipt: &NodeStorageCleanReceipt) -> Self {
        Self {
            schema_name: STORAGE_RECEIPT_SCHEMA_NAME.to_string(),
            schema_version: STORAGE_RECEIPT_SCHEMA_VERSION,
            operation_id: receipt.operation_id().as_str().to_string(),
            plan_sha256: receipt.plan_digest().as_str().to_string(),
            removed_targets: receipt.removed_targets(),
            reclaimed_bytes: receipt.reclaimed_bytes(),
            models_to_download: receipt
                .models_to_download()
                .iter()
                .map(|model| model.as_str().to_string())
                .collect(),
        }
    }

    // Reconstructs one typed receipt only from the exact current schema.
    fn into_receipt(self) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        if self.schema_name != STORAGE_RECEIPT_SCHEMA_NAME
            || self.schema_version != STORAGE_RECEIPT_SCHEMA_VERSION
        {
            return Err(NodeStorageError::ProviderUnavailable);
        }
        NodeStorageCleanReceipt::new(
            OperationId::parse(&self.operation_id)
                .map_err(|_| NodeStorageError::ProviderUnavailable)?,
            Sha256Digest::parse(&self.plan_sha256)
                .map_err(|_| NodeStorageError::ProviderUnavailable)?,
            self.removed_targets,
            self.reclaimed_bytes,
            self.models_to_download
                .into_iter()
                .map(|model| {
                    LogicalModelName::parse(&model)
                        .map_err(|_| NodeStorageError::ProviderUnavailable)
                })
                .collect::<Result<Vec<_>, _>>()?,
            false,
        )
    }
}

// Coordinates selected cleanup through category owners and one atomic receipt boundary.
pub struct ManagedCoreNodeStorageCleanupPort {
    owners: BTreeMap<NodeStorageCategory, Arc<dyn CoreNodeStorageCategoryCleanupPort>>,
    receipts: Arc<dyn CoreNodeStorageCleanupReceiptStore>,
}

impl ManagedCoreNodeStorageCleanupPort {
    // Creates one cleanup composition that refuses unsupported or duplicated owners.
    pub fn new(
        owners: impl IntoIterator<
            Item = (
                NodeStorageCategory,
                Arc<dyn CoreNodeStorageCategoryCleanupPort>,
            ),
        >,
        receipts: Arc<dyn CoreNodeStorageCleanupReceiptStore>,
    ) -> Result<Self, NodeStorageError> {
        let mut mapped = BTreeMap::new();
        for (category, owner) in owners {
            if !matches!(
                category,
                NodeStorageCategory::Caches | NodeStorageCategory::Benchmarks
            ) || mapped.insert(category, owner).is_some()
            {
                return Err(NodeStorageError::InvalidRequest);
            }
        }
        if mapped.is_empty() {
            return Err(NodeStorageError::InvalidRequest);
        }
        Ok(Self {
            owners: mapped,
            receipts,
        })
    }
}

impl NodeStorageCleanupPort for ManagedCoreNodeStorageCleanupPort {
    // Replays one complete receipt or applies every selected owner in stable category order.
    fn clean(
        &self,
        request: &NodeStorageCleanRequest,
    ) -> Result<NodeStorageCleanReceipt, NodeStorageError> {
        if let Some(receipt) = self.receipts.read(request.operation_id())? {
            if receipt.plan_digest() != request.plan_digest() {
                return Err(NodeStorageError::PlanChanged);
            }
            return NodeStorageCleanReceipt::new(
                receipt.operation_id().clone(),
                receipt.plan_digest().clone(),
                receipt.removed_targets(),
                receipt.reclaimed_bytes(),
                receipt.models_to_download().to_vec(),
                true,
            );
        }
        let mut removed_targets = 0_u64;
        let mut reclaimed_bytes = 0_u64;
        let mut models = Vec::new();
        for category in request.categories() {
            let owner = self
                .owners
                .get(category)
                .ok_or(NodeStorageError::InvalidRequest)?;
            let cleanup = owner.clean(request.operation_id(), request.plan_digest())?;
            removed_targets = removed_targets
                .checked_add(cleanup.removed_targets)
                .ok_or(NodeStorageError::InvalidProjection)?;
            reclaimed_bytes = reclaimed_bytes
                .checked_add(cleanup.reclaimed_bytes)
                .ok_or(NodeStorageError::InvalidProjection)?;
            models.extend(cleanup.models_to_download);
        }
        let receipt = NodeStorageCleanReceipt::new(
            request.operation_id().clone(),
            request.plan_digest().clone(),
            removed_targets,
            reclaimed_bytes,
            models,
            false,
        )?;
        self.receipts.save(&receipt)
    }
}

// Measures one exact owner tree while rejecting links, foreign owners, and special files.
fn measure_path(
    path: &Path,
    owner_user_id: u32,
) -> Result<CoreNodeStorageMeasurement, NodeStorageError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(_) => return Err(NodeStorageError::ProviderUnavailable),
    };
    if metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
        return Err(NodeStorageError::ProviderUnavailable);
    }
    if metadata.is_file() {
        return Ok(CoreNodeStorageMeasurement::new(
            metadata.blocks().saturating_mul(512),
            metadata.len(),
            1,
        ));
    }
    if !metadata.is_dir() {
        return Err(NodeStorageError::ProviderUnavailable);
    }
    let mut paths = fs::read_dir(path)
        .map_err(|_| NodeStorageError::ProviderUnavailable)?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| NodeStorageError::ProviderUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.into_iter().try_fold(
        CoreNodeStorageMeasurement::new(metadata.blocks().saturating_mul(512), 0, 0),
        |total, child| total.checked_add(measure_path(&child, owner_user_id)?),
    )
}

// Requires one existing directory to remain owner-only and link-safe.
fn require_private_directory(path: &Path, owner_user_id: u32) -> Result<(), NodeStorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| NodeStorageError::ProviderUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        || metadata.nlink() < 1
    {
        return Err(NodeStorageError::ProviderUnavailable);
    }
    Ok(())
}

// Returns whether one descriptor refers to an owner-only single-link regular file.
fn private_file_metadata(metadata: &fs::Metadata, owner_user_id: u32) -> bool {
    metadata.is_file()
        && metadata.uid() == owner_user_id
        && metadata.mode() & 0o777 == PRIVATE_FILE_MODE
        && metadata.nlink() == 1
}

// Removes only one attempt-owned private temporary file when it exists.
fn remove_owned_temporary(path: &Path, owner_user_id: u32) -> Result<(), NodeStorageError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(NodeStorageError::ProviderUnavailable),
    };
    if metadata.file_type().is_symlink() || !private_file_metadata(&metadata, owner_user_id) {
        return Err(NodeStorageError::ProviderUnavailable);
    }
    fs::remove_file(path).map_err(|_| NodeStorageError::ProviderUnavailable)
}

// Synchronizes one owner-validated receipt namespace after publication.
fn sync_directory(path: &Path) -> Result<(), NodeStorageError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| NodeStorageError::ProviderUnavailable)?;
    directory
        .sync_all()
        .map_err(|_| NodeStorageError::ProviderUnavailable)
}

// Returns whether a native path is absolute, normalized, and free of control components.
fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Appends one unambiguous length-framed identity field to a plan digest.
fn framed_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

// Parses one SHA-256 result without leaking digest-construction details.
fn parsed_digest(bytes: impl AsRef<[u8]>) -> Result<Sha256Digest, NodeStorageError> {
    let value = bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&value).map_err(|_| NodeStorageError::ProviderUnavailable)
}
