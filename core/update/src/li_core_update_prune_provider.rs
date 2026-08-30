// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::li_core_update_artifact_provider::{
    require_absolute_normal_path, verify_core_native_tree,
};
use crate::{
    CoreInstallation, CoreUpdateArtifactIo, CoreUpdateError, CoreUpdatePathKind,
    CoreUpdatePruneProvider, CoreVersion,
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const VERSION_DIRECTORY_MODE: u32 = 0o755;
const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
const PRIVATE_FILE_MODE: u32 = 0o400;
const PRIVATE_EXECUTABLE_MODE: u32 = 0o500;
const IMMUTABLE_FILE_MODE: u32 = 0o444;
const IMMUTABLE_EXECUTABLE_MODE: u32 = 0o555;
const MAXIMUM_PRUNE_TREE_ENTRIES: usize = 40_000;
const MAXIMUM_PRUNE_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// Carries the exact Core and update-workspace identities that remain live.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoreUpdatePruneReferences {
    core_installations: Vec<CoreInstallation>,
    update_workspaces: Vec<Sha256Digest>,
}

impl CoreUpdatePruneReferences {
    // Forms one canonical union of immutable Core and update-recovery references.
    pub fn new(
        mut core_installations: Vec<CoreInstallation>,
        mut update_workspaces: Vec<Sha256Digest>,
    ) -> Self {
        core_installations.sort();
        core_installations.dedup();
        update_workspaces.sort();
        update_workspaces.dedup();
        Self {
            core_installations,
            update_workspaces,
        }
    }

    // Returns every exact Core installation retained by live or recovery state.
    pub fn core_installations(&self) -> &[CoreInstallation] {
        &self.core_installations
    }

    // Returns every update workspace still owned by a nonterminal journal.
    pub fn update_workspaces(&self) -> &[Sha256Digest] {
        &self.update_workspaces
    }
}

// Supplies the already-merged live reference set without exposing manager storage.
pub trait CoreUpdatePruneReferenceProvider: Send + Sync {
    // Returns exact references observed from one consistent composition-root snapshot.
    fn references(
        &self,
        update_id: &Sha256Digest,
        active: &CoreInstallation,
    ) -> Result<CoreUpdatePruneReferences, CoreUpdateError>;
}

// Identifies one no-follow filesystem entry kind at the prune boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdatePruneEntryKind {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

// Carries one raw no-follow entry for provider-owned semantic verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdatePruneEntry {
    relative_path: PathBuf,
    kind: CoreUpdatePruneEntryKind,
    mode: u32,
    bytes: u64,
    sha256: Option<Sha256Digest>,
}

impl CoreUpdatePruneEntry {
    // Creates one raw directory entry with its exact relative identity and mode.
    pub fn directory(relative_path: PathBuf, mode: u32) -> Result<Self, CoreUpdateError> {
        Self::new(
            relative_path,
            CoreUpdatePruneEntryKind::Directory,
            mode,
            0,
            None,
        )
    }

    // Creates one raw regular-file entry with an optional inventory digest.
    pub fn regular_file(
        relative_path: PathBuf,
        mode: u32,
        bytes: u64,
        sha256: Option<Sha256Digest>,
    ) -> Result<Self, CoreUpdateError> {
        Self::new(
            relative_path,
            CoreUpdatePruneEntryKind::RegularFile,
            mode,
            bytes,
            sha256,
        )
    }

    // Creates one raw symlink entry so policy can reject it without following it.
    pub fn symlink(relative_path: PathBuf, mode: u32) -> Result<Self, CoreUpdateError> {
        Self::new(
            relative_path,
            CoreUpdatePruneEntryKind::Symlink,
            mode,
            0,
            None,
        )
    }

    // Creates one raw unsupported filesystem entry for fail-closed fixtures.
    pub fn other(relative_path: PathBuf, mode: u32) -> Result<Self, CoreUpdateError> {
        Self::new(
            relative_path,
            CoreUpdatePruneEntryKind::Other,
            mode,
            0,
            None,
        )
    }

    // Creates one structurally valid raw entry without judging its semantic mode.
    fn new(
        relative_path: PathBuf,
        kind: CoreUpdatePruneEntryKind,
        mode: u32,
        bytes: u64,
        sha256: Option<Sha256Digest>,
    ) -> Result<Self, CoreUpdateError> {
        require_relative_path(&relative_path)?;
        Ok(Self {
            relative_path,
            kind,
            mode,
            bytes,
            sha256,
        })
    }

    // Returns the exact path relative to the requested inventory root.
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    // Returns the no-follow entry kind.
    pub const fn kind(&self) -> CoreUpdatePruneEntryKind {
        self.kind
    }

    // Returns the exact Unix permission bits.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    // Returns the regular-file size or zero for non-files.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    // Returns the exact file digest when a recursive inventory computed one.
    pub const fn sha256(&self) -> Option<&Sha256Digest> {
        self.sha256.as_ref()
    }
}

// Supplies only the native reads and exact deletions required by pruning.
pub trait CoreUpdatePruneIo: Send + Sync {
    // Returns one final path kind without following a symbolic link.
    fn path_kind(&self, path: &Path) -> Result<CoreUpdatePathKind, CoreUpdateError>;

    // Requires one owner-bound no-follow directory with an exact mode.
    fn require_directory(&self, path: &Path, mode: u32) -> Result<(), CoreUpdateError>;

    // Lists immediate owner-bound children without following symbolic links.
    fn directory_entries(&self, root: &Path) -> Result<Vec<CoreUpdatePruneEntry>, CoreUpdateError>;

    // Inventories and hashes one bounded owner-bound tree without following links.
    fn inventory(
        &self,
        root: &Path,
        maximum_entries: usize,
        maximum_bytes: u64,
    ) -> Result<Vec<CoreUpdatePruneEntry>, CoreUpdateError>;

    // Reads one bounded owner-bound regular file through a no-follow descriptor.
    fn read_regular_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CoreUpdateError>;

    // Removes one exact verified tree and persists only its immediate parent.
    fn remove_tree(
        &self,
        path: &Path,
        root_mode: u32,
        parent_mode: u32,
    ) -> Result<(), CoreUpdateError>;

    // Removes one exact empty version root and persists the versions directory.
    fn remove_empty_directory(
        &self,
        path: &Path,
        mode: u32,
        parent_mode: u32,
    ) -> Result<(), CoreUpdateError>;
}

// Implements owner-bound no-follow pruning operations on a Unix filesystem.
pub struct FilesystemCoreUpdatePruneIo {
    owner_user_id: u32,
}

impl FilesystemCoreUpdatePruneIo {
    // Creates one native prune capability bound to the installing user.
    pub const fn new(owner_user_id: u32) -> Self {
        Self { owner_user_id }
    }

    // Converts one no-follow metadata record into a raw provider entry.
    fn entry(
        &self,
        relative_path: PathBuf,
        metadata: &fs::Metadata,
        sha256: Option<Sha256Digest>,
    ) -> Result<CoreUpdatePruneEntry, CoreUpdateError> {
        if metadata.uid() != self.owner_user_id {
            return Err(unsafe_prune_layout_error());
        }
        let mode = metadata.mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            return CoreUpdatePruneEntry::symlink(relative_path, mode);
        }
        if metadata.is_dir() {
            return CoreUpdatePruneEntry::directory(relative_path, mode);
        }
        if metadata.is_file() {
            if metadata.nlink() != 1 {
                return Err(unsafe_prune_layout_error());
            }
            return CoreUpdatePruneEntry::regular_file(relative_path, mode, metadata.len(), sha256);
        }
        CoreUpdatePruneEntry::other(relative_path, mode)
    }

    // Opens one owner-bound file without following its final path.
    fn open_regular_file(&self, path: &Path, maximum_bytes: u64) -> Result<File, CoreUpdateError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| prune_io_error("prune file opening is unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| prune_io_error("prune file inspection is unavailable"))?;
        if !metadata.is_file()
            || metadata.uid() != self.owner_user_id
            || metadata.nlink() != 1
            || metadata.len() > maximum_bytes
        {
            return Err(unsafe_prune_layout_error());
        }
        Ok(file)
    }

    // Hashes one already-bounded owner-bound file through its open descriptor.
    fn file_digest(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Sha256Digest, CoreUpdateError> {
        let mut file = self.open_regular_file(path, maximum_bytes)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| prune_io_error("prune file hashing is unavailable"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        parse_digest(&format!("{:x}", digest.finalize()))
    }

    // Makes only validated owner-bound directories writable before exact removal.
    fn make_directories_writable(&self, root: &Path) -> Result<(), CoreUpdateError> {
        let inventory =
            self.inventory(root, MAXIMUM_PRUNE_TREE_ENTRIES, MAXIMUM_PRUNE_TREE_BYTES)?;
        let mut directories = inventory
            .iter()
            .filter(|entry| entry.kind() == CoreUpdatePruneEntryKind::Directory)
            .map(|entry| root.join(entry.relative_path()))
            .collect::<Vec<_>>();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            fs::set_permissions(
                &directory,
                fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
            )
            .map_err(|_| prune_io_error("prune tree protection is unavailable"))?;
        }
        fs::set_permissions(root, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .map_err(|_| prune_io_error("prune tree protection is unavailable"))
    }
}

impl CoreUpdatePruneIo for FilesystemCoreUpdatePruneIo {
    // Returns one final path kind without following a symbolic link.
    fn path_kind(&self, path: &Path) -> Result<CoreUpdatePathKind, CoreUpdateError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                let kind = if metadata.file_type().is_symlink() {
                    CoreUpdatePathKind::Symlink
                } else if metadata.is_dir() {
                    CoreUpdatePathKind::Directory
                } else if metadata.is_file() {
                    CoreUpdatePathKind::RegularFile
                } else {
                    CoreUpdatePathKind::Other
                };
                Ok(kind)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(CoreUpdatePathKind::Missing)
            }
            Err(_) => Err(prune_io_error("prune path inspection is unavailable")),
        }
    }

    // Requires one owner-bound no-follow directory with an exact mode.
    fn require_directory(&self, path: &Path, mode: u32) -> Result<(), CoreUpdateError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| prune_io_error("prune directory inspection is unavailable"))?;
        require_owned_directory(&metadata, self.owner_user_id, mode)
    }

    // Lists immediate owner-bound children without following symbolic links.
    fn directory_entries(&self, root: &Path) -> Result<Vec<CoreUpdatePruneEntry>, CoreUpdateError> {
        let mut entries = Vec::new();
        for child in fs::read_dir(root)
            .map_err(|_| prune_io_error("prune directory listing is unavailable"))?
        {
            let child =
                child.map_err(|_| prune_io_error("prune directory listing is unavailable"))?;
            let path = child.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| unsafe_prune_layout_error())?
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| prune_io_error("prune entry inspection is unavailable"))?;
            entries.push(self.entry(relative, &metadata, None)?);
        }
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(entries)
    }

    // Inventories and hashes one bounded owner-bound tree without following links.
    fn inventory(
        &self,
        root: &Path,
        maximum_entries: usize,
        maximum_bytes: u64,
    ) -> Result<Vec<CoreUpdatePruneEntry>, CoreUpdateError> {
        let mut pending = vec![root.to_path_buf()];
        let mut entries = Vec::new();
        let mut total_bytes = 0_u64;
        while let Some(directory) = pending.pop() {
            for child in fs::read_dir(&directory)
                .map_err(|_| prune_io_error("prune tree inventory is unavailable"))?
            {
                let child =
                    child.map_err(|_| prune_io_error("prune tree inventory is unavailable"))?;
                let path = child.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| unsafe_prune_layout_error())?
                    .to_path_buf();
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|_| prune_io_error("prune entry inspection is unavailable"))?;
                if metadata.file_type().is_symlink()
                    || (!metadata.is_dir() && !metadata.is_file())
                    || metadata.uid() != self.owner_user_id
                    || metadata.mode() & 0o7000 != 0
                {
                    return Err(unsafe_prune_layout_error());
                }
                entries
                    .len()
                    .checked_add(1)
                    .filter(|count| *count <= maximum_entries)
                    .ok_or_else(|| prune_io_error("prune tree exceeds its boundary"))?;
                let sha256 = if metadata.is_file() {
                    total_bytes = total_bytes
                        .checked_add(metadata.len())
                        .filter(|bytes| *bytes <= maximum_bytes)
                        .ok_or_else(|| prune_io_error("prune tree exceeds its boundary"))?;
                    Some(self.file_digest(&path, maximum_bytes)?)
                } else {
                    pending.push(path);
                    None
                };
                entries.push(self.entry(relative, &metadata, sha256)?);
            }
        }
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(entries)
    }

    // Reads one bounded owner-bound regular file through a no-follow descriptor.
    fn read_regular_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CoreUpdateError> {
        let mut file = self.open_regular_file(path, maximum_bytes)?;
        let expected = file
            .metadata()
            .map_err(|_| prune_io_error("prune file inspection is unavailable"))?
            .len();
        let mut bytes = Vec::with_capacity(
            usize::try_from(expected)
                .map_err(|_| prune_io_error("prune file exceeds its boundary"))?,
        );
        file.read_to_end(&mut bytes)
            .map_err(|_| prune_io_error("prune file reading is unavailable"))?;
        if bytes.len() as u64 != expected {
            return Err(prune_io_error("prune file changed while being read"));
        }
        Ok(bytes)
    }

    // Removes one exact verified tree and persists only its immediate parent.
    fn remove_tree(
        &self,
        path: &Path,
        root_mode: u32,
        parent_mode: u32,
    ) -> Result<(), CoreUpdateError> {
        match self.path_kind(path)? {
            CoreUpdatePathKind::Missing => return Ok(()),
            CoreUpdatePathKind::Directory => {}
            _ => return Err(unsafe_prune_layout_error()),
        }
        self.require_directory(path, root_mode)?;
        let parent = path.parent().ok_or_else(unsafe_prune_layout_error)?;
        self.require_directory(parent, parent_mode)?;
        self.make_directories_writable(path)?;
        fs::remove_dir_all(path)
            .map_err(|_| prune_io_error("exact prune removal is unavailable"))?;
        sync_owned_directory(parent, self.owner_user_id, parent_mode)
    }

    // Removes one exact empty version root and persists the versions directory.
    fn remove_empty_directory(
        &self,
        path: &Path,
        mode: u32,
        parent_mode: u32,
    ) -> Result<(), CoreUpdateError> {
        match self.path_kind(path)? {
            CoreUpdatePathKind::Missing => return Ok(()),
            CoreUpdatePathKind::Directory => {}
            _ => return Err(unsafe_prune_layout_error()),
        }
        self.require_directory(path, mode)?;
        let parent = path.parent().ok_or_else(unsafe_prune_layout_error)?;
        self.require_directory(parent, parent_mode)?;
        fs::remove_dir(path)
            .map_err(|_| prune_io_error("empty Core version removal is unavailable"))?;
        sync_owned_directory(parent, self.owner_user_id, parent_mode)
    }
}

// Describes one complete immutable Core and update-workspace cleanup decision before mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdatePrunePlan {
    plan_id: Sha256Digest,
    update_id: Sha256Digest,
    active: CoreInstallation,
    references: CoreUpdatePruneReferences,
    core_installations: Vec<CoreInstallation>,
    update_workspaces: Vec<Sha256Digest>,
    version_roots: Vec<CoreVersion>,
}

impl CoreUpdatePrunePlan {
    // Returns the deterministic identity of this exact observed plan.
    pub const fn plan_id(&self) -> &Sha256Digest {
        &self.plan_id
    }

    // Returns the exact stale immutable Core identities selected for removal.
    pub fn core_installations(&self) -> &[CoreInstallation] {
        &self.core_installations
    }

    // Returns the exact stale update workspace identities selected for removal.
    pub fn update_workspaces(&self) -> &[Sha256Digest] {
        &self.update_workspaces
    }

    // Returns the exact version roots that become empty after planned removals.
    pub fn version_roots(&self) -> &[CoreVersion] {
        &self.version_roots
    }

    // Returns whether this plan performs no filesystem mutation.
    pub fn is_empty(&self) -> bool {
        self.core_installations.is_empty()
            && self.update_workspaces.is_empty()
            && self.version_roots.is_empty()
    }
}

// Records one deterministic completed or dry-run cleanup attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdatePruneReceipt {
    receipt_id: Sha256Digest,
    plan_id: Sha256Digest,
    dry_run: bool,
    removed_core_installations: Vec<CoreInstallation>,
    removed_update_workspaces: Vec<Sha256Digest>,
    removed_version_roots: Vec<CoreVersion>,
}

impl CoreUpdatePruneReceipt {
    // Returns the deterministic identity of this exact outcome.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the plan identity verified immediately before mutation.
    pub const fn plan_id(&self) -> &Sha256Digest {
        &self.plan_id
    }

    // Returns whether the receipt describes a read-only dry run.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    // Returns immutable Core identities actually removed by this attempt.
    pub fn removed_core_installations(&self) -> &[CoreInstallation] {
        &self.removed_core_installations
    }

    // Returns update workspaces actually removed by this attempt.
    pub fn removed_update_workspaces(&self) -> &[Sha256Digest] {
        &self.removed_update_workspaces
    }

    // Returns empty version roots actually removed by this attempt.
    pub fn removed_version_roots(&self) -> &[CoreVersion] {
        &self.removed_version_roots
    }
}

// Owns exact reference-aware deletion after a verified Core handoff commits.
pub struct ReferenceAwareCoreUpdatePruneProvider {
    letsinfer_home: PathBuf,
    core_root: PathBuf,
    versions_root: PathBuf,
    staging_root: PathBuf,
    current_link: PathBuf,
    artifacts: Arc<dyn CoreUpdateArtifactIo>,
    io: Arc<dyn CoreUpdatePruneIo>,
    references: Arc<dyn CoreUpdatePruneReferenceProvider>,
}

impl ReferenceAwareCoreUpdatePruneProvider {
    // Creates one provider rooted at a canonical absolute LETSINFER_HOME.
    pub fn new(
        letsinfer_home: PathBuf,
        artifacts: Arc<dyn CoreUpdateArtifactIo>,
        io: Arc<dyn CoreUpdatePruneIo>,
        references: Arc<dyn CoreUpdatePruneReferenceProvider>,
    ) -> Result<Self, CoreUpdateError> {
        require_absolute_normal_path(&letsinfer_home)?;
        if letsinfer_home.parent().is_none() {
            return Err(unsafe_prune_layout_error());
        }
        let core_root = letsinfer_home.join("core");
        Ok(Self {
            versions_root: core_root.join("versions"),
            staging_root: core_root.join("staging"),
            current_link: core_root.join("current"),
            letsinfer_home,
            core_root,
            artifacts,
            io,
            references,
        })
    }

    // Produces one deterministic fail-closed plan without changing the filesystem.
    pub fn plan(
        &self,
        update_id: &Sha256Digest,
        active: &CoreInstallation,
    ) -> Result<CoreUpdatePrunePlan, CoreUpdateError> {
        let references = self.references.references(update_id, active)?;
        let (core_installations, version_roots) =
            self.inspect_core_installations(active, &references)?;
        let update_workspaces = self.inspect_update_workspaces(&references)?;
        let plan_id = prune_plan_identity(
            update_id,
            active,
            &references,
            &core_installations,
            &update_workspaces,
            &version_roots,
        )?;
        Ok(CoreUpdatePrunePlan {
            plan_id,
            update_id: update_id.clone(),
            active: active.clone(),
            references,
            core_installations,
            update_workspaces,
            version_roots,
        })
    }

    // Revalidates one exact plan and applies only its listed targets.
    pub fn execute(
        &self,
        plan: &CoreUpdatePrunePlan,
        dry_run: bool,
    ) -> Result<CoreUpdatePruneReceipt, CoreUpdateError> {
        let observed = self.plan(&plan.update_id, &plan.active)?;
        if &observed != plan {
            return Err(prune_io_error("Core prune plan changed before execution"));
        }
        if dry_run {
            return prune_receipt(plan, true, false);
        }
        for update_id in &plan.update_workspaces {
            self.io.remove_tree(
                &self.staging_root.join(update_id.as_str()),
                PRIVATE_DIRECTORY_MODE,
                PRIVATE_DIRECTORY_MODE,
            )?;
        }
        for installation in &plan.core_installations {
            self.io.remove_tree(
                &self.installation_path(installation),
                IMMUTABLE_DIRECTORY_MODE,
                VERSION_DIRECTORY_MODE,
            )?;
        }
        for version in &plan.version_roots {
            self.io.remove_empty_directory(
                &self.versions_root.join(version.as_str()),
                VERSION_DIRECTORY_MODE,
                VERSION_DIRECTORY_MODE,
            )?;
        }
        prune_receipt(plan, false, true)
    }

    // Plans and executes one update-owned prune while retaining a typed receipt.
    pub fn prune_with_receipt(
        &self,
        update_id: &Sha256Digest,
        active: &CoreInstallation,
        dry_run: bool,
    ) -> Result<CoreUpdatePruneReceipt, CoreUpdateError> {
        let plan = self.plan(update_id, active)?;
        self.execute(&plan, dry_run)
    }

    // Returns one exact immutable Core path from a validated installation identity.
    fn installation_path(&self, installation: &CoreInstallation) -> PathBuf {
        self.versions_root
            .join(installation.version().as_str())
            .join(installation.source_identity().as_str())
    }

    // Inspects and verifies every versioned Core before selecting unreferenced identities.
    fn inspect_core_installations(
        &self,
        active: &CoreInstallation,
        references: &CoreUpdatePruneReferences,
    ) -> Result<(Vec<CoreInstallation>, Vec<CoreVersion>), CoreUpdateError> {
        self.artifacts
            .require_directory(&self.letsinfer_home, PRIVATE_DIRECTORY_MODE)?;
        self.artifacts
            .require_directory(&self.core_root, PRIVATE_DIRECTORY_MODE)?;
        self.artifacts
            .require_directory(&self.versions_root, VERSION_DIRECTORY_MODE)?;
        let active_path = self.installation_path(active);
        if self.artifacts.read_symlink(&self.current_link)? != active_path {
            return Err(unsafe_prune_layout_error());
        }

        let mut observed = BTreeMap::new();
        let mut version_members = BTreeMap::<CoreVersion, Vec<CoreInstallation>>::new();
        for version_entry in self.io.directory_entries(&self.versions_root)? {
            require_direct_child(&version_entry)?;
            if version_entry.kind() != CoreUpdatePruneEntryKind::Directory
                || version_entry.mode() != VERSION_DIRECTORY_MODE
            {
                return Err(unsafe_prune_layout_error());
            }
            let version_text = component_text(version_entry.relative_path())?;
            let version = CoreVersion::parse(version_text)?;
            let version_root = self.versions_root.join(version.as_str());
            self.io
                .require_directory(&version_root, VERSION_DIRECTORY_MODE)?;
            let mut members = Vec::new();
            for identity_entry in self.io.directory_entries(&version_root)? {
                require_direct_child(&identity_entry)?;
                if identity_entry.kind() != CoreUpdatePruneEntryKind::Directory
                    || identity_entry.mode() != IMMUTABLE_DIRECTORY_MODE
                {
                    return Err(unsafe_prune_layout_error());
                }
                let identity = parse_digest(component_text(identity_entry.relative_path())?)?;
                let installation = CoreInstallation::new(version.clone(), identity);
                let path = self.installation_path(&installation);
                verify_core_native_tree(
                    self.artifacts.as_ref(),
                    &path,
                    IMMUTABLE_DIRECTORY_MODE,
                    &installation,
                )?;
                observed.insert(installation.clone(), path);
                members.push(installation);
            }
            members.sort();
            version_members.insert(version, members);
        }

        let mut retained = references
            .core_installations()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        retained.insert(active.clone());
        for installation in &retained {
            if !observed.contains_key(installation) {
                return Err(prune_io_error(
                    "referenced Core installation is unavailable",
                ));
            }
        }

        let core_installations = observed
            .keys()
            .filter(|installation| !retained.contains(*installation))
            .cloned()
            .collect::<Vec<_>>();
        let removable = core_installations.iter().collect::<BTreeSet<_>>();
        let version_roots = version_members
            .into_iter()
            .filter_map(|(version, members)| {
                (members.is_empty() || members.iter().all(|member| removable.contains(member)))
                    .then_some(version)
            })
            .collect::<Vec<_>>();
        Ok((core_installations, version_roots))
    }

    // Selects only safe unreferenced update workspaces under the fixed staging root.
    fn inspect_update_workspaces(
        &self,
        references: &CoreUpdatePruneReferences,
    ) -> Result<Vec<Sha256Digest>, CoreUpdateError> {
        match self.io.path_kind(&self.staging_root)? {
            CoreUpdatePathKind::Missing => return Ok(Vec::new()),
            CoreUpdatePathKind::Directory => {}
            _ => return Err(unsafe_prune_layout_error()),
        }
        self.io
            .require_directory(&self.staging_root, PRIVATE_DIRECTORY_MODE)?;
        let retained = references
            .update_workspaces()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut removable = Vec::new();
        for entry in self.io.directory_entries(&self.staging_root)? {
            require_direct_child(&entry)?;
            if entry.kind() != CoreUpdatePruneEntryKind::Directory
                || entry.mode() != PRIVATE_DIRECTORY_MODE
            {
                return Err(unsafe_prune_layout_error());
            }
            let identity = parse_digest(component_text(entry.relative_path())?)?;
            self.verify_safe_workspace(&self.staging_root.join(identity.as_str()))?;
            if !retained.contains(&identity) {
                removable.push(identity);
            }
        }
        removable.sort();
        Ok(removable)
    }

    // Requires one transient workspace to remain owner-bound and link-free.
    fn verify_safe_workspace(&self, root: &Path) -> Result<(), CoreUpdateError> {
        self.io.require_directory(root, PRIVATE_DIRECTORY_MODE)?;
        for entry in
            self.io
                .inventory(root, MAXIMUM_PRUNE_TREE_ENTRIES, MAXIMUM_PRUNE_TREE_BYTES)?
        {
            match entry.kind() {
                CoreUpdatePruneEntryKind::Directory
                    if matches!(
                        entry.mode(),
                        PRIVATE_DIRECTORY_MODE | IMMUTABLE_DIRECTORY_MODE
                    ) => {}
                CoreUpdatePruneEntryKind::RegularFile
                    if matches!(
                        entry.mode(),
                        0o600
                            | PRIVATE_FILE_MODE
                            | PRIVATE_EXECUTABLE_MODE
                            | IMMUTABLE_FILE_MODE
                            | IMMUTABLE_EXECUTABLE_MODE
                    ) && entry.sha256().is_some() => {}
                _ => return Err(unsafe_prune_layout_error()),
            }
        }
        Ok(())
    }
}

impl CoreUpdatePruneProvider for ReferenceAwareCoreUpdatePruneProvider {
    // Removes only verified identities absent from the injected live reference snapshot.
    fn prune(
        &self,
        update_id: &Sha256Digest,
        active: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        self.prune_with_receipt(update_id, active, false)
            .map(|_| ())
    }
}

// Creates one completed or dry-run receipt from the exact plan lists.
fn prune_receipt(
    plan: &CoreUpdatePrunePlan,
    dry_run: bool,
    removed: bool,
) -> Result<CoreUpdatePruneReceipt, CoreUpdateError> {
    let core_installations = removed
        .then(|| plan.core_installations.clone())
        .unwrap_or_default();
    let update_workspaces = removed
        .then(|| plan.update_workspaces.clone())
        .unwrap_or_default();
    let version_roots = removed
        .then(|| plan.version_roots.clone())
        .unwrap_or_default();
    let receipt_id = prune_receipt_identity(
        plan,
        dry_run,
        &core_installations,
        &update_workspaces,
        &version_roots,
    )?;
    Ok(CoreUpdatePruneReceipt {
        receipt_id,
        plan_id: plan.plan_id.clone(),
        dry_run,
        removed_core_installations: core_installations,
        removed_update_workspaces: update_workspaces,
        removed_version_roots: version_roots,
    })
}

// Derives one deterministic plan identity from references and exact removal lists.
fn prune_plan_identity(
    update_id: &Sha256Digest,
    active: &CoreInstallation,
    references: &CoreUpdatePruneReferences,
    core_installations: &[CoreInstallation],
    update_workspaces: &[Sha256Digest],
    version_roots: &[CoreVersion],
) -> Result<Sha256Digest, CoreUpdateError> {
    let mut fields = vec![
        update_id.as_str().to_string(),
        active.version().as_str().to_string(),
        active.source_identity().as_str().to_string(),
    ];
    append_installations(
        &mut fields,
        "reference_core",
        references.core_installations(),
    );
    append_digests(
        &mut fields,
        "reference_workspace",
        references.update_workspaces(),
    );
    append_installations(&mut fields, "remove_core", core_installations);
    append_digests(&mut fields, "remove_workspace", update_workspaces);
    fields.extend(
        version_roots
            .iter()
            .map(|version| format!("remove_version:{}", version.as_str())),
    );
    domain_digest("li_core_update_prune_plan_v1", &fields)
}

// Derives one deterministic receipt identity from the exact observed outcome.
fn prune_receipt_identity(
    plan: &CoreUpdatePrunePlan,
    dry_run: bool,
    core_installations: &[CoreInstallation],
    update_workspaces: &[Sha256Digest],
    version_roots: &[CoreVersion],
) -> Result<Sha256Digest, CoreUpdateError> {
    let mut fields = vec![
        plan.plan_id.as_str().to_string(),
        if dry_run { "dry_run" } else { "applied" }.to_string(),
    ];
    append_installations(&mut fields, "removed_core", core_installations);
    append_digests(&mut fields, "removed_workspace", update_workspaces);
    fields.extend(
        version_roots
            .iter()
            .map(|version| format!("removed_version:{}", version.as_str())),
    );
    domain_digest("li_core_update_prune_receipt_v1", &fields)
}

// Appends canonical installation identities with one explicit collection label.
fn append_installations(fields: &mut Vec<String>, label: &str, installations: &[CoreInstallation]) {
    fields.extend(installations.iter().map(|installation| {
        format!(
            "{label}:{}:{}",
            installation.version().as_str(),
            installation.source_identity().as_str()
        )
    }));
}

// Appends canonical SHA-256 identities with one explicit collection label.
fn append_digests(fields: &mut Vec<String>, label: &str, identities: &[Sha256Digest]) {
    fields.extend(
        identities
            .iter()
            .map(|identity| format!("{label}:{}", identity.as_str())),
    );
}

// Hashes length-prefixed fields into one domain-separated deterministic identity.
fn domain_digest(domain: &str, fields: &[String]) -> Result<Sha256Digest, CoreUpdateError> {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain.as_bytes());
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    parse_digest(&format!("{:x}", digest.finalize()))
}

// Parses one canonical digest while preserving prune-specific failure language.
fn parse_digest(value: &str) -> Result<Sha256Digest, CoreUpdateError> {
    Sha256Digest::parse(value).map_err(|_| unsafe_prune_layout_error())
}

// Requires one direct child entry with no nested or special path components.
fn require_direct_child(entry: &CoreUpdatePruneEntry) -> Result<(), CoreUpdateError> {
    if entry.relative_path().components().count() != 1 {
        return Err(unsafe_prune_layout_error());
    }
    require_relative_path(entry.relative_path())
}

// Returns UTF-8 text from one exact normal relative path component.
fn component_text(path: &Path) -> Result<&str, CoreUpdateError> {
    match path.components().next() {
        Some(Component::Normal(value)) if path.components().count() == 1 => {
            value.to_str().ok_or_else(unsafe_prune_layout_error)
        }
        _ => Err(unsafe_prune_layout_error()),
    }
}

// Requires one nonempty relative path containing only normal components.
fn require_relative_path(path: &Path) -> Result<(), CoreUpdateError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(unsafe_prune_layout_error());
    }
    Ok(())
}

// Requires one metadata snapshot to be an owner-bound directory of an exact mode.
fn require_owned_directory(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    mode: u32,
) -> Result<(), CoreUpdateError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o7777 != mode
    {
        return Err(unsafe_prune_layout_error());
    }
    Ok(())
}

// Persists one exact owner-bound directory through a no-follow descriptor.
fn sync_owned_directory(path: &Path, owner_user_id: u32, mode: u32) -> Result<(), CoreUpdateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| prune_io_error("prune persistence is unavailable"))?;
    require_owned_directory(&metadata, owner_user_id, mode)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| prune_io_error("prune persistence is unavailable"))?;
    directory
        .sync_all()
        .map_err(|_| prune_io_error("prune persistence is unavailable"))
}

// Creates one stable redacted failure for an exact prune boundary.
fn prune_io_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("prune", reason)
}

// Creates one stable fail-closed layout error without exposing host paths.
fn unsafe_prune_layout_error() -> CoreUpdateError {
    CoreUpdateError::provider("prune", "Core prune layout is unsafe")
}
