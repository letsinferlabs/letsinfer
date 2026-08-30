// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::Sha256Digest;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    ActivatedCoreUpdate, CoreInstallation, CoreUpdateArtifactProvider, CoreUpdateError,
    CoreVersion, PreparedCoreUpdate,
};

pub(crate) const CORE_RELEASE_MANIFEST_NAME: &str = "li_core_release_manifest_v1.json";
pub(crate) const CORE_RELEASE_MANIFEST_SCHEMA_NAME: &str = "li_core_release_manifest";
pub(crate) const CORE_RELEASE_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAXIMUM_CORE_RELEASE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAXIMUM_CORE_RELEASE_FILES: usize = 6;
pub(crate) const MAXIMUM_CORE_RELEASE_BYTES: u64 = 1024 * 1024 * 1024;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const VERSION_DIRECTORY_MODE: u32 = 0o755;
const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
const IMMUTABLE_FILE_MODE: u32 = 0o444;
const IMMUTABLE_EXECUTABLE_MODE: u32 = 0o555;

// Describes one final path type without following a symlink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdatePathKind {
    Missing,
    Directory,
    RegularFile,
    Symlink,
    Other,
}

// Describes one no-follow entry returned from an immutable Core inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdateArtifactEntryKind {
    Directory,
    RegularFile,
}

// Carries one exact immutable native-tree entry through provider validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateArtifactEntry {
    relative_path: PathBuf,
    kind: CoreUpdateArtifactEntryKind,
    mode: u32,
    bytes: u64,
    sha256: Option<Sha256Digest>,
}

impl CoreUpdateArtifactEntry {
    // Creates one no-follow directory inventory entry.
    pub fn directory(relative_path: PathBuf, mode: u32) -> Result<Self, CoreUpdateError> {
        require_relative_path(&relative_path)?;
        Ok(Self {
            relative_path,
            kind: CoreUpdateArtifactEntryKind::Directory,
            mode,
            bytes: 0,
            sha256: None,
        })
    }

    // Creates one no-follow regular-file inventory entry.
    pub fn regular_file(
        relative_path: PathBuf,
        mode: u32,
        bytes: u64,
        sha256: Sha256Digest,
    ) -> Result<Self, CoreUpdateError> {
        require_relative_path(&relative_path)?;
        Ok(Self {
            relative_path,
            kind: CoreUpdateArtifactEntryKind::RegularFile,
            mode,
            bytes,
            sha256: Some(sha256),
        })
    }

    // Returns the contained path relative to its immutable native root.
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    // Returns whether this entry is a directory or regular file.
    pub const fn kind(&self) -> CoreUpdateArtifactEntryKind {
        self.kind
    }

    // Returns the exact Unix permission bits observed without following links.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    // Returns the exact regular-file byte count or zero for a directory.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    // Returns the exact regular-file digest when this entry is a file.
    pub const fn sha256(&self) -> Option<&Sha256Digest> {
        self.sha256.as_ref()
    }
}

// Supplies every native filesystem operation required by immutable Core handoff.
pub trait CoreUpdateArtifactIo: Send + Sync {
    // Returns one final path type without following a symlink.
    fn path_kind(&self, path: &Path) -> Result<CoreUpdatePathKind, CoreUpdateError>;

    // Requires one owner-bound no-follow directory with an exact mode.
    fn require_directory(&self, path: &Path, mode: u32) -> Result<(), CoreUpdateError>;

    // Reads one symlink target without resolving or normalizing it.
    fn read_symlink(&self, path: &Path) -> Result<PathBuf, CoreUpdateError>;

    // Reads one bounded owner-bound regular file through a no-follow descriptor.
    fn read_regular_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CoreUpdateError>;

    // Inventories one immutable tree without following any contained symlink.
    fn inventory(&self, root: &Path) -> Result<Vec<CoreUpdateArtifactEntry>, CoreUpdateError>;

    // Creates or validates one exact private update workspace.
    fn prepare_workspace(&self, path: &Path) -> Result<(), CoreUpdateError>;

    // Creates or validates one exact public-read immutable version directory.
    fn prepare_version_directory(&self, path: &Path) -> Result<(), CoreUpdateError>;

    // Atomically installs one staged immutable tree when its destination is absent.
    fn install_immutable_tree(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<(), CoreUpdateError>;

    // Atomically replaces one exact managed symlink or leaves the expected target unchanged.
    fn replace_symlink(
        &self,
        link: &Path,
        expected: &Path,
        destination: &Path,
        temporary: &Path,
    ) -> Result<(), CoreUpdateError>;

    // Persists one directory after the verified handoff reaches commit.
    fn sync_directory(&self, path: &Path) -> Result<(), CoreUpdateError>;

    // Removes one exact private workspace without following contained symlinks.
    fn remove_workspace(&self, path: &Path) -> Result<(), CoreUpdateError>;
}

// Carries the provider-owned destination and exact release request to one installer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateCandidateRequest {
    update_id: Sha256Digest,
    requested_version: Option<CoreVersion>,
    current: CoreInstallation,
    workspace: PathBuf,
    release_root: PathBuf,
}

impl CoreUpdateCandidateRequest {
    // Returns the stable update identity used for native installer replay.
    pub const fn update_id(&self) -> &Sha256Digest {
        &self.update_id
    }

    // Returns the exact requested version or absence for latest-compatible resolution.
    pub const fn requested_version(&self) -> Option<&CoreVersion> {
        self.requested_version.as_ref()
    }

    // Returns the exact active installation observed before preparation.
    pub const fn current(&self) -> &CoreInstallation {
        &self.current
    }

    // Returns the private workspace owned only by this update identity.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    // Returns the exact native release root that the installer must materialize and verify.
    pub fn release_root(&self) -> &Path {
        &self.release_root
    }
}

// Materializes one signed and verified candidate into a provider-owned workspace.
pub trait CoreUpdateCandidateInstaller: Send + Sync {
    // Resolves and prepares one candidate idempotently without moving the active pointer.
    fn prepare(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<CoreInstallation, CoreUpdateError>;
}

// Implements owner-bound no-follow Core artifact operations on a Unix filesystem.
pub struct FilesystemCoreUpdateArtifactIo {
    owner_user_id: u32,
}

impl FilesystemCoreUpdateArtifactIo {
    // Creates one filesystem capability bound to the installing user's exact identity.
    pub const fn new(owner_user_id: u32) -> Self {
        Self { owner_user_id }
    }
}

impl CoreUpdateArtifactIo for FilesystemCoreUpdateArtifactIo {
    // Returns one final path type without following a symlink.
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
            Err(_) => Err(artifact_io_error("path inspection is unavailable")),
        }
    }

    // Requires one owner-bound no-follow directory with an exact mode.
    fn require_directory(&self, path: &Path, mode: u32) -> Result<(), CoreUpdateError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| artifact_io_error("directory inspection is unavailable"))?;
        require_owned_directory(&metadata, self.owner_user_id, mode)
    }

    // Reads one symlink target without resolving or normalizing it.
    fn read_symlink(&self, path: &Path) -> Result<PathBuf, CoreUpdateError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| artifact_io_error("active pointer inspection is unavailable"))?;
        if !metadata.file_type().is_symlink() || metadata.uid() != self.owner_user_id {
            return Err(unsafe_layout_error());
        }
        fs::read_link(path)
            .map_err(|_| artifact_io_error("active pointer inspection is unavailable"))
    }

    // Reads one bounded owner-bound regular file through a no-follow descriptor.
    fn read_regular_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CoreUpdateError> {
        let mut file = open_owned_regular_file(path, self.owner_user_id, maximum_bytes)?;
        let expected_bytes = file
            .metadata()
            .map_err(|_| artifact_io_error("native file inspection is unavailable"))?
            .len();
        let mut bytes = Vec::with_capacity(
            usize::try_from(expected_bytes)
                .map_err(|_| artifact_io_error("native file exceeds its boundary"))?,
        );
        file.read_to_end(&mut bytes)
            .map_err(|_| artifact_io_error("native file reading is unavailable"))?;
        if bytes.len() as u64 != expected_bytes {
            return Err(artifact_io_error("native file changed while being read"));
        }
        Ok(bytes)
    }

    // Inventories one immutable tree without following any contained symlink.
    fn inventory(&self, root: &Path) -> Result<Vec<CoreUpdateArtifactEntry>, CoreUpdateError> {
        let root_metadata = fs::symlink_metadata(root)
            .map_err(|_| artifact_io_error("source inventory is unavailable"))?;
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || root_metadata.uid() != self.owner_user_id
            || !matches!(
                root_metadata.mode() & 0o777,
                PRIVATE_DIRECTORY_MODE | IMMUTABLE_DIRECTORY_MODE
            )
        {
            return Err(unsafe_layout_error());
        }
        let mut pending = vec![root.to_path_buf()];
        let mut entries = Vec::new();
        let mut file_count = 0_usize;
        let mut total_bytes = 0_u64;
        while let Some(directory) = pending.pop() {
            let mut children = fs::read_dir(&directory)
                .map_err(|_| artifact_io_error("source inventory is unavailable"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| artifact_io_error("source inventory is unavailable"))?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let path = child.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| unsafe_layout_error())?
                    .to_path_buf();
                require_relative_path(&relative)?;
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|_| artifact_io_error("source inventory is unavailable"))?;
                if metadata.uid() != self.owner_user_id || metadata.file_type().is_symlink() {
                    return Err(unsafe_layout_error());
                }
                let mode = metadata.mode() & 0o777;
                if metadata.is_dir() {
                    if mode != IMMUTABLE_DIRECTORY_MODE {
                        return Err(unsafe_layout_error());
                    }
                    entries.push(CoreUpdateArtifactEntry::directory(relative, mode)?);
                    pending.push(path);
                } else if metadata.is_file() {
                    file_count = file_count.checked_add(1).ok_or_else(unsafe_layout_error)?;
                    total_bytes = total_bytes
                        .checked_add(metadata.len())
                        .ok_or_else(unsafe_layout_error)?;
                    if total_bytes
                        > MAXIMUM_CORE_RELEASE_BYTES + MAXIMUM_CORE_RELEASE_MANIFEST_BYTES
                        || file_count > MAXIMUM_CORE_RELEASE_FILES + 1
                    {
                        return Err(artifact_io_error("source inventory exceeds its boundary"));
                    }
                    let digest = hash_owned_regular_file(
                        &path,
                        self.owner_user_id,
                        MAXIMUM_CORE_RELEASE_BYTES,
                    )?;
                    entries.push(CoreUpdateArtifactEntry::regular_file(
                        relative,
                        mode,
                        metadata.len(),
                        digest,
                    )?);
                } else {
                    return Err(unsafe_layout_error());
                }
            }
        }
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(entries)
    }

    // Creates or validates one exact private update workspace.
    fn prepare_workspace(&self, path: &Path) -> Result<(), CoreUpdateError> {
        let parent = path.parent().ok_or_else(unsafe_layout_error)?;
        prepare_owned_directory(parent, self.owner_user_id)?;
        prepare_owned_directory(path, self.owner_user_id)
    }

    // Creates or validates one exact public-read immutable version directory.
    fn prepare_version_directory(&self, path: &Path) -> Result<(), CoreUpdateError> {
        let parent = path.parent().ok_or_else(unsafe_layout_error)?;
        self.require_directory(parent, VERSION_DIRECTORY_MODE)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                require_owned_directory(&metadata, self.owner_user_id, VERSION_DIRECTORY_MODE)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| {
                    artifact_io_error("Core version directory creation is unavailable")
                })?;
                if fs::set_permissions(path, fs::Permissions::from_mode(VERSION_DIRECTORY_MODE))
                    .is_err()
                {
                    let _ = fs::remove_dir(path);
                    return Err(artifact_io_error(
                        "Core version directory protection is unavailable",
                    ));
                }
                let metadata = fs::symlink_metadata(path).map_err(|_| {
                    artifact_io_error("Core version directory inspection is unavailable")
                })?;
                if let Err(error) =
                    require_owned_directory(&metadata, self.owner_user_id, VERSION_DIRECTORY_MODE)
                {
                    let _ = fs::remove_dir(path);
                    return Err(error);
                }
                Ok(())
            }
            Err(_) => Err(artifact_io_error(
                "Core version directory inspection is unavailable",
            )),
        }
    }

    // Atomically installs one staged immutable tree when its destination is absent.
    fn install_immutable_tree(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<(), CoreUpdateError> {
        self.require_directory(source, PRIVATE_DIRECTORY_MODE)?;
        let parent = destination.parent().ok_or_else(unsafe_layout_error)?;
        self.require_directory(parent, VERSION_DIRECTORY_MODE)?;
        match self.path_kind(destination)? {
            CoreUpdatePathKind::Missing => {}
            CoreUpdatePathKind::Directory => return Ok(()),
            _ => return Err(unsafe_layout_error()),
        }
        fs::rename(source, destination)
            .map_err(|_| artifact_io_error("immutable Core installation is unavailable"))?;
        if fs::set_permissions(
            destination,
            fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE),
        )
        .is_err()
        {
            let _ = fs::rename(destination, source);
            return Err(artifact_io_error(
                "immutable Core protection is unavailable",
            ));
        }
        sync_owned_directory(parent, self.owner_user_id, VERSION_DIRECTORY_MODE)
    }

    // Atomically replaces one exact managed symlink after checking its old target.
    fn replace_symlink(
        &self,
        link: &Path,
        expected: &Path,
        destination: &Path,
        temporary: &Path,
    ) -> Result<(), CoreUpdateError> {
        let parent = link.parent().ok_or_else(unsafe_layout_error)?;
        self.require_directory(parent, PRIVATE_DIRECTORY_MODE)?;
        if temporary.parent() != Some(parent) || temporary == link {
            return Err(unsafe_layout_error());
        }
        let observed = self.read_symlink(link)?;
        if observed == destination {
            return Ok(());
        }
        if observed != expected {
            return Err(artifact_io_error("active Core changed concurrently"));
        }
        match self.path_kind(temporary)? {
            CoreUpdatePathKind::Missing => {}
            CoreUpdatePathKind::Symlink => {
                if self.read_symlink(temporary)? != destination {
                    return Err(unsafe_layout_error());
                }
                fs::remove_file(temporary)
                    .map_err(|_| artifact_io_error("active pointer staging is unavailable"))?;
            }
            _ => return Err(unsafe_layout_error()),
        }
        symlink(destination, temporary)
            .map_err(|_| artifact_io_error("active pointer staging is unavailable"))?;
        sync_owned_directory(parent, self.owner_user_id, PRIVATE_DIRECTORY_MODE)?;
        fs::rename(temporary, link)
            .map_err(|_| artifact_io_error("active pointer activation is unavailable"))
    }

    // Persists one directory after the verified handoff reaches commit.
    fn sync_directory(&self, path: &Path) -> Result<(), CoreUpdateError> {
        sync_owned_directory(path, self.owner_user_id, PRIVATE_DIRECTORY_MODE)
    }

    // Removes one exact private workspace without following contained symlinks.
    fn remove_workspace(&self, path: &Path) -> Result<(), CoreUpdateError> {
        match self.path_kind(path)? {
            CoreUpdatePathKind::Missing => {
                let parent = path.parent().ok_or_else(unsafe_layout_error)?;
                return match self.path_kind(parent)? {
                    CoreUpdatePathKind::Missing => Ok(()),
                    CoreUpdatePathKind::Directory => {
                        sync_owned_directory(parent, self.owner_user_id, PRIVATE_DIRECTORY_MODE)
                    }
                    _ => Err(unsafe_layout_error()),
                };
            }
            CoreUpdatePathKind::Directory => {}
            _ => return Err(unsafe_layout_error()),
        }
        self.require_directory(path, PRIVATE_DIRECTORY_MODE)?;
        make_owned_tree_writable(path, self.owner_user_id)?;
        fs::remove_dir_all(path)
            .map_err(|_| artifact_io_error("Core update workspace cleanup is unavailable"))?;
        let parent = path.parent().ok_or_else(unsafe_layout_error)?;
        sync_owned_directory(parent, self.owner_user_id, PRIVATE_DIRECTORY_MODE)
    }
}

// Owns immutable Core layout verification, candidate staging, and active-pointer handoff.
pub struct FilesystemCoreUpdateArtifactProvider {
    letsinfer_home: PathBuf,
    core_root: PathBuf,
    versions_root: PathBuf,
    staging_root: PathBuf,
    current_link: PathBuf,
    io: Arc<dyn CoreUpdateArtifactIo>,
    installer: Arc<dyn CoreUpdateCandidateInstaller>,
}

impl FilesystemCoreUpdateArtifactProvider {
    // Creates one provider rooted at a canonical absolute LETSINFER_HOME.
    pub fn new(
        letsinfer_home: PathBuf,
        io: Arc<dyn CoreUpdateArtifactIo>,
        installer: Arc<dyn CoreUpdateCandidateInstaller>,
    ) -> Result<Self, CoreUpdateError> {
        require_absolute_normal_path(&letsinfer_home)?;
        if letsinfer_home.parent().is_none() {
            return Err(unsafe_layout_error());
        }
        let core_root = letsinfer_home.join("core");
        Ok(Self {
            versions_root: core_root.join("versions"),
            staging_root: core_root.join("staging"),
            current_link: core_root.join("current"),
            letsinfer_home,
            core_root,
            io,
            installer,
        })
    }

    // Requires fixed private roots before reading or mutating an installed Core.
    fn require_layout_roots(&self) -> Result<(), CoreUpdateError> {
        self.io
            .require_directory(&self.letsinfer_home, PRIVATE_DIRECTORY_MODE)?;
        self.io
            .require_directory(&self.core_root, PRIVATE_DIRECTORY_MODE)?;
        self.io
            .require_directory(&self.versions_root, VERSION_DIRECTORY_MODE)
    }

    // Returns and validates the exact immutable installation behind the current pointer.
    fn active_installation(&self) -> Result<CoreInstallation, CoreUpdateError> {
        self.require_layout_roots()?;
        let target = self.io.read_symlink(&self.current_link)?;
        let installation = self.installation_from_path(&target)?;
        self.verify_installation(&target, &installation)?;
        Ok(installation)
    }

    // Reconstructs one installation identity only from its exact managed path shape.
    fn installation_from_path(&self, path: &Path) -> Result<CoreInstallation, CoreUpdateError> {
        require_absolute_normal_path(path)?;
        let relative = path
            .strip_prefix(&self.versions_root)
            .map_err(|_| unsafe_layout_error())?;
        let components = relative.components().collect::<Vec<_>>();
        if components.len() != 2 {
            return Err(unsafe_layout_error());
        }
        let version_text = normal_component_text(components[0])?;
        let identity_text = normal_component_text(components[1])?;
        let version = CoreVersion::parse(version_text)?;
        let source_identity =
            Sha256Digest::parse(identity_text).map_err(|_| unsafe_layout_error())?;
        if self.installation_path(&CoreInstallation::new(
            version.clone(),
            source_identity.clone(),
        )) != path
        {
            return Err(unsafe_layout_error());
        }
        Ok(CoreInstallation::new(version, source_identity))
    }

    // Returns one content-addressed immutable installation path.
    fn installation_path(&self, installation: &CoreInstallation) -> PathBuf {
        self.versions_root
            .join(installation.version().as_str())
            .join(installation.source_identity().as_str())
    }

    // Returns one exact provider-owned workspace for the update identity.
    fn workspace_path(&self, update_id: &Sha256Digest) -> PathBuf {
        self.staging_root.join(update_id.as_str())
    }

    // Returns one exact staged source path that the installer may populate.
    fn staged_release_path(&self, update_id: &Sha256Digest) -> PathBuf {
        self.workspace_path(update_id).join("release")
    }

    // Returns one collision-free same-directory temporary pointer path.
    fn pointer_temporary_path(&self, update_id: &Sha256Digest) -> PathBuf {
        self.core_root.join(format!(
            ".current.li_core_update_{}.tmp",
            update_id.as_str()
        ))
    }

    // Verifies one complete immutable native tree against its manifest and path identity.
    fn verify_installation(
        &self,
        root: &Path,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        if root == self.installation_path(installation) {
            let version_root = root.parent().ok_or_else(unsafe_layout_error)?;
            self.io
                .require_directory(version_root, VERSION_DIRECTORY_MODE)?;
        } else if !root.starts_with(&self.staging_root) {
            return Err(unsafe_layout_error());
        }
        let root_mode = if root == self.installation_path(installation) {
            IMMUTABLE_DIRECTORY_MODE
        } else {
            PRIVATE_DIRECTORY_MODE
        };
        verify_core_native_tree(self.io.as_ref(), root, root_mode, installation)
    }

    // Requires a prepared receipt to belong to this update and staged installation.
    fn require_prepared_receipt(
        &self,
        update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        let expected = prepared_receipt_id(update_id, prepared.installation())?;
        if prepared.receipt_id() != &expected {
            return Err(CoreUpdateError::InvalidContract {
                reason: "prepared Core receipt does not match its update identity",
            });
        }
        Ok(())
    }

    // Requires an activation receipt to belong to this update and exact handoff.
    fn require_activation_receipt(
        &self,
        update_id: &Sha256Digest,
        activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        let expected =
            activation_receipt_id(update_id, activation.previous(), activation.installation())?;
        if activation.receipt_id() != &expected {
            return Err(CoreUpdateError::InvalidContract {
                reason: "activated Core receipt does not match its update identity",
            });
        }
        Ok(())
    }

    // Validates the staged source when present or its installed destination after replay.
    fn require_candidate_material(
        &self,
        update_id: &Sha256Digest,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        let staged = self.staged_release_path(update_id);
        match self.io.path_kind(&staged)? {
            CoreUpdatePathKind::Directory => self.verify_installation(&staged, installation),
            CoreUpdatePathKind::Missing => {
                let destination = self.installation_path(installation);
                self.verify_installation(&destination, installation)
            }
            _ => Err(unsafe_layout_error()),
        }
    }

    // Removes only this update's exact workspace after validating any remaining source.
    fn discard_workspace(
        &self,
        update_id: &Sha256Digest,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        let workspace = self.workspace_path(update_id);
        match self.io.path_kind(&workspace)? {
            CoreUpdatePathKind::Missing => self.io.remove_workspace(&workspace),
            CoreUpdatePathKind::Directory => {
                let staged = self.staged_release_path(update_id);
                match self.io.path_kind(&staged)? {
                    CoreUpdatePathKind::Missing => {}
                    CoreUpdatePathKind::Directory => {
                        self.verify_installation(&staged, installation)?;
                    }
                    _ => return Err(unsafe_layout_error()),
                }
                self.io.remove_workspace(&workspace)
            }
            _ => Err(unsafe_layout_error()),
        }
    }

    // Removes a failed preparation workspace without widening cleanup beyond its update ID.
    fn cleanup_failed_preparation(&self, update_id: &Sha256Digest) {
        let workspace = self.workspace_path(update_id);
        let _ = self.io.remove_workspace(&workspace);
    }
}

impl CoreUpdateArtifactProvider for FilesystemCoreUpdateArtifactProvider {
    // Returns the exact active immutable Core installation.
    fn current(&self, _update_id: &Sha256Digest) -> Result<CoreInstallation, CoreUpdateError> {
        self.active_installation()
    }

    // Acquires and verifies one requested or latest compatible release idempotently.
    fn prepare(
        &self,
        update_id: &Sha256Digest,
        requested_version: Option<&CoreVersion>,
        current: &CoreInstallation,
    ) -> Result<PreparedCoreUpdate, CoreUpdateError> {
        if &self.active_installation()? != current {
            return Err(artifact_io_error("active Core changed before preparation"));
        }
        let workspace = self.workspace_path(update_id);
        if let Err(error) = self.io.prepare_workspace(&workspace) {
            self.cleanup_failed_preparation(update_id);
            return Err(error);
        }
        let request = CoreUpdateCandidateRequest {
            update_id: update_id.clone(),
            requested_version: requested_version.cloned(),
            current: current.clone(),
            release_root: self.staged_release_path(update_id),
            workspace,
        };
        let installation = match self.installer.prepare(&request) {
            Ok(installation) => installation,
            Err(error) => {
                self.cleanup_failed_preparation(update_id);
                return Err(error);
            }
        };
        if requested_version.is_some_and(|version| version != installation.version()) {
            self.cleanup_failed_preparation(update_id);
            return Err(CoreUpdateError::InvalidContract {
                reason: "native installer returned a different requested Core version",
            });
        }
        if let Err(error) = self.verify_installation(request.release_root(), &installation) {
            self.cleanup_failed_preparation(update_id);
            return Err(error);
        }
        Ok(PreparedCoreUpdate::new(
            prepared_receipt_id(update_id, &installation)?,
            installation,
        ))
    }

    // Discards only the exact prepared workspace after pre-activation failure or no-op.
    fn discard(
        &self,
        update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        self.require_prepared_receipt(update_id, prepared)?;
        self.discard_workspace(update_id, prepared.installation())
    }

    // Moves the immutable active pointer and returns one reversible receipt.
    fn activate(
        &self,
        update_id: &Sha256Digest,
        prepared: &PreparedCoreUpdate,
        current: &CoreInstallation,
    ) -> Result<ActivatedCoreUpdate, CoreUpdateError> {
        self.require_layout_roots()?;
        self.require_prepared_receipt(update_id, prepared)?;
        if prepared.installation() == current {
            return Err(CoreUpdateError::InvalidContract {
                reason: "Core activation cannot replace an installation with itself",
            });
        }
        self.verify_installation(&self.installation_path(current), current)?;
        self.require_candidate_material(update_id, prepared.installation())?;
        let source = self.staged_release_path(update_id);
        let destination = self.installation_path(prepared.installation());
        let version_root = destination.parent().ok_or_else(unsafe_layout_error)?;
        self.io.prepare_version_directory(version_root)?;
        match self.io.path_kind(&destination)? {
            CoreUpdatePathKind::Missing => {
                if self.io.path_kind(&source)? != CoreUpdatePathKind::Directory {
                    return Err(unsafe_layout_error());
                }
                self.io.install_immutable_tree(&source, &destination)?;
            }
            CoreUpdatePathKind::Directory => {}
            _ => return Err(unsafe_layout_error()),
        }
        self.verify_installation(&destination, prepared.installation())?;
        let active = self.active_installation()?;
        if &active == current {
            self.io.replace_symlink(
                &self.current_link,
                &self.installation_path(current),
                &destination,
                &self.pointer_temporary_path(update_id),
            )?;
        } else if &active != prepared.installation() {
            return Err(artifact_io_error("active Core changed concurrently"));
        }
        ActivatedCoreUpdate::new(
            activation_receipt_id(update_id, current, prepared.installation())?,
            current.clone(),
            prepared.installation().clone(),
        )
    }

    // Restores the previous active pointer and removes only this candidate's staging state.
    fn rollback(
        &self,
        update_id: &Sha256Digest,
        activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        self.require_layout_roots()?;
        self.require_activation_receipt(update_id, activation)?;
        let previous_path = self.installation_path(activation.previous());
        let candidate_path = self.installation_path(activation.installation());
        self.verify_installation(&previous_path, activation.previous())?;
        self.verify_installation(&candidate_path, activation.installation())?;
        let active = self.active_installation()?;
        if &active == activation.installation() {
            self.io.replace_symlink(
                &self.current_link,
                &candidate_path,
                &previous_path,
                &self.pointer_temporary_path(update_id),
            )?;
        } else if &active != activation.previous() {
            return Err(artifact_io_error("active Core changed concurrently"));
        }
        self.io.sync_directory(&self.core_root)?;
        self.discard_workspace(update_id, activation.installation())
    }

    // Makes a verified active-pointer handoff non-reversible before pruning.
    fn commit(
        &self,
        update_id: &Sha256Digest,
        activation: &ActivatedCoreUpdate,
    ) -> Result<(), CoreUpdateError> {
        self.require_layout_roots()?;
        self.require_activation_receipt(update_id, activation)?;
        if self.active_installation()? != *activation.installation() {
            return Err(artifact_io_error("candidate Core is not active at commit"));
        }
        self.io.sync_directory(&self.core_root)?;
        self.discard_workspace(update_id, activation.installation())
    }
}

// Stores one normalized native release file before installed-mode projection.
pub(crate) struct CoreReleaseFileRecord {
    pub(crate) bytes: u64,
    pub(crate) release_mode: u32,
    pub(crate) sha256: Sha256Digest,
}

// Stores one validated native platform and its exact executable closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreReleasePlatformIdentity {
    LinuxArm64,
    LinuxX86_64,
    MacosArm64,
}

impl CoreReleasePlatformIdentity {
    // Parses one closed native platform identity without accepting aliases.
    pub(crate) fn parse(
        operating_system: &str,
        architecture: &str,
    ) -> Result<Self, CoreUpdateError> {
        match (operating_system, architecture) {
            ("linux", "arm64") => Ok(Self::LinuxArm64),
            ("linux", "x86_64") => Ok(Self::LinuxX86_64),
            ("macos", "arm64") => Ok(Self::MacosArm64),
            _ => Err(unsafe_layout_error()),
        }
    }

    // Returns the complete ordered native binary closure for this platform.
    fn file_paths(self) -> &'static [&'static str] {
        match self {
            Self::LinuxArm64 | Self::LinuxX86_64 => &[
                "bin/li_benchmark_worker",
                "bin/li_core_setup",
                "bin/li_gateway",
                "bin/li_letsinfer",
                "bin/li_node",
                "bin/li_watchdog",
            ],
            Self::MacosArm64 => &[
                "bin/li_benchmark_worker",
                "bin/li_core_setup",
                "bin/li_gateway",
                "bin/li_hardware_macos_probe",
                "bin/li_letsinfer",
                "bin/li_node",
            ],
        }
    }
}

// Stores one fully validated native Core release manifest.
pub(crate) struct CoreReleaseManifest {
    pub(crate) version: CoreVersion,
    pub(crate) platform: CoreReleasePlatformIdentity,
    pub(crate) files: BTreeMap<PathBuf, CoreReleaseFileRecord>,
}

// Decodes the closed published native Core release manifest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseManifestDocument {
    schema: CoreReleaseSchemaDocument,
    release: CoreReleaseIdentityDocument,
    platform: CoreReleasePlatformDocument,
    files: Vec<CoreReleaseFileDocument>,
}

// Decodes the nested native release schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseSchemaDocument {
    name: String,
    version: u32,
}

// Decodes the exact native Core release identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseIdentityDocument {
    version: String,
}

// Decodes the closed native target identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleasePlatformDocument {
    os: String,
    architecture: String,
}

// Decodes one native release file record before semantic validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseFileDocument {
    path: String,
    bytes: u64,
    mode: u32,
    sha256: String,
}

// Parses one closed native manifest and requires its exact release identity.
pub(crate) fn parse_core_release_manifest(
    bytes: &[u8],
) -> Result<CoreReleaseManifest, CoreUpdateError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| unsafe_layout_error())?;
    let mut canonical = serde_json::to_vec(&value).map_err(|_| unsafe_layout_error())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(unsafe_layout_error());
    }
    let document: CoreReleaseManifestDocument =
        serde_json::from_value(value).map_err(|_| unsafe_layout_error())?;
    if document.schema.name != CORE_RELEASE_MANIFEST_SCHEMA_NAME
        || document.schema.version != CORE_RELEASE_MANIFEST_SCHEMA_VERSION
    {
        return Err(unsafe_layout_error());
    }
    let version =
        CoreVersion::parse(&document.release.version).map_err(|_| unsafe_layout_error())?;
    let platform =
        CoreReleasePlatformIdentity::parse(&document.platform.os, &document.platform.architecture)?;
    let expected_paths = platform.file_paths();
    if document.files.len() != expected_paths.len()
        || document.files.len() > MAXIMUM_CORE_RELEASE_FILES
    {
        return Err(unsafe_layout_error());
    }
    let mut records = BTreeMap::new();
    let mut total_bytes = 0_u64;
    for (record, expected_path) in document.files.into_iter().zip(expected_paths) {
        if record.path != *expected_path {
            return Err(unsafe_layout_error());
        }
        let relative = PathBuf::from(record.path);
        require_relative_path(&relative)?;
        if relative == Path::new(CORE_RELEASE_MANIFEST_NAME)
            || records.contains_key(&relative)
            || record.bytes == 0
            || record.mode != 0o755
        {
            return Err(unsafe_layout_error());
        }
        total_bytes = total_bytes
            .checked_add(record.bytes)
            .ok_or_else(unsafe_layout_error)?;
        if total_bytes > MAXIMUM_CORE_RELEASE_BYTES {
            return Err(unsafe_layout_error());
        }
        let sha256 = Sha256Digest::parse(&record.sha256).map_err(|_| unsafe_layout_error())?;
        records.insert(
            relative,
            CoreReleaseFileRecord {
                bytes: record.bytes,
                release_mode: record.mode,
                sha256,
            },
        );
    }
    Ok(CoreReleaseManifest {
        version,
        platform,
        files: records,
    })
}

// Verifies one complete staged or immutable native Core tree and release identity.
pub(crate) fn verify_core_native_tree(
    io: &dyn CoreUpdateArtifactIo,
    root: &Path,
    root_mode: u32,
    installation: &CoreInstallation,
) -> Result<(), CoreUpdateError> {
    io.require_directory(root, root_mode)?;
    let manifest_path = root.join(CORE_RELEASE_MANIFEST_NAME);
    let manifest_bytes =
        io.read_regular_file(&manifest_path, MAXIMUM_CORE_RELEASE_MANIFEST_BYTES)?;
    let manifest_identity = digest_bytes(&manifest_bytes)?;
    if &manifest_identity != installation.source_identity() {
        return Err(unsafe_layout_error());
    }
    let manifest = parse_core_release_manifest(&manifest_bytes)?;
    if &manifest.version != installation.version() {
        return Err(unsafe_layout_error());
    }
    let observed = io.inventory(root)?;
    verify_core_release_inventory(
        &manifest.files,
        &observed,
        manifest_bytes.len() as u64,
        &manifest_identity,
    )
}

// Verifies exact native files, modes, sizes, hashes, and directory closure.
fn verify_core_release_inventory(
    expected: &BTreeMap<PathBuf, CoreReleaseFileRecord>,
    observed: &[CoreUpdateArtifactEntry],
    manifest_bytes: u64,
    manifest_sha256: &Sha256Digest,
) -> Result<(), CoreUpdateError> {
    let mut observed_files = BTreeMap::new();
    let mut observed_paths = BTreeSet::new();
    for entry in observed {
        require_relative_path(entry.relative_path())?;
        if !observed_paths.insert(entry.relative_path().to_path_buf()) {
            return Err(unsafe_layout_error());
        }
        match entry.kind() {
            CoreUpdateArtifactEntryKind::Directory => {
                if entry.mode() != IMMUTABLE_DIRECTORY_MODE
                    || entry.bytes() != 0
                    || entry.sha256().is_some()
                {
                    return Err(unsafe_layout_error());
                }
            }
            CoreUpdateArtifactEntryKind::RegularFile => {
                observed_files.insert(entry.relative_path().to_path_buf(), entry);
            }
        }
    }
    let manifest = observed_files
        .remove(Path::new(CORE_RELEASE_MANIFEST_NAME))
        .ok_or_else(unsafe_layout_error)?;
    if manifest.mode() != IMMUTABLE_FILE_MODE
        || manifest.bytes() != manifest_bytes
        || manifest.sha256() != Some(manifest_sha256)
    {
        return Err(unsafe_layout_error());
    }
    if observed_files.len() != expected.len()
        || observed_paths
            != expected
                .keys()
                .flat_map(|path| [PathBuf::from("bin"), path.clone()])
                .chain(std::iter::once(PathBuf::from(CORE_RELEASE_MANIFEST_NAME)))
                .collect::<BTreeSet<_>>()
    {
        return Err(unsafe_layout_error());
    }
    for (path, record) in expected {
        let observed = observed_files.get(path).ok_or_else(unsafe_layout_error)?;
        let expected_mode = if record.release_mode & 0o111 == 0 {
            IMMUTABLE_FILE_MODE
        } else {
            IMMUTABLE_EXECUTABLE_MODE
        };
        if observed.mode() != expected_mode
            || observed.bytes() != record.bytes
            || observed.sha256() != Some(&record.sha256)
        {
            return Err(unsafe_layout_error());
        }
    }
    Ok(())
}

// Requires one nonempty relative path containing only normal components.
fn require_relative_path(path: &Path) -> Result<(), CoreUpdateError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(unsafe_layout_error());
    }
    Ok(())
}

// Requires one absolute lexically normalized path with no root escape components.
pub(crate) fn require_absolute_normal_path(path: &Path) -> Result<(), CoreUpdateError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(unsafe_layout_error());
    }
    Ok(())
}

// Returns UTF-8 text from one required normal path component.
fn normal_component_text(component: Component<'_>) -> Result<&str, CoreUpdateError> {
    match component {
        Component::Normal(value) => value.to_str().ok_or_else(unsafe_layout_error),
        _ => Err(unsafe_layout_error()),
    }
}

// Derives one stable prepared receipt from its update and candidate identities.
fn prepared_receipt_id(
    update_id: &Sha256Digest,
    installation: &CoreInstallation,
) -> Result<Sha256Digest, CoreUpdateError> {
    artifact_receipt_id(
        "li_core_update_prepared_v1",
        &[
            update_id.as_str(),
            installation.version().as_str(),
            installation.source_identity().as_str(),
        ],
    )
}

// Derives one stable activation receipt from its complete reversible handoff.
fn activation_receipt_id(
    update_id: &Sha256Digest,
    previous: &CoreInstallation,
    installation: &CoreInstallation,
) -> Result<Sha256Digest, CoreUpdateError> {
    artifact_receipt_id(
        "li_core_update_activated_v1",
        &[
            update_id.as_str(),
            previous.version().as_str(),
            previous.source_identity().as_str(),
            installation.version().as_str(),
            installation.source_identity().as_str(),
        ],
    )
}

// Hashes one domain-separated receipt from length-prefixed canonical fields.
fn artifact_receipt_id(domain: &str, fields: &[&str]) -> Result<Sha256Digest, CoreUpdateError> {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain.as_bytes());
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        CoreUpdateError::InvalidContract {
            reason: "Core artifact receipt identity could not be derived",
        }
    })
}

// Hashes exact bytes into one lowercase SHA-256 identity.
fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, CoreUpdateError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).map_err(|_| {
        CoreUpdateError::InvalidContract {
            reason: "Core release identity could not be derived",
        }
    })
}

// Opens one owner-bound bounded regular file without following its final path.
fn open_owned_regular_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: u64,
) -> Result<File, CoreUpdateError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| artifact_io_error("native file opening is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| artifact_io_error("native file inspection is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes
    {
        return Err(unsafe_layout_error());
    }
    Ok(file)
}

// Hashes one bounded no-follow regular file after owner validation.
fn hash_owned_regular_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: u64,
) -> Result<Sha256Digest, CoreUpdateError> {
    let mut file = open_owned_regular_file(path, owner_user_id, maximum_bytes)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| artifact_io_error("native file hashing is unavailable"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| artifact_io_error("native file hashing is unavailable"))
}

// Requires one metadata snapshot to be an exact owner-bound directory.
fn require_owned_directory(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    mode: u32,
) -> Result<(), CoreUpdateError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != mode
    {
        return Err(unsafe_layout_error());
    }
    Ok(())
}

// Creates or validates one exact owner-only directory without following a symlink.
fn prepare_owned_directory(path: &Path, owner_user_id: u32) -> Result<(), CoreUpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_owned_directory(&metadata, owner_user_id, PRIVATE_DIRECTORY_MODE),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| artifact_io_error("Core update workspace creation is unavailable"))?;
            if fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .is_err()
            {
                let _ = fs::remove_dir(path);
                return Err(artifact_io_error(
                    "Core update workspace protection is unavailable",
                ));
            }
            let metadata = fs::symlink_metadata(path).map_err(|_| {
                artifact_io_error("Core update workspace inspection is unavailable")
            })?;
            if let Err(error) =
                require_owned_directory(&metadata, owner_user_id, PRIVATE_DIRECTORY_MODE)
            {
                let _ = fs::remove_dir(path);
                return Err(error);
            }
            Ok(())
        }
        Err(_) => Err(artifact_io_error(
            "Core update workspace inspection is unavailable",
        )),
    }
}

// Makes one exact owner-bound workspace writable only after rejecting every symlink.
fn make_owned_tree_writable(root: &Path, owner_user_id: u32) -> Result<(), CoreUpdateError> {
    let mut pending = vec![root.to_path_buf()];
    let mut directories = Vec::new();
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|_| artifact_io_error("Core update workspace inspection is unavailable"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != owner_user_id
        {
            return Err(unsafe_layout_error());
        }
        directories.push(directory.clone());
        for entry in fs::read_dir(&directory)
            .map_err(|_| artifact_io_error("Core update workspace inspection is unavailable"))?
        {
            let path = entry
                .map_err(|_| artifact_io_error("Core update workspace inspection is unavailable"))?
                .path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| {
                artifact_io_error("Core update workspace inspection is unavailable")
            })?;
            if metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
                return Err(unsafe_layout_error());
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|_| {
                    artifact_io_error("Core update workspace protection is unavailable")
                })?;
            } else {
                return Err(unsafe_layout_error());
            }
        }
    }
    for directory in directories.into_iter().rev() {
        fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .map_err(|_| artifact_io_error("Core update workspace protection is unavailable"))?;
    }
    Ok(())
}

// Syncs one exact owner-bound directory through a no-follow descriptor.
fn sync_owned_directory(path: &Path, owner_user_id: u32, mode: u32) -> Result<(), CoreUpdateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| artifact_io_error("Core update persistence is unavailable"))?;
    require_owned_directory(&metadata, owner_user_id, mode)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| artifact_io_error("Core update persistence is unavailable"))?;
    directory
        .sync_all()
        .map_err(|_| artifact_io_error("Core update persistence is unavailable"))
}

// Creates one stable redacted provider error for an external artifact boundary.
fn artifact_io_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("artifacts", reason)
}

// Creates one stable unsafe-layout failure without exposing host paths.
fn unsafe_layout_error() -> CoreUpdateError {
    CoreUpdateError::provider("artifacts", "installed Core layout is unsafe")
}
