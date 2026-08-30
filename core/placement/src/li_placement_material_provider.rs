// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use getrandom::fill;
use li_core_interface::{
    CredentialId, EndpointAddress, EndpointHealth, EndpointScheme, NodeAddress, NodeId, Placement,
    PlacementEndpoint, PlacementId, RuntimeSource, Sha256Digest, TechnicalName, TokenCountContract,
    TokenCountProtocol,
};
use li_runtime_manager::RuntimeExecutionImageReference;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    LinuxContainerLaunchPlan, LinuxContainerReadiness, LinuxPlacementMaterialProvider,
    MacosLaunchAgentPlan, MacosPlacementMaterialProvider, PlacementCredentialDisposition,
    PlacementCredentialProvider, PlacementCredentialReferences, PlacementError, PlacementStore,
    ShellFreeCommand, ShellFreeEnvironmentValue,
};

const MATERIAL_ROOT_NAME: &str = "placement_material";
const PLAN_FILE_NAME: &str = "li_placement_launch_plan_v3.json";
const DIGEST_FILE_NAME: &str = "li_placement_launch_plan_v3.sha256";
const SCHEMA_NAME: &str = "letsinfer.placement-launch-plan";
const SCHEMA_VERSION: u16 = 3;
const MAX_PLAN_BYTES: usize = 1024 * 1024;

// Selects one sealed platform-native launch plan without sharing platform mechanisms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedPlacementLaunchPlan {
    Linux(LinuxContainerLaunchPlan),
    Macos(MacosLaunchAgentPlan),
}

impl ResolvedPlacementLaunchPlan {
    // Requires one resolved plan to match the exact placement and secret-exclusion contract.
    pub fn validate_for(&self, placement: &Placement) -> Result<(), PlacementError> {
        match self {
            Self::Linux(plan) => {
                plan.validate_for(placement)?;
                plan.create_command().validate_persistable()
            }
            Self::Macos(plan) => {
                plan.validate_for(placement)?;
                plan.command().validate_persistable()
            }
        }
    }

    // Returns the deterministic SHA-256 identity of one validated plan document.
    pub fn identity(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.validate_for(placement)?;
        Sha256Digest::parse(&sha256(&plan_payload(self)?))
            .map_err(|_| PlacementError::ExecutionUnavailable)
    }

    // Requires endpoint identity and every secret-file reference to match provisioning.
    pub fn validate_credentials(
        &self,
        references: &PlacementCredentialReferences,
    ) -> Result<(), PlacementError> {
        let (placement_id, command, endpoint) = match self {
            Self::Linux(plan) => (plan.placement_id(), plan.create_command(), plan.endpoint()),
            Self::Macos(plan) => (plan.placement_id(), plan.command(), plan.endpoint()),
        };
        if placement_id != references.placement_id()
            || endpoint.is_some_and(|endpoint| {
                endpoint.credential_id() != references.credential_id()
                    || endpoint.ca_credential_id() != Some(references.ca_credential_id())
            })
            || [
                references.engine_credential_file(),
                references.tls_certificate_file(),
                references.tls_private_key_file(),
            ]
            .iter()
            .any(|path| !command_references_path(command, path))
            || !command_references_value(command, references.credential_bundle_sha256().as_str())
        {
            return Err(PlacementError::InvalidRequest {
                reason: "launch plan differs from provisioned credential references",
            });
        }
        Ok(())
    }
}

// Resolves runtime-specific immutable inputs into one platform-native launch plan.
pub trait PlacementLaunchPlanResolver: Send + Sync {
    // Returns one exact plan without writing it or exposing secret material.
    fn resolve(
        &self,
        placement: &Placement,
        credentials: &PlacementCredentialReferences,
    ) -> Result<ResolvedPlacementLaunchPlan, PlacementError>;
}

// Supplies unique private incoming-directory identities.
pub trait PlacementMaterialIdentityProvider: Send + Sync {
    // Returns one canonical lowercase 128-bit identity.
    fn identity(&self) -> Result<String, PlacementError>;
}

// Supplies the independently durable expected identity for one placement plan.
pub trait PlacementLaunchPlanIdentityProvider: Send + Sync {
    // Returns the durable plan digest when staging has already committed it.
    fn expected_identity(
        &self,
        placement: &Placement,
    ) -> Result<Option<Sha256Digest>, PlacementError>;
}

// Reads committed launch-plan identity from the PlacementManager aggregate store.
pub struct StoredPlacementLaunchPlanIdentityProvider {
    store: Arc<dyn PlacementStore>,
}

// Reads already-committed placement plans without acquiring staging or credential capabilities.
pub struct FilesystemPlacementMaterialReader {
    root: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn PlacementMaterialIo>,
    plan_identities: Arc<dyn PlacementLaunchPlanIdentityProvider>,
}

// Supplies one caller-observed plan identity so a composed snapshot cannot cross generations.
struct ExactPlacementLaunchPlanIdentity<'a> {
    value: &'a Sha256Digest,
}

impl PlacementLaunchPlanIdentityProvider for ExactPlacementLaunchPlanIdentity<'_> {
    // Returns the exact identity already bound into the caller's immutable snapshot.
    fn expected_identity(
        &self,
        _placement: &Placement,
    ) -> Result<Option<Sha256Digest>, PlacementError> {
        Ok(Some(self.value.clone()))
    }
}

impl FilesystemPlacementMaterialReader {
    // Creates one read-only material boundary rooted at the explicit placement directory.
    pub fn new(
        root: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn PlacementMaterialIo>,
        plan_identities: Arc<dyn PlacementLaunchPlanIdentityProvider>,
    ) -> Result<Self, PlacementError> {
        if !root.is_absolute()
            || root.file_name().and_then(|value| value.to_str()) != Some(MATERIAL_ROOT_NAME)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement material root is invalid",
            });
        }
        Ok(Self {
            root,
            owner_user_id,
            io,
            plan_identities,
        })
    }

    // Returns one exact committed macOS plan and rejects absent or foreign platform material.
    pub fn macos_plan(
        &self,
        placement: &Placement,
    ) -> Result<Option<MacosLaunchAgentPlan>, PlacementError> {
        self.macos_plan_with_identity(placement, self.plan_identities.as_ref())
    }

    // Reads one macOS plan against an identity from the same already-observed owner snapshot.
    pub fn macos_plan_with_expected_identity(
        &self,
        placement: &Placement,
        expected_identity: &Sha256Digest,
    ) -> Result<Option<MacosLaunchAgentPlan>, PlacementError> {
        self.macos_plan_with_identity(
            placement,
            &ExactPlacementLaunchPlanIdentity {
                value: expected_identity,
            },
        )
    }

    // Reads one exact macOS plan through a caller-selected durable identity boundary.
    fn macos_plan_with_identity(
        &self,
        placement: &Placement,
        plan_identities: &dyn PlacementLaunchPlanIdentityProvider,
    ) -> Result<Option<MacosLaunchAgentPlan>, PlacementError> {
        let directory = self.root.join(placement.placement_id().as_str());
        match FilesystemPlacementMaterialProvider::read_plan_value(
            self.io.as_ref(),
            plan_identities,
            self.owner_user_id,
            &directory,
            placement,
        )? {
            Some(ResolvedPlacementLaunchPlan::Macos(plan)) => Ok(Some(plan)),
            Some(ResolvedPlacementLaunchPlan::Linux(_)) => {
                Err(PlacementError::ExecutionUnavailable)
            }
            None => Ok(None),
        }
    }
}

impl StoredPlacementLaunchPlanIdentityProvider {
    // Creates one adapter without transferring aggregate-store ownership.
    pub const fn new(store: Arc<dyn PlacementStore>) -> Self {
        Self { store }
    }
}

impl PlacementLaunchPlanIdentityProvider for StoredPlacementLaunchPlanIdentityProvider {
    // Returns no identity before staging and the exact committed identity afterward.
    fn expected_identity(
        &self,
        placement: &Placement,
    ) -> Result<Option<Sha256Digest>, PlacementError> {
        let record = self
            .store
            .read(placement.placement_group_id())?
            .ok_or(PlacementError::GroupNotFound)?;
        Ok(record
            .record()
            .launch_plan_identity(placement.placement_id())
            .cloned())
    }
}

// Reads operating-system entropy for private staging identities.
#[derive(Default)]
pub struct SystemPlacementMaterialIdentityProvider;

impl PlacementMaterialIdentityProvider for SystemPlacementMaterialIdentityProvider {
    // Returns one lowercase identity from 128 bits of operating-system entropy.
    fn identity(&self) -> Result<String, PlacementError> {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes).map_err(|_| PlacementError::ExecutionUnavailable)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

// Defines exact owner-checked filesystem operations for launch-plan material.
pub trait PlacementMaterialIo: Send + Sync {
    // Creates or validates one private owner-only directory.
    fn ensure_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Creates one bounded private regular file and syncs its directory.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Reads one bounded private regular file or reports exact absence.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError>;

    // Atomically renames one private directory within its parent.
    fn rename_private_directory(
        &self,
        source: &Path,
        destination: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Removes one exact material directory containing only known files.
    fn remove_material_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, PlacementError>;

    // Lists direct child names without following them.
    fn entries(&self, path: &Path, owner_user_id: u32) -> Result<Vec<String>, PlacementError>;
}

// Performs private, no-follow, durable launch-plan filesystem operations.
#[derive(Default)]
pub struct SystemPlacementMaterialIo;

impl PlacementMaterialIo for SystemPlacementMaterialIo {
    // Creates or validates one private owner-only directory.
    fn ensure_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_private_directory(&metadata, owner_user_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| PlacementError::ExecutionUnavailable)?;
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
                validate_private_directory(&metadata, owner_user_id)
            }
            Err(_) => Err(PlacementError::ExecutionUnavailable),
        }
    }

    // Creates one exclusive private file without replacing existing material.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if payload.is_empty() || payload.len() > MAX_PLAN_BYTES {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let parent = path.parent().ok_or(PlacementError::ExecutionUnavailable)?;
        self.ensure_private_directory(parent, owner_user_id)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        file.write_all(payload)
            .and_then(|_| file.sync_all())
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(parent)
    }

    // Reads one bounded private file through a no-follow descriptor.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        };
        let metadata = file
            .metadata()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        validate_private_file(&metadata, owner_user_id, maximum_bytes)?;
        let mut payload = Vec::new();
        file.take(maximum_bytes as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if payload.len() > maximum_bytes {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(Some(payload))
    }

    // Renames one validated private directory and syncs its common parent.
    fn rename_private_directory(
        &self,
        source: &Path,
        destination: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        let parent = source
            .parent()
            .ok_or(PlacementError::ExecutionUnavailable)?;
        if destination.parent() != Some(parent) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        match fs::symlink_metadata(destination) {
            Ok(_) => return Err(PlacementError::ExecutionUnavailable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        }
        validate_private_directory(
            &fs::symlink_metadata(source).map_err(|_| PlacementError::ExecutionUnavailable)?,
            owner_user_id,
        )?;
        let entries = self.entries(source, owner_user_id)?;
        if entries.len() != 2
            || !entries.iter().any(|value| value == PLAN_FILE_NAME)
            || !entries.iter().any(|value| value == DIGEST_FILE_NAME)
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        fs::rename(source, destination).map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(parent)
    }

    // Removes only the two known private launch-plan files and their directory.
    fn remove_material_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        };
        validate_private_directory(&metadata, owner_user_id)?;
        let entries = self.entries(path, owner_user_id)?;
        if entries
            .iter()
            .any(|name| !matches!(name.as_str(), PLAN_FILE_NAME | DIGEST_FILE_NAME))
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        for name in entries {
            let file = path.join(name);
            let metadata =
                fs::symlink_metadata(&file).map_err(|_| PlacementError::ExecutionUnavailable)?;
            validate_private_file(&metadata, owner_user_id, MAX_PLAN_BYTES)?;
            fs::remove_file(file).map_err(|_| PlacementError::ExecutionUnavailable)?;
        }
        fs::remove_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(path.parent().ok_or(PlacementError::ExecutionUnavailable)?)?;
        Ok(true)
    }

    // Lists bounded direct child names after validating the parent directory.
    fn entries(&self, path: &Path, owner_user_id: u32) -> Result<Vec<String>, PlacementError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(PlacementError::ExecutionUnavailable),
        };
        validate_private_directory(&metadata, owner_user_id)?;
        let mut values = Vec::new();
        for entry in fs::read_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)? {
            let entry = entry.map_err(|_| PlacementError::ExecutionUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            if name.is_empty() || name.len() > 255 || values.len() >= 128 {
                return Err(PlacementError::ExecutionUnavailable);
            }
            values.push(name);
        }
        values.sort();
        Ok(values)
    }
}

// Persists sealed platform plans atomically and reconstructs them after restart.
pub struct FilesystemPlacementMaterialProvider {
    root: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn PlacementMaterialIo>,
    resolver: Arc<dyn PlacementLaunchPlanResolver>,
    staging_identities: Arc<dyn PlacementMaterialIdentityProvider>,
    plan_identities: Arc<dyn PlacementLaunchPlanIdentityProvider>,
    credentials: Arc<dyn PlacementCredentialProvider>,
    cache_root: Option<PathBuf>,
}

impl FilesystemPlacementMaterialProvider {
    // Creates one provider rooted at the exact private placement-material directory.
    pub fn new(
        root: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn PlacementMaterialIo>,
        resolver: Arc<dyn PlacementLaunchPlanResolver>,
        staging_identities: Arc<dyn PlacementMaterialIdentityProvider>,
        plan_identities: Arc<dyn PlacementLaunchPlanIdentityProvider>,
        credentials: Arc<dyn PlacementCredentialProvider>,
    ) -> Result<Self, PlacementError> {
        if !root.is_absolute()
            || root.file_name().and_then(|value| value.to_str()) != Some(MATERIAL_ROOT_NAME)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement material root is invalid",
            });
        }
        Ok(Self {
            root,
            owner_user_id,
            io,
            resolver,
            staging_identities,
            plan_identities,
            credentials,
            cache_root: None,
        })
    }

    // Adds the stable private cache root used by the sealed per-placement launch plan.
    pub fn with_cache_root(mut self, cache_root: PathBuf) -> Result<Self, PlacementError> {
        if !cache_root.is_absolute()
            || cache_root.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement cache root is invalid",
            });
        }
        self.cache_root = Some(cache_root);
        Ok(self)
    }

    // Returns the exact final directory for one placement.
    fn destination(&self, placement: &Placement) -> PathBuf {
        self.root.join(placement.placement_id().as_str())
    }

    // Returns one unique private incoming directory for a placement.
    fn incoming(&self, placement: &Placement, identity: &str) -> Result<PathBuf, PlacementError> {
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(self.root.join(format!(
            ".{}.incoming.{}",
            placement.placement_id().as_str(),
            identity
        )))
    }

    // Stages one audited plan through a unique directory and atomic activation.
    fn stage_plan(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        if let Some(cache_root) = &self.cache_root {
            self.io
                .ensure_private_directory(cache_root, self.owner_user_id)?;
            let installation_root =
                cache_root.join(placement.assignment().runtime_installation_id().as_str());
            self.io
                .ensure_private_directory(&installation_root, self.owner_user_id)?;
            self.io.ensure_private_directory(
                &installation_root.join(placement.placement_id().as_str()),
                self.owner_user_id,
            )?;
        }
        self.io
            .ensure_private_directory(&self.root, self.owner_user_id)?;
        if let Some(existing) = self.read_plan(&self.destination(placement), placement)? {
            existing.validate_for(placement)?;
            existing.validate_credentials(
                &self
                    .credentials
                    .existing(placement)?
                    .ok_or(PlacementError::ExecutionUnavailable)?,
            )?;
            return existing.identity(placement);
        }
        let provision = self.credentials.provision(placement)?;
        let result = self.stage_provisioned_plan(placement, provision.references());
        if result.is_err() {
            if provision.disposition() == PlacementCredentialDisposition::Created {
                let winner_uses_credentials = self
                    .read_plan(&self.destination(placement), placement)
                    .ok()
                    .flatten()
                    .is_some_and(|winner| {
                        winner.validate_credentials(provision.references()).is_ok()
                    });
                if !winner_uses_credentials {
                    let _ = self
                        .credentials
                        .remove_if_matches(placement, provision.references());
                }
            }
        }
        result
    }

    // Resolves, audits, writes, verifies, and atomically activates one provisioned plan.
    fn stage_provisioned_plan(
        &self,
        placement: &Placement,
        credentials: &PlacementCredentialReferences,
    ) -> Result<Sha256Digest, PlacementError> {
        let resolved = self.resolver.resolve(placement, credentials)?;
        resolved.validate_for(placement)?;
        resolved.validate_credentials(credentials)?;
        if let Some(expected) = self.plan_identities.expected_identity(placement)? {
            if resolved.identity(placement)? != expected {
                return Err(PlacementError::ExecutionUnavailable);
            }
        }
        let identity = self.staging_identities.identity()?;
        let incoming = self.incoming(placement, &identity)?;
        self.io
            .ensure_private_directory(&incoming, self.owner_user_id)?;
        let result = (|| {
            let payload = plan_payload(&resolved)?;
            let digest = sha256(&payload);
            self.io.write_private_file(
                &incoming.join(PLAN_FILE_NAME),
                &payload,
                self.owner_user_id,
            )?;
            self.io.write_private_file(
                &incoming.join(DIGEST_FILE_NAME),
                format!("{digest}\n").as_bytes(),
                self.owner_user_id,
            )?;
            let observed = self
                .read_plan(&incoming, placement)?
                .ok_or(PlacementError::ExecutionUnavailable)?;
            if observed != resolved {
                return Err(PlacementError::ExecutionUnavailable);
            }
            match self.io.rename_private_directory(
                &incoming,
                &self.destination(placement),
                self.owner_user_id,
            ) {
                Ok(()) => Ok(()),
                Err(_) => {
                    let winner = self
                        .read_plan(&self.destination(placement), placement)?
                        .ok_or(PlacementError::ExecutionUnavailable)?;
                    if winner != resolved {
                        return Err(PlacementError::ExecutionUnavailable);
                    }
                    self.io
                        .remove_material_directory(&incoming, self.owner_user_id)?;
                    Ok(())
                }
            }
        })();
        if result.is_err() {
            let _ = self
                .io
                .remove_material_directory(&incoming, self.owner_user_id);
        }
        result?;
        resolved.identity(placement)
    }

    // Reads and integrity-verifies one complete plan directory.
    fn read_plan(
        &self,
        directory: &Path,
        placement: &Placement,
    ) -> Result<Option<ResolvedPlacementLaunchPlan>, PlacementError> {
        Self::read_plan_value(
            self.io.as_ref(),
            self.plan_identities.as_ref(),
            self.owner_user_id,
            directory,
            placement,
        )
    }

    // Reads and integrity-verifies one complete placement plan through injected native boundaries.
    fn read_plan_value(
        io: &dyn PlacementMaterialIo,
        plan_identities: &dyn PlacementLaunchPlanIdentityProvider,
        owner_user_id: u32,
        directory: &Path,
        placement: &Placement,
    ) -> Result<Option<ResolvedPlacementLaunchPlan>, PlacementError> {
        let plan = io.read_private_file(
            &directory.join(PLAN_FILE_NAME),
            MAX_PLAN_BYTES,
            owner_user_id,
        )?;
        let digest = io.read_private_file(&directory.join(DIGEST_FILE_NAME), 128, owner_user_id)?;
        match (plan, digest) {
            (None, None) => Ok(None),
            (Some(plan), Some(digest)) => {
                let digest = std::str::from_utf8(&digest)
                    .map_err(|_| PlacementError::ExecutionUnavailable)?;
                let expected = digest
                    .strip_suffix('\n')
                    .ok_or(PlacementError::ExecutionUnavailable)?;
                if Sha256Digest::parse(expected).is_err() || expected != sha256(&plan) {
                    return Err(PlacementError::ExecutionUnavailable);
                }
                if let Some(durable) = plan_identities.expected_identity(placement)? {
                    if expected != durable.as_str() {
                        return Err(PlacementError::ExecutionUnavailable);
                    }
                }
                let resolved = plan_from_payload(&plan, placement)?;
                resolved.validate_for(placement)?;
                Ok(Some(resolved))
            }
            _ => Err(PlacementError::ExecutionUnavailable),
        }
    }

    // Removes final and stale incoming directories for one exact placement only.
    fn remove_plan(&self, placement: &Placement) -> Result<(), PlacementError> {
        let credentials = self.credentials.existing(placement)?;
        self.io
            .remove_material_directory(&self.destination(placement), self.owner_user_id)?;
        for entry in self.io.entries(&self.root, self.owner_user_id)? {
            if is_incoming_name(placement.placement_id(), &entry) {
                self.io
                    .remove_material_directory(&self.root.join(entry), self.owner_user_id)?;
            }
        }
        if let Some(credentials) = credentials {
            self.credentials
                .remove_if_matches(placement, &credentials)?;
        }
        Ok(())
    }
}

impl LinuxPlacementMaterialProvider for FilesystemPlacementMaterialProvider {
    // Stages one exact plan and returns its immutable launch identity.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.stage_plan(placement)
    }

    // Returns one exact Linux plan and rejects a stored macOS plan.
    fn plan(
        &self,
        placement: &Placement,
    ) -> Result<Option<LinuxContainerLaunchPlan>, PlacementError> {
        match self.read_plan(&self.destination(placement), placement)? {
            Some(ResolvedPlacementLaunchPlan::Linux(plan)) => Ok(Some(plan)),
            Some(ResolvedPlacementLaunchPlan::Macos(_)) => {
                Err(PlacementError::ExecutionUnavailable)
            }
            None => Ok(None),
        }
    }

    // Removes only this placement's exact final and stale incoming material.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError> {
        self.remove_plan(placement)
    }
}

impl MacosPlacementMaterialProvider for FilesystemPlacementMaterialProvider {
    // Stages one exact plan and returns its immutable launch identity.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.stage_plan(placement)
    }

    // Returns one exact macOS plan and rejects a stored Linux plan.
    fn plan(&self, placement: &Placement) -> Result<Option<MacosLaunchAgentPlan>, PlacementError> {
        match self.read_plan(&self.destination(placement), placement)? {
            Some(ResolvedPlacementLaunchPlan::Macos(plan)) => Ok(Some(plan)),
            Some(ResolvedPlacementLaunchPlan::Linux(_)) => {
                Err(PlacementError::ExecutionUnavailable)
            }
            None => Ok(None),
        }
    }

    // Removes only this placement's exact final and stale incoming material.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError> {
        self.remove_plan(placement)
    }
}

// Stores one closed versioned plan document.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanDocument {
    schema_name: String,
    schema_version: u16,
    platform: String,
    placement_id: String,
    runtime_installation_id: String,
    task_id: String,
    command: CommandDocument,
    endpoint: Option<EndpointDocument>,
    linux: Option<LinuxPlanDocument>,
    macos: Option<MacosPlanDocument>,
}

// Stores one shell-free command without native process state.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandDocument {
    executable: String,
    arguments: Vec<String>,
    environment: Vec<EnvironmentDocument>,
    working_directory: String,
}

// Stores one environment field together with its owner.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDocument {
    name: String,
    value: String,
    ownership: String,
}

// Stores Linux-only immutable launch identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxPlanDocument {
    container_name: String,
    image_reference: String,
    local_config_digest: Option<String>,
    image_id: String,
    readiness: LinuxReadinessDocument,
}

// Stores one closed Linux readiness mechanism.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LinuxReadinessDocument {
    Endpoint {
        attempts: u16,
        interval_milliseconds: u64,
    },
    Exec {
        arguments: Vec<String>,
        attempts: u16,
        interval_milliseconds: u64,
    },
}

// Stores macOS-only immutable launch identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosPlanDocument {
    label: String,
    executable_sha256: String,
    readiness_attempts: u16,
    readiness_interval_milliseconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log_path: Option<String>,
}

// Stores one endpoint without credential material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointDocument {
    placement_id: String,
    node_id: String,
    scheme: String,
    host: String,
    port: u16,
    credential_id: String,
    ca_credential_id: Option<String>,
    token_count: Option<TokenCountDocument>,
    max_active_requests: u32,
    max_context_tokens: u64,
    health: EndpointHealthDocument,
}

// Stores one exact token-count endpoint contract.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenCountDocument {
    path: String,
    protocol: String,
}

// Stores one bounded endpoint health snapshot.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointHealthDocument {
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<i32>,
    prefix_keys: Vec<String>,
}

// Serializes one audited resolved plan into deterministic private JSON bytes.
fn plan_payload(plan: &ResolvedPlacementLaunchPlan) -> Result<Vec<u8>, PlacementError> {
    let document = plan_document(plan);
    let mut payload =
        serde_json::to_vec(&document).map_err(|_| PlacementError::ExecutionUnavailable)?;
    payload.push(b'\n');
    if payload.len() > MAX_PLAN_BYTES {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(payload)
}

// Projects one resolved plan into its closed private document.
fn plan_document(plan: &ResolvedPlacementLaunchPlan) -> PlanDocument {
    match plan {
        ResolvedPlacementLaunchPlan::Linux(plan) => PlanDocument {
            schema_name: SCHEMA_NAME.to_string(),
            schema_version: SCHEMA_VERSION,
            platform: "linux".to_string(),
            placement_id: plan.placement_id().as_str().to_string(),
            runtime_installation_id: plan.runtime_installation_id().as_str().to_string(),
            task_id: plan.task_id().as_str().to_string(),
            command: command_document(plan.create_command()),
            endpoint: plan.endpoint().map(endpoint_document),
            linux: Some(LinuxPlanDocument {
                container_name: plan.container_name().as_str().to_string(),
                image_reference: plan.image_reference().as_str().to_string(),
                local_config_digest: plan
                    .image_reference()
                    .local_config_digest()
                    .map(|digest| digest.as_str().to_string()),
                image_id: plan.image_id().as_str().to_string(),
                readiness: match plan.readiness() {
                    LinuxContainerReadiness::Endpoint { attempts, interval } => {
                        LinuxReadinessDocument::Endpoint {
                            attempts: *attempts,
                            interval_milliseconds: interval.as_millis() as u64,
                        }
                    }
                    LinuxContainerReadiness::Exec {
                        arguments,
                        attempts,
                        interval,
                    } => LinuxReadinessDocument::Exec {
                        arguments: arguments.clone(),
                        attempts: *attempts,
                        interval_milliseconds: interval.as_millis() as u64,
                    },
                },
            }),
            macos: None,
        },
        ResolvedPlacementLaunchPlan::Macos(plan) => PlanDocument {
            schema_name: SCHEMA_NAME.to_string(),
            schema_version: SCHEMA_VERSION,
            platform: "macos".to_string(),
            placement_id: plan.placement_id().as_str().to_string(),
            runtime_installation_id: plan.runtime_installation_id().as_str().to_string(),
            task_id: plan.task_id().as_str().to_string(),
            command: command_document(plan.command()),
            endpoint: plan.endpoint().map(endpoint_document),
            linux: None,
            macos: Some(MacosPlanDocument {
                label: plan.label().as_str().to_string(),
                executable_sha256: plan.executable_identity().as_str().to_string(),
                readiness_attempts: plan.readiness_attempts(),
                readiness_interval_milliseconds: plan.readiness_interval().as_millis() as u64,
                log_path: plan
                    .log_path()
                    .map(|path| path.to_string_lossy().into_owned()),
            }),
        },
    }
}

// Projects one shell-free command into private plan fields.
fn command_document(command: &ShellFreeCommand) -> CommandDocument {
    CommandDocument {
        executable: command.executable().to_string_lossy().into_owned(),
        arguments: command.arguments().to_vec(),
        environment: command
            .environment()
            .iter()
            .map(|value| EnvironmentDocument {
                name: value.name().to_string(),
                value: value.value().to_string(),
                ownership: value.ownership_name().to_string(),
            })
            .collect(),
        working_directory: command.working_directory().to_string_lossy().into_owned(),
    }
}

// Projects one endpoint without reading credential contents.
fn endpoint_document(endpoint: &PlacementEndpoint) -> EndpointDocument {
    EndpointDocument {
        placement_id: endpoint.placement_id().as_str().to_string(),
        node_id: endpoint.node_id().as_str().to_string(),
        scheme: match endpoint.address().scheme() {
            EndpointScheme::Http => "http",
            EndpointScheme::Https => "https",
        }
        .to_string(),
        host: endpoint.address().host().as_str().to_string(),
        port: endpoint.address().port(),
        credential_id: endpoint.credential_id().as_str().to_string(),
        ca_credential_id: endpoint
            .ca_credential_id()
            .map(|value| value.as_str().to_string()),
        token_count: endpoint.token_count().map(|value| TokenCountDocument {
            path: value.path().to_string(),
            protocol: "letsinfer_v1".to_string(),
        }),
        max_active_requests: endpoint.max_active_requests(),
        max_context_tokens: endpoint.max_context_tokens(),
        health: EndpointHealthDocument {
            healthy: endpoint.health().healthy(),
            memory_pressure: endpoint.health().memory_pressure(),
            temperature_millicelsius: endpoint.health().temperature_millicelsius(),
            prefix_keys: endpoint
                .health()
                .prefix_keys()
                .iter()
                .map(|value| value.as_str().to_string())
                .collect(),
        },
    }
}

// Reconstructs and validates one resolved plan from private JSON bytes.
fn plan_from_payload(
    payload: &[u8],
    placement: &Placement,
) -> Result<ResolvedPlacementLaunchPlan, PlacementError> {
    let document: PlanDocument =
        serde_json::from_slice(payload).map_err(|_| PlacementError::ExecutionUnavailable)?;
    if document.schema_name != SCHEMA_NAME
        || document.schema_version != SCHEMA_VERSION
        || document.placement_id != placement.placement_id().as_str()
        || document.runtime_installation_id
            != placement.assignment().runtime_installation_id().as_str()
        || document.task_id != placement.assignment().task_id().as_str()
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    let command = command_from_document(document.command)?;
    command.validate_persistable()?;
    let endpoint = document.endpoint.map(endpoint_from_document).transpose()?;
    match (document.platform.as_str(), document.linux, document.macos) {
        ("linux", Some(linux), None) => {
            if linux.container_name != format!("li_placement_{}", placement.placement_id().as_str())
            {
                return Err(PlacementError::ExecutionUnavailable);
            }
            let image_id = Sha256Digest::parse(&linux.image_id)
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            let image_reference = match linux.local_config_digest {
                Some(digest) => RuntimeExecutionImageReference::local_config(
                    Sha256Digest::parse(&digest)
                        .map_err(|_| PlacementError::ExecutionUnavailable)?,
                ),
                None => RuntimeExecutionImageReference::distribution(
                    &RuntimeSource::parse(&linux.image_reference)
                        .map_err(|_| PlacementError::ExecutionUnavailable)?,
                ),
            };
            Ok(ResolvedPlacementLaunchPlan::Linux(
                LinuxContainerLaunchPlan::new(
                    placement,
                    image_reference,
                    image_id,
                    command,
                    match linux.readiness {
                        LinuxReadinessDocument::Endpoint {
                            attempts,
                            interval_milliseconds,
                        } => LinuxContainerReadiness::endpoint(
                            attempts,
                            std::time::Duration::from_millis(interval_milliseconds),
                        )?,
                        LinuxReadinessDocument::Exec {
                            arguments,
                            attempts,
                            interval_milliseconds,
                        } => LinuxContainerReadiness::exec(
                            arguments,
                            attempts,
                            std::time::Duration::from_millis(interval_milliseconds),
                        )?,
                    },
                    endpoint,
                )?,
            ))
        }
        ("macos", None, Some(macos)) => {
            let plan = MacosLaunchAgentPlan::new(
                placement,
                command,
                Sha256Digest::parse(&macos.executable_sha256)
                    .map_err(|_| PlacementError::ExecutionUnavailable)?,
                endpoint,
                macos.readiness_attempts,
                std::time::Duration::from_millis(macos.readiness_interval_milliseconds),
            )?;
            let plan = match macos.log_path {
                Some(log_path) => {
                    let path = PathBuf::from(log_path);
                    let root = path.parent().ok_or(PlacementError::ExecutionUnavailable)?;
                    let plan = plan.with_log_root(root.to_path_buf())?;
                    if plan.log_path() != Some(&path) {
                        return Err(PlacementError::ExecutionUnavailable);
                    }
                    plan
                }
                None => plan,
            };
            if plan.label().as_str() != macos.label {
                return Err(PlacementError::ExecutionUnavailable);
            }
            Ok(ResolvedPlacementLaunchPlan::Macos(plan))
        }
        _ => Err(PlacementError::ExecutionUnavailable),
    }
}

// Reconstructs one shell-free command and its ownership-separated environment.
fn command_from_document(document: CommandDocument) -> Result<ShellFreeCommand, PlacementError> {
    let mut runtime = Vec::new();
    let mut core = Vec::new();
    for value in document.environment {
        match value.ownership.as_str() {
            "runtime" => runtime.push(ShellFreeEnvironmentValue::runtime(
                &value.name,
                &value.value,
            )?),
            "core" => core.push(ShellFreeEnvironmentValue::core(&value.name, &value.value)?),
            _ => return Err(PlacementError::ExecutionUnavailable),
        }
    }
    ShellFreeCommand::new(
        PathBuf::from(document.executable),
        document.arguments,
        runtime,
        core,
        PathBuf::from(document.working_directory),
    )
}

// Reconstructs one endpoint from credential references and bounded health fields.
fn endpoint_from_document(document: EndpointDocument) -> Result<PlacementEndpoint, PlacementError> {
    PlacementEndpoint::new(
        PlacementId::parse(&document.placement_id)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        NodeId::parse(&document.node_id).map_err(|_| PlacementError::ExecutionUnavailable)?,
        EndpointAddress::new(
            match document.scheme.as_str() {
                "http" => EndpointScheme::Http,
                "https" => EndpointScheme::Https,
                _ => return Err(PlacementError::ExecutionUnavailable),
            },
            NodeAddress::parse(&document.host).map_err(|_| PlacementError::ExecutionUnavailable)?,
            document.port,
        )
        .map_err(|_| PlacementError::ExecutionUnavailable)?,
        CredentialId::parse(&document.credential_id)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        document
            .ca_credential_id
            .map(|value| CredentialId::parse(&value))
            .transpose()
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        document
            .token_count
            .map(token_count_from_document)
            .transpose()?,
        document.max_active_requests,
        document.max_context_tokens,
        EndpointHealth::new(
            document.health.healthy,
            document.health.memory_pressure,
            document.health.temperature_millicelsius,
            document
                .health
                .prefix_keys
                .into_iter()
                .map(|value| {
                    TechnicalName::parse(&value).map_err(|_| PlacementError::ExecutionUnavailable)
                })
                .collect::<Result<Vec<_>, PlacementError>>()?,
        )
        .map_err(|_| PlacementError::ExecutionUnavailable)?,
    )
    .map_err(|_| PlacementError::ExecutionUnavailable)
}

// Reconstructs one exact token-count contract.
fn token_count_from_document(
    document: TokenCountDocument,
) -> Result<TokenCountContract, PlacementError> {
    if document.protocol != "letsinfer_v1" {
        return Err(PlacementError::ExecutionUnavailable);
    }
    TokenCountContract::new(&document.path, TokenCountProtocol::LetsInferV1)
        .map_err(|_| PlacementError::ExecutionUnavailable)
}

// Returns whether one shell-free command carries one exact file reference.
fn command_references_path(command: &ShellFreeCommand, path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    command
        .environment()
        .iter()
        .any(|value| value.value() == path)
        || command.arguments().iter().any(|value| {
            value == path
                || value
                    .strip_prefix(path)
                    .is_some_and(|suffix| suffix.starts_with(':'))
        })
}

// Returns whether one shell-free command carries one exact non-secret identity value.
fn command_references_value(command: &ShellFreeCommand, expected: &str) -> bool {
    command
        .environment()
        .iter()
        .any(|value| value.value() == expected)
        || command.arguments().iter().any(|value| {
            value == expected
                || value
                    .split_once('=')
                    .is_some_and(|(_, value)| value == expected)
        })
}

// Returns the lowercase SHA-256 of exact private plan bytes.
fn sha256(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(payload);
    format!("{:x}", digest.finalize())
}

// Returns whether one child is a canonical stale incoming directory for a placement.
fn is_incoming_name(placement_id: &PlacementId, value: &str) -> bool {
    let Some(identity) = value.strip_prefix(&format!(".{}.incoming.", placement_id.as_str()))
    else {
        return false;
    };
    identity.len() == 32
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Requires one owner-only private directory metadata record.
fn validate_private_directory(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), PlacementError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Requires one bounded owner-only private regular file metadata record.
fn validate_private_file(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), PlacementError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Syncs one material directory after file or directory mutation.
fn sync_directory(path: &Path) -> Result<(), PlacementError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PlacementError::ExecutionUnavailable)
}
