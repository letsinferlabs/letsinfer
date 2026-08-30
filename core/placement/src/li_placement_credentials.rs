// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use getrandom::fill;
use li_core_interface::{CredentialId, Placement, PlacementId, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    PlacementError, PlacementMaterialIdentityProvider, ShellFreeCommand, ShellFreeCommandOutput,
    ShellFreeCommandRunner,
};

const SECRET_ROOT_NAME: &str = "placement_secrets";
const CREDENTIAL_FILE_NAME: &str = "li_engine_credential";
const CERTIFICATE_FILE_NAME: &str = "li_engine_tls_certificate.pem";
const PRIVATE_KEY_FILE_NAME: &str = "li_engine_tls_private_key.pem";
const METADATA_FILE_NAME: &str = "li_placement_credentials_v1.json";
const SCHEMA_NAME: &str = "letsinfer.placement-credentials";
const SCHEMA_VERSION: u16 = 1;
const MAX_CREDENTIAL_BYTES: usize = 512;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const TLS_STAGING_ROOT_NAME: &str = "placement_tls_staging";
const TLS_STAGED_CERTIFICATE_NAME: &str = "li_generated_certificate.pem";
const TLS_STAGED_PRIVATE_KEY_NAME: &str = "li_generated_private_key.pem";

// Carries reference-only credential identity into durable launch plans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementCredentialReferences {
    placement_id: PlacementId,
    credential_id: CredentialId,
    ca_credential_id: CredentialId,
    engine_credential_file: PathBuf,
    tls_certificate_file: PathBuf,
    tls_private_key_file: PathBuf,
    tls_certificate_sha256: Sha256Digest,
    credential_bundle_sha256: Sha256Digest,
}

impl PlacementCredentialReferences {
    // Creates one complete reference set without reading secret file contents.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placement_id: PlacementId,
        credential_id: CredentialId,
        ca_credential_id: CredentialId,
        engine_credential_file: PathBuf,
        tls_certificate_file: PathBuf,
        tls_private_key_file: PathBuf,
        tls_certificate_sha256: Sha256Digest,
        credential_bundle_sha256: Sha256Digest,
    ) -> Result<Self, PlacementError> {
        let paths = [
            &engine_credential_file,
            &tls_certificate_file,
            &tls_private_key_file,
        ];
        if credential_id == ca_credential_id
            || paths.iter().any(|path| !path.is_absolute())
            || paths[0] == paths[1]
            || paths[0] == paths[2]
            || paths[1] == paths[2]
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement credential references are incomplete or ambiguous",
            });
        }
        Ok(Self {
            placement_id,
            credential_id,
            ca_credential_id,
            engine_credential_file,
            tls_certificate_file,
            tls_private_key_file,
            tls_certificate_sha256,
            credential_bundle_sha256,
        })
    }

    // Returns the exact placement owning these credentials.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the internal Engine credential identity.
    pub const fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    // Returns the certificate-authority credential identity.
    pub const fn ca_credential_id(&self) -> &CredentialId {
        &self.ca_credential_id
    }

    // Returns the private Engine credential file path.
    pub fn engine_credential_file(&self) -> &Path {
        &self.engine_credential_file
    }

    // Returns the public TLS certificate file path.
    pub fn tls_certificate_file(&self) -> &Path {
        &self.tls_certificate_file
    }

    // Returns the private TLS key file path.
    pub fn tls_private_key_file(&self) -> &Path {
        &self.tls_private_key_file
    }

    // Returns the exact public certificate SHA-256.
    pub const fn tls_certificate_sha256(&self) -> &Sha256Digest {
        &self.tls_certificate_sha256
    }

    // Returns the immutable digest covering every credential and TLS byte.
    pub const fn credential_bundle_sha256(&self) -> &Sha256Digest {
        &self.credential_bundle_sha256
    }
}

// Distinguishes new credential creation from idempotent replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementCredentialDisposition {
    Created,
    Existing,
}

// Returns reference-only credentials and whether this call created them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementCredentialProvision {
    references: PlacementCredentialReferences,
    disposition: PlacementCredentialDisposition,
}

impl PlacementCredentialProvision {
    // Creates one exact credential-provision result.
    pub const fn new(
        references: PlacementCredentialReferences,
        disposition: PlacementCredentialDisposition,
    ) -> Self {
        Self {
            references,
            disposition,
        }
    }

    // Returns reference-only credential identity.
    pub const fn references(&self) -> &PlacementCredentialReferences {
        &self.references
    }

    // Returns whether this call created the exact secret directory.
    pub const fn disposition(&self) -> PlacementCredentialDisposition {
        self.disposition
    }
}

// Holds generated TLS bytes until the filesystem provider durably writes them.
pub struct PlacementTlsMaterial {
    ca_credential_id: CredentialId,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}

impl PlacementTlsMaterial {
    // Creates one bounded PEM certificate/private-key pair from an injected generator.
    pub fn new(
        ca_credential_id: CredentialId,
        certificate: Vec<u8>,
        mut private_key: Vec<u8>,
    ) -> Result<Self, PlacementError> {
        if !valid_certificate(&certificate) || !valid_private_key(&private_key) {
            private_key.fill(0);
            return Err(PlacementError::InvalidRequest {
                reason: "placement TLS material is invalid or unbounded",
            });
        }
        Ok(Self {
            ca_credential_id,
            certificate,
            private_key,
        })
    }
}

impl fmt::Debug for PlacementTlsMaterial {
    // Redacts TLS private material from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlacementTlsMaterial")
            .field("ca_credential_id", &self.ca_credential_id)
            .field("certificate", &"[public-certificate]")
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl Drop for PlacementTlsMaterial {
    // Clears private-key bytes before releasing their allocation.
    fn drop(&mut self) {
        self.private_key.fill(0);
    }
}

// Holds all generated secret bytes until one atomic provisioning attempt completes.
pub struct PlacementSecretMaterial {
    credential_id: CredentialId,
    engine_credential: Vec<u8>,
    tls: PlacementTlsMaterial,
}

impl PlacementSecretMaterial {
    // Creates one bounded single-line Engine credential plus TLS material.
    pub fn new(
        credential_id: CredentialId,
        mut engine_credential: Vec<u8>,
        tls: PlacementTlsMaterial,
    ) -> Result<Self, PlacementError> {
        if credential_id == tls.ca_credential_id || !valid_engine_credential(&engine_credential) {
            engine_credential.fill(0);
            return Err(PlacementError::InvalidRequest {
                reason: "placement Engine credential is invalid or unbounded",
            });
        }
        Ok(Self {
            credential_id,
            engine_credential,
            tls,
        })
    }
}

impl fmt::Debug for PlacementSecretMaterial {
    // Redacts every secret byte while retaining reference identity.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlacementSecretMaterial")
            .field("credential_id", &self.credential_id)
            .field("engine_credential", &"[redacted]")
            .field("tls", &self.tls)
            .finish()
    }
}

impl Drop for PlacementSecretMaterial {
    // Clears Engine credential bytes before releasing their allocation.
    fn drop(&mut self) {
        self.engine_credential.fill(0);
    }
}

// Generates a TLS pair without giving the credential store platform policy.
pub trait PlacementTlsMaterialProvider: Send + Sync {
    // Returns one fresh placement-scoped certificate and private key.
    fn generate(&self, placement: &Placement) -> Result<PlacementTlsMaterial, PlacementError>;
}

// Generates all secret bytes consumed by the filesystem provisioner.
pub trait PlacementSecretMaterialProvider: Send + Sync {
    // Returns one fresh internal Engine credential and TLS pair.
    fn generate(&self, placement: &Placement) -> Result<PlacementSecretMaterial, PlacementError>;
}

// Uses operating-system entropy for Engine credentials and an injected TLS generator.
pub struct RandomPlacementSecretMaterialProvider {
    tls: Arc<dyn PlacementTlsMaterialProvider>,
}

impl RandomPlacementSecretMaterialProvider {
    // Creates one secret source from the platform TLS generator.
    pub const fn new(tls: Arc<dyn PlacementTlsMaterialProvider>) -> Self {
        Self { tls }
    }
}

impl PlacementSecretMaterialProvider for RandomPlacementSecretMaterialProvider {
    // Generates independent credential identity and 256-bit Engine bearer material.
    fn generate(&self, placement: &Placement) -> Result<PlacementSecretMaterial, PlacementError> {
        let mut identity = [0_u8; 16];
        let mut credential = [0_u8; 32];
        fill(&mut identity).map_err(|_| PlacementError::ExecutionUnavailable)?;
        fill(&mut credential).map_err(|_| PlacementError::ExecutionUnavailable)?;
        let credential_id = CredentialId::parse(&hex(&identity))
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        let mut bearer = format!("li_internal_{}", hex(&credential)).into_bytes();
        identity.fill(0);
        credential.fill(0);
        let tls = match self.tls.generate(placement) {
            Ok(tls) => tls,
            Err(error) => {
                bearer.fill(0);
                return Err(error);
            }
        };
        PlacementSecretMaterial::new(credential_id, bearer, tls)
    }
}

// Defines private temporary workspace operations for shell-free TLS generation.
pub trait PlacementTlsWorkspaceIo: Send + Sync {
    // Creates or validates one private owner-only directory.
    fn ensure_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Reads one bounded generated regular file with optional owner-only mode.
    fn read_generated_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
        owner_only: bool,
    ) -> Result<Vec<u8>, PlacementError>;

    // Removes one exact workspace containing only generated certificate/key files.
    fn remove_workspace(&self, path: &Path, owner_user_id: u32) -> Result<(), PlacementError>;
}

// Performs private, no-follow TLS generation workspace operations.
#[derive(Default)]
pub struct SystemPlacementTlsWorkspaceIo;

impl PlacementTlsWorkspaceIo for SystemPlacementTlsWorkspaceIo {
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
                validate_private_directory(
                    &fs::symlink_metadata(path)
                        .map_err(|_| PlacementError::ExecutionUnavailable)?,
                    owner_user_id,
                )
            }
            Err(_) => Err(PlacementError::ExecutionUnavailable),
        }
    }

    // Reads one bounded generated file through a no-follow descriptor.
    fn read_generated_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
        owner_only: bool,
    ) -> Result<Vec<u8>, PlacementError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != owner_user_id
            || metadata.mode() & if owner_only { 0o077 } else { 0o022 } != 0
            || metadata.len() > maximum_bytes as u64
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut payload = Vec::new();
        file.take(maximum_bytes as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if payload.is_empty() || payload.len() > maximum_bytes {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(payload)
    }

    // Removes only the exact generated certificate/key pair and workspace.
    fn remove_workspace(&self, path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
        validate_private_directory(
            &fs::symlink_metadata(path).map_err(|_| PlacementError::ExecutionUnavailable)?,
            owner_user_id,
        )?;
        let mut names = Vec::new();
        for entry in fs::read_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)? {
            let entry = entry.map_err(|_| PlacementError::ExecutionUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            if !matches!(
                name.as_str(),
                TLS_STAGED_CERTIFICATE_NAME | TLS_STAGED_PRIVATE_KEY_NAME
            ) {
                return Err(PlacementError::ExecutionUnavailable);
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| PlacementError::ExecutionUnavailable)?;
            if !metadata.file_type().is_file() || metadata.uid() != owner_user_id {
                return Err(PlacementError::ExecutionUnavailable);
            }
            names.push(name);
        }
        for name in names {
            fs::remove_file(path.join(name)).map_err(|_| PlacementError::ExecutionUnavailable)?;
        }
        fs::remove_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(path.parent().ok_or(PlacementError::ExecutionUnavailable)?)
    }
}

// Generates placement TLS through fixed direct OpenSSL argv and private staging.
pub struct OpenSslPlacementTlsMaterialProvider {
    openssl: ShellFreeCommand,
    workspace_root: PathBuf,
    owner_user_id: u32,
    runner: Arc<dyn ShellFreeCommandRunner>,
    io: Arc<dyn PlacementTlsWorkspaceIo>,
    identities: Arc<dyn PlacementMaterialIdentityProvider>,
}

impl OpenSslPlacementTlsMaterialProvider {
    // Creates one OpenSSL generator from explicit command, workspace, and I/O capabilities.
    pub fn new(
        openssl: ShellFreeCommand,
        workspace_root: PathBuf,
        owner_user_id: u32,
        runner: Arc<dyn ShellFreeCommandRunner>,
        io: Arc<dyn PlacementTlsWorkspaceIo>,
        identities: Arc<dyn PlacementMaterialIdentityProvider>,
    ) -> Result<Self, PlacementError> {
        if openssl
            .executable()
            .file_name()
            .and_then(|value| value.to_str())
            != Some("openssl")
            || !openssl.arguments().is_empty()
            || openssl
                .environment()
                .iter()
                .any(|value| !value.is_core_owned())
            || !workspace_root.is_absolute()
            || workspace_root.file_name().and_then(|value| value.to_str())
                != Some(TLS_STAGING_ROOT_NAME)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "OpenSSL placement TLS configuration is invalid",
            });
        }
        Ok(Self {
            openssl,
            workspace_root,
            owner_user_id,
            runner,
            io,
            identities,
        })
    }

    // Returns one exact DNS or IP subject alternative name.
    fn subject(&self, placement: &Placement) -> Result<(String, String), PlacementError> {
        let host = placement.assignment().address().as_str();
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok((host.to_string(), format!("IP:{address}")));
        }
        if host.len() > 253
            || host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement TLS hostname is invalid",
            });
        }
        Ok((host.to_string(), format!("DNS:{host}")))
    }
}

impl PlacementTlsMaterialProvider for OpenSslPlacementTlsMaterialProvider {
    // Generates one bounded self-signed server certificate and private key.
    fn generate(&self, placement: &Placement) -> Result<PlacementTlsMaterial, PlacementError> {
        self.io
            .ensure_private_directory(&self.workspace_root, self.owner_user_id)?;
        let identity = self.identities.identity()?;
        if !is_lower_hex(&identity, 32) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let (common_name, subject_alternative_name) = self.subject(placement)?;
        let workspace = self.workspace_root.join(format!(
            ".tls.{}.{}",
            placement.placement_id().as_str(),
            identity
        ));
        self.io
            .ensure_private_directory(&workspace, self.owner_user_id)?;
        let certificate_path = workspace.join(TLS_STAGED_CERTIFICATE_NAME);
        let private_key_path = workspace.join(TLS_STAGED_PRIVATE_KEY_NAME);
        let result = (|| {
            let command = self.openssl.with_arguments(vec![
                "req".to_string(),
                "-x509".to_string(),
                "-newkey".to_string(),
                "rsa:3072".to_string(),
                "-sha256".to_string(),
                "-nodes".to_string(),
                "-days".to_string(),
                "825".to_string(),
                "-subj".to_string(),
                format!("/CN={common_name}"),
                "-addext".to_string(),
                format!("subjectAltName={subject_alternative_name},DNS:localhost,IP:127.0.0.1"),
                "-keyout".to_string(),
                private_key_path.to_string_lossy().into_owned(),
                "-out".to_string(),
                certificate_path.to_string_lossy().into_owned(),
            ])?;
            let output = self.runner.run(&command, 1024)?;
            require_command_success(output)?;
            let certificate = self.io.read_generated_file(
                &certificate_path,
                MAX_CERTIFICATE_BYTES,
                self.owner_user_id,
                false,
            )?;
            let private_key = self.io.read_generated_file(
                &private_key_path,
                MAX_PRIVATE_KEY_BYTES,
                self.owner_user_id,
                true,
            )?;
            let certificate_digest = sha256(&certificate);
            PlacementTlsMaterial::new(
                CredentialId::parse(&certificate_digest[..32])
                    .map_err(|_| PlacementError::ExecutionUnavailable)?,
                certificate,
                private_key,
            )
        })();
        let cleanup = self.io.remove_workspace(&workspace, self.owner_user_id);
        match (result, cleanup) {
            (Ok(material), Ok(())) => Ok(material),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

// Requires one command result to succeed without exposing stderr.
fn require_command_success(output: ShellFreeCommandOutput) -> Result<(), PlacementError> {
    if output.status() == 0 {
        Ok(())
    } else {
        Err(PlacementError::ExecutionUnavailable)
    }
}

// Defines atomic reference-only credential provisioning for material staging.
pub trait PlacementCredentialProvider: Send + Sync {
    // Creates or replays one exact placement-scoped credential directory.
    fn provision(
        &self,
        placement: &Placement,
    ) -> Result<PlacementCredentialProvision, PlacementError>;

    // Returns verified credential references when already provisioned.
    fn existing(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError>;

    // Removes only one exact reference-matching credential directory.
    fn remove_if_matches(
        &self,
        placement: &Placement,
        references: &PlacementCredentialReferences,
    ) -> Result<bool, PlacementError>;
}

// Reads already-provisioned placement credentials without owning mutation capabilities.
pub trait PlacementCredentialReader: Send + Sync {
    // Returns verified credential references when already provisioned.
    fn existing(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError>;
}

// Defines exact private filesystem operations for placement secret material.
pub trait PlacementSecretIo: Send + Sync {
    // Creates or validates one private owner-only directory.
    fn ensure_private_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Creates one bounded private file and syncs its directory.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError>;

    // Reads one bounded private file or reports exact absence.
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

    // Removes one exact directory containing only credential-owned files.
    fn remove_secret_directory(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, PlacementError>;
}

// Performs private, no-follow, durable placement-secret filesystem operations.
#[derive(Default)]
pub struct SystemPlacementSecretIo;

impl PlacementSecretIo for SystemPlacementSecretIo {
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
                validate_private_directory(
                    &fs::symlink_metadata(path)
                        .map_err(|_| PlacementError::ExecutionUnavailable)?,
                    owner_user_id,
                )
            }
            Err(_) => Err(PlacementError::ExecutionUnavailable),
        }
    }

    // Creates one exclusive private secret file without replacement.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if payload.is_empty() || payload.len() > MAX_PRIVATE_KEY_BYTES {
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

    // Reads one bounded private secret file through a no-follow descriptor.
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

    // Renames one complete private secret directory and syncs its parent.
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
        require_secret_file_set(source, owner_user_id)?;
        fs::rename(source, destination).map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(parent)
    }

    // Removes only the four known owner-only credential files and directory.
    fn remove_secret_directory(
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
        let entries = secret_entries(path, owner_user_id)?;
        for name in entries {
            fs::remove_file(path.join(name)).map_err(|_| PlacementError::ExecutionUnavailable)?;
        }
        fs::remove_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)?;
        sync_directory(path.parent().ok_or(PlacementError::ExecutionUnavailable)?)?;
        Ok(true)
    }
}

// Owns atomic creation, verification, replay, and exact removal of placement secrets.
pub struct FilesystemPlacementCredentialProvider {
    root: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn PlacementSecretIo>,
    material: Arc<dyn PlacementSecretMaterialProvider>,
    identities: Arc<dyn PlacementMaterialIdentityProvider>,
}

// Owns the narrow read-only placement credential boundary used by Gateway.
pub struct FilesystemPlacementCredentialReader {
    root: PathBuf,
    owner_user_id: u32,
    io: Arc<dyn PlacementSecretIo>,
}

impl FilesystemPlacementCredentialReader {
    // Creates one reader rooted at the exact private placement-secrets directory.
    pub fn new(
        root: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn PlacementSecretIo>,
    ) -> Result<Self, PlacementError> {
        if !root.is_absolute()
            || root.file_name().and_then(|value| value.to_str()) != Some(SECRET_ROOT_NAME)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement secret root is invalid",
            });
        }
        Ok(Self {
            root,
            owner_user_id,
            io,
        })
    }

    // Returns the exact final secret directory for one placement.
    fn destination(&self, placement: &Placement) -> PathBuf {
        self.root.join(placement.placement_id().as_str())
    }

    // Reads and digest-verifies one complete credential directory.
    fn read_references(
        &self,
        placement: &Placement,
        directory: &Path,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        read_credential_references(self.io.as_ref(), self.owner_user_id, placement, directory)
    }
}

impl PlacementCredentialReader for FilesystemPlacementCredentialReader {
    // Returns verified references without exposing credential or private-key bytes.
    fn existing(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        self.read_references(placement, &self.destination(placement))
    }
}

impl FilesystemPlacementCredentialProvider {
    // Creates one credential owner rooted at the exact private placement-secrets directory.
    pub fn new(
        root: PathBuf,
        owner_user_id: u32,
        io: Arc<dyn PlacementSecretIo>,
        material: Arc<dyn PlacementSecretMaterialProvider>,
        identities: Arc<dyn PlacementMaterialIdentityProvider>,
    ) -> Result<Self, PlacementError> {
        if !root.is_absolute()
            || root.file_name().and_then(|value| value.to_str()) != Some(SECRET_ROOT_NAME)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement secret root is invalid",
            });
        }
        Ok(Self {
            root,
            owner_user_id,
            io,
            material,
            identities,
        })
    }

    // Returns the exact final secret directory for one placement.
    fn destination(&self, placement: &Placement) -> PathBuf {
        self.root.join(placement.placement_id().as_str())
    }

    // Returns one unique incoming secret directory.
    fn incoming(&self, placement: &Placement, identity: &str) -> Result<PathBuf, PlacementError> {
        if !is_lower_hex(identity, 32) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(self.root.join(format!(
            ".{}.incoming.{}",
            placement.placement_id().as_str(),
            identity
        )))
    }

    // Reads and digest-verifies one complete credential directory.
    fn read_references(
        &self,
        placement: &Placement,
        directory: &Path,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        read_credential_references(self.io.as_ref(), self.owner_user_id, placement, directory)
    }
}

// Reads one complete credential directory and clears every secret buffer before returning.
fn read_credential_references(
    io: &dyn PlacementSecretIo,
    owner_user_id: u32,
    placement: &Placement,
    directory: &Path,
) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
    let metadata = io.read_private_file(
        &directory.join(METADATA_FILE_NAME),
        MAX_METADATA_BYTES,
        owner_user_id,
    )?;
    let credential = io.read_private_file(
        &directory.join(CREDENTIAL_FILE_NAME),
        MAX_CREDENTIAL_BYTES,
        owner_user_id,
    )?;
    let certificate = io.read_private_file(
        &directory.join(CERTIFICATE_FILE_NAME),
        MAX_CERTIFICATE_BYTES,
        owner_user_id,
    )?;
    let private_key = io.read_private_file(
        &directory.join(PRIVATE_KEY_FILE_NAME),
        MAX_PRIVATE_KEY_BYTES,
        owner_user_id,
    )?;
    match (metadata, credential, certificate, private_key) {
        (None, None, None, None) => Ok(None),
        (Some(metadata), Some(mut credential), Some(certificate), Some(mut private_key)) => {
            let result = (|| {
                let document: CredentialMetadataDocument = serde_json::from_slice(&metadata)
                    .map_err(|_| PlacementError::ExecutionUnavailable)?;
                credential_references_from_document(
                    placement,
                    directory,
                    document,
                    &credential,
                    &certificate,
                    &private_key,
                )
            })();
            credential.fill(0);
            private_key.fill(0);
            result.map(Some)
        }
        _ => Err(PlacementError::ExecutionUnavailable),
    }
}

impl PlacementCredentialProvider for FilesystemPlacementCredentialProvider {
    // Creates or replays one exact credential directory without returning secret bytes.
    fn provision(
        &self,
        placement: &Placement,
    ) -> Result<PlacementCredentialProvision, PlacementError> {
        self.io
            .ensure_private_directory(&self.root, self.owner_user_id)?;
        if let Some(existing) = self.read_references(placement, &self.destination(placement))? {
            return Ok(PlacementCredentialProvision::new(
                existing,
                PlacementCredentialDisposition::Existing,
            ));
        }
        let material = self.material.generate(placement)?;
        let identity = self.identities.identity()?;
        let incoming = self.incoming(placement, &identity)?;
        self.io
            .ensure_private_directory(&incoming, self.owner_user_id)?;
        let result = (|| {
            let document = credential_metadata_document(placement, &material);
            let mut metadata =
                serde_json::to_vec(&document).map_err(|_| PlacementError::ExecutionUnavailable)?;
            metadata.push(b'\n');
            self.io.write_private_file(
                &incoming.join(CREDENTIAL_FILE_NAME),
                &material.engine_credential,
                self.owner_user_id,
            )?;
            self.io.write_private_file(
                &incoming.join(CERTIFICATE_FILE_NAME),
                &material.tls.certificate,
                self.owner_user_id,
            )?;
            self.io.write_private_file(
                &incoming.join(PRIVATE_KEY_FILE_NAME),
                &material.tls.private_key,
                self.owner_user_id,
            )?;
            self.io.write_private_file(
                &incoming.join(METADATA_FILE_NAME),
                &metadata,
                self.owner_user_id,
            )?;
            self.read_references(placement, &incoming)?
                .ok_or(PlacementError::ExecutionUnavailable)?;
            match self.io.rename_private_directory(
                &incoming,
                &self.destination(placement),
                self.owner_user_id,
            ) {
                Ok(()) => Ok(PlacementCredentialProvision::new(
                    self.read_references(placement, &self.destination(placement))?
                        .ok_or(PlacementError::ExecutionUnavailable)?,
                    PlacementCredentialDisposition::Created,
                )),
                Err(_) => {
                    let winner = self
                        .read_references(placement, &self.destination(placement))?
                        .ok_or(PlacementError::ExecutionUnavailable)?;
                    self.io
                        .remove_secret_directory(&incoming, self.owner_user_id)?;
                    Ok(PlacementCredentialProvision::new(
                        winner,
                        PlacementCredentialDisposition::Existing,
                    ))
                }
            }
        })();
        if result.is_err() {
            let _ = self
                .io
                .remove_secret_directory(&incoming, self.owner_user_id);
        }
        result
    }

    // Returns verified references without exposing credential or private-key bytes.
    fn existing(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        self.read_references(placement, &self.destination(placement))
    }

    // Removes one reference-matching credential directory and rejects stale callers.
    fn remove_if_matches(
        &self,
        placement: &Placement,
        references: &PlacementCredentialReferences,
    ) -> Result<bool, PlacementError> {
        let Some(existing) = self.existing(placement)? else {
            return Ok(false);
        };
        if &existing != references {
            return Err(PlacementError::StoreConflict);
        }
        self.io
            .remove_secret_directory(&self.destination(placement), self.owner_user_id)
    }
}

// Stores only placement credential identities, filenames, and content digests.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialMetadataDocument {
    schema_name: String,
    schema_version: u16,
    placement_id: String,
    credential_id: String,
    ca_credential_id: String,
    credential_file: String,
    certificate_file: String,
    private_key_file: String,
    credential_sha256: String,
    certificate_sha256: String,
    private_key_sha256: String,
    credential_bundle_sha256: String,
}

// Projects one in-memory secret bundle into reference-only metadata.
fn credential_metadata_document(
    placement: &Placement,
    material: &PlacementSecretMaterial,
) -> CredentialMetadataDocument {
    CredentialMetadataDocument {
        schema_name: SCHEMA_NAME.to_string(),
        schema_version: SCHEMA_VERSION,
        placement_id: placement.placement_id().as_str().to_string(),
        credential_id: material.credential_id.as_str().to_string(),
        ca_credential_id: material.tls.ca_credential_id.as_str().to_string(),
        credential_file: CREDENTIAL_FILE_NAME.to_string(),
        certificate_file: CERTIFICATE_FILE_NAME.to_string(),
        private_key_file: PRIVATE_KEY_FILE_NAME.to_string(),
        credential_sha256: sha256(&material.engine_credential),
        certificate_sha256: sha256(&material.tls.certificate),
        private_key_sha256: sha256(&material.tls.private_key),
        credential_bundle_sha256: credential_bundle_sha256(
            &material.engine_credential,
            &material.tls.certificate,
            &material.tls.private_key,
        ),
    }
}

// Reconstructs references after validating every identity, filename, and secret digest.
fn credential_references_from_document(
    placement: &Placement,
    directory: &Path,
    document: CredentialMetadataDocument,
    credential: &[u8],
    certificate: &[u8],
    private_key: &[u8],
) -> Result<PlacementCredentialReferences, PlacementError> {
    if document.schema_name != SCHEMA_NAME
        || document.schema_version != SCHEMA_VERSION
        || document.placement_id != placement.placement_id().as_str()
        || document.credential_file != CREDENTIAL_FILE_NAME
        || document.certificate_file != CERTIFICATE_FILE_NAME
        || document.private_key_file != PRIVATE_KEY_FILE_NAME
        || document.credential_sha256 != sha256(credential)
        || document.certificate_sha256 != sha256(certificate)
        || document.private_key_sha256 != sha256(private_key)
        || document.credential_bundle_sha256
            != credential_bundle_sha256(credential, certificate, private_key)
        || !valid_engine_credential(credential)
        || !valid_certificate(certificate)
        || !valid_private_key(private_key)
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    PlacementCredentialReferences::new(
        placement.placement_id().clone(),
        CredentialId::parse(&document.credential_id)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        CredentialId::parse(&document.ca_credential_id)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        directory.join(CREDENTIAL_FILE_NAME),
        directory.join(CERTIFICATE_FILE_NAME),
        directory.join(PRIVATE_KEY_FILE_NAME),
        Sha256Digest::parse(&document.certificate_sha256)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
        Sha256Digest::parse(&document.credential_bundle_sha256)
            .map_err(|_| PlacementError::ExecutionUnavailable)?,
    )
}

// Returns the exact set of files permitted inside one credential directory.
fn secret_file_names() -> [&'static str; 4] {
    [
        CREDENTIAL_FILE_NAME,
        CERTIFICATE_FILE_NAME,
        PRIVATE_KEY_FILE_NAME,
        METADATA_FILE_NAME,
    ]
}

// Requires exactly four private regular files with the credential-owned names.
fn require_secret_file_set(path: &Path, owner_user_id: u32) -> Result<(), PlacementError> {
    let names = secret_entries(path, owner_user_id)?;
    let mut expected = secret_file_names().map(str::to_string).to_vec();
    expected.sort();
    if names != expected {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Returns validated known secret filenames while permitting partial rollback sets.
fn secret_entries(path: &Path, owner_user_id: u32) -> Result<Vec<String>, PlacementError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| PlacementError::ExecutionUnavailable)? {
        let entry = entry.map_err(|_| PlacementError::ExecutionUnavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| PlacementError::ExecutionUnavailable)?;
        validate_private_file(&metadata, owner_user_id, MAX_PRIVATE_KEY_BYTES)?;
        if !secret_file_names().contains(&name.as_str()) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

// Returns whether one byte sequence is a bounded PEM certificate.
fn valid_certificate(value: &[u8]) -> bool {
    value.len() <= MAX_CERTIFICATE_BYTES
        && value.starts_with(b"-----BEGIN CERTIFICATE-----\n")
        && value.ends_with(b"-----END CERTIFICATE-----\n")
}

// Returns whether one Engine credential is bounded, ASCII, and single-line.
fn valid_engine_credential(value: &[u8]) -> bool {
    (32..=MAX_CREDENTIAL_BYTES).contains(&value.len())
        && value.is_ascii()
        && !value
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

// Returns whether one byte sequence is a bounded PEM private key.
fn valid_private_key(value: &[u8]) -> bool {
    value.len() <= MAX_PRIVATE_KEY_BYTES
        && ((value.starts_with(concat!("-----BEGIN PRIVATE", " KEY-----\n").as_bytes())
            && value.ends_with(concat!("-----END PRIVATE", " KEY-----\n").as_bytes()))
            || (value.starts_with(concat!("-----BEGIN RSA PRIVATE", " KEY-----\n").as_bytes())
                && value.ends_with(concat!("-----END RSA PRIVATE", " KEY-----\n").as_bytes()))
            || (value.starts_with(concat!("-----BEGIN EC PRIVATE", " KEY-----\n").as_bytes())
                && value.ends_with(concat!("-----END EC PRIVATE", " KEY-----\n").as_bytes())))
}

// Returns the lowercase SHA-256 of one exact byte sequence.
fn sha256(value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(value);
    format!("{:x}", digest.finalize())
}

// Returns one domain-separated digest covering all placement credential bytes.
fn credential_bundle_sha256(credential: &[u8], certificate: &[u8], private_key: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"letsinfer-placement-credential-bundle-v1\0");
    for value in [credential, certificate, private_key] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

// Returns lowercase hexadecimal text for one byte sequence.
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Returns whether one string is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
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

// Syncs one secret directory after file or directory mutation.
fn sync_directory(path: &Path) -> Result<(), PlacementError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PlacementError::ExecutionUnavailable)
}
