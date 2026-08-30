// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{Sha256Digest, UnixMilliseconds};
use sha2::{Digest, Sha256};

use crate::{
    PairingCandidate, PairingContext, PairingCredentials, PairingError, PairingMaterialProvider,
    PairingMembershipState, PairingNativeCommand, PairingNativeCommandOutput,
    PairingNativeCommandRunner, PairingTrustProvider,
};

const TRUST_STAGING_ROOT_NAME: &str = "pairing_trust_staging";
const SITE_PRIVATE_KEY_NAME: &str = "li_site_private_key.pem";
const SITE_PUBLIC_KEY_NAME: &str = "li_site_public_key.pem";
const SITE_CA_CERTIFICATE_NAME: &str = "li_site_ca_certificate.pem";
const LOCAL_CONTROL_CERTIFICATE_NAME: &str = "li_local_control_certificate.pem";
const CANDIDATE_PUBLIC_KEY_NAME: &str = "li_candidate_public_key.pem";
const CANDIDATE_PUBLIC_KEY_DER_NAME: &str = "li_candidate_public_key.der";
const PROOF_SIGNATURE_NAME: &str = "li_candidate_proof.sig";
const ENROLLMENT_TRANSCRIPT_NAME: &str = "li_enrollment_transcript.bin";
const SITE_PRIVATE_PUBLIC_KEY_DER_NAME: &str = "li_site_private_public_key.der";
const SITE_PUBLIC_KEY_DER_NAME: &str = "li_site_public_key.der";
const SITE_CA_PUBLIC_KEY_NAME: &str = "li_site_ca_public_key.pem";
const SITE_CA_PUBLIC_KEY_DER_NAME: &str = "li_site_ca_public_key.der";
const SITE_CA_CERTIFICATE_DER_NAME: &str = "li_site_ca_certificate.der";
const LOCAL_CONTROL_CERTIFICATE_DER_NAME: &str = "li_local_control_certificate.der";
const MEMBER_EXTENSIONS_NAME: &str = "li_member_extensions.cnf";
const MEMBER_CERTIFICATE_NAME: &str = "li_member_certificate.pem";
const MEMBER_CERTIFICATE_PUBLIC_KEY_NAME: &str = "li_member_certificate_public_key.pem";
const MEMBER_CERTIFICATE_PUBLIC_KEY_DER_NAME: &str = "li_member_certificate_public_key.der";
const MEMBER_CERTIFICATE_DER_NAME: &str = "li_member_certificate.der";
const MEMBERSHIP_TRANSCRIPT_NAME: &str = "li_membership_transcript.bin";
const MEMBERSHIP_SIGNATURE_NAME: &str = "li_membership_signature.bin";
const MEMBERSHIP_TRANSCRIPT_DOMAIN: &[u8] = b"letsinfer-membership-v1\0";
const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 2 * 1024;
const MAX_TRANSCRIPT_BYTES: usize = 64 * 1024;
const MAX_DER_BYTES: usize = 64 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 8 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const CERTIFICATE_FRESHNESS_SECONDS: &str = "2592000";
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

// Names the complete private identity required for pairing trust issuance.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingTrustIdentityFiles {
    site_private_key: PathBuf,
    site_public_key: PathBuf,
    site_ca_certificate: PathBuf,
    local_control_certificate: PathBuf,
}

impl PairingTrustIdentityFiles {
    // Creates one unambiguous absolute identity-file set.
    pub fn new(
        site_private_key: PathBuf,
        site_public_key: PathBuf,
        site_ca_certificate: PathBuf,
        local_control_certificate: PathBuf,
    ) -> Result<Self, PairingError> {
        let paths = [
            &site_private_key,
            &site_public_key,
            &site_ca_certificate,
            &local_control_certificate,
        ];
        if paths.iter().any(|path| !is_safe_absolute_path(path))
            || paths
                .iter()
                .enumerate()
                .any(|(index, path)| paths.iter().skip(index + 1).any(|other| path == other))
        {
            return Err(PairingError::InvalidRequest {
                reason: "pairing trust identity files are unsafe or ambiguous",
            });
        }
        Ok(Self {
            site_private_key,
            site_public_key,
            site_ca_certificate,
            local_control_certificate,
        })
    }
}

impl fmt::Debug for PairingTrustIdentityFiles {
    // Redacts private identity paths from diagnostic presentation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingTrustIdentityFiles")
            .field("site_private_key", &"<redacted>")
            .field("site_public_key", &"<private-path>")
            .field("site_ca_certificate", &"<private-path>")
            .field("local_control_certificate", &"<private-path>")
            .finish()
    }
}

// Defines bounded owner-only workspace operations for pairing trust commands.
pub trait PairingTrustWorkspaceIo: Send + Sync {
    // Creates or validates the owner-only staging root.
    fn ensure_private_root(&self, path: &Path, owner_user_id: u32) -> Result<(), PairingError>;

    // Creates one new owner-only operation workspace without reusing a collision.
    fn create_private_workspace(&self, path: &Path, owner_user_id: u32)
        -> Result<(), PairingError>;

    // Writes one new bounded owner-only input file.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<(), PairingError>;

    // Creates one empty owner-only output file for a native command.
    fn create_private_output_file(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PairingError>;

    // Reads one non-empty bounded owner-only regular file without following links.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Vec<u8>, PairingError>;

    // Removes exactly one known workspace and reports whether it existed.
    fn remove_workspace(&self, path: &Path, owner_user_id: u32) -> Result<bool, PairingError>;
}

// Performs no-follow pairing trust workspace operations on Unix hosts.
#[derive(Default)]
pub struct SystemPairingTrustWorkspaceIo;

impl PairingTrustWorkspaceIo for SystemPairingTrustWorkspaceIo {
    // Creates or validates the owner-only staging root.
    fn ensure_private_root(&self, path: &Path, owner_user_id: u32) -> Result<(), PairingError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_private_directory(&metadata, owner_user_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(path)?;
                validate_private_directory(
                    &fs::symlink_metadata(path).map_err(|_| PairingError::TrustUnavailable)?,
                    owner_user_id,
                )
            }
            Err(_) => Err(PairingError::TrustUnavailable),
        }
    }

    // Creates one new owner-only operation workspace without reusing a collision.
    fn create_private_workspace(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PairingError> {
        let parent = path.parent().ok_or(PairingError::TrustUnavailable)?;
        validate_private_directory(
            &fs::symlink_metadata(parent).map_err(|_| PairingError::TrustUnavailable)?,
            owner_user_id,
        )?;
        create_private_directory(path)?;
        validate_private_directory(
            &fs::symlink_metadata(path).map_err(|_| PairingError::TrustUnavailable)?,
            owner_user_id,
        )
    }

    // Writes one new bounded owner-only input file.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<(), PairingError> {
        if payload.is_empty() || payload.len() > maximum_bytes {
            return Err(PairingError::TrustUnavailable);
        }
        validate_private_parent(path, owner_user_id)?;
        let mut file = new_private_file(path)?;
        file.write_all(payload)
            .and_then(|_| file.sync_all())
            .map_err(|_| PairingError::TrustUnavailable)?;
        sync_directory(path.parent().ok_or(PairingError::TrustUnavailable)?)
    }

    // Creates one empty owner-only output file for a native command.
    fn create_private_output_file(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), PairingError> {
        validate_private_parent(path, owner_user_id)?;
        new_private_file(path)?
            .sync_all()
            .map_err(|_| PairingError::TrustUnavailable)?;
        sync_directory(path.parent().ok_or(PairingError::TrustUnavailable)?)
    }

    // Reads one non-empty bounded owner-only regular file without following links.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        owner_user_id: u32,
    ) -> Result<Vec<u8>, PairingError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| PairingError::TrustUnavailable)?;
        validate_private_file(
            &file
                .metadata()
                .map_err(|_| PairingError::TrustUnavailable)?,
            owner_user_id,
            maximum_bytes,
        )?;
        let mut payload = Vec::new();
        file.take(maximum_bytes as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|_| PairingError::TrustUnavailable)?;
        if payload.is_empty() || payload.len() > maximum_bytes {
            return Err(PairingError::TrustUnavailable);
        }
        Ok(payload)
    }

    // Removes exactly one known workspace and reports whether it existed.
    fn remove_workspace(&self, path: &Path, owner_user_id: u32) -> Result<bool, PairingError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(PairingError::TrustUnavailable),
        };
        validate_private_directory(&metadata, owner_user_id)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(path).map_err(|_| PairingError::TrustUnavailable)? {
            let entry = entry.map_err(|_| PairingError::TrustUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PairingError::TrustUnavailable)?;
            if !is_trust_workspace_file(&name) {
                return Err(PairingError::TrustUnavailable);
            }
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| PairingError::TrustUnavailable)?;
            validate_private_file(&metadata, owner_user_id, MAX_CERTIFICATE_BYTES)?;
            entries.push(name);
        }
        for name in entries {
            fs::remove_file(path.join(name)).map_err(|_| PairingError::TrustUnavailable)?;
        }
        fs::remove_dir(path).map_err(|_| PairingError::TrustUnavailable)?;
        sync_directory(path.parent().ok_or(PairingError::TrustUnavailable)?)?;
        Ok(true)
    }
}

// Verifies P-256 possession and issues site-signed node membership credentials.
pub struct OpenSslPairingTrustProvider {
    openssl: PathBuf,
    identity_files: PairingTrustIdentityFiles,
    workspace_root: PathBuf,
    owner_user_id: u32,
    runner: Arc<dyn PairingNativeCommandRunner>,
    io: Arc<dyn PairingTrustWorkspaceIo>,
    material: Arc<dyn PairingMaterialProvider>,
}

impl OpenSslPairingTrustProvider {
    // Creates one trust provider from explicit native, identity, I/O, and entropy capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        openssl: PathBuf,
        identity_files: PairingTrustIdentityFiles,
        workspace_root: PathBuf,
        owner_user_id: u32,
        runner: Arc<dyn PairingNativeCommandRunner>,
        io: Arc<dyn PairingTrustWorkspaceIo>,
        material: Arc<dyn PairingMaterialProvider>,
    ) -> Result<Self, PairingError> {
        let identity_paths = [
            &identity_files.site_private_key,
            &identity_files.site_public_key,
            &identity_files.site_ca_certificate,
            &identity_files.local_control_certificate,
        ];
        if !is_safe_absolute_path(&openssl)
            || openssl.file_name().and_then(|value| value.to_str()) != Some("openssl")
            || !is_safe_absolute_path(&workspace_root)
            || workspace_root.file_name().and_then(|value| value.to_str())
                != Some(TRUST_STAGING_ROOT_NAME)
            || identity_paths
                .iter()
                .any(|path| path.starts_with(&workspace_root))
        {
            return Err(PairingError::InvalidRequest {
                reason: "OpenSSL pairing trust configuration is invalid",
            });
        }
        Ok(Self {
            openssl,
            identity_files,
            workspace_root,
            owner_user_id,
            runner,
            io,
            material,
        })
    }

    // Runs one trust operation in a fresh private workspace and always attempts exact cleanup.
    fn with_workspace<Value>(
        &self,
        operation: &str,
        body: impl FnOnce(&Path) -> Result<Value, PairingError>,
    ) -> Result<Value, PairingError> {
        self.io
            .ensure_private_root(&self.workspace_root, self.owner_user_id)
            .map_err(trust_error)?;
        let workspace = self.workspace_path(operation)?;
        self.io
            .create_private_workspace(&workspace, self.owner_user_id)
            .map_err(trust_error)?;
        let result = body(&workspace);
        let cleanup = self
            .io
            .remove_workspace(&workspace, self.owner_user_id)
            .map_err(trust_error)
            .and_then(|removed| removed.then_some(()).ok_or(PairingError::TrustUnavailable));
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(trust_error(error)),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    // Returns one collision-rejecting workspace identity from injected secure material.
    fn workspace_path(&self, operation: &str) -> Result<PathBuf, PairingError> {
        if !matches!(operation, "verify" | "issue") {
            return Err(PairingError::TrustUnavailable);
        }
        let mut identity = [0_u8; 16];
        self.material.fill(&mut identity).map_err(trust_error)?;
        let name = format!(".trust.{operation}.{}", hexadecimal(&identity));
        identity.fill(0);
        Ok(self.workspace_root.join(name))
    }

    // Executes one exact OpenSSL argv and rejects timeout, output overflow, and failure.
    fn run(&self, arguments: Vec<String>) -> Result<PairingNativeCommandOutput, PairingError> {
        let command =
            PairingNativeCommand::new(self.openssl.clone(), arguments).map_err(trust_error)?;
        let output = self
            .runner
            .run(&command, COMMAND_TIMEOUT, MAX_COMMAND_OUTPUT_BYTES)
            .map_err(trust_error)?;
        if output.timed_out() || output.status() != 0 {
            return Err(PairingError::TrustUnavailable);
        }
        Ok(output)
    }

    // Writes one bounded private input into an operation workspace.
    fn write(
        &self,
        workspace: &Path,
        name: &str,
        payload: &[u8],
        maximum_bytes: usize,
    ) -> Result<PathBuf, PairingError> {
        let path = workspace.join(name);
        self.io
            .write_private_file(&path, payload, maximum_bytes, self.owner_user_id)
            .map_err(trust_error)?;
        Ok(path)
    }

    // Creates one private output target inside an operation workspace.
    fn output(&self, workspace: &Path, name: &str) -> Result<PathBuf, PairingError> {
        let path = workspace.join(name);
        self.io
            .create_private_output_file(&path, self.owner_user_id)
            .map_err(trust_error)?;
        Ok(path)
    }

    // Reads one bounded private output from an operation workspace.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, PairingError> {
        self.io
            .read_private_file(path, maximum_bytes, self.owner_user_id)
            .map_err(trust_error)
    }

    // Canonicalizes and validates one exact P-256 public key.
    fn canonical_public_key(
        &self,
        workspace: &Path,
        public_key: &[u8],
    ) -> Result<(PathBuf, Vec<u8>, Sha256Digest), PairingError> {
        if !valid_public_key_pem(public_key) {
            return Err(PairingError::TrustUnavailable);
        }
        let public_key_path = self.write(
            workspace,
            CANDIDATE_PUBLIC_KEY_NAME,
            public_key,
            MAX_PUBLIC_KEY_BYTES,
        )?;
        let der_path = self.output(workspace, CANDIDATE_PUBLIC_KEY_DER_NAME)?;
        self.run(vec![
            "pkey".to_string(),
            "-pubin".to_string(),
            "-in".to_string(),
            path_argument(&public_key_path)?,
            "-outform".to_string(),
            "DER".to_string(),
            "-out".to_string(),
            path_argument(&der_path)?,
        ])?;
        let der = self.read(&der_path, MAX_DER_BYTES)?;
        if !is_p256_spki(&der) {
            return Err(PairingError::TrustUnavailable);
        }
        let fingerprint = sha256_digest(&der)?;
        Ok((public_key_path, der, fingerprint))
    }

    // Copies the configured site identity into one stable private workspace snapshot.
    fn copy_site_identity(&self, workspace: &Path) -> Result<WorkspaceSiteIdentity, PairingError> {
        let private_key = self
            .io
            .read_private_file(
                &self.identity_files.site_private_key,
                MAX_PRIVATE_KEY_BYTES,
                self.owner_user_id,
            )
            .map_err(trust_error)?;
        let public_key = self
            .io
            .read_private_file(
                &self.identity_files.site_public_key,
                MAX_PUBLIC_KEY_BYTES,
                self.owner_user_id,
            )
            .map_err(trust_error)?;
        let ca_certificate = self
            .io
            .read_private_file(
                &self.identity_files.site_ca_certificate,
                MAX_CERTIFICATE_BYTES,
                self.owner_user_id,
            )
            .map_err(trust_error)?;
        let local_control_certificate = self
            .io
            .read_private_file(
                &self.identity_files.local_control_certificate,
                MAX_CERTIFICATE_BYTES,
                self.owner_user_id,
            )
            .map_err(trust_error)?;
        if !valid_private_key_pem(&private_key)
            || !valid_public_key_pem(&public_key)
            || !valid_certificate_pem(&ca_certificate)
            || !valid_certificate_pem(&local_control_certificate)
        {
            return Err(PairingError::TrustUnavailable);
        }
        Ok(WorkspaceSiteIdentity {
            private_key: self.write(
                workspace,
                SITE_PRIVATE_KEY_NAME,
                &private_key,
                MAX_PRIVATE_KEY_BYTES,
            )?,
            public_key: self.write(
                workspace,
                SITE_PUBLIC_KEY_NAME,
                &public_key,
                MAX_PUBLIC_KEY_BYTES,
            )?,
            ca_certificate: self.write(
                workspace,
                SITE_CA_CERTIFICATE_NAME,
                &ca_certificate,
                MAX_CERTIFICATE_BYTES,
            )?,
            local_control_certificate: self.write(
                workspace,
                LOCAL_CONTROL_CERTIFICATE_NAME,
                &local_control_certificate,
                MAX_CERTIFICATE_BYTES,
            )?,
            public_key_bytes: public_key,
            ca_certificate_bytes: ca_certificate,
        })
    }

    // Proves the copied signing key, public key, CA, and pinned control certificate identities.
    fn validate_site_identity(
        &self,
        workspace: &Path,
        identity: &WorkspaceSiteIdentity,
        context: &PairingContext,
    ) -> Result<(), PairingError> {
        let site_public_der_path = self.output(workspace, SITE_PUBLIC_KEY_DER_NAME)?;
        self.pkey_der(&identity.public_key, true, &site_public_der_path)?;
        let site_public_der = self.read(&site_public_der_path, MAX_DER_BYTES)?;
        if !is_p256_spki(&site_public_der)
            || &sha256_digest(&site_public_der)? != context.public_key_fingerprint()
        {
            return Err(PairingError::TrustUnavailable);
        }

        let private_public_der_path = self.output(workspace, SITE_PRIVATE_PUBLIC_KEY_DER_NAME)?;
        self.pkey_der(&identity.private_key, false, &private_public_der_path)?;
        if self.read(&private_public_der_path, MAX_DER_BYTES)? != site_public_der {
            return Err(PairingError::TrustUnavailable);
        }

        let ca_public_path = self.output(workspace, SITE_CA_PUBLIC_KEY_NAME)?;
        self.run(vec![
            "x509".to_string(),
            "-in".to_string(),
            path_argument(&identity.ca_certificate)?,
            "-noout".to_string(),
            "-pubkey".to_string(),
            "-out".to_string(),
            path_argument(&ca_public_path)?,
        ])?;
        let ca_public_der_path = self.output(workspace, SITE_CA_PUBLIC_KEY_DER_NAME)?;
        self.pkey_der(&ca_public_path, true, &ca_public_der_path)?;
        if self.read(&ca_public_der_path, MAX_DER_BYTES)? != site_public_der {
            return Err(PairingError::TrustUnavailable);
        }

        self.verify_certificate(&identity.ca_certificate, &identity.ca_certificate, None)?;
        let ca_der_path = self.output(workspace, SITE_CA_CERTIFICATE_DER_NAME)?;
        self.certificate_der(&identity.ca_certificate, &ca_der_path)?;
        let _ = self.read(&ca_der_path, MAX_DER_BYTES)?;

        self.verify_certificate(
            &identity.local_control_certificate,
            &identity.ca_certificate,
            Some("sslserver"),
        )?;
        self.verify_certificate(
            &identity.local_control_certificate,
            &identity.ca_certificate,
            Some("sslclient"),
        )?;
        let local_der_path = self.output(workspace, LOCAL_CONTROL_CERTIFICATE_DER_NAME)?;
        self.certificate_der(&identity.local_control_certificate, &local_der_path)?;
        if &sha256_digest(&self.read(&local_der_path, MAX_DER_BYTES)?)?
            != context.certificate_fingerprint()
        {
            return Err(PairingError::TrustUnavailable);
        }
        Ok(())
    }

    // Converts one public or private key to canonical public SPKI DER.
    fn pkey_der(&self, source: &Path, public: bool, output: &Path) -> Result<(), PairingError> {
        let mut arguments = vec!["pkey".to_string()];
        if public {
            arguments.push("-pubin".to_string());
        }
        arguments.extend([
            "-in".to_string(),
            path_argument(source)?,
            "-pubout".to_string(),
            "-outform".to_string(),
            "DER".to_string(),
            "-out".to_string(),
            path_argument(output)?,
        ]);
        self.run(arguments).map(|_| ())
    }

    // Converts one certificate to canonical DER bytes.
    fn certificate_der(&self, certificate: &Path, output: &Path) -> Result<(), PairingError> {
        self.run(vec![
            "x509".to_string(),
            "-in".to_string(),
            path_argument(certificate)?,
            "-outform".to_string(),
            "DER".to_string(),
            "-out".to_string(),
            path_argument(output)?,
        ])
        .map(|_| ())
    }

    // Verifies one certificate against an exact CA, optional purpose, and freshness horizon.
    fn verify_certificate(
        &self,
        certificate: &Path,
        ca_certificate: &Path,
        purpose: Option<&str>,
    ) -> Result<(), PairingError> {
        let mut arguments = vec!["verify".to_string()];
        if let Some(purpose) = purpose {
            arguments.extend(["-purpose".to_string(), purpose.to_string()]);
        }
        arguments.extend([
            "-CAfile".to_string(),
            path_argument(ca_certificate)?,
            path_argument(certificate)?,
        ]);
        self.run(arguments)?;
        self.run(vec![
            "x509".to_string(),
            "-in".to_string(),
            path_argument(certificate)?,
            "-noout".to_string(),
            "-checkend".to_string(),
            CERTIFICATE_FRESHNESS_SECONDS.to_string(),
        ])?;
        Ok(())
    }
}

impl PairingTrustProvider for OpenSslPairingTrustProvider {
    // Verifies the exact enrollment transcript with one canonical P-256 candidate key.
    fn verify_candidate(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        if transcript.is_empty()
            || transcript.len() > MAX_TRANSCRIPT_BYTES
            || signature.is_empty()
            || signature.len() > MAX_SIGNATURE_BYTES
        {
            return Err(PairingError::TrustUnavailable);
        }
        self.with_workspace("verify", |workspace| {
            let (public_key_path, _, fingerprint) =
                self.canonical_public_key(workspace, public_key)?;
            let signature_path = self.write(
                workspace,
                PROOF_SIGNATURE_NAME,
                signature,
                MAX_SIGNATURE_BYTES,
            )?;
            let transcript_path = self.write(
                workspace,
                ENROLLMENT_TRANSCRIPT_NAME,
                transcript,
                MAX_TRANSCRIPT_BYTES,
            )?;
            self.run(vec![
                "dgst".to_string(),
                "-sha256".to_string(),
                "-verify".to_string(),
                path_argument(&public_key_path)?,
                "-signature".to_string(),
                path_argument(&signature_path)?,
                path_argument(&transcript_path)?,
            ])?;
            Ok(fingerprint)
        })
    }

    // Issues one validated certificate and site signature for manager-selected membership state.
    fn issue_membership(
        &self,
        context: &PairingContext,
        candidate: &PairingCandidate,
        public_key_fingerprint: &Sha256Digest,
        state: PairingMembershipState,
        approval_expires_at: Option<UnixMilliseconds>,
    ) -> Result<PairingCredentials, PairingError> {
        self.with_workspace("issue", |workspace| {
            let (candidate_public_key_path, candidate_der, observed_fingerprint) =
                self.canonical_public_key(workspace, candidate.public_key())?;
            if &observed_fingerprint != public_key_fingerprint {
                return Err(PairingError::TrustUnavailable);
            }
            let site_identity = self.copy_site_identity(workspace)?;
            self.validate_site_identity(workspace, &site_identity, context)?;

            let extensions = member_extensions(candidate);
            let extensions_path = self.write(
                workspace,
                MEMBER_EXTENSIONS_NAME,
                extensions.as_bytes(),
                MAX_TRANSCRIPT_BYTES,
            )?;
            let member_certificate_path = self.output(workspace, MEMBER_CERTIFICATE_NAME)?;
            let mut serial = [0_u8; 20];
            self.material.fill(&mut serial).map_err(trust_error)?;
            if serial.iter().all(|byte| *byte == 0) {
                serial.fill(0);
                return Err(PairingError::TrustUnavailable);
            }
            let serial_argument = format!("0x{}", hexadecimal(&serial));
            serial.fill(0);
            self.run(vec![
                "x509".to_string(),
                "-new".to_string(),
                "-force_pubkey".to_string(),
                path_argument(&candidate_public_key_path)?,
                "-subj".to_string(),
                format!(
                    "/CN=Let's Infer node {}",
                    candidate.identity().node_id().as_str()
                ),
                "-CA".to_string(),
                path_argument(&site_identity.ca_certificate)?,
                "-CAkey".to_string(),
                path_argument(&site_identity.private_key)?,
                "-set_serial".to_string(),
                serial_argument,
                "-days".to_string(),
                "36500".to_string(),
                "-sha256".to_string(),
                "-extfile".to_string(),
                path_argument(&extensions_path)?,
                "-out".to_string(),
                path_argument(&member_certificate_path)?,
            ])?;
            self.verify_certificate(
                &member_certificate_path,
                &site_identity.ca_certificate,
                Some("sslserver"),
            )?;
            self.verify_certificate(
                &member_certificate_path,
                &site_identity.ca_certificate,
                Some("sslclient"),
            )?;

            let member_public_path = self.output(workspace, MEMBER_CERTIFICATE_PUBLIC_KEY_NAME)?;
            self.run(vec![
                "x509".to_string(),
                "-in".to_string(),
                path_argument(&member_certificate_path)?,
                "-noout".to_string(),
                "-pubkey".to_string(),
                "-out".to_string(),
                path_argument(&member_public_path)?,
            ])?;
            let member_public_der_path =
                self.output(workspace, MEMBER_CERTIFICATE_PUBLIC_KEY_DER_NAME)?;
            self.pkey_der(&member_public_path, true, &member_public_der_path)?;
            if self.read(&member_public_der_path, MAX_DER_BYTES)? != candidate_der {
                return Err(PairingError::TrustUnavailable);
            }

            let extension_output = self.run(vec![
                "x509".to_string(),
                "-in".to_string(),
                path_argument(&member_certificate_path)?,
                "-noout".to_string(),
                "-ext".to_string(),
                "subjectAltName".to_string(),
            ])?;
            let expected_uri = format!(
                "URI:urn:letsinfer:node:{}",
                candidate.identity().node_id().as_str()
            );
            if !certificate_has_uri(extension_output.stdout(), &expected_uri) {
                return Err(PairingError::TrustUnavailable);
            }

            let member_der_path = self.output(workspace, MEMBER_CERTIFICATE_DER_NAME)?;
            self.certificate_der(&member_certificate_path, &member_der_path)?;
            let certificate_fingerprint =
                sha256_digest(&self.read(&member_der_path, MAX_DER_BYTES)?)?;
            let certificate_validity_output = self.run(vec![
                "x509".to_string(),
                "-in".to_string(),
                path_argument(&member_certificate_path)?,
                "-noout".to_string(),
                "-startdate".to_string(),
                "-enddate".to_string(),
            ])?;
            let (member_valid_from, member_expires_at) =
                certificate_validity(certificate_validity_output.stdout())?;
            let member_certificate = self.read(&member_certificate_path, MAX_CERTIFICATE_BYTES)?;
            if !valid_certificate_pem(&member_certificate) {
                return Err(PairingError::TrustUnavailable);
            }

            let membership_transcript = pairing_membership_transcript(
                context,
                candidate,
                public_key_fingerprint,
                &certificate_fingerprint,
                state,
                approval_expires_at,
            );
            let membership_path = self.write(
                workspace,
                MEMBERSHIP_TRANSCRIPT_NAME,
                &membership_transcript,
                MAX_TRANSCRIPT_BYTES,
            )?;
            let membership_signature_path = self.output(workspace, MEMBERSHIP_SIGNATURE_NAME)?;
            self.run(vec![
                "dgst".to_string(),
                "-sha256".to_string(),
                "-sign".to_string(),
                path_argument(&site_identity.private_key)?,
                "-out".to_string(),
                path_argument(&membership_signature_path)?,
                path_argument(&membership_path)?,
            ])?;
            let membership_signature =
                self.read(&membership_signature_path, MAX_SIGNATURE_BYTES)?;
            PairingCredentials::new(
                site_identity.public_key_bytes,
                site_identity.ca_certificate_bytes,
                member_certificate,
                membership_signature,
                certificate_fingerprint,
                member_valid_from,
                member_expires_at,
            )
            .map_err(trust_error)
        })
    }
}

// Holds a private snapshot of the exact site identity used by one issuance.
struct WorkspaceSiteIdentity {
    private_key: PathBuf,
    public_key: PathBuf,
    ca_certificate: PathBuf,
    local_control_certificate: PathBuf,
    public_key_bytes: Vec<u8>,
    ca_certificate_bytes: Vec<u8>,
}

// Returns certificate extensions binding one exact child-node identity.
fn member_extensions(candidate: &PairingCandidate) -> String {
    format!(
        "basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth,clientAuth\n\
         subjectAltName=URI:urn:letsinfer:node:{}\n",
        candidate.identity().node_id().as_str()
    )
}

// Returns the canonical membership bytes signed by the site authority.
pub fn pairing_membership_transcript(
    context: &PairingContext,
    candidate: &PairingCandidate,
    public_key_fingerprint: &Sha256Digest,
    certificate_fingerprint: &Sha256Digest,
    state: PairingMembershipState,
    approval_expires_at: Option<UnixMilliseconds>,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    append_field(&mut transcript, MEMBERSHIP_TRANSCRIPT_DOMAIN);
    append_field(
        &mut transcript,
        context.identity().node_id().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        context.identity().machine_id().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        context.identity().installation_id().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        context.control_address().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        &context.private_control_port().to_be_bytes(),
    );
    append_field(
        &mut transcript,
        context.public_key_fingerprint().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        context.certificate_fingerprint().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        candidate.identity().node_id().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        candidate.identity().machine_id().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        candidate.identity().installation_id().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        candidate.display_name().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        candidate.control_address().as_str().as_bytes(),
    );
    append_field(
        &mut transcript,
        &candidate.installation_created_at().value().to_be_bytes(),
    );
    append_field(&mut transcript, public_key_fingerprint.as_str().as_bytes());
    append_field(&mut transcript, certificate_fingerprint.as_str().as_bytes());
    append_field(
        &mut transcript,
        match state {
            PairingMembershipState::Active => b"active",
            PairingMembershipState::PendingApproval => b"pending",
        },
    );
    match approval_expires_at {
        Some(expires_at) => {
            append_field(&mut transcript, b"1");
            append_field(&mut transcript, &expires_at.value().to_be_bytes());
        }
        None => append_field(&mut transcript, b"0"),
    }
    transcript
}

// Adds one length-delimited value to a canonical trust transcript.
fn append_field(transcript: &mut Vec<u8>, value: &[u8]) {
    transcript.extend_from_slice(&(value.len() as u64).to_be_bytes());
    transcript.extend_from_slice(value);
}

// Returns whether OpenSSL reported the exact expected URI SAN token.
fn certificate_has_uri(output: &[u8], expected_uri: &str) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };
    output
        .split([',', '\n'])
        .map(str::trim)
        .any(|value| value == expected_uri)
}

// Parses the exact bounded OpenSSL validity document without using locale-sensitive defaults.
fn certificate_validity(
    output: &[u8],
) -> Result<(UnixMilliseconds, UnixMilliseconds), PairingError> {
    let output = std::str::from_utf8(output).map_err(trust_error)?;
    let mut valid_from = None;
    let mut expires_at = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("notBefore=") {
            if valid_from.replace(certificate_time(value)?).is_some() {
                return Err(PairingError::TrustUnavailable);
            }
        } else if let Some(value) = line.strip_prefix("notAfter=") {
            if expires_at.replace(certificate_time(value)?).is_some() {
                return Err(PairingError::TrustUnavailable);
            }
        } else if !line.trim().is_empty() {
            return Err(PairingError::TrustUnavailable);
        }
    }
    let valid_from = valid_from.ok_or(PairingError::TrustUnavailable)?;
    let expires_at = expires_at.ok_or(PairingError::TrustUnavailable)?;
    if expires_at <= valid_from {
        return Err(PairingError::TrustUnavailable);
    }
    Ok((valid_from, expires_at))
}

// Converts OpenSSL's fixed English UTC certificate timestamp to Unix milliseconds.
fn certificate_time(value: &str) -> Result<UnixMilliseconds, PairingError> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 5 || parts[4] != "GMT" {
        return Err(PairingError::TrustUnavailable);
    }
    let month = certificate_month(parts[0])?;
    let day = decimal_time_value(parts[1], 1, 31)?;
    let clock: Vec<&str> = parts[2].split(':').collect();
    if clock.len() != 3 {
        return Err(PairingError::TrustUnavailable);
    }
    let hour = decimal_time_value(clock[0], 0, 23)?;
    let minute = decimal_time_value(clock[1], 0, 59)?;
    let second = decimal_time_value(clock[2], 0, 59)?;
    let year = decimal_time_value(parts[3], 1970, 9999)?;
    let days_in_month = certificate_month_days(year, month);
    if day > days_in_month {
        return Err(PairingError::TrustUnavailable);
    }
    let prior_year_days: u64 = (1970..year)
        .map(|current| if is_leap_year(current) { 366_u64 } else { 365 })
        .sum();
    let prior_month_days: u64 = (1..month)
        .map(|current| u64::from(certificate_month_days(year, current)))
        .sum();
    let days = prior_year_days
        .checked_add(prior_month_days)
        .and_then(|value| value.checked_add(u64::from(day - 1)))
        .ok_or(PairingError::TrustUnavailable)?;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(u64::from(hour) * 3_600))
        .and_then(|value| value.checked_add(u64::from(minute) * 60))
        .and_then(|value| value.checked_add(u64::from(second)))
        .ok_or(PairingError::TrustUnavailable)?;
    seconds
        .checked_mul(1_000)
        .map(UnixMilliseconds::new)
        .ok_or(PairingError::TrustUnavailable)
}

// Maps OpenSSL's fixed English month token to its calendar index.
fn certificate_month(value: &str) -> Result<u32, PairingError> {
    match value {
        "Jan" => Ok(1),
        "Feb" => Ok(2),
        "Mar" => Ok(3),
        "Apr" => Ok(4),
        "May" => Ok(5),
        "Jun" => Ok(6),
        "Jul" => Ok(7),
        "Aug" => Ok(8),
        "Sep" => Ok(9),
        "Oct" => Ok(10),
        "Nov" => Ok(11),
        "Dec" => Ok(12),
        _ => Err(PairingError::TrustUnavailable),
    }
}

// Parses one unsigned decimal time field inside an exact inclusive bound.
fn decimal_time_value(value: &str, minimum: u32, maximum: u32) -> Result<u32, PairingError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PairingError::TrustUnavailable);
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| PairingError::TrustUnavailable)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(PairingError::TrustUnavailable);
    }
    Ok(value)
}

// Returns the exact number of days in one validated calendar month.
fn certificate_month_days(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Returns Gregorian leap-year membership for certificate UTC conversion.
fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

// Returns a validated lowercase SHA-256 identity for exact bytes.
fn sha256_digest(payload: &[u8]) -> Result<Sha256Digest, PairingError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(payload))).map_err(trust_error)
}

// Requires one canonical uncompressed P-256 SubjectPublicKeyInfo document.
fn is_p256_spki(payload: &[u8]) -> bool {
    payload.len() == 91 && payload.starts_with(P256_SPKI_PREFIX)
}

// Requires one bounded ASCII PEM public key envelope.
fn valid_public_key_pem(payload: &[u8]) -> bool {
    valid_pem(
        payload,
        b"-----BEGIN PUBLIC KEY-----",
        b"-----END PUBLIC KEY-----",
        MAX_PUBLIC_KEY_BYTES,
    )
}

// Requires one bounded ASCII PKCS#8 or legacy EC private key envelope.
fn valid_private_key_pem(payload: &[u8]) -> bool {
    let private_begin = [b"-----BEGIN ".as_slice(), b"PRIVATE KEY-----"].concat();
    let private_end = [b"-----END ".as_slice(), b"PRIVATE KEY-----"].concat();
    let legacy_begin = [b"-----BEGIN EC ".as_slice(), b"PRIVATE KEY-----"].concat();
    let legacy_end = [b"-----END EC ".as_slice(), b"PRIVATE KEY-----"].concat();
    valid_pem(payload, &private_begin, &private_end, MAX_PRIVATE_KEY_BYTES)
        || valid_pem(payload, &legacy_begin, &legacy_end, MAX_PRIVATE_KEY_BYTES)
}

// Requires one bounded ASCII PEM certificate envelope.
fn valid_certificate_pem(payload: &[u8]) -> bool {
    valid_pem(
        payload,
        b"-----BEGIN CERTIFICATE-----",
        b"-----END CERTIFICATE-----",
        MAX_CERTIFICATE_BYTES,
    )
}

// Requires one exact bounded ASCII PEM envelope without NUL or carriage returns.
fn valid_pem(payload: &[u8], begin: &[u8], end: &[u8], maximum_bytes: usize) -> bool {
    if payload.is_empty()
        || payload.len() > maximum_bytes
        || payload.contains(&0)
        || payload.contains(&b'\r')
        || !payload.is_ascii()
    {
        return false;
    }
    let trimmed = trim_ascii_whitespace(payload);
    trimmed.starts_with(begin) && trimmed.ends_with(end)
}

// Removes only outer ASCII whitespace from one public textual credential.
fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

// Returns an exact UTF-8 path argument without lossy conversion.
fn path_argument(path: &Path) -> Result<String, PairingError> {
    path.to_str()
        .map(str::to_string)
        .ok_or(PairingError::TrustUnavailable)
}

// Converts random bytes to lowercase hexadecimal workspace or serial text.
fn hexadecimal(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

// Redacts every external trust failure to the stable trust boundary.
fn trust_error(_: impl Sized) -> PairingError {
    PairingError::TrustUnavailable
}

// Returns whether one native path is absolute and contains no traversal component.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

// Creates one directory with owner-only permissions from its first visible instant.
fn create_private_directory(path: &Path) -> Result<(), PairingError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|_| PairingError::TrustUnavailable)
}

// Creates one owner-only no-follow regular file without replacing existing state.
fn new_private_file(path: &Path) -> Result<File, PairingError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| PairingError::TrustUnavailable)
}

// Requires one file parent to be an exact owner-only regular directory.
fn validate_private_parent(path: &Path, owner_user_id: u32) -> Result<(), PairingError> {
    validate_private_directory(
        &fs::symlink_metadata(path.parent().ok_or(PairingError::TrustUnavailable)?)
            .map_err(|_| PairingError::TrustUnavailable)?,
        owner_user_id,
    )
}

// Requires one exact owner-only directory without links or special file types.
fn validate_private_directory(
    metadata: &fs::Metadata,
    owner_user_id: u32,
) -> Result<(), PairingError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o077 != 0
    {
        return Err(PairingError::TrustUnavailable);
    }
    Ok(())
}

// Requires one owner-only bounded regular file without accepting empty output policy.
fn validate_private_file(
    metadata: &fs::Metadata,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), PairingError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(PairingError::TrustUnavailable);
    }
    Ok(())
}

// Flushes one directory after workspace creation, file creation, or removal.
fn sync_directory(path: &Path) -> Result<(), PairingError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| PairingError::TrustUnavailable)
}

// Returns whether one workspace file belongs exclusively to this trust provider.
fn is_trust_workspace_file(name: &str) -> bool {
    matches!(
        name,
        SITE_PRIVATE_KEY_NAME
            | SITE_PUBLIC_KEY_NAME
            | SITE_CA_CERTIFICATE_NAME
            | LOCAL_CONTROL_CERTIFICATE_NAME
            | CANDIDATE_PUBLIC_KEY_NAME
            | CANDIDATE_PUBLIC_KEY_DER_NAME
            | PROOF_SIGNATURE_NAME
            | ENROLLMENT_TRANSCRIPT_NAME
            | SITE_PRIVATE_PUBLIC_KEY_DER_NAME
            | SITE_PUBLIC_KEY_DER_NAME
            | SITE_CA_PUBLIC_KEY_NAME
            | SITE_CA_PUBLIC_KEY_DER_NAME
            | SITE_CA_CERTIFICATE_DER_NAME
            | LOCAL_CONTROL_CERTIFICATE_DER_NAME
            | MEMBER_EXTENSIONS_NAME
            | MEMBER_CERTIFICATE_NAME
            | MEMBER_CERTIFICATE_PUBLIC_KEY_NAME
            | MEMBER_CERTIFICATE_PUBLIC_KEY_DER_NAME
            | MEMBER_CERTIFICATE_DER_NAME
            | MEMBERSHIP_TRANSCRIPT_NAME
            | MEMBERSHIP_SIGNATURE_NAME
    )
}
