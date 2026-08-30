// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::{
    PairingError, PairingMaterialProvider, PairingNativeCommand, PairingNativeCommandRunner,
    PairingTrustWorkspaceIo,
};

const CANDIDATE_STAGING_ROOT_NAME: &str = "pairing_candidate_staging";
const PUBLIC_KEY_NAME: &str = "li_candidate_public_key.pem";
const PUBLIC_KEY_DER_NAME: &str = "li_candidate_public_key.der";
const TRANSCRIPT_NAME: &str = "li_candidate_transcript.bin";
const SIGNATURE_NAME: &str = "li_candidate_transcript.sig";
const AUTHORITY_CERTIFICATE_NAME: &str = "li_main_ca_certificate.pem";
const MEMBER_CERTIFICATE_NAME: &str = "li_child_certificate.pem";
const MEMBER_PUBLIC_KEY_NAME: &str = "li_child_public_key.pem";
const MEMBER_PUBLIC_KEY_DER_NAME: &str = "li_child_public_key.der";
const MEMBER_CERTIFICATE_DER_NAME: &str = "li_child_certificate.der";
const MAXIMUM_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const MAXIMUM_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAXIMUM_TRANSCRIPT_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 2 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

// Binds candidate possession proof to existing owner-only local identity files.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingCandidateIdentityFiles {
    private_key: PathBuf,
    public_key: PathBuf,
}

impl PairingCandidateIdentityFiles {
    // Creates one distinct absolute local key pair without discovering identity paths.
    pub fn new(private_key: PathBuf, public_key: PathBuf) -> Result<Self, PairingError> {
        if !is_safe_absolute_path(&private_key)
            || !is_safe_absolute_path(&public_key)
            || private_key == public_key
        {
            return Err(PairingError::InvalidRequest {
                reason: "candidate identity files are unsafe or ambiguous",
            });
        }
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

impl fmt::Debug for PairingCandidateIdentityFiles {
    // Redacts the private identity path and keeps the public path private to composition.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCandidateIdentityFiles")
            .field("private_key", &"<redacted>")
            .field("public_key", &"<private-path>")
            .finish()
    }
}

// Returns canonical local public identity and possession signatures for candidate workflows.
pub trait PairingCandidateTrustProvider: Send + Sync {
    // Reads and canonicalizes the exact existing local public key.
    fn public_key(&self) -> Result<(Vec<u8>, Sha256Digest), PairingError>;

    // Signs one bounded canonical transcript using the existing owner-only local private key.
    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>, PairingError>;

    // Verifies one bounded transcript and returns the canonical public-key fingerprint.
    fn verify(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError>;

    // Verifies the issued child certificate against the exact main CA and local candidate key.
    fn verify_membership_certificate(
        &self,
        candidate_public_key: &[u8],
        main_ca_certificate: &[u8],
        child_certificate: &[u8],
        expected_child_leaf_sha256: &Sha256Digest,
    ) -> Result<(), PairingError>;
}

// Uses shell-free OpenSSL commands and owner-only workspaces for candidate proof operations.
pub struct OpenSslPairingCandidateTrustProvider {
    openssl: PathBuf,
    identity: PairingCandidateIdentityFiles,
    workspace_root: PathBuf,
    owner_user_id: u32,
    runner: Arc<dyn PairingNativeCommandRunner>,
    io: Arc<dyn PairingTrustWorkspaceIo>,
    material: Arc<dyn PairingMaterialProvider>,
}

impl OpenSslPairingCandidateTrustProvider {
    // Creates one provider from explicit native, identity, storage, and entropy capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        openssl: PathBuf,
        identity: PairingCandidateIdentityFiles,
        workspace_root: PathBuf,
        owner_user_id: u32,
        runner: Arc<dyn PairingNativeCommandRunner>,
        io: Arc<dyn PairingTrustWorkspaceIo>,
        material: Arc<dyn PairingMaterialProvider>,
    ) -> Result<Self, PairingError> {
        if !is_safe_absolute_path(&openssl)
            || openssl.file_name().and_then(|value| value.to_str()) != Some("openssl")
            || !is_safe_absolute_path(&workspace_root)
            || workspace_root.file_name().and_then(|value| value.to_str())
                != Some(CANDIDATE_STAGING_ROOT_NAME)
            || identity.private_key.starts_with(&workspace_root)
            || identity.public_key.starts_with(&workspace_root)
        {
            return Err(PairingError::InvalidRequest {
                reason: "OpenSSL candidate trust configuration is invalid",
            });
        }
        Ok(Self {
            openssl,
            identity,
            workspace_root,
            owner_user_id,
            runner,
            io,
            material,
        })
    }

    // Runs one proof operation in a fresh owner-only workspace and always attempts cleanup.
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

    // Creates one collision-resistant workspace name from injected secure material.
    fn workspace_path(&self, operation: &str) -> Result<PathBuf, PairingError> {
        if operation.is_empty()
            || operation.len() > 32
            || !operation
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(PairingError::TrustUnavailable);
        }
        let mut nonce = [0_u8; 16];
        self.material.fill(&mut nonce).map_err(trust_error)?;
        let name = format!("{operation}_{}", hexadecimal(&nonce));
        nonce.fill(0);
        Ok(self.workspace_root.join(name))
    }

    // Writes one bounded private input file into the current workspace.
    fn write(
        &self,
        workspace: &Path,
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<PathBuf, PairingError> {
        let path = workspace.join(name);
        self.io
            .write_private_file(&path, bytes, maximum_bytes, self.owner_user_id)
            .map_err(trust_error)?;
        Ok(path)
    }

    // Creates one owner-only output path before granting it to OpenSSL.
    fn output(&self, workspace: &Path, name: &str) -> Result<PathBuf, PairingError> {
        let path = workspace.join(name);
        self.io
            .create_private_output_file(&path, self.owner_user_id)
            .map_err(trust_error)?;
        Ok(path)
    }

    // Reads one bounded owner-only workspace output.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, PairingError> {
        self.io
            .read_private_file(path, maximum_bytes, self.owner_user_id)
            .map_err(trust_error)
    }

    // Runs one exact shell-free OpenSSL operation under fixed time and output bounds.
    fn run(&self, arguments: Vec<String>) -> Result<(), PairingError> {
        let command = PairingNativeCommand::new(self.openssl.clone(), arguments)?;
        let output = self.runner.run(&command, COMMAND_TIMEOUT, 8 * 1024)?;
        if output.timed_out() || output.status() != 0 {
            return Err(PairingError::TrustUnavailable);
        }
        Ok(())
    }

    // Converts one public key file to canonical SPKI DER.
    fn public_key_der(&self, source: &Path, output: &Path) -> Result<(), PairingError> {
        self.run(vec![
            "pkey".to_string(),
            "-pubin".to_string(),
            "-in".to_string(),
            path_argument(source)?,
            "-pubout".to_string(),
            "-outform".to_string(),
            "DER".to_string(),
            "-out".to_string(),
            path_argument(output)?,
        ])
    }

    // Canonicalizes one supplied public key and returns its exact fingerprint.
    fn canonical_public_key(
        &self,
        workspace: &Path,
        bytes: &[u8],
    ) -> Result<(PathBuf, Sha256Digest), PairingError> {
        if !(128..=MAXIMUM_PUBLIC_KEY_BYTES).contains(&bytes.len()) {
            return Err(PairingError::TrustUnavailable);
        }
        let public_key = self.write(workspace, PUBLIC_KEY_NAME, bytes, MAXIMUM_PUBLIC_KEY_BYTES)?;
        let der = self.output(workspace, PUBLIC_KEY_DER_NAME)?;
        self.public_key_der(&public_key, &der)?;
        let fingerprint = digest(&self.read(&der, MAXIMUM_PUBLIC_KEY_BYTES)?)?;
        Ok((public_key, fingerprint))
    }
}

impl PairingCandidateTrustProvider for OpenSslPairingCandidateTrustProvider {
    // Reads and canonicalizes the owner-only existing public key.
    fn public_key(&self) -> Result<(Vec<u8>, Sha256Digest), PairingError> {
        let public_key = self
            .io
            .read_private_file(
                &self.identity.public_key,
                MAXIMUM_PUBLIC_KEY_BYTES,
                self.owner_user_id,
            )
            .map_err(trust_error)?;
        self.with_workspace("public_key", |workspace| {
            let (_, fingerprint) = self.canonical_public_key(workspace, &public_key)?;
            Ok((public_key, fingerprint))
        })
    }

    // Signs one exact bounded transcript using the existing owner-only private key.
    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>, PairingError> {
        if transcript.is_empty() || transcript.len() > MAXIMUM_TRANSCRIPT_BYTES {
            return Err(PairingError::TrustUnavailable);
        }
        self.io
            .read_private_file(
                &self.identity.private_key,
                MAXIMUM_PRIVATE_KEY_BYTES,
                self.owner_user_id,
            )
            .map_err(trust_error)?;
        self.with_workspace("sign", |workspace| {
            let transcript = self.write(
                workspace,
                TRANSCRIPT_NAME,
                transcript,
                MAXIMUM_TRANSCRIPT_BYTES,
            )?;
            let signature = self.output(workspace, SIGNATURE_NAME)?;
            self.run(vec![
                "dgst".to_string(),
                "-sha256".to_string(),
                "-sign".to_string(),
                path_argument(&self.identity.private_key)?,
                "-out".to_string(),
                path_argument(&signature)?,
                path_argument(&transcript)?,
            ])?;
            self.read(&signature, MAXIMUM_SIGNATURE_BYTES)
        })
    }

    // Verifies one exact transcript and returns the canonical supplied-key fingerprint.
    fn verify(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        if transcript.is_empty()
            || transcript.len() > MAXIMUM_TRANSCRIPT_BYTES
            || signature.is_empty()
            || signature.len() > MAXIMUM_SIGNATURE_BYTES
        {
            return Err(PairingError::TrustUnavailable);
        }
        self.with_workspace("verify", |workspace| {
            let (public_key, fingerprint) = self.canonical_public_key(workspace, public_key)?;
            let transcript = self.write(
                workspace,
                TRANSCRIPT_NAME,
                transcript,
                MAXIMUM_TRANSCRIPT_BYTES,
            )?;
            let signature = self.write(
                workspace,
                SIGNATURE_NAME,
                signature,
                MAXIMUM_SIGNATURE_BYTES,
            )?;
            self.run(vec![
                "dgst".to_string(),
                "-sha256".to_string(),
                "-verify".to_string(),
                path_argument(&public_key)?,
                "-signature".to_string(),
                path_argument(&signature)?,
                path_argument(&transcript)?,
            ])?;
            Ok(fingerprint)
        })
    }

    // Verifies CA issuance, exact local public-key continuity, and exact certificate digest.
    fn verify_membership_certificate(
        &self,
        candidate_public_key: &[u8],
        main_ca_certificate: &[u8],
        child_certificate: &[u8],
        expected_child_leaf_sha256: &Sha256Digest,
    ) -> Result<(), PairingError> {
        if main_ca_certificate.is_empty()
            || main_ca_certificate.len() > 64 * 1024
            || child_certificate.is_empty()
            || child_certificate.len() > 64 * 1024
        {
            return Err(PairingError::TrustUnavailable);
        }
        self.with_workspace("membership", |workspace| {
            let (_, candidate_fingerprint) =
                self.canonical_public_key(workspace, candidate_public_key)?;
            let candidate_der = self.read(
                &workspace.join(PUBLIC_KEY_DER_NAME),
                MAXIMUM_PUBLIC_KEY_BYTES,
            )?;
            let authority = self.write(
                workspace,
                AUTHORITY_CERTIFICATE_NAME,
                main_ca_certificate,
                64 * 1024,
            )?;
            let certificate = self.write(
                workspace,
                MEMBER_CERTIFICATE_NAME,
                child_certificate,
                64 * 1024,
            )?;
            self.run(vec![
                "verify".to_string(),
                "-purpose".to_string(),
                "sslserver".to_string(),
                "-CAfile".to_string(),
                path_argument(&authority)?,
                path_argument(&certificate)?,
            ])?;
            self.run(vec![
                "verify".to_string(),
                "-purpose".to_string(),
                "sslclient".to_string(),
                "-CAfile".to_string(),
                path_argument(&authority)?,
                path_argument(&certificate)?,
            ])?;
            let member_public = self.output(workspace, MEMBER_PUBLIC_KEY_NAME)?;
            self.run(vec![
                "x509".to_string(),
                "-in".to_string(),
                path_argument(&certificate)?,
                "-noout".to_string(),
                "-pubkey".to_string(),
                "-out".to_string(),
                path_argument(&member_public)?,
            ])?;
            let member_public_der = self.output(workspace, MEMBER_PUBLIC_KEY_DER_NAME)?;
            self.public_key_der(&member_public, &member_public_der)?;
            if self.read(&member_public_der, MAXIMUM_PUBLIC_KEY_BYTES)? != candidate_der {
                return Err(PairingError::TrustUnavailable);
            }
            let member_certificate_der = self.output(workspace, MEMBER_CERTIFICATE_DER_NAME)?;
            self.run(vec![
                "x509".to_string(),
                "-in".to_string(),
                path_argument(&certificate)?,
                "-outform".to_string(),
                "DER".to_string(),
                "-out".to_string(),
                path_argument(&member_certificate_der)?,
            ])?;
            if digest(&self.read(&member_certificate_der, 64 * 1024)?)?
                != *expected_child_leaf_sha256
            {
                return Err(PairingError::TrustUnavailable);
            }
            let (_, observed_candidate_fingerprint) = self.public_key()?;
            if observed_candidate_fingerprint != candidate_fingerprint {
                return Err(PairingError::TrustUnavailable);
            }
            Ok(())
        })
    }
}

// Returns a lower-hex SHA-256 identity for canonical public-key bytes.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, PairingError> {
    let value = Sha256::digest(bytes);
    Sha256Digest::parse(&hexadecimal(&value)).map_err(Into::into)
}

// Returns lower-hex text without native formatting dependencies.
fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Converts one safe absolute path to an OpenSSL argument.
fn path_argument(path: &Path) -> Result<String, PairingError> {
    if !is_safe_absolute_path(path) {
        return Err(PairingError::TrustUnavailable);
    }
    path.to_str()
        .map(str::to_string)
        .ok_or(PairingError::TrustUnavailable)
}

// Returns whether one path is absolute, normalized, and free of terminal controls.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path
            .to_str()
            .is_some_and(|value| !value.chars().any(char::is_control))
}

// Collapses every candidate trust failure into the stable trust boundary.
fn trust_error(_error: impl fmt::Debug) -> PairingError {
    PairingError::TrustUnavailable
}
