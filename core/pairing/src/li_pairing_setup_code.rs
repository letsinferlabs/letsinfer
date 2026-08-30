// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use li_core_interface::{InstallationId, PairingInviteId, Sha256Digest};
use sha2::{Digest, Sha256};

use crate::PairingError;

const SETUP_SECRET_BYTES: usize = 32;
const SETUP_CODE_BOUND: u64 = 100_000_000;
const SETUP_CODE_DOMAIN: &[u8] = b"letsinfer-pairing-setup-code-v1\0";
const HMAC_BLOCK_BYTES: usize = 64;

// Derives one restart-stable setup code without exposing or persisting its plaintext.
pub trait PairingSetupCodeProvider: Send + Sync {
    // Derives the exact eight ASCII digits bound to one installation and invitation.
    fn derive(
        &self,
        installation_id: &InstallationId,
        invite_id: &PairingInviteId,
        nonce: &Sha256Digest,
        salt: &[u8; 16],
    ) -> Result<[u8; 8], PairingError>;
}

// Identifies one exact owner-bound installation secret file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingSetupSecretFileReference {
    path: PathBuf,
    owner_user_id: u32,
}

impl PairingSetupSecretFileReference {
    // Creates one reference only from an absolute path and explicit native owner.
    pub fn new(path: PathBuf, owner_user_id: u32) -> Result<Self, PairingError> {
        if !path.is_absolute() {
            return Err(PairingError::InvalidRequest {
                reason: "pairing setup secret path must be absolute",
            });
        }
        Ok(Self {
            path,
            owner_user_id,
        })
    }

    // Returns the exact absolute secret path selected by composition.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // Returns the effective user required to own the secret.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }
}

// Carries one descriptor-shaped secret-file observation for native or deterministic providers.
pub struct PairingSetupSecretFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    regular_file: bool,
    bytes: Vec<u8>,
}

impl PairingSetupSecretFile {
    // Creates one exact observation without validating its trust metadata early.
    pub fn new(
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        regular_file: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_user_id,
            mode,
            link_count,
            regular_file,
            bytes,
        }
    }
}

impl fmt::Debug for PairingSetupSecretFile {
    // Presents only metadata while redacting every secret byte.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingSetupSecretFile")
            .field("owner_user_id", &self.owner_user_id)
            .field("mode", &self.mode)
            .field("link_count", &self.link_count)
            .field("regular_file", &self.regular_file)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for PairingSetupSecretFile {
    // Clears observed secret bytes after validation or failure.
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

// Reads one exact setup secret through an injected no-follow native boundary.
pub trait PairingSetupSecretFileProvider: Send + Sync {
    // Returns one descriptor-shaped secret observation without following its final component.
    fn read_no_follow(&self, path: &Path) -> Result<PairingSetupSecretFile, PairingError>;
}

// Supplies production owner-bound no-follow setup secret reads.
#[derive(Default)]
pub struct SystemPairingSetupSecretFileProvider;

impl PairingSetupSecretFileProvider for SystemPairingSetupSecretFileProvider {
    // Opens, bounds, and revalidates one exact native secret descriptor.
    fn read_no_follow(&self, path: &Path) -> Result<PairingSetupSecretFile, PairingError> {
        read_system_secret(path)
    }
}

// Owns one installation secret and deterministic HMAC-SHA256 setup-code derivation.
pub struct HmacPairingSetupCodeProvider {
    secret: [u8; SETUP_SECRET_BYTES],
}

impl HmacPairingSetupCodeProvider {
    // Loads one exact owner-only secret and rejects every unsafe metadata or length shape.
    pub fn load(
        reference: &PairingSetupSecretFileReference,
        provider: &dyn PairingSetupSecretFileProvider,
    ) -> Result<Self, PairingError> {
        let file = provider.read_no_follow(reference.path())?;
        if file.owner_user_id != reference.owner_user_id()
            || file.mode != 0o600
            || file.link_count != 1
            || !file.regular_file
            || file.bytes.len() != SETUP_SECRET_BYTES
        {
            return Err(PairingError::StateUnavailable);
        }
        let mut secret = [0_u8; SETUP_SECRET_BYTES];
        secret.copy_from_slice(&file.bytes);
        Ok(Self { secret })
    }
}

impl PairingSetupCodeProvider for HmacPairingSetupCodeProvider {
    // Derives unbiased decimal digits from installation-bound domain-separated HMAC output.
    fn derive(
        &self,
        installation_id: &InstallationId,
        invite_id: &PairingInviteId,
        nonce: &Sha256Digest,
        salt: &[u8; 16],
    ) -> Result<[u8; 8], PairingError> {
        let acceptance_bound = (u64::from(u32::MAX) + 1) / SETUP_CODE_BOUND * SETUP_CODE_BOUND;
        for counter in 0_u8..=u8::MAX {
            let mut input = Vec::with_capacity(256);
            append_field(&mut input, SETUP_CODE_DOMAIN);
            append_field(&mut input, installation_id.as_str().as_bytes());
            append_field(&mut input, invite_id.as_str().as_bytes());
            append_field(&mut input, nonce.as_str().as_bytes());
            append_field(&mut input, salt);
            append_field(&mut input, &[counter]);
            let output = hmac_sha256(&self.secret, &input);
            let candidate = u64::from(u32::from_be_bytes(
                output[..4]
                    .try_into()
                    .map_err(|_| PairingError::StateUnavailable)?,
            ));
            if candidate < acceptance_bound {
                let text = format!("{:08}", candidate % SETUP_CODE_BOUND);
                let mut digits = [0_u8; 8];
                digits.copy_from_slice(text.as_bytes());
                return Ok(digits);
            }
        }
        Err(PairingError::EntropyUnavailable)
    }
}

impl fmt::Debug for HmacPairingSetupCodeProvider {
    // Redacts the installation-bound secret from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacPairingSetupCodeProvider(<redacted>)")
    }
}

impl Drop for HmacPairingSetupCodeProvider {
    // Clears retained secret bytes when process composition releases the provider.
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

// Opens and revalidates one exact secret file without following its final path component.
fn read_system_secret(path: &Path) -> Result<PairingSetupSecretFile, PairingError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PairingError::StateUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| PairingError::StateUnavailable)?;
    if before.len() != SETUP_SECRET_BYTES as u64 {
        return Err(PairingError::StateUnavailable);
    }
    let mut bytes = Vec::with_capacity(SETUP_SECRET_BYTES);
    Read::by_ref(&mut file)
        .take((SETUP_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PairingError::StateUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| PairingError::StateUnavailable)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.len() != SETUP_SECRET_BYTES
    {
        bytes.fill(0);
        return Err(PairingError::StateUnavailable);
    }
    Ok(PairingSetupSecretFile::new(
        after.uid(),
        after.mode() & 0o777,
        after.nlink(),
        after.file_type().is_file(),
        bytes,
    ))
}

// Computes one RFC-2104 HMAC-SHA256 digest without exposing intermediate secret material.
fn hmac_sha256(secret: &[u8; SETUP_SECRET_BYTES], input: &[u8]) -> [u8; 32] {
    let mut inner_key = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_key = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in secret.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(input);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    let result = outer.finalize().into();
    inner_key.fill(0);
    outer_key.fill(0);
    result
}

// Appends one length-delimited transcript field to prevent concatenation ambiguity.
fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}
