// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use li_audit_manager::{AuditCheckpointCryptography, AuditError};

const MAX_CHECKPOINT_SIGNATURE_BYTES: usize = 4096;
const MAX_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

// Names checkpoint keys by reference so private key bytes never enter NodeManager memory.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeAuditCheckpointKeyReferences {
    private_key: PathBuf,
    public_key: PathBuf,
}

impl NodeAuditCheckpointKeyReferences {
    // Creates one unambiguous absolute private/public key reference pair.
    pub fn new(
        private_key: PathBuf,
        public_key: PathBuf,
    ) -> Result<Self, NodeAuditCryptographyError> {
        if !is_safe_absolute_path(&private_key)
            || !is_safe_absolute_path(&public_key)
            || private_key == public_key
        {
            return Err(NodeAuditCryptographyError::InvalidConfiguration);
        }
        Ok(Self {
            private_key,
            public_key,
        })
    }

    // Returns the private signing-key reference without reading its bytes.
    pub fn private_key(&self) -> &Path {
        &self.private_key
    }

    // Returns the pinned public verification-key reference.
    pub fn public_key(&self) -> &Path {
        &self.public_key
    }
}

impl fmt::Debug for NodeAuditCheckpointKeyReferences {
    // Redacts both private identity paths from diagnostic output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeAuditCheckpointKeyReferences")
            .field("private_key", &"<redacted>")
            .field("public_key", &"<private-path>")
            .finish()
    }
}

// Isolates the two exact OpenSSL operations used by checkpoint cryptography.
pub trait NodeAuditOpenSslRunner: Send + Sync {
    // Signs exact event-hash text using a private key reference rather than key bytes.
    fn sign(
        &self,
        openssl: &Path,
        private_key: &Path,
        event_hash: &[u8],
    ) -> Result<Vec<u8>, NodeAuditCryptographyError>;

    // Verifies one opaque signature using the pinned public key reference.
    fn verify(
        &self,
        openssl: &Path,
        public_key: &Path,
        event_hash: &[u8],
        signature: &[u8],
    ) -> Result<bool, NodeAuditCryptographyError>;
}

// Executes shell-free OpenSSL commands with a private verification workspace.
pub struct SystemNodeAuditOpenSslRunner {
    verification_workspace: PathBuf,
    owner_user_id: u32,
    timeout: Duration,
    next_file: AtomicU64,
}

impl SystemNodeAuditOpenSslRunner {
    // Creates one runner from an explicit owner-only workspace and bounded timeout.
    pub fn new(
        verification_workspace: PathBuf,
        owner_user_id: u32,
        timeout: Duration,
    ) -> Result<Self, NodeAuditCryptographyError> {
        if !is_safe_absolute_path(&verification_workspace)
            || timeout.is_zero()
            || timeout > MAX_COMMAND_TIMEOUT
        {
            return Err(NodeAuditCryptographyError::InvalidConfiguration);
        }
        Ok(Self {
            verification_workspace,
            owner_user_id,
            timeout,
            next_file: AtomicU64::new(1),
        })
    }

    // Creates one owner-only signature file without following or replacing a link.
    fn signature_file(
        &self,
        signature: &[u8],
    ) -> Result<(PathBuf, File), NodeAuditCryptographyError> {
        validate_private_directory(&self.verification_workspace, self.owner_user_id)?;
        let identity = self.next_file.fetch_add(1, Ordering::SeqCst);
        let path = self.verification_workspace.join(format!(
            "li_audit_signature_{}_{}",
            std::process::id(),
            identity
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| NodeAuditCryptographyError::WorkspaceUnavailable)?;
        if file
            .write_all(signature)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(NodeAuditCryptographyError::WorkspaceUnavailable);
        }
        Ok((path, file))
    }
}

impl NodeAuditOpenSslRunner for SystemNodeAuditOpenSslRunner {
    // Signs exact event-hash text through a shell-free bounded OpenSSL process.
    fn sign(
        &self,
        openssl: &Path,
        private_key: &Path,
        event_hash: &[u8],
    ) -> Result<Vec<u8>, NodeAuditCryptographyError> {
        validate_key_file(private_key, self.owner_user_id, true)?;
        let arguments = vec![
            "dgst".to_string(),
            "-sha256".to_string(),
            "-sign".to_string(),
            path_argument(private_key)?,
        ];
        let output = run_command(openssl, &arguments, event_hash, self.timeout, true)?;
        if !output.status_success
            || output.stdout.is_empty()
            || output.stdout.len() > MAX_CHECKPOINT_SIGNATURE_BYTES
        {
            return Err(NodeAuditCryptographyError::SigningFailed);
        }
        Ok(output.stdout)
    }

    // Verifies one signature through a temporary owner-only file and exact cleanup.
    fn verify(
        &self,
        openssl: &Path,
        public_key: &Path,
        event_hash: &[u8],
        signature: &[u8],
    ) -> Result<bool, NodeAuditCryptographyError> {
        validate_key_file(public_key, self.owner_user_id, false)?;
        if signature.is_empty() || signature.len() > MAX_CHECKPOINT_SIGNATURE_BYTES {
            return Err(NodeAuditCryptographyError::VerificationFailed);
        }
        let (signature_path, signature_file) = self.signature_file(signature)?;
        drop(signature_file);
        let operation = (|| {
            let arguments = vec![
                "dgst".to_string(),
                "-sha256".to_string(),
                "-verify".to_string(),
                path_argument(public_key)?,
                "-signature".to_string(),
                path_argument(&signature_path)?,
            ];
            let output = run_command(openssl, &arguments, event_hash, self.timeout, false)?;
            match output.status_code {
                Some(0) => Ok(true),
                Some(1) => Ok(false),
                _ => Err(NodeAuditCryptographyError::VerificationFailed),
            }
        })();
        let cleanup = fs::remove_file(&signature_path)
            .map_err(|_| NodeAuditCryptographyError::WorkspaceUnavailable);
        match (operation, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

// Implements AuditManager cryptography while retaining only key paths and a native runner.
pub struct OpenSslNodeAuditCheckpointCryptography {
    openssl: PathBuf,
    keys: NodeAuditCheckpointKeyReferences,
    runner: Arc<dyn NodeAuditOpenSslRunner>,
}

impl OpenSslNodeAuditCheckpointCryptography {
    // Creates one provider from explicit executable, key references, and native runner.
    pub fn new(
        openssl: PathBuf,
        keys: NodeAuditCheckpointKeyReferences,
        runner: Arc<dyn NodeAuditOpenSslRunner>,
    ) -> Result<Self, NodeAuditCryptographyError> {
        if !is_safe_absolute_path(&openssl)
            || openssl.file_name().and_then(|value| value.to_str()) != Some("openssl")
        {
            return Err(NodeAuditCryptographyError::InvalidConfiguration);
        }
        Ok(Self {
            openssl,
            keys,
            runner,
        })
    }
}

impl fmt::Debug for OpenSslNodeAuditCheckpointCryptography {
    // Redacts executable and key paths while exposing no native runner internals.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenSslNodeAuditCheckpointCryptography")
            .field("openssl", &"<native-path>")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl AuditCheckpointCryptography for OpenSslNodeAuditCheckpointCryptography {
    // Signs exact lowercase event-hash text without reading private key bytes into Core.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
        require_event_hash(event_hash)?;
        self.runner
            .sign(&self.openssl, self.keys.private_key(), event_hash)
            .map_err(|_| AuditError::provider("signing", "OpenSSL checkpoint signing failed"))
    }

    // Verifies one bounded opaque checkpoint signature against the pinned public key.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError> {
        require_event_hash(event_hash)?;
        if signature.is_empty() || signature.len() > MAX_CHECKPOINT_SIGNATURE_BYTES {
            return Err(AuditError::provider(
                "verification",
                "checkpoint signature is invalid",
            ));
        }
        self.runner
            .verify(&self.openssl, self.keys.public_key(), event_hash, signature)
            .map_err(|_| {
                AuditError::provider("verification", "OpenSSL checkpoint verification failed")
            })
    }
}

// Describes one redacted native checkpoint cryptography failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeAuditCryptographyError {
    InvalidConfiguration,
    KeyUnavailable,
    WorkspaceUnavailable,
    ProcessUnavailable,
    ProcessTimedOut,
    SigningFailed,
    VerificationFailed,
}

impl fmt::Display for NodeAuditCryptographyError {
    // Presents stable provider language without executable, key, or workspace paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("audit cryptography configuration is invalid")
            }
            Self::KeyUnavailable => formatter.write_str("audit checkpoint key is unavailable"),
            Self::WorkspaceUnavailable => {
                formatter.write_str("audit verification workspace is unavailable")
            }
            Self::ProcessUnavailable => formatter.write_str("OpenSSL is unavailable"),
            Self::ProcessTimedOut => formatter.write_str("OpenSSL timed out"),
            Self::SigningFailed => formatter.write_str("audit checkpoint signing failed"),
            Self::VerificationFailed => formatter.write_str("audit checkpoint verification failed"),
        }
    }
}

impl Error for NodeAuditCryptographyError {}

// Stores one bounded process result without retaining stderr or command paths.
struct NativeCommandOutput {
    status_success: bool,
    status_code: Option<i32>,
    stdout: Vec<u8>,
}

// Runs one shell-free command with bounded time and optional captured output.
fn run_command(
    executable: &Path,
    arguments: &[String],
    input: &[u8],
    timeout: Duration,
    capture_stdout: bool,
) -> Result<NativeCommandOutput, NodeAuditCryptographyError> {
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(if capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| NodeAuditCryptographyError::ProcessUnavailable)?;
    let write_result = child
        .stdin
        .take()
        .ok_or(NodeAuditCryptographyError::ProcessUnavailable)?
        .write_all(input);
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(NodeAuditCryptographyError::ProcessUnavailable);
    }
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                if let Some(output) = child.stdout.take() {
                    output
                        .take(MAX_CHECKPOINT_SIGNATURE_BYTES as u64 + 1)
                        .read_to_end(&mut stdout)
                        .map_err(|_| NodeAuditCryptographyError::ProcessUnavailable)?;
                }
                return Ok(NativeCommandOutput {
                    status_success: status.success(),
                    status_code: status.code(),
                    stdout,
                });
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NodeAuditCryptographyError::ProcessTimedOut);
            }
            Err(_) => return Err(NodeAuditCryptographyError::ProcessUnavailable),
        }
    }
}

// Requires the exact 64-byte lowercase event-hash wire form.
fn require_event_hash(event_hash: &[u8]) -> Result<(), AuditError> {
    if event_hash.len() != 64
        || !event_hash
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AuditError::provider(
            "cryptography",
            "event hash is not canonical lowercase SHA-256 text",
        ));
    }
    Ok(())
}

// Validates one key as a direct regular file owned by the configured user.
fn validate_key_file(
    path: &Path,
    owner_user_id: u32,
    is_private: bool,
) -> Result<(), NodeAuditCryptographyError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| NodeAuditCryptographyError::KeyUnavailable)?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || (is_private && mode & 0o077 != 0)
        || (!is_private && mode & 0o022 != 0)
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        return Err(NodeAuditCryptographyError::KeyUnavailable);
    }
    Ok(())
}

// Validates the caller-provided verification workspace without widening permissions.
fn validate_private_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), NodeAuditCryptographyError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| NodeAuditCryptographyError::WorkspaceUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(NodeAuditCryptographyError::WorkspaceUnavailable);
    }
    Ok(())
}

// Converts one exact native path to an argument without lossy replacement.
fn path_argument(path: &Path) -> Result<String, NodeAuditCryptographyError> {
    path.to_str()
        .map(str::to_string)
        .ok_or(NodeAuditCryptographyError::InvalidConfiguration)
}

// Returns whether one native path is absolute, normalized, and traversal-free.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}
