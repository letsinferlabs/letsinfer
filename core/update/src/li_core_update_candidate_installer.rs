// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use li_core_interface::Sha256Digest;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::li_core_update_artifact_provider::{
    parse_core_release_manifest, require_absolute_normal_path, verify_core_native_tree,
    CoreReleaseFileRecord, CoreReleasePlatformIdentity, FilesystemCoreUpdateArtifactIo,
    CORE_RELEASE_MANIFEST_NAME, MAXIMUM_CORE_RELEASE_BYTES, MAXIMUM_CORE_RELEASE_MANIFEST_BYTES,
};
use crate::{
    CoreInstallation, CoreUpdateCandidateInstaller, CoreUpdateCandidateRequest, CoreUpdateError,
    CoreVersion,
};

const GITHUB_API_ROOT: &str = "https://api.github.com/repos/letsinferlabs/letsinfer/releases";
const GITHUB_DOWNLOAD_ROOT: &str = "https://github.com/letsinferlabs/letsinfer/releases/download";
const CHECKSUM_DOCUMENT_NAME: &str = "SHA256SUMS";
const CHECKSUM_SIGNATURE_NAME: &str = "SHA256SUMS.sig";
const RELEASE_METADATA_NAME: &str = "li_core_update_release.json";
const RECEIPT_NAME: &str = "li_core_update_candidate_receipt_v1";
const RECEIPT_TEMPORARY_NAME: &str = ".li_core_update_candidate_receipt_v1.tmp";
const RELEASE_TEMPORARY_NAME: &str = ".li_core_update_release.tmp";
const DOWNLOAD_DIRECTORY_NAME: &str = "downloads";
const LOCK_NAME: &str = ".li_core_update_candidate.lock";
const RECEIPT_IDENTITY: &str = "li_core_update_candidate_receipt_v1";
const RELEASE_SIGNER_IDENTITY: &str = "letsinfer-release";
const RELEASE_SIGNATURE_NAMESPACE: &str = "letsinfer-release";
const MAXIMUM_RELEASE_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_CHECKSUM_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_CHECKSUM_SIGNATURE_BYTES: u64 = 1024 * 1024;
const MAXIMUM_CORE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_ARCHIVE_MEMBERS: usize = 25_000;
const MAXIMUM_RELEASES: usize = 100;
const MAXIMUM_RELEASE_ASSETS: usize = 64;
const MAXIMUM_COMMAND_DIAGNOSTIC_BYTES: usize = 4 * 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const CURL_COMMAND_TIMEOUT: Duration = Duration::from_secs(330);
const SIGNATURE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
const IMMUTABLE_FILE_MODE: u32 = 0o444;
const IMMUTABLE_EXECUTABLE_MODE: u32 = 0o555;

// Selects one released Core archive from the closed supported platform set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreUpdateReleasePlatform {
    LinuxArm64,
    LinuxX86_64,
    MacosArm64,
}

impl CoreUpdateReleasePlatform {
    // Returns the exact signed Core archive name for this platform.
    pub const fn archive_name(self) -> &'static str {
        match self {
            Self::LinuxArm64 => "letsinfer-linux-arm64.tar.gz",
            Self::LinuxX86_64 => "letsinfer-linux-x86_64.tar.gz",
            Self::MacosArm64 => "letsinfer-macos-arm64.tar.gz",
        }
    }

    // Returns the exact native manifest platform selected by this release asset.
    const fn identity(self) -> CoreReleasePlatformIdentity {
        match self {
            Self::LinuxArm64 => CoreReleasePlatformIdentity::LinuxArm64,
            Self::LinuxX86_64 => CoreReleasePlatformIdentity::LinuxX86_64,
            Self::MacosArm64 => CoreReleasePlatformIdentity::MacosArm64,
        }
    }
}

// Carries one exact shell-free native command invocation through an injected runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateCommand {
    executable: PathBuf,
    arguments: Vec<OsString>,
    standard_input: Vec<u8>,
    timeout: Duration,
    maximum_output_bytes: usize,
}

impl CoreUpdateCommand {
    // Creates one command from an absolute executable, exact arguments, and bounded input.
    pub fn new(
        executable: PathBuf,
        arguments: Vec<OsString>,
        standard_input: Vec<u8>,
    ) -> Result<Self, CoreUpdateError> {
        Self::new_bounded(
            executable,
            arguments,
            standard_input,
            SIGNATURE_COMMAND_TIMEOUT,
            MAXIMUM_COMMAND_DIAGNOSTIC_BYTES,
        )
    }

    // Creates one command with explicit execution and aggregate-output bounds.
    pub fn new_bounded(
        executable: PathBuf,
        arguments: Vec<OsString>,
        standard_input: Vec<u8>,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<Self, CoreUpdateError> {
        require_absolute_normal_path(&executable)?;
        if executable.parent().is_none()
            || matches!(
                executable.file_name().and_then(OsStr::to_str),
                Some("bash" | "dash" | "env" | "fish" | "ksh" | "sh" | "zsh")
            )
            || standard_input.len() > MAXIMUM_CHECKSUM_DOCUMENT_BYTES as usize
            || timeout.is_zero()
            || maximum_output_bytes == 0
            || maximum_output_bytes > MAXIMUM_COMMAND_DIAGNOSTIC_BYTES
        {
            return Err(candidate_error("native command is invalid"));
        }
        Ok(Self {
            executable,
            arguments,
            standard_input,
            timeout,
            maximum_output_bytes,
        })
    }

    // Returns the exact native executable without performing path discovery.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns the shell-free argument vector in invocation order.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    // Returns the exact bytes supplied to the child process standard input.
    pub fn standard_input(&self) -> &[u8] {
        &self.standard_input
    }

    // Returns the hard child-process execution deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    // Returns the combined retained stdout and stderr byte ceiling.
    pub const fn maximum_output_bytes(&self) -> usize {
        self.maximum_output_bytes
    }
}

// Carries bounded native command diagnostics without exposing process internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUpdateCommandOutput {
    success: bool,
    standard_output: Vec<u8>,
    standard_error: Vec<u8>,
}

impl CoreUpdateCommandOutput {
    // Creates one deterministic command result for production or mocked runners.
    pub fn new(
        success: bool,
        standard_output: Vec<u8>,
        standard_error: Vec<u8>,
    ) -> Result<Self, CoreUpdateError> {
        if standard_output.len() > MAXIMUM_COMMAND_DIAGNOSTIC_BYTES
            || standard_error.len() > MAXIMUM_COMMAND_DIAGNOSTIC_BYTES
        {
            return Err(command_error(
                "native command diagnostics exceed their boundary",
            ));
        }
        Ok(Self {
            success,
            standard_output,
            standard_error,
        })
    }

    // Returns whether the child process exited successfully.
    pub const fn is_success(&self) -> bool {
        self.success
    }

    // Returns the bounded child standard output.
    pub fn standard_output(&self) -> &[u8] {
        &self.standard_output
    }

    // Returns the bounded child standard error.
    pub fn standard_error(&self) -> &[u8] {
        &self.standard_error
    }
}

// Executes one exact native argv without a shell or executable discovery.
pub trait CoreUpdateCommandRunner: Send + Sync {
    // Runs one command and returns only bounded captured output.
    fn run(&self, command: &CoreUpdateCommand) -> Result<CoreUpdateCommandOutput, CoreUpdateError>;
}

// Runs shell-free native commands through the operating system process API.
pub struct ProcessCoreUpdateCommandRunner;

impl CoreUpdateCommandRunner for ProcessCoreUpdateCommandRunner {
    // Spawns one exact executable, writes bounded input, and waits for termination.
    fn run(&self, request: &CoreUpdateCommand) -> Result<CoreUpdateCommandOutput, CoreUpdateError> {
        let mut child = Command::new(request.executable())
            .args(request.arguments())
            .env_clear()
            .stdin(if request.standard_input().is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| command_error("native command could not start"))?;
        if !request.standard_input().is_empty() {
            child
                .stdin
                .take()
                .ok_or_else(|| command_error("native command input is unavailable"))?
                .write_all(request.standard_input())
                .map_err(|_| command_error("native command input could not be written"))?;
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| command_error("native command output is unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| command_error("native command diagnostics are unavailable"))?;
        let maximum_output_bytes = request.maximum_output_bytes();
        let stdout_reader = thread::spawn(move || drain_bounded(stdout, maximum_output_bytes));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr, maximum_output_bytes));
        let deadline = Instant::now()
            .checked_add(request.timeout())
            .ok_or_else(|| command_error("native command deadline is invalid"))?;
        let status = wait_for_command(&mut child, deadline);
        let standard_output = join_command_output(stdout_reader);
        let standard_error = join_command_output(stderr_reader);
        let status = status?;
        let standard_output = standard_output?;
        let standard_error = standard_error?;
        if standard_output
            .len()
            .checked_add(standard_error.len())
            .is_none_or(|bytes| bytes > maximum_output_bytes)
        {
            return Err(command_error(
                "native command diagnostics exceed their boundary",
            ));
        }
        CoreUpdateCommandOutput::new(status, standard_output, standard_error)
    }
}

// Drains one child stream completely while retaining no more than its exact byte cap.
fn drain_bounded<Reader: Read>(
    mut reader: Reader,
    maximum_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut retained = Vec::with_capacity(maximum_bytes.min(8 * 1024));
    let mut oversized = false;
    let mut block = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut block)?;
        if count == 0 {
            break;
        }
        let remaining = maximum_bytes.saturating_sub(retained.len());
        let keep = remaining.min(count);
        retained.extend_from_slice(&block[..keep]);
        oversized |= keep != count;
    }
    Ok((!oversized).then_some(retained))
}

// Joins one bounded output reader without accepting panic, I/O, or size failure.
fn join_command_output(
    reader: thread::JoinHandle<io::Result<Option<Vec<u8>>>>,
) -> Result<Vec<u8>, CoreUpdateError> {
    reader
        .join()
        .map_err(|_| command_error("native command output reader failed"))?
        .map_err(|_| command_error("native command output could not be read"))?
        .ok_or_else(|| command_error("native command diagnostics exceed their boundary"))
}

// Waits for one command until its hard deadline and kills only that owned child on expiry.
fn wait_for_command(child: &mut Child, deadline: Instant) -> Result<bool, CoreUpdateError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = wait_for_child_exit(child, PROCESS_CLEANUP_TIMEOUT);
                return Err(command_error("native command exceeded its deadline"));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = wait_for_child_exit(child, PROCESS_CLEANUP_TIMEOUT);
                return Err(command_error("native command state is unavailable"));
            }
        }
    }
}

// Proves one killed child exits within the bounded cleanup interval.
fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<(), CoreUpdateError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| command_error("native command cleanup deadline is invalid"))?;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) | Err(_) => return Err(command_error("native command could not be retired")),
        }
    }
}

// Downloads one bounded release document or asset through an injected transport.
pub trait CoreUpdateReleaseTransport: Send + Sync {
    // Downloads one exact approved HTTPS URL into an already-created private file.
    fn download(
        &self,
        url: &str,
        destination: &Path,
        maximum_bytes: u64,
    ) -> Result<(), CoreUpdateError>;
}

// Downloads GitHub release inputs with a shell-free curl argv matching the bootstrap policy.
pub struct CurlCoreUpdateReleaseTransport {
    curl_command: PathBuf,
    runner: Arc<dyn CoreUpdateCommandRunner>,
}

impl CurlCoreUpdateReleaseTransport {
    // Creates one transport from an explicitly resolved curl executable and command runner.
    pub fn new(
        curl_command: PathBuf,
        runner: Arc<dyn CoreUpdateCommandRunner>,
    ) -> Result<Self, CoreUpdateError> {
        require_absolute_normal_path(&curl_command)?;
        if curl_command.parent().is_none() {
            return Err(candidate_error("curl command path is invalid"));
        }
        Ok(Self {
            curl_command,
            runner,
        })
    }
}

impl CoreUpdateReleaseTransport for CurlCoreUpdateReleaseTransport {
    // Downloads only official GitHub HTTPS inputs with bounded time, size, and redirects.
    fn download(
        &self,
        url: &str,
        destination: &Path,
        maximum_bytes: u64,
    ) -> Result<(), CoreUpdateError> {
        require_approved_github_url(url)?;
        require_absolute_normal_path(destination)?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_CORE_ARCHIVE_BYTES {
            return Err(download_error("download size boundary is invalid"));
        }
        let arguments = vec![
            OsString::from("--fail"),
            OsString::from("--location"),
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--proto"),
            OsString::from("=https"),
            OsString::from("--proto-redir"),
            OsString::from("=https"),
            OsString::from("--tlsv1.2"),
            OsString::from("--connect-timeout"),
            OsString::from("20"),
            OsString::from("--max-time"),
            OsString::from("300"),
            OsString::from("--retry"),
            OsString::from("2"),
            OsString::from("--retry-delay"),
            OsString::from("1"),
            OsString::from("--max-filesize"),
            OsString::from(maximum_bytes.to_string()),
            OsString::from("--user-agent"),
            OsString::from("letsinfer-core-update/1"),
            OsString::from("--header"),
            OsString::from("Accept: application/vnd.github+json"),
            OsString::from("--output"),
            destination.as_os_str().to_os_string(),
            OsString::from(url),
        ];
        let request = CoreUpdateCommand::new_bounded(
            self.curl_command.clone(),
            arguments,
            Vec::new(),
            CURL_COMMAND_TIMEOUT,
            MAXIMUM_COMMAND_DIAGNOSTIC_BYTES,
        )?;
        let output = self.runner.run(&request)?;
        if !output.is_success() {
            return Err(download_error("GitHub release download failed"));
        }
        Ok(())
    }
}

// Verifies the SSH signature over one exact checksum document.
pub trait CoreUpdateSignatureVerifier: Send + Sync {
    // Requires the configured release signer and namespace to authenticate the message.
    fn verify(&self, message: &[u8], signature: &Path) -> Result<(), CoreUpdateError>;
}

// Verifies release SSHSIG documents through one configured shell-free ssh-keygen command.
pub struct SshKeygenCoreUpdateSignatureVerifier {
    ssh_keygen_command: PathBuf,
    allowed_signers: PathBuf,
    runner: Arc<dyn CoreUpdateCommandRunner>,
}

impl SshKeygenCoreUpdateSignatureVerifier {
    // Creates one verifier bound to the exact executable and configured trust document.
    pub fn new(
        ssh_keygen_command: PathBuf,
        allowed_signers: PathBuf,
        runner: Arc<dyn CoreUpdateCommandRunner>,
    ) -> Result<Self, CoreUpdateError> {
        require_absolute_normal_path(&ssh_keygen_command)?;
        require_absolute_normal_path(&allowed_signers)?;
        if ssh_keygen_command.parent().is_none() || allowed_signers.parent().is_none() {
            return Err(signature_error(
                "release signature configuration is invalid",
            ));
        }
        Ok(Self {
            ssh_keygen_command,
            allowed_signers,
            runner,
        })
    }
}

impl CoreUpdateSignatureVerifier for SshKeygenCoreUpdateSignatureVerifier {
    // Invokes ssh-keygen with the fixed release identity and namespace over exact bytes.
    fn verify(&self, message: &[u8], signature: &Path) -> Result<(), CoreUpdateError> {
        if message.is_empty() || message.len() > MAXIMUM_CHECKSUM_DOCUMENT_BYTES as usize {
            return Err(signature_error("signed checksum document is invalid"));
        }
        require_absolute_normal_path(signature)?;
        require_safe_verification_file(
            &self.allowed_signers,
            MAXIMUM_CHECKSUM_DOCUMENT_BYTES,
            "configured release trust is unsafe",
        )?;
        require_safe_verification_file(
            signature,
            MAXIMUM_CHECKSUM_SIGNATURE_BYTES,
            "release signature file is unsafe",
        )?;
        let arguments = vec![
            OsString::from("-Y"),
            OsString::from("verify"),
            OsString::from("-f"),
            self.allowed_signers.as_os_str().to_os_string(),
            OsString::from("-I"),
            OsString::from(RELEASE_SIGNER_IDENTITY),
            OsString::from("-n"),
            OsString::from(RELEASE_SIGNATURE_NAMESPACE),
            OsString::from("-s"),
            signature.as_os_str().to_os_string(),
        ];
        let request = CoreUpdateCommand::new_bounded(
            self.ssh_keygen_command.clone(),
            arguments,
            message.to_vec(),
            SIGNATURE_COMMAND_TIMEOUT,
            MAXIMUM_COMMAND_DIAGNOSTIC_BYTES,
        )?;
        let output = self.runner.run(&request)?;
        if !output.is_success() {
            return Err(signature_error("release checksum signature is invalid"));
        }
        Ok(())
    }
}

// Owns one exclusive provider workspace throughout candidate preparation.
pub trait CoreUpdateCandidateWorkspace: Send {
    // Returns a fully verified prior result without contacting the release service.
    fn replay(
        &mut self,
        platform: CoreUpdateReleasePlatform,
    ) -> Result<Option<CoreInstallation>, CoreUpdateError>;

    // Removes only partial candidate-owned state before a fresh preparation attempt.
    fn reset(&mut self) -> Result<(), CoreUpdateError>;

    // Creates one exact private download destination beneath this workspace.
    fn prepare_asset(&mut self, name: &str) -> Result<PathBuf, CoreUpdateError>;

    // Reads one exact bounded private asset without following links.
    fn read_asset(&self, name: &str, maximum_bytes: u64) -> Result<Vec<u8>, CoreUpdateError>;

    // Hashes one exact bounded private asset without loading it into memory.
    fn digest_asset(
        &self,
        name: &str,
        maximum_bytes: u64,
    ) -> Result<(Sha256Digest, u64), CoreUpdateError>;

    // Extracts, closes, verifies, and atomically records one signed native Core candidate.
    fn materialize(
        &mut self,
        archive_name: &str,
        version: &CoreVersion,
        archive_sha256: &Sha256Digest,
        platform: CoreUpdateReleasePlatform,
    ) -> Result<CoreInstallation, CoreUpdateError>;

    // Removes downloaded release inputs after a verified result becomes replayable.
    fn cleanup_downloads(&mut self) -> Result<(), CoreUpdateError>;
}

// Supplies one exclusive filesystem workspace for each exact update request.
pub trait CoreUpdateCandidateFilesystem: Send + Sync {
    // Opens and locks the exact provider-owned workspace without widening its scope.
    fn open(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<Box<dyn CoreUpdateCandidateWorkspace>, CoreUpdateError>;
}

// Implements candidate workspaces with owner-bound no-follow Unix filesystem operations.
pub struct FilesystemCoreUpdateCandidateFilesystem {
    owner_user_id: u32,
}

impl FilesystemCoreUpdateCandidateFilesystem {
    // Creates one filesystem capability bound to the installing user's exact identity.
    pub const fn new(owner_user_id: u32) -> Self {
        Self { owner_user_id }
    }
}

impl CoreUpdateCandidateFilesystem for FilesystemCoreUpdateCandidateFilesystem {
    // Validates the provider paths and acquires a crash-releasing exclusive file lock.
    fn open(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<Box<dyn CoreUpdateCandidateWorkspace>, CoreUpdateError> {
        require_absolute_normal_path(request.workspace())?;
        require_absolute_normal_path(request.release_root())?;
        if request.release_root() != request.workspace().join("release") {
            return Err(filesystem_error(
                "candidate native root is outside its workspace",
            ));
        }
        require_owned_directory(
            request.workspace(),
            self.owner_user_id,
            PRIVATE_DIRECTORY_MODE,
        )?;
        let lock_path = request.workspace().join(LOCK_NAME);
        let lock_file = open_or_create_private_file(&lock_path, self.owner_user_id)?;
        let result = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(filesystem_error("candidate workspace lock is unavailable"));
        }
        require_owned_regular_file(&lock_file, self.owner_user_id, None)?;
        Ok(Box::new(FilesystemCoreUpdateCandidateWorkspace {
            owner_user_id: self.owner_user_id,
            update_id: request.update_id().clone(),
            requested_version: request.requested_version().cloned(),
            current: request.current().clone(),
            workspace: request.workspace().to_path_buf(),
            release_root: request.release_root().to_path_buf(),
            _lock_file: lock_file,
        }))
    }
}

// Resolves, authenticates, and materializes one official GitHub Core release candidate.
pub struct GithubCoreUpdateCandidateInstaller {
    platform: CoreUpdateReleasePlatform,
    transport: Arc<dyn CoreUpdateReleaseTransport>,
    signature_verifier: Arc<dyn CoreUpdateSignatureVerifier>,
    filesystem: Arc<dyn CoreUpdateCandidateFilesystem>,
    active_preparation: Mutex<()>,
}

impl GithubCoreUpdateCandidateInstaller {
    // Creates one installer from explicit platform, transport, trust, and filesystem ports.
    pub fn new(
        platform: CoreUpdateReleasePlatform,
        transport: Arc<dyn CoreUpdateReleaseTransport>,
        signature_verifier: Arc<dyn CoreUpdateSignatureVerifier>,
        filesystem: Arc<dyn CoreUpdateCandidateFilesystem>,
    ) -> Self {
        Self {
            platform,
            transport,
            signature_verifier,
            filesystem,
            active_preparation: Mutex::new(()),
        }
    }

    // Performs the signed release flow inside one already-exclusive candidate workspace.
    fn prepare_locked(
        &self,
        request: &CoreUpdateCandidateRequest,
        workspace: &mut dyn CoreUpdateCandidateWorkspace,
    ) -> Result<CoreInstallation, CoreUpdateError> {
        if let Some(installation) = workspace.replay(self.platform)? {
            workspace.cleanup_downloads()?;
            return Ok(installation);
        }
        workspace.reset()?;
        let metadata_url = release_metadata_url(request.requested_version());
        let metadata_path = workspace.prepare_asset(RELEASE_METADATA_NAME)?;
        self.transport.download(
            &metadata_url,
            &metadata_path,
            MAXIMUM_RELEASE_METADATA_BYTES,
        )?;
        let metadata =
            workspace.read_asset(RELEASE_METADATA_NAME, MAXIMUM_RELEASE_METADATA_BYTES)?;
        let release = resolve_release(&metadata, request)?;
        let archive_name = self.platform.archive_name();
        let checksum_asset = release.required_asset(CHECKSUM_DOCUMENT_NAME)?;
        let signature_asset = release.required_asset(CHECKSUM_SIGNATURE_NAME)?;
        let archive_asset = release.required_asset(archive_name)?;

        let checksum_path = workspace.prepare_asset(CHECKSUM_DOCUMENT_NAME)?;
        self.transport.download(
            &checksum_asset.url,
            &checksum_path,
            MAXIMUM_CHECKSUM_DOCUMENT_BYTES,
        )?;
        require_downloaded_size(
            workspace,
            CHECKSUM_DOCUMENT_NAME,
            checksum_asset.bytes,
            MAXIMUM_CHECKSUM_DOCUMENT_BYTES,
        )?;
        let checksum_bytes =
            workspace.read_asset(CHECKSUM_DOCUMENT_NAME, MAXIMUM_CHECKSUM_DOCUMENT_BYTES)?;

        let signature_path = workspace.prepare_asset(CHECKSUM_SIGNATURE_NAME)?;
        self.transport.download(
            &signature_asset.url,
            &signature_path,
            MAXIMUM_CHECKSUM_SIGNATURE_BYTES,
        )?;
        require_downloaded_size(
            workspace,
            CHECKSUM_SIGNATURE_NAME,
            signature_asset.bytes,
            MAXIMUM_CHECKSUM_SIGNATURE_BYTES,
        )?;
        self.signature_verifier
            .verify(&checksum_bytes, &signature_path)?;
        let expected_archive_sha256 = checksum_record(&checksum_bytes, archive_name)?;

        let archive_path = workspace.prepare_asset(archive_name)?;
        self.transport.download(
            &archive_asset.url,
            &archive_path,
            MAXIMUM_CORE_ARCHIVE_BYTES,
        )?;
        let (archive_sha256, archive_bytes) =
            workspace.digest_asset(archive_name, MAXIMUM_CORE_ARCHIVE_BYTES)?;
        if archive_bytes != archive_asset.bytes || archive_sha256 != expected_archive_sha256 {
            return Err(checksum_error("Core archive checksum or size is invalid"));
        }
        let installation = workspace.materialize(
            archive_name,
            &release.version,
            &archive_sha256,
            self.platform,
        )?;
        workspace.cleanup_downloads()?;
        Ok(installation)
    }
}

impl CoreUpdateCandidateInstaller for GithubCoreUpdateCandidateInstaller {
    // Resolves and prepares one candidate idempotently without moving the active pointer.
    fn prepare(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<CoreInstallation, CoreUpdateError> {
        let _preparation = self
            .active_preparation
            .lock()
            .map_err(|_| candidate_error("candidate preparation ownership is unavailable"))?;
        let mut workspace = self.filesystem.open(request)?;
        let result = self.prepare_locked(request, workspace.as_mut());
        if result.is_err() {
            let _ = workspace.reset();
        }
        result
    }
}

// Stores one selected release and its exact validated public assets.
struct ResolvedRelease {
    version: CoreVersion,
    assets: BTreeMap<String, ResolvedReleaseAsset>,
}

impl ResolvedRelease {
    // Returns one required asset without accepting a missing or duplicated identity.
    fn required_asset(&self, name: &str) -> Result<&ResolvedReleaseAsset, CoreUpdateError> {
        self.assets
            .get(name)
            .ok_or_else(|| release_error("required Core release asset is unavailable"))
    }
}

// Stores one exact release asset URL and declared byte count.
struct ResolvedReleaseAsset {
    url: String,
    bytes: u64,
}

// Decodes the GitHub release fields used by the signed candidate resolver.
#[derive(Deserialize)]
struct GithubReleaseDocument {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubReleaseAssetDocument>,
}

// Decodes one GitHub release asset before exact URL and size validation.
#[derive(Deserialize)]
struct GithubReleaseAssetDocument {
    name: String,
    browser_download_url: String,
    size: u64,
}

// Stores SemVer precedence without allowing build metadata to affect ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticVersion {
    core: [String; 3],
    prerelease: Option<Vec<String>>,
}

impl SemanticVersion {
    // Parses a previously validated Core version into its precedence components.
    fn from_core_version(version: &CoreVersion) -> Self {
        let without_build = version
            .as_str()
            .split_once('+')
            .map_or(version.as_str(), |(value, _)| value);
        let (base, prerelease) = without_build
            .split_once('-')
            .map_or((without_build, None), |(base, value)| (base, Some(value)));
        let mut components = base.split('.');
        let core = [
            components.next().unwrap_or_default().to_string(),
            components.next().unwrap_or_default().to_string(),
            components.next().unwrap_or_default().to_string(),
        ];
        let prerelease = prerelease.map(|value| value.split('.').map(str::to_string).collect());
        Self { core, prerelease }
    }

    // Returns whether this version belongs to the prerelease channel.
    fn is_prerelease(&self) -> bool {
        self.prerelease.is_some()
    }
}

impl Ord for SemanticVersion {
    // Compares exact SemVer numeric and prerelease precedence while ignoring build metadata.
    fn cmp(&self, other: &Self) -> Ordering {
        for (left, right) in self.core.iter().zip(&other.core) {
            let ordering = compare_numeric_text(left, right);
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => compare_prerelease(left, right),
        }
    }
}

impl PartialOrd for SemanticVersion {
    // Delegates partial ordering to the total SemVer precedence relation.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Stores one closed candidate receipt parsed from the private replay marker.
struct CandidateReceipt {
    update_id: Sha256Digest,
    current_version: CoreVersion,
    current_source_identity: Sha256Digest,
    version: CoreVersion,
    source_identity: Sha256Digest,
    archive_sha256: Sha256Digest,
}

// Holds one exclusive filesystem workspace and releases its lock on drop.
struct FilesystemCoreUpdateCandidateWorkspace {
    owner_user_id: u32,
    update_id: Sha256Digest,
    requested_version: Option<CoreVersion>,
    current: CoreInstallation,
    workspace: PathBuf,
    release_root: PathBuf,
    _lock_file: File,
}

impl FilesystemCoreUpdateCandidateWorkspace {
    // Returns the exact private directory containing untrusted release downloads.
    fn download_root(&self) -> PathBuf {
        self.workspace.join(DOWNLOAD_DIRECTORY_NAME)
    }

    // Returns one validated release asset path under the private download root.
    fn asset_path(&self, name: &str) -> Result<PathBuf, CoreUpdateError> {
        require_asset_name(name)?;
        Ok(self.download_root().join(name))
    }

    // Returns the exact private candidate receipt path.
    fn receipt_path(&self) -> PathBuf {
        self.workspace.join(RECEIPT_NAME)
    }

    // Returns the same-directory temporary receipt path used for atomic publication.
    fn receipt_temporary_path(&self) -> PathBuf {
        self.workspace.join(RECEIPT_TEMPORARY_NAME)
    }

    // Returns the exact temporary release root used before verified materialization.
    fn release_temporary_path(&self) -> PathBuf {
        self.workspace.join(RELEASE_TEMPORARY_NAME)
    }

    // Requires one replay receipt to describe this exact immutable request.
    fn require_matching_receipt(&self, receipt: &CandidateReceipt) -> Result<(), CoreUpdateError> {
        if receipt.update_id != self.update_id
            || receipt.current_version != *self.current.version()
            || receipt.current_source_identity != *self.current.source_identity()
        {
            return Err(filesystem_error(
                "candidate replay receipt does not match its request",
            ));
        }
        if let Some(requested) = &self.requested_version {
            if requested != &receipt.version {
                return Err(filesystem_error(
                    "candidate replay version does not match its pin",
                ));
            }
        } else {
            let current = SemanticVersion::from_core_version(self.current.version());
            let candidate = SemanticVersion::from_core_version(&receipt.version);
            if current.is_prerelease() != candidate.is_prerelease() || candidate < current {
                return Err(filesystem_error(
                    "candidate replay changed its release channel",
                ));
            }
        }
        Ok(())
    }

    // Writes one complete replay receipt after source verification succeeds.
    fn write_receipt(
        &self,
        installation: &CoreInstallation,
        archive_sha256: &Sha256Digest,
    ) -> Result<(), CoreUpdateError> {
        let bytes = encode_receipt(&self.update_id, &self.current, installation, archive_sha256);
        let temporary = self.receipt_temporary_path();
        remove_missing_or_owned_file(&temporary, self.owner_user_id)?;
        write_private_file(&temporary, self.owner_user_id, &bytes)?;
        fs::rename(&temporary, self.receipt_path())
            .map_err(|_| filesystem_error("candidate receipt publication is unavailable"))?;
        sync_owned_directory(&self.workspace, self.owner_user_id)
    }
}

impl CoreUpdateCandidateWorkspace for FilesystemCoreUpdateCandidateWorkspace {
    // Reconstructs one complete candidate only from its receipt and verified native tree.
    fn replay(
        &mut self,
        platform: CoreUpdateReleasePlatform,
    ) -> Result<Option<CoreInstallation>, CoreUpdateError> {
        let receipt_path = self.receipt_path();
        let receipt_metadata = match fs::symlink_metadata(&receipt_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(filesystem_error(
                    "candidate receipt inspection is unavailable",
                ))
            }
        };
        if receipt_metadata.file_type().is_symlink()
            || !receipt_metadata.is_file()
            || receipt_metadata.uid() != self.owner_user_id
            || receipt_metadata.nlink() != 1
            || receipt_metadata.mode() & 0o777 != PRIVATE_FILE_MODE
        {
            return Err(filesystem_error("candidate receipt is unsafe"));
        }
        let bytes = read_owned_regular_file(&receipt_path, self.owner_user_id, 4096, false)?;
        let receipt = parse_receipt(&bytes)?;
        self.require_matching_receipt(&receipt)?;
        let installation = CoreInstallation::new(receipt.version, receipt.source_identity);
        let io = FilesystemCoreUpdateArtifactIo::new(self.owner_user_id);
        verify_core_native_tree(
            &io,
            &self.release_root,
            PRIVATE_DIRECTORY_MODE,
            &installation,
        )?;
        require_installed_platform(&io, &self.release_root, platform.identity())?;
        let _ = receipt.archive_sha256;
        Ok(Some(installation))
    }

    // Removes exact partial downloads, source material, and receipt while preserving the lock.
    fn reset(&mut self) -> Result<(), CoreUpdateError> {
        for path in [
            self.download_root(),
            self.release_root.clone(),
            self.release_temporary_path(),
            self.receipt_path(),
            self.receipt_temporary_path(),
        ] {
            remove_owned_path(&path, self.owner_user_id)?;
        }
        create_owned_directory(&self.download_root(), self.owner_user_id)
    }

    // Creates one exclusive owner-only regular file for an injected transport.
    fn prepare_asset(&mut self, name: &str) -> Result<PathBuf, CoreUpdateError> {
        require_owned_directory(
            &self.download_root(),
            self.owner_user_id,
            PRIVATE_DIRECTORY_MODE,
        )?;
        let path = self.asset_path(name)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| filesystem_error("candidate download destination is unavailable"))?;
        require_owned_regular_file(&file, self.owner_user_id, Some(0))?;
        Ok(path)
    }

    // Reads one exact bounded private asset through an owner-bound no-follow descriptor.
    fn read_asset(&self, name: &str, maximum_bytes: u64) -> Result<Vec<u8>, CoreUpdateError> {
        read_owned_regular_file(
            &self.asset_path(name)?,
            self.owner_user_id,
            maximum_bytes,
            true,
        )
    }

    // Streams one exact private asset through SHA-256 after validating its metadata.
    fn digest_asset(
        &self,
        name: &str,
        maximum_bytes: u64,
    ) -> Result<(Sha256Digest, u64), CoreUpdateError> {
        hash_owned_regular_file(&self.asset_path(name)?, self.owner_user_id, maximum_bytes)
    }

    // Extracts a closed native archive and publishes its verified manifest identity atomically.
    fn materialize(
        &mut self,
        archive_name: &str,
        version: &CoreVersion,
        archive_sha256: &Sha256Digest,
        platform: CoreUpdateReleasePlatform,
    ) -> Result<CoreInstallation, CoreUpdateError> {
        let temporary = self.release_temporary_path();
        remove_owned_path(&temporary, self.owner_user_id)?;
        if fs::symlink_metadata(&self.release_root).is_ok() {
            return Err(filesystem_error(
                "candidate release destination already exists",
            ));
        }
        create_owned_directory(&temporary, self.owner_user_id)?;
        let archive_path = self.asset_path(archive_name)?;
        let source_identity = extract_core_archive(
            &archive_path,
            &temporary,
            self.owner_user_id,
            version,
            platform.identity(),
        )?;
        let installation = CoreInstallation::new(version.clone(), source_identity);
        fs::rename(&temporary, &self.release_root)
            .map_err(|_| filesystem_error("candidate release publication is unavailable"))?;
        sync_owned_directory(&self.workspace, self.owner_user_id)?;
        let io = FilesystemCoreUpdateArtifactIo::new(self.owner_user_id);
        verify_core_native_tree(
            &io,
            &self.release_root,
            PRIVATE_DIRECTORY_MODE,
            &installation,
        )?;
        self.write_receipt(&installation, archive_sha256)?;
        Ok(installation)
    }

    // Removes only release downloads after a complete source and receipt are durable.
    fn cleanup_downloads(&mut self) -> Result<(), CoreUpdateError> {
        remove_owned_path(&self.download_root(), self.owner_user_id)
    }
}

// Returns the exact GitHub API URL for a pinned or latest-channel resolution.
fn release_metadata_url(requested_version: Option<&CoreVersion>) -> String {
    match requested_version {
        Some(version) => format!("{GITHUB_API_ROOT}/tags/v{}", version.as_str()),
        None => format!("{GITHUB_API_ROOT}?per_page={MAXIMUM_RELEASES}&page=1"),
    }
}

// Resolves one pinned release or the highest release in the active SemVer channel.
fn resolve_release(
    bytes: &[u8],
    request: &CoreUpdateCandidateRequest,
) -> Result<ResolvedRelease, CoreUpdateError> {
    let selected = if let Some(requested) = request.requested_version() {
        let document: GithubReleaseDocument = serde_json::from_slice(bytes)
            .map_err(|_| release_error("pinned GitHub release metadata is invalid"))?;
        let version = release_version(&document)?;
        if &version != requested {
            return Err(release_error(
                "pinned GitHub release tag does not match its request",
            ));
        }
        document
    } else {
        let documents: Vec<GithubReleaseDocument> = serde_json::from_slice(bytes)
            .map_err(|_| release_error("GitHub release metadata is invalid"))?;
        select_latest_release(documents, request.current().version())?
    };
    resolved_release(selected)
}

// Selects the unique highest non-draft release in the current stable or prerelease channel.
fn select_latest_release(
    documents: Vec<GithubReleaseDocument>,
    current_version: &CoreVersion,
) -> Result<GithubReleaseDocument, CoreUpdateError> {
    if documents.is_empty() || documents.len() > MAXIMUM_RELEASES {
        return Err(release_error(
            "GitHub release list is empty or exceeds its boundary",
        ));
    }
    let current = SemanticVersion::from_core_version(current_version);
    let mut candidates = Vec::new();
    for document in documents {
        if document.draft || !document.tag_name.starts_with('v') {
            continue;
        }
        let Ok(version) = CoreVersion::parse(&document.tag_name[1..]) else {
            continue;
        };
        let semantic = SemanticVersion::from_core_version(&version);
        if semantic.is_prerelease() == current.is_prerelease()
            && document.prerelease == semantic.is_prerelease()
        {
            candidates.push((semantic, version, document));
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let Some((semantic, _, _)) = candidates.last() else {
        return Err(release_error(
            "compatible GitHub release channel is unavailable",
        ));
    };
    if semantic < &current {
        return Err(release_error(
            "latest GitHub release is older than the active Core",
        ));
    }
    if candidates.len() > 1 {
        let previous = &candidates[candidates.len() - 2];
        let selected_version = &candidates[candidates.len() - 1].1;
        if previous.0 == *semantic && &previous.1 != selected_version {
            return Err(release_error(
                "latest GitHub release precedence is ambiguous",
            ));
        }
    }
    candidates
        .pop()
        .map(|(_, _, document)| document)
        .ok_or_else(|| release_error("compatible GitHub release channel is unavailable"))
}

// Converts one selected GitHub document into a closed exact release contract.
fn resolved_release(document: GithubReleaseDocument) -> Result<ResolvedRelease, CoreUpdateError> {
    if document.draft
        || document.assets.is_empty()
        || document.assets.len() > MAXIMUM_RELEASE_ASSETS
    {
        return Err(release_error("selected GitHub release is incomplete"));
    }
    let version = release_version(&document)?;
    let tag = format!("v{}", version.as_str());
    let mut assets = BTreeMap::new();
    for asset in document.assets {
        require_asset_name(&asset.name)?;
        if asset.size == 0 || asset.size > MAXIMUM_CORE_ARCHIVE_BYTES {
            return Err(release_error("GitHub release asset size is invalid"));
        }
        let expected_url = format!("{GITHUB_DOWNLOAD_ROOT}/{tag}/{}", asset.name);
        if asset.browser_download_url != expected_url {
            return Err(release_error("GitHub release asset URL is invalid"));
        }
        if assets
            .insert(
                asset.name,
                ResolvedReleaseAsset {
                    url: expected_url,
                    bytes: asset.size,
                },
            )
            .is_some()
        {
            return Err(release_error("GitHub release asset is duplicated"));
        }
    }
    Ok(ResolvedRelease { version, assets })
}

// Parses and cross-checks one Core tag against the GitHub prerelease flag.
fn release_version(document: &GithubReleaseDocument) -> Result<CoreVersion, CoreUpdateError> {
    let version_text = document
        .tag_name
        .strip_prefix('v')
        .ok_or_else(|| release_error("GitHub Core release tag is invalid"))?;
    let version = CoreVersion::parse(version_text)
        .map_err(|_| release_error("GitHub Core release tag is invalid"))?;
    let semantic = SemanticVersion::from_core_version(&version);
    if document.prerelease != semantic.is_prerelease() {
        return Err(release_error(
            "GitHub release channel conflicts with its tag",
        ));
    }
    Ok(version)
}

// Requires a downloaded asset to equal its signed release metadata size.
fn require_downloaded_size(
    workspace: &dyn CoreUpdateCandidateWorkspace,
    name: &str,
    expected_bytes: u64,
    maximum_bytes: u64,
) -> Result<(), CoreUpdateError> {
    let (_, actual_bytes) = workspace.digest_asset(name, maximum_bytes)?;
    if actual_bytes != expected_bytes {
        return Err(download_error("downloaded release asset size is invalid"));
    }
    Ok(())
}

// Returns one exact archive digest from the complete signature-authenticated checksum document.
fn checksum_record(bytes: &[u8], archive_name: &str) -> Result<Sha256Digest, CoreUpdateError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CHECKSUM_DOCUMENT_BYTES as usize {
        return Err(checksum_error(
            "signed checksum document is empty or oversized",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| checksum_error("signed checksum document is not UTF-8"))?;
    let mut records = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| checksum_error("signed checksum record is invalid"))?;
        require_asset_name(name)?;
        let digest = Sha256Digest::parse(digest)
            .map_err(|_| checksum_error("signed checksum digest is invalid"))?;
        if records.insert(name, digest).is_some() {
            return Err(checksum_error("signed checksum record is duplicated"));
        }
    }
    records
        .remove(archive_name)
        .ok_or_else(|| checksum_error("Core archive checksum record is unavailable"))
}

// Extracts one normalized native archive and returns its exact release-manifest identity.
fn extract_core_archive(
    archive_path: &Path,
    destination: &Path,
    owner_user_id: u32,
    expected_version: &CoreVersion,
    expected_platform: CoreReleasePlatformIdentity,
) -> Result<Sha256Digest, CoreUpdateError> {
    let source = open_owned_regular_file(
        archive_path,
        owner_user_id,
        MAXIMUM_CORE_ARCHIVE_BYTES,
        true,
    )?;
    let mut archive = Archive::new(GzDecoder::new(source));
    let mut member_paths = BTreeSet::new();
    let mut directory_paths = BTreeSet::new();
    let mut file_records = BTreeMap::new();
    let mut member_count = 0_usize;
    let mut total_bytes = 0_u64;
    let entries = archive
        .entries()
        .map_err(|_| archive_error("Core archive is unreadable"))?;
    for entry in entries {
        let mut entry = entry.map_err(|_| archive_error("Core archive entry is invalid"))?;
        member_count = member_count
            .checked_add(1)
            .ok_or_else(|| archive_error("Core archive member count overflowed"))?;
        if member_count > MAXIMUM_ARCHIVE_MEMBERS {
            return Err(archive_error("Core archive exceeds its member boundary"));
        }
        let path = archive_relative_path(entry.path_bytes().as_ref())?;
        if !member_paths.insert(path.clone()) {
            return Err(archive_error("Core archive path is duplicated"));
        }
        let header = entry.header();
        require_normalized_archive_header(header, &path)?;
        if path.as_os_str().is_empty() {
            if member_count != 1 || !header.entry_type().is_dir() {
                return Err(archive_error("Core archive root is invalid"));
            }
            directory_paths.insert(PathBuf::new());
            continue;
        }
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        if !directory_paths.contains(parent) {
            return Err(archive_error("Core archive parent directory is missing"));
        }
        let destination_path = destination.join(&path);
        if header.entry_type().is_dir() {
            fs::create_dir(&destination_path)
                .map_err(|_| archive_error("Core archive directory could not be created"))?;
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
            )
            .map_err(|_| archive_error("Core archive directory could not be protected"))?;
            directory_paths.insert(path);
        } else if header.entry_type().is_file() {
            let bytes = header
                .size()
                .map_err(|_| archive_error("Core archive file size is invalid"))?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or_else(|| archive_error("Core archive byte count overflowed"))?;
            if total_bytes > MAXIMUM_CORE_RELEASE_BYTES + MAXIMUM_CORE_RELEASE_MANIFEST_BYTES {
                return Err(archive_error(
                    "Core archive exceeds its extraction boundary",
                ));
            }
            let mode = header
                .mode()
                .map_err(|_| archive_error("Core archive file mode is invalid"))?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&destination_path)
                .map_err(|_| archive_error("Core archive file could not be created"))?;
            let copied = std::io::copy(&mut entry, &mut output)
                .map_err(|_| archive_error("Core archive file could not be extracted"))?;
            if copied != bytes {
                return Err(archive_error(
                    "Core archive file size changed during extraction",
                ));
            }
            output
                .sync_all()
                .map_err(|_| archive_error("Core archive file could not be persisted"))?;
            file_records.insert(path, (mode, bytes));
        } else {
            return Err(archive_error("Core archive entry type is invalid"));
        }
    }
    if member_count == 0 || !directory_paths.contains(Path::new("")) {
        return Err(archive_error("Core archive root is missing"));
    }
    let manifest_path = destination.join(CORE_RELEASE_MANIFEST_NAME);
    let manifest_bytes = read_owned_regular_file(
        &manifest_path,
        owner_user_id,
        MAXIMUM_CORE_RELEASE_MANIFEST_BYTES,
        true,
    )?;
    let manifest = parse_core_release_manifest(&manifest_bytes)
        .map_err(|_| archive_error("Core archive release manifest is invalid"))?;
    if &manifest.version != expected_version || manifest.platform != expected_platform {
        return Err(archive_error(
            "Core archive release identity differs from its selected asset",
        ));
    }
    require_closed_archive_inventory(
        &directory_paths,
        &file_records,
        &manifest.files,
        manifest_bytes.len() as u64,
    )?;
    for (path, (mode, _)) in &file_records {
        let installed_mode = if *mode & 0o111 == 0 {
            IMMUTABLE_FILE_MODE
        } else {
            IMMUTABLE_EXECUTABLE_MODE
        };
        fs::set_permissions(
            destination.join(path),
            fs::Permissions::from_mode(installed_mode),
        )
        .map_err(|_| archive_error("Core native file could not be protected"))?;
    }
    let mut directories = directory_paths.iter().cloned().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        if path.as_os_str().is_empty() {
            continue;
        }
        let absolute = destination.join(path);
        sync_directory(&absolute)?;
        fs::set_permissions(
            absolute,
            fs::Permissions::from_mode(IMMUTABLE_DIRECTORY_MODE),
        )
        .map_err(|_| archive_error("Core native directory could not be protected"))?;
    }
    sync_directory(destination)?;
    let source_identity = digest_bytes(&manifest_bytes)?;
    let installation = CoreInstallation::new(expected_version.clone(), source_identity.clone());
    let io = FilesystemCoreUpdateArtifactIo::new(owner_user_id);
    verify_core_native_tree(&io, destination, PRIVATE_DIRECTORY_MODE, &installation)
        .map_err(|_| archive_error("Core archive native identity is invalid"))?;
    Ok(source_identity)
}

// Requires the archive members to equal the manifest files and their parent directories.
fn require_closed_archive_inventory(
    directory_paths: &BTreeSet<PathBuf>,
    file_records: &BTreeMap<PathBuf, (u32, u64)>,
    manifest_records: &BTreeMap<PathBuf, CoreReleaseFileRecord>,
    manifest_bytes: u64,
) -> Result<(), CoreUpdateError> {
    let mut expected_files = BTreeMap::new();
    expected_files.insert(
        PathBuf::from(CORE_RELEASE_MANIFEST_NAME),
        (0o644, manifest_bytes),
    );
    for (path, record) in manifest_records {
        expected_files.insert(path.clone(), (record.release_mode, record.bytes));
    }
    if file_records != &expected_files {
        return Err(archive_error(
            "Core archive files differ from its release manifest",
        ));
    }
    let mut expected_directories = BTreeSet::from([PathBuf::new()]);
    for path in expected_files.keys() {
        let mut parent = path.parent();
        while let Some(value) = parent {
            expected_directories.insert(value.to_path_buf());
            if value.as_os_str().is_empty() {
                break;
            }
            parent = value.parent();
        }
    }
    if directory_paths != &expected_directories {
        return Err(archive_error(
            "Core archive directories differ from its release manifest",
        ));
    }
    Ok(())
}

// Requires one replayed native tree to match the platform selected by this provider.
fn require_installed_platform(
    io: &dyn crate::CoreUpdateArtifactIo,
    root: &Path,
    expected_platform: CoreReleasePlatformIdentity,
) -> Result<(), CoreUpdateError> {
    let bytes = io.read_regular_file(
        &root.join(CORE_RELEASE_MANIFEST_NAME),
        MAXIMUM_CORE_RELEASE_MANIFEST_BYTES,
    )?;
    let manifest = parse_core_release_manifest(&bytes)?;
    if manifest.platform != expected_platform {
        return Err(filesystem_error(
            "candidate replay platform differs from its provider",
        ));
    }
    Ok(())
}

// Returns one release-relative path after requiring the exact letsinfer archive root.
fn archive_relative_path(bytes: &[u8]) -> Result<PathBuf, CoreUpdateError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| archive_error("Core archive path is not UTF-8"))?;
    if text.is_empty() || text.contains('\\') || text.contains('\0') {
        return Err(archive_error("Core archive path is invalid"));
    }
    let path = Path::new(text);
    if path == Path::new("letsinfer") {
        return Ok(PathBuf::new());
    }
    let relative = path
        .strip_prefix("letsinfer")
        .map_err(|_| archive_error("Core archive root is invalid"))?;
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(archive_error("Core archive path is unsafe"));
    }
    Ok(relative.to_path_buf())
}

// Requires deterministic owner, time, mode, and entry-type metadata on one archive member.
fn require_normalized_archive_header(
    header: &tar::Header,
    path: &Path,
) -> Result<(), CoreUpdateError> {
    let is_directory = header.entry_type().is_dir();
    let is_file = header.entry_type().is_file();
    if !is_directory && !is_file {
        return Err(archive_error("Core archive entry type is invalid"));
    }
    let mode = header
        .mode()
        .map_err(|_| archive_error("Core archive mode is invalid"))?;
    let expected_mode = if is_directory { 0o755 } else { mode };
    if header
        .uid()
        .map_err(|_| archive_error("Core archive owner is invalid"))?
        != 0
        || header
            .gid()
            .map_err(|_| archive_error("Core archive group is invalid"))?
            != 0
        || header
            .mtime()
            .map_err(|_| archive_error("Core archive time is invalid"))?
            != 0
        || header
            .username()
            .map_err(|_| archive_error("Core archive owner name is invalid"))?
            .unwrap_or_default()
            != ""
        || header
            .groupname()
            .map_err(|_| archive_error("Core archive group name is invalid"))?
            .unwrap_or_default()
            != ""
        || (is_directory && mode != expected_mode)
        || (is_file && !matches!(mode, 0o644 | 0o755))
        || (is_directory
            && header
                .size()
                .map_err(|_| archive_error("Core archive directory size is invalid"))?
                != 0)
        || (path.as_os_str().is_empty() && !is_directory)
    {
        return Err(archive_error("Core archive metadata is not normalized"));
    }
    Ok(())
}

// Encodes one closed bounded replay marker without serializing external release metadata.
fn encode_receipt(
    update_id: &Sha256Digest,
    current: &CoreInstallation,
    installation: &CoreInstallation,
    archive_sha256: &Sha256Digest,
) -> Vec<u8> {
    format!(
        "{RECEIPT_IDENTITY}\nupdate_id={}\ncurrent_version={}\ncurrent_source_identity={}\nversion={}\nsource_identity={}\narchive_sha256={}\n",
        update_id.as_str(),
        current.version().as_str(),
        current.source_identity().as_str(),
        installation.version().as_str(),
        installation.source_identity().as_str(),
        archive_sha256.as_str(),
    )
    .into_bytes()
}

// Parses one exact replay marker while rejecting missing, repeated, or unknown fields.
fn parse_receipt(bytes: &[u8]) -> Result<CandidateReceipt, CoreUpdateError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| filesystem_error("candidate receipt is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(RECEIPT_IDENTITY) {
        return Err(filesystem_error("candidate receipt identity is invalid"));
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| filesystem_error("candidate receipt field is invalid"))?;
        if value.is_empty() || fields.insert(name, value).is_some() {
            return Err(filesystem_error("candidate receipt field is invalid"));
        }
    }
    if fields.len() != 6 {
        return Err(filesystem_error("candidate receipt shape is invalid"));
    }
    Ok(CandidateReceipt {
        update_id: receipt_digest(&fields, "update_id")?,
        current_version: receipt_version(&fields, "current_version")?,
        current_source_identity: receipt_digest(&fields, "current_source_identity")?,
        version: receipt_version(&fields, "version")?,
        source_identity: receipt_digest(&fields, "source_identity")?,
        archive_sha256: receipt_digest(&fields, "archive_sha256")?,
    })
}

// Parses one required receipt digest without accepting alternate encodings.
fn receipt_digest(
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<Sha256Digest, CoreUpdateError> {
    fields
        .get(name)
        .ok_or_else(|| filesystem_error("candidate receipt digest is missing"))
        .and_then(|value| {
            Sha256Digest::parse(value)
                .map_err(|_| filesystem_error("candidate receipt digest is invalid"))
        })
}

// Parses one required receipt version through the shared Core identity contract.
fn receipt_version(
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<CoreVersion, CoreUpdateError> {
    fields
        .get(name)
        .ok_or_else(|| filesystem_error("candidate receipt version is missing"))
        .and_then(|value| {
            CoreVersion::parse(value)
                .map_err(|_| filesystem_error("candidate receipt version is invalid"))
        })
}

// Compares canonical nonnegative integer text without narrowing its range.
fn compare_numeric_text(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

// Compares dot-separated prerelease identifiers by the SemVer precedence rules.
fn compare_prerelease(left: &[String], right: &[String]) -> Ordering {
    for (left_identifier, right_identifier) in left.iter().zip(right) {
        let left_numeric = left_identifier.bytes().all(|byte| byte.is_ascii_digit());
        let right_numeric = right_identifier.bytes().all(|byte| byte.is_ascii_digit());
        let ordering = match (left_numeric, right_numeric) {
            (true, true) => compare_numeric_text(left_identifier, right_identifier),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => left_identifier.as_bytes().cmp(right_identifier.as_bytes()),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

// Requires one release asset filename with no path or command syntax.
fn require_asset_name(value: &str) -> Result<(), CoreUpdateError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(release_error("release asset name is invalid"));
    }
    Ok(())
}

// Requires one URL to use the exact official GitHub API or release-download roots.
fn require_approved_github_url(url: &str) -> Result<(), CoreUpdateError> {
    let api = url == format!("{GITHUB_API_ROOT}?per_page={MAXIMUM_RELEASES}&page=1")
        || url.starts_with(&format!("{GITHUB_API_ROOT}/tags/v"));
    let download = url.starts_with(&format!("{GITHUB_DOWNLOAD_ROOT}/v"));
    if (!api && !download)
        || url.contains('#')
        || url.contains('@')
        || url.contains("..")
        || url.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(download_error("release URL is not approved"));
    }
    Ok(())
}

// Requires one nonempty single-link verification input that cannot be replaced through a symlink.
fn require_safe_verification_file(
    path: &Path,
    maximum_bytes: u64,
    reason: &'static str,
) -> Result<(), CoreUpdateError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| signature_error(reason))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
        || metadata.mode() & 0o022 != 0
    {
        return Err(signature_error(reason));
    }
    Ok(())
}

// Creates or validates one owner-bound private directory without following links.
fn create_owned_directory(path: &Path, owner_user_id: u32) -> Result<(), CoreUpdateError> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_owned_directory(path, owner_user_id, PRIVATE_DIRECTORY_MODE),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| filesystem_error("candidate directory creation is unavailable"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| filesystem_error("candidate directory protection is unavailable"))?;
            require_owned_directory(path, owner_user_id, PRIVATE_DIRECTORY_MODE)
        }
        Err(_) => Err(filesystem_error(
            "candidate directory inspection is unavailable",
        )),
    }
}

// Requires one exact no-follow directory owned by the configured user.
fn require_owned_directory(
    path: &Path,
    owner_user_id: u32,
    mode: u32,
) -> Result<(), CoreUpdateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| filesystem_error("candidate directory inspection is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != mode
    {
        return Err(filesystem_error("candidate directory is unsafe"));
    }
    Ok(())
}

// Opens or creates one owner-only no-follow lock file with a single link.
fn open_or_create_private_file(path: &Path, owner_user_id: u32) -> Result<File, CoreUpdateError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| filesystem_error("candidate lock file is unavailable"))?;
    require_owned_regular_file(&file, owner_user_id, None)?;
    Ok(file)
}

// Opens one owner-bound no-follow regular file and enforces its maximum size.
fn open_owned_regular_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: u64,
    require_nonempty: bool,
) -> Result<File, CoreUpdateError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| filesystem_error("candidate file is unavailable"))?;
    let metadata = require_owned_regular_file(&file, owner_user_id, None)?;
    if metadata.len() > maximum_bytes || (require_nonempty && metadata.len() == 0) {
        return Err(filesystem_error("candidate file exceeds its boundary"));
    }
    Ok(file)
}

// Requires one open descriptor to remain an owner-only single-link regular file.
fn require_owned_regular_file(
    file: &File,
    owner_user_id: u32,
    expected_bytes: Option<u64>,
) -> Result<fs::Metadata, CoreUpdateError> {
    let metadata = file
        .metadata()
        .map_err(|_| filesystem_error("candidate file inspection is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != PRIVATE_FILE_MODE
        || expected_bytes.is_some_and(|bytes| metadata.len() != bytes)
    {
        return Err(filesystem_error("candidate file is unsafe"));
    }
    Ok(metadata)
}

// Reads one stable owner-bound regular file without accepting size changes.
fn read_owned_regular_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: u64,
    require_nonempty: bool,
) -> Result<Vec<u8>, CoreUpdateError> {
    let mut file = open_owned_regular_file(path, owner_user_id, maximum_bytes, require_nonempty)?;
    let expected_bytes = file
        .metadata()
        .map_err(|_| filesystem_error("candidate file inspection is unavailable"))?
        .len();
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_bytes)
            .map_err(|_| filesystem_error("candidate file exceeds its boundary"))?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_| filesystem_error("candidate file reading is unavailable"))?;
    if bytes.len() as u64 != expected_bytes {
        return Err(filesystem_error("candidate file changed while being read"));
    }
    Ok(bytes)
}

// Hashes one stable owner-bound regular file and returns its exact length.
fn hash_owned_regular_file(
    path: &Path,
    owner_user_id: u32,
    maximum_bytes: u64,
) -> Result<(Sha256Digest, u64), CoreUpdateError> {
    let mut file = open_owned_regular_file(path, owner_user_id, maximum_bytes, true)?;
    let expected_bytes = file
        .metadata()
        .map_err(|_| filesystem_error("candidate file inspection is unavailable"))?
        .len();
    let mut digest = Sha256::new();
    let mut block = [0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut block)
            .map_err(|_| filesystem_error("candidate file hashing is unavailable"))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| filesystem_error("candidate file size overflowed"))?;
        if total > maximum_bytes {
            return Err(filesystem_error("candidate file exceeds its boundary"));
        }
        digest.update(&block[..count]);
    }
    if total != expected_bytes {
        return Err(filesystem_error(
            "candidate file changed while being hashed",
        ));
    }
    Ok((digest_from_hasher(digest)?, total))
}

// Writes one exclusive owner-only file and persists its exact bytes.
fn write_private_file(
    path: &Path,
    owner_user_id: u32,
    bytes: &[u8],
) -> Result<(), CoreUpdateError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| filesystem_error("candidate receipt creation is unavailable"))?;
    require_owned_regular_file(&file, owner_user_id, Some(0))?;
    file.write_all(bytes)
        .map_err(|_| filesystem_error("candidate receipt writing is unavailable"))?;
    file.sync_all()
        .map_err(|_| filesystem_error("candidate receipt persistence is unavailable"))
}

// Removes one absent or owner-bound regular file without following it.
fn remove_missing_or_owned_file(path: &Path, owner_user_id: u32) -> Result<(), CoreUpdateError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(filesystem_error("candidate file inspection is unavailable")),
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == owner_user_id
                && metadata.nlink() == 1 =>
        {
            fs::remove_file(path)
                .map_err(|_| filesystem_error("candidate file cleanup is unavailable"))
        }
        Ok(_) => Err(filesystem_error("candidate file is unsafe")),
    }
}

// Removes one exact owner-bound tree without following any contained links.
fn remove_owned_path(path: &Path, owner_user_id: u32) -> Result<(), CoreUpdateError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(filesystem_error(
                "candidate cleanup inspection is unavailable",
            ))
        }
    };
    if metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
        return Err(filesystem_error("candidate cleanup path is unsafe"));
    }
    if metadata.is_file() {
        if metadata.nlink() != 1 {
            return Err(filesystem_error("candidate cleanup file is unsafe"));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(|_| filesystem_error("candidate cleanup protection is unavailable"))?;
        return fs::remove_file(path)
            .map_err(|_| filesystem_error("candidate file cleanup is unavailable"));
    }
    if !metadata.is_dir() {
        return Err(filesystem_error("candidate cleanup path type is invalid"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
        .map_err(|_| filesystem_error("candidate cleanup protection is unavailable"))?;
    let mut children = fs::read_dir(path)
        .map_err(|_| filesystem_error("candidate cleanup enumeration is unavailable"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| filesystem_error("candidate cleanup enumeration is unavailable"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        remove_owned_path(&child.path(), owner_user_id)?;
    }
    fs::remove_dir(path).map_err(|_| filesystem_error("candidate directory cleanup is unavailable"))
}

// Persists one exact owner-bound directory after an atomic transition.
fn sync_owned_directory(path: &Path, owner_user_id: u32) -> Result<(), CoreUpdateError> {
    require_owned_directory(path, owner_user_id, PRIVATE_DIRECTORY_MODE)?;
    sync_directory(path)
}

// Persists one directory without following a replacement file path.
fn sync_directory(path: &Path) -> Result<(), CoreUpdateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| filesystem_error("candidate directory persistence is unavailable"))
}

// Returns one validated SHA-256 identity from exact bytes.
fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, CoreUpdateError> {
    digest_from_hasher(Sha256::new_with_prefix(bytes))
}

// Converts one SHA-256 state into the shared lowercase digest identity.
fn digest_from_hasher(digest: Sha256) -> Result<Sha256Digest, CoreUpdateError> {
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| candidate_error("candidate digest could not be represented"))
}

// Creates one stable release-resolution failure.
fn release_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("release resolution", reason)
}

// Creates one stable HTTPS transport failure.
fn download_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("release download", reason)
}

// Creates one stable SSH signature-verification failure.
fn signature_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("release signature", reason)
}

// Creates one stable signed checksum failure.
fn checksum_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("release checksum", reason)
}

// Creates one stable closed-archive failure.
fn archive_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("release archive", reason)
}

// Creates one stable candidate filesystem failure.
fn filesystem_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("candidate filesystem", reason)
}

// Creates one stable native command failure.
fn command_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("native command", reason)
}

// Creates one stable candidate-orchestration failure.
fn candidate_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("candidate preparation", reason)
}
