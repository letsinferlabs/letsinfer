// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use li_core_interface::{OperationId, Sha256Digest};

use crate::li_benchmark_evidence::{
    digest_bytes, parsed_evidence, read_private_file, require_absolute_normal_path,
    require_directory, require_private_file_metadata, BenchmarkEvidenceEntryKind,
    BenchmarkEvidenceNativeIo, MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
};
use crate::{BenchmarkError, BenchmarkEvidence, BenchmarkSignature, BenchmarkSigningProvider};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAXIMUM_COMMAND_OUTPUT_BYTES: usize = 64 << 10;
const MAXIMUM_KEY_BYTES: usize = 16 << 10;
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

// Carries one exact bounded shell-free OpenSSL invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkSigningCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    maximum_output_bytes: usize,
}

impl BenchmarkSigningCommand {
    // Creates one absolute OpenSSL command with fixed execution and output bounds.
    pub(crate) fn new(executable: PathBuf, arguments: Vec<String>) -> Result<Self, BenchmarkError> {
        require_absolute_normal_path(&executable)
            .map_err(|_| signing_provider_error("signing command is invalid"))?;
        let total_bytes = arguments.iter().map(String::len).sum::<usize>();
        if executable.file_name().and_then(OsStr::to_str) != Some("openssl")
            || arguments.is_empty()
            || arguments.len() > 16
            || total_bytes > 16 * 1024
            || arguments.iter().any(|argument| {
                argument.is_empty()
                    || argument.len() > 4096
                    || argument.chars().any(char::is_control)
            })
        {
            return Err(signing_provider_error("signing command is invalid"));
        }
        Ok(Self {
            executable,
            arguments,
            timeout: COMMAND_TIMEOUT,
            maximum_output_bytes: MAXIMUM_COMMAND_OUTPUT_BYTES,
        })
    }

    // Returns the exact absolute OpenSSL executable.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns the exact shell-free argv in invocation order.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    // Returns the hard child-process deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    // Returns the combined stdout and stderr retention ceiling.
    pub const fn maximum_output_bytes(&self) -> usize {
        self.maximum_output_bytes
    }
}

// Returns bounded native command output without exposing it through provider errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkSigningCommandOutput {
    status: i32,
    standard_output: Vec<u8>,
    standard_error: Vec<u8>,
    timed_out: bool,
}

impl BenchmarkSigningCommandOutput {
    // Creates one deterministic process result within the fixed aggregate byte ceiling.
    pub fn new(
        status: i32,
        standard_output: Vec<u8>,
        standard_error: Vec<u8>,
        timed_out: bool,
    ) -> Result<Self, BenchmarkError> {
        if standard_output
            .len()
            .checked_add(standard_error.len())
            .is_none_or(|bytes| bytes > MAXIMUM_COMMAND_OUTPUT_BYTES)
        {
            return Err(signing_provider_error("signing command output is invalid"));
        }
        Ok(Self {
            status,
            standard_output,
            standard_error,
            timed_out,
        })
    }

    // Returns the child exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns bounded stdout required for signature and key parsing.
    pub fn standard_output(&self) -> &[u8] {
        &self.standard_output
    }

    // Returns bounded stderr retained only at the native boundary.
    pub fn standard_error(&self) -> &[u8] {
        &self.standard_error
    }

    // Returns whether the runner killed the child at its deadline.
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }

    // Returns whether the child completed successfully before its deadline.
    pub const fn is_success(&self) -> bool {
        self.status == 0 && !self.timed_out
    }
}

// Executes exact bounded signing commands without a shell.
pub trait BenchmarkSigningCommandRunner: Send + Sync {
    // Runs one command and returns only bounded captured output.
    fn run(
        &self,
        command: &BenchmarkSigningCommand,
    ) -> Result<BenchmarkSigningCommandOutput, BenchmarkError>;
}

// Executes OpenSSL directly on the active Unix host.
#[derive(Default)]
pub struct SystemBenchmarkSigningCommandRunner;

impl BenchmarkSigningCommandRunner for SystemBenchmarkSigningCommandRunner {
    // Spawns exact argv with an empty environment, bounded output, and forced timeout cleanup.
    fn run(
        &self,
        command: &BenchmarkSigningCommand,
    ) -> Result<BenchmarkSigningCommandOutput, BenchmarkError> {
        let deadline = Instant::now()
            .checked_add(command.timeout())
            .ok_or_else(|| signing_provider_error("signing command failed"))?;
        let mut child = Command::new(command.executable())
            .args(command.arguments())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| signing_provider_error("signing command failed"))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            let _ = child.kill();
            let _ = wait_for_exit(&mut child, PROCESS_CLEANUP_TIMEOUT);
            return Err(signing_provider_error("signing command failed"));
        };
        let maximum_output_bytes = command.maximum_output_bytes();
        let stdout_reader = thread::spawn(move || drain_bounded(stdout, maximum_output_bytes));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr, maximum_output_bytes));
        let mut timed_out = false;
        let mut native_failure = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(-1),
                Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
                Ok(None) => {
                    timed_out = true;
                    native_failure |= child.kill().is_err();
                    break wait_for_exit(&mut child, PROCESS_CLEANUP_TIMEOUT)?;
                }
                Err(_) => {
                    native_failure = true;
                    let _ = child.kill();
                    break wait_for_exit(&mut child, PROCESS_CLEANUP_TIMEOUT)?;
                }
            }
        };
        let standard_output = join_output(stdout_reader)?;
        let standard_error = join_output(stderr_reader)?;
        if native_failure {
            return Err(signing_provider_error("signing command failed"));
        }
        BenchmarkSigningCommandOutput::new(status, standard_output, standard_error, timed_out)
    }
}

// Signs and verifies exact materialized benchmark records with an Ed25519 OpenSSL identity.
pub struct OpensslBenchmarkSigningProvider {
    openssl: PathBuf,
    private_key: PathBuf,
    public_key: PathBuf,
    evidence_root: PathBuf,
    workspace_root: PathBuf,
    owner_user_id: u32,
    native_io: Arc<dyn BenchmarkEvidenceNativeIo>,
    runner: Arc<dyn BenchmarkSigningCommandRunner>,
    active_operation: Mutex<()>,
}

impl OpensslBenchmarkSigningProvider {
    // Creates one provider from explicit key references, paths, native I/O, and command runner.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        openssl: PathBuf,
        private_key: PathBuf,
        public_key: PathBuf,
        evidence_root: PathBuf,
        workspace_root: PathBuf,
        owner_user_id: u32,
        native_io: Arc<dyn BenchmarkEvidenceNativeIo>,
        runner: Arc<dyn BenchmarkSigningCommandRunner>,
    ) -> Result<Self, BenchmarkError> {
        for path in [
            &openssl,
            &private_key,
            &public_key,
            &evidence_root,
            &workspace_root,
        ] {
            require_absolute_normal_path(path)
                .map_err(|_| signing_provider_error("signing configuration is invalid"))?;
        }
        if openssl.file_name().and_then(OsStr::to_str) != Some("openssl")
            || private_key == public_key
            || evidence_root == workspace_root
        {
            return Err(signing_provider_error("signing configuration is invalid"));
        }
        Ok(Self {
            openssl,
            private_key,
            public_key,
            evidence_root,
            workspace_root,
            owner_user_id,
            native_io,
            runner,
            active_operation: Mutex::new(()),
        })
    }

    // Verifies the executable, directories, and key references without signing or mutation.
    pub fn preflight(&self) -> Result<(), BenchmarkError> {
        self.require_inputs()
    }

    // Acquires exclusive temporary-file ownership for one bounded signing operation.
    fn operation_guard(&self) -> Result<MutexGuard<'_, ()>, BenchmarkError> {
        self.active_operation
            .lock()
            .map_err(|_| signing_provider_error("signing state is unavailable"))
    }

    // Resolves one immutable evidence path from its schema-owned identity.
    fn evidence_path(&self, evidence: &BenchmarkEvidence) -> PathBuf {
        self.evidence_root
            .join(format!("{}.json", evidence.evidence_id().as_str()))
    }

    // Resolves one deterministic owner-only message workspace path.
    fn message_path(&self, identity: &str) -> PathBuf {
        self.workspace_root
            .join(format!(".li_benchmark_message_{identity}.tmp"))
    }

    // Resolves one deterministic owner-only raw signature workspace path.
    fn signature_path(&self, evidence: &BenchmarkEvidence) -> PathBuf {
        self.workspace_root.join(format!(
            ".li_benchmark_signature_{}.tmp",
            evidence.evidence_id().as_str()
        ))
    }

    // Requires a trusted executable, owner-only directories, and single-link keys.
    fn require_inputs(&self) -> Result<(), BenchmarkError> {
        let executable = self
            .native_io
            .metadata(&self.openssl)
            .map_err(|_| signing_provider_error("signing executable is unsafe"))?
            .ok_or_else(|| signing_provider_error("signing executable is unavailable"))?;
        if executable.kind() != BenchmarkEvidenceEntryKind::RegularFile
            || (executable.owner_user_id() != 0 && executable.owner_user_id() != self.owner_user_id)
            || executable.mode() & 0o022 != 0
            || executable.mode() & 0o111 == 0
            || executable.link_count() != 1
            || executable.byte_count() == 0
        {
            return Err(signing_provider_error("signing executable is unsafe"));
        }
        require_directory(
            self.native_io.as_ref(),
            &self.evidence_root,
            self.owner_user_id,
        )
        .map_err(|_| signing_provider_error("signing evidence directory is unsafe"))?;
        require_directory(
            self.native_io.as_ref(),
            &self.workspace_root,
            self.owner_user_id,
        )
        .map_err(|_| signing_provider_error("signing workspace is unsafe"))?;
        for key in [&self.private_key, &self.public_key] {
            let parent = key
                .parent()
                .ok_or_else(|| signing_provider_error("signing key is unsafe"))?;
            require_directory(self.native_io.as_ref(), parent, self.owner_user_id)
                .map_err(|_| signing_provider_error("signing key is unsafe"))?;
            let metadata = self
                .native_io
                .metadata(key)
                .map_err(|_| signing_provider_error("signing key is unsafe"))?
                .ok_or_else(|| signing_provider_error("signing key is unavailable"))?;
            require_private_file_metadata(&metadata, self.owner_user_id, Some(MAXIMUM_KEY_BYTES))
                .map_err(|_| signing_provider_error("signing key is unsafe"))?;
        }
        Ok(())
    }

    // Reads one immutable evidence file and verifies every receipt projection before signing.
    fn evidence_bytes(&self, evidence: &BenchmarkEvidence) -> Result<Vec<u8>, BenchmarkError> {
        let bytes = read_private_file(
            self.native_io.as_ref(),
            &self.evidence_path(evidence),
            self.owner_user_id,
            MAXIMUM_BENCHMARK_EVIDENCE_BYTES,
        )
        .map_err(|_| signing_provider_error("signing evidence is unavailable"))?;
        let parsed = parsed_evidence(&bytes)?;
        if &parsed.receipt != evidence {
            return Err(BenchmarkError::EvidenceRejected);
        }
        Ok(bytes)
    }

    // Derives the canonical public-key identity through fixed OpenSSL DER output.
    fn key_id(&self) -> Result<Sha256Digest, BenchmarkError> {
        let command = BenchmarkSigningCommand::new(
            self.openssl.clone(),
            vec![
                "pkey".to_string(),
                "-pubin".to_string(),
                "-in".to_string(),
                path_text(&self.public_key)?,
                "-outform".to_string(),
                "DER".to_string(),
            ],
        )?;
        let output = self
            .runner
            .run(&command)
            .map_err(|_| signing_provider_error("signing command failed"))?;
        if !output.is_success()
            || output.standard_output().is_empty()
            || output.standard_output().len() > MAXIMUM_KEY_BYTES
        {
            return Err(signing_provider_error("signing public key is invalid"));
        }
        Ok(digest_bytes(output.standard_output()))
    }

    // Removes one safe provider-owned temporary file and synchronizes its directory.
    fn cleanup_temporary(&self, path: &Path) -> Result<(), BenchmarkError> {
        let Some(metadata) = self
            .native_io
            .metadata(path)
            .map_err(|_| signing_cleanup_error())?
        else {
            return Ok(());
        };
        require_private_file_metadata(&metadata, self.owner_user_id, None)
            .map_err(|_| signing_cleanup_error())?;
        self.native_io
            .remove_private_file(path)
            .map_err(|_| signing_cleanup_error())?;
        self.native_io
            .sync_directory(&self.workspace_root)
            .map_err(|_| signing_cleanup_error())
    }

    // Writes one exact temporary file after safely removing only prior owned state.
    fn write_temporary(&self, path: &Path, bytes: &[u8]) -> Result<(), BenchmarkError> {
        self.cleanup_temporary(path)?;
        if self.native_io.write_private_file(path, bytes).is_err() {
            self.cleanup_temporary(path)?;
            return Err(signing_provider_error("signing workspace write failed"));
        }
        let observed = match read_private_file(
            self.native_io.as_ref(),
            path,
            self.owner_user_id,
            bytes.len().max(1),
        ) {
            Ok(observed) => observed,
            Err(_) => {
                self.cleanup_temporary(path)?;
                return Err(signing_provider_error("signing workspace write failed"));
            }
        };
        if observed != bytes {
            self.cleanup_temporary(path)?;
            return Err(signing_provider_error("signing workspace write failed"));
        }
        Ok(())
    }
}

impl BenchmarkSigningProvider for OpensslBenchmarkSigningProvider {
    // Signs exact canonical evidence bytes through the established Ed25519 pkeyutl contract.
    fn sign(
        &self,
        job_id: &OperationId,
        evidence: &BenchmarkEvidence,
    ) -> Result<BenchmarkSignature, BenchmarkError> {
        let _guard = self.operation_guard()?;
        self.require_inputs()?;
        let bytes = self.evidence_bytes(evidence)?;
        let key_id = self.key_id()?;
        let message = self.message_path(job_id.as_str());
        let command = BenchmarkSigningCommand::new(
            self.openssl.clone(),
            vec![
                "pkeyutl".to_string(),
                "-sign".to_string(),
                "-inkey".to_string(),
                path_text(&self.private_key)?,
                "-rawin".to_string(),
                "-in".to_string(),
                path_text(&message)?,
            ],
        )?;
        self.write_temporary(&message, &bytes)?;
        let output = self.runner.run(&command);
        let cleanup = self.cleanup_temporary(&message);
        cleanup?;
        let output = output.map_err(|_| signing_provider_error("benchmark signing failed"))?;
        if !output.is_success() || output.standard_output().len() != ED25519_SIGNATURE_BYTES {
            return Err(signing_provider_error("benchmark signing failed"));
        }
        BenchmarkSignature::new(key_id, &URL_SAFE_NO_PAD.encode(output.standard_output()))
    }

    // Verifies one detached signature against exact canonical evidence and the configured key.
    fn verify(
        &self,
        evidence: &BenchmarkEvidence,
        signature: &BenchmarkSignature,
    ) -> Result<bool, BenchmarkError> {
        let _guard = self.operation_guard()?;
        self.require_inputs()?;
        let bytes = self.evidence_bytes(evidence)?;
        let key_id = self.key_id()?;
        if signature.key_id() != &key_id {
            return Ok(false);
        }
        let raw_signature = match URL_SAFE_NO_PAD.decode(signature.value()) {
            Ok(value) if value.len() == ED25519_SIGNATURE_BYTES => value,
            Ok(_) | Err(_) => return Ok(false),
        };
        let message = self.message_path(evidence.evidence_id().as_str());
        let signature_path = self.signature_path(evidence);
        let command = BenchmarkSigningCommand::new(
            self.openssl.clone(),
            vec![
                "pkeyutl".to_string(),
                "-verify".to_string(),
                "-pubin".to_string(),
                "-inkey".to_string(),
                path_text(&self.public_key)?,
                "-sigfile".to_string(),
                path_text(&signature_path)?,
                "-rawin".to_string(),
                "-in".to_string(),
                path_text(&message)?,
            ],
        )?;
        self.write_temporary(&message, &bytes)?;
        if let Err(error) = self.write_temporary(&signature_path, &raw_signature) {
            self.cleanup_temporary(&message)?;
            return Err(error);
        }
        let output = self.runner.run(&command);
        let signature_cleanup = self.cleanup_temporary(&signature_path);
        let message_cleanup = self.cleanup_temporary(&message);
        signature_cleanup?;
        message_cleanup?;
        let output = output.map_err(|_| signing_provider_error("benchmark verification failed"))?;
        Ok(output.is_success())
    }
}

// Converts one normal UTF-8 path into one exact argv element.
fn path_text(path: &Path) -> Result<String, BenchmarkError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| signing_provider_error("signing path is invalid"))
}

// Drains one child stream while retaining no more than its exact byte ceiling.
fn drain_bounded<Reader: Read>(
    mut reader: Reader,
    maximum_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut retained = Vec::with_capacity(maximum_bytes.min(8 * 1024));
    let mut oversized = false;
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let remaining = maximum_bytes.saturating_sub(retained.len());
        let retain = remaining.min(count);
        retained.extend_from_slice(&chunk[..retain]);
        oversized |= retain != count;
    }
    Ok((!oversized).then_some(retained))
}

// Joins one bounded reader without accepting panic, I/O, or truncation.
fn join_output(
    reader: thread::JoinHandle<io::Result<Option<Vec<u8>>>>,
) -> Result<Vec<u8>, BenchmarkError> {
    reader
        .join()
        .map_err(|_| signing_provider_error("signing command failed"))?
        .map_err(|_| signing_provider_error("signing command failed"))?
        .ok_or_else(|| signing_provider_error("signing command output is invalid"))
}

// Waits for one killed child to exit within the exact cleanup interval.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<i32, BenchmarkError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| signing_provider_error("signing command failed"))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
            Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) | Err(_) => return Err(signing_provider_error("signing command failed")),
        }
    }
}

// Returns one stable redacted signing failure.
fn signing_provider_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("signing", reason)
}

// Returns one stable cleanup failure without exposing a temporary path.
fn signing_cleanup_error() -> BenchmarkError {
    signing_provider_error("signing cleanup failed")
}
