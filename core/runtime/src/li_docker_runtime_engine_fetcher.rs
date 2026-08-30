// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use li_core_interface::{CpuArchitecture, EngineDistribution, OperatingSystem};

use crate::{
    RuntimeCandidate, RuntimeEngineArtifactFetcher, RuntimeError, RuntimeExactCandidateArtifacts,
    RuntimeExactEngineArtifact, RuntimeExactEngineCleanup, RuntimeExactEngineOwnership,
};

const MAX_COMMAND_OUTPUT: usize = 4 * 1024;

// Carries one exact shell-free Docker Engine acquisition command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEngineCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    working_directory: PathBuf,
}

impl RuntimeEngineCommand {
    // Creates one bounded command with explicit environment ownership.
    pub fn new(
        executable: PathBuf,
        arguments: Vec<String>,
        environment: Vec<(String, String)>,
        working_directory: PathBuf,
    ) -> Result<Self, RuntimeError> {
        validate_environment(&environment)?;
        if !is_safe_absolute_path(&executable)
            || !is_safe_absolute_path(&working_directory)
            || arguments.is_empty()
            || arguments.len() > 64
            || arguments.iter().map(String::len).sum::<usize>() > 16 * 1024
            || arguments.iter().any(|value| {
                value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
            })
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(Self {
            executable,
            arguments,
            environment,
            working_directory,
        })
    }

    // Returns the exact executable path.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns exact argv without an executable token.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    // Returns sorted explicit process environment.
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    // Returns the exact private working directory.
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }
}

// Carries one bounded Docker command result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEngineCommandOutput {
    status: i32,
    stdout: Vec<u8>,
}

impl RuntimeEngineCommandOutput {
    // Creates one exact command result for production or deterministic mocks.
    pub const fn new(status: i32, stdout: Vec<u8>) -> Self {
        Self { status, stdout }
    }

    // Returns the process exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns bounded machine-readable standard output.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

// Defines shell-free Docker execution behind one deterministic boundary.
pub trait RuntimeEngineCommandRunner: Send + Sync {
    // Executes one exact command and bounds captured standard output.
    fn run(
        &self,
        command: &RuntimeEngineCommand,
        maximum_stdout_bytes: usize,
    ) -> Result<RuntimeEngineCommandOutput, RuntimeError>;
}

// Executes Docker directly without a shell or inherited process environment.
pub struct SystemRuntimeEngineCommandRunner;

impl RuntimeEngineCommandRunner for SystemRuntimeEngineCommandRunner {
    // Executes one exact Docker command with null stdin and stderr.
    fn run(
        &self,
        command: &RuntimeEngineCommand,
        maximum_stdout_bytes: usize,
    ) -> Result<RuntimeEngineCommandOutput, RuntimeError> {
        let output = Command::new(command.executable())
            .args(command.arguments())
            .env_clear()
            .envs(command.environment().iter().cloned())
            .current_dir(command.working_directory())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .output()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if output.stdout.len() > maximum_stdout_bytes {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(RuntimeEngineCommandOutput::new(
            output.status.code().unwrap_or(-1),
            output.stdout,
        ))
    }
}

// Defines private Engine receipt operations behind one deterministic boundary.
pub trait DockerRuntimeEngineIo: Send + Sync {
    // Requires one empty private Engine destination.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError>;

    // Writes one atomic secret-free verified Engine receipt.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError>;

    // Removes every contained acquisition entry while retaining the destination root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError>;
}

// Implements private no-follow Engine receipt operations on the host filesystem.
pub struct SystemDockerRuntimeEngineIo;

impl DockerRuntimeEngineIo for SystemDockerRuntimeEngineIo {
    // Requires one owner-only empty destination created by RuntimeManager staging.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if destination
            .read_dir()
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
            .next()
            .is_some()
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(())
    }

    // Writes and atomically activates one bounded canonical receipt.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if receipt.is_empty() || receipt.len() > 64 * 1024 {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let incoming = destination.join(".li_engine_oci_v1.json.incoming");
        let final_path = destination.join("li_engine_oci_v1.json");
        if incoming.exists()
            || incoming.is_symlink()
            || final_path.exists()
            || final_path.is_symlink()
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let mut file = create_new_file(&incoming, 0o600)?;
        file.write_all(receipt)
            .and_then(|_| file.sync_all())
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        fs::rename(&incoming, &final_path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
    }

    // Removes only regular files and private directories below the exact root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        clear_directory(destination)
    }
}

// Pulls and verifies exact OCI Engine image identity before recording its local availability.
pub struct DockerRuntimeEngineFetcher {
    docker: PathBuf,
    working_directory: PathBuf,
    environment: Vec<(String, String)>,
    runner: Arc<dyn RuntimeEngineCommandRunner>,
    io: Arc<dyn DockerRuntimeEngineIo>,
}

impl DockerRuntimeEngineFetcher {
    // Creates one provider from explicit Docker executable, environment, process, and I/O ports.
    pub fn new(
        docker: PathBuf,
        working_directory: PathBuf,
        environment: Vec<(String, String)>,
        runner: Arc<dyn RuntimeEngineCommandRunner>,
        io: Arc<dyn DockerRuntimeEngineIo>,
    ) -> Result<Self, RuntimeError> {
        validate_environment(&environment)?;
        if !is_safe_absolute_path(&docker) || !is_safe_absolute_path(&working_directory) {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(Self {
            docker,
            working_directory,
            environment,
            runner,
            io,
        })
    }

    // Inspects one exact image and returns its immutable ID plus normalized platform.
    fn inspect(&self, reference: &str) -> Result<Option<(String, String)>, RuntimeError> {
        let output = self.runner.run(
            &self.command(vec![
                "image".to_string(),
                "inspect".to_string(),
                reference.to_string(),
                "--format".to_string(),
                "{{.Id}}|{{.Os}}/{{.Architecture}}".to_string(),
            ])?,
            MAX_COMMAND_OUTPUT,
        )?;
        if output.status() != 0 {
            return Ok(None);
        }
        let value = std::str::from_utf8(output.stdout())
            .map_err(|_| RuntimeError::EngineAcquisitionInvalid)?
            .trim();
        let (identity, platform) = value
            .split_once('|')
            .ok_or(RuntimeError::EngineAcquisitionInvalid)?;
        if identity.is_empty() || platform.is_empty() || value.matches('|').count() != 1 {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(Some((identity.to_string(), normalized_platform(platform)?)))
    }

    // Pulls one exact image through fixed Docker argv.
    fn pull(&self, reference: &str, platform: &str) -> Result<(), RuntimeError> {
        let output = self.runner.run(
            &self.command(vec![
                "pull".to_string(),
                "--platform".to_string(),
                docker_platform(platform)?.to_string(),
                reference.to_string(),
            ])?,
            MAX_COMMAND_OUTPUT,
        )?;
        if output.status() != 0 {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        Ok(())
    }

    // Observes one exact reference and rejects a conflicting local image identity.
    fn exact_reference_present(
        &self,
        reference: &str,
        expected_identity: &str,
    ) -> Result<bool, RuntimeError> {
        match self.inspect(reference)? {
            Some((identity, _)) if identity == expected_identity => Ok(true),
            Some(_) => Err(RuntimeError::EngineAcquisitionInvalid),
            None => Ok(false),
        }
    }

    // Records exact configuration and tag state before any verifier image mutation.
    fn prepare_exact_ownership(
        &self,
        cleanup: &RuntimeExactEngineCleanup,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        let expected_identity = format!("sha256:{}", cleanup.config_digest().as_str());
        let preexisting_config =
            self.exact_reference_present(&expected_identity, &expected_identity)?;
        let preexisting_reference =
            self.exact_reference_present(cleanup.reference(), &expected_identity)?;
        let preexisting_local_tag = if cleanup.local_tag() == cleanup.reference() {
            preexisting_reference
        } else {
            self.exact_reference_present(cleanup.local_tag(), &expected_identity)?
        };
        RuntimeExactEngineOwnership::prepared(
            cleanup.clone(),
            preexisting_config,
            preexisting_reference,
            preexisting_local_tag,
        )
    }

    // Revalidates every identity whose exact presence is required by one ownership receipt.
    fn verify_exact_ownership(
        &self,
        ownership: &RuntimeExactEngineOwnership,
    ) -> Result<(), RuntimeError> {
        if !ownership.is_acquired() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let cleanup = ownership.cleanup();
        let expected_identity = format!("sha256:{}", cleanup.config_digest().as_str());
        if !self.exact_reference_present(&expected_identity, &expected_identity)? {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let reference_present =
            self.exact_reference_present(cleanup.reference(), &expected_identity)?;
        let local_tag_present = if cleanup.local_tag() == cleanup.reference() {
            reference_present
        } else {
            self.exact_reference_present(cleanup.local_tag(), &expected_identity)?
        };
        if (ownership.preexisting_reference() || ownership.created_reference())
            && !reference_present
            || (ownership.preexisting_local_tag() || ownership.created_local_tag())
                && !local_tag_present
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        Ok(())
    }

    // Loads one retained OCI archive and binds only transaction-owned image identities.
    fn load_exact(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        ownership: &RuntimeExactEngineOwnership,
        destination: &Path,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        self.io.prepare_destination(destination)?;
        let EngineDistribution::Oci {
            reference,
            immutable_id,
            ..
        } = candidate.runtime().engine_distribution()
        else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        };
        let RuntimeExactEngineArtifact::BuiltOci {
            archive_file,
            config_digest,
            local_tag,
        } = artifacts.engine()
        else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        };
        if config_digest != immutable_id || !is_safe_absolute_path(archive_file) {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        let result = (|| {
            let expected_identity = format!("sha256:{}", immutable_id.as_str());
            let expected_platform = target_platform(candidate)?;
            if ownership.cleanup().reference() != reference.as_str()
                || ownership.cleanup().local_tag() != local_tag
                || ownership.cleanup().config_digest() != config_digest
            {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            if ownership.is_acquired() {
                self.verify_exact_ownership(ownership)?;
                let receipt =
                    canonical_receipt(reference.as_str(), &expected_identity, &expected_platform)?;
                self.io.write_receipt(destination, &receipt)?;
                return Ok(ownership.clone());
            }
            let current = self.prepare_exact_ownership(ownership.cleanup())?;
            if current.preexisting_config() != ownership.preexisting_config()
                || current.preexisting_reference() != ownership.preexisting_reference()
                || current.preexisting_local_tag() != ownership.preexisting_local_tag()
            {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            let acquired = if ownership.preexisting_config() {
                ownership.acquired(false, false, false)?
            } else {
                let load_result = self.runner.run(
                    &self.command(vec![
                        "load".to_string(),
                        "--input".to_string(),
                        archive_file.display().to_string(),
                    ])?,
                    MAX_COMMAND_OUTPUT,
                );
                let config_present =
                    self.exact_reference_present(&expected_identity, &expected_identity)?;
                let local_tag_present =
                    self.exact_reference_present(local_tag, &expected_identity)?;
                if !config_present || !local_tag_present {
                    return match load_result {
                        Ok(output) if output.status() != 0 => {
                            Err(RuntimeError::EngineAcquisitionUnavailable)
                        }
                        Err(error) => Err(error),
                        _ => Err(RuntimeError::EngineAcquisitionInvalid),
                    };
                }
                let reference_present = if local_tag == reference.as_str() {
                    true
                } else if self.exact_reference_present(reference.as_str(), &expected_identity)? {
                    true
                } else {
                    let tag_result = self.runner.run(
                        &self.command(vec![
                            "tag".to_string(),
                            local_tag.clone(),
                            reference.as_str().to_string(),
                        ])?,
                        MAX_COMMAND_OUTPUT,
                    );
                    let present =
                        self.exact_reference_present(reference.as_str(), &expected_identity)?;
                    if !present {
                        return match tag_result {
                            Ok(output) if output.status() != 0 => {
                                Err(RuntimeError::EngineAcquisitionUnavailable)
                            }
                            Err(error) => Err(error),
                            _ => Err(RuntimeError::EngineAcquisitionInvalid),
                        };
                    }
                    true
                };
                ownership.acquired(true, reference_present, true)?
            };
            self.verify_exact_ownership(&acquired)?;
            let receipt =
                canonical_receipt(reference.as_str(), &expected_identity, &expected_platform)?;
            self.io.write_receipt(destination, &receipt)?;
            Ok(acquired)
        })();
        if result.is_err() {
            let _ = self.io.clear_destination(destination);
        }
        result
    }

    // Removes only image identities proven created by this exact transaction.
    fn remove_exact_image(
        &self,
        ownership: &RuntimeExactEngineOwnership,
    ) -> Result<(), RuntimeError> {
        let cleanup = ownership.cleanup();
        let expected_identity = format!("sha256:{}", cleanup.config_digest().as_str());
        if !ownership.is_acquired() {
            let current = self.prepare_exact_ownership(cleanup)?;
            return if current.preexisting_config() == ownership.preexisting_config()
                && current.preexisting_reference() == ownership.preexisting_reference()
                && current.preexisting_local_tag() == ownership.preexisting_local_tag()
            {
                Ok(())
            } else {
                Err(RuntimeError::EngineAcquisitionInvalid)
            };
        }
        if !ownership.created_config()
            && !ownership.created_reference()
            && !ownership.created_local_tag()
        {
            return Ok(());
        }
        let mut created_references = Vec::new();
        if ownership.created_reference() {
            created_references.push(cleanup.reference().to_string());
        }
        if ownership.created_local_tag() && cleanup.local_tag() != cleanup.reference() {
            created_references.push(cleanup.local_tag().to_string());
        }
        let mut present = Vec::new();
        for reference in &created_references {
            if self.exact_reference_present(reference, &expected_identity)? {
                present.push(reference.clone());
            }
        }
        if !present.is_empty() {
            let mut arguments = vec!["image".to_string(), "rm".to_string()];
            arguments.extend(present);
            let result = self
                .runner
                .run(&self.command(arguments)?, MAX_COMMAND_OUTPUT);
            let remaining = created_references
                .iter()
                .map(|reference| self.exact_reference_present(reference, &expected_identity))
                .collect::<Result<Vec<_>, _>>()?;
            if remaining.iter().any(|present| *present) {
                return match result {
                    Ok(output) if output.status() != 0 => {
                        Err(RuntimeError::EngineAcquisitionUnavailable)
                    }
                    Err(error) => Err(error),
                    _ => Err(RuntimeError::EngineAcquisitionInvalid),
                };
            }
        }
        if ownership.created_config()
            && self.exact_reference_present(&expected_identity, &expected_identity)?
        {
            let result = self.runner.run(
                &self.command(vec![
                    "image".to_string(),
                    "rm".to_string(),
                    expected_identity.clone(),
                ])?,
                MAX_COMMAND_OUTPUT,
            );
            if self.exact_reference_present(&expected_identity, &expected_identity)? {
                return match result {
                    Ok(output) if output.status() != 0 => {
                        Err(RuntimeError::EngineAcquisitionUnavailable)
                    }
                    Err(error) => Err(error),
                    _ => Err(RuntimeError::EngineAcquisitionInvalid),
                };
            }
        }
        Ok(())
    }

    // Creates one exact command from provider-owned Docker composition.
    fn command(&self, arguments: Vec<String>) -> Result<RuntimeEngineCommand, RuntimeError> {
        RuntimeEngineCommand::new(
            self.docker.clone(),
            arguments,
            self.environment.clone(),
            self.working_directory.clone(),
        )
    }

    // Acquires and verifies one exact OCI distribution for one candidate target.
    fn acquire(
        &self,
        candidate: &RuntimeCandidate,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.io.prepare_destination(destination)?;
        let EngineDistribution::Oci {
            reference,
            immutable_id,
            ..
        } = candidate.runtime().engine_distribution()
        else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        };
        let expected_platform = target_platform(candidate)?;
        let result = (|| {
            let observed = match self.inspect(reference.as_str())? {
                Some(value) => value,
                None => {
                    self.pull(reference.as_str(), &expected_platform)?;
                    self.inspect(reference.as_str())?
                        .ok_or(RuntimeError::EngineAcquisitionUnavailable)?
                }
            };
            let expected_identity = format!("sha256:{}", immutable_id.as_str());
            if observed.0 != expected_identity || observed.1 != expected_platform {
                return Err(RuntimeError::EngineAcquisitionInvalid);
            }
            let receipt =
                canonical_receipt(reference.as_str(), &expected_identity, &expected_platform)?;
            self.io.write_receipt(destination, &receipt)
        })();
        if result.is_err() {
            let _ = self.io.clear_destination(destination);
        }
        result
    }
}

impl RuntimeEngineArtifactFetcher for DockerRuntimeEngineFetcher {
    // Acquires one exact OCI Engine and ignores runtime-pack paths it does not own.
    fn fetch(
        &self,
        candidate: &RuntimeCandidate,
        _runtime_root: &Path,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.acquire(candidate, destination)
    }

    // Records exact local image ownership before any built verifier mutation.
    fn prepare_exact(
        &self,
        cleanup: &RuntimeExactEngineCleanup,
    ) -> Result<RuntimeExactEngineOwnership, RuntimeError> {
        self.prepare_exact_ownership(cleanup)
    }

    // Uses retained OCI bytes for a built verifier Engine and ordinary exact reuse otherwise.
    fn fetch_exact(
        &self,
        candidate: &RuntimeCandidate,
        artifacts: &RuntimeExactCandidateArtifacts,
        ownership: Option<&RuntimeExactEngineOwnership>,
        _runtime_root: &Path,
        destination: &Path,
    ) -> Result<Option<RuntimeExactEngineOwnership>, RuntimeError> {
        match artifacts.engine() {
            RuntimeExactEngineArtifact::BuiltOci { .. } => self
                .load_exact(
                    candidate,
                    artifacts,
                    ownership.ok_or(RuntimeError::EngineAcquisitionInvalid)?,
                    destination,
                )
                .map(Some),
            RuntimeExactEngineArtifact::Reuse if ownership.is_none() => {
                self.acquire(candidate, destination)?;
                Ok(None)
            }
            RuntimeExactEngineArtifact::Reuse => Err(RuntimeError::EngineAcquisitionInvalid),
            RuntimeExactEngineArtifact::BuiltNative => Err(RuntimeError::EngineAcquisitionInvalid),
        }
    }

    // Revalidates exact completed ownership before reusing an activated installation.
    fn verify_exact(&self, ownership: &RuntimeExactEngineOwnership) -> Result<(), RuntimeError> {
        self.verify_exact_ownership(ownership)
    }

    // Removes only the exact verifier-built OCI image tags recorded during acquisition.
    fn remove_exact(&self, ownership: &RuntimeExactEngineOwnership) -> Result<(), RuntimeError> {
        self.remove_exact_image(ownership)
    }
}

// Returns the canonical target platform identity.
fn target_platform(candidate: &RuntimeCandidate) -> Result<String, RuntimeError> {
    let operating_system = match candidate.target().operating_system() {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    };
    let architecture = match candidate.target().architecture() {
        CpuArchitecture::Arm64 => "arm64",
        CpuArchitecture::X86_64 => "x86_64",
    };
    let platform = format!("{operating_system}/{architecture}");
    if operating_system != "linux" {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(platform)
}

// Returns Docker's platform spelling for one canonical Core platform.
fn docker_platform(platform: &str) -> Result<&'static str, RuntimeError> {
    match platform {
        "linux/arm64" => Ok("linux/arm64"),
        "linux/x86_64" => Ok("linux/amd64"),
        _ => Err(RuntimeError::EngineAcquisitionInvalid),
    }
}

// Normalizes Docker's architecture spelling into Core's canonical platform.
fn normalized_platform(platform: &str) -> Result<String, RuntimeError> {
    match platform {
        "linux/arm64" | "linux/aarch64" => Ok("linux/arm64".to_string()),
        "linux/amd64" | "linux/x86_64" => Ok("linux/x86_64".to_string()),
        _ => Err(RuntimeError::EngineAcquisitionInvalid),
    }
}

// Encodes one deterministic secret-free Engine receipt.
fn canonical_receipt(
    reference: &str,
    immutable_id: &str,
    platform: &str,
) -> Result<Vec<u8>, RuntimeError> {
    let value = serde_json::json!({
        "schema": {"name": "li_engine_oci_receipt", "version": 1},
        "reference": reference,
        "immutable_id": immutable_id,
        "platform": platform
    });
    let mut bytes =
        serde_json::to_vec(&value).map_err(|_| RuntimeError::EngineAcquisitionInvalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Validates a sorted bounded non-secret process environment.
fn validate_environment(environment: &[(String, String)]) -> Result<(), RuntimeError> {
    let names: HashSet<&str> = environment.iter().map(|(name, _)| name.as_str()).collect();
    if environment.len() > 64
        || names.len() != environment.len()
        || environment
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
            > 16 * 1024
        || environment.iter().any(|(name, value)| {
            !is_environment_name(name)
                || is_sensitive_name(name)
                || value.len() > 4_096
                || value.chars().any(char::is_control)
        })
    {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    Ok(())
}

// Returns whether one process environment name uses a portable uppercase alphabet.
fn is_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

// Returns whether one environment name could carry embedded credential material.
fn is_sensitive_name(value: &str) -> bool {
    ["AUTH", "CREDENTIAL", "PASSWORD", "SECRET", "TOKEN"]
        .iter()
        .any(|marker| value.contains(marker))
}

// Returns whether one absolute path has no parent or platform-prefix ambiguity.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Requires one no-follow owner-only directory.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::EngineAcquisitionInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
    }
    Ok(())
}

// Removes every safe contained receipt entry from one private directory.
fn clear_directory(path: &Path) -> Result<(), RuntimeError> {
    for entry in path
        .read_dir()
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
    {
        let path = entry
            .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?
            .path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
        if metadata.is_dir() {
            clear_directory(&path)?;
            fs::remove_dir(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        } else if metadata.is_file() {
            fs::remove_file(&path).map_err(|_| RuntimeError::EngineAcquisitionUnavailable)?;
        } else {
            return Err(RuntimeError::EngineAcquisitionInvalid);
        }
    }
    Ok(())
}

// Creates one no-follow regular file with an exact mode.
fn create_new_file(path: &Path, mode: u32) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| RuntimeError::EngineAcquisitionUnavailable)
}
