// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::PlacementError;

const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 32 * 1024;
const MAX_ENVIRONMENT: usize = 128;
const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024;
const MAX_VALUE_BYTES: usize = 4_096;
const FORBIDDEN_EXECUTABLES: &[&str] = &[
    "bash",
    "dash",
    "env",
    "fish",
    "ksh",
    "powershell",
    "pwsh",
    "sh",
    "zsh",
];

// Stores one validated environment field without shell interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellFreeEnvironmentValue {
    name: String,
    value: String,
    ownership: EnvironmentOwnership,
}

// Identifies whether one environment value belongs to a runtime or Core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnvironmentOwnership {
    Runtime,
    Core,
}

impl ShellFreeEnvironmentValue {
    // Creates one bounded runtime-owned environment value.
    pub fn runtime(name: &str, value: &str) -> Result<Self, PlacementError> {
        if name.starts_with("LETSINFER_") {
            return Err(PlacementError::InvalidRequest {
                reason: "runtime environment cannot override protected LETSINFER_ values",
            });
        }
        environment_value(name, value, EnvironmentOwnership::Runtime)
    }

    // Creates one bounded Core-owned protected environment value.
    pub fn protected(name: &str, value: &str) -> Result<Self, PlacementError> {
        if !name.starts_with("LETSINFER_") {
            return Err(PlacementError::InvalidRequest {
                reason: "protected environment must use the LETSINFER_ namespace",
            });
        }
        environment_value(name, value, EnvironmentOwnership::Core)
    }

    // Creates one bounded Core-owned native environment value.
    pub fn core(name: &str, value: &str) -> Result<Self, PlacementError> {
        environment_value(name, value, EnvironmentOwnership::Core)
    }

    // Returns the canonical environment name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // Returns the exact environment value.
    pub fn value(&self) -> &str {
        &self.value
    }

    // Returns whether this value belongs to Core rather than runtime input.
    pub(crate) const fn is_core_owned(&self) -> bool {
        matches!(self.ownership, EnvironmentOwnership::Core)
    }

    // Returns whether this value belongs to runtime-authored configuration.
    pub(crate) const fn is_runtime_owned(&self) -> bool {
        matches!(self.ownership, EnvironmentOwnership::Runtime)
    }

    // Rejects secret-bearing environment names or values before plan persistence.
    pub(crate) fn validate_persistable(&self) -> Result<(), PlacementError> {
        if looks_like_secret(self.value()) || sensitive_name_requires_reference(self.name()) {
            return Err(PlacementError::InvalidRequest {
                reason: "durable launch plan cannot contain secret environment values",
            });
        }
        Ok(())
    }

    // Returns the private persistence name for environment ownership.
    pub(crate) const fn ownership_name(&self) -> &'static str {
        match self.ownership {
            EnvironmentOwnership::Runtime => "runtime",
            EnvironmentOwnership::Core => "core",
        }
    }
}

// Stores one fully resolved command that cannot invoke a shell implicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellFreeCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    environment: Vec<ShellFreeEnvironmentValue>,
    working_directory: PathBuf,
}

impl ShellFreeCommand {
    // Creates one absolute shell-free command with closed environment ownership.
    pub fn new(
        executable: PathBuf,
        arguments: Vec<String>,
        runtime_environment: Vec<ShellFreeEnvironmentValue>,
        protected_environment: Vec<ShellFreeEnvironmentValue>,
        working_directory: PathBuf,
    ) -> Result<Self, PlacementError> {
        validate_executable(&executable)?;
        validate_arguments(&arguments)?;
        if !working_directory.is_absolute() {
            return Err(PlacementError::InvalidRequest {
                reason: "shell-free working directory must be absolute",
            });
        }
        let mut environment = runtime_environment;
        if environment
            .iter()
            .any(|value| value.ownership != EnvironmentOwnership::Runtime)
            || protected_environment
                .iter()
                .any(|value| value.ownership != EnvironmentOwnership::Core)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "shell-free environment ownership is invalid",
            });
        }
        environment.extend(protected_environment);
        validate_environment(&environment)?;
        Ok(Self {
            executable,
            arguments,
            environment,
            working_directory,
        })
    }

    // Returns the absolute executable path.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns exact argv values without an executable or shell string.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    // Returns the complete closed environment.
    pub fn environment(&self) -> &[ShellFreeEnvironmentValue] {
        &self.environment
    }

    // Returns the exact working directory.
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    // Reuses executable and environment for one fixed Core-owned subcommand.
    pub fn with_arguments(&self, arguments: Vec<String>) -> Result<Self, PlacementError> {
        validate_arguments(&arguments)?;
        Ok(Self {
            executable: self.executable.clone(),
            arguments,
            environment: self.environment.clone(),
            working_directory: self.working_directory.clone(),
        })
    }

    // Rejects secret-bearing argv or environment before durable plan storage.
    pub(crate) fn validate_persistable(&self) -> Result<(), PlacementError> {
        if self.arguments.iter().any(|value| {
            looks_like_secret(value)
                || value
                    .strip_prefix('-')
                    .map(|name| {
                        name.trim_start_matches('-')
                            .replace('-', "_")
                            .to_ascii_uppercase()
                    })
                    .is_some_and(|name| sensitive_name_requires_reference(&name))
        }) || self.environment.iter().any(|value| {
            looks_like_secret(value.value()) || sensitive_name_requires_reference(value.name())
        }) {
            return Err(PlacementError::InvalidRequest {
                reason: "durable launch plan cannot contain secret values",
            });
        }
        Ok(())
    }
}

// Returns one bounded shell-free command result without stderr or secret output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellFreeCommandOutput {
    status: i32,
    stdout: Vec<u8>,
}

impl ShellFreeCommandOutput {
    // Creates one exact process result for production or deterministic mocks.
    pub const fn new(status: i32, stdout: Vec<u8>) -> Self {
        Self { status, stdout }
    }

    // Returns the native process exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns bounded standard output required for machine parsing.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

// Defines shell-free native command execution behind one mockable boundary.
pub trait ShellFreeCommandRunner: Send + Sync {
    // Executes exact argv and bounds captured standard output.
    fn run(
        &self,
        command: &ShellFreeCommand,
        maximum_stdout_bytes: usize,
    ) -> Result<ShellFreeCommandOutput, PlacementError>;

    // Executes exact argv while retaining both bounded output streams for opaque runtime logs.
    fn run_combined(
        &self,
        command: &ShellFreeCommand,
        maximum_output_bytes: usize,
    ) -> Result<ShellFreeCommandOutput, PlacementError> {
        self.run(command, maximum_output_bytes)
    }
}

// Executes commands directly through the operating-system process API.
#[derive(Default)]
pub struct SystemShellFreeCommandRunner;

impl ShellFreeCommandRunner for SystemShellFreeCommandRunner {
    // Executes one command with no shell, inherited environment, or unbounded output.
    fn run(
        &self,
        command: &ShellFreeCommand,
        maximum_stdout_bytes: usize,
    ) -> Result<ShellFreeCommandOutput, PlacementError> {
        if maximum_stdout_bytes == 0 || maximum_stdout_bytes > 16 * 1024 * 1024 {
            return Err(PlacementError::InvalidRequest {
                reason: "shell-free command output bound is invalid",
            });
        }
        validate_system_executable(command.executable())?;
        let output = Command::new(command.executable())
            .args(command.arguments())
            .env_clear()
            .envs(
                command
                    .environment()
                    .iter()
                    .map(|value| (value.name(), value.value())),
            )
            .current_dir(command.working_directory())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if output.stdout.len() > maximum_stdout_bytes {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(ShellFreeCommandOutput::new(
            output.status.code().unwrap_or(-1),
            output.stdout,
        ))
    }

    // Executes exact argv and combines both bounded native streams without a shell.
    fn run_combined(
        &self,
        command: &ShellFreeCommand,
        maximum_output_bytes: usize,
    ) -> Result<ShellFreeCommandOutput, PlacementError> {
        if maximum_output_bytes == 0 || maximum_output_bytes > 16 * 1024 * 1024 {
            return Err(PlacementError::InvalidRequest {
                reason: "shell-free command output bound is invalid",
            });
        }
        validate_system_executable(command.executable())?;
        let output = Command::new(command.executable())
            .args(command.arguments())
            .env_clear()
            .envs(
                command
                    .environment()
                    .iter()
                    .map(|value| (value.name(), value.value())),
            )
            .current_dir(command.working_directory())
            .output()
            .map_err(|_| PlacementError::ExecutionUnavailable)?;
        if output.stdout.len().saturating_add(output.stderr.len()) > maximum_output_bytes {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        Ok(ShellFreeCommandOutput::new(
            output.status.code().unwrap_or(-1),
            combined,
        ))
    }
}

// Creates one validated environment value without classifying its owner.
fn environment_value(
    name: &str,
    value: &str,
    ownership: EnvironmentOwnership,
) -> Result<ShellFreeEnvironmentValue, PlacementError> {
    if !valid_environment_name(name)
        || value.len() > MAX_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(PlacementError::InvalidRequest {
            reason: "shell-free environment value is invalid",
        });
    }
    Ok(ShellFreeEnvironmentValue {
        name: name.to_string(),
        value: value.to_string(),
        ownership,
    })
}

// Requires one absolute executable that is not a shell or environment trampoline.
fn validate_executable(executable: &Path) -> Result<(), PlacementError> {
    let name = executable
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PlacementError::InvalidRequest {
            reason: "shell-free executable path is invalid",
        })?;
    if !executable.is_absolute() || FORBIDDEN_EXECUTABLES.contains(&name) {
        return Err(PlacementError::InvalidRequest {
            reason: "shell-free executable cannot be relative or a shell",
        });
    }
    Ok(())
}

// Requires one non-symlink, executable, non-writable native binary.
pub(crate) fn validate_system_executable(executable: &Path) -> Result<(), PlacementError> {
    let metadata =
        fs::symlink_metadata(executable).map_err(|_| PlacementError::ExecutionUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(PlacementError::ExecutionUnavailable);
    }
    Ok(())
}

// Requires bounded argv values without control characters or empty ambiguity.
fn validate_arguments(arguments: &[String]) -> Result<(), PlacementError> {
    let bytes = arguments.iter().map(String::len).sum::<usize>();
    if arguments.len() > MAX_ARGUMENTS
        || bytes > MAX_ARGUMENT_BYTES
        || arguments.iter().any(|value| {
            value.is_empty() || value.len() > MAX_VALUE_BYTES || value.chars().any(char::is_control)
        })
    {
        return Err(PlacementError::InvalidRequest {
            reason: "shell-free command arguments are invalid or unbounded",
        });
    }
    Ok(())
}

// Requires unique bounded environment names across runtime and Core ownership.
fn validate_environment(environment: &[ShellFreeEnvironmentValue]) -> Result<(), PlacementError> {
    let names: HashSet<&str> = environment.iter().map(|value| value.name()).collect();
    let bytes = environment
        .iter()
        .map(|value| value.name().len() + value.value().len())
        .sum::<usize>();
    if environment.len() > MAX_ENVIRONMENT
        || names.len() != environment.len()
        || bytes > MAX_ENVIRONMENT_BYTES
    {
        return Err(PlacementError::InvalidRequest {
            reason: "shell-free command environment is duplicated or unbounded",
        });
    }
    Ok(())
}

// Returns whether one environment name uses the canonical process alphabet.
fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

// Returns whether one sensitive field name lacks an explicit reference suffix.
fn sensitive_name_requires_reference(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let sensitive = upper.contains("PASSWORD")
        || upper.contains("SECRET")
        || upper.contains("API_KEY")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("SIGNING_KEY")
        || upper.contains("ENCRYPTION_KEY")
        || upper.contains("ACCESS_TOKEN")
        || upper.contains("AUTH_TOKEN")
        || upper.contains("CREDENTIAL")
        || upper == "TOKEN"
        || upper.ends_with("_TOKEN");
    let reference = ["_FILE", "_PATH", "_ID", "_SHA256", "_DIGEST"]
        .iter()
        .any(|suffix| upper.ends_with(suffix));
    sensitive && !reference
}

// Returns whether one value resembles private key or bearer material.
fn looks_like_secret(value: &str) -> bool {
    let bearer = value
        .strip_prefix("li_")
        .and_then(|value| value.split_once('_'));
    value.contains("-----BEGIN")
        || value.contains(concat!("PRIVATE", " KEY"))
        || ((value.starts_with("ghp_")
            || value.starts_with("hf_")
            || value.starts_with("sk-")
            || value.starts_with("sk_"))
            && value.len() > 24)
        || bearer.is_some_and(|(identity, secret)| {
            identity.len() == 32
                && secret.len() == 64
                && identity
                    .bytes()
                    .chain(secret.bytes())
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
