// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::PairingError;

const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_ARGUMENT_VALUE_BYTES: usize = 4 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

// Stores one closed shell-free native command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingNativeCommand {
    executable: PathBuf,
    arguments: Vec<String>,
}

impl PairingNativeCommand {
    // Creates one absolute executable and bounded argv without a shell or inherited arguments.
    pub fn new(executable: PathBuf, arguments: Vec<String>) -> Result<Self, PairingError> {
        validate_executable(&executable)?;
        validate_arguments(&arguments)?;
        Ok(Self {
            executable,
            arguments,
        })
    }

    // Returns the exact absolute executable path.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns exact argv values without an executable or shell string.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

// Returns one bounded native command result for production or deterministic mocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingNativeCommandOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

impl PairingNativeCommandOutput {
    // Creates one exact process result without interpreting its bytes.
    pub const fn new(status: i32, stdout: Vec<u8>, stderr: Vec<u8>, timed_out: bool) -> Self {
        Self {
            status,
            stdout,
            stderr,
            timed_out,
        }
    }

    // Returns the native process exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns bounded standard output required for machine parsing.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    // Returns bounded standard error for diagnostics at the composition boundary.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    // Returns whether the runner stopped the process at its exact deadline.
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }
}

// Owns one long-running native publisher process behind a mockable lifecycle.
pub trait PairingNativeProcess: Send {
    // Proves that the process survives its bounded startup interval.
    fn require_running(&mut self, startup_timeout: Duration) -> Result<(), PairingError>;

    // Stops the exact process and waits only for the supplied bounded interval.
    fn stop(&mut self, shutdown_timeout: Duration) -> Result<(), PairingError>;
}

// Executes exact native argv and owns publisher process construction.
pub trait PairingNativeCommandRunner: Send + Sync {
    // Executes one command with bounded time and output collection.
    fn run(
        &self,
        command: &PairingNativeCommand,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError>;

    // Starts one long-running command without routing it through a shell.
    fn spawn(
        &self,
        command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError>;
}

// Executes pairing-native commands on the active host.
#[derive(Default)]
pub struct SystemPairingNativeCommandRunner;

impl PairingNativeCommandRunner for SystemPairingNativeCommandRunner {
    // Executes exact argv with empty stdin, bounded capture, and forced deadline cleanup.
    fn run(
        &self,
        command: &PairingNativeCommand,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError> {
        if timeout.is_zero() || maximum_output_bytes == 0 {
            return Err(PairingError::DiscoveryUnavailable);
        }
        let mut child = native_command(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let stdout_reader = thread::spawn(move || drain_bounded(stdout, maximum_output_bytes));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr, maximum_output_bytes));
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break exit_status(status.code()),
                Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
                Ok(None) => {
                    timed_out = true;
                    if child.kill().is_err() {
                        let _ = wait_for_exit(&mut child, Duration::from_secs(1));
                        return Err(PairingError::DiscoveryUnavailable);
                    }
                    break wait_for_exit(&mut child, Duration::from_secs(1))?;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = wait_for_exit(&mut child, Duration::from_secs(1));
                    return Err(PairingError::DiscoveryUnavailable);
                }
            }
        };
        let stdout = join_output(stdout_reader)?;
        let stderr = join_output(stderr_reader)?;
        if stdout
            .len()
            .checked_add(stderr.len())
            .is_none_or(|count| count > maximum_output_bytes)
        {
            return Err(PairingError::DiscoveryUnavailable);
        }
        Ok(PairingNativeCommandOutput::new(
            status, stdout, stderr, timed_out,
        ))
    }

    // Starts one exact publisher with all inherited stream capabilities closed.
    fn spawn(
        &self,
        command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError> {
        let child = native_command(command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        Ok(Box::new(SystemPairingNativeProcess { child: Some(child) }))
    }
}

// Owns one system publisher process until explicit shutdown or drop.
struct SystemPairingNativeProcess {
    child: Option<Child>,
}

impl PairingNativeProcess for SystemPairingNativeProcess {
    // Rejects a publisher that exits before its startup proof interval completes.
    fn require_running(&mut self, startup_timeout: Duration) -> Result<(), PairingError> {
        let child = self
            .child
            .as_mut()
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let deadline = Instant::now()
            .checked_add(startup_timeout)
            .ok_or(PairingError::DiscoveryUnavailable)?;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    return Err(PairingError::DiscoveryUnavailable);
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
                Ok(None) => return Ok(()),
                Err(_) => return Err(PairingError::DiscoveryUnavailable),
            }
        }
    }

    // Kills only the owned publisher and proves its bounded retirement.
    fn stop(&mut self, shutdown_timeout: Duration) -> Result<(), PairingError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if child
            .try_wait()
            .map_err(|_| PairingError::DiscoveryUnavailable)?
            .is_some()
        {
            return Ok(());
        }
        child
            .kill()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        wait_for_exit(&mut child, shutdown_timeout).map(|_| ())
    }
}

impl Drop for SystemPairingNativeProcess {
    // Prevents an abandoned provider from leaving its exact publisher resident.
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = wait_for_exit(child, Duration::from_secs(1));
        }
        self.child = None;
    }
}

// Creates one closed process builder from validated command input.
fn native_command(command: &PairingNativeCommand) -> Command {
    let mut native = Command::new(command.executable());
    native
        .args(command.arguments())
        .env_clear()
        .stdin(Stdio::null());
    native
}

// Drains one stream completely while retaining no more than its exact byte cap.
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

// Joins one bounded output reader without accepting panic, I/O, or size failure.
fn join_output(
    reader: thread::JoinHandle<io::Result<Option<Vec<u8>>>>,
) -> Result<Vec<u8>, PairingError> {
    reader
        .join()
        .map_err(|_| PairingError::DiscoveryUnavailable)?
        .map_err(|_| PairingError::DiscoveryUnavailable)?
        .ok_or(PairingError::DiscoveryUnavailable)
}

// Polls one killed child until it exits or its bounded cleanup window ends.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<i32, PairingError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(PairingError::DiscoveryUnavailable)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(exit_status(status.code())),
            Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) | Err(_) => return Err(PairingError::DiscoveryUnavailable),
        }
    }
}

// Normalizes an unavailable signal exit code without fabricating success.
const fn exit_status(status: Option<i32>) -> i32 {
    match status {
        Some(status) => status,
        None => -1,
    }
}

// Rejects non-absolute, shell, and malformed executable identities.
fn validate_executable(executable: &Path) -> Result<(), PairingError> {
    if !executable.is_absolute()
        || executable
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || executable.file_name().is_none()
        || matches!(
            executable.file_name().and_then(OsStr::to_str),
            Some("bash" | "dash" | "env" | "fish" | "ksh" | "sh" | "zsh")
        )
    {
        return Err(PairingError::InvalidRequest {
            reason: "pairing native executable must be an absolute non-shell path",
        });
    }
    Ok(())
}

// Rejects oversized or control-bearing argv before native execution.
fn validate_arguments(arguments: &[String]) -> Result<(), PairingError> {
    let total_bytes = arguments.iter().map(String::len).sum::<usize>();
    if arguments.len() > MAX_ARGUMENTS
        || total_bytes > MAX_ARGUMENT_BYTES
        || arguments.iter().any(|value| {
            value.len() > MAX_ARGUMENT_VALUE_BYTES
                || value.is_empty()
                || value.chars().any(char::is_control)
        })
    {
        return Err(PairingError::InvalidRequest {
            reason: "pairing native command arguments are invalid",
        });
    }
    Ok(())
}
