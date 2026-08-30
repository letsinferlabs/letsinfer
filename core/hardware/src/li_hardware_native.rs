// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::HardwareError;

const MAX_NATIVE_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const NATIVE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const NATIVE_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);

// Isolates native file and process reads used by hardware providers.
pub trait HardwareNativeIo: Send + Sync {
    // Reads one exact native text file through an injected absolute path.
    fn read_text(&self, path: &Path) -> Result<String, HardwareError>;

    // Runs one exact absolute executable without a shell.
    fn run(&self, command: &Path, arguments: &[&str]) -> Result<String, HardwareError>;
}

// Uses the active host filesystem and process APIs for production observations.
pub trait HardwareCommandWait: Send + Sync {
    // Returns the maximum time allowed for child exit and complete output closure.
    fn timeout(&self) -> Duration;

    // Returns the bounded poll interval used while child and output remain incomplete.
    fn poll_interval(&self) -> Duration;
}

// Uses a monotonic deadline to bound production native command execution.
#[derive(Default)]
struct SystemHardwareCommandWait;

impl HardwareCommandWait for SystemHardwareCommandWait {
    // Returns the fixed production native command timeout.
    fn timeout(&self) -> Duration {
        NATIVE_COMMAND_TIMEOUT
    }

    // Returns the fixed production native command poll interval.
    fn poll_interval(&self) -> Duration {
        NATIVE_COMMAND_POLL_INTERVAL
    }
}

// Uses the active host filesystem and a bounded injected process waiter.
pub struct SystemHardwareNativeIo {
    wait: Arc<dyn HardwareCommandWait>,
}

impl SystemHardwareNativeIo {
    // Creates production native I/O with an explicit bounded command waiter.
    pub const fn new(wait: Arc<dyn HardwareCommandWait>) -> Self {
        Self { wait }
    }
}

impl Default for SystemHardwareNativeIo {
    // Creates production native I/O with the fixed monotonic timeout contract.
    fn default() -> Self {
        Self::new(Arc::new(SystemHardwareCommandWait))
    }
}

impl HardwareNativeIo for SystemHardwareNativeIo {
    // Reads one bounded UTF-8 native file.
    fn read_text(&self, path: &Path) -> Result<String, HardwareError> {
        let file = open_native_file(path, false)?;
        let bytes = read_bounded(file)?;
        if bytes.is_empty() {
            return Err(HardwareError::InvalidObservation {
                reason: "native file output is empty",
            });
        }
        String::from_utf8(bytes).map_err(|_| HardwareError::InvalidObservation {
            reason: "native file output is not UTF-8",
        })
    }

    // Runs one bounded native command with fixed arguments and captured output.
    fn run(&self, command: &Path, arguments: &[&str]) -> Result<String, HardwareError> {
        if arguments.len() > 32 || arguments.iter().any(|value| value.len() > 4096) {
            return Err(HardwareError::InvalidObservation {
                reason: "native command arguments are invalid or unbounded",
            });
        }
        let _command_file = open_native_file(command, true)?;
        let mut process = Command::new(command);
        process
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            process.process_group(0);
        }
        let mut child = process
            .spawn()
            .map_err(|_| HardwareError::ProviderUnavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(HardwareError::ProviderUnavailable)?;
        let (output_sender, output_receiver) = mpsc::sync_channel(1);
        let output_reader = thread::spawn(move || {
            let _ = output_sender.send(read_bounded(stdout));
        });
        let (status, bytes) = match wait_for_command(&mut child, &output_receiver, &*self.wait) {
            Ok(Some(completion)) => completion,
            Ok(None) => {
                terminate_child(&mut child);
                let _ = output_reader.join();
                return Err(HardwareError::ProviderUnavailable);
            }
            Err(error) => {
                terminate_child(&mut child);
                let _ = output_reader.join();
                return Err(error);
            }
        };
        output_reader
            .join()
            .map_err(|_| HardwareError::ProviderUnavailable)?;
        if !status.success() || bytes.is_empty() {
            return Err(HardwareError::ProviderUnavailable);
        }
        String::from_utf8(bytes).map_err(|_| HardwareError::InvalidObservation {
            reason: "native command output is not UTF-8",
        })
    }
}

// Waits until both direct-child status and every inherited stdout writer are complete.
fn wait_for_command(
    child: &mut Child,
    output: &mpsc::Receiver<Result<Vec<u8>, HardwareError>>,
    wait: &dyn HardwareCommandWait,
) -> Result<Option<(ExitStatus, Vec<u8>)>, HardwareError> {
    let timeout = wait.timeout();
    let poll_interval = wait.poll_interval();
    if timeout > NATIVE_COMMAND_TIMEOUT || poll_interval > NATIVE_COMMAND_TIMEOUT {
        return Err(HardwareError::InvalidObservation {
            reason: "native command wait policy is unbounded",
        });
    }
    let deadline =
        Instant::now()
            .checked_add(timeout)
            .ok_or(HardwareError::InvalidObservation {
                reason: "native command wait policy is invalid",
            })?;
    let mut status = None;
    let mut bytes = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| HardwareError::ProviderUnavailable)?;
        }
        if bytes.is_none() {
            match output.try_recv() {
                Ok(result) => bytes = Some(result?),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(HardwareError::ProviderUnavailable),
            }
        }
        if status.is_some() && bytes.is_some() {
            return Ok(Some((
                status.expect("checked status"),
                bytes.expect("checked output"),
            )));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

// Terminates and reaps one failed or timed-out native child without leaking it.
fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: this process created a dedicated positive process group with the child PID.
        let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = child.kill();
    let _ = child.wait();
}

// Opens one absolute owner-trusted regular native input without following its final path.
fn open_native_file(path: &Path, require_executable: bool) -> Result<File, HardwareError> {
    if !is_normal_absolute_path(path) {
        return Err(HardwareError::InvalidObservation {
            reason: "native path must be absolute and normalized",
        });
    }
    let canonical_path = fs::canonicalize(path).map_err(|_| HardwareError::ProviderUnavailable)?;
    if canonical_path != path {
        return Err(HardwareError::InvalidObservation {
            reason: "native path cannot contain symbolic links",
        });
    }
    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| HardwareError::ProviderUnavailable)?;
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| HardwareError::ProviderUnavailable)?;
    validate_native_file(&file, require_executable)?;
    Ok(file)
}

// Requires one native descriptor to remain regular, unaliased, trusted, and non-writable.
fn validate_native_file(file: &File, require_executable: bool) -> Result<(), HardwareError> {
    let metadata = file
        .metadata()
        .map_err(|_| HardwareError::ProviderUnavailable)?;
    if !metadata.is_file() {
        return Err(HardwareError::InvalidObservation {
            reason: "native input must be a regular file",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode();
        let owner = metadata.uid();
        if !has_safe_native_metadata(
            owner,
            effective_user_id(),
            metadata.nlink(),
            mode,
            require_executable,
        ) {
            return Err(HardwareError::InvalidObservation {
                reason: "native input ownership or mode is unsafe",
            });
        }
    }
    Ok(())
}

// Returns whether Unix native metadata is singly linked, owner-trusted, and mode-safe.
#[cfg(unix)]
const fn has_safe_native_metadata(
    owner: u32,
    effective_user: u32,
    link_count: u64,
    mode: u32,
    require_executable: bool,
) -> bool {
    link_count == 1
        && (owner == 0 || owner == effective_user)
        && mode & 0o022 == 0
        && (!require_executable || mode & 0o111 != 0)
}

// Returns the effective account trusted to own configured native dependencies.
#[cfg(unix)]
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and only reads the process credential identity.
    unsafe { libc::geteuid() }
}

// Reads one descriptor to a fixed bound before allocating any unbounded native output.
fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, HardwareError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_NATIVE_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| HardwareError::ProviderUnavailable)?;
    if bytes.len() > MAX_NATIVE_OUTPUT_BYTES {
        return Err(HardwareError::InvalidObservation {
            reason: "native output exceeds the supported bound",
        });
    }
    Ok(bytes)
}

// Returns whether one native path is absolute without traversal or redundant components.
fn is_normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::has_safe_native_metadata;

    // Rejects foreign owners, aliases, writable modes, and non-executable commands.
    #[test]
    fn native_metadata_contract_is_fail_closed() {
        assert!(has_safe_native_metadata(501, 501, 1, 0o100600, false));
        assert!(has_safe_native_metadata(0, 501, 1, 0o100755, true));
        assert!(!has_safe_native_metadata(502, 501, 1, 0o100600, false));
        assert!(!has_safe_native_metadata(501, 501, 2, 0o100600, false));
        assert!(!has_safe_native_metadata(501, 501, 1, 0o100622, false));
        assert!(!has_safe_native_metadata(501, 501, 1, 0o100600, true));
    }
}
