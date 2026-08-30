// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::MachineId;

use crate::{CoreSetupIdentitySourceError, CoreSetupMachineIdentityProvider};

const LINUX_MACHINE_IDENTITY_MAXIMUM_BYTES: usize = 33;
const LINUX_MACHINE_IDENTITY_PATH: &str = "/etc/machine-id";
const LINUX_MACHINE_IDENTITY_MODE: u32 = 0o444;
const SYSTEM_OWNER_USER_ID: u32 = 0;
const MACOS_IOREG_ARGUMENTS: [&str; 3] = ["-rd1", "-c", "IOPlatformExpertDevice"];
const MACOS_IOREG_MAXIMUM_OUTPUT_BYTES: usize = 64 * 1024;
const MACOS_IOREG_MAXIMUM_TIMEOUT: Duration = Duration::from_secs(5);
const MACOS_IOREG_EXECUTABLE_MODE: u32 = 0o755;

// Reads one exact native machine-identity file through a caller-selected safety boundary.
pub trait CoreSetupMachineIdentityFileReader: Send + Sync {
    // Returns one bounded file document without following any path component.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, CoreSetupIdentitySourceError>;
}

// Runs one exact native machine-identity command through a caller-selected process boundary.
pub trait CoreSetupMachineIdentityCommandRunner: Send + Sync {
    // Returns bounded stdout from one successful shell-free command.
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        owner_user_id: u32,
        timeout: Duration,
        poll_interval: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<Vec<u8>, CoreSetupIdentitySourceError>;
}

// Supplies production descriptor-anchored machine-identity file reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreSetupMachineIdentityFileReader;

impl CoreSetupMachineIdentityFileReader for SystemCoreSetupMachineIdentityFileReader {
    // Opens every component without following links and validates the stable final descriptor.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, CoreSetupIdentitySourceError> {
        if maximum_bytes == 0 || maximum_bytes > LINUX_MACHINE_IDENTITY_MAXIMUM_BYTES {
            return Err(CoreSetupIdentitySourceError::Invalid);
        }
        let mut file = open_absolute_file_no_follow(path)?;
        let before = validate_machine_identity_file(&file, owner_user_id, maximum_bytes)?;
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
        let after = validate_machine_identity_file(&file, owner_user_id, maximum_bytes)?;
        if bytes.len() as u64 != before.len()
            || bytes.len() > maximum_bytes
            || !same_file(&before, &after)
        {
            return Err(CoreSetupIdentitySourceError::Invalid);
        }
        Ok(bytes)
    }
}

// Supplies production shell-free, bounded, kill-on-timeout machine-identity commands.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreSetupMachineIdentityCommandRunner;

impl CoreSetupMachineIdentityCommandRunner for SystemCoreSetupMachineIdentityCommandRunner {
    // Executes one owner-bound immutable binary without inherited environment or diagnostics.
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        owner_user_id: u32,
        timeout: Duration,
        poll_interval: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<Vec<u8>, CoreSetupIdentitySourceError> {
        validate_machine_identity_executable(executable, owner_user_id)?;
        validate_machine_identity_command(arguments, timeout, poll_interval, maximum_stdout_bytes)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(CoreSetupIdentitySourceError::Invalid)?;
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command
            .spawn()
            .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            return Err(CoreSetupIdentitySourceError::Unavailable);
        };
        let (output_sender, output_receiver) = mpsc::sync_channel(1);
        let output_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(maximum_stdout_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = output_sender.send(result);
        });
        let mut status = None;
        let mut output = None;
        loop {
            if status.is_none() {
                match child.try_wait() {
                    Ok(value) => status = value,
                    Err(_) => {
                        terminate_child(&mut child);
                        let _ = output_reader.join();
                        return Err(CoreSetupIdentitySourceError::Unavailable);
                    }
                }
            }
            if output.is_none() {
                match output_receiver.try_recv() {
                    Ok(Ok(value)) => output = Some(value),
                    Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                        terminate_child(&mut child);
                        let _ = output_reader.join();
                        return Err(CoreSetupIdentitySourceError::Unavailable);
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            if status.is_some() && output.is_some() {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                terminate_child(&mut child);
                let _ = output_reader.join();
                return Err(CoreSetupIdentitySourceError::Unavailable);
            }
            thread::sleep(poll_interval.min(remaining));
        }
        output_reader
            .join()
            .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
        let output = output.ok_or(CoreSetupIdentitySourceError::Unavailable)?;
        let status = status.ok_or(CoreSetupIdentitySourceError::Unavailable)?;
        if output.len() > maximum_stdout_bytes {
            return Err(CoreSetupIdentitySourceError::Invalid);
        }
        if !status.success() {
            return Err(CoreSetupIdentitySourceError::Unavailable);
        }
        if output.is_empty() {
            return Err(CoreSetupIdentitySourceError::Invalid);
        }
        Ok(output)
    }
}

// Reaps one complete native process group after any ambiguous process boundary.
fn terminate_child(child: &mut Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: the command created a dedicated positive process group with its child PID.
        let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
        if result != 0 {
            let _ = child.kill();
        }
    } else {
        let _ = child.kill();
    }
    let _ = child.wait();
}

// Reads one canonical Linux machine-id file through an injected native file boundary.
pub struct LinuxCoreSetupMachineIdentityProvider {
    path: PathBuf,
    owner_user_id: u32,
    reader: Arc<dyn CoreSetupMachineIdentityFileReader>,
}

impl LinuxCoreSetupMachineIdentityProvider {
    // Creates one Linux source from an exact file path, owner, and mockable reader.
    pub fn new(
        path: PathBuf,
        owner_user_id: u32,
        reader: Arc<dyn CoreSetupMachineIdentityFileReader>,
    ) -> Self {
        Self {
            path,
            owner_user_id,
            reader,
        }
    }

    // Creates the production Linux source from the fixed root-owned system identity file.
    pub fn system(reader: Arc<dyn CoreSetupMachineIdentityFileReader>) -> Self {
        Self {
            path: PathBuf::from(LINUX_MACHINE_IDENTITY_PATH),
            owner_user_id: SYSTEM_OWNER_USER_ID,
            reader,
        }
    }
}

impl CoreSetupMachineIdentityProvider for LinuxCoreSetupMachineIdentityProvider {
    // Reads exactly 32 lowercase hexadecimal bytes with at most one trailing newline.
    fn machine_id(&self) -> Result<MachineId, CoreSetupIdentitySourceError> {
        let bytes = self.reader.read(
            &self.path,
            self.owner_user_id,
            LINUX_MACHINE_IDENTITY_MAXIMUM_BYTES,
        )?;
        parse_linux_machine_identity(&bytes)
    }
}

// Reads one canonical IOPlatformUUID through an injected macOS ioreg process boundary.
pub struct MacosCoreSetupMachineIdentityProvider {
    executable: PathBuf,
    owner_user_id: u32,
    timeout: Duration,
    poll_interval: Duration,
    runner: Arc<dyn CoreSetupMachineIdentityCommandRunner>,
}

impl MacosCoreSetupMachineIdentityProvider {
    // Creates one macOS source from an exact executable, owner, deadline, and mockable runner.
    pub fn new(
        executable: PathBuf,
        owner_user_id: u32,
        timeout: Duration,
        poll_interval: Duration,
        runner: Arc<dyn CoreSetupMachineIdentityCommandRunner>,
    ) -> Self {
        Self {
            executable,
            owner_user_id,
            timeout,
            poll_interval,
            runner,
        }
    }

    // Creates the production macOS source from a root-owned native system executable.
    pub fn system(
        executable: PathBuf,
        timeout: Duration,
        poll_interval: Duration,
        runner: Arc<dyn CoreSetupMachineIdentityCommandRunner>,
    ) -> Self {
        Self {
            executable,
            owner_user_id: SYSTEM_OWNER_USER_ID,
            timeout,
            poll_interval,
            runner,
        }
    }
}

impl CoreSetupMachineIdentityProvider for MacosCoreSetupMachineIdentityProvider {
    // Runs the fixed ioreg query and normalizes its unique IOPlatformUUID to Core identity form.
    fn machine_id(&self) -> Result<MachineId, CoreSetupIdentitySourceError> {
        validate_machine_identity_command(
            &MACOS_IOREG_ARGUMENTS,
            self.timeout,
            self.poll_interval,
            MACOS_IOREG_MAXIMUM_OUTPUT_BYTES,
        )?;
        let output = self.runner.run(
            &self.executable,
            &MACOS_IOREG_ARGUMENTS,
            self.owner_user_id,
            self.timeout,
            self.poll_interval,
            MACOS_IOREG_MAXIMUM_OUTPUT_BYTES,
        )?;
        if output.is_empty() || output.len() > MACOS_IOREG_MAXIMUM_OUTPUT_BYTES {
            return Err(CoreSetupIdentitySourceError::Invalid);
        }
        parse_macos_machine_identity(&output)
    }
}

// Parses the exact systemd machine-id text form without trimming unexpected whitespace.
fn parse_linux_machine_identity(bytes: &[u8]) -> Result<MachineId, CoreSetupIdentitySourceError> {
    let value = match bytes {
        [value @ .., b'\n'] if value.len() == 32 => value,
        value if value.len() == 32 => value,
        _ => return Err(CoreSetupIdentitySourceError::Invalid),
    };
    let value = std::str::from_utf8(value).map_err(|_| CoreSetupIdentitySourceError::Invalid)?;
    parse_nonzero_machine_identity(value)
}

// Extracts exactly one canonical ioreg IOPlatformUUID property from bounded UTF-8 output.
fn parse_macos_machine_identity(bytes: &[u8]) -> Result<MachineId, CoreSetupIdentitySourceError> {
    let output = std::str::from_utf8(bytes).map_err(|_| CoreSetupIdentitySourceError::Invalid)?;
    let mut identity = None;
    for line in output.lines() {
        let Some(value) = line
            .trim()
            .strip_prefix("\"IOPlatformUUID\" = \"")
            .and_then(|value| value.strip_suffix('"'))
        else {
            continue;
        };
        if identity.is_some() {
            return Err(CoreSetupIdentitySourceError::Invalid);
        }
        identity = Some(normalize_platform_uuid(value)?);
    }
    identity.ok_or(CoreSetupIdentitySourceError::Invalid)
}

// Removes the four canonical UUID separators and lowercases its hexadecimal digits.
fn normalize_platform_uuid(value: &str) -> Result<MachineId, CoreSetupIdentitySourceError> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte != b'-',
            _ => !byte.is_ascii_hexdigit(),
        })
    {
        return Err(CoreSetupIdentitySourceError::Invalid);
    }
    let normalized = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect::<String>();
    parse_nonzero_machine_identity(&normalized)
}

// Requires one nonzero canonical Core machine identity.
fn parse_nonzero_machine_identity(value: &str) -> Result<MachineId, CoreSetupIdentitySourceError> {
    let identity = MachineId::parse(value).map_err(|_| CoreSetupIdentitySourceError::Invalid)?;
    if value.bytes().all(|byte| byte == b'0') {
        return Err(CoreSetupIdentitySourceError::Invalid);
    }
    Ok(identity)
}

// Requires bounded fixed ioreg arguments, output, and timeout before process creation.
fn validate_machine_identity_command(
    arguments: &[&str],
    timeout: Duration,
    poll_interval: Duration,
    maximum_stdout_bytes: usize,
) -> Result<(), CoreSetupIdentitySourceError> {
    if arguments != MACOS_IOREG_ARGUMENTS
        || timeout.is_zero()
        || timeout > MACOS_IOREG_MAXIMUM_TIMEOUT
        || poll_interval.is_zero()
        || poll_interval > timeout
        || maximum_stdout_bytes != MACOS_IOREG_MAXIMUM_OUTPUT_BYTES
    {
        return Err(CoreSetupIdentitySourceError::Invalid);
    }
    Ok(())
}

// Requires one immutable owner-bound executable reached without following any path component.
fn validate_machine_identity_executable(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreSetupIdentitySourceError> {
    let file = open_absolute_file_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != MACOS_IOREG_EXECUTABLE_MODE
        || metadata.len() == 0
    {
        return Err(CoreSetupIdentitySourceError::Unavailable);
    }
    Ok(())
}

// Requires one stable exact-mode, single-link Linux machine-id descriptor.
fn validate_machine_identity_file(
    file: &File,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<Metadata, CoreSetupIdentitySourceError> {
    let metadata = file
        .metadata()
        .map_err(|_| CoreSetupIdentitySourceError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != LINUX_MACHINE_IDENTITY_MODE
    {
        return Err(CoreSetupIdentitySourceError::Unavailable);
    }
    if metadata.len() == 0 || metadata.len() > maximum_bytes as u64 {
        return Err(CoreSetupIdentitySourceError::Invalid);
    }
    Ok(metadata)
}

// Opens one normalized absolute regular-file path through descriptor-anchored traversal.
fn open_absolute_file_no_follow(path: &Path) -> Result<File, CoreSetupIdentitySourceError> {
    let mut components = normal_components(path)?;
    let name = components
        .pop()
        .ok_or(CoreSetupIdentitySourceError::Invalid)?;
    let mut parent = open_root_directory()?;
    for component in components {
        parent = open_child_directory(&parent, component)?;
    }
    let name = CString::new(name.as_bytes()).map_err(|_| CoreSetupIdentitySourceError::Invalid)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    file_from_descriptor(descriptor)
}

// Returns every ordinary component of one non-root absolute native source path.
fn normal_components(path: &Path) -> Result<Vec<&OsStr>, CoreSetupIdentitySourceError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(CoreSetupIdentitySourceError::Invalid);
    }
    let mut values = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => values.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(CoreSetupIdentitySourceError::Invalid)
            }
        }
    }
    Ok(values)
}

// Opens the immutable filesystem root as the traversal anchor.
fn open_root_directory() -> Result<File, CoreSetupIdentitySourceError> {
    let root = CString::new("/").map_err(|_| CoreSetupIdentitySourceError::Invalid)?;
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

// Opens one ordinary no-follow child directory relative to its proven parent.
fn open_child_directory(parent: &File, name: &OsStr) -> Result<File, CoreSetupIdentitySourceError> {
    let name = CString::new(name.as_bytes()).map_err(|_| CoreSetupIdentitySourceError::Invalid)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

// Transfers one successful native descriptor into exactly one automatic close owner.
fn file_from_descriptor(descriptor: libc::c_int) -> Result<File, CoreSetupIdentitySourceError> {
    if descriptor < 0 {
        return Err(CoreSetupIdentitySourceError::Unavailable);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

// Proves one open descriptor retained its exact filesystem identity throughout a read.
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
}
