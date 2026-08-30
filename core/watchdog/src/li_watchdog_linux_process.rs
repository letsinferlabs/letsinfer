// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::{
    WatchdogError, WatchdogLinuxCapability, WatchdogLinuxHostFileProvider, WatchdogProcessState,
    WatchdogProtectedEngine,
};

const MAX_PROC_STAT_BYTES: usize = 4_096;
const MAX_PROC_CGROUP_BYTES: usize = 8_192;
const MAX_BOOT_ID_BYTES: usize = 64;
const MAX_CGROUP_PROCS_BYTES: usize = 256 * 1_024;
const MAX_CGROUP_MEMBERS: usize = 4_096;
const MAX_NATIVE_PATH_BYTES: usize = 4_095;

// Identifies the only two process signals Watchdog containment may issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogLinuxSignal {
    Terminate,
    Kill,
}

// Owns one exact pidfd after descriptor identity has been verified twice.
pub trait WatchdogLinuxPidFd: Send + Sync {
    // Returns whether the exact pidfd identity is still resident.
    fn state(&self) -> Result<WatchdogProcessState, WatchdogError>;

    // Sends one closed containment signal to the exact pidfd identity.
    fn signal(&self, signal: WatchdogLinuxSignal) -> Result<(), WatchdogError>;

    // Waits one bounded interval for the exact pidfd identity to exit.
    fn wait_for_exit(&self, duration: Duration) -> Result<bool, WatchdogError>;
}

// Isolates pidfd creation from procfs identity parsing and product policy.
pub trait WatchdogLinuxPidFdProvider: Send + Sync {
    // Opens one exact process or reports exit or unsupported kernel capability explicitly.
    fn open(
        &self,
        process_id: u32,
    ) -> Result<WatchdogLinuxCapability<Option<Arc<dyn WatchdogLinuxPidFd>>>, WatchdogError>;
}

// Isolates descriptor-bound process identity and cgroup containment operations.
pub trait WatchdogLinuxProcessProvider: Send + Sync {
    // Binds one descriptor to an exact pidfd or reports that its process already exited.
    fn bind(
        &self,
        target: &WatchdogProtectedEngine,
    ) -> Result<Option<Arc<dyn WatchdogLinuxPidFd>>, WatchdogError>;

    // Returns whether one exact descriptor-bound cgroup currently has no members.
    fn cgroup_is_empty(&self, cgroup: &str) -> Result<bool, WatchdogError>;

    // Sends SIGKILL only to pidfd-revalidated members of one exact cgroup.
    fn kill_cgroup_members(&self, cgroup: &str) -> Result<(), WatchdogError>;

    // Waits one caller-bounded containment polling interval.
    fn wait(&self, duration: Duration);
}

// Describes the exact procfs paths used to verify descriptor process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogLinuxProcessLayout {
    proc_root: PathBuf,
    boot_id: PathBuf,
}

impl WatchdogLinuxProcessLayout {
    // Creates one explicit procfs layout without traversal ambiguity.
    pub fn new(proc_root: PathBuf, boot_id: PathBuf) -> Result<Self, WatchdogError> {
        validate_process_path(&proc_root)?;
        validate_process_path(&boot_id)?;
        Ok(Self { proc_root, boot_id })
    }

    // Returns the fixed production Linux procfs layout.
    pub fn system() -> Self {
        Self::new(
            PathBuf::from("/proc"),
            PathBuf::from("/proc/sys/kernel/random/boot_id"),
        )
        .expect("fixed Linux Watchdog process layout")
    }

    // Returns one exact process file without accepting caller-controlled components.
    fn process_path(&self, process_id: u32, name: &'static str) -> PathBuf {
        self.proc_root.join(process_id.to_string()).join(name)
    }
}

// Opens Linux pidfds directly and reports unsupported kernels without a PID fallback.
#[derive(Default)]
pub struct SystemWatchdogLinuxPidFdProvider;

impl WatchdogLinuxPidFdProvider for SystemWatchdogLinuxPidFdProvider {
    // Opens one close-on-exec pidfd through the fixed Linux syscall.
    fn open(
        &self,
        process_id: u32,
    ) -> Result<WatchdogLinuxCapability<Option<Arc<dyn WatchdogLinuxPidFd>>>, WatchdogError> {
        if process_id <= 1 || process_id > i32::MAX as u32 {
            return Err(process_error("process identity is invalid"));
        }
        system_pidfd_open(process_id)
    }
}

// Verifies start-time, boot, and cgroup identity around pidfd acquisition.
pub struct SystemWatchdogLinuxProcessProvider {
    layout: WatchdogLinuxProcessLayout,
    files: Arc<dyn WatchdogLinuxHostFileProvider>,
    pidfds: Arc<dyn WatchdogLinuxPidFdProvider>,
}

impl SystemWatchdogLinuxProcessProvider {
    // Creates one process provider over explicit procfs and pidfd dependencies.
    pub fn new(
        layout: WatchdogLinuxProcessLayout,
        files: Arc<dyn WatchdogLinuxHostFileProvider>,
        pidfds: Arc<dyn WatchdogLinuxPidFdProvider>,
    ) -> Self {
        Self {
            layout,
            files,
            pidfds,
        }
    }

    // Reads one complete process identity or reports exact process absence.
    fn process_identity(
        &self,
        process_id: u32,
    ) -> Result<Option<WatchdogLinuxProcessIdentity>, WatchdogError> {
        let stat = match self.files.read(
            &self.layout.process_path(process_id, "stat"),
            MAX_PROC_STAT_BYTES,
        )? {
            WatchdogLinuxCapability::Available(value) => strict_text(value)?,
            WatchdogLinuxCapability::Unsupported => return Ok(None),
        };
        let cgroup = required_process_text(
            self.files.read(
                &self.layout.process_path(process_id, "cgroup"),
                MAX_PROC_CGROUP_BYTES,
            )?,
            "process cgroup identity is unavailable",
        )?;
        let boot_id = required_process_text(
            self.files.read(&self.layout.boot_id, MAX_BOOT_ID_BYTES)?,
            "boot identity is unavailable",
        )?;
        Ok(Some(WatchdogLinuxProcessIdentity {
            start_ticks: parse_process_start_ticks(&stat)?,
            boot_id: parse_boot_id(&boot_id)?,
            cgroup: parse_process_cgroup(&cgroup)?,
        }))
    }

    // Reads only one cgroup identity for last-resort member revalidation.
    fn process_cgroup(&self, process_id: u32) -> Result<Option<String>, WatchdogError> {
        match self.files.read(
            &self.layout.process_path(process_id, "cgroup"),
            MAX_PROC_CGROUP_BYTES,
        )? {
            WatchdogLinuxCapability::Available(value) => {
                strict_text(value).and_then(|value| parse_process_cgroup(&value).map(Some))
            }
            WatchdogLinuxCapability::Unsupported => Ok(None),
        }
    }

    // Requires one parsed process identity to match every descriptor-bound field.
    fn validate_identity(
        &self,
        target: &WatchdogProtectedEngine,
        identity: &WatchdogLinuxProcessIdentity,
    ) -> Result<(), WatchdogError> {
        if target.process_start_ticks() != Some(identity.start_ticks)
            || target.boot_id() != Some(identity.boot_id.as_str())
            || target.cgroup() != Some(identity.cgroup.as_str())
        {
            return Err(process_error(
                "process start, boot, or cgroup identity did not match its descriptor",
            ));
        }
        Ok(())
    }
}

impl WatchdogLinuxProcessProvider for SystemWatchdogLinuxProcessProvider {
    // Verifies descriptor identity before and after opening the exact pidfd.
    fn bind(
        &self,
        target: &WatchdogProtectedEngine,
    ) -> Result<Option<Arc<dyn WatchdogLinuxPidFd>>, WatchdogError> {
        let process_id = target
            .process_id()
            .ok_or_else(|| process_error("bound descriptor has no process identity"))?;
        let Some(before) = self.process_identity(process_id)? else {
            return Ok(None);
        };
        self.validate_identity(target, &before)?;
        let pidfd = match self.pidfds.open(process_id)? {
            WatchdogLinuxCapability::Available(Some(pidfd)) => pidfd,
            WatchdogLinuxCapability::Available(None) => return Ok(None),
            WatchdogLinuxCapability::Unsupported => {
                return Err(process_error("pidfd is unsupported"))
            }
        };
        if let Some(after) = self.process_identity(process_id)? {
            self.validate_identity(target, &after)?;
            if before != after {
                return Err(process_error(
                    "process identity changed during pidfd binding",
                ));
            }
        }
        Ok(Some(pidfd))
    }

    // Reads one bounded cgroup member list and distinguishes absence from malformed state.
    fn cgroup_is_empty(&self, cgroup: &str) -> Result<bool, WatchdogError> {
        validate_cgroup_path(cgroup)?;
        match self.files.read(
            &Path::new(cgroup).join("cgroup.procs"),
            MAX_CGROUP_PROCS_BYTES,
        )? {
            WatchdogLinuxCapability::Available(value) => {
                let members = parse_cgroup_members(&strict_text(value)?)?;
                Ok(members.is_empty())
            }
            WatchdogLinuxCapability::Unsupported => Ok(true),
        }
    }

    // Revalidates every member's current cgroup before signaling its exact pidfd.
    fn kill_cgroup_members(&self, cgroup: &str) -> Result<(), WatchdogError> {
        validate_cgroup_path(cgroup)?;
        let source = match self.files.read(
            &Path::new(cgroup).join("cgroup.procs"),
            MAX_CGROUP_PROCS_BYTES,
        )? {
            WatchdogLinuxCapability::Available(value) => strict_text(value)?,
            WatchdogLinuxCapability::Unsupported => return Ok(()),
        };
        for process_id in parse_cgroup_members(&source)? {
            if self.process_cgroup(process_id)?.as_deref() != Some(cgroup) {
                continue;
            }
            let pidfd = match self.pidfds.open(process_id)? {
                WatchdogLinuxCapability::Available(Some(pidfd)) => pidfd,
                WatchdogLinuxCapability::Available(None) => continue,
                WatchdogLinuxCapability::Unsupported => {
                    return Err(process_error("pidfd is unsupported"))
                }
            };
            pidfd.signal(WatchdogLinuxSignal::Kill)?;
        }
        Ok(())
    }

    // Sleeps only for the caller-selected bounded containment interval.
    fn wait(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

// Stores one fully parsed descriptor-comparable procfs identity.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WatchdogLinuxProcessIdentity {
    start_ticks: u64,
    boot_id: String,
    cgroup: String,
}

// Owns one production Linux pidfd until every process observation is complete.
#[cfg(target_os = "linux")]
struct SystemWatchdogLinuxPidFd {
    descriptor: OwnedFd,
}

#[cfg(target_os = "linux")]
impl WatchdogLinuxPidFd for SystemWatchdogLinuxPidFd {
    // Polls one pidfd without waiting to distinguish a live process from an exited one.
    fn state(&self) -> Result<WatchdogProcessState, WatchdogError> {
        if poll_pidfd(self.descriptor.as_raw_fd(), Duration::ZERO)? {
            Ok(WatchdogProcessState::Exited)
        } else {
            Ok(WatchdogProcessState::Running)
        }
    }

    // Sends SIGTERM or SIGKILL through pidfd_send_signal without PID fallback.
    fn signal(&self, signal: WatchdogLinuxSignal) -> Result<(), WatchdogError> {
        let signal = match signal {
            WatchdogLinuxSignal::Terminate => libc::SIGTERM,
            WatchdogLinuxSignal::Kill => libc::SIGKILL,
        };
        // SAFETY: the owned pidfd and fixed signal are passed without user pointers.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.descriptor.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(process_error("pidfd signal failed"))
        }
    }

    // Polls one pidfd for at most the exact caller-owned duration.
    fn wait_for_exit(&self, duration: Duration) -> Result<bool, WatchdogError> {
        poll_pidfd(self.descriptor.as_raw_fd(), duration)
    }
}

// Opens one pidfd on Linux and classifies kernel absence separately from process exit.
#[cfg(target_os = "linux")]
fn system_pidfd_open(
    process_id: u32,
) -> Result<WatchdogLinuxCapability<Option<Arc<dyn WatchdogLinuxPidFd>>>, WatchdogError> {
    // SAFETY: pidfd_open accepts a positive PID and fixed zero flags.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0_u32) };
    if descriptor >= 0 {
        let descriptor =
            i32::try_from(descriptor).map_err(|_| process_error("pidfd descriptor is invalid"))?;
        // SAFETY: pidfd_open returned a new owned descriptor on success.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        return Ok(WatchdogLinuxCapability::Available(Some(Arc::new(
            SystemWatchdogLinuxPidFd { descriptor },
        ))));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(WatchdogLinuxCapability::Available(None)),
        Some(libc::ENOSYS) | Some(libc::EINVAL) => Ok(WatchdogLinuxCapability::Unsupported),
        _ => Err(process_error("pidfd could not be opened")),
    }
}

// Reports explicit pidfd absence when this Linux provider is compiled for another host.
#[cfg(not(target_os = "linux"))]
fn system_pidfd_open(
    _process_id: u32,
) -> Result<WatchdogLinuxCapability<Option<Arc<dyn WatchdogLinuxPidFd>>>, WatchdogError> {
    Ok(WatchdogLinuxCapability::Unsupported)
}

// Polls one Linux pidfd with EINTR-safe bounded elapsed-time accounting.
#[cfg(target_os = "linux")]
fn poll_pidfd(descriptor: i32, duration: Duration) -> Result<bool, WatchdogError> {
    if duration > Duration::from_secs(30) {
        return Err(process_error("pidfd wait exceeds its bound"));
    }
    let started = std::time::Instant::now();
    loop {
        let remaining = duration.saturating_sub(started.elapsed());
        let milliseconds = if duration.is_zero() {
            0
        } else {
            i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
        };
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll references one initialized local pollfd for the bounded call.
        let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if result > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(process_error("pidfd became invalid"));
            }
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(process_error("pidfd poll failed"));
        }
        if started.elapsed() >= duration {
            return Ok(false);
        }
    }
}

// Converts one available required procfs capability into strict UTF-8 text.
fn required_process_text(
    capability: WatchdogLinuxCapability<Vec<u8>>,
    reason: &'static str,
) -> Result<String, WatchdogError> {
    match capability {
        WatchdogLinuxCapability::Available(value) => strict_text(value),
        WatchdogLinuxCapability::Unsupported => Err(process_error(reason)),
    }
}

// Converts one bounded procfs byte vector into strict UTF-8.
fn strict_text(value: Vec<u8>) -> Result<String, WatchdogError> {
    String::from_utf8(value).map_err(|_| process_error("procfs value is not valid UTF-8"))
}

// Parses field 22 from one Linux proc stat record without trusting its command text.
fn parse_process_start_ticks(source: &str) -> Result<u64, WatchdogError> {
    let command_end = source
        .rfind(')')
        .ok_or_else(|| process_error("process stat is malformed"))?;
    let fields = source[command_end + 1..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let value = fields
        .get(19)
        .ok_or_else(|| process_error("process start time is missing"))?
        .parse::<u64>()
        .map_err(|_| process_error("process start time is malformed"))?;
    if value == 0 {
        return Err(process_error("process start time is invalid"));
    }
    Ok(value)
}

// Parses one exact lowercase RFC-4122 boot identity.
fn parse_boot_id(source: &str) -> Result<String, WatchdogError> {
    let value = source.trim();
    if value.len() != 36
        || value.as_bytes()[8] != b'-'
        || value.as_bytes()[13] != b'-'
        || value.as_bytes()[18] != b'-'
        || value.as_bytes()[23] != b'-'
        || value.bytes().enumerate().any(|(index, byte)| {
            !matches!(index, 8 | 13 | 18 | 23)
                && !byte.is_ascii_digit()
                && !(b'a'..=b'f').contains(&byte)
        })
    {
        return Err(process_error("boot identity is malformed"));
    }
    Ok(value.to_string())
}

// Parses the exact cgroup-v2 membership line into its canonical filesystem path.
fn parse_process_cgroup(source: &str) -> Result<String, WatchdogError> {
    let mut unified = source.lines().filter_map(|line| line.strip_prefix("0::"));
    let relative = unified
        .next()
        .ok_or_else(|| process_error("unified cgroup identity is missing"))?;
    if unified.next().is_some() || !relative.starts_with('/') {
        return Err(process_error("unified cgroup identity is ambiguous"));
    }
    let path = format!("/sys/fs/cgroup{relative}");
    validate_cgroup_path(&path)?;
    Ok(path)
}

// Parses one bounded whitespace-separated cgroup process list.
fn parse_cgroup_members(source: &str) -> Result<Vec<u32>, WatchdogError> {
    let mut members = Vec::new();
    for value in source.split_whitespace() {
        let process_id = value
            .parse::<u32>()
            .map_err(|_| process_error("cgroup process identity is malformed"))?;
        if process_id <= 1 || process_id > i32::MAX as u32 {
            return Err(process_error("cgroup process identity is invalid"));
        }
        members.push(process_id);
        if members.len() > MAX_CGROUP_MEMBERS {
            return Err(process_error("cgroup member count exceeded its bound"));
        }
    }
    members.sort_unstable();
    members.dedup();
    Ok(members)
}

// Requires one cgroup path to remain inside the exact Linux cgroup-v2 root.
fn validate_cgroup_path(value: &str) -> Result<(), WatchdogError> {
    if !value.starts_with("/sys/fs/cgroup/")
        || value.len() > MAX_NATIVE_PATH_BYTES
        || value.contains("..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'.' | b':' | b'-')
        })
    {
        return Err(process_error("cgroup path is invalid"));
    }
    Ok(())
}

// Rejects relative, traversing, NUL-containing, or unbounded procfs paths.
fn validate_process_path(path: &Path) -> Result<(), WatchdogError> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() > MAX_NATIVE_PATH_BYTES
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(WatchdogError::InvalidContract {
            reason: "Linux Watchdog process path is invalid",
        });
    }
    Ok(())
}

// Creates one stable redacted Linux process-provider failure.
const fn process_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("Linux process protection", reason)
}
