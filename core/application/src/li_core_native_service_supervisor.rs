// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::Sha256Digest;
use li_core_update_manager::{CoreUpdateError, CoreUpdateResidentService, CoreUpdateServiceState};
use sha2::{Digest, Sha256};

use crate::{
    CoreNativeServiceRetirementState, CoreNativeServiceSupervisor, CoreProcessPlatform,
    CoreResidentProcess, CoreServiceDefinition,
};

const MAXIMUM_NATIVE_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const NATIVE_COMMAND_TIMEOUT_MILLISECONDS: u64 = 30_000;
const MAXIMUM_SERVICE_DEFINITION_BYTES: u64 = 64 * 1024;
const PRIVATE_SERVICE_DEFINITION_MODE: u32 = 0o600;
const LAUNCHD_BOOTSTRAP_ATTEMPTS: usize = 30;
const LAUNCHD_BOOTSTRAP_RETRY_MILLISECONDS: u64 = 250;

// Represents every exact systemd activity state consumed by resident lifecycle policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemdActivity {
    Active,
    Inactive,
    Failed,
}

// Carries one bounded shell-free native supervisor command result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreNativeServiceCommandOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

// Carries the exact launchd identity fields shared by resident and placement admission.
pub(crate) struct CoreLaunchdLoadedJob {
    path: PathBuf,
    #[cfg(target_os = "macos")]
    state: String,
    program: PathBuf,
    arguments: Vec<String>,
    #[cfg(target_os = "macos")]
    environment: Option<BTreeMap<String, String>>,
    #[cfg(target_os = "macos")]
    working_directory: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    process_id: Option<u32>,
}

impl CoreLaunchdLoadedJob {
    // Returns the plist path from which launchd loaded this job.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    // Returns whether launchd reports the process as currently running.
    #[cfg(target_os = "macos")]
    pub(crate) fn is_running(&self) -> bool {
        self.state == "running"
    }

    // Returns the exact executable selected by launchd.
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    // Returns launchd's complete ordered argv including the executable.
    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    // Returns explicit loaded environment fields when launchd represents them.
    #[cfg(target_os = "macos")]
    pub(crate) fn environment(&self) -> Option<&BTreeMap<String, String>> {
        self.environment.as_ref()
    }

    // Returns the loaded working directory when launchd represents it.
    #[cfg(target_os = "macos")]
    pub(crate) fn working_directory(&self) -> Option<&Path> {
        self.working_directory.as_deref()
    }

    // Returns the unique positive process identity when the job is running.
    #[cfg(target_os = "macos")]
    pub(crate) const fn process_id(&self) -> Option<u32> {
        self.process_id
    }
}

impl CoreNativeServiceCommandOutput {
    // Creates one exact process result for a production runner or deterministic mock.
    pub const fn new(status: i32, stdout: Vec<u8>) -> Self {
        Self {
            status,
            stdout,
            stderr: Vec::new(),
        }
    }

    // Creates one exact process result carrying bounded diagnostic output.
    pub const fn new_with_stderr(status: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            status,
            stdout,
            stderr,
        }
    }

    // Returns the native exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns the bounded standard output used for closed state parsing.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    // Returns bounded standard error used only for exact native failure classification.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

// Defines exact shell-free native command execution behind one mockable boundary.
pub trait CoreNativeServiceCommandRunner: Send + Sync {
    // Executes one fixed supervisor executable and argv under strict time and output bounds.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError>;
}

// Isolates bounded native service retry waits for deterministic lifecycle tests.
pub trait CoreNativeServiceWaiter: Send + Sync {
    // Waits for one already-bounded retry interval.
    fn wait(&self, duration: Duration) -> Result<(), CoreUpdateError>;
}

// Applies native service retry waits through the host monotonic sleep primitive.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreNativeServiceWaiter;

impl CoreNativeServiceWaiter for SystemCoreNativeServiceWaiter {
    // Sleeps for one nonzero interval within the launchd retry bound.
    fn wait(&self, duration: Duration) -> Result<(), CoreUpdateError> {
        if duration.is_zero()
            || duration > Duration::from_millis(LAUNCHD_BOOTSTRAP_RETRY_MILLISECONDS)
        {
            return Err(native_service_error(
                "native service retry bound is invalid",
            ));
        }
        std::thread::sleep(duration);
        Ok(())
    }
}

// Executes native supervisor commands without a shell or inherited environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreNativeServiceCommandRunner;

impl CoreNativeServiceCommandRunner for SystemCoreNativeServiceCommandRunner {
    // Executes one verified system binary with bounded stdout and a kill-on-timeout deadline.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError> {
        validate_native_executable(executable)?;
        validate_native_arguments(arguments)?;
        if timeout.is_zero()
            || timeout > Duration::from_millis(NATIVE_COMMAND_TIMEOUT_MILLISECONDS)
            || maximum_stdout_bytes == 0
            || maximum_stdout_bytes > MAXIMUM_NATIVE_COMMAND_OUTPUT_BYTES
        {
            return Err(native_service_error("native command bounds are invalid"));
        }
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(target_os = "linux")]
        if executable.file_name().and_then(|value| value.to_str()) == Some("systemctl") {
            let user_runtime_root = format!("/run/user/{}", unsafe { libc::geteuid() });
            command.env("XDG_RUNTIME_DIR", &user_runtime_root).env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={user_runtime_root}/bus"),
            );
        }
        let mut child = command
            .spawn()
            .map_err(|_| native_service_error("native command could not start"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| native_service_error("native command output is unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| native_service_error("native command diagnostics are unavailable"))?;
        let output_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take((maximum_stdout_bytes as u64).saturating_add(1))
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let diagnostic_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .take((maximum_stdout_bytes as u64).saturating_add(1))
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| native_service_error("native command deadline is invalid"))?;
        let status = loop {
            match child
                .try_wait()
                .map_err(|_| native_service_error("native command status is unavailable"))?
            {
                Some(status) => break status,
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = output_reader.join();
                    let _ = diagnostic_reader.join();
                    return Err(native_service_error("native command timed out"));
                }
            }
        };
        let stdout = output_reader
            .join()
            .map_err(|_| native_service_error("native command output failed"))?
            .map_err(|_| native_service_error("native command output failed"))?;
        let stderr = diagnostic_reader
            .join()
            .map_err(|_| native_service_error("native command diagnostics failed"))?
            .map_err(|_| native_service_error("native command diagnostics failed"))?;
        if stdout
            .len()
            .checked_add(stderr.len())
            .is_none_or(|length| length > maximum_stdout_bytes)
        {
            return Err(native_service_error(
                "native command output exceeded its bound",
            ));
        }
        Ok(CoreNativeServiceCommandOutput::new_with_stderr(
            status.code().unwrap_or(-1),
            stdout,
            stderr,
        ))
    }
}

// Isolates owner-bound service-definition filesystem mechanics for deterministic tests.
pub trait CoreNativeServiceIo: Send + Sync {
    // Reads one optional owner-only definition without following its final path.
    fn read_private_file(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<u8>>, CoreUpdateError>;

    // Atomically creates or replaces one exact owner-only definition and persists its directory.
    fn replace_private_file(
        &self,
        path: &Path,
        bytes: &[u8],
        owner_user_id: u32,
        mode: u32,
    ) -> Result<(), CoreUpdateError>;

    // Removes one optional owner-only definition and persists its directory.
    fn remove_private_file(&self, path: &Path, owner_user_id: u32)
        -> Result<bool, CoreUpdateError>;
}

// Implements no-follow owner-bound atomic service-definition I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreNativeServiceIo;

impl CoreNativeServiceIo for SystemCoreNativeServiceIo {
    // Opens and reads one bounded exact-mode definition through a no-follow descriptor.
    fn read_private_file(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<u8>>, CoreUpdateError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_SERVICE_DEFINITION_BYTES {
            return Err(native_service_error("service definition bound is invalid"));
        }
        validate_service_parent(path, owner_user_id)?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(native_service_error("service definition is unavailable")),
        };
        let before = validate_private_file(&file, owner_user_id, maximum_bytes)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| native_service_error("service definition could not be read"))?;
        let after = validate_private_file(&file, owner_user_id, maximum_bytes)?;
        if bytes.is_empty()
            || bytes.len() as u64 != before.len()
            || bytes.len() as u64 > maximum_bytes
            || !metadata_identity_is_stable(&before, &after)
        {
            return Err(native_service_error(
                "service definition changed while it was read",
            ));
        }
        Ok(Some(bytes))
    }

    // Writes through one collision-resistant same-directory file before atomic rename.
    fn replace_private_file(
        &self,
        path: &Path,
        bytes: &[u8],
        owner_user_id: u32,
        mode: u32,
    ) -> Result<(), CoreUpdateError> {
        if bytes.is_empty()
            || bytes.len() as u64 > MAXIMUM_SERVICE_DEFINITION_BYTES
            || mode != PRIVATE_SERVICE_DEFINITION_MODE
        {
            return Err(native_service_error("service definition is invalid"));
        }
        let parent = validate_service_parent(path, owner_user_id)?;
        if let Some(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .ok()
        {
            validate_private_file(&file, owner_user_id, MAXIMUM_SERVICE_DEFINITION_BYTES)?;
        } else if fs::symlink_metadata(path).is_ok() {
            return Err(native_service_error("service definition is unsafe"));
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| native_service_error("service definition identity is unavailable"))?;
        let temporary = parent.join(format!(
            ".li_service_{}.tmp",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
                .map_err(|_| native_service_error("service definition could not be staged"))?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| native_service_error("service definition could not be persisted"))?;
            let metadata =
                validate_private_file(&file, owner_user_id, MAXIMUM_SERVICE_DEFINITION_BYTES)?;
            if metadata.len() != bytes.len() as u64 {
                return Err(native_service_error(
                    "service definition could not be persisted",
                ));
            }
            drop(file);
            fs::rename(&temporary, path)
                .map_err(|_| native_service_error("service definition could not be activated"))?;
            sync_directory(&parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    // Removes only a validated exact-mode definition and persists its parent.
    fn remove_private_file(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<bool, CoreUpdateError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(native_service_error("service definition is unavailable")),
        };
        validate_private_file(&file, owner_user_id, MAXIMUM_SERVICE_DEFINITION_BYTES)?;
        let parent = validate_service_parent(path, owner_user_id)?;
        drop(file);
        fs::remove_file(path)
            .map_err(|_| native_service_error("service definition could not be removed"))?;
        sync_directory(&parent)?;
        Ok(true)
    }
}

// Controls the fixed Core systemd user units or launchd agents for one local user.
pub struct SystemCoreNativeServiceSupervisor {
    platform: CoreProcessPlatform,
    service_root: PathBuf,
    owner_user_id: u32,
    supervisor_executable: PathBuf,
    runner: Arc<dyn CoreNativeServiceCommandRunner>,
    io: Arc<dyn CoreNativeServiceIo>,
    waiter: Arc<dyn CoreNativeServiceWaiter>,
}

impl SystemCoreNativeServiceSupervisor {
    // Creates one native supervisor from an exact platform root and executable.
    pub fn new(
        platform: CoreProcessPlatform,
        home_directory: PathBuf,
        owner_user_id: u32,
        supervisor_executable: PathBuf,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
        io: Arc<dyn CoreNativeServiceIo>,
    ) -> Result<Self, CoreUpdateError> {
        Self::new_with_waiter(
            platform,
            home_directory,
            owner_user_id,
            supervisor_executable,
            runner,
            io,
            Arc::new(SystemCoreNativeServiceWaiter),
        )
    }

    // Executes one command only within the remaining caller-owned readiness deadline.
    fn run_before(
        &self,
        arguments: Vec<String>,
        deadline: Instant,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError> {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| native_service_error("native service readiness deadline expired"))?;
        self.runner.run(
            &self.supervisor_executable,
            &arguments,
            timeout.min(Duration::from_millis(NATIVE_COMMAND_TIMEOUT_MILLISECONDS)),
            MAXIMUM_NATIVE_COMMAND_OUTPUT_BYTES,
        )
    }

    // Creates one native supervisor with an explicit bounded retry-wait capability.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_waiter(
        platform: CoreProcessPlatform,
        home_directory: PathBuf,
        owner_user_id: u32,
        supervisor_executable: PathBuf,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
        io: Arc<dyn CoreNativeServiceIo>,
        waiter: Arc<dyn CoreNativeServiceWaiter>,
    ) -> Result<Self, CoreUpdateError> {
        let expected_executable = match platform {
            CoreProcessPlatform::Linux => Path::new("/usr/bin/systemctl"),
            CoreProcessPlatform::Macos => Path::new("/bin/launchctl"),
        };
        if !is_safe_home_directory(&home_directory) || supervisor_executable != expected_executable
        {
            return Err(native_service_error(
                "native supervisor configuration is invalid",
            ));
        }
        let service_root = match platform {
            CoreProcessPlatform::Linux => home_directory.join(".config/systemd/user"),
            CoreProcessPlatform::Macos => home_directory.join("Library/LaunchAgents"),
        };
        Ok(Self {
            platform,
            service_root,
            owner_user_id,
            supervisor_executable,
            runner,
            io,
            waiter,
        })
    }

    // Returns the exact definition path beneath the configured native service root.
    fn definition_path(&self, process: CoreResidentProcess) -> Result<PathBuf, CoreUpdateError> {
        let filename = match self.platform {
            CoreProcessPlatform::Linux => process.linux_service_identity().to_string(),
            CoreProcessPlatform::Macos => format!(
                "{}.plist",
                process
                    .macos_service_identity()
                    .ok_or_else(|| native_service_error("resident service is unsupported"))?
            ),
        };
        Ok(self.service_root.join(filename))
    }

    // Executes one fixed native supervisor subcommand through the bounded runner.
    fn run(
        &self,
        arguments: Vec<String>,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError> {
        self.runner.run(
            &self.supervisor_executable,
            &arguments,
            Duration::from_millis(NATIVE_COMMAND_TIMEOUT_MILLISECONDS),
            MAXIMUM_NATIVE_COMMAND_OUTPUT_BYTES,
        )
    }

    // Requires one mutation command to return successful status.
    fn require_success(
        &self,
        arguments: Vec<String>,
        reason: &'static str,
    ) -> Result<(), CoreUpdateError> {
        if self.run(arguments)?.status() == 0 {
            Ok(())
        } else {
            Err(native_service_error(reason))
        }
    }

    // Retries only launchd's transient input/output status within one fixed global bound.
    fn bootstrap_launchd(&self, domain: String, path: String) -> Result<(), CoreUpdateError> {
        for attempt in 0..LAUNCHD_BOOTSTRAP_ATTEMPTS {
            let output = self.run(vec!["bootstrap".to_string(), domain.clone(), path.clone()])?;
            if output.status() == 0 {
                return Ok(());
            }
            if !is_transient_launchd_bootstrap_failure(&output)
                || attempt + 1 == LAUNCHD_BOOTSTRAP_ATTEMPTS
            {
                return Err(native_service_error("launchd service could not be loaded"));
            }
            self.waiter
                .wait(Duration::from_millis(LAUNCHD_BOOTSTRAP_RETRY_MILLISECONDS))?;
        }
        Err(native_service_error("launchd service could not be loaded"))
    }

    // Reads the exact optional definition bytes for one process.
    fn definition_bytes(
        &self,
        process: CoreResidentProcess,
    ) -> Result<Option<Vec<u8>>, CoreUpdateError> {
        self.io.read_private_file(
            &self.definition_path(process)?,
            self.owner_user_id,
            MAXIMUM_SERVICE_DEFINITION_BYTES,
        )
    }

    // Returns the closed enablement and activity state of one systemd user unit.
    fn systemd_state(
        &self,
        process: CoreResidentProcess,
    ) -> Result<(bool, SystemdActivity), CoreUpdateError> {
        let identity = process.linux_service_identity().to_string();
        let enabled = self.run(vec![
            "--user".to_string(),
            "is-enabled".to_string(),
            identity.clone(),
        ])?;
        let active = self.run(vec![
            "--user".to_string(),
            "is-active".to_string(),
            identity,
        ])?;
        Ok((
            parse_systemd_enabled(&enabled)?,
            parse_systemd_active(&active)?,
        ))
    }

    // Returns systemd state while bounding both commands by one shared absolute deadline.
    fn systemd_state_before(
        &self,
        process: CoreResidentProcess,
        deadline: Instant,
    ) -> Result<(bool, SystemdActivity), CoreUpdateError> {
        let identity = process.linux_service_identity().to_string();
        let enabled = self.run_before(
            vec![
                "--user".to_string(),
                "is-enabled".to_string(),
                identity.clone(),
            ],
            deadline,
        )?;
        let active = self.run_before(
            vec!["--user".to_string(), "is-active".to_string(), identity],
            deadline,
        )?;
        Ok((
            parse_systemd_enabled(&enabled)?,
            parse_systemd_active(&active)?,
        ))
    }

    // Returns the closed loaded and active state of one launchd GUI-domain job.
    fn launchd_state(&self, process: CoreResidentProcess) -> Result<(bool, bool), CoreUpdateError> {
        let target = self.launchd_target(process)?;
        parse_launchd_state(&self.run(vec!["print".to_string(), target])?)
    }

    // Returns launchd state through the caller-owned absolute readiness deadline.
    fn launchd_state_before(
        &self,
        process: CoreResidentProcess,
        deadline: Instant,
    ) -> Result<(bool, bool), CoreUpdateError> {
        let target = self.launchd_target(process)?;
        parse_launchd_state(&self.run_before(vec!["print".to_string(), target], deadline)?)
    }

    // Returns the exact launchd GUI-domain target for one supported process.
    fn launchd_target(&self, process: CoreResidentProcess) -> Result<String, CoreUpdateError> {
        Ok(format!(
            "gui/{}/{}",
            self.owner_user_id,
            process
                .macos_service_identity()
                .ok_or_else(|| native_service_error("resident service is unsupported"))?
        ))
    }

    // Proves the systemd manager loaded this exact path, executable, and argument identity.
    fn systemd_loaded_identity(
        &self,
        definition: &CoreServiceDefinition,
    ) -> Result<bool, CoreUpdateError> {
        let output = self.run(vec![
            "--user".to_string(),
            "show".to_string(),
            definition.service_identity().to_string(),
            "--property".to_string(),
            "FragmentPath".to_string(),
            "--property".to_string(),
            "ExecStart".to_string(),
            "--property".to_string(),
            "NeedDaemonReload".to_string(),
        ])?;
        parse_systemd_loaded_identity(
            &output,
            &self.definition_path(definition.process())?,
            definition,
        )
    }

    // Proves systemd loaded identity within one shared readiness deadline.
    fn systemd_loaded_identity_before(
        &self,
        definition: &CoreServiceDefinition,
        deadline: Instant,
    ) -> Result<bool, CoreUpdateError> {
        let output = self.run_before(
            vec![
                "--user".to_string(),
                "show".to_string(),
                definition.service_identity().to_string(),
                "--property".to_string(),
                "FragmentPath".to_string(),
                "--property".to_string(),
                "ExecStart".to_string(),
                "--property".to_string(),
                "NeedDaemonReload".to_string(),
            ],
            deadline,
        )?;
        parse_systemd_loaded_identity(
            &output,
            &self.definition_path(definition.process())?,
            definition,
        )
    }

    // Proves launchd loaded this exact target, plist path, executable, and argument array.
    fn launchd_loaded_identity(
        &self,
        definition: &CoreServiceDefinition,
    ) -> Result<bool, CoreUpdateError> {
        let target = self.launchd_target(definition.process())?;
        let output = self.run(vec!["print".to_string(), target.clone()])?;
        parse_launchd_loaded_identity(
            &output,
            &target,
            &self.definition_path(definition.process())?,
            definition,
        )
    }

    // Proves launchd loaded identity within one shared readiness deadline.
    fn launchd_loaded_identity_before(
        &self,
        definition: &CoreServiceDefinition,
        deadline: Instant,
    ) -> Result<bool, CoreUpdateError> {
        let target = self.launchd_target(definition.process())?;
        let output = self.run_before(vec!["print".to_string(), target.clone()], deadline)?;
        parse_launchd_loaded_identity(
            &output,
            &target,
            &self.definition_path(definition.process())?,
            definition,
        )
    }

    // Requires the definition to belong to this supervisor platform and exact fixed filename.
    fn require_definition(
        &self,
        definition: &CoreServiceDefinition,
    ) -> Result<(), CoreUpdateError> {
        let expected = self.definition_path(definition.process())?;
        if expected.file_name().and_then(|value| value.to_str()) != Some(definition.filename())
            || definition.mode() != PRIVATE_SERVICE_DEFINITION_MODE
            || definition.bytes().is_empty()
            || definition.bytes().len() as u64 > MAXIMUM_SERVICE_DEFINITION_BYTES
        {
            return Err(native_service_error(
                "service definition does not match its platform",
            ));
        }
        Ok(())
    }

    // Installs or restores one exact systemd definition and requested activity.
    fn install_systemd(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        let identity = definition.service_identity().to_string();
        self.io.replace_private_file(
            &self.definition_path(definition.process())?,
            definition.bytes(),
            self.owner_user_id,
            definition.mode(),
        )?;
        self.require_success(
            vec!["--user".to_string(), "daemon-reload".to_string()],
            "systemd definitions could not be reloaded",
        )?;
        self.require_success(
            vec!["--user".to_string(), "enable".to_string(), identity.clone()],
            "systemd service could not be enabled",
        )?;
        self.require_success(
            vec![
                "--user".to_string(),
                if active { "restart" } else { "stop" }.to_string(),
                identity,
            ],
            "systemd service activity could not be restored",
        )
    }

    // Removes one systemd definition after stopping and disabling its exact unit.
    fn remove_systemd(&self, process: CoreResidentProcess) -> Result<(), CoreUpdateError> {
        let identity = process.linux_service_identity().to_string();
        self.definition_bytes(process)?;
        let (enabled, activity) = self.systemd_state(process)?;
        match activity {
            SystemdActivity::Active => self.require_success(
                vec!["--user".to_string(), "stop".to_string(), identity.clone()],
                "systemd service could not be stopped",
            )?,
            SystemdActivity::Failed => self.require_success(
                vec![
                    "--user".to_string(),
                    "reset-failed".to_string(),
                    identity.clone(),
                ],
                "systemd service failure could not be reset",
            )?,
            SystemdActivity::Inactive => {}
        }
        if enabled {
            self.require_success(
                vec!["--user".to_string(), "disable".to_string(), identity],
                "systemd service could not be disabled",
            )?;
        }
        self.io
            .remove_private_file(&self.definition_path(process)?, self.owner_user_id)?;
        self.require_success(
            vec!["--user".to_string(), "daemon-reload".to_string()],
            "systemd definitions could not be reloaded",
        )
    }

    // Retires one exact systemd identity and always closes a prior remove-before-reload window.
    fn retire_systemd(
        &self,
        process: CoreResidentProcess,
        expected: &Sha256Digest,
        state: &CoreNativeServiceRetirementState,
    ) -> Result<(), CoreUpdateError> {
        let identity = process.linux_service_identity().to_string();
        if state.is_loaded() {
            self.require_success(
                vec![
                    "--user".to_string(),
                    "disable".to_string(),
                    "--now".to_string(),
                    identity,
                ],
                "systemd service could not be disabled",
            )?;
        }
        if state.definition_identity().is_some() {
            self.require_retirement_definition(process, expected)?;
            if !self
                .io
                .remove_private_file(&self.definition_path(process)?, self.owner_user_id)?
            {
                return Err(native_service_error(
                    "systemd service definition changed during retirement",
                ));
            }
        }
        self.require_success(
            vec!["--user".to_string(), "daemon-reload".to_string()],
            "systemd definitions could not be reloaded",
        )
    }

    // Installs or restores one exact launchd definition and requested activity.
    fn install_launchd(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        if !active {
            return Err(native_service_error(
                "a resident launchd service must remain active",
            ));
        }
        let process = definition.process();
        let path = self.definition_path(process)?;
        let target = self.launchd_target(process)?;
        let (loaded, _) = self.launchd_state(process)?;
        if loaded {
            self.require_success(
                vec!["bootout".to_string(), target.clone()],
                "launchd service could not be unloaded",
            )?;
        }
        self.io.replace_private_file(
            &path,
            definition.bytes(),
            self.owner_user_id,
            definition.mode(),
        )?;
        self.require_success(
            vec!["enable".to_string(), target.clone()],
            "launchd service could not be enabled",
        )?;
        self.bootstrap_launchd(
            format!("gui/{}", self.owner_user_id),
            path.to_str()
                .ok_or_else(|| native_service_error("launchd definition path is invalid"))?
                .to_string(),
        )?;
        self.require_success(
            vec!["kickstart".to_string(), "-k".to_string(), target],
            "launchd service activity could not be restored",
        )
    }

    // Removes one exact launchd job and its owner-only definition.
    fn remove_launchd(&self, process: CoreResidentProcess) -> Result<(), CoreUpdateError> {
        let (loaded, _) = self.launchd_state(process)?;
        if loaded {
            self.require_success(
                vec!["bootout".to_string(), self.launchd_target(process)?],
                "launchd service could not be unloaded",
            )?;
        }
        self.io
            .remove_private_file(&self.definition_path(process)?, self.owner_user_id)?;
        Ok(())
    }

    // Retires one exact launchd identity from active, unloaded-partial, or absent replay state.
    fn retire_launchd(
        &self,
        process: CoreResidentProcess,
        expected: &Sha256Digest,
        state: &CoreNativeServiceRetirementState,
    ) -> Result<(), CoreUpdateError> {
        if state.is_loaded() {
            self.require_success(
                vec!["bootout".to_string(), self.launchd_target(process)?],
                "launchd service could not be unloaded",
            )?;
        }
        if state.definition_identity().is_some() {
            self.require_retirement_definition(process, expected)?;
            if !self
                .io
                .remove_private_file(&self.definition_path(process)?, self.owner_user_id)?
            {
                return Err(native_service_error(
                    "launchd service definition changed during retirement",
                ));
            }
        }
        Ok(())
    }

    // Re-reads and binds one still-present definition immediately before native removal.
    fn require_retirement_definition(
        &self,
        process: CoreResidentProcess,
        expected: &Sha256Digest,
    ) -> Result<(), CoreUpdateError> {
        let bytes = self.definition_bytes(process)?.ok_or_else(|| {
            native_service_error("native service definition changed during retirement")
        })?;
        if definition_identity(&bytes)? != *expected {
            return Err(native_service_error(
                "native service definition changed during retirement",
            ));
        }
        Ok(())
    }
}

impl CoreNativeServiceSupervisor for SystemCoreNativeServiceSupervisor {
    // Observes one exact consistent definition and native loaded/activity state.
    fn observe(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        if platform != self.platform {
            return Err(native_service_error("native service platform changed"));
        }
        let bytes = self.definition_bytes(process)?;
        let (loaded, active) = match self.platform {
            CoreProcessPlatform::Linux => {
                let (loaded, activity) = self.systemd_state(process)?;
                (loaded, activity == SystemdActivity::Active)
            }
            CoreProcessPlatform::Macos => self.launchd_state(process)?,
        };
        if bytes.is_some() != loaded || (active && !loaded) {
            return Err(native_service_error("native service state is inconsistent"));
        }
        let identity = bytes.as_deref().map(definition_identity).transpose()?;
        CoreUpdateServiceState::new(
            update_service(process),
            identity.clone(),
            active.then_some(identity).flatten(),
        )
    }

    // Observes definition bytes independently from enabled or loaded state for exact replay.
    fn retirement_state(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
    ) -> Result<CoreNativeServiceRetirementState, CoreUpdateError> {
        if platform != self.platform {
            return Err(native_service_error("native service platform changed"));
        }
        let identity = self
            .definition_bytes(process)?
            .as_deref()
            .map(definition_identity)
            .transpose()?;
        let (loaded, active) = match self.platform {
            CoreProcessPlatform::Linux => {
                let (loaded, activity) = self.systemd_state(process)?;
                (loaded, activity == SystemdActivity::Active)
            }
            CoreProcessPlatform::Macos => self.launchd_state(process)?,
        };
        CoreNativeServiceRetirementState::new(identity, loaded, active)
    }

    // Retires only one exact planned identity or a reachable post-application replay projection.
    fn retire(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        expected_definition_identity: &Sha256Digest,
    ) -> Result<(), CoreUpdateError> {
        let state = self.retirement_state(platform, process)?;
        if !state.is_retirable(expected_definition_identity) {
            return Err(native_service_error(
                "native service retirement identity changed",
            ));
        }
        match self.platform {
            CoreProcessPlatform::Linux => {
                self.retire_systemd(process, expected_definition_identity, &state)
            }
            CoreProcessPlatform::Macos => {
                self.retire_launchd(process, expected_definition_identity, &state)
            }
        }
    }

    // Installs one exact platform definition and requested activity.
    fn install(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        self.require_definition(definition)?;
        match self.platform {
            CoreProcessPlatform::Linux => self.install_systemd(definition, active),
            CoreProcessPlatform::Macos => self.install_launchd(definition, active),
        }
    }

    // Tests exact definition bytes, loaded state, and activity without mutation.
    fn is_ready(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<bool, CoreUpdateError> {
        if platform != self.platform || (definition.is_none() && active) {
            return Err(native_service_error(
                "native service readiness contract is invalid",
            ));
        }
        if let Some(definition) = definition {
            self.require_definition(definition)?;
            if definition.process() != process {
                return Err(native_service_error("native service identity changed"));
            }
        }
        let bytes = self.definition_bytes(process)?;
        let (loaded, observed_active, failed) = match self.platform {
            CoreProcessPlatform::Linux => {
                let (loaded, activity) = self.systemd_state(process)?;
                (
                    loaded,
                    activity == SystemdActivity::Active,
                    activity == SystemdActivity::Failed,
                )
            }
            CoreProcessPlatform::Macos => {
                let (loaded, active) = self.launchd_state(process)?;
                (loaded, active, false)
            }
        };
        if failed {
            return Ok(false);
        }
        Ok(match definition {
            Some(definition) => {
                let loaded_identity = if loaded {
                    match self.platform {
                        CoreProcessPlatform::Linux => self.systemd_loaded_identity(definition)?,
                        CoreProcessPlatform::Macos => self.launchd_loaded_identity(definition)?,
                    }
                } else {
                    false
                };
                bytes.as_deref() == Some(definition.bytes())
                    && loaded
                    && loaded_identity
                    && observed_active == active
            }
            None => bytes.is_none() && !loaded && !observed_active,
        })
    }

    // Tests exact definition, loaded process, and activity within one absolute command deadline.
    fn is_ready_with_timeout(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        if platform != self.platform
            || (definition.is_none() && active)
            || timeout.is_zero()
            || timeout > Duration::from_secs(90)
        {
            return Err(native_service_error(
                "native service readiness contract is invalid",
            ));
        }
        if let Some(definition) = definition {
            self.require_definition(definition)?;
            if definition.process() != process {
                return Err(native_service_error("native service identity changed"));
            }
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| native_service_error("native service readiness deadline is invalid"))?;
        let bytes = self.definition_bytes(process)?;
        let (loaded, observed_active, failed) = match self.platform {
            CoreProcessPlatform::Linux => {
                let (loaded, activity) = self.systemd_state_before(process, deadline)?;
                (
                    loaded,
                    activity == SystemdActivity::Active,
                    activity == SystemdActivity::Failed,
                )
            }
            CoreProcessPlatform::Macos => {
                let (loaded, active) = self.launchd_state_before(process, deadline)?;
                (loaded, active, false)
            }
        };
        if failed {
            return Ok(false);
        }
        Ok(match definition {
            Some(definition) => {
                let loaded_identity = if loaded {
                    match self.platform {
                        CoreProcessPlatform::Linux => {
                            self.systemd_loaded_identity_before(definition, deadline)?
                        }
                        CoreProcessPlatform::Macos => {
                            self.launchd_loaded_identity_before(definition, deadline)?
                        }
                    }
                } else {
                    false
                };
                bytes.as_deref() == Some(definition.bytes())
                    && loaded
                    && loaded_identity
                    && observed_active == active
            }
            None => bytes.is_none() && !loaded && !observed_active,
        })
    }

    // Restores one exact prior platform definition or its exact prior absence.
    fn restore(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        if platform != self.platform || (definition.is_none() && active) {
            return Err(native_service_error(
                "native service restoration contract is invalid",
            ));
        }
        match definition {
            Some(definition) if definition.process() == process => self.install(definition, active),
            Some(_) => Err(native_service_error("native service identity changed")),
            None => match self.platform {
                CoreProcessPlatform::Linux => self.remove_systemd(process),
                CoreProcessPlatform::Macos => self.remove_launchd(process),
            },
        }
    }
}

// Requires one non-root absolute normalized home before deriving native integration paths.
fn is_safe_home_directory(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Validates one non-symlink, executable, non-writable native supervisor binary.
fn validate_native_executable(path: &Path) -> Result<(), CoreUpdateError> {
    if !path.is_absolute() {
        return Err(native_service_error(
            "native supervisor executable is invalid",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| native_service_error("native supervisor executable is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(native_service_error(
            "native supervisor executable is unsafe",
        ));
    }
    Ok(())
}

// Validates one bounded control-free native argv before process creation.
fn validate_native_arguments(arguments: &[String]) -> Result<(), CoreUpdateError> {
    if arguments.is_empty()
        || arguments.len() > 16
        || arguments.iter().any(|argument| {
            argument.is_empty() || argument.len() > 4_096 || argument.chars().any(char::is_control)
        })
    {
        return Err(native_service_error(
            "native supervisor arguments are invalid",
        ));
    }
    Ok(())
}

// Validates one open owner-only regular definition and its byte bound.
fn validate_private_file(
    file: &File,
    owner_user_id: u32,
    maximum_bytes: u64,
) -> Result<fs::Metadata, CoreUpdateError> {
    let metadata = file
        .metadata()
        .map_err(|_| native_service_error("service definition metadata is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_SERVICE_DEFINITION_MODE
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(native_service_error("service definition is unsafe"));
    }
    Ok(metadata)
}

// Proves one open definition retained its exact descriptor identity throughout a bounded read.
fn metadata_identity_is_stable(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.file_type().is_file()
        && after.file_type().is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

// Validates the exact owner-bound, non-writable service directory before mutation.
fn validate_service_parent(path: &Path, owner_user_id: u32) -> Result<PathBuf, CoreUpdateError> {
    let parent = path
        .parent()
        .ok_or_else(|| native_service_error("service definition path is invalid"))?
        .to_path_buf();
    let metadata = fs::symlink_metadata(&parent)
        .map_err(|_| native_service_error("service definition directory is unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(native_service_error(
            "service definition directory is unsafe",
        ));
    }
    Ok(parent)
}

// Persists one already-validated service-definition directory.
fn sync_directory(path: &Path) -> Result<(), CoreUpdateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| native_service_error("service definition directory could not be persisted"))
}

// Derives one exact service definition identity from its complete bytes.
fn definition_identity(bytes: &[u8]) -> Result<Sha256Digest, CoreUpdateError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| native_service_error("service definition identity is invalid"))
}

// Parses one closed UTF-8 supervisor state token without accepting extra lines.
fn output_text(output: &CoreNativeServiceCommandOutput) -> Result<&str, CoreUpdateError> {
    std::str::from_utf8(output.stdout())
        .map(str::trim)
        .map_err(|_| native_service_error("native supervisor state is invalid"))
}

// Selects launchd's diagnostic stream without combining unrelated command output.
fn diagnostic_text(output: &CoreNativeServiceCommandOutput) -> Result<&str, CoreUpdateError> {
    let bytes = if output.stderr().is_empty() {
        output.stdout()
    } else {
        output.stderr()
    };
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| native_service_error("native supervisor diagnostics are invalid"))
}

// Recognizes only launchd's documented transient bootstrap input/output failure.
fn is_transient_launchd_bootstrap_failure(output: &CoreNativeServiceCommandOutput) -> bool {
    output.status() == 5
        && diagnostic_text(output).is_ok_and(|text| {
            text.contains("Bootstrap failed: 5:") && text.contains("Input/output error")
        })
}

// Parses only the supported systemd enablement states.
fn parse_systemd_enabled(output: &CoreNativeServiceCommandOutput) -> Result<bool, CoreUpdateError> {
    match (output.status(), output_text(output)?) {
        (0, "enabled") => Ok(true),
        (1, "disabled") | (4, "not-found") => Ok(false),
        _ => Err(native_service_error("systemd enablement state is invalid")),
    }
}

// Parses only the supported systemd activity states without collapsing failure into inactivity.
fn parse_systemd_active(
    output: &CoreNativeServiceCommandOutput,
) -> Result<SystemdActivity, CoreUpdateError> {
    match (output.status(), output_text(output)?) {
        (0, "active") => Ok(SystemdActivity::Active),
        (3, "inactive") | (4, "inactive" | "unknown") => Ok(SystemdActivity::Inactive),
        (3, "failed") => Ok(SystemdActivity::Failed),
        _ => Err(native_service_error("systemd activity state is invalid")),
    }
}

// Parses a launchd print result into exact loaded and active state.
fn parse_launchd_state(
    output: &CoreNativeServiceCommandOutput,
) -> Result<(bool, bool), CoreUpdateError> {
    if output.status() == 113 {
        return Ok((false, false));
    }
    if output.status() != 0 {
        return Err(native_service_error("launchd activity state is invalid"));
    }
    let text = output_text(output)?;
    let states = launchd_state_values(text).collect::<Vec<_>>();
    if states.len() != 1 {
        return Err(native_service_error("launchd activity state is invalid"));
    }
    match states[0] {
        "running" => Ok((true, true)),
        "exited" | "waiting" => Ok((true, false)),
        _ => Err(native_service_error("launchd activity state is invalid")),
    }
}

// Returns only direct job-state values from full or compact launchctl output.
fn launchd_state_values(text: &str) -> impl Iterator<Item = &str> {
    let is_full_record = text
        .lines()
        .next()
        .is_some_and(|line| line.ends_with(" = {"));
    text.lines().filter_map(move |line| {
        let field = if is_full_record {
            launchd_direct_field(line)?
        } else if line.starts_with('\t') {
            return None;
        } else {
            line
        };
        field.strip_prefix("state = ")
    })
}

// Returns one direct launchd job field without admitting nested block fields.
fn launchd_direct_field(line: &str) -> Option<&str> {
    let field = line.strip_prefix('\t')?;
    (!field.starts_with('\t')).then_some(field)
}

// Parses the three exact systemd properties that bind disk state to the loaded process.
fn parse_systemd_loaded_identity(
    output: &CoreNativeServiceCommandOutput,
    definition_path: &Path,
    definition: &CoreServiceDefinition,
) -> Result<bool, CoreUpdateError> {
    if output.status() != 0 {
        return Err(native_service_error(
            "systemd loaded process identity is unavailable",
        ));
    }
    let mut fragment_path = None;
    let mut exec_start = None;
    let mut needs_reload = None;
    for line in output_text(output)?.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| native_service_error("systemd loaded process identity is invalid"))?;
        let slot = match name {
            "FragmentPath" => &mut fragment_path,
            "ExecStart" => &mut exec_start,
            "NeedDaemonReload" => &mut needs_reload,
            _ => {
                return Err(native_service_error(
                    "systemd loaded process identity is invalid",
                ))
            }
        };
        if slot.replace(value).is_some() {
            return Err(native_service_error(
                "systemd loaded process identity is duplicated",
            ));
        }
    }
    let fragment_path = fragment_path
        .ok_or_else(|| native_service_error("systemd loaded process identity is incomplete"))?;
    let exec_start = exec_start
        .ok_or_else(|| native_service_error("systemd loaded process identity is incomplete"))?;
    let needs_reload = needs_reload
        .ok_or_else(|| native_service_error("systemd loaded process identity is incomplete"))?;
    Ok(
        fragment_path == definition_path.to_str().unwrap_or_default()
            && needs_reload == "no"
            && parse_systemd_exec_start(exec_start, definition)?,
    )
}

// Parses one closed systemd ExecStart record and compares its exact executable and argv.
fn parse_systemd_exec_start(
    value: &str,
    definition: &CoreServiceDefinition,
) -> Result<bool, CoreUpdateError> {
    let body = value
        .strip_prefix("{ ")
        .and_then(|value| value.strip_suffix(" }"))
        .ok_or_else(|| native_service_error("systemd ExecStart identity is invalid"))?;
    let mut path = None;
    let mut arguments = None;
    let mut observed_fields = BTreeSet::new();
    for field in body.split(" ; ") {
        let (name, value) = field
            .split_once('=')
            .ok_or_else(|| native_service_error("systemd ExecStart identity is invalid"))?;
        if !matches!(
            name,
            "path"
                | "argv[]"
                | "ignore_errors"
                | "start_time"
                | "stop_time"
                | "pid"
                | "code"
                | "status"
        ) || !observed_fields.insert(name)
        {
            return Err(native_service_error(
                "systemd ExecStart identity is invalid",
            ));
        }
        match name {
            "path" => path = Some(value),
            "argv[]" => arguments = Some(value),
            _ => {}
        }
    }
    let expected_path = definition
        .executable()
        .to_str()
        .ok_or_else(|| native_service_error("systemd executable identity is invalid"))?;
    let expected_arguments = expected_process_arguments(definition)?;
    Ok(path == Some(expected_path) && arguments == Some(expected_arguments.as_str()))
}

// Parses launchd's target, plist path, program, and ordered argument block exactly once.
fn parse_launchd_loaded_identity(
    output: &CoreNativeServiceCommandOutput,
    target: &str,
    definition_path: &Path,
    definition: &CoreServiceDefinition,
) -> Result<bool, CoreUpdateError> {
    if output.status() != 0 {
        return Err(native_service_error(
            "launchd loaded process identity is unavailable",
        ));
    }
    let loaded = parse_launchd_loaded_job(output_text(output)?, target)?;
    let expected_path = definition_path
        .to_str()
        .ok_or_else(|| native_service_error("launchd definition path is invalid"))?;
    let expected_program = definition
        .executable()
        .to_str()
        .ok_or_else(|| native_service_error("launchd executable identity is invalid"))?;
    let expected_arguments = std::iter::once(definition.executable().as_os_str())
        .chain(
            definition
                .arguments()
                .iter()
                .map(std::ffi::OsString::as_os_str),
        )
        .map(|value| {
            value
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| native_service_error("launchd argument identity is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(loaded.path() == Path::new(expected_path)
        && loaded.program() == Path::new(expected_program)
        && loaded.arguments() == expected_arguments)
}

// Parses launchd's target, plist path, process, argv, and represented execution environment.
pub(crate) fn parse_launchd_loaded_job(
    text: &str,
    target: &str,
) -> Result<CoreLaunchdLoadedJob, CoreUpdateError> {
    let mut lines = text.lines().peekable();
    let expected_header = format!("{target} = {{");
    if lines.next() != Some(expected_header.as_str()) {
        return Err(native_service_error(
            "launchd loaded process target is invalid",
        ));
    }
    let mut path = None;
    let mut state = None;
    let mut program = None;
    let mut arguments = None;
    let mut environment = None;
    let mut working_directory = None;
    let mut process_id = None;
    while let Some(raw_line) = lines.next() {
        let Some(line) = launchd_direct_field(raw_line) else {
            continue;
        };
        if let Some(value) = line.strip_prefix("path = ") {
            if path.replace(value.to_string()).is_some() {
                return Err(native_service_error(
                    "launchd loaded process identity is duplicated",
                ));
            }
        } else if let Some(value) = line.strip_prefix("state = ") {
            if !matches!(value, "running" | "waiting" | "exited")
                || state.replace(value.to_string()).is_some()
            {
                return Err(native_service_error(
                    "launchd loaded process identity is invalid",
                ));
            }
        } else if let Some(value) = line.strip_prefix("program = ") {
            if program.replace(value.to_string()).is_some() {
                return Err(native_service_error(
                    "launchd loaded process identity is duplicated",
                ));
            }
        } else if line == "arguments = {" {
            if arguments.is_some() {
                return Err(native_service_error(
                    "launchd loaded process identity is duplicated",
                ));
            }
            let mut values = Vec::new();
            loop {
                let raw_value = lines.next().ok_or_else(|| {
                    native_service_error("launchd loaded process identity is incomplete")
                })?;
                if raw_value == "\t}" {
                    break;
                }
                let value = raw_value.strip_prefix("\t\t").ok_or_else(|| {
                    native_service_error("launchd loaded process arguments are invalid")
                })?;
                if value.is_empty() || value.chars().any(char::is_control) {
                    return Err(native_service_error(
                        "launchd loaded process arguments are invalid",
                    ));
                }
                values.push(value.to_string());
            }
            arguments = Some(values);
        } else if line == "environment = {" {
            if environment.is_some() {
                return Err(native_service_error(
                    "launchd loaded process identity is duplicated",
                ));
            }
            let mut values = BTreeMap::new();
            loop {
                let raw_value = lines.next().ok_or_else(|| {
                    native_service_error("launchd loaded process identity is incomplete")
                })?;
                if raw_value == "\t}" {
                    break;
                }
                let value = raw_value.strip_prefix("\t\t").ok_or_else(|| {
                    native_service_error("launchd loaded process environment is invalid")
                })?;
                let (name, value) = value.split_once(" => ").ok_or_else(|| {
                    native_service_error("launchd loaded process environment is invalid")
                })?;
                if name.is_empty()
                    || name.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
                    || values.insert(name.to_string(), value.to_string()).is_some()
                {
                    return Err(native_service_error(
                        "launchd loaded process environment is invalid",
                    ));
                }
            }
            environment = Some(values);
        } else if let Some(value) = line.strip_prefix("working directory = ") {
            if value.is_empty()
                || value.chars().any(char::is_control)
                || working_directory.replace(PathBuf::from(value)).is_some()
            {
                return Err(native_service_error(
                    "launchd loaded process identity is invalid",
                ));
            }
        } else if let Some(value) = line.strip_prefix("pid = ") {
            let value = value
                .parse::<u32>()
                .map_err(|_| native_service_error("launchd loaded process identity is invalid"))?;
            if value <= 1 || process_id.replace(value).is_some() {
                return Err(native_service_error(
                    "launchd loaded process identity is invalid",
                ));
            }
        }
    }
    let path =
        PathBuf::from(path.ok_or_else(|| {
            native_service_error("launchd loaded process identity is incomplete")
        })?);
    let state = state
        .ok_or_else(|| native_service_error("launchd loaded process identity is incomplete"))?;
    let program =
        PathBuf::from(program.ok_or_else(|| {
            native_service_error("launchd loaded process identity is incomplete")
        })?);
    let arguments = arguments
        .ok_or_else(|| native_service_error("launchd loaded process identity is incomplete"))?;
    #[cfg(not(target_os = "macos"))]
    let _ = (state, environment, working_directory, process_id);
    Ok(CoreLaunchdLoadedJob {
        path,
        #[cfg(target_os = "macos")]
        state,
        program,
        arguments,
        #[cfg(target_os = "macos")]
        environment,
        #[cfg(target_os = "macos")]
        working_directory,
        #[cfg(target_os = "macos")]
        process_id,
    })
}

// Builds the exact whitespace-free systemd argv representation returned by systemctl show.
fn expected_process_arguments(
    definition: &CoreServiceDefinition,
) -> Result<String, CoreUpdateError> {
    std::iter::once(definition.executable().as_os_str())
        .chain(
            definition
                .arguments()
                .iter()
                .map(std::ffi::OsString::as_os_str),
        )
        .map(|value| {
            let value = value
                .to_str()
                .ok_or_else(|| native_service_error("systemd argument identity is invalid"))?;
            if value.is_empty() || value.chars().any(char::is_whitespace) {
                return Err(native_service_error(
                    "systemd argument identity is ambiguous",
                ));
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(" "))
}

// Maps one resident process into the Core-update service identity.
const fn update_service(process: CoreResidentProcess) -> CoreUpdateResidentService {
    match process {
        CoreResidentProcess::Node => CoreUpdateResidentService::Node,
        CoreResidentProcess::Gateway => CoreUpdateResidentService::Gateway,
        CoreResidentProcess::Watchdog => CoreUpdateResidentService::Watchdog,
    }
}

// Creates one stable redacted native-service failure.
fn native_service_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("native service", reason)
}
